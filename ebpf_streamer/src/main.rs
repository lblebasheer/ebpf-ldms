#[rustfmt::skip]
use log::{debug, warn};
use std::{
    collections::{hash_map::Entry, HashMap},
    convert::TryFrom,
    time::Instant,
};

use async_channel;
use aya::maps::{Map, MapData, RingBuf};
use ciborium::de::from_reader;
use clap::Parser;
use ldms_stream::SockStream;
use smol::{block_on, Async};

#[derive(Parser)]
#[command(name = "ebpf_streamer")]
#[command(author = "Ershaad Basheer <ebasheer@lbl.gov>")]
#[command(version = "0.3")]
#[command(about = "Stream count of slow function calls to LDMS", long_about = None)]
struct EbpfStreamer {
    /// Name of LDMS stream to which messages are published
    #[arg(id="stream",long,default_value_t = String::from("nersc"),value_name="STREAM")]
    stream: String,
    /// Average message rate limit for an individual producer in messages/interval (see --interval)
    #[arg(
        id = "msglimit",
        long,
        default_value_t = 2,
        value_name = "MSGPERPERIOD"
    )]
    msglimit: u32,
    /// Length of time interval over which message limits are calculated. In seconds
    #[arg(id = "interval", long, default_value_t = 1, value_name = "INTERVAL")]
    interval: u32,
    /// Hostname or IP address of LDMS daemon
    #[arg(id="host",long,default_value_t = String::from("localhost"),value_name="HOST")]
    host: String,
    /// TCP Port of LDMS daemon
    #[arg(id="port",long,default_value_t = String::from("60003"),value_name="PORT")]
    port: String,
    /// Authentication method when connecting to LDMS daemon
    #[arg(id="authentication",long,default_value_t = String::from("none"),value_name="none|munge")]
    authentication: String,
}

async fn ring_loop(
    stream: SockStream,
    ring_buf: RingBuf<MapData>,
    msglimit: u32,
    interval: u32,
) -> anyhow::Result<()> {
    // track tokens for each producer sending messages to us.
    let mut producer_tokens: HashMap<(String, String), u32> = HashMap::new();
    let (maxtokens, interval) = match (msglimit, interval) {
        (0, 0) => {
            warn!("Invalid msglimit and interval. Setting to 1 msg/second");
            (1, 1)
        }
        (0, j @ 1..) => {
            warn!("Invalid msglimit. Setting to 1 msg/{interval} second(s)");
            (1, j)
        }
        (i @ 1.., 0) => {
            warn!("Invalid interval. Setting to 1 second");
            (i, 1)
        }
        (i @ 1.., j @ 1..) => (i, j),
    };
    let mut window_start = Instant::now();
    let mut ring_buf_f = Async::new(ring_buf)?;
    loop {
        let _ = ring_buf_f.readable().await;
        while let Some(item) = ring_buf_f.get_mut().next() {
            debug!("{:?}", item);
            let v: ciborium::Value = from_reader(&item as &[u8]).unwrap();
            let serde_v = serde_json::to_value(v)?;

            // ratelimit.
            let (id, version) = (&serde_v["id"], &serde_v["version"]);
            if *id == serde_json::Value::Null || *version == serde_json::Value::Null {
                warn!("\"id\" or \"version\" fields not found in message. Skipping message.");
                continue;
            }
            let _entry = producer_tokens
                .entry((id.to_string(), version.to_string()))
                .or_insert(maxtokens);
            let now = Instant::now();
            if (now - window_start).as_millis() > (interval * 1000).into() {
                window_start = now;
                for v in producer_tokens.values_mut() {
                    *v = maxtokens;
                }
                producer_tokens
                    .entry((id.to_string(), version.to_string()))
                    .and_modify(|e| {
                        *e = e.saturating_sub(1);
                    });
            } else {
                let Entry::Occupied(mut entry) =
                    producer_tokens.entry((id.to_string(), version.to_string()))
                else {
                    panic!("id: {id}, version: {version} not found in HashMap")
                };
                let tokens = entry.get_mut();
                if *tokens > 0 {
                    *tokens -= 1;
                } else {
                    debug!(
                        "Token bucket empty for id: {id}, version: {version}. Skipping message."
                    );
                    continue;
                }
            }

            let msg = serde_json::to_string(&serde_v)?;
            stream.ldms_stream_publish(&msg)?;
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cli = EbpfStreamer::parse();
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut stream = SockStream::new(
        "sock",
        &cli.authentication,
        &cli.host,
        &cli.port,
        &cli.stream,
    )?;
    stream.connect()?;

    let ring_buf = RingBuf::try_from(Map::RingBuf(
        MapData::from_pin("/sys/fs/bpf/LDMS_SHARED_STREAM").unwrap(),
    ))
    .unwrap();
    let readtask = smol::spawn(ring_loop(stream, ring_buf, cli.msglimit, cli.interval));

    let (s, ctrl_c) = async_channel::bounded(100);
    let handle = move || {
        s.try_send(()).ok();
    };
    ctrlc::set_handler(handle).unwrap();
    block_on(async {
        println!("Waiting for Ctrl-C...");

        // Receive a message that indicates the Ctrl-C signal occurred.
        ctrl_c.recv().await.ok();
        readtask.cancel().await;
    });
    println!("Exiting...");

    Ok(())
}
