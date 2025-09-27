#![feature(impl_trait_in_bindings)]
mod cli;

use std::{
    collections::{hash_map::Entry, HashMap},
    convert::TryFrom,
    time::Duration,
};

use async_channel;
use aya::maps::{Map, MapData, RingBuf};
use burster::{sliding_window_counter, Limiter, SlidingWindowCounter};
use ciborium::de::from_reader;
use clap::Parser;
use ldms_stream::SockStream;
use log::{debug, warn};
use smol::{block_on, Async};

async fn ring_loop(
    stream: SockStream,
    ring_buf: RingBuf<MapData>,
    msglimit: u64,
    interval: u64,
    hostname: String,
) -> anyhow::Result<()> {
    // track tokens for each producer sending messages to us.
    let mut producer_tokens: HashMap<
        (String, String),
        SlidingWindowCounter<impl Fn() -> Duration>,
    > = HashMap::new();
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

    let hostname = serde_json::Value::String(hostname);
    let mut ring_buf_f = Async::new(ring_buf)?;
    loop {
        let _ = ring_buf_f.readable().await;
        while let Some(item) = ring_buf_f.get_mut().next() {
            debug!("{:?}", item);
            let v: ciborium::Value = from_reader(&item as &[u8]).unwrap();
            let mut serde_v = serde_json::to_value(v)?;
            serde_v
                .as_object_mut()
                .unwrap()
                .insert("hostname".to_string(), hostname.clone());

            // ratelimit.
            let (id, version) = (&serde_v["id"], &serde_v["version"]);
            if *id == serde_json::Value::Null || *version == serde_json::Value::Null {
                warn!("\"id\" or \"version\" fields not found in message. Skipping message.");
                continue;
            }
            let _entry = producer_tokens
                .entry((id.to_string(), version.to_string()))
                .or_insert(sliding_window_counter(maxtokens, interval * 1000));

            if let Entry::Occupied(mut entry) =
                producer_tokens.entry((id.to_string(), version.to_string()))
            {
                if !entry.get_mut().try_consume_one().is_ok() {
                    debug!(
                        "Token bucket for {} {} empty. Skipping message.",
                        id, version
                    );
                    continue;
                }
            } else {
                panic!("id: {id}, version: {version} not found in HashMap")
            };

            let msg = serde_json::to_string(&serde_v)?;
            stream.ldms_stream_publish(&msg)?;
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cli = cli::EbpfStreamer::parse();
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
    let readtask = smol::spawn(ring_loop(
        stream,
        ring_buf,
        cli.msglimit,
        cli.interval,
        cli.hostname,
    ));

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
