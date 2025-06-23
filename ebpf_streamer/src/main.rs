#[rustfmt::skip]
use log::{debug, warn};
use aya::maps::{RingBuf, MapData};
use std::convert::TryFrom;
use async_io::Async;
use async_channel;
use smol::block_on;
use ldms_stream::{SockStream};
use clap::Parser;
use ciborium::{Value,de::from_reader};
use serde::{Serialize};

#[derive(Parser)]
#[command(name = "ebpf_streamer")]
#[command(author = "Ershaad Basheer <ebasheer@lbl.gov>")]
#[command(version = "0.2")]
#[command(about = "Stream count of slow function calls to LDMS", long_about = None)]
struct EbpfStreamer {
    #[arg(id="stream",long,default_value_t = String::from("nersc"),value_name="STREAM")]
    stream: String,
    #[arg(id="interval",long,default_value_t = 2.0,value_name="INTERVAL")]
    interval: f64,
    #[arg(id="host",long,default_value_t = String::from("localhost"),value_name="HOST")]
    host: String,
    #[arg(id="port",long,default_value_t = String::from("60003"),value_name="PORT")]
    port: String,
    #[arg(id="authentication",long,default_value_t = String::from("none"),value_name="none|munge")]
    authentication: String,
}

#[derive(Serialize)]
struct Sample {
    name: String,
    value: u64,
}

async fn ring_next(stream: SockStream, ring_buf: RingBuf<MapData>) -> anyhow::Result<()> {
    let mut ring_buf_f = Async::new(ring_buf)?;
    loop {
        let _ = ring_buf_f.readable().await;
        while let Some(item) = ring_buf_f.get_mut().next() {
            println!("length: {}", item.len());
            let v: Value = from_reader(&item as &[u8]).unwrap();
            let msg = serde_json::to_string(&v)?;
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

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ebpf_streamer"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {e}");
    }

    let mut stream = SockStream::new("sock", &cli.authentication, &cli.host, &cli.port, &cli.stream)?;
    stream.connect()?;

    let ring_buf = RingBuf::try_from(ebpf.take_map("LDMS_SHARED_STREAM").unwrap()).unwrap();
    let readtask = smol::spawn(ring_next(stream, ring_buf));

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
