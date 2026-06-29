#![feature(impl_trait_in_bindings)]
mod cli;

use std::{
    collections::{hash_map::Entry, HashMap},
    convert::TryFrom,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aya::maps::{Map, MapData, RingBuf};
use burster::{sliding_window_counter, Limiter, SlidingWindowCounter};
use ciborium::de::from_reader;
use clap::Parser;
use cli::ValidateClap;
use ftail::Ftail;
use ldms_stream::SockStream;
use log::{debug, error, trace, warn, LevelFilter};
use smol::{block_on, Async};

fn map_insert_key<T: Into<serde_json::Value>>(obj: &mut serde_json::Value, key: &str, value: T) {
    obj.as_object_mut()
        .unwrap()
        .insert(key.to_string(), value.into());
}

fn map_remove_key(obj: &mut serde_json::Value, key: &str) {
    obj.as_object_mut().unwrap().remove(key);
}

fn current_mono_realtime_offset() -> SystemTime {
    // as_nanos() returns u128
    let now_mono =
        Duration::from(nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC).unwrap());
    // wallclock time
    let now_real = SystemTime::now();
    let now_minus = now_real - now_mono;
    let offset = now_real.duration_since(now_minus).unwrap();
    let secs = offset.as_secs();
    let micros = offset.subsec_micros();
    debug!("Calculated offset between wallclock and CLOCK_MONOTONIC: {secs}.{micros}");
    now_minus
}

async fn ring_loop(
    stream: SockStream,
    ring_buf: RingBuf<MapData>,
    msglimit: u64,
    interval: u64,
    hostname: String,
) -> anyhow::Result<()> {
    // track tokens for each producer sending messages to us.
    let mut producer_tokens: HashMap<String, SlidingWindowCounter<impl Fn() -> Duration>> =
        HashMap::new();

    let hostname_json = serde_json::Value::String(hostname.clone());
    let time_offset = current_mono_realtime_offset();
    let mut ring_buf_f = Async::new(ring_buf)?;
    loop {
        let _ = ring_buf_f.readable().await;
        while let Some(item) = ring_buf_f.get_mut().next() {
            let v: ciborium::Value = match from_reader(&item as &[u8]) {
                Ok(v) => v,
                Err(err) => {
                    error!("Failed to deserialize CBOR. Skipping. Description: {}", err);
                    continue;
                }
            };
            let mut serde_v = match serde_json::to_value(&v) {
                Ok(serde_v) => serde_v,
                Err(err) => {
                    error!(
                        "Failed to deserialize CBOR to JSON. Skipping: Description {}",
                        err
                    );
                    continue;
                }
            };
            let (id, timestamp_monotonic) = (&serde_v["id"], &serde_v["timestamp_monotonic"]);

            if *id == serde_json::Value::Null || *timestamp_monotonic == serde_json::Value::Null {
                warn!("\"id\", \"timestamp_monotonic\" fields not found in message. Skipping message.");
                continue;
            }

            let id = id.as_str().unwrap_or("invalid id field").to_string();
            let timestamp_monotonic = timestamp_monotonic.as_u64().unwrap_or(0u64);

            // Insert/override "hostname" field. Required for omni
            map_insert_key(&mut serde_v, "hostname", hostname_json.as_str());

            // Generate timestamp field from received monotonic clock timestamp. Required for omni.
            map_insert_key(
                &mut serde_v,
                "timestamp",
                match (time_offset + Duration::from_nanos(timestamp_monotonic))
                    .duration_since(UNIX_EPOCH)
                {
                    Ok(unixtime) => {
                        let mut ts: f64 = unixtime.as_secs() as f64;
                        ts += (unixtime.subsec_nanos() as f64) / 1_000_000_000_f64;
                        ts
                    }
                    Err(_) => {
                        error!("Generating timestamp failed. Skipping message.");
                        continue;
                    }
                },
            );

            // Remove timestamp_monotonic field since OMNI doesn't care about it
            map_remove_key(&mut serde_v, "timestamp_monotonic");

            // Track sliding window limits for each id.
            let _entry = producer_tokens
                .entry(id.to_string())
                .or_insert(sliding_window_counter(msglimit, interval * 1000));

            match producer_tokens.entry(id.to_string()) {
                Entry::Vacant(e) => {
                    e.insert(sliding_window_counter(msglimit, interval * 1000));
                }
                Entry::Occupied(mut e) => {
                    if e.get_mut().try_consume_one().is_err() {
                        trace!("Rate limit exceeded for {}. Skipping message.", id,);
                        continue;
                    }
                }
            };

            let msg = serde_json::to_string(&serde_v)?;
            debug!("Received message in JSON: {msg}");
            stream.ldms_msg_publish(&msg)?;
        }
    }
}

fn main() -> anyhow::Result<()> {
    let mut cli = cli::EbpfStreamer::parse();
    Ftail::new()
        .console_env_level() // log to console
        .single_file(&Path::new(&cli.logfile), true, LevelFilter::Debug)
        .max_file_size(100)
        .init()?; // initialize logger
    cli.parse_ratelimit();

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
    });
    drop(readtask);
    println!("Exiting...");

    Ok(())
}
