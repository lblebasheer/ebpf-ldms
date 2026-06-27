use anyhow::{Context as _, anyhow};
use aya::{
    Btf, Ebpf,
    programs::{FEntry, FExit},
};
#[rustfmt::skip]
use log::{debug, warn};
use std::path::Path;

const RINGBUF_PIN_PATH: &str = "/sys/fs/bpf/LDMS_SHARED_STREAM";

fn load_ebpf(bytes: &[u8]) -> anyhow::Result<Ebpf> {
    let mut ebpf = Ebpf::load(bytes)?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            smol::spawn(async move {
                let mut logger = smol::Async::new(logger).unwrap();
                loop {
                    logger.readable().await.unwrap();
                    // SAFETY: flush() does not replace the inner I/O source
                    unsafe { logger.get_mut() }.flush();
                }
            })
            .detach();
        }
    }
    Ok(ebpf)
}

fn attach_fentry(
    ebpf: &mut Ebpf,
    prog_name: &str,
    kernel_fn: &str,
    btf: &Btf,
) -> anyhow::Result<()> {
    let prog: &mut FEntry = ebpf.program_mut(prog_name).unwrap().try_into()?;
    prog.load(kernel_fn, btf)?;
    prog.attach()?;
    Ok(())
}

fn attach_fexit(
    ebpf: &mut Ebpf,
    prog_name: &str,
    kernel_fn: &str,
    btf: &Btf,
) -> anyhow::Result<()> {
    let prog: &mut FExit = ebpf.program_mut(prog_name).unwrap().try_into()?;
    prog.load(kernel_fn, btf)?;
    prog.attach()?;
    Ok(())
}

fn attach_probe_pair(
    ebpf: &mut Ebpf,
    entry_name: &str,
    exit_name: &str,
    kernel_fn: &str,
    btf: &Btf,
) -> anyhow::Result<()> {
    attach_fentry(ebpf, entry_name, kernel_fn, btf)?;
    attach_fexit(ebpf, exit_name, kernel_fn, btf)?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Exit if the shared ring buffer is not present. Usually indicating the streamer daemon isn't
    // running
    if !Path::new(RINGBUF_PIN_PATH).exists() {
        return Err(anyhow!(
            "Pinned Ring Buffer not found at {}.\nStreamer daemon may not be running",
            RINGBUF_PIN_PATH
        ));
    }

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

    let btf = Btf::from_sys_fs().context("BTF from sysfs")?;

    let mut ebpf = load_ebpf(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/nerscfslat"
    )))?;

    let probes = [
        ("filp_close_entry", "filp_close_exit", "filp_close"),
        ("vfs_fsync_range_entry", "vfs_fsync_range_exit", "vfs_fsync_range"),
        ("vfs_write_entry", "vfs_write_exit", "vfs_write"),
        ("vfs_writev_entry", "vfs_writev_exit", "vfs_writev"),
        ("vfs_iter_write_entry", "vfs_iter_write_exit", "vfs_iter_write"),
        ("vfs_read_entry", "vfs_read_exit", "vfs_read"),
        ("vfs_readv_entry", "vfs_readv_exit", "vfs_readv"),
        ("vfs_iter_read_entry", "vfs_iter_read_exit", "vfs_iter_read"),
    ];

    for (entry, exit, fn_name) in &probes {
        attach_probe_pair(&mut ebpf, entry, exit, fn_name, &btf)?;
    }

    let (tx, rx) = smol::channel::bounded::<()>(1);
    ctrlc::set_handler(move || {
        let _ = tx.send_blocking(());
    })?;
    println!("Waiting for Ctrl-C...");
    smol::block_on(rx.recv()).ok();
    println!("Exiting...");

    Ok(())
}
