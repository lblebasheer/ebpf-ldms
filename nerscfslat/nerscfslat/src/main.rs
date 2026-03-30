use anyhow::{Context as _, anyhow};
use aya::{
    Btf, Ebpf,
    programs::{FEntry, FExit},
};
#[rustfmt::skip]
use log::{debug, warn};
use std::path::Path;

use tokio::signal;

const RINGBUF_PIN_PATH: &str = "/sys/fs/bpf/LDMS_SHARED_STREAM";

fn load_ebpf(bytes: &[u8]) -> anyhow::Result<Ebpf> {
    let mut ebpf = Ebpf::load(bytes)?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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

    let mut ebpf_close = load_ebpf(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/nerscfslat-close"
    )))?;
    attach_probe_pair(
        &mut ebpf_close,
        "filp_close_entry",
        "filp_close_exit",
        "filp_close",
        &btf,
    )?;

    let mut ebpf_fsync = load_ebpf(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/nerscfslat-fsync"
    )))?;
    attach_probe_pair(
        &mut ebpf_fsync,
        "vfs_fsync_range_entry",
        "vfs_fsync_range_exit",
        "vfs_fsync_range",
        &btf,
    )?;

    let mut ebpf_writev = load_ebpf(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/nerscfslat-writev"
    )))?;
    attach_probe_pair(
        &mut ebpf_writev,
        "vfs_writev_entry",
        "vfs_writev_exit",
        "vfs_writev",
        &btf,
    )?;

    let mut ebpf_write = load_ebpf(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/nerscfslat-write"
    )))?;
    attach_probe_pair(
        &mut ebpf_write,
        "vfs_write_entry",
        "vfs_write_exit",
        "vfs_write",
        &btf,
    )?;

    let mut ebpf_read = load_ebpf(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/nerscfslat-read"
    )))?;
    attach_probe_pair(
        &mut ebpf_read,
        "vfs_read_entry",
        "vfs_read_exit",
        "vfs_read",
        &btf,
    )?;

    let mut ebpf_readv = load_ebpf(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/nerscfslat-readv"
    )))?;
    attach_probe_pair(
        &mut ebpf_readv,
        "vfs_readv_entry",
        "vfs_readv_exit",
        "vfs_readv",
        &btf,
    )?;

    let mut ebpf_iterread = load_ebpf(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/nerscfslat-iterread"
    )))?;
    attach_probe_pair(
        &mut ebpf_iterread,
        "vfs_iter_read_entry",
        "vfs_iter_read_exit",
        "vfs_iter_read",
        &btf,
    )?;

    let mut ebpf_iterwrite = load_ebpf(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/nerscfslat-iterwrite"
    )))?;
    attach_probe_pair(
        &mut ebpf_iterwrite,
        "vfs_iter_write_entry",
        "vfs_iter_write_exit",
        "vfs_iter_write",
        &btf,
    )?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
