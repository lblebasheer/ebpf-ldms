#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::path,
    cty::{c_uchar, c_void},
    helpers::{bpf_d_path, bpf_ktime_get_ns, bpf_map_update_elem},
    macros::{fentry, fexit, map},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::{FEntryContext, FExitContext},
};
use aya_log_ebpf::{debug, error};
use minicbor::Encoder;
use nerscfslat_common::{
    AGG_INTERVAL, EntryRec, EventFields, FsWriteStats, NUM_PATH_PREFIX, PATHFRAGLEN,
};

#[allow(nonstandard_style)]
#[allow(unnecessary_transmutes)]
#[allow(unsafe_op_in_unsafe_fn)]
#[allow(dead_code)]
mod vmlinux;

const BUFSIZE: usize = 1024;

#[map]
static COUNTER: Array<u64> = Array::with_max_entries(1, 0);

#[map]
static mut WRITESTATS: Array<FsWriteStats> = Array::with_max_entries(NUM_PATH_PREFIX, 0);

#[map]
static PATHBUF: PerCpuArray<[c_uchar; PATHFRAGLEN]> = PerCpuArray::with_max_entries(1, 0);

#[map]
static PTRLIST: HashMap<usize, EntryRec> = HashMap::with_max_entries(1024, 0);

#[map]
static LDMS_SHARED_STREAM: RingBuf = RingBuf::pinned(8192, 0);

#[fentry(function = "filp_close")]
pub fn filp_close_entry(ctx: FEntryContext) -> u32 {
    match try_fslat_entry(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[fexit(function = "filp_close")]
pub fn filp_close_exit(ctx: FExitContext) -> u32 {
    match try_fslat_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_fslat_entry(ctx: FEntryContext) -> Result<u32, u32> {
    let now = unsafe { bpf_ktime_get_ns() };
    let filp: *mut vmlinux::file = ctx.arg(0);
    let pathptr = unsafe { &raw mut (*filp).f_path };
    let Some(pathbuf_ptr) = PATHBUF.get_ptr_mut(0) else {
        return Err(1);
    };
    let ret = unsafe {
        bpf_d_path(
            pathptr as *mut path,
            pathbuf_ptr as *mut i8,
            PATHFRAGLEN as u32,
        )
    };
    if ret < 0 {
        return Err(1);
    }
    {
        let entryrec = EntryRec {
            timestamp: now,
            pathfrag: unsafe { *pathbuf_ptr },
            fraglen: (ret - 1) as usize,
        };
        let _ = PTRLIST.insert(&(filp as usize), &entryrec, 0u64);
    }
    Ok(0)
}

fn try_fslat_exit(ctx: FExitContext) -> Result<u32, u32> {
    let filp: *const vmlinux::file = ctx.arg(0);
    let Some(countptr) = COUNTER.get_ptr_mut(0) else {
        return Err(1);
    };
    let eventf = EventFields {
        id: "fslat",
        version: "v1",
        monotonic: unsafe { bpf_ktime_get_ns() },
        seq: unsafe { *countptr },
    };

    match unsafe { PTRLIST.get(filp as usize) } {
        Some(entryrec) => {
            let now = unsafe { bpf_ktime_get_ns() };
            let delta = now - entryrec.timestamp;
            for idx in 0..NUM_PATH_PREFIX {
                #[allow(static_mut_refs)]
                let Some(fsstat) = (unsafe { WRITESTATS.get_ptr_mut(idx) }) else {
                    return Err(1);
                };
                let pathstr = unsafe { core::str::from_utf8_unchecked(&entryrec.pathfrag) };
                let pathfragstr = unsafe { core::str::from_utf8_unchecked(&(*fsstat).pathfrag) };
                let (path, pathfrag) = unsafe {
                    (
                        pathstr.get_unchecked(0..entryrec.fraglen.min(PATHFRAGLEN)),
                        pathfragstr.get_unchecked(0..(*fsstat).fraglen.min(PATHFRAGLEN))
                    )
                };
                if !pathfrag.is_empty() && path.starts_with(pathfrag) {
                    if now - unsafe { (*fsstat).lastpublish } > AGG_INTERVAL {
                        if unsafe { (*fsstat).count } > 0 {
                            let Ok(_) = ringbuf_put(&eventf, fsstat, "ns") else {
                                error!(ctx, "ringbuf_put() failed");
                                return Err(1);
                            };
                            unsafe {
                                *countptr += 1;
                            }
                        }
                        let Ok(_) = clear_stats(&ctx, idx, fsstat, now) else {
                            error!(ctx, "update_stats() failed");
                            return Err(1);
                        };
                    } else {
                        let Ok(_) = update_stats(&ctx, idx, fsstat, delta) else {
                            error!(ctx, "update_stats() failed");
                            return Err(1);
                        };
                    }
                }
                let _ = PTRLIST.remove(&(filp as usize));
            }
        }
        None => {}
    };
    Ok(0)
}

fn update_stats(
    ctx: &FExitContext,
    idx: u32,
    fsstat: *mut FsWriteStats,
    latency: u64,
) -> Result<u32, u32> {
    unsafe {
        let mut ws: FsWriteStats = *fsstat;
        if latency < ws.min {
            ws.min = latency;
        }
        if latency > ws.max {
            ws.max = latency;
        }
        ws.count += 1;
        ws.total += latency;

        #[allow(static_mut_refs)]
        bpf_map_update_elem(
            &raw mut WRITESTATS as *mut c_void,
            &raw const idx as *const c_void,
            &raw const ws as *const c_void,
            0u64,
        );
    }
    Ok(0)
}

fn clear_stats(
    ctx: &FExitContext,
    idx: u32,
    fsstat: *mut FsWriteStats,
    now: u64,
) -> Result<u32, u32> {
    unsafe {
        let mut ws: FsWriteStats = *fsstat;
        ws.lastpublish = now;
        ws.count = 0;
        ws.total = 0;
        ws.min = u64::MAX;
        ws.max = u64::MIN;
        #[allow(static_mut_refs)]
        bpf_map_update_elem(
            &raw mut WRITESTATS as *mut c_void,
            &raw const idx as *const c_void,
            &raw const ws as *const c_void,
            0u64,
        );
    }
    Ok(0)
}

fn ringbuf_put(
    eventf: &EventFields,
    fsstat: *mut FsWriteStats,
    unit: &str,
) -> Result<u32, u32> {
    let Some(mut dataent) = LDMS_SHARED_STREAM.reserve::<[u8; BUFSIZE]>(0) else {
        return Err(1);
    };
    let pathfragstr = unsafe { core::str::from_utf8_unchecked(&(*fsstat).pathfrag) };
    let pathfrag =
        unsafe { pathfragstr.get_unchecked(..(*fsstat).fraglen.clamp(0, PATHFRAGLEN)) };
    let EventFields {
        id,
        version,
        monotonic,
        seq,
    } = *eventf;
    let dataent_bytes: *mut [u8] = dataent.as_mut_ptr();
    let mut encoder = unsafe { Encoder::new(&mut *dataent_bytes) };
    unsafe {
        encoder
            .begin_map()
            .unwrap_unchecked()
            .str("id")
            .unwrap_unchecked()
            .str(id)
            .unwrap_unchecked()
            .str("version")
            .unwrap_unchecked()
            .str(version)
            .unwrap_unchecked()
            .str("timestamp_monotonic")
            .unwrap_unchecked()
            .u64(monotonic)
            .unwrap_unchecked()
            .str("metrics")
            .unwrap_unchecked()
            .begin_array()
            .unwrap_unchecked()
            .begin_map()
            .unwrap_unchecked()
            .str("sequence")
            .unwrap_unchecked()
            .u64(seq)
            .unwrap_unchecked()
            .str("min_latency")
            .unwrap_unchecked()
            .u64((*fsstat).min)
            .unwrap_unchecked()
            .str("max_latency")
            .unwrap_unchecked()
            .u64((*fsstat).max)
            .unwrap_unchecked()
            .str("total_latency")
            .unwrap_unchecked()
            .u64((*fsstat).total)
            .unwrap_unchecked()
            .str("count_samples")
            .unwrap_unchecked()
            .u64((*fsstat).count)
            .unwrap_unchecked()
            .str("interval")
            .unwrap_unchecked()
            .u64(AGG_INTERVAL)
            .unwrap_unchecked()
            .str("unit")
            .unwrap_unchecked()
            .str(unit)
            .unwrap_unchecked()
            .str("path_prefix")
            .unwrap_unchecked()
            .str(pathfrag)
            .unwrap_unchecked()
            .end()
            .unwrap_unchecked()
            .end()
            .unwrap_unchecked()
            .end()
            .unwrap_unchecked();
    }
    dataent.submit(0);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
