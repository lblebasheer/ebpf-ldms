#![no_std]
use aya_ebpf::{
    bindings::path,
    cty::{c_char, c_void},
    helpers::{bpf_d_path, bpf_ktime_get_ns, bpf_map_update_elem},
    macros::map,
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::{FEntryContext, FExitContext},
};
use aya_log_ebpf::{debug, error};
use minicbor::Encoder;

pub const PATHFRAGLEN: usize = 15 + 1;
pub const NUM_PATH_PREFIX: u32 = 8;
pub const AGG_INTERVAL: u64 = 1000 * 1000 * 500; // 500ms
pub const BUFSIZE: usize = 1024;

#[map]
pub static COUNTER: Array<u64> = Array::with_max_entries(1, 0);

#[map]
pub static mut WRITESTATS: Array<FsWriteStats> = Array::with_max_entries(NUM_PATH_PREFIX, 0);

#[map]
pub static PATHBUF: PerCpuArray<PathSlice> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static PTRLIST: HashMap<usize, EntryRec> = HashMap::with_max_entries(1024, 0);

#[map]
pub static LDMS_SHARED_STREAM: RingBuf = RingBuf::pinned(8192, 0);

#[allow(nonstandard_style)]
#[allow(unnecessary_transmutes)]
#[allow(unsafe_op_in_unsafe_fn)]
#[allow(dead_code)]
mod vmlinux;

type PathSlice = [u8; PATHFRAGLEN];

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FsWriteStats {
    pub path_prefix: PathSlice,
    pub min: u64,
    pub max: u64,
    pub total: u64,
    pub count: u64,
    pub lastpublish: u64,
}

pub struct EntryRec {
    pub timestamp: u64,
    pub path: PathSlice,
}

pub struct EventFields<'a> {
    pub id: &'a str,
    pub version: &'a str,
    pub monotonic: u64,
    pub seq: u64,
    pub path_prefix: &'a [u8],
}

pub fn try_fslat_entry(ctx: FEntryContext, _filpop: &str) -> Result<u32, u32> {
    let now = unsafe { bpf_ktime_get_ns() };
    let filp: *mut vmlinux::file = ctx.arg(0);
    let pathptr = unsafe { &raw mut (*filp).f_path };
    let Some(pathbuf_ptr) = PATHBUF.get_ptr_mut(0) else {
        return Err(1);
    };
    let ret = unsafe {
        bpf_d_path(
            pathptr as *mut path,
            pathbuf_ptr as *mut c_char,
            PATHFRAGLEN as u32,
        )
    };
    if ret < 0 {
        return Err(1);
    }
    {
        let entryrec = EntryRec {
            timestamp: now,
            path: unsafe { *pathbuf_ptr },
        };
        let _ = PTRLIST.insert(&(filp as usize), &entryrec, 0u64);
    }
    Ok(0)
}

fn find_null_pos(haystack: &[u8]) -> usize {
    let mut idx = 0;
    for i in 0..PATHFRAGLEN {
        if haystack[i] == 0 {
            idx = i;
            break;
        }
    }
    idx
}

pub fn starts_with(needle: &[u8], haystack: &[u8], len: usize) -> bool {
    if needle[0] == 0 {
        return false;
    }
    let mut i = 0;
    let mut j = 0;
    while i < len {
        if haystack[j] != needle[i] {
            return false;
        }
        i += 1;
        j += 1;
    }
    true
}

pub fn try_fslat_exit(ctx: FExitContext, filpop: &str) -> Result<u32, u32> {
    let filp: *const vmlinux::file = ctx.arg(0);
    let Some(countptr) = COUNTER.get_ptr_mut(0) else {
        return Err(1);
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
                let path_prefix_len = unsafe { find_null_pos(&(*fsstat).path_prefix) };
                if unsafe { starts_with(&(*fsstat).path_prefix, &entryrec.path, path_prefix_len) } {
                    if now - unsafe { (*fsstat).lastpublish } > AGG_INTERVAL {
                        let eventf = EventFields {
                            id: "fslat",
                            version: "v1",
                            monotonic: unsafe { bpf_ktime_get_ns() },
                            seq: unsafe { *countptr },
                            path_prefix: unsafe { &(*fsstat).path_prefix },
                        };

                        let Ok(_) = update_stats(&ctx, idx, fsstat, delta) else {
                            error!(ctx, "update_stats() failed");
                            return Err(1);
                        };
                        let Ok(_) = ringbuf_put(&eventf, fsstat, filpop, "ns") else {
                            error!(ctx, "ringbuf_put() failed");
                            return Err(1);
                        };
                        let Ok(_) = clear_stats(&ctx, idx, fsstat, now) else {
                            error!(ctx, "clear_stats() failed");
                            return Err(1);
                        };
                        unsafe {
                            *countptr += 1;
                        }
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

pub fn update_stats(
    _ctx: &FExitContext,
    idx: u32,
    fsstat: *mut FsWriteStats,
    latency: u64,
) -> Result<u32, u32> {
    unsafe {
        #[allow(static_mut_refs)]
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

pub fn clear_stats(
    _ctx: &FExitContext,
    idx: u32,
    fsstat: *mut FsWriteStats,
    now: u64,
) -> Result<u32, u32> {
    unsafe {
        #[allow(static_mut_refs)]
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

pub fn ringbuf_put(
    eventf: &EventFields,
    fsstat: *mut FsWriteStats,
    filpop: &str,
    unit: &str,
) -> Result<u32, u32> {
    #[allow(static_mut_refs)]
    let Some(mut dataent) = LDMS_SHARED_STREAM.reserve::<[u8; BUFSIZE]>(0) else {
        return Err(1);
    };

    let EventFields {
        id,
        version,
        monotonic,
        seq,
        path_prefix,
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
            .str("opname")
            .unwrap_unchecked()
            .str(filpop)
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
            .str(core::str::from_utf8_unchecked(
                path_prefix.split_at_unchecked(find_null_pos(path_prefix)).0,
            ))
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
