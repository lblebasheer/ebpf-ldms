#![no_std]
#![no_main]

use core::borrow::BorrowMut;

use aya_ebpf::{
    bindings::path,
    cty::{c_uchar, c_void},
    helpers::{bpf_d_path, bpf_ktime_get_ns, bpf_map_update_elem},
    macros::{fentry, fexit, map},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::{FEntryContext, FExitContext},
};
use aya_log_ebpf::debug;
use minicbor::Encoder;
use nerscfslat_common::{EntryRec, FsWriteStats, NUM_PATH_PREFIX, PATHFRAGLEN};

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

struct EventFields<'a> {
    id: &'a str,
    version: &'a str,
    monotonic: u64,
    seq: u64,
}

fn hashmap_pathentry(
    ctx: FEntryContext,
    path: &[c_uchar; PATHFRAGLEN],
    pathlen: usize,
) -> Option<&FsWriteStats> {
    for idx in 0..NUM_PATH_PREFIX {
        #[allow(static_mut_refs)]
        let Some(entry) = (unsafe { WRITESTATS.get(idx) }) else {
            return None;
        };
        let pathstr = unsafe { core::str::from_utf8_unchecked(path) };
        let pathfragstr = unsafe { core::str::from_utf8_unchecked(&entry.pathfrag) };
        let path = unsafe { pathstr.get_unchecked(..pathlen.clamp(0, PATHFRAGLEN)) };
        let pathfrag = unsafe { pathfragstr.get_unchecked(..entry.fraglen.clamp(0, PATHFRAGLEN)) };
        if path.starts_with(pathfrag) && !pathfrag.is_empty() {
            return Some(entry);
        }
    }
    None
}

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
    // exclude trailing null
//    let Some(entry) = hashmap_pathentry(
//        ctx,
//        unsafe { pathbuf_ptr.as_ref().unwrap() },
//        (ret - 1) as usize,
//    ) else {
//        return Ok(0);
//    };

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
            let Ok(_) = update_stats(ctx, entryrec, "filp_close") else {
                return Err(1);
            };
            let Ok(_) = ringbuf_put(&eventf, "filp_close", 0, "ns") else {
                return Err(1);
            };
            let _ = PTRLIST.remove(&(filp as usize));
            unsafe {
                *countptr += 1;
            }
        }
        None => {}
    };
    Ok(0)
}

fn update_stats(ctx: FExitContext, entryrec: &EntryRec, op: &str) -> Result<u32, u32> {
    let now = unsafe { bpf_ktime_get_ns() };
    let delta = now - entryrec.timestamp;
    for idx in 0..NUM_PATH_PREFIX {
        #[allow(static_mut_refs)]
        let Some(entry) = (unsafe { WRITESTATS.get(idx) }) else {
            return Err(1);
        };
        let pathstr = unsafe { core::str::from_utf8_unchecked(&entryrec.pathfrag) };
        let pathfragstr = unsafe { core::str::from_utf8_unchecked(&entry.pathfrag) };
        let path = unsafe { pathstr.get_unchecked(..entryrec.fraglen.clamp(0, PATHFRAGLEN)) };
        let pathfrag = unsafe { pathfragstr.get_unchecked(..entry.fraglen.clamp(0, PATHFRAGLEN)) };
        debug!(ctx, "{}", path);
        debug!(ctx, "-> {}", pathfrag);
        if path.starts_with(pathfrag) && !pathfrag.is_empty() {
            {
                unsafe {
                    let mut ws: FsWriteStats = *entry;
                    if delta < ws.min {
                        ws.min = delta;
                    }
                    if delta > ws.max {
                        ws.max = delta;
                    }
                    ws.total += delta;
                    ws.count += 1;
                    #[allow(static_mut_refs)]
                    bpf_map_update_elem(
                        &raw mut WRITESTATS as *mut c_void,
                        &raw const idx as *const c_void,
                        &raw const ws as *const c_void,
                        0u64,
                    );
                }
            }
        }
    }

    Ok(0)
}

fn ringbuf_put(eventf: &EventFields, op_name: &str, latency: u64, unit: &str) -> Result<u32, u32> {
    let Some(mut dataent) = LDMS_SHARED_STREAM.reserve::<[u8; BUFSIZE]>(0) else {
        return Err(1);
    };
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
            .str("latency")
            .unwrap_unchecked()
            .u64(latency)
            .unwrap_unchecked()
            .str("unit")
            .unwrap_unchecked()
            .str(unit)
            .unwrap_unchecked()
            .str("operation")
            .unwrap_unchecked()
            .str(op_name)
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
