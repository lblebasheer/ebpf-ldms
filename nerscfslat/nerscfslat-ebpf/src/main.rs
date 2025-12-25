#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::{fentry, fexit, map},
    maps::{Array, HashMap, RingBuf},
    programs::{FEntryContext, FExitContext},
};
use minicbor::Encoder;

#[allow(nonstandard_style)]
#[allow(unnecessary_transmutes)]
#[allow(unsafe_op_in_unsafe_fn)]
#[allow(dead_code)]
mod vmlinux;

const BUFSIZE: usize = 1024;

#[map]
static COUNTER: Array<u64> = Array::with_max_entries(1, 0);

#[map]
static PTRLIST: HashMap<usize, u64> = HashMap::with_max_entries(1024, 0);

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
    let filp: *const vmlinux::file = ctx.arg(0);
    let _ = PTRLIST.insert(&(filp as usize), &now, 0u64);
    Ok(0)
}

fn try_fslat_exit(ctx: FExitContext) -> Result<u32, u32> {
    let filp: *const vmlinux::file = ctx.arg(0);
    let now = unsafe { bpf_ktime_get_ns() };
    let Some(countptr) = COUNTER.get_ptr_mut(0) else {
        return Err(1);
    };

    match unsafe { PTRLIST.get(filp as usize) } {
        Some(nsecs) => {
            let delta = now - nsecs;
            if delta > 10 {
                let Some(mut dataent) = LDMS_SHARED_STREAM.reserve::<[u8; BUFSIZE]>(0) else {
                    return Err(1);
                };
                let dataent_bytes: *mut [u8] = dataent.as_mut_ptr();
                let mut encoder = unsafe { Encoder::new(&mut *dataent_bytes) };
                unsafe {
                    encoder
                          .begin_map()
                          .unwrap_unchecked()
                          .str("id")
                          .unwrap_unchecked()
                          .str("fslat")
                          .unwrap_unchecked()
                          .str("version")
                          .unwrap_unchecked()
                          .str("v1")
                          .unwrap_unchecked()
                          .str("timestamp_monotonic")
                          .unwrap_unchecked()
                          .u64(now)
                          .unwrap_unchecked()
                          .str("metrics")
                          .unwrap_unchecked()
                              .begin_array()
                              .unwrap_unchecked()
                                  .begin_map()
                                  .unwrap_unchecked()
                                      .str("sequence")
                                      .unwrap_unchecked()
                                      .u64(*countptr)
                                      .unwrap_unchecked()
                                      .str("latency")
                                      .unwrap_unchecked()
                                      .u64(delta)
                                      .unwrap_unchecked()
                                  .end()
                                  .unwrap_unchecked()
                              .end()
                              .unwrap_unchecked()
                          .end()
                          .unwrap_unchecked();
                }
                dataent.submit(0);
                let _ = PTRLIST.remove(&(filp as usize));
            }
        unsafe { *countptr += 1; }
        }
        None => {},
    };
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
