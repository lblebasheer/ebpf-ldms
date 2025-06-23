#![no_std]
#![no_main]

use aya_ebpf::{maps::RingBuf,macros::map};

#[map]
static LDMS_SHARED_STREAM: RingBuf = RingBuf::pinned(1024, 0);

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
