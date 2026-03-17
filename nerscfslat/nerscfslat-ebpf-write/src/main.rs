#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{fentry, fexit},
    programs::{FEntryContext, FExitContext},
};
use nerscfslat_common::{try_fslat_entry, try_fslat_exit};

#[fentry(function = "vfs_write")]
pub fn vfs_write_entry(ctx: FEntryContext) -> u32 {
    match try_fslat_entry(ctx, "vfs_write", 0) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[fexit(function = "vfs_write")]
pub fn vfs_write_exit(ctx: FExitContext) -> u32 {
    match try_fslat_exit(ctx, "vfs_write") {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
