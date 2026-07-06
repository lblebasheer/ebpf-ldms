#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{fentry, fexit},
    programs::{FEntryContext, FExitContext},
};
use vfslatency_common::{
    maps::{CLOSE_STATS, FSYNC_STATS, READ_STATS, READV_STATS, WRITE_STATS, WRITEV_STATS, KREAD_STATS, KWRITE_STATS},
    try_fslat_entry, try_fslat_exit,
};

macro_rules! fslat_probe {
    ($entry:ident, $exit:ident, $fn:literal, $exit_arg:expr, $map:ident) => {
        #[fentry(function = $fn)]
        pub fn $entry(ctx: FEntryContext) -> u32 {
            match try_fslat_entry(ctx, $fn) {
                Ok(r) => r,
                Err(r) => r,
            }
        }
        #[fexit(function = $fn)]
        pub fn $exit(ctx: FExitContext) -> u32 {
            let ret = ctx.arg($exit_arg);
            let map = unsafe { &*(&raw mut $map as *const _) };
            match try_fslat_exit(ctx, $fn, ret, map) {
                Ok(r) => r,
                Err(r) => r,
            }
        }
    };
}

fslat_probe!(
    filp_close_entry,
    filp_close_exit,
    "filp_close",
    2,
    CLOSE_STATS
);
fslat_probe!(
    vfs_fsync_range_entry,
    vfs_fsync_range_exit,
    "vfs_fsync_range",
    4,
    FSYNC_STATS
);
fslat_probe!(vfs_write_entry, vfs_write_exit, "vfs_write", 4, WRITE_STATS);
fslat_probe!(
    vfs_writev_entry,
    vfs_writev_exit,
    "vfs_writev",
    5,
    WRITEV_STATS
);
fslat_probe!(vfs_read_entry, vfs_read_exit, "vfs_read", 4, READ_STATS);
fslat_probe!(vfs_readv_entry, vfs_readv_exit, "vfs_readv", 5, READV_STATS);
fslat_probe!(kernel_read_entry, kernel_read_exit, "kernel_read", 4, KREAD_STATS);
fslat_probe!(kernel_write_entry, kernel_write_exit, "kernel_write", 4, KWRITE_STATS);

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual BSD/GPL\0";
