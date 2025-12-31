#![no_std]
use aya_ebpf::{bindings::bpf_spin_lock, cty::c_uchar};

pub const PATHFRAGLEN: usize = 32 + 1;
pub const NUM_PATH_PREFIX: u32 = 8;

#[repr(C)]
pub struct FsWriteStats {
    pub lock: bpf_spin_lock,
    pub pathfrag: [c_uchar; PATHFRAGLEN],
    pub fraglen: usize,
    pub min: u64,
    pub max: u64,
    pub total: u64,
    pub count: u64,
}
