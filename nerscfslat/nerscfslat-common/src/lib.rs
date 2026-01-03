#![no_std]
use aya_ebpf::cty::c_uchar;
use aya_ebpf::bindings::bpf_timer;

pub const PATHFRAGLEN: usize = 32 + 1;
pub const NUM_PATH_PREFIX: u32 = 8;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FsWriteStats {
    pub pathfrag: [c_uchar; PATHFRAGLEN],
    pub fraglen: usize,
    pub min: u64,
    pub max: u64,
    pub total: u64,
    pub count: u64,
    pub timer: bpf_timer,
}

#[repr(C)]
pub struct EntryRec {
    pub timestamp: u64,
    pub pathfrag: [c_uchar; PATHFRAGLEN],
    pub fraglen: usize,
}
