#![no_std]
use aya_ebpf::cty::c_uchar;

pub const PATHFRAGLEN: usize = 16 + 1;
pub const NUM_PATH_PREFIX: u32 = 8;
pub const AGG_INTERVAL: u64 = 1000 * 1000 * 500; // 500ms

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FsWriteStats {
    pub pathfrag: [c_uchar; PATHFRAGLEN],
    pub fraglen: usize,
    pub min: u64,
    pub max: u64,
    pub total: u64,
    pub count: u64,
    pub lastpublish: u64,
}

#[repr(C)]
pub struct EntryRec {
    pub timestamp: u64,
    pub pathfrag: [c_uchar; PATHFRAGLEN],
    pub fraglen: usize,
}

pub struct EventFields<'a> {
    pub id: &'a str,
    pub version: &'a str,
    pub monotonic: u64,
    pub seq: u64,
}
