use aya_ebpf::{
    bindings::{bpf_dynptr, bpf_spin_lock},
    btf_maps,
    macros::{btf_map, map},
    maps::{Array, LruHashMap, PerCpuArray, RingBuf},
    programs::FEntryContext,
};
use bare_metal_modulo::ModNumC;

use crate::constants::*;

// Global counter. per ebpf program (nerscfslat_ebpf_close, nerscfslat-ebpf-fsync ...etc)
#[map]
pub static COUNTER: Array<u64> = Array::with_max_entries(1, 0);

// Map per VFS function. One array entry for each prefix that contains prefix itself and collected
// stats
#[btf_map]
pub static mut CLOSE_STATS: btf_maps::Array<FsLatencyStats, { NUM_PATH_PREFIX as usize }, 0> =
    btf_maps::Array::new();
#[btf_map]
pub static mut FSYNC_STATS: btf_maps::Array<FsLatencyStats, { NUM_PATH_PREFIX as usize }, 0> =
    btf_maps::Array::new();
#[btf_map]
pub static mut WRITE_STATS: btf_maps::Array<FsLatencyStats, { NUM_PATH_PREFIX as usize }, 0> =
    btf_maps::Array::new();
#[btf_map]
pub static mut WRITEV_STATS: btf_maps::Array<FsLatencyStats, { NUM_PATH_PREFIX as usize }, 0> =
    btf_maps::Array::new();
#[btf_map]
pub static mut ITER_WRITE_STATS: btf_maps::Array<FsLatencyStats, { NUM_PATH_PREFIX as usize }, 0> =
    btf_maps::Array::new();
#[btf_map]
pub static mut READ_STATS: btf_maps::Array<FsLatencyStats, { NUM_PATH_PREFIX as usize }, 0> =
    btf_maps::Array::new();
#[btf_map]
pub static mut READV_STATS: btf_maps::Array<FsLatencyStats, { NUM_PATH_PREFIX as usize }, 0> =
    btf_maps::Array::new();
#[btf_map]
pub static mut ITER_READ_STATS: btf_maps::Array<FsLatencyStats, { NUM_PATH_PREFIX as usize }, 0> =
    btf_maps::Array::new();

// Used as a scratch area to hold the assembled path constructed by partial_d_path() from struct path
#[map]
pub static PATHBUF: PerCpuArray<PathSlice> = PerCpuArray::with_max_entries(1, 0);

// ring buffer that temporarily holds the last NUM_COMP path components closest to '/',  resolved from struct path
#[map]
pub static PATHBUFTMP: PerCpuArray<PathComponent> = PerCpuArray::with_max_entries(NUM_COMP, 0);

// Map to hold the entry time of function call. indexed by (pid, tgid)
#[map]
pub static PTRLIST: LruHashMap<PidTgid, EntryRec> = LruHashMap::with_max_entries(8192, 0);

#[map]
pub static LDMS_SHARED_STREAM: RingBuf = RingBuf::pinned(1024, 0);

use crate::vmlinux;

pub type PathSlice = [u8; PATHFRAGLEN];
pub type PathCompSlice = [u8; PATHCOMPLEN];
pub type PidTgid = (u32, u32);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PathComponent {
    pub len: usize,
    pub pathcomp: PathCompSlice,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FsLatencyStats {
    pub lock: bpf_spin_lock,
    pub pathlen: u32,
    pub path_prefix: PathSlice,
    pub min: u64,
    pub max: u64,
    pub total_lat: u64,
    pub total_bytes: u64,
    pub count: u64,
    pub lastpublish: u64,
    pub is_frozen: bool,
}

#[repr(C)]
pub struct EntryRec {
    pub timestamp: u64,
    pub path: PathSlice,
}

#[repr(C)]
pub struct EventFields<'a> {
    pub id: &'a str,
    pub monotonic: u64,
    pub seq: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct StatsSnapshot {
    pub pathlen: u32,
    pub path_prefix: PathSlice,
    pub min: u64,
    pub max: u64,
    pub total_lat: u64,
    pub total_bytes: u64,
    pub count: u64,
}

#[repr(C)]
pub struct AssembleCtx<'a> {
    pub start: ModNumC<u32, { NUM_COMP as usize }>,
    pub copied: u32,
    pub num_components: u32,
    pub pathfrag_dynptr: *mut bpf_dynptr,
    pub is_absolute: bool,
    pub ctx: &'a FEntryContext,
}

#[repr(C)]
pub struct PathWalkCtx<'a> {
    pub dentry: *mut vmlinux::dentry,
    pub mnt: *const vmlinux::mount,
    pub loop_ctr: u32,
    pub mod_ctr: ModNumC<u32, { NUM_COMP as usize }>,
    pub root_dentry: *mut vmlinux::dentry,
    pub root_vfsmount: *const vmlinux::vfsmount,
    pub is_absolute: bool,
    pub ctx: &'a FEntryContext,
}
