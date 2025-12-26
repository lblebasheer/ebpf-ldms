#![no_std]
use aya_ebpf::bindings::bpf_spin_lock;

#[repr(C)]
pub struct FsWriteStats {
    pub lock: bpf_spin_lock,
    pub min: u64,
    pub max: u64,
    pub total: u64,
    pub count: u64,
}
