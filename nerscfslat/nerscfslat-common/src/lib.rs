#![no_std]
use core::mem::offset_of;

use aya_ebpf::{
    bindings::bpf_dynptr,
    cty::{c_uchar, c_void},
    helpers::{
        bpf_dynptr_from_mem, bpf_dynptr_write, bpf_get_current_task_btf, bpf_ktime_get_ns,
        bpf_loop, bpf_map_update_elem, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes,
    },
    macros::map,
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::{FEntryContext, FExitContext},
};
use aya_log_ebpf::{debug, error};
use minicbor::Encoder;

const PATHFRAGLEN: usize = 16 + 1;
const PATHCOMPLEN: usize = PATHFRAGLEN;
const NUM_PATH_PREFIX: u32 = 8;
const AGG_INTERVAL: u64 = 1000 * 1000 * 500; // 500ms
const BUFSIZE: usize = 1024;
const NUM_COMP: u32 = 3;
const MAX_PARENT: u32 = 5;
const MAX_PARENT_LOOP: u32 = 10;

#[map]
pub static COUNTER: Array<u64> = Array::with_max_entries(1, 0);

#[map]
pub static mut WRITESTATS: Array<FsWriteStats> = Array::with_max_entries(NUM_PATH_PREFIX, 0);

#[map]
pub static PATHBUF: PerCpuArray<PathSlice> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static PATHBUFTMP: PerCpuArray<PathComponent> = PerCpuArray::with_max_entries(NUM_COMP, 0);

#[map]
pub static PTRLIST: HashMap<usize, EntryRec> = HashMap::with_max_entries(1024, 0);

#[map]
pub static LDMS_SHARED_STREAM: RingBuf = RingBuf::pinned(8192, 0);

#[allow(nonstandard_style)]
#[allow(unnecessary_transmutes)]
#[allow(unsafe_op_in_unsafe_fn)]
#[allow(dead_code)]
mod vmlinux;

type PathSlice = [u8; PATHFRAGLEN];
type PathCompSlice = [u8; PATHCOMPLEN];

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PathComponent {
    pub len: usize,
    pub pathcomp: PathCompSlice,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FsWriteStats {
    pub path_prefix: PathSlice,
    pub min: u64,
    pub max: u64,
    pub total: u64,
    pub count: u64,
    pub lastpublish: u64,
}

#[repr(C)]
pub struct EntryRec {
    pub timestamp: u64,
    pub path: PathSlice,
}

#[repr(C)]
pub struct EventFields<'a> {
    pub id: &'a str,
    pub version: &'a str,
    pub monotonic: u64,
    pub seq: u64,
    pub path_prefix: &'a [u8],
}

#[repr(C)]
struct AssembleCtx<'a> {
    start: u32,
    copied: u32,
    pathfrag_dynptr: *mut bpf_dynptr,
    ctx: &'a FEntryContext,
}

pub fn try_fslat_entry(ctx: FEntryContext, _filpop: &str) -> Result<u32, u32> {
    let now = unsafe { bpf_ktime_get_ns() };
    let filp: *mut vmlinux::file = ctx.arg(0);
    let pathptr = unsafe { &raw mut (*filp).f_path };
    let Some(pathbuf_ptr) = PATHBUF.get_ptr_mut(0) else {
        return Err(1);
    };
    let ret = partial_d_path(&ctx, pathptr as *const vmlinux::path, pathbuf_ptr);
    if ret < 0 {
        return Err(1);
    }
    {
        let entryrec = EntryRec {
            timestamp: now,
            path: unsafe { *pathbuf_ptr },
        };
        let _ = PTRLIST.insert(&(filp as usize), &entryrec, 0u64);
    }
    debug!(ctx, "assemComp {}", unsafe {
        core::str::from_utf8_unchecked(&*pathbuf_ptr)
    });
    Ok(0)
}

fn find_null_pos(haystack: &[u8], maxlen: usize) -> usize {
    let mut idx = 0;
    for i in 0..maxlen {
        if haystack[i] == 0 {
            idx = i;
            break;
        }
    }
    idx
}

pub fn starts_with(needle: &[u8], haystack: &[u8], len: usize) -> bool {
    if needle[0] == 0 {
        return false;
    }
    let mut i = 0;
    let mut j = 0;
    while i < len {
        if haystack[j] != needle[i] {
            return false;
        }
        i += 1;
        j += 1;
    }
    true
}

pub fn partial_d_path(
    ctx: &FEntryContext,
    path: *const vmlinux::path,
    pathfrag: *mut PathSlice,
) -> i32 {
    let mut pathfrag_dynptr = bpf_dynptr {
        __opaque: [0u64; 2],
    };
    unsafe {
        bpf_dynptr_from_mem(
            pathfrag as *mut c_void,
            PATHFRAGLEN as u32,
            0,
            &mut pathfrag_dynptr,
        );
    }

    let mut assem_ctx = AssembleCtx {
        start: 0,
        copied: 0,
        pathfrag_dynptr: &mut pathfrag_dynptr as *mut bpf_dynptr,
        ctx,
    };
    // struct path { struct dentry *dentry }
    let mut dentry_ptr = unsafe {
        bpf_probe_read_kernel(&raw const (*path).dentry as *const *mut vmlinux::dentry)
            .unwrap_unchecked()
    };
    // struct path { struct vfsmount *mnt }
    let vfsmount_ptr = unsafe {
        bpf_probe_read_kernel(&raw const (*path).mnt as *const *const vmlinux::vfsmount)
            .unwrap_unchecked()
    };
    // container_of(vfsmount_ptr, mount, mnt)
    // find the address of the struct mount that contains struct vfsmount at address vfsmount_ptr
    let mut mnt_ptr =
        unsafe { vfsmount_ptr.sub(offset_of!(vmlinux::mount, mnt)) as *const vmlinux::mount };

    let current = unsafe { bpf_get_current_task_btf() as *const vmlinux::task_struct };
    let root_path_mnt_ptr = unsafe {
        bpf_probe_read_kernel(
            &raw const (*(*current).fs).root.mnt as *const *const vmlinux::vfsmount,
        )
        .unwrap_unchecked()
    };
    let root_path_dentry_ptr = unsafe {
        bpf_probe_read_kernel(
            &raw const (*(*current).fs).root.dentry as *const *mut vmlinux::dentry,
        )
        .unwrap_unchecked()
    };

    let mut pathidx = 0;
    for _i in 0..MAX_PARENT_LOOP {
        if pathidx > MAX_PARENT {
            break;
        }
        // fs/d_path.c: const struct dentry *parent = READ_ONCE(dentry->d_parent)
        let dentry_d_parent_ptr = unsafe {
            bpf_probe_read_kernel(&raw const (*dentry_ptr).d_parent as *const *mut vmlinux::dentry)
                .unwrap_unchecked()
        };
        // Update all the pointers that are derived from mnt_ptr
        let mnt_mnt_ptr = unsafe { &raw const (*mnt_ptr).mnt as *const vmlinux::vfsmount };
        // struct mount { struct vfsmount mnt { struct dentry *mnt_root } }
        let mnt_mnt_mnt_root_ptr = unsafe {
            bpf_probe_read_kernel(&raw const (*mnt_mnt_ptr).mnt_root as *const *mut vmlinux::dentry)
                .unwrap_unchecked()
        };
        // fs/d_path.c: while (dentry != root->dentry || &mnt->mnt != root->mnt) {
        if dentry_ptr == root_path_dentry_ptr && mnt_mnt_ptr == root_path_mnt_ptr {
            break;
        }
        unsafe {
            // fs/d_path.c: if (dentry == mnt->mnt.mnt_root) {
            if dentry_ptr == mnt_mnt_mnt_root_ptr {
                // fs/d_path.c: struct mount *m = READ_ONCE(mnt->mnt_parent)
                let m = bpf_probe_read_kernel(
                    &raw const (*mnt_ptr).mnt_parent as *const *const vmlinux::mount,
                )
                .unwrap_unchecked();
                if mnt_ptr != m {
                    // struct mount { struct dentry *mnt_mountpoint }
                    // fs/d_path.c: dentry = READ_ONCE(mnt->mnt_mountpoint)
                    dentry_ptr = bpf_probe_read_kernel(
                        &raw const (*mnt_ptr).mnt_mountpoint as *const *mut vmlinux::dentry,
                    )
                    .unwrap_unchecked();
                    // fs/d_path.c: mnt = m
                    mnt_ptr = m;
                    continue;
                }
            }
            // fs/d_path.c: if (unlikely(dentry == parent))
            if dentry_ptr == dentry_d_parent_ptr {
                break;
            }
            let dentry_d_name = bpf_probe_read_kernel(
                &raw const (*dentry_ptr).d_name.name as *const *const c_uchar,
            )
            .unwrap_unchecked();
            let Some(buf_elem) = PATHBUFTMP.get_ptr_mut(pathidx % NUM_COMP) else {
                return -1;
            };
            let d_name = bpf_probe_read_kernel_str_bytes(
                dentry_d_name,
                &mut (*buf_elem).pathcomp as &mut [u8],
            )
            .unwrap_unchecked();
            (*buf_elem).len = d_name.len();
            assem_ctx.start = (pathidx % NUM_COMP) as u32;
            pathidx += 1;
            debug!(ctx, "path: {}", core::str::from_utf8_unchecked(d_name));
            dentry_ptr = dentry_d_parent_ptr;
        }
    }
    unsafe {
        bpf_loop(
            NUM_COMP,
            assemble_pathfrag as *mut c_void,
            &mut assem_ctx as *mut AssembleCtx as *mut c_void,
            0_u64,
        );
        bpf_dynptr_write(
            &pathfrag_dynptr as *const bpf_dynptr,
            assem_ctx.copied,
            &0u8 as *const u8 as *mut c_void,
            1u32,
            0u64,
        );
    }
    assem_ctx.copied as i32
}

extern "C" fn assemble_pathfrag(index: u32, ctx: *mut AssembleCtx) -> u64 {
    let idx = unsafe { ((*ctx).start - index) % NUM_COMP };
    let Some(buf_elem) = PATHBUFTMP.get(idx) else {
        unsafe { debug!((*ctx).ctx, "bad index into PATHBUFTMP") };
        return 1;
    };

    let path = &(*buf_elem).pathcomp as *const [u8] as *mut u8;
    let len = buf_elem.len as u32;
    if !aya_ebpf::check_bounds_signed(len as i64, 1i64, (PATHFRAGLEN - 1) as i64) {
        return 1;
    }
    unsafe {
        let copied = (*ctx).copied as u32;
        let remaining = PATHFRAGLEN as u32 - copied - 1;
        if !aya_ebpf::check_bounds_signed(copied as i64, 0i64, (PATHFRAGLEN - 1) as i64) {
            return 1;
        }
        if !aya_ebpf::check_bounds_signed(remaining as i64, 0i64, (PATHFRAGLEN - 1) as i64) {
            return 1;
        }
        if 0 > bpf_dynptr_write(
            (*ctx).pathfrag_dynptr as *const bpf_dynptr,
            copied,
            path as *mut c_void,
            remaining.min(len),
            0u64,
        ) {
            return 1;
        }

        (*ctx).copied = copied as u32 + remaining.min(len);
    }
    0
}

pub fn try_fslat_exit(ctx: FExitContext, filpop: &str) -> Result<u32, u32> {
    let filp: *const vmlinux::file = ctx.arg(0);
    let Some(countptr) = COUNTER.get_ptr_mut(0) else {
        return Err(1);
    };

    match unsafe { PTRLIST.get(filp as usize) } {
        Some(entryrec) => {
            let now = unsafe { bpf_ktime_get_ns() };
            let delta = now - entryrec.timestamp;
            for idx in 0..NUM_PATH_PREFIX {
                #[allow(static_mut_refs)]
                let Some(fsstat) = (unsafe { WRITESTATS.get_ptr_mut(idx) }) else {
                    return Err(1);
                };
                let path_prefix_len = unsafe { find_null_pos(&(*fsstat).path_prefix, PATHFRAGLEN) };
                if unsafe { starts_with(&(*fsstat).path_prefix, &entryrec.path, path_prefix_len) } {
                    if now - unsafe { (*fsstat).lastpublish } > AGG_INTERVAL {
                        let eventf = EventFields {
                            id: "fslat",
                            version: "v1",
                            monotonic: unsafe { bpf_ktime_get_ns() },
                            seq: unsafe { *countptr },
                            path_prefix: unsafe { &(*fsstat).path_prefix },
                        };

                        let Ok(_) = update_stats(&ctx, idx, fsstat, delta) else {
                            error!(ctx, "update_stats() failed");
                            return Err(1);
                        };
                        let Ok(_) = ringbuf_put(&eventf, fsstat, filpop, "ns") else {
                            error!(ctx, "ringbuf_put() failed");
                            return Err(1);
                        };
                        let Ok(_) = clear_stats(&ctx, idx, fsstat, now) else {
                            error!(ctx, "clear_stats() failed");
                            return Err(1);
                        };
                        unsafe {
                            *countptr += 1;
                        }
                    } else {
                        let Ok(_) = update_stats(&ctx, idx, fsstat, delta) else {
                            error!(ctx, "update_stats() failed");
                            return Err(1);
                        };
                    }
                }
                let _ = PTRLIST.remove(&(filp as usize));
            }
        }
        None => {}
    };
    Ok(0)
}

pub fn update_stats(
    _ctx: &FExitContext,
    idx: u32,
    fsstat: *mut FsWriteStats,
    latency: u64,
) -> Result<u32, u32> {
    unsafe {
        #[allow(static_mut_refs)]
        let mut ws: FsWriteStats = *fsstat;
        if latency < ws.min {
            ws.min = latency;
        }
        if latency > ws.max {
            ws.max = latency;
        }
        ws.count += 1;
        ws.total += latency;

        #[allow(static_mut_refs)]
        bpf_map_update_elem(
            &raw mut WRITESTATS as *mut c_void,
            &raw const idx as *const c_void,
            &raw const ws as *const c_void,
            0u64,
        );
    }
    Ok(0)
}

pub fn clear_stats(
    _ctx: &FExitContext,
    idx: u32,
    fsstat: *mut FsWriteStats,
    now: u64,
) -> Result<u32, u32> {
    unsafe {
        #[allow(static_mut_refs)]
        let mut ws: FsWriteStats = *fsstat;
        ws.lastpublish = now;
        ws.count = 0;
        ws.total = 0;
        ws.min = u64::MAX;
        ws.max = u64::MIN;
        #[allow(static_mut_refs)]
        bpf_map_update_elem(
            &raw mut WRITESTATS as *mut c_void,
            &raw const idx as *const c_void,
            &raw const ws as *const c_void,
            0u64,
        );
    }
    Ok(0)
}

pub fn ringbuf_put(
    eventf: &EventFields,
    fsstat: *mut FsWriteStats,
    filpop: &str,
    unit: &str,
) -> Result<u32, u32> {
    #[allow(static_mut_refs)]
    let Some(mut dataent) = LDMS_SHARED_STREAM.reserve::<[u8; BUFSIZE]>(0) else {
        return Err(1);
    };

    let EventFields {
        id,
        version,
        monotonic,
        seq,
        path_prefix,
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
            .str("opname")
            .unwrap_unchecked()
            .str(filpop)
            .unwrap_unchecked()
            .str("sequence")
            .unwrap_unchecked()
            .u64(seq)
            .unwrap_unchecked()
            .str("min_latency")
            .unwrap_unchecked()
            .u64((*fsstat).min)
            .unwrap_unchecked()
            .str("max_latency")
            .unwrap_unchecked()
            .u64((*fsstat).max)
            .unwrap_unchecked()
            .str("total_latency")
            .unwrap_unchecked()
            .u64((*fsstat).total)
            .unwrap_unchecked()
            .str("count_samples")
            .unwrap_unchecked()
            .u64((*fsstat).count)
            .unwrap_unchecked()
            .str("interval")
            .unwrap_unchecked()
            .u64(AGG_INTERVAL)
            .unwrap_unchecked()
            .str("unit")
            .unwrap_unchecked()
            .str(unit)
            .unwrap_unchecked()
            .str("path_prefix")
            .unwrap_unchecked()
            .str(core::str::from_utf8_unchecked(
                path_prefix
                    .split_at_unchecked(find_null_pos(path_prefix, PATHFRAGLEN))
                    .0,
            ))
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
