#![no_std]
use core::mem::offset_of;

use aya_ebpf::{
    EbpfContext,
    bindings::bpf_dynptr,
    cty::{c_uchar, c_void},
    helpers::{
        bpf_dynptr_from_mem, bpf_dynptr_write, bpf_get_current_task_btf, bpf_ktime_get_ns,
        bpf_loop, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes, bpf_spin_lock,
        bpf_spin_unlock,
    },
    programs::{FEntryContext, FExitContext},
};
use aya_log_ebpf::{debug, error, trace};
use bare_metal_modulo::{MNum, ModNumC};
use minicbor::Encoder;

mod maps;
#[allow(nonstandard_style)]
#[allow(unnecessary_transmutes)]
#[allow(unsafe_op_in_unsafe_fn)]
#[allow(dead_code)]
mod vmlinux;
use crate::maps::*;
mod constants;
use crate::constants::*;

pub fn try_fslat_entry(ctx: FEntryContext, _filpop: &str, file_arg_idx: usize) -> Result<u32, u32> {
    let now = unsafe { bpf_ktime_get_ns() };
    let filp: *mut vmlinux::file = ctx.arg(file_arg_idx);
    let pathptr = unsafe { &raw mut (*filp).f_path };
    let Some(pathbuf_ptr) = PATHBUF.get_ptr_mut(0) else {
        return Err(1);
    };
    let mut ret = partial_d_path(&ctx, pathptr as *const vmlinux::path, pathbuf_ptr);
    if ret < 0 {
        return Err(1);
    }
    {
        let entryrec = EntryRec {
            timestamp: now,
            path: unsafe { *pathbuf_ptr },
        };
        let _ = PTRLIST.insert(&(ctx.pid(), ctx.tgid()), &entryrec, 0u64);
    }
    ret = ret.clamp(0, PATHFRAGLEN as i32);
    trace!(ctx, "partial_path: {}", unsafe {
        core::str::from_utf8_unchecked(&(*pathbuf_ptr).get_unchecked(..ret as usize))
    });
    Ok(0)
}

pub fn starts_with(needle: &[u8], haystack: &[u8], len: usize) -> bool {
    if len == 0 || len > haystack.len() {
        return false;
    }
    for i in 0..len.clamp(1, PATHFRAGLEN) {
        if haystack[i] != needle[i] {
            return false;
        }
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

    // struct path { struct dentry *dentry }
    let dentry = unsafe { (*path).dentry as *mut vmlinux::dentry };
    // struct path { struct vfsmount *mnt }
    let vfsmount_ptr = unsafe { (*path).mnt as *const vmlinux::vfsmount };
    // container_of(vfsmount_ptr, mount, mnt)
    // find the address of the struct mount that contains struct vfsmount at address vfsmount_ptr
    let mnt =
        unsafe { vfsmount_ptr.byte_sub(offset_of!(vmlinux::mount, mnt)) as *const vmlinux::mount };

    let current = unsafe { bpf_get_current_task_btf() as *const vmlinux::task_struct };
    let root_vfsmount = unsafe { (*(*current).fs).root.mnt as *const vmlinux::vfsmount };
    let root_dentry = unsafe { (*(*current).fs).root.dentry as *mut vmlinux::dentry };

    let mut walk_ctx = PathWalkCtx {
        dentry,
        mnt,
        loop_ctr: 0,
        mod_ctr: ModNumC::new(0),
        root_dentry,
        root_vfsmount,
        is_absolute: false,
        ctx,
    };
    unsafe {
        bpf_loop(
            MAX_PARENT_LOOP,
            path_walk_step as *mut c_void,
            &mut walk_ctx as *mut PathWalkCtx as *mut c_void,
            0u64,
        );
    }

    let mut assem_ctx = AssembleCtx {
        // walk_ctx.mod_ctr points to the next buffer element to be filled
        // by path_walk_step
        start: walk_ctx.mod_ctr - 1,
        copied: 0,
        num_components: NUM_COMP.min(walk_ctx.loop_ctr),
        pathfrag_dynptr: &mut pathfrag_dynptr as *mut bpf_dynptr,
        is_absolute: walk_ctx.is_absolute,
        ctx,
    };
    unsafe {
        // If we have an absolute pathname
        // prepend a / to the path
        if assem_ctx.is_absolute {
            bpf_dynptr_write(
                assem_ctx.pathfrag_dynptr as *const bpf_dynptr,
                0u32,
                &b'/' as *const u8 as *mut c_void,
                1u32,
                0u64,
            );
            assem_ctx.copied = 1;
        }
        bpf_loop(
            NUM_COMP.min(assem_ctx.num_components),
            assemble_pathfrag as *mut c_void,
            &mut assem_ctx as *mut AssembleCtx as *mut c_void,
            0_u64,
        );
    }
    assem_ctx.copied as i32
}

extern "C" fn path_walk_step(_index: u32, ctx: *mut PathWalkCtx) -> u64 {
    unsafe {
        let dentry = (*ctx).dentry;
        let mnt = (*ctx).mnt;
        // fs/d_path.c: const struct dentry *parent = READ_ONCE(dentry->d_parent)
        let parent =
            bpf_probe_read_kernel(&raw const (*dentry).d_parent as *const *mut vmlinux::dentry)
                .unwrap_unchecked();
        // &mnt->mnt: the embedded struct vfsmount within struct mount
        let vfsmount = &raw const (*mnt).mnt as *const vmlinux::vfsmount;
        // mnt->mnt.mnt_root: the root dentry of the current mount
        let mnt_root =
            bpf_probe_read_kernel(&raw const (*vfsmount).mnt_root as *const *mut vmlinux::dentry)
                .unwrap_unchecked();
        // fs/d_path.c: while (dentry != root->dentry || &mnt->mnt != root->mnt) {
        if dentry == (*ctx).root_dentry && vfsmount == (*ctx).root_vfsmount {
            // We reached the process root directory
            (*ctx).is_absolute = true;
            return 1;
        }
        // fs/d_path.c: if (dentry == mnt->mnt.mnt_root) {
        if dentry == mnt_root {
            // fs/d_path.c: struct mount *m = READ_ONCE(mnt->mnt_parent)
            let parent_mnt =
                bpf_probe_read_kernel(&raw const (*mnt).mnt_parent as *const *const vmlinux::mount)
                    .unwrap_unchecked();
            if mnt != parent_mnt {
                // fs/d_path.c: dentry = READ_ONCE(mnt->mnt_mountpoint)
                (*ctx).dentry = bpf_probe_read_kernel(
                    &raw const (*mnt).mnt_mountpoint as *const *mut vmlinux::dentry,
                )
                .unwrap_unchecked();
                // fs/d_path.c: mnt = m
                (*ctx).mnt = parent_mnt;
                return 0;
            }
        }
        // fs/d_path.c: if (unlikely(dentry == parent))
        if dentry == parent {
            (*ctx).is_absolute = true;
            return 1;
        }
        let name_ptr =
            bpf_probe_read_kernel(&raw const (*dentry).d_name.name as *const *const c_uchar)
                .unwrap_unchecked();
        let Some(comp) = PATHBUFTMP.get_ptr_mut((*ctx).mod_ctr.a()) else {
            return 1;
        };
        // Copy dentry->d_name.name to path components ringbuffer PATHBUFTMP.
        let name = bpf_probe_read_kernel_str_bytes(name_ptr, &mut (*comp).pathcomp as &mut [u8])
            .unwrap_unchecked();
        (*comp).len = name.len();
        (*ctx).dentry = parent;
        (*ctx).loop_ctr += 1;
        (*ctx).mod_ctr += 1;
        if (*ctx).loop_ctr > MAX_PARENT {
            return 1;
        }
    }
    0
}

extern "C" fn assemble_pathfrag(index: u32, ctx: *mut AssembleCtx) -> u64 {
    // index into PATHBUFTMP ring buffer starting at the last path component written, which is
    // closest to the root
    let idx = unsafe { (*ctx).start } - index;
    let Some(buf_elem) = PATHBUFTMP.get(idx.a()) else {
        unsafe { debug!((*ctx).ctx, "bad index into PATHBUFTMP") };
        return 1;
    };

    let path = &(*buf_elem).pathcomp as *const [u8] as *mut u8;
    let len = buf_elem.len as u32;
    let len = if buf_elem.len > PATHFRAGLEN {
        PATHFRAGLEN as u32
    } else {
        len
    };
    unsafe {
        let copied = (*ctx).copied as u32;
        let remaining = PATHFRAGLEN as u32 - copied;
        if !aya_ebpf::check_bounds_signed(copied as i64, 0i64, PATHFRAGLEN as i64) {
            return 1;
        }
        if !aya_ebpf::check_bounds_signed(remaining as i64, 0i64, PATHFRAGLEN as i64) {
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

        // Match on the penultimate pathname component
        if index < ((*ctx).num_components - 1) {
            bpf_dynptr_write(
                (*ctx).pathfrag_dynptr as *const bpf_dynptr,
                copied + len,
                &b'/' as *const u8 as *mut c_void,
                1u32,
                0u64,
            );
            (*ctx).copied = copied as u32 + remaining.min(len) + 1;
        } else {
            (*ctx).copied = copied as u32 + remaining.min(len);
        }
    }
    0
}

pub fn try_fslat_exit(ctx: FExitContext, filpop: &str, ret: u64) -> Result<u32, u32> {
    let Some(countptr) = COUNTER.get_ptr_mut(0) else {
        return Err(1);
    };
    let pid_tgid = (ctx.pid(), ctx.tgid());

    match unsafe { PTRLIST.get(pid_tgid) } {
        Some(entryrec) => {
            let now = unsafe { bpf_ktime_get_ns() };
            for idx in 0..NUM_PATH_PREFIX {
                #[allow(static_mut_refs)]
                let Some(fsstat) = (unsafe { FSLATENCYSTATS.get_ptr_mut(idx) }) else {
                    return Err(1);
                };
                if unsafe {
                    starts_with(
                        &(*fsstat).path_prefix,
                        &entryrec.path,
                        (*fsstat).pathlen as usize,
                    )
                } {
                    if now - unsafe { (*fsstat).lastpublish } > AGG_INTERVAL {
                        let eventf = EventFields {
                            id: "fslat/v2",
                            monotonic: unsafe { bpf_ktime_get_ns() },
                            seq: unsafe { *countptr },
                            path_prefix: unsafe { &(*fsstat).path_prefix },
                        };

                        if update_stats(fsstat, entryrec.timestamp, now, ret) != 0 {
                            error!(ctx, "update_stats() failed");
                            return Err(1);
                        }
                        let Ok(_) = ringbuf_put(&eventf, fsstat, filpop, "ns") else {
                            error!(ctx, "ringbuf_put() failed");
                            return Err(1);
                        };
                        let Ok(_) = clear_stats(&ctx, fsstat, now) else {
                            error!(ctx, "clear_stats() failed");
                            return Err(1);
                        };
                        unsafe {
                            *countptr += 1;
                        }
                    } else {
                        if update_stats(fsstat, entryrec.timestamp, now, ret) != 0 {
                            error!(ctx, "update_stats() failed");
                            return Err(1);
                        }
                    }
                }
            }
            let _ = PTRLIST.remove(&(pid_tgid));
        }
        None => {}
    };
    Ok(0)
}

pub fn update_stats(fsstat: *mut FsLatencyStats, start: u64, end: u64, bytes: u64) -> u32 {
    unsafe {
        let latency = end - start;
        if latency < (*fsstat).min || (*fsstat).min == 0 {
            (*fsstat).min = latency;
        }
        if latency > (*fsstat).max || (*fsstat).max == 0 {
            (*fsstat).max = latency;
        }
        (*fsstat).count += 1;
        (*fsstat).total_lat += latency;
        (*fsstat).total_bytes += bytes;

        // Compute the net new coverage this interval adds to active_time by subtracting
        // any portion already covered by intervals still in the window.
        let mut contribution: i64 = latency as i64;
        for i in 0..NUM_INTERVAL as usize {
            let iv = (*fsstat).intervals[i];
            if iv.start == 0 && iv.end == 0 {
                continue; // empty slot
            }
            if start <= iv.end && iv.start <= end {
                let overlap_start = start.max(iv.start);
                let overlap_end = end.min(iv.end);
                contribution -= (overlap_end - overlap_start) as i64;
            }
        }
        if contribution > 0 {
            (*fsstat).active_time += contribution as u64;
        }

        // Append interval, evicting the oldest slot when the buffer is full.
        let slot = {(*fsstat).interval_head.a() as usize}.clamp(0, (NUM_INTERVAL-1) as usize);
        bpf_spin_lock(&mut (*fsstat).lock);
        (*fsstat).intervals[slot] = Interval { start, end };
        bpf_spin_unlock(&mut (*fsstat).lock);
        (*fsstat).interval_head += 1;
    }
    0
}

pub fn clear_stats(_ctx: &FExitContext, fsstat: *mut FsLatencyStats, now: u64) -> Result<u32, u32> {
    unsafe {
        (*fsstat).lastpublish = now;
        (*fsstat).count = 0;
        (*fsstat).total_lat = 0;
        (*fsstat).total_bytes = 0;
        (*fsstat).min = u64::MAX;
        (*fsstat).max = u64::MIN;
        (*fsstat).active_time = 0;
        (*fsstat).interval_head = ModNumC::new(0);
    }
    Ok(0)
}

pub fn ringbuf_put(
    eventf: &EventFields,
    fsstat: *mut FsLatencyStats,
    filpop: &str,
    unit: &str,
) -> Result<u32, u32> {
    #[allow(static_mut_refs)]
    let Some(mut dataent) = LDMS_SHARED_STREAM.reserve::<[u8; BUFSIZE]>(0) else {
        return Err(1);
    };

    let EventFields {
        id,
        monotonic,
        seq,
        path_prefix,
    } = *eventf;
    let dataent_bytes: *mut [u8] = dataent.as_mut_ptr();
    let mut encoder = unsafe { Encoder::new(&mut *dataent_bytes) };
    let pathlen = unsafe { (*fsstat).pathlen as usize };
    if !aya_ebpf::check_bounds_signed(pathlen as i64, 1i64, PATHFRAGLEN as i64) {
        dataent.discard(0u64);
        return Err(1);
    }
    unsafe {
        encoder
            .begin_map()
            .unwrap_unchecked()
            .str_noncanonical("id")
            .unwrap_unchecked()
            .str_noncanonical(id)
            .unwrap_unchecked()
            .str_noncanonical("timestamp_monotonic")
            .unwrap_unchecked()
            .u64_noncanonical(monotonic)
            .unwrap_unchecked()
            .str_noncanonical("opname")
            .unwrap_unchecked()
            .str_noncanonical(filpop)
            .unwrap_unchecked()
            .str_noncanonical("sequence")
            .unwrap_unchecked()
            .u64_noncanonical(seq)
            .unwrap_unchecked()
            .str_noncanonical("unit")
            .unwrap_unchecked()
            .str_noncanonical(unit)
            .unwrap_unchecked()
            .str_noncanonical("metrics")
            .unwrap_unchecked()
            .begin_map()
            .unwrap_unchecked()
            .str_noncanonical("min_latency")
            .unwrap_unchecked()
            .u64_noncanonical((*fsstat).min)
            .unwrap_unchecked()
            .str_noncanonical("max_latency")
            .unwrap_unchecked()
            .u64_noncanonical((*fsstat).max)
            .unwrap_unchecked()
            .str_noncanonical("total_latency")
            .unwrap_unchecked()
            .u64_noncanonical((*fsstat).total_lat)
            .unwrap_unchecked()
            .str_noncanonical("total_bytes")
            .unwrap_unchecked()
            .u64_noncanonical((*fsstat).total_bytes)
            .unwrap_unchecked()
            .str_noncanonical("count_samples")
            .unwrap_unchecked()
            .u64_noncanonical((*fsstat).count)
            .unwrap_unchecked()
            .str_noncanonical("active_time")
            .unwrap_unchecked()
            .u64_noncanonical((*fsstat).active_time)
            .unwrap_unchecked()
            .end()
            .unwrap_unchecked()
            .str_noncanonical("path_prefix")
            .unwrap_unchecked()
            .str_noncanonical(core::str::from_utf8_unchecked(
                path_prefix.get_unchecked(..pathlen),
            ))
            .unwrap_unchecked()
            .end()
            .unwrap_unchecked();
    }
    dataent.submit(0);
    Ok(0)
}
