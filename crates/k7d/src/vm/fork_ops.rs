//! Fork-source preparation, keyframes, the accumulated dirty bitmap
//! and warm-fork entry points of [`Vm`].
//!
//! Moved out of `vm/mod.rs` verbatim so the machine core can be counted
//! apart from the live-fork engine (`utils/loc.py`).

use super::{
    clear_dirty_log, clip_extent, seek_memfd, AsRawFd, GuestMemory, Path, PathBuf, PreparedBase,
    Vm, VmError,
};

impl Vm {
    /// Prepare this VM as a fork source.
    ///
    /// Performs the **one-time** cold snapshot + restore + dirty-tracking-enable
    /// sequence described in part 1. After this call, the VM is "fork-ready":
    /// subsequent `fork_warm()` calls only copy the pages dirtied since this point.
    ///
    /// Returns the path to the `base.mem` file that all future warm forks will use
    /// as their `MAP_PRIVATE` backing. The directory is owned by this `Vm` and
    /// cleaned up on Drop.
    ///
    /// Note: the caller **must** reconnect the agent after this call because the
    /// source VM is replaced by a restored one (fresh vsock backend; existing
    /// connections die). The CID itself is **preserved** so
    /// cached-CID clients — the pod's shim — keep working by redialing.
    pub fn prepare_fork_source(&mut self) -> Result<PathBuf, crate::fork::ForkError> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static FORK_SRC_COUNTER: AtomicU64 = AtomicU64::new(0);
        let seq = FORK_SRC_COUNTER.fetch_add(1, Ordering::SeqCst);
        let base_dir =
            std::env::temp_dir().join(format!("k7d-fork-src-{}-{seq}", std::process::id()));
        std::fs::create_dir_all(&base_dir)?;
        let base_mem = self.prepare_fork_source_in(&base_dir)?;
        // The tempdir is owned by this VM — clean up on Drop.
        self.fork_source_dir = Some(base_dir);
        Ok(base_mem)
    }

    /// Explicitly allow this virtiofs-backed VM to be prepared as a
    /// **slow** fork source.
    ///
    /// VMs with virtiofs shares cannot take the `CoW`
    /// (`MAP_PRIVATE(base.mem)` + dirty-delta) fast-fork path — every
    /// fork is a full memfd copy of guest RAM. `prepare_fork_source*`
    /// refuses such VMs loudly by default so nothing degrades
    /// silently; callers that knowingly accept full-copy forks (the
    /// daemon's virtiofs sandbox pods, the cluster-adopt path)
    /// call this first. No-op for share-less VMs.
    pub fn allow_slow_fork(&mut self) {
        if !self.virtiofs_shares.is_empty() {
            log::warn!(
                "allow_slow_fork: VM (cid {}) has {} virtiofs share(s) — forks will be \
                 full-memfd copies, not CoW (slow path, explicitly opted in)",
                self.guest_cid,
                self.virtiofs_shares.len()
            );
        }
        self.slow_fork_allowed = true;
    }

    /// Like `prepare_fork_source`, but writes the base snapshot into
    /// `base_dir` (caller owns the directory) instead of a private tempdir.
    /// Used by the snapshot tree, which manages per-node directories itself.
    pub fn prepare_fork_source_in(
        &mut self,
        base_dir: &Path,
    ) -> Result<PathBuf, crate::fork::ForkError> {
        self.check_fork_source_allowed()?;
        std::fs::create_dir_all(base_dir)?;

        self.snapshot(base_dir)
            .map_err(crate::fork::ForkError::Snapshot)?;
        // `snapshot` already wrote every page. Count a miss so the 200 ms
        // question has data; do not refuse — a full dump is what ran.
        let _ = self.take_full_dump_if_not_quiescent();
        self.restore_swap_onto_base(base_dir)
    }

    /// Forkability validation: virtiofs shares force every fork onto the
    /// slow full-memfd path (vhost-user needs fd-backed shared memory).
    /// That trade must be taken knowingly ([`Self::allow_slow_fork`]),
    /// never inherited silently.
    pub(crate) fn check_fork_source_allowed(&self) -> Result<(), crate::fork::ForkError> {
        if !self.virtiofs_shares.is_empty() && !self.slow_fork_allowed {
            return Err(crate::fork::ForkError::VirtiofsSlowForkNotAllowed {
                shares: self.virtiofs_shares.len(),
            });
        }
        Ok(())
    }

    /// Like [`Self::prepare_fork_source_in`], but write the keyframe
    /// **incrementally** against `ancestor_mem`: `FICLONE`
    /// the ancestor's `memory.bin` and overwrite only the pages this VM
    /// has dirtied since it was materialized from that very file, so a
    /// fork point down the tree costs O(divergence) instead of O(guest
    /// RAM).
    ///
    /// The caller must guarantee that this VM's memory *is* `ancestor_mem`
    /// plus its accumulated dirty set — true for a warm-fork child of the
    /// node that owns `ancestor_mem`, and for a resumed node whose applied
    /// `delta.pack` was re-seeded into the bitmap (CHALLENGES #143). The
    /// snapshot tree is the only caller and derives `ancestor_mem` from
    /// `nearest_checkpoint`.
    ///
    /// Falls back to a full dump — loudly, never silently — when the VM
    /// has virtiofs shares, when dirty tracking is off, or when the two
    /// paths are not on one reflink filesystem (`EXDEV` / `EOPNOTSUPP`).
    /// [`PreparedBase::incremental`] says which path ran.
    pub fn prepare_fork_source_incremental_in(
        &mut self,
        base_dir: &Path,
        ancestor_mem: &Path,
    ) -> Result<PreparedBase, crate::fork::ForkError> {
        std::fs::create_dir_all(base_dir)?;
        let was_running = self.is_running();
        if was_running {
            self.pause().map_err(crate::snapshot::SnapshotError::Vm)?;
        }
        let (incremental, disk_bytes) =
            match self.write_keyframe_paused(base_dir, Some(ancestor_mem)) {
                Ok(written) => written,
                Err(e) => {
                    if was_running {
                        self.resume().map_err(crate::snapshot::SnapshotError::Vm)?;
                    }
                    return Err(e);
                }
            };
        let t_swap = std::time::Instant::now();
        let base_mem = self.restore_swap_onto_base(base_dir)?;
        if was_running && self.paused() {
            self.resume().map_err(crate::snapshot::SnapshotError::Vm)?;
        }
        log::info!(
            "prepare_fork_source_incremental_in: restore-swap took {:?}",
            t_swap.elapsed()
        );
        Ok(PreparedBase {
            base_mem,
            incremental,
            disk_bytes,
        })
    }

    /// Write this **paused** VM's keyframe into `base_dir` without
    /// swapping onto it: incrementally against `ancestor_mem` when given
    /// (see [`Self::prepare_fork_source_incremental_in`] for the
    /// contract), else as a full dump. Returns `(incremental,
    /// disk_bytes)`. Every fallback to a full dump is logged and runs
    /// under the same pause.
    pub(crate) fn write_keyframe_paused(
        &mut self,
        base_dir: &Path,
        ancestor_mem: Option<&Path>,
    ) -> Result<(bool, u64), crate::fork::ForkError> {
        let missed_park = self.take_full_dump_if_not_quiescent();
        let Some(ancestor_mem) = ancestor_mem else {
            return self.write_full_keyframe_paused(base_dir);
        };
        if !self.virtiofs_shares.is_empty() {
            // Keep-live sources never take the CoW fork path at all
            // (CHALLENGES #39) and virtiofsd's FUSE DMA is invisible to
            // the bitmap, so an incremental keyframe would be incomplete.
            log::warn!(
                "write_keyframe_paused: VM (cid {}) has {} virtiofs share(s) — \
                 writing a full keyframe instead",
                self.guest_cid,
                self.virtiofs_shares.len()
            );
            return self.write_full_keyframe_paused(base_dir);
        }
        if !self.dirty_tracking_enabled {
            log::warn!(
                "write_keyframe_paused: VM (cid {}) has no dirty tracking — \
                 the divergence from {} is unknown, writing a full keyframe instead",
                self.guest_cid,
                ancestor_mem.display()
            );
            return self.write_full_keyframe_paused(base_dir);
        }
        if missed_park {
            log::warn!(
                "write_keyframe_paused: VM (cid {}) missed the 200ms park \
                 — writing a full keyframe instead of an incremental dirty-delta",
                self.guest_cid
            );
            return self.write_full_keyframe_paused(base_dir);
        }
        // The complete dirty set vs the ancestor keyframe: KVM's log ∪
        // the device-DMA bitmaps ∪ the vhost-vsock rings (#101). The
        // pages the TRANSPORT_RESET injection writes are merged inside
        // `snapshot_vm_incremental`, which does the injection.
        let mut dirty = self
            .get_and_accumulate_dirty()
            .map_err(crate::snapshot::SnapshotError::Vm)?
            .to_vec();
        match crate::snapshot::snapshot_vm_incremental(self, base_dir, ancestor_mem, &mut dirty) {
            Ok(dirty_bytes) => Ok((true, dirty_bytes)),
            Err(crate::snapshot::SnapshotError::ReflinkUnsupported {
                ancestor,
                dest,
                detail,
            }) => {
                // Loud, never silent: the deploy is supposed to keep the
                // whole tree root on the reflink XFS, so landing here
                // means the node is misconfigured and every keyframe is
                // about to cost a full dump.
                log::warn!(
                    "write_keyframe_paused: FICLONE {} -> {} failed ({detail}); \
                     falling back to a FULL keyframe dump — put the tree root on a \
                     reflink-capable filesystem to get O(divergence) fork points",
                    ancestor.display(),
                    dest.display(),
                );
                self.write_full_keyframe_paused(base_dir)
            }
            Err(e) => Err(crate::fork::ForkError::Snapshot(e)),
        }
    }

    pub(crate) fn write_full_keyframe_paused(
        &mut self,
        base_dir: &Path,
    ) -> Result<(bool, u64), crate::fork::ForkError> {
        self.check_fork_source_allowed()?;
        crate::snapshot::snapshot_vm(self, base_dir).map_err(crate::fork::ForkError::Snapshot)?;
        Ok((false, self.mem_span()))
    }

    /// The half of `prepare_fork_source_in` that runs **after** the
    /// keyframe is on disk: hand virtiofs sources back live, otherwise
    /// shut the source down and restore it onto its own new
    /// `memory.bin` (preserving the vsock CID) so later warm forks share
    /// that file's page cache.
    ///
    /// A virtiofs source is left in whatever run state it arrived in; a
    /// swapped source comes back running.
    pub(crate) fn restore_swap_onto_base(
        &mut self,
        base_dir: &Path,
    ) -> Result<PathBuf, crate::fork::ForkError> {
        let (base_mem, husk) = self.restore_swap_onto_base_keep_husk(base_dir)?;
        drop(husk);
        Ok(base_mem)
    }

    /// [`Self::restore_swap_onto_base`], but hand back the swapped-out
    /// husk instead of dropping it. The restored copy already runs;
    /// unmapping the husk's RAM takes seconds for a guest of tens of
    /// GiB, so a caller timing the pause stops its clock first.
    pub(crate) fn restore_swap_onto_base_keep_husk(
        &mut self,
        base_dir: &Path,
    ) -> Result<(PathBuf, Option<Self>), crate::fork::ForkError> {
        let base_mem = base_dir.join("memory.bin");

        // VMs with virtiofs shares keep running as-is: vhost-user needs
        // an fd-backed shared mapping, which the restored copy's
        // MAP_PRIVATE CoW memory cannot provide — a swap would leave
        // every FUSE mount dead (runc, container rootfs — CHALLENGES.md
        // #39). Forks of such sources are full memfd copies instead of
        // base.mem CoW (see `fork::restore_vm_from_state`), so the
        // source does not need to run on the base.mem mapping. Bonus:
        // the vsock CID is unchanged, so shim-held agent connections
        // survive prepare.
        if !self.virtiofs_shares.is_empty() {
            self.enable_dirty_tracking()?;
            self.fork_source_base_path = Some(base_mem.clone());
            log::info!(
                "prepare_fork_source: keeping source live ({} virtiofs shares, cid {})",
                self.virtiofs_shares.len(),
                self.guest_cid
            );
            return Ok((base_mem, None));
        }

        // Move the source's TAP into the restored VM so the host bridge link
        // survives the swap below. Without this, dropping the original `Vm`
        // would tear down the kernel-side TAP interface and break networking
        // for every subsequent warm fork.
        let tap = self.take_tap();

        // The restored copy must keep the source's vsock
        // CID. The pod's shim caches the CID at Create and has no refresh
        // channel once the daemon drops the sandbox records at adopt
        // (CHALLENGES.md #39/#47 territory) — restoring on a fresh CID
        // breaks every later exec/log against the source. The kernel
        // holds a CID until the vhost-vsock fd that claimed it closes,
        // so stop the source's vCPU and drop its devices (which closes
        // that fd) BEFORE the restored VM re-claims the same CID. The
        // guest is frozen-in-snapshot either way; if the restore below
        // fails, the source is dead and the error propagates loudly
        // (same blast radius as a failed swap had before).
        let source_cid = self.guest_cid;
        self.shutdown();
        self.mmio_registry.lock().unwrap().shutdown_all();
        let mut restored = crate::fork::restore_vm_preserving_cid(base_dir, tap, source_cid)?;
        // Enable dirty tracking BEFORE starting the vCPU. Any page the restored
        // guest writes must show up in the bitmap so the warm fork can copy it.
        // If we started the vCPU first, pages dirtied before enable would drift
        // silently from base.mem and corrupt every future fork's memory.
        restored.enable_dirty_tracking()?;
        restored.start()?;

        // Hand the scratch image to the restored copy, for the
        // same reason as the TAP above — the restored VM's block backend
        // is already reading and writing that file, and dropping the
        // husk's handle would unlink it out from under the live guest
        // (and out from under every later fork's FICLONE).
        restored.scratch_disk = self.scratch_disk.take();
        // Same for the reflinked RW images a *forked* VM was built with:
        // the husk owns their directory (`fork_state_dir`, removed on
        // Drop) but the restored copy's block backends reopened those
        // exact files. Without this transfer the husk's Drop deletes the
        // live guest's disk (silently — the open fd keeps working) and
        // every later fork's FICLONE fails ENOENT, which broke
        // fork-of-fork for any VM with a RW block device
        // (CHALLENGES.md #130).
        restored.fork_state_dir = self.fork_state_dir.take();
        // The per-container images are the same class of
        // resource — the live guest is reading and writing them too.
        restored.container_scratch_disks = std::mem::take(&mut self.container_scratch_disks);
        // Data-disk handles move across too, but for a different reason:
        // they own no cleanup, and the restored copy is now the live
        // source, so it is the VM that must be able to report which
        // persistent disks it was created with.
        restored.data_disks = std::mem::take(&mut self.data_disks);
        restored.docker_disk = self.docker_disk.take();

        // The old source was already shut down above (CID release);
        // dropping the swapped-out husk just unmaps its memory.
        std::mem::swap(self, &mut restored);

        self.fork_source_base_path = Some(base_mem.clone());
        Ok((base_mem, Some(restored)))
    }

    /// Number of pages marked dirty in the accumulated bitmap since dirty
    /// tracking was enabled. Returns `None` if tracking is not enabled.
    ///
    /// Used by the snapshot tree to estimate per-VM non-reclaimable RAM.
    #[must_use]
    pub fn accumulated_dirty_pages(&self) -> Option<u64> {
        self.accumulated_dirty
            .as_ref()
            .map(|b| b.iter().map(|w| u64::from(w.count_ones())).sum())
    }

    /// Return a copy of the accumulated dirty bitmap (if tracking is enabled).
    #[must_use]
    pub fn accumulated_dirty_bitmap(&self) -> Option<Vec<u64>> {
        self.accumulated_dirty.clone()
    }

    /// Seed the accumulated dirty bitmap with pre-existing dirty page marks.
    ///
    /// Used by the snapshot tree when forking a child: the child's delta
    /// against the parent's `memory.bin` must include every page the parent
    /// had marked dirty at fork time (those pages were memcpy'd into the
    /// child's `CoW` mapping). ORs `preseed` into the accumulated bitmap;
    /// tracking must already be enabled.
    pub fn seed_accumulated_dirty(&mut self, preseed: &[u64]) -> Result<(), VmError> {
        let acc = self.accumulated_dirty.as_mut().ok_or_else(|| {
            VmError::Pipe(std::io::Error::other(
                "dirty tracking not enabled — cannot seed bitmap",
            ))
        })?;
        for (i, &w) in preseed.iter().enumerate() {
            if i < acc.len() {
                acc[i] |= w;
            }
        }
        Ok(())
    }

    /// Enable KVM dirty page tracking on the VM's memory slot.
    ///
    /// Re-registers every RAM slot with `KVM_MEM_LOG_DIRTY_PAGES`. Allocates
    /// the `accumulated_dirty` bitmap. Idempotent: no-op if already enabled.
    ///
    /// Also enables `KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2` (Linux 5.0+) so we can
    /// re-arm write protection between `KVM_GET_DIRTY_LOG` calls without
    /// dropping the memory region.
    pub fn enable_dirty_tracking(&mut self) -> Result<(), VmError> {
        if self.dirty_tracking_enabled {
            return Ok(());
        }

        // Enable MANUAL_DIRTY_LOG_PROTECT2 (cap 168) before re-registering the
        // memory region, so that KVM_GET_DIRTY_LOG does NOT auto-clear and we
        // can re-arm write protection via KVM_CLEAR_DIRTY_LOG instead.
        // args[0] = KVM_DIRTY_LOG_MANUAL_PROTECT_ENABLE (bit 0).
        let cap = kvm_bindings::kvm_enable_cap {
            cap: kvm_bindings::KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2,
            args: [1, 0, 0, 0],
            ..Default::default()
        };
        if let Err(e) = self.vm_fd.enable_cap(&cap) {
            log::warn!("KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2 not available: {e}");
        }

        // Briefly pause the vCPU while we re-register the memory region.
        let was_running = self.is_running();
        if was_running {
            self.pause()?;
        }

        let mem_host_addr = self.mem_host_addr();
        for (slot, gpa, size) in self.mem_layout().slots() {
            let mem_region = kvm_bindings::kvm_userspace_memory_region {
                slot,
                guest_phys_addr: gpa,
                memory_size: size,
                userspace_addr: mem_host_addr + gpa,
                flags: kvm_bindings::KVM_MEM_LOG_DIRTY_PAGES,
            };
            // SAFETY: userspace_addr points into the VM's existing memory
            // mapping, kept alive by self.guest_memory / self.cow_mmap_addr.
            unsafe {
                self.vm_fd
                    .set_user_memory_region(mem_region)
                    .map_err(VmError::SetUserMemoryRegion)?;
            }
        }

        if was_running {
            self.resume()?;
        }

        // Bitmap: one bit per 4 KiB page of the GPA span (so page index ==
        // `memory.bin` offset / 4096, hole included and never dirty).
        // 256 MB / 4 KiB = 65 536 pages = 1024 u64s.
        let pages = self.mem_span().div_ceil(4096);
        let words = (pages as usize).div_ceil(64);
        self.accumulated_dirty = Some(vec![0u64; words]);
        self.dirty_tracking_enabled = true;
        log::info!("dirty tracking enabled ({pages} pages, {words} words)");
        Ok(())
    }

    /// Harvest the dirty log, OR it into the accumulated bitmap, and
    /// return the accumulated bitmap (union of all pages dirtied since
    /// dirty tracking was enabled).
    pub fn get_and_accumulate_dirty(&mut self) -> Result<&[u64], VmError> {
        self.harvest_dirty()?;
        Ok(self
            .accumulated_dirty
            .as_deref()
            .expect("harvest checked tracking"))
    }

    /// Pages dirtied since the previous harvest — KVM's log ∪ the
    /// device-DMA bitmaps ∪ the vhost-vsock rings — as a span-indexed
    /// bitmap, also OR'd into the accumulated bitmap. Safe on a
    /// **running** VM: a page written at any point after its bit is
    /// cleared here is reported by a later harvest, which is what the
    /// live keyframe (`snapshot::LiveKeyframe`) relies on.
    pub fn harvest_dirty(&mut self) -> Result<Vec<u64>, VmError> {
        if !self.dirty_tracking_enabled {
            return Err(VmError::Pipe(std::io::Error::other(
                "dirty tracking not enabled",
            )));
        }
        let mem_host_addr = self.mem_host_addr();
        let mem_span = self.mem_span();
        let mut round = vec![0u64; self.accumulated_dirty.as_ref().map_or(0, Vec::len)];
        let round_words = round.len();

        // One KVM bitmap per RAM slot. Both region boundaries are whole
        // bitmap words (see
        // `mem_layout::tests::region_boundaries_are_bitmap_word_aligned`),
        // so a slot's bits land at a word offset with no shifting.
        for (slot, gpa, size) in self.mem_layout().slots() {
            let bitmap = self.vm_fd.get_dirty_log(slot, size as usize).map_err(|e| {
                VmError::Pipe(std::io::Error::other(format!(
                    "KVM_GET_DIRTY_LOG slot {slot}: {e}"
                )))
            })?;
            // Re-arm write protection for exactly the pages GET reported.
            // With MANUAL_DIRTY_LOG_PROTECT2 GET no longer clears; an
            // all-ones clear on a running guest would also drop a write
            // that landed after GET on a page GET saw clean.
            clear_dirty_log(&self.vm_fd, slot, size, &bitmap)?;
            let word_offset = (gpa / 4096 / 64) as usize;
            // Dropping words here would silently lose dirty pages and hand
            // forks a stale copy of them, so a short bitmap is an error.
            let dst = round
                .get_mut(word_offset..word_offset + bitmap.len())
                .ok_or_else(|| {
                    VmError::Pipe(std::io::Error::other(format!(
                        "dirty bitmap of the slot at {gpa:#x} ({} words at word {word_offset}) \
                         does not fit the {round_words}-word span bitmap",
                        bitmap.len(),
                    )))
                })?;
            for (d, w) in dst.iter_mut().zip(bitmap) {
                *d |= w;
            }
        }

        // Device-DMA dirty pages: KVM's log only sees vCPU writes, so
        // in-process device workers that write guest memory through k7d's
        // own mapping report (and here drain) their pages. Without this,
        // warm forks on the base.mem + dirty-delta path would silently miss
        // read completions and used-ring updates (host-side #27 class).
        // vhost-vsock has no userspace worker to report anything, so its
        // virtqueue rings and buffers are marked from the queue state.
        self.mmio_registry.lock().unwrap().merge_dirty_pages_all(
            &mut round,
            mem_host_addr,
            mem_span,
        );

        let acc = self.accumulated_dirty.as_mut().expect("bitmap allocated");
        for (a, r) in acc.iter_mut().zip(&round) {
            *a |= r;
        }
        Ok(round)
    }

    /// Guest-physical `[start, end)` extents of RAM that may hold data:
    /// for a memfd-backed guest, the memfd's `SEEK_DATA` extents clipped
    /// to the RAM slots (never-touched pages are holes and read as zero);
    /// for a restored guest, its whole RAM slots. Never the MMIO hole.
    pub fn ram_data_extents(&self) -> Result<Vec<(u64, u64)>, VmError> {
        use vm_memory::GuestMemoryRegion;
        let slots = self.mem_layout().slots();
        // The memfd only describes guest RAM when the guest runs on it.
        let memfd = if self.restored || self.cow_mmap_addr.is_some() {
            None
        } else {
            self.guest_memory
                .iter()
                .next()
                .and_then(|r| r.file_offset().map(|f| f.file().as_raw_fd()))
        };
        let Some(fd) = memfd else {
            return Ok(slots
                .iter()
                .map(|&(_, gpa, size)| (gpa, gpa + size))
                .collect());
        };
        let mut out = Vec::new();
        for (_, gpa, size) in slots {
            let end = gpa + size;
            let mut pos = gpa;
            while pos < end {
                let Some(data) = seek_memfd(fd, pos, libc::SEEK_DATA)? else {
                    break;
                };
                if data >= end {
                    break;
                }
                let hole = seek_memfd(fd, data, libc::SEEK_HOLE)?.unwrap_or(end);
                if let Some(ext) = clip_extent(data, hole, gpa, end) {
                    out.push(ext);
                }
                pos = hole;
            }
        }
        Ok(out)
    }

    /// Path to the `base.mem` file this VM is fork-ready against, if any.
    #[must_use]
    pub fn fork_source_base_path(&self) -> Option<&Path> {
        self.fork_source_base_path.as_deref()
    }

    /// Declare that this VM's memory is a `MAP_PRIVATE` mapping of
    /// `base_mem`, so warm forks can use it without a fresh prepare.
    ///
    /// Point this VM at a `memory.bin` for `fork_warm` without writing
    /// a new keyframe. Used for (1) a resumed checkpoint and (2) an
    /// in-tree child that maps its ancestor's file plus a dirty bitmap.
    pub fn set_fork_source_base_path(&mut self, base_mem: PathBuf) {
        self.fork_source_base_path = Some(base_mem);
    }

    /// Warm fork: create a new VM from this source's `base.mem` plus the current
    /// dirty delta (memory-to-memory copy). No disk I/O during the hot path.
    ///
    /// The source must have `fork_source_base_path` set (own keyframe
    /// or an inherited ancestor file).
    ///
    /// Steps (part 1, §Warm fork):
    /// 1. Pause source.
    /// 2. Read dirty bitmap, accumulate, save CPU+devices+IRQ state in memory.
    /// 3. Resume source immediately (steps 5–11 run while source is live).
    /// 4. mmap `base.mem` with `MAP_PRIVATE`, memcpy dirty pages from source.
    /// 5. Build a new KVM VM from the in-memory state.
    /// 6. Inject `TRANSPORT_RESET` into the **fork's** memory only.
    pub fn fork_warm(&mut self, fork_id: &str) -> Result<Self, crate::fork::ForkError> {
        let mut out = self.fork_warm_batch(&[fork_id], None)?;
        Ok(out.pop().expect("single fork"))
    }

    /// Batched warm fork: create N forks from the same paused moment.
    ///
    /// The source is paused once, the dirty bitmap captured once, CPU state
    /// saved once — then each fork is materialized independently.
    ///
    /// `dilation` names the child's factor; `None`
    /// inherits the source's.
    pub fn fork_warm_batch(
        &mut self,
        fork_ids: &[&str],
        dilation: Option<u32>,
    ) -> Result<Vec<Self>, crate::fork::ForkError> {
        let forks = fork_ids.iter().map(|&id| (id, None)).collect();
        self.fork_warm_batch_with_taps(forks, dilation)
    }

    /// [`Self::fork_warm_batch`] where each fork may take its own TAP
    /// for the virtio-net slot. A snapshot with virtio-net and no TAP
    /// yields a fork whose guest network is inactive.
    pub fn fork_warm_batch_with_taps(
        &mut self,
        forks: Vec<(&str, Option<crate::network::TapDevice>)>,
        dilation: Option<u32>,
    ) -> Result<Vec<Self>, crate::fork::ForkError> {
        let base_path = self.fork_source_base_path.clone().ok_or_else(|| {
            crate::fork::ForkError::Reflink(
                "VM not prepared as fork source — call prepare_fork_source() first".into(),
            )
        })?;

        let was_running = self.is_running();
        if was_running {
            self.pause().map_err(crate::snapshot::SnapshotError::Vm)?;
        }
        let force_full_dump = self.take_full_dump_if_not_quiescent();

        // Capture dirty bitmap + CPU + device + IRQ state (all in-memory).
        let dirty_bitmap = self
            .get_and_accumulate_dirty()
            .map_err(crate::snapshot::SnapshotError::Vm)?
            .to_vec();
        let state = crate::snapshot::capture_vm_state(self)?;
        let source_mem_addr = self.mem_host_addr();

        // The source must stay paused during memcpy: if it resumes, it may write
        // to pages we're about to copy, making the fork's memory inconsistent
        // with its captured vCPU state. Per fork, memcpy time is
        // O(dirty_pages) — 0.5 µs/page, so ≤15 ms even at 100% dirty on 256 MB.
        let mut out = Vec::with_capacity(forks.len());
        let mut fork_err: Option<crate::fork::ForkError> = None;
        for (id, tap) in forks {
            let restored = match tap {
                Some(tap) => crate::fork::restore_vm_from_state_with_tap(
                    &base_path,
                    &dirty_bitmap,
                    source_mem_addr,
                    &state,
                    id,
                    tap,
                    dilation,
                    force_full_dump,
                ),
                None => crate::fork::restore_vm_from_state(
                    &base_path,
                    &dirty_bitmap,
                    source_mem_addr,
                    &state,
                    id,
                    dilation,
                    force_full_dump,
                ),
            };
            match restored {
                Ok(fork) => out.push(fork),
                Err(e) => {
                    fork_err = Some(e);
                    break;
                }
            }
        }

        if was_running {
            self.resume().map_err(crate::snapshot::SnapshotError::Vm)?;
        }

        if let Some(e) = fork_err {
            return Err(e);
        }
        Ok(out)
    }

    /// Fork this VM into an independent copy with `CoW` memory and reflinked disk.
    ///
    /// The source VM is paused during the snapshot phase, then resumed.
    /// The returned VM has its own vsock CID and `CoW` memory mapping.
    /// If virtiofs is configured, the state directory is reflink-copied.
    ///
    /// `fork_id` is used to name the fork's working directories.
    pub fn fork(&mut self, fork_id: &str) -> Result<Self, crate::fork::ForkError> {
        let fork_base = std::env::temp_dir().join(format!("k7d-fork-{}", std::process::id()));
        std::fs::create_dir_all(&fork_base)?;
        crate::fork::fork_vm(self, fork_id, &fork_base)
    }

    /// Set the fork state directory path (used internally after fork).
    pub(crate) fn set_fork_state_dir(&mut self, path: PathBuf) {
        self.fork_state_dir = Some(path);
    }

    /// Take ownership of the fork state directory away from this VM, so
    /// Drop no longer removes it. Used by tree suspend: the reflinked RW
    /// images inside it ARE the node's disk state and must outlive the
    /// `Vm` — resume reflinks fresh copies from them (CHALLENGES.md #130).
    pub(crate) fn take_fork_state_dir(&mut self) -> Option<PathBuf> {
        self.fork_state_dir.take()
    }
}
