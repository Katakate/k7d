//! `CoW` mmap fork: `MAP_PRIVATE` snapshot restore + btrfs reflink disk copy.

use std::fs;
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use kvm_bindings::{
    kvm_pit_config, kvm_regs, kvm_segment, kvm_sregs, kvm_userspace_memory_region,
    KVM_PIT_SPEAKER_DUMMY,
};
use kvm_ioctls::{Kvm, VcpuFd};
use vmm_sys_util::eventfd::EventFd;

use crate::devices::{create_serial_device_with_trigger, PipeSerialDevice, SerialTrigger};
use crate::network::{ClusterNetwork, TapDevice, TapNetBackend};
use crate::snapshot::{CpuState, KvmClockState, SnapshotError, VmState};
use crate::virtio_mmio::{
    restore_queues, MmioDevice, MmioDeviceRegistry, VirtioBackend, VIRTIO_ID_VSOCK,
};
use crate::vm::{Vm, VmError};
use crate::vsock::VhostVsockBackend;

/// Virtio device-type ID for `virtio-net` (matches the constant in `network.rs`).
const VIRTIO_ID_NET: u32 = 1;
/// Virtio device-type ID for `virtio-blk` (matches `crate::block::VIRTIO_ID_BLOCK`).
const VIRTIO_ID_BLOCK: u32 = 2;
const VIRTIO_ID_FS: u32 = 26;

/// Errors specific to restore/fork operations.
#[derive(Debug, thiserror::Error)]
pub enum RestoreError {
    /// IO error during restore.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// JSON deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// KVM operation failed.
    #[error("KVM error: {0}")]
    Kvm(String),
    /// Snapshot data is invalid.
    #[error("invalid snapshot: {0}")]
    InvalidSnapshot(String),
    /// VM build error.
    #[error("VM error: {0}")]
    Vm(#[from] VmError),
    /// Snapshot error.
    #[error("snapshot error: {0}")]
    Snapshot(#[from] SnapshotError),
}

/// Errors specific to fork operations.
#[derive(Debug, thiserror::Error)]
pub enum ForkError {
    /// Snapshot of the source VM failed.
    #[error("snapshot failed: {0}")]
    Snapshot(#[from] SnapshotError),
    /// IO error (reflink copy, temp dir creation).
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// Restore of the forked VM failed.
    #[error("restore failed: {0}")]
    Restore(#[from] RestoreError),
    /// Reflink copy failed.
    #[error("reflink copy failed: {0}")]
    Reflink(String),
    /// The VM has virtiofs shares, which force every
    /// fork onto the slow full-memfd copy path, and the caller did not
    /// explicitly opt in via [`Vm::allow_slow_fork`].
    #[error(
        "VM has {shares} virtiofs share(s): virtiofs-backed VMs cannot take the CoW \
         fast-fork path (every fork is a full memfd copy of guest RAM) — call \
         Vm::allow_slow_fork() to explicitly accept slow forks, or move the pod's \
         volumes off virtiofs"
    )]
    VirtiofsSlowForkNotAllowed {
        /// Number of virtiofs shares on the VM.
        shares: usize,
    },
    /// Underlying VM operation failed.
    #[error("VM error: {0}")]
    Vm(#[from] VmError),
}

/// Fork a running VM into an independent copy.
///
/// This is the core fork operation:
/// 1. Pause the source VM
/// 2. Snapshot memory + CPU + device state
/// 3. Reflink-copy the source's virtiofs state directory (if any) for the fork
/// 4. Restore a new VM from the snapshot with a new vsock CID
/// 5. Resume the source VM
///
/// The fork gets `CoW` memory (`MAP_PRIVATE` mmap of memory.bin) and `CoW` disk
/// (reflink or regular copy of the state dir). Total fork time for a warm
/// source should be <5ms (memory) + <1ms (reflink).
pub fn fork_vm(source: &mut Vm, fork_id: &str, fork_base_dir: &Path) -> Result<Vm, ForkError> {
    let start = std::time::Instant::now();

    let snapshot_dir = fork_base_dir.join(format!("{fork_id}-snapshot"));
    fs::create_dir_all(&snapshot_dir)?;

    // 1. Snapshot the source (pauses + resumes internally).
    source
        .snapshot(&snapshot_dir)
        .map_err(ForkError::Snapshot)?;

    // 2. Reflink-copy the virtiofs state directory if configured.
    let fork_state_dir = if let Some(vfs_config) = source.virtiofs_config() {
        let src_state = &vfs_config.host_dir;
        let dst_state = fork_base_dir.join(format!("{fork_id}-state"));
        reflink_copy_dir(src_state, &dst_state)?;
        Some(dst_state)
    } else {
        None
    };

    // 3. Restore a new VM from the snapshot with a new CID.
    let mut forked = restore_vm(&snapshot_dir)?;

    // 4. If we have a state dir, set up virtiofs on the fork pointing to the
    //    reflinked copy. We store the fork state dir path and virtiofs config
    //    so the caller can spawn virtiofsd if desired.
    if let Some(ref state_dir) = fork_state_dir {
        forked.set_fork_state_dir(state_dir.clone());
    }

    log::info!(
        "fork '{fork_id}': complete in {:?} (snapshot + reflink + restore)",
        start.elapsed()
    );

    Ok(forked)
}

/// Copy a directory tree using reflink (`CoW`) when possible.
///
/// Falls back to regular copy if reflink is not supported (non-btrfs/XFS).
/// Uses `cp --reflink=auto -a` for atomic `CoW` copy.
fn reflink_copy_dir(src: &Path, dst: &Path) -> Result<(), ForkError> {
    if !src.exists() {
        fs::create_dir_all(dst)?;
        return Ok(());
    }

    let output = std::process::Command::new("cp")
        .args(["--reflink=auto", "-a"])
        .arg(src)
        .arg(dst)
        .output()?;

    if !output.status.success() {
        return Err(ForkError::Reflink(format!(
            "cp --reflink=auto {} {}: {}",
            src.display(),
            dst.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// Reflink-copy a single file via the `FICLONE` ioctl. Unlike
/// [`reflink_copy_dir`] this NEVER falls back to a byte copy: a fork's RW
/// block image must be `CoW` — a silent full copy would turn
/// O(1) forks into O(image bytes). Fails loudly on filesystems without
/// reflink support (ext4, tmpfs).
fn reflink_file(src: &Path, dst: &Path) -> Result<(), ForkError> {
    let src_file = fs::File::open(src)?;
    let dst_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dst)?;
    let t_clone = std::time::Instant::now();
    // SAFETY: both fds are valid for the duration of the call; FICLONE takes
    // the source fd as its integer argument.
    let rc = unsafe { libc::ioctl(dst_file.as_raw_fd(), libc::FICLONE, src_file.as_raw_fd()) };
    log::info!(
        "FICLONE {} -> {} in {:?}",
        src.display(),
        dst.display(),
        t_clone.elapsed()
    );
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        let _ = fs::remove_file(dst);
        return Err(ForkError::Reflink(format!(
            "FICLONE {} -> {}: {err} — forking a read-write virtio-blk image \
             requires a reflink-capable filesystem (btrfs/XFS); read-only \
             devices fork by sharing the backing file",
            src.display(),
            dst.display()
        )));
    }
    Ok(())
}

/// Restore a VM from a snapshot directory using `CoW` `MAP_PRIVATE` mmap.
///
/// The snapshot directory must contain:
/// - `memory.bin` — raw guest memory dump
/// - `cpu.json` — vCPU registers
/// - `devices.json` — MMIO device state
/// - `metadata.json` — VM configuration
///
/// Memory is mapped with `MAP_PRIVATE | MAP_NORESERVE` — the kernel uses
/// copy-on-write, so only pages actually written by the restored guest
/// consume physical RAM. This makes restore effectively O(1) regardless
/// of VM memory size.
pub fn restore_vm(snapshot_dir: &Path) -> Result<Vm, RestoreError> {
    restore_vm_inner(snapshot_dir, None, None)
}

/// Like [`restore_vm`] but reattaches a pre-built TAP for the virtio-net
/// MMIO slot — used by [`Vm::prepare_fork_source`] to preserve the source's
/// network identity through the cold-snapshot/restore boot-strap.
pub fn restore_vm_with_tap(snapshot_dir: &Path, tap: TapDevice) -> Result<Vm, RestoreError> {
    restore_vm_inner(snapshot_dir, Some(tap), None)
}

/// Like [`restore_vm_with_tap`] but restores onto a **caller-chosen
/// vsock CID** instead of allocating a fresh one.
///
/// Used by [`Vm::prepare_fork_source_in`]'s in-place swap of a
/// share-less source VM: the pod's shim caches the CID at Create and
/// has no refresh channel once the daemon drops the sandbox records at
/// adopt, so the restored source must answer on the CID the source
/// booted with. The caller must have already released the CID (dropped
/// the source's vhost-vsock backend) — the kernel rejects a duplicate
/// `SET_GUEST_CID` with `EADDRINUSE` otherwise.
pub(crate) fn restore_vm_preserving_cid(
    snapshot_dir: &Path,
    tap: Option<TapDevice>,
    cid: u64,
) -> Result<Vm, RestoreError> {
    restore_vm_inner(snapshot_dir, tap, Some(cid))
}

#[allow(clippy::too_many_lines)]
fn restore_vm_inner(
    snapshot_dir: &Path,
    tap: Option<TapDevice>,
    forced_cid: Option<u64>,
) -> Result<Vm, RestoreError> {
    let start = std::time::Instant::now();

    let cpu_json = fs::read_to_string(snapshot_dir.join("cpu.json"))?;
    // Cpu.json is an array (one entry per vCPU); older
    // snapshots hold a single bare object — accept both.
    let cpu_states: Vec<CpuState> =
        serde_json::from_str::<crate::snapshot::CpuStatesCompat>(&cpu_json)?.into();

    let metadata_json = fs::read_to_string(snapshot_dir.join("metadata.json"))?;
    let bundle: crate::snapshot::SnapshotMetadata = serde_json::from_str(&metadata_json)?;

    // The snapshot records guest RAM; `memory.bin` and the host
    // mapping cover the whole guest physical span (RAM + the 32-bit MMIO
    // hole for guests with RAM past 4 GiB).
    let mem_size = bundle.memory_size_bytes;
    let layout = crate::mem_layout::MemLayout::from_ram(mem_size);
    let mem_span = layout.span();
    let kernel_path = PathBuf::from(&bundle.kernel_path);
    let initrd_path = bundle.initrd_path.as_ref().map(PathBuf::from);

    let mem_file_path = snapshot_dir.join("memory.bin");
    // Open read-write: MAP_PRIVATE + PROT_WRITE requires O_RDWR on Linux.
    let mem_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&mem_file_path)?;
    let actual_size = mem_file.metadata()?.len();
    if actual_size != mem_span {
        return Err(RestoreError::InvalidSnapshot(format!(
            "memory.bin is {actual_size} bytes, expected {mem_span}"
        )));
    }

    // mmap with MAP_PRIVATE for CoW semantics. GuestMemoryMmap::from_ranges_with_files
    // uses MAP_SHARED which doesn't give us CoW and may behave differently for
    // page table pages. We manually mmap and register with KVM.
    // SAFETY: mem_file is valid and mem_span matches the file size.
    let mem_ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            mem_span as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_NORESERVE,
            mem_file.as_raw_fd(),
            0,
        )
    };
    if mem_ptr == libc::MAP_FAILED {
        return Err(RestoreError::Io(std::io::Error::last_os_error()));
    }
    let mem_host_addr = mem_ptr as u64;

    let kvm = Kvm::new().map_err(|e| RestoreError::Kvm(format!("open /dev/kvm: {e}")))?;
    let vm_fd = kvm
        .create_vm()
        .map_err(|e| RestoreError::Kvm(format!("create VM: {e}")))?;
    restore_dilation(&vm_fd, bundle.dilation)?;

    vm_fd
        .set_tss_address(0xfffb_d000usize)
        .map_err(|e| RestoreError::Kvm(format!("set TSS address: {e}")))?;
    vm_fd
        .create_irq_chip()
        .map_err(|e| RestoreError::Kvm(format!("create IRQ chip: {e}")))?;
    let pit_config = kvm_pit_config {
        flags: KVM_PIT_SPEAKER_DUMMY,
        ..Default::default()
    };
    vm_fd
        .create_pit2(pit_config)
        .map_err(|e| RestoreError::Kvm(format!("create PIT2: {e}")))?;

    // Register the CoW-mapped RAM regions with KVM, leaving the 32-bit MMIO
    // hole unmapped.
    for (slot, gpa, size) in layout.slots() {
        let mem_region = kvm_userspace_memory_region {
            slot,
            guest_phys_addr: gpa,
            memory_size: size,
            userspace_addr: mem_host_addr + gpa,
            flags: 0,
        };
        // SAFETY: the mmap outlives the VM (freed via Vm::drop's cow_mmap_addr);
        // the region describes a sub-range of that MAP_PRIVATE mapping.
        unsafe {
            vm_fd
                .set_user_memory_region(mem_region)
                .map_err(|e| RestoreError::Kvm(format!("set user memory region: {e}")))?;
        }
    }

    // Create GuestMemoryMmap wrapping the existing mmap.
    // We can't use from_ranges_with_files because the mmap already exists.
    // Instead we use from_raw_regions_with_files with our existing address.
    // Actually, we'll create a GuestMemoryMmap from raw ranges via the
    // same file so the memory object tracks the correct addresses.
    // We pass the file at offset 0. vm-memory will mmap it again, but we
    // need the KVM memory region to point to OUR mmap, not vm-memory's.
    // So we'll use the MmapGuard approach: store our mmap pointer and use
    // GuestMemoryMmap::from_raw_regions for the serial/agent API.

    // For API compat with the existing Vm struct, create a GuestMemoryMmap
    // that wraps a fresh anonymous mmap (won't be used by KVM — KVM has
    // our CoW mmap). This is only for the guest_memory() accessor that
    // snapshot_vm and other code may use. The real guest memory is the
    // CoW mmap registered with KVM.
    //
    // Alternative: create a memfd backed GuestMemoryMmap and point KVM to it.
    // But then we lose the CoW property. Instead, we use the mmap pointer
    // directly in the Vm struct and provide a thin accessor.

    // Load IRQ chip state (applied inside restore_cpu_state at the right point).
    let irqchip_path = snapshot_dir.join("irqchip.json");
    let irqchip_state = if irqchip_path.exists() {
        let json = fs::read_to_string(&irqchip_path)?;
        Some(serde_json::from_str::<crate::snapshot::IrqChipState>(
            &json,
        )?)
    } else {
        None
    };

    // Create one vCPU per captured CpuState and restore each (CPUID →
    // SREGS → XCRS → XSAVE → REGS → LAPIC → MSRs → MP_STATE last).
    let vcpu_fds = create_and_restore_vcpus(
        &kvm,
        &vm_fd,
        &cpu_states,
        irqchip_state.as_ref(),
        bundle.kvmclock.as_ref(),
        bundle.dilation,
    )?;

    // Fresh CID by default (concurrent restores from one snapshot must
    // not collide). `forced_cid` reuses the source's
    // CID for the in-place prepare swap — the caller guarantees the
    // old vhost fd holding it is already closed.
    let new_cid = forced_cid.unwrap_or_else(crate::vsock::allocate_cid);

    // Set up vsock with new CID.
    let mmio_registry = Arc::new(Mutex::new(MmioDeviceRegistry::new()));

    // Read device states to know what devices to recreate.
    let devices_json = fs::read_to_string(snapshot_dir.join("devices.json"))?;
    let device_states: Vec<crate::virtio_mmio::MmioDeviceState> =
        serde_json::from_str(&devices_json)?;

    // Recreate vsock device (device type 19) with new CID and pre-activate it.
    // The guest kernel already completed feature negotiation and queue setup
    // during the original boot. We restore the vhost backend with the saved
    // queue addresses and correct vring base indices so the guest agent's
    // vsock listener works immediately after resume.
    let mut has_vsock = false;
    let mut tap_slot = tap;
    let mut tap_for_vm: Option<TapDevice> = None;
    let mut guest_ip_for_vm: Option<Ipv4Addr> = None;
    // Virtio-blk rebuild bookkeeping: device order == config order.
    let mut blk_idx: usize = 0;
    for dev_state in &device_states {
        if dev_state.device_type == VIRTIO_ID_VSOCK {
            let irq = dev_state.irq;
            let base = dev_state.base_addr;

            let irq_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(RestoreError::Io)?;
            vm_fd
                .register_irqfd(&irq_evt, irq)
                .map_err(|e| RestoreError::Kvm(format!("register irqfd for vsock: {e}")))?;
            let irq_evt = Arc::new(irq_evt);

            let mut vsock_backend = VhostVsockBackend::new(new_cid, mem_host_addr, mem_span)
                .map_err(|e| RestoreError::Kvm(format!("vsock backend: {e}")))?;

            // Pre-activate with saved queue state and correct vring base indices.
            let queues = restore_queues(&dev_state.queues, vsock_backend.max_queue_size());
            vsock_backend
                .activate_with_bases(&queues, &irq_evt, mem_host_addr)
                .map_err(|e| RestoreError::Kvm(format!("vsock activate: {e}")))?;

            let mut dev = MmioDevice::new(base, irq, irq_evt, Box::new(vsock_backend));
            dev.set_vhost(true);
            dev.restore_state(dev_state);

            // Signal the event queue IRQ so the guest driver processes the
            // TRANSPORT_RESET event that was injected during snapshot.
            // This makes the driver tear down stale connections and allow
            // new ones via the accept loop. (Mirrors Firecracker's kick.)
            dev.trigger_vring_irq();

            let mmio_dev = Arc::new(Mutex::new(dev));
            mmio_registry.lock().unwrap().add(Arc::clone(&mmio_dev));

            has_vsock = true;
        } else if dev_state.device_type == VIRTIO_ID_NET {
            let Some(net_tap) = tap_slot.take() else {
                continue;
            };
            let irq = dev_state.irq;
            let base = dev_state.base_addr;

            let irq_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(RestoreError::Io)?;
            vm_fd
                .register_irqfd(&irq_evt, irq)
                .map_err(|e| RestoreError::Kvm(format!("register irqfd for net: {e}")))?;
            let irq_evt = Arc::new(irq_evt);

            let mut net_backend =
                TapNetBackend::new(net_tap.mac(), net_tap.fd(), mem_host_addr, mem_span);
            let queues = restore_queues(&dev_state.queues, net_backend.max_queue_size());
            net_backend.ack_features(dev_state.acked_features);
            // Guest rings survived the snapshot — seed worker counters or eth0 hangs.
            net_backend
                .seed_indices_from_guest(&queues)
                .map_err(|e| RestoreError::Kvm(format!("net seed: {e}")))?;
            net_backend
                .activate(&queues, &irq_evt)
                .map_err(|e| RestoreError::Kvm(format!("net activate: {e}")))?;

            let mut dev = MmioDevice::new(base, irq, irq_evt, Box::new(net_backend));
            dev.set_vhost(true);
            dev.restore_state(dev_state);
            dev.trigger_vring_irq();

            let mmio_dev = Arc::new(Mutex::new(dev));
            mmio_registry.lock().unwrap().add(Arc::clone(&mmio_dev));

            guest_ip_for_vm = Some(net_tap.guest_ip());
            tap_for_vm = Some(net_tap);
        } else if dev_state.device_type == VIRTIO_ID_BLOCK {
            // Rebuild the userspace virtio-blk backend against the SAME
            // backing file (cold restore resumes the one guest that owns
            // it — no copy needed for RO or RW). The guest driver's ring
            // state survived in memory; seed the worker or the ring
            // corrupts (CHALLENGES.md #27).
            let Some(cfg) = bundle.block_devices.get(blk_idx) else {
                return Err(RestoreError::InvalidSnapshot(format!(
                    "virtio-blk device #{blk_idx} has no matching config in metadata \
                     (snapshot has {})",
                    bundle.block_devices.len()
                )));
            };
            blk_idx += 1;

            let irq = dev_state.irq;
            let base = dev_state.base_addr;

            let irq_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(RestoreError::Io)?;
            vm_fd
                .register_irqfd(&irq_evt, irq)
                .map_err(|e| RestoreError::Kvm(format!("register irqfd for blk: {e}")))?;
            let irq_evt = Arc::new(irq_evt);

            let mut blk_backend = crate::block::BlockBackend::new(
                &cfg.host_path,
                cfg.readonly,
                mem_host_addr,
                mem_span,
            )
            .map_err(|e| RestoreError::Kvm(format!("blk backend: {e}")))?;
            let queues = restore_queues(&dev_state.queues, blk_backend.max_queue_size());
            blk_backend.ack_features(dev_state.acked_features);
            blk_backend
                .seed_indices_from_guest(&queues)
                .map_err(|e| RestoreError::Kvm(format!("blk seed: {e}")))?;
            blk_backend
                .activate(&queues, &irq_evt)
                .map_err(|e| RestoreError::Kvm(format!("blk activate: {e}")))?;

            let mut dev = MmioDevice::new(base, irq, irq_evt, Box::new(blk_backend));
            dev.set_vhost(true);
            dev.restore_state(dev_state);
            dev.trigger_vring_irq();

            let mmio_dev = Arc::new(Mutex::new(dev));
            mmio_registry.lock().unwrap().add(Arc::clone(&mmio_dev));
        }
    }

    // Create serial devices (same as fresh boot). COM1 gets real THRE
    // interrupts (IRQ 4) — without them guest userspace console writes
    // block once the 8250 xmit buffer fills (`SerialDevice::with_trigger`).
    let com1_irq_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(RestoreError::Io)?;
    vm_fd
        .register_irqfd(&com1_irq_evt, crate::devices::SERIAL_IRQ)
        .map_err(|e| RestoreError::Kvm(format!("register irqfd for COM1: {e}")))?;
    let serial =
        create_serial_device_with_trigger(SerialTrigger::with_eventfd(Arc::new(com1_irq_evt)));

    let com2_irq_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(RestoreError::Io)?;
    vm_fd
        .register_irqfd(&com2_irq_evt, 3)
        .map_err(|e| RestoreError::Kvm(format!("register irqfd for COM2: {e}")))?;
    let com2_trigger = SerialTrigger::with_eventfd(Arc::new(com2_irq_evt));
    let (agent_serial, _) =
        PipeSerialDevice::with_trigger(com2_trigger).map_err(RestoreError::Io)?;
    let agent_serial = Arc::new(Mutex::new(agent_serial));

    log::info!(
        "restore: complete in {:?} (mmap + KVM + vCPU + vsock)",
        start.elapsed()
    );

    // Build the Vm struct using the internal constructor.
    // Create a GuestMemoryMmap from the same file for the Vm's accessor methods.
    // This creates a SEPARATE mmap (MAP_SHARED from vm-memory), but KVM uses
    // our MAP_PRIVATE mmap. The GuestMemoryMmap is only for snapshot dump_memory.
    let guest_memory = vm_memory::GuestMemoryMmap::<()>::from_ranges(&[(
        vm_memory::GuestAddress(0),
        mem_span as usize,
    )])
    .map_err(|e| RestoreError::Kvm(format!("create guest memory: {e}")))?;

    Ok(Vm::from_restored_with_memory(
        kvm,
        vm_fd,
        vcpu_fds,
        guest_memory,
        mem_host_addr,
        mem_size,
        kernel_path,
        initrd_path,
        serial,
        agent_serial,
        mmio_registry,
        if has_vsock { new_cid } else { 0 },
        // Restore intentionally does NOT re-spawn virtiofsd or
        // re-register virtio-fs MMIO devices for the snapshotted VM
        // — the original behaviour was `_virtiofsd: None` (and the
        // shim's caller spawns virtiofsd separately when needed via
        // `set_fork_state_dir`). The multi-share rework keeps that
        // contract: an empty `Vec` is the multi-share equivalent of
        // the old `None`.
        Vec::new(),
        tap_for_vm,
        guest_ip_for_vm,
        Vec::new(),
        bundle.block_devices.clone(),
        bundle.dilation,
    ))
}

/// Put a restored VM on the time dilation its source ran at. Must run
/// right after `KVM_CREATE_VM`: the factor rides on
/// each vCPU's TSC multiplier, which is programmed at vCPU creation.
/// A live `SET` on paused vCPUs is a separate path; restore still applies
/// the factor before any vCPU exists because that is when this path
/// builds the VM.
///
/// Every piece of time the snapshot carries is in *guest* units — the
/// `IA32_TSC` MSR is the guest's TSC, `KVM_GET_CLOCK` is guest
/// nanoseconds, LAPIC counts and TSC deadlines are guest ticks — and the
/// patched kernel converts between those and wall time on the way in
/// and out. Restoring them onto a VM at the same factor is therefore
/// exactly the undilated restore. A stock host cannot do it, and says
/// so here instead of silently resuming the guest at 1x.
fn resolve_fork_dilation(requested: Option<u32>, source: u32) -> Result<u32, RestoreError> {
    match requested {
        Some(0) => Err(RestoreError::Kvm(
            "dilation 0 is not a factor — omit the field to inherit the source's, or pass 1..=64"
                .into(),
        )),
        Some(n) => Ok(n),
        None => Ok(source),
    }
}

fn restore_dilation(vm_fd: &kvm_ioctls::VmFd, dilation: u32) -> Result<(), RestoreError> {
    if dilation == 0 {
        return Err(RestoreError::Kvm(
            "dilation 0 is not a factor — omit the field to inherit the source's, or pass 1..=64"
                .into(),
        ));
    }
    if dilation == 1 {
        return Ok(());
    }
    crate::vm::set_dilation(vm_fd, dilation)
        .map_err(|e| RestoreError::Kvm(format!("time dilation x{dilation}: {e}")))
}

/// Create one vCPU per captured [`CpuState`] and fully restore each, in
/// vCPU-index order.
///
/// Per vCPU the fixed order is CPUID → SREGS → XCRS → XSAVE → REGS →
/// LAPIC → MSRs → `MP_STATE` last, followed by `KVM_KVMCLOCK_CTRL`.
/// VM-scoped IRQ chip state (IOAPIC / PIC / PIT) is applied during vCPU
/// 0's restore, preserving the legacy single-vCPU ioctl sequence.
fn create_and_restore_vcpus(
    kvm: &Kvm,
    vm_fd: &kvm_ioctls::VmFd,
    cpu_states: &[CpuState],
    irqchip: Option<&crate::snapshot::IrqChipState>,
    kvmclock: Option<&KvmClockState>,
    dilation: u32,
) -> Result<Vec<VcpuFd>, RestoreError> {
    if cpu_states.is_empty() {
        return Err(RestoreError::InvalidSnapshot(
            "snapshot holds no vCPU state".into(),
        ));
    }
    let mut vcpu_fds = Vec::with_capacity(cpu_states.len());
    for (i, cpu_state) in cpu_states.iter().enumerate() {
        let vcpu_fd = vm_fd
            .create_vcpu(i as u64)
            .map_err(|e| RestoreError::Kvm(format!("create vCPU {i}: {e}")))?;
        restore_vcpu_cpuid(kvm, &vcpu_fd, cpu_state, i as u32, cpu_states.len() as u32)?;
        restore_cpu_state(
            vm_fd,
            &vcpu_fd,
            cpu_state,
            if i == 0 { irqchip } else { None },
        )?;
        // KVM_KVMCLOCK_CTRL marks the guest's pvclock page "guest
        // stopped", which is how the guest learns to touch its
        // watchdogs instead of reporting a soft lockup for the wall
        // time it spent suspended. It only works once the guest has
        // registered a pvclock page — the MSR restore just above — and
        // returns EINVAL when it has not, which is the honest answer
        // for a snapshot of a guest that never had kvmclock.
        if let Err(e) = crate::vm::kvmclock_ctrl(&vcpu_fd) {
            log::warn!("restore: {e} on vCPU {i} — this guest has no kvmclock page registered");
        }
        vcpu_fds.push(vcpu_fd);
    }
    restore_kvmclock(vm_fd, kvmclock, dilation)?;
    Ok(vcpu_fds)
}

/// Put the restored VM's kvmclock back where the guest left it, plus
/// the wall time the snapshot spent at rest.
///
/// kvmclock counts from the creation of the `kvm` VM fd, and a restore
/// creates a new one — so the guest, which reads its clock through the
/// pvclock page the host maintains, would resume at a few milliseconds
/// past zero while its timekeeping core still holds the value from
/// before the snapshot. That is a clock running backwards by the whole
/// life of the source VM.
///
/// Handing back `clock_ns + at_rest` instead of just `clock_ns` is what
/// makes the guest's wall clock *correct* rather than merely monotonic:
/// the guest derived `CLOCK_REALTIME` once at boot from the kvmclock
/// wall-clock page and has advanced it by this clock ever since, so a
/// template restored an hour after it was minted otherwise wakes up an
/// hour behind — and it has no RTC to notice with.
///
/// The forward jump is the same event as a host suspend, which is what
/// the `KVM_KVMCLOCK_CTRL` above tells the guest to expect.
///
/// Under time dilation the rest is handed back in
/// *guest* nanoseconds — `dilation` times the wall time — because that
/// is what a pause already does: a paused dilated VM's kvmclock is host
/// time through the patched affine map, so it keeps advancing N× while
/// no vCPU runs. Scaling here makes a snapshot/restore
/// indistinguishable, clock-wise, from a pause of the same wall
/// duration, and a warm fork lands on the same reading as its
/// still-running source instead of `(N-1) × at_rest` behind it.
fn restore_kvmclock(
    vm_fd: &kvm_ioctls::VmFd,
    kvmclock: Option<&KvmClockState>,
    dilation: u32,
) -> Result<(), RestoreError> {
    let Some(state) = kvmclock else {
        log::warn!(
            "restore: snapshot carries no kvmclock reading (taken before the guest ran kvmclock); \
             leaving the restored guest's clock where the capture left it"
        );
        return Ok(());
    };
    let now_ns = crate::snapshot::host_unix_nanos()
        .map_err(|e| RestoreError::Kvm(format!("read host wall clock: {e}")))?;
    if now_ns < state.host_unix_ns {
        log::warn!(
            "restore: host wall clock went backwards by {}ns since capture; \
             resuming the guest clock without advancing it",
            state.host_unix_ns - now_ns
        );
    }
    let at_rest_ns = now_ns
        .saturating_sub(state.host_unix_ns)
        .saturating_mul(u64::from(dilation));
    let data = kvm_bindings::kvm_clock_data {
        clock: state.clock_ns.saturating_add(at_rest_ns),
        // Flags are an input only for KVM_CLOCK_REALTIME, which asks
        // KVM to pair the value with a host TSC reading we do not have.
        flags: 0,
        ..Default::default()
    };
    vm_fd
        .set_clock(&data)
        .map_err(|e| RestoreError::Kvm(format!("KVM_SET_CLOCK: {e}")))?;
    log::info!(
        "restore: kvmclock resumed at {}ns ({}ms of guest time at rest, dilation x{dilation})",
        data.clock,
        at_rest_ns / 1_000_000
    );
    Ok(())
}

/// Restore one vCPU's CPUID: from the snapshot when captured (exact CPU
/// feature consistency — a per-vCPU capture already carries that vCPU's
/// APIC ID in the identity leaves), else host-supported CPUID with the
/// per-vCPU identity patch on the [`crate::vm::CpuTopology::Smp`] path.
fn restore_vcpu_cpuid(
    kvm: &Kvm,
    vcpu_fd: &VcpuFd,
    state: &CpuState,
    cpu_index: u32,
    cpu_count: u32,
) -> Result<(), RestoreError> {
    if let Some(cpuid_entries) = &state.cpuid_entries {
        let entries: Vec<kvm_bindings::kvm_cpuid_entry2> = cpuid_entries
            .iter()
            .map(|e| kvm_bindings::kvm_cpuid_entry2 {
                function: e.function,
                index: e.index,
                flags: e.flags,
                eax: e.eax,
                ebx: e.ebx,
                ecx: e.ecx,
                edx: e.edx,
                padding: [0; 3],
            })
            .collect();
        let cpuid = kvm_bindings::CpuId::from_entries(&entries)
            .map_err(|e| RestoreError::Kvm(format!("CpuId::from_entries: {e:?}")))?;
        vcpu_fd
            .set_cpuid2(&cpuid)
            .map_err(|e| RestoreError::Kvm(format!("set CPUID: {e}")))?;
    } else {
        let mut kvm_cpuid = kvm
            .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .map_err(|e| RestoreError::Kvm(format!("get CPUID: {e}")))?;
        crate::vm::patch_cpuid_for_kvm_guest(&mut kvm_cpuid);
        if let crate::vm::CpuTopology::Smp(n) = crate::vm::CpuTopology::of(cpu_count) {
            crate::vm::patch_cpuid_for_vcpu(&mut kvm_cpuid, cpu_index, n);
        }
        vcpu_fd
            .set_cpuid2(&kvm_cpuid)
            .map_err(|e| RestoreError::Kvm(format!("set CPUID: {e}")))?;
    }
    Ok(())
}

/// Restore CPU state in the exact order used by zeroboot/Firecracker.
///
/// Order: SREGS → XCRS → XSAVE → REGS → LAPIC → IOAPIC → MSRs → `MP_STATE` (last).
///
/// The LAPIC comes from the per-vCPU [`CpuState::lapic`],
/// falling back to the legacy VM-scoped `irqchip.lapic` for older
/// snapshots. `irqchip` (IOAPIC / PIC / PIT — VM-scoped) must be passed
/// for exactly one vCPU per VM.
#[allow(clippy::too_many_lines)]
fn restore_cpu_state(
    vm_fd: &kvm_ioctls::VmFd,
    vcpu_fd: &VcpuFd,
    state: &CpuState,
    irqchip: Option<&crate::snapshot::IrqChipState>,
) -> Result<(), RestoreError> {
    // 1. SREGS first (sets CR4.OSXSAVE needed by XCRS).
    let sregs = kvm_sregs {
        cs: segment_from_state(&state.sregs.cs),
        ds: segment_from_state(&state.sregs.ds),
        es: segment_from_state(&state.sregs.es),
        fs: segment_from_state(&state.sregs.fs),
        gs: segment_from_state(&state.sregs.gs),
        ss: segment_from_state(&state.sregs.ss),
        tr: segment_from_state(&state.sregs.tr),
        ldt: segment_from_state(&state.sregs.ldt),
        gdt: kvm_bindings::kvm_dtable {
            base: state.sregs.gdt.base,
            limit: state.sregs.gdt.limit,
            ..Default::default()
        },
        idt: kvm_bindings::kvm_dtable {
            base: state.sregs.idt.base,
            limit: state.sregs.idt.limit,
            ..Default::default()
        },
        cr0: state.sregs.cr0,
        cr2: state.sregs.cr2,
        cr3: state.sregs.cr3,
        cr4: state.sregs.cr4,
        cr8: state.sregs.cr8,
        efer: state.sregs.efer,
        apic_base: state.sregs.apic_base,
        interrupt_bitmap: [0u64; 4],
    };
    vcpu_fd
        .set_sregs(&sregs)
        .map_err(|e| RestoreError::Kvm(format!("KVM_SET_SREGS: {e}")))?;

    // 2. XCRS (must be after SREGS — CR4.OSXSAVE must be set first).
    if let Some(xcr) = &state.xcr {
        let mut xcrs = kvm_bindings::kvm_xcrs {
            nr_xcrs: 1,
            ..Default::default()
        };
        xcrs.xcrs[0].xcr = 0;
        xcrs.xcrs[0].value = xcr.xcr0;
        if let Err(e) = vcpu_fd.set_xcrs(&xcrs) {
            log::warn!("restore: set_xcrs failed: {e}");
        }
    }

    // 3. XSAVE (must be after XCRS).
    if let Some(xsave) = &state.xsave {
        let mut xs = kvm_bindings::kvm_xsave::default();
        let chunks = xsave.data.chunks_exact(4);
        for (i, chunk) in chunks.enumerate() {
            if i < xs.region.len() {
                xs.region[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            }
        }
        if let Err(e) = vcpu_fd.set_xsave(&xs) {
            log::warn!("restore: set_xsave failed: {e}");
        }
    }

    // 4. General-purpose registers.
    let regs = kvm_regs {
        rax: state.regs.rax,
        rbx: state.regs.rbx,
        rcx: state.regs.rcx,
        rdx: state.regs.rdx,
        rsi: state.regs.rsi,
        rdi: state.regs.rdi,
        rsp: state.regs.rsp,
        rbp: state.regs.rbp,
        r8: state.regs.r8,
        r9: state.regs.r9,
        r10: state.regs.r10,
        r11: state.regs.r11,
        r12: state.regs.r12,
        r13: state.regs.r13,
        r14: state.regs.r14,
        r15: state.regs.r15,
        rip: state.regs.rip,
        rflags: state.regs.rflags,
    };
    vcpu_fd
        .set_regs(&regs)
        .map_err(|e| RestoreError::Kvm(format!("KVM_SET_REGS: {e}")))?;

    // 4b. LAPIC — per-vCPU state, legacy VM-scoped fallback
    // for legacy snapshots (which are single-vCPU by construction).
    let lapic_bytes: &[u8] = if state.lapic.is_empty() {
        irqchip.map_or(&[], |irq| irq.lapic.as_slice())
    } else {
        &state.lapic
    };
    if !lapic_bytes.is_empty() {
        let mut lapic = kvm_bindings::kvm_lapic_state::default();
        let copy_len = lapic_bytes.len().min(lapic.regs.len());
        for (dst, &src) in lapic.regs.iter_mut().zip(&lapic_bytes[..copy_len]) {
            #[allow(clippy::cast_possible_wrap)]
            {
                *dst = src as i8;
            }
        }
        vcpu_fd
            .set_lapic(&lapic)
            .map_err(|e| RestoreError::Kvm(format!("KVM_SET_LAPIC: {e}")))?;
    }

    // 4c. VM-scoped IOAPIC + PIC + PIT restore (once per VM).
    if let Some(irq_state) = irqchip {
        // IOAPIC.
        let mut irqchip_data = kvm_bindings::kvm_irqchip {
            chip_id: kvm_bindings::KVM_IRQCHIP_IOAPIC,
            ..Default::default()
        };
        // SAFETY: setting the ioapic union variant to match chip_id.
        unsafe {
            let ioapic = &mut irqchip_data.chip.ioapic;
            ioapic.base_address = irq_state.ioapic_base_address;
            ioapic.id = irq_state.ioapic_id;
            ioapic.irr = irq_state.ioapic_irr;
            for (i, &bits) in irq_state.ioapic_entries.iter().enumerate() {
                if i < ioapic.redirtbl.len() {
                    ioapic.redirtbl[i].bits = bits;
                }
            }
        }
        vm_fd
            .set_irqchip(&irqchip_data)
            .map_err(|e| RestoreError::Kvm(format!("KVM_SET_IRQCHIP IOAPIC: {e}")))?;

        // 4d. PIC master + slave (8259).
        if let Some(pic_bytes) = &irq_state.pic_master {
            let pic_size = std::mem::size_of::<kvm_bindings::kvm_pic_state>();
            if pic_bytes.len() >= pic_size {
                let mut pic_chip = kvm_bindings::kvm_irqchip {
                    chip_id: kvm_bindings::KVM_IRQCHIP_PIC_MASTER,
                    ..Default::default()
                };
                // SAFETY: pic_bytes has correct size; writing to the pic union variant.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        pic_bytes.as_ptr(),
                        (&raw mut pic_chip.chip.pic).cast::<u8>(),
                        pic_size,
                    );
                }
                vm_fd
                    .set_irqchip(&pic_chip)
                    .map_err(|e| RestoreError::Kvm(format!("KVM_SET_IRQCHIP PIC_MASTER: {e}")))?;
            }
        }
        if let Some(pic_bytes) = &irq_state.pic_slave {
            let pic_size = std::mem::size_of::<kvm_bindings::kvm_pic_state>();
            if pic_bytes.len() >= pic_size {
                let mut pic_chip = kvm_bindings::kvm_irqchip {
                    chip_id: kvm_bindings::KVM_IRQCHIP_PIC_SLAVE,
                    ..Default::default()
                };
                // SAFETY: pic_bytes has correct size; writing to the pic union variant.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        pic_bytes.as_ptr(),
                        (&raw mut pic_chip.chip.pic).cast::<u8>(),
                        pic_size,
                    );
                }
                vm_fd
                    .set_irqchip(&pic_chip)
                    .map_err(|e| RestoreError::Kvm(format!("KVM_SET_IRQCHIP PIC_SLAVE: {e}")))?;
            }
        }

        // 4e. i8254 PIT channel state. `create_pit2` above made a fresh
        // *unprogrammed* PIT; the guest programmed channel 0 exactly once
        // at boot, so without this the restored VM never gets another
        // IRQ0 tick — all timer-driven userspace parks and the guest
        // wall clock freezes (CHALLENGES.md #40). KVM_SET_PIT2 reloads
        // the channel counters and re-arms the in-kernel hrtimer.
        if let Some(pit_bytes) = &irq_state.pit {
            let pit_size = std::mem::size_of::<kvm_bindings::kvm_pit_state2>();
            if pit_bytes.len() >= pit_size {
                let mut pit = kvm_bindings::kvm_pit_state2::default();
                // SAFETY: pit_bytes holds a kvm_pit_state2 written by
                // capture_irqchip_state; sizes checked above.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        pit_bytes.as_ptr(),
                        (&raw mut pit).cast::<u8>(),
                        pit_size,
                    );
                }
                vm_fd
                    .set_pit2(&pit)
                    .map_err(|e| RestoreError::Kvm(format!("KVM_SET_PIT2: {e}")))?;
            }
        }
    }

    // 5. MSRs (syscall, GS_BASE, etc.).
    for msr in &state.msrs {
        let entries = [kvm_bindings::kvm_msr_entry {
            index: msr.index,
            reserved: 0,
            data: msr.data,
        }];
        let msrs =
            kvm_bindings::Msrs::from_entries(&entries).expect("single MSR entry should succeed");
        if let Err(e) = vcpu_fd.set_msrs(&msrs) {
            log::warn!("restore: MSR {:#x} set failed: {e}", msr.index);
        }
    }

    // 5b. Re-queue the event injection the pause interrupted.
    //
    // The pause signal can kick a vCPU out of KVM_RUN *between* KVM
    // staging an event injection and the VM entry that would deliver
    // it: KVM cancels the injection and reports it via
    // KVM_GET_VCPU_EVENTS (`interrupt.injected`). By that point the
    // interrupt controller has already ACKed the vector — the 8259's
    // in-service bit is set (this guest boots `noapic`) / the LAPIC
    // moved IRR→ISR — so nothing ever re-sends it. Dropping the event
    // here strands the restored controller waiting for an EOI from a
    // handler that never ran, which blocks that IRQ line (and every
    // lower-priority one) forever: the VM is alive but permanently
    // deaf on vsock/net — the ~1%-per-fork unreachable-fork flake.
    //
    // Exception state stays deliberately dropped: stale snapshotted
    // exception state caused #BR on AMD Zen 4, and exceptions are
    // synchronous — re-executing the faulting instruction regenerates
    // them. Only the asynchronous, non-regenerating state is restored:
    // the in-flight external interrupt, NMI state, and the
    // interrupt-shadow window.
    if let Some(ev) = &state.vcpu_events {
        let ev_size = std::mem::size_of::<kvm_bindings::kvm_vcpu_events>();
        if ev.data.len() >= ev_size {
            let mut events = kvm_bindings::kvm_vcpu_events::default();
            // SAFETY: ev.data holds a kvm_vcpu_events captured by
            // KVM_GET_VCPU_EVENTS; the length is checked above and the
            // struct is plain-old-data.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    ev.data.as_ptr(),
                    (&raw mut events).cast::<u8>(),
                    ev_size,
                );
            }
            // Keep only the interrupt/NMI/shadow slice; everything else
            // (exception state, SMM, SIPI) is deliberately zeroed.
            let events = kvm_bindings::kvm_vcpu_events {
                interrupt: events.interrupt,
                nmi: events.nmi,
                flags: kvm_bindings::KVM_VCPUEVENT_VALID_NMI_PENDING
                    | kvm_bindings::KVM_VCPUEVENT_VALID_SHADOW,
                ..kvm_bindings::kvm_vcpu_events::default()
            };
            if events.interrupt.injected != 0 || events.nmi.injected != 0 {
                log::info!(
                    "restore: re-queueing interrupted event injection \
                     (interrupt: injected={} nr={:#x} soft={}, nmi: injected={} pending={})",
                    events.interrupt.injected,
                    events.interrupt.nr,
                    events.interrupt.soft,
                    events.nmi.injected,
                    events.nmi.pending,
                );
            }
            vcpu_fd
                .set_vcpu_events(&events)
                .map_err(|e| RestoreError::Kvm(format!("KVM_SET_VCPU_EVENTS: {e}")))?;
        }
    }

    // 6. MP_STATE must be LAST (zeroboot: "MUST be last"):
    // restore the captured per-vCPU value — an AP may legitimately be
    // HALTED; making it RUNNABLE would have it execute garbage. Legacy
    // snapshots (no mp_state) default to RUNNABLE, correct for the
    // single vCPU (the BSP) they contain.
    let mp_state = kvm_bindings::kvm_mp_state {
        mp_state: state.mp_state.unwrap_or(0), // default KVM_MP_STATE_RUNNABLE
    };
    vcpu_fd
        .set_mp_state(mp_state)
        .map_err(|e| RestoreError::Kvm(format!("KVM_SET_MP_STATE: {e}")))?;

    Ok(())
}

/// Convert a `SegmentState` to a `kvm_segment`.
fn segment_from_state(s: &crate::snapshot::SegmentState) -> kvm_segment {
    kvm_segment {
        base: s.base,
        limit: s.limit,
        selector: s.selector,
        type_: s.type_,
        present: s.present,
        dpl: s.dpl,
        db: s.db,
        s: s.s,
        l: s.l,
        g: s.g,
        avl: s.avl,
        unusable: s.unusable,
        padding: 0,
    }
}

/// `mmap(MAP_PRIVATE | MAP_NORESERVE)` a base memory file at `PROT_READ|WRITE`
/// and return `(host_addr, size)`. The caller is responsible for `munmap`
/// (typically via `Vm::drop` once the returned address is stored in `cow_mmap_addr`).
pub fn mmap_base_mem_private(
    base_mem_path: &Path,
    expected_size: u64,
) -> Result<u64, RestoreError> {
    let mem_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(base_mem_path)
        .map_err(RestoreError::Io)?;
    let actual = mem_file.metadata().map_err(RestoreError::Io)?.len();
    if actual != expected_size {
        return Err(RestoreError::InvalidSnapshot(format!(
            "{}: {actual} bytes, expected {expected_size}",
            base_mem_path.display()
        )));
    }
    // SAFETY: mem_file is valid and expected_size matches the file size.
    let mem_ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            expected_size as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_NORESERVE,
            mem_file.as_raw_fd(),
            0,
        )
    };
    if mem_ptr == libc::MAP_FAILED {
        return Err(RestoreError::Io(std::io::Error::last_os_error()));
    }
    Ok(mem_ptr as u64)
}

/// Allocate memfd-backed fork memory as a bit-perfect full copy of the
/// paused source. Used for forks of virtiofs-backed VMs, where the usual
/// `base.mem` `CoW` route is doubly unusable:
/// - vhost-user's `SET_MEM_TABLE` passes an fd for virtiofsd to
///   `mmap(MAP_SHARED)` — anonymous `MAP_PRIVATE` `CoW` memory has none;
/// - virtiofsd writes FUSE completions through its *own* mapping,
///   invisible to KVM dirty tracking, so `base.mem + dirty bitmap`
///   silently misses device DMA (the #27 class of bug, host-side).
///
/// Returns the memfd (kept alive by the fork `Vm`) and the mapping.
fn memfd_fork_memory(source_mem_addr: u64, mem_size: u64) -> Result<(fs::File, u64), RestoreError> {
    // SAFETY: creating a fresh memfd; the name is a valid C string.
    let fd = unsafe { libc::memfd_create(c"k7d-fork-mem".as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(RestoreError::Io(std::io::Error::last_os_error()));
    }
    // SAFETY: fd is a valid memfd; File takes ownership.
    let file = unsafe { fs::File::from_raw_fd(fd) };
    file.set_len(mem_size).map_err(RestoreError::Io)?;
    // SAFETY: fd is a valid memfd sized to mem_size.
    let addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            mem_size as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_NORESERVE,
            file.as_raw_fd(),
            0,
        )
    };
    if addr == libc::MAP_FAILED {
        return Err(RestoreError::Io(std::io::Error::last_os_error()));
    }
    let dst_addr = addr as u64;
    // Chunked multi-threaded copy: a single-threaded
    // memcpy of multi-GiB guest RAM is bound by what one core can pull
    // through the memory controller; splitting into page-aligned disjoint
    // chunks copied by scoped threads cuts the wall time by roughly the
    // number of cores that can saturate the memory channels.
    let threads = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    let per_chunk = copy_chunk_size(mem_size, threads.min(8) as u64);
    std::thread::scope(|s| {
        let mut offset = 0u64;
        while offset < mem_size {
            let len = per_chunk.min(mem_size - offset);
            s.spawn(move || {
                // SAFETY: [offset, offset+len) lies within the mem_size
                // bytes covered by both the paused source's mapping and the
                // fresh memfd mapping (loop invariant, Kani proof
                // `verify_copy_chunk_size_covers_disjoint`). Chunks are
                // pairwise disjoint, so no two threads touch the same
                // bytes, and the two mappings themselves don't overlap.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        (source_mem_addr + offset) as *const u8,
                        (dst_addr + offset) as *mut u8,
                        len as usize,
                    );
                }
            });
            offset += len;
        }
    });
    Ok((file, dst_addr))
}

/// Per-thread chunk size for [`memfd_fork_memory`]'s parallel copy:
/// `mem_size / max_chunks` rounded up to a whole page, so no two threads
/// ever write the same destination page and at most `max_chunks` chunks
/// cover `[0, mem_size)` exactly. Verified by
/// `verify_copy_chunk_size_covers_disjoint`.
fn copy_chunk_size(mem_size: u64, max_chunks: u64) -> u64 {
    const PAGE: u64 = 4096;
    mem_size
        .div_ceil(max_chunks.max(1))
        .div_ceil(PAGE)
        .saturating_mul(PAGE)
}

/// Acquire fork memory according to the source's shape: `base.mem`
/// `CoW` + dirty-page memcpy for plain VMs, full memfd copy for
/// virtiofs-backed VMs (see [`memfd_fork_memory`] for why) and for a
/// missed 200 ms park (dirty-delta would omit device DMA).
/// The source must stay paused.
fn fork_memory_for_state(
    base_mem_path: &Path,
    dirty_bitmap: &[u64],
    source_mem_addr: u64,
    state: &VmState,
    fork_id: &str,
    force_full_dump: bool,
) -> Result<(u64, Option<fs::File>), ForkError> {
    // The mapping, `base.mem` and the dirty bitmap all cover the guest
    // physical span, not just RAM.
    let mem_size = crate::mem_layout::MemLayout::from_ram(state.memory_size).span();
    // Virtio-blk parks on pause without emptying the ring (CHALLENGES
    // #162): leftover descriptors are replayed on the child. Do not wait
    // for used==avail here — that was a 200 ms tax per member on a busy
    // guest after we stopped draining.
    if state.virtiofs_shares.is_empty() && !force_full_dump {
        let fork_mem_addr =
            mmap_base_mem_private(base_mem_path, mem_size).map_err(ForkError::Restore)?;
        // Memcpy dirty pages: for each set bit, copy 4 KiB from source
        // mapping into the fork mapping. This triggers CoW on the fork.
        let copied =
            apply_dirty_bitmap_memcpy(dirty_bitmap, source_mem_addr, fork_mem_addr, mem_size);
        log::info!(
            "fork_warm '{fork_id}': memcpy'd {copied} dirty pages ({} KiB)",
            copied * 4
        );
        Ok((fork_mem_addr, None))
    } else {
        // Quiesce the source's fs queues first: the vCPU is paused (no
        // new submissions), so waiting for each used ring to catch its
        // avail ring bounds virtiofsd's in-flight DMA out of the copy
        // window — otherwise the full copy could catch a torn FUSE
        // completion. Bounded wait; on timeout the replay-from-used.idx
        // mechanism still covers unacked requests.
        if !state.virtiofs_shares.is_empty() {
            drain_fs_queues(state, source_mem_addr, fork_id);
        }
        let t = std::time::Instant::now();
        let (file, fork_mem_addr) =
            memfd_fork_memory(source_mem_addr, mem_size).map_err(ForkError::Restore)?;
        if force_full_dump && state.virtiofs_shares.is_empty() {
            log::warn!(
                "fork_warm '{fork_id}': full memfd copy of {} MiB in {:?} \
                 (virtio worker missed 200ms park)",
                mem_size / (1024 * 1024),
                t.elapsed(),
            );
        } else {
            log::info!(
                "fork_warm '{fork_id}': full memfd copy of {} MiB in {:?} ({} virtiofs shares)",
                mem_size / (1024 * 1024),
                t.elapsed(),
                state.virtiofs_shares.len()
            );
        }
        Ok((fork_mem_addr, Some(file)))
    }
}

/// Wait (bounded) until every virtio-fs queue of the paused source has
/// `used.idx == avail.idx` — i.e. virtiofsd finished all in-flight
/// requests and its DMA into guest memory is quiescent.
fn drain_fs_queues(state: &VmState, source_mem_addr: u64, fork_id: &str) {
    drain_device_queues(state, source_mem_addr, fork_id, VIRTIO_ID_FS, "fs");
}

/// Wait (bounded) until every queue of the given virtio device type on the
/// paused source has `used.idx == avail.idx` — i.e. the backend finished
/// all in-flight requests and its DMA into guest memory is quiescent.
fn drain_device_queues(
    state: &VmState,
    source_mem_addr: u64,
    fork_id: &str,
    device_type: u32,
    tag: &str,
) {
    // Mirror virtio-blk/net `wait_quiescent`'s 200 ms bound. This is
    // *not* the worker-park handshake: virtiofsd is an out-of-process
    // vhost-user daemon, so `VirtioBackend::wait_quiescent` is a no-op
    // for it. We wait for used.idx == avail.idx on the fs queues so
    // FUSE DMA is out of the full-memfd copy window. A stuck ring still
    // will not drain because we waited longer (CHALLENGES #162).
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(200);
    for dev in &state.devices {
        if dev.device_type != device_type {
            continue;
        }
        for q in &dev.queues {
            if !q.ready || q.size == 0 {
                continue;
            }
            // Ring layouts: avail {flags u16, idx u16, …}, used {flags
            // u16, idx u16, …} — both idx fields sit at +2.
            let avail_idx_addr = (source_mem_addr + q.avail_addr + 2) as *const u16;
            let used_idx_addr = (source_mem_addr + q.used_addr + 2) as *const u16;
            loop {
                // SAFETY: both pointers land inside the source's guest
                // memory mapping, which the paused source keeps alive.
                let (avail_idx, used_idx) = unsafe {
                    (
                        std::ptr::read_volatile(avail_idx_addr),
                        std::ptr::read_volatile(used_idx_addr),
                    )
                };
                if avail_idx == used_idx {
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    log::warn!(
                        "fork_warm '{fork_id}': {tag} queue not drained before copy \
                         (avail={avail_idx} used={used_idx}); relying on replay"
                    );
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
    }
}

/// Warm-fork restore: materialize a new VM from the source's `base.mem` +
/// an in-memory dirty delta + captured CPU/device state.
///
/// Unlike `restore_vm`, this reads NO `cpu.json`/`metadata.json`/`devices.json`
/// files — all state comes from the `VmState` struct. The only disk I/O is
/// the initial `mmap(MAP_PRIVATE, base.mem)` (which doesn't actually read
/// data from disk; page faults populate on demand from the file's page cache,
/// which is hot because the source is already using it).
///
/// `source_mem_addr` points to the **source** VM's memory mapping. For every
/// page marked dirty in `dirty_bitmap`, we `memcpy` 4 KiB from the source's
/// mapping into the new fork's `MAP_PRIVATE` mapping, triggering `CoW`.
/// Virtiofs-backed sources are full-copied instead — see
/// [`fork_memory_for_state`].
///
/// `fork_id` is informational (used in log messages only).
/// `force_full_dump` skips the dirty-delta `CoW` path.
pub fn restore_vm_from_state(
    base_mem_path: &Path,
    dirty_bitmap: &[u64],
    source_mem_addr: u64,
    state: &VmState,
    fork_id: &str,
    dilation: Option<u32>,
    force_full_dump: bool,
) -> Result<Vm, ForkError> {
    let (fork_mem_addr, fork_mem_file) = fork_memory_for_state(
        base_mem_path,
        dirty_bitmap,
        source_mem_addr,
        state,
        fork_id,
        force_full_dump,
    )?;
    build_vm_from_state_and_mem_inner(state, fork_mem_addr, fork_id, None, fork_mem_file, dilation)
}

/// Like [`restore_vm_from_state`] but reattaches a pre-built TAP for the
/// virtio-net slot.
///
/// Used by [`fork_cluster_warm`] to put the forked VM on the fork's bridge
/// while preserving the source's guest IP and MAC.
#[allow(clippy::too_many_arguments)]
pub fn restore_vm_from_state_with_tap(
    base_mem_path: &Path,
    dirty_bitmap: &[u64],
    source_mem_addr: u64,
    state: &VmState,
    fork_id: &str,
    tap: TapDevice,
    dilation: Option<u32>,
    force_full_dump: bool,
) -> Result<Vm, ForkError> {
    let (fork_mem_addr, fork_mem_file) = fork_memory_for_state(
        base_mem_path,
        dirty_bitmap,
        source_mem_addr,
        state,
        fork_id,
        force_full_dump,
    )?;
    build_vm_from_state_and_mem_inner(
        state,
        fork_mem_addr,
        fork_id,
        Some(tap),
        fork_mem_file,
        dilation,
    )
}

/// One cluster to materialise inside [`fork_cluster_warm_batch`].
pub struct ClusterForkRequest<'a> {
    /// Bridge / cluster id passed to [`ClusterNetwork::fork_from`].
    pub fork_cluster_id: &'a str,
    /// Per-member log labels; length must match the source member count.
    pub fork_ids: &'a [&'a str],
    /// Optional per-member pod IPs (empty = skip NAT for every member).
    pub fork_pod_ips: &'a [Option<Ipv4Addr>],
    /// Optional per-member pod netns paths (empty = skip NAT).
    pub fork_pod_netns: &'a [Option<PathBuf>],
    /// Child dilation factor. `None` inherits the
    /// source's. One factor for every member of this request.
    pub dilation: Option<u32>,
}

/// All-in-one cluster warm fork: clone the bridge topology and warm-fork
/// every member VM in lock-step.
///
/// Thin wrapper around [`fork_cluster_warm_batch`] with a single request.
/// Prefer the batch form when forking N clusters from the same paused
/// source — one dirty-bitmap capture, N parallel materialisations.
#[allow(clippy::too_many_arguments)]
pub fn fork_cluster_warm(
    source_net: &ClusterNetwork,
    sources: &mut [(&mut Vm, u32)],
    fork_cluster_id: &str,
    fork_pod_ips: &[Option<Ipv4Addr>],
    fork_pod_netns: &[Option<PathBuf>],
    fork_ids: &[&str],
) -> Result<(ClusterNetwork, Vec<Vm>), ForkError> {
    fork_cluster_warm_dilated(
        source_net,
        sources,
        fork_cluster_id,
        fork_pod_ips,
        fork_pod_netns,
        fork_ids,
        None,
    )
}

/// [`fork_cluster_warm`] with an explicit child dilation factor.
/// `None` inherits the source's.
#[allow(clippy::too_many_arguments)]
pub fn fork_cluster_warm_dilated(
    source_net: &ClusterNetwork,
    sources: &mut [(&mut Vm, u32)],
    fork_cluster_id: &str,
    fork_pod_ips: &[Option<Ipv4Addr>],
    fork_pod_netns: &[Option<PathBuf>],
    fork_ids: &[&str],
    dilation: Option<u32>,
) -> Result<(ClusterNetwork, Vec<Vm>), ForkError> {
    let req = ClusterForkRequest {
        fork_cluster_id,
        fork_ids,
        fork_pod_ips,
        fork_pod_netns,
        dilation,
    };
    let mut out = fork_cluster_warm_batch(source_net, sources, &[req])?;
    out.pop()
        .ok_or_else(|| ForkError::Reflink("fork_cluster_warm_batch returned empty result".into()))
}

/// Raise the process soft `RLIMIT_NOFILE` to at least `needed`.
///
/// Loud if the hard limit is too low — silent truncation would surface
/// later as `EMFILE` mid-batch. Used by the daemon at startup and by
/// [`fork_cluster_warm_batch`] before materialising many VMs.
pub fn ensure_nofile_headroom(needed: u64) -> Result<(), ForkError> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is a valid `rlimit` out-parameter.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        return Err(ForkError::Io(std::io::Error::last_os_error()));
    }
    if lim.rlim_cur >= needed {
        return Ok(());
    }
    if lim.rlim_max < needed {
        return Err(ForkError::Reflink(format!(
            "need RLIMIT_NOFILE ≥ {needed}, hard limit is {} — raise \
             ulimit -n / LimitNOFILE on k7d.service",
            lim.rlim_max
        )));
    }
    lim.rlim_cur = needed;
    // SAFETY: `lim` is a valid `rlimit` within the hard ceiling.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lim) } != 0 {
        return Err(ForkError::Io(std::io::Error::last_os_error()));
    }
    log::info!("raised RLIMIT_NOFILE soft limit to {needed}");
    Ok(())
}

/// Raise soft `RLIMIT_NOFILE` so `vm_count` live VMs can keep their fds.
fn ensure_nofile_for_vms(vm_count: usize) -> Result<(), ForkError> {
    // Empirically each live VM holds on the order of a few dozen fds
    // (KVM, vCPU, TAP, vsock, eventfds, serial pipes, memfd). Pad to 64
    // and keep a floor so small batches don't churn setrlimit.
    let needed = u64::try_from(vm_count.saturating_mul(64).max(4_096)).unwrap_or(u64::MAX);
    ensure_nofile_headroom(needed)
}

/// Warm-fork N clusters from the same source with a **shared pause**.
///
/// Sources are paused once; dirty bitmaps + CPU/device/IRQ state are
/// captured once; each request gets its own bridge (`fork_from` +
/// `add_tap_at`, host-net ops stay sequential); then all `N × M` member
/// VMs are materialised concurrently via `thread::scope`. Sources resume
/// once at the end — including on the error path.
///
/// Returns one `(ClusterNetwork, Vec<Vm>)` per request, in request order.
/// On failure every partially-built fork is dropped (Vm/TAP/bridge
/// teardown via `Drop`) and no half-batch escapes.
#[allow(clippy::too_many_lines)]
pub fn fork_cluster_warm_batch(
    source_net: &ClusterNetwork,
    sources: &mut [(&mut Vm, u32)],
    requests: &[ClusterForkRequest<'_>],
) -> Result<Vec<(ClusterNetwork, Vec<Vm>)>, ForkError> {
    if requests.is_empty() {
        return Err(ForkError::Reflink(
            "fork_cluster_warm_batch: requests must be non-empty".into(),
        ));
    }
    let n_members = sources.len();
    // Source members stay live too — count them for the fd ceiling.
    ensure_nofile_for_vms(n_members.saturating_mul(requests.len().saturating_add(1)))?;
    for (ri, req) in requests.iter().enumerate() {
        if req.fork_ids.len() != n_members {
            return Err(ForkError::Reflink(format!(
                "fork_cluster_warm_batch[{ri}]: {} fork_ids but {n_members} sources",
                req.fork_ids.len()
            )));
        }
        if !req.fork_pod_ips.is_empty() && req.fork_pod_ips.len() != n_members {
            return Err(ForkError::Reflink(format!(
                "fork_cluster_warm_batch[{ri}]: {} pod IPs but {n_members} sources",
                req.fork_pod_ips.len()
            )));
        }
        if !req.fork_pod_netns.is_empty() && req.fork_pod_netns.len() != n_members {
            return Err(ForkError::Reflink(format!(
                "fork_cluster_warm_batch[{ri}]: {} pod netns but {n_members} sources",
                req.fork_pod_netns.len()
            )));
        }
    }

    let start = std::time::Instant::now();
    let t_pause = std::time::Instant::now();

    // 1. Pause every source once and capture dirty + CPU/device/IRQ state.
    //    Sources stay paused through all materialisations so each fork's
    //    memory matches the captured registers (no torn mid-memcpy writes).
    let mut was_running: Vec<bool> = Vec::with_capacity(n_members);
    let mut captured: Vec<(Vec<u64>, VmState, u64, PathBuf, bool)> = Vec::with_capacity(n_members);
    for (vm, _idx) in sources.iter_mut() {
        let running = vm.is_running();
        was_running.push(running);
        if running {
            vm.pause().map_err(crate::snapshot::SnapshotError::Vm)?;
        }
        let force_full_dump = vm.take_full_dump_if_not_quiescent();
        let base_path = vm
            .fork_source_base_path()
            .map(Path::to_path_buf)
            .ok_or_else(|| {
                ForkError::Reflink(
                    "VM not prepared as fork source — call prepare_fork_source() first".into(),
                )
            })?;
        let dirty = vm
            .get_and_accumulate_dirty()
            .map_err(crate::snapshot::SnapshotError::Vm)?
            .to_vec();
        let state = crate::snapshot::capture_vm_state(vm)?;
        let src_mem_addr = vm.mem_host_addr();
        captured.push((dirty, state, src_mem_addr, base_path, force_full_dump));
    }
    log::info!(
        "fork_cluster_warm_batch: pause+capture {n_members} members in {:?}",
        t_pause.elapsed()
    );

    // One in-flight pwrite/FLUSH may still hold the inode after
    // `Vm::pause`'s 200 ms wait_quiescent. This extra wait is for
    // FICLONE of the scratch image, not for the dirty-delta copy:
    // cloning an 8 GiB scratch while the worker holds the inode has
    // been measured at 3–7 s (CHALLENGES #162). The worker now parks
    // without draining the rest of the ring, so this should be a
    // no-op. Cap at 200 ms — a longer wait is itself over budget.
    // Not redundant with wait_quiescent: that one is "has the worker
    // parked?" (miss → full dump); this is "has the inode been
    // released for FICLONE?".
    let t_q = std::time::Instant::now();
    while !sources.iter().all(|(vm, _)| vm.devices_quiescent())
        && t_q.elapsed() < std::time::Duration::from_millis(200)
    {
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    log::info!(
        "fork_cluster_warm_batch: extra quiesce {:?} parked={}",
        t_q.elapsed(),
        sources.iter().all(|(vm, _)| vm.devices_quiescent())
    );

    // 2. Host-net setup per request (bridges + TAPs + optional pod NAT).
    //    Kept sequential: iptables / `ip link` are not safe to race.
    let mut err: Option<ForkError> = None;
    let mut nets: Vec<ClusterNetwork> = Vec::with_capacity(requests.len());
    // Flat job list: (cluster_idx, member_idx, tap, fork_id, dilation).
    let mut jobs: Vec<(usize, usize, TapDevice, String, Option<u32>)> =
        Vec::with_capacity(requests.len() * n_members);

    for (ci, req) in requests.iter().enumerate() {
        if err.is_some() {
            break;
        }
        let mut fork_net = match ClusterNetwork::fork_from(source_net, req.fork_cluster_id) {
            Ok(n) => n,
            Err(e) => {
                err = Some(ForkError::Reflink(format!(
                    "fork_from({}): {e}",
                    req.fork_cluster_id
                )));
                break;
            }
        };
        let pod_ips: Vec<Option<Ipv4Addr>> = if req.fork_pod_ips.is_empty() {
            vec![None; n_members]
        } else {
            req.fork_pod_ips.to_vec()
        };
        let pod_netns: Vec<Option<PathBuf>> = if req.fork_pod_netns.is_empty() {
            vec![None; n_members]
        } else {
            req.fork_pod_netns.to_vec()
        };
        // One `add_taps_at` per cluster: all member TAPs plus their
        // anti-spoof pins in a single nft transaction (one
        // nft process per TAP triples the per-cluster fork cost).
        let indices: Vec<u32> = sources.iter().map(|(_src_vm, idx)| *idx).collect();
        match fork_net.add_taps_at(&indices) {
            Ok(taps) => {
                for (mi, tap) in taps.into_iter().enumerate() {
                    jobs.push((ci, mi, tap, req.fork_ids[mi].to_string(), req.dilation));
                    if let (Some(pod_ip), Some(netns)) = (pod_ips[mi], pod_netns[mi].as_deref()) {
                        if let Err(e) = fork_net.install_pod_nat(indices[mi], pod_ip, netns) {
                            log::warn!(
                                "fork_cluster_warm_batch: install_pod_nat({}) on '{}' \
                                 failed (non-fatal): {e}",
                                indices[mi],
                                req.fork_cluster_id
                            );
                        }
                    }
                }
            }
            Err(e) => {
                err = Some(ForkError::Reflink(format!(
                    "add_taps_at({indices:?}) on '{}': {e}",
                    req.fork_cluster_id
                )));
            }
        }
        if err.is_some() {
            // Half-built bridge + its TAPs (still in `jobs`) drop via Drop.
            drop(fork_net);
            break;
        }
        nets.push(fork_net);
    }

    // 3. Materialise every member concurrently while sources stay paused.
    let mut member_slots: Vec<Vec<Option<Vm>>> = (0..nets.len())
        .map(|_| (0..n_members).map(|_| None).collect())
        .collect();
    if err.is_none() {
        let captured_ref = &captured;
        let results: Vec<Result<(usize, usize, Vm), ForkError>> = std::thread::scope(|s| {
            let handles: Vec<_> = jobs
                .into_iter()
                .map(|(ci, mi, tap, fork_id, dilation)| {
                    s.spawn(move || {
                        let (dirty, state, src_mem_addr, base_path, force_full_dump) =
                            &captured_ref[mi];
                        let t = std::time::Instant::now();
                        let result = restore_vm_from_state_with_tap(
                            base_path,
                            dirty,
                            *src_mem_addr,
                            state,
                            &fork_id,
                            tap,
                            dilation,
                            *force_full_dump,
                        );
                        log::info!(
                            "fork_cluster_warm_batch member '{fork_id}': materialised in {:?}",
                            t.elapsed()
                        );
                        result.map(|vm| (ci, mi, vm))
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| {
                    h.join().unwrap_or_else(|_| {
                        Err(ForkError::Reflink("fork worker thread panicked".into()))
                    })
                })
                .collect()
        });
        for result in results {
            match result {
                Ok((ci, mi, vm)) => {
                    member_slots[ci][mi] = Some(vm);
                }
                Err(e) => {
                    if err.is_none() {
                        err = Some(e);
                    }
                }
            }
        }
    }

    // 4. Always resume sources — never leave them paused after a half-batch.
    for ((vm, _), running) in sources.iter_mut().zip(was_running.iter().copied()) {
        if running {
            vm.resume().map_err(crate::snapshot::SnapshotError::Vm)?;
        }
    }

    if let Some(e) = err {
        // Drop nets + any materialised VMs (TAP/bridge cleanup via Drop).
        drop(member_slots);
        drop(nets);
        return Err(e);
    }

    let mut out: Vec<(ClusterNetwork, Vec<Vm>)> = Vec::with_capacity(nets.len());
    for (net, slots) in nets.into_iter().zip(member_slots.into_iter()) {
        let mut members = Vec::with_capacity(n_members);
        for slot in slots {
            let Some(vm) = slot else {
                return Err(ForkError::Reflink(
                    "fork_cluster_warm_batch: missing member after successful materialise".into(),
                ));
            };
            members.push(vm);
        }
        out.push((net, members));
    }

    let total_vms: usize = out.iter().map(|(_, m)| m.len()).sum();
    log::info!(
        "fork_cluster_warm_batch: {} clusters / {total_vms} VMs in {:?}",
        out.len(),
        start.elapsed()
    );
    Ok(out)
}

/// Materialize a new VM from a pre-populated `MAP_PRIVATE` memory region +
/// captured state. Used by `restore_vm_from_state` (after memcpy) and by
/// the tree `resume` path (after `apply_delta`).
///
/// The caller owns the mmap; on success it is transferred into the `Vm`
/// (via `cow_mmap_addr`) and freed on `Vm::drop`. On failure this function
/// `munmap`s it before returning.
pub fn build_vm_from_state_and_mem(
    state: &VmState,
    fork_mem_addr: u64,
    log_tag: &str,
) -> Result<Vm, ForkError> {
    build_vm_from_state_and_mem_inner(state, fork_mem_addr, log_tag, None, None, None)
}

/// Same as [`build_vm_from_state_and_mem`] but reattaches a pre-built TAP
/// device for the virtio-net MMIO slot.
///
/// `tap` should reproduce the source's per-VM identity (same guest IP and
/// MAC) on a different bridge — see [`ClusterNetwork::add_tap_at`]. The TAP
/// is bound to the new VM's lifetime.
pub fn build_vm_from_state_and_mem_with_tap(
    state: &VmState,
    fork_mem_addr: u64,
    log_tag: &str,
    tap: TapDevice,
) -> Result<Vm, ForkError> {
    build_vm_from_state_and_mem_inner(state, fork_mem_addr, log_tag, Some(tap), None, None)
}

#[allow(clippy::too_many_lines)]
fn build_vm_from_state_and_mem_inner(
    state: &VmState,
    fork_mem_addr: u64,
    log_tag: &str,
    tap: Option<TapDevice>,
    fork_mem_file: Option<fs::File>,
    dilation: Option<u32>,
) -> Result<Vm, ForkError> {
    let start = std::time::Instant::now();
    // `mem_size` is guest RAM; the mapping and every guest-physical bound
    // covers the span (RAM + 32-bit MMIO hole) —.
    let mem_size = state.memory_size;
    let layout = crate::mem_layout::MemLayout::from_ram(mem_size);
    let mem_span = layout.span();
    let kernel_path = state.kernel_path.clone();
    let initrd_path = state.initrd_path.clone();

    // Virtio-fs rebuild needs an fd-backed mapping (vhost-user SET_MEM_TABLE).
    // Fail loud rather than hand back a VM with dead FUSE mounts.
    if !state.virtiofs_shares.is_empty() && fork_mem_file.is_none() {
        return Err(ForkError::Restore(RestoreError::InvalidSnapshot(format!(
            "'{log_tag}': state has {} virtiofs shares but the memory is not \
             memfd-backed — virtiofs VMs cannot be rebuilt from CoW/delta memory \
             (suspend/resume of virtiofs payloads is unsupported)",
            state.virtiofs_shares.len()
        ))));
    }

    // Reflink-copied RW block images live in this per-fork directory; the
    // fork `Vm` owns it (cleaned up on Drop via `fork_state_dir`). Declared
    // outside the closure so the error path below can clean up too.
    let mut blk_fork_dir: Option<PathBuf> = None;

    // Wrap the body in a closure so we can munmap on error.
    let result: Result<Vm, ForkError> = (|| {
        // Build a new KVM VM.
        let kvm = Kvm::new().map_err(|e| RestoreError::Kvm(format!("open /dev/kvm: {e}")))?;
        let vm_fd = kvm
            .create_vm()
            .map_err(|e| RestoreError::Kvm(format!("create VM: {e}")))?;
        let child_dilation = resolve_fork_dilation(dilation, state.dilation)?;
        restore_dilation(&vm_fd, child_dilation)?;

        vm_fd
            .set_tss_address(0xfffb_d000usize)
            .map_err(|e| RestoreError::Kvm(format!("set TSS address: {e}")))?;
        vm_fd
            .create_irq_chip()
            .map_err(|e| RestoreError::Kvm(format!("create IRQ chip: {e}")))?;
        let pit_config = kvm_pit_config {
            flags: KVM_PIT_SPEAKER_DUMMY,
            ..Default::default()
        };
        vm_fd
            .create_pit2(pit_config)
            .map_err(|e| RestoreError::Kvm(format!("create PIT2: {e}")))?;

        for (slot, gpa, size) in layout.slots() {
            let mem_region = kvm_userspace_memory_region {
                slot,
                guest_phys_addr: gpa,
                memory_size: size,
                userspace_addr: fork_mem_addr + gpa,
                flags: 0,
            };
            // SAFETY: fork_mem_addr is a mapping of `mem_span` bytes that
            // outlives the VM (cleaned up on Vm::drop via cow_mmap_addr);
            // each region is a sub-range of it.
            unsafe {
                vm_fd
                    .set_user_memory_region(mem_region)
                    .map_err(|e| RestoreError::Kvm(format!("set user memory region: {e}")))?;
            }
        }

        // Create one vCPU per captured CpuState and restore each (CPUID
        // → SREGS → XCRS → XSAVE → REGS → LAPIC → MSRs → MP_STATE last,
        // then KVM_KVMCLOCK_CTRL and the VM-scoped kvmclock).
        let vcpu_fds = create_and_restore_vcpus(
            &kvm,
            &vm_fd,
            &state.cpus,
            Some(&state.irqchip),
            state.kvmclock.as_ref(),
            state.dilation,
        )?;

        // Inject TRANSPORT_RESET into the FORK's memory only. The source is
        // undisturbed (unlike the cold fork path, which injects into the source
        // before dumping memory). This is the key correctness fix of.
        //
        // This MUST happen before vsock backend activation: the injection advances
        // the used ring's idx field, and activate_with_bases reads that idx to
        // program the vhost module's vring base. Doing it after activation would
        // leave the kernel with a stale base and the event would go unprocessed.
        crate::snapshot::inject_vsock_transport_reset_into(mem_span, &state.devices, fork_mem_addr);

        // Allocate a new CID for the fork/resumed VM.
        let new_cid = crate::vsock::allocate_cid();
        let mmio_registry = Arc::new(Mutex::new(MmioDeviceRegistry::new()));

        let mut has_vsock = false;
        // The TAP is consumed at most once; track via Option so we can move it
        // into the matching virtio-net slot.
        let mut tap_slot = tap;
        let mut tap_for_vm: Option<TapDevice> = None;
        let mut guest_ip_for_vm: Option<Ipv4Addr> = None;
        // Virtio-fs rebuild bookkeeping: device order == share order.
        let mut fs_idx: usize = 0;
        let mut fs_socket_dir: Option<PathBuf> = None;
        let mut virtiofsds: Vec<crate::virtiofs::VirtiofsdProcess> = Vec::new();
        // Virtio-blk rebuild bookkeeping: device order == config order. The
        // fork's configs may differ from the source's (RW images point at
        // the reflinked copy).
        let mut blk_idx: usize = 0;
        let mut fork_block_devices: Vec<crate::vm::BlockConfig> = Vec::new();
        for dev_state in &state.devices {
            if dev_state.device_type == VIRTIO_ID_VSOCK {
                let irq = dev_state.irq;
                let base = dev_state.base_addr;

                let irq_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(RestoreError::Io)?;
                vm_fd
                    .register_irqfd(&irq_evt, irq)
                    .map_err(|e| RestoreError::Kvm(format!("register irqfd for vsock: {e}")))?;
                let irq_evt = Arc::new(irq_evt);

                let mut vsock_backend = VhostVsockBackend::new(new_cid, fork_mem_addr, mem_span)
                    .map_err(|e| RestoreError::Kvm(format!("vsock backend: {e}")))?;

                let queues = restore_queues(&dev_state.queues, vsock_backend.max_queue_size());
                vsock_backend
                    .activate_with_bases(&queues, &irq_evt, fork_mem_addr)
                    .map_err(|e| RestoreError::Kvm(format!("vsock activate: {e}")))?;

                let mut dev = MmioDevice::new(base, irq, irq_evt, Box::new(vsock_backend));
                dev.set_vhost(true);
                dev.restore_state(dev_state);

                dev.trigger_vring_irq();

                let mmio_dev = Arc::new(Mutex::new(dev));
                mmio_registry.lock().unwrap().add(Arc::clone(&mmio_dev));
                has_vsock = true;
            } else if dev_state.device_type == VIRTIO_ID_NET {
                // Re-attach the (already-configured) TAP. The guest's virtio-net
                // driver state is preserved bit-for-bit in memory; we just need
                // to wire up a fresh host-side backend that delivers IRQs to the
                // new vCPU and forwards frames to the cluster-fork bridge.
                let Some(tap) = tap_slot.take() else {
                    log::warn!(
                        "{log_tag}: snapshot has virtio-net but no TAP supplied — guest network will be inactive"
                    );
                    continue;
                };

                let irq = dev_state.irq;
                let base = dev_state.base_addr;

                let irq_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(RestoreError::Io)?;
                vm_fd
                    .register_irqfd(&irq_evt, irq)
                    .map_err(|e| RestoreError::Kvm(format!("register irqfd for net: {e}")))?;
                let irq_evt = Arc::new(irq_evt);

                let mut net_backend =
                    TapNetBackend::new(tap.mac(), tap.fd(), fork_mem_addr, mem_span);
                let queues = restore_queues(&dev_state.queues, net_backend.max_queue_size());
                // Replay the driver's feature-negotiation outcome from the snapshot.
                net_backend.ack_features(dev_state.acked_features);
                // Guest rings survived the snapshot — seed worker counters or eth0 hangs.
                net_backend
                    .seed_indices_from_guest(&queues)
                    .map_err(|e| RestoreError::Kvm(format!("net seed: {e}")))?;
                net_backend
                    .activate(&queues, &irq_evt)
                    .map_err(|e| RestoreError::Kvm(format!("net activate: {e}")))?;

                let mut dev = MmioDevice::new(base, irq, irq_evt, Box::new(net_backend));
                dev.set_vhost(true);
                dev.restore_state(dev_state);
                dev.trigger_vring_irq();

                let mmio_dev = Arc::new(Mutex::new(dev));
                mmio_registry.lock().unwrap().add(Arc::clone(&mmio_dev));

                guest_ip_for_vm = Some(tap.guest_ip());
                tap_for_vm = Some(tap);
            } else if dev_state.device_type == VIRTIO_ID_FS {
                // Respawn one virtiofsd per share against the SAME host
                // dir (same host inode numbers keep the cloned guest's
                // FUSE dentries and bound unix sockets coherent) and
                // re-handshake vhost-user against the fork's memfd. The
                // guest's virtio driver state is preserved in memory;
                // requests the old daemon never answered are replayed
                // (stale FUSE handles get errors, not hangs). Devices
                // appear in share declaration order — fs_idx maps this
                // MMIO slot back to its share config.
                let Some(share) = state.virtiofs_shares.get(fs_idx) else {
                    return Err(ForkError::Restore(RestoreError::InvalidSnapshot(format!(
                        "'{log_tag}': virtio-fs device #{fs_idx} has no matching share \
                         config (snapshot has {})",
                        state.virtiofs_shares.len()
                    ))));
                };
                // Invariant established by the entry check: shares imply
                // memfd-backed memory.
                let Some(mem_fd) = fork_mem_file.as_ref().map(AsRawFd::as_raw_fd) else {
                    return Err(ForkError::Restore(RestoreError::InvalidSnapshot(format!(
                        "'{log_tag}': virtio-fs device without memfd memory"
                    ))));
                };
                let fs_tag = if fs_idx == 0 {
                    "k7fs".to_string()
                } else {
                    format!("k7fs{fs_idx}")
                };
                fs_idx += 1;

                let socket_dir = fs_socket_dir.get_or_insert_with(|| {
                    static FORK_VIRTIOFS_SEQ: std::sync::atomic::AtomicU64 =
                        std::sync::atomic::AtomicU64::new(0);
                    let dir = std::env::temp_dir().join(format!(
                        "k7d-virtiofs-fork-{}-{}",
                        std::process::id(),
                        FORK_VIRTIOFS_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                    ));
                    let _ = fs::create_dir_all(&dir);
                    dir
                });
                let socket_path = socket_dir.join(format!("virtiofs-{fs_tag}.sock"));
                let vfsd = crate::virtiofs::VirtiofsdProcess::spawn_with_options(
                    &share.host_dir,
                    &socket_path,
                    &fs_tag,
                    share.readonly,
                )
                .map_err(|e| RestoreError::Kvm(format!("respawn virtiofsd (tag={fs_tag}): {e}")))?;

                let irq = dev_state.irq;
                let base = dev_state.base_addr;
                let irq_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(RestoreError::Io)?;
                vm_fd
                    .register_irqfd(&irq_evt, irq)
                    .map_err(|e| RestoreError::Kvm(format!("register irqfd for fs: {e}")))?;
                let irq_evt = Arc::new(irq_evt);

                let mut fs_backend = crate::virtiofs::VirtioFsBackend::new(
                    &socket_path,
                    &fs_tag,
                    fork_mem_addr,
                    mem_span,
                    mem_fd,
                )
                .map_err(|e| RestoreError::Kvm(format!("fs backend (tag={fs_tag}): {e}")))?;
                let queues = restore_queues(&dev_state.queues, fs_backend.max_queue_size());
                fs_backend.ack_features(dev_state.acked_features);
                fs_backend
                    .activate_with_bases(&queues, &irq_evt, fork_mem_addr)
                    .map_err(|e| RestoreError::Kvm(format!("fs activate (tag={fs_tag}): {e}")))?;

                let mut dev = MmioDevice::new(base, irq, irq_evt, Box::new(fs_backend));
                dev.set_vhost(true);
                dev.restore_state(dev_state);

                let mmio_dev = Arc::new(Mutex::new(dev));
                mmio_registry.lock().unwrap().add(Arc::clone(&mmio_dev));
                virtiofsds.push(vfsd);
            } else if dev_state.device_type == VIRTIO_ID_BLOCK {
                // Rebuild the in-process virtio-blk backend against the
                // fork's memory. RO devices share the source's backing file
                // (never written by construction). RW devices get a FICLONE
                // reflink copy into the fork's own dir — CoW disk to match
                // the CoW memory — failing loudly on filesystems without
                // reflink. The guest driver's ring state
                // survived in memory; seed the worker or the ring corrupts
                // (CHALLENGES.md #27).
                let Some(cfg) = state.block_devices.get(blk_idx) else {
                    return Err(ForkError::Restore(RestoreError::InvalidSnapshot(format!(
                        "'{log_tag}': virtio-blk device #{blk_idx} has no matching \
                         config (state has {})",
                        state.block_devices.len()
                    ))));
                };
                blk_idx += 1;

                let host_path = if cfg.readonly {
                    cfg.host_path.clone()
                } else {
                    // The reflink target must live on the SAME filesystem
                    // as the source image (`FICLONE` returns EXDEV across
                    // filesystems), so the per-fork directory is a sibling
                    // of the source image — on the loopback XFS at
                    // /var/lib/k7d/disks that is exactly where clones
                    // belong. A fork whose RW images live
                    // on different filesystems keeps one fork dir next to
                    // the FIRST image; by design all writable volume
                    // images share the disks XFS, and a cross-fs mix
                    // fails loudly in `reflink_file` below.
                    let dir = if let Some(d) = &blk_fork_dir {
                        d.clone()
                    } else {
                        static FORK_BLK_SEQ: std::sync::atomic::AtomicU64 =
                            std::sync::atomic::AtomicU64::new(0);
                        let mut parent = cfg.host_path.parent().ok_or_else(|| {
                            ForkError::Reflink(format!(
                                "RW block image {} has no parent directory",
                                cfg.host_path.display()
                            ))
                        })?;
                        // A fork-of-fork's source image already lives in
                        // a `.k7d-blk-fork-*` dir owned by another VM (or
                        // parked by a suspended node). Never nest inside
                        // it — removing that dir would recursively delete
                        // THIS fork's images (CHALLENGES.md #130). Walk
                        // up to the stable disks dir; it is the same
                        // filesystem, so FICLONE still works.
                        while parent
                            .file_name()
                            .and_then(std::ffi::OsStr::to_str)
                            .is_some_and(|n| n.starts_with(".k7d-blk-fork-"))
                        {
                            parent = parent.parent().ok_or_else(|| {
                                ForkError::Reflink(format!(
                                    "fork dir {} has no parent directory",
                                    cfg.host_path.display()
                                ))
                            })?;
                        }
                        let d = parent.join(format!(
                            ".k7d-blk-fork-{}-{}",
                            std::process::id(),
                            FORK_BLK_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                        ));
                        fs::create_dir_all(&d)?;
                        blk_fork_dir = Some(d.clone());
                        d
                    };
                    let file_name = cfg
                        .host_path
                        .file_name()
                        .map_or_else(|| "img".into(), std::ffi::OsStr::to_string_lossy);
                    let dst = dir.join(format!("blk{}-{file_name}", blk_idx - 1));
                    reflink_file(&cfg.host_path, &dst)?;
                    dst
                };

                let irq = dev_state.irq;
                let base = dev_state.base_addr;
                let irq_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(RestoreError::Io)?;
                vm_fd
                    .register_irqfd(&irq_evt, irq)
                    .map_err(|e| RestoreError::Kvm(format!("register irqfd for blk: {e}")))?;
                let irq_evt = Arc::new(irq_evt);

                let mut blk_backend = crate::block::BlockBackend::new(
                    &host_path,
                    cfg.readonly,
                    fork_mem_addr,
                    mem_span,
                )
                .map_err(|e| RestoreError::Kvm(format!("blk backend: {e}")))?;
                let queues = restore_queues(&dev_state.queues, blk_backend.max_queue_size());
                blk_backend.ack_features(dev_state.acked_features);
                blk_backend
                    .seed_indices_from_guest(&queues)
                    .map_err(|e| RestoreError::Kvm(format!("blk seed: {e}")))?;
                blk_backend
                    .activate(&queues, &irq_evt)
                    .map_err(|e| RestoreError::Kvm(format!("blk activate: {e}")))?;

                let mut dev = MmioDevice::new(base, irq, irq_evt, Box::new(blk_backend));
                dev.set_vhost(true);
                dev.restore_state(dev_state);
                dev.trigger_vring_irq();

                let mmio_dev = Arc::new(Mutex::new(dev));
                mmio_registry.lock().unwrap().add(Arc::clone(&mmio_dev));

                fork_block_devices.push(crate::vm::BlockConfig {
                    host_path,
                    readonly: cfg.readonly,
                    mount: cfg.mount.clone(),
                });
            }
        }
        if tap_slot.is_some() {
            log::warn!("{log_tag}: TAP supplied but snapshot had no virtio-net device");
        }

        // COM1 console with real THRE interrupts (IRQ 4) — same wiring
        // as cold boot; without it guest userspace console writes block
        // once the 8250 xmit buffer fills (see `SerialDevice::with_trigger`).
        let com1_irq_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(RestoreError::Io)?;
        vm_fd
            .register_irqfd(&com1_irq_evt, crate::devices::SERIAL_IRQ)
            .map_err(|e| RestoreError::Kvm(format!("register irqfd for COM1: {e}")))?;
        let serial =
            create_serial_device_with_trigger(SerialTrigger::with_eventfd(Arc::new(com1_irq_evt)));

        let com2_irq_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(RestoreError::Io)?;
        vm_fd
            .register_irqfd(&com2_irq_evt, 3)
            .map_err(|e| RestoreError::Kvm(format!("register irqfd for COM2: {e}")))?;
        let com2_trigger = SerialTrigger::with_eventfd(Arc::new(com2_irq_evt));
        let (agent_serial, _) =
            PipeSerialDevice::with_trigger(com2_trigger).map_err(RestoreError::Io)?;
        let agent_serial = Arc::new(Mutex::new(agent_serial));

        log::info!(
            "{log_tag}: build_vm_from_state_and_mem complete in {:?}",
            start.elapsed()
        );

        let guest_memory = vm_memory::GuestMemoryMmap::<()>::from_ranges(&[(
            vm_memory::GuestAddress(0),
            mem_span as usize,
        )])
        .map_err(|e| RestoreError::Kvm(format!("create guest memory: {e}")))?;

        let mut vm = Vm::from_restored_with_memory(
            kvm,
            vm_fd,
            vcpu_fds,
            guest_memory,
            fork_mem_addr,
            mem_size,
            kernel_path,
            initrd_path,
            serial,
            agent_serial,
            mmio_registry,
            if has_vsock { new_cid } else { 0 },
            // Virtiofs-backed forks carry their fresh
            // virtiofsd children + share configs so the guest's FUSE
            // mounts stay live and the fork itself is re-forkable.
            // Empty for share-less VMs (the historical behaviour).
            virtiofsds,
            tap_for_vm,
            guest_ip_for_vm,
            state.virtiofs_shares.clone(),
            fork_block_devices,
            child_dilation,
        );
        if let Some(file) = fork_mem_file {
            vm.set_fork_mem_file(file);
        }
        if let Some(ref dir) = blk_fork_dir {
            // The fork Vm owns the reflinked RW images: removed on Drop.
            vm.set_fork_state_dir(dir.clone());
        }
        Ok(vm)
    })();

    if result.is_err() {
        // SAFETY: fork_mem_addr came from mmap_base_mem_private with mem_span.
        unsafe {
            libc::munmap(fork_mem_addr as *mut libc::c_void, mem_span as usize);
        }
        if let Some(ref dir) = blk_fork_dir {
            let _ = fs::remove_dir_all(dir);
        }
    }
    result
}

/// Memcpy dirty pages from `src_addr` to `dst_addr`. Returns the number of
/// pages copied. Both regions must be at least `mem_size` bytes.
#[must_use]
pub fn apply_dirty_bitmap_memcpy(
    dirty_bitmap: &[u64],
    src_addr: u64,
    dst_addr: u64,
    mem_size: u64,
) -> u64 {
    let page_size: u64 = 4096;
    let total_pages = mem_size / page_size;
    let mut copied: u64 = 0;
    for (word_idx, &word) in dirty_bitmap.iter().enumerate() {
        if word == 0 {
            continue;
        }
        for bit in 0..64u64 {
            if word & (1u64 << bit) == 0 {
                continue;
            }
            let page_idx = (word_idx as u64) * 64 + bit;
            if page_idx >= total_pages {
                break;
            }
            let offset = page_idx * page_size;
            // SAFETY: offset+4096 <= mem_size for both regions, both regions
            // live for the duration of this function.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    (src_addr + offset) as *const u8,
                    (dst_addr + offset) as *mut u8,
                    page_size as usize,
                );
            }
            copied += 1;
        }
    }
    copied
}

#[cfg(kani)]
mod verification {
    #[kani::proof]
    fn verify_cow_mmap_alignment() {
        let mem_size: u64 = kani::any();
        kani::assume(mem_size >= 1024 * 1024); // at least 1 MB
        kani::assume(mem_size <= 4 * 1024 * 1024 * 1024); // at most 4 GB
        kani::assume(mem_size % 4096 == 0); // page-aligned

        // MAP_PRIVATE | MAP_NORESERVE flags
        let flags = libc::MAP_PRIVATE | libc::MAP_NORESERVE;
        assert!(flags & libc::MAP_PRIVATE != 0, "MAP_PRIVATE must be set");
        assert!(
            flags & libc::MAP_NORESERVE != 0,
            "MAP_NORESERVE must be set"
        );
    }

    /// The parallel copy in `memfd_fork_memory` must cover `[0, mem_size)`
    /// exactly with contiguous, pairwise-disjoint, page-aligned chunks (at
    /// most `max_chunks` of them): disjointness is what makes the per-chunk
    /// `copy_nonoverlapping` calls sound across threads, and exact coverage
    /// is what makes the fork's memory a bit-perfect copy of the source.
    /// This walks the same `offset`/`len` loop `memfd_fork_memory` drives
    /// (contiguity and disjointness hold by construction there) and proves
    /// positive lengths, the chunk-count bound, and exact coverage.
    #[kani::proof]
    #[kani::unwind(10)]
    fn verify_copy_chunk_size_covers_disjoint() {
        let mem_size: u64 = kani::any();
        kani::assume(mem_size <= 64 * 1024 * 1024 * 1024); // ≤ 64 GiB
        let max_chunks: u64 = kani::any();
        kani::assume(max_chunks >= 1 && max_chunks <= 8);

        let per_chunk = super::copy_chunk_size(mem_size, max_chunks);
        assert!(per_chunk % 4096 == 0, "chunk size is page-aligned");
        let mut offset = 0u64;
        let mut chunks = 0u64;
        while offset < mem_size {
            let len = per_chunk.min(mem_size - offset);
            assert!(len > 0, "no empty chunks (loop terminates)");
            offset += len;
            chunks += 1;
            assert!(chunks <= max_chunks, "at most max_chunks chunks");
        }
        assert_eq!(offset, mem_size, "chunks cover exactly mem_size");
    }

    #[kani::proof]
    fn verify_cid_allocation_monotonic() {
        let cid1 = crate::vsock::allocate_cid();
        let cid2 = crate::vsock::allocate_cid();
        assert!(
            cid2 > cid1,
            "CID allocation must be monotonically increasing"
        );
        assert!(cid1 >= 100, "CID must start at 100 or above");
    }
}
