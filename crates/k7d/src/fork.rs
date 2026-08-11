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
use crate::snapshot::{CpuState, SnapshotError, VmState};
use crate::virtio_mmio::{MmioDevice, MmioDeviceRegistry, VirtioBackend};
use crate::vm::{Vm, VmError};
use crate::vsock::VhostVsockBackend;

/// Virtio device-type ID for `virtio-net` (matches the constant in `network.rs`).
const VIRTIO_ID_NET: u32 = 1;
/// Virtio device-type ID for `virtio-blk` (matches `crate::block::VIRTIO_ID_BLOCK`).
const VIRTIO_ID_BLOCK: u32 = 2;
const VIRTIO_ID_FS: u32 = 26;
/// Virtio device-type ID for vsock.
const VIRTIO_ID_VSOCK: u32 = 19;

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
    /// internal notes: the VM has virtiofs shares, which force every
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
/// This is the core milestone 9 operation:
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
    // SAFETY: both fds are valid for the duration of the call; FICLONE takes
    // the source fd as its integer argument.
    let rc = unsafe { libc::ioctl(dst_file.as_raw_fd(), libc::FICLONE, src_file.as_raw_fd()) };
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
    // internal notes: cpu.json is an array (one entry per vCPU); pre-17b
    // snapshots hold a single bare object — accept both.
    let cpu_states: Vec<CpuState> =
        serde_json::from_str::<crate::snapshot::CpuStatesCompat>(&cpu_json)?.into();

    let metadata_json = fs::read_to_string(snapshot_dir.join("metadata.json"))?;
    let bundle: crate::snapshot::SnapshotMetadata = serde_json::from_str(&metadata_json)?;

    let mem_size = bundle.memory_size_bytes;
    let kernel_path = PathBuf::from(&bundle.kernel_path);
    let initrd_path = bundle.initrd_path.as_ref().map(PathBuf::from);

    let mem_file_path = snapshot_dir.join("memory.bin");
    // Open read-write: MAP_PRIVATE + PROT_WRITE requires O_RDWR on Linux.
    let mem_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&mem_file_path)?;
    let actual_size = mem_file.metadata()?.len();
    if actual_size != mem_size {
        return Err(RestoreError::InvalidSnapshot(format!(
            "memory.bin is {actual_size} bytes, expected {mem_size}"
        )));
    }

    // mmap with MAP_PRIVATE for CoW semantics. GuestMemoryMmap::from_ranges_with_files
    // uses MAP_SHARED which doesn't give us CoW and may behave differently for
    // page table pages. We manually mmap and register with KVM.
    // SAFETY: mem_file is valid and mem_size matches the file size.
    let mem_ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            mem_size as usize,
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

    // Register the GuestMemoryMmap's CoW-mapped memory with KVM.
    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: mem_size,
        userspace_addr: mem_host_addr,
        flags: 0,
    };
    // SAFETY: guest_memory owns the mmap and will outlive the VM; the region
    // describes a contiguous MAP_PRIVATE mmap backed by memory.bin.
    unsafe {
        vm_fd
            .set_user_memory_region(mem_region)
            .map_err(|e| RestoreError::Kvm(format!("set user memory region: {e}")))?;
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
    let vcpu_fds = create_and_restore_vcpus(&kvm, &vm_fd, &cpu_states, irqchip_state.as_ref())?;

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

            let mut vsock_backend = VhostVsockBackend::new(new_cid, mem_host_addr, mem_size)
                .map_err(|e| RestoreError::Kvm(format!("vsock backend: {e}")))?;

            // Pre-activate with saved queue state and correct vring base indices.
            let queues: Vec<crate::virtio_mmio::VirtqueueState> = dev_state
                .queues
                .iter()
                .map(|qs| crate::virtio_mmio::VirtqueueState {
                    max_size: qs.size,
                    size: qs.size,
                    ready: qs.ready,
                    desc_addr: vm_memory::GuestAddress(qs.desc_addr),
                    avail_addr: vm_memory::GuestAddress(qs.avail_addr),
                    used_addr: vm_memory::GuestAddress(qs.used_addr),
                })
                .collect();
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

            let queues: Vec<crate::virtio_mmio::VirtqueueState> = dev_state
                .queues
                .iter()
                .map(|qs| crate::virtio_mmio::VirtqueueState {
                    max_size: qs.size,
                    size: qs.size,
                    ready: qs.ready,
                    desc_addr: vm_memory::GuestAddress(qs.desc_addr),
                    avail_addr: vm_memory::GuestAddress(qs.avail_addr),
                    used_addr: vm_memory::GuestAddress(qs.used_addr),
                })
                .collect();

            let mut net_backend = TapNetBackend::new(net_tap.mac(), net_tap.fd(), mem_host_addr);
            net_backend.ack_features(dev_state.acked_features);
            // Guest rings survived the snapshot — seed worker counters or eth0 hangs.
            net_backend.seed_indices_from_guest(&queues);
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

            let queues: Vec<crate::virtio_mmio::VirtqueueState> = dev_state
                .queues
                .iter()
                .map(|qs| crate::virtio_mmio::VirtqueueState {
                    max_size: qs.size,
                    size: qs.size,
                    ready: qs.ready,
                    desc_addr: vm_memory::GuestAddress(qs.desc_addr),
                    avail_addr: vm_memory::GuestAddress(qs.avail_addr),
                    used_addr: vm_memory::GuestAddress(qs.used_addr),
                })
                .collect();

            let mut blk_backend = crate::block::BlockBackend::new(
                &cfg.host_path,
                cfg.readonly,
                mem_host_addr,
                mem_size,
            )
            .map_err(|e| RestoreError::Kvm(format!("blk backend: {e}")))?;
            blk_backend.ack_features(dev_state.acked_features);
            blk_backend.seed_indices_from_guest(&queues);
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
        mem_size as usize,
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
        // — pre-10b behaviour was `_virtiofsd: None` (and the
        // shim's caller spawns virtiofsd separately when needed via
        // `set_fork_state_dir`). 10b's multi-share rework keeps that
        // contract: an empty `Vec` is the multi-share equivalent of
        // the old `None`.
        Vec::new(),
        tap_for_vm,
        guest_ip_for_vm,
        Vec::new(),
        bundle.block_devices.clone(),
    ))
}

/// Create one vCPU per captured [`CpuState`] and fully restore each, in
/// vCPU-index order.
///
/// Per vCPU the fixed order is CPUID → SREGS → XCRS → XSAVE → REGS →
/// LAPIC → MSRs → `MP_STATE` last, followed by `KVM_KVMCLOCK_CTRL`.
/// VM-scoped IRQ chip state (IOAPIC / PIC / PIT) is applied during vCPU
/// 0's restore, preserving the pre-17b single-vCPU ioctl sequence.
fn create_and_restore_vcpus(
    kvm: &Kvm,
    vm_fd: &kvm_ioctls::VmFd,
    cpu_states: &[CpuState],
    irqchip: Option<&crate::snapshot::IrqChipState>,
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
        // KVM_KVMCLOCK_CTRL: tell KVM to reset the pvclock TSC stable bit.
        let kvmclock_ctrl: libc::c_ulong = 0x0000_AE7D;
        // SAFETY: vcpu_fd is valid; KVM_KVMCLOCK_CTRL takes no args.
        unsafe {
            libc::ioctl(vcpu_fd.as_raw_fd(), kvmclock_ctrl);
        }
        vcpu_fds.push(vcpu_fd);
    }
    Ok(vcpu_fds)
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
/// falling back to the legacy VM-scoped `irqchip.lapic` for pre-17b
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
    // for pre-17b snapshots (which are single-vCPU by construction).
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

    // 5b. Skip vcpu_events restore for now — on AMD, the snapshotted
    // vcpu_events may contain stale exception state that causes #BR.
    // TODO: investigate which fields of vcpu_events are safe to restore on AMD.

    // 6. MP_STATE must be LAST (zeroboot: "MUST be last"). internal notes:
    // restore the captured per-vCPU value — an AP may legitimately be
    // HALTED; making it RUNNABLE would have it execute garbage. Pre-17b
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
/// virtiofs-backed VMs (see [`memfd_fork_memory`] for why). The source
/// must stay paused.
fn fork_memory_for_state(
    base_mem_path: &Path,
    dirty_bitmap: &[u64],
    source_mem_addr: u64,
    state: &VmState,
    fork_id: &str,
) -> Result<(u64, Option<fs::File>), ForkError> {
    let mem_size = state.memory_size;
    // Virtio-blk queues must be quiescent before ANY memory capture: the
    // in-process worker drains + parks on pause (`Vm::pause` waits for it),
    // so this converges immediately in practice — it is the used==avail
    // safety net mirroring `drain_fs_queues`.
    drain_device_queues(state, source_mem_addr, fork_id, VIRTIO_ID_BLOCK, "blk");
    if state.virtiofs_shares.is_empty() {
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
        drain_fs_queues(state, source_mem_addr, fork_id);
        let t = std::time::Instant::now();
        let (file, fork_mem_addr) =
            memfd_fork_memory(source_mem_addr, mem_size).map_err(ForkError::Restore)?;
        log::info!(
            "fork_warm '{fork_id}': full memfd copy of {} MiB in {:?} ({} virtiofs shares)",
            mem_size / (1024 * 1024),
            t.elapsed(),
            state.virtiofs_shares.len()
        );
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
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
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
pub fn restore_vm_from_state(
    base_mem_path: &Path,
    dirty_bitmap: &[u64],
    source_mem_addr: u64,
    state: &VmState,
    fork_id: &str,
) -> Result<Vm, ForkError> {
    let (fork_mem_addr, fork_mem_file) =
        fork_memory_for_state(base_mem_path, dirty_bitmap, source_mem_addr, state, fork_id)?;
    build_vm_from_state_and_mem_inner(state, fork_mem_addr, fork_id, None, fork_mem_file)
}

/// Like [`restore_vm_from_state`] but reattaches a pre-built TAP for the
/// virtio-net slot.
///
/// Used by [`fork_cluster_warm`] to put the forked VM on the fork's bridge
/// while preserving the source's guest IP and MAC.
pub fn restore_vm_from_state_with_tap(
    base_mem_path: &Path,
    dirty_bitmap: &[u64],
    source_mem_addr: u64,
    state: &VmState,
    fork_id: &str,
    tap: TapDevice,
) -> Result<Vm, ForkError> {
    let (fork_mem_addr, fork_mem_file) =
        fork_memory_for_state(base_mem_path, dirty_bitmap, source_mem_addr, state, fork_id)?;
    build_vm_from_state_and_mem_inner(state, fork_mem_addr, fork_id, Some(tap), fork_mem_file)
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
    let req = ClusterForkRequest {
        fork_cluster_id,
        fork_ids,
        fork_pod_ips,
        fork_pod_netns,
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

    // 1. Pause every source once and capture dirty + CPU/device/IRQ state.
    //    Sources stay paused through all materialisations so each fork's
    //    memory matches the captured registers (no torn mid-memcpy writes).
    let mut was_running: Vec<bool> = Vec::with_capacity(n_members);
    let mut captured: Vec<(Vec<u64>, VmState, u64, PathBuf)> = Vec::with_capacity(n_members);
    for (vm, _idx) in sources.iter_mut() {
        let running = vm.is_running();
        was_running.push(running);
        if running {
            vm.pause().map_err(crate::snapshot::SnapshotError::Vm)?;
        }
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
        captured.push((dirty, state, src_mem_addr, base_path));
    }

    // 2. Host-net setup per request (bridges + TAPs + optional pod NAT).
    //    Kept sequential: iptables / `ip link` are not safe to race.
    let mut err: Option<ForkError> = None;
    let mut nets: Vec<ClusterNetwork> = Vec::with_capacity(requests.len());
    // Flat job list: (cluster_idx, member_idx, tap, fork_id).
    let mut jobs: Vec<(usize, usize, TapDevice, String)> =
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
        for (mi, (_src_vm, vm_index)) in sources.iter().enumerate() {
            match fork_net.add_tap_at(*vm_index) {
                Ok(tap) => {
                    jobs.push((ci, mi, tap, req.fork_ids[mi].to_string()));
                }
                Err(e) => {
                    err = Some(ForkError::Reflink(format!(
                        "add_tap_at({vm_index}) on '{}': {e}",
                        req.fork_cluster_id
                    )));
                    break;
                }
            }
            if let (Some(pod_ip), Some(netns)) = (pod_ips[mi], pod_netns[mi].as_deref()) {
                if let Err(e) = fork_net.install_pod_nat(*vm_index, pod_ip, netns) {
                    log::warn!(
                        "fork_cluster_warm_batch: install_pod_nat({vm_index}) on '{}' \
                         failed (non-fatal): {e}",
                        req.fork_cluster_id
                    );
                }
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
                .map(|(ci, mi, tap, fork_id)| {
                    s.spawn(move || {
                        let (dirty, state, src_mem_addr, base_path) = &captured_ref[mi];
                        let t = std::time::Instant::now();
                        let result = restore_vm_from_state_with_tap(
                            base_path,
                            dirty,
                            *src_mem_addr,
                            state,
                            &fork_id,
                            tap,
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
    build_vm_from_state_and_mem_inner(state, fork_mem_addr, log_tag, None, None)
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
    build_vm_from_state_and_mem_inner(state, fork_mem_addr, log_tag, Some(tap), None)
}

#[allow(clippy::too_many_lines)]
fn build_vm_from_state_and_mem_inner(
    state: &VmState,
    fork_mem_addr: u64,
    log_tag: &str,
    tap: Option<TapDevice>,
    fork_mem_file: Option<fs::File>,
) -> Result<Vm, ForkError> {
    let start = std::time::Instant::now();
    let mem_size = state.memory_size;
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

        let mem_region = kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: 0,
            memory_size: mem_size,
            userspace_addr: fork_mem_addr,
            flags: 0,
        };
        // SAFETY: fork_mem_addr is a MAP_PRIVATE region of mem_size bytes that
        // outlives the VM (cleaned up on Vm::drop via cow_mmap_addr).
        unsafe {
            vm_fd
                .set_user_memory_region(mem_region)
                .map_err(|e| RestoreError::Kvm(format!("set user memory region: {e}")))?;
        }

        // Create one vCPU per captured CpuState and restore each (CPUID
        // → SREGS → XCRS → XSAVE → REGS → LAPIC → MSRs → MP_STATE last,
        // then KVM_KVMCLOCK_CTRL).
        let vcpu_fds = create_and_restore_vcpus(&kvm, &vm_fd, &state.cpus, Some(&state.irqchip))?;

        // Inject TRANSPORT_RESET into the FORK's memory only. The source is
        // undisturbed (unlike the cold fork path, which injects into the source
        // before dumping memory). This is the key correctness fix of internal notes
        //
        // This MUST happen before vsock backend activation: the injection advances
        // the used ring's idx field, and activate_with_bases reads that idx to
        // program the vhost module's vring base. Doing it after activation would
        // leave the kernel with a stale base and the event would go unprocessed.
        crate::snapshot::inject_vsock_transport_reset_into(mem_size, &state.devices, fork_mem_addr);

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

                let mut vsock_backend = VhostVsockBackend::new(new_cid, fork_mem_addr, mem_size)
                    .map_err(|e| RestoreError::Kvm(format!("vsock backend: {e}")))?;

                let queues: Vec<crate::virtio_mmio::VirtqueueState> = dev_state
                    .queues
                    .iter()
                    .map(|qs| crate::virtio_mmio::VirtqueueState {
                        max_size: qs.size,
                        size: qs.size,
                        ready: qs.ready,
                        desc_addr: vm_memory::GuestAddress(qs.desc_addr),
                        avail_addr: vm_memory::GuestAddress(qs.avail_addr),
                        used_addr: vm_memory::GuestAddress(qs.used_addr),
                    })
                    .collect();
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

                let queues: Vec<crate::virtio_mmio::VirtqueueState> = dev_state
                    .queues
                    .iter()
                    .map(|qs| crate::virtio_mmio::VirtqueueState {
                        max_size: qs.size,
                        size: qs.size,
                        ready: qs.ready,
                        desc_addr: vm_memory::GuestAddress(qs.desc_addr),
                        avail_addr: vm_memory::GuestAddress(qs.avail_addr),
                        used_addr: vm_memory::GuestAddress(qs.used_addr),
                    })
                    .collect();

                let mut net_backend = TapNetBackend::new(tap.mac(), tap.fd(), fork_mem_addr);
                // Replay the driver's feature-negotiation outcome from the snapshot.
                net_backend.ack_features(dev_state.acked_features);
                // Guest rings survived the snapshot — seed worker counters or eth0 hangs.
                net_backend.seed_indices_from_guest(&queues);
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

                let queues: Vec<crate::virtio_mmio::VirtqueueState> = dev_state
                    .queues
                    .iter()
                    .map(|qs| crate::virtio_mmio::VirtqueueState {
                        max_size: qs.size,
                        size: qs.size,
                        ready: qs.ready,
                        desc_addr: vm_memory::GuestAddress(qs.desc_addr),
                        avail_addr: vm_memory::GuestAddress(qs.avail_addr),
                        used_addr: vm_memory::GuestAddress(qs.used_addr),
                    })
                    .collect();

                let mut fs_backend = crate::virtiofs::VirtioFsBackend::new(
                    &socket_path,
                    &fs_tag,
                    fork_mem_addr,
                    mem_size,
                    mem_fd,
                )
                .map_err(|e| RestoreError::Kvm(format!("fs backend (tag={fs_tag}): {e}")))?;
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
                        let parent = cfg.host_path.parent().ok_or_else(|| {
                            ForkError::Reflink(format!(
                                "RW block image {} has no parent directory",
                                cfg.host_path.display()
                            ))
                        })?;
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

                let queues: Vec<crate::virtio_mmio::VirtqueueState> = dev_state
                    .queues
                    .iter()
                    .map(|qs| crate::virtio_mmio::VirtqueueState {
                        max_size: qs.size,
                        size: qs.size,
                        ready: qs.ready,
                        desc_addr: vm_memory::GuestAddress(qs.desc_addr),
                        avail_addr: vm_memory::GuestAddress(qs.avail_addr),
                        used_addr: vm_memory::GuestAddress(qs.used_addr),
                    })
                    .collect();

                let mut blk_backend = crate::block::BlockBackend::new(
                    &host_path,
                    cfg.readonly,
                    fork_mem_addr,
                    mem_size,
                )
                .map_err(|e| RestoreError::Kvm(format!("blk backend: {e}")))?;
                blk_backend.ack_features(dev_state.acked_features);
                blk_backend.seed_indices_from_guest(&queues);
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
            mem_size as usize,
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
            // internal notes: virtiofs-backed forks carry their fresh
            // virtiofsd children + share configs so the guest's FUSE
            // mounts stay live and the fork itself is re-forkable.
            // Empty for share-less VMs (the historical behaviour).
            virtiofsds,
            tap_for_vm,
            guest_ip_for_vm,
            state.virtiofs_shares.clone(),
            fork_block_devices,
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
        // SAFETY: fork_mem_addr came from mmap_base_mem_private with mem_size.
        unsafe {
            libc::munmap(fork_mem_addr as *mut libc::c_void, mem_size as usize);
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
