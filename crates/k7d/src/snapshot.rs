//! VM snapshot: memory dump, CPU registers, device state.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use vm_memory::{GuestAddress, GuestMemory};

use crate::virtio_mmio::MmioDeviceState;
use crate::vm::Vm;

/// Errors from snapshot operations.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("VM error: {0}")]
    Vm(#[from] crate::vm::VmError),
    #[error("KVM error: {0}")]
    Kvm(String),
    #[error("VM must be paused before snapshotting")]
    NotPaused,
    /// An incremental keyframe could not `FICLONE` its ancestor: the two
    /// paths are not on one reflink-capable filesystem. The caller falls
    /// back to a full dump — loudly .
    #[error(
        "FICLONE {ancestor} -> {dest}: {detail} — an incremental keyframe needs \
         ancestor and child on one reflink-capable filesystem (the tree root \
         belongs on the XFS loopback, see `disks::ensure_reflink_tree_root`)"
    )]
    ReflinkUnsupported {
        /// The ancestor `memory.bin` we tried to clone.
        ancestor: std::path::PathBuf,
        /// The clone destination.
        dest: std::path::PathBuf,
        /// The `FICLONE` errno.
        detail: String,
    },
}

/// Saved vCPU general-purpose registers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuRegs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

/// Saved segment register state.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SegmentState {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub type_: u8,
    pub present: u8,
    pub dpl: u8,
    pub db: u8,
    pub s: u8,
    pub l: u8,
    pub g: u8,
    pub avl: u8,
    pub unusable: u8,
}

/// Saved descriptor table register (GDT/IDT).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DtableState {
    pub base: u64,
    pub limit: u16,
}

/// Saved vCPU special registers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuSregs {
    pub cs: SegmentState,
    pub ds: SegmentState,
    pub es: SegmentState,
    pub fs: SegmentState,
    pub gs: SegmentState,
    pub ss: SegmentState,
    pub tr: SegmentState,
    pub ldt: SegmentState,
    pub gdt: DtableState,
    pub idt: DtableState,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
}

/// Saved FPU state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuFpu {
    pub fpr: Vec<[u8; 16]>,
    pub fcw: u16,
    pub fsw: u16,
    pub ftwx: u8,
    pub last_opcode: u16,
    pub last_ip: u64,
    pub last_dp: u64,
    pub xmm: Vec<[u8; 16]>,
    pub mxcsr: u32,
}

/// A single MSR (model-specific register) entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsrEntry {
    /// MSR index.
    pub index: u32,
    /// MSR value.
    pub data: u64,
}

/// Saved XSAVE state (raw bytes from `KVM_GET_XSAVE`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XsaveState {
    /// Raw XSAVE area bytes (typically 4096 bytes for non-AVX512).
    pub data: Vec<u8>,
}

/// Saved XCR registers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XcrState {
    pub xcr0: u64,
}

/// Saved CPUID entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuidEntry {
    pub function: u32,
    pub index: u32,
    pub flags: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

/// Saved vCPU events (pending interrupts/exceptions).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcpuEventsState {
    pub data: Vec<u8>,
}

/// Complete CPU state for a single vCPU.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuState {
    pub regs: CpuRegs,
    pub sregs: CpuSregs,
    pub fpu: CpuFpu,
    pub msrs: Vec<MsrEntry>,
    #[serde(default)]
    pub xsave: Option<XsaveState>,
    #[serde(default)]
    pub xcr: Option<XcrState>,
    #[serde(default)]
    pub cpuid_entries: Option<Vec<CpuidEntry>>,
    #[serde(default)]
    pub vcpu_events: Option<VcpuEventsState>,
    /// Per-vCPU Local APIC state (raw bytes from `KVM_GET_LAPIC`).
    ///
    /// The LAPIC is per-vCPU state — legacy snapshots
    /// stored the (single) vCPU's LAPIC VM-scoped in
    /// [`IrqChipState::lapic`]; restore falls back to that field when
    /// this one is empty (legacy snapshots).
    #[serde(default)]
    pub lapic: Vec<u8>,
    /// Per-vCPU `KVM_GET_MP_STATE` value. Restored LAST in
    /// the per-vCPU sequence. `None` (legacy snapshots) restores as
    /// `KVM_MP_STATE_RUNNABLE` — correct for the BSP, which is the only
    /// vCPU such snapshots can contain. An AP may legitimately be
    /// HALTED at capture time; restoring it RUNNABLE would make it
    /// execute garbage.
    #[serde(default)]
    pub mp_state: Option<u32>,
}

/// The VM's kvmclock reading, paired with the host wall clock it was
/// taken next to.
///
/// kvmclock is VM-scoped, not vCPU-scoped: it counts nanoseconds from
/// the moment the `kvm` VM fd was created. A restore builds a brand new
/// VM fd, so its clock starts back at zero while the guest's
/// timekeeping is still holding the value it read before the snapshot —
/// hence [`crate::fork::restore_kvmclock`], which needs both halves of
/// this pair: the reading to resume from, and the host instant that
/// says how long the snapshot has been sitting there.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KvmClockState {
    /// `kvm_clock_data.clock` — nanoseconds on this VM's kvmclock.
    pub clock_ns: u64,
    /// Host `CLOCK_REALTIME`, in nanoseconds since the Unix epoch, read
    /// next to the `KVM_GET_CLOCK` ioctl.
    pub host_unix_ns: u64,
}

/// Host `CLOCK_REALTIME` in nanoseconds since the Unix epoch.
pub(crate) fn host_unix_nanos() -> Result<u64, SnapshotError> {
    let since_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| SnapshotError::Kvm(format!("host clock is before the Unix epoch: {e}")))?;
    u64::try_from(since_epoch.as_nanos())
        .map_err(|_| SnapshotError::Kvm("host clock is past the year 2554".into()))
}

/// Read the VM's kvmclock and the host wall clock together.
fn capture_kvmclock(vm: &Vm) -> Result<KvmClockState, SnapshotError> {
    let clock = vm
        .vm_fd()
        .get_clock()
        .map_err(|e| SnapshotError::Kvm(format!("KVM_GET_CLOCK: {e}")))?;
    Ok(KvmClockState {
        clock_ns: clock.clock,
        host_unix_ns: host_unix_nanos()?,
    })
}

/// Compat wrapper for CPU state on disk: accepts either a bare
/// `CpuState` object (legacy single-vCPU `cpu.json` / `VmState.cpu`)
/// or an array of them (17b+ `cpus`). New writes are always the
/// plural array form.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum CpuStatesCompat {
    /// Current shape: one entry per vCPU, in vCPU-index order.
    Many(Vec<CpuState>),
    /// Legacy shape: a single vCPU's state as a bare object.
    One(Box<CpuState>),
}

impl From<CpuStatesCompat> for Vec<CpuState> {
    fn from(compat: CpuStatesCompat) -> Self {
        match compat {
            CpuStatesCompat::Many(v) => v,
            CpuStatesCompat::One(one) => vec![*one],
        }
    }
}

/// Deserialize `VmState::cpus` from either shape (see [`CpuStatesCompat`]).
fn de_cpus<'de, D>(deserializer: D) -> Result<Vec<CpuState>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    CpuStatesCompat::deserialize(deserializer).map(Into::into)
}

/// Snapshot metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    /// Guest RAM in bytes. `memory.bin` is `MemLayout::from_ram(this).span()`
    /// bytes long, which is larger for guests with RAM past 4 GiB — it also
    /// covers the 32-bit MMIO hole.
    pub memory_size_bytes: u64,
    pub kernel_path: String,
    pub initrd_path: Option<String>,
    pub guest_cid: u64,
    pub timestamp_unix: u64,
    /// Virtio-blk device configs, in device order. Cold restore rebuilds
    /// one `BlockBackend` per entry against the same backing file.
    /// Empty for snapshots taken before virtio-blk (serde default).
    #[serde(default)]
    pub block_devices: Vec<crate::vm::BlockConfig>,
    /// kvmclock reading at capture. `None` in snapshots taken before
    /// the guest had kvmclock at all — restore says so and
    /// leaves the clock alone rather than guessing an origin.
    #[serde(default)]
    pub kvmclock: Option<KvmClockState>,
    /// Time dilation factor the source ran at . Restore
    /// applies it to the new VM before its first vCPU exists and fails
    /// loudly on a host without the patch. Snapshots from before the
    /// field existed were all taken at 1 (the capture refused anything
    /// else), which is what the serde default says.
    #[serde(default = "one")]
    pub dilation: u32,
}

const fn one() -> u32 {
    1
}

/// Saved IRQ chip state (LAPIC + PIC + IOAPIC) for interrupt delivery after restore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrqChipState {
    /// Legacy VM-scoped Local APIC state (old snapshots only).
    ///
    /// The LAPIC is per-vCPU state moved it to
    /// [`CpuState::lapic`]. New captures leave this empty; restore
    /// reads it only when a vCPU's own `lapic` field is empty.
    #[serde(default)]
    pub lapic: Vec<u8>,
    /// I/O APIC state (`base_address`, id, irr, entries).
    pub ioapic_base_address: u64,
    pub ioapic_id: u32,
    pub ioapic_irr: u32,
    /// I/O APIC redirection entries (24 entries, each u64).
    pub ioapic_entries: Vec<u64>,
    /// PIC master raw bytes (from `KVM_GET_IRQCHIP` `KVM_IRQCHIP_PIC_MASTER`).
    #[serde(default)]
    pub pic_master: Option<Vec<u8>>,
    /// PIC slave raw bytes.
    #[serde(default)]
    pub pic_slave: Option<Vec<u8>>,
    /// i8254 PIT raw bytes (`kvm_pit_state2` from `KVM_GET_PIT2`).
    ///
    /// Load-bearing: the guest programs PIT channel 0 exactly once at
    /// boot. Restore creates a fresh (unprogrammed) PIT via
    /// `KVM_CREATE_PIT2`, so without `KVM_SET_PIT2` the restored guest
    /// never receives another IRQ0 — every timer-driven process parks
    /// forever and `CLOCK_REALTIME` freezes (kernel timekeeping stops
    /// being tick-driven past the TSC `max_idle_ns` clamp). Vsock-
    /// interrupt-driven paths (agent exec) keep working, which is why
    /// busybox-guest tests never caught this. See CHALLENGES.md #40.
    #[serde(default)]
    pub pit: Option<Vec<u8>>,
}

/// In-memory VM state snapshot for warm fork and suspend/resume.
///
/// Captures CPU + IRQ chip + device state. Total size ~10 KB. Serializable
/// to JSON so suspend can persist it to `cpu.json` and resume can reload it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmState {
    /// Complete per-vCPU state (registers, MSRs, XSAVE, CPUID, LAPIC,
    /// `mp_state`, …), in vCPU-index order. Deserialization accepts the
    /// legacy singular `cpu` field (a bare object) from older
    /// snapshots.
    #[serde(alias = "cpu", deserialize_with = "de_cpus")]
    pub cpus: Vec<CpuState>,
    /// LAPIC + IOAPIC + PIC master/slave state.
    pub irqchip: IrqChipState,
    /// MMIO device states (captured so vsock etc. can be rebuilt).
    pub devices: Vec<MmioDeviceState>,
    /// Guest RAM in bytes (not the mapping length — see
    /// [`SnapshotMetadata::memory_size_bytes`]).
    pub memory_size: u64,
    /// Kernel path (used for metadata only — fork inherits the source's kernel).
    pub kernel_path: std::path::PathBuf,
    /// Initrd path (metadata only).
    pub initrd_path: Option<std::path::PathBuf>,
    /// Source guest CID (informational — fork uses a new CID).
    pub guest_cid: u64,
    /// Virtiofs share configs of the source, in device order. A fork of
    /// a virtiofs-backed VM respawns one virtiofsd per share (same host
    /// dirs) and re-handshakes vhost-user against a full-copy memfd —
    /// see `fork::restore_vm_from_state`. Empty for share-less VMs and
    /// for older snapshots (serde default).
    #[serde(default)]
    pub virtiofs_shares: Vec<crate::vm::VirtiofsConfig>,
    /// Virtio-blk device configs of the source, in device order. A fork
    /// rebuilds each backend: read-only devices share the backing file;
    /// read-write devices are reflinked (`FICLONE`) into the fork's dir,
    /// failing loudly when the filesystem cannot reflink.
    /// Empty for older snapshots (serde default).
    #[serde(default)]
    pub block_devices: Vec<crate::vm::BlockConfig>,
    /// kvmclock reading at capture — see [`KvmClockState`]. Every fork
    /// off this state re-bases its own clock from it.
    #[serde(default)]
    pub kvmclock: Option<KvmClockState>,
    /// Time dilation factor of the source ; every fork
    /// off this state runs at the same one. See
    /// [`SnapshotMetadata::dilation`].
    #[serde(default = "one")]
    pub dilation: u32,
}

/// Capture the full in-memory VM state for warm fork.
///
/// The VM must be paused before calling this. Performs no disk I/O.
pub fn capture_vm_state(vm: &Vm) -> Result<VmState, SnapshotError> {
    let cpus = capture_all_cpu_states(vm)?;
    let irqchip = capture_irqchip_state(vm)?;
    let devices = {
        let registry = vm.mmio_registry().lock().unwrap();
        registry.snapshot_device_states()
    };
    Ok(VmState {
        cpus,
        irqchip,
        devices,
        memory_size: vm.memory_size(),
        kernel_path: vm.kernel_path().to_path_buf(),
        initrd_path: vm.initrd_path().map(std::path::Path::to_path_buf),
        guest_cid: vm.guest_cid(),
        virtiofs_shares: vm.virtiofs_shares().to_vec(),
        block_devices: vm.block_devices().to_vec(),
        kvmclock: Some(capture_kvmclock(vm)?),
        dilation: vm.dilation(),
    })
}

impl From<&kvm_bindings::kvm_segment> for SegmentState {
    fn from(seg: &kvm_bindings::kvm_segment) -> Self {
        Self {
            base: seg.base,
            limit: seg.limit,
            selector: seg.selector,
            type_: seg.type_,
            present: seg.present,
            dpl: seg.dpl,
            db: seg.db,
            s: seg.s,
            l: seg.l,
            g: seg.g,
            avl: seg.avl,
            unusable: seg.unusable,
        }
    }
}

impl From<&kvm_bindings::kvm_dtable> for DtableState {
    fn from(dt: &kvm_bindings::kvm_dtable) -> Self {
        Self {
            base: dt.base,
            limit: dt.limit,
        }
    }
}

// x86_64 MSR indices essential for snapshot/restore.
// This is the minimal set needed for a Linux guest to resume correctly.
// Based on Firecracker's SERIALIZABLE_MSR_RANGES.
const MSR_INDICES: &[u32] = &[
    0x0000_0010, // IA32_TSC
    0x0000_0174, // IA32_SYSENTER_CS
    0x0000_0175, // IA32_SYSENTER_ESP
    0x0000_0176, // IA32_SYSENTER_EIP
    0x0000_0277, // IA32_PAT
    0xC000_0080, // IA32_EFER (also in sregs, but the canonical source is MSR)
    0xC000_0081, // IA32_STAR
    0xC000_0082, // IA32_LSTAR
    0xC000_0083, // IA32_CSTAR
    0xC000_0084, // IA32_FMASK (syscall flag mask)
    0xC000_0100, // IA32_FS_BASE
    0xC000_0101, // IA32_GS_BASE
    0xC000_0102, // IA32_KERNEL_GS_BASE
    0xC000_0103, // IA32_TSC_AUX
    0x0000_001B, // IA32_APIC_BASE
    // IA32_TSC_DEADLINE: the one-shot LAPIC timer arm. NOT part of
    // KVM_GET_LAPIC — without it a vCPU whose deadline timer was armed
    // at capture never receives that timer interrupt after restore.
    // Harmless on the 1-vCPU BSP (PIT tick keeps timekeeping alive,
    // CHALLENGES.md #40) but an SMP AP parked on its LAPIC tick hangs
    // whatever the guest scheduler queued there.
    // Restored in the MSR loop AFTER KVM_SET_LAPIC, so the write
    // re-arms KVM's software timer against the restored TSC.
    0x0000_06E0, // IA32_TSC_DEADLINE
    0x0000_003A, // IA32_FEATURE_CONTROL
    0x0000_048B, // IA32_VMX_PROCBASED_CTLS2 — may not exist; skip on error
    // The two halves of the kvmclock handshake, and the reason they are
    // restored: each holds a guest physical address the guest published
    // once at boot, so writing them back is what re-registers the
    // pvclock page with the new VM fd. Restoring them is not optional
    // now that the guest actually runs kvmclock — without
    // MSR_KVM_SYSTEM_TIME_NEW the host never updates the page the
    // restored guest is reading its clock out of.
    //
    // The list stops here on purpose. `0x4b56_4d02` and up (async page
    // faults, steal time, PV EOI, poll control) are the same kind of
    // address handshake for paravirt features `vm::patch_cpuid_for_kvm_guest`
    // deliberately does not advertise; the two must be changed together.
    0x4B56_4D00, // MSR_KVM_WALL_CLOCK_NEW
    0x4B56_4D01, // MSR_KVM_SYSTEM_TIME_NEW
];

/// Capture every vCPU's state, in vCPU-index order. The VM must be
/// paused (`Vm::pause` refills `vcpu_fds` in index order).
fn capture_all_cpu_states(vm: &Vm) -> Result<Vec<CpuState>, SnapshotError> {
    if vm.is_running() || vm.vcpu_fds().len() != vm.vcpu_count() as usize {
        return Err(SnapshotError::NotPaused);
    }
    vm.vcpu_fds().iter().map(capture_cpu_state).collect()
}

/// Capture VM-scoped IRQ chip state (IOAPIC + PIC + PIT) from the VM.
/// Per-vCPU LAPICs are captured in [`capture_cpu_state`] —
/// the legacy `lapic` field stays empty on new captures.
fn capture_irqchip_state(vm: &Vm) -> Result<IrqChipState, SnapshotError> {
    let vm_fd = vm.vm_fd();

    // Get IOAPIC state.
    let mut irqchip = kvm_bindings::kvm_irqchip {
        chip_id: kvm_bindings::KVM_IRQCHIP_IOAPIC,
        ..Default::default()
    };
    vm_fd
        .get_irqchip(&mut irqchip)
        .map_err(|e| SnapshotError::Kvm(format!("KVM_GET_IRQCHIP IOAPIC: {e}")))?;
    // SAFETY: we requested KVM_IRQCHIP_IOAPIC, so the union contains ioapic.
    let ioapic_state = unsafe { irqchip.chip.ioapic };
    let entries: Vec<u64> = ioapic_state
        .redirtbl
        .iter()
        .map(|e| {
            // SAFETY: kvm_ioapic_entry is a union of {bits: u64, fields: ...}
            unsafe { e.bits }
        })
        .collect();

    // Get PIC master and slave state.
    let pic_master = {
        let mut pic = kvm_bindings::kvm_irqchip {
            chip_id: kvm_bindings::KVM_IRQCHIP_PIC_MASTER,
            ..Default::default()
        };
        vm_fd
            .get_irqchip(&mut pic)
            .map_err(|e| SnapshotError::Kvm(format!("KVM_GET_IRQCHIP PIC_MASTER: {e}")))?;
        // SAFETY: pic.chip.pic is valid for KVM_IRQCHIP_PIC_MASTER.
        let pic_bytes: Vec<u8> = unsafe {
            std::slice::from_raw_parts(
                (&raw const pic.chip.pic).cast::<u8>(),
                std::mem::size_of::<kvm_bindings::kvm_pic_state>(),
            )
            .to_vec()
        };
        pic_bytes
    };
    let pic_slave = {
        let mut pic = kvm_bindings::kvm_irqchip {
            chip_id: kvm_bindings::KVM_IRQCHIP_PIC_SLAVE,
            ..Default::default()
        };
        vm_fd
            .get_irqchip(&mut pic)
            .map_err(|e| SnapshotError::Kvm(format!("KVM_GET_IRQCHIP PIC_SLAVE: {e}")))?;
        // SAFETY: pic.chip.pic is valid for KVM_IRQCHIP_PIC_SLAVE.
        let pic_bytes: Vec<u8> = unsafe {
            std::slice::from_raw_parts(
                (&raw const pic.chip.pic).cast::<u8>(),
                std::mem::size_of::<kvm_bindings::kvm_pic_state>(),
            )
            .to_vec()
        };
        pic_bytes
    };

    // Get PIT channel state (see the field doc on `IrqChipState::pit`).
    let pit = vm_fd
        .get_pit2()
        .map_err(|e| SnapshotError::Kvm(format!("KVM_GET_PIT2: {e}")))?;
    // SAFETY: kvm_pit_state2 is a plain repr(C) struct; reading its bytes
    // for serialization is well-defined.
    let pit_bytes: Vec<u8> = unsafe {
        std::slice::from_raw_parts(
            (&raw const pit).cast::<u8>(),
            std::mem::size_of::<kvm_bindings::kvm_pit_state2>(),
        )
        .to_vec()
    };

    Ok(IrqChipState {
        lapic: Vec::new(),
        ioapic_base_address: ioapic_state.base_address,
        ioapic_id: ioapic_state.id,
        ioapic_irr: ioapic_state.irr,
        ioapic_entries: entries,
        pic_master: Some(pic_master),
        pic_slave: Some(pic_slave),
        pit: Some(pit_bytes),
    })
}

/// Read MSRs from the vCPU, skipping any that the kernel doesn't support.
fn capture_msrs(vcpu_fd: &kvm_ioctls::VcpuFd) -> Vec<MsrEntry> {
    let mut results = Vec::new();
    for &index in MSR_INDICES {
        let entries = [kvm_bindings::kvm_msr_entry {
            index,
            reserved: 0,
            data: 0,
        }];
        let mut msrs = kvm_bindings::Msrs::from_entries(&entries)
            .expect("single MSR entry should always succeed");
        match vcpu_fd.get_msrs(&mut msrs) {
            Ok(1) => {
                let entry = &msrs.as_slice()[0];
                results.push(MsrEntry {
                    index: entry.index,
                    data: entry.data,
                });
            }
            _ => {
                log::trace!("MSR {index:#x} not available, skipping");
            }
        }
    }
    results
}

/// Capture CPU registers from the paused `VcpuFd`.
fn capture_regs(vcpu_fd: &kvm_ioctls::VcpuFd) -> Result<CpuRegs, SnapshotError> {
    let regs = vcpu_fd
        .get_regs()
        .map_err(|e| SnapshotError::Kvm(format!("KVM_GET_REGS: {e}")))?;
    Ok(CpuRegs {
        rax: regs.rax,
        rbx: regs.rbx,
        rcx: regs.rcx,
        rdx: regs.rdx,
        rsi: regs.rsi,
        rdi: regs.rdi,
        rsp: regs.rsp,
        rbp: regs.rbp,
        r8: regs.r8,
        r9: regs.r9,
        r10: regs.r10,
        r11: regs.r11,
        r12: regs.r12,
        r13: regs.r13,
        r14: regs.r14,
        r15: regs.r15,
        rip: regs.rip,
        rflags: regs.rflags,
    })
}

/// Capture special registers from the paused `VcpuFd`.
fn capture_sregs(vcpu_fd: &kvm_ioctls::VcpuFd) -> Result<CpuSregs, SnapshotError> {
    let sregs = vcpu_fd
        .get_sregs()
        .map_err(|e| SnapshotError::Kvm(format!("KVM_GET_SREGS: {e}")))?;
    Ok(CpuSregs {
        cs: SegmentState::from(&sregs.cs),
        ds: SegmentState::from(&sregs.ds),
        es: SegmentState::from(&sregs.es),
        fs: SegmentState::from(&sregs.fs),
        gs: SegmentState::from(&sregs.gs),
        ss: SegmentState::from(&sregs.ss),
        tr: SegmentState::from(&sregs.tr),
        ldt: SegmentState::from(&sregs.ldt),
        gdt: DtableState::from(&sregs.gdt),
        idt: DtableState::from(&sregs.idt),
        cr0: sregs.cr0,
        cr2: sregs.cr2,
        cr3: sregs.cr3,
        cr4: sregs.cr4,
        cr8: sregs.cr8,
        efer: sregs.efer,
        apic_base: sregs.apic_base,
    })
}

/// Capture FPU state from the paused `VcpuFd`.
fn capture_fpu(vcpu_fd: &kvm_ioctls::VcpuFd) -> Result<CpuFpu, SnapshotError> {
    let fpu = vcpu_fd
        .get_fpu()
        .map_err(|e| SnapshotError::Kvm(format!("KVM_GET_FPU: {e}")))?;
    Ok(CpuFpu {
        fpr: fpu.fpr.to_vec(),
        fcw: fpu.fcw,
        fsw: fpu.fsw,
        ftwx: fpu.ftwx,
        last_opcode: fpu.last_opcode,
        last_ip: fpu.last_ip,
        last_dp: fpu.last_dp,
        xmm: fpu.xmm.to_vec(),
        mxcsr: fpu.mxcsr,
    })
}

/// Capture full CPU state from the paused `VcpuFd`.
fn capture_cpu_state(vcpu_fd: &kvm_ioctls::VcpuFd) -> Result<CpuState, SnapshotError> {
    // Capture XSAVE state (extended processor state: SSE, AVX, etc.).
    let xsave = match vcpu_fd.get_xsave() {
        Ok(xs) => {
            // kvm_xsave.region is [u32; 1024] = 4096 bytes.
            let bytes: Vec<u8> = xs.region.iter().flat_map(|v| v.to_le_bytes()).collect();
            Some(XsaveState { data: bytes })
        }
        Err(e) => {
            log::warn!("KVM_GET_XSAVE failed: {e}, skipping");
            None
        }
    };

    // Capture XCR0 (controls which XSAVE components are enabled).
    let xcr = match vcpu_fd.get_xcrs() {
        Ok(xcr_result) => {
            let xcr0 = if xcr_result.nr_xcrs > 0 {
                xcr_result.xcrs[0].value
            } else {
                0
            };
            Some(XcrState { xcr0 })
        }
        Err(e) => {
            log::warn!("KVM_GET_XCRS failed: {e}, skipping");
            None
        }
    };

    // Capture CPUID entries for exact restore on the same CPU.
    let cpuid_entries = match vcpu_fd.get_cpuid2(kvm_bindings::KVM_MAX_CPUID_ENTRIES) {
        Ok(cpuid) => {
            let entries: Vec<CpuidEntry> = cpuid
                .as_slice()
                .iter()
                .map(|e| CpuidEntry {
                    function: e.function,
                    index: e.index,
                    flags: e.flags,
                    eax: e.eax,
                    ebx: e.ebx,
                    ecx: e.ecx,
                    edx: e.edx,
                })
                .collect();
            Some(entries)
        }
        Err(e) => {
            log::warn!("KVM_GET_CPUID2 failed: {e}, skipping");
            None
        }
    };

    // Capture vcpu_events (pending interrupts/exceptions).
    let vcpu_events = match vcpu_fd.get_vcpu_events() {
        Ok(events) => {
            // SAFETY: kvm_vcpu_events is a plain-old-data struct; reading as raw bytes is safe.
            let bytes: Vec<u8> = unsafe {
                std::slice::from_raw_parts(
                    (&raw const events).cast::<u8>(),
                    std::mem::size_of::<kvm_bindings::kvm_vcpu_events>(),
                )
                .to_vec()
            };
            Some(VcpuEventsState { data: bytes })
        }
        Err(e) => {
            log::warn!("KVM_GET_VCPU_EVENTS failed: {e}, skipping");
            None
        }
    };

    // Per-vCPU LAPIC (moved off the VM-scoped IrqChipState).
    let lapic = vcpu_fd
        .get_lapic()
        .map_err(|e| SnapshotError::Kvm(format!("KVM_GET_LAPIC: {e}")))?;
    // kvm_lapic_state.regs is [i8; 1024]; convert to u8.
    let lapic_bytes: Vec<u8> = lapic.regs.iter().map(|&b| b as u8).collect();

    // Per-vCPU mp_state: the BSP is RUNNABLE; an AP may be
    // HALTED — restore must reinstate exactly what was captured.
    let mp_state = vcpu_fd
        .get_mp_state()
        .map_err(|e| SnapshotError::Kvm(format!("KVM_GET_MP_STATE: {e}")))?;

    Ok(CpuState {
        regs: capture_regs(vcpu_fd)?,
        sregs: capture_sregs(vcpu_fd)?,
        fpu: capture_fpu(vcpu_fd)?,
        msrs: capture_msrs(vcpu_fd),
        xsave,
        xcr,
        cpuid_entries,
        vcpu_events,
        lapic: lapic_bytes,
        mp_state: Some(mp_state.mp_state),
    })
}

/// Inject `VIRTIO_VSOCK_EVENT_TRANSPORT_RESET` into the vsock event queue.
///
/// The virtio-vsock spec defines an event queue (queue index 2) that carries
/// `virtio_vsock_event` structures from device to driver. By writing a
/// `TRANSPORT_RESET` event into this queue before snapshotting, we ensure
/// the guest driver processes it on resume and tears down all stale connections.
/// Listen sockets remain active and accept new connections.
///
/// The event is written into `target_mem_addr` — for cold snapshots, this is
/// the source VM's own memory. For warm forks, pass the fork's `MAP_PRIVATE`
/// mapping address to inject without disturbing the source's live connections.
///
/// `mem_span` is the guest physical address span (see [`Vm::mem_span`]), used
/// to bounds-check the descriptor the guest published.
///
/// Returns the guest-physical page indices the injection **wrote**. These
/// are host-side writes into guest RAM: KVM's dirty log cannot see them,
/// so an incremental keyframe that clones an ancestor `memory.bin` and
/// patches only the dirty set has to be told about them explicitly, or
/// the child boots on the ancestor's stale event ring (the #101 class —
/// see `Vm::prepare_fork_source_incremental_in`). The full-dump path
/// writes every page anyway and ignores the return value.
///
/// This mirrors Firecracker's `prepare_save` → `send_transport_reset_event`.
pub(crate) fn inject_vsock_transport_reset_into(
    mem_span: u64,
    device_states: &[MmioDeviceState],
    target_mem_addr: u64,
) -> Vec<u64> {
    const VSOCK_DEVICE_TYPE: u32 = 19;
    const EVQ_INDEX: usize = 2;
    const VIRTIO_VSOCK_EVENT_TRANSPORT_RESET: u32 = 0;

    let mem_base = target_mem_addr;
    let mut written_pages: Vec<u64> = Vec::new();
    // Record every guest-physical byte range the injection writes, as
    // page indices. Ranges are tiny (4/8/2 bytes) but may straddle a
    // page boundary, so walk from the first to the last page touched.
    let mut mark = |gpa: u64, len: u64| {
        let mut page = gpa / 4096;
        let last = (gpa + len - 1) / 4096;
        while page <= last {
            written_pages.push(page);
            page += 1;
        }
    };

    for state in device_states {
        if state.device_type != VSOCK_DEVICE_TYPE || !state.activated {
            continue;
        }
        if let Some(evq) = state.queues.get(EVQ_INDEX) {
            if !evq.ready || evq.size == 0 {
                continue;
            }
            // Pop a descriptor from the available ring.
            let avail_base = mem_base + evq.avail_addr;
            // SAFETY: avail_base points into valid guest memory (VM is paused).
            let avail_idx = unsafe { std::ptr::read_volatile((avail_base + 2) as *const u16) };
            let used_base = mem_base + evq.used_addr;
            // SAFETY: used_base + 2 points to the used ring idx in valid guest memory.
            let used_idx = unsafe { std::ptr::read_volatile((used_base + 2) as *const u16) };

            if avail_idx == used_idx {
                log::warn!("snapshot: vsock event queue empty, cannot inject TRANSPORT_RESET");
                continue;
            }

            // Read the next available descriptor index.
            let ring_offset = 4 + (used_idx % evq.size) as u64 * 2;
            // SAFETY: avail ring entry is within guest memory bounds.
            let desc_idx: u16 =
                unsafe { std::ptr::read_volatile((avail_base + ring_offset) as *const u16) };

            // Read the descriptor to get the buffer address.
            let desc_base = mem_base + evq.desc_addr;
            let desc_addr_ptr = (desc_base + u64::from(desc_idx) * 16) as *const u64;
            // SAFETY: descriptor table is in valid guest memory.
            let buf_gpa = unsafe { std::ptr::read_volatile(desc_addr_ptr) };

            // Write VIRTIO_VSOCK_EVENT_TRANSPORT_RESET (u32) to the buffer.
            if buf_gpa == 0 || buf_gpa >= mem_span {
                log::warn!(
                    "snapshot: vsock evq descriptor {desc_idx} has invalid buf_gpa={buf_gpa:#x}"
                );
                continue;
            }
            let buf_hva = (mem_base + buf_gpa) as *mut u8;
            // SAFETY: buf_gpa is verified within guest RAM bounds.
            // Write as bytes to avoid alignment requirements.
            unsafe {
                let val = VIRTIO_VSOCK_EVENT_TRANSPORT_RESET.to_le_bytes();
                std::ptr::copy_nonoverlapping(val.as_ptr(), buf_hva, 4);
            }
            mark(buf_gpa, 4);

            // Add the descriptor to the used ring.
            let used_ring_offset = 4 + (used_idx % evq.size) as u64 * 8;
            // SAFETY: used ring entry is within guest memory.
            unsafe {
                let entry_ptr = (used_base + used_ring_offset) as *mut u32;
                std::ptr::write_volatile(entry_ptr, u32::from(desc_idx));
                std::ptr::write_volatile(entry_ptr.add(1), 4); // len = sizeof(u32)
            }
            mark(evq.used_addr + used_ring_offset, 8);
            // Advance used idx.
            // SAFETY: used_base + 2 points to the used ring idx field.
            unsafe {
                std::ptr::write_volatile((used_base + 2) as *mut u16, used_idx.wrapping_add(1));
            }
            mark(evq.used_addr + 2, 2);

            log::info!(
                "snapshot: injected TRANSPORT_RESET into vsock event queue \
                 (desc={desc_idx}, buf_gpa={buf_gpa:#x})"
            );
        }
    }
    written_pages
}

/// Dump guest memory to a file.
///
/// Writes the whole guest physical address span, so `memory.bin` offsets are
/// guest physical addresses and a restore can `MAP_PRIVATE` the file straight
/// back. For guests with RAM past 4 GiB that includes the (all-zero, never
/// touched) 32-bit MMIO hole —.
fn dump_memory(vm: &Vm, snapshot_dir: &Path) -> Result<(), SnapshotError> {
    let mem_size = vm.mem_span() as usize;
    let host_addr = dump_host_addr(vm)?;

    // Write to a temp file and rename over `memory.bin`. NEVER truncate
    // the destination in place: a VM resumed from this very checkpoint
    // has `memory.bin` MAP_PRIVATE-mmapped as its RAM backing, and
    // `File::create`'s O_TRUNC would pull the pages out from under KVM
    // (EFAULT on the vCPU, SIGBUS on host access — CHALLENGES.md #130).
    // The rename keeps the old inode alive under any existing mapping.
    let mem_path = snapshot_dir.join("memory.bin");
    let tmp_path = snapshot_dir.join("memory.bin.tmp");
    let mut mem_file = fs::File::create(&tmp_path)?;
    // SAFETY: host_addr points to a valid mmap'd region of mem_size bytes.
    // For fresh VMs this is the memfd-backed GuestMemoryMmap region.
    // For restored VMs this is the MAP_PRIVATE CoW mmap.
    // Both are alive for the duration of this call (vm is borrowed).
    let mem_slice = unsafe { std::slice::from_raw_parts(host_addr, mem_size) };
    mem_file.write_all(mem_slice)?;
    mem_file.flush()?;
    drop(mem_file);
    fs::rename(&tmp_path, &mem_path)?;
    Ok(())
}

/// Host address the guest-physical span starts at, for reading guest RAM
/// out of a paused VM.
fn dump_host_addr(vm: &Vm) -> Result<*const u8, SnapshotError> {
    if vm.is_restored() {
        Ok(vm.mem_host_addr() as *const u8)
    } else {
        vm.guest_memory()
            .get_host_address(GuestAddress(0))
            .map(<*mut u8>::cast_const)
            .map_err(|e| SnapshotError::Kvm(format!("failed to get host address: {e}")))
    }
}

/// A reflink clone of an ancestor keyframe, opened for writing, that has
/// not been published under its final name yet.
///
/// Held across the `TRANSPORT_RESET` injection so the injection only
/// happens once the clone is known to have succeeded: on a non-reflink
/// filesystem the caller falls back to a full dump, and a second
/// injection would push a second event into the guest's vsock event
/// queue.
struct ClonedKeyframe {
    file: fs::File,
    tmp_path: PathBuf,
    dest_path: PathBuf,
    published: bool,
}

impl Drop for ClonedKeyframe {
    fn drop(&mut self) {
        // An unpublished clone must not survive the failure that
        // abandoned it: `create_new` would then fail EEXIST on every
        // later prepare of this node.
        if !self.published {
            let _ = fs::remove_file(&self.tmp_path);
        }
    }
}

impl ClonedKeyframe {
    /// `FICLONE` `ancestor_mem` into `snapshot_dir/memory.bin.tmp`.
    ///
    /// Fails with [`SnapshotError::ReflinkUnsupported`] when the two
    /// paths are not on one reflink-capable filesystem, so the caller
    /// can fall back to the full dump **loudly**.
    fn clone_from(
        snapshot_dir: &Path,
        ancestor_mem: &Path,
        mem_span: u64,
    ) -> Result<Self, SnapshotError> {
        use std::os::fd::AsRawFd;

        // Same tmp + rename discipline as the full dump (#130): the file
        // we are about to publish may already be MAP_PRIVATE-mapped by a
        // live VM, so the old inode must stay alive.
        let tmp_path = snapshot_dir.join("memory.bin.tmp");
        // A tmp file left behind by a crashed prepare would make
        // `create_new` fail EEXIST forever.
        let _ = fs::remove_file(&tmp_path);

        let ancestor = fs::File::open(ancestor_mem)?;
        let ancestor_len = ancestor.metadata()?.len();
        if ancestor_len != mem_span {
            return Err(SnapshotError::Kvm(format!(
                "ancestor keyframe {} is {ancestor_len} bytes but this VM's guest-physical \
                 span is {mem_span} — refusing to clone a base of a different shape",
                ancestor_mem.display(),
            )));
        }

        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        // SAFETY: both fds are valid for the duration of the call;
        // FICLONE takes the source fd as its integer argument.
        let rc = unsafe { libc::ioctl(file.as_raw_fd(), libc::FICLONE, ancestor.as_raw_fd()) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            drop(file);
            let _ = fs::remove_file(&tmp_path);
            return Err(SnapshotError::ReflinkUnsupported {
                ancestor: ancestor_mem.to_path_buf(),
                dest: tmp_path,
                detail: err.to_string(),
            });
        }
        Ok(Self {
            file,
            tmp_path,
            dest_path: snapshot_dir.join("memory.bin"),
            published: false,
        })
    }

    /// `pwrite` every page set in `dirty_bitmap` from the paused mapping
    /// at `host_addr` into the clone, then publish it with `rename`.
    ///
    /// Returns the bytes of dirt written — the keyframe's physical disk
    /// cost, which is what the tree's disk budget must count: the cloned
    /// file reports its full logical length, and `st_blocks` is no help
    /// because XFS counts a shared extent in every file that references
    /// it . A dirty page outside the span is an error,
    /// never a silent skip.
    fn patch_and_publish(
        mut self,
        dirty_bitmap: &[u64],
        host_addr: *const u8,
        mem_span: u64,
    ) -> Result<u64, SnapshotError> {
        let t_write = Instant::now();
        let (written, runs) = self.patch(dirty_bitmap, host_addr, mem_span)?;
        let write_took = t_write.elapsed();
        // Deliberately no `fsync`: the full dump this replaces does not
        // fsync either (`dump_memory` writes and renames), and a
        // keyframe is host-lifetime state, not a durable artifact. An
        // fsync here costs 2-5 s per member against ~100 ms of writes,
        // because every patched page has to break a shared extent and
        // that lands in the refcount btree (the referenced work §5,
        // CHALLENGES #154). Readers and `MAP_PRIVATE` see the page
        // cache regardless.
        fs::rename(&self.tmp_path, &self.dest_path)?;
        self.published = true;
        log::info!(
            "snapshot: patched {} MiB in {runs} run(s) in {write_took:?}",
            written / (1024 * 1024),
        );
        Ok(written)
    }

    /// Write the dirty set a **run at a time**, not a page at a time.
    ///
    /// Guest dirt is clustered, and one `pwrite` per 4 KiB page is what
    /// made the first measured incremental keyframe slower than the full
    /// dump it was meant to replace: ~400 000 syscalls for a 30 s-idle
    /// k3s node . Coalescing adjacent
    /// pages into a single write turns that into a few thousand.
    fn patch(
        &self,
        dirty_bitmap: &[u64],
        host_addr: *const u8,
        mem_span: u64,
    ) -> Result<(u64, u64), SnapshotError> {
        use std::os::unix::fs::FileExt;

        let pages = mem_span.div_ceil(4096);
        // Checked up front, and once, so the walk below stays total and
        // allocation-free — which is what makes it model-checkable.
        if let Some(top) = highest_dirty_page(dirty_bitmap) {
            if top >= pages {
                return Err(SnapshotError::Kvm(format!(
                    "dirty bitmap marks page {top}, beyond the {pages}-page \
                     guest-physical span — refusing to write a keyframe from a \
                     bitmap that does not describe this VM"
                )));
            }
        }

        let mut written: u64 = 0;
        let mut runs: u64 = 0;
        for_each_dirty_run(dirty_bitmap, |start, end| {
            let offset = start * 4096;
            let len = ((end - start) * 4096) as usize;
            // SAFETY: every run lies within the set bits of the bitmap,
            // whose highest is below `pages` by the check above, so
            // `offset + len <= mem_span`; `host_addr` points at a
            // mapping of at least `mem_span` bytes kept alive by the
            // borrowed (paused) VM.
            let bytes = unsafe { std::slice::from_raw_parts(host_addr.add(offset as usize), len) };
            self.file.write_all_at(bytes, offset)?;
            written += len as u64;
            runs += 1;
            Ok::<(), SnapshotError>(())
        })?;
        Ok((written, runs))
    }
}

/// Highest page index set in `dirty_bitmap`, or `None` if it is clear.
///
/// The bound check for the whole walk: a bitmap whose top set bit is
/// inside the guest-physical span has every set bit inside it.
fn highest_dirty_page(dirty_bitmap: &[u64]) -> Option<u64> {
    for (word_idx, &word) in dirty_bitmap.iter().enumerate().rev() {
        if word != 0 {
            return Some((word_idx as u64) * 64 + u64::from(63 - word.leading_zeros()));
        }
    }
    None
}

/// Call `f(start, end)` once per maximal run of contiguous set pages in
/// `dirty_bitmap`, in ascending order, as half-open page ranges.
///
/// Split out of [`ClonedKeyframe::patch`] so the arithmetic that decides
/// which bytes get written — the part whose soundness the `unsafe`
/// slice in the caller rests on — is pure, total and allocation-free,
/// and so can be model-checked (`verify_dirty_runs_cover_exactly`).
fn for_each_dirty_run<F, E>(dirty_bitmap: &[u64], mut f: F) -> Result<(), E>
where
    F: FnMut(u64, u64) -> Result<(), E>,
{
    // The open run, as [start, end).
    let mut run: Option<(u64, u64)> = None;
    for (word_idx, &word) in dirty_bitmap.iter().enumerate() {
        if word == 0 {
            if let Some((start, end)) = run.take() {
                f(start, end)?;
            }
            continue;
        }
        for bit in 0..64u64 {
            let page_idx = (word_idx as u64) * 64 + bit;
            if word & (1u64 << bit) == 0 {
                if let Some((start, end)) = run.take() {
                    f(start, end)?;
                }
                continue;
            }
            match run {
                Some((start, end)) if end == page_idx => run = Some((start, page_idx + 1)),
                open => {
                    if let Some((start, end)) = open {
                        f(start, end)?;
                    }
                    run = Some((page_idx, page_idx + 1));
                }
            }
        }
    }
    if let Some((start, end)) = run.take() {
        f(start, end)?;
    }
    Ok(())
}

/// Write the non-memory half of a snapshot: `cpu.json`, `devices.json`,
/// `irqchip.json`, `metadata.json`. Shared by the full and incremental
/// keyframe paths so a restore cannot tell them apart.
fn write_state_files(vm: &Vm, snapshot_dir: &Path) -> Result<(), SnapshotError> {
    let cpu_states = capture_all_cpu_states(vm)?;
    let cpu_json = serde_json::to_string_pretty(&cpu_states)?;
    fs::write(snapshot_dir.join("cpu.json"), cpu_json)?;

    let device_states = {
        let registry = vm.mmio_registry().lock().unwrap();
        registry.snapshot_device_states()
    };
    let devices_json = serde_json::to_string_pretty(&device_states)?;
    fs::write(snapshot_dir.join("devices.json"), devices_json)?;

    // Save IRQ chip state for interrupt delivery after restore.
    let irqchip_state = capture_irqchip_state(vm)?;
    let irqchip_json = serde_json::to_string_pretty(&irqchip_state)?;
    fs::write(snapshot_dir.join("irqchip.json"), irqchip_json)?;

    let metadata = SnapshotMetadata {
        memory_size_bytes: vm.memory_size(),
        kernel_path: vm.kernel_path().to_string_lossy().to_string(),
        initrd_path: vm.initrd_path().map(|p| p.to_string_lossy().to_string()),
        guest_cid: vm.guest_cid(),
        timestamp_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        block_devices: vm.block_devices().to_vec(),
        kvmclock: Some(capture_kvmclock(vm)?),
        dilation: vm.dilation(),
    };
    let metadata_json = serde_json::to_string_pretty(&metadata)?;
    fs::write(snapshot_dir.join("metadata.json"), metadata_json)?;
    Ok(())
}

/// Snapshot a paused VM as an **incremental keyframe** against
/// `ancestor_mem` : clone the ancestor's `memory.bin` and
/// overwrite only `dirty_bitmap`, then write the same state files a
/// full snapshot writes.
///
/// `dirty_bitmap` must already be the complete set of pages that differ
/// from the ancestor keyframe — the KVM log ∪ device-DMA ∪ vsock-ring
/// merge `Vm::get_and_accumulate_dirty` returns. The
/// `TRANSPORT_RESET` injection this function performs is a *host* write
/// into guest RAM that no bitmap can have seen, so its pages are OR'd in
/// here before anything is written.
///
/// Returns the bytes of dirt written (the keyframe's physical cost).
pub(crate) fn snapshot_vm_incremental(
    vm: &Vm,
    snapshot_dir: &Path,
    ancestor_mem: &Path,
    dirty_bitmap: &mut [u64],
) -> Result<u64, SnapshotError> {
    if vm.is_running() || vm.vcpu_fds().len() != vm.vcpu_count() as usize {
        return Err(SnapshotError::NotPaused);
    }
    let start = Instant::now();
    fs::create_dir_all(snapshot_dir)?;

    let mem_span = vm.mem_span();
    let host_addr = dump_host_addr(vm)?;

    // Clone before injecting: a non-reflink filesystem sends the caller
    // to the full dump, which injects a TRANSPORT_RESET of its own, and
    // two events in the guest's vsock event queue is not a state the
    // driver ever sees on a real reset.
    let t_clone = Instant::now();
    let clone = ClonedKeyframe::clone_from(snapshot_dir, ancestor_mem, mem_span)?;
    log::info!(
        "snapshot: FICLONE of {} took {:?}",
        ancestor_mem.display(),
        t_clone.elapsed()
    );

    let device_states_for_reset = {
        let registry = vm.mmio_registry().lock().unwrap();
        registry.snapshot_device_states()
    };
    let injected =
        inject_vsock_transport_reset_into(mem_span, &device_states_for_reset, vm.mem_host_addr());
    for page in injected {
        let word = (page / 64) as usize;
        if word >= dirty_bitmap.len() {
            return Err(SnapshotError::Kvm(format!(
                "TRANSPORT_RESET injection wrote page {page}, outside the \
                 {}-word dirty bitmap of this VM",
                dirty_bitmap.len()
            )));
        }
        dirty_bitmap[word] |= 1u64 << (page % 64);
    }

    let written = clone.patch_and_publish(dirty_bitmap, host_addr, mem_span)?;
    log::info!(
        "snapshot: incremental keyframe {} MiB dirt over {} in {:?}",
        written / (1024 * 1024),
        ancestor_mem.display(),
        start.elapsed()
    );

    write_state_files(vm, snapshot_dir)?;
    log::info!(
        "snapshot: incremental complete in {:?} to {}",
        start.elapsed(),
        snapshot_dir.display()
    );
    Ok(written)
}

/// Take a snapshot of the given VM to the specified directory.
///
/// The VM must be paused (`vm.pause()`) before calling this.
/// Creates the directory and writes four files:
/// - `memory.bin` — raw guest memory dump
/// - `cpu.json` — per-vCPU registers (JSON array, one entry per vCPU;
///   legacy snapshots hold a single bare object instead)
/// - `devices.json` — MMIO device state
/// - `metadata.json` — VM configuration
pub fn snapshot_vm(vm: &Vm, snapshot_dir: &Path) -> Result<(), SnapshotError> {
    if vm.is_running() || vm.vcpu_fds().len() != vm.vcpu_count() as usize {
        return Err(SnapshotError::NotPaused);
    }

    let start = Instant::now();
    fs::create_dir_all(snapshot_dir)?;

    // Inject VIRTIO_VSOCK_EVENT_TRANSPORT_RESET into the vsock event queue
    // BEFORE dumping memory. This ensures the reset event is captured in
    // the snapshot. On restore, the guest driver processes it and tears
    // down stale connections, allowing new vsock connections to work.
    // (Firecracker does this in prepare_save before serializing state.)
    let device_states_for_reset = {
        let registry = vm.mmio_registry().lock().unwrap();
        registry.snapshot_device_states()
    };
    inject_vsock_transport_reset_into(vm.mem_span(), &device_states_for_reset, vm.mem_host_addr());

    dump_memory(vm, snapshot_dir)?;
    log::info!(
        "snapshot: memory dump {}MB in {:?}",
        vm.memory_size() / (1024 * 1024),
        start.elapsed()
    );

    write_state_files(vm, snapshot_dir)?;

    log::info!(
        "snapshot: complete in {:?} to {}",
        start.elapsed(),
        snapshot_dir.display()
    );

    Ok(())
}

#[cfg(kani)]
mod verification {
    use super::highest_dirty_page;

    /// `highest_dirty_page` really is the maximum. This is the bound the
    /// `unsafe` slice in `ClonedKeyframe::patch` rests on: `patch`
    /// compares one number against the page count and every run the walk
    /// then emits is at or below it, so no write reads past the end of
    /// the paused VM's mapping.
    ///
    /// The walk itself is checked exhaustively in `dirty_run_tests`
    /// rather than here — a symbolic bitmap unrolls the 64-bit loop into
    /// a formula that puts CBMC out of memory (CHALLENGES #155).
    #[kani::proof]
    #[kani::unwind(66)]
    fn verify_highest_dirty_page_is_max() {
        let word: u64 = kani::any();
        let top = highest_dirty_page(&[word]);
        match top {
            None => assert_eq!(word, 0, "None only for a clear bitmap"),
            Some(top) => {
                assert!(top < 64);
                assert!(word & (1u64 << top) != 0, "the reported page is set");
                let mut p = top + 1;
                while p < 64 {
                    assert!(word & (1u64 << p) == 0, "nothing is set above it");
                    p += 1;
                }
            }
        }
    }
}

#[cfg(test)]
mod dirty_run_tests {
    use super::{for_each_dirty_run, highest_dirty_page};

    fn runs(bitmap: &[u64]) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        let r: Result<(), ()> = for_each_dirty_run(bitmap, |s, e| {
            out.push((s, e));
            Ok(())
        });
        r.unwrap();
        out
    }

    /// The runs must be exactly the dirty set: every page handed to the
    /// writer is dirty, every dirty page is handed over exactly once,
    /// and the runs are non-empty, ascending, disjoint and maximal.
    ///
    /// That is what makes an incremental keyframe equal to the full dump
    /// it replaces: a page the walk misses leaves the child running on
    /// the ancestor's stale bytes. Checked exhaustively over every
    /// 16-page pattern, straddling the word boundary so a run that
    /// crosses it is covered too — the shapes are all there, and a
    /// symbolic version of this is what put CBMC out of memory
    /// (CHALLENGES #155).
    #[test]
    fn dirty_runs_cover_the_dirty_set_exactly() {
        for pattern in 0u32..(1 << 16) {
            // Bits 56..64 of word 0 and 0..8 of word 1.
            let w0 = u64::from(pattern & 0xFF) << 56;
            let w1 = u64::from(pattern >> 8);
            let mut seen0 = 0u64;
            let mut seen1 = 0u64;
            let mut prev_end: Option<u64> = None;
            for (start, end) in runs(&[w0, w1]) {
                assert!(start < end, "{pattern:#x}: runs are non-empty");
                assert!(end <= 128, "{pattern:#x}: no run leaves the bitmap");
                assert!(
                    prev_end.is_none_or(|e| start > e),
                    "{pattern:#x}: runs are ascending, disjoint and maximal"
                );
                prev_end = Some(end);
                for p in start..end {
                    let (bit, seen) = if p < 64 {
                        (1u64 << p, &mut seen0)
                    } else {
                        (1u64 << (p - 64), &mut seen1)
                    };
                    let word = if p < 64 { w0 } else { w1 };
                    assert!(word & bit != 0, "{pattern:#x}: page {p} is not dirty");
                    assert!(*seen & bit == 0, "{pattern:#x}: page {p} written twice");
                    *seen |= bit;
                }
            }
            assert_eq!(seen0, w0, "{pattern:#x}: word 0 covered exactly");
            assert_eq!(seen1, w1, "{pattern:#x}: word 1 covered exactly");
        }
    }

    /// A run spanning the word boundary must come out as **one** run,
    /// spelled out because it is the case the per-word loop would most
    /// plausibly get wrong.
    #[test]
    fn dirty_run_joins_across_the_word_boundary() {
        assert_eq!(runs(&[1 << 63, 1]), vec![(63, 65)]);
        assert_eq!(runs(&[1 << 63, 0b11]), vec![(63, 66)]);
        // Bit 62 of word 0 and bit 0 of word 1 are not adjacent.
        assert_eq!(runs(&[1 << 62, 1]), vec![(62, 63), (64, 65)]);
        assert_eq!(runs(&[u64::MAX, u64::MAX]), vec![(0, 128)]);
        assert_eq!(runs(&[0, 0]), Vec::new());
    }

    #[test]
    fn highest_dirty_page_spans_words() {
        assert_eq!(highest_dirty_page(&[0, 0]), None);
        assert_eq!(highest_dirty_page(&[0b101, 0]), Some(2));
        assert_eq!(highest_dirty_page(&[u64::MAX, 1]), Some(64));
        assert_eq!(highest_dirty_page(&[1, 1 << 63]), Some(127));
    }
}
