//! VM snapshot: memory dump, CPU registers, device state.

use std::fs;
use std::io::Write;
use std::path::Path;
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
    /// internal notes: the LAPIC is per-vCPU state — pre-17b snapshots
    /// stored the (single) vCPU's LAPIC VM-scoped in
    /// [`IrqChipState::lapic`]; restore falls back to that field when
    /// this one is empty (legacy snapshots).
    #[serde(default)]
    pub lapic: Vec<u8>,
    /// Per-vCPU `KVM_GET_MP_STATE` value. Restored LAST in
    /// the per-vCPU sequence. `None` (pre-17b snapshots) restores as
    /// `KVM_MP_STATE_RUNNABLE` — correct for the BSP, which is the only
    /// vCPU such snapshots can contain. An AP may legitimately be
    /// HALTED at capture time; restoring it RUNNABLE would make it
    /// execute garbage.
    #[serde(default)]
    pub mp_state: Option<u32>,
}

/// Compat wrapper for CPU state on disk: accepts either a bare
/// `CpuState` object (pre-17b single-vCPU `cpu.json` / `VmState.cpu`)
/// or an array of them (17b+ `cpus`). New writes are always the
/// plural array form.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum CpuStatesCompat {
    /// 17b+ shape: one entry per vCPU, in vCPU-index order.
    Many(Vec<CpuState>),
    /// Legacy pre-17b shape: a single vCPU's state as a bare object.
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
    pub memory_size_bytes: u64,
    pub kernel_path: String,
    pub initrd_path: Option<String>,
    pub guest_cid: u64,
    pub timestamp_unix: u64,
    /// Virtio-blk device configs, in device order. Cold restore rebuilds
    /// one `BlockBackend` per entry against the same backing file (spec
    /// 14a Inc 1). Empty for pre-14a snapshots (serde default).
    #[serde(default)]
    pub block_devices: Vec<crate::vm::BlockConfig>,
}

/// Saved IRQ chip state (LAPIC + PIC + IOAPIC) for interrupt delivery after restore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrqChipState {
    /// Legacy VM-scoped Local APIC state (pre-17b snapshots only).
    ///
    /// The LAPIC is per-vCPU state; internal notes
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
    /// legacy singular `cpu` field (a bare object) from pre-17b
    /// snapshots.
    #[serde(alias = "cpu", deserialize_with = "de_cpus")]
    pub cpus: Vec<CpuState>,
    /// LAPIC + IOAPIC + PIC master/slave state.
    pub irqchip: IrqChipState,
    /// MMIO device states (captured so vsock etc. can be rebuilt).
    pub devices: Vec<MmioDeviceState>,
    /// Guest memory size in bytes.
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
    /// for pre-13a snapshots (serde default).
    #[serde(default)]
    pub virtiofs_shares: Vec<crate::vm::VirtiofsConfig>,
    /// Virtio-blk device configs of the source, in device order. A fork
    /// rebuilds each backend: read-only devices share the backing file;
    /// read-write devices are reflinked (`FICLONE`) into the fork's dir,
    /// failing loudly when the filesystem cannot reflink.
    /// Empty for pre-14a snapshots (serde default).
    #[serde(default)]
    pub block_devices: Vec<crate::vm::BlockConfig>,
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
    0x4B56_4D00, // KVM_MSR_WALL_CLOCK (kvmclock)
    0x4B56_4D01, // KVM_MSR_SYSTEM_TIME
    0x4B56_4D03, // KVM_MSR_WALL_CLOCK_NEW
    0x4B56_4D04, // KVM_MSR_SYSTEM_TIME_NEW
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

    // Per-vCPU LAPIC.
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
/// This mirrors Firecracker's `prepare_save` → `send_transport_reset_event`.
pub(crate) fn inject_vsock_transport_reset_into(
    memory_size: u64,
    device_states: &[MmioDeviceState],
    target_mem_addr: u64,
) {
    const VSOCK_DEVICE_TYPE: u32 = 19;
    const EVQ_INDEX: usize = 2;
    const VIRTIO_VSOCK_EVENT_TRANSPORT_RESET: u32 = 0;

    let mem_base = target_mem_addr;

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
            if buf_gpa == 0 || buf_gpa >= memory_size {
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

            // Add the descriptor to the used ring.
            let used_ring_offset = 4 + (used_idx % evq.size) as u64 * 8;
            // SAFETY: used ring entry is within guest memory.
            unsafe {
                let entry_ptr = (used_base + used_ring_offset) as *mut u32;
                std::ptr::write_volatile(entry_ptr, u32::from(desc_idx));
                std::ptr::write_volatile(entry_ptr.add(1), 4); // len = sizeof(u32)
            }
            // Advance used idx.
            // SAFETY: used_base + 2 points to the used ring idx field.
            unsafe {
                std::ptr::write_volatile((used_base + 2) as *mut u16, used_idx.wrapping_add(1));
            }

            log::info!(
                "snapshot: injected TRANSPORT_RESET into vsock event queue \
                 (desc={desc_idx}, buf_gpa={buf_gpa:#x})"
            );
        }
    }
}

/// Dump guest memory to a file.
fn dump_memory(vm: &Vm, snapshot_dir: &Path) -> Result<(), SnapshotError> {
    let mem_size = vm.memory_size() as usize;

    let host_addr: *const u8 = if vm.is_restored() {
        vm.mem_host_addr() as *const u8
    } else {
        vm.guest_memory()
            .get_host_address(GuestAddress(0))
            .map_err(|e| SnapshotError::Kvm(format!("failed to get host address: {e}")))?
    };

    let mem_path = snapshot_dir.join("memory.bin");
    let mut mem_file = fs::File::create(&mem_path)?;
    // SAFETY: host_addr points to a valid mmap'd region of mem_size bytes.
    // For fresh VMs this is the memfd-backed GuestMemoryMmap region.
    // For restored VMs this is the MAP_PRIVATE CoW mmap.
    // Both are alive for the duration of this call (vm is borrowed).
    let mem_slice = unsafe { std::slice::from_raw_parts(host_addr, mem_size) };
    mem_file.write_all(mem_slice)?;
    mem_file.flush()?;
    Ok(())
}

/// Take a snapshot of the given VM to the specified directory.
///
/// The VM must be paused (`vm.pause()`) before calling this.
/// Creates the directory and writes four files:
/// - `memory.bin` — raw guest memory dump
/// - `cpu.json` — per-vCPU registers (JSON array, one entry per vCPU;
///   pre-17b snapshots hold a single bare object instead)
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
    inject_vsock_transport_reset_into(
        vm.memory_size(),
        &device_states_for_reset,
        vm.mem_host_addr(),
    );

    dump_memory(vm, snapshot_dir)?;
    log::info!(
        "snapshot: memory dump {}MB in {:?}",
        vm.memory_size() / (1024 * 1024),
        start.elapsed()
    );

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
    };
    let metadata_json = serde_json::to_string_pretty(&metadata)?;
    fs::write(snapshot_dir.join("metadata.json"), metadata_json)?;

    log::info!(
        "snapshot: complete in {:?} to {}",
        start.elapsed(),
        snapshot_dir.display()
    );

    Ok(())
}
