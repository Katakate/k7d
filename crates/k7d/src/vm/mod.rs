//! KVM VM creation, memory mapping, vCPU run loop.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use kvm_bindings::{
    kvm_pit_config, kvm_regs, kvm_segment, kvm_userspace_memory_region, KVM_PIT_SPEAKER_DUMMY,
};
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use linux_loader::configurator::linux::LinuxBootConfigurator;
use linux_loader::configurator::{BootConfigurator, BootParams};
use linux_loader::loader::bootparam::{boot_params, setup_header};
use linux_loader::loader::bzimage::BzImage as BzImageLoader;
use linux_loader::loader::elf::Elf as ElfLoader;
use linux_loader::loader::{load_cmdline, Cmdline, KernelLoader};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

use serde::{Deserialize, Serialize};

use crate::api::AgentClient;
use crate::block::BlockBackend;
use crate::devices::{
    PipeSerialDevice, SerialTrigger, SharedPipeSerialDevice, SharedSerialDevice,
    I8042_COMMAND_PORT, I8042_RESET_PULSE, SERIAL2_PORT_BASE, SERIAL_PORT_BASE, SERIAL_PORT_SIZE,
};
use crate::mem_layout::MemLayout;
use crate::network::{TapDevice, TapNetBackend};
use crate::virtio_mmio::{
    attach_device, MmioDeviceRegistry, NotQuiescent, Placement, SharedMmioRegistry, Transport,
};
use crate::virtiofs::{VirtioFsBackend, VirtiofsdProcess};
use crate::vsock::{allocate_cid, VhostVsockBackend};

// The clock owner and the live-fork engine are `impl Vm` blocks in child
// modules: they see this module's private fields and helpers unchanged,
// and `crate::vm::*` paths keep resolving through the re-export.
mod clock;
mod fork_ops;
pub use clock::*;

/// Errors from VM operations.
#[derive(Debug, thiserror::Error)]
pub enum VmError {
    #[error("failed to open /dev/kvm: {0}")]
    KvmOpen(kvm_ioctls::Error),
    #[error("failed to create VM: {0}")]
    CreateVm(kvm_ioctls::Error),
    #[error("failed to set TSS address: {0}")]
    SetTssAddress(kvm_ioctls::Error),
    #[error("failed to create IRQ chip: {0}")]
    CreateIrqChip(kvm_ioctls::Error),
    #[error("failed to create PIT2: {0}")]
    CreatePit2(kvm_ioctls::Error),
    #[error("failed to set user memory region: {0}")]
    SetUserMemoryRegion(kvm_ioctls::Error),
    #[error("failed to create vCPU: {0}")]
    CreateVcpu(kvm_ioctls::Error),
    #[error("failed to get supported CPUID: {0}")]
    GetCpuid(kvm_ioctls::Error),
    #[error("failed to set CPUID: {0}")]
    SetCpuid(kvm_ioctls::Error),
    /// The kernel is one of the two artifacts no verb pins: the VM
    /// broker opens it by name as uid `k7d` (privilege separation), so a
    /// root-only mode on a path the *caller* can read is a real and
    /// otherwise baffling failure. The uid is in the message for that
    /// reason (CHALLENGES #250).
    #[error("failed to read kernel {path} as uid {uid}: {source}")]
    KernelFile {
        /// The kernel image that could not be read.
        path: PathBuf,
        /// Effective uid of the process that tried.
        uid: u32,
        /// What the open or read returned.
        source: std::io::Error,
    },
    #[error(
        "{path} is neither an ELF vmlinux (no \\x7fELF at 0) nor a bzImage \
         (no 'HdrS' at 0x202): first bytes {head:02x?}"
    )]
    KernelFormat {
        /// The rejected kernel image.
        path: PathBuf,
        /// The first bytes read from it, for the error message.
        head: Vec<u8>,
    },
    #[error("bzImage loader returned no setup header for {0} — cannot build the zero page")]
    BzImageNoSetupHeader(PathBuf),
    #[error("failed to load kernel: {0}")]
    KernelLoad(linux_loader::loader::Error),
    #[error("failed to load command line: {0}")]
    CmdlineLoad(linux_loader::loader::Error),
    #[error("failed to write boot params: {0}")]
    BootParams(linux_loader::configurator::Error),
    #[error("failed to set registers: {0}")]
    SetRegs(kvm_ioctls::Error),
    #[error("failed to get special registers: {0}")]
    GetSregs(kvm_ioctls::Error),
    #[error("failed to set special registers: {0}")]
    SetSregs(kvm_ioctls::Error),
    #[error("failed to set FPU: {0}")]
    SetFpu(kvm_ioctls::Error),
    #[error("failed to write guest memory: {0}")]
    GuestMemory(vm_memory::GuestMemoryError),
    #[error("failed to create guest memory: {0}")]
    CreateMemory(vm_memory::mmap::FromRangesError),
    #[error("failed to run vCPU: {0}")]
    VcpuRun(kvm_ioctls::Error),
    #[error("cmdline error: {0}")]
    Cmdline(linux_loader::cmdline::Error),
    #[error("failed to open initrd file: {0}")]
    InitrdFile(std::io::Error),
    #[error("failed to load initrd: {0}")]
    InitrdLoad(vm_memory::GuestMemoryError),
    #[error("agent error: {0}")]
    Agent(#[from] crate::api::AgentError),
    #[error("pipe error: {0}")]
    Pipe(std::io::Error),
    #[error("failed to spawn vCPU thread: {0}")]
    SpawnVcpuThread(std::io::Error),
    #[error(
        "KVM_SET_SIGNAL_MASK on a vCPU failed: {0} — without it the stop signal is \
         swallowed outside KVM_RUN and the VM cannot be reliably paused"
    )]
    VcpuSignalMask(std::io::Error),
    #[error(
        "{op} needs a paused VM: running={running}, \
         {have} of {want} vCPU fds recovered"
    )]
    NotPaused {
        /// The operation that refused to touch a running VM.
        op: &'static str,
        /// Whether the vCPU run loops are still going.
        running: bool,
        /// vCPU fds currently owned by the `Vm` (rest are in run threads).
        have: usize,
        /// vCPU fds a fully paused VM owns.
        want: usize,
    },
    #[error("failed to get KVM clock: {0}")]
    GetClock(kvm_ioctls::Error),
    #[error("failed to get TSC frequency: {0}")]
    GetTscKhz(kvm_ioctls::Error),
    #[error("failed to get MP state: {0}")]
    GetMpState(kvm_ioctls::Error),
    #[error("failed to read MSR {index:#x} on vCPU {cpu}: {reason}")]
    GetMsr {
        /// MSR index that could not be read.
        index: u32,
        /// vCPU the read was attempted on.
        cpu: usize,
        /// Why it failed.
        reason: String,
    },
    #[error("warp_clock: {0:?} is not a forward, non-zero, representable jump")]
    WarpDelta(Duration),
    #[error(
        "warp_clock: vCPU 0 has no KVM_VCPU_TSC_OFFSET device attribute \
         (group KVM_VCPU_TSC_CTRL, needs KVM_CAP_VCPU_ATTRIBUTES — Linux 5.18+): {0}"
    )]
    WarpNoTscOffsetAttr(String),
    #[error("warp_clock: KVM_SET_CLOCK += {delta_ns}ns: {reason} (the guest clock did not move)")]
    WarpSetClock {
        /// The jump that was refused.
        delta_ns: u64,
        /// Why `KVM_SET_CLOCK` failed.
        reason: String,
    },
    #[error("warp_clock: {what} on vCPU {cpu}: {reason} — {rollback}")]
    WarpVcpu {
        /// vCPU the warp died on. Named so the caller knows which
        /// guest CPU to look at.
        cpu: usize,
        /// The step that failed.
        what: &'static str,
        /// Why it failed.
        reason: String,
        /// What the rollback managed to put back.
        rollback: String,
    },
    #[error("warp_clock_lockstep: {0} did not resume after the warp")]
    WarpResume(String),
    #[error(
        "warp_clock_lockstep: no VMs to warp — a cluster-wide warp of nothing is a caller bug"
    )]
    WarpNoVms,
    #[error(
        "set_dilation x{factor}: {reason} — a live factor change needs every vCPU paused \
         (the kernel answers EBUSY while any of them is runnable) and the carried patch \
         from utils/kvm-dilation"
    )]
    SetDilation {
        /// The factor that was refused.
        factor: u32,
        /// Why the kernel refused it.
        reason: String,
    },
    #[error("set_dilation: {0} is not a factor in 1..=64")]
    DilationFactor(u32),
    #[error("set_dilation_lockstep: {0} did not resume after the factor change")]
    DilationResume(String),
    #[error(
        "set_dilation_lockstep: no VMs — a cluster-wide factor change of nothing is a caller bug"
    )]
    DilationNoVms,
    #[error(
        "vCPU {cpu} did not leave KVM_RUN within {waited:?} of being signalled ({reason}) — \
         the VM is neither running nor paused, so nothing may read its state"
    )]
    VcpuStop {
        /// vCPU that would not stop.
        cpu: usize,
        /// How long it was signalled for.
        waited: Duration,
        /// What went wrong: a timeout, or a thread that died without
        /// handing its `VcpuFd` back.
        reason: String,
    },
    #[error("failed to read the LAPIC of vCPU {cpu}: {reason}")]
    GetLapic {
        /// vCPU whose APIC page could not be read.
        cpu: usize,
        /// Why `KVM_GET_LAPIC` failed.
        reason: String,
    },
    #[error("KVM_GET_PIT2: {0}")]
    GetPit(String),
    #[error(
        "the APIC bus cycle could not be calibrated ({reason}) — without it a \
         `TMCCT` reading is a count, not a deadline, so auto-warp has no target"
    )]
    ApicUncalibrated {
        /// What the calibration attempt actually saw.
        reason: String,
    },
}

/// Where one [`Vm::pause`] spent its wall time. All host time.
#[derive(Debug, Default, Clone, Copy)]
pub struct PauseCost {
    /// Telling every virtio backend to stop touching guest memory.
    pub freeze: Duration,
    /// Getting every vCPU out of `KVM_RUN` and parked.
    pub stop_vcpus: Duration,
    /// How many signals it took in total. One per vCPU means every
    /// first signal landed; more means something is holding the vCPU
    /// that a signal does not reach, and the pause is really waiting
    /// for that (`CHALLENGES.md` #183).
    pub stop_signal_rounds: u32,
    /// Waiting for the backends' worker threads to park.
    pub quiesce: Duration,
}

/// How long [`Vm::stop_vcpu_threads`] waits for one vCPU to confirm it
/// is out of `KVM_RUN` before signalling it again. Short because a
/// delivered signal takes microseconds and a missed one is invisible;
/// the retry *is* the mechanism, not a fallback.
const VCPU_STOP_RETRY: Duration = Duration::from_micros(50);

/// Ceiling on that wait, which the retry doubles towards.
///
/// The backoff is not politeness. The stop signal is a real-time one, so
/// every `pthread_kill` *queues* an instance against `RLIMIT_SIGPENDING`
/// — a limit counted per *user*, not per thread, so one vCPU that will
/// not park takes every other VM in the process down with it: their
/// `pthread_kill`s start failing with `EAGAIN` and their pauses fail
/// for want of a signal that was never sent. A flat 50 µs retry queued
/// 45 536 signals against one wedged vCPU in a single 5 s timeout and
/// did exactly that (`CHALLENGES.md` #185). Doubling to 20 ms costs
/// ~260 signals for the same 5 s.
const VCPU_STOP_RETRY_MAX: Duration = Duration::from_millis(20);

/// How long one vCPU may refuse to leave `KVM_RUN` while being
/// signalled before that is an error. Generous: a vCPU inside a slow
/// MMIO handler is stopping, just not yet. A vCPU that has not stopped
/// after this is not slow, it is stuck, and a `pause` that returns
/// anyway hands its caller a VM whose state nothing may read.
const VCPU_STOP_TIMEOUT: Duration = Duration::from_secs(5);

// x86_64 memory layout constants
const ZERO_PAGE_START: u64 = 0x7000;
const BOOT_STACK_POINTER: u64 = 0x8ff0;
const CMDLINE_START: u64 = 0x20000;
const HIMEM_START: u64 = 0x0010_0000;
const KVM_TSS_ADDRESS: u64 = 0xfffb_d000;

// Page table addresses
const PML4_START: u64 = 0x9000;
const PDPTE_START: u64 = 0xa000;
const PDE_START: u64 = 0xb000;

// GDT / IDT addresses
const BOOT_GDT_OFFSET: u64 = 0x500;
const BOOT_IDT_OFFSET: u64 = 0x520;

// CR / EFER flags
const EFER_LMA: u64 = 0x400;
const EFER_LME: u64 = 0x100;
const X86_CR0_PE: u64 = 0x1;
const X86_CR0_PG: u64 = 0x8000_0000;
const X86_CR4_PAE: u64 = 0x20;

// bzImage boot constants
/// Offset of the `HdrS` magic inside a bzImage's real-mode setup header.
const BZIMAGE_MAGIC_OFFSET: usize = 0x202;
/// Offset of the 64-bit entry point into a bzImage's *loaded*
/// protected-mode kernel. `BzImage::load` copies the compressed kernel
/// to `kernel_load` and the 64-bit boot protocol says the loader jumps
/// to `kernel_load + 0x200` (`startup_64`) with the CPU already in long
/// mode — the ELF path's "entry point is what the header says" does not
/// apply here.
const BZIMAGE_64BIT_ENTRY_OFFSET: u64 = 0x200;

// Boot params header constants
const KERNEL_LOADER_OTHER: u8 = 0xff;
const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
const KERNEL_HDR_MAGIC: u32 = 0x5372_6448;
const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x0100_0000;
const E820_RAM: u32 = 1;
const E820_RESERVED: u32 = 2;

// MMIO device addresses — placed in the 32-bit MMIO hole, so
// they never overlap guest RAM regardless of how much RAM the guest has
// and always stay addressable in 32 bits.
const MMIO_IRQ_BASE: u32 = crate::virtio_mmio::VIRTIO_IRQ_BASE; // IRQ 5+ for virtio devices (COM1=4, COM2=3)
/// Guest boots `noapic` (8259 PIC, IRQs 0..=15). Each virtio device
/// (mmio window or PCI `INTx`) takes `MMIO_IRQ_BASE + idx`; IRQ 16+ makes
/// `request_irq` return `-EINVAL` and the device never appears
/// (`virtio_net` probe -22). IOAPIC has 24 pins but this guest does not
/// use it.
const PIC_IRQ_MAX: u32 = 15;
const MMIO_DEVICE_BUDGET: usize = (PIC_IRQ_MAX - MMIO_IRQ_BASE + 1) as usize;

/// Configuration for one host-guest directory sharing.
///
/// Introduces multi-share virtiofs (one virtiofsd + one
/// virtio-fs MMIO device per share, all on the same VM). For
/// backward compatibility with legacy callers, the existing
/// [`VmBuilder::virtiofs`] single-share API still works — it
/// becomes a thin wrapper around [`VmBuilder::virtiofs_share`] with
/// `readonly: false`. New callers should prefer
/// [`VmBuilder::virtiofs_share`] when they want explicit per-share
/// read-only semantics or need more than one share per VM.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VirtiofsConfig {
    /// Host directory to share.
    pub host_dir: PathBuf,
    /// Mount point inside the guest.
    pub guest_mount: String,
    /// If true, the share is mounted read-only in the guest AND
    /// `virtiofsd` runs with no write capability against the host
    /// directory. Defaults to `false` for backward compatibility
    /// with the historical single-share API (where every share was
    /// read-write).
    pub readonly: bool,
}

/// Configuration for one virtio-blk device backed by a raw host file.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockConfig {
    /// Backing file on the host (raw image; size must be a non-zero
    /// multiple of 512 bytes).
    pub host_path: PathBuf,
    /// If true, the device advertises `VIRTIO_BLK_F_RO` and rejects guest
    /// writes with `VIRTIO_BLK_S_IOERR`. Read-only devices fork by sharing
    /// the backing file; read-write devices require reflink support.
    pub readonly: bool,
    /// Optional guest-mount instruction. When set, the
    /// builder emits a `k7d.blk=<dev>:<mount>:<fstype>:<ro|rw>` kernel
    /// cmdline entry and the guest agent mounts the device before
    /// containers start — the same discipline as `k7d.virtiofs=`.
    /// `None` (the default, and the value deserialized from older
    /// snapshots) leaves mounting to the guest workload.
    #[serde(default)]
    pub mount: Option<BlockMountSpec>,
}

/// Guest-mount instruction for a virtio-blk device, carried on
/// [`BlockConfig::mount`] and encoded into the `k7d.blk=` kernel
/// cmdline param.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockMountSpec {
    /// Absolute mount point inside the guest (e.g. `/run/k7d/rootfs`).
    /// Must not contain `:` or `,` (the cmdline separators).
    pub guest_mount: String,
    /// Filesystem type passed to `mount -t` in the guest (e.g. `erofs`,
    /// `ext4`).
    pub fstype: String,
}

/// Network configuration for a VM.
pub struct NetworkConfig {
    /// TAP device to use.
    pub tap: TapDevice,
}

/// The single- vs multi-vCPU branch point.
///
/// **Every** place where single- and multi-vCPU behavior diverges must
/// route through this enum so a future Antithesis-style deterministic
/// replay mode — which will run `vcpus == 1` only (SMP is inherently
/// non-deterministic) — can find every divergence with one grep and
/// sit on the [`CpuTopology::Single`] path without a refactor.
///
/// Current divergences:
/// - MP-table emission at cold boot (`Smp` only; `Single` memory stays
///   byte-identical to the original layout),
/// - per-vCPU CPUID identity patching at cold boot and on the restore
///   fallback path (`Smp` only; `Single` keeps the raw host CPUID).
///
/// The capture/restore loops over vCPUs are shape-generic (a plain
/// `for` that degenerates to one iteration) and intentionally NOT
/// branch points — `Single` pays no SMP-only cost there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuTopology {
    /// One vCPU — the byte-stable substrate reserved for a future
    /// deterministic / bit-faithful replay mode.
    Single,
    /// N > 1 vCPUs (SMP): MP table + per-vCPU CPUID identity.
    Smp(u32),
}

impl CpuTopology {
    /// Classify a vCPU count. `0` is invalid everywhere (the builder
    /// rejects it) and maps to `Single` here only to keep this total.
    #[must_use]
    pub fn of(vcpus: u32) -> Self {
        if vcpus > 1 {
            Self::Smp(vcpus)
        } else {
            Self::Single
        }
    }
}

/// Builder for constructing a VM with configuration.
pub struct VmBuilder {
    kernel_path: Option<PathBuf>,
    initrd_path: Option<PathBuf>,
    memory_mb: u64,
    /// Guest vCPU count. Defaults to 1. When > 1, the
    /// builder emits an MP table so the guest kernel discovers the
    /// additional CPUs (ACPI is compiled out); `vcpus == 1` boots stay
    /// byte-identical to the original layout (no MP table, no E820
    /// reservation) so single-vCPU snapshots and the fork/tree suites
    /// are untouched.
    vcpus: u32,
    cmdline: String,
    vsock_enabled: bool,
    guest_cid: u64,
    /// Virtiofs shares, in declaration order. Index 0 is the
    /// "primary" share — when present, it preserves the historical
    /// `.virtiofs(host, "/mnt/state")` semantics: tag `k7fs`, mount
    /// at `/mnt/state`, read-write, used by `sync_state_to_guest`,
    /// `read_guest_file`, and `fork::warm_fork`'s reflink. Further
    /// shares (index >= 1) get tags `k7fs1`, `k7fs2`, … and are
    /// mounted by the agent at startup according to the
    /// `k7d.virtiofs=` kernel cmdline param.
    virtiofs_shares: Vec<VirtiofsConfig>,
    /// Virtio-blk devices, in declaration order (`/dev/vda`, `/dev/vdb`, …).
    block_devices: Vec<BlockConfig>,
    /// Absolute guest directories the agent creates at boot
    /// (`k7d.mkdir=` cmdline param). The guest rootfs is tmpfs, so
    /// these are tmpfs directories — uses them for
    /// emptyDir volumes (`/run/k7d/emptydir/<name>`).
    guest_dirs: Vec<String>,
    network: Option<NetworkConfig>,
    /// The sandbox's writable scratch image, attached as one
    /// more read-write virtio-blk device and owned by the built `Vm`.
    scratch_disk: Option<crate::disks::ScratchDisk>,
    /// Per-container writable images, same ownership rules.
    container_scratch_disks: Vec<crate::disks::ScratchDisk>,
    /// Named persistent data disks. Attached as
    /// read-write virtio-blk devices like the scratch images, but
    /// **retained**: the built `Vm` never unlinks them.
    data_disks: Vec<crate::disks::DataDisk>,
    /// Docker graph scratch image. Same ownership as
    /// [`Self::scratch_disk`]: unlinked on Drop, reflinked on fork.
    docker_disk: Option<crate::disks::ScratchDisk>,
    /// When true, the builder appends `k7d.docker=1` so the agent
    /// supervises dockerd. Set by [`Self::docker_disk`].
    docker: bool,
    /// Continuous time dilation factor: guest time runs
    /// `dilation` times faster than wall time. 1 is stock. Anything
    /// above 1 requires the carried KVM patch in `utils/kvm-dilation`
    /// and fails the build loudly on a stock host.
    dilation: u32,
    /// Advertise `CPUID.1:ECX[24]` so the guest arms the TSC-deadline
    /// timer. See [`Self::tsc_deadline_timer`].
    tsc_deadline: bool,
    /// Which bus the virtio devices sit on. See [`Self::transport`].
    transport: Transport,
}

impl Default for VmBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Default guest artifact paths `(kernel, initrd)`.
///
/// Resolution order (first complete pair wins):
/// 1. `K7D_KERNEL` + `K7D_INITRD` env (both required if either is set)
/// 2. Workspace root baked at compile time (`CARGO_MANIFEST_DIR/../../guest/...`)
/// 3. Installed share dir `/usr/local/share/k7d/{vmlinux,initramfs.cpio.gz}`
///
/// The workspace outranks the install because a host that builds k7d and
/// also has it installed holds both, and `make test` rebuilds the guest
/// before every run precisely so the suite cannot boot a stale one — an
/// installed copy winning there silently tests artifacts nobody built.
/// An installed binary has no workspace (the baked path belongs to
/// whichever host compiled it), so it still resolves to the share dir.
///
/// That last sentence holds only for a binary built on another host. A
/// build node runs binaries whose baked path is real, so this must only
/// be called by processes whose environment somebody sets deliberately:
/// the daemon (`k7d.service`) and the tests. The shim is neither — it
/// is spawned by containerd with no environment — so it sends no guest
/// paths at all and lets the daemon answer. See CHALLENGES #72.
/// Kernel command line every k7d guest boots with, on either backend.
///
/// The reasoning behind each token is in [`VmBuilder::new`], where this
/// used to be a literal. It is a constant so the Firecracker backend
/// (`crates/k7d/src/fc/`) boots the *same* guest with the *same*
/// arguments: a guest that behaves differently under the two VMMs
/// because one of them quietly dropped `clocksource=kvm-clock` would be
/// a miserable thing to debug. Both backends append their own
/// `virtio_mmio.device=` enumeration on top — k7d's builder for the
/// native path, Firecracker itself for the legacy (`MPTable`) path.
pub const DEFAULT_GUEST_CMDLINE: &str = "console=ttyS0 earlyprintk=serial,ttyS0,115200 noapic reboot=k panic=1 pci=off rdinit=/init initcall_debug mitigations=off cpuidle_haltpoll.force=1 haltpoll.guest_halt_poll_ns=200000 haltpoll.guest_halt_poll_grow_start=200000 haltpoll.guest_halt_poll_allow_shrink=0 clocksource=kvm-clock";

#[must_use]
pub fn default_guest_paths() -> (PathBuf, PathBuf) {
    let env_kernel = std::env::var_os("K7D_KERNEL");
    let env_initrd = std::env::var_os("K7D_INITRD");
    match (env_kernel, env_initrd) {
        (Some(k), Some(i)) => return (PathBuf::from(k), PathBuf::from(i)),
        (None, None) => {}
        (Some(_), None) => {
            panic!("K7D_KERNEL is set but K7D_INITRD is missing — set both or neither")
        }
        (None, Some(_)) => {
            panic!("K7D_INITRD is set but K7D_KERNEL is missing — set both or neither")
        }
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    let workspace_kernel = root.join("guest/kernel/vmlinux");
    let workspace_initrd = root.join("guest/rootfs/initramfs.cpio.gz");
    if workspace_kernel.is_file() && workspace_initrd.is_file() {
        return (workspace_kernel, workspace_initrd);
    }

    let share = PathBuf::from("/usr/local/share/k7d");
    let installed_kernel = share.join("vmlinux");
    let installed_initrd = share.join("initramfs.cpio.gz");
    if installed_kernel.is_file() && installed_initrd.is_file() {
        return (installed_kernel, installed_initrd);
    }

    // Neither exists: hand back the workspace pair so the failure names
    // the path a developer is expected to build, not one of two guesses.
    (workspace_kernel, workspace_initrd)
}

impl VmBuilder {
    /// Create a new builder with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            kernel_path: None,
            initrd_path: None,
            memory_mb: 256,
            vcpus: 1,
            // `clocksource=kvm-clock`: the guest would otherwise settle
            // on `tsc`. On a host with an invariant TSC the guest
            // demotes kvm-clock to rating 299, just under tsc's 300, on
            // the reasoning that a TSC that never stops needs no
            // paravirt help. That reasoning does not survive fork and
            // restore: the guest TSC of a restored VM resumes at the
            // value it was captured with, so a guest timing itself off
            // the TSC wakes up believing no time passed, while kvmclock
            // is VM-scoped state the host re-bases in one ioctl
            // (`KVM_SET_CLOCK`, see `fork::restore_kvmclock`). Pinning
            // it makes the clock the guest reads the clock k7d owns.
            //
            // There is no `k7d.now=` here any more: kvmclock hands the
            // guest the host's wall clock at boot through the
            // `MSR_KVM_WALL_CLOCK_NEW` page, which is what that
            // parameter was standing in for while the guest had no
            // kvmclock and no RTC.
            //
            // `idle=poll` is gone. It arrived as the other half of
            // `mitigations=off` when the VERW MDS mitigation was
            // faulting AMD Zen guests after restore; `CONFIG_CPU_MITIGATIONS`
            // being unset in `guest/kernel/config-minimal` retired that
            // reason. What it was then paying for is wake latency: a
            // guest that HLTs has to be woken by an interrupt for every
            // host round trip, and dropping the flag took
            // the virtiofs write path from 1.2 ms (1.14–1.34 across ten
            // runs) to a mean of 1.7 ms with a tail that broke the 2 ms
            // budget twice in ten. Boot-to-agent did not move either
            // way. The price was a whole host core per idle vCPU —
            // measured at 100% of a core against 1% for a guest that
            // halts — which a warm pool of idle VMs must not pay.
            //
            // The replacement is the guest haltpoll cpuidle governor
            // (`CONFIG_CPU_IDLE` + `CONFIG_HALTPOLL_CPUIDLE`): poll
            // briefly in guest mode, then HLT. Host-side
            // `kvm.halt_poll_ns` (200 µs, already on) is a different
            // mechanism — it keeps the host thread from scheduling out
            // after a vmexit, it does not remove the vmexit. Measured
            // with idle=poll off and the old kernel: default 200 µs
            // still broke the virtiofs budget in 2 of 10, and bumping
            // it to 2 ms did the same (still 2 of 10). The 0.5 ms is
            // the vmexit, which only guest-side polling removes.
            //
            // The governor starts `poll_limit_ns` at 0 and shrinks it
            // whenever an idle exceeds `guest_halt_poll_ns`, so a
            // warm-pool VM that has been sitting idle is back to
            // plain HLT on the next request. Vanilla haltpoll is
            // written for a recently-busy guest; k7d's is a parked
            // one. `guest/kernel/patches/haltpoll-seed-poll-limit.patch`
            // seeds the window at `guest_halt_poll_ns` instead of 0,
            // and the cmdline pins the vanilla 200 µs window, jumps
            // there on grow, and never shrinks. `CONFIG_NO_HZ_IDLE` +
            // `HIGH_RES_TIMERS` plus leaving `stop_tick` true in
            // `haltpoll_select` keep that window from being charged
            // once per HZ=250 tick. Leftover PIT IRQs at ~43 Hz
            // (`noapic`) still charge it: 43 Hz × 2 ms was 8.6% of a
            // host core; 43 Hz × 200 µs is ~0.86% predicted,
            // measured 1.0% over 5 s, under the 2% budget.
            // The 2 ms pin was trying to catch a virtiofs write after
            // a 1 s settle, which cannot work — after 1 s the guest
            // has already HLTed.
            //
            // Haltpoll only helps a request that arrives *during* the
            // poll window after the previous wakeup. `test_latency_virtiofs_write`
            // therefore settles 50 ms (not 1 s) and issues two warmups
            // so the timed write is that request; a 1 s gap is many
            // governor cycles past the window and takes the HLT path
            // (~1.9 ms, flaky against the 2 ms budget).
            //
            // `cpuidle_haltpoll.force=1` rather than advertising
            // `KVM_HINTS_REALTIME` (CPUID.0x4000_0001:EDX[0]). The
            // driver only installs if that hint is set or force=1 is
            // on the cmdline (`haltpoll_want()` in
            // `drivers/cpuidle/cpuidle-haltpoll.c`), and it also
            // refuses to load if any `idle=` override is present.
            // The hint is a claim that every vCPU has a dedicated host
            // CPU. k7d does not pin vCPUs and pods carry CPU quotas, so
            // force=1 is "I know what I am asking for" without a
            // promise `patch_cpuid_for_kvm_guest` would have to keep.
            // `mitigations=off` and `clocksource=kvm-clock` stay.
            cmdline: String::from(DEFAULT_GUEST_CMDLINE),
            vsock_enabled: false,
            // Every fresh VmBuilder gets a unique vsock CID from the
            // 100+ pool — vhost-vsock is a kernel-global namespace
            // and `SET_GUEST_CID` returns `EADDRINUSE` for any CID
            // that's already bound, including by another VM on the
            // same host (e.g. the `k7-api` pod's shim, or a
            // concurrent test). The legacy default `DEFAULT_GUEST_CID
            // = 3` capped a node at exactly one VM that didn't
            // override the CID, which broke (a) running multiple
            // `runtimeClassName: k7` pods on a node, (b) every
            // unit/integration test that built a `Vm` while `k7-api`
            // was up, and (c) any test suite running with
            // `--test-threads > 1`.
            //
            // Callers that need a specific CID (snapshot restore,
            // warm-fork preserving CID across forks, tests pinning
            // the CID for debugging) still call `.guest_cid(...)`
            // explicitly. `DEFAULT_GUEST_CID = 3` is kept in
            // `crate::vsock` as the historical name for the well-
            // known CID that the production `k7-api` deployment
            // happens to bind to today; nothing in the build path
            // references it any more.
            guest_cid: allocate_cid(),
            virtiofs_shares: Vec::new(),
            block_devices: Vec::new(),
            guest_dirs: Vec::new(),
            network: None,
            scratch_disk: None,
            container_scratch_disks: Vec::new(),
            data_disks: Vec::new(),
            docker_disk: None,
            docker: false,
            dilation: 1,
            tsc_deadline: false,
            transport: Transport::Mmio,
        }
    }

    /// Which bus the virtio devices sit on. [`Transport::Mmio`] is the
    /// default and what every k7d guest so far boots. [`Transport::Pci`]
    /// puts every device behind a legacy PCI bus (`crate::pci`): no
    /// `virtio_mmio.device=` tokens are emitted, the cmdline must not
    /// carry `pci=off`, and it must keep `noapic` — `INTx` rides the 8259
    /// lines, and a multi-vCPU guest that enables its IOAPIC would look
    /// for `MPTable` PCI routing entries this VMM does not write.
    #[must_use]
    pub fn transport(mut self, transport: Transport) -> Self {
        self.transport = transport;
        self
    }

    /// Set the path to the kernel image (vmlinux ELF).
    #[must_use]
    pub fn kernel(mut self, path: impl AsRef<Path>) -> Self {
        self.kernel_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Set the path to the initrd (initramfs) image.
    #[must_use]
    pub fn initrd(mut self, path: impl AsRef<Path>) -> Self {
        self.initrd_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Boot what the installed disk's bootloader entries say: kernel,
    /// initrd and command line from a [`crate::bls::DiskBoot`]. The
    /// disk itself still has to be attached with
    /// [`Self::block_device`]; this only replaces the external
    /// kernel/initrd pair and the base command line.
    #[must_use]
    pub fn boot_from(self, boot: &crate::bls::DiskBoot) -> Self {
        self.kernel(&boot.kernel)
            .initrd(&boot.initrd)
            .cmdline(&boot.cmdline)
    }

    /// Set both kernel and initrd from [`default_guest_paths`], which
    /// prefers `K7D_KERNEL`/`K7D_INITRD`, then the build workspace, then
    /// the installed share dir.
    #[must_use]
    pub fn kernel_and_initrd(self) -> Self {
        let (kernel, initrd) = default_guest_paths();
        self.kernel(kernel).initrd(initrd)
    }

    /// Replace the whole kernel command line.
    ///
    /// The default is the minimal guest's line (initramfs `rdinit`,
    /// haltpoll tuning, `noapic`, …) and every device parameter the
    /// builder derives — `virtio_mmio.device=`, `k7d.blk=`,
    /// `k7d.virtiofs=`, `k7d.mkdir=` — is still appended at
    /// [`Self::build`] time, whatever base is set here.
    ///
    /// A guest with a different init contract needs a different base
    /// line: an Ubuntu node image boots `root=/dev/vda` into
    /// systemd and must not carry `rdinit=/init`. Overriding is
    /// deliberate and total — there is no merge, so a caller that drops
    /// `console=ttyS0` gets a VM whose agent marker never reaches the
    /// host and whose [`Vm::connect_agent`] therefore times out.
    #[must_use]
    pub fn cmdline(mut self, cmdline: &str) -> Self {
        self.cmdline = cmdline.to_string();
        self
    }

    /// Set guest memory size in megabytes.
    #[must_use]
    pub fn memory_mb(mut self, mb: u64) -> Self {
        self.memory_mb = mb;
        self
    }

    /// Set the guest vCPU count. Validated loudly at
    /// [`Self::build`] time: 0 and values past the MP table maximum
    /// fail the build. `vcpus > 1` gates the MP table emission.
    #[must_use]
    pub fn vcpus(mut self, vcpus: u32) -> Self {
        self.vcpus = vcpus;
        self
    }

    /// Run this guest's clocks `n` times faster than wall time.
    /// `n == 1` is stock.
    ///
    /// The factor is a property of the VM, not of a vCPU: it rides on
    /// each vCPU's hardware TSC multiplier, which KVM programs at vCPU
    /// creation, so it is set on the VM fd before any vCPU exists. A
    /// host without the carried patch fails [`VmBuilder::build`] rather
    /// than running the guest at 1x behind the caller's back.
    #[must_use]
    pub fn dilation(mut self, n: u32) -> Self {
        self.dilation = n;
        self
    }

    /// Advertise the TSC-deadline LAPIC timer (`CPUID.1:ECX[24]`), which
    /// KVM always emulates but host kernel 6.8 leaves out of
    /// `KVM_GET_SUPPORTED_CPUID`. The guest then registers
    /// `lapic-deadline` instead of the one-shot `lapic`, as it does
    /// unasked on 7.0. Off by default: it is how the dilation suite
    /// exercises both timer modes on one host kernel.
    #[must_use]
    pub fn tsc_deadline_timer(mut self, on: bool) -> Self {
        self.tsc_deadline = on;
        self
    }

    /// Enable vhost-vsock device for host-guest communication.
    #[must_use]
    pub fn vsock(mut self, enabled: bool) -> Self {
        self.vsock_enabled = enabled;
        self
    }

    /// Override the guest vsock CID.
    ///
    /// Every fresh [`VmBuilder`] is preconfigured with a unique CID
    /// from [`crate::vsock::allocate_cid`], so most callers don't
    /// need to set this explicitly. Use this only when you need a
    /// specific CID — e.g. snapshot restore (CID is part of the
    /// snapshot identity), warm-fork preserving the source's CID,
    /// or a test pinning a specific CID for reproducibility.
    /// vhost-vsock rejects `SET_GUEST_CID` for an already-bound CID
    /// with `EADDRINUSE`, so two live VMs on the same host must
    /// have distinct CIDs.
    #[must_use]
    pub fn guest_cid(mut self, cid: u64) -> Self {
        self.guest_cid = cid;
        self
    }

    /// Attach a TAP device for virtio-net networking.
    #[must_use]
    pub fn network(mut self, tap: TapDevice) -> Self {
        self.network = Some(NetworkConfig { tap });
        self
    }

    /// Share a host directory into the guest at the given mount point
    /// (read-write).
    ///
    /// This is a thin convenience wrapper around
    /// [`Self::virtiofs_share`] with `readonly = false`. Calling this
    /// multiple times **replaces** the primary share — for true
    /// multi-share use [`Self::virtiofs_share`] directly.
    ///
    /// Backward compatibility: this preserves the legacy single-
    /// share semantics. The primary share gets tag `k7fs` and is
    /// the one returned by [`Vm::virtiofs_config`].
    #[must_use]
    pub fn virtiofs(mut self, host_dir: impl AsRef<Path>, guest_mount: &str) -> Self {
        let new_primary = VirtiofsConfig {
            host_dir: host_dir.as_ref().to_path_buf(),
            guest_mount: guest_mount.to_string(),
            readonly: false,
        };
        if self.virtiofs_shares.is_empty() {
            self.virtiofs_shares.push(new_primary);
        } else {
            // Preserve "calling .virtiofs() twice replaces" semantics
            // — the legacy API was Option<VirtiofsConfig>, so a
            // second call overwrote the first. Keep that behaviour
            // for the primary slot.
            self.virtiofs_shares[0] = new_primary;
        }
        self
    }

    /// Add an explicit virtiofs share, with control over read-only
    /// flag. Each call appends a new share; the first share added is
    /// the "primary" (tag `k7fs`, returned by [`Vm::virtiofs_config`]).
    ///
    /// Each share gets its own [`crate::virtiofs::VirtiofsdProcess`]
    /// and its own virtio-fs MMIO device. The guest agent mounts
    /// each share at `guest_mount` with the correct `ro`/`rw` flag
    /// based on the `k7d.virtiofs=` cmdline param this builder
    /// emits.
    ///
    /// `readonly: true` is enforced on the host by bind-remounting
    /// the share root `MS_RDONLY` before virtiofsd chroots, plus the
    /// in-guest `mount -o ro` the agent issues
    /// when it sees `:ro` in `k7d.virtiofs=`. The rust-vmm virtiofsd
    /// we ship has no `--readonly` flag.
    #[must_use]
    pub fn virtiofs_share(
        mut self,
        host_dir: impl AsRef<Path>,
        guest_mount: &str,
        readonly: bool,
    ) -> Self {
        self.virtiofs_shares.push(VirtiofsConfig {
            host_dir: host_dir.as_ref().to_path_buf(),
            guest_mount: guest_mount.to_string(),
            readonly,
        });
        self
    }

    /// Attach a virtio-blk device backed by a raw host file.
    /// Devices appear in the guest in declaration order
    /// (`/dev/vda`, `/dev/vdb`, …).
    ///
    /// The file is opened at [`Self::build`] time (`O_RDONLY` when
    /// `readonly`, `O_RDWR` otherwise) and validated loudly: missing file,
    /// empty file, or a size that is not a multiple of 512 fails the build.
    #[must_use]
    pub fn block_device(mut self, host_path: impl AsRef<Path>, readonly: bool) -> Self {
        self.block_devices.push(BlockConfig {
            host_path: host_path.as_ref().to_path_buf(),
            readonly,
            mount: None,
        });
        self
    }

    /// Attach a virtio-blk device like [`Self::block_device`], and have
    /// the guest agent mount it at `guest_mount` (with `mount -t
    /// <fstype>`, `-o ro` when `readonly`) before containers start.
    /// The builder encodes the instruction into the
    /// `k7d.blk=` kernel cmdline param, mirroring `k7d.virtiofs=`:
    /// `k7d.blk=vda:/run/k7d/rootfs:erofs:ro,…`.
    #[must_use]
    pub fn block_device_mounted(
        mut self,
        host_path: impl AsRef<Path>,
        readonly: bool,
        guest_mount: &str,
        fstype: &str,
    ) -> Self {
        self.block_devices.push(BlockConfig {
            host_path: host_path.as_ref().to_path_buf(),
            readonly,
            mount: Some(BlockMountSpec {
                guest_mount: guest_mount.to_string(),
                fstype: fstype.to_string(),
            }),
        });
        self
    }

    /// Have the guest agent create an absolute directory at boot,
    /// before containers start. The guest rootfs is
    /// the initramfs tmpfs, so the directory is guest-RAM-backed and
    /// forks inherit its contents through the memory `CoW` for free —
    /// this is how emptyDir volumes move off virtiofs
    /// (`/run/k7d/emptydir/<name>`, see [`crate::volumes_blk`]).
    ///
    /// Encoded as the `k7d.mkdir=` kernel cmdline param (comma-
    /// separated), mirroring `k7d.virtiofs=` / `k7d.blk=`. The path
    /// must be absolute and must not contain `,` (the separator) —
    /// validated loudly at [`Self::build`] time.
    #[must_use]
    pub fn guest_dir(mut self, path: &str) -> Self {
        self.guest_dirs.push(path.to_string());
        self
    }

    /// Attach the sandbox's writable scratch disk: the image
    /// becomes one more read-write virtio-blk device, agent-mounted at
    /// [`crate::disks::SCRATCH_GUEST_MOUNT`], and the built [`Vm`] owns
    /// it (the image is removed when the VM goes away).
    ///
    /// The guest agent puts every container's overlay `upper`/`work`
    /// there, so container writes land on the host image instead of
    /// guest RAM. Declare it LAST if the caller also assigns guest
    /// device names by index — like every other block device, position
    /// determines `/dev/vdX`.
    #[must_use]
    pub fn scratch_disk(self, disk: crate::disks::ScratchDisk) -> Self {
        let mut builder = self.block_device_mounted(
            disk.path(),
            false,
            crate::disks::SCRATCH_GUEST_MOUNT,
            "ext4",
        );
        builder.scratch_disk = Some(disk);
        builder
    }

    /// Attach a container's **own** scratch disk: one more
    /// read-write virtio-blk image, agent-mounted at
    /// [`crate::disks::container_scratch_mount`], owned by the built
    /// [`Vm`] exactly like the sandbox scratch.
    ///
    /// `name` is the Kubernetes container name. A container that has
    /// one of these puts its overlay `upper`/`work` on it instead of
    /// on the shared sandbox scratch, which is what scopes a full
    /// writable layer to the container that filled it.
    #[must_use]
    pub fn container_scratch_disk(self, name: &str, disk: crate::disks::ScratchDisk) -> Self {
        let mount = crate::disks::container_scratch_mount(name);
        let mut builder = self.block_device_mounted(disk.path(), false, &mount, "ext4");
        builder.container_scratch_disks.push(disk);
        builder
    }

    /// Attach a **named persistent** data disk: one
    /// more read-write virtio-blk image, agent-mounted at the disk's
    /// [`crate::disks::DataDisk::guest_mount`] as ext4, whose lifetime is
    /// *not* the VM's.
    ///
    /// The built [`Vm`] holds the handle for reporting only — unlike
    /// [`Self::scratch_disk`], nothing unlinks the image when the VM goes
    /// away. That is the point: an inner node's `/var/lib/longhorn` has
    /// to still be there for the next VM that claims the same `id`.
    ///
    /// A warm fork clones it into the child's own file like every other
    /// read-write block device, so two live VMs never mount one ext4.
    #[must_use]
    pub fn data_disk(self, disk: crate::disks::DataDisk) -> Self {
        let mount = disk.guest_mount().to_string();
        let mut builder = self.block_device_mounted(disk.path(), false, &mount, "ext4");
        builder.data_disks.push(disk);
        builder
    }

    /// Attach the Docker graph disk: one more read-write
    /// virtio-blk image, agent-mounted at
    /// [`crate::disks::DOCKER_GRAPH_GUEST_MOUNT`], owned by the built
    /// [`Vm`] exactly like the sandbox scratch. Also puts `k7d.docker=1`
    /// on the kernel cmdline so the agent starts dockerd.
    #[must_use]
    pub fn docker_disk(self, disk: crate::disks::ScratchDisk) -> Self {
        let mut builder = self.block_device_mounted(
            disk.path(),
            false,
            crate::disks::DOCKER_GRAPH_GUEST_MOUNT,
            "ext4",
        );
        builder.docker_disk = Some(disk);
        builder.docker = true;
        builder
    }

    /// Build and return a configured (but not started) VM.
    #[allow(clippy::too_many_lines)]
    pub fn build(self) -> Result<Vm, VmError> {
        let kernel_path = self.kernel_path.expect("kernel path is required");

        // Validate the vCPU count loudly before any resource
        // is allocated — never clamp silently.
        if self.vcpus == 0 || self.vcpus > u32::from(crate::mptable::MAX_SUPPORTED_CPUS) {
            return Err(VmError::Pipe(std::io::Error::other(format!(
                "invalid vcpus={}: must be 1..={}",
                self.vcpus,
                crate::mptable::MAX_SUPPORTED_CPUS
            ))));
        }

        let mem_size = self.memory_mb * 1024 * 1024;
        // Guest RAM straddles the 32-bit MMIO hole once it
        // passes `MMIO_HOLE_START`. `mem_span` is the guest physical
        // address space (and therefore the host mapping) length — RAM
        // plus the hole; `mem_size` stays the RAM total.
        let layout = MemLayout::from_ram(mem_size);
        let mem_span = layout.span();

        let kvm = Kvm::new().map_err(VmError::KvmOpen)?;
        let vm_fd = kvm.create_vm().map_err(VmError::CreateVm)?;

        // Before the vCPUs exist: their TSC multipliers are programmed
        // at creation and the factor rides on them.
        if self.dilation != 1 {
            set_dilation(&vm_fd, self.dilation).map_err(|e| {
                VmError::Pipe(std::io::Error::other(format!(
                    "time dilation x{}: {e}",
                    self.dilation
                )))
            })?;
        }

        // x86_64: set TSS address before creating IRQ chip
        vm_fd
            .set_tss_address(KVM_TSS_ADDRESS as usize)
            .map_err(VmError::SetTssAddress)?;

        // Create in-kernel IRQ chip and PIT
        vm_fd.create_irq_chip().map_err(VmError::CreateIrqChip)?;
        let pit_config = kvm_pit_config {
            flags: KVM_PIT_SPEAKER_DUMMY,
            ..Default::default()
        };
        vm_fd.create_pit2(pit_config).map_err(VmError::CreatePit2)?;

        // Allocate guest memory via memfd so we can share the fd with
        // virtiofsd. It travels over the vhost-user socket as SCM_RIGHTS
        // (`set_mem_table`), never by inheritance, so `MFD_CLOEXEC` stays
        // set: the helpers k7d execs must not hold the guest's RAM.
        // SAFETY: creating a memfd; name is a valid C string literal.
        let mem_fd_raw =
            unsafe { libc::memfd_create(c"k7d-guest-mem".as_ptr(), libc::MFD_CLOEXEC) };
        if mem_fd_raw < 0 {
            return Err(VmError::Pipe(std::io::Error::last_os_error()));
        }
        #[allow(clippy::cast_possible_wrap)]
        // SAFETY: mem_fd_raw is a valid memfd; setting the file size to the
        // full GPA span. The MMIO hole inside it is never touched by anyone,
        // so it costs address space but no pages.
        if unsafe { libc::ftruncate(mem_fd_raw, mem_span as libc::off_t) } < 0 {
            // SAFETY: mem_fd_raw is valid.
            unsafe { libc::close(mem_fd_raw) };
            return Err(VmError::Pipe(std::io::Error::last_os_error()));
        }

        // SAFETY: mem_fd_raw is a valid memfd; File takes ownership (for use in FileOffset).
        let mem_file = unsafe { File::from_raw_fd(mem_fd_raw) };
        let mem_fd_for_virtiofs = mem_file.as_raw_fd();

        let guest_memory = GuestMemoryMmap::<()>::from_ranges_with_files(&[(
            GuestAddress(0),
            mem_span as usize,
            Some(vm_memory::FileOffset::new(mem_file, 0)),
        )])
        .map_err(VmError::CreateMemory)?;

        let mem_host_addr = guest_memory.get_host_address(GuestAddress(0)).unwrap() as u64;

        // Register the RAM regions with KVM — one below the MMIO hole and,
        // for guests larger than it, one past 4 GiB. The hole itself is
        // deliberately left unmapped so accesses there reach the devices
        // (virtio-mmio, IOAPIC, LAPIC, KVM's TSS) instead of RAM.
        for (slot, gpa, size) in layout.slots() {
            let mem_region = kvm_userspace_memory_region {
                slot,
                guest_phys_addr: gpa,
                memory_size: size,
                userspace_addr: mem_host_addr + gpa,
                flags: 0,
            };
            // SAFETY: guest_memory is valid and will outlive the VM; the region
            // describes a sub-range of the contiguous mmap it owns.
            unsafe {
                vm_fd
                    .set_user_memory_region(mem_region)
                    .map_err(VmError::SetUserMemoryRegion)?;
            }
        }

        // Load the kernel — ELF `vmlinux` or bzImage `vmlinuz`, decided
        // by magic bytes. A bzImage hands back its own setup header,
        // which the zero page must carry verbatim.
        let (kernel_entry, setup_hdr) = load_kernel_image(&guest_memory, &kernel_path)?;

        // Set up virtio-MMIO devices and build cmdline with device params.
        //
        // Slot layout: each virtio-mmio device gets a 4 KiB GPA window
        // starting at `MMIO_HOLE_START` and a unique IRQ starting
        // at `MMIO_IRQ_BASE` (= 5). Slots are allocated sequentially
        // by `next_slot` as devices are added — the order is fixed at
        // (vsock?, virtiofs[0..N]?, blk[0..N]?, net?), matching the
        // historical (vsock@5, fs@6, net@7) layout for the common
        // single-fs-share case and extending naturally by giving each
        // additional virtiofs/blk device its own slot before net.
        let mut full_cmdline = self.cmdline.clone();
        let mmio_registry = Arc::new(std::sync::Mutex::new(MmioDeviceRegistry::new()));

        // Every virtio device consumes one PIC IRQ (`MMIO_IRQ_BASE +
        // idx`) on either transport. The guest boots `noapic`, so IRQ
        // 16+ is not requestable and the device probe fails (-EINVAL).
        let mmio_devices = usize::from(self.vsock_enabled)
            + self.virtiofs_shares.len()
            + self.block_devices.len()
            + usize::from(self.network.is_some());
        if mmio_devices > MMIO_DEVICE_BUDGET {
            return Err(VmError::Pipe(std::io::Error::other(format!(
                "{mmio_devices} virtio devices exceed the PIC IRQ budget \
                 (IRQs {MMIO_IRQ_BASE}..={PIC_IRQ_MAX}, at most {MMIO_DEVICE_BUDGET} devices) — reduce \
                 block devices / virtiofs shares / image slots"
            ))));
        }

        // A PCI guest discovers its devices by probing the bus, so the
        // cmdline carries no `virtio_mmio.device=` tokens — and must not
        // turn the bus off or route its interrupts through an IOAPIC
        // this VMM gives no PCI routing for (see `VmBuilder::transport`).
        let transport = self.transport;
        if transport == Transport::Pci {
            let tokens: Vec<&str> = self.cmdline.split_whitespace().collect();
            if tokens.contains(&"pci=off") {
                return Err(VmError::Pipe(std::io::Error::other(
                    "transport=pci but the kernel cmdline carries `pci=off` — the guest \
                     would never probe the bus and see no devices; drop the token",
                )));
            }
            if !tokens.contains(&"noapic") {
                return Err(VmError::Pipe(std::io::Error::other(
                    "transport=pci requires `noapic` on the kernel cmdline: INTx is \
                     delivered on 8259 lines and no MPTable PCI routing is written",
                )));
            }
        }

        let mut next_slot: u32 = 0;
        let placement = |idx: u32| Placement::for_index(transport, idx);
        let device_token = |p: &Placement| match transport {
            Transport::Mmio => format!(" virtio_mmio.device=4K@0x{:x}:{}", p.base_addr, p.irq),
            Transport::Pci => String::new(),
        };
        let attach_err = |e: String| VmError::Pipe(std::io::Error::other(e));

        if self.vsock_enabled {
            let p = placement(next_slot);
            next_slot += 1;
            attach_device(&vm_fd, &mmio_registry, p, None, |_| {
                VhostVsockBackend::new(self.guest_cid, mem_host_addr, mem_span)
            })
            .map_err(attach_err)?;
            full_cmdline.push_str(&device_token(&p));
            log::info!(
                "virtio-{transport} vsock at {:#x} irq {}",
                p.base_addr,
                p.irq
            );
        }

        // Spawn one virtiofsd per share, register one virtio-fs MMIO
        // device per share. Per-share Unix socket lives in a
        // **VM-unique** directory; tag is `k7fs` for index 0 (legacy
        // single-share name) and `k7fs<N>` for additional shares. The
        // agent reads `k7d.virtiofs=tag:mount:ro,...` from the kernel
        // cmdline and mounts each share inside the guest.
        //
        // The directory used to be keyed by process id alone, which
        // was fine when each shim process owned exactly one VM but
        // collides in the daemon era: two VMs built by the same k7d
        // process reuse the same `virtiofs-k7fs.sock` path, the second
        // virtiofsd dies at startup ("Resource temporarily
        // unavailable" on its pid file), and the build times out —
        // exactly what wedged pod recovery after a shim crash.
        // A per-process sequence number makes the
        // path unique per VM.
        let mut virtiofsd_processes: Vec<VirtiofsdProcess> = Vec::new();
        let mut virtiofs_share_specs: Vec<String> = Vec::new();
        if !self.virtiofs_shares.is_empty() {
            static VIRTIOFS_DIR_SEQ: AtomicU64 = AtomicU64::new(0);
            let socket_dir = std::env::temp_dir().join(format!(
                "k7d-virtiofs-{}-{}",
                std::process::id(),
                VIRTIOFS_DIR_SEQ.fetch_add(1, Ordering::SeqCst)
            ));
            let _ = std::fs::create_dir_all(&socket_dir);

            for (idx, share) in self.virtiofs_shares.iter().enumerate() {
                let p = placement(next_slot);
                next_slot += 1;

                let tag = if idx == 0 {
                    "k7fs".to_string()
                } else {
                    format!("k7fs{idx}")
                };
                let socket_path = socket_dir.join(format!("virtiofs-{tag}.sock"));

                let vfsd = VirtiofsdProcess::spawn_with_options(
                    &share.host_dir,
                    &socket_path,
                    &tag,
                    share.readonly,
                )
                .map_err(|e| VmError::Pipe(std::io::Error::other(e)))?;

                attach_device(&vm_fd, &mmio_registry, p, None, |_| {
                    VirtioFsBackend::new(
                        &socket_path,
                        &tag,
                        mem_host_addr,
                        mem_span,
                        mem_fd_for_virtiofs,
                    )
                })
                .map_err(attach_err)?;

                full_cmdline.push_str(&device_token(&p));
                log::info!(
                    "virtio-{transport} virtiofs[{idx}] tag={tag} ro={} at {:#x} irq {}",
                    share.readonly,
                    p.base_addr,
                    p.irq
                );

                virtiofsd_processes.push(vfsd);
                // Encode the per-share spec for the agent's cmdline
                // parser. Format: `<tag>:<mount>:<ro|rw>`. Comma-
                // separated across shares.
                virtiofs_share_specs.push(format!(
                    "{tag}:{}:{}",
                    share.guest_mount,
                    if share.readonly { "ro" } else { "rw" }
                ));
            }

            if !virtiofs_share_specs.is_empty() {
                full_cmdline.push_str(&format!(" k7d.virtiofs={}", virtiofs_share_specs.join(",")));
            }
        }

        // Add one virtio-blk MMIO device per configured block device.
        // Userspace backend — no vhost handshake, no
        // guest-memory fd requirement, so block-backed VMs stay on the
        // CoW fork path. Devices with a mount spec are collected into
        // the `k7d.blk=` cmdline param the guest agent mounts from,
        // keyed by the guest device name that
        // declaration order determines (`vda`, `vdb`, …).
        let mut blk_mount_specs: Vec<String> = Vec::new();
        for (idx, blk) in self.block_devices.iter().enumerate() {
            if let Some(m) = &blk.mount {
                if idx >= 26 || m.guest_mount.contains([':', ',']) || m.fstype.contains([':', ','])
                {
                    return Err(VmError::Pipe(std::io::Error::other(format!(
                        "invalid block mount spec for device {idx} \
                         (max 26 mounted devices; mount/fstype must not contain ':' or ','): \
                         {m:?}"
                    ))));
                }
                let letter = char::from(b'a' + idx as u8);
                blk_mount_specs.push(format!(
                    "vd{letter}:{}:{}:{}",
                    m.guest_mount,
                    m.fstype,
                    if blk.readonly { "ro" } else { "rw" }
                ));
            }
            let p = placement(next_slot);
            next_slot += 1;

            attach_device(&vm_fd, &mmio_registry, p, None, |_| {
                BlockBackend::new(&blk.host_path, blk.readonly, mem_host_addr, mem_span)
            })
            .map_err(attach_err)?;

            full_cmdline.push_str(&device_token(&p));
            log::info!(
                "virtio-{transport} blk[{idx}] file={} ro={} mount={:?} at {:#x} irq {}",
                blk.host_path.display(),
                blk.readonly,
                blk.mount,
                p.base_addr,
                p.irq
            );
        }
        if !blk_mount_specs.is_empty() {
            full_cmdline.push_str(&format!(" k7d.blk={}", blk_mount_specs.join(",")));
        }

        // Guest directories the agent creates at boot (emptyDir on
        // guest tmpfs). Validated loudly: an absolute,
        // comma-free path or the build fails.
        if !self.guest_dirs.is_empty() {
            for dir in &self.guest_dirs {
                if !dir.starts_with('/') || dir.contains([',', ' ']) {
                    return Err(VmError::Pipe(std::io::Error::other(format!(
                        "invalid guest dir {dir:?}: must be absolute and contain no ',' or space"
                    ))));
                }
            }
            full_cmdline.push_str(&format!(" k7d.mkdir={}", self.guest_dirs.join(",")));
        }
        if self.docker {
            full_cmdline.push_str(" k7d.docker=1");
        }

        // Add virtio-net MMIO device if network is configured.
        let mut tap_device = None;
        let mut guest_ip = None;
        if let Some(net_config) = self.network {
            // virtio-net is currently the last device allocated, so
            // we don't bump `next_slot` after consuming it. If you
            // add another device family after net here, reinstate
            // `next_slot += 1;` to keep the counter honest.
            let p = placement(next_slot);

            attach_device(&vm_fd, &mmio_registry, p, None, |_| {
                Ok(TapNetBackend::new(
                    net_config.tap.mac(),
                    net_config.tap.fd(),
                    mem_host_addr,
                    mem_span,
                ))
            })
            .map_err(attach_err)?;

            full_cmdline.push_str(&device_token(&p));
            log::info!("virtio-{transport} net at {:#x} irq {}", p.base_addr, p.irq);

            guest_ip = Some(net_config.tap.guest_ip());
            tap_device = Some(net_config.tap);
        }

        let mut cmdline = Cmdline::new(0x10000).map_err(VmError::Cmdline)?;
        cmdline
            .insert_str(&full_cmdline)
            .map_err(VmError::Cmdline)?;
        load_cmdline(&guest_memory, GuestAddress(CMDLINE_START), &cmdline)
            .map_err(VmError::CmdlineLoad)?;

        // Load initrd if provided, at the top of the LOW RAM region. The
        // Linux boot protocol carries the initrd address in the 32-bit
        // `hdr.ramdisk_image` (the 64-bit `ext_ramdisk_image` extension
        // is not used here), so an initrd placed at the top of a >4 GiB
        // guest's RAM would be truncated and the kernel would panic with
        // "VFS: Unable to mount root fs" — the actual breaker.
        let initrd_config = if let Some(ref initrd_path) = self.initrd_path {
            let initrd_data = std::fs::read(initrd_path).map_err(VmError::InitrdFile)?;
            let initrd_size = initrd_data.len();
            if initrd_size as u64 + HIMEM_START >= layout.low_size {
                return Err(VmError::Pipe(std::io::Error::other(format!(
                    "initrd of {initrd_size} bytes does not fit below the guest's low RAM \
                     end ({:#x}) — raise memory_mb",
                    layout.low_size
                ))));
            }
            // Align initrd address down to page boundary
            let initrd_addr_raw = (layout.low_size - initrd_size as u64) & !0xFFF;
            let initrd_addr = GuestAddress(initrd_addr_raw);
            guest_memory
                .write_slice(&initrd_data, initrd_addr)
                .map_err(VmError::InitrdLoad)?;
            log::info!(
                "initrd loaded: addr={:#x} size={}",
                initrd_addr.raw_value(),
                initrd_size
            );
            Some((initrd_addr, initrd_size))
        } else {
            None
        };

        // Multi-vCPU guests discover CPUs via the MP table
        // (ACPI is compiled out of the guest kernel). Gated on
        // `CpuTopology` so single-vCPU boots stay byte-identical (no MP
        // table bytes, no extra E820 entry) — the fork/tree suites and
        // the snapshot format depend on that stability.
        let mptable_reservation = match CpuTopology::of(self.vcpus) {
            CpuTopology::Smp(n) => {
                let size = crate::mptable::setup_mptable(&guest_memory, n as u8)
                    .map_err(|e| VmError::Pipe(std::io::Error::other(e)))?;
                Some((crate::mptable::MPTABLE_START, size as u64))
            }
            CpuTopology::Single => None,
        };

        // Configure boot parameters (zero page)
        configure_boot_params(
            &guest_memory,
            GuestAddress(CMDLINE_START),
            full_cmdline.len(),
            layout,
            initrd_config,
            mptable_reservation,
            setup_hdr,
        )?;

        // Create the vCPUs. Every vCPU gets CPUID + FPU setup; only
        // vCPU 0 (the BSP) gets boot registers — APs stay in their KVM
        // reset state (`KVM_MP_STATE_UNINITIALIZED`) awaiting the
        // INIT/SIPI sequence the Linux guest itself sends during SMP
        // bring-up.
        let mut kvm_cpuid = kvm
            .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .map_err(VmError::GetCpuid)?;
        patch_cpuid_for_kvm_guest(&mut kvm_cpuid);
        if self.tsc_deadline {
            if !kvm.check_extension(kvm_ioctls::Cap::TscDeadlineTimer) {
                return Err(VmError::Pipe(std::io::Error::other(
                    "tsc_deadline_timer: KVM_CAP_TSC_DEADLINE_TIMER is not available",
                )));
            }
            for entry in kvm_cpuid.as_mut_slice().iter_mut() {
                if entry.function == 0x1 {
                    entry.ecx |= 1 << 24;
                }
            }
        }
        let mut vcpu_fds = Vec::with_capacity(self.vcpus as usize);
        for cpu_index in 0..self.vcpus {
            let vcpu_fd = vm_fd
                .create_vcpu(cpu_index as u64)
                .map_err(VmError::CreateVcpu)?;
            match CpuTopology::of(self.vcpus) {
                CpuTopology::Smp(n) => {
                    // Patch the per-CPU identity leaves so each vCPU
                    // reports its own (initial) APIC ID. The single-vCPU
                    // path keeps the raw host-supported CPUID untouched
                    // (byte-stability for the fork suite).
                    let mut cpuid = kvm_cpuid.clone();
                    patch_cpuid_for_vcpu(&mut cpuid, cpu_index, n);
                    vcpu_fd.set_cpuid2(&cpuid).map_err(VmError::SetCpuid)?;
                }
                CpuTopology::Single => {
                    vcpu_fd.set_cpuid2(&kvm_cpuid).map_err(VmError::SetCpuid)?;
                }
            }
            if cpu_index == 0 {
                // Setup CPU registers for 64-bit Linux boot (BSP only).
                setup_regs(&vcpu_fd, kernel_entry)?;
                setup_sregs(&guest_memory, &vcpu_fd)?;
            }
            setup_fpu(&vcpu_fd)?;
            vcpu_fds.push(vcpu_fd);
        }

        // COM1 console — deliver real THRE interrupts on IRQ 4. Guest
        // userspace writes to /dev/console (agent logging) drain through
        // the 8250 tty path, which blocks forever once its 4 KiB xmit
        // buffer fills unless the device raises TX interrupts (kernel
        // printk polls and never noticed).
        let com1_irq_evt =
            crate::fdutil::eventfd_cloexec(libc::EFD_NONBLOCK).map_err(VmError::Pipe)?;
        vm_fd
            .register_irqfd(&com1_irq_evt, crate::devices::SERIAL_IRQ)
            .map_err(|e| VmError::Pipe(std::io::Error::other(e)))?;
        let serial = crate::devices::create_serial_device_with_trigger(
            SerialTrigger::with_eventfd(Arc::new(com1_irq_evt)),
        );

        // COM2 for agent communication — use irqfd to deliver IRQ 3 to guest
        let com2_irq_evt =
            crate::fdutil::eventfd_cloexec(libc::EFD_NONBLOCK).map_err(VmError::Pipe)?;
        vm_fd
            .register_irqfd(&com2_irq_evt, 3)
            .map_err(|e| VmError::Pipe(std::io::Error::other(e)))?;
        let com2_trigger = SerialTrigger::with_eventfd(Arc::new(com2_irq_evt));
        let (agent_serial, _) =
            PipeSerialDevice::with_trigger(com2_trigger).map_err(VmError::Pipe)?;
        let agent_serial = Arc::new(std::sync::Mutex::new(agent_serial));

        Ok(Vm {
            _kvm: kvm,
            vm_fd,
            vcpus: self.vcpus,
            vcpu_fds,
            guest_memory,
            memory_size: mem_size,
            kernel_path,
            initrd_path: self.initrd_path,
            serial,
            agent_serial,
            mmio_registry,
            guest_cid: if self.vsock_enabled {
                self.guest_cid
            } else {
                0
            },
            virtiofsds: virtiofsd_processes,
            tap: tap_device,
            guest_ip,
            virtiofs_shares: self.virtiofs_shares,
            block_devices: self.block_devices,
            running: Arc::new(AtomicBool::new(false)),
            paused: Arc::new(AtomicBool::new(false)),
            vcpu_threads: Vec::new(),
            vcpu_return_rxs: Vec::new(),
            vcpu_resume_txs: Vec::new(),
            vcpu_telemetry: Vec::new(),
            last_pause: PauseCost::default(),
            pause_not_quiescent: Vec::new(),
            vcpu_tids: Vec::new(),
            vcpu_kernel_tids: Vec::new(),
            restored: false,
            cow_mmap_addr: None,
            fork_mem_file: None,
            fork_state_dir: None,
            fork_source_base_path: None,
            dirty_tracking_enabled: false,
            accumulated_dirty: None,
            fork_source_dir: None,
            slow_fork_allowed: false,
            scratch_disk: self.scratch_disk,
            container_scratch_disks: self.container_scratch_disks,
            data_disks: self.data_disks,
            docker_disk: self.docker_disk,
            dilation: self.dilation,
            dilation_peak: self.dilation,
            clock_at_rest_ms: 0,
        })
    }
}

/// A running (or ready-to-run) KVM virtual machine.
/// Field order matters for Drop: devices must be dropped before guest memory.
pub struct Vm {
    _kvm: Kvm,
    vm_fd: VmFd,
    /// Guest vCPU count this VM was built with. Restored /
    /// forked VMs inherit the captured vCPU count.
    vcpus: u32,
    /// The vCPU fds, in vCPU-index order. Populated while the VM is
    /// stopped/paused; drained into the run-loop threads by
    /// [`Self::start`] and refilled by [`Self::pause`].
    vcpu_fds: Vec<VcpuFd>,
    serial: SharedSerialDevice,
    agent_serial: SharedPipeSerialDevice,
    /// MMIO devices dropped before guest memory to avoid use-after-free in workers.
    mmio_registry: SharedMmioRegistry,
    /// All `virtiofsd` child processes spawned for this VM's
    /// virtiofs shares. Dropped before `guest_memory` (field order)
    /// so each daemon's vhost-user socket goes away cleanly before
    /// the backing memfd is unmapped. Empty for restored VMs (which
    /// never re-spawn virtiofsd) and for VMs with no virtiofs shares
    /// configured.
    virtiofsds: Vec<VirtiofsdProcess>,
    tap: Option<TapDevice>,
    guest_cid: u64,
    /// Guest memory size in bytes.
    memory_size: u64,
    /// Path to the kernel image used to boot this VM.
    kernel_path: PathBuf,
    /// Path to the initrd image, if any.
    initrd_path: Option<PathBuf>,
    /// Guest memory dropped LAST (after all devices that reference it).
    guest_memory: GuestMemoryMmap,
    guest_ip: Option<std::net::Ipv4Addr>,
    /// Virtiofs shares attached to this VM, in declaration order.
    /// Index 0 is the "primary" share (the one returned by
    /// [`Self::virtiofs_config`] and used by `sync_state_to_guest`
    /// / `read_guest_file` / `fork::warm_fork`'s reflink) — its tag
    /// is `k7fs` and it mounts at the path the caller passed to
    /// [`VmBuilder::virtiofs`]. Additional shares (index >= 1) get
    /// tags `k7fs1`, `k7fs2`, … and are mounted by the guest agent
    /// according to the `k7d.virtiofs=` kernel cmdline param.
    virtiofs_shares: Vec<VirtiofsConfig>,
    /// Virtio-blk devices attached to this VM, in declaration order
    /// (`/dev/vda`, `/dev/vdb`, …). Persisted in snapshots so restore /
    /// fork can rebuild the backends.
    block_devices: Vec<BlockConfig>,
    /// Whether the vCPU run-loop threads should stay alive at all.
    /// Cleared only by [`Vm::shutdown`] — a pause uses [`Vm::paused`],
    /// because a thread that exits and is replaced makes KVM
    /// `synchronize_rcu` on the next `KVM_RUN` (`CHALLENGES.md` #183).
    running: Arc<AtomicBool>,
    /// Whether the vCPU threads should hand their `VcpuFd`s over and
    /// park. See [`Vm::pause`].
    paused: Arc<AtomicBool>,
    /// One run-loop thread per vCPU, in vCPU-index order. Lives for as
    /// long as the VM does, across any number of pauses.
    vcpu_threads: Vec<thread::JoinHandle<()>>,
    /// Per-thread channels to receive each `VcpuFd` back when its
    /// run-loop thread parks or stops, in vCPU-index order.
    vcpu_return_rxs: Vec<mpsc::Receiver<VcpuFd>>,
    /// Per-thread channels to hand each `VcpuFd` back to its parked
    /// thread on resume, in vCPU-index order. Dropping them is how a
    /// parked thread is told to exit.
    vcpu_resume_txs: Vec<mpsc::Sender<VcpuFd>>,
    /// What each vCPU thread is doing, in vCPU-index order. Read only
    /// by [`Vm::where_is_vcpu_thread`].
    vcpu_telemetry: Vec<Arc<VcpuTelemetry>>,
    /// Where the last [`Vm::pause`] spent its time. See
    /// [`Vm::last_pause_cost`].
    last_pause: PauseCost,
    /// Devices that missed the 200 ms park deadline on the last
    /// [`Self::pause`]. Empty when every worker parked. `pause` itself
    /// never fails (it has non-fork callers); the fork path reads this.
    pause_not_quiescent: Vec<NotQuiescent>,
    /// `pthread_t` of each vCPU thread (for sending signals to break
    /// `KVM_RUN`), in vCPU-index order.
    vcpu_tids: Vec<Arc<AtomicU64>>,
    /// Kernel TID of each vCPU thread (written to a CPU
    /// cgroup's `cgroup.threads` — pthread ids are useless there).
    /// `0` while the thread hasn't published it yet / isn't running.
    vcpu_kernel_tids: Vec<Arc<AtomicU64>>,
    /// Whether this VM was restored from a snapshot.
    restored: bool,
    /// For restored VMs: the `MAP_PRIVATE` mmap address (for cleanup on Drop).
    cow_mmap_addr: Option<u64>,
    /// For virtiofs-backed forks: the memfd behind the fork's full-copy
    /// memory (see `fork::memfd_fork_memory`). Held so the fd stays
    /// valid for the vhost-user `SET_MEM_TABLE` handshake and any later
    /// re-fork; the mapping itself is unmapped via `cow_mmap_addr`.
    fork_mem_file: Option<File>,
    /// For forked VMs: the reflink-copied state directory (cleaned up on Drop).
    fork_state_dir: Option<PathBuf>,
    /// Path to the `base.mem` file this VM is fork-ready against.
    /// Set by `prepare_fork_source`.
    fork_source_base_path: Option<PathBuf>,
    /// Whether KVM dirty tracking is enabled on this VM's memory slot.
    dirty_tracking_enabled: bool,
    /// Accumulated dirty bitmap across all `get_and_accumulate_dirty` calls since
    /// dirty tracking was enabled. One bit per 4 KiB page; `u64` word per 256 KiB.
    accumulated_dirty: Option<Vec<u64>>,
    /// Parent directory holding the `base.mem` + `cpu.json` for this fork source.
    /// Cleaned up on Drop when the VM owns it.
    fork_source_dir: Option<PathBuf>,
    /// Explicit opt-in for slow (full-memfd) forks of
    /// virtiofs-backed VMs. `prepare_fork_source*` on a VM with any
    /// virtiofs share fails loudly unless [`Self::allow_slow_fork`]
    /// was called first — silent degradation from the `CoW` fast path
    /// to a full memory copy is forbidden.
    slow_fork_allowed: bool,
    /// The sandbox's writable scratch image (containers'
    /// overlay upper). Declared LAST so it drops after the devices that
    /// read and write it — dropping it unlinks the host image.
    ///
    /// A fork does not inherit this handle: `fork::restore_vm_from_state`
    /// reflinks every read-write image into the fork's own directory,
    /// which the fork owns via `fork_state_dir`.
    scratch_disk: Option<crate::disks::ScratchDisk>,
    /// Per-container writable images, one per container that
    /// asked for its own writable-space limit. Same ownership and fork
    /// rules as `scratch_disk`.
    container_scratch_disks: Vec<crate::disks::ScratchDisk>,
    /// Named persistent data disks. Held for reporting;
    /// deliberately **not** cleaned up on drop — `delete_vm` leaves a
    /// data disk's image alone, and only an explicit
    /// [`crate::disks::DataDisk::delete`] (or the age-gated sweep)
    /// removes it.
    ///
    /// A fork does not inherit these handles: like every read-write
    /// image, the child's copy is a reflink in the fork's own directory,
    /// and so — after `prepare_fork_source` — is the source's.
    data_disks: Vec<crate::disks::DataDisk>,
    /// Docker graph scratch image. Same ownership as
    /// [`Self::scratch_disk`]: unlinked on Drop, reflinked on fork.
    docker_disk: Option<crate::disks::ScratchDisk>,
    /// Time dilation factor this VM runs at *now*; 1 for
    /// every VM that did not ask for it. A restored or forked VM runs at
    /// the factor its snapshot was taken at — the
    /// snapshot carries it, and `fork::restore_dilation` applies it
    /// before the first vCPU exists. [`Vm::set_dilation_live`] moves it
    /// on a paused VM.
    dilation: u32,
    /// The highest factor this VM has ever run at — what the fork and
    /// snapshot refusal asks, because dropping the factor back to 1 does
    /// not bring the guest's clock back out of the host's future.
    dilation_peak: u32,
    /// Guest-time milliseconds the snapshot this VM was restored from
    /// spent at rest (`(now − capture) × dilation`). `0` for a cold
    /// boot, a snapshot with no kvmclock reading, and a [`crate::fork::ClockMode::Frozen`]
    /// restore still reports the gap — frozen only skips adding it.
    clock_at_rest_ms: u64,
}

/// Outcome of preparing a VM as a fork source.
///
/// The `disk_bytes` field is what the snapshot tree's disk budget must
/// count for the keyframe: an incremental keyframe is a reflink clone,
/// so its file reports the full logical span while it physically adds
/// only the dirty extents — and `st_blocks` is no help, because XFS
/// counts a shared extent in every file that references it.
#[derive(Debug, Clone)]
pub struct PreparedBase {
    /// Path to the `memory.bin` future warm forks `MAP_PRIVATE`.
    pub base_mem: PathBuf,
    /// Whether the keyframe was written incrementally (`FICLONE` +
    /// dirty pages) rather than as a full dump.
    pub incremental: bool,
    /// Physical bytes this keyframe added to the filesystem.
    pub disk_bytes: u64,
}

impl PreparedBase {
    /// A full-dump keyframe: every byte of the span is newly written.
    #[must_use]
    pub fn full(base_mem: PathBuf, mem_span: u64) -> Self {
        Self {
            base_mem,
            incremental: false,
            disk_bytes: mem_span,
        }
    }
}

impl Vm {
    /// Create a new VM builder.
    #[must_use]
    pub fn builder() -> VmBuilder {
        VmBuilder::new()
    }

    /// Restore a VM from a snapshot directory using `CoW` `MAP_PRIVATE` mmap.
    ///
    /// The restored VM gets a new vsock CID. Memory is mapped copy-on-write
    /// from the snapshot's `memory.bin` — no upfront copy, O(1) time.
    /// The guest clock is rebased to real now ([`crate::fork::ClockMode::Wall`]).
    /// [`Self::restore_with_clock`] selects `frozen` instead.
    pub fn restore(snapshot_dir: &std::path::Path) -> Result<Self, crate::fork::RestoreError> {
        crate::fork::restore_vm(snapshot_dir)
    }

    /// [`Self::restore`] with an explicit kvmclock rebase.
    ///
    /// [`crate::fork::ClockMode::Wall`] matches [`Self::restore`].
    /// [`crate::fork::ClockMode::Frozen`] does not add the at-rest gap.
    pub fn restore_with_clock(
        snapshot_dir: &std::path::Path,
        clock: crate::fork::ClockMode,
    ) -> Result<Self, crate::fork::RestoreError> {
        crate::fork::restore_vm_with_clock(snapshot_dir, clock)
    }

    /// Internal constructor for a VM restored from snapshot with proper `GuestMemoryMmap`.
    ///
    /// Called by `fork::restore_vm`. Not public API — use `Vm::restore()`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_restored_with_memory(
        kvm: Kvm,
        vm_fd: VmFd,
        vcpu_fds: Vec<VcpuFd>,
        guest_memory: GuestMemoryMmap,
        cow_mmap_addr: u64,
        memory_size: u64,
        kernel_path: PathBuf,
        initrd_path: Option<PathBuf>,
        serial: SharedSerialDevice,
        agent_serial: SharedPipeSerialDevice,
        mmio_registry: SharedMmioRegistry,
        guest_cid: u64,
        virtiofsds: Vec<crate::virtiofs::VirtiofsdProcess>,
        tap: Option<crate::network::TapDevice>,
        guest_ip: Option<std::net::Ipv4Addr>,
        virtiofs_shares: Vec<VirtiofsConfig>,
        block_devices: Vec<BlockConfig>,
        dilation: u32,
    ) -> Self {
        // GuestMemoryMmap is created by the caller with MAP_PRIVATE
        // mapping of the snapshot file. KVM uses this same mapping.
        assert!(
            !vcpu_fds.is_empty(),
            "restored VM must carry at least one vCPU fd"
        );
        Self {
            _kvm: kvm,
            vm_fd,
            // Restored/forked VMs inherit the captured vCPU
            // count — one fd per captured CpuState, in index order.
            vcpus: vcpu_fds.len() as u32,
            vcpu_fds,
            guest_memory,
            memory_size,
            kernel_path,
            initrd_path,
            serial,
            agent_serial,
            mmio_registry,
            guest_cid,
            virtiofsds,
            tap,
            guest_ip,
            virtiofs_shares,
            block_devices,
            running: Arc::new(AtomicBool::new(false)),
            paused: Arc::new(AtomicBool::new(false)),
            vcpu_threads: Vec::new(),
            vcpu_return_rxs: Vec::new(),
            vcpu_resume_txs: Vec::new(),
            vcpu_telemetry: Vec::new(),
            last_pause: PauseCost::default(),
            pause_not_quiescent: Vec::new(),
            vcpu_tids: Vec::new(),
            vcpu_kernel_tids: Vec::new(),
            restored: true,
            cow_mmap_addr: Some(cow_mmap_addr),
            fork_mem_file: None,
            fork_state_dir: None,
            fork_source_base_path: None,
            dirty_tracking_enabled: false,
            accumulated_dirty: None,
            fork_source_dir: None,
            slow_fork_allowed: false,
            // A restored VM either replaces its source (the swap in
            // `prepare_fork_source_in` moves the handle across) or is a
            // fork owning reflinked copies via `fork_state_dir`.
            scratch_disk: None,
            container_scratch_disks: Vec::new(),
            data_disks: Vec::new(),
            docker_disk: None,
            dilation,
            dilation_peak: dilation,
            clock_at_rest_ms: 0,
        }
    }

    /// Guest-time milliseconds this VM's snapshot spent at rest.
    ///
    /// Written when the VM is restored. `0` until then.
    #[must_use]
    pub fn clock_at_rest_ms(&self) -> u64 {
        self.clock_at_rest_ms
    }

    pub(crate) fn set_clock_at_rest_ms(&mut self, ms: u64) {
        self.clock_at_rest_ms = ms;
    }

    /// Host path of this VM's scratch image, when it has one.
    #[must_use]
    pub fn scratch_disk_path(&self) -> Option<&Path> {
        self.scratch_disk
            .as_ref()
            .map(crate::disks::ScratchDisk::path)
    }

    /// Host paths of this VM's per-container scratch images,
    /// in declaration order.
    #[must_use]
    pub fn container_scratch_paths(&self) -> Vec<&Path> {
        self.container_scratch_disks
            .iter()
            .map(crate::disks::ScratchDisk::path)
            .collect()
    }

    /// This VM's named persistent data disks, in declaration order.
    #[must_use]
    pub fn data_disks(&self) -> &[crate::disks::DataDisk] {
        &self.data_disks
    }

    /// Attach the memfd backing a virtiofs-capable fork's memory (see
    /// [`crate::fork::memfd_fork_memory`]). Held for the VM's lifetime.
    pub(crate) fn set_fork_mem_file(&mut self, file: File) {
        self.fork_mem_file = Some(file);
    }

    /// Start one vCPU run loop per vCPU in background threads.
    ///
    /// Called once per VM. A pause does not stop these threads and a
    /// resume does not replace them — see [`Vm::pause`].
    pub fn start(&mut self) -> Result<(), VmError> {
        assert!(!self.vcpu_fds.is_empty(), "VM already started");
        assert!(
            self.vcpu_threads.is_empty(),
            "VM already has vCPU threads — resume(), not start(), is what follows a pause"
        );
        self.running.store(true, Ordering::SeqCst);
        self.paused.store(false, Ordering::SeqCst);
        install_vcpu_signal_handler();
        // Before any thread enters the guest: a vCPU that cannot be
        // signalled out of `KVM_RUN` cannot be paused, so refuse to
        // start rather than discover it at the first pause.
        for vcpu_fd in &self.vcpu_fds {
            set_kvm_signal_mask(vcpu_fd)?;
        }

        for (cpu_index, vcpu_fd) in self.vcpu_fds.drain(..).enumerate() {
            let serial = Arc::clone(&self.serial);
            let agent_serial = Arc::clone(&self.agent_serial);
            let mmio_registry = Arc::clone(&self.mmio_registry);
            let (return_tx, rx) = mpsc::channel();
            let (resume_tx, resume_rx) = mpsc::channel();
            let telemetry = Arc::new(VcpuTelemetry::default());
            let control = VcpuControl {
                running: Arc::clone(&self.running),
                paused: Arc::clone(&self.paused),
                return_tx,
                resume_rx,
                telemetry: Arc::clone(&telemetry),
            };
            let tid = Arc::new(AtomicU64::new(0));
            let kernel_tid = Arc::new(AtomicU64::new(0));

            let handle = {
                let tid = Arc::clone(&tid);
                let kernel_tid = Arc::clone(&kernel_tid);
                thread::Builder::new()
                    // Visible in /proc/<tid>/comm — used by ps/gdb and the
                    // Cgroup-membership integration test.
                    .name(format!("vcpu{cpu_index}"))
                    .spawn(move || {
                        // Block the stop signal on this thread *before*
                        // publishing the pthread id: a `pause` that sees
                        // the id signals immediately, and until the
                        // signal is blocked here that signal can be
                        // swallowed outside `KVM_RUN`.
                        block_vcpu_stop_signal();
                        // SAFETY: pthread_self() returns the calling thread's ID.
                        tid.store(unsafe { libc::pthread_self() } as u64, Ordering::SeqCst);
                        // SAFETY: gettid has no preconditions.
                        kernel_tid.store(unsafe { libc::gettid() } as u64, Ordering::SeqCst);
                        vcpu_run_loop(
                            cpu_index,
                            vcpu_fd,
                            &serial,
                            &agent_serial,
                            &mmio_registry,
                            control,
                        );
                    })
                    .map_err(VmError::SpawnVcpuThread)?
            };

            self.vcpu_threads.push(handle);
            self.vcpu_return_rxs.push(rx);
            self.vcpu_resume_txs.push(resume_tx);
            self.vcpu_telemetry.push(telemetry);
            self.vcpu_tids.push(tid);
            self.vcpu_kernel_tids.push(kernel_tid);
        }
        Ok(())
    }

    /// Read serial output, waiting up to `timeout` for data.
    /// Returns all output accumulated so far.
    #[must_use]
    pub fn serial_output(&self, timeout: Duration) -> String {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let output = {
                let dev = self.serial.lock().unwrap();
                String::from_utf8_lossy(dev.output()).to_string()
            };
            if output.contains("Kernel panic")
                || output.contains("Freeing unused kernel")
                || std::time::Instant::now() >= deadline
            {
                return output;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    /// Connect to the guest agent.
    /// Uses vsock if enabled, otherwise falls back to COM2 serial pipe.
    ///
    /// For restored VMs, skips the serial boot marker wait and connects
    /// via vsock directly (the guest agent is already running).
    pub fn connect_agent(&self, timeout: Duration) -> Result<AgentClient, VmError> {
        if self.is_restored() && self.guest_cid > 0 {
            // Restored VM: agent is already running, connect via vsock directly.
            return Ok(AgentClient::connect_vsock(self.guest_cid, timeout)?);
        }

        let deadline = std::time::Instant::now() + timeout;
        // Poll serial output for the agent startup marker
        loop {
            let output = {
                let dev = self.serial.lock().unwrap();
                String::from_utf8_lossy(dev.output()).to_string()
            };
            if output.contains("k7-agent") && output.contains("listen") {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err(VmError::Agent(crate::api::AgentError::Timeout));
            }
            thread::sleep(Duration::from_millis(10));
        }

        if self.guest_cid > 0 {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            Ok(AgentClient::connect_vsock(
                self.guest_cid,
                remaining.max(Duration::from_secs(10)),
            )?)
        } else {
            Ok(AgentClient::new(Arc::clone(&self.agent_serial), timeout)?)
        }
    }

    /// Sync the host state directory into the guest after agent connects.
    /// Pushes all files from the host directory to the guest mount point.
    ///
    /// Operates on the **primary** virtiofs share (index 0) only —
    /// callers that have configured multiple shares must do their own
    /// per-share sync via the agent protocol if needed.
    pub fn sync_state_to_guest(&self, agent: &mut AgentClient) -> Result<(), VmError> {
        let Some(config) = self.virtiofs_shares.first() else {
            return Ok(());
        };
        let host_dir = &config.host_dir;
        let guest_mount = &config.guest_mount;

        // Create the guest mount directory
        agent
            .exec(&["mkdir", "-p", guest_mount])
            .map_err(VmError::Agent)?;

        // Walk the host directory and push each file
        if host_dir.exists() {
            sync_dir_to_guest(agent, host_dir, host_dir, guest_mount)?;
        }
        Ok(())
    }

    /// Read a file from the guest's **primary** virtiofs share back
    /// to the host.
    pub fn read_guest_file(
        &self,
        agent: &mut AgentClient,
        relative_path: &str,
    ) -> Result<Vec<u8>, VmError> {
        let config = self
            .virtiofs_shares
            .first()
            .expect("virtiofs not configured");
        let guest_path = format!("{}/{}", config.guest_mount, relative_path);
        agent.read_file(&guest_path).map_err(VmError::Agent)
    }

    /// Get the assigned guest IP address, if networking is configured.
    #[must_use]
    pub fn guest_ip(&self) -> Option<std::net::Ipv4Addr> {
        self.guest_ip
    }

    /// Get the **primary** virtiofs share's configuration, if any.
    ///
    /// Backward-compatible accessor for code that predates
    /// multi-share support — returns the share at index 0, which is
    /// the one set by [`VmBuilder::virtiofs`] and the one that
    /// `fork::warm_fork`'s reflink-copy operates on. New code that
    /// needs all shares should use [`Self::virtiofs_shares`].
    #[must_use]
    pub fn virtiofs_config(&self) -> Option<&VirtiofsConfig> {
        self.virtiofs_shares.first()
    }

    /// Get all virtiofs shares attached to this VM, in declaration
    /// order. Empty when no shares are configured.
    #[must_use]
    pub fn virtiofs_shares(&self) -> &[VirtiofsConfig] {
        &self.virtiofs_shares
    }

    /// Get all virtio-blk devices attached to this VM, in declaration
    /// order. Empty when none are configured.
    #[must_use]
    pub fn block_devices(&self) -> &[BlockConfig] {
        &self.block_devices
    }

    /// Whether this VM's memory is a full memfd copy of its fork source
    /// (the virtiofs / vhost-user path) rather than a `CoW`
    /// `MAP_PRIVATE` mapping of `base.mem`. Always `false` for cold-boot
    /// and plain restored VMs. Test hook for the "block-only VMs
    /// stay on the `CoW` fork path" invariant.
    #[must_use]
    pub fn fork_memory_is_full_copy(&self) -> bool {
        self.fork_mem_file.is_some()
    }

    /// Pause the VM, stopping the vCPU and returning the `VcpuFd` for register access.
    ///
    /// After pausing, the VM can be resumed with `resume()` or shut down.
    ///
    /// Userspace virtio workers (`TapNetBackend`) are paused around the vCPU
    /// join so they stop mutating guest rings for the warm-fork capture
    /// window — otherwise in-flight TCP on the source dies across a dual-VM
    /// pause.
    pub fn pause(&mut self) -> Result<(), VmError> {
        if !self.running.load(Ordering::SeqCst) || self.paused.load(Ordering::SeqCst) {
            return Ok(());
        }
        // Freeze net workers first (brief MMIO lock) so they stop dirtying
        // pages before we join the vCPU and capture the bitmap.
        let t = Instant::now();
        self.mmio_registry.lock().unwrap().set_paused_all(true);
        self.last_pause.freeze = t.elapsed();

        // Recover the fds in vCPU-index order (each thread owns its own
        // channel, so `rxs[i]` always yields vCPU i's fd).
        let t = Instant::now();
        let parked = self.park_vcpu_threads();
        self.last_pause.stop_vcpus = t.elapsed();
        parked?;
        // Wait (bounded) for paused userspace workers to stop touching
        // guest memory. Virtio-blk finishes the in-flight request, then
        // parks; leftover ring entries are replayed (CHALLENGES #162).
        // DMA from that in-flight request is in the dirty bitmap before
        // memcpy. No-op for backends without userspace DMA workers.
        // A miss is recorded, not swallowed: pause itself cannot fail
        // (warp / shutdown / snapshot all call it). The fork path reads
        // `pause_not_quiescent` and takes a full memory dump instead of a
        // dirty-delta copy that would miss in-flight device DMA.
        let t = Instant::now();
        self.pause_not_quiescent = self.mmio_registry.lock().unwrap().wait_quiescent_all();
        self.last_pause.quiesce = t.elapsed();
        Ok(())
    }

    /// Where the last [`Self::pause`] spent its time.
    ///
    /// Exposed because a pause is wall time in which no guest time
    /// passes, so for anything that pauses repeatedly — the auto-warp
    /// policy loop — it is the entire cost of the
    /// exercise, and a total is not enough to act on (`CHALLENGES.md`
    /// #183).
    #[must_use]
    pub fn last_pause_cost(&self) -> PauseCost {
        self.last_pause
    }

    /// Get every vCPU out of `KVM_RUN` and take its `VcpuFd`, leaving
    /// the threads alive and parked. Returns the fds in vCPU-index
    /// order.
    ///
    /// The threads must survive the pause. A vCPU thread that exits and
    /// is replaced by a fresh one makes KVM notice on the next
    /// `KVM_RUN` that "the thread running this VCPU changed", and it
    /// republishes `vcpu->pid` behind a full `synchronize_rcu()` — a
    /// grace period the calling thread waits out in state `D`, where no
    /// signal reaches it. That cost ~2 ms per vCPU, so the auto-warp
    /// policy loop measured a 6 ms pause on a 3-node cluster against
    /// 0.8 ms for the whole warp, and spent it in the one place
    /// a warp has nothing to show for it (`CHALLENGES.md` #183).
    ///
    /// Signals until each thread confirms it has parked, rather than
    /// once: a thread publishes its own `pthread_t` from inside itself,
    /// so a `pause` close behind a `resume` can find `vcpu_tids` still
    /// zero and signal nobody. Handing the `VcpuFd` back is the
    /// confirmation. The signal cannot be *lost* — see
    /// [`set_kvm_signal_mask`].
    fn park_vcpu_threads(&mut self) -> Result<(), VmError> {
        self.paused.store(true, Ordering::SeqCst);

        let mut rounds = 0_u32;
        for cpu in 0..self.vcpu_return_rxs.len() {
            let started = Instant::now();
            let mut cpu_rounds = 0_u32;
            let mut wait = VCPU_STOP_RETRY;
            let mut failed = None;
            loop {
                if let Err(e) = self.signal_vcpu_thread(cpu) {
                    failed = Some(e);
                }
                rounds += 1;
                cpu_rounds += 1;
                match self.vcpu_return_rxs[cpu].recv_timeout(wait) {
                    // Straight onto the VM rather than into a local:
                    // a park that fails on vCPU 1 must not *drop* vCPU
                    // 0's fd, which would close the vCPU on the way out
                    // of an error path.
                    Ok(vcpu_fd) => {
                        self.vcpu_fds.push(vcpu_fd);
                        break;
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if started.elapsed() >= VCPU_STOP_TIMEOUT {
                            let sending = failed.map_or_else(
                                || "every pthread_kill was accepted".to_string(),
                                |e| format!("a pthread_kill failed: {e}"),
                            );
                            return Err(VmError::VcpuStop {
                                cpu,
                                waited: started.elapsed(),
                                reason: format!(
                                    "{cpu_rounds} signals did not move it ({sending}) — {}",
                                    self.where_is_vcpu_thread(cpu)
                                ),
                            });
                        }
                        wait = (wait * 2).min(VCPU_STOP_RETRY_MAX);
                    }
                    // The run loop hands its fd over on every path it
                    // has, so a closed channel means the thread died
                    // some other way. The VM cannot be resumed without
                    // that fd, so this is an error and not a shrug.
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        return Err(VmError::VcpuStop {
                            cpu,
                            waited: started.elapsed(),
                            reason: "its thread ended without handing the VcpuFd back".to_string(),
                        });
                    }
                }
            }
        }

        self.last_pause.stop_signal_rounds = rounds;
        Ok(())
    }

    /// Where a vCPU thread that would not stop actually is, for the
    /// error that gives up on it.
    ///
    /// A signal only releases a thread that is in `KVM_RUN`. Anything
    /// else it is blocked on — a device mutex, an uninterruptible RCU
    /// grace period — it stays blocked on, and retrying changes
    /// nothing, so "it did not stop" on its own is not a diagnosis. The
    /// kernel `wchan`, current syscall and stack are.
    ///
    /// The signal lines of `/proc/<tid>/status` are here for the same
    /// reason: they are the kernel's own answer to "was the stop signal
    /// delivered", which no amount of userspace bookkeeping can give.
    /// `SigPnd` with the stop signal's bit set while `SigBlk` also has it
    /// means the signal arrived and `KVM_SET_SIGNAL_MASK` is not
    /// unblocking it inside `KVM_RUN`; `SigQ` at its limit means
    /// `pthread_kill` has been failing with `EAGAIN` and no signal was
    /// sent at all.
    fn where_is_vcpu_thread(&self, cpu: usize) -> String {
        let Some(kernel_tid) = self.vcpu_kernel_tids.get(cpu) else {
            return "no kernel tid published".to_string();
        };
        let kernel_tid = kernel_tid.load(Ordering::SeqCst);
        let read = |what: &str| {
            std::fs::read_to_string(format!("/proc/self/task/{kernel_tid}/{what}"))
                .map_or_else(|e| format!("<{e}>"), |s| s.trim().replace('\n', " | "))
        };
        let signals = read("status")
            .split(" | ")
            .filter(|l| l.starts_with("Sig") || l.starts_with("ShdPnd"))
            .collect::<Vec<_>>()
            .join(" ");
        let sample = || {
            self.vcpu_telemetry
                .get(cpu)
                .map_or((u8::MAX, 0, 0, 0), |t| {
                    (
                        t.phase.load(Ordering::Relaxed),
                        t.exits.load(Ordering::Relaxed),
                        t.entries.load(Ordering::Relaxed),
                        t.eintrs.load(Ordering::Relaxed),
                    )
                })
        };
        let before = sample();
        thread::sleep(Duration::from_millis(2));
        let after = sample();
        format!(
            "tid {kernel_tid} phase={} (then {}) exits={} (+{}) KVM_RUN entries={} (+{}) \
             EINTRs={} (+{}) in 2ms, stop signal={}, {signals}, wchan={:?} syscall={:?} \
             stack={:?}",
            vcpu_phase::name(before.0),
            vcpu_phase::name(after.0),
            before.1,
            after.1.saturating_sub(before.1),
            before.2,
            after.2.saturating_sub(before.2),
            before.3,
            after.3.saturating_sub(before.3),
            vcpu_stop_signal(),
            read("wchan"),
            read("syscall"),
            read("stack"),
        )
    }

    /// True when every virtio backend has parked (or has no worker).
    /// Fork materialise waits for this before `FICLONE` (CHALLENGES #162).
    #[must_use]
    pub fn devices_quiescent(&self) -> bool {
        self.mmio_registry.lock().unwrap().all_quiescent()
    }

    /// Devices that missed the 200 ms park deadline on the last pause.
    #[must_use]
    pub fn pause_not_quiescent(&self) -> &[NotQuiescent] {
        &self.pause_not_quiescent
    }

    /// Take the last pause's miss list so a fork path can choose a full
    /// dump instead of a dirty-delta copy. `pause` itself never fails.
    #[must_use]
    pub fn take_pause_not_quiescent(&mut self) -> Vec<NotQuiescent> {
        std::mem::take(&mut self.pause_not_quiescent)
    }

    /// If the last pause missed the 200 ms park deadline, count it and
    /// tell the caller to take a full memory dump instead of the dirty
    /// delta. Resumes nothing — the caller owns pause/resume.
    pub fn take_full_dump_if_not_quiescent(&mut self) -> bool {
        let missed = self.take_pause_not_quiescent();
        if missed.is_empty() {
            return false;
        }
        crate::virtio_mmio::record_fork_nonquiescent(&missed);
        log::warn!(
            "virtio worker(s) did not park within 200ms — full memory dump \
             instead of dirty-delta: {}",
            missed
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        );
        true
    }

    /// Test-only: make `wait_quiescent` ignore `parked` and wait out the
    /// 200 ms deadline, so a fork can be shown to take the full-dump path
    /// rather than a torn dirty-delta. Workers still park.
    pub fn hold_virtio_workers_for_test(&self, hold: bool) {
        self.mmio_registry
            .lock()
            .unwrap()
            .hold_park_for_test_all(hold);
    }

    /// Resume a paused VM by restarting the vCPU run loop.
    pub fn resume(&mut self) -> Result<(), VmError> {
        if !self.paused.load(Ordering::SeqCst) {
            return Ok(());
        }
        if self.vcpu_fds.len() != self.vcpus as usize {
            return Err(VmError::Pipe(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "{} of {} vCPU fds available for resume",
                    self.vcpu_fds.len(),
                    self.vcpus
                ),
            )));
        }
        // Clear the flag before handing the fds back, or a thread that
        // wakes promptly reads `paused` still set and parks again —
        // handing the fd straight back to a channel nobody is reading.
        self.paused.store(false, Ordering::SeqCst);
        for (cpu, vcpu_fd) in self.vcpu_fds.drain(..).enumerate() {
            self.vcpu_resume_txs[cpu]
                .send(vcpu_fd)
                .map_err(|_| VmError::VcpuStop {
                    cpu,
                    waited: Duration::ZERO,
                    reason: "its thread is gone, so it cannot take its VcpuFd back".to_string(),
                })?;
        }
        // vCPU first, then workers — guest can handle IRQs as frames resume.
        self.mmio_registry.lock().unwrap().set_paused_all(false);
        Ok(())
    }

    /// Get a reference to the KVM `VmFd`.
    #[must_use]
    pub fn vm_fd(&self) -> &VmFd {
        &self.vm_fd
    }

    /// Get a reference to vCPU 0's `VcpuFd` (only available when paused).
    #[must_use]
    pub fn vcpu_fd(&self) -> Option<&VcpuFd> {
        self.vcpu_fds.first()
    }

    /// All vCPU fds in vCPU-index order (capture loop).
    /// Complete only while the VM is stopped/paused — empty (or
    /// partially drained) while the run-loop threads own the fds.
    #[must_use]
    pub fn vcpu_fds(&self) -> &[VcpuFd] {
        &self.vcpu_fds
    }

    /// Guest vCPU count this VM was built with.
    #[must_use]
    pub fn vcpu_count(&self) -> u32 {
        self.vcpus
    }

    /// Device-bound virtqueues with work the guest has handed over and
    /// not yet had completed — one description per queue, empty when
    /// every device is idle (CHALLENGES #79's `avail`/`used` handshake).
    ///
    /// Only queues the *driver* fills with requests are compared:
    /// `avail.idx > used.idx` on a receive queue (virtio-net RX, vsock
    /// RX) is the normal resting state of a guest that has posted
    /// buffers for traffic that has not arrived, so treating it as
    /// "work in flight" would decline every warp forever. The
    /// host-to-guest direction is covered by
    /// [`Self::tap_has_pending_frame`] instead.
    #[must_use]
    pub fn virtio_queues_in_flight(&self) -> Vec<String> {
        self.mmio_registry
            .lock()
            .unwrap()
            .queues_in_flight(self.mem_host_addr(), self.mem_span())
    }

    /// Whether the host side of this VM's TAP has a frame queued for
    /// the guest.
    ///
    /// Host-owned and readable without consuming anything: `poll` with
    /// a zero timeout. `Ok(false)` on a VM with no TAP — a VM with no
    /// network has no frames to be caught mid-flight.
    pub fn tap_has_pending_frame(&self) -> Result<bool, String> {
        let Some(tap) = &self.tap else {
            return Ok(false);
        };
        tap.has_pending_frame()
    }

    /// Every vCPU fd is back from its run thread, i.e. vCPU ioctls
    /// cannot race `KVM_RUN`. Returns the vCPU count on success.
    fn require_paused(&self, op: &'static str) -> Result<usize, VmError> {
        let running = self.is_running();
        let want = self.vcpus as usize;
        if running || self.vcpu_fds.len() != want {
            return Err(VmError::NotPaused {
                op,
                running,
                have: self.vcpu_fds.len(),
                want,
            });
        }
        Ok(want)
    }

    /// Kernel TID of the running BSP (vCPU 0) thread, waiting up to
    /// `timeout` for the freshly spawned thread to publish it (storing
    /// the TID is the thread's first action, so the wait is
    /// microseconds in practice). `None` when the VM isn't running or
    /// the wait times out. uses this to place the vCPU thread
    /// into a CPU cgroup — `cgroup.threads` takes kernel TIDs, not
    /// pthread ids. Multi-vCPU callers must use
    /// [`Self::vcpu_kernel_tids`] so the cap covers every thread.
    #[must_use]
    pub fn vcpu_kernel_tid(&self, timeout: Duration) -> Option<u32> {
        self.vcpu_kernel_tids(timeout)
            .and_then(|tids| tids.first().copied())
    }

    /// Kernel TIDs of **all** running vCPU threads, in vCPU-index
    /// order, waiting up to `timeout` for every freshly spawned thread
    /// to publish its TID. `None` when the VM isn't running or the
    /// wait times out. The per-VM CPU cgroup must contain
    /// every vCPU thread so the pod's CFS quota caps the whole VM.
    #[must_use]
    pub fn vcpu_kernel_tids(&self, timeout: Duration) -> Option<Vec<u32>> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if self.vcpu_kernel_tids.len() == self.vcpus as usize {
                let tids: Vec<u32> = self
                    .vcpu_kernel_tids
                    .iter()
                    .map(|t| t.load(Ordering::SeqCst) as u32)
                    .collect();
                if tids.iter().all(|&t| t != 0) {
                    return Some(tids);
                }
            }
            if !self.running.load(Ordering::SeqCst) || std::time::Instant::now() >= deadline {
                return None;
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    /// PIDs of this VM's virtiofsd helper processes, so a tree can pull
    /// them into its cgroup jail. Empty for a VM
    /// with no virtiofs share.
    #[must_use]
    pub fn virtiofsd_pids(&self) -> Vec<u32> {
        self.virtiofsds.iter().map(VirtiofsdProcess::pid).collect()
    }

    /// Send the stop signal to every vCPU thread that has published its
    /// pthread id, breaking them out of a blocking `KVM_RUN`.
    fn signal_vcpu_threads(&self) {
        for cpu in 0..self.vcpu_tids.len() {
            if let Err(e) = self.signal_vcpu_thread(cpu) {
                log::warn!("could not signal vCPU {cpu} to stop: {e}");
            }
        }
    }

    /// Send the stop signal to **one** vCPU thread, if it has published its
    /// pthread id.
    ///
    /// One, not all of them, and the distinction is load-bearing:
    /// It is a real-time signal, so every `pthread_kill`
    /// *queues* another instance rather than coalescing. Signalling
    /// every vCPU once per vCPU being waited for left each thread with a
    /// backlog that grew by a signal per pause, and since the signal is
    /// blocked outside `KVM_RUN` (see [`set_kvm_signal_mask`]) the whole
    /// backlog was waiting at the next entry: every `KVM_RUN` after the
    /// resume returned `EINTR` immediately, so the vCPUs spun at 100%
    /// and the guest never executed at all.
    /// The error is returned rather than dropped because the only two
    /// ways it fails are both diagnoses a stuck pause needs and neither
    /// is visible otherwise: `ESRCH` (the thread is gone) and `EAGAIN`
    /// (`RLIMIT_SIGPENDING` is full, so no signal was queued at all —
    /// see [`VCPU_STOP_RETRY_MAX`]).
    fn signal_vcpu_thread(&self, cpu: usize) -> Result<(), std::io::Error> {
        let Some(tid) = self.vcpu_tids.get(cpu) else {
            return Ok(());
        };
        let tid = tid.load(Ordering::SeqCst);
        if tid == 0 {
            return Ok(());
        }
        // SAFETY: tid is a valid pthread_t stored by the vCPU thread;
        // the stop signal has a registered no-op handler.
        let rc = unsafe { libc::pthread_kill(tid as libc::pthread_t, vcpu_stop_signal()) };
        if rc == 0 {
            Ok(())
        } else {
            // pthread_kill returns the errno rather than setting it.
            Err(std::io::Error::from_raw_os_error(rc))
        }
    }

    /// Get a reference to the guest memory.
    #[must_use]
    pub fn guest_memory(&self) -> &GuestMemoryMmap {
        &self.guest_memory
    }

    /// Guest RAM in bytes — what the guest reports as `MemTotal` (before
    /// its own kernel reservations). Not the same as [`Self::mem_span`]
    /// once the guest is large enough to straddle the 32-bit MMIO hole.
    #[must_use]
    pub fn memory_size(&self) -> u64 {
        self.memory_size
    }

    /// Length of this VM's guest physical address space, and therefore of
    /// its host mapping, its `memory.bin`, and its dirty bitmaps.
    /// Equals [`Self::memory_size`] plus the 32-bit MMIO hole
    /// for guests with RAM past 4 GiB, and exactly [`Self::memory_size`]
    /// for every smaller guest.
    #[must_use]
    pub fn mem_span(&self) -> u64 {
        self.mem_layout().span()
    }

    /// This VM's guest RAM split across the 32-bit MMIO hole.
    #[must_use]
    pub fn mem_layout(&self) -> MemLayout {
        MemLayout::from_ram(self.memory_size)
    }

    /// Get the kernel path.
    #[must_use]
    pub fn kernel_path(&self) -> &Path {
        &self.kernel_path
    }

    /// Get the initrd path, if any.
    #[must_use]
    pub fn initrd_path(&self) -> Option<&Path> {
        self.initrd_path.as_deref()
    }

    /// Get a reference to the MMIO device registry.
    #[must_use]
    pub fn mmio_registry(&self) -> &SharedMmioRegistry {
        &self.mmio_registry
    }

    /// Which bus this VM's virtio devices sit on. A VM with no devices
    /// at all reports [`Transport::Mmio`].
    #[must_use]
    pub fn transport(&self) -> Transport {
        if self.mmio_registry.lock().unwrap().has_pci_bus() {
            Transport::Pci
        } else {
            Transport::Mmio
        }
    }

    /// Get the guest vsock CID.
    #[must_use]
    pub fn guest_cid(&self) -> u64 {
        self.guest_cid
    }

    /// Whether the vCPUs are executing guest code — false both for a
    /// paused VM (threads alive, fds handed over) and a shut-down one.
    /// Callers that need "the vCPU ioctls cannot race `KVM_RUN`" want
    /// exactly this.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst) && !self.paused.load(Ordering::SeqCst)
    }

    /// Whether a vCPU left its run loop on its own: the guest asked
    /// for a reset (`reboot=k`'s i8042 pulse), triple-faulted, or KVM
    /// refused to run it. One is enough — the kernel parks the other
    /// CPUs in `HLT` first, and with the in-kernel LAPIC those never
    /// exit `KVM_RUN`. The guest is gone; only [`Self::shutdown`] (or
    /// drop) follows. False for a VM that was never started or is
    /// paused.
    #[must_use]
    pub fn guest_exited(&self) -> bool {
        self.vcpu_telemetry
            .iter()
            .any(|t| t.phase.load(Ordering::Relaxed) == vcpu_phase::EXITED)
    }

    /// Whether the vCPU threads are parked after [`Self::pause`].
    /// Distinct from [`Self::is_running`]: a shut-down VM is neither
    /// running nor paused.
    #[must_use]
    pub fn paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    /// Get the host virtual address of guest memory.
    ///
    /// For CoW-restored VMs, returns the `MAP_PRIVATE` mmap address.
    /// For normally-booted VMs, returns the memfd-backed `GuestMemoryMmap` address.
    #[must_use]
    pub fn mem_host_addr(&self) -> u64 {
        self.cow_mmap_addr
            .unwrap_or_else(|| self.guest_memory.get_host_address(GuestAddress(0)).unwrap() as u64)
    }

    /// Mark this VM's guest RAM `MADV_MERGEABLE`.
    ///
    /// Call it from the process that owns the mapping, after the guest
    /// is running: the VM broker under privilege separation, otherwise
    /// the daemon. `madvise` only sets a VMA flag, so it does not extend
    /// a fork pause when it runs after resume. Does not call
    /// `PR_SET_MEMORY_MERGE` and does not write `/sys/kernel/mm/ksm`.
    pub fn advise_memory_mergeable(&self) -> std::io::Result<()> {
        crate::ksm::advise_mergeable(self.mem_host_addr(), self.mem_span())
    }

    /// Whether this VM was restored from a snapshot (`CoW` memory).
    #[must_use]
    pub fn is_restored(&self) -> bool {
        self.restored
    }

    /// Take the host TAP device out of this VM, leaving it without networking.
    ///
    /// Used during the `prepare_fork_source` boot-strap to transfer the host
    /// TAP into the restored VM that replaces the source — without this, the
    /// kernel-side TAP interface would be dropped (and cleaned up) when the
    /// source VM is dropped.
    pub fn take_tap(&mut self) -> Option<TapDevice> {
        self.tap.take()
    }

    /// Take a snapshot of the VM to the given directory.
    ///
    /// The VM is paused, state is saved, and then optionally resumed.
    /// Creates `memory.bin`, `cpu.json`, `devices.json`, and `metadata.json`
    /// in the snapshot directory.
    pub fn snapshot(&mut self, snapshot_dir: &Path) -> Result<(), crate::snapshot::SnapshotError> {
        let was_running = self.is_running();
        if was_running {
            self.pause().map_err(crate::snapshot::SnapshotError::Vm)?;
        }
        let result = crate::snapshot::snapshot_vm(self, snapshot_dir);
        if was_running {
            self.resume().map_err(crate::snapshot::SnapshotError::Vm)?;
        }
        result
    }

    /// Shut down the VM, stopping and joining every vCPU thread.
    pub fn shutdown(&mut self) {
        // Park first, so the fds are accounted for and every thread is
        // known to be out of `KVM_RUN`; then let the threads go. The
        // fds are dropped afterwards — nothing resumes a VM that has
        // been shut down.
        if self.running.load(Ordering::SeqCst) && !self.paused.load(Ordering::SeqCst) {
            if let Err(e) = self.park_vcpu_threads() {
                log::error!("shutdown: {e}");
            }
        }
        self.running.store(false, Ordering::SeqCst);
        // Dropping the senders is what releases a thread parked in
        // `resume_rx.recv()`; the signal is for one that is somehow
        // still in `KVM_RUN`.
        self.vcpu_resume_txs.clear();
        self.signal_vcpu_threads();
        for handle in self.vcpu_threads.drain(..) {
            let _ = handle.join();
        }
        // The threads are gone; their kernel TIDs must not be handed out.
        for kernel_tid in self.vcpu_kernel_tids.drain(..) {
            kernel_tid.store(0, Ordering::SeqCst);
        }
        self.vcpu_tids.clear();
        self.vcpu_return_rxs.clear();
        self.vcpu_telemetry.clear();
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        // Stop the vCPU thread first so no new MMIO writes / queue notifies
        // are issued against the devices we're about to tear down.
        self.shutdown();

        // Tear down virtio device workers BEFORE the guest-memory mapping is
        // released. Worker threads (TapNetBackend's RX/TX, vsock IRQ pumps)
        // read from raw guest-memory pointers; if they're still polling when
        // `cow_mmap_addr` is munmap'd or `guest_memory` drops, the next
        // dereference is a use-after-free and the process dies with SIGSEGV
        // (cloud-hypervisor learned this the hard way: see Net::drop calling
        // `wait_for_epoll_threads`, comment "ensure all references to tap FDs
        // are dropped (#4868)").
        //
        // Drop every device explicitly here. Each device's Drop calls
        // shutdown() on its backend, which writes the worker's `running` flag
        // and joins the worker thread. Only after this is it safe to unmap
        // the mmap region.
        {
            let mut registry = self.mmio_registry.lock().unwrap();
            registry.shutdown_all();
        }

        if let Some(addr) = self.cow_mmap_addr.take() {
            // SAFETY: addr was returned by a successful mmap(MAP_PRIVATE)
            // in fork::restore_vm, with size == self.memory_size. Worker
            // threads that referenced this region were joined above.
            unsafe {
                libc::munmap(addr as *mut libc::c_void, self.memory_size as usize);
            }
        }
        if let Some(ref dir) = self.fork_state_dir {
            let _ = std::fs::remove_dir_all(dir);
        }
        if let Some(ref dir) = self.fork_source_dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// The pause plumbing one vCPU thread obeys: the two flags that say
/// whether to run, park or exit, and the two channel ends its `VcpuFd`
/// travels over when it parks and is let go again.
struct VcpuControl {
    /// Cleared only by [`Vm::shutdown`].
    running: Arc<AtomicBool>,
    /// Set by [`Vm::park_vcpu_threads`], cleared by [`Vm::resume`].
    paused: Arc<AtomicBool>,
    /// Where the `VcpuFd` goes when the thread parks or exits.
    return_tx: mpsc::Sender<VcpuFd>,
    /// Where it comes back from on resume. A closed channel means the
    /// VM is going away and already owns the fd.
    resume_rx: mpsc::Receiver<VcpuFd>,
    /// What the thread is doing, for [`Vm::where_is_vcpu_thread`].
    telemetry: Arc<VcpuTelemetry>,
}

/// What a vCPU thread is doing right now, published so a pause that
/// gives up on it can say more than that it did not stop.
///
/// The kernel can only report where a thread is when it is *in* the
/// kernel. A vCPU that will not park while `/proc` says `syscall:
/// running` is somewhere in this loop with no syscall outstanding, and
/// only the loop can say where.
#[derive(Debug, Default)]
struct VcpuTelemetry {
    /// One of the [`vcpu_phase`] constants.
    phase: AtomicU8,
    /// KVM exits handled. Whether this is still climbing separates a
    /// thread wedged on one exit from one spinning through millions.
    exits: AtomicU64,
    /// `KVM_RUN` calls made, and of those, the ones that came back
    /// `EINTR`.
    ///
    /// Both are needed to tell the two ways a vCPU fails to park
    /// apart, and `phase` cannot: a thread spinning
    /// `KVM_RUN` → `EINTR` → `KVM_RUN` sits in `IN_KVM_RUN` almost
    /// always and handles no exits, which is exactly what a thread
    /// wedged inside one `KVM_RUN` looks like. A climbing `entries`
    /// says it is spinning, a static one says it is stuck.
    entries: AtomicU64,
    /// See [`VcpuTelemetry::entries`].
    eintrs: AtomicU64,
}

/// Values of [`VcpuTelemetry::phase`]. Plain constants because they
/// live in an atomic on the vCPU's hot path.
mod vcpu_phase {
    pub const STARTING: u8 = 0;
    pub const IN_KVM_RUN: u8 = 1;
    pub const HANDLING_EXIT: u8 = 2;
    pub const PARKING: u8 = 3;
    pub const PARKED: u8 = 4;
    pub const EXITED: u8 = 5;

    /// Name a phase for a diagnostic.
    #[must_use]
    pub fn name(phase: u8) -> &'static str {
        match phase {
            STARTING => "starting",
            IN_KVM_RUN => "in KVM_RUN",
            HANDLING_EXIT => "handling a KVM exit",
            PARKING => "parking",
            PARKED => "parked",
            EXITED => "exited",
            other => {
                debug_assert!(false, "unknown vCPU phase {other}");
                "unknown"
            }
        }
    }
}

/// The vCPU run loop — handles KVM exits and dispatches IO to devices.
///
/// When the loop exits, the `VcpuFd` is sent back through `vcpu_tx` so the
/// caller can read registers for snapshot/restore.
#[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
fn vcpu_run_loop(
    cpu_index: usize,
    mut vcpu_fd: VcpuFd,
    serial: &SharedSerialDevice,
    agent_serial: &SharedPipeSerialDevice,
    mmio_registry: &SharedMmioRegistry,
    control: VcpuControl,
) {
    let VcpuControl {
        running,
        paused,
        return_tx,
        resume_rx,
        telemetry,
    } = control;
    let phase = |p: u8| telemetry.phase.store(p, Ordering::Relaxed);
    let mut exit_count: u64 = 0;
    while running.load(Ordering::SeqCst) {
        if paused.load(Ordering::SeqCst) {
            phase(vcpu_phase::PARKING);
            // Hand the fd over and park — do not exit. A replacement
            // thread would make the next `KVM_RUN` on this vCPU take
            // KVM's `synchronize_rcu` for the changed owner, ~2 ms of
            // uninterruptible wait that no signal shortens
            // (`CHALLENGES.md` #183).
            if return_tx.send(vcpu_fd).is_err() {
                phase(vcpu_phase::EXITED);
                return;
            }
            phase(vcpu_phase::PARKED);
            match resume_rx.recv() {
                Ok(fd) => {
                    // Any signal that arrived after this thread had
                    // already decided to park is still queued, and
                    // would come due at the next `KVM_RUN` entry.
                    drain_vcpu_stop_signals();
                    vcpu_fd = fd;
                }
                // The VM dropped this thread's sender: it is going
                // away, and it already holds the fd.
                Err(_) => {
                    phase(vcpu_phase::EXITED);
                    return;
                }
            }
            continue;
        }
        phase(vcpu_phase::IN_KVM_RUN);
        telemetry.entries.fetch_add(1, Ordering::Relaxed);
        let ran = vcpu_fd.run();
        phase(vcpu_phase::HANDLING_EXIT);
        match ran {
            Ok(exit) => {
                exit_count += 1;
                telemetry.exits.store(exit_count, Ordering::Relaxed);
                match exit {
                    VcpuExit::IoIn(addr, data) => {
                        if (SERIAL_PORT_BASE..SERIAL_PORT_BASE + SERIAL_PORT_SIZE).contains(&addr) {
                            let offset = (addr - SERIAL_PORT_BASE) as u8;
                            let mut dev = serial.lock().unwrap();
                            data[0] = dev.read(offset);
                        } else if (SERIAL2_PORT_BASE..SERIAL2_PORT_BASE + SERIAL_PORT_SIZE)
                            .contains(&addr)
                        {
                            let offset = (addr - SERIAL2_PORT_BASE) as u8;
                            let mut dev = agent_serial.lock().unwrap();
                            data[0] = dev.read(offset);
                        } else if crate::pci::PciBus::handles_port(addr) {
                            // 0xCF8/0xCFC: PCI configuration space. A VM
                            // without a PCI bus reads zero, as before.
                            if !mmio_registry.lock().unwrap().pio_read(addr, data) {
                                data.fill(0);
                            }
                        } else {
                            data.fill(0);
                        }
                    }
                    VcpuExit::IoOut(addr, data) => {
                        if (SERIAL_PORT_BASE..SERIAL_PORT_BASE + SERIAL_PORT_SIZE).contains(&addr) {
                            let offset = (addr - SERIAL_PORT_BASE) as u8;
                            let mut dev = serial.lock().unwrap();
                            for &byte in data {
                                dev.write(offset, byte);
                            }
                        } else if (SERIAL2_PORT_BASE..SERIAL2_PORT_BASE + SERIAL_PORT_SIZE)
                            .contains(&addr)
                        {
                            let offset = (addr - SERIAL2_PORT_BASE) as u8;
                            let mut dev = agent_serial.lock().unwrap();
                            for &byte in data {
                                dev.write(offset, byte);
                            }
                        } else if crate::pci::PciBus::handles_port(addr) {
                            mmio_registry.lock().unwrap().pio_write(addr, data);
                        } else if addr == I8042_COMMAND_PORT
                            && data.first() == Some(&I8042_RESET_PULSE)
                        {
                            // `reboot=k` without ACPI: the kernel pulses
                            // the i8042 reset line, then would jump to the
                            // BIOS reset vector — and there is no BIOS, so
                            // it would run zeros forever (CHALLENGES #308).
                            // The pulse is the reboot; end the guest here.
                            log::info!(
                                "vCPU {cpu_index} guest reset through the keyboard controller \
                                 after {exit_count} exits"
                            );
                            break;
                        }
                    }
                    VcpuExit::Hlt => {
                        log::info!("vCPU {cpu_index} halted after {exit_count} exits");
                        break;
                    }
                    VcpuExit::Shutdown => {
                        if let Ok(regs) = vcpu_fd.get_regs() {
                            // Mode context distinguishes a kernel triple
                            // fault from an AP that resumed outside long
                            // mode (CHALLENGES #260) — RIP alone does not.
                            let mode = vcpu_fd.get_sregs().map_or_else(
                                |e| format!("sregs unavailable: {e}"),
                                |s| {
                                    format!(
                                        "CS={:#x} (base={:#x} l={} db={}) CR0={:#x} CR3={:#x} \
                                         CR4={:#x} EFER={:#x} APIC_BASE={:#x}",
                                        s.cs.selector,
                                        s.cs.base,
                                        s.cs.l,
                                        s.cs.db,
                                        s.cr0,
                                        s.cr3,
                                        s.cr4,
                                        s.efer,
                                        s.apic_base
                                    )
                                },
                            );
                            log::error!(
                                "vCPU {cpu_index} shutdown (triple fault) after {exit_count} \
                                 exits: RIP={:#x} RSP={:#x} RAX={:#x} RFLAGS={:#x} {mode}",
                                regs.rip,
                                regs.rsp,
                                regs.rax,
                                regs.rflags,
                            );
                        } else {
                            log::info!("vCPU {cpu_index} shutdown after {exit_count} exits");
                        }
                        break;
                    }
                    VcpuExit::MmioRead(addr, data) => {
                        let reg = mmio_registry.lock().unwrap();
                        if !reg.handle_read(addr, data) {
                            data.fill(0);
                        }
                    }
                    VcpuExit::MmioWrite(addr, data) => {
                        let reg = mmio_registry.lock().unwrap();
                        let _ = reg.handle_write(addr, data);
                    }
                    VcpuExit::FailEntry(reason, cpu) => {
                        log::error!(
                            "KVM fail entry on vCPU {cpu_index}: reason={reason:#x} cpu={cpu} \
                             after {exit_count} exits"
                        );
                        break;
                    }
                    VcpuExit::InternalError => {
                        log::error!(
                            "KVM internal error on vCPU {cpu_index} after {exit_count} exits"
                        );
                        break;
                    }
                    other => {
                        log::warn!(
                            "unhandled vCPU {cpu_index} exit: {other:?} after {exit_count} exits"
                        );
                    }
                }
            }
            Err(e) => {
                if e.errno() == libc::EINTR {
                    telemetry.eintrs.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                if e.errno() == libc::EAGAIN {
                    continue;
                }
                log::error!("vCPU {cpu_index} run failed: {e} (after {exit_count} exits)");
                break;
            }
        }
    }
    phase(vcpu_phase::EXITED);
    let _ = return_tx.send(vcpu_fd);
}

/// `lseek(fd, pos, whence)` for `SEEK_DATA` / `SEEK_HOLE`; `None` on
/// `ENXIO` (no data at or after `pos`).
fn seek_memfd(fd: RawFd, pos: u64, whence: libc::c_int) -> Result<Option<u64>, VmError> {
    // SAFETY: lseek on a valid fd owned by the guest memory region.
    #[allow(clippy::cast_possible_wrap)]
    let r = unsafe { libc::lseek(fd, pos as libc::off_t, whence) };
    if r < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENXIO) {
            return Ok(None);
        }
        return Err(VmError::Pipe(err));
    }
    #[allow(clippy::cast_sign_loss)]
    Ok(Some(r as u64))
}

/// `[start, end)` intersected with `[lo, hi)`, page-aligned outward;
/// `None` if empty. Outward rounding keeps a partial page whole — the
/// writer copies pages, and the caller's slots are page-aligned.
fn clip_extent(start: u64, end: u64, lo: u64, hi: u64) -> Option<(u64, u64)> {
    let s = (start.max(lo) / 4096) * 4096;
    let e = end.min(hi).div_ceil(4096) * 4096;
    let (s, e) = (s.max(lo), e.min(hi));
    (s < e).then_some((s, e))
}

/// Clear the KVM dirty log for the pages set in `mask` (one bit per page
/// of the slot) via the raw `KVM_CLEAR_DIRTY_LOG` ioctl.
///
/// `kvm-ioctls` 0.19.1 does not expose a safe wrapper for this ioctl. We call it
/// directly to re-arm write protection on tracked pages after reading the dirty
/// bitmap. Requires `KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2` (Linux 5.0+) to be enabled.
fn clear_dirty_log(vm_fd: &VmFd, slot: u32, memory_size: u64, mask: &[u64]) -> Result<(), VmError> {
    #[repr(C)]
    struct KvmClearDirtyLog {
        slot: u32,
        num_pages: u32,
        first_page: u64,
        dirty_bitmap: u64,
    }

    // KVM_CLEAR_DIRTY_LOG = _IOWR(KVMIO, 0xc0, struct kvm_clear_dirty_log)
    // KVMIO = 0xAE; sizeof(struct kvm_clear_dirty_log) = 24.
    // _IOWR(type, nr, size) = (3 << 30) | (size << 16) | (type << 8) | nr.
    // _IOWR(KVMIO=0xAE, 0xc0, struct kvm_clear_dirty_log) with sizeof=24.
    const KVM_CLEAR_DIRTY_LOG: libc::c_ulong = 0xC018_AEC0;

    let num_pages = memory_size.div_ceil(4096) as u32;
    let words = (num_pages as usize).div_ceil(64);
    if mask.len() < words {
        return Err(VmError::Pipe(std::io::Error::other(format!(
            "KVM_CLEAR_DIRTY_LOG slot {slot}: {}-word mask for {num_pages} pages",
            mask.len()
        ))));
    }
    if mask[..words].iter().all(|&w| w == 0) {
        return Ok(());
    }
    let req = KvmClearDirtyLog {
        slot,
        num_pages,
        first_page: 0,
        dirty_bitmap: mask.as_ptr() as u64,
    };

    // SAFETY: vm_fd is valid; KvmClearDirtyLog matches the kernel's struct layout
    // and the mask points to at least `words * 8` bytes of valid memory.
    let rc = unsafe {
        libc::ioctl(
            vm_fd.as_raw_fd(),
            KVM_CLEAR_DIRTY_LOG,
            std::ptr::from_ref(&req),
        )
    };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        // ENOTTY / EINVAL means MANUAL_DIRTY_LOG_PROTECT2 cap not enabled — treat as non-fatal:
        // without it, KVM_GET_DIRTY_LOG implicitly clears, which is also fine for correctness.
        if matches!(err.raw_os_error(), Some(libc::ENOTTY | libc::EINVAL)) {
            log::debug!("KVM_CLEAR_DIRTY_LOG unsupported (non-fatal): {err}");
            return Ok(());
        }
        return Err(VmError::Pipe(err));
    }
    Ok(())
}

/// Make [`vcpu_stop_signal`] deliverable to this vCPU thread *only* while it is
/// inside `KVM_RUN`, so a pause can never lose one.
///
/// Blocking the signal on the thread and handing KVM a mask that leaves
/// only that signal unblocked is the whole trick, and both halves are
/// needed:
///
/// - Blocked on the thread, a signal that arrives while the thread is
///   handling an MMIO exit — or anywhere else outside `KVM_RUN` — stays
///   *pending* instead of being eaten by the no-op handler.
/// - `KVM_SET_SIGNAL_MASK` makes KVM swap that mask in for the duration
///   of guest execution and back out on the way home. The pending
///   signal is therefore delivered the instant the thread enters
///   `KVM_RUN`, which returns `EINTR`.
///
/// So one `pthread_kill` is enough, always. Without this, most signals
/// landed outside `KVM_RUN` and were swallowed, leaving the thread to
/// sit in `KVM_RUN` until the *guest* next exited on its own: the
/// auto-warp loop measured 10.6 signals and ~1.1 ms per vCPU to stop a
/// 3-node cluster, against 0.8 ms for the whole warp
/// (`CHALLENGES.md` #183).
///
/// The mask blocks everything else on purpose. An empty mask also works
/// for correctness — a spurious `EINTR` only costs a re-entry — but it
/// would let every process-directed `SIGCHLD` from a `kubectl` or
/// `virtiofsd` child kick a vCPU out of the guest.
fn set_kvm_signal_mask(vcpu_fd: &VcpuFd) -> Result<(), VmError> {
    // KVM_SET_SIGNAL_MASK = _IOW(KVMIO, 0x8b, struct kvm_signal_mask),
    // whose payload is `{ __u32 len; __u8 sigset[]; }` with `len` the
    // kernel's `sigset_t` size (8 on x86_64, not glibc's 128).
    const KVM_SET_SIGNAL_MASK: libc::c_ulong = 0x4004_AE8B;
    const KERNEL_SIGSET_BYTES: usize = 8;

    #[repr(C)]
    struct KvmSignalMask {
        len: u32,
        sigset: [u8; KERNEL_SIGSET_BYTES],
    }

    let signo = vcpu_stop_signal();

    // Block everything except the stop signal while in the guest. The kernel
    // drops SIGKILL/SIGSTOP from the set itself.
    let mut mask = KvmSignalMask {
        len: KERNEL_SIGSET_BYTES as u32,
        sigset: [0xff; KERNEL_SIGSET_BYTES],
    };
    let bit = usize::try_from(signo - 1).expect("the stop signal is positive");
    mask.sigset[bit / 8] &= !(1u8 << (bit % 8));

    // SAFETY: vcpu_fd is a live vCPU fd and KvmSignalMask matches the
    // kernel's struct layout for a `len` of 8.
    let rc = unsafe {
        libc::ioctl(
            vcpu_fd.as_raw_fd(),
            KVM_SET_SIGNAL_MASK,
            std::ptr::from_ref(&mask),
        )
    };
    if rc < 0 {
        return Err(VmError::VcpuSignalMask(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Accept and discard any queued stop signal on the calling vCPU thread.
///
/// The signal is blocked here (see [`block_vcpu_stop_signal`]), so
/// pending instances sit in the queue until `KVM_RUN` unblocks them,
/// where each one costs an immediate `EINTR`. A thread that parked
/// without needing its signal must therefore drop it before running
/// again.
fn drain_vcpu_stop_signals() {
    // SAFETY: a freshly zeroed sigset_t filled through libc's own
    // accessors, and out-parameters that are valid for the call.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut set);
        libc::sigaddset(&raw mut set, vcpu_stop_signal());
        let now = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let mut info: libc::siginfo_t = std::mem::zeroed();
        while libc::sigtimedwait(&raw const set, &raw mut info, &raw const now) > 0 {}
    }
}

/// Block [`vcpu_stop_signal`] on the calling vCPU thread — the other half of
/// [`set_kvm_signal_mask`], which must run on the thread itself.
fn block_vcpu_stop_signal() {
    // SAFETY: a freshly zeroed sigset_t, filled only through libc's own
    // accessors, and a null old-set pointer, which is allowed.
    let rc = unsafe {
        let mut blocked: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut blocked);
        libc::sigaddset(&raw mut blocked, vcpu_stop_signal());
        libc::pthread_sigmask(libc::SIG_BLOCK, &raw const blocked, std::ptr::null_mut())
    };
    // `SIG_BLOCK` with a set built by `sigemptyset`/`sigaddset` has no
    // failure mode on Linux, and a vCPU whose stop signal is deliverable
    // outside `KVM_RUN` cannot be reliably paused — so this is an
    // invariant, not a condition to fall back from.
    assert_eq!(
        rc,
        0,
        "pthread_sigmask(SIG_BLOCK, signal {}) failed: {rc}",
        vcpu_stop_signal()
    );
}

/// The signal that gets a vCPU out of `KVM_RUN`.
///
/// Deliberately *not* the `SIGRTMIN` the virtio workers are interrupted
/// with, because the vCPU path keeps this one blocked outside `KVM_RUN`
/// (see [`set_kvm_signal_mask`]) and a blocked real-time signal queues
/// rather than coalescing. Virtio device activation happens on an MMIO
/// exit, i.e. *on a vCPU thread*, so a worker spawned there inherits
/// that thread's mask — and with one signal for both jobs, every pause
/// queued a `SIGRTMIN` into a worker that would never dequeue it. Three
/// per cycle filled the per-*user* `RLIMIT_SIGPENDING` after ~86 000
/// cycles, at which point `pthread_kill` returned `EAGAIN` and vCPUs
/// stopped being stoppable at all (`CHALLENGES.md` #185).
///
/// glibc's `SIGRTMIN()` already skips its own three reserved real-time
/// signals, so `+1` is a free one.
fn vcpu_stop_signal() -> libc::c_int {
    libc::SIGRTMIN() + 1
}

/// Install a no-op signal handler for both kick signals, used to
/// interrupt `KVM_RUN` and the virtio workers' blocking IO.
///
/// `KVM_RUN` blocks the vCPU thread (especially during HLT). To pause the VM,
/// we send [`vcpu_stop_signal`] via `pthread_kill`, which causes `KVM_RUN` to return
/// `EINTR`. The handler itself is a no-op — we just need the signal delivery.
/// It must still exist: a signal whose disposition is the default would
/// kill the process rather than interrupt an ioctl.
///
/// This is safe to call multiple times (idempotent).
fn install_vcpu_signal_handler() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // SAFETY: sigaction with SA_SIGINFO and a valid handler pointer.
        unsafe {
            extern "C" fn noop_handler(
                _signum: libc::c_int,
                _info: *mut libc::siginfo_t,
                _ctx: *mut libc::c_void,
            ) {
            }

            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_flags = libc::SA_SIGINFO;
            sa.sa_sigaction = noop_handler as usize;
            libc::sigemptyset(&raw mut sa.sa_mask);
            libc::sigaction(vcpu_stop_signal(), &sa, std::ptr::null_mut());
            libc::sigaction(libc::SIGRTMIN(), &sa, std::ptr::null_mut());
        }
    });
}

/// Configure the "zero page" (`boot_params`) for the Linux boot protocol.
///
/// `mptable_reservation` is `Some((addr, size))` when an MP table was
/// written to guest memory (`vcpus > 1` only) — the region is
/// reported as E820-reserved so the guest never allocates over it.
/// `None` keeps the E820 map byte-identical to the original layout.
/// Which of the two kernel image formats a file holds.
///
/// k7d's own guest is an uncompressed ELF `vmlinux`; a distro kernel
/// (`/boot/vmlinuz-*`) is a bzImage. Both boot on this VMM,
/// but they differ in where the entry point is and in whether the zero
/// page must carry the image's own setup header — so the format is
/// decided once, by magic bytes, instead of being guessed by trying
/// loaders until one stops erroring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelFormat {
    /// Uncompressed ELF `vmlinux` (`\x7fELF` at offset 0).
    Elf,
    /// Compressed bzImage (`HdrS` at offset 0x202).
    BzImage,
}

impl KernelFormat {
    /// Classify a kernel image from its first bytes (at least
    /// `0x206` of them). `None` means neither magic matched, which is
    /// always a loud error at the call site — never a "try anyway".
    #[must_use]
    pub fn detect(head: &[u8]) -> Option<Self> {
        if head.starts_with(&[0x7f, b'E', b'L', b'F']) {
            return Some(Self::Elf);
        }
        if head.len() >= BZIMAGE_MAGIC_OFFSET + 4
            && &head[BZIMAGE_MAGIC_OFFSET..BZIMAGE_MAGIC_OFFSET + 4] == b"HdrS"
        {
            return Some(Self::BzImage);
        }
        None
    }
}

/// Load `kernel_path` into `guest_memory` and return the address the BSP
/// must start at, plus the image's setup header when it brought one.
///
/// The returned setup header belongs in the zero page verbatim (see
/// [`configure_boot_params`]): a bzImage's decompressor reads
/// `setup_sects`, `init_size`, `relocatable_kernel`, `pref_address` and
/// `loadflags` back out of it, and a hand-built header like the ELF path
/// uses would send it decompressing into the wrong place.
fn load_kernel_image(
    guest_memory: &GuestMemoryMmap,
    kernel_path: &Path,
) -> Result<(GuestAddress, Option<setup_header>), VmError> {
    use std::io::Read;

    let kernel_err = |source: std::io::Error| VmError::KernelFile {
        path: kernel_path.to_path_buf(),
        // SAFETY: `geteuid` takes no arguments and cannot fail.
        uid: unsafe { libc::geteuid() },
        source,
    };
    let mut kernel_file = File::open(kernel_path).map_err(kernel_err)?;
    let mut head = vec![0u8; BZIMAGE_MAGIC_OFFSET + 4];
    // A kernel shorter than the magic window is simply not a kernel;
    // `read` filling less than the buffer leaves zeros, which matches
    // neither magic and therefore fails loudly below.
    let read = kernel_file.read(&mut head).map_err(kernel_err)?;
    head.truncate(read);

    match KernelFormat::detect(&head) {
        Some(KernelFormat::Elf) => {
            let loaded = ElfLoader::load(
                guest_memory,
                None,
                &mut kernel_file,
                Some(GuestAddress(HIMEM_START)),
            )
            .map_err(VmError::KernelLoad)?;
            log::info!(
                "kernel loaded (ELF): entry={:#x}",
                loaded.kernel_load.raw_value()
            );
            Ok((loaded.kernel_load, None))
        }
        Some(KernelFormat::BzImage) => {
            let loaded = BzImageLoader::load(
                guest_memory,
                None,
                &mut kernel_file,
                Some(GuestAddress(HIMEM_START)),
            )
            .map_err(VmError::KernelLoad)?;
            let hdr = loaded
                .setup_header
                .ok_or_else(|| VmError::BzImageNoSetupHeader(kernel_path.to_path_buf()))?;
            let entry = loaded
                .kernel_load
                .raw_value()
                .checked_add(BZIMAGE_64BIT_ENTRY_OFFSET)
                .ok_or_else(|| {
                    VmError::Pipe(std::io::Error::other(
                        "bzImage load address plus the 64-bit entry offset overflows",
                    ))
                })?;
            // `setup_header` is `#[repr(packed)]`, so these are read out
            // by value: a reference to a packed field (which `log!`'s
            // format args would take) is undefined behaviour.
            let (setup_sects, init_size, relocatable) =
                (hdr.setup_sects, hdr.init_size, hdr.relocatable_kernel);
            log::info!(
                "kernel loaded (bzImage): load={:#x} entry={entry:#x} \
                 setup_sects={setup_sects} init_size={init_size:#x} \
                 relocatable={relocatable}",
                loaded.kernel_load.raw_value(),
            );
            Ok((GuestAddress(entry), Some(hdr)))
        }
        None => Err(VmError::KernelFormat {
            path: kernel_path.to_path_buf(),
            head: head.into_iter().take(8).collect(),
        }),
    }
}

fn configure_boot_params(
    guest_memory: &GuestMemoryMmap,
    cmdline_addr: GuestAddress,
    cmdline_size: usize,
    layout: MemLayout,
    initrd_config: Option<(GuestAddress, usize)>,
    mptable_reservation: Option<(u64, u64)>,
    setup_hdr: Option<setup_header>,
) -> Result<(), VmError> {
    let mut params = boot_params::default();

    if let Some(hdr) = setup_hdr {
        // A bzImage's own header, with `code32_start` already pointing
        // at where the loader put the kernel. Everything the
        // decompressor needs (`init_size`, `pref_address`,
        // `relocatable_kernel`, `setup_sects`, `version`, and the
        // LOADED_HIGH bit in `loadflags`) is in these bytes, so it is
        // copied rather than rebuilt. `loadflags`' CAN_USE_HEAP bit is
        // deliberately left as the image shipped it (clear): it grants
        // the *real-mode* setup code a heap at `heap_end_ptr`, and this
        // VMM never runs that code — it enters at the 64-bit entry
        // point with the CPU already in long mode.
        params.hdr = hdr;
    } else {
        params.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
        params.hdr.header = KERNEL_HDR_MAGIC;
        params.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;
        // Protocol version 2.14+ supports initrd and other features
        params.hdr.version = 0x020e;
    }
    params.hdr.type_of_loader = KERNEL_LOADER_OTHER;
    params.hdr.cmd_line_ptr = cmdline_addr.raw_value() as u32;
    params.hdr.cmdline_size = cmdline_size as u32;

    if let Some((initrd_addr, initrd_size)) = initrd_config {
        let rd_img = initrd_addr.raw_value() as u32;
        let rd_sz = initrd_size as u32;
        params.hdr.ramdisk_image = rd_img;
        params.hdr.ramdisk_size = rd_sz;
    }

    // E820 memory map: report usable RAM
    // Entry 0: low memory [0, 0x9fc00) — conventional RAM below EBDA
    add_e820_entry(&mut params, 0, 0x9fc00, E820_RAM);
    // Reserve the MP table region (multi-vCPU boots only —
    // it lives at 0x9fc00, just past usable low RAM, like Firecracker).
    if let Some((addr, size)) = mptable_reservation {
        add_e820_entry(&mut params, addr, size, E820_RESERVED);
    }
    // Entry 1: [1MB, end of the low RAM region)
    add_e820_entry(
        &mut params,
        HIMEM_START,
        layout.low_size.saturating_sub(HIMEM_START),
        E820_RAM,
    );
    // Entry 2: RAM past the 32-bit MMIO hole. The hole itself
    // is simply absent from the map, which Linux treats as reserved.
    if layout.has_high_mem() {
        add_e820_entry(
            &mut params,
            crate::mem_layout::HIGH_MEM_START,
            layout.high_size,
            E820_RAM,
        );
    }

    LinuxBootConfigurator::write_bootparams(
        &BootParams::new(&params, GuestAddress(ZERO_PAGE_START)),
        guest_memory,
    )
    .map_err(VmError::BootParams)?;

    Ok(())
}

/// Add an entry to the E820 memory map in `boot_params`.
fn add_e820_entry(params: &mut boot_params, addr: u64, size: u64, mem_type: u32) {
    let i = params.e820_entries as usize;
    if i < params.e820_table.len() {
        params.e820_table[i].addr = addr;
        params.e820_table[i].size = size;
        params.e820_table[i].type_ = mem_type;
        params.e820_entries += 1;
    }
}

/// GDT entry encoding (matches Linux/x86 convention).
fn gdt_entry(flags: u16, base: u32, limit: u32) -> u64 {
    ((u64::from(base) & 0xff00_0000u64) << (56 - 24))
        | ((u64::from(flags) & 0x0000_f0ffu64) << 40)
        | ((u64::from(limit) & 0x000f_0000u64) << (48 - 16))
        | ((u64::from(base) & 0x00ff_ffffu64) << 16)
        | (u64::from(limit) & 0x0000_ffffu64)
}

/// Extract segment descriptor fields from a GDT entry.
fn kvm_segment_from_gdt(entry: u64, table_index: u8) -> kvm_segment {
    let get_base = |e: u64| -> u64 {
        ((e & 0xFF00_0000_0000_0000) >> 32)
            | ((e & 0x0000_00FF_0000_0000) >> 16)
            | ((e & 0x0000_0000_FFFF_0000) >> 16)
    };
    let get_limit = |e: u64| -> u32 {
        let limit = ((e & 0x000F_0000_0000_0000) >> 32) | (e & 0xFFFF);
        let g = ((e & 0x0080_0000_0000_0000) >> 55) as u32;
        if g == 1 {
            ((limit as u32) << 12) | 0xFFF
        } else {
            limit as u32
        }
    };
    let get_g = |e: u64| -> u8 { ((e & 0x0080_0000_0000_0000) >> 55) as u8 };
    let get_db = |e: u64| -> u8 { ((e & 0x0040_0000_0000_0000) >> 54) as u8 };
    let get_l = |e: u64| -> u8 { ((e & 0x0020_0000_0000_0000) >> 53) as u8 };
    let get_avl = |e: u64| -> u8 { ((e & 0x0010_0000_0000_0000) >> 52) as u8 };
    let get_p = |e: u64| -> u8 { ((e & 0x0000_8000_0000_0000) >> 47) as u8 };
    let get_dpl = |e: u64| -> u8 { ((e & 0x0000_6000_0000_0000) >> 45) as u8 };
    let get_s = |e: u64| -> u8 { ((e & 0x0000_1000_0000_0000) >> 44) as u8 };
    let get_type = |e: u64| -> u8 { ((e & 0x0000_0F00_0000_0000) >> 40) as u8 };

    let p = get_p(entry);
    kvm_segment {
        base: get_base(entry),
        limit: get_limit(entry),
        selector: u16::from(table_index) * 8,
        type_: get_type(entry),
        present: p,
        dpl: get_dpl(entry),
        db: get_db(entry),
        s: get_s(entry),
        l: get_l(entry),
        g: get_g(entry),
        avl: get_avl(entry),
        padding: 0,
        unusable: u8::from(p == 0),
    }
}

/// Set up general-purpose registers for the Linux 64-bit boot protocol.
fn setup_regs(vcpu: &VcpuFd, entry_addr: GuestAddress) -> Result<(), VmError> {
    let regs = kvm_regs {
        rflags: 0x0000_0000_0000_0002,
        rip: entry_addr.raw_value(),
        rsp: BOOT_STACK_POINTER,
        rbp: BOOT_STACK_POINTER,
        rsi: ZERO_PAGE_START,
        ..Default::default()
    };
    vcpu.set_regs(&regs).map_err(VmError::SetRegs)
}

/// Set up special registers: GDT, IDT, segments, paging for long mode.
fn setup_sregs(guest_memory: &GuestMemoryMmap, vcpu: &VcpuFd) -> Result<(), VmError> {
    let mut sregs = vcpu.get_sregs().map_err(VmError::GetSregs)?;

    // GDT entries for Linux 64-bit boot
    let gdt_table = [
        gdt_entry(0, 0, 0),            // NULL
        gdt_entry(0xa09b, 0, 0xfffff), // CODE
        gdt_entry(0xc093, 0, 0xfffff), // DATA
        gdt_entry(0x808b, 0, 0xfffff), // TSS
    ];

    let code_seg = kvm_segment_from_gdt(gdt_table[1], 1);
    let data_seg = kvm_segment_from_gdt(gdt_table[2], 2);
    let tss_seg = kvm_segment_from_gdt(gdt_table[3], 3);

    // Write GDT to guest memory
    for (i, entry) in gdt_table.iter().enumerate() {
        guest_memory
            .write_obj(*entry, GuestAddress(BOOT_GDT_OFFSET + (i as u64) * 8))
            .map_err(VmError::GuestMemory)?;
    }
    sregs.gdt.base = BOOT_GDT_OFFSET;
    sregs.gdt.limit = (std::mem::size_of_val(&gdt_table) as u16) - 1;

    // Write IDT (empty)
    guest_memory
        .write_obj(0u64, GuestAddress(BOOT_IDT_OFFSET))
        .map_err(VmError::GuestMemory)?;
    sregs.idt.base = BOOT_IDT_OFFSET;
    sregs.idt.limit = (std::mem::size_of::<u64>() as u16) - 1;

    // Set segment registers
    sregs.cs = code_seg;
    sregs.ds = data_seg;
    sregs.es = data_seg;
    sregs.fs = data_seg;
    sregs.gs = data_seg;
    sregs.ss = data_seg;
    sregs.tr = tss_seg;

    // Enable protected mode + long mode
    // Clear NW and CD flags from default state, then set PE
    sregs.cr0 = (sregs.cr0 & !(0x6000_0000u64)) | X86_CR0_PE;
    sregs.efer |= EFER_LME | EFER_LMA;

    // Set up identity-mapped page tables for the first 1 GiB
    let boot_pml4_addr = GuestAddress(PML4_START);
    let boot_pdpte_addr = GuestAddress(PDPTE_START);
    let boot_pde_addr = GuestAddress(PDE_START);

    // PML4[0] -> PDPT
    guest_memory
        .write_obj(boot_pdpte_addr.raw_value() | 0x03, boot_pml4_addr)
        .map_err(VmError::GuestMemory)?;
    // PDPT[0] -> PD
    guest_memory
        .write_obj(boot_pde_addr.raw_value() | 0x03, boot_pdpte_addr)
        .map_err(VmError::GuestMemory)?;
    // 512 x 2MB pages covering [0, 1GiB)
    for i in 0u64..512 {
        guest_memory
            .write_obj((i << 21) + 0x83u64, boot_pde_addr.unchecked_add(i * 8))
            .map_err(VmError::GuestMemory)?;
    }

    sregs.cr3 = boot_pml4_addr.raw_value();
    sregs.cr4 |= X86_CR4_PAE;
    sregs.cr0 |= X86_CR0_PG;

    vcpu.set_sregs(&sregs).map_err(VmError::SetSregs)
}

/// Patch the per-CPU identity leaves of a host-supported CPUID for one
/// vCPU of a multi-vCPU guest (following Firecracker's
/// `normalize`): leaf 0x1 gets the initial APIC ID (EBX[31:24]), the
/// max-addressable-IDs field (EBX[23:16]) and the HTT flag (EDX[28]);
/// leaf 0xB (extended topology) gets the x2APIC ID in EDX plus sane
/// level counts. KVM already numbers LAPIC IDs by vCPU index, so the
/// patched values line up with the MP table's processor entries.
///
/// Only called on the [`CpuTopology::Smp`] path — single-vCPU boots
/// keep the raw host-supported CPUID (byte-stability for the
/// fork/snapshot suites). Also used by the restore paths' no-captured-
/// CPUID fallback.
pub(crate) fn patch_cpuid_for_vcpu(
    cpuid: &mut kvm_bindings::CpuId,
    cpu_index: u32,
    cpu_count: u32,
) {
    for entry in cpuid.as_mut_slice().iter_mut() {
        match entry.function {
            0x1 => {
                // EBX[31:24] initial APIC ID; EBX[23:16] max addressable
                // logical-processor IDs in this package.
                entry.ebx = (entry.ebx & 0x0000_ffff)
                    | ((cpu_count.next_power_of_two() & 0xff) << 16)
                    | ((cpu_index & 0xff) << 24);
                // EDX[28] HTT: EBX[23:16] is valid.
                entry.edx |= 1 << 28;
            }
            0xB => {
                // One logical processor per core: subleaf 0 (logical
                // processor domain) is 1-wide, subleaf 1 (core domain)
                // spans all vCPUs. EDX carries the x2APIC ID.
                entry.eax = 0;
                entry.ebx = 0;
                entry.ecx = entry.index & 0xff;
                match entry.index {
                    0 => {
                        entry.ebx = 1;
                        entry.ecx |= 1 << 8; // domain type: logical processor
                    }
                    1 => {
                        entry.eax = cpu_count.next_power_of_two().ilog2();
                        entry.ebx = cpu_count & 0xffff;
                        entry.ecx |= 2 << 8; // domain type: core
                    }
                    _ => {}
                }
                entry.edx = cpu_index;
            }
            _ => {}
        }
    }
}

/// Tell the guest it is a guest, and offer it exactly the paravirt
/// features k7d can carry across a snapshot.
///
/// `KVM_GET_SUPPORTED_CPUID` hands back the KVM signature leaves
/// (`0x4000_0000`/`0x4000_0001`) but leaves CPUID.1:ECX[31] clear, and
/// the guest gates its whole paravirt path on that one bit
/// (`kvm_para_available()` → `kvm_cpuid_base()`). Without it the guest
/// logs "Booting paravirtualized kernel on bare hardware",
/// `kvmclock_init` returns early, and `CONFIG_KVM_GUEST=y` buys nothing
/// — which is how k7d guests ran for their whole history.
///
/// Leaf `0x4000_0001` is narrowed to kvmclock: `CLOCKSOURCE2` (the
/// `MSR_KVM_*_NEW` pair) and the TSC-stable bit. Every other feature
/// KVM offers there — async page faults, steal time, PV EOI, PV TLB
/// flush, poll control — has the guest hand the host a guest physical
/// address through a per-vCPU MSR, and a restored guest whose MSR was
/// not carried across keeps a page the host has stopped writing.
/// Advertising one of them is therefore a promise to snapshot it: add
/// its MSR to `snapshot::MSR_INDICES` in the same commit.
pub(crate) fn patch_cpuid_for_kvm_guest(cpuid: &mut kvm_bindings::CpuId) {
    /// CPUID.1:ECX[31] — "running under a hypervisor".
    const HYPERVISOR: u32 = 1 << 31;
    /// `KVM_FEATURE_CLOCKSOURCE2` | `KVM_FEATURE_CLOCKSOURCE_STABLE_BIT`.
    const KVM_PV_FEATURES: u32 = (1 << 3) | (1 << 24);

    for entry in cpuid.as_mut_slice().iter_mut() {
        match entry.function {
            0x1 => entry.ecx |= HYPERVISOR,
            0x4000_0001 => {
                entry.eax &= KVM_PV_FEATURES;
                // EDX carries hints, not features. Bit 0 is
                // `KVM_HINTS_REALTIME` — the bit the guest haltpoll
                // driver looks for. It means "every vCPU has a
                // dedicated host CPU". k7d does not pin vCPUs, so we
                // keep this clear on purpose and load haltpoll with
                // `cpuidle_haltpoll.force=1` on the cmdline instead.
                // Do not set this bit to get a side effect.
                entry.edx = 0;
            }
            _ => {}
        }
    }
}

/// Set up FPU registers.
fn setup_fpu(vcpu: &VcpuFd) -> Result<(), VmError> {
    let fpu = kvm_bindings::kvm_fpu {
        fcw: 0x37f,
        mxcsr: 0x1f80,
        ..Default::default()
    };
    vcpu.set_fpu(&fpu).map_err(VmError::SetFpu)
}

/// Recursively sync a host directory to the guest via the agent.
fn sync_dir_to_guest(
    agent: &mut AgentClient,
    base: &Path,
    dir: &Path,
    guest_mount: &str,
) -> Result<(), VmError> {
    for entry in std::fs::read_dir(dir).map_err(VmError::InitrdFile)? {
        let entry = entry.map_err(VmError::InitrdFile)?;
        let path = entry.path();
        let relative = path.strip_prefix(base).unwrap();
        let guest_path = format!("{}/{}", guest_mount, relative.display());

        if path.is_dir() {
            agent
                .exec(&["mkdir", "-p", &guest_path])
                .map_err(VmError::Agent)?;
            sync_dir_to_guest(agent, base, &path, guest_mount)?;
        } else if path.is_file() {
            let data = std::fs::read(&path).map_err(VmError::InitrdFile)?;
            agent
                .write_file(&guest_path, &data)
                .map_err(VmError::Agent)?;
        }
    }
    Ok(())
}

#[cfg(kani)]
mod verification {
    use super::*;
    use crate::mem_layout::MMIO_HOLE_START;

    /// A clipped `SEEK_DATA` extent stays inside its page-aligned RAM
    /// slot, is page-aligned, and covers every byte of the extent that
    /// lies in the slot — the live keyframe's pass-0 `pwrite` reads
    /// exactly that range out of the guest mapping, and a byte it missed
    /// would read back as a hole (zero) in the keyframe.
    #[kani::proof]
    fn verify_clip_extent_in_slot() {
        let (lo_pg, hi_pg, start, end): (u64, u64, u64, u64) =
            (kani::any(), kani::any(), kani::any(), kani::any());
        kani::assume(lo_pg < hi_pg && hi_pg <= 1 << 40);
        kani::assume(start < end && end <= 1 << 52);
        let (lo, hi) = (lo_pg * 4096, hi_pg * 4096);
        match clip_extent(start, end, lo, hi) {
            None => assert!(
                end <= lo || start >= hi,
                "only a disjoint extent clips to nothing"
            ),
            Some((s, e)) => {
                assert!(lo <= s && s < e && e <= hi);
                assert!(s % 4096 == 0 && e % 4096 == 0);
                assert!(s <= start.max(lo) && end.min(hi) <= e);
            }
        }
    }

    /// The initrd goes at the top of the LOW RAM region, so its
    /// address must stay page-aligned, clear of the kernel, inside low RAM
    /// — and, because the boot protocol carries it in a 32-bit field,
    /// below 4 GiB for every guest size including the huge ones.
    #[kani::proof]
    #[kani::unwind(2)]
    fn verify_initrd_placement_within_bounds() {
        let mem_mb: u64 = kani::any();
        kani::assume(mem_mb >= 64 && mem_mb <= 64 * 1024);
        let layout = MemLayout::from_ram(mem_mb * 1024 * 1024);

        let initrd_size: u64 = kani::any();
        // Bound the size *before* using it in arithmetic: `kani::any()`
        // spans all of `u64`, and the addition in the second assume is
        // itself checked for overflow.
        kani::assume(initrd_size > 0 && initrd_size < layout.low_size);
        kani::assume(initrd_size + HIMEM_START < layout.low_size);

        let initrd_addr_raw = (layout.low_size - initrd_size) & !0xFFF;

        assert!(
            initrd_addr_raw >= HIMEM_START,
            "initrd overlaps kernel area"
        );
        assert!(
            initrd_addr_raw + initrd_size <= layout.low_size,
            "initrd extends past low guest memory"
        );
        assert!(initrd_addr_raw % 4096 == 0, "initrd not page-aligned");
        assert!(
            initrd_addr_raw + initrd_size <= u64::from(u32::MAX),
            "initrd address must fit the 32-bit boot_params field"
        );
    }

    /// The E820 low-RAM entry must never underflow, and RAM must never be
    /// reported inside the 32-bit MMIO hole.
    #[kani::proof]
    fn verify_e820_regions_are_sane() {
        let mem_size: u64 = kani::any();
        kani::assume(mem_size >= 2 * 1024 * 1024);
        kani::assume(mem_size <= 64 * 1024 * 1024 * 1024);
        let layout = MemLayout::from_ram(mem_size);

        let low_entry = layout.low_size.saturating_sub(HIMEM_START);
        assert!(HIMEM_START + low_entry <= MMIO_HOLE_START);
        assert!(layout.low_size + layout.high_size == mem_size);
        if layout.has_high_mem() {
            assert!(layout.span() > crate::mem_layout::HIGH_MEM_START);
        } else {
            assert!(layout.span() == mem_size);
        }
    }

    #[kani::proof]
    fn verify_gdt_roundtrip() {
        let flags: u16 = kani::any();
        let base: u32 = kani::any();
        let limit_raw: u32 = kani::any();
        kani::assume(limit_raw <= 0x000f_ffff); // 20-bit limit field

        let entry = gdt_entry(flags, base, limit_raw);
        let seg = kvm_segment_from_gdt(entry, 1);

        assert_eq!(seg.base, u64::from(base));

        // type_ is encoded from flags bits 0-3
        assert_eq!(seg.type_, (flags & 0x0F) as u8);
        assert_eq!(seg.present, ((flags >> 7) & 1) as u8);
        assert_eq!(seg.dpl, ((flags >> 5) & 3) as u8);
        assert_eq!(seg.s, ((flags >> 4) & 1) as u8);
    }

    #[kani::proof]
    fn verify_page_table_entries_valid() {
        let i: u64 = kani::any();
        kani::assume(i < 512);

        let pde = (i << 21) + 0x83u64;

        assert!(pde & 1 == 1, "PDE must be present");
        assert!(pde & 2 == 2, "PDE must be writable");
        assert!(pde & 0x80 == 0x80, "PDE must be 2MB page");
        let phys_addr = pde & 0x000F_FFFF_FFE0_0000;
        assert!(phys_addr == i * (2 * 1024 * 1024), "PDE maps wrong address");
    }

    #[kani::proof]
    fn verify_serial_port_ranges_no_overlap() {
        let addr: u16 = kani::any();

        let in_com1 = (SERIAL_PORT_BASE..SERIAL_PORT_BASE + SERIAL_PORT_SIZE).contains(&addr);
        let in_com2 = (SERIAL2_PORT_BASE..SERIAL2_PORT_BASE + SERIAL_PORT_SIZE).contains(&addr);

        assert!(!(in_com1 && in_com2), "COM1 and COM2 port ranges overlap");
    }

    #[kani::proof]
    fn verify_e820_entry_bounded() {
        let mut params = boot_params::default();

        add_e820_entry(&mut params, 0, 0x9fc00, E820_RAM);
        assert_eq!(params.e820_entries, 1);
        assert!((params.e820_entries as usize) <= params.e820_table.len());

        add_e820_entry(
            &mut params,
            HIMEM_START,
            256 * 1024 * 1024 - HIMEM_START,
            E820_RAM,
        );
        assert_eq!(params.e820_entries, 2);
        assert!((params.e820_entries as usize) <= params.e820_table.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm_ioctls::VcpuExit;

    /// The two kernel formats are told apart by magic, and anything
    /// else is refused rather than fed to a loader "to see".
    #[test]
    fn kernel_format_detects_elf_and_bzimage_and_refuses_the_rest() {
        let mut elf = vec![0u8; 0x400];
        elf[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        assert_eq!(KernelFormat::detect(&elf), Some(KernelFormat::Elf));

        let mut bz = vec![0u8; 0x400];
        bz[BZIMAGE_MAGIC_OFFSET..BZIMAGE_MAGIC_OFFSET + 4].copy_from_slice(b"HdrS");
        // A bzImage's first bytes are the real-mode boot sector, which
        // starts with the `MZ`-ish jump — never the ELF magic.
        bz[..2].copy_from_slice(b"MZ");
        assert_eq!(KernelFormat::detect(&bz), Some(KernelFormat::BzImage));

        assert_eq!(KernelFormat::detect(&[0u8; 0x400]), None);
        assert_eq!(
            KernelFormat::detect(b"HdrS"),
            None,
            "magic must be at 0x202"
        );
        assert_eq!(KernelFormat::detect(&[]), None);
    }

    /// A file that is neither format fails at `build` with the loud
    /// format error, naming the path — not with a loader's "invalid ELF
    /// magic number", which reads as a broken kernel rather than a
    /// wrong file.
    #[test]
    fn build_refuses_a_kernel_that_is_neither_elf_nor_bzimage() {
        let dir = tempfile::tempdir().unwrap();
        let bogus = dir.path().join("not-a-kernel");
        std::fs::write(&bogus, b"#!/bin/sh\necho hello\n").unwrap();
        match VmBuilder::new().kernel(&bogus).build() {
            Err(VmError::KernelFormat { path, .. }) => assert_eq!(path, bogus),
            Err(other) => panic!("expected KernelFormat, got {other}"),
            Ok(_) => panic!("a shell script must not boot as a kernel"),
        }
    }

    /// The bzImage zero page carries the image's *own* setup header, and
    /// the ELF one carries the hand-built header. Asserted on the bytes
    /// written to guest memory, because getting this backwards is a
    /// silent decompressor crash rather than an error.
    #[test]
    fn boot_params_carry_the_bzimage_setup_header_verbatim() {
        let mem =
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 16 * 1024 * 1024)]).unwrap();
        let layout = MemLayout::from_ram(16 * 1024 * 1024);

        let hdr = setup_header {
            setup_sects: 0x1d,
            header: KERNEL_HDR_MAGIC,
            version: 0x020f,
            loadflags: 0x1,
            relocatable_kernel: 1,
            init_size: 0x0123_4000,
            ..Default::default()
        };
        configure_boot_params(
            &mem,
            GuestAddress(CMDLINE_START),
            7,
            layout,
            None,
            None,
            Some(hdr),
        )
        .unwrap();
        // Fields are copied out by value: `setup_header` is packed, so a
        // reference to one of its fields is UB (and `assert_eq!` takes
        // references).
        let written: boot_params = mem.read_obj(GuestAddress(ZERO_PAGE_START)).unwrap();
        let w = written.hdr;
        assert_eq!({ w.init_size }, 0x0123_4000);
        assert_eq!({ w.relocatable_kernel }, 1);
        assert_eq!({ w.version }, 0x020f);
        assert_eq!({ w.setup_sects }, 0x1d);
        assert_eq!({ w.type_of_loader }, KERNEL_LOADER_OTHER);
        assert_eq!({ w.cmd_line_ptr }, CMDLINE_START as u32);
        assert_eq!(
            { w.loadflags } & 0x80,
            0,
            "CAN_USE_HEAP must stay clear: no real-mode setup code runs"
        );

        // The ELF path is unchanged: no image header, so the
        // hand-built 2.14 one.
        configure_boot_params(
            &mem,
            GuestAddress(CMDLINE_START),
            7,
            layout,
            None,
            None,
            None,
        )
        .unwrap();
        let written: boot_params = mem.read_obj(GuestAddress(ZERO_PAGE_START)).unwrap();
        let w = written.hdr;
        assert_eq!({ w.version }, 0x020e);
        assert_eq!({ w.boot_flag }, KERNEL_BOOT_FLAG_MAGIC);
        assert_eq!({ w.init_size }, 0, "no bzImage fields leak in");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_kvm_long_mode_io() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();

        vm.set_tss_address(0xfffb_d000usize).unwrap();
        vm.create_irq_chip().unwrap();
        vm.create_pit2(kvm_pit_config {
            flags: KVM_PIT_SPEAKER_DUMMY,
            ..Default::default()
        })
        .unwrap();

        let mem_size: usize = 256 * 1024 * 1024;
        let load_addr = GuestAddress(0);
        let guest_memory = GuestMemoryMmap::<()>::from_ranges(&[(load_addr, mem_size)]).unwrap();

        let mem_region = kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: 0,
            memory_size: mem_size as u64,
            userspace_addr: guest_memory.get_host_address(load_addr).unwrap() as u64,
            flags: 0,
        };
        // SAFETY: guest_memory lives for the duration of the test; the region
        // is a contiguous mmap'd range owned by GuestMemoryMmap.
        unsafe { vm.set_user_memory_region(mem_region).unwrap() }

        let code_addr = GuestAddress(HIMEM_START);
        let code: &[u8] = &[
            0xba, 0xf8, 0x03, 0x00, 0x00, // mov edx, 0x3f8
            0xb0, 0x4b, // mov al, 'K'
            0xee, // out dx, al
            0xeb, 0xfe, // jmp $
        ];
        guest_memory.write_slice(code, code_addr).unwrap();

        let mut vcpu = vm.create_vcpu(0).unwrap();
        setup_sregs(&guest_memory, &vcpu).unwrap();
        setup_fpu(&vcpu).unwrap();

        let regs = kvm_regs {
            rflags: 2,
            rip: HIMEM_START,
            rsp: BOOT_STACK_POINTER,
            rbp: BOOT_STACK_POINTER,
            rsi: ZERO_PAGE_START,
            ..Default::default()
        };
        vcpu.set_regs(&regs).unwrap();

        let exit = vcpu.run().unwrap();
        match exit {
            VcpuExit::IoOut(port, data) => {
                assert_eq!(port, 0x3f8);
                assert_eq!(data, &[0x4b]);
            }
            VcpuExit::Shutdown => panic!("vCPU shutdown (triple fault)"),
            VcpuExit::FailEntry(reason, _) => panic!("fail entry: {:#x}", reason),
            other => panic!("expected IoOut, got {:?}", other),
        }
    }
}
