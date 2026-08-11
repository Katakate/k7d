//! KVM VM creation, memory mapping, vCPU run loop.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use kvm_bindings::{
    kvm_pit_config, kvm_regs, kvm_segment, kvm_userspace_memory_region, KVM_PIT_SPEAKER_DUMMY,
};
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use linux_loader::configurator::linux::LinuxBootConfigurator;
use linux_loader::configurator::{BootConfigurator, BootParams};
use linux_loader::loader::bootparam::boot_params;
use linux_loader::loader::elf::Elf as ElfLoader;
use linux_loader::loader::{load_cmdline, Cmdline, KernelLoader};
use std::os::unix::io::{AsRawFd, FromRawFd};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

use serde::{Deserialize, Serialize};

use crate::api::AgentClient;
use crate::block::BlockBackend;
use crate::devices::{
    PipeSerialDevice, SerialTrigger, SharedPipeSerialDevice, SharedSerialDevice, SERIAL2_PORT_BASE,
    SERIAL_PORT_BASE, SERIAL_PORT_SIZE,
};
use crate::network::{TapDevice, TapNetBackend};
use crate::virtio_mmio::{MmioDevice, MmioDeviceRegistry, SharedMmioRegistry};
use crate::virtiofs::{VirtioFsBackend, VirtiofsdProcess};
use crate::vsock::{allocate_cid, VhostVsockBackend};

use vmm_sys_util::eventfd::EventFd;

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
    #[error("failed to open kernel file: {0}")]
    KernelFile(std::io::Error),
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
}

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

// Boot params header constants
const KERNEL_LOADER_OTHER: u8 = 0xff;
const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
const KERNEL_HDR_MAGIC: u32 = 0x5372_6448;
const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x0100_0000;
const E820_RAM: u32 = 1;
const E820_RESERVED: u32 = 2;

// MMIO device addresses — placed ABOVE guest RAM so KVM generates MMIO exits
const MMIO_GAP: u64 = 0x1000; // gap between RAM end and first MMIO device
const MMIO_IRQ_BASE: u32 = 5; // IRQ 5+ for virtio devices (COM1=4, COM2=3)
/// IOAPIC pin count — every virtio-mmio device burns one pin
/// (IRQ `MMIO_IRQ_BASE + idx`), so at most `24 - 5 = 19` devices fit
///.
const IOAPIC_PINS: usize = 24;

/// Configuration for one host-guest directory sharing.
///
/// internal notes(one virtiofsd + one
/// virtio-fs MMIO device per share, all on the same VM). For
/// backward compatibility with pre-10b callers, the existing
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

/// Configuration for one virtio-blk device backed by a raw host file
///.
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
    /// `None` (the default, and the value deserialized from pre-Inc 2
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
///   byte-identical to the pre-17a layout),
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
    /// byte-identical to the pre-17a layout (no MP table, no E820
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
    /// these are tmpfs directories — internal notes
    /// emptyDir volumes (`/run/k7d/emptydir/<name>`).
    guest_dirs: Vec<String>,
    network: Option<NetworkConfig>,
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
/// 2. Installed share dir `/usr/local/share/k7d/{vmlinux,initramfs.cpio.gz}`
/// 3. Workspace root baked at compile time (`CARGO_MANIFEST_DIR/../../guest/...`)
///
/// Shared by [`VmBuilder::kernel_and_initrd`] and control-plane clients
/// that need to pass explicit paths to the k7d daemon.
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

    let share = PathBuf::from("/usr/local/share/k7d");
    let installed_kernel = share.join("vmlinux");
    let installed_initrd = share.join("initramfs.cpio.gz");
    if installed_kernel.is_file() && installed_initrd.is_file() {
        return (installed_kernel, installed_initrd);
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    (
        root.join("guest/kernel/vmlinux"),
        root.join("guest/rootfs/initramfs.cpio.gz"),
    )
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
            cmdline: String::from(
                "console=ttyS0 earlyprintk=serial,ttyS0,115200 noapic reboot=k panic=1 pci=off rdinit=/init initcall_debug mitigations=off idle=poll",
            ),
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
        }
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

    /// Set both kernel and initrd from default guest artifact paths.
    /// Searches relative to `CARGO_MANIFEST_DIR` for
    /// `guest/kernel/vmlinux` and `guest/rootfs/initramfs.cpio.gz`.
    #[must_use]
    pub fn kernel_and_initrd(self) -> Self {
        let (kernel, initrd) = default_guest_paths();
        self.kernel(kernel).initrd(initrd)
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
    /// Backward compatibility: this preserves the pre-10b single-
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
    /// `readonly: true` is enforced via the in-guest mount option
    /// `-o ro`. The agent reads `:ro` out of the `k7d.virtiofs=`
    /// cmdline param and passes `-o ro` to `mount -t virtiofs …`.
    /// Any write from a guest userspace process is bounced with
    /// `EROFS` at the VFS layer before reaching virtiofsd, matching
    /// the `runc` `ConfigMap` / `Secret` contract.
    ///
    /// The host-side `virtiofsd --readonly` belt-and-suspenders that
    /// internal notes's design sketch describes does not exist in the
    /// rust-vmm `virtiofsd` (≥1.7 removed the flag); see
    /// [`crate::virtiofs::VirtiofsdProcess::spawn_with_options`] for
    /// the place to add it back if a future virtiofsd build re-
    /// exposes the option.
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

    /// Attach a virtio-blk device backed by a raw host file (internal notes
    /// Inc 1). Devices appear in the guest in declaration order
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
    /// <fstype>`, `-o ro` when `readonly`) before containers start
    ///. The builder encodes the instruction into the
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

    /// Build and return a configured (but not started) VM.
    #[allow(clippy::too_many_lines)]
    pub fn build(self) -> Result<Vm, VmError> {
        let kernel_path = self.kernel_path.expect("kernel path is required");

        // internal notes: validate the vCPU count loudly before any resource
        // is allocated — never clamp silently.
        if self.vcpus == 0 || self.vcpus > u32::from(crate::mptable::MAX_SUPPORTED_CPUS) {
            return Err(VmError::Pipe(std::io::Error::other(format!(
                "invalid vcpus={}: must be 1..={}",
                self.vcpus,
                crate::mptable::MAX_SUPPORTED_CPUS
            ))));
        }

        let mem_size = self.memory_mb * 1024 * 1024;

        let kvm = Kvm::new().map_err(VmError::KvmOpen)?;
        let vm_fd = kvm.create_vm().map_err(VmError::CreateVm)?;

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

        // Allocate guest memory via memfd so we can share the fd with virtiofsd.
        // SAFETY: creating a memfd; name is a valid C string literal.
        let mem_fd_raw =
            unsafe { libc::memfd_create(c"k7d-guest-mem".as_ptr(), libc::MFD_CLOEXEC) };
        if mem_fd_raw < 0 {
            return Err(VmError::Pipe(std::io::Error::last_os_error()));
        }
        #[allow(clippy::cast_possible_wrap)]
        // SAFETY: mem_fd_raw is a valid memfd; setting the file size to mem_size.
        if unsafe { libc::ftruncate(mem_fd_raw, mem_size as libc::off_t) } < 0 {
            // SAFETY: mem_fd_raw is valid.
            unsafe { libc::close(mem_fd_raw) };
            return Err(VmError::Pipe(std::io::Error::last_os_error()));
        }

        // Remove CLOEXEC so virtiofsd can inherit the fd if needed
        // SAFETY: mem_fd_raw is valid.
        unsafe { libc::fcntl(mem_fd_raw, libc::F_SETFD, 0) };

        // SAFETY: mem_fd_raw is a valid memfd; File takes ownership (for use in FileOffset).
        let mem_file = unsafe { File::from_raw_fd(mem_fd_raw) };
        let mem_fd_for_virtiofs = mem_file.as_raw_fd();

        let guest_memory = GuestMemoryMmap::<()>::from_ranges_with_files(&[(
            GuestAddress(0),
            mem_size as usize,
            Some(vm_memory::FileOffset::new(mem_file, 0)),
        )])
        .map_err(VmError::CreateMemory)?;

        let mem_host_addr = guest_memory.get_host_address(GuestAddress(0)).unwrap() as u64;

        // Register memory with KVM
        let mem_region = kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: 0,
            memory_size: mem_size,
            userspace_addr: mem_host_addr,
            flags: 0,
        };
        // SAFETY: guest_memory is valid and will outlive the VM; the region
        // describes a contiguous mmap'd range owned by GuestMemoryMmap.
        unsafe {
            vm_fd
                .set_user_memory_region(mem_region)
                .map_err(VmError::SetUserMemoryRegion)?;
        }

        // Load kernel
        let mut kernel_file = File::open(&kernel_path).map_err(VmError::KernelFile)?;
        let entry_addr = ElfLoader::load(
            &guest_memory,
            None,
            &mut kernel_file,
            Some(GuestAddress(HIMEM_START)),
        )
        .map_err(VmError::KernelLoad)?;
        log::info!(
            "kernel loaded: entry={:#x}",
            entry_addr.kernel_load.raw_value()
        );

        // Set up virtio-MMIO devices and build cmdline with device params.
        //
        // Slot layout: each virtio-mmio device gets a 4 KiB GPA window
        // starting at `mem_size + MMIO_GAP` and a unique IRQ starting
        // at `MMIO_IRQ_BASE` (= 5). Slots are allocated sequentially
        // by `next_slot` as devices are added — the order is fixed at
        // (vsock?, virtiofs[0..N]?, blk[0..N]?, net?), matching the
        // historical (vsock@5, fs@6, net@7) layout for the common
        // single-fs-share case and extending naturally by giving each
        // additional virtiofs/blk device its own slot before net.
        let mut full_cmdline = self.cmdline.clone();
        let mmio_registry = Arc::new(std::sync::Mutex::new(MmioDeviceRegistry::new()));

        // internal notes: every virtio-mmio device consumes one IOAPIC
        // pin (IRQ `MMIO_IRQ_BASE + idx`, 24 pins total). Fail loud
        // BEFORE allocating past the budget — a device on a phantom
        // pin would silently never deliver interrupts.
        let mmio_devices = usize::from(self.vsock_enabled)
            + self.virtiofs_shares.len()
            + self.block_devices.len()
            + usize::from(self.network.is_some());
        if MMIO_IRQ_BASE as usize + mmio_devices > IOAPIC_PINS {
            return Err(VmError::Pipe(std::io::Error::other(format!(
                "{mmio_devices} virtio-mmio devices exceed the IOAPIC pin budget \
                 (IRQs {MMIO_IRQ_BASE}..{IOAPIC_PINS}, at most {} devices) — reduce \
                 block devices / virtiofs shares / image slots",
                IOAPIC_PINS - MMIO_IRQ_BASE as usize
            ))));
        }

        let mut next_slot: u32 = 0;
        let mmio_slot = |idx: u32| -> (u64, u32) {
            (
                mem_size + MMIO_GAP + u64::from(idx) * 0x1000,
                MMIO_IRQ_BASE + idx,
            )
        };

        if self.vsock_enabled {
            let (base, irq) = mmio_slot(next_slot);
            next_slot += 1;

            let irq_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(VmError::Pipe)?;
            vm_fd
                .register_irqfd(&irq_evt, irq)
                .map_err(|e| VmError::Pipe(std::io::Error::other(e)))?;
            let irq_evt = Arc::new(irq_evt);

            let vsock_backend = VhostVsockBackend::new(self.guest_cid, mem_host_addr, mem_size)
                .map_err(|e| VmError::Pipe(std::io::Error::other(e)))?;

            let mut dev = MmioDevice::new(base, irq, irq_evt, Box::new(vsock_backend));
            dev.set_vhost(true);
            let mmio_dev = Arc::new(std::sync::Mutex::new(dev));

            mmio_registry.lock().unwrap().add(Arc::clone(&mmio_dev));

            // Add virtio_mmio.device= to kernel cmdline
            full_cmdline.push_str(&format!(" virtio_mmio.device=4K@0x{base:x}:{irq}"));
            log::info!("virtio-mmio vsock at {base:#x} irq {irq}");
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
        // exactly what wedged pod recovery after a shim crash (spec
        // 11a increment 4). A per-process sequence number makes the
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
                let (base, irq) = mmio_slot(next_slot);
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

                let irq_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(VmError::Pipe)?;
                vm_fd
                    .register_irqfd(&irq_evt, irq)
                    .map_err(|e| VmError::Pipe(std::io::Error::other(e)))?;
                let irq_evt = Arc::new(irq_evt);

                let fs_backend = VirtioFsBackend::new(
                    &socket_path,
                    &tag,
                    mem_host_addr,
                    mem_size,
                    mem_fd_for_virtiofs,
                )
                .map_err(|e| VmError::Pipe(std::io::Error::other(e)))?;

                let mut dev = MmioDevice::new(base, irq, irq_evt, Box::new(fs_backend));
                dev.set_vhost(true);
                let mmio_dev = Arc::new(std::sync::Mutex::new(dev));
                mmio_registry.lock().unwrap().add(Arc::clone(&mmio_dev));

                full_cmdline.push_str(&format!(" virtio_mmio.device=4K@0x{base:x}:{irq}"));
                log::info!(
                    "virtio-mmio virtiofs[{idx}] tag={tag} ro={} at {base:#x} irq {irq}",
                    share.readonly
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

        // Add one virtio-blk MMIO device per configured block device
        //. Userspace backend — no vhost handshake, no
        // guest-memory fd requirement, so block-backed VMs stay on the
        // CoW fork path. Devices with a mount spec are collected into
        // the `k7d.blk=` cmdline param the guest agent mounts from
        //, keyed by the guest device name that
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
            let (base, irq) = mmio_slot(next_slot);
            next_slot += 1;

            let irq_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(VmError::Pipe)?;
            vm_fd
                .register_irqfd(&irq_evt, irq)
                .map_err(|e| VmError::Pipe(std::io::Error::other(e)))?;
            let irq_evt = Arc::new(irq_evt);

            let blk_backend =
                BlockBackend::new(&blk.host_path, blk.readonly, mem_host_addr, mem_size)
                    .map_err(|e| VmError::Pipe(std::io::Error::other(e)))?;

            let mut dev = MmioDevice::new(base, irq, irq_evt, Box::new(blk_backend));
            // The worker signals the irqfd directly (like TapNetBackend), so
            // INTERRUPT_STATUS must always report INT_VRING.
            dev.set_vhost(true);
            let mmio_dev = Arc::new(std::sync::Mutex::new(dev));
            mmio_registry.lock().unwrap().add(Arc::clone(&mmio_dev));

            full_cmdline.push_str(&format!(" virtio_mmio.device=4K@0x{base:x}:{irq}"));
            log::info!(
                "virtio-mmio blk[{idx}] file={} ro={} mount={:?} at {base:#x} irq {irq}",
                blk.host_path.display(),
                blk.readonly,
                blk.mount
            );
        }
        if !blk_mount_specs.is_empty() {
            full_cmdline.push_str(&format!(" k7d.blk={}", blk_mount_specs.join(",")));
        }

        // Guest directories the agent creates at boot (internal notes,
        // emptyDir on guest tmpfs). Validated loudly: an absolute,
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

        // Add virtio-net MMIO device if network is configured.
        let mut tap_device = None;
        let mut guest_ip = None;
        if let Some(net_config) = self.network {
            // virtio-net is currently the last device allocated, so
            // we don't bump `next_slot` after consuming it. If you
            // add another device family after net here, reinstate
            // `next_slot += 1;` to keep the counter honest.
            let (base, irq) = mmio_slot(next_slot);

            let irq_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(VmError::Pipe)?;
            vm_fd
                .register_irqfd(&irq_evt, irq)
                .map_err(|e| VmError::Pipe(std::io::Error::other(e)))?;
            let irq_evt = Arc::new(irq_evt);

            let net_backend =
                TapNetBackend::new(net_config.tap.mac(), net_config.tap.fd(), mem_host_addr);

            let mut dev = MmioDevice::new(base, irq, irq_evt, Box::new(net_backend));
            dev.set_vhost(true);
            let mmio_dev = Arc::new(std::sync::Mutex::new(dev));
            mmio_registry.lock().unwrap().add(Arc::clone(&mmio_dev));

            full_cmdline.push_str(&format!(" virtio_mmio.device=4K@0x{base:x}:{irq}"));
            log::info!("virtio-mmio net at {base:#x} irq {irq}");

            guest_ip = Some(net_config.tap.guest_ip());
            tap_device = Some(net_config.tap);
        }

        let mut cmdline = Cmdline::new(0x10000).map_err(VmError::Cmdline)?;
        cmdline
            .insert_str(&full_cmdline)
            .map_err(VmError::Cmdline)?;
        load_cmdline(&guest_memory, GuestAddress(CMDLINE_START), &cmdline)
            .map_err(VmError::CmdlineLoad)?;

        // Load initrd if provided
        let initrd_config = if let Some(ref initrd_path) = self.initrd_path {
            let initrd_data = std::fs::read(initrd_path).map_err(VmError::InitrdFile)?;
            let initrd_size = initrd_data.len();
            // Align initrd address down to page boundary
            let initrd_addr_raw = (mem_size - initrd_size as u64) & !0xFFF;
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

        // internal notes: multi-vCPU guests discover CPUs via the MP table
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
            mem_size,
            initrd_config,
            mptable_reservation,
        )?;

        // Create the vCPUs. Every vCPU gets CPUID + FPU setup; only
        // vCPU 0 (the BSP) gets boot registers — APs stay in their KVM
        // reset state (`KVM_MP_STATE_UNINITIALIZED`) awaiting the
        // INIT/SIPI sequence the Linux guest itself sends during SMP
        // bring-up.
        let kvm_cpuid = kvm
            .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .map_err(VmError::GetCpuid)?;
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
                setup_regs(&vcpu_fd, entry_addr.kernel_load)?;
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
        let com1_irq_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(VmError::Pipe)?;
        vm_fd
            .register_irqfd(&com1_irq_evt, crate::devices::SERIAL_IRQ)
            .map_err(|e| VmError::Pipe(std::io::Error::other(e)))?;
        let serial = crate::devices::create_serial_device_with_trigger(
            SerialTrigger::with_eventfd(Arc::new(com1_irq_evt)),
        );

        // COM2 for agent communication — use irqfd to deliver IRQ 3 to guest
        let com2_irq_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(VmError::Pipe)?;
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
            _virtiofsds: virtiofsd_processes,
            tap: tap_device,
            guest_ip,
            virtiofs_shares: self.virtiofs_shares,
            block_devices: self.block_devices,
            running: Arc::new(AtomicBool::new(false)),
            vcpu_threads: Vec::new(),
            vcpu_return_rxs: Vec::new(),
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
    _virtiofsds: Vec<VirtiofsdProcess>,
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
    running: Arc<AtomicBool>,
    /// One run-loop thread per vCPU, in vCPU-index order.
    vcpu_threads: Vec<thread::JoinHandle<()>>,
    /// Per-thread channels to receive each `VcpuFd` back when its
    /// run-loop thread stops, in vCPU-index order.
    vcpu_return_rxs: Vec<mpsc::Receiver<VcpuFd>>,
    /// `pthread_t` of each vCPU thread (for sending signals to break
    /// `KVM_RUN`), in vCPU-index order.
    vcpu_tids: Vec<Arc<AtomicU64>>,
    /// Kernel TID of each vCPU thread (internal notes: written to a CPU
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
    /// internal notes: explicit opt-in for slow (full-memfd) forks of
    /// virtiofs-backed VMs. `prepare_fork_source*` on a VM with any
    /// virtiofs share fails loudly unless [`Self::allow_slow_fork`]
    /// was called first — silent degradation from the `CoW` fast path
    /// to a full memory copy is forbidden.
    slow_fork_allowed: bool,
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
    pub fn restore(snapshot_dir: &std::path::Path) -> Result<Self, crate::fork::RestoreError> {
        crate::fork::restore_vm(snapshot_dir)
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
            // internal notes: restored/forked VMs inherit the captured vCPU
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
            _virtiofsds: virtiofsds,
            tap,
            guest_ip,
            virtiofs_shares,
            block_devices,
            running: Arc::new(AtomicBool::new(false)),
            vcpu_threads: Vec::new(),
            vcpu_return_rxs: Vec::new(),
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
        }
    }

    /// Attach the memfd backing a virtiofs-capable fork's memory (see
    /// [`crate::fork::memfd_fork_memory`]). Held for the VM's lifetime.
    pub(crate) fn set_fork_mem_file(&mut self, file: File) {
        self.fork_mem_file = Some(file);
    }

    /// Start one vCPU run loop per vCPU in background threads.
    pub fn start(&mut self) -> Result<(), VmError> {
        assert!(!self.vcpu_fds.is_empty(), "VM already started");
        self.running.store(true, Ordering::SeqCst);
        install_vcpu_signal_handler();

        for (cpu_index, vcpu_fd) in self.vcpu_fds.drain(..).enumerate() {
            let serial = Arc::clone(&self.serial);
            let agent_serial = Arc::clone(&self.agent_serial);
            let mmio_registry = Arc::clone(&self.mmio_registry);
            let running = Arc::clone(&self.running);
            let (tx, rx) = mpsc::channel();
            let tid = Arc::new(AtomicU64::new(0));
            let kernel_tid = Arc::new(AtomicU64::new(0));

            let handle = {
                let tid = Arc::clone(&tid);
                let kernel_tid = Arc::clone(&kernel_tid);
                thread::Builder::new()
                    // Visible in /proc/<tid>/comm — used by ps/gdb and the
                    // internal notes
                    .name(format!("vcpu{cpu_index}"))
                    .spawn(move || {
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
                            &running,
                            tx,
                        );
                    })
                    .map_err(VmError::SpawnVcpuThread)?
            };

            self.vcpu_threads.push(handle);
            self.vcpu_return_rxs.push(rx);
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
    /// Backward-compatible accessor for code that predates internal notes's
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
    /// and plain restored VMs. Test hook for internal notes's "block-only VMs
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
        if !self.running.load(Ordering::SeqCst) {
            return Ok(());
        }
        // Freeze net workers first (brief MMIO lock) so they stop dirtying
        // pages before we join the vCPU and capture the bitmap.
        self.mmio_registry.lock().unwrap().set_paused_all(true);

        self.running.store(false, Ordering::SeqCst);

        // Signal every vCPU thread to break out of KVM_RUN (which may be
        // blocked in HLT). The signal handler is a no-op; the signal makes
        // KVM_RUN return EINTR, then each thread checks `running` and exits.
        self.signal_vcpu_threads();

        for handle in self.vcpu_threads.drain(..) {
            let _ = handle.join();
        }
        // The threads are gone; their kernel TIDs must not be handed out.
        for kernel_tid in self.vcpu_kernel_tids.drain(..) {
            kernel_tid.store(0, Ordering::SeqCst);
        }
        self.vcpu_tids.clear();
        // Recover the fds in vCPU-index order (each thread owns its own
        // channel, so `rxs[i]` always yields vCPU i's fd).
        for rx in self.vcpu_return_rxs.drain(..) {
            if let Ok(vcpu_fd) = rx.recv() {
                self.vcpu_fds.push(vcpu_fd);
            }
        }
        // Wait (bounded) for paused userspace workers to actually stop
        // touching guest memory. The virtio-blk worker drains in-flight
        // requests before parking, so after this returns every device-DMA
        // write is recorded in its dirty bitmap and memory captures
        // (snapshot dump, fork memcpy) see a quiescent image. No-op for
        // backends without userspace DMA workers.
        self.mmio_registry.lock().unwrap().wait_quiescent_all();
        Ok(())
    }

    /// Resume a paused VM by restarting the vCPU run loop.
    pub fn resume(&mut self) -> Result<(), VmError> {
        if self.running.load(Ordering::SeqCst) {
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
        self.start()?;
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

    /// All vCPU fds in vCPU-index order.
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

    /// Kernel TID of the running BSP (vCPU 0) thread, waiting up to
    /// `timeout` for the freshly spawned thread to publish it (storing
    /// the TID is the thread's first action, so the wait is
    /// microseconds in practice). `None` when the VM isn't running or
    /// the wait times out. internal notes
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
    /// wait times out. internal notes: the per-VM CPU cgroup must contain
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

    /// Send `SIGRTMIN` to every vCPU thread that has published its
    /// pthread id, breaking them out of a blocking `KVM_RUN`.
    fn signal_vcpu_threads(&self) {
        for tid in &self.vcpu_tids {
            let tid = tid.load(Ordering::SeqCst);
            if tid != 0 {
                // SAFETY: tid is a valid pthread_t stored by the vCPU
                // thread; SIGRTMIN has a registered no-op handler.
                unsafe {
                    libc::pthread_kill(tid as libc::pthread_t, libc::SIGRTMIN());
                }
            }
        }
    }

    /// Get a reference to the guest memory.
    #[must_use]
    pub fn guest_memory(&self) -> &GuestMemoryMmap {
        &self.guest_memory
    }

    /// Get the guest memory size in bytes.
    #[must_use]
    pub fn memory_size(&self) -> u64 {
        self.memory_size
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

    /// Get the guest vsock CID.
    #[must_use]
    pub fn guest_cid(&self) -> u64 {
        self.guest_cid
    }

    /// Check if the VM is currently running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
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

    /// Prepare this VM as a fork source.
    ///
    /// Performs the **one-time** cold snapshot + restore + dirty-tracking-enable
    /// sequence described in internal notes, the VM is "fork-ready":
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
    /// daemon's virtiofs sandbox pods, the 13a cluster-adopt path)
    /// call this first. No-op for share-less VMs.
    pub fn allow_slow_fork(&mut self) {
        if !self.virtiofs_shares.is_empty() {
            log::warn!(
                "allow_slow_fork: VM (cid {}) has {} virtiofs share(s) — forks will be \
                 full-memfd copies, not CoW",
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
        // internal notes: virtiofs shares force
        // every fork onto the slow full-memfd path (vhost-user needs
        // fd-backed shared memory — see the parent spec's "Why"). That
        // trade must be taken knowingly, never inherited silently.
        if !self.virtiofs_shares.is_empty() && !self.slow_fork_allowed {
            return Err(crate::fork::ForkError::VirtiofsSlowForkNotAllowed {
                shares: self.virtiofs_shares.len(),
            });
        }
        std::fs::create_dir_all(base_dir)?;

        self.snapshot(base_dir)
            .map_err(crate::fork::ForkError::Snapshot)?;
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
            return Ok(base_mem);
        }

        // Move the source's TAP into the restored VM so the host bridge link
        // survives the swap below. Without this, dropping the original `Vm`
        // would tear down the kernel-side TAP interface and break networking
        // for every subsequent warm fork.
        let tap = self.take_tap();

        // internal notes: the restored copy must keep the source's vsock
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

        // The old source was already shut down above (CID release);
        // dropping the swapped-out husk just unmaps its memory.
        std::mem::swap(self, &mut restored);
        drop(restored);

        self.fork_source_base_path = Some(base_mem.clone());
        Ok(base_mem)
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
    /// Re-registers slot 0 with `KVM_MEM_LOG_DIRTY_PAGES`. Allocates the
    /// `accumulated_dirty` bitmap. Idempotent: no-op if already enabled.
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

        let mem_region = kvm_bindings::kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: 0,
            memory_size: self.memory_size,
            userspace_addr: self.mem_host_addr(),
            flags: kvm_bindings::KVM_MEM_LOG_DIRTY_PAGES,
        };
        // SAFETY: userspace_addr points to the VM's existing memory mapping,
        // which is kept alive by self.guest_memory / self.cow_mmap_addr.
        unsafe {
            self.vm_fd
                .set_user_memory_region(mem_region)
                .map_err(VmError::SetUserMemoryRegion)?;
        }

        if was_running {
            self.resume()?;
        }

        // Bitmap: one bit per 4 KiB page. 256 MB / 4 KiB = 65 536 pages = 1024 u64s.
        let pages = self.memory_size.div_ceil(4096);
        let words = (pages as usize).div_ceil(64);
        self.accumulated_dirty = Some(vec![0u64; words]);
        self.dirty_tracking_enabled = true;
        log::info!("dirty tracking enabled ({pages} pages, {words} words)");
        Ok(())
    }

    /// Read the KVM dirty bitmap, OR it into the accumulated bitmap, and clear KVM's copy.
    ///
    /// Returns a reference to the accumulated bitmap (union of all pages dirtied
    /// since dirty tracking was enabled).
    pub fn get_and_accumulate_dirty(&mut self) -> Result<&[u64], VmError> {
        if !self.dirty_tracking_enabled {
            return Err(VmError::Pipe(std::io::Error::other(
                "dirty tracking not enabled",
            )));
        }

        let bitmap = self
            .vm_fd
            .get_dirty_log(0, self.memory_size as usize)
            .map_err(|e| VmError::Pipe(std::io::Error::other(format!("KVM_GET_DIRTY_LOG: {e}"))))?;

        let acc = self.accumulated_dirty.as_mut().expect("bitmap allocated");
        for (i, &w) in bitmap.iter().enumerate() {
            if i < acc.len() {
                acc[i] |= w;
            }
        }

        // Merge device-DMA dirty pages: KVM's log only sees vCPU writes, so
        // in-process device workers (virtio-blk) that write guest memory
        // through k7d's own mapping report their pages here. Without this,
        // warm forks on the base.mem + dirty-delta path would silently miss
        // read completions and used-ring updates (host-side #27 class).
        self.mmio_registry
            .lock()
            .unwrap()
            .merge_dirty_pages_all(acc);

        // Re-arm write protection. With MANUAL_DIRTY_LOG_PROTECT2, KVM_GET_DIRTY_LOG
        // no longer clears the bitmap — we must do it explicitly via KVM_CLEAR_DIRTY_LOG
        // so that subsequent guest writes are tracked again.
        clear_dirty_log(&self.vm_fd, 0, self.memory_size)?;

        Ok(acc.as_slice())
    }

    /// Path to the `base.mem` file this VM is fork-ready against, if any.
    #[must_use]
    pub fn fork_source_base_path(&self) -> Option<&Path> {
        self.fork_source_base_path.as_deref()
    }

    /// Warm fork: create a new VM from this source's `base.mem` plus the current
    /// dirty delta (memory-to-memory copy). No disk I/O during the hot path.
    ///
    /// The source must have been prepared via `prepare_fork_source()` first.
    ///
    /// Steps:
    /// 1. Pause source.
    /// 2. Read dirty bitmap, accumulate, save CPU+devices+IRQ state in memory.
    /// 3. Resume source immediately (steps 5–11 run while source is live).
    /// 4. mmap `base.mem` with `MAP_PRIVATE`, memcpy dirty pages from source.
    /// 5. Build a new KVM VM from the in-memory state.
    /// 6. Inject `TRANSPORT_RESET` into the **fork's** memory only.
    pub fn fork_warm(&mut self, fork_id: &str) -> Result<Self, crate::fork::ForkError> {
        let mut out = self.fork_warm_batch(&[fork_id])?;
        Ok(out.pop().expect("single fork"))
    }

    /// Batched warm fork: create N forks from the same paused moment.
    ///
    /// The source is paused once, the dirty bitmap captured once, CPU state
    /// saved once — then each fork is materialized independently.
    pub fn fork_warm_batch(
        &mut self,
        fork_ids: &[&str],
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

        // Capture dirty bitmap + CPU + device + IRQ state (all in-memory).
        let dirty_bitmap = self
            .get_and_accumulate_dirty()
            .map_err(crate::snapshot::SnapshotError::Vm)?
            .to_vec();
        let state = crate::snapshot::capture_vm_state(self)?;
        let source_mem_addr = self.mem_host_addr();

        // The source must stay paused during memcpy: if it resumes, it may write
        // to pages we're about to copy, making the fork's memory inconsistent
        // with its captured vCPU state. Per internal notes, memcpy time is
        // O(dirty_pages) — 0.5 µs/page, so ≤15 ms even at 100% dirty on 256 MB.
        let mut forks = Vec::with_capacity(fork_ids.len());
        let mut fork_err: Option<crate::fork::ForkError> = None;
        for &id in fork_ids {
            match crate::fork::restore_vm_from_state(
                &base_path,
                &dirty_bitmap,
                source_mem_addr,
                &state,
                id,
            ) {
                Ok(fork) => forks.push(fork),
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
        Ok(forks)
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
        self.running.store(false, Ordering::SeqCst);
        self.signal_vcpu_threads();
        for handle in self.vcpu_threads.drain(..) {
            let _ = handle.join();
        }
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
    running: &AtomicBool,
    vcpu_tx: mpsc::Sender<VcpuFd>,
) {
    let mut exit_count: u64 = 0;
    while running.load(Ordering::SeqCst) {
        match vcpu_fd.run() {
            Ok(exit) => {
                exit_count += 1;
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
                        }
                    }
                    VcpuExit::Hlt => {
                        log::info!("vCPU {cpu_index} halted after {exit_count} exits");
                        break;
                    }
                    VcpuExit::Shutdown => {
                        if let Ok(regs) = vcpu_fd.get_regs() {
                            log::error!(
                                "vCPU {cpu_index} shutdown (triple fault) after {exit_count} \
                                 exits: RIP={:#x} RSP={:#x}",
                                regs.rip,
                                regs.rsp,
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
    let _ = vcpu_tx.send(vcpu_fd);
}

/// Clear the KVM dirty log for a memory slot via the raw `KVM_CLEAR_DIRTY_LOG` ioctl.
///
/// `kvm-ioctls` 0.19.1 does not expose a safe wrapper for this ioctl. We call it
/// directly to re-arm write protection on tracked pages after reading the dirty
/// bitmap. Requires `KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2` (Linux 5.0+) to be enabled.
fn clear_dirty_log(vm_fd: &VmFd, slot: u32, memory_size: u64) -> Result<(), VmError> {
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
    // Pass an all-ones bitmap: clear every tracked page.
    let bitmap: Vec<u64> = vec![u64::MAX; words];
    let req = KvmClearDirtyLog {
        slot,
        num_pages,
        first_page: 0,
        dirty_bitmap: bitmap.as_ptr() as u64,
    };

    // SAFETY: vm_fd is valid; KvmClearDirtyLog matches the kernel's struct layout
    // and the bitmap points to `words * 8` bytes of valid memory.
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

/// Install a no-op signal handler for `SIGRTMIN`, used to interrupt `KVM_RUN`.
///
/// `KVM_RUN` blocks the vCPU thread (especially during HLT). To pause the VM,
/// we send `SIGRTMIN` via `pthread_kill`, which causes `KVM_RUN` to return
/// `EINTR`. The handler itself is a no-op — we just need the signal delivery.
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
            libc::sigaction(libc::SIGRTMIN(), &sa, std::ptr::null_mut());
        }
    });
}

/// Configure the "zero page" (`boot_params`) for the Linux boot protocol.
///
/// `mptable_reservation` is `Some((addr, size))` when an MP table was
/// written to guest memory — the region is
/// reported as E820-reserved so the guest never allocates over it.
/// `None` keeps the E820 map byte-identical to the pre-17a layout.
fn configure_boot_params(
    guest_memory: &GuestMemoryMmap,
    cmdline_addr: GuestAddress,
    cmdline_size: usize,
    mem_size: u64,
    initrd_config: Option<(GuestAddress, usize)>,
    mptable_reservation: Option<(u64, u64)>,
) -> Result<(), VmError> {
    let mut params = boot_params::default();

    params.hdr.type_of_loader = KERNEL_LOADER_OTHER;
    params.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
    params.hdr.header = KERNEL_HDR_MAGIC;
    params.hdr.cmd_line_ptr = cmdline_addr.raw_value() as u32;
    params.hdr.cmdline_size = cmdline_size as u32;
    params.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;
    // Protocol version 2.14+ supports initrd and other features
    params.hdr.version = 0x020e;

    if let Some((initrd_addr, initrd_size)) = initrd_config {
        let rd_img = initrd_addr.raw_value() as u32;
        let rd_sz = initrd_size as u32;
        params.hdr.ramdisk_image = rd_img;
        params.hdr.ramdisk_size = rd_sz;
    }

    // E820 memory map: report usable RAM
    // Entry 0: low memory [0, 0x9fc00) — conventional RAM below EBDA
    add_e820_entry(&mut params, 0, 0x9fc00, E820_RAM);
    // Reserve the MP table region (internal notes, multi-vCPU boots only —
    // it lives at 0x9fc00, just past usable low RAM, like Firecracker).
    if let Some((addr, size)) = mptable_reservation {
        add_e820_entry(&mut params, addr, size, E820_RESERVED);
    }
    // Entry 1: high memory [1MB, end of RAM)
    let high_mem_size = mem_size.saturating_sub(HIMEM_START);
    add_e820_entry(&mut params, HIMEM_START, high_mem_size, E820_RAM);

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
/// vCPU of a multi-vCPU guest (internal notes, following Firecracker's
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

    #[kani::proof]
    #[kani::unwind(2)]
    fn verify_initrd_placement_within_bounds() {
        let mem_mb: u64 = kani::any();
        kani::assume(mem_mb >= 64 && mem_mb <= 4096);
        let mem_size = mem_mb * 1024 * 1024;

        let initrd_size: u64 = kani::any();
        kani::assume(initrd_size > 0 && initrd_size < mem_size / 2);

        let initrd_addr_raw = (mem_size - initrd_size) & !0xFFF;

        assert!(
            initrd_addr_raw >= HIMEM_START,
            "initrd overlaps kernel area"
        );
        assert!(
            initrd_addr_raw + initrd_size <= mem_size,
            "initrd extends past guest memory"
        );
        assert!(initrd_addr_raw % 4096 == 0, "initrd not page-aligned");
    }

    #[kani::proof]
    fn verify_high_mem_no_underflow() {
        let mem_size: u64 = kani::any();
        kani::assume(mem_size >= 2 * 1024 * 1024);
        kani::assume(mem_size <= 64 * 1024 * 1024 * 1024);

        let high_mem_size = mem_size.saturating_sub(HIMEM_START);
        if mem_size > HIMEM_START {
            assert!(high_mem_size > 0);
            assert!(high_mem_size == mem_size - HIMEM_START);
        } else {
            assert!(high_mem_size == 0);
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
