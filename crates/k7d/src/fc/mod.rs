//! Firecracker backend: a microVM run by stock upstream Firecracker
//! under the stock jailer.
//!
//! k7d owns no guest memory and issues no KVM ioctl on this path. It
//! stages a chroot, runs the pinned `jailer`, drives the pinned
//! `firecracker` over its API socket, and talks to the same guest agent
//! over Firecracker's vsock UDS. What that buys — and what it costs —
//! matter; the short version is that a
//! guest→VMM escape lands in an unprivileged, chrooted, seccomp'd
//! process with one VM in it instead of in the daemon that owns the
//! node's whole fleet.
//!
//! It boots the same `config-minimal` kernel + busybox initramfs the
//! native backend boots, attaches disks and a TAP, and takes snapshot
//! points and forks ([`snapshot`]).

pub mod api;
pub mod snapshot;
pub mod spawn;
pub mod stage;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::api::AgentClient;
use crate::vsock::AGENT_VSOCK_PORT;

use self::api::FcApi;
use self::snapshot::{
    ForkSnapshot, MemoryBackend, NetworkOverride, SnapshotCreateParams, SnapshotLoadParams,
};
use self::stage::{Chroot, UidLease, SNAP_SUBDIR};

/// Guest kernel name inside the chroot.
pub const CHROOT_KERNEL_NAME: &str = "vmlinux";
/// Initramfs name inside the chroot.
pub const CHROOT_INITRD_NAME: &str = "initramfs.cpio.gz";
/// API socket path as Firecracker sees it (chroot-relative).
pub const CHROOT_API_SOCKET: &str = "/run/firecracker.socket";
/// vsock UDS path as Firecracker sees it (chroot-relative).
pub const CHROOT_VSOCK_UDS: &str = "/run/v.sock";

/// Firecracker's id for the VM's only network interface. The guest
/// sees it as `eth0`, the same name the native backend's virtio-net
/// device gets, so the agent's network configuration is unchanged.
pub const NET_IFACE_ID: &str = "eth0";

/// Render a MAC for Firecracker's `guest_mac` field.
#[must_use]
fn format_mac(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Guest-side vsock CID for every Firecracker VM.
///
/// Unlike the native backend's host-global `AF_VSOCK` CIDs, this one is
/// private to the microVM: the host does not reach the guest through
/// the vsock namespace at all, it connects to
/// `<chroot>/run/v.sock` and asks Firecracker to forward. So every FC
/// VM can use the same CID, and none of them collide with a native VM.
pub const FC_GUEST_CID: u32 = 3;

/// How long a stopped Firecracker process is given to disappear after
/// `SIGKILL` before k7d gives up and logs loudly.
const KILL_WAIT: Duration = Duration::from_secs(2);

/// Failures on the Firecracker path.
#[derive(Debug, thiserror::Error)]
pub enum FcError {
    /// Bad or missing configuration (env, binaries, paths).
    #[error("firecracker config: {message}")]
    Config {
        /// What is wrong and what to set.
        message: String,
    },
    /// Chroot staging failed.
    #[error("firecracker staging {path}: {message}")]
    Stage {
        /// Path involved.
        path: PathBuf,
        /// Underlying reason.
        message: String,
    },
    /// A disk and the chroot are on different filesystems, so it cannot
    /// be hard-linked into the jail.
    ///
    /// Only writable disks reach this: read-only artifacts cross the
    /// boundary through `stage::ro_cache_dir`, but a writable disk
    /// cannot be copied — the guest's writes have to land in the host's
    /// file, which means the same inode, which means one filesystem.
    #[error(
        "cannot hard-link {src} ({src_fs}) into {dst} ({dst_fs}): a hard link cannot \
         cross filesystems, and a writable disk cannot be copied in without the \
         guest's writes being thrown away with the jail — put the jailer chroot base \
         on the same filesystem as {src_fs} (`disks::ensure_reflink_fc_root`, or \
         K7D_FC_CHROOT_BASE)"
    )]
    CrossFilesystem {
        /// Disk image that could not be linked in.
        src: PathBuf,
        /// Filesystem holding it.
        src_fs: String,
        /// Chroot directory.
        dst: PathBuf,
        /// Filesystem holding it.
        dst_fs: String,
    },
    /// Every uid in the configured range is in use.
    #[error("no free Firecracker uid in [{base}, {base}+{count}) — too many live FC VMs")]
    UidsExhausted {
        /// `K7D_FC_UID_BASE`.
        base: u32,
        /// Range size.
        count: u32,
    },
    /// The jailer could not be started, or exited non-zero.
    #[error("jailer: {message}")]
    Spawn {
        /// Reason, including the jailer's stderr when it produced any.
        message: String,
    },
    /// Firecracker never bound its API socket.
    #[error("firecracker API socket {path} did not accept within {timeout:?}")]
    SocketTimeout {
        /// Socket we waited on.
        path: PathBuf,
        /// How long we waited.
        timeout: Duration,
    },
    /// A Firecracker API call failed.
    #[error("firecracker {method} {uri}: {message}")]
    Api {
        /// HTTP method.
        method: &'static str,
        /// Request URI.
        uri: String,
        /// Firecracker's `fault_message`, or a transport failure.
        message: String,
    },
    /// Talking to the guest agent over the vsock UDS failed.
    #[error("firecracker agent at {path}: {message}")]
    Agent {
        /// vsock UDS path.
        path: PathBuf,
        /// Reason.
        message: String,
    },
}

/// What a Firecracker VM is created from.
#[derive(Debug, Clone)]
pub struct FcConfig {
    /// VM identity (jailer `--id`, chroot leaf, cgroup leaf).
    pub vm_id: String,
    /// Guest RAM in MiB.
    pub memory_mb: u64,
    /// vCPU count.
    pub vcpus: u32,
    /// Host path of the guest kernel (the daemon's `K7D_KERNEL`).
    pub kernel: PathBuf,
    /// Host path of the initramfs (the daemon's `K7D_INITRD`).
    pub initrd: Option<PathBuf>,
    /// Kernel command line. Firecracker appends its own
    /// `virtio_mmio.device=` tokens.
    pub cmdline: String,
    /// Pod CFS quota (µs), applied as the cgroup's `cpu.max`.
    pub cpu_quota_us: Option<u64>,
    /// Pod CFS period (µs).
    pub cpu_period_us: Option<u64>,
    /// Block devices **in guest device order**: entry `i` is the
    /// guest's `/dev/vd{a+i}`. The caller (`control::create_vm`) builds
    /// this in exactly the order the native backend attaches them, so
    /// the `/dev/vdX` names a shim computed from `block_devices`
    /// positions mean the same thing on both backends.
    pub drives: Vec<FcDrive>,
    /// virtio-net device, when the VM joins a cluster bridge.
    pub net: Option<FcNet>,
    /// KVM dirty-page logging (`PUT /machine-config track_dirty_pages`).
    /// On for every VM that can become a fork source — a tree member —
    /// so its Diff snapshots are exactly the pages written since the
    /// last point. Off for a pod VM: nothing forks it, and the
    /// logging costs a write fault per first touch of every page.
    pub track_dirty_pages: bool,
}

/// One block device to hand Firecracker.
#[derive(Debug, Clone)]
pub struct FcDrive {
    /// File name inside the chroot's `img/` or `disk/` directory.
    pub name: String,
    /// Host path of the backing file, linked into the chroot at stage.
    pub host_path: PathBuf,
    /// Read-only images (erofs rootfs, image slots) vs writable disks
    /// (scratch, container scratch, data, docker graph).
    pub read_only: bool,
}

/// The virtio-net device of a Firecracker VM.
#[derive(Debug, Clone)]
pub struct FcNet {
    /// Host TAP interface name, already up on the cluster bridge and
    /// released by k7d ([`crate::network::TapDevice::detach_for_vmm`]).
    pub host_dev_name: String,
    /// MAC the guest sees — the bridge allocator's, so the guest's L2
    /// identity does not depend on which VMM booted it.
    pub guest_mac: [u8; 6],
}

/// A writable disk handed to a Firecracker VM, kept alive by the
/// [`FcVm`] so the image outlives the guest that is writing to it.
///
/// The native backend parks these in the `Vm` for the same reason.
/// Which one it is decides what happens at teardown, and that is the
/// type's own business: a [`crate::disks::ScratchDisk`] unlinks its
/// image on drop, a [`crate::disks::DataDisk`] deliberately does not.
#[derive(Debug)]
pub enum FcDisk {
    /// Sandbox, per-container or Docker-graph scratch: dropped with
    /// the VM.
    Scratch(crate::disks::ScratchDisk),
    /// Named persistent disk: outlives the VM.
    Data(crate::disks::DataDisk),
}

/// A snapshot point of a live [`FcVm`]: what a child or a rollback loads.
///
/// Only the latest point is kept. The tree API rolls back to "the
/// node's restore point", singular, and a child already loaded from an
/// older point holds its own reflink of it — so an older point's files
/// would keep only extents nothing else references.
#[derive(Debug)]
struct Point {
    index: u32,
    /// `<vm_dir>/snap/vmstate-N`, root-owned, `0444`.
    vmstate: PathBuf,
    /// `<vm_dir>/snap/restore-N.mem`, a reflink of `base.mem`.
    restore_mem: PathBuf,
    /// `(drive index, <vm_dir>/snap/disk-N-<name>)` for every writable
    /// drive — reflinked at the same pause as the memory, so a child's
    /// disk and memory are from one instant.
    disks: Vec<(usize, PathBuf)>,
    /// Data bytes of the Diff that produced this point.
    diff_bytes: u64,
}

/// On-disk record of a suspended Firecracker VM.
///
/// Written next to `vmstate` + `memory.bin` so resume can re-stage a
/// jail without keeping the original chroot. Read-only drive paths are
/// the originals (kernel, erofs); writable ones are reflinks of the
/// point's disk clones, taken at the same pause as the Full snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspendMeta {
    /// Guest RAM in MiB.
    pub memory_mb: u64,
    /// vCPU count.
    pub vcpus: u32,
    /// Host kernel path.
    pub kernel: PathBuf,
    /// Host initrd path.
    pub initrd: Option<PathBuf>,
    /// Boot args the guest was created with.
    pub cmdline: String,
    /// Pod CFS quota (µs).
    pub cpu_quota_us: Option<u64>,
    /// Pod CFS period (µs).
    pub cpu_period_us: Option<u64>,
    /// Always `true` on resume: a restored VM must be able to become a
    /// fork source.
    pub track_dirty_pages: bool,
    /// Drives in guest device order.
    pub drives: Vec<SuspendDrive>,
    /// Guest MAC when the VM had a TAP.
    #[serde(default)]
    pub guest_mac: Option<[u8; 6]>,
}

/// One drive in [`SuspendMeta`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspendDrive {
    /// File name inside the chroot's `img/` or `disk/` directory.
    pub name: String,
    /// Host path to link or reflink from on resume.
    pub host_path: PathBuf,
    /// Read-only (erofs / slots) vs writable (scratch, data).
    pub read_only: bool,
}

/// Filename of [`SuspendMeta`] in a suspend / member directory.
pub const SUSPEND_META: &str = "fc.json";

/// Logical bytes of an exported Full snapshot in `dir` (`vmstate`,
/// `memory.bin`, [`SUSPEND_META`], `disk-*`). Suspended-node disk
/// accounting; the live path uses Diff extent sizes instead.
#[must_use]
pub fn exported_snapshot_bytes(dir: &Path) -> u64 {
    let mut n = 0u64;
    for name in ["vmstate", "memory.bin", SUSPEND_META] {
        if let Ok(md) = std::fs::metadata(dir.join(name)) {
            n = n.saturating_add(md.len());
        }
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return n;
    };
    for e in rd.flatten() {
        let name = e.file_name();
        if name.to_string_lossy().starts_with("disk-") {
            if let Ok(md) = e.metadata() {
                n = n.saturating_add(md.len());
            }
        }
    }
    n
}

/// What [`FcVm::prepare_fork_source`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointReport {
    /// `false` when the Diff was empty and the existing point stands.
    pub wrote: bool,
    /// `true` when the point was built by applying a Diff onto an
    /// existing `base.mem` (or a seed from `load.mem`) rather than by
    /// adopting a complete image.
    pub incremental: bool,
    /// Data bytes of the Diff (guest RAM in `full` mode).
    pub diff_bytes: u64,
    /// The point's `restore-N.mem`.
    pub restore_mem: PathBuf,
}

/// Mint a daemon-unique id for a fork child.
///
/// Not derived from the label: the jailer takes the id as a path leaf
/// and a cgroup name, so it must be unique across every live FC VM of
/// this daemon and short enough to nest.
fn child_vm_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!(
        "fcf-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    )
}

/// Drive id of the `index`-th block device, i.e. the guest's
/// `/dev/vd{a+index}`.
///
/// Positional and not a name, because that is the only identity the
/// shim has: it computes `/dev/vdX` from a device's position in
/// `VmConfig.block_devices` long before the daemon has staged anything,
/// and the image-slot late fill has to be able to name the drive it
/// filled from that alone.
#[must_use]
pub fn drive_id(index: usize) -> String {
    format!("d{index}")
}

/// A live (or paused) Firecracker microVM.
///
/// Dropping it kills the jailed process, removes the chroot, removes
/// the cgroup, and releases the uid — in that order, which is why the
/// `Drop` body is explicit rather than left to field order.
#[derive(Debug)]
pub struct FcVm {
    vm_id: String,
    pid: u32,
    api: FcApi,
    agent_uds: PathBuf,
    cgroup_dir: PathBuf,
    paused: bool,
    /// What this VM was created from. `config.drives` is **live**: index
    /// `i` is the guest's `/dev/vd{a+i}`, and a late fill
    /// ([`Self::update_drive`]) or a fork ([`Self::fork_batch`], which
    /// repoints a child's writable drives at its own clones) updates it
    /// in place. A child is created from a clone of its parent's.
    config: FcConfig,
    /// Per-drive counter of late fills, so each `PATCH /drives` gets a
    /// file name Firecracker has not already opened.
    fills: u32,
    /// The latest snapshot point, if one was taken.
    point: Option<Point>,
    /// Points taken so far; names the next one.
    points_taken: u32,
    /// `load.mem` this VM was `LoadSnapshot`ed from, when it was. Its
    /// first point seeds `base.mem` from this file; a VM booted from
    /// scratch seeds it from its first Diff, which is complete.
    loaded_from: Option<PathBuf>,
    /// Dropped after the process is dead: removing a chroot out from
    /// under a running Firecracker would leave it with open fds to
    /// unlinked files and no way to see that had happened.
    chroot: Chroot,
    /// Dropped after the chroot, so the hard links into the jail are
    /// gone before a `ScratchDisk` unlinks the image they pointed at.
    disks: Vec<FcDisk>,
    /// The VM's TAP, deleted when this drops. k7d released the
    /// descriptor to Firecracker but still owns the device.
    tap: Option<crate::network::TapDevice>,
    /// Released last, so a uid is never handed to a second VM while the
    /// first one's process still exists.
    uid: UidLease,
}

impl FcVm {
    /// Stage, spawn and configure a microVM. The guest is **not**
    /// running yet — [`FcVm::start`] issues `InstanceStart`.
    ///
    /// `tap` is the device `config.net` names, taken by value because
    /// handing it to Firecracker is destructive: the VM's uid is only
    /// known here, and the TAP has to be given to that uid and released
    /// before Firecracker's `PUT /network-interfaces` opens it. From
    /// then on k7d owns the device but not its descriptor, and the
    /// [`FcVm`] holds it so a failed boot deletes it.
    pub fn create(
        config: &FcConfig,
        tap: Option<crate::network::TapDevice>,
    ) -> Result<Self, FcError> {
        let mut vm = Self::spawn_unconfigured(config, tap)?;
        // From here on every failure must go through `vm`'s Drop, so
        // configuration errors tear the process and chroot down instead
        // of leaking a jailed Firecracker with no owner.
        vm.configure(config)?;
        Ok(vm)
    }

    /// Stage the chroot and start the jailed VMM with nothing configured
    /// — the state both a boot ([`Self::configure`]) and a
    /// `LoadSnapshot` ([`Self::spawn_child`]) start from.
    fn spawn_unconfigured(
        config: &FcConfig,
        tap: Option<crate::network::TapDevice>,
    ) -> Result<Self, FcError> {
        let fc_binary = binary_from_env("K7D_FC_BINARY", "/usr/local/bin/firecracker")?;
        let jailer_binary = binary_from_env("K7D_FC_JAILER", "/usr/local/bin/jailer")?;
        let exec_name = spawn::exec_file_name(&fc_binary)?;
        let base = stage::chroot_base();
        std::fs::create_dir_all(&base).map_err(|e| FcError::Stage {
            path: base.clone(),
            message: format!("create jailer chroot base: {e}"),
        })?;

        let uid = UidLease::acquire()?;
        let chroot = stage::stage(
            &base,
            &exec_name,
            &config.vm_id,
            &config.kernel,
            config.initrd.as_deref(),
            uid.uid(),
        )?;

        let spawned = spawn::spawn(
            &spawn::JailerArgs {
                vm_id: &config.vm_id,
                exec_file: &fc_binary,
                jailer: &jailer_binary,
                chroot_base: &base,
                uid: uid.uid(),
                memory_mb: config.memory_mb,
                cpu_quota_us: config.cpu_quota_us,
                cpu_period_us: config.cpu_period_us,
            },
            &chroot,
        )?;

        Ok(Self {
            vm_id: config.vm_id.clone(),
            pid: spawned.pid,
            api: FcApi::new(&chroot.api_socket()),
            agent_uds: chroot.vsock_uds(),
            cgroup_dir: spawned.cgroup_dir,
            paused: false,
            config: config.clone(),
            fills: 0,
            point: None,
            points_taken: 0,
            loaded_from: None,
            chroot,
            disks: Vec::new(),
            tap,
            uid,
        })
    }

    fn configure(&mut self, config: &FcConfig) -> Result<(), FcError> {
        self.api.put_machine_config(&api::MachineConfig {
            vcpu_count: config.vcpus,
            mem_size_mib: config.memory_mb,
            track_dirty_pages: config.track_dirty_pages,
        })?;
        self.api.put_boot_source(&api::BootSource {
            kernel_image_path: format!("/{CHROOT_KERNEL_NAME}"),
            initrd_path: config
                .initrd
                .as_ref()
                .map(|_| format!("/{CHROOT_INITRD_NAME}")),
            boot_args: config.cmdline.clone(),
        })?;
        self.api.put_vsock(&api::VsockDevice {
            guest_cid: FC_GUEST_CID,
            uds_path: CHROOT_VSOCK_UDS.to_string(),
        })?;
        // Declared in `config.drives` order, which is guest device
        // order: Firecracker hands the guest one virtio-mmio device per
        // drive in the order it received them, and the guest kernel
        // names them `/dev/vda`, `/dev/vdb`, … in that order.
        for (index, drive) in config.drives.iter().enumerate() {
            let path_on_host = if drive.read_only {
                self.chroot.link_read_only(&drive.name, &drive.host_path)?
            } else {
                self.chroot.link_read_write(&drive.name, &drive.host_path)?
            };
            self.api.put_drive(&api::Drive {
                drive_id: drive_id(index),
                path_on_host,
                is_root_device: false,
                is_read_only: drive.read_only,
                cache_type: api::CACHE_TYPE_UNSAFE,
                io_engine: api::IO_ENGINE_SYNC,
            })?;
        }
        if let Some(ref net) = config.net {
            // Hand the device over before Firecracker asks for it.
            // `PUT /network-interfaces` opens the TAP immediately, as
            // the jailed uid: without TUNSETOWNER that `TUNSETIFF` is
            // EPERM (no CAP_NET_ADMIN in the jail), and with k7d still
            // holding the single-queue fd it would be EBUSY.
            let uid = self.uid.uid();
            if let Some(ref mut tap) = self.tap {
                tap.detach_for_vmm(uid).map_err(|e| FcError::Config {
                    message: format!("release TAP {} to Firecracker: {e}", tap.name()),
                })?;
            }
            self.api.put_network_interface(&api::NetworkInterface {
                iface_id: NET_IFACE_ID.to_string(),
                host_dev_name: net.host_dev_name.clone(),
                guest_mac: format_mac(net.guest_mac),
            })?;
        }
        Ok(())
    }

    /// Take ownership of the writable disks attached to this VM, so
    /// their images live exactly as long as the guest writing to them.
    pub fn adopt_disks(&mut self, disks: Vec<FcDisk>) {
        self.disks.extend(disks);
    }

    /// The VM's TAP, when it has one.
    #[must_use]
    pub fn tap(&self) -> Option<&crate::network::TapDevice> {
        self.tap.as_ref()
    }

    /// Repoint the `index`-th block device at `host_path` on the
    /// running VM (`PATCH /drives`).
    ///
    /// This is how a post-boot image reaches a Firecracker guest. The
    /// native backend fills the slot's backing file in place through
    /// the fd its block backend opened at boot; k7d cannot reach into
    /// another process's fd table, and Firecracker's answer is to
    /// re-open a path instead. Read-only by construction: the drive
    /// being repointed is an image slot, and a writable disk whose
    /// backing file changed underneath a running guest would be a
    /// corrupt filesystem, not a feature.
    pub fn update_drive(&mut self, index: usize, host_path: &Path) -> Result<(), FcError> {
        let drive = self
            .config
            .drives
            .get(index)
            .ok_or_else(|| FcError::Config {
                message: format!(
                    "no drive at index {index} on VM {} (it has {})",
                    self.vm_id,
                    self.config.drives.len()
                ),
            })?;
        if !drive.read_only {
            return Err(FcError::Config {
                message: format!(
                    "drive {} of VM {} is writable — repointing it under a running \
                     guest would leave the guest's page cache describing a filesystem \
                     that is no longer there",
                    drive_id(index),
                    self.vm_id
                ),
            });
        }
        // A fresh name every time: Firecracker still holds the previous
        // file open until the PATCH lands, and linking onto a path it
        // has open would swap the bytes under it.
        self.fills += 1;
        let name = format!("{}-fill{}", drive_id(index), self.fills);
        let staged = self.chroot.link_read_only(&name, host_path)?;
        self.api.patch_drive(&drive_id(index), &staged)?;
        let previous = std::mem::replace(
            &mut self.config.drives[index],
            FcDrive {
                name,
                host_path: host_path.to_path_buf(),
                read_only: true,
            },
        );
        // The guest is now reading the new file; the old link is dead
        // weight (an empty slot backing file, or a previous fill).
        let stale = self
            .chroot
            .root()
            .join(stage::IMG_SUBDIR)
            .join(previous.name);
        if let Err(e) = std::fs::remove_file(&stale) {
            log::warn!("fc: remove stale drive link {}: {e}", stale.display());
        }
        Ok(())
    }

    /// Number of block devices declared on this VM.
    #[must_use]
    pub fn drive_count(&self) -> usize {
        self.config.drives.len()
    }

    /// Named persistent data disks attached to this VM, in declaration
    /// order. Scratch / docker-graph images are not included.
    #[must_use]
    pub fn data_disks(&self) -> Vec<&crate::disks::DataDisk> {
        self.disks
            .iter()
            .filter_map(|d| match d {
                FcDisk::Data(d) => Some(d),
                FcDisk::Scratch(_) => None,
            })
            .collect()
    }

    /// Console text Firecracker (and the jailer) wrote to
    /// [`spawn::STDERR_FILE`]. An empty file is a successful empty dump.
    pub fn serial_output(&self) -> Result<String, FcError> {
        let path = self.chroot.root().join(spawn::STDERR_FILE);
        match std::fs::read(&path) {
            Ok(bytes) => Ok(String::from_utf8_lossy(&bytes).into_owned()),
            Err(e) => Err(FcError::Stage {
                path,
                message: format!("read serial: {e}"),
            }),
        }
    }

    /// Host path currently backing the `index`-th block device.
    #[must_use]
    pub fn drive_host_path(&self, index: usize) -> Option<&Path> {
        self.config.drives.get(index).map(|d| d.host_path.as_path())
    }

    /// Boot the guest (`PUT /actions InstanceStart`).
    pub fn start(&mut self) -> Result<(), FcError> {
        self.api.instance_start()?;
        self.paused = false;
        Ok(())
    }

    /// Pause the guest (`PATCH /vm {state: Paused}`).
    pub fn pause(&mut self) -> Result<(), FcError> {
        self.api.set_vm_state("Paused")?;
        self.paused = true;
        Ok(())
    }

    /// Resume a paused guest (`PATCH /vm {state: Resumed}`).
    pub fn resume(&mut self) -> Result<(), FcError> {
        self.api.set_vm_state("Resumed")?;
        self.paused = false;
        Ok(())
    }

    /// Whether the last state change was a pause.
    #[must_use]
    pub fn paused(&self) -> bool {
        self.paused
    }

    /// Whether the VMM process is alive and reports a running instance.
    #[must_use]
    pub fn is_running(&self) -> bool {
        if !process_alive(self.pid) {
            return false;
        }
        self.api
            .instance_info()
            .is_ok_and(|info| info.state == "Running")
    }

    /// Kill the VMM. Idempotent; the chroot and uid survive until drop.
    pub fn stop(&mut self) {
        kill_and_wait(self.pid);
    }

    /// Guest RAM in MiB.
    #[must_use]
    pub fn memory_mb(&self) -> u64 {
        self.config.memory_mb
    }

    /// vCPU count.
    #[must_use]
    pub fn vcpu_count(&self) -> u32 {
        self.config.vcpus
    }

    /// Host pid of the jailed Firecracker process.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// VM identity.
    #[must_use]
    pub fn vm_id(&self) -> &str {
        &self.vm_id
    }

    /// Host path of the vsock UDS the agent is reached through.
    #[must_use]
    pub fn agent_uds(&self) -> &Path {
        &self.agent_uds
    }

    /// Chroot Firecracker sees as `/`.
    #[must_use]
    pub fn chroot_root(&self) -> &Path {
        self.chroot.root()
    }

    /// Unprivileged uid (and gid) the jailer dropped Firecracker to.
    #[must_use]
    pub fn uid(&self) -> u32 {
        self.uid.uid()
    }

    /// cgroup v2 directory the jailer put the process in.
    #[must_use]
    pub fn cgroup_dir(&self) -> &Path {
        &self.cgroup_dir
    }

    /// Connect to the guest agent through Firecracker's vsock UDS.
    pub fn connect_agent(&self, timeout: Duration) -> Result<AgentClient, FcError> {
        AgentClient::connect_fc_uds(&self.agent_uds, AGENT_VSOCK_PORT, timeout).map_err(|e| {
            FcError::Agent {
                path: self.agent_uds.clone(),
                message: e.to_string(),
            }
        })
    }

    /// Non-reclaimable private RAM of the VMM process, in bytes.
    ///
    /// `Private_Dirty` from `smaps_rollup` — the figure we pick
    /// for FC tree-budget accounting, since k7d has no dirty bitmap of
    /// its own on this path.
    #[must_use]
    pub fn private_dirty_bytes(&self) -> u64 {
        let Ok(text) = std::fs::read_to_string(format!("/proc/{}/smaps_rollup", self.pid)) else {
            return 0;
        };
        text.lines()
            .find_map(|l| l.strip_prefix("Private_Dirty:"))
            .and_then(|v| v.split_whitespace().next())
            .and_then(|kb| kb.parse::<u64>().ok())
            .map_or(0, |kb| kb * 1024)
    }

    // --- Snapshot points and forks ---

    /// Take a snapshot point in the configured [`ForkSnapshot`] mode:
    /// pause → `PUT /snapshot/create` → materialise `base.mem` →
    /// `restore-N.mem` = `FICLONE(base.mem)` → clone the writable disks
    /// → resume. What children and rollbacks load from.
    ///
    /// Idempotent in the only sense that matters: a `Diff` that turns
    /// out empty (nothing dirtied since the last point) leaves the
    /// existing point in place and reports `wrote: false`.
    pub fn prepare_fork_source(&mut self) -> Result<PointReport, FcError> {
        let mode = snapshot::fork_mode()?;
        self.take_point(mode)
    }

    /// `restore-N.mem` of the current point, if one was taken.
    #[must_use]
    pub fn restore_mem(&self) -> Option<&Path> {
        self.point.as_ref().map(|p| p.restore_mem.as_path())
    }

    /// The `load.mem` this VM was `LoadSnapshot`ed from — k7d's own
    /// reflink of it, outside the jail.
    #[must_use]
    pub fn load_mem(&self) -> Option<&Path> {
        self.loaded_from.as_deref()
    }

    /// Data bytes of the Diff behind the current point (what a point
    /// is booked at); 0 without a point.
    #[must_use]
    pub fn point_diff_bytes(&self) -> u64 {
        self.point.as_ref().map_or(0, |p| p.diff_bytes)
    }

    /// Whether this VM's memory is copy-on-write of the file it was
    /// loaded from: every allocated extent of its `load.mem` is shared
    /// (`FIEMAP_EXTENT_SHARED`) with the parent's restore point. A VM
    /// booted from scratch has no `load.mem` and reports `false`.
    pub fn fork_memory_cow(&self) -> Result<bool, FcError> {
        match &self.loaded_from {
            Some(load) => snapshot::is_cow(load),
            None => Ok(false),
        }
    }

    /// Fork `count` children from this VM's state **now**: take a point
    /// (a no-op when nothing was dirtied), then load one child per
    /// slot from it. Children are running when this returns; their
    /// agent has yet to be reached.
    ///
    /// Children of a networked parent need their own TAPs
    /// (`network_overrides`); single-VM trees are unbridged, so this
    /// entry point takes none and refuses a networked parent loudly.
    pub fn fork_batch(&mut self, count: usize) -> Result<(PointReport, Vec<FcVm>), FcError> {
        let report = self.prepare_fork_source()?;
        let mut children = Vec::with_capacity(count);
        for _ in 0..count {
            children.push(self.spawn_child(None)?);
        }
        Ok((report, children))
    }

    /// A child of the **current point** — the state as of the last
    /// [`Self::prepare_fork_source`], not as of now. The source is not
    /// paused or snapshotted; it may have diverged arbitrarily since.
    /// Takes a point first only when there is none yet.
    pub fn rollback_child(&mut self) -> Result<FcVm, FcError> {
        if self.point.is_none() {
            self.prepare_fork_source()?;
        }
        self.spawn_child(None)
    }

    /// Full snapshot of this VM into `dir`: `vmstate`, `memory.bin`,
    /// writable-disk clones, and [`SUSPEND_META`] (suspend-to-disk).
    ///
    /// Goes through a **Full** point rather than a side `PUT
    /// /snapshot/create`: a Full snapshot resets Firecracker's dirty
    /// bitmap, so a later Diff would describe "since this snapshot"
    /// while `base.mem` still said "as of the last point". Making the
    /// Full dump *be* the new point keeps the two in step.
    pub fn snapshot(&mut self, dir: &Path) -> Result<(), FcError> {
        self.take_point(ForkSnapshot::Full)?;
        self.export_point(dir)
    }

    /// Write the current point into `dir` without taking another
    /// snapshot. [`Self::snapshot`] calls this after a Full point;
    /// cluster fork does not — children load from the live point.
    pub fn export_point(&self, dir: &Path) -> Result<(), FcError> {
        let point = self.point.as_ref().ok_or_else(|| FcError::Config {
            message: format!("VM {} has no point to export", self.vm_id),
        })?;
        std::fs::create_dir_all(dir).map_err(|e| FcError::Stage {
            path: dir.to_path_buf(),
            message: format!("create snapshot dir: {e}"),
        })?;
        let vmstate_dst = dir.join("vmstate");
        let _ = std::fs::remove_file(&vmstate_dst);
        std::fs::copy(&point.vmstate, &vmstate_dst).map_err(|e| FcError::Stage {
            path: vmstate_dst,
            message: format!("copy vmstate: {e}"),
        })?;
        let mem = dir.join("memory.bin");
        let _ = std::fs::remove_file(&mem);
        if let Err(reflink_err) = snapshot::reflink(&point.restore_mem, &mem, 0o600) {
            // `dir` is the caller's and may be on another filesystem;
            // a suspend-to-disk is O(guest RAM) anyway on the native
            // backend, so a byte copy here is the documented cost and
            // not a fallback that hides one.
            log::warn!(
                "fc: {reflink_err}; copying {} to {} instead",
                point.restore_mem.display(),
                mem.display()
            );
            std::fs::copy(&point.restore_mem, &mem).map_err(|e| FcError::Stage {
                path: mem.clone(),
                message: format!("copy memory: {e}"),
            })?;
        }
        let mut drives = Vec::with_capacity(self.config.drives.len());
        for (index, drive) in self.config.drives.iter().enumerate() {
            if drive.read_only {
                drives.push(SuspendDrive {
                    name: drive.name.clone(),
                    host_path: drive.host_path.clone(),
                    read_only: true,
                });
                continue;
            }
            let (_, clone) = point
                .disks
                .iter()
                .find(|(i, _)| *i == index)
                .ok_or_else(|| FcError::Config {
                    message: format!(
                        "point {} has no disk clone for writable drive {}",
                        point.index,
                        drive_id(index)
                    ),
                })?;
            let dst = dir.join(format!("disk-{}", drive.name));
            let _ = std::fs::remove_file(&dst);
            snapshot::reflink(clone, &dst, 0o600)?;
            drives.push(SuspendDrive {
                name: drive.name.clone(),
                host_path: dst,
                read_only: false,
            });
        }
        let meta = SuspendMeta {
            memory_mb: self.config.memory_mb,
            vcpus: self.config.vcpus,
            kernel: self.config.kernel.clone(),
            initrd: self.config.initrd.clone(),
            cmdline: self.config.cmdline.clone(),
            cpu_quota_us: self.config.cpu_quota_us,
            cpu_period_us: self.config.cpu_period_us,
            track_dirty_pages: true,
            drives,
            guest_mac: self.config.net.as_ref().map(|n| n.guest_mac),
        };
        let meta_path = dir.join(SUSPEND_META);
        let json = serde_json::to_vec_pretty(&meta).map_err(|e| FcError::Stage {
            path: meta_path.clone(),
            message: format!("serialize {SUSPEND_META}: {e}"),
        })?;
        std::fs::write(&meta_path, json).map_err(|e| FcError::Stage {
            path: meta_path,
            message: format!("write {SUSPEND_META}: {e}"),
        })?;
        Ok(())
    }

    /// Re-stage a jail and `LoadSnapshot` from a directory produced by
    /// [`Self::snapshot`].
    ///
    /// `tap` is the VM's TAP on the (possibly recreated) bridge; the
    /// guest MAC in the snapshot is kept so L2 identity survives.
    pub fn load_exported(
        dir: &Path,
        tap: Option<crate::network::TapDevice>,
    ) -> Result<Self, FcError> {
        let meta_path = dir.join(SUSPEND_META);
        let bytes = std::fs::read(&meta_path).map_err(|e| FcError::Stage {
            path: meta_path.clone(),
            message: format!("read {SUSPEND_META}: {e}"),
        })?;
        let meta: SuspendMeta = serde_json::from_slice(&bytes).map_err(|e| FcError::Stage {
            path: meta_path,
            message: format!("parse {SUSPEND_META}: {e}"),
        })?;
        let net = match (&tap, &meta.guest_mac) {
            (Some(tap), Some(mac)) => Some(FcNet {
                host_dev_name: tap.name().to_string(),
                guest_mac: *mac,
            }),
            (Some(tap), None) => Some(FcNet {
                host_dev_name: tap.name().to_string(),
                guest_mac: tap.mac(),
            }),
            (None, Some(_)) => {
                return Err(FcError::Config {
                    message: format!(
                        "exported VM in {} had a network interface; resume needs a TAP",
                        dir.display()
                    ),
                })
            }
            (None, None) => None,
        };
        let config = FcConfig {
            vm_id: child_vm_id(),
            memory_mb: meta.memory_mb,
            vcpus: meta.vcpus,
            kernel: meta.kernel,
            initrd: meta.initrd,
            cmdline: meta.cmdline,
            cpu_quota_us: meta.cpu_quota_us,
            cpu_period_us: meta.cpu_period_us,
            drives: meta
                .drives
                .iter()
                .map(|d| FcDrive {
                    name: d.name.clone(),
                    host_path: d.host_path.clone(),
                    read_only: d.read_only,
                })
                .collect(),
            net,
            track_dirty_pages: true,
        };
        let mut disks = Vec::new();
        for (index, drive) in config.drives.iter().enumerate() {
            if drive.read_only {
                continue;
            }
            disks.push((index, drive.host_path.clone()));
        }
        let point = Point {
            index: 0,
            vmstate: dir.join("vmstate"),
            restore_mem: dir.join("memory.bin"),
            disks,
            diff_bytes: 0,
        };
        Self::spawn_from_point(&point, config, tap, 0)
    }

    /// Pause, take the point, resume — resuming even when the point
    /// failed, so a broken snapshot does not leave the source hung.
    fn take_point(&mut self, mode: ForkSnapshot) -> Result<PointReport, FcError> {
        let was_paused = self.paused;
        if !was_paused {
            self.pause()?;
        }
        let result = self.take_point_paused(mode);
        let resumed = if was_paused { Ok(()) } else { self.resume() };
        let report = result?;
        resumed?;
        Ok(report)
    }

    #[allow(clippy::too_many_lines)]
    fn take_point_paused(&mut self, mode: ForkSnapshot) -> Result<PointReport, FcError> {
        let n = self.points_taken + 1;
        let jail = self.chroot.jail_snap_dir();
        let own = self.chroot.snap_dir();
        let jail_vmstate = jail.join(format!("vmstate-{n}"));
        let jail_mem = jail.join(format!("diff-{n}.mem"));
        let t0 = Instant::now();
        self.api.create_snapshot(&SnapshotCreateParams {
            snapshot_type: mode.api_name(),
            snapshot_path: format!("/{SNAP_SUBDIR}/vmstate-{n}"),
            mem_file_path: format!("/{SNAP_SUBDIR}/diff-{n}.mem"),
        })?;
        let t_create = t0.elapsed();

        let bytes = match mode {
            ForkSnapshot::Diff => snapshot::diff_bytes(&jail_mem)?,
            ForkSnapshot::Full => self.config.memory_mb * 1024 * 1024,
        };
        if mode == ForkSnapshot::Diff && bytes == 0 {
            if let Some(point) = &self.point {
                // Nothing dirtied since the last point: it still
                // describes this VM exactly. Nothing to materialise.
                let _ = std::fs::remove_file(&jail_vmstate);
                let _ = std::fs::remove_file(&jail_mem);
                log::info!(
                    "fc: {} point {} unchanged (empty diff, create {t_create:?})",
                    self.vm_id,
                    point.index
                );
                return Ok(PointReport {
                    wrote: false,
                    incremental: true,
                    diff_bytes: 0,
                    restore_mem: point.restore_mem.clone(),
                });
            }
        }

        let vmstate = own.join(format!("vmstate-{n}"));
        adopt(&jail_vmstate, &vmstate, 0o444)?;
        let base = own.join("base.mem");
        let incremental = match (mode, base.exists(), &self.loaded_from) {
            // A Full dump is the memory; it replaces whatever base
            // there was. (`rename` over the old base leaves every
            // `restore-N` reflink of it intact — they hold the inode.)
            (ForkSnapshot::Full, _, _) => {
                adopt(&jail_mem, &base, 0o600)?;
                false
            }
            // First Diff of a VM booted from scratch: every page ever
            // written since boot, so it *is* the memory.
            (ForkSnapshot::Diff, false, None) => {
                adopt(&jail_mem, &base, 0o600)?;
                false
            }
            // First Diff of a loaded VM: memory at load + the diff.
            (ForkSnapshot::Diff, false, Some(load)) => {
                snapshot::reflink(load, &base, 0o600)?;
                snapshot::apply_diff_onto_base(&jail_mem, &base)?;
                remove_loud(&jail_mem)?;
                true
            }
            (ForkSnapshot::Diff, true, _) => {
                snapshot::apply_diff_onto_base(&jail_mem, &base)?;
                remove_loud(&jail_mem)?;
                true
            }
        };
        let t_base = t0.elapsed();
        let restore = own.join(format!("restore-{n}.mem"));
        snapshot::reflink(&base, &restore, 0o444)?;

        // Disks at the same instant as the memory: the VM is still
        // paused, so a block write the guest issued just before the
        // pause is in these clones exactly when it is in the memory.
        let mut disks = Vec::new();
        for (index, drive) in self.config.drives.iter().enumerate() {
            if drive.read_only {
                continue;
            }
            let clone = own.join(format!("disk-{n}-{}", drive.name));
            snapshot::reflink(&drive.host_path, &clone, 0o400)?;
            disks.push((index, clone));
        }

        // Only the latest point is kept (see `Point`). Children loaded
        // from the old one hold their own reflinks of its files.
        if let Some(old) = self.point.take() {
            for path in std::iter::once(&old.vmstate)
                .chain(std::iter::once(&old.restore_mem))
                .chain(old.disks.iter().map(|(_, p)| p))
            {
                if let Err(e) = std::fs::remove_file(path) {
                    log::warn!("fc: retire point {}: {e}", path.display());
                }
            }
        }
        self.point = Some(Point {
            index: n,
            vmstate,
            restore_mem: restore.clone(),
            disks,
            diff_bytes: bytes,
        });
        self.points_taken = n;
        log::info!(
            "fc: {} point {n} ({mode:?}, {bytes} bytes, incremental={incremental}): create \
             {t_create:?}, base {:?}, total {:?}",
            self.vm_id,
            t_base - t_create,
            t0.elapsed()
        );
        Ok(PointReport {
            wrote: true,
            incremental,
            diff_bytes: bytes,
            restore_mem: restore,
        })
    }

    /// Stage a chroot, load this VM's current point into a fresh jailed
    /// Firecracker, and resume it. `tap` is the child's own TAP when
    /// the parent is networked (`network_overrides`).
    pub fn spawn_child(&self, tap: Option<crate::network::TapDevice>) -> Result<FcVm, FcError> {
        let point = self.point.as_ref().ok_or_else(|| FcError::Config {
            message: format!("VM {} has no snapshot point to fork from", self.vm_id),
        })?;
        let mut config = self.config.clone();
        config.vm_id = child_vm_id();
        config.track_dirty_pages = true;
        Self::spawn_from_point(point, config, tap, self.fills)
    }

    /// Stage a chroot, load `point`, and resume. Shared by
    /// [`Self::spawn_child`] (live fork) and [`Self::load_exported`]
    /// (suspend/resume).
    fn spawn_from_point(
        point: &Point,
        mut config: FcConfig,
        tap: Option<crate::network::TapDevice>,
        fills: u32,
    ) -> Result<FcVm, FcError> {
        config.track_dirty_pages = true;
        let network_overrides = match (&mut config.net, &tap) {
            (Some(net), Some(tap)) => {
                net.host_dev_name = tap.name().to_string();
                vec![NetworkOverride {
                    iface_id: NET_IFACE_ID.to_string(),
                    host_dev_name: net.host_dev_name.clone(),
                }]
            }
            (Some(_), None) => {
                return Err(FcError::Config {
                    message: format!(
                        "VM {} has a network interface; a fork child needs its own TAP",
                        config.vm_id
                    ),
                })
            }
            (None, Some(tap)) => {
                return Err(FcError::Config {
                    message: format!(
                        "TAP {} offered to a child of unbridged VM {}",
                        tap.name(),
                        config.vm_id
                    ),
                })
            }
            (None, None) => Vec::new(),
        };

        let t0 = Instant::now();
        let mut child = Self::spawn_unconfigured(&config, tap)?;
        child.fills = fills;
        child.stage_from_point(point)?;
        if let Some(ref mut tap) = child.tap {
            let uid = child.uid.uid();
            tap.detach_for_vmm(uid).map_err(|e| FcError::Config {
                message: format!("release TAP {} to Firecracker: {e}", tap.name()),
            })?;
        }
        let t_staged = t0.elapsed();
        child.api.load_snapshot(&SnapshotLoadParams {
            snapshot_path: format!("/{SNAP_SUBDIR}/vmstate"),
            mem_backend: MemoryBackend {
                backend_type: "File",
                backend_path: format!("/{SNAP_SUBDIR}/load.mem"),
            },
            track_dirty_pages: true,
            resume_vm: true,
            clock_realtime: true,
            network_overrides,
        })?;
        child.paused = false;
        let load = child.loaded_from.clone().ok_or_else(|| FcError::Config {
            message: format!("child {} has no load.mem after staging", child.vm_id),
        })?;
        if !snapshot::is_cow(&load)? {
            return Err(FcError::Stage {
                path: load,
                message: format!(
                    "shares no extents with {} — the child's memory is a copy, not \
                     copy-on-write; refusing to call that a fork",
                    point.restore_mem.display()
                ),
            });
        }
        log::info!(
            "fc: loaded {} from {} (stage {t_staged:?}, load {:?}, total {:?})",
            child.vm_id,
            point.restore_mem.display(),
            t0.elapsed() - t_staged,
            t0.elapsed()
        );
        Ok(child)
    }

    /// Put `point`'s files where the jailed Firecracker will look for
    /// them and repoint this VM's writable drives at its own clones.
    fn stage_from_point(&mut self, point: &Point) -> Result<(), FcError> {
        let Self {
            chroot,
            config,
            loaded_from,
            ..
        } = self;
        let jail = chroot.jail_snap_dir();
        let jail_load = jail.join("load.mem");
        let own_load = chroot.snap_dir().join("load.mem");
        // Live forks reflink from a restore point already on the jail
        // filesystem. Resume from a tree-dir export can be EXDEV
        // (tests put K7D_TREE_ROOT on /tmp; the jail is on the reflink
        // XFS). Copy onto the jail FS first, then reflink load.mem so
        // `is_cow` still holds (CHALLENGES #225). Never copy *into*
        // load.mem — that file must share extents.
        match snapshot::reflink(&point.restore_mem, &jail_load, 0o444) {
            Ok(()) => snapshot::reflink(&point.restore_mem, &own_load, 0o400)?,
            Err(e) if is_exdev(&e) => {
                let imported = chroot.snap_dir().join("imported.mem");
                log::warn!(
                    "fc: {e}; copying {} onto {} for resume, then reflinking load.mem",
                    point.restore_mem.display(),
                    imported.display()
                );
                copy_file(&point.restore_mem, &imported, 0o400)?;
                snapshot::reflink(&imported, &jail_load, 0o444)?;
                snapshot::reflink(&imported, &own_load, 0o400)?;
            }
            Err(e) => return Err(e),
        }
        *loaded_from = Some(own_load);
        let vmstate = jail.join("vmstate");
        hard_link_or_copy(&point.vmstate, &vmstate)?;
        for (index, drive) in config.drives.iter_mut().enumerate() {
            if drive.read_only {
                chroot.link_read_only(&drive.name, &drive.host_path)?;
                continue;
            }
            let (_, clone) = point
                .disks
                .iter()
                .find(|(i, _)| *i == index)
                .ok_or_else(|| FcError::Config {
                    message: format!(
                        "point {} has no disk clone for writable drive {}",
                        point.index,
                        drive_id(index)
                    ),
                })?;
            let dst = chroot.disk_path(&drive.name);
            clone_or_copy(clone, &dst, 0o600)?;
            stage::chown(&dst, chroot.uid())?;
            drive.host_path = dst;
        }
        Ok(())
    }
}

/// Move a file Firecracker wrote as the jailed uid into k7d's
/// root-owned bookkeeping: `rename` (same filesystem), `chown 0:0`,
/// `chmod mode`. From here on the jail cannot touch it.
fn adopt(src: &Path, dst: &Path, mode: u32) -> Result<(), FcError> {
    std::fs::rename(src, dst).map_err(|e| FcError::Stage {
        path: dst.to_path_buf(),
        message: format!("adopt {}: {e}", src.display()),
    })?;
    stage::chown(dst, 0)?;
    std::fs::set_permissions(dst, std::fs::Permissions::from_mode(mode)).map_err(|e| {
        FcError::Stage {
            path: dst.to_path_buf(),
            message: format!("chmod {mode:o}: {e}"),
        }
    })
}

fn remove_loud(path: &Path) -> Result<(), FcError> {
    std::fs::remove_file(path).map_err(|e| FcError::Stage {
        path: path.to_path_buf(),
        message: format!("remove: {e}"),
    })
}

fn is_exdev(e: &FcError) -> bool {
    matches!(e, FcError::Stage { message, .. } if message.contains("os error 18")
        || message.contains("cross-device"))
}

fn copy_file(src: &Path, dst: &Path, mode: u32) -> Result<(), FcError> {
    let _ = std::fs::remove_file(dst);
    std::fs::copy(src, dst).map_err(|e| FcError::Stage {
        path: dst.to_path_buf(),
        message: format!("copy {}: {e}", src.display()),
    })?;
    std::fs::set_permissions(dst, std::fs::Permissions::from_mode(mode)).map_err(|e| {
        FcError::Stage {
            path: dst.to_path_buf(),
            message: format!("chmod {mode:o}: {e}"),
        }
    })
}

fn clone_or_copy(src: &Path, dst: &Path, mode: u32) -> Result<(), FcError> {
    match snapshot::reflink(src, dst, mode) {
        Ok(()) => Ok(()),
        Err(e) if is_exdev(&e) => {
            log::warn!(
                "fc: {e}; copying {} to {} (resume import, not a fork)",
                src.display(),
                dst.display()
            );
            copy_file(src, dst, mode)
        }
        Err(e) => Err(e),
    }
}

fn hard_link_or_copy(src: &Path, dst: &Path) -> Result<(), FcError> {
    match std::fs::hard_link(src, dst) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
            log::warn!(
                "fc: hard-link {} → {}: {e}; copying (resume import)",
                src.display(),
                dst.display()
            );
            copy_file(src, dst, 0o444)
        }
        Err(e) => Err(FcError::Stage {
            path: dst.to_path_buf(),
            message: format!("hard-link {}: {e}", src.display()),
        }),
    }
}

impl Drop for FcVm {
    fn drop(&mut self) {
        kill_and_wait(self.pid);
        remove_cgroup(&self.cgroup_dir);
        // `chroot` and `uid` drop after this body, in that order.
    }
}

/// Resolve a pinned binary from `var`, falling back to `default`.
///
/// Returned **canonicalized**, because the jailer canonicalizes
/// `--exec-file` before taking its file name for the chroot path
/// (`<base>/<exec-name>/<id>/root`). `utils/install-firecracker.sh`
/// installs `firecracker` as a symlink to a versioned binary, so
/// resolving it here is what keeps k7d's staged kernel and the jailer's
/// chroot in the same directory instead of two that differ only by
/// version suffix (CHALLENGES #214).
///
/// Loud when the result is not an executable file: booting an FC VM
/// without Firecracker installed must say so, not fail later inside the
/// jailer with a path nobody chose.
fn binary_from_env(var: &str, default: &str) -> Result<PathBuf, FcError> {
    let path = std::env::var(var).map_or_else(|_| PathBuf::from(default), PathBuf::from);
    let resolved = std::fs::canonicalize(&path).map_err(|e| FcError::Config {
        message: format!(
            "{} is not usable ({e}); set {var}, or install it with \
             utils/install-firecracker.sh",
            path.display()
        ),
    })?;
    if !resolved.is_file() {
        return Err(FcError::Config {
            message: format!(
                "{} is not a file (set {var}; install it with utils/install-firecracker.sh)",
                resolved.display()
            ),
        });
    }
    Ok(resolved)
}

/// Narrow a stored pid to a real, single-process pid.
///
/// `kill(2)` reads non-positive pids as process **groups** — `-1` is
/// "every process the caller may signal". A corrupt or truncated pid
/// file must therefore never reach `kill` unchecked; it becomes `None`
/// and the caller treats the process as gone.
fn signalable_pid(pid: u32) -> Option<libc::pid_t> {
    libc::pid_t::try_from(pid).ok().filter(|p| *p >= 1)
}

/// Whether `pid` still exists.
#[must_use]
pub fn process_alive(pid: u32) -> bool {
    let Some(pid) = signalable_pid(pid) else {
        return false;
    };
    // SAFETY: signal 0 performs error checking only; no signal is sent,
    // and `pid` is a positive single-process pid.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// Kill the jailed Firecracker process and wait for it to disappear.
///
/// `SIGKILL`, not a `SIGTERM`-then-`SIGKILL` ladder: with
/// `--new-pid-ns` the process is init(1) of its own pid namespace, and
/// the kernel delivers a signal from an ancestor namespace to such a
/// process **only if it installed a handler for it**. Firecracker
/// handles `SIGBUS`/`SIGSEGV`/`SIGSYS`/`SIGXCPU`/`SIGXFSZ`/`SIGPIPE`/
/// `SIGHUP`/`SIGILL` and not `SIGTERM`, so a `SIGTERM` here is
/// discarded by the kernel and the only thing a grace period buys is a
/// fixed stall on every single `stop_vm`. `SIGKILL` and `SIGSTOP` are
/// the two signals forcibly delivered across the boundary.
///
/// Killing the namespace's init tears down everything in it, so there
/// is nothing else to reap. k7d is not the parent (the jailer exits
/// immediately after `clone`), so this polls rather than `wait`s.
pub fn kill_and_wait(pid: u32) {
    let Some(target) = signalable_pid(pid) else {
        return;
    };
    if !process_alive(pid) {
        return;
    }
    // SAFETY: `target` is a positive single-process pid; no memory is
    // touched by `kill`.
    unsafe { libc::kill(target, libc::SIGKILL) };
    let deadline = Instant::now() + KILL_WAIT;
    while process_alive(pid) {
        if Instant::now() >= deadline {
            log::error!("fc: firecracker pid {pid} still alive {KILL_WAIT:?} after SIGKILL");
            return;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// Remove the jailer's per-VM cgroup, and its now-empty parent.
///
/// cgroup directories cannot be removed while they hold processes, so
/// this runs after [`kill_and_wait`]. Both `rmdir`s are best-effort and
/// logged: a leftover empty cgroup is a wart, not a failure that should
/// mask the reason a VM was being torn down.
fn remove_cgroup(dir: &Path) {
    if !dir.exists() {
        return;
    }
    if let Err(e) = std::fs::remove_dir(dir) {
        log::warn!("fc: remove cgroup {}: {e}", dir.display());
        return;
    }
    if let Some(parent) = dir.parent() {
        let _ = std::fs::remove_dir(parent);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drive_ids_track_guest_device_order() {
        // The shim names `/dev/vd{a+i}` from a device's position in
        // `VmConfig.block_devices`; a drive id has to be derivable from
        // the same number and nothing else.
        assert_eq!(drive_id(0), "d0");
        assert_eq!(drive_id(25), "d25");
    }

    #[test]
    fn macs_render_as_firecracker_expects() {
        assert_eq!(
            format_mac([0xaa, 0xbb, 0x00, 0x00, 0x00, 0x02]),
            "aa:bb:00:00:00:02"
        );
    }

    #[test]
    fn missing_binary_is_loud() {
        let err = binary_from_env("K7D_FC_BINARY_TEST_MISSING", "/nonexistent/firecracker")
            .expect_err("must not proceed without the binary");
        assert!(err.to_string().contains("install-firecracker.sh"), "{err}");
    }

    #[test]
    fn non_process_pids_are_never_signalled() {
        // `kill(2)` reads 0 as "my process group" and -1 (u32::MAX cast
        // to pid_t) as "everything I may signal". Both must be filtered
        // out before any signal is sent.
        assert_eq!(signalable_pid(0), None);
        assert_eq!(signalable_pid(u32::MAX), None);
        assert_eq!(signalable_pid(1234), Some(1234));
        assert!(!process_alive(0));
        assert!(!process_alive(u32::MAX));
        kill_and_wait(0);
        kill_and_wait(u32::MAX);
    }
}
