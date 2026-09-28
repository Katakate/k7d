//! Privilege separation: a root **node broker** and an unprivileged
//! **VM broker**, one binary, one unit.
//!
//! Capability bounding measured which capabilities k7d and its helpers
//! actually spend and pinned the bounding set to that union. The
//! pre-seccomp helper spawner moved `execve` into [`crate::spawner`] so
//! the daemon's seccomp filter stopped being the union of every
//! helper's. Both shrank what the daemon *may* do. Neither changed the
//! fact that the process parsing guest-controlled FUSE traffic, shim
//! JSON, agent replies and virtio descriptor chains was uid 0 with
//! `CAP_SYS_ADMIN`.
//!
//! Privilege separation splits that process in two:
//!
//! * The **node broker** is `main()`'s parent after [`start`]. It keeps
//!   root and the capability-bounding set, has no listening socket, and serves
//!   exactly one peer over a pre-`fork` `SOCK_SEQPACKET` socketpair. Its
//!   request type is the closed [`Verb`] table below — there is no
//!   `exec`, no `mount(source, target)`, no `chown` and no `write_file`
//!   verb, because each of those is a capability with a free parameter,
//!   which is the thing the split exists to remove.
//! * The **VM broker** is the child: parent-death signal, bounding set
//!   dropped, `setgroups([kvm])`, uid/gid `k7d`, `NoNewPrivs`,
//!   `DUMPABLE=0`, and an assertion read back out of
//!   `/proc/self/status` before it goes on to fork the helper spawner,
//!   install its logger, install its own filter and bind the control
//!   socket. Everything reachable from the shim or a guest lives here.
//!
//! ## Ordering, which is the whole thing
//!
//! [`drop_privileges`] is four syscalls in an order where every swap is
//! a silent downgrade rather than a failure:
//!
//! 1. `PR_SET_PDEATHSIG` **before** the credential change. The setting
//!    survives a plain `setresuid` but not an `execve` of a privileged
//!    binary, and re-reading it with `PR_GET_PDEATHSIG` afterwards is
//!    cheap, so the code asserts rather than assumes.
//! 2. `PR_CAPBSET_DROP` **before** `setresuid`. Dropping a bounding-set
//!    bit needs `CAP_SETPCAP` in the *effective* set, and `setresuid`
//!    away from 0 clears the effective set. Swapped, every `prctl`
//!    returns `EPERM`, and a process whose bounding set is still the
//!    capability-bounding mask looks exactly like one whose bounding set is empty in every
//!    log line — the difference only shows in `/proc/<pid>/status`.
//!    That is why the last step re-reads it (`CHALLENGES.md` #246).
//! 3. `setgroups` **before** `setresgid`/`setresuid`: it needs
//!    `CAP_SETGID`, and it is what keeps `/dev/kvm` (`root:kvm 0660`)
//!    openable at all.
//! 4. The delegated cgroup subtree is created and handed over **here**,
//!    while this process is still root, not by the node broker over a
//!    verb. Privilege separation wants the fork hot path to have no
//!    round trip; a handshake would need a channel before the channel exists.
//!
//! ## Staging
//!
//! The verb table below is the closed table in full. Every family is
//! served as of `fc.*` verbs and `K7D_PRIVSEP` on — registration and
//! the pinned-fd opens (privilege separation), `net.*`,
//! `virtiofsd.spawn` and the share mounts (pinned-descriptor verbs),
//! and the Firecracker jail (`fc.*`) — and `K7D_PRIVSEP` is therefore
//! `on` in the shipped unit. `K7D_PRIVSEP=off` still runs exactly the
//! single root process k7d was before privilege separation, which is
//! what the shim, the test binaries and `k7d doctor` are
//! ([`Role::Unsplit`]).

use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub mod client;
pub mod jail;
pub mod node;
pub mod paths;

pub use crate::seqmsg::{FDS_MAX, MESSAGE_MAX};

/// Account the VM broker runs as. Created by `packaging/install.sh` and
/// `your node provisioning`.
pub const VM_BROKER_USER: &str = "k7d";

/// Supplementary group that carries `/dev/kvm` and `/dev/vhost-vsock`
/// (`root:kvm 0660`; `packaging/60-k7d.rules` covers the vsock device on
/// distros whose udev defaults do not).
pub const KVM_GROUP: &str = "kvm";

/// Name of the delegated cgroup subtree under the service cgroup. The
/// VM broker lives in it and creates its per-VM and per-tree children
/// there as uid `k7d`, with no round trip on the fork path.
pub const DELEGATED_SUBDIR: &str = "vm";

/// Sibling of [`DELEGATED_SUBDIR`] the node broker moves *itself* into.
///
/// cgroup v2 refuses to enable a domain controller in a cgroup that has
/// member processes of its own (the no-internal-process rule), and the
/// service cgroup has two: both brokers. So the node broker vacates it
/// into `node/` before enabling the controllers, which is the same thing
/// systemd's own delegation guidance asks a delegatee to do
/// (`CHALLENGES.md` #246).
pub const NODE_SUBDIR: &str = "node";

/// Controllers delegated with the subtree. `cpu` caps a pod's vCPU
/// threads, `pids` bounds a tree, `memory` and `cpuset` are what a
/// future budget would need — enabling them once at startup is cheaper
/// than discovering the parent never delegated them.
pub const DELEGATED_CONTROLLERS: &[&str] = &["cpu", "cpuset", "memory", "pids"];

// --- the closed verb table -------------------------------------------

/// A share (virtiofs `host_dir`) as it crosses at registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareSpec {
    /// Host directory the guest sees through virtiofs.
    pub host_dir: String,
    /// Whether the node broker must remount it `MS_RDONLY`.
    pub readonly: bool,
}

/// A virtio-blk backing file the shim opened for us.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockSpec {
    /// Host path of the image.
    pub host_path: String,
    /// `false` means the VM broker gets an `O_RDWR` descriptor.
    pub readonly: bool,
}

/// One TAP the node broker created, as the reply describes it.
///
/// The node broker derives the name, MAC and address from the tree id
/// and the index — the VM broker never names a link — and the
/// descriptor for entry `i` is `fds[i]` of the same datagram.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TapInfo {
    /// Index inside the tree, echoed so the caller can zip the vector.
    pub vm_index: u32,
    /// Host interface name.
    pub name: String,
    /// Guest-visible MAC.
    pub mac: [u8; 6],
    /// Guest-visible IPv4 address.
    pub ip: String,
}

/// One file the node broker links into a Firecracker jail at
/// [`Verb::FcSpawn`].
///
/// §4.4 spells this `Block(DeviceIdx) | Erofs(DeviceIdx) | Kernel |
/// Initrd`; the names here say what the variants *do* — where the file
/// lands in the jail and whether the guest may write it — because
/// "Erofs" is also what an image slot and a late fill arrive as, and
/// "Block" is not the writable half of anything else in this crate.
///
/// Every variant names a **registered** index, never a path. Two thirds
/// of a Firecracker VM's files are not in the shim's `VmConfig` at all —
/// scratch disks, data disks, reflinked tree clones and the guest pair
/// are the VM broker's own or the installer's — so they cross through
/// [`Verb::VmRegisterDisk`] first and are indices by the time they get
/// here (see that verb for why late registration and not a pin id).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageRef {
    /// Hard-linked into `img/<name>`, left root-owned and world-readable:
    /// an erofs rootfs, an image slot, a late fill.
    ReadOnly {
        /// Index into the registered `blocks`.
        device_idx: u16,
        /// File name inside the jail's `img/`.
        name: String,
    },
    /// Hard-linked into `disk/<name>` and `chown`ed to the jail uid, so
    /// the guest's writes land in the host's inode.
    ReadWrite {
        /// Index into the registered `blocks`.
        device_idx: u16,
        /// File name inside the jail's `disk/`.
        name: String,
    },
    /// Hard-linked to `<root>/vmlinux`.
    Kernel {
        /// Index into the registered `blocks`.
        device_idx: u16,
    },
    /// Hard-linked to `<root>/initramfs.cpio.gz`.
    Initrd {
        /// Index into the registered `blocks`.
        device_idx: u16,
    },
}

/// A writable disk a restored jail starts from: reflinked into
/// `disk/<name>` rather than hard-linked, because the source is a
/// snapshot the guest must not be able to write back through.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FcRestoreDisk {
    /// Index into the registered `blocks`.
    pub device_idx: u16,
    /// File name inside the jail's `disk/`.
    pub name: String,
}

/// Where a [`Verb::FcSpawn`] loads its guest state from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FcRestore {
    /// A snapshot point of another jail this node broker still holds.
    ///
    /// The live fork path. Nothing crosses but two ids: the node broker
    /// resolves `<source vm_dir>/snap/{vmstate-N, restore-N.mem,
    /// disk-N-*}` out of its own table, which is the only place those
    /// paths are knowable — the VM broker sees that directory through a
    /// magic link and could not name it to a validator if it wanted to.
    Point {
        /// Jail whose point the child loads.
        source_vm_id: String,
        /// Point index (`restore-N.mem`).
        generation: u32,
    },
    /// A snapshot directory exported by an earlier daemon
    /// (`FcVm::snapshot`), whose files crossed as registered blocks.
    ///
    /// Resume-from-disk: those files are in a tree or sandbox directory
    /// with a real host path, so they go through the same validator every
    /// other path does.
    Exported {
        /// Registered index of `vmstate`.
        vmstate_idx: u16,
        /// Registered index of `memory.bin`.
        mem_idx: u16,
        /// Writable-disk clones, in the jail names they take.
        disks: Vec<FcRestoreDisk>,
    },
}

/// Which of a Firecracker jail's two sockets to connect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FcSocket {
    /// The `firecracker.socket` HTTP API.
    Api,
    /// The guest-facing `v.sock` multiplexer.
    Vsock,
}

/// One block device of a jail, as [`FcJailRecord`] lists them.
///
/// The jail knows its drives by **name** — what it linked into `img/`
/// or `disk/` — and not by guest position: `fc.spawn` takes the
/// read-only and the writable set as two lists. Guest order is the
/// VMM's (`GET /vm/config` answers `d<i>` → `/img/<name>`), so a
/// rebuild joins the two on the name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FcJailDrive {
    /// File name inside the jail's `img/` or `disk/`.
    pub name: String,
    /// Host path the jail links it from — the current one, after any
    /// late fill. For a drive the jail cloned itself (a restored VM's
    /// writable disks) this is inside `<vm_dir>`, which the VM broker
    /// reaches through the descriptor and not by name.
    pub host_path: String,
    /// Read-only image vs writable disk.
    pub read_only: bool,
}

/// One Firecracker jail the node broker still holds, for the
/// Firecracker re-adoption path (`K7D_VM_BROKER_RESTART`).
///
/// Everything a new VM broker needs to rebuild an `FcVm` around a
/// process it did not start, and nothing it can learn from the VMM
/// itself: `Running` vs `Paused`, the boot args and the guest device
/// order are `GET /` and `GET /vm/config` over the API socket, which
/// the descriptors that travel with this record reach. Two descriptors
/// come with each record in the reply — the Firecracker pidfd and the
/// `O_PATH|O_DIRECTORY` fd of `<vm_dir>`, the same pair `fc.spawn`
/// hands back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FcJailRecord {
    /// Id the VM broker registered.
    pub vm_id: String,
    /// Sandbox the shim reattaches by, from the registration. `None`
    /// is a jail nobody can name again — a test VM, a fork child — and
    /// is what the re-adopting VM broker `fc.kill`s.
    pub sandbox_id: Option<String>,
    /// Firecracker pid in the host pid namespace.
    pub pid: u32,
    /// Jail uid from the lease.
    pub uid: u32,
    /// Whether the jail was given a TAP.
    pub tap: bool,
    /// `<vm_dir>` as a real path (see [`Reply::FcSpawned`]).
    pub vm_dir: String,
    /// Guest RAM in MiB.
    pub memory_mb: u64,
    /// Guest vCPU count.
    pub vcpus: u32,
    /// CFS `(quota, period)` in µs, when the pod capped CPU.
    pub cpu: Option<(u64, u64)>,
    /// Host path of the guest kernel linked into the jail.
    pub kernel: String,
    /// Host path of the initramfs, when there was one.
    pub initrd: Option<String>,
    /// Every block device the jail holds, by name.
    pub drives: Vec<FcJailDrive>,
    /// Point index the jail was restored from, for a fork child; `0`
    /// for a resume from an exported directory, which has no index. A
    /// pod booted from scratch has none. Either `Some` means the jail
    /// has a `snap/load.mem` the rebuilt `FcVm` seeds its base from.
    pub restored_from: Option<u32>,
}

/// Records per `fc.list` page: each carries two descriptors and a
/// datagram carries at most [`FDS_MAX`].
pub const FC_LIST_PAGE: usize = FDS_MAX / 2;

/// What the VM broker may ask the node broker to do. One variant per
/// row of the closed verb table, which is one row per capability use in
/// the capability-bounding measured table (`CHALLENGES.md` #244).
///
/// Every variant carries ids the node broker already knows, never a
/// path — except [`Verb::VmRegister`], which is where the paths from the
/// shim's `VmConfig` cross once, are validated against the §5 root
/// allowlist and are pinned as `O_PATH` descriptors ([`paths`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verb {
    /// Control channel only: hand back one end of a fresh socketpair
    /// and serve it on a thread of its own.
    ChannelOpen,
    /// The VM broker has finished `shutdown_all`; release what is left
    /// and exit 0.
    Shutdown,

    /// Introduce a VM and everything it is allowed to name. Idempotent
    /// for the same body; a different body for a live id is `EEXIST`.
    VmRegister {
        /// Id every later verb refers to.
        vm_id: String,
        /// Sandbox the shim reattaches by, when there is one.
        sandbox_id: Option<String>,
        /// Tree the VM belongs to, when it is a cluster member.
        tree_id: Option<String>,
        /// `native` or `firecracker`.
        backend: String,
        /// virtiofs shares, in `VmConfig` order.
        shares: Vec<ShareSpec>,
        /// virtio-blk backing files, in device order.
        blocks: Vec<BlockSpec>,
        /// hostPath sources for etc-file volumes, in order.
        etc_volumes: Vec<String>,
        /// CNI network namespace, when the pod has one.
        netns: Option<String>,
    },
    /// Append one more backing file to a registered VM's `blocks` and
    /// answer with the index it took.
    ///
    /// The second of the two ways out of §4.4's gap, and the one this
    /// increment took. `Verb::FcSpawn` names its images by index into
    /// `blocks`, but most of a Firecracker VM's files were never in the
    /// shim's `VmConfig`: scratch and data disks are made by the VM
    /// broker at run time under `/var/lib/k7d/disks`, erofs images under
    /// `/var/lib/k7d/images`, snapshot exports under
    /// `/var/lib/k7d/{trees,sandboxes}`, and the guest pair is the
    /// installer's. They are deliberately *not* registered at
    /// `vm.register` — the native fork path opens them directly as
    /// `k7d` and must stay verb-free (§4.5) — but the jail has to
    /// hard-link and `chown` them, which is root's.
    ///
    /// The alternative was extending the pinned-descriptor `PINS` table so the VM
    /// broker's own images carried pin ids from creation. That would
    /// have put the boundary's vocabulary into `disks.rs`, `erofs.rs`
    /// and the snapshot exporter — three modules that create files on
    /// the *native* path too, where no pin is wanted — and it would
    /// have needed a second, differently-shaped validator, because a
    /// pin id is minted where the file is made rather than checked
    /// against a root. This verb is smaller and reuses
    /// [`paths::validate`] unchanged, which is the property §4.3 asks
    /// for: no verb takes a free path that is not validated against an
    /// allowlisted root.
    ///
    /// Idempotent: the same path registered twice answers with the index
    /// it already has.
    VmRegisterDisk {
        /// Id from a previous [`Verb::VmRegister`].
        vm_id: String,
        /// Host path, validated against the block-file roots (§5).
        path: String,
        /// Whether the jail may write through it.
        writable: bool,
    },
    /// Forget the id and tear down anything still held for it.
    VmRelease {
        /// Id from a previous [`Verb::VmRegister`].
        vm_id: String,
    },

    /// Bridge, addresses, sysctls and the tree's nft jail.
    ///
    /// Idempotent, and an *upsert*: a second call for a live tree with a
    /// different policy re-renders the jail (`ClusterNetwork::
    /// set_egress`), which is what `tree_adopt_cluster` needs.
    NetTreeCreate {
        /// Tree the bridge belongs to.
        tree_id: String,
        /// Egress posture for the tree's nft jail.
        egress: crate::netjail::EgressPolicy,
    },
    /// Remove the bridge and the jail table.
    NetTreeDestroy {
        /// Tree whose bridge goes away.
        tree_id: String,
    },
    /// Create TAPs on the tree's bridge, one per index.
    ///
    /// A vector rather than one index per verb because the anti-spoof
    /// pin for a whole cluster is a single `nft` transaction: one `nft`
    /// process per TAP is what the batch fork path's budget in
    /// `LATENCY_BUDGETS.md` cannot pay, and a verb per TAP would have
    /// reintroduced it from the other side of the boundary.
    NetTapCreate {
        /// Tree whose bridge the TAPs join.
        tree_id: String,
        /// Indices inside the tree; each decides a name, MAC and IP.
        indices: Vec<u32>,
    },
    /// Hand one TAP to a jailed Firecracker: `TUNSETOWNER`,
    /// `TUNSETGROUP`, `TUNSETPERSIST`.
    ///
    /// Separate from [`Verb::NetTapCreate`] because the jail uid does
    /// not exist yet when the TAP is allocated — `UidLease::acquire`
    /// runs inside `FcVm::create`, long after `acquire_network`.
    NetTapDetach {
        /// Tree the TAP belongs to.
        tree_id: String,
        /// Index inside the tree.
        vm_index: u32,
        /// Jail uid to hand the persistent device to.
        uid: u32,
    },
    /// Remove one TAP, its nft table and the tree's record of its index.
    NetTapDestroy {
        /// Tree the TAP belongs to.
        tree_id: String,
        /// Index inside the tree.
        vm_index: u32,
    },
    /// Wire the TAP into the pod's CNI network namespace: move the
    /// link, build `k7-podbr0`, and install the pod NAT.
    NetPodAttach {
        /// Tree the TAP belongs to.
        tree_id: String,
        /// Index inside the tree.
        vm_index: u32,
        /// CNI network namespace path.
        netns: String,
        /// Pod address the NAT translates to the guest's.
        pod_ip: String,
    },
    /// Install the pod's DNAT/SNAT alone, without moving the link (the
    /// batch fork path, whose TAPs are already where they belong).
    NetPodNat {
        /// Tree the TAP belongs to.
        tree_id: String,
        /// Index inside the tree.
        vm_index: u32,
        /// CNI network namespace path.
        netns: String,
        /// Pod address the NAT translates to the guest's.
        pod_ip: String,
    },
    /// Read `eth0`'s IPv4 addresses inside a pod's CNI namespace.
    ///
    /// The one `net.*` verb that changes nothing. It is here because
    /// entering a namespace is `CAP_SYS_ADMIN` whether you mean to write
    /// in it or only to look, and `create_vm` has to learn the pod's
    /// address *before* it has a tree, a TAP or an index to name
    /// (`control.rs`'s CNI attach) — so there is nothing pinned to refer
    /// to and the handle arrives as a path, validated like every other
    /// netns (`Class::Netns`: allowlisted roots, `RESOLVE_NO_SYMLINKS`,
    /// and an `fstatfs` that must say nsfs).
    NetPodIp {
        /// CNI network namespace path.
        netns: String,
    },
    /// Best-effort reverse of [`Verb::NetPodAttach`] on pod delete.
    NetPodDetach {
        /// Tree the TAP belongs to.
        tree_id: String,
        /// Index inside the tree.
        vm_index: u32,
        /// CNI network namespace path.
        netns: String,
    },
    /// Move one link into a network namespace.
    NetLinkToNetns {
        /// Interface name to move.
        link: String,
        /// Target network namespace path.
        netns: String,
    },

    /// Bind-mount a share root onto itself and remount it read-only.
    ShareRemountRo {
        /// VM the share belongs to.
        vm_id: String,
        /// Index into the registered `shares`.
        share_idx: u16,
    },
    /// `umount2` a share root this VM's [`Verb::ShareRemountRo`] made.
    ShareUmount {
        /// VM the share belongs to.
        vm_id: String,
        /// Index into the registered `shares`.
        share_idx: u16,
    },
    /// Hand over a duplicate of the pinned `O_PATH` share root, for
    /// `fstat`/`statfs` diagnostics.
    SharePin {
        /// VM the share belongs to.
        vm_id: String,
        /// Index into the registered `shares`.
        share_idx: u16,
    },
    /// Spawn `virtiofsd` on a listener the VM broker bound and passed.
    VirtiofsdSpawn {
        /// VM the share belongs to.
        vm_id: String,
        /// Index into the registered `shares`.
        share_idx: u16,
        /// virtiofs tag the guest mounts.
        tag: String,
        /// Tree whose helper cgroup the process belongs in.
        tree: Option<String>,
    },
    /// Open a registered virtio-blk backing file.
    DiskOpen {
        /// VM the device belongs to.
        vm_id: String,
        /// Index into the registered `blocks`.
        device_idx: u16,
    },
    /// Open a registered etc-file volume source, read-only.
    VolumeOpen {
        /// VM the volume belongs to.
        vm_id: String,
        /// Index into the registered `etc_volumes`.
        volume_idx: u16,
    },

    /// Stage a jail and exec the Firecracker jailer in it.
    FcSpawn {
        /// VM the jail belongs to.
        vm_id: String,
        /// Guest vCPU count.
        vcpus: u32,
        /// Guest RAM in MiB.
        memory_mb: u64,
        /// CFS `(quota, period)` in µs, when the pod capped CPU.
        cpu: Option<(u64, u64)>,
        /// Whether the jail needs a persistent TAP.
        tap: bool,
        /// Every file that has to exist inside the jail before
        /// Firecracker is allowed to look for it.
        images: Vec<ImageRef>,
        /// Guest state to load, for a fork child or a resume.
        restore_from: Option<FcRestore>,
    },
    /// Connect one of the jail's sockets and hand over the stream.
    FcConnect {
        /// VM whose jail is dialled.
        vm_id: String,
        /// Which socket.
        which: FcSocket,
    },
    /// Link an image into the jail's `img/` under a fresh name, before
    /// the VM broker's `PATCH /drives`, and unlink the one it replaces.
    ///
    /// Read-only by construction: the drive being repointed is an image
    /// slot, and the VM broker's own `update_drive` refuses a writable
    /// one before it gets here.
    FcUpdateDrive {
        /// VM whose jail gets the image.
        vm_id: String,
        /// Index into the registered `blocks`.
        device_idx: u16,
        /// Name to link it in as, inside `img/`.
        name: String,
        /// Name of the link it replaces, unlinked after the new one is
        /// in place. Empty on the first fill.
        replaces: String,
    },
    /// Move everything the jailed Firecracker just wrote for point `N`
    /// out of the chroot and hand it to `k7d`.
    ///
    /// `<root>/snap/{vmstate-N, diff-N.mem}` are `rename`d into
    /// `<vm_dir>/snap/`, and each writable disk is reflinked to
    /// `<vm_dir>/snap/disk-N-<name>` at the same pause. From there the
    /// point is the VM broker's own file tree: applying the diff onto
    /// `base.mem`, minting `restore-N.mem` and retiring the previous
    /// point need no capability and therefore no further verb.
    FcSnapshotExport {
        /// VM whose snapshot is exported.
        vm_id: String,
        /// Point index (`vmstate-N`).
        generation: u32,
    },
    /// Kill the jailed Firecracker and remove its cgroup.
    FcKill {
        /// VM to kill.
        vm_id: String,
    },
    /// The jails the node broker still holds (§9.3), one page at a
    /// time: [`FC_LIST_PAGE`] records per reply, each with its two
    /// descriptors, ordered by `vm_id` so the pages are stable.
    FcList {
        /// Zero-based page.
        page: u32,
    },

    /// A re-forked VM broker announcing itself on the control channel
    /// (`K7D_VM_BROKER_RESTART`). The node broker only logs it: what generation is
    /// talking, and that it is not the one it forked at start-up.
    RestartHello {
        /// How many times the VM broker has been respawned; the first
        /// successor is 1.
        epoch: u32,
    },

    /// Collect the status of a helper that has already exited. The
    /// caller polls the pidfd from the reply first, so this never holds
    /// the channel while a helper runs.
    HelperWait {
        /// Pid from a [`Reply::Spawned`].
        pid: u32,
    },
    /// Kill and reap a helper whose handle was dropped unwaited.
    HelperReap {
        /// Pid from a [`Reply::Spawned`].
        pid: u32,
    },

    /// Read KSM counters for guest mappings in the VM broker.
    ///
    /// Read-only. The node broker opens `/proc/<vm-broker-pid>/smaps`
    /// and `ksm_stat` because `PR_SET_DUMPABLE=0` makes those files
    /// root-owned, so the VM broker cannot read its own. The pid is
    /// the node broker's child — the verb does not take a pid, so it
    /// cannot be pointed at another process. k7d never writes
    /// `/sys/kernel/mm/ksm`.
    KsmQuery {
        /// Host address and length of each guest RAM mapping, in the
        /// VM broker's address space.
        ranges: Vec<KsmRange>,
    },
}

/// One guest-RAM range for [`Verb::KsmQuery`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KsmRange {
    /// Host userspace address of the mapping.
    pub start: u64,
    /// Length in bytes. Page-aligned guest span.
    pub len: u64,
}

/// What the node broker answers. The verb table says which replies
/// carry descriptors and how many; a reply with the wrong count is a
/// protocol abort, not an error the caller may ignore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reply {
    /// Done, no payload.
    Ok,
    /// The payload is the `SCM_RIGHTS` array alone.
    Fds,
    /// A helper started; its pidfd comes with this datagram.
    Spawned {
        /// Helper pid in the host pid namespace.
        pid: u32,
    },
    /// An index into something the node broker keeps in order —
    /// today only [`Verb::VmRegisterDisk`]'s `blocks`.
    Index {
        /// Position the entry took.
        index: u16,
    },
    /// Raw `wait4` status, for `ExitStatus::from_raw`.
    Exited {
        /// Raw status.
        raw_status: i32,
    },
    /// Answer to [`Verb::NetPodIp`]: every IPv4 address `eth0` carries
    /// inside the namespace, in the order `ip addr` listed them.
    PodIp {
        /// Dotted-quad addresses.
        addrs: Vec<String>,
    },
    /// A tree's bridge is up.
    Tree {
        /// Interface name the node broker derived from the tree id.
        bridge: String,
    },
    /// TAPs were created, in the order asked for; descriptor `i` of the
    /// datagram belongs to entry `i`.
    Taps(Vec<TapInfo>),
    /// A jail is running. Two descriptors come with this datagram: the
    /// Firecracker pidfd, and an `O_PATH|O_DIRECTORY` fd of the jail's
    /// `<vm_dir>`.
    ///
    /// §6 names three — the pidfd plus one fd each for the API socket's
    /// directory (`<root>/run`) and the vsock UDS's. Both sockets are in
    /// `<root>/run`, so that pair is really `<root>/run` and `<root>`,
    /// and neither reaches `<vm_dir>/snap` — the VM broker's own point
    /// bookkeeping, which is a sibling of `<root>` and not under it.
    /// One fd of the parent reaches all three (`root/run/…`, `root/…`,
    /// `snap/…`) through the same magic link, so that is what crosses.
    FcSpawned {
        /// `<vm_dir>` as a **name**, for the one thing the descriptor
        /// cannot do: be handed to another process.
        ///
        /// The VM broker publishes the guest agent's UDS path to the
        /// shim (`AgentEndpoint::FcUds`), and the shim dials it itself.
        /// `/proc/self/fd/<n>/…` resolves in the VM broker's fd table
        /// and nowhere else, so what crosses to a *third* process has
        /// to be the real path — which the shim can walk because it is
        /// root and the chroot base is `0700` root. The VM broker keeps
        /// using the descriptor for its own opens; this string it only
        /// passes on (CHALLENGES #248).
        vm_dir: String,
        /// Firecracker pid.
        pid: u32,
        /// Jail uid from the lease.
        uid: u32,
    },
    /// Answer to [`Verb::FcList`]: one page. Descriptors `2i` and
    /// `2i+1` of the datagram are record `i`'s pidfd and `<vm_dir>` fd.
    FcList {
        /// The page's records.
        records: Vec<FcJailRecord>,
        /// Whether a page after this one exists.
        more: bool,
    },
    /// Answer to [`Verb::KsmQuery`]. `merging_pages[i]` is the smaps
    /// KSM page count of `ranges[i]`. `stat` is the process-wide file.
    KsmQuery {
        /// Per-range merged pages, same order as the request.
        merging_pages: Vec<u64>,
        /// `/proc/<vm-broker-pid>/ksm_stat`.
        stat: crate::ksm::KsmProcStat,
    },
    /// The verb was refused or the syscall failed. `errno` is preserved
    /// so `io::ErrorKind` survives the hop; `message` is for the log.
    Failed {
        /// `errno`, or 0 when the refusal has none of its own.
        errno: i32,
        /// Human-readable reason, always naming the id or index.
        message: String,
    },
}

impl Reply {
    /// A refusal with an `errno`.
    #[must_use]
    pub fn failed(errno: i32, message: impl Into<String>) -> Self {
        Self::Failed {
            errno,
            message: message.into(),
        }
    }
}

/// Turn a [`Reply::Failed`] back into an `io::Error` with its kind
/// intact, so a caller that branches on `ErrorKind::PermissionDenied`
/// still sees it through the hop.
#[must_use]
pub fn reply_error(errno: i32, message: String) -> io::Error {
    if errno == 0 {
        io::Error::other(message)
    } else {
        io::Error::new(io::Error::from_raw_os_error(errno).kind(), message)
    }
}

// --- start-up --------------------------------------------------------

/// Which half of the pair this process is. Every process that links the
/// library and did not call [`start`] — the shim, the test binaries,
/// `k7d doctor` — is [`Role::Unsplit`] and does its privileged work
/// itself, as it does today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// No split: this process is root and calls the privileged code
    /// directly.
    Unsplit,
    /// The unprivileged child. Privileged work is a verb.
    VmBroker,
}

/// Whether to split (`K7D_PRIVSEP`). The shipped unit sets `on`; unset
/// is **off**, because the processes that link this library without
/// being the daemon — the shim, `k7d doctor`, every in-process test —
/// are root and have no node broker to talk to. An unrecognised value
/// is an error, never a silent choice.
pub fn enabled() -> Result<bool, String> {
    match std::env::var("K7D_PRIVSEP") {
        Err(_) => Ok(false),
        Ok(v) => match v.trim() {
            "" | "off" | "0" => Ok(false),
            "on" | "1" => Ok(true),
            other => Err(format!("K7D_PRIVSEP={other:?} is not one of on|off")),
        },
    }
}

/// Whether a VM broker that dies is re-forked and the standalone
/// Firecracker sandboxes handed to its successor (`K7D_VM_BROKER_RESTART`).
/// Ships **off**: the unit does not set it, and off is
/// exactly §9.2 — release everything, exit non-zero, let systemd start
/// a clean pair. An unrecognised value is an error, never a silent
/// choice.
pub fn restart_enabled() -> Result<bool, String> {
    match std::env::var("K7D_VM_BROKER_RESTART") {
        Err(_) => Ok(false),
        Ok(v) => match v.trim() {
            "" | "off" | "0" => Ok(false),
            "on" | "1" => Ok(true),
            other => Err(format!(
                "K7D_VM_BROKER_RESTART={other:?} is not one of on|off"
            )),
        },
    }
}

/// The argument the node broker's watcher passes when it re-execs this
/// binary as a successor VM broker: `<flag>=<fd>:<epoch>:<subtree>`,
/// where `<fd>` is the inherited control-channel socket, `<epoch>` the
/// generation (first successor = 1) and `<subtree>` the delegated
/// cgroup to join. Nobody types this; it is how `main` re-enters
/// [`start`] on the other side of an `execve`.
pub const RESPAWN_FLAG: &str = "--vm-broker-respawn";

/// Descriptor number the watcher `dup2`s the control socket onto before
/// the `execve`, so the successor knows where to find it whatever the
/// node broker's fd table looked like.
pub const RESPAWN_CONTROL_FD: u32 = 3;

/// Parse [`RESPAWN_FLAG`] out of `args`, if it is there.
fn respawn_args(args: &[String]) -> Result<Option<(std::os::fd::RawFd, u32, PathBuf)>, String> {
    let prefix = format!("{RESPAWN_FLAG}=");
    let Some(value) = args.iter().find_map(|a| a.strip_prefix(prefix.as_str())) else {
        return Ok(None);
    };
    let bad = || format!("{RESPAWN_FLAG}={value:?}: want <fd>:<epoch>:<cgroup subtree>");
    let mut parts = value.splitn(3, ':');
    let fd = parts
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .and_then(|fd| std::os::fd::RawFd::try_from(fd).ok())
        .ok_or_else(bad)?;
    let epoch = parts
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|e| *e > 0)
        .ok_or_else(bad)?;
    let subtree = parts.next().filter(|s| !s.is_empty()).ok_or_else(bad)?;
    Ok(Some((fd, epoch, PathBuf::from(subtree))))
}

/// Fork the pair.
///
/// Returns [`Role::Unsplit`] when `K7D_PRIVSEP` is off. Otherwise the
/// parent becomes the node broker and **never returns**; the child
/// returns [`Role::VmBroker`] as uid `k7d` with an empty capability set,
/// and `main` carries on with the rest of the privilege-separation start order:
/// `spawner::start()`, then the logger, then its own seccomp filter,
/// then `control::serve`.
///
/// A process exec'd with [`RESPAWN_FLAG`] is a **successor** VM broker
/// (`K7D_VM_BROKER_RESTART`): still root, one inherited control socket, a node broker
/// that is its parent and is still holding the previous generation's
/// Firecracker jails. It skips the fork, drops privileges the same way
/// and returns [`Role::VmBroker`] with `client::restart_epoch() > 0`,
/// which is what tells `main` to re-adopt.
///
/// Call this as the first statement of `main` after argument parsing —
/// before `env_logger::init()`, the signal handlers, `seccomp::install`
/// and any thread. `fork` from a multi-threaded process hands the child
/// whatever locks the other threads held, and both halves allocate.
pub fn start() -> Result<Role, String> {
    if !enabled()? {
        return Ok(Role::Unsplit);
    }
    if unsafe_geteuid() != 0 {
        return Err(format!(
            "K7D_PRIVSEP is on but this process is uid {} — the node broker must start as root",
            unsafe_geteuid()
        ));
    }
    let uid = lookup_uid(VM_BROKER_USER)?;
    let gid = lookup_gid(VM_BROKER_USER)?;
    let kvm = lookup_gid(KVM_GROUP)?;

    let args: Vec<String> = std::env::args().collect();
    if let Some((fd, epoch, subtree)) = respawn_args(&args)? {
        use std::os::fd::FromRawFd;
        // SAFETY: the watcher `dup2`ed the control socket onto this
        // number with `CLOEXEC` clear and closed everything else above
        // stderr before the `execve`, so it is ours and nothing else in
        // this fresh process refers to it.
        let control = unsafe { OwnedFd::from_raw_fd(fd) };
        // `execve("/proc/self/exe")` names the image `exe` in `comm`.
        // Call it what the first generation is called, so `ps` (and
        // the tests) can tell the VM broker from the jails it inherits.
        // SAFETY: PR_SET_NAME reads a NUL-terminated string of at most
        // 16 bytes.
        unsafe { libc::prctl(libc::PR_SET_NAME, c"k7d".as_ptr()) };
        drop_privileges(uid, gid, kvm, &subtree)?;
        let role = client::adopt_successor(control, epoch);
        client::restart_hello(epoch).map_err(|e| format!("restart hello: {e}"))?;
        return Ok(role);
    }
    let restart = restart_enabled()?;

    // Before the fork, while this process is the unit's only one: the
    // service cgroup cannot enable a domain controller with a member
    // process inside it, and after the fork there are two.
    let subtree = prepare_delegated_cgroups(uid, gid)?;

    let (node_end, vm_end) =
        crate::seqmsg::socketpair().map_err(|e| format!("socketpair for the node broker: {e}"))?;

    // SAFETY: the caller guarantees this process is still
    // single-threaded (see the doc comment), so the child inherits no
    // held lock.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!(
            "fork the VM broker: {}",
            io::Error::last_os_error()
        ));
    }
    if pid == 0 {
        drop(node_end);
        // Never returns: either it serves the VM broker or it exits.
        match drop_privileges(uid, gid, kvm, &subtree) {
            Ok(()) => return Ok(client::adopt(vm_end)),
            Err(e) => {
                eprintln!("k7d VM broker: {e}");
                // Not `exit`: nothing in this child registered an
                // atexit handler worth running, and a partially
                // dropped process must not run any more code.
                // SAFETY: _exit never returns and is async-signal-safe.
                unsafe { libc::_exit(3) };
            }
        }
    }
    drop(vm_end);
    node::main(
        node_end,
        u32::try_from(pid).expect("fork returned a positive pid"),
        restart.then_some(node::RespawnPolicy { subtree, args }),
    )
}

/// Turn this process into the VM broker, in the one order where no step
/// can silently succeed at doing nothing. See the module docs.
fn drop_privileges(
    uid: u32,
    gid: u32,
    kvm_gid: u32,
    subtree: &std::path::Path,
) -> Result<(), String> {
    // 1. Parent death. Before the credential change, and read back:
    //    `execve` of a privileged binary clears it, and a VM broker
    //    that outlives its node broker holds VMs nothing can tear down.
    prctl1(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong)
        .map_err(|e| format!("PR_SET_PDEATHSIG: {e}"))?;
    let mut got: libc::c_int = 0;
    // SAFETY: PR_GET_PDEATHSIG writes one int through the pointer.
    let rc = unsafe { libc::prctl(libc::PR_GET_PDEATHSIG, &raw mut got) };
    if rc < 0 || got != libc::SIGKILL {
        return Err(format!(
            "PR_GET_PDEATHSIG says {got} (rc {rc}), want SIGKILL — the VM broker would outlive \
             its node broker"
        ));
    }

    // 2. Move into the delegated subtree while still root. Writing a pid
    //    into `<service>/vm/cgroup.procs` needs write access on the
    //    destination *and* on the common ancestor's `cgroup.procs`, and
    //    the ancestor is `<service>/`, which stays root-owned. So this
    //    move has to happen before the credential change; every later
    //    `mkdir` under `vm/` is then an ordinary unprivileged write and
    //    the fork hot path has no round trip.
    join_cgroup(subtree)?;

    // 3. Bounding set, then ambient, then credentials. `CAP_SETPCAP`
    //    lives in the effective set, which step 4 clears.
    let last_cap = last_cap()?;
    for cap in 0..=last_cap {
        if let Err(e) = prctl1(libc::PR_CAPBSET_DROP, libc::c_ulong::from(cap)) {
            return Err(format!("PR_CAPBSET_DROP({cap}): {e}"));
        }
    }
    prctl(
        libc::PR_CAP_AMBIENT,
        libc::c_ulong::try_from(libc::PR_CAP_AMBIENT_CLEAR_ALL).expect("a positive constant"),
        0,
    )
    .map_err(|e| format!("PR_CAP_AMBIENT_CLEAR_ALL: {e}"))?;

    // 4. Credentials. `setgroups` needs `CAP_SETGID` and is what makes
    //    /dev/kvm openable at all; the gid goes before the uid because
    //    after the uid there is no `CAP_SETGID` left.
    let groups = [kvm_gid];
    // SAFETY: `groups` is a valid array of the length passed.
    if unsafe { libc::setgroups(groups.len(), groups.as_ptr()) } < 0 {
        return Err(format!(
            "setgroups([{kvm_gid}]): {} — without group {KVM_GROUP} the VM broker cannot open \
             /dev/kvm",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: setresgid takes three gids.
    if unsafe { libc::setresgid(gid, gid, gid) } < 0 {
        return Err(format!("setresgid({gid}): {}", io::Error::last_os_error()));
    }
    // SAFETY: setresuid takes three uids. No `PR_SET_KEEPCAPS`, so this
    // clears the effective and permitted sets, which is the point.
    if unsafe { libc::setresuid(uid, uid, uid) } < 0 {
        return Err(format!("setresuid({uid}): {}", io::Error::last_os_error()));
    }

    // 5. No new privileges, and no other process reading this one's
    //    guest memory. `DUMPABLE=0` keeps /proc/<vm-broker>/{fd,mem}
    //    root-owned even though the process is uid k7d, so a second
    //    `k7d`-uid process — a fuzz run, a test — cannot walk it.
    prctl1(libc::PR_SET_NO_NEW_PRIVS, 1).map_err(|e| format!("PR_SET_NO_NEW_PRIVS: {e}"))?;
    prctl1(libc::PR_SET_DUMPABLE, 0).map_err(|e| format!("PR_SET_DUMPABLE: {e}"))?;

    assert_unprivileged(uid)
}

/// Read the result back out of `/proc/self/status` rather than trusting
/// the return codes above. Every step here can succeed at doing nothing
/// if the previous one ran in the wrong order, and the difference
/// between "jailed" and "root with a different name" is invisible in
/// every log line the daemon prints afterwards.
fn assert_unprivileged(want_uid: u32) -> Result<(), String> {
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|e| format!("read /proc/self/status: {e}"))?;
    for field in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        let got = status
            .lines()
            .find_map(|l| l.strip_prefix(field)?.strip_prefix(':'))
            .ok_or_else(|| format!("no {field} in /proc/self/status"))?
            .trim();
        if got.trim_start_matches('0').is_empty() {
            continue;
        }
        return Err(format!(
            "{field} is {got} after the uid drop, want empty — the capability drop ran after \
             setresuid cleared CAP_SETPCAP (privilege-separation drop order, CHALLENGES #246)"
        ));
    }
    let uid_line = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .ok_or_else(|| "no Uid in /proc/self/status".to_string())?;
    let all_dropped = uid_line
        .split_whitespace()
        .all(|f| f.parse::<u32>() == Ok(want_uid));
    if !all_dropped {
        return Err(format!(
            "Uid: {} after setresuid({want_uid}) — real, effective, saved and fs uid must all be \
             the VM broker's",
            uid_line.trim()
        ));
    }
    let nnp = status
        .lines()
        .find_map(|l| l.strip_prefix("NoNewPrivs:"))
        .map(str::trim);
    if nnp != Some("1") {
        return Err(format!("NoNewPrivs is {nnp:?}, want 1"));
    }
    Ok(())
}

/// Lay out the delegated cgroups, before the fork, and return the
/// subtree the VM broker must join.
///
/// The layout is
///
/// ```text
/// <service>/            root-owned, no member processes
/// ├── node/             root-owned, holds the node broker
/// ├── vm/               k7d-owned  — VmCpuCgroup, TreeCgroup threads
/// /sys/fs/cgroup/k7d-jail/  k7d-owned — TreeCgroup helper (domain) half
/// ```
///
/// The order is forced, and getting it wrong looks like a bug in the
/// kernel rather than in this function (`CHALLENGES.md` #246):
///
/// 1. `node/` and `vm/` are created first, and this process moves into
///    `node/`. cgroup v2 refuses `+memory` in a cgroup that has member
///    processes, and `<service>/` has this one.
/// 2. Only then are the controllers enabled in `<service>/
///    cgroup.subtree_control`, which is what makes `cpu.max`,
///    `pids.max` and `memory.max` exist in `vm/` at all.
/// 3. `vm/` and the four files a delegatee is documented to need are
///    handed to `k7d`. Nothing else is: handing over the *parent's*
///    `cgroup.subtree_control` would be a write outside the subtree,
///    which is the thing the split removes.
///
/// `/sys/fs/cgroup/k7d-jail` is prepared the same way because
/// `TreeCgroup`'s domain half lives there and is also on the fork hot
/// path. `/sys/fs/cgroup/k7d` — the jailer's parent cgroup — is
/// deliberately *not* prepared: it stays root-only, and §10.4 asserts
/// uid `k7d` cannot create in it.
fn prepare_delegated_cgroups(uid: u32, gid: u32) -> Result<std::path::PathBuf, String> {
    let service = crate::cgroup::self_cgroup_dir().map_err(|e| e.to_string())?;
    let subtree = service.join(DELEGATED_SUBDIR);
    let node = service.join(NODE_SUBDIR);
    mkdir_idempotent(&node)?;
    mkdir_idempotent(&subtree)?;
    join_cgroup(&node)?;
    enable_controllers(
        &service.join("cgroup.subtree_control"),
        DELEGATED_CONTROLLERS,
    )?;
    // Only the four files a delegatee is documented to need.
    for name in [
        "",
        "cgroup.procs",
        "cgroup.threads",
        "cgroup.subtree_control",
        "cgroup.type",
    ] {
        let path = if name.is_empty() {
            subtree.clone()
        } else {
            subtree.join(name)
        };
        chown(&path, uid, gid)?;
    }

    // `TreeCgroup`'s `memory.max` half cannot live under `vm/`: that
    // becomes a *domain threaded* root the moment the first
    // `VmCpuCgroup` is created, and a threaded subtree may only enable
    // threaded controllers. It has its own root, which is on the fork
    // hot path too and so is delegated rather than verbed.
    let jail = std::path::Path::new(crate::cgroup::HELPER_ROOT);
    mkdir_idempotent(jail)?;
    enable_controllers(&jail.join("cgroup.subtree_control"), &["memory", "pids"])?;
    chown(jail, uid, gid)?;
    chown(&jail.join("cgroup.procs"), uid, gid)?;
    chown(&jail.join("cgroup.subtree_control"), uid, gid)?;
    // Where `virtiofsd.spawn` lands a helper. A leaf, because the
    // controllers just enabled above make `k7-jail` itself unable to
    // hold member processes, and under `k7-jail` rather than beside the
    // node broker, because that is what lets the VM broker move the
    // helper again later without a capability — see
    // `node::HELPER_SPAWNED_SUBDIR`.
    let spawned = jail.join(node::HELPER_SPAWNED_SUBDIR);
    mkdir_idempotent(&spawned)?;
    chown(&spawned, uid, gid)?;
    chown(&spawned.join("cgroup.procs"), uid, gid)?;
    Ok(subtree)
}

fn mkdir_idempotent(path: &std::path::Path) -> Result<(), String> {
    match std::fs::create_dir(path) {
        Ok(()) => Ok(()),
        // A restarted unit finds its own leftovers; the ownership and
        // controller writes below are idempotent too.
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(format!("mkdir {}: {e}", path.display())),
    }
}

/// Enable controllers in one `cgroup.subtree_control`. A controller the
/// parent slice never delegated is a loud failure, not a reason to run
/// without the cap a pod asked for.
fn enable_controllers(control: &std::path::Path, controllers: &[&str]) -> Result<(), String> {
    let want: String = controllers
        .iter()
        .map(|c| format!("+{c}"))
        .collect::<Vec<_>>()
        .join(" ");
    std::fs::write(control, &want).map_err(|e| {
        format!(
            "write {want:?} to {}: {e} — the unit needs `Delegate={}` so systemd does not take \
             the controllers back, and the cgroup must have no member processes of its own",
            control.display(),
            controllers.join(" ")
        )
    })
}

/// Move the calling process into `dir`.
fn join_cgroup(dir: &std::path::Path) -> Result<(), String> {
    let procs = dir.join("cgroup.procs");
    std::fs::write(&procs, std::process::id().to_string()).map_err(|e| {
        format!(
            "move pid {} into {}: {e}",
            std::process::id(),
            procs.display()
        )
    })
}

fn chown(path: &std::path::Path, uid: u32, gid: u32) -> Result<(), String> {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|e| format!("{}: {e}", path.display()))?;
    // SAFETY: `c` is a valid C string that outlives the call.
    if unsafe { libc::chown(c.as_ptr(), uid, gid) } < 0 {
        return Err(format!(
            "chown {} to {uid}:{gid}: {}",
            path.display(),
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// `/proc/sys/kernel/cap_last_cap`. Read rather than assumed: a
/// hardcoded `CAP_LAST_CAP` that is too small leaves the newest
/// capability in the bounding set on a newer kernel, and the assertion
/// in [`assert_unprivileged`] would be the only thing that noticed.
fn last_cap() -> Result<u32, String> {
    let text = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .map_err(|e| format!("read /proc/sys/kernel/cap_last_cap: {e}"))?;
    text.trim()
        .parse()
        .map_err(|e| format!("parse cap_last_cap {:?}: {e}", text.trim()))
}

/// One `prctl`, with **all five** arguments given.
///
/// `prctl(2)` is variadic, and several of the operations this module uses
/// — `PR_SET_NO_NEW_PRIVS`, `PR_CAP_AMBIENT` — require `arg3`, `arg4` and
/// `arg5` to be zero and answer `EINVAL` otherwise. Handing glibc's
/// variadic wrapper only the arguments an operation *reads* leaves the
/// rest as whatever the argument registers happened to hold, so those two
/// fail on most hosts and none of the diagnostics point at the arity
/// (`CHALLENGES.md` #246). Every call goes through this one function so
/// that cannot recur per operation.
fn prctl(op: libc::c_int, arg2: libc::c_ulong, arg3: libc::c_ulong) -> io::Result<()> {
    // SAFETY: every operation used here takes scalars only and reads no
    // memory through the arguments.
    if unsafe { libc::prctl(op, arg2, arg3, 0 as libc::c_ulong, 0 as libc::c_ulong) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `prctl` with one meaningful argument and the rest zeroed.
fn prctl1(op: libc::c_int, arg2: libc::c_ulong) -> io::Result<()> {
    prctl(op, arg2, 0)
}

fn unsafe_geteuid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// `getpwnam` for the VM broker's account, with the failure spelling out
/// which packaging step is missing.
fn lookup_uid(name: &str) -> Result<u32, String> {
    let c = std::ffi::CString::new(name).map_err(|e| e.to_string())?;
    // SAFETY: `c` outlives the call; the returned pointer is glibc's
    // static storage, read before any other libc call touches it.
    let pw = unsafe { libc::getpwnam(c.as_ptr()) };
    if pw.is_null() {
        return Err(format!(
            "no account {name:?} — `packaging/install.sh` (or \
             your node provisioning) creates it with `useradd --system --groups kvm`"
        ));
    }
    // SAFETY: non-null `passwd` from getpwnam.
    Ok(unsafe { (*pw).pw_uid })
}

fn lookup_gid(name: &str) -> Result<u32, String> {
    let c = std::ffi::CString::new(name).map_err(|e| e.to_string())?;
    // SAFETY: as above, for the group database.
    let gr = unsafe { libc::getgrnam(c.as_ptr()) };
    if gr.is_null() {
        return Err(format!("no group {name:?}"));
    }
    // SAFETY: non-null `group` from getgrnam.
    Ok(unsafe { (*gr).gr_gid })
}

/// Encode one datagram, refusing anything over the wire limit before it
/// reaches the kernel so the error names the verb rather than arriving
/// as `MSG_TRUNC` on the far side.
pub(crate) fn encode<T: Serialize + std::fmt::Debug>(value: &T) -> io::Result<Vec<u8>> {
    let payload = serde_json::to_vec(value).map_err(io::Error::other)?;
    if payload.len() > MESSAGE_MAX {
        return Err(io::Error::other(format!(
            "broker message is {} bytes, over the {MESSAGE_MAX}-byte datagram limit: {value:?}",
            payload.len()
        )));
    }
    Ok(payload)
}

/// The two halves disagreeing about the protocol is not an error a
/// caller can handle: one of them is holding a descriptor the other
/// thinks it owns. Abort instead of guessing (pre-seccomp helper
/// spawner behaviour).
pub(crate) fn protocol_abort(what: &str) -> ! {
    log::error!("broker protocol error: {what}");
    eprintln!("k7d: broker protocol error: {what}");
    std::process::abort();
}

/// Send one reply on `sock`, aborting on a transport failure.
pub(crate) fn send_reply(sock: impl AsFd, reply: &Reply, fds: &[OwnedFd]) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let payload = encode(reply)?;
    let raw: Vec<_> = fds.iter().map(AsRawFd::as_raw_fd).collect();
    crate::seqmsg::send_msg(sock.as_fd(), &payload, &raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_env<T>(val: Option<&str>, f: impl FnOnce() -> T) -> T {
        with_key("K7D_PRIVSEP", val, f)
    }

    fn with_key<T>(key: &str, val: Option<&str>, f: impl FnOnce() -> T) -> T {
        let prev = std::env::var(key).ok();
        match val {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        let out = f();
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        out
    }

    #[test]
    fn privsep_mode_is_total_and_loud() {
        assert!(!with_env(None, enabled).expect("unset is off"));
        assert!(!with_env(Some("off"), enabled).unwrap());
        assert!(!with_env(Some("0"), enabled).unwrap());
        assert!(with_env(Some("on"), enabled).unwrap());
        assert!(with_env(Some("1"), enabled).unwrap());
        assert!(with_env(Some("maybe"), enabled).is_err());
    }

    /// The restart flag ships off (`K7D_VM_BROKER_RESTART`: "the flag
    /// ships off; only the test turns it on") and is as strict as the
    /// split flag.
    #[test]
    fn restart_flag_defaults_off_and_is_loud() {
        let key = "K7D_VM_BROKER_RESTART";
        assert!(!with_key(key, None, restart_enabled).expect("unset is off"));
        assert!(!with_key(key, Some("off"), restart_enabled).unwrap());
        assert!(with_key(key, Some("1"), restart_enabled).unwrap());
        assert!(with_key(key, Some("on"), restart_enabled).unwrap());
        assert!(with_key(key, Some("yes"), restart_enabled).is_err());
        let unit = include_str!("../../../../packaging/k7d.service.in");
        assert!(
            !unit.lines().any(|l| l
                .trim_start()
                .starts_with("Environment=K7D_VM_BROKER_RESTART")),
            "the shipped unit must not turn VM-broker restart on"
        );
    }

    /// The successor's argument round-trips and refuses every partial
    /// form: a malformed flag must fail the exec, not fall through to a
    /// second node broker.
    #[test]
    fn respawn_flag_parses_or_refuses() {
        let none = respawn_args(&["--socket".into(), "/tmp/x".into()]).unwrap();
        assert!(none.is_none());
        let some = respawn_args(&[format!("{RESPAWN_FLAG}=3:2:/sys/fs/cgroup/k7d.service/vm")])
            .unwrap()
            .expect("parsed");
        assert_eq!(some.0, 3);
        assert_eq!(some.1, 2);
        assert_eq!(
            some.2,
            std::path::Path::new("/sys/fs/cgroup/k7d.service/vm")
        );
        for bad in ["3:2", "3:0:/x", "x:1:/x", "3:1:", ""] {
            assert!(
                respawn_args(&[format!("{RESPAWN_FLAG}={bad}")]).is_err(),
                "{bad:?} must be refused"
            );
        }
    }

    /// One of every variant, so the round-trip tests below cover the
    /// whole table rather than the variants someone remembered. Split by
    /// family, which is how §4 groups them.
    fn all_verbs() -> Vec<Verb> {
        let mut v = lifecycle_and_net_verbs();
        v.extend(resource_and_fc_verbs());
        v
    }

    fn lifecycle_and_net_verbs() -> Vec<Verb> {
        vec![
            Verb::ChannelOpen,
            Verb::Shutdown,
            Verb::VmRegister {
                vm_id: "vm-1".into(),
                sandbox_id: Some("sb".into()),
                tree_id: None,
                backend: "native".into(),
                shares: vec![ShareSpec {
                    host_dir: "/var/lib/k7d/trees/a".into(),
                    readonly: true,
                }],
                blocks: vec![BlockSpec {
                    host_path: "/var/lib/k7d/images/a.img".into(),
                    readonly: false,
                }],
                etc_volumes: vec!["/var/lib/kubelet/pods/x/etc/hosts".into()],
                netns: Some("/run/netns/cni-1".into()),
            },
            Verb::VmRelease {
                vm_id: "vm-1".into(),
            },
            Verb::NetTreeCreate {
                tree_id: "t".into(),
                egress: crate::netjail::EgressPolicy {
                    mode: crate::netjail::EgressMode::Deny,
                    ..crate::netjail::EgressPolicy::default()
                },
            },
            Verb::NetTreeDestroy {
                tree_id: "t".into(),
            },
            Verb::NetTapCreate {
                tree_id: "t".into(),
                indices: vec![0, 3],
            },
            Verb::NetTapDetach {
                tree_id: "t".into(),
                vm_index: 3,
                uid: 90_001,
            },
            Verb::NetTapDestroy {
                tree_id: "t".into(),
                vm_index: 3,
            },
            Verb::NetPodAttach {
                tree_id: "t".into(),
                vm_index: 3,
                netns: "/run/netns/cni-1".into(),
                pod_ip: "10.42.0.7".into(),
            },
            Verb::NetPodNat {
                tree_id: "t".into(),
                vm_index: 3,
                netns: "/run/netns/cni-1".into(),
                pod_ip: "10.42.0.7".into(),
            },
            Verb::NetPodIp {
                netns: "/run/netns/cni-1".into(),
            },
            Verb::NetPodDetach {
                tree_id: "t".into(),
                vm_index: 3,
                netns: "/run/netns/cni-1".into(),
            },
            Verb::NetLinkToNetns {
                link: "t12ab3t0".into(),
                netns: "/run/netns/cni-1".into(),
            },
        ]
    }

    fn resource_and_fc_verbs() -> Vec<Verb> {
        vec![
            Verb::ShareRemountRo {
                vm_id: "vm-1".into(),
                share_idx: 0,
            },
            Verb::ShareUmount {
                vm_id: "vm-1".into(),
                share_idx: 0,
            },
            Verb::SharePin {
                vm_id: "vm-1".into(),
                share_idx: 0,
            },
            Verb::VirtiofsdSpawn {
                vm_id: "vm-1".into(),
                share_idx: 0,
                tag: "k7fs".into(),
                tree: Some("t".into()),
            },
            Verb::DiskOpen {
                vm_id: "vm-1".into(),
                device_idx: 1,
            },
            Verb::VolumeOpen {
                vm_id: "vm-1".into(),
                volume_idx: 0,
            },
            Verb::FcSpawn {
                vm_id: "vm-1".into(),
                vcpus: 2,
                memory_mb: 2048,
                cpu: Some((20_000, 100_000)),
                tap: true,
                images: vec![
                    ImageRef::Kernel { device_idx: 0 },
                    ImageRef::Initrd { device_idx: 1 },
                    ImageRef::ReadOnly {
                        device_idx: 2,
                        name: "d0".into(),
                    },
                    ImageRef::ReadWrite {
                        device_idx: 3,
                        name: "d1".into(),
                    },
                ],
                restore_from: Some(FcRestore::Exported {
                    vmstate_idx: 4,
                    mem_idx: 5,
                    disks: vec![FcRestoreDisk {
                        device_idx: 6,
                        name: "d1".into(),
                    }],
                }),
            },
            Verb::FcSpawn {
                vm_id: "vm-2".into(),
                vcpus: 1,
                memory_mb: 512,
                cpu: None,
                tap: false,
                images: Vec::new(),
                restore_from: Some(FcRestore::Point {
                    source_vm_id: "vm-1".into(),
                    generation: 3,
                }),
            },
            Verb::FcConnect {
                vm_id: "vm-1".into(),
                which: FcSocket::Api,
            },
            Verb::FcUpdateDrive {
                vm_id: "vm-1".into(),
                device_idx: 0,
                name: "d0-fill1".into(),
                replaces: "d0".into(),
            },
            Verb::FcSnapshotExport {
                vm_id: "vm-1".into(),
                generation: 7,
            },
            Verb::FcKill {
                vm_id: "vm-1".into(),
            },
            Verb::FcList { page: 1 },
            Verb::RestartHello { epoch: 2 },
            Verb::HelperWait { pid: 4242 },
            Verb::HelperReap { pid: 4242 },
        ]
    }

    fn all_replies() -> Vec<Reply> {
        vec![
            Reply::Ok,
            Reply::Fds,
            Reply::Spawned { pid: 1 },
            Reply::Exited { raw_status: 256 },
            Reply::Tree {
                bridge: "k7-br-t".into(),
            },
            Reply::Taps(vec![TapInfo {
                vm_index: 3,
                name: "t12ab3t3".into(),
                mac: [0xaa, 0xbb, 0, 0, 0, 5],
                ip: "10.200.0.5".into(),
            }]),
            Reply::FcSpawned {
                vm_dir: "/var/lib/k7d/fc/firecracker/vm-1".into(),
                pid: 2,
                uid: 90_001,
            },
            Reply::Index { index: 4 },
            Reply::PodIp {
                addrs: vec!["10.42.0.7".into()],
            },
            Reply::FcList {
                records: vec![FcJailRecord {
                    vm_id: "vm-1".into(),
                    sandbox_id: Some("sb-1".into()),
                    pid: 3,
                    uid: 90_001,
                    tap: true,
                    vm_dir: "/var/lib/k7d/fc/firecracker/vm-1".into(),
                    memory_mb: 512,
                    vcpus: 2,
                    cpu: Some((100_000, 100_000)),
                    kernel: "/usr/local/share/k7d/vmlinux".into(),
                    initrd: None,
                    drives: vec![FcJailDrive {
                        name: "d0.erofs".into(),
                        host_path: "/var/lib/k7d/images/d0.erofs".into(),
                        read_only: true,
                    }],
                    restored_from: None,
                }],
                more: false,
            },
            Reply::failed(libc::EACCES, "no"),
        ]
    }

    /// Every verb survives the wire. A variant that does not is a verb
    /// the node broker would answer `EPROTO` to on a node nobody tested.
    #[test]
    fn every_verb_round_trips() {
        for verb in &all_verbs() {
            let bytes = encode(verb).expect("encode");
            let back: Verb = serde_json::from_slice(&bytes).expect("decode");
            assert_eq!(&back, verb);
        }
    }

    /// And every reply, including the ones whose payload is only a
    /// descriptor count.
    #[test]
    fn every_reply_round_trips() {
        for reply in &all_replies() {
            let bytes = encode(reply).expect("encode");
            let back: Reply = serde_json::from_slice(&bytes).expect("decode");
            assert_eq!(&back, reply);
        }
    }

    /// A payload over the datagram limit is refused with the verb in the
    /// message, rather than sent and then reported as `MSG_TRUNC` by a
    /// peer that cannot say which request it was.
    #[test]
    fn an_oversized_message_is_refused_before_the_kernel_sees_it() {
        let verb = Verb::VmRegister {
            vm_id: "vm-1".into(),
            sandbox_id: None,
            tree_id: None,
            backend: "native".into(),
            shares: (0..4000)
                .map(|i| ShareSpec {
                    host_dir: format!(
                        "/var/lib/kubelet/pods/{i}/volumes/kubernetes.io~empty-dir/d"
                    ),
                    readonly: false,
                })
                .collect(),
            blocks: Vec::new(),
            etc_volumes: Vec::new(),
            netns: None,
        };
        let err = encode(&verb).expect_err("must refuse");
        assert!(err.to_string().contains("datagram limit"), "{err}");
    }

    /// `errno` survives the hop, which is what lets a caller keep
    /// branching on `ErrorKind` after the operation moved processes.
    #[test]
    fn failed_replies_keep_their_error_kind() {
        assert_eq!(
            reply_error(libc::EACCES, "denied".into()).kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            reply_error(libc::ENOENT, "gone".into()).kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            reply_error(0, "no errno".into()).kind(),
            io::ErrorKind::Other
        );
    }

    /// Every library source file, paired with the part of it that is not
    /// a test module. The split is at `#[cfg(test)]`: a `fork` in a unit
    /// test is a test's business, and counting it would make the
    /// placement assertions below un-assertable.
    fn production_sources() -> Vec<(&'static str, &'static str)> {
        // `include_str!` rather than a directory walk: the test then
        // fails to *compile* when a file is renamed, instead of passing
        // because it silently scanned nothing.
        let files: Vec<(&str, &str)> = vec![
            ("broker/mod.rs", include_str!("mod.rs")),
            ("broker/node.rs", include_str!("node.rs")),
            ("broker/client.rs", include_str!("client.rs")),
            ("broker/paths.rs", include_str!("paths.rs")),
            ("spawner.rs", include_str!("../spawner.rs")),
            ("main.rs", include_str!("../main.rs")),
            ("control.rs", include_str!("../control.rs")),
            ("volumes.rs", include_str!("../volumes.rs")),
            ("virtiofs.rs", include_str!("../virtiofs.rs")),
            ("network.rs", include_str!("../network.rs")),
            ("netjail.rs", include_str!("../netjail.rs")),
            ("netns.rs", include_str!("../netns.rs")),
            ("cgroup.rs", include_str!("../cgroup.rs")),
            ("vm.rs", include_str!("../vm.rs")),
            ("vsock.rs", include_str!("../vsock.rs")),
            ("block.rs", include_str!("../block.rs")),
            ("api.rs", include_str!("../api.rs")),
            ("fc/mod.rs", include_str!("../fc/mod.rs")),
            ("fc/spawn.rs", include_str!("../fc/spawn.rs")),
            ("fc/stage.rs", include_str!("../fc/stage.rs")),
            ("seccomp.rs", include_str!("../seccomp.rs")),
        ];
        files
            .into_iter()
            .map(|(name, body)| {
                let prod = body.split("#[cfg(test)]").next().unwrap_or(body);
                (name, prod)
            })
            .collect()
    }

    fn files_containing(needle: &str) -> Vec<&'static str> {
        production_sources()
            .into_iter()
            .filter(|(_, body)| body.contains(needle))
            .map(|(name, _)| name)
            .collect()
    }

    /// `fork()` without an immediate `execve` may only happen while the
    /// process is single-threaded, because the child inherits every lock
    /// the other threads held and both halves of this one allocate.
    ///
    /// There are exactly two such forks and both are provably pre-thread:
    /// [`start`] is `main`'s first statement, and `spawner::start` is the
    /// VM broker's. A third one added anywhere else — a worker thread
    /// forking a helper, a channel thread forking a jailer — would
    /// deadlock rarely and unreproducibly, which is why this is a grep
    /// test and not a runtime check.
    #[test]
    fn fork_happens_only_where_the_process_is_single_threaded() {
        assert_eq!(
            files_containing("libc::fork("),
            vec!["broker/mod.rs", "spawner.rs"],
            "a new fork(2) call site: it must be provably before any thread exists"
        );
    }

    /// `mount`, `umount2` and `chown` are capabilities with a free
    /// parameter, which is why none of them is a verb. They stay in the
    /// files the node broker calls into, and nothing the guest or the shim
    /// can reach may grow one: a `chown` in `api.rs` or `control.rs` would
    /// be reachable from a parsed message.
    #[test]
    fn the_privileged_syscalls_stay_on_the_node_brokers_side() {
        for (needle, want) in [
            ("libc::mount(", vec!["volumes.rs"]),
            ("libc::umount2(", vec!["volumes.rs"]),
            ("libc::chown(", vec!["broker/mod.rs", "fc/stage.rs"]),
            ("libc::setresuid", vec!["broker/mod.rs"]),
            ("libc::setgroups", vec!["broker/mod.rs"]),
        ] {
            assert_eq!(
                files_containing(needle),
                want,
                "{needle} moved or spread — privilege separation places it, and a new caller needs a verb \
                 rather than a call"
            );
        }
    }

    /// The unit and both installers agree about the account, the udev rule
    /// and the delegation.
    ///
    /// `packaging/k7d-account.sh` exists so the release install and the
    /// node-reset script cannot drift; a second copy of the `useradd`
    /// would be a second thing to forget, and the failure mode is a node
    /// where the split refuses to start with `no account "k7d"`.
    #[test]
    fn packaging_provisions_the_vm_broker_everywhere_it_installs() {
        let account = include_str!("../../../../packaging/k7d-account.sh");
        for needed in [
            "k7d_create_account",
            "k7d_install_udev_rule",
            "k7d_own_state_dirs",
            "k7d_provision_vm_broker_identity",
        ] {
            assert!(account.contains(needed), "k7d-account.sh lost {needed}");
        }
        for (name, body) in [
            (
                "install.sh",
                include_str!("../../../../packaging/install.sh"),
            ),
            (
                "setup-node-after-reset.sh",
                include_str!("../../../../your node provisioning"),
            ),
        ] {
            assert!(
                body.contains("k7d-account.sh")
                    && body.contains("k7d_provision_vm_broker_identity"),
                "{name} must source packaging/k7d-account.sh and call \
                 k7d_provision_vm_broker_identity, not repeat the useradd"
            );
        }
        let unit = include_str!("../../../../packaging/k7d.service.in");
        for needed in [
            "RuntimeDirectory=k7d",
            "RuntimeDirectoryPreserve=yes",
            "K7D_PRIVSEP",
        ] {
            assert!(unit.contains(needed), "k7d.service.in lost {needed}");
        }
        let delegate = unit
            .lines()
            .find(|l| l.starts_with("Delegate="))
            .unwrap_or_else(|| panic!("k7d.service.in must set Delegate="));
        for controller in DELEGATED_CONTROLLERS {
            assert!(
                delegate.contains(controller),
                "{delegate} does not delegate {controller}, which \
                 prepare_delegated_cgroups enables"
            );
        }
    }

    /// The shipped unit opts in. Every verb family is served as of
    /// `fc.*` verbs and `K7D_PRIVSEP` on, and a node that runs the packaged `k7d.service` is a
    /// node that runs split — which is the only way the split is ever
    /// exercised outside the test suite.
    #[test]
    fn the_shipped_unit_turns_the_split_on() {
        let unit = include_str!("../../../../packaging/k7d.service.in");
        let line = unit
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with("Environment=K7D_PRIVSEP"))
            .unwrap_or_else(|| panic!("k7d.service.in must set K7D_PRIVSEP"));
        assert_eq!(
            line, "Environment=K7D_PRIVSEP=on",
            "packaged unit must set K7D_PRIVSEP=on"
        );
    }

    /// `RestrictSUIDSGID=yes` and the node broker cannot both be in the
    /// unit: systemd blocks `openat2` with ENOSYS under it, and
    /// `openat2` is the path validator. Guarded here because the option
    /// is exactly the kind of line a hardening pass adds back, and the
    /// symptom is a `CreateVm` that blames the shim's `hostPath`
    /// (CHALLENGES #249).
    #[test]
    fn the_shipped_unit_does_not_restrict_suid_sgid() {
        let unit = include_str!("../../../../packaging/k7d.service.in");
        let set = unit
            .lines()
            .map(str::trim)
            .any(|l| l.starts_with("RestrictSUIDSGID=") && !l.ends_with("=no"));
        assert!(
            !set,
            "RestrictSUIDSGID makes openat2 return ENOSYS, which is every \
             path validation and the jail's setgid run/ (CHALLENGES #249)"
        );
    }
}
