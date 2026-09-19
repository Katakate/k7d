//! The VM broker's side of the channel: one socketpair per worker
//! thread, taken from a bounded pool.
//!
//! The pre-seccomp helper spawner has a single serialized connection behind a `Mutex`,
//! which is right for it: a spawn is a `fork`/`execve` and the pidfd in
//! the reply keeps the *waiting* off the socket. It is wrong here.
//! `fc.spawn` stages a jail and waits for an API socket, `net.tree_
//! create` runs a bridge plus an `nft -f` plus several `ip` calls, and
//! both are issued from many `handle_connection` threads at once during
//! a fork batch or a cluster boot. One serialized channel would make
//! those queue behind each other for no reason.
//!
//! So: a channel per thread, a node-broker thread per channel, no
//! request ids and no reordering. A socketpair costs two descriptors and
//! one thread, which is less than a multiplexer costs and keeps both
//! parsers trivial. The pool is capped ([`BROKER_CHANNELS_MAX`]) because
//! an unbounded one is a descriptor leak with extra steps; a thread that
//! finds the pool empty and the cap reached waits, and `k7d doctor`
//! reports the high-water mark so that back-pressure is visible before
//! it is a symptom.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::os::fd::{AsFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, OnceLock};

use super::{encode, protocol_abort, reply_error, Reply, Role, Verb};
use crate::seqmsg::{recv_msg, MESSAGE_MAX};

/// Most verb channels at once. Well above the thread count a node with
/// hundreds of live VMs reaches (`handle_connection` threads are
/// short-lived and hand their channel back), and low enough that
/// exhaustion is a bug report rather than an `EMFILE`.
pub const BROKER_CHANNELS_MAX: usize = 64;

/// The control channel (channel 0). Only `channel.open` and `shutdown`
/// travel on it, so the lock is held for microseconds.
static CONTROL: OnceLock<Mutex<OwnedFd>> = OnceLock::new();

/// Free verb channels, plus the counters `k7d doctor` publishes.
static POOL: Mutex<Vec<OwnedFd>> = Mutex::new(Vec::new());
static POOL_FREED: Condvar = Condvar::new();
static LIVE: AtomicUsize = AtomicUsize::new(0);
static IN_USE: AtomicUsize = AtomicUsize::new(0);
static HIGH_WATER: AtomicUsize = AtomicUsize::new(0);

/// Test double: every verb is refused with `EPERM`. What the
/// `control_request` fuzz target runs against, so a `Daemon` built in a
/// fuzz process cannot reach a real privileged operation even if one
/// were somehow available to it.
static DENY_ALL: AtomicBool = AtomicBool::new(false);

thread_local! {
    /// This thread's channel, returned to the pool when the thread ends.
    static CHANNEL: RefCell<Option<Lease>> = const { RefCell::new(None) };
}

/// A channel on loan to one thread.
struct Lease(Option<OwnedFd>);

impl Drop for Lease {
    fn drop(&mut self) {
        if let Some(fd) = self.0.take() {
            IN_USE.fetch_sub(1, Ordering::SeqCst);
            POOL.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(fd);
            POOL_FREED.notify_one();
        }
    }
}

/// Register the socketpair end [`super::start`] inherited. Called in the
/// child, after the uid drop and before anything else runs.
pub(super) fn adopt(vm_end: OwnedFd) -> Role {
    if CONTROL.set(Mutex::new(vm_end)).is_err() {
        protocol_abort("a second broker control channel — start() ran twice");
    }
    Role::VmBroker
}

/// Which generation of VM broker this process is: 0 for the one
/// [`super::start`] forked, `n` for the `n`th successor the node
/// broker re-exec'd after a crash (`K7D_VM_BROKER_RESTART`). Read by `main` to
/// decide whether there are jails to re-adopt.
static RESTART_EPOCH: AtomicU32 = AtomicU32::new(0);

/// [`adopt`] for a successor: the control socket came through `execve`
/// rather than `fork`, and the epoch says which generation this is.
pub(super) fn adopt_successor(control: OwnedFd, epoch: u32) -> Role {
    RESTART_EPOCH.store(epoch, Ordering::SeqCst);
    adopt(control)
}

/// See [`RESTART_EPOCH`].
#[must_use]
pub fn restart_epoch() -> u32 {
    RESTART_EPOCH.load(Ordering::SeqCst)
}

/// A successor's first message: tell the node broker which generation
/// is talking, so the log says so before the first `fc.list`.
pub(super) fn restart_hello(epoch: u32) -> io::Result<()> {
    let (reply, fds) = call_control(&Verb::RestartHello { epoch }, &[])?;
    if !fds.is_empty() {
        protocol_abort("the restart hello reply carried descriptors");
    }
    match reply {
        Reply::Ok => Ok(()),
        Reply::Failed { errno, message } => Err(reply_error(errno, message)),
        other => protocol_abort(&format!("unexpected reply to restart hello: {other:?}")),
    }
}

/// Whether this process is the VM broker, i.e. whether privileged work
/// is a verb. False in the shim, in the test binaries, in `k7d doctor`
/// and in a daemon started without `K7D_PRIVSEP`, all of which are root
/// and call the privileged code directly.
#[must_use]
pub fn is_split() -> bool {
    CONTROL.get().is_some()
}

/// Refuse every verb from now on. Irreversible on purpose: a fuzz target
/// that could turn it back off would be one bug away from running a real
/// privileged operation.
pub fn deny_all() {
    DENY_ALL.store(true, Ordering::SeqCst);
}

/// `(in use, high water, cap)` for `k7d doctor`.
#[must_use]
pub fn channel_stats() -> (usize, usize, usize) {
    (
        IN_USE.load(Ordering::Relaxed),
        HIGH_WATER.load(Ordering::Relaxed),
        BROKER_CHANNELS_MAX,
    )
}

/// Issue one verb on this thread's channel.
///
/// `fds` travel with the request; the reply's descriptors come back in
/// the order the verb table gives. A transport failure is not an error
/// the caller can handle — the node broker and the VM broker would
/// disagree about who owns a descriptor — so it aborts.
pub fn call(verb: &Verb, fds: &[RawFd]) -> io::Result<(Reply, Vec<OwnedFd>)> {
    if DENY_ALL.load(Ordering::SeqCst) {
        return Ok((
            Reply::failed(libc::EPERM, format!("broker denied: {verb:?}")),
            Vec::new(),
        ));
    }
    let payload = encode(verb)?;
    CHANNEL.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            *slot = Some(acquire()?);
        }
        let lease = slot.as_ref().expect("just filled");
        let sock = lease.0.as_ref().expect("a lease always holds its channel");
        round_trip(sock.as_fd(), &payload, fds)
    })
}

/// Issue one verb on the control channel. Only `channel.open` and
/// `shutdown` belong here.
fn call_control(verb: &Verb, fds: &[RawFd]) -> io::Result<(Reply, Vec<OwnedFd>)> {
    let control = CONTROL
        .get()
        .ok_or_else(|| io::Error::other("no broker control channel in this process"))?;
    let payload = encode(verb)?;
    let guard = control
        .lock()
        .unwrap_or_else(|_| protocol_abort("broker control mutex poisoned"));
    round_trip(guard.as_fd(), &payload, fds)
}

fn round_trip(
    sock: std::os::fd::BorrowedFd<'_>,
    payload: &[u8],
    fds: &[RawFd],
) -> io::Result<(Reply, Vec<OwnedFd>)> {
    if let Err(e) = crate::seqmsg::send_msg(sock, payload, fds) {
        protocol_abort(&format!("sendmsg on a broker channel: {e}"));
    }
    let mut buf = vec![0u8; MESSAGE_MAX];
    let mut received = Vec::new();
    let got = match recv_msg(sock, &mut buf, &mut received) {
        // EOF is the node broker gone. `PR_SET_PDEATHSIG` normally kills
        // this process first; if the ordering went the other way there is
        // nothing left that can remove a TAP or an nft table, so the only
        // correct move is to stop.
        Ok(0) => protocol_abort("the node broker closed the channel"),
        Ok(n) => n,
        Err(e) => protocol_abort(&format!("recvmsg on a broker channel: {e}")),
    };
    match serde_json::from_slice::<Reply>(&buf[..got]) {
        Ok(reply) => Ok((reply, received)),
        Err(e) => protocol_abort(&format!("undecodable reply from the node broker: {e}")),
    }
}

/// Take a channel from the pool, opening a new one while under the cap.
fn acquire() -> io::Result<Lease> {
    loop {
        {
            let mut pool = POOL
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(fd) = pool.pop() {
                return Ok(lease(fd));
            }
            if LIVE.load(Ordering::SeqCst) < BROKER_CHANNELS_MAX {
                // Opening drops the pool lock: `channel.open` is a round
                // trip on the control channel and must not hold it.
                LIVE.fetch_add(1, Ordering::SeqCst);
                drop(pool);
                return match open_channel() {
                    Ok(fd) => Ok(lease(fd)),
                    Err(e) => {
                        LIVE.fetch_sub(1, Ordering::SeqCst);
                        Err(e)
                    }
                };
            }
            // At the cap: wait for a thread to give one back. Loud in
            // `doctor` (high water == cap), never silently unbounded.
            let (pool_again, timeout) = POOL_FREED
                .wait_timeout(pool, std::time::Duration::from_secs(5))
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if timeout.timed_out() && pool_again.is_empty() {
                log::warn!(
                    "all {BROKER_CHANNELS_MAX} broker channels have been in use for 5s — \
                     a verb is blocking longer than it should"
                );
            }
        }
    }
}

fn lease(fd: OwnedFd) -> Lease {
    let now = IN_USE.fetch_add(1, Ordering::SeqCst) + 1;
    HIGH_WATER.fetch_max(now, Ordering::SeqCst);
    Lease(Some(fd))
}

fn open_channel() -> io::Result<OwnedFd> {
    let (reply, mut fds) = call_control(&Verb::ChannelOpen, &[])?;
    match reply {
        Reply::Fds => {
            if fds.len() != 1 {
                protocol_abort("channel.open answered with something other than one descriptor");
            }
            Ok(fds.remove(0))
        }
        Reply::Failed { errno, message } => Err(reply_error(errno, message)),
        other => protocol_abort(&format!("unexpected reply to channel.open: {other:?}")),
    }
}

/// Tell the node broker that `shutdown_all` is done. After this the VM
/// broker issues no more verbs.
pub fn shutdown() -> io::Result<()> {
    let (reply, fds) = call_control(&Verb::Shutdown, &[])?;
    if !fds.is_empty() {
        protocol_abort("the shutdown reply carried descriptors");
    }
    match reply {
        Reply::Ok => Ok(()),
        Reply::Failed { errno, message } => Err(reply_error(errno, message)),
        other => protocol_abort(&format!("unexpected reply to shutdown: {other:?}")),
    }
}

/// Introduce a VM and every host path it is allowed to name.
///
/// This is where the shim's paths cross into the node broker, once, and
/// where `openat2` decides whether they may (`super::paths`). Calling it
/// before any disk is provisioned and before any bridge is touched is
/// what makes a refused path a `CreateVm` error with the offending index
/// named, rather than a half-built VM.
///
/// A no-op in an un-split process: there is no boundary to cross, and
/// the daemon then opens what it always opened, as root.
pub fn register_vm(vm_id: &str, config: &crate::control::VmConfig) -> io::Result<()> {
    if !is_split() {
        return Ok(());
    }
    let verb = Verb::VmRegister {
        vm_id: vm_id.to_string(),
        sandbox_id: config.sandbox_id.clone(),
        tree_id: config.network.as_ref().map(|n| n.cluster_id.clone()),
        backend: format!("{:?}", config.backend).to_lowercase(),
        shares: config
            .virtiofs
            .iter()
            .map(|s| super::ShareSpec {
                host_dir: s.host_dir.clone(),
                readonly: s.readonly,
            })
            .collect(),
        blocks: config
            .block_devices
            .iter()
            .map(|b| super::BlockSpec {
                host_path: b.host_path.clone(),
                readonly: b.readonly,
            })
            .collect(),
        // The etc-file volume sources the shim packs into an image
        // (`volumes_blk.rs`) migrate with `volume.open`'s call site.
        etc_volumes: Vec::new(),
        netns: config
            .network
            .as_ref()
            .and_then(|n| n.pod_netns.as_ref())
            .cloned(),
    };
    ok(&verb)?;
    // After the node broker accepted them, not before: a refused
    // registration must leave nothing behind to look up.
    remember_pins(vm_id, &verb);
    Ok(())
}

/// Forget a VM and let the node broker undo anything still held for it.
///
/// Idempotent, and deliberately not fatal on failure: this runs from
/// teardown, where the VM is already gone and the only thing a `?` would
/// achieve is skipping the rest of the teardown.
pub fn release_vm(vm_id: &str) {
    if !is_split() {
        return;
    }
    if let Err(e) = ok(&Verb::VmRelease {
        vm_id: vm_id.to_string(),
    }) {
        log::error!("vm.release({vm_id}): {e}");
    }
    forget_pins(vm_id);
}

/// Which of a registered VM's index spaces a pinned host path belongs
/// to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Pin {
    /// `shares` — `share.pin`, `share.remount_ro`, `virtiofsd.spawn`.
    Share,
    /// `blocks` — `disk.open`.
    Block,
    /// `etc_volumes` — `volume.open`.
    Volume,
}

/// Registered host paths, so a call site deep inside a `Vm` can name the
/// `(vm_id, index)` pair a verb takes.
///
/// The verbs still carry no path. What this table solves is a different
/// problem: `virtiofs.rs`, `block.rs` and `volumes_blk.rs` are reached
/// from `VmBuilder::build` and from `fork::restore_vm_inner`, which
/// reconstructs a VM out of a snapshot and has no VM id in scope at all.
/// Threading a broker id down through the builder, the `Vm`, the
/// snapshot format and the restore path would put the boundary's
/// vocabulary into four layers that have no other use for it, and would
/// still have nothing to thread on the restore side. `vm.register` saw
/// both halves once, so it remembers the mapping here and the lookup is
/// a local translation.
///
/// One path can belong to several live VMs — a hostPath two pods mount,
/// a fork still serving its source's share — so the value is a list.
/// Any survivor answers, because every entry pins the same inode; a
/// release removes only its own.
type PinTable = HashMap<(Pin, String), Vec<PinRef>>;

/// `(vm_id, index)` as a later verb takes it.
type PinRef = (String, u16);

static PINS: Mutex<Option<PinTable>> = Mutex::new(None);

fn pins<T>(f: impl FnOnce(&mut PinTable) -> T) -> T {
    let mut guard = PINS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f(guard.get_or_insert_with(HashMap::new))
}

fn remember_pins(vm_id: &str, verb: &Verb) {
    let Verb::VmRegister {
        shares,
        blocks,
        etc_volumes,
        ..
    } = verb
    else {
        return;
    };
    pins(|p| {
        let mut note = |kind: Pin, path: &str, idx: usize| {
            let slot = p.entry((kind, path.to_string())).or_default();
            let entry = (vm_id.to_string(), u16::try_from(idx).unwrap_or(u16::MAX));
            if !slot.contains(&entry) {
                slot.push(entry);
            }
        };
        for (i, s) in shares.iter().enumerate() {
            note(Pin::Share, &s.host_dir, i);
        }
        for (i, b) in blocks.iter().enumerate() {
            note(Pin::Block, &b.host_path, i);
        }
        for (i, v) in etc_volumes.iter().enumerate() {
            note(Pin::Volume, v, i);
        }
    });
}

fn forget_pins(vm_id: &str) {
    pins(|p| {
        p.retain(|_, slots| {
            slots.retain(|(id, _)| id != vm_id);
            !slots.is_empty()
        });
    });
}

/// The `(vm_id, index)` a host path was registered under, if any.
///
/// `None` is not an error: the VM broker's own images — scratch disks,
/// data disks, tree memory files, the erofs cache it wrote — are
/// `k7d`-owned under `/var/lib/k7d`, are deliberately never registered,
/// and are opened directly so the fork path stays verb-free (§4.5).
#[must_use]
pub fn pinned_as(kind: Pin, path: &std::path::Path) -> Option<PinRef> {
    if !is_split() {
        return None;
    }
    let key = path.to_string_lossy().into_owned();
    pins(|p| p.get(&(kind, key)).and_then(|v| v.first()).cloned())
}

/// Create (or re-policy) a tree's bridge and jail; returns the link
/// name the node broker derived from the id.
pub fn net_tree_create(tree_id: &str, egress: &crate::netjail::EgressPolicy) -> io::Result<String> {
    let verb = Verb::NetTreeCreate {
        tree_id: tree_id.to_string(),
        egress: egress.clone(),
    };
    let (reply, fds) = call(&verb, &[])?;
    if !fds.is_empty() {
        protocol_abort("net.tree_create answered with descriptors");
    }
    match reply {
        Reply::Tree { bridge } => Ok(bridge),
        Reply::Failed { errno, message } => Err(reply_error(errno, message)),
        other => protocol_abort(&format!("unexpected reply to net.tree_create: {other:?}")),
    }
}

/// Create one TAP per index and take their descriptors.
///
/// The descriptors come back in `indices` order, one per entry, and the
/// count is checked rather than trusted: a mismatch means the two halves
/// disagree about which device a descriptor is, which is not an error a
/// caller can do anything sensible with.
pub fn net_tap_create(
    tree_id: &str,
    indices: &[u32],
) -> io::Result<Vec<(super::TapInfo, OwnedFd)>> {
    let verb = Verb::NetTapCreate {
        tree_id: tree_id.to_string(),
        indices: indices.to_vec(),
    };
    let (reply, fds) = call(&verb, &[])?;
    match reply {
        Reply::Taps(infos) => {
            if infos.len() != indices.len() || fds.len() != indices.len() {
                protocol_abort(&format!(
                    "net.tap_create for {} index(es) answered with {} info(s) and {} \
                     descriptor(s)",
                    indices.len(),
                    infos.len(),
                    fds.len()
                ));
            }
            Ok(infos.into_iter().zip(fds).collect())
        }
        Reply::Failed { errno, message } => Err(reply_error(errno, message)),
        other => protocol_abort(&format!("unexpected reply to net.tap_create: {other:?}")),
    }
}

/// Re-open a registered host path through the pin the node broker made
/// of it at `vm.register`.
///
/// `None` means the path is not registered, which is the VM broker's own
/// image and is opened directly by the caller.
#[must_use]
pub fn open_pinned(kind: Pin, path: &std::path::Path) -> Option<io::Result<OwnedFd>> {
    let (vm_id, idx) = pinned_as(kind, path)?;
    let verb = match kind {
        Pin::Share => Verb::SharePin {
            vm_id,
            share_idx: idx,
        },
        Pin::Block => Verb::DiskOpen {
            vm_id,
            device_idx: idx,
        },
        Pin::Volume => Verb::VolumeOpen {
            vm_id,
            volume_idx: idx,
        },
    };
    Some(fds(&verb, 1).map(|mut got| got.remove(0)))
}

/// Hand the node broker a bound, listening vhost-user socket and have it
/// exec `virtiofsd` on it.
///
/// This is the one descriptor that travels the other way. virtiofsd
/// keeps its `--sandbox chroot` and its inherited capability set on the
/// root side, while the socket it serves is one the VM broker made in a
/// directory it owns — so the path the guest's FUSE traffic arrives on
/// never has to be a parameter the node broker resolves.
///
/// Returns the helper's pid and the pidfd to poll it with. Killing it is
/// [`Verb::HelperReap`]: the child is root's, and the VM broker has no
/// `CAP_KILL`.
pub fn virtiofsd_spawn(
    vm_id: &str,
    share_idx: u16,
    tag: &str,
    tree: Option<String>,
    listener: RawFd,
) -> io::Result<(u32, OwnedFd)> {
    let verb = Verb::VirtiofsdSpawn {
        vm_id: vm_id.to_string(),
        share_idx,
        tag: tag.to_string(),
        tree,
    };
    let (reply, mut got) = call(&verb, &[listener])?;
    match reply {
        Reply::Spawned { pid } => {
            if got.len() != 1 {
                protocol_abort(&format!(
                    "virtiofsd.spawn answered with {} descriptors, want the pidfd alone",
                    got.len()
                ));
            }
            Ok((pid, got.remove(0)))
        }
        Reply::Failed { errno, message } => Err(reply_error(errno, message)),
        other => protocol_abort(&format!("unexpected reply to virtiofsd.spawn: {other:?}")),
    }
}

// --- fc.* -------------------------------------------------------------

/// Introduce one more backing file and take the index `fc.spawn` names
/// it by.
///
/// The second half of §4.4's images gap. Most of a Firecracker VM's
/// files were never in the shim's `VmConfig` — scratch and data disks
/// the VM broker made at run time, erofs images it built, a tree
/// member's exported `vmstate`/`memory.bin`, the installer's guest pair
/// — and they have to be hard-linked and `chown`ed into a jail, which
/// is root's work on a name the VM broker chose. They cross here, once,
/// through the same `paths::validate` the only other path-carrying
/// verb uses.
pub fn fc_register_disk(vm_id: &str, path: &std::path::Path, writable: bool) -> io::Result<u16> {
    let verb = Verb::VmRegisterDisk {
        vm_id: vm_id.to_string(),
        path: path.to_string_lossy().into_owned(),
        writable,
    };
    let (reply, fds) = call(&verb, &[])?;
    if !fds.is_empty() {
        protocol_abort("vm.register_disk answered with descriptors");
    }
    match reply {
        Reply::Index { index } => Ok(index),
        Reply::Failed { errno, message } => Err(reply_error(errno, message)),
        other => protocol_abort(&format!("unexpected reply to vm.register_disk: {other:?}")),
    }
}

/// `eth0`'s IPv4 addresses inside a pod's CNI namespace.
///
/// Un-split this is `nsenter` in-process, as it always was; split it is
/// a verb, because `setns` is `CAP_SYS_ADMIN` even to read.
pub fn pod_ip(netns: &std::path::Path) -> io::Result<Vec<std::net::Ipv4Addr>> {
    if !is_split() {
        return crate::netns::link_addrs_v4(netns, "eth0")
            .map_err(|e| io::Error::other(e.to_string()));
    }
    let verb = Verb::NetPodIp {
        netns: netns.to_string_lossy().into_owned(),
    };
    let (reply, fds) = call(&verb, &[])?;
    if !fds.is_empty() {
        protocol_abort("net.pod_ip answered with descriptors");
    }
    match reply {
        Reply::PodIp { addrs } => addrs
            .iter()
            .map(|a| {
                a.parse::<std::net::Ipv4Addr>()
                    .map_err(|e| io::Error::other(format!("net.pod_ip returned {a:?}: {e}")))
            })
            .collect(),
        Reply::Failed { errno, message } => Err(reply_error(errno, message)),
        other => protocol_abort(&format!("unexpected reply to net.pod_ip: {other:?}")),
    }
}

/// What a `fc.spawn` hands back: the jail's identity plus the two
/// descriptors everything else about the VM is reached through.
pub struct Spawned {
    /// `<vm_dir>` as a real path. Only ever passed on to a third
    /// process (see [`Reply::FcSpawned`]); this one opens through
    /// `dir`.
    pub vm_dir: std::path::PathBuf,
    /// Firecracker pid in the host pid namespace.
    pub pid: u32,
    /// uid the jailer dropped it to.
    pub uid: u32,
    /// Firecracker's pidfd. The VM broker polls it and cannot kill
    /// through it — different uid, no `CAP_KILL`; `fc.kill` is the verb.
    pub pidfd: OwnedFd,
    /// `O_PATH|O_DIRECTORY` of the jail's `<vm_dir>`, through which
    /// `/proc/self/fd/<n>/root/run/firecracker.socket` and
    /// `/proc/self/fd/<n>/snap/…` resolve without the 0700 ancestors
    /// being consulted at all.
    pub dir: OwnedFd,
}

/// Stage a jail and start the jailed Firecracker in it.
pub fn fc_spawn(verb: &Verb) -> io::Result<Spawned> {
    let (reply, mut got) = call(verb, &[])?;
    match reply {
        Reply::FcSpawned { vm_dir, pid, uid } => {
            if got.len() != 2 {
                protocol_abort(&format!(
                    "fc.spawn answered with {} descriptor(s), want the pidfd and the jail dir",
                    got.len()
                ));
            }
            let dir = got.remove(1);
            let pidfd = got.remove(0);
            Ok(Spawned {
                vm_dir: std::path::PathBuf::from(vm_dir),
                pid,
                uid,
                pidfd,
                dir,
            })
        }
        Reply::Failed { errno, message } => Err(reply_error(errno, message)),
        other => protocol_abort(&format!("unexpected reply to fc.spawn: {other:?}")),
    }
}

/// One jail the node broker still holds, with the two descriptors a
/// rebuild needs (`K7D_VM_BROKER_RESTART`).
#[derive(Debug)]
pub struct HeldJail {
    /// What the node broker knows about it.
    pub record: super::FcJailRecord,
    /// Firecracker's pidfd (see [`Spawned::pidfd`]).
    pub pidfd: OwnedFd,
    /// `O_PATH|O_DIRECTORY` of `<vm_dir>` (see [`Spawned::dir`]).
    pub dir: OwnedFd,
}

/// Every jail the node broker held over from the previous VM broker,
/// page by page. Empty when this is the first generation, or when the
/// node broker released everything (the flag was off, or nothing
/// qualified).
pub fn fc_list() -> io::Result<Vec<HeldJail>> {
    let mut held = Vec::new();
    for page in 0.. {
        let verb = Verb::FcList { page };
        let (reply, mut got) = call(&verb, &[])?;
        let (records, more) = match reply {
            Reply::FcList { records, more } => (records, more),
            Reply::Failed { errno, message } => return Err(reply_error(errno, message)),
            other => protocol_abort(&format!("unexpected reply to fc.list: {other:?}")),
        };
        if got.len() != 2 * records.len() {
            protocol_abort(&format!(
                "fc.list page {page} answered {} record(s) with {} descriptor(s), want two each",
                records.len(),
                got.len()
            ));
        }
        for record in records.into_iter().rev() {
            let dir = got.pop().expect("counted");
            let pidfd = got.pop().expect("counted");
            held.push(HeldJail { record, pidfd, dir });
        }
        if !more {
            break;
        }
    }
    held.sort_by(|a, b| a.record.vm_id.cmp(&b.record.vm_id));
    Ok(held)
}

/// Dial one of a jail's sockets through the node broker.
///
/// The documented fallback, not the happy path: both sockets are
/// normally reachable by name through the `<vm_dir>` descriptor, and an
/// agent connection that went through a verb could not be redialled
/// without one (`AgentClient::reconnect_fc`). Used when the direct
/// connect is refused, which is the case this repairs — the node broker
/// re-groups and re-modes the socket before connecting.
pub fn fc_connect(vm_id: &str, which: super::FcSocket) -> io::Result<OwnedFd> {
    let verb = Verb::FcConnect {
        vm_id: vm_id.to_string(),
        which,
    };
    Ok(fds(&verb, 1)?.remove(0))
}

/// One verb whose reply is [`Reply::Ok`] and nothing else.
pub fn ok(verb: &Verb) -> io::Result<()> {
    let (reply, fds) = call(verb, &[])?;
    if !fds.is_empty() {
        protocol_abort(&format!("{verb:?} answered with descriptors"));
    }
    match reply {
        Reply::Ok => Ok(()),
        Reply::Failed { errno, message } => Err(reply_error(errno, message)),
        other => protocol_abort(&format!("unexpected reply to {verb:?}: {other:?}")),
    }
}

/// One verb whose reply is exactly `want` descriptors.
pub fn fds(verb: &Verb, want: usize) -> io::Result<Vec<OwnedFd>> {
    let (reply, received) = call(verb, &[])?;
    match reply {
        Reply::Fds => {
            if received.len() != want {
                protocol_abort(&format!(
                    "{verb:?} answered with {} descriptors, want {want}",
                    received.len()
                ));
            }
            Ok(received)
        }
        Reply::Failed { errno, message } => Err(reply_error(errno, message)),
        other => protocol_abort(&format!("unexpected reply to {verb:?}: {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A process that never called `start()` — the shim, this test
    /// binary — is not split, so every privileged call site takes the
    /// direct path it takes today.
    #[test]
    fn a_process_without_a_control_channel_is_not_split() {
        assert!(!is_split());
        let err = call_control(&Verb::Shutdown, &[]).expect_err("no channel");
        assert!(
            err.to_string().contains("no broker control channel"),
            "{err}"
        );
    }

    /// The counters start empty and the cap is what `doctor` reports.
    #[test]
    fn channel_stats_report_the_cap() {
        let (_, _, cap) = channel_stats();
        assert_eq!(cap, BROKER_CHANNELS_MAX);
    }

    /// The fuzz double refuses without needing a peer at all, which is
    /// what lets `control_request` drive `Daemon::handle` in a process
    /// that has no node broker and no capabilities.
    #[test]
    fn deny_all_refuses_without_a_channel() {
        // A child process: `deny_all` is deliberately irreversible, so
        // flipping it here would poison every other test in the binary.
        // SAFETY: the child only calls `call`, `_exit` and what they
        // reach; nothing else in this binary holds a lock it needs.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", io::Error::last_os_error());
        if pid == 0 {
            deny_all();
            let out = call(&Verb::FcList { page: 0 }, &[]);
            let code = match out {
                Ok((Reply::Failed { errno, .. }, _)) if errno == libc::EPERM => 0,
                _ => 1,
            };
            // SAFETY: _exit is async-signal-safe and never returns.
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        // SAFETY: `pid` is this process's child and `status` is valid.
        unsafe { libc::waitpid(pid, &raw mut status, 0) };
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "deny_all must refuse every verb with EPERM (status {status:#x})"
        );
    }
}
