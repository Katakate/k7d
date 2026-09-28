//! The root half: a closed verb table, one peer, no listening socket.
//!
//! The node broker is `main()`'s parent after [`super::start`]. It keeps
//! the capability-bounding set and its own seccomp list, and the only thing it
//! ever reads is a [`Verb`] from the VM broker over a socketpair that
//! has no path and no other peer. There is deliberately no `exec` verb,
//! no `mount(source, target)` verb, no `chown` verb and no `write_file`
//! verb: each of those is a capability with a free parameter, and a
//! compromised VM broker that can send `["nft", "-f", "-"]` with its own
//! stdin has `CAP_NET_ADMIN` whatever the process boundary says.
//!
//! What it holds is the [`VmTable`]: per registered VM, the `O_PATH`
//! descriptors that `vm.register` validated and pinned, and the record
//! of what has to be undone. That table is what makes `vm.release`
//! total, and it is why a VM broker crash no longer leaks — §9.2's
//! watcher walks it before exiting non-zero.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::paths::{self, Class, Pinned};
use super::{protocol_abort, send_reply, Reply, ShareSpec, Verb};
use crate::seqmsg::{self, MESSAGE_MAX};

/// Most VM-broker respawns in [`RESPAWN_WINDOW`] before the node broker
/// gives up and exits non-zero (`K7D_VM_BROKER_RESTART`). A VM broker that
/// keeps dying is a bug systemd should see, not a loop that hides it.
pub const RESPAWN_MAX: usize = 3;
/// Window for [`RESPAWN_MAX`].
pub const RESPAWN_WINDOW: Duration = Duration::from_secs(60);
/// A successor that dies this soon after its exec did not start: the
/// node broker exits non-zero at once rather than trying twice more.
pub const RESPAWN_FAST_FAIL: Duration = Duration::from_secs(5);

/// How the node broker re-forks a VM broker that died
/// (`K7D_VM_BROKER_RESTART=on`). `None` is §9.2: release everything and
/// exit non-zero.
#[derive(Debug, Clone)]
pub struct RespawnPolicy {
    /// Delegated cgroup subtree the successor joins before dropping
    /// privileges — the one [`super::start`] prepared, passed by name
    /// because the successor is on the other side of an `execve`.
    pub subtree: std::path::PathBuf,
    /// This process's own argv, re-used for the successor so `--socket`
    /// and friends mean the same thing to it.
    pub args: Vec<String>,
}

/// Set by the `SIGTERM`/`SIGINT` handler. A VM broker that exits while
/// this is set is the orderly path (§9.4), so the node broker exits 0;
/// one that exits while it is clear is a crash, so it exits non-zero and
/// lets systemd restart the pair (§9.2).
static DRAINING: AtomicBool = AtomicBool::new(false);

/// The VM broker's pid, for the signal handler (which may only touch
/// atomics and async-signal-safe calls).
static VM_BROKER_PID: AtomicU32 = AtomicU32::new(0);

/// Everything the node broker holds on one VM's behalf.
#[derive(Debug)]
struct VmEntry {
    sandbox_id: Option<String>,
    tree_id: Option<String>,
    backend: String,
    shares: Vec<ShareSpec>,
    /// Pinned share roots, parallel to `shares`.
    share_fds: Vec<Pinned>,
    /// Pinned virtio-blk backing files, in device order. Append-only:
    /// `vm.register_disk` puts the VM broker's own images here too, so
    /// an index handed out once means the same file forever.
    block_fds: Vec<Pinned>,
    /// Whether each block is opened read-write.
    block_writable: Vec<bool>,
    /// How many of `block_fds` came from `vm.register`. Everything past
    /// it arrived later through `vm.register_disk` and is deliberately
    /// **not** part of the body a re-registration has to match.
    registered_blocks: usize,
    /// Host path of each entry in `block_fds`, so `vm.register_disk` is
    /// idempotent for a path it has already seen.
    block_paths: Vec<String>,
    /// Whether the entry exists only because `vm.register_disk` created
    /// it — a fork child or a resumed VM the shim never registered. Such
    /// an entry is released with its jail rather than with a `StopVm`
    /// nothing will send for it.
    auto_created: bool,
    /// Pinned hostPath sources for etc-file volumes.
    volume_fds: Vec<Pinned>,
    /// Pinned pod netns handle, when the VM has one.
    netns_fd: Option<Pinned>,
    /// Shares this VM's `share.remount_ro` bind-mounted and therefore
    /// owes a `umount2`.
    remounted: HashSet<u16>,
}

impl VmEntry {
    /// Whether a re-registration is the same request. Idempotency is
    /// what lets a shim retry `CreateVm`; a *different* body for a live
    /// id is `EEXIST`, because silently re-pinning would let a caller
    /// swap the paths of a VM that is already running.
    fn matches(&self, other: &Self) -> bool {
        self.sandbox_id == other.sandbox_id
            && self.tree_id == other.tree_id
            && self.backend == other.backend
            && self.shares == other.shares
            // Only the registration-time prefix: a live VM that has
            // since had disks appended still matches the `CreateVm` a
            // shim is retrying.
            && self.block_writable[..self.registered_blocks] == other.block_writable[..]
            && self.share_fds.len() == other.share_fds.len()
            && self.registered_blocks == other.block_fds.len()
            && self.volume_fds.len() == other.volume_fds.len()
            && self.netns_fd.is_some() == other.netns_fd.is_some()
    }
}

static VM_TABLE: Mutex<Option<HashMap<String, VmEntry>>> = Mutex::new(None);

fn table<T>(f: impl FnOnce(&mut HashMap<String, VmEntry>) -> T) -> T {
    let mut guard = VM_TABLE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f(guard.get_or_insert_with(HashMap::new))
}

/// One tree's host networking, held on the node broker's side.
///
/// The VM broker keeps a mirror of this — the same bridge name, the
/// same `(vm_index, ip, mac)` entries — because every mutation of it is
/// a verb, so the two cannot drift. What only exists here is the part
/// that needs `CAP_NET_ADMIN`: the `ClusterNetwork`'s nft jail guard and
/// the `TapDevice`s themselves.
///
/// The node broker keeps its copy of each TAP descriptor rather than
/// closing it after the hand-over. A TAP that is not `IFF_PERSIST` dies
/// with the last descriptor on it, and the Firecracker hand-over
/// (`net.tap_detach`) happens long after `net.tap_create` — a node
/// broker that had dropped its copy would have to `TUNSETIFF` its way
/// back onto a device the VM broker still holds, which answers `EBUSY`
/// on a single-queue TAP. Holding it also means a VM broker that is
/// `SIGKILL`ed leaves the link for `release_all` to delete rather than
/// half-deleting it under the bridge.
struct TreeRecord {
    /// Dropped after `taps`: the TAPs are enslaved to this bridge.
    net: crate::network::ClusterNetwork,
    taps: HashMap<u32, crate::network::TapDevice>,
    /// Which jail uid each TAP was handed to (`net.tap_detach`). The
    /// only link the node broker has from a TAP to a VM: the VM table
    /// knows `tree_id`, not `vm_index`, so this is what lets the restart
    /// path keep a survivor's TAP and delete its neighbours' (`K7D_VM_BROKER_RESTART`).
    detached_to: HashMap<u32, u32>,
}

impl Drop for TreeRecord {
    fn drop(&mut self) {
        // Field order would drop `net` first. The bridge must outlive
        // the links on it, or `ip link delete <tap>` races the bridge's
        // own teardown and logs a failure for work the kernel already
        // did.
        self.taps.clear();
    }
}

static TREE_TABLE: Mutex<Option<HashMap<String, TreeRecord>>> = Mutex::new(None);

fn trees<T>(f: impl FnOnce(&mut HashMap<String, TreeRecord>) -> T) -> T {
    let mut guard = TREE_TABLE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f(guard.get_or_insert_with(HashMap::new))
}

fn unknown_tree(tree_id: &str) -> Reply {
    Reply::failed(
        libc::ENOENT,
        format!("tree {tree_id} has no bridge — net.tree_create must come first"),
    )
}

fn string_failure(what: &str, e: &str) -> Reply {
    Reply::failed(0, format!("{what}: {e}"))
}

/// Serve the VM broker until it is gone. Never returns.
///
/// `respawn` is `Some` when `K7D_VM_BROKER_RESTART` is on: a VM broker
/// that dies is then re-exec'd and handed the standalone Firecracker
/// sandboxes (`K7D_VM_BROKER_RESTART`) instead of taking the node broker down.
pub fn main(control: OwnedFd, vm_pid: u32, respawn: Option<RespawnPolicy>) -> ! {
    // Single-threaded here too, so the logger's locks are safe to take.
    env_logger::init();
    VM_BROKER_PID.store(vm_pid, Ordering::SeqCst);
    log::info!(
        "k7d node broker (pid {}) serving the VM broker (pid {vm_pid}) over a SOCK_SEQPACKET \
         socketpair; verb table only, no listening socket{}",
        std::process::id(),
        if respawn.is_some() {
            "; K7D_VM_BROKER_RESTART=on — a crashed VM broker is re-forked and its standalone \
             Firecracker sandboxes survive it"
        } else {
            ""
        }
    );
    install_signal_handlers();
    let (tx, rx) = mpsc::channel();
    watch_vm_broker(vm_pid, respawn, tx);
    if let Err(e) = hand_runtime_dir_to_vm_broker() {
        fatal(&format!("prepare the runtime directory: {e}"));
    }
    sweep_orphans();
    match crate::seccomp::install_for_node_broker() {
        Ok(mode) => log::info!("node broker seccomp mode: {mode:?}"),
        Err(e) => fatal(&format!("seccomp: {e}")),
    }
    serve(control, &rx)
}

/// systemd's `KillMode=control-group` signals all three processes. The
/// node broker is the unit's main pid, so unlike the helper spawner it
/// *acts* on the signal: it forwards it and then keeps serving verbs,
/// because the VM broker's `shutdown_all` issues `vm.release` and
/// friends on its way out and a node broker that had already exited
/// would turn an orderly stop into a leak.
extern "C" fn on_signal(_sig: libc::c_int) {
    DRAINING.store(true, Ordering::SeqCst);
    let pid = VM_BROKER_PID.load(Ordering::SeqCst);
    if pid != 0 {
        // SAFETY: kill(2) with a pid this process forked and has not
        // reaped; async-signal-safe.
        unsafe {
            libc::kill(
                libc::pid_t::try_from(pid).unwrap_or(libc::pid_t::MAX),
                libc::SIGTERM,
            )
        };
    }
}

fn install_signal_handlers() {
    // SAFETY: `on_signal` stores to an atomic and calls `kill`, both
    // async-signal-safe.
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as libc::sighandler_t);
    }
}

/// Release everything and exit when the VM broker goes — or, under
/// `K7D_VM_BROKER_RESTART`, release what cannot survive and re-fork.
///
/// The asymmetry with the pre-seccomp helper spawner's `watch_spawner` is deliberate: a dead
/// spawner leaves the daemon unable to *do* anything, while a dead VM
/// broker leaves the node broker holding TAPs, nft tables, mounts and
/// Firecracker pids that nothing else knows about. Releasing them here
/// is the only place that knowledge exists, and exiting non-zero is what
/// makes systemd start a clean pair instead of leaving a half-live unit.
///
/// This thread is created **before** the node broker's seccomp filter
/// is installed and so never carries it (`seccompiler::apply_filter` is
/// per-thread, no `TSYNC`); the successor it execs installs the VM
/// broker's own filter after its uid drop, as the first generation does.
fn watch_vm_broker(first_pid: u32, respawn: Option<RespawnPolicy>, tx: mpsc::Sender<OwnedFd>) {
    let first_pidfd = match seqmsg::pidfd_open(first_pid) {
        Ok(fd) => fd,
        Err(e) => fatal(&format!(
            "pidfd_open on the VM broker (pid {first_pid}): {e}"
        )),
    };
    std::thread::Builder::new()
        .name("k7d-vm-broker-watch".into())
        .spawn(move || {
            let mut vm_pid = first_pid;
            let mut pidfd = first_pidfd;
            let mut epoch = 0u32;
            let mut spawned_at: Option<Instant> = None;
            let mut respawns: VecDeque<Instant> = VecDeque::new();
            loop {
                let how = wait_for_death(&pidfd, vm_pid);
                VM_BROKER_PID.store(0, Ordering::SeqCst);
                let who = format!("VM broker generation {epoch} (pid {vm_pid})");
                // DRAINING wins over everything else (§9.4): `systemctl
                // stop` and `restart` are the orderly path whatever the
                // flag says, so no respawn and exit 0.
                if DRAINING.load(Ordering::SeqCst) {
                    let released = release_all();
                    log::info!("{who} {how} during shutdown; released {released} registered VM(s)");
                    std::process::exit(0);
                }
                let Some(policy) = &respawn else {
                    let released = release_all();
                    log::error!(
                        "{who} is gone ({how}) — released {released} registered VM(s) and \
                         exiting so systemd starts a clean pair"
                    );
                    eprintln!("k7d: VM broker pid {vm_pid} {how}; exiting");
                    std::process::exit(1);
                };
                if let Some(refusal) = refuse_respawn(spawned_at, &mut respawns) {
                    let released = release_all();
                    log::error!(
                        "{who} is gone ({how}); {refusal} — released {released} registered \
                         VM(s) and exiting so systemd sees the failure"
                    );
                    eprintln!("k7d: VM broker pid {vm_pid} {how}; {refusal}; exiting");
                    std::process::exit(1);
                }
                let (kept, released) = release_non_survivors();
                epoch += 1;
                log::warn!(
                    "{who} is gone ({how}) — kept {kept} standalone Firecracker sandbox(es) for \
                     its successor, released {released} registered VM(s); re-forking as \
                     generation {epoch}"
                );
                let successor = match respawn_vm_broker(policy, epoch) {
                    Ok(s) => s,
                    Err(e) => {
                        let released = release_all();
                        log::error!(
                            "re-forking the VM broker as generation {epoch}: {e} — released \
                             {released} VM(s) and exiting so systemd sees the failure"
                        );
                        eprintln!("k7d: re-fork the VM broker: {e}; exiting");
                        std::process::exit(1);
                    }
                };
                vm_pid = successor.pid;
                pidfd = successor.pidfd;
                let now = Instant::now();
                spawned_at = Some(now);
                respawns.push_back(now);
                VM_BROKER_PID.store(vm_pid, Ordering::SeqCst);
                // A SIGTERM that landed while no VM broker existed set
                // DRAINING with nobody to forward to; forward it now so
                // the stop stays orderly.
                if DRAINING.load(Ordering::SeqCst) {
                    // SAFETY: kill(2) on a child this thread just spawned
                    // and has not reaped.
                    unsafe {
                        libc::kill(
                            libc::pid_t::try_from(vm_pid).unwrap_or(libc::pid_t::MAX),
                            libc::SIGTERM,
                        )
                    };
                }
                log::info!("VM broker generation {epoch} is pid {vm_pid}");
                if tx.send(successor.node_end).is_err() {
                    fatal("the control-channel loop is gone; nothing can serve the successor");
                }
            }
        })
        .expect("spawn the VM broker watchdog thread");
}

/// Block until the VM broker at `pidfd` is dead and reaped; say how.
fn wait_for_death(pidfd: &OwnedFd, vm_pid: u32) -> String {
    loop {
        match seqmsg::pidfd_exited(pidfd.as_fd(), 1000) {
            Ok(true) => break,
            Ok(false) => {}
            Err(e) => log::error!("VM broker watchdog: poll: {e}"),
        }
    }
    let mut status = 0;
    // SAFETY: the VM broker is this process's child; `status` is valid.
    unsafe {
        libc::waitpid(
            libc::pid_t::try_from(vm_pid).unwrap_or(libc::pid_t::MAX),
            &raw mut status,
            0,
        )
    };
    if libc::WIFSIGNALED(status) {
        format!("killed by signal {}", libc::WTERMSIG(status))
    } else {
        format!("exited {}", libc::WEXITSTATUS(status))
    }
}

/// The two ways a respawn is refused (`K7D_VM_BROKER_RESTART`): the previous
/// successor died within [`RESPAWN_FAST_FAIL`] of its exec — it never
/// started, and trying again would only prove it twice more — or there
/// have already been [`RESPAWN_MAX`] respawns inside [`RESPAWN_WINDOW`].
/// Both become a non-zero exit systemd sees, never a loop.
fn refuse_respawn(spawned_at: Option<Instant>, respawns: &mut VecDeque<Instant>) -> Option<String> {
    if let Some(at) = spawned_at {
        let lived = at.elapsed();
        if lived < RESPAWN_FAST_FAIL {
            return Some(format!(
                "the successor died {lived:?} after its exec (under {RESPAWN_FAST_FAIL:?}), so \
                 it never started"
            ));
        }
    }
    let now = Instant::now();
    while respawns
        .front()
        .is_some_and(|t| now.duration_since(*t) > RESPAWN_WINDOW)
    {
        respawns.pop_front();
    }
    if respawns.len() >= RESPAWN_MAX {
        return Some(format!(
            "already re-forked it {} times in the last {RESPAWN_WINDOW:?} (limit {RESPAWN_MAX})",
            respawns.len()
        ));
    }
    None
}

/// A freshly exec'd successor VM broker.
struct Successor {
    pid: u32,
    pidfd: OwnedFd,
    /// The node broker's end of its control channel.
    node_end: OwnedFd,
}

/// Re-exec this binary as generation `epoch` of the VM broker.
///
/// `fork`+`execve` and not a bare `fork`: this process is multi-threaded
/// by now, and a forked copy of it would inherit the verb-channel
/// threads' locks and the node broker's seccomp filter. The exec'd
/// image re-enters [`super::start`], which sees [`super::RESPAWN_FLAG`]
/// and drops privileges the way the first generation did. It is still
/// root at that point because it has this process's bounding set, which
/// is exactly what `drop_privileges` needs and then destroys.
///
/// Through [`crate::spawner::command`] like every other exec in the
/// crate: the node broker has no spawner attached, so this is the
/// in-process path (its own filter allows `execve`), and the control
/// socket reaches the successor the way `virtiofsd --fd 3` gets its
/// listener — `dup2`ed onto a fixed number between fork and exec, the
/// only descriptor without `CLOEXEC` in the new image.
fn respawn_vm_broker(policy: &RespawnPolicy, epoch: u32) -> io::Result<Successor> {
    let (node_end, vm_end) = seqmsg::socketpair()?;
    let flag_prefix = format!("{}=", super::RESPAWN_FLAG);
    let mut command = crate::spawner::command("/proc/self/exe");
    command
        .args(
            policy
                .args
                .iter()
                .skip(1)
                .filter(|a| !a.starts_with(&flag_prefix)),
        )
        .arg(format!(
            "{}={}:{epoch}:{}",
            super::RESPAWN_FLAG,
            super::RESPAWN_CONTROL_FD,
            policy.subtree.display()
        ))
        .fd(super::RESPAWN_CONTROL_FD, vm_end);
    let child = command.spawn()?;
    let pid = child.id();
    let pidfd = child.pidfd_dup()?;
    // The watcher reaps with `waitpid`, as it does the first
    // generation; dropping an in-process `Child` neither waits nor
    // kills.
    drop(child);
    Ok(Successor {
        pid,
        pidfd,
        node_end,
    })
}

/// `/run/k7d` is created by `RuntimeDirectory=k7d` and therefore owned by
/// root, because the unit has no `User=`. The VM broker binds
/// `k7d.sock` in it, so ownership has to move before it tries.
fn hand_runtime_dir_to_vm_broker() -> Result<(), String> {
    let dir = std::path::Path::new(crate::control::DEFAULT_SOCKET)
        .parent()
        .ok_or_else(|| format!("{} has no parent", crate::control::DEFAULT_SOCKET))?
        .to_path_buf();
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    let uid = super::lookup_uid(super::VM_BROKER_USER)?;
    let gid = super::lookup_gid(super::VM_BROKER_USER)?;
    super::chown(&dir, uid, gid)?;
    Ok(())
}

/// Whether a transport error means the peer is gone rather than that
/// the protocol broke. A VM broker that was `SIGKILL`ed mid-request
/// leaves its channels answering exactly this, and the watcher — not
/// the thread that happened to be replying — owns what happens next.
fn peer_gone(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset | io::ErrorKind::NotConnected
    )
}

/// Control-channel loop. `channel.open` spawns a thread per channel;
/// everything else on this channel is a protocol error.
///
/// When the VM broker goes, the watcher decides: it either exits the
/// process (§9.2, the flag off, a respawn refused) or re-forks and
/// sends the successor's control end down `successors`, and this loop
/// carries on with that one (`K7D_VM_BROKER_RESTART`).
fn serve(mut control: OwnedFd, successors: &mpsc::Receiver<OwnedFd>) -> ! {
    let mut buf = vec![0u8; MESSAGE_MAX];
    loop {
        let mut fds = Vec::new();
        let got = match seqmsg::recv_msg(control.as_fd(), &mut buf, &mut fds) {
            Ok(0) => {
                control = next_control(successors);
                continue;
            }
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if peer_gone(&e) => {
                control = next_control(successors);
                continue;
            }
            Err(e) => protocol_abort(&format!("recvmsg on the control channel: {e}")),
        };
        let verb: Verb = match serde_json::from_slice(&buf[..got]) {
            Ok(v) => v,
            Err(e) => protocol_abort(&format!("undecodable control request: {e}")),
        };
        let (reply, reply_fds) = match verb {
            Verb::ChannelOpen => open_channel(),
            Verb::Shutdown => {
                let released = release_all();
                log::info!(
                    "the VM broker finished shutdown_all; released {released} registered VM(s)"
                );
                let _ = send_reply(control.as_fd(), &Reply::Ok, &[]);
                std::process::exit(0);
            }
            Verb::RestartHello { epoch } => {
                log::info!(
                    "VM broker generation {epoch} (pid {}) is talking on the control channel; \
                     {} Firecracker jail(s) held for it to re-adopt",
                    VM_BROKER_PID.load(Ordering::SeqCst),
                    super::jail::count()
                );
                (Reply::Ok, Vec::new())
            }
            other => (
                Reply::failed(
                    libc::EPROTO,
                    format!("{other:?} does not travel on the control channel"),
                ),
                Vec::new(),
            ),
        };
        match send_reply(control.as_fd(), &reply, &reply_fds) {
            Ok(()) => {}
            Err(e) if peer_gone(&e) => {
                log::warn!("the VM broker went away before its control reply: {e}");
            }
            Err(e) => protocol_abort(&format!("sendmsg on the control channel: {e}")),
        }
    }
}

/// The VM broker closed the control channel. Wait for the watcher's
/// verdict: a successor's end, or the process exiting under us.
fn next_control(successors: &mpsc::Receiver<OwnedFd>) -> OwnedFd {
    log::info!("the VM broker closed the control channel");
    match successors.recv_timeout(Duration::from_secs(60)) {
        Ok(fd) => {
            log::info!("serving the successor VM broker on a fresh control channel");
            fd
        }
        Err(_) => {
            fatal("the VM broker closed the control channel and no successor arrived within 60s")
        }
    }
}

/// Make a verb channel and serve it on a thread of its own.
fn open_channel() -> (Reply, Vec<OwnedFd>) {
    let (ours, theirs) = match seqmsg::socketpair() {
        Ok(pair) => pair,
        Err(e) => {
            return (
                Reply::failed(
                    e.raw_os_error().unwrap_or(0),
                    format!("socketpair for a verb channel: {e}"),
                ),
                Vec::new(),
            )
        }
    };
    let spawned = std::thread::Builder::new()
        .name("k7d-broker-channel".into())
        .spawn(move || channel_loop(&ours));
    match spawned {
        Ok(_) => (Reply::Fds, vec![theirs]),
        Err(e) => (
            Reply::failed(0, format!("spawn a channel thread: {e}")),
            Vec::new(),
        ),
    }
}

/// One channel, one thread, one request at a time: no request ids, no
/// reordering, no head-of-line blocking between threads.
fn channel_loop(sock: &OwnedFd) {
    let mut buf = vec![0u8; MESSAGE_MAX];
    loop {
        let mut fds = Vec::new();
        let got = match seqmsg::recv_msg(sock.as_fd(), &mut buf, &mut fds) {
            // The VM broker dropped this channel (a worker thread ended
            // and the pool shrank, or the process is gone). Either way
            // this thread has nothing left to serve.
            Ok(0) => return,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if peer_gone(&e) => return,
            Err(e) => protocol_abort(&format!("recvmsg on a verb channel: {e}")),
        };
        let verb: Verb = match serde_json::from_slice(&buf[..got]) {
            Ok(v) => v,
            Err(e) => protocol_abort(&format!("undecodable verb: {e}")),
        };
        let (reply, reply_fds) = dispatch(verb, fds);
        match send_reply(sock.as_fd(), &reply, &reply_fds) {
            Ok(()) => {}
            // The VM broker died while this verb ran. Whatever the verb
            // built is in the tables, and the watcher's release pass —
            // or the successor's `fc.list` — is what finds it there.
            Err(e) if peer_gone(&e) => return,
            Err(e) => protocol_abort(&format!("sendmsg on a verb channel: {e}")),
        }
    }
}

/// The closed verb table.
fn dispatch(verb: Verb, fds: Vec<OwnedFd>) -> (Reply, Vec<OwnedFd>) {
    match verb {
        Verb::ChannelOpen | Verb::Shutdown => (
            Reply::failed(
                libc::EPROTO,
                "channel.open and shutdown travel on the control channel only".to_string(),
            ),
            Vec::new(),
        ),

        Verb::VmRegister {
            vm_id,
            sandbox_id,
            tree_id,
            backend,
            shares,
            blocks,
            etc_volumes,
            netns,
        } => (
            register(
                vm_id,
                sandbox_id,
                tree_id,
                backend,
                shares,
                &blocks,
                &etc_volumes,
                netns.as_deref(),
            ),
            Vec::new(),
        ),
        Verb::VmRegisterDisk {
            vm_id,
            path,
            writable,
        } => (register_disk(&vm_id, &path, writable), Vec::new()),
        Verb::VmRelease { vm_id } => (release(&vm_id), Vec::new()),

        Verb::SharePin { vm_id, share_idx } => pin_share(&vm_id, share_idx),
        Verb::ShareRemountRo { vm_id, share_idx } => (remount_ro(&vm_id, share_idx), Vec::new()),
        Verb::ShareUmount { vm_id, share_idx } => (umount(&vm_id, share_idx), Vec::new()),
        Verb::DiskOpen { vm_id, device_idx } => open_disk(&vm_id, device_idx),
        Verb::VolumeOpen { vm_id, volume_idx } => open_volume(&vm_id, volume_idx),

        Verb::NetTreeCreate { tree_id, egress } => (tree_create(&tree_id, &egress), Vec::new()),
        Verb::NetTreeDestroy { tree_id } => (tree_destroy(&tree_id), Vec::new()),
        Verb::NetTapCreate { tree_id, indices } => tap_create(&tree_id, &indices),
        Verb::NetTapDetach {
            tree_id,
            vm_index,
            uid,
        } => (tap_detach(&tree_id, vm_index, uid), Vec::new()),
        Verb::NetTapDestroy { tree_id, vm_index } => (tap_destroy(&tree_id, vm_index), Vec::new()),
        Verb::NetPodAttach {
            tree_id,
            vm_index,
            netns,
            pod_ip,
        } => (pod_attach(&tree_id, vm_index, &netns, &pod_ip), Vec::new()),
        Verb::NetPodNat {
            tree_id,
            vm_index,
            netns,
            pod_ip,
        } => (pod_nat(&tree_id, vm_index, &netns, &pod_ip), Vec::new()),
        Verb::NetPodIp { netns } => (pod_ip(&netns), Vec::new()),
        Verb::NetPodDetach {
            tree_id,
            vm_index,
            netns,
        } => (pod_detach(&tree_id, vm_index, &netns), Vec::new()),
        Verb::NetLinkToNetns { link, netns } => (link_to_netns(&link, &netns), Vec::new()),
        Verb::VirtiofsdSpawn {
            vm_id,
            share_idx,
            tag,
            tree,
        } => virtiofsd_spawn(&vm_id, share_idx, &tag, tree.as_deref(), fds),
        Verb::FcSpawn { .. }
        | Verb::FcConnect { .. }
        | Verb::FcUpdateDrive { .. }
        | Verb::FcSnapshotExport { .. }
        | Verb::FcKill { .. }
        | Verb::FcList { .. } => dispatch_fc(verb),
        Verb::RestartHello { .. } => (
            Reply::failed(
                libc::EPROTO,
                "the restart hello travels on the control channel only".to_string(),
            ),
            Vec::new(),
        ),
        Verb::HelperWait { pid } => (helper_wait(pid), Vec::new()),
        Verb::HelperReap { pid } => (helper_reap(pid), Vec::new()),
        Verb::KsmQuery { ranges } => (ksm_query(&ranges), Vec::new()),
    }
}

/// Read the VM broker's smaps / `ksm_stat`. Never a caller-supplied pid.
fn ksm_query(ranges: &[super::KsmRange]) -> Reply {
    let pid = VM_BROKER_PID.load(Ordering::SeqCst);
    if pid == 0 {
        return Reply::failed(
            libc::ESRCH,
            "ksm query: the VM broker pid is not known yet".to_string(),
        );
    }
    let ranges: Vec<(u64, u64)> = ranges.iter().map(|r| (r.start, r.len)).collect();
    match crate::ksm::read_proc(pid, &ranges) {
        Ok(snap) => Reply::KsmQuery {
            merging_pages: snap.merging_pages,
            stat: snap.stat,
        },
        Err(e) => Reply::failed(libc::EIO, format!("ksm query pid {pid}: {e}")),
    }
}

/// The `fc.*` half of [`dispatch`], split out so neither is a hundred
/// lines of `match` arm.
fn dispatch_fc(verb: Verb) -> (Reply, Vec<OwnedFd>) {
    match verb {
        Verb::FcSpawn {
            vm_id,
            vcpus,
            memory_mb,
            cpu,
            tap,
            images,
            restore_from,
        } => super::jail::spawn_jail(
            &super::jail::SpawnRequest {
                vm_id: &vm_id,
                vcpus,
                memory_mb,
                cpu,
                tap,
                images: &images,
                restore_from: restore_from.as_ref(),
            },
            &|idx| block_path(&vm_id, idx),
        ),
        Verb::FcConnect { vm_id, which } => super::jail::connect(&vm_id, which),
        Verb::FcUpdateDrive {
            vm_id,
            device_idx,
            name,
            replaces,
        } => (
            match block_path(&vm_id, device_idx) {
                Ok(src) => super::jail::update_drive(&vm_id, &src, &name, &replaces),
                Err(reply) => reply,
            },
            Vec::new(),
        ),
        Verb::FcSnapshotExport { vm_id, generation } => {
            (super::jail::snapshot_export(&vm_id, generation), Vec::new())
        }
        Verb::FcKill { vm_id } => (fc_kill(&vm_id), Vec::new()),
        Verb::FcList { page } => fc_list(page),
        other => (
            Reply::failed(libc::EPROTO, format!("{other:?} is not an fc.* verb")),
            Vec::new(),
        ),
    }
}

/// `vm.register`: the one verb that takes paths.
#[allow(clippy::too_many_arguments)]
fn register(
    vm_id: String,
    sandbox_id: Option<String>,
    tree_id: Option<String>,
    backend: String,
    shares: Vec<ShareSpec>,
    blocks: &[super::BlockSpec],
    etc_volumes: &[String],
    netns: Option<&str>,
) -> Reply {
    let mut share_fds = Vec::with_capacity(shares.len());
    for (i, share) in shares.iter().enumerate() {
        match paths::validate(Class::ShareDir, &share.host_dir, !share.readonly) {
            Ok(pinned) => share_fds.push(pinned),
            Err(e) => return indexed_refusal("virtiofs", i, &e),
        }
    }
    let mut block_fds = Vec::with_capacity(blocks.len());
    for (i, block) in blocks.iter().enumerate() {
        match paths::validate(Class::BlockFile, &block.host_path, !block.readonly) {
            Ok(pinned) => block_fds.push(pinned),
            Err(e) => return indexed_refusal("block_devices", i, &e),
        }
    }
    let mut volume_fds = Vec::with_capacity(etc_volumes.len());
    for (i, source) in etc_volumes.iter().enumerate() {
        match paths::validate(Class::ShareDir, source, false)
            .or_else(|_| paths::validate(Class::BlockFile, source, false))
        {
            Ok(pinned) => volume_fds.push(pinned),
            Err(e) => return indexed_refusal("etc_volumes", i, &e),
        }
    }
    let netns_fd = match netns {
        None => None,
        Some(path) => match paths::validate(Class::Netns, path, false) {
            Ok(pinned) => Some(pinned),
            Err(e) => return Reply::failed(libc::EACCES, format!("network.pod_netns: {e}")),
        },
    };

    let entry = VmEntry {
        sandbox_id,
        tree_id,
        backend,
        block_writable: blocks.iter().map(|b| !b.readonly).collect(),
        registered_blocks: blocks.len(),
        block_paths: blocks.iter().map(|b| b.host_path.clone()).collect(),
        auto_created: false,
        shares,
        share_fds,
        block_fds,
        volume_fds,
        netns_fd,
        remounted: HashSet::new(),
    };
    table(|t| match t.get(&vm_id) {
        Some(existing) if existing.matches(&entry) => Reply::Ok,
        Some(_) => Reply::failed(
            libc::EEXIST,
            format!(
                "vm {vm_id} is already registered with a different body — re-registering would \
                 swap the paths of a live VM"
            ),
        ),
        None => {
            log::info!(
                "registered vm {vm_id}: {} share(s), {} block device(s), {} etc volume(s), \
                 netns {}",
                entry.share_fds.len(),
                entry.block_fds.len(),
                entry.volume_fds.len(),
                entry
                    .netns_fd
                    .as_ref()
                    .map_or("none".into(), |p| p.path().display().to_string())
            );
            t.insert(vm_id, entry);
            Reply::Ok
        }
    })
}

/// `vm.register_disk`: validate one more backing file against the
/// block-file roots and append it to the entry's `blocks`.
///
/// Creates the entry when there is none. A fork child and a resumed VM
/// get their ids from `fc::child_vm_id`, which nothing registered and
/// nothing will `StopVm`; making them register first would be a second
/// verb on the fork path for no gain, so the entry is minted here and
/// released with the jail (`auto_created`).
fn register_disk(vm_id: &str, path: &str, writable: bool) -> Reply {
    let pinned = match paths::validate(Class::BlockFile, path, writable) {
        Ok(pinned) => pinned,
        Err(e) => {
            return Reply::failed(
                e.raw_os_error().unwrap_or(libc::EACCES),
                format!("vm.register_disk({vm_id}): {e}"),
            )
        }
    };
    table(|t| {
        let entry = t.entry(vm_id.to_string()).or_insert_with(|| VmEntry {
            sandbox_id: None,
            tree_id: None,
            backend: "firecracker".to_string(),
            shares: Vec::new(),
            share_fds: Vec::new(),
            block_fds: Vec::new(),
            block_writable: Vec::new(),
            registered_blocks: 0,
            block_paths: Vec::new(),
            auto_created: true,
            volume_fds: Vec::new(),
            netns_fd: None,
            remounted: HashSet::new(),
        });
        // Idempotent for a repeated path, which the fork path does hit:
        // every child re-registers the same read-only erofs images its
        // parent did.
        if let Some(index) = entry
            .block_paths
            .iter()
            .position(|p| p == path)
            .filter(|i| entry.block_writable[*i] == writable)
        {
            return index_reply(vm_id, index);
        }
        let index = entry.block_fds.len();
        entry.block_fds.push(pinned);
        entry.block_writable.push(writable);
        entry.block_paths.push(path.to_string());
        index_reply(vm_id, index)
    })
}

fn index_reply(vm_id: &str, index: usize) -> Reply {
    match u16::try_from(index) {
        Ok(index) => Reply::Index { index },
        Err(_) => Reply::failed(
            libc::ERANGE,
            format!("vm {vm_id} has more than {} block devices", u16::MAX),
        ),
    }
}

/// Name the field and the index, so the shim's `CreateVm` failure points
/// at the offending entry instead of saying "permission denied".
fn indexed_refusal(field: &str, index: usize, e: &io::Error) -> Reply {
    Reply::failed(
        e.raw_os_error().unwrap_or(libc::EACCES),
        format!("{field}[{index}]: {e}"),
    )
}

fn release(vm_id: &str) -> Reply {
    // Idempotent: `StopVm` and `Drop for VmEntry` both reach here, and a
    // release of an unknown id is the desired end state either way.
    let Some(entry) = table(|t| t.remove(vm_id)) else {
        return Reply::Ok;
    };
    release_entry(vm_id, &entry);
    Reply::Ok
}

fn release_entry(vm_id: &str, entry: &VmEntry) {
    // Before the mounts: a live jail holds hard links into the images
    // this entry pinned, and `fc.kill` is what removes them.
    let _ = super::jail::kill(vm_id);
    for idx in &entry.remounted {
        let Some(pinned) = entry.share_fds.get(usize::from(*idx)) else {
            continue;
        };
        if let Err(e) = crate::volumes::umount_path(pinned.path()) {
            log::error!(
                "release vm {vm_id}: umount share[{idx}] {}: {e}",
                pinned.path().display()
            );
        }
    }
}

/// Release every id still in the table. Returns how many, for the one
/// log line per VM the crash paths owe (§9.2).
fn release_all() -> usize {
    let entries: Vec<(String, VmEntry)> = table(|t| t.drain().collect());
    let n = entries.len();
    for (vm_id, entry) in entries {
        log::error!(
            "releasing vm {vm_id} (backend {}, sandbox {:?}, tree {:?}) on behalf of a VM broker \
             that is gone",
            entry.backend,
            entry.sandbox_id,
            entry.tree_id
        );
        release_entry(&vm_id, &entry);
    }
    // Bridges, TAPs and nft tables last: a VM's release may still name
    // them, and they are the state a crashed VM broker cannot clean up
    // itself. Dropping the records is the teardown.
    let orphaned: Vec<(String, TreeRecord)> = trees(|t| t.drain().collect());
    for (tree_id, record) in orphaned {
        log::error!(
            "releasing tree {tree_id} (bridge {}, {} TAP(s)) on behalf of a VM broker that is \
             gone",
            record.net.bridge_name(),
            record.taps.len()
        );
        drop(record);
    }
    n
}

/// Whether a registered VM is handed to the successor VM broker rather
/// than released (`K7D_VM_BROKER_RESTART`).
///
/// Survives: a **Firecracker** VM the shim can name again — it has a
/// `sandbox_id` — that belongs to no cluster but its own pod's (no
/// `tree_id`, or the `tree_id` *is* the sandbox id, which is what the
/// shim registers for a networked pod), whose jail this process holds
/// and whose Firecracker is still running. Its jail, pidfd, TAP, bridge,
/// uid lease and pinned descriptors stay in the tables for `fc.list`.
///
/// Explicitly **not** survived, and released here like any crash:
/// - **trees / clusters**: a `tree_id` naming anything but the pod
///   itself. The members were forked from a point the dead VM broker
///   held in memory; the bridge and its nft jail go with them.
/// - **the warm pool** and **fork children** (`fcf-*`): registered by
///   the VM broker itself with no `sandbox_id`. Nobody will ever name
///   them again.
/// - **native VMs**: their KVM descriptors and vhost queues were the VM
///   broker's address space. Their virtiofsd helpers are reaped with
///   them.
/// - **in-flight `PauseVm` / `ForkVm`**: a pod caught paused stays
///   paused — the successor reads `GET /` and tells the truth, and the
///   shim's retry decides. A fork whose child jail exists but was never
///   registered with a sandbox is released with the rest.
fn survives(vm_id: &str, entry: &VmEntry) -> Result<(), &'static str> {
    if entry.backend != "firecracker" {
        return Err("not a Firecracker VM — a native VM's KVM state died with the VM broker");
    }
    let Some(sandbox_id) = &entry.sandbox_id else {
        return Err("no sandbox id — nothing can name it again");
    };
    if entry
        .tree_id
        .as_ref()
        .is_some_and(|tree| tree != sandbox_id)
    {
        return Err("a cluster member — trees are not survived");
    }
    if !super::jail::is_live(vm_id) {
        return Err("no running Firecracker jail — the spawn was in flight, or the VMM is gone");
    }
    Ok(())
}

/// Under `K7D_VM_BROKER_RESTART`: release what [`survives`] refuses,
/// keep the rest for the successor. Returns `(kept, released)`.
fn release_non_survivors() -> (usize, usize) {
    let mut kept = Vec::new();
    let mut gone = Vec::new();
    for (vm_id, entry) in table(|t| t.drain().collect::<Vec<_>>()) {
        match survives(&vm_id, &entry) {
            Ok(()) => kept.push((vm_id, entry)),
            Err(why) => gone.push((vm_id, entry, why)),
        }
    }
    for (vm_id, entry, why) in &gone {
        log::error!(
            "releasing vm {vm_id} (backend {}, sandbox {:?}, tree {:?}) on behalf of a VM broker \
             that is gone: {why}",
            entry.backend,
            entry.sandbox_id,
            entry.tree_id
        );
        release_entry(vm_id, entry);
    }
    // Every helper belongs to a native VM (Firecracker has none), and
    // native VMs are not survived; a virtiofsd with no VM is a leak.
    for (pid, mut child) in helpers(|h| h.drain().collect::<Vec<_>>()) {
        if let Err(e) = child.kill() {
            log::warn!("kill helper {pid} of a VM that did not survive: {e}");
        }
        if let Err(e) = child.wait() {
            log::warn!("reap helper {pid}: {e}");
        }
    }
    // Trees: a survivor's own bridge stays, minus any TAP that was
    // handed to a jail other than a survivor's; every other tree goes.
    let survivor_trees: HashSet<&str> = kept
        .iter()
        .filter_map(|(_, e)| e.tree_id.as_deref())
        .collect();
    let survivor_uids: HashSet<u32> = kept
        .iter()
        .filter_map(|(vm_id, _)| super::jail::uid_of(vm_id))
        .collect();
    let orphaned: Vec<(String, TreeRecord)> = trees(|t| {
        let mut orphaned = Vec::new();
        for tree_id in t.keys().cloned().collect::<Vec<_>>() {
            if survivor_trees.contains(tree_id.as_str()) {
                let record = t.get_mut(&tree_id).expect("key just listed");
                let stray: Vec<u32> = record
                    .taps
                    .keys()
                    .filter(|idx| {
                        !record
                            .detached_to
                            .get(idx)
                            .is_some_and(|uid| survivor_uids.contains(uid))
                    })
                    .copied()
                    .collect();
                for idx in stray {
                    log::error!("releasing TAP {idx} of tree {tree_id}: no surviving VM holds it");
                    drop(record.taps.remove(&idx));
                    record.detached_to.remove(&idx);
                    record.net.remove_entry(idx);
                }
            } else if let Some(record) = t.remove(&tree_id) {
                orphaned.push((tree_id, record));
            }
        }
        orphaned
    });
    for (tree_id, record) in orphaned {
        log::error!(
            "releasing tree {tree_id} (bridge {}, {} TAP(s)) on behalf of a VM broker that is \
             gone: trees are not survived",
            record.net.bridge_name(),
            record.taps.len()
        );
        drop(record);
    }
    for (vm_id, entry) in &kept {
        log::warn!(
            "keeping vm {vm_id} (sandbox {:?}, jail uid {:?}) for the successor VM broker",
            entry.sandbox_id,
            super::jail::uid_of(vm_id)
        );
    }
    let counts = (kept.len(), gone.len());
    table(|t| t.extend(kept));
    counts
}

/// `fc.list`: one page of held jails, each record naming the sandbox
/// the VM table registered it under.
fn fc_list(page: u32) -> (Reply, Vec<OwnedFd>) {
    let (reply, fds) = super::jail::list(page);
    let Reply::FcList { mut records, more } = reply else {
        return (reply, fds);
    };
    table(|t| {
        for record in &mut records {
            record.sandbox_id = t.get(&record.vm_id).and_then(|e| e.sandbox_id.clone());
        }
    });
    (Reply::FcList { records, more }, fds)
}

fn with_share<T>(
    vm_id: &str,
    idx: u16,
    f: impl FnOnce(&mut VmEntry, usize) -> T,
) -> Result<T, Reply> {
    table(|t| {
        let Some(entry) = t.get_mut(vm_id) else {
            return Err(unregistered(vm_id));
        };
        if usize::from(idx) >= entry.share_fds.len() {
            return Err(Reply::failed(
                libc::ERANGE,
                format!(
                    "vm {vm_id} registered {} share(s); share_idx {idx} is out of range",
                    entry.share_fds.len()
                ),
            ));
        }
        Ok(f(entry, usize::from(idx)))
    })
}

fn unregistered(vm_id: &str) -> Reply {
    Reply::failed(
        libc::ENOENT,
        format!("vm {vm_id} is not registered — vm.register must come first"),
    )
}

fn pin_share(vm_id: &str, idx: u16) -> (Reply, Vec<OwnedFd>) {
    match with_share(vm_id, idx, |entry, i| entry.share_fds[i].dup()) {
        Err(reply) => (reply, Vec::new()),
        Ok(Ok(fd)) => (Reply::Fds, vec![fd]),
        Ok(Err(e)) => (
            Reply::failed(e.raw_os_error().unwrap_or(0), format!("share.pin: {e}")),
            Vec::new(),
        ),
    }
}

fn remount_ro(vm_id: &str, idx: u16) -> Reply {
    let outcome = with_share(vm_id, idx, |entry, i| {
        let path = entry.share_fds[i].path().to_path_buf();
        match crate::volumes::remount_share_readonly(&path) {
            Ok(true) => {
                entry.remounted.insert(idx);
                Ok(true)
            }
            Ok(false) => Ok(false),
            Err(e) => Err(e),
        }
    });
    match outcome {
        Err(reply) => reply,
        Ok(Ok(_)) => Reply::Ok,
        Ok(Err(e)) => Reply::failed(0, format!("share.remount_ro: {e}")),
    }
}

fn umount(vm_id: &str, idx: u16) -> Reply {
    let outcome = with_share(vm_id, idx, |entry, i| {
        let path = entry.share_fds[i].path().to_path_buf();
        entry.remounted.remove(&idx);
        crate::volumes::umount_path(&path)
    });
    match outcome {
        Err(reply) => reply,
        Ok(Ok(())) => Reply::Ok,
        Ok(Err(e)) => Reply::failed(0, format!("share.umount: {e}")),
    }
}

fn open_disk(vm_id: &str, idx: u16) -> (Reply, Vec<OwnedFd>) {
    let opened = table(|t| {
        let Some(entry) = t.get(vm_id) else {
            return Err(unregistered(vm_id));
        };
        let Some(pinned) = entry.block_fds.get(usize::from(idx)) else {
            return Err(Reply::failed(
                libc::ERANGE,
                format!(
                    "vm {vm_id} registered {} block device(s); device_idx {idx} is out of range",
                    entry.block_fds.len()
                ),
            ));
        };
        let flags = if entry.block_writable[usize::from(idx)] {
            libc::O_RDWR
        } else {
            libc::O_RDONLY
        };
        Ok(pinned.reopen(flags))
    });
    match opened {
        Err(reply) => (reply, Vec::new()),
        Ok(Ok(fd)) => (Reply::Fds, vec![fd]),
        Ok(Err(e)) => (
            Reply::failed(e.raw_os_error().unwrap_or(0), format!("disk.open: {e}")),
            Vec::new(),
        ),
    }
}

fn open_volume(vm_id: &str, idx: u16) -> (Reply, Vec<OwnedFd>) {
    let opened = table(|t| {
        let Some(entry) = t.get(vm_id) else {
            return Err(unregistered(vm_id));
        };
        let Some(pinned) = entry.volume_fds.get(usize::from(idx)) else {
            return Err(Reply::failed(
                libc::ERANGE,
                format!(
                    "vm {vm_id} registered {} etc volume(s); volume_idx {idx} is out of range",
                    entry.volume_fds.len()
                ),
            ));
        };
        Ok(pinned.reopen(libc::O_RDONLY))
    });
    match opened {
        Err(reply) => (reply, Vec::new()),
        Ok(Ok(fd)) => (Reply::Fds, vec![fd]),
        Ok(Err(e)) => (
            Reply::failed(e.raw_os_error().unwrap_or(0), format!("volume.open: {e}")),
            Vec::new(),
        ),
    }
}

// --- fc.* -------------------------------------------------------------

/// The host path a registered block index resolves to, re-checked
/// against the `(dev, ino)` the pin recorded.
///
/// The `fc.*` verbs hard-link and `chown` these, which is the one thing
/// the `O_PATH` pin alone cannot express — `link(2)` needs a name. The
/// re-check is what keeps a swapped name from becoming a `chown` of
/// whatever is there now (`jail::pinned_path`).
fn block_path(vm_id: &str, idx: u16) -> Result<std::path::PathBuf, Reply> {
    let pinned = table(|t| {
        let Some(entry) = t.get(vm_id) else {
            return Err(unregistered(vm_id));
        };
        let Some(pinned) = entry.block_fds.get(usize::from(idx)) else {
            return Err(Reply::failed(
                libc::ERANGE,
                format!(
                    "vm {vm_id} has {} block device(s); device_idx {idx} is out of range",
                    entry.block_fds.len()
                ),
            ));
        };
        super::jail::pinned_path(pinned, &format!("vm {vm_id} block[{idx}]"))
    });
    pinned
}

/// `fc.kill`, plus the registration when nothing else will release it.
fn fc_kill(vm_id: &str) -> Reply {
    let reply = super::jail::kill(vm_id);
    let auto = table(|t| t.get(vm_id).is_some_and(|e| e.auto_created));
    if auto {
        if let Some(entry) = table(|t| t.remove(vm_id)) {
            release_entry(vm_id, &entry);
        }
    }
    reply
}

// --- net.* ------------------------------------------------------------
//
// The node broker holds the real `ClusterNetwork`; the VM broker holds a
// mirror with the same bridge name and the same entries. Nothing here
// takes a link name from the caller — every name, MAC and address is
// derived from the tree id and the index, on this side, by the same code
// that derived them before the split.

fn tree_create(tree_id: &str, egress: &crate::netjail::EgressPolicy) -> Reply {
    trees(|t| match t.get_mut(tree_id) {
        // Idempotent for cooperating pods on a shared bridge, and an
        // upsert for `tree_adopt_cluster`, which adopts a bridge born
        // `Open` into a tree with a stricter posture.
        Some(record) => {
            if record.net.egress() == egress {
                return Reply::Tree {
                    bridge: record.net.bridge_name().to_string(),
                };
            }
            match record.net.set_egress(egress.clone()) {
                Ok(()) => Reply::Tree {
                    bridge: record.net.bridge_name().to_string(),
                },
                Err(e) => string_failure(&format!("net.tree_create({tree_id}) re-policy"), &e),
            }
        }
        None => match crate::network::ClusterNetwork::create_with_egress(tree_id, egress.clone()) {
            Ok(net) => {
                let bridge = net.bridge_name().to_string();
                t.insert(
                    tree_id.to_string(),
                    TreeRecord {
                        net,
                        taps: HashMap::new(),
                        detached_to: HashMap::new(),
                    },
                );
                log::info!("tree {tree_id}: bridge {bridge} up");
                Reply::Tree { bridge }
            }
            Err(e) => string_failure(&format!("net.tree_create({tree_id})"), &e),
        },
    })
}

fn tree_destroy(tree_id: &str) -> Reply {
    // Idempotent: the VM broker's `Drop for ClusterNetwork` and an
    // explicit `destroy()` both reach here.
    drop(trees(|t| t.remove(tree_id)));
    Reply::Ok
}

fn tap_create(tree_id: &str, indices: &[u32]) -> (Reply, Vec<OwnedFd>) {
    let created = trees(|t| {
        let Some(record) = t.get_mut(tree_id) else {
            return Err(unknown_tree(tree_id));
        };
        let taps = match record.net.add_taps_at(indices) {
            Ok(taps) => taps,
            Err(e) => {
                return Err(string_failure(
                    &format!("net.tap_create({tree_id}, {indices:?})"),
                    &e,
                ))
            }
        };
        // Duplicate before storing: the reply hands the VM broker a
        // descriptor onto the same open file, and this side keeps its
        // own so a non-persistent device does not die when the VM broker
        // closes its copy (see `TreeRecord`).
        let mut infos = Vec::with_capacity(taps.len());
        let mut fds = Vec::with_capacity(taps.len());
        for tap in &taps {
            match dup_owned(tap.fd()) {
                Ok(fd) => fds.push(fd),
                Err(e) => {
                    return Err(Reply::failed(
                        e.raw_os_error().unwrap_or(0),
                        format!("net.tap_create({tree_id}): dup {}: {e}", tap.name()),
                    ))
                }
            }
            infos.push(super::TapInfo {
                vm_index: tap.vm_index(),
                name: tap.name().to_string(),
                mac: tap.mac(),
                ip: tap.guest_ip().to_string(),
            });
        }
        for tap in taps {
            record.taps.insert(tap.vm_index(), tap);
        }
        Ok((Reply::Taps(infos), fds))
    });
    match created {
        Ok(out) => out,
        Err(reply) => (reply, Vec::new()),
    }
}

fn dup_owned(fd: std::os::fd::RawFd) -> io::Result<OwnedFd> {
    use std::os::fd::FromRawFd;
    // SAFETY: `fd` is a live descriptor owned by a `TapDevice` in the
    // tree table; `dup` does not take ownership of it.
    let copy = unsafe { libc::dup(fd) };
    if copy < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `dup` returned a fresh descriptor this process owns.
    Ok(unsafe { OwnedFd::from_raw_fd(copy) })
}

fn with_tap<T>(
    tree_id: &str,
    vm_index: u32,
    f: impl FnOnce(&mut TreeRecord) -> T,
) -> Result<T, Reply> {
    trees(|t| {
        let Some(record) = t.get_mut(tree_id) else {
            return Err(unknown_tree(tree_id));
        };
        if !record.taps.contains_key(&vm_index) {
            return Err(Reply::failed(
                libc::ENOENT,
                format!("tree {tree_id} has no TAP at index {vm_index}"),
            ));
        }
        Ok(f(record))
    })
}

fn tap_detach(tree_id: &str, vm_index: u32, uid: u32) -> Reply {
    match with_tap(tree_id, vm_index, |record| {
        let detached = record
            .taps
            .get_mut(&vm_index)
            .expect("checked present")
            .detach_for_vmm(uid);
        if detached.is_ok() {
            record.detached_to.insert(vm_index, uid);
        }
        detached
    }) {
        Err(reply) => reply,
        Ok(Ok(())) => Reply::Ok,
        Ok(Err(e)) => string_failure(&format!("net.tap_detach({tree_id}[{vm_index}], {uid})"), &e),
    }
}

fn tap_destroy(tree_id: &str, vm_index: u32) -> Reply {
    // Idempotent, like every release path: `Drop for TapDevice` on the
    // VM broker's side and an explicit teardown both reach here.
    trees(|t| {
        if let Some(record) = t.get_mut(tree_id) {
            drop(record.taps.remove(&vm_index));
            record.detached_to.remove(&vm_index);
            record.net.remove_entry(vm_index);
        }
    });
    Reply::Ok
}

/// Validate a network namespace handle the way `vm.register` validates a
/// share root.
///
/// The netns cannot come from the `VmTable`: the batch fork path names
/// its members by `(tree_id, vm_index)` and has no `vm_id` to hand over
/// at all (`fork_cluster_warm_batch`). So the same validator runs here —
/// allowlisted roots, `RESOLVE_NO_SYMLINKS`, and an `fstatfs` that must
/// say `NSFS_MAGIC` — rather than the path being taken on trust.
fn validate_netns(netns: &str) -> Result<std::path::PathBuf, Reply> {
    paths::validate(Class::Netns, netns, false)
        .map(|pinned| pinned.path().to_path_buf())
        .map_err(|e| {
            Reply::failed(
                e.raw_os_error().unwrap_or(libc::EACCES),
                format!("pod_netns {netns:?}: {e}"),
            )
        })
}

fn parse_pod_ip(pod_ip: &str) -> Result<std::net::Ipv4Addr, Reply> {
    pod_ip.parse().map_err(|e| {
        Reply::failed(
            libc::EINVAL,
            format!("pod_ip {pod_ip:?} is not an IPv4 address: {e}"),
        )
    })
}

fn pod_attach(tree_id: &str, vm_index: u32, netns: &str, pod_ip: &str) -> Reply {
    let (netns, pod_ip) = match (validate_netns(netns), parse_pod_ip(pod_ip)) {
        (Ok(n), Ok(p)) => (n, p),
        (Err(reply), _) | (_, Err(reply)) => return reply,
    };
    match with_tap(tree_id, vm_index, |record| {
        record.net.attach_to_pod_netns(vm_index, &netns, pod_ip)
    }) {
        Err(reply) => reply,
        Ok(Ok(())) => Reply::Ok,
        Ok(Err(e)) => string_failure(&format!("net.pod_attach({tree_id}[{vm_index}])"), &e),
    }
}

fn pod_nat(tree_id: &str, vm_index: u32, netns: &str, pod_ip: &str) -> Reply {
    let (netns, pod_ip) = match (validate_netns(netns), parse_pod_ip(pod_ip)) {
        (Ok(n), Ok(p)) => (n, p),
        (Err(reply), _) | (_, Err(reply)) => return reply,
    };
    match with_tap(tree_id, vm_index, |record| {
        record.net.install_pod_nat(vm_index, pod_ip, &netns)
    }) {
        Err(reply) => reply,
        Ok(Ok(())) => Reply::Ok,
        Ok(Err(e)) => string_failure(&format!("net.pod_nat({tree_id}[{vm_index}])"), &e),
    }
}

/// `ip -4 -o addr show dev eth0` inside a pod's netns, which needs
/// `setns` and therefore the node broker.
fn pod_ip(netns: &str) -> Reply {
    let netns = match validate_netns(netns) {
        Ok(n) => n,
        Err(reply) => return reply,
    };
    match crate::netns::link_addrs_v4(&netns, "eth0") {
        Ok(addrs) => Reply::PodIp {
            addrs: addrs.iter().map(std::string::ToString::to_string).collect(),
        },
        Err(e) => string_failure(&format!("net.pod_ip({})", netns.display()), &e.to_string()),
    }
}

fn pod_detach(tree_id: &str, vm_index: u32, netns: &str) -> Reply {
    // The pod netns is normally destroyed by containerd before this
    // runs, and a handle that no longer resolves is the end state this
    // verb wants anyway.
    let Ok(netns) = validate_netns(netns) else {
        return Reply::Ok;
    };
    trees(|t| {
        if let Some(record) = t.get(tree_id) {
            let _ = record.net.detach_from_pod_netns(vm_index, &netns);
        }
    });
    Reply::Ok
}

fn link_to_netns(link: &str, netns: &str) -> Reply {
    let netns = match validate_netns(netns) {
        Ok(n) => n,
        Err(reply) => return reply,
    };
    match crate::netns::move_link_to_netns(link, &netns) {
        Ok(()) => Reply::Ok,
        Err(e) => string_failure(&format!("net.link_to_netns({link})"), &e.to_string()),
    }
}

// --- virtiofsd.spawn + helper lifecycle -------------------------------

/// Helpers this side started, by pid. The VM broker polls the pidfd it
/// was given and only comes back for the status, so nothing here is held
/// while a helper runs.
static HELPERS: Mutex<Option<HashMap<u32, crate::spawner::Child>>> = Mutex::new(None);

fn helpers<T>(f: impl FnOnce(&mut HashMap<u32, crate::spawner::Child>) -> T) -> T {
    let mut guard = HELPERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f(guard.get_or_insert_with(HashMap::new))
}

/// Leaf cgroup under [`crate::cgroup::HELPER_ROOT`] that node-broker
/// helpers are moved into at spawn.
///
/// Not `HELPER_ROOT` itself: it has controllers in `cgroup.subtree_
/// control`, and cgroup v2's no-internal-process rule forbids member
/// processes there. Not the node broker's own cgroup either, and that is
/// the point — a migration needs write on the destination *and* on the
/// two cgroups' common ancestor, so a helper left in `<service>/node`
/// could only ever be moved by root. Landing it under `HELPER_ROOT`
/// makes that ancestor `HELPER_ROOT`, which privilege separation handed to `k7d`, and
/// `TreeCgroup::add_process` therefore stays a plain write with no verb
/// and no capability — which is what keeps it off the fork path's bill.
pub const HELPER_SPAWNED_SUBDIR: &str = "spawned";

fn virtiofsd_spawn(
    vm_id: &str,
    share_idx: u16,
    tag: &str,
    tree: Option<&str>,
    mut fds: Vec<OwnedFd>,
) -> (Reply, Vec<OwnedFd>) {
    if fds.len() != 1 {
        return (
            Reply::failed(
                libc::EINVAL,
                format!(
                    "virtiofsd.spawn({vm_id}[{share_idx}]) carried {} descriptor(s), want the \
                     bound listener alone",
                    fds.len()
                ),
            ),
            Vec::new(),
        );
    }
    let listener = fds.remove(0);
    let share = match with_share(vm_id, share_idx, |entry, i| entry.share_fds[i].dup()) {
        Err(reply) => return (reply, Vec::new()),
        Ok(Ok(fd)) => fd,
        Ok(Err(e)) => {
            return (
                Reply::failed(
                    e.raw_os_error().unwrap_or(0),
                    format!("virtiofsd.spawn({vm_id}[{share_idx}]): dup the share pin: {e}"),
                ),
                Vec::new(),
            )
        }
    };
    match crate::virtiofs::spawn_jailed(&listener, &share, tag) {
        Ok(child) => {
            let pid = child.id();
            if let Err(e) = place_helper(pid, tree) {
                log::error!("virtiofsd.spawn({vm_id}[{share_idx}]) pid {pid}: {e}");
            }
            let pidfd = match child.pidfd_dup() {
                Ok(fd) => fd,
                Err(e) => {
                    let mut child = child;
                    let _ = child.kill();
                    let _ = child.wait();
                    return (
                        Reply::failed(
                            e.raw_os_error().unwrap_or(0),
                            format!("virtiofsd.spawn({vm_id}[{share_idx}]): dup the pidfd: {e}"),
                        ),
                        Vec::new(),
                    );
                }
            };
            helpers(|h| h.insert(pid, child));
            (Reply::Spawned { pid }, vec![pidfd])
        }
        Err(e) => (
            Reply::failed(
                e.raw_os_error().unwrap_or(0),
                format!("virtiofsd.spawn({vm_id}[{share_idx}], tag={tag}): {e}"),
            ),
            Vec::new(),
        ),
    }
}

/// Move a freshly spawned helper out of the node broker's cgroup and
/// into one the VM broker can move it out of again.
fn place_helper(pid: u32, tree: Option<&str>) -> io::Result<()> {
    let root = std::path::Path::new(crate::cgroup::HELPER_ROOT);
    let dir = match tree {
        // The tree's domain half, when the caller already knows which
        // tree the share belongs to — `memory.max` then applies from the
        // first page rather than from the later `add_process`.
        Some(id) if root.join(format!("tree-{id}")).join("helpers").is_dir() => {
            root.join(format!("tree-{id}")).join("helpers")
        }
        _ => root.join(HELPER_SPAWNED_SUBDIR),
    };
    std::fs::write(dir.join("cgroup.procs"), pid.to_string())
        .map_err(|e| io::Error::other(format!("move pid {pid} into {}: {e}", dir.display())))
}

fn helper_wait(pid: u32) -> Reply {
    let Some(mut child) = helpers(|h| h.remove(&pid)) else {
        return Reply::failed(
            libc::ESRCH,
            format!("helper.wait({pid}): this node broker did not start it"),
        );
    };
    match child.wait() {
        Ok(status) => Reply::Exited {
            raw_status: std::os::unix::process::ExitStatusExt::into_raw(status),
        },
        Err(e) => Reply::failed(
            e.raw_os_error().unwrap_or(0),
            format!("helper.wait({pid}): {e}"),
        ),
    }
}

fn helper_reap(pid: u32) -> Reply {
    // Idempotent: a `Drop` on the VM broker's side runs whether or not
    // the helper was already waited for.
    if let Some(mut child) = helpers(|h| h.remove(&pid)) {
        let _ = child.kill();
        let _ = child.wait();
    }
    Reply::Ok
}

/// Everything a crashed predecessor left on the host that only root can
/// remove (§9.1). The VM broker's own leftovers — its cgroups, its tree
/// files — are swept by `main()` on its side, where they are owned.
pub fn sweep_orphans() {
    let jails = crate::netjail::clean_stale_jails();
    if !jails.is_empty() {
        log::warn!("node broker reaped stale net jails: {jails:?}");
    }
    let tap_jails = crate::netjail::clean_stale_tap_jails();
    if !tap_jails.is_empty() {
        log::warn!("node broker reaped stale tap anti-spoof jails: {tap_jails:?}");
    }
}

fn fatal(what: &str) -> ! {
    log::error!("k7d node broker: {what}");
    eprintln!("k7d node broker: {what}");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::BlockSpec;

    fn clear_table() {
        table(std::collections::HashMap::clear);
    }

    fn tmproot(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("k7d-node-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp root");
        dir
    }

    fn with_root<T>(root: &std::path::Path, f: impl FnOnce() -> T) -> T {
        let prev = std::env::var(paths::EXTRA_ROOTS_ENV).ok();
        std::env::set_var(paths::EXTRA_ROOTS_ENV, root);
        let out = f();
        match prev {
            Some(v) => std::env::set_var(paths::EXTRA_ROOTS_ENV, v),
            None => std::env::remove_var(paths::EXTRA_ROOTS_ENV),
        }
        out
    }

    /// Registration pins, later verbs name indices, and `vm.release`
    /// forgets — the lifecycle every other verb depends on.
    #[test]
    fn registration_pins_and_release_forgets() {
        clear_table();
        let root = tmproot("lifecycle");
        std::fs::create_dir(root.join("share")).expect("mkdir");
        std::fs::write(root.join("disk.img"), b"disk").expect("write");
        let register = || Verb::VmRegister {
            vm_id: "vm-a".into(),
            sandbox_id: Some("sb".into()),
            tree_id: None,
            backend: "native".into(),
            shares: vec![ShareSpec {
                host_dir: root.join("share").display().to_string(),
                readonly: false,
            }],
            blocks: vec![BlockSpec {
                host_path: root.join("disk.img").display().to_string(),
                readonly: true,
            }],
            etc_volumes: Vec::new(),
            netns: None,
        };
        with_root(&root, || {
            assert_eq!(dispatch(register(), Vec::new()).0, Reply::Ok);
            // Idempotent for the same body.
            assert_eq!(dispatch(register(), Vec::new()).0, Reply::Ok);

            let (reply, fds) = dispatch(
                Verb::SharePin {
                    vm_id: "vm-a".into(),
                    share_idx: 0,
                },
                Vec::new(),
            );
            assert_eq!(reply, Reply::Fds);
            assert_eq!(fds.len(), 1);

            let (reply, fds) = dispatch(
                Verb::DiskOpen {
                    vm_id: "vm-a".into(),
                    device_idx: 0,
                },
                Vec::new(),
            );
            assert_eq!(reply, Reply::Fds);
            assert_eq!(fds.len(), 1);

            assert_eq!(
                dispatch(
                    Verb::VmRelease {
                        vm_id: "vm-a".into()
                    },
                    Vec::new()
                )
                .0,
                Reply::Ok
            );
            // …and again, because both `StopVm` and `Drop` reach it.
            assert_eq!(
                dispatch(
                    Verb::VmRelease {
                        vm_id: "vm-a".into()
                    },
                    Vec::new()
                )
                .0,
                Reply::Ok
            );
            let (reply, _) = dispatch(
                Verb::SharePin {
                    vm_id: "vm-a".into(),
                    share_idx: 0,
                },
                Vec::new(),
            );
            let Reply::Failed { errno, message } = reply else {
                panic!("a released id must not answer verbs");
            };
            assert_eq!(errno, libc::ENOENT, "{message}");
        });
        std::fs::remove_dir_all(&root).ok();
    }

    /// A second registration with different paths for a live id is
    /// `EEXIST`: accepting it would let a caller swap the backing files
    /// of a VM that is already running.
    #[test]
    fn re_registering_a_live_id_with_a_different_body_is_refused() {
        clear_table();
        let root = tmproot("eexist");
        std::fs::create_dir(root.join("one")).expect("mkdir");
        std::fs::create_dir(root.join("two")).expect("mkdir");
        let register = |name: &str| Verb::VmRegister {
            vm_id: "vm-b".into(),
            sandbox_id: None,
            tree_id: None,
            backend: "native".into(),
            shares: vec![ShareSpec {
                host_dir: root.join(name).display().to_string(),
                readonly: false,
            }],
            blocks: Vec::new(),
            etc_volumes: Vec::new(),
            netns: None,
        };
        with_root(&root, || {
            assert_eq!(dispatch(register("one"), Vec::new()).0, Reply::Ok);
            let Reply::Failed { errno, .. } = dispatch(register("two"), Vec::new()).0 else {
                panic!("a different body must be refused");
            };
            assert_eq!(errno, libc::EEXIST);
            assert_eq!(
                dispatch(
                    Verb::VmRelease {
                        vm_id: "vm-b".into()
                    },
                    Vec::new()
                )
                .0,
                Reply::Ok
            );
        });
        std::fs::remove_dir_all(&root).ok();
    }

    /// The refusal names the field and the index, which
    /// is the difference between a shim error an operator can act on and
    /// "permission denied".
    #[test]
    fn a_refused_path_names_its_field_and_index() {
        clear_table();
        let root = tmproot("indexed");
        std::fs::create_dir(root.join("ok")).expect("mkdir");
        let reply = with_root(&root, || {
            dispatch(
                Verb::VmRegister {
                    vm_id: "vm-c".into(),
                    sandbox_id: None,
                    tree_id: None,
                    backend: "native".into(),
                    shares: vec![
                        ShareSpec {
                            host_dir: root.join("ok").display().to_string(),
                            readonly: false,
                        },
                        ShareSpec {
                            host_dir: "/etc".to_string(),
                            readonly: true,
                        },
                    ],
                    blocks: Vec::new(),
                    etc_volumes: Vec::new(),
                    netns: None,
                },
                Vec::new(),
            )
            .0
        });
        let Reply::Failed { errno, message } = reply else {
            panic!("/etc must be refused");
        };
        assert_eq!(errno, libc::EACCES);
        assert!(message.starts_with("virtiofs[1]:"), "{message}");
        // A registration that failed leaves nothing behind.
        let (reply, _) = dispatch(
            Verb::SharePin {
                vm_id: "vm-c".into(),
                share_idx: 0,
            },
            Vec::new(),
        );
        assert!(matches!(reply, Reply::Failed { errno, .. } if errno == libc::ENOENT));
        std::fs::remove_dir_all(&root).ok();
    }

    /// An index past what registration pinned is `ERANGE`, not a panic
    /// and not a neighbouring device.
    #[test]
    fn an_out_of_range_index_is_refused() {
        clear_table();
        let root = tmproot("range");
        std::fs::create_dir(root.join("s")).expect("mkdir");
        with_root(&root, || {
            dispatch(
                Verb::VmRegister {
                    vm_id: "vm-d".into(),
                    sandbox_id: None,
                    tree_id: None,
                    backend: "native".into(),
                    shares: vec![ShareSpec {
                        host_dir: root.join("s").display().to_string(),
                        readonly: false,
                    }],
                    blocks: Vec::new(),
                    etc_volumes: Vec::new(),
                    netns: None,
                },
                Vec::new(),
            );
            for verb in [
                Verb::SharePin {
                    vm_id: "vm-d".into(),
                    share_idx: 1,
                },
                Verb::DiskOpen {
                    vm_id: "vm-d".into(),
                    device_idx: 0,
                },
                Verb::VolumeOpen {
                    vm_id: "vm-d".into(),
                    volume_idx: 0,
                },
            ] {
                let (reply, fds) = dispatch(verb.clone(), Vec::new());
                assert!(fds.is_empty());
                let Reply::Failed { errno, message } = reply else {
                    panic!("{verb:?} must be out of range");
                };
                assert_eq!(errno, libc::ERANGE, "{message}");
            }
            dispatch(
                Verb::VmRelease {
                    vm_id: "vm-d".into(),
                },
                Vec::new(),
            );
        });
        std::fs::remove_dir_all(&root).ok();
    }

    /// `channel.open` and `shutdown` are control-channel verbs; a verb
    /// channel refuses them rather than serving a second control plane.
    #[test]
    fn control_verbs_do_not_travel_on_a_verb_channel() {
        for verb in [Verb::ChannelOpen, Verb::Shutdown] {
            let Reply::Failed { errno, .. } = dispatch(verb, Vec::new()).0 else {
                panic!("must be refused on a verb channel");
            };
            assert_eq!(errno, libc::EPROTO);
        }
    }

    /// `vm.register_disk` is how a VM-broker-owned image becomes an
    /// index `fc.spawn` can name. It validates against
    /// the same roots `vm.register` does, it is idempotent for a path it
    /// has already pinned, and it mints an entry for an id the shim
    /// never registered — a fork child's.
    #[test]
    fn register_disk_appends_an_index_and_stays_idempotent() {
        clear_table();
        let root = tmproot("late-disk");
        std::fs::create_dir(root.join("share")).expect("mkdir");
        std::fs::write(root.join("a.img"), b"a").expect("write");
        std::fs::write(root.join("b.img"), b"b").expect("write");
        with_root(&root, || {
            assert_eq!(
                dispatch(
                    Verb::VmRegister {
                        vm_id: "vm-late".into(),
                        sandbox_id: None,
                        tree_id: None,
                        backend: "firecracker".into(),
                        shares: vec![ShareSpec {
                            host_dir: root.join("share").display().to_string(),
                            readonly: true,
                        }],
                        blocks: Vec::new(),
                        etc_volumes: Vec::new(),
                        netns: None,
                    },
                    Vec::new(),
                )
                .0,
                Reply::Ok
            );
            let add = |vm: &str, name: &str| {
                dispatch(
                    Verb::VmRegisterDisk {
                        vm_id: vm.into(),
                        path: root.join(name).display().to_string(),
                        writable: false,
                    },
                    Vec::new(),
                )
                .0
            };
            assert_eq!(add("vm-late", "a.img"), Reply::Index { index: 0 });
            assert_eq!(add("vm-late", "b.img"), Reply::Index { index: 1 });
            assert_eq!(add("vm-late", "a.img"), Reply::Index { index: 0 });
            // …and the index is openable, which is what makes it a
            // block device and not just a number.
            let (reply, fds) = dispatch(
                Verb::DiskOpen {
                    vm_id: "vm-late".into(),
                    device_idx: 1,
                },
                Vec::new(),
            );
            assert_eq!(reply, Reply::Fds);
            assert_eq!(fds.len(), 1);

            // A path outside every root is refused here exactly as it is
            // at registration.
            let Reply::Failed { errno, message } = dispatch(
                Verb::VmRegisterDisk {
                    vm_id: "vm-late".into(),
                    path: "/etc/shadow".into(),
                    writable: false,
                },
                Vec::new(),
            )
            .0
            else {
                panic!("/etc/shadow must be refused");
            };
            assert_eq!(errno, libc::EACCES, "{message}");

            // An id nothing registered — a fork child's — gets an entry
            // of its own rather than an ENOENT.
            assert_eq!(add("fcf-child", "a.img"), Reply::Index { index: 0 });
            assert!(table(|t| t["fcf-child"].auto_created));
            assert!(!table(|t| t["vm-late"].auto_created));

            for vm in ["vm-late", "fcf-child"] {
                dispatch(Verb::VmRelease { vm_id: vm.into() }, Vec::new());
            }
        });
        std::fs::remove_dir_all(&root).ok();
    }

    /// A re-registration still matches after disks were appended: the
    /// shim retrying `CreateVm` must not get `EEXIST` because the
    /// daemon has since staged a scratch disk.
    #[test]
    fn appending_a_disk_does_not_break_registration_idempotency() {
        clear_table();
        let root = tmproot("late-idem");
        std::fs::write(root.join("boot.img"), b"boot").expect("write");
        std::fs::write(root.join("scratch.img"), b"scratch").expect("write");
        let register = || Verb::VmRegister {
            vm_id: "vm-idem".into(),
            sandbox_id: None,
            tree_id: None,
            backend: "firecracker".into(),
            shares: Vec::new(),
            blocks: vec![BlockSpec {
                host_path: root.join("boot.img").display().to_string(),
                readonly: true,
            }],
            etc_volumes: Vec::new(),
            netns: None,
        };
        with_root(&root, || {
            assert_eq!(dispatch(register(), Vec::new()).0, Reply::Ok);
            assert_eq!(
                dispatch(
                    Verb::VmRegisterDisk {
                        vm_id: "vm-idem".into(),
                        path: root.join("scratch.img").display().to_string(),
                        writable: true,
                    },
                    Vec::new(),
                )
                .0,
                Reply::Index { index: 1 }
            );
            assert_eq!(dispatch(register(), Vec::new()).0, Reply::Ok);
            dispatch(
                Verb::VmRelease {
                    vm_id: "vm-idem".into(),
                },
                Vec::new(),
            );
        });
        std::fs::remove_dir_all(&root).ok();
    }

    /// Every `fc.*` verb is served now, so an unknown id is `ENOENT`
    /// with the missing step named — not `ENOSYS`, which is what it
    /// answered while the family was declared and unimplemented.
    #[test]
    fn the_firecracker_family_is_served() {
        clear_table();
        for verb in [
            Verb::FcConnect {
                vm_id: "nope".into(),
                which: super::super::FcSocket::Api,
            },
            Verb::FcSnapshotExport {
                vm_id: "nope".into(),
                generation: 1,
            },
        ] {
            let Reply::Failed { errno, message } = dispatch(verb.clone(), Vec::new()).0 else {
                panic!("{verb:?} on an unknown jail must be refused");
            };
            assert_eq!(errno, libc::ENOENT, "{message}");
            assert!(message.contains("fc.spawn must come first"), "{message}");
        }
        // `fc.spawn` for an id with no registration cannot resolve its
        // kernel, and says which table is empty.
        let Reply::Failed { errno, message } = dispatch(
            Verb::FcSpawn {
                vm_id: "nope".into(),
                vcpus: 1,
                memory_mb: 256,
                cpu: None,
                tap: false,
                images: vec![super::super::ImageRef::Kernel { device_idx: 0 }],
                restore_from: None,
            },
            Vec::new(),
        )
        .0
        else {
            panic!("an unregistered vm cannot name a kernel");
        };
        assert_eq!(errno, libc::ENOENT, "{message}");
        assert_eq!(
            dispatch(
                Verb::FcKill {
                    vm_id: "nope".into()
                },
                Vec::new()
            )
            .0,
            Reply::Ok
        );
        assert_eq!(
            dispatch(Verb::FcList { page: 0 }, Vec::new()).0,
            Reply::FcList {
                records: Vec::new(),
                more: false
            }
        );
    }
}
