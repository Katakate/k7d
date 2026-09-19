//! The one process in k7d that calls `execve`.
//!
//! A seccomp filter survives `execve` (`seccomp.rs`, reason 2), so for as
//! long as the daemon exec'd its own helpers — `ip`, `iptables`, `nft`,
//! `virtiofsd`, `mkfs.*`, `losetup`, `mount`, `cp`, the Firecracker
//! jailer — the filter installed on the daemon had to be the *union* of
//! what the daemon needs and what every one of those helpers needs. That
//! handed anything running in the daemon `chroot`, `pivot_root`,
//! `unshare`, `capset`, `setuid`, `mknod` and `*xattr` for free.
//!
//! This module moves the `execve` out of the filtered process. `start()`
//! forks a single-purpose child from `main()` **before** the logger, the
//! signal handlers, the daemon's own filter, the warm pool, or any
//! thread exists, and keeps a `SOCK_SEQPACKET` socketpair to it. The
//! child installs the *helper* allowlist on itself
//! ([`crate::seccomp::install_for_spawner`]) and spends the rest of its
//! life forking helpers on request; the daemon installs
//! `DAEMON_SYSCALLS` only and never execs again.
//!
//! Why that ordering is load-bearing, in the order the traps bite:
//!
//! * `fork()` from a multi-threaded process gives the child whatever
//!   locks the other threads happened to hold — including glibc's
//!   malloc arena and `env_logger`'s. The spawner allocates (it parses
//!   requests) so it must be forked while the daemon is still
//!   single-threaded, which means before `env_logger::init()`.
//! * The child inherits signal dispositions, so it must set its own.
//!   `systemd` stops a unit by signalling the whole cgroup
//!   (`KillMode=control-group`), and the spawner is in it — a spawner
//!   that took the default `SIGTERM` disposition died on every
//!   `systemctl restart k7d` *before* the daemon had finished shutting
//!   down, so the watchdog below turned an ordinary restart into a
//!   crash exit and a restart loop. The spawner therefore *catches*
//!   `SIGTERM`/`SIGINT` and does nothing with them
//!   ([`ignore_unit_shutdown_signals`], which explains why a handler
//!   and not `SIG_IGN`): its lifetime is its socket, not a signal. When
//!   the daemon goes away for any reason, graceful or `SIGKILL`, the
//!   socket closes and the spawner exits on EOF.
//! * Re-forking a spawner *after* `seccomp::install()` is impossible by
//!   construction: the new child would inherit the daemon's filter and
//!   die on the first `execve`. So there is exactly one spawner per
//!   daemon, and if it dies unexpectedly the daemon exits (loudly,
//!   within 5 s) and lets systemd restart the pair — unless the daemon
//!   is itself shutting down, which [`mark_shutting_down`] is how the
//!   watchdog is told apart from the case above.
//!
//! ## What crosses the socket
//!
//! One datagram per request, `serde_json` over `SOCK_SEQPACKET` (framing
//! is the kernel's, and a truncated datagram aborts rather than being
//! parsed half-way). Descriptors a helper is *meant* to have — the
//! jailer's `stderr.log`, the write end of an `output()` pipe — travel
//! as `SCM_RIGHTS` alongside it. Everything else the spawner holds is
//! `CLOEXEC`, so a helper's `/proc/self/fd` shows exactly the stdio the
//! request passed and nothing of the daemon.
//!
//! [`Spawned`] carries a `pidfd` back, which is what keeps a serialized
//! socket from serializing the *helpers*: only issuing a spawn and
//! collecting an already-exited status hold the connection lock, while
//! waiting for a helper to finish is a `poll()` on that pidfd in the
//! calling thread.
//!
//! ## Not the daemon
//!
//! `k7d`'s library is also linked into the containerd shim and into the
//! test binaries, neither of which forks a spawner (and neither of which
//! installs a seccomp filter). [`command`] therefore execs in-process
//! when no spawner is registered, using the `pidfd` wait that
//! `netns::run_capture` needed against the shim's Tokio `SIGCHLD` reaper.
//! In the daemon that path is unreachable: `start()` runs before anything
//! can spawn and `main` exits if it fails.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Output};
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

/// Biggest request or reply datagram. argv for the widest call site
/// (`iptables` rule specs, the jailer's ~20 arguments) is a few hundred
/// bytes; 64 KiB is room for a pathological hostPath without being a
/// buffer worth streaming.
const MESSAGE_MAX: usize = 64 * 1024;

/// Descriptor the spawner keeps its end of the socketpair on. Fixed so
/// the child can `close_range` everything above it.
const SPAWNER_SOCK_FD: RawFd = 3;

/// How the child should set up one of the three standard descriptors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StdioSpec {
    /// `/dev/null`.
    Null,
    /// The spawner's own descriptor, i.e. the daemon's (journald).
    Inherit,
    /// A descriptor passed with this request via `SCM_RIGHTS`.
    Fd,
}

/// One helper to exec. `argv[0]` is the program.
#[derive(Debug, Serialize, Deserialize)]
struct SpawnRequest {
    /// Program plus arguments, as raw bytes (paths are not UTF-8).
    argv: Vec<Vec<u8>>,
    /// Variables to set on top of the spawner's inherited environment.
    envp: Vec<(Vec<u8>, Vec<u8>)>,
    /// Working directory for the helper, when the caller set one.
    cwd: Option<Vec<u8>>,
    /// stdin, stdout, stderr. `Fd` slots consume the passed descriptors
    /// in this order.
    stdio: [StdioSpec; 3],
    /// Descriptor numbers the child should find its remaining passed
    /// descriptors on, in order after the `Fd` stdio slots.
    ///
    /// One caller: `virtiofsd --fd 3 --shared-dir /proc/self/fd/4`, the
    /// only helper k7d hands something other than stdio (pinned-descriptor
    /// verbs). Numbers rather than "the next free fd" because the child
    /// is told which numbers to look at on its command line.
    extra_fds: Vec<u32>,
    /// `setsid()` between fork and exec — the Firecracker jailer without
    /// `--daemonize` asks `getsid(0)` whether it leads a session
    /// (`CHALLENGES.md` #214).
    setsid: bool,
    /// `umask()` between fork and exec, when the caller needs the mode
    /// of files the helper *itself* creates.
    ///
    /// One caller: the Firecracker jailer. Firecracker binds its API
    /// socket and `v.sock` with a plain `UnixListener::bind`, which
    /// takes `0777 & ~umask`, and the jailer sets no umask of its own —
    /// so this is the only place the mode of those two sockets is
    /// decided, and connecting to a Unix socket needs write permission
    /// on it (Firecracker jail staging).
    umask: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
enum Request {
    Spawn(SpawnRequest),
    /// Collect the exit status of an **already exited** helper. The
    /// client polls the pidfd first, so this never blocks the socket.
    Wait {
        pid: u32,
    },
    /// Kill and reap a helper whose handle was dropped unwaited.
    Reap {
        pid: u32,
    },
}

#[derive(Debug, Serialize, Deserialize)]
enum Reply {
    /// Helper forked; its pidfd comes with this datagram.
    Spawned { pid: u32 },
    /// Raw `wait4` status, for [`ExitStatus::from_raw`].
    Exited { raw_status: i32 },
    /// `Reap` completed.
    Done,
    /// The spawner refused or the syscall failed. `errno` is preserved so
    /// `io::Error::kind()` still says `NotFound` for a missing `mkfs.erofs`.
    Failed { errno: i32, message: String },
}

// --- message plumbing -------------------------------------------------

/// `SCM_RIGHTS` control buffer, aligned for `cmsghdr`. Room for
/// [`MAX_PASSED_FDS`]; `CMSG_SPACE(5 * 4)` is 40 bytes.
#[repr(align(8))]
struct CmsgBuf([u8; 64]);

/// Most descriptors one request carries: three stdio slots plus the two
/// `virtiofsd` is handed by number (`--fd`, `--shared-dir
/// /proc/self/fd/N`).
const MAX_PASSED_FDS: usize = 5;

/// A pid as the kernel's signed type. Pids are always below
/// `pid_t::MAX`, but the cast is fallible on paper and the crate does
/// not silence `cast_possible_wrap`.
fn as_pid(pid: u32) -> libc::pid_t {
    libc::pid_t::try_from(pid).unwrap_or(libc::pid_t::MAX)
}

fn last_error() -> io::Error {
    io::Error::last_os_error()
}

/// Send one datagram plus `fds`.
fn send_msg(sock: BorrowedFd<'_>, payload: &[u8], fds: &[RawFd]) -> io::Result<()> {
    assert!(
        fds.len() <= MAX_PASSED_FDS,
        "at most {MAX_PASSED_FDS} fds per request"
    );
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr().cast::<libc::c_void>().cast_mut(),
        iov_len: payload.len(),
    };
    // SAFETY: an all-zero msghdr is the documented "nothing set" value.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    let mut cmsg = CmsgBuf([0u8; 64]);
    if !fds.is_empty() {
        let bytes = u32::try_from(std::mem::size_of_val(fds)).expect("fd array fits u32");
        // SAFETY: CMSG_SPACE/CMSG_LEN are pure arithmetic on their argument.
        let (space, len) = unsafe { (libc::CMSG_SPACE(bytes), libc::CMSG_LEN(bytes)) };
        assert!(space as usize <= cmsg.0.len(), "cmsg buffer too small");
        msg.msg_control = cmsg.0.as_mut_ptr().cast::<libc::c_void>();
        msg.msg_controllen = space as _;
        // SAFETY: msg_control points at an aligned buffer of msg_controllen
        // bytes, so CMSG_FIRSTHDR yields a header inside it; the writes
        // below stay within CMSG_SPACE(bytes).
        unsafe {
            let hdr = libc::CMSG_FIRSTHDR(&raw const msg);
            (*hdr).cmsg_level = libc::SOL_SOCKET;
            (*hdr).cmsg_type = libc::SCM_RIGHTS;
            (*hdr).cmsg_len = len as _;
            std::ptr::copy_nonoverlapping(
                fds.as_ptr(),
                libc::CMSG_DATA(hdr).cast::<RawFd>(),
                fds.len(),
            );
        }
    }
    // SAFETY: `msg` describes `payload` and `cmsg`, both live for the call.
    let sent = unsafe { libc::sendmsg(sock.as_raw_fd(), &raw const msg, 0) };
    if sent < 0 {
        return Err(last_error());
    }
    if sent as usize != payload.len() {
        return Err(io::Error::other(format!(
            "short sendmsg on the spawner socket: {sent} of {} bytes",
            payload.len()
        )));
    }
    Ok(())
}

/// Receive one datagram into `buf`, collecting any passed descriptors.
///
/// `Ok(0)` is EOF: the peer is gone.
fn recv_msg(sock: BorrowedFd<'_>, buf: &mut [u8], fds: &mut Vec<OwnedFd>) -> io::Result<usize> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: buf.len(),
    };
    // SAFETY: an all-zero msghdr is the documented "nothing set" value.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    let mut cmsg = CmsgBuf([0u8; 64]);
    msg.msg_control = cmsg.0.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = cmsg.0.len() as _;
    // SAFETY: `msg` describes `buf` and `cmsg`, both live for the call.
    // MSG_CMSG_CLOEXEC is what keeps a received descriptor from leaking
    // into the next helper.
    let got = unsafe { libc::recvmsg(sock.as_raw_fd(), &raw mut msg, libc::MSG_CMSG_CLOEXEC) };
    if got < 0 {
        return Err(last_error());
    }
    if msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err(io::Error::other(
            "truncated datagram on the spawner socket (payload or SCM_RIGHTS did not fit)",
        ));
    }
    // SAFETY: after a successful recvmsg the control buffer holds
    // well-formed headers; each SCM_RIGHTS payload is `n` descriptors
    // this process now owns.
    unsafe {
        let mut hdr = libc::CMSG_FIRSTHDR(&raw const msg);
        while !hdr.is_null() {
            if (*hdr).cmsg_level == libc::SOL_SOCKET && (*hdr).cmsg_type == libc::SCM_RIGHTS {
                let bytes = (*hdr).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let data = libc::CMSG_DATA(hdr).cast::<RawFd>();
                for i in 0..bytes / std::mem::size_of::<RawFd>() {
                    fds.push(OwnedFd::from_raw_fd(data.add(i).read_unaligned()));
                }
            }
            hdr = libc::CMSG_NXTHDR(&raw const msg, hdr);
        }
    }
    Ok(got as usize)
}

// --- the parent's handle ----------------------------------------------

/// The daemon's end of the spawner socketpair.
struct Spawner {
    conn: Mutex<OwnedFd>,
    pid: u32,
}

static SPAWNER: OnceLock<Spawner> = OnceLock::new();

/// Set by the daemon's signal handler via [`mark_shutting_down`]. Read
/// by the watchdog so a spawner that dies while the whole unit is going
/// down is not reported as a crash.
static SHUTTING_DOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Tell the watchdog the daemon is on its way out, so it does not turn
/// a dying spawner into a non-zero exit.
///
/// Called from the `SIGTERM`/`SIGINT` handler, so this does nothing but
/// store to an atomic.
pub fn mark_shutting_down() {
    SHUTTING_DOWN.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Pid of the spawner child, when this process forked one. Reported by
/// `k7d doctor` so an operator (and the hardening test) can check the
/// *second* filter from outside.
#[must_use]
pub fn pid() -> Option<u32> {
    SPAWNER.get().map(|s| s.pid)
}

/// Fork the spawner. Call once, from `main`, after `handle_info_flags()`
/// and before `env_logger::init()`, the signal handlers, `seccomp`, the
/// pool, or any thread.
pub fn start() -> Result<u32, String> {
    if let Some(existing) = SPAWNER.get() {
        return Err(format!(
            "spawner already started (pid {}) — a second one would inherit the daemon's filter",
            existing.pid
        ));
    }
    let mut socks = [-1i32; 2];
    // SAFETY: `socks` is a valid 2-element array for socketpair(2) to fill.
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            socks.as_mut_ptr(),
        )
    };
    if rc < 0 {
        return Err(format!("socketpair for the spawner: {}", last_error()));
    }
    // SAFETY: socketpair returned two fresh descriptors this process owns.
    let (ours, theirs) = unsafe {
        (
            OwnedFd::from_raw_fd(socks[0]),
            OwnedFd::from_raw_fd(socks[1]),
        )
    };

    // SAFETY: the caller guarantees this process is still single-threaded
    // (see the module docs), so the child inherits no held lock.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork the spawner: {}", last_error()));
    }
    if pid == 0 {
        drop(ours);
        child_main(theirs);
    }
    drop(theirs);
    let pid = pid as u32;
    let watch = pidfd_open(pid).map_err(|e| format!("pidfd_open on the spawner: {e}"))?;
    SPAWNER
        .set(Spawner {
            conn: Mutex::new(ours),
            pid,
        })
        .map_err(|_| "spawner already started".to_string())?;
    watch_spawner(watch, pid);
    Ok(pid)
}

/// Exit the daemon when the spawner dies: without it there is no way to
/// bring a network up, mount a share or boot a Firecracker VM, and a
/// replacement cannot be forked once the daemon's filter is installed.
/// systemd restarts the pair; live VMs die with the process as they do
/// on any daemon crash.
fn watch_spawner(pidfd: OwnedFd, pid: u32) {
    std::thread::Builder::new()
        .name("k7d-spawner-watch".into())
        .spawn(move || {
            let mut poll_fd = libc::pollfd {
                fd: pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            loop {
                // SAFETY: one valid pollfd for the length given.
                let rc = unsafe { libc::poll(&raw mut poll_fd, 1, 1000) };
                if rc < 0 {
                    let e = last_error();
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    log::error!("spawner watchdog: poll: {e}");
                    continue;
                }
                if rc == 0 {
                    continue;
                }
                break;
            }
            let mut status = 0;
            // SAFETY: the spawner is this process's child; `status` is valid.
            unsafe { libc::waitpid(as_pid(pid), &raw mut status, 0) };
            let how = if libc::WIFSIGNALED(status) {
                format!("killed by signal {}", libc::WTERMSIG(status))
            } else {
                format!("exited {}", libc::WEXITSTATUS(status))
            };
            // A spawner that goes while the unit is stopping is the
            // shutdown working, not a crash: systemd signals the whole
            // cgroup, so exiting non-zero here would make every
            // `systemctl restart` a failure and, with
            // `Restart=on-failure`, a restart loop.
            if SHUTTING_DOWN.load(std::sync::atomic::Ordering::SeqCst) {
                log::info!("spawner (pid {pid}) {how} during shutdown");
                return;
            }
            log::error!(
                "spawner (pid {pid}) is gone ({how}) — k7d cannot exec a helper any more and \
                 cannot fork a replacement behind its own seccomp filter; exiting"
            );
            eprintln!("k7d: spawner pid {pid} {how}; exiting");
            std::process::exit(1);
        })
        .expect("spawn the spawner watchdog thread");
}

/// A protocol error means the spawner and the daemon disagree about what
/// is being exec'd. Abort rather than guess.
fn protocol_abort(what: &str) -> ! {
    log::error!("spawner protocol error: {what}");
    eprintln!("k7d: spawner protocol error: {what}");
    std::process::abort();
}

/// One request/reply round trip. Holds the connection lock for exactly
/// that long.
fn round_trip(request: &Request, fds: &[RawFd]) -> Result<(Reply, Vec<OwnedFd>), io::Error> {
    let spawner = SPAWNER.get().expect("round_trip without a spawner");
    let payload = serde_json::to_vec(request).map_err(io::Error::other)?;
    if payload.len() > MESSAGE_MAX {
        return Err(io::Error::other(format!(
            "spawn request is {} bytes, over the {MESSAGE_MAX}-byte datagram limit",
            payload.len()
        )));
    }
    let conn = spawner
        .conn
        .lock()
        .unwrap_or_else(|_| protocol_abort("connection mutex poisoned"));
    if let Err(e) = send_msg(conn.as_fd(), &payload, fds) {
        protocol_abort(&format!("sendmsg: {e}"));
    }
    let mut buf = vec![0u8; MESSAGE_MAX];
    let mut received = Vec::new();
    let got = match recv_msg(conn.as_fd(), &mut buf, &mut received) {
        Ok(0) => protocol_abort("the spawner closed the socket"),
        Ok(n) => n,
        Err(e) => protocol_abort(&format!("recvmsg: {e}")),
    };
    drop(conn);
    match serde_json::from_slice::<Reply>(&buf[..got]) {
        Ok(reply) => Ok((reply, received)),
        Err(e) => protocol_abort(&format!("undecodable reply: {e}")),
    }
}

// --- the child --------------------------------------------------------

/// The spawner process. Never returns.
fn child_main(sock: OwnedFd) -> ! {
    let sock = match seat_socket(sock) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("k7d spawner: {e}");
            // SAFETY: _exit is async-signal-safe and never returns.
            unsafe { libc::_exit(1) };
        }
    };
    ignore_unit_shutdown_signals();
    if let Err(e) = crate::seccomp::install_for_spawner() {
        eprintln!("k7d spawner: seccomp: {e}");
        // SAFETY: as above.
        unsafe { libc::_exit(1) };
    }
    serve(&sock)
}

/// Signal handler that does nothing: the spawner's exit condition is
/// EOF on its socket, never a signal.
extern "C" fn ignore_signal(_sig: libc::c_int) {}

/// Survive the cgroup-wide `SIGTERM` that `systemctl stop`/`restart`
/// sends, so the daemon can shut down in its own time and the spawner
/// can leave on the EOF that follows.
///
/// A *handler* rather than `SIG_IGN` on purpose: `execve` resets caught
/// signals to their default disposition but leaves ignored ones
/// ignored, so `SIG_IGN` here would hand every helper — `virtiofsd`,
/// the jailer, Firecracker itself — a process that cannot be asked to
/// terminate.
fn ignore_unit_shutdown_signals() {
    // SAFETY: `ignore_signal` has an empty body, which is
    // async-signal-safe by construction.
    unsafe {
        libc::signal(libc::SIGTERM, ignore_signal as libc::sighandler_t);
        libc::signal(libc::SIGINT, ignore_signal as libc::sighandler_t);
    }
}

/// Put the socket on [`SPAWNER_SOCK_FD`], mark it `CLOEXEC` (so no
/// helper inherits it), and close every other inherited descriptor above
/// the standard three — which the spawner keeps, because `StdioSpec::Inherit`
/// means "the daemon's journald stdio".
fn seat_socket(sock: OwnedFd) -> io::Result<OwnedFd> {
    let raw = sock.into_raw_fd();
    if raw != SPAWNER_SOCK_FD {
        // SAFETY: both arguments are descriptors this process owns; dup2
        // closes the destination if it was open.
        if unsafe { libc::dup2(raw, SPAWNER_SOCK_FD) } < 0 {
            return Err(last_error());
        }
        // SAFETY: `raw` is owned here and no longer referenced.
        unsafe { libc::close(raw) };
    }
    // dup2 clears CLOEXEC on the new descriptor; put it back.
    // SAFETY: F_SETFD on a descriptor this process owns.
    if unsafe { libc::fcntl(SPAWNER_SOCK_FD, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(last_error());
    }
    // SAFETY: close_range(2) on a half-open range this process owns
    // nothing meaningful in; EINVAL on old kernels is tolerated below.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            SPAWNER_SOCK_FD as libc::c_uint + 1,
            libc::c_uint::MAX,
            0,
        )
    };
    if rc < 0 {
        return Err(last_error());
    }
    // SAFETY: SPAWNER_SOCK_FD is open and owned by this process.
    Ok(unsafe { OwnedFd::from_raw_fd(SPAWNER_SOCK_FD) })
}

/// Request loop. EOF means the daemon is gone; nothing else can ask for
/// a helper, so the spawner exits with it.
fn serve(sock: &OwnedFd) -> ! {
    let mut children: HashMap<u32, std::process::Child> = HashMap::new();
    let mut buf = vec![0u8; MESSAGE_MAX];
    loop {
        let mut fds = Vec::new();
        let got = match recv_msg(sock.as_fd(), &mut buf, &mut fds) {
            Ok(0) => {
                // SAFETY: async-signal-safe; the daemon is gone.
                unsafe { libc::_exit(0) };
            }
            Ok(n) => n,
            // The unit-wide `SIGTERM` lands here as `EINTR`, since the
            // spawner catches it rather than dying of it. Waiting again
            // is right: the daemon's shutdown closes the socket and the
            // next call returns the EOF above.
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                eprintln!("k7d spawner: recvmsg: {e}");
                // SAFETY: as above.
                unsafe { libc::_exit(1) };
            }
        };
        let request: Request = match serde_json::from_slice(&buf[..got]) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("k7d spawner: undecodable request: {e}");
                std::process::abort();
            }
        };
        let (reply, reply_fds) = handle(&request, fds, &mut children);
        let payload = match serde_json::to_vec(&reply) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("k7d spawner: unencodable reply: {e}");
                std::process::abort();
            }
        };
        let raw: Vec<RawFd> = reply_fds.iter().map(AsRawFd::as_raw_fd).collect();
        if let Err(e) = send_msg(sock.as_fd(), &payload, &raw) {
            eprintln!("k7d spawner: sendmsg: {e}");
            std::process::abort();
        }
    }
}

/// A spawner-side refusal with no errno of its own.
fn failed(message: String) -> (Reply, Vec<OwnedFd>) {
    (Reply::Failed { errno: 0, message }, Vec::new())
}

fn handle(
    request: &Request,
    fds: Vec<OwnedFd>,
    children: &mut HashMap<u32, std::process::Child>,
) -> (Reply, Vec<OwnedFd>) {
    match request {
        Request::Spawn(req) => spawn_helper(req, fds, children),
        Request::Wait { pid } => match children.remove(pid) {
            // The client polls the helper's pidfd before asking, so the
            // process is already a zombie and this does not block.
            Some(mut child) => match child.wait() {
                Ok(status) => (
                    Reply::Exited {
                        raw_status: status.into_raw(),
                    },
                    Vec::new(),
                ),
                Err(e) => failed(format!("wait for {pid}: {e}")),
            },
            None => failed(format!("wait for {pid}: not a helper of this spawner")),
        },
        Request::Reap { pid } => match children.remove(pid) {
            Some(mut child) => {
                let _ = child.kill();
                let _ = child.wait();
                (Reply::Done, Vec::new())
            }
            None => failed(format!("reap {pid}: not a helper of this spawner")),
        },
    }
}

fn spawn_helper(
    req: &SpawnRequest,
    fds: Vec<OwnedFd>,
    children: &mut HashMap<u32, std::process::Child>,
) -> (Reply, Vec<OwnedFd>) {
    let mut argv = req.argv.iter();
    let Some(program) = argv.next() else {
        return failed("spawn request has an empty argv".to_string());
    };
    let mut cmd = std::process::Command::new(OsStr::from_bytes(program));
    for arg in argv {
        cmd.arg(OsStr::from_bytes(arg));
    }
    for (k, v) in &req.envp {
        cmd.env(OsStr::from_bytes(k), OsStr::from_bytes(v));
    }
    if let Some(cwd) = &req.cwd {
        cmd.current_dir(Path::new(OsStr::from_bytes(cwd)));
    }
    let mut passed = fds.into_iter();
    for (slot, spec) in req.stdio.iter().enumerate() {
        let stdio = match spec {
            StdioSpec::Null => std::process::Stdio::null(),
            StdioSpec::Inherit => std::process::Stdio::inherit(),
            StdioSpec::Fd => match passed.next() {
                Some(fd) => std::process::Stdio::from(fd),
                None => return failed(format!("stdio slot {slot} wants an fd, none was passed")),
            },
        };
        match slot {
            0 => cmd.stdin(stdio),
            1 => cmd.stdout(stdio),
            _ => cmd.stderr(stdio),
        };
    }
    let extras: Vec<OwnedFd> = passed.collect();
    let placed = match place_extra_fds(&mut cmd, &extras, &req.extra_fds) {
        Ok(held) => held,
        Err(e) => return failed(e.to_string()),
    };
    apply_pre_exec(&mut cmd, req.setsid, req.umask);
    let spawned = cmd.spawn();
    drop((placed, extras));
    match spawned {
        Ok(child) => {
            let pid = child.id();
            match pidfd_open(pid) {
                Ok(pidfd) => {
                    children.insert(pid, child);
                    (Reply::Spawned { pid }, vec![pidfd])
                }
                Err(e) => {
                    let mut child = child;
                    let _ = child.kill();
                    let _ = child.wait();
                    failed(format!("pidfd_open for helper {pid}: {e}"))
                }
            }
        }
        Err(e) => (
            Reply::Failed {
                errno: e.raw_os_error().unwrap_or(0),
                message: format!(
                    "spawn {}: {e}",
                    String::from_utf8_lossy(&req.argv[0]).into_owned()
                ),
            },
            Vec::new(),
        ),
    }
}

// --- the client surface -----------------------------------------------

/// What a child's stdio descriptor should be. Mirrors the subset of
/// [`std::process::Stdio`] the call sites use, minus `piped()` on stdin
/// (nothing in k7d writes to a helper's stdin — `nft` gets a file).
#[derive(Debug)]
pub enum Stdio {
    /// `/dev/null`.
    Null,
    /// The daemon's own descriptor.
    Inherit,
    /// A pipe this process reads.
    Piped,
    /// An open descriptor to hand over.
    Fd(OwnedFd),
}

impl From<std::fs::File> for Stdio {
    fn from(file: std::fs::File) -> Self {
        Self::Fd(OwnedFd::from(file))
    }
}

impl From<OwnedFd> for Stdio {
    fn from(fd: OwnedFd) -> Self {
        Self::Fd(fd)
    }
}

/// A helper to run, with the `std::process::Command` surface k7d uses.
///
/// `Command::new` lives in this module and nowhere else in the crate
/// (`only_spawner_execs` enforces it): the point of the increment is
/// that one process execs.
#[derive(Debug)]
pub struct Command {
    argv: Vec<OsString>,
    envp: Vec<(OsString, OsString)>,
    cwd: Option<PathBuf>,
    stdin: Stdio,
    stdout: Stdio,
    stderr: Stdio,
    setsid: bool,
    umask: Option<u32>,
    extra: Vec<(u32, OwnedFd)>,
}

/// Start building a helper invocation.
pub fn command<S: AsRef<OsStr>>(program: S) -> Command {
    Command {
        argv: vec![program.as_ref().to_os_string()],
        envp: Vec::new(),
        cwd: None,
        stdin: Stdio::Inherit,
        stdout: Stdio::Inherit,
        stderr: Stdio::Inherit,
        setsid: false,
        umask: None,
        extra: Vec::new(),
    }
}

impl Command {
    /// Append one argument.
    pub fn arg<S: AsRef<OsStr>>(&mut self, arg: S) -> &mut Self {
        self.argv.push(arg.as_ref().to_os_string());
        self
    }

    /// Append several arguments.
    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        for arg in args {
            self.arg(arg);
        }
        self
    }

    /// Set one environment variable on top of the daemon's environment.
    pub fn env<K: AsRef<OsStr>, V: AsRef<OsStr>>(&mut self, key: K, value: V) -> &mut Self {
        self.envp
            .push((key.as_ref().to_os_string(), value.as_ref().to_os_string()));
        self
    }

    /// Working directory for the helper.
    pub fn current_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut Self {
        self.cwd = Some(dir.as_ref().to_path_buf());
        self
    }

    /// stdin. `Stdio::Piped` is rejected at spawn time.
    pub fn stdin<S: Into<Stdio>>(&mut self, stdio: S) -> &mut Self {
        self.stdin = stdio.into();
        self
    }

    /// stdout.
    pub fn stdout<S: Into<Stdio>>(&mut self, stdio: S) -> &mut Self {
        self.stdout = stdio.into();
        self
    }

    /// stderr.
    pub fn stderr<S: Into<Stdio>>(&mut self, stdio: S) -> &mut Self {
        self.stderr = stdio.into();
        self
    }

    /// Ask for `setsid()` between fork and exec.
    pub fn setsid(&mut self, yes: bool) -> &mut Self {
        self.setsid = yes;
        self
    }

    /// Set the helper's `umask` between fork and exec.
    ///
    /// For a helper that creates a file whose mode nothing else can
    /// choose. The Firecracker jailer is the one caller: the sockets
    /// Firecracker binds inside the jail get `0777 & ~umask` and no
    /// `chmod` afterwards, and one of them does not exist until long
    /// after the node broker could have re-moded it.
    pub fn umask(&mut self, mask: u32) -> &mut Self {
        self.umask = Some(mask);
        self
    }

    /// Hand the helper `fd` as descriptor number `target`.
    ///
    /// For a helper whose command line names a descriptor —
    /// `virtiofsd --fd 3`, which is how a vhost-user socket the caller
    /// already bound reaches it (`virtiofsd.spawn` / pinned-descriptor
    /// verbs). Everything else
    /// goes through the three stdio slots.
    pub fn fd(&mut self, target: u32, fd: OwnedFd) -> &mut Self {
        self.extra.push((target, fd));
        self
    }

    /// Fork and exec the helper, returning a handle.
    pub fn spawn(&mut self) -> io::Result<Child> {
        let mut specs = [StdioSpec::Null; 3];
        let mut pass: Vec<OwnedFd> = Vec::new();
        let mut reads: [Option<OwnedFd>; 3] = [None, None, None];
        for (slot, stdio) in [&mut self.stdin, &mut self.stdout, &mut self.stderr]
            .into_iter()
            .enumerate()
        {
            specs[slot] = match std::mem::replace(stdio, Stdio::Null) {
                Stdio::Null => StdioSpec::Null,
                Stdio::Inherit => StdioSpec::Inherit,
                Stdio::Fd(fd) => {
                    pass.push(fd);
                    StdioSpec::Fd
                }
                Stdio::Piped => {
                    if slot == 0 {
                        return Err(io::Error::other(
                            "spawner: a piped stdin is not supported (write to a file instead)",
                        ));
                    }
                    let (read, write) = crate::fdutil::pipe_cloexec()?;
                    reads[slot] = Some(read);
                    pass.push(write);
                    StdioSpec::Fd
                }
            };
        }
        let [_, stdout, stderr] = reads;
        let mut extra_fds = Vec::with_capacity(self.extra.len());
        for (target, fd) in std::mem::take(&mut self.extra) {
            extra_fds.push(target);
            pass.push(fd);
        }
        let request = SpawnRequest {
            argv: self
                .argv
                .iter()
                .map(|a| a.as_os_str().as_bytes().to_vec())
                .collect(),
            envp: self
                .envp
                .iter()
                .map(|(k, v)| {
                    (
                        k.as_os_str().as_bytes().to_vec(),
                        v.as_os_str().as_bytes().to_vec(),
                    )
                })
                .collect(),
            cwd: self.cwd.as_ref().map(|p| p.as_os_str().as_bytes().to_vec()),
            stdio: specs,
            extra_fds,
            setsid: self.setsid,
            umask: self.umask,
        };
        let (pid, pidfd, local) = if SPAWNER.get().is_some() {
            let (pid, pidfd) = spawn_remote(request, &pass)?;
            (pid, pidfd, None)
        } else {
            let (pid, pidfd, child) = spawn_local(&request, pass)?;
            (pid, pidfd, Some(child))
        };
        Ok(Child {
            pid,
            pidfd,
            local,
            stdout,
            stderr,
            status: None,
        })
    }

    /// Run to completion with inherited stdio, returning the status.
    pub fn status(&mut self) -> io::Result<ExitStatus> {
        self.spawn()?.wait()
    }

    /// Run to completion capturing stdout and stderr, as
    /// `std::process::Command::output` does: stdin is `/dev/null` and
    /// both output streams are pipes.
    ///
    /// The write ends live in the helper only — they are passed with
    /// `SCM_RIGHTS` and dropped here before the drain starts, which is
    /// what makes the read ends see EOF at all (`docs/bug-candidates.md`
    /// #28: a write end left open in this process, or in the spawner,
    /// hangs the read forever).
    pub fn output(&mut self) -> io::Result<Output> {
        if matches!(self.stdin, Stdio::Inherit) {
            self.stdin = Stdio::Null;
        }
        if matches!(self.stdout, Stdio::Inherit) {
            self.stdout = Stdio::Piped;
        }
        if matches!(self.stderr, Stdio::Inherit) {
            self.stderr = Stdio::Piped;
        }
        self.spawn()?.wait_with_output()
    }
}

/// Ask the spawner to exec. The passed descriptors are dropped on
/// return: the helper holds the only copies.
fn spawn_remote(request: SpawnRequest, pass: &[OwnedFd]) -> io::Result<(u32, OwnedFd)> {
    let raw: Vec<RawFd> = pass.iter().map(AsRawFd::as_raw_fd).collect();
    let (reply, mut fds) = round_trip(&Request::Spawn(request), &raw)?;
    match reply {
        Reply::Spawned { pid } => {
            if fds.len() != 1 {
                protocol_abort("Spawned reply without exactly one pidfd");
            }
            Ok((pid, fds.remove(0)))
        }
        Reply::Failed { errno, message } => Err(spawner_error(errno, message)),
        other => protocol_abort(&format!("unexpected reply to Spawn: {other:?}")),
    }
}

fn spawner_error(errno: i32, message: String) -> io::Error {
    if errno == 0 {
        io::Error::other(message)
    } else {
        // Keep the errno so callers that branch on `ErrorKind::NotFound`
        // (a node without `mkfs.erofs`) still see it through the spawner.
        io::Error::new(io::Error::from_raw_os_error(errno).kind(), message)
    }
}

/// Arrange for `extras[i]` to be descriptor `targets[i]` in the child.
///
/// Two steps, and both are needed. The sources are first moved above
/// every target with `F_DUPFD_CLOEXEC`, because a `dup2(from, to)` where
/// `from` is itself one of the targets would close a descriptor a later
/// iteration still has to copy. Then a `pre_exec` closure does the
/// `dup2`s, which is also what clears `CLOEXEC` on them — it is the only
/// reason they survive the `execve` at all.
///
/// Returns the relocated sources; they must stay alive until after
/// `spawn`, since the closure runs in the forked child and refers to
/// their numbers.
fn place_extra_fds(
    cmd: &mut std::process::Command,
    extras: &[OwnedFd],
    targets: &[u32],
) -> io::Result<Vec<OwnedFd>> {
    if extras.len() != targets.len() {
        return Err(io::Error::other(format!(
            "spawner: {} extra descriptor(s) passed for {} target slot(s)",
            extras.len(),
            targets.len()
        )));
    }
    if extras.is_empty() {
        return Ok(Vec::new());
    }
    let above = RawFd::try_from(targets.iter().copied().max().unwrap_or(0))
        .map_err(|_| io::Error::other("spawner: extra fd target out of range"))?
        + 1;
    let mut held = Vec::with_capacity(extras.len());
    let mut moves: Vec<(RawFd, RawFd)> = Vec::with_capacity(extras.len());
    for (fd, target) in extras.iter().zip(targets) {
        // SAFETY: `fd` is a live descriptor this process owns; F_DUPFD_
        // CLOEXEC returns a new one and does not consume it.
        let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, above) };
        if raw < 0 {
            return Err(last_error());
        }
        // SAFETY: fcntl returned a fresh descriptor this process owns.
        held.push(unsafe { OwnedFd::from_raw_fd(raw) });
        moves.push((
            raw,
            RawFd::try_from(*target)
                .map_err(|_| io::Error::other("spawner: extra fd target out of range"))?,
        ));
    }
    // SAFETY: the closure calls `dup2` alone — async-signal-safe, and it
    // touches no allocator or lock between `fork` and `execve`.
    unsafe {
        cmd.pre_exec(move || {
            for (from, to) in &moves {
                if libc::dup2(*from, *to) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    Ok(held)
}

/// The two things k7d asks for between `fork` and `execve`. Both are
/// async-signal-safe and touch nothing the closure does not own.
fn apply_pre_exec(cmd: &mut std::process::Command, setsid: bool, umask: Option<u32>) {
    if !setsid && umask.is_none() {
        return;
    }
    // SAFETY: `setsid` and `umask` are async-signal-safe, and the
    // closure allocates nothing and touches no shared state.
    unsafe {
        cmd.pre_exec(move || {
            if setsid && libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            if let Some(mask) = umask {
                libc::umask(mask as libc::mode_t);
            }
            Ok(())
        })
    };
}

/// Exec in this process. The shim and the test binaries take this path;
/// the daemon never does (see the module docs).
fn spawn_local(
    request: &SpawnRequest,
    pass: Vec<OwnedFd>,
) -> io::Result<(u32, OwnedFd, std::process::Child)> {
    let mut argv = request.argv.iter();
    let program = argv
        .next()
        .ok_or_else(|| io::Error::other("spawn request has an empty argv"))?;
    let mut cmd = std::process::Command::new(OsStr::from_bytes(program));
    for arg in argv {
        cmd.arg(OsStr::from_bytes(arg));
    }
    for (k, v) in &request.envp {
        cmd.env(OsStr::from_bytes(k), OsStr::from_bytes(v));
    }
    if let Some(cwd) = &request.cwd {
        cmd.current_dir(Path::new(OsStr::from_bytes(cwd)));
    }
    let mut passed = pass.into_iter();
    for (slot, spec) in request.stdio.iter().enumerate() {
        let stdio = match spec {
            StdioSpec::Null => std::process::Stdio::null(),
            StdioSpec::Inherit => std::process::Stdio::inherit(),
            StdioSpec::Fd => std::process::Stdio::from(
                passed
                    .next()
                    .ok_or_else(|| io::Error::other("stdio slot wants an fd, none was passed"))?,
            ),
        };
        match slot {
            0 => cmd.stdin(stdio),
            1 => cmd.stdout(stdio),
            _ => cmd.stderr(stdio),
        };
    }
    let extras: Vec<OwnedFd> = passed.collect();
    let placed = place_extra_fds(&mut cmd, &extras, &request.extra_fds)?;
    apply_pre_exec(&mut cmd, request.setsid, request.umask);
    let child = cmd.spawn();
    drop((placed, extras));
    let mut child = child?;
    let pid = child.id();
    // No pidfd, no race-free wait — kill what was just started rather
    // than fall back to the `waitpid` the shim's Tokio reaper steals.
    let pidfd = match pidfd_open(pid) {
        Ok(fd) => fd,
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
    };
    Ok((pid, pidfd, child))
}

/// `pidfd_open(2)`. Always `CLOEXEC` per the man page, so it never
/// reaches a helper.
fn pidfd_open(pid: u32) -> io::Result<OwnedFd> {
    // SAFETY: pidfd_open takes a pid and flags and returns a descriptor.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, as_pid(pid), 0u32) };
    if raw < 0 {
        return Err(last_error());
    }
    // SAFETY: the syscall returned a fresh descriptor this process owns.
    Ok(unsafe { OwnedFd::from_raw_fd(raw as RawFd) })
}

/// A running helper.
///
/// Two hops away in the daemon (helper → spawner → daemon), so
/// `wait`/`kill` go through the pidfd and the spawner rather than
/// `waitpid` on a process that is not this one's child.
#[derive(Debug)]
pub struct Child {
    pid: u32,
    pidfd: OwnedFd,
    /// Present only on the in-process path.
    local: Option<std::process::Child>,
    /// Read end of the stdout pipe, when `Stdio::Piped` was asked for.
    stdout: Option<OwnedFd>,
    /// Read end of the stderr pipe.
    stderr: Option<OwnedFd>,
    status: Option<ExitStatus>,
}

impl Child {
    /// Helper pid, in the host pid namespace.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.pid
    }

    /// A duplicate of the helper's pidfd.
    ///
    /// For a caller that has to give someone else a way to notice the
    /// exit: the node broker sends this across the broker channel so the
    /// VM broker can poll a `virtiofsd` it is not allowed to `wait` for
    /// (privilege separation). A duplicate, because this handle's own
    /// `wait`/`kill` still need theirs.
    pub fn pidfd_dup(&self) -> io::Result<OwnedFd> {
        self.pidfd.try_clone()
    }

    /// `SIGKILL` the helper. Sent from this process: the daemon holds
    /// `CAP_KILL`, and the spawner keeps the pid unreaped until
    /// [`Child::wait`], so it cannot land on a recycled pid.
    pub fn kill(&mut self) -> io::Result<()> {
        if self.status.is_some() {
            return Ok(());
        }
        // SAFETY: kill(2) with a pid this process holds a pidfd for.
        if unsafe { libc::kill(as_pid(self.pid), libc::SIGKILL) } < 0 {
            let e = last_error();
            // Already exited: the reap is still owed, which `wait` does.
            if e.raw_os_error() != Some(libc::ESRCH) {
                return Err(e);
            }
        }
        Ok(())
    }

    /// Wait for the helper and return its status.
    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        if let Some(status) = self.status {
            return Ok(status);
        }
        self.poll_exit()?;
        let status = match self.local.take() {
            // In-process: collect through the pidfd rather than
            // `waitpid`, which loses the status to the shim's Tokio
            // SIGCHLD reaper (ECHILD — every `ip`/`nsenter` call in
            // `attach_to_pod_netns` appeared to fail).
            Some(child) => self.collect_local(child)?,
            None => self.collect_remote()?,
        };
        self.status = Some(status);
        Ok(status)
    }

    /// Drain stdout and stderr to EOF, then wait.
    pub fn wait_with_output(mut self) -> io::Result<Output> {
        let (stdout, stderr) = drain(self.stdout.take(), self.stderr.take())?;
        let status = self.wait()?;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }

    /// Block until the helper exits.
    fn poll_exit(&self) -> io::Result<()> {
        let mut poll_fd = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            // SAFETY: one valid pollfd for the length given.
            let rc = unsafe { libc::poll(&raw mut poll_fd, 1, -1) };
            if rc < 0 {
                let e = last_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            return Ok(());
        }
    }

    fn collect_local(&self, child: std::process::Child) -> io::Result<ExitStatus> {
        // SAFETY: siginfo_t is plain old data and an all-zero bit pattern
        // is the "uninitialized" value waitid documents.
        let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: P_PIDFD with a pidfd this process owns; `si` is valid
        // for the call.
        let rc = unsafe {
            libc::waitid(
                libc::P_PIDFD,
                self.pidfd.as_raw_fd() as libc::id_t,
                &raw mut si,
                libc::WEXITED,
            )
        };
        drop(child);
        if rc < 0 {
            let e = last_error();
            if e.raw_os_error() == Some(libc::ECHILD) {
                // A SIGCHLD reaper (Tokio, in the shim) got there first.
                // The commands on this path are idempotent `ip`/`nsenter`
                // invocations; success-of-unknown-status is what the
                // pre-spawner code did and the alternative is to fall over.
                return Ok(ExitStatus::from_raw(0));
            }
            return Err(e);
        }
        // SAFETY: after a successful waitid these are the integer fields
        // the kernel filled in.
        let raw = unsafe {
            let status = si.si_status();
            if si.si_code == libc::CLD_EXITED {
                (status & 0xff) << 8
            } else {
                status & 0x7f
            }
        };
        Ok(ExitStatus::from_raw(raw))
    }

    fn collect_remote(&self) -> io::Result<ExitStatus> {
        let (reply, fds) = round_trip(&Request::Wait { pid: self.pid }, &[])?;
        if !fds.is_empty() {
            protocol_abort("Wait reply carried descriptors");
        }
        match reply {
            Reply::Exited { raw_status } => Ok(ExitStatus::from_raw(raw_status)),
            Reply::Failed { errno, message } => Err(spawner_error(errno, message)),
            other => protocol_abort(&format!("unexpected reply to Wait: {other:?}")),
        }
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if self.status.is_some() {
            return;
        }
        if self.local.is_some() {
            // std leaves the zombie to the caller too; the sites that
            // drop unwaited are `let _ = …` teardown paths.
            return;
        }
        // The spawner is the parent, so an unwaited helper stays a zombie
        // in *its* table until told otherwise.
        let _ = round_trip(&Request::Reap { pid: self.pid }, &[]);
    }
}

/// Read both pipes to EOF without deadlocking on either: a helper that
/// fills the pipe we are not reading would otherwise block forever
/// (`std::process::Command::output` uses two readers for the same
/// reason).
fn drain(stdout: Option<OwnedFd>, stderr: Option<OwnedFd>) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut out = (Vec::new(), Vec::new());
    let mut ends = [stdout, stderr];
    loop {
        let mut polls: Vec<libc::pollfd> = Vec::with_capacity(2);
        let mut which: Vec<usize> = Vec::with_capacity(2);
        for (i, end) in ends.iter().enumerate() {
            if let Some(fd) = end {
                polls.push(libc::pollfd {
                    fd: fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                });
                which.push(i);
            }
        }
        if polls.is_empty() {
            return Ok(out);
        }
        // SAFETY: `polls` is valid for the length passed.
        let rc = unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, -1) };
        if rc < 0 {
            let e = last_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        for (slot, poll) in which.iter().zip(polls.iter()) {
            if poll.revents == 0 {
                continue;
            }
            let mut buf = [0u8; 8192];
            // SAFETY: reading into a local buffer from a descriptor we own.
            let n =
                unsafe { libc::read(poll.fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
            if n < 0 {
                let e = last_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if n == 0 {
                ends[*slot] = None;
                continue;
            }
            let sink = if *slot == 0 { &mut out.0 } else { &mut out.1 };
            sink.extend_from_slice(&buf[..n as usize]);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    /// The rule the increment rests on: exactly one module in the crate
    /// calls `Command::new`. Same shape as `fdutil`'s pipe lint.
    #[test]
    fn only_spawner_execs() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        rust_files(&src, &mut files);
        assert!(files.len() > 10, "found only {} source files", files.len());
        let mut offenders = Vec::new();
        for path in files {
            if path.file_name().is_some_and(|n| n == "spawner.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read source");
            for (i, line) in text.lines().enumerate() {
                if line.contains("Command::new(") {
                    offenders.push(format!("{}:{}: {}", path.display(), i + 1, line.trim()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "Command::new outside spawner.rs — the daemon's seccomp filter has no `execve`, so \
             these would die with SIGSYS; use spawner::command():\n{}",
            offenders.join("\n")
        );
    }

    fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read src dir").flatten() {
            let path = entry.path();
            if path.is_dir() {
                rust_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    /// The in-process path (what the shim and these tests take) runs a
    /// helper, captures both streams, and reports the status.
    #[test]
    fn local_backend_captures_output_and_status() {
        let out = command("/bin/sh")
            .args(["-c", "echo out; echo err >&2; exit 3"])
            .output()
            .expect("run /bin/sh");
        assert_eq!(out.status.code(), Some(3));
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "out");
        assert_eq!(String::from_utf8_lossy(&out.stderr).trim(), "err");
    }

    /// A missing program keeps its `ErrorKind` — `erofs.rs` branches on
    /// it to say "install erofs-utils" instead of "mkfs failed".
    #[test]
    fn missing_program_is_not_found() {
        let err = command("/nonexistent/k7d-helper")
            .output()
            .expect_err("must fail");
        assert_eq!(err.kind(), io::ErrorKind::NotFound, "{err}");
    }

    /// `output()` must not leave the write end of its own pipe open, or
    /// the drain never sees EOF. A helper that exits without writing is
    /// the shortest test of that.
    #[test]
    fn output_sees_eof_when_the_helper_writes_nothing() {
        let out = command("/bin/true").output().expect("run /bin/true");
        assert!(out.status.success());
        assert!(out.stdout.is_empty() && out.stderr.is_empty());
    }

    /// A helper's `/proc/self/fd` holds only the descriptors the request
    /// passed: its three stdio slots, plus whatever the helper itself
    /// opens. The helper-fd assertion from Firecracker jail integrity,
    /// now on the spawner's surface.
    #[test]
    fn helper_inherits_only_its_stdio() {
        let out = command("/bin/sh")
            .args(["-c", "ls /proc/self/fd"])
            .output()
            .expect("run ls /proc/self/fd");
        let listing = String::from_utf8_lossy(&out.stdout);
        let extra: Vec<&str> = listing
            .split_whitespace()
            .filter(|fd| fd.parse::<u32>().is_ok_and(|n| n > 3))
            .collect();
        assert!(
            extra.is_empty(),
            "helper inherited descriptors beyond its stdio: {extra:?} in {listing:?}"
        );
    }

    #[test]
    fn piped_stdin_is_refused_loudly() {
        let err = command("/bin/true")
            .stdin(Stdio::Piped)
            .status()
            .expect_err("piped stdin must be refused");
        assert!(err.to_string().contains("piped stdin"), "{err}");
    }
}
