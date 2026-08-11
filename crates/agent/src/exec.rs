//! Interactive PTY exec — `kubectl exec -it` support.
//!
//! One PTY exec session = one dedicated vsock connection. After the
//! `container_exec_pty` handshake (handled by `main.rs`'s connection
//! loop, which hands the connection over to [`run_pty_session`]), both
//! directions carry newline-delimited JSON:
//!
//! - client → agent: `{"type":"stdin","data":"<base64>"}`,
//!   `{"type":"winch","rows":R,"cols":C}`, `{"type":"eof"}`
//! - agent → client: `{"type":"container_exec_pty_result",...}` once,
//!   then `{"type":"stdout","data":"<base64>"}` and finally
//!   `{"type":"exit","code":N}`.
//!
//! The agent allocates the PTY pair from the guest's `/dev/ptmx`,
//! spawns `runc exec` with the slave as stdio (child does `setsid()` +
//! `TIOCSCTTY`, so the container process gets a real controlling
//! terminal — job control, Ctrl+C via the line discipline, SIGWINCH on
//! resize). `eof` or an abrupt disconnect hangs the session up: SIGHUP
//! to the PTY's foreground process group, SIGKILL fallback if the child
//! is not reaped within 2s. The non-PTY exec path
//! ([`crate::container::ContainerManager::exec`]) is untouched.

use std::fs::File;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde::Deserialize;
use serde_json::json;

use crate::container::ContainerManager;

/// Parameters from a `container_exec_pty` handshake request.
pub struct PtyExecParams {
    /// Target container name.
    pub name: String,
    /// Exec session id (logging only — the session is the connection).
    pub id: String,
    /// Command argv.
    pub args: Vec<String>,
    /// `$TERM` for the exec process.
    pub term: String,
    /// Initial window rows.
    pub rows: u16,
    /// Initial window cols.
    pub cols: u16,
}

/// Client → agent streaming messages (post-handshake).
#[derive(Deserialize)]
#[serde(tag = "type")]
enum ClientMsg {
    #[serde(rename = "stdin")]
    Stdin { data: String },
    #[serde(rename = "winch")]
    Winch { rows: u16, cols: u16 },
    #[serde(rename = "eof")]
    Eof,
}

/// Serialize `value` as one JSON line and write it under the lock.
fn send_line<W: Write>(write: &Mutex<W>, value: &serde_json::Value) -> std::io::Result<()> {
    let mut s = value.to_string();
    s.push('\n');
    let mut w = write.lock().unwrap();
    w.write_all(s.as_bytes())?;
    w.flush()
}

/// Apply a window size to the PTY master (the kernel delivers SIGWINCH
/// to the slave's foreground process group).
fn set_winsize(master: RawFd, rows: u16, cols: u16) {
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: master is a valid PTY master fd; TIOCSWINSZ reads a
    // properly initialized winsize struct.
    unsafe { libc::ioctl(master, libc::TIOCSWINSZ as _, &raw const ws) };
}

/// Allocate a PTY pair from `/dev/ptmx` (raw ioctls — portable to musl,
/// no `openpty(3)`/libutil linkage). Returns `(master, slave)`.
fn open_pty() -> Result<(File, File), String> {
    let master = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY)
        .open("/dev/ptmx")
        .map_err(|e| format!("open /dev/ptmx: {e} (is devpts mounted at /dev/pts?)"))?;
    let unlock: libc::c_int = 0;
    // SAFETY: master is a valid ptmx fd; TIOCSPTLCK reads an int.
    if unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSPTLCK as _, &raw const unlock) } < 0 {
        return Err(format!("TIOCSPTLCK: {}", std::io::Error::last_os_error()));
    }
    let mut pty_num: libc::c_uint = 0;
    // SAFETY: master is a valid ptmx fd; TIOCGPTN writes an unsigned int.
    if unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCGPTN as _, &raw mut pty_num) } < 0 {
        return Err(format!("TIOCGPTN: {}", std::io::Error::last_os_error()));
    }
    let slave_path = format!("/dev/pts/{pty_num}");
    let slave = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY)
        .open(&slave_path)
        .map_err(|e| format!("open {slave_path}: {e}"))?;
    Ok((master, slave))
}

/// Allocate the PTY, size it, and spawn `runc exec` with the slave as
/// stdio and as controlling terminal. Returns the master read/write
/// dups and the child (`runc exec` in the foreground — its exit status
/// is the container process's exit status).
fn start_session(
    params: &PtyExecParams,
    containers: &ContainerManager,
) -> Result<(File, File, Child), String> {
    if !containers.contains(&params.name) {
        return Err(format!("container {} not found", params.name));
    }
    if params.args.is_empty() {
        return Err("empty command".to_string());
    }

    let (master, slave) = open_pty()?;
    set_winsize(master.as_raw_fd(), params.rows, params.cols);

    // `-t` is load-bearing: foreground non-terminal `runc exec`
    // inserts *pipes* between runc and the container process (so the
    // exec'd process would see stdin as a pipe, not a tty). With `-t`
    // runc allocates the container-side PTY from the container's own
    // devpts, makes it the process's controlling terminal, proxies it
    // to runc's stdio (our slave), performs the initial resize from
    // our slave's winsize, and forwards SIGWINCH — while still running
    // in the foreground so `wait()` yields the real exit code.
    let mut cmd = Command::new(crate::container::runc_path());
    cmd.arg("exec")
        .arg("-t")
        .arg("--env")
        .arg(format!("TERM={}", params.term))
        .arg(&params.name);
    for a in &params.args {
        cmd.arg(a);
    }
    cmd.stdin(Stdio::from(
        slave.try_clone().map_err(|e| format!("dup slave: {e}"))?,
    ));
    cmd.stdout(Stdio::from(
        slave.try_clone().map_err(|e| format!("dup slave: {e}"))?,
    ));
    cmd.stderr(Stdio::from(slave));
    // SAFETY: the pre_exec hook runs in the forked child before exec
    // and only calls async-signal-safe functions (setsid, ioctl). fd 0
    // is the PTY slave (stdio dup2 happens before pre_exec hooks).
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd.spawn().map_err(|e| format!("spawn runc exec: {e}"))?;
    // Parent must not hold slave fds: the master's read side reports
    // EOF/EIO only once ALL slave fds are closed (i.e. when the exec
    // process exits). `cmd` moved them into the child.

    let master_write = master.try_clone().map_err(|e| format!("dup master: {e}"))?;
    Ok((master, master_write, child))
}

/// Hang the session up: SIGHUP to the PTY's foreground process group
/// (precise — the shell may have moved itself to a new pgrp), SIGKILL
/// fallback if the reaper thread hasn't collected the child within 2s.
fn hangup(master: RawFd, child_pid: i32, reaped: &AtomicBool) {
    if reaped.load(Ordering::SeqCst) {
        return;
    }
    let mut fg: libc::pid_t = 0;
    // SAFETY: master is a valid PTY master fd; TIOCGPGRP writes a pid_t.
    let have_fg = unsafe { libc::ioctl(master, libc::TIOCGPGRP as _, &raw mut fg) } == 0 && fg > 0;
    if have_fg {
        // SAFETY: kill with a negative pid signals the process group.
        unsafe { libc::kill(-fg, libc::SIGHUP) };
    }
    // SAFETY: child_pid is the pid of our spawned (unreaped) child.
    unsafe { libc::kill(child_pid, libc::SIGHUP) };
    for _ in 0..20 {
        if reaped.load(Ordering::SeqCst) {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    // SAFETY: as above — escalate to SIGKILL after the grace period.
    unsafe {
        libc::kill(child_pid, libc::SIGKILL);
        if have_fg {
            libc::kill(-fg, libc::SIGKILL);
        }
    }
}

/// Run a PTY exec session on a connection whose handshake line was
/// already consumed. Sends the handshake response, then bridges the
/// connection and the PTY until the exec process exits or the client
/// goes away. Consumes the connection.
pub fn run_pty_session<R, W>(
    reader: BufReader<R>,
    write: W,
    containers: &ContainerManager,
    params: &PtyExecParams,
) where
    R: Read,
    W: Write + Send + 'static,
{
    let write = Arc::new(Mutex::new(write));
    let (master_read, master_write, child) = match start_session(params, containers) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("k7-agent: exec_pty {} failed: {e}", params.id);
            let _ = send_line(
                &write,
                &json!({"type": "container_exec_pty_result", "ok": false, "error": e}),
            );
            return;
        }
    };
    eprintln!(
        "k7-agent: exec_pty {} started in {} (pid {})",
        params.id,
        params.name,
        child.id()
    );
    // Even if this write fails (client already gone) keep going: the
    // client loop below sees the dead connection immediately and takes
    // the hangup path, which reaps the child.
    let _ = send_line(
        &write,
        &json!({"type": "container_exec_pty_result", "ok": true, "error": ""}),
    );
    drive_session(reader, &write, master_read, master_write, child);
    eprintln!("k7-agent: exec_pty {} finished", params.id);
}

#[allow(clippy::needless_pass_by_value)]
fn drive_session<R, W>(
    mut reader: BufReader<R>,
    write: &Arc<Mutex<W>>,
    master_read: File,
    mut master_write: File,
    child: Child,
) where
    R: Read,
    W: Write + Send + 'static,
{
    #[allow(clippy::cast_possible_wrap)]
    let child_pid = child.id() as i32;
    let master_fd = master_write.as_raw_fd();
    let reaped = Arc::new(AtomicBool::new(false));

    // Reader thread: PTY master → client. Owns child reaping — after
    // the master reports EOF/EIO (all slave fds closed = process
    // exited), wait() the child and send the final exit message.
    let reaper_thread = {
        let write = Arc::clone(write);
        let reaped = Arc::clone(&reaped);
        thread::spawn(move || {
            let mut child = child;
            let mut master = master_read;
            let mut buf = [0u8; 8192];
            loop {
                match master.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        // A failed send means the client is gone; keep
                        // draining so the process can exit and be reaped.
                        let _ = send_line(
                            &write,
                            &json!({"type": "stdout", "data": crate::base64_encode(&buf[..n])}),
                        );
                    }
                    Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
                    // EIO once the last slave fd closes.
                    Err(_) => break,
                }
            }
            let code = child.wait().map_or(-1, |st| {
                st.code().unwrap_or_else(|| 128 + st.signal().unwrap_or(0))
            });
            reaped.store(true, Ordering::SeqCst);
            let _ = send_line(&write, &json!({"type": "exit", "code": code}));
        })
    };

    // Client loop (this thread): client → PTY master.
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break, // client disconnected
            Ok(_) => {}
        }
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<ClientMsg>(line.trim()) {
            Ok(ClientMsg::Stdin { data }) => match crate::base64_decode(&data) {
                Ok(bytes) => {
                    if master_write.write_all(&bytes).is_err() {
                        break; // PTY gone (process exited)
                    }
                }
                Err(e) => eprintln!("k7-agent: exec_pty bad stdin base64: {e}"),
            },
            Ok(ClientMsg::Winch { rows, cols }) => set_winsize(master_fd, rows, cols),
            Ok(ClientMsg::Eof) => break, // explicit detach
            Err(e) => eprintln!("k7-agent: exec_pty bad message: {e}"),
        }
    }

    // Detach / disconnect / process-exited: hang up (no-op when the
    // reaper already collected the child) and wait for the reaper so
    // every fd (master dups, vsock write half) is dropped before we
    // return — no leaked PTY pairs.
    hangup(master_fd, child_pid, &reaped);
    drop(master_write);
    let _ = reaper_thread.join();
}
