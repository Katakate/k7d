//! Shim-side PTY exec bridge — `kubectl exec -it` support.
//!
//! Bridges containerd's exec attach (stdin/stdout FIFOs +
//! `ResizePty`/`CloseIO` ttrpc calls) to the guest agent's
//! `container_exec_pty` streaming session over a dedicated vsock
//! connection. Non-PTY execs keep using `task.rs`'s `run_exec_bridge`
//! (`container_exec` + `container_wait_exec`).

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use k7d::api::{AgentClient, AgentError, PtyEvent, PtyExecWriter};

/// Registry entry for one exec id.
pub enum PtySessionState {
    /// `ResizePty` arrived before the bridge connected (containerd
    /// sends the initial size racing `Start`) — remember it so the
    /// handshake carries the real window.
    Pending { rows: u16, cols: u16 },
    /// Live session: `ResizePty`/`CloseIO` route through this handle.
    Active(PtyExecWriter),
}

/// Shared registry of PTY exec sessions, keyed by exec id.
pub type PtySessions = Arc<Mutex<HashMap<String, PtySessionState>>>;

/// Create an empty session registry.
pub fn new_sessions() -> PtySessions {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Everything the bridge thread needs, captured at `Start` time.
pub struct PtyBridgeParams {
    /// Guest vsock CID of the sandbox VM.
    pub guest_cid: u64,
    /// Container name inside the guest.
    pub container: String,
    /// containerd exec id (registry key).
    pub exec_id: String,
    /// Exec argv.
    pub args: Vec<String>,
    /// `$TERM` for the exec process.
    pub term: String,
    /// containerd stdin FIFO path (may be empty).
    pub stdin_path: String,
    /// containerd stdout FIFO path (tty execs merge stderr into it).
    pub stdout_path: String,
    /// Exec exit code slot polled by `Wait`.
    pub exit_code: Arc<Mutex<Option<i32>>>,
}

/// Detach watchdog. containerd's CRI never tells a runtime that the
/// client of a *tty* exec went away: it holds the stdin FIFO open
/// read-write itself (no FIFO EOF for our stdin pump) and its
/// `CloseIO(stdin)` call is gated on `stdinOnce && !tty` (see
/// containerd `internal/cri/io/exec_io.go`) so it never fires either.
/// The one observable signal is CRI closing its read end of the stdout
/// FIFO at detach — after which our write end polls POLLERR (no
/// readers). Watch for that and hang the session up. The returned flag
/// stops the watchdog once the session is over.
fn spawn_detach_watchdog(
    stdout_file: Option<&std::fs::File>,
    writer: PtyExecWriter,
    exec_id: &str,
) -> Arc<AtomicBool> {
    let done = Arc::new(AtomicBool::new(false));
    let Some(dup) = stdout_file.map(std::fs::File::try_clone) else {
        return done;
    };
    let dup = match dup {
        Ok(f) => f,
        Err(e) => {
            log::warn!("pty exec {exec_id}: dup stdout for detach watch: {e}");
            return done;
        }
    };
    let flag = Arc::clone(&done);
    let exec_id = exec_id.to_string();
    std::thread::spawn(move || {
        let mut pfd = libc::pollfd {
            fd: dup.as_raw_fd(),
            events: 0, // POLLERR is always reported
            revents: 0,
        };
        while !flag.load(Ordering::SeqCst) {
            pfd.revents = 0;
            // SAFETY: pfd points at one valid pollfd; `dup` keeps the
            // fd alive for the thread's lifetime.
            let n = unsafe { libc::poll(&raw mut pfd, 1, 500) };
            if n > 0 && pfd.revents & libc::POLLERR != 0 {
                log::info!("pty exec {exec_id}: client detached, hanging up");
                let _ = writer.send_eof();
                break;
            }
        }
    });
    done
}

/// Stdin pump: containerd FIFO → agent. FIFO EOF means the client
/// detached — tell the agent to hang the session up. (For tty execs
/// under the CRI the EOF never actually arrives — see
/// [`spawn_detach_watchdog`] — but direct ctr/containerd clients do
/// close the FIFO.)
fn spawn_stdin_pump(writer: PtyExecWriter, stdin_path: String, exec_id: String) {
    std::thread::spawn(move || {
        let mut fifo = match std::fs::File::open(&stdin_path) {
            Ok(f) => f,
            Err(e) => {
                log::error!("pty exec {exec_id}: open stdin FIFO: {e}");
                let _ = writer.send_eof();
                return;
            }
        };
        let mut buf = [0u8; 8192];
        loop {
            match fifo.read(&mut buf) {
                Ok(0) => {
                    let _ = writer.send_eof();
                    break;
                }
                Ok(n) => {
                    if writer.send_stdin(&buf[..n]).is_err() {
                        break; // session gone
                    }
                }
                Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
                Err(_) => {
                    let _ = writer.send_eof();
                    break;
                }
            }
        }
    });
}

fn set_exit(exit_code: &Arc<Mutex<Option<i32>>>, code: i32) {
    let mut ec = exit_code.lock().unwrap();
    if ec.is_none() {
        *ec = Some(code);
    }
}

/// Run one PTY exec session to completion. Called on a dedicated
/// thread from the `Start(exec_id)` handler.
pub fn run_pty_exec_bridge(sessions: &PtySessions, p: &PtyBridgeParams) {
    // Open containerd's stdout FIFO first — the open blocks until the
    // CRI attach opens the read end, which also means the client is
    // ready before the exec process starts producing output.
    let mut stdout_file = if p.stdout_path.is_empty() {
        None
    } else {
        match std::fs::OpenOptions::new().write(true).open(&p.stdout_path) {
            Ok(f) => Some(f),
            Err(e) => {
                log::error!("pty exec {}: open stdout FIFO: {e}", p.exec_id);
                None
            }
        }
    };

    // Initial window: a ResizePty that raced Start left a Pending entry.
    let (rows, cols) = match sessions.lock().unwrap().get(&p.exec_id) {
        Some(PtySessionState::Pending { rows, cols }) => (*rows, *cols),
        _ => (24, 80),
    };

    let args: Vec<&str> = p.args.iter().map(String::as_str).collect();
    let mut session = match AgentClient::connect_pty_exec(
        p.guest_cid,
        Duration::from_secs(10),
        &p.container,
        &p.exec_id,
        &args,
        &p.term,
        rows,
        cols,
    ) {
        Ok(s) => s,
        Err(e) => {
            log::error!("pty exec {}: agent handshake failed: {e}", p.exec_id);
            sessions.lock().unwrap().remove(&p.exec_id);
            set_exit(&p.exit_code, -1);
            return;
        }
    };

    // Flip the registry entry to Active; forward any resize that raced
    // the handshake.
    {
        let mut map = sessions.lock().unwrap();
        if let Some(PtySessionState::Pending { rows: pr, cols: pc }) = map.get(&p.exec_id) {
            if (*pr, *pc) != (rows, cols) {
                let _ = session.send_winch(*pr, *pc);
            }
        }
        map.insert(p.exec_id.clone(), PtySessionState::Active(session.writer()));
    }

    if !p.stdin_path.is_empty() {
        spawn_stdin_pump(session.writer(), p.stdin_path.clone(), p.exec_id.clone());
    }

    let done = spawn_detach_watchdog(stdout_file.as_ref(), session.writer(), &p.exec_id);

    // Main loop: agent → containerd stdout FIFO, until exit.
    loop {
        match session.read_event() {
            Ok(PtyEvent::Stdout(bytes)) => {
                if let Some(ref mut f) = stdout_file {
                    if f.write_all(&bytes).and_then(|()| f.flush()).is_err() {
                        // EPIPE — the CRI reader closed, i.e. the client
                        // detached. Hang up, but keep draining so the
                        // exit event still lands.
                        stdout_file = None;
                        let _ = session.send_eof();
                    }
                }
            }
            Ok(PtyEvent::Exit(code)) => {
                set_exit(&p.exit_code, code);
                break;
            }
            Err(AgentError::Timeout) => {} // idle stream (1s recv timeout); retry
            Err(e) => {
                log::error!("pty exec {}: stream error: {e}", p.exec_id);
                set_exit(&p.exit_code, -1);
                break;
            }
        }
    }
    done.store(true, Ordering::SeqCst);
    sessions.lock().unwrap().remove(&p.exec_id);
    // Dropping `session` closes the vsock connection; the agent treats
    // that as detach for any process still alive (SIGHUP + reap).
}
