//! FIFO bridge: connects containerd's stdio FIFOs to the guest agent's
//! container output. Enables `kubectl logs` by writing container stdout/stderr
//! to the FIFOs that containerd reads from.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use k7d::api::AgentClient;
use k7d::guest::AgentEndpoint;
use k7d::vsock::AGENT_VSOCK_PORT;

/// How long one `container_output` poll may block.
///
/// A native vsock client polls a silent socket until its request
/// deadline. `prepare_fork_source` replaces the source VM's vsock
/// backend and leaves this bridge's existing connection silent, so the
/// default 30s deadline would freeze log streaming — and, if the pod is
/// deleted in that window, containerd's `io.Wait()` — for half a minute.
/// One second is enough for a live agent and is the bound on reconnecting
/// after the swap. Teardown does not even wait this long: [`OutputBridge`]'s
/// `Drop` closes the FIFOs itself.
const OUTPUT_REQUEST_TIMEOUT: Duration = Duration::from_secs(1);

/// Spawns a background thread that polls the agent for container output
/// and writes it to the containerd stdout/stderr FIFOs.
///
/// Returns a handle that stops the bridge when dropped. Drop closes the
/// FIFO write ends immediately, so containerd's `task.Delete` (which
/// blocks in `io.Wait()` until those ends close) is not stuck behind an
/// in-flight agent read.
pub fn start_output_bridge(
    container_name: String,
    endpoint: AgentEndpoint,
    stdout_path: String,
    stderr_path: String,
) -> OutputBridge {
    let stop = Arc::new(AtomicBool::new(false));
    let stdout = Arc::new(Mutex::new(None));
    let stderr = Arc::new(Mutex::new(None));

    let stop_thread = Arc::clone(&stop);
    let stdout_thread = Arc::clone(&stdout);
    let stderr_thread = Arc::clone(&stderr);
    let handle = thread::spawn(move || {
        run_output_bridge(
            &container_name,
            &endpoint,
            &stdout_path,
            &stderr_path,
            &stop_thread,
            &stdout_thread,
            &stderr_thread,
        );
    });

    OutputBridge {
        stop,
        stdout,
        stderr,
        _handle: Some(handle),
    }
}

/// Handle to a running output bridge. Stops the bridge and closes its
/// stdio FIFOs on drop.
pub struct OutputBridge {
    stop: Arc<AtomicBool>,
    stdout: Arc<Mutex<Option<File>>>,
    stderr: Arc<Mutex<Option<File>>>,
    _handle: Option<thread::JoinHandle<()>>,
}

impl Drop for OutputBridge {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // containerd will not send `task.Delete` until these write ends
        // close (`io.Wait()`). The bridge thread may be inside a vsock
        // read on a connection the fork-source swap already killed; that
        // read must not keep the FIFOs open.
        close_fifo(&self.stdout);
        close_fifo(&self.stderr);
    }
}

fn close_fifo(slot: &Mutex<Option<File>>) {
    *slot.lock().unwrap() = None;
}

fn run_output_bridge(
    container_name: &str,
    endpoint: &AgentEndpoint,
    stdout_path: &str,
    stderr_path: &str,
    stop: &AtomicBool,
    stdout_slot: &Mutex<Option<File>>,
    stderr_slot: &Mutex<Option<File>>,
) {
    let stdout = open_write_fifo(stdout_path);
    let stderr = open_write_fifo(stderr_path);
    if stdout.is_none() && stderr.is_none() {
        return;
    }
    if !install_fifo(stdout_slot, stop, stdout) || !install_fifo(stderr_slot, stop, stderr) {
        return;
    }

    let mut stdout_offset: u64 = 0;
    let mut stderr_offset: u64 = 0;
    #[allow(unused_assignments)]
    let _ = stderr_offset;

    while !stop.load(Ordering::SeqCst) {
        let Ok(mut agent) = AgentClient::connect_endpoint(endpoint, Duration::from_secs(2)) else {
            thread::sleep(Duration::from_secs(1));
            continue;
        };
        agent.set_request_timeout(OUTPUT_REQUEST_TIMEOUT);

        while !stop.load(Ordering::SeqCst) {
            match agent.container_output(container_name, stdout_offset, 64 * 1024) {
                Ok(output) => {
                    if !output.stdout.is_empty() {
                        if !write_fifo(stdout_slot, output.stdout.as_bytes()) {
                            return;
                        }
                        stdout_offset += output.stdout.len() as u64;
                    }
                    if !output.stderr.is_empty() {
                        if !write_fifo(stderr_slot, output.stderr.as_bytes()) {
                            return;
                        }
                        stderr_offset += output.stderr.len() as u64;
                    }
                }
                Err(_) => {
                    break;
                }
            }
            thread::sleep(Duration::from_millis(200));
        }
    }
}

/// Open `path` for writing, or `None` when the path is empty or the open
/// fails. A failed open is logged; the caller skips that stream.
fn open_write_fifo(path: &str) -> Option<File> {
    if path.is_empty() {
        return None;
    }
    match OpenOptions::new().write(true).open(path) {
        Ok(file) => Some(file),
        Err(e) => {
            log::warn!("failed to open FIFO {path}: {e}");
            None
        }
    }
}

/// Publish `file` into `slot`, unless the bridge is already stopping.
/// `None` means this stream is unused and is not a failure.
fn install_fifo(slot: &Mutex<Option<File>>, stop: &AtomicBool, file: Option<File>) -> bool {
    let Some(file) = file else {
        return true;
    };
    let mut slot = slot.lock().unwrap();
    if stop.load(Ordering::SeqCst) {
        return false;
    }
    *slot = Some(file);
    true
}

/// Write `bytes` to the FIFO. `false` means Drop already closed it and
/// the bridge thread should exit.
fn write_fifo(slot: &Mutex<Option<File>>, bytes: &[u8]) -> bool {
    let mut slot = slot.lock().unwrap();
    let Some(file) = slot.as_mut() else {
        return false;
    };
    let _ = file.write_all(bytes);
    true
}

/// Placeholder constant for vsock port (re-exported for convenience).
pub const _VSOCK_PORT: u32 = AGENT_VSOCK_PORT;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    use std::thread;
    use std::time::{Duration, Instant};

    use k7d::guest::AgentEndpoint;

    /// Drop must close the stdout FIFO even while the bridge thread is
    /// still dialing the agent. containerd's `io.Wait()` is this read
    /// returning EOF; it must not sit out the agent's request deadline.
    #[test]
    fn drop_closes_stdout_fifo_without_waiting_for_agent() {
        let dir = std::env::temp_dir().join(format!("k7d-fifo-bridge-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("stdout");
        let c_path = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        // SAFETY: `c_path` is a NUL-terminated path in a directory we
        // just created; `mkfifo` only creates that inode.
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo: {}", std::io::Error::last_os_error());

        // A reader has to exist first: opening a FIFO for write blocks
        // until then. Non-blocking so this open does not wait for the
        // bridge thread.
        let mut reader = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&path)
            .unwrap();

        let bridge = start_output_bridge(
            "ctr".into(),
            AgentEndpoint::Vsock { cid: 99_999 },
            path.to_str().unwrap().to_string(),
            String::new(),
        );
        // Let the thread open and publish the write end.
        thread::sleep(Duration::from_millis(200));
        let started = Instant::now();
        drop(bridge);

        let deadline = Instant::now() + Duration::from_secs(2);
        let mut buf = [0u8; 8];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "stdout FIFO still open {:?} after drop",
                        started.elapsed()
                    );
                    thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("read FIFO: {e}"),
            }
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "FIFO close took {:?}",
            started.elapsed()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
