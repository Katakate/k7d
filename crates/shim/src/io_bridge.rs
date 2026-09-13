//! FIFO bridge: connects containerd's stdio FIFOs to the guest agent's
//! container output. Enables `kubectl logs` by writing container stdout/stderr
//! to the FIFOs that containerd reads from.

use std::fs::OpenOptions;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use k7d::api::AgentClient;
use k7d::guest::AgentEndpoint;
use k7d::vsock::AGENT_VSOCK_PORT;

/// Spawns a background thread that polls the agent for container output
/// and writes it to the containerd stdout/stderr FIFOs.
///
/// Returns a handle that stops the bridge when dropped.
pub fn start_output_bridge(
    container_name: String,
    endpoint: AgentEndpoint,
    stdout_path: String,
    stderr_path: String,
) -> OutputBridge {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);

    let handle = thread::spawn(move || {
        run_output_bridge(
            &container_name,
            &endpoint,
            &stdout_path,
            &stderr_path,
            &stop_clone,
        );
    });

    OutputBridge {
        stop,
        _handle: Some(handle),
    }
}

/// Handle to a running output bridge. Stops the bridge on drop.
pub struct OutputBridge {
    stop: Arc<AtomicBool>,
    _handle: Option<thread::JoinHandle<()>>,
}

impl Drop for OutputBridge {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn run_output_bridge(
    container_name: &str,
    endpoint: &AgentEndpoint,
    stdout_path: &str,
    stderr_path: &str,
    stop: &AtomicBool,
) {
    // Open FIFOs for writing (these block until containerd opens the read end)
    let mut stdout_file = if stdout_path.is_empty() {
        None
    } else {
        match OpenOptions::new().write(true).open(stdout_path) {
            Ok(f) => Some(f),
            Err(e) => {
                log::warn!("failed to open stdout FIFO {stdout_path}: {e}");
                None
            }
        }
    };

    let mut stderr_file = if stderr_path.is_empty() {
        None
    } else {
        match OpenOptions::new().write(true).open(stderr_path) {
            Ok(f) => Some(f),
            Err(e) => {
                log::warn!("failed to open stderr FIFO {stderr_path}: {e}");
                None
            }
        }
    };

    if stdout_file.is_none() && stderr_file.is_none() {
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

        while !stop.load(Ordering::SeqCst) {
            match agent.container_output(container_name, stdout_offset, 64 * 1024) {
                Ok(output) => {
                    if let Some(ref mut f) = stdout_file {
                        if !output.stdout.is_empty() {
                            let _ = f.write_all(output.stdout.as_bytes());
                            stdout_offset += output.stdout.len() as u64;
                        }
                    }
                    if let Some(ref mut f) = stderr_file {
                        if !output.stderr.is_empty() {
                            let _ = f.write_all(output.stderr.as_bytes());
                            stderr_offset += output.stderr.len() as u64;
                        }
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

/// Placeholder constant for vsock port (re-exported for convenience).
pub const _VSOCK_PORT: u32 = AGENT_VSOCK_PORT;
