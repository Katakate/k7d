//! Host-side agent client — vsock or serial transport.

use std::io::{self, Read, Write};
use std::os::unix::io::FromRawFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::devices::PipeSerialDevice;
use crate::vsock::AGENT_VSOCK_PORT;

/// Agent protocol request types.
#[derive(Debug, Serialize)]
#[serde(tag = "type")]
enum Request {
    #[serde(rename = "ping")]
    Ping,
    #[serde(rename = "exec")]
    Exec { id: String, args: Vec<String> },
    #[serde(rename = "write_file")]
    WriteFile { path: String, data: String },
    #[serde(rename = "read_file")]
    ReadFile { path: String },
    #[serde(rename = "container_start")]
    ContainerStart { name: String, bundle: String },
    #[serde(rename = "container_exec")]
    ContainerExec {
        name: String,
        id: String,
        args: Vec<String>,
    },
    /// internal notes: interactive PTY exec handshake. After the agent's
    /// `container_exec_pty_result` the connection switches to the
    /// streaming mode driven by [`PtyExecSession`].
    #[serde(rename = "container_exec_pty")]
    ContainerExecPty {
        name: String,
        id: String,
        args: Vec<String>,
        term: String,
        rows: u16,
        cols: u16,
    },
    #[serde(rename = "container_wait_exec")]
    ContainerWaitExec { id: String },
    #[serde(rename = "container_stop")]
    ContainerStop { name: String },
    #[serde(rename = "container_list")]
    ContainerList,
    #[serde(rename = "container_output")]
    ContainerOutput {
        name: String,
        offset: u64,
        limit: usize,
    },
    #[serde(rename = "container_wait")]
    ContainerWait { name: String },
    /// internal notes: non-blocking exit probe — the shim's exit
    /// watcher polls this (the blocking `container_wait` cannot outlive
    /// the 30s per-request read deadline for long-running containers).
    #[serde(rename = "container_wait_poll")]
    ContainerWaitPoll { name: String },
    #[serde(rename = "container_signal")]
    ContainerSignal { name: String, signal: i32 },
    /// internal notes: mount a virtio-blk device whose backing file
    /// the host filled after boot (image slot). The agent issues
    /// `BLKFLSBUF` first to drop pages the kernel cached from the
    /// boot-time partition scan of the then-empty device.
    #[serde(rename = "mount_blk")]
    MountBlk {
        device: String,
        fstype: String,
        mountpoint: String,
        ro: bool,
    },
}

/// Pong response from agent.
#[derive(Debug, Deserialize)]
pub struct PongResponse {
    /// Agent version.
    pub version: String,
}

/// Exec result from agent.
#[derive(Debug, Deserialize)]
pub struct ExecResponse {
    /// Request ID.
    pub id: String,
    /// Process exit code.
    pub exit_code: i32,
    /// Captured stdout.
    pub stdout: String,
    /// Captured stderr.
    pub stderr: String,
}

/// Container start result from agent.
#[derive(Debug, Deserialize)]
pub struct ContainerStartResponse {
    /// Whether the operation succeeded.
    pub ok: bool,
    /// Error message if failed.
    pub error: String,
}

/// Container exec result from agent.
#[derive(Debug, Deserialize)]
pub struct ContainerExecResponse {
    /// Request ID.
    pub id: String,
    /// Process exit code.
    pub exit_code: i32,
    /// Captured stdout.
    pub stdout: String,
    /// Captured stderr.
    pub stderr: String,
}

/// Container list result from agent.
#[derive(Debug, Deserialize)]
pub struct ContainerListResponse {
    /// Names of running containers.
    pub containers: Vec<String>,
}

/// Container output (stdout/stderr from main process) from agent.
#[derive(Debug, Deserialize)]
pub struct ContainerOutputResponse {
    /// Accumulated stdout from the container's main process.
    pub stdout: String,
    /// Accumulated stderr from the container's main process.
    pub stderr: String,
}

/// Container wait result from agent.
#[derive(Debug, Deserialize)]
pub struct ContainerWaitResponse {
    /// Container exit code.
    pub exit_code: i32,
}

/// Raw response from agent (for deserialization).
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum RawResponse {
    #[serde(rename = "pong")]
    Pong { version: String },
    #[serde(rename = "exec_result")]
    ExecResult {
        #[allow(dead_code)]
        id: String,
        exit_code: i32,
        stdout: String,
        stderr: String,
    },
    #[serde(rename = "write_file_result")]
    WriteFileResult { ok: bool, error: String },
    #[serde(rename = "read_file_result")]
    ReadFileResult {
        ok: bool,
        data: String,
        error: String,
    },
    #[serde(rename = "container_start_result")]
    ContainerStartResult { ok: bool, error: String },
    #[serde(rename = "container_exec_result")]
    ContainerExecResult {
        ok: bool,
        #[allow(dead_code)]
        id: String,
        error: String,
    },
    #[serde(rename = "container_exec_pty_result")]
    ContainerExecPtyResult { ok: bool, error: String },
    #[serde(rename = "container_wait_exec_result")]
    ContainerWaitExecResult {
        #[allow(dead_code)]
        id: String,
        done: bool,
        exit_code: i32,
        stdout: String,
        stderr: String,
    },
    #[serde(rename = "container_stop_result")]
    ContainerStopResult { ok: bool, error: String },
    #[serde(rename = "container_list_result")]
    ContainerListResult { containers: Vec<String> },
    #[serde(rename = "container_output_result")]
    ContainerOutputResult {
        ok: bool,
        stdout: String,
        stderr: String,
        error: String,
    },
    #[serde(rename = "container_wait_result")]
    ContainerWaitResult {
        ok: bool,
        exit_code: i32,
        error: String,
    },
    #[serde(rename = "container_wait_poll_result")]
    ContainerWaitPollResult {
        ok: bool,
        done: bool,
        exit_code: i32,
        error: String,
    },
    #[serde(rename = "container_signal_result")]
    ContainerSignalResult { ok: bool, error: String },
    #[serde(rename = "mount_blk_result")]
    MountBlkResult { ok: bool, error: String },
}

/// Errors from agent communication.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unexpected response type")]
    UnexpectedResponse,
    #[error("agent not ready within timeout")]
    Timeout,
    #[error("agent returned error: {0}")]
    Remote(String),
}

/// Transport-agnostic send/receive for the agent.
enum Transport {
    /// COM2 serial pipe — send via FIFO enqueue, receive via pipe.
    Serial {
        agent_serial: Arc<Mutex<PipeSerialDevice>>,
        read_file: std::fs::File,
    },
    /// `AF_VSOCK` stream socket.
    Vsock {
        read_file: std::fs::File,
        write_file: std::fs::File,
    },
}

/// A connection to the guest agent.
pub struct AgentClient {
    transport: Transport,
}

impl AgentClient {
    /// Create an agent client over the COM2 serial pipe.
    pub fn new(
        agent_serial: Arc<Mutex<PipeSerialDevice>>,
        _timeout: Duration,
    ) -> Result<Self, AgentError> {
        let read_fd = agent_serial.lock().unwrap().read_fd;
        // SAFETY: read_fd is a valid pipe fd from PipeSerialDevice; dup returns
        // a new fd that we take ownership of via File::from_raw_fd.
        let dup_fd = unsafe { libc::dup(read_fd) };
        // SAFETY: dup_fd is a valid fd; setting O_NONBLOCK for async reads.
        unsafe {
            libc::fcntl(dup_fd, libc::F_SETFL, libc::O_NONBLOCK);
        }
        // SAFETY: we own dup_fd (just created via dup); File takes ownership.
        let read_file = unsafe { std::fs::File::from_raw_fd(dup_fd) };

        Ok(Self {
            transport: Transport::Serial {
                agent_serial,
                read_file,
            },
        })
    }

    /// Connect to the agent via `AF_VSOCK`.
    pub fn connect_vsock(guest_cid: u64, timeout: Duration) -> Result<Self, AgentError> {
        let deadline = std::time::Instant::now() + timeout;

        loop {
            match Self::try_vsock_connect(guest_cid) {
                Ok(client) => return Ok(client),
                Err(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn try_vsock_connect(guest_cid: u64) -> Result<Self, AgentError> {
        // SAFETY: creating an AF_VSOCK stream socket; no preconditions.
        let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(AgentError::Io(io::Error::last_os_error()));
        }

        let addr = libc::sockaddr_vm {
            svm_family: libc::AF_VSOCK as u16,
            svm_reserved1: 0,
            svm_port: AGENT_VSOCK_PORT,
            svm_cid: guest_cid as u32,
            svm_zero: [0u8; 4],
        };

        // SAFETY: fd is a valid socket; addr is a properly initialized sockaddr_vm.
        if unsafe {
            libc::connect(
                fd,
                (&raw const addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_vm>() as u32,
            )
        } < 0
        {
            let err = io::Error::last_os_error();
            // SAFETY: fd is a valid socket fd we just created.
            unsafe { libc::close(fd) };
            return Err(AgentError::Io(err));
        }

        // A blocking read on a vsock socket never wakes if the guest
        // agent stops responding, which turns the request deadline in
        // `read_response_line` into dead code and can wedge a caller
        // forever. A 1s receive timeout surfaces as `WouldBlock`, which
        // the read loops treat as "poll again until the deadline".
        let tv = libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        };
        // SAFETY: fd is a valid connected socket; tv is a valid timeval.
        if unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const tv).cast::<libc::c_void>(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        } < 0
        {
            let err = io::Error::last_os_error();
            // SAFETY: fd is a valid socket fd we just created.
            unsafe { libc::close(fd) };
            return Err(AgentError::Io(err));
        }

        // SAFETY: fd is a connected socket; File takes ownership.
        let read_file = unsafe { std::fs::File::from_raw_fd(fd) };
        let write_file = read_file.try_clone()?;

        Ok(Self {
            transport: Transport::Vsock {
                read_file,
                write_file,
            },
        })
    }

    fn send_bytes(&mut self, data: &[u8]) {
        match &mut self.transport {
            Transport::Serial { agent_serial, .. } => {
                const CHUNK_SIZE: usize = 32;
                for chunk in data.chunks(CHUNK_SIZE) {
                    {
                        let mut dev = agent_serial.lock().unwrap();
                        for &byte in chunk {
                            dev.enqueue_input(byte);
                        }
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            Transport::Vsock { write_file, .. } => {
                let _ = write_file.write_all(data);
            }
        }
    }

    fn read_response_line(&mut self, timeout: Duration) -> Result<String, AgentError> {
        let deadline = std::time::Instant::now() + timeout;
        let mut line = Vec::new();
        let mut buf = [0u8; 1];

        let read_file = match &mut self.transport {
            Transport::Serial { read_file, .. } => read_file as &mut dyn Read,
            Transport::Vsock { read_file, .. } => read_file as &mut dyn Read,
        };

        loop {
            match read_file.read(&mut buf) {
                Ok(0) | Err(_) if std::time::Instant::now() >= deadline => {
                    return Err(AgentError::Timeout);
                }
                Ok(0) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(1) => {
                    if buf[0] == b'\n' {
                        return String::from_utf8(line).map_err(|_| {
                            AgentError::Io(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "invalid utf8",
                            ))
                        });
                    }
                    line.push(buf[0]);
                }
                Ok(_) => unreachable!(),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        return Err(AgentError::Timeout);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(AgentError::Io(e)),
            }
        }
    }

    fn send_request(&mut self, req: &Request) -> Result<RawResponse, AgentError> {
        let mut json = serde_json::to_string(req)?;
        json.push('\n');
        self.send_bytes(json.as_bytes());
        let line = self.read_response_line(Duration::from_secs(30))?;
        let resp: RawResponse = serde_json::from_str(line.trim())?;
        Ok(resp)
    }

    /// Ping the agent and get version info.
    pub fn ping(&mut self) -> Result<PongResponse, AgentError> {
        match self.send_request(&Request::Ping)? {
            RawResponse::Pong { version } => Ok(PongResponse { version }),
            _ => Err(AgentError::UnexpectedResponse),
        }
    }

    /// Execute a command in the guest and return the result.
    pub fn exec(&mut self, args: &[&str]) -> Result<ExecResponse, AgentError> {
        let id = format!(
            "{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let req = Request::Exec {
            id: id.clone(),
            args: args.iter().copied().map(String::from).collect(),
        };
        match self.send_request(&req)? {
            RawResponse::ExecResult {
                id: _,
                exit_code,
                stdout,
                stderr,
            } => Ok(ExecResponse {
                id,
                exit_code,
                stdout,
                stderr,
            }),
            _ => Err(AgentError::UnexpectedResponse),
        }
    }

    /// Write a file inside the guest at the given path.
    pub fn write_file(&mut self, guest_path: &str, data: &[u8]) -> Result<(), AgentError> {
        let req = Request::WriteFile {
            path: guest_path.to_string(),
            data: base64_encode(data),
        };
        match self.send_request(&req)? {
            RawResponse::WriteFileResult { ok, error } => {
                if ok {
                    Ok(())
                } else {
                    Err(AgentError::Remote(error))
                }
            }
            _ => Err(AgentError::UnexpectedResponse),
        }
    }

    /// Mount a virtio-blk device inside the guest (internal notes�
    /// image-slot attach): the agent flushes the device's buffer
    /// cache (`BLKFLSBUF`) and mounts it at `mountpoint`.
    pub fn mount_blk(
        &mut self,
        device: &str,
        fstype: &str,
        mountpoint: &str,
        ro: bool,
    ) -> Result<(), AgentError> {
        let req = Request::MountBlk {
            device: device.to_string(),
            fstype: fstype.to_string(),
            mountpoint: mountpoint.to_string(),
            ro,
        };
        match self.send_request(&req)? {
            RawResponse::MountBlkResult { ok, error } => {
                if ok {
                    Ok(())
                } else {
                    Err(AgentError::Remote(error))
                }
            }
            _ => Err(AgentError::UnexpectedResponse),
        }
    }

    /// Read a file from the guest at the given path.
    pub fn read_file(&mut self, guest_path: &str) -> Result<Vec<u8>, AgentError> {
        let req = Request::ReadFile {
            path: guest_path.to_string(),
        };
        match self.send_request(&req)? {
            RawResponse::ReadFileResult { ok, data, error } => {
                if ok {
                    base64_decode(&data)
                        .map_err(|e| AgentError::Remote(format!("base64 decode: {e}")))
                } else {
                    Err(AgentError::Remote(error))
                }
            }
            _ => Err(AgentError::UnexpectedResponse),
        }
    }

    /// Start a container from an OCI bundle inside the guest.
    pub fn container_start(&mut self, name: &str, bundle_path: &str) -> Result<(), AgentError> {
        let req = Request::ContainerStart {
            name: name.to_string(),
            bundle: bundle_path.to_string(),
        };
        match self.send_request(&req)? {
            RawResponse::ContainerStartResult { ok, error } => {
                if ok {
                    Ok(())
                } else {
                    Err(AgentError::Remote(error))
                }
            }
            _ => Err(AgentError::UnexpectedResponse),
        }
    }

    /// Execute a command inside a running container.
    ///
    /// Dispatches `runc exec` asynchronously on the agent side, then polls
    /// for the result. The agent connection is not blocked while the exec
    /// runs — other requests (ping, list, output) can be sent concurrently
    /// on a separate connection.
    pub fn container_exec(
        &mut self,
        name: &str,
        args: &[&str],
    ) -> Result<ContainerExecResponse, AgentError> {
        let id = format!(
            "{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );

        // Dispatch the exec (returns immediately)
        let req = Request::ContainerExec {
            name: name.to_string(),
            id: id.clone(),
            args: args.iter().copied().map(String::from).collect(),
        };
        match self.send_request(&req)? {
            RawResponse::ContainerExecResult { ok, error, .. } => {
                if !ok {
                    return Err(AgentError::Remote(error));
                }
            }
            _ => return Err(AgentError::UnexpectedResponse),
        }

        // Poll for completion
        loop {
            let wait_req = Request::ContainerWaitExec { id: id.clone() };
            match self.send_request(&wait_req)? {
                RawResponse::ContainerWaitExecResult {
                    done: true,
                    exit_code,
                    stdout,
                    stderr,
                    ..
                } => {
                    return Ok(ContainerExecResponse {
                        id,
                        exit_code,
                        stdout,
                        stderr,
                    });
                }
                RawResponse::ContainerWaitExecResult { done: false, .. } => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                _ => return Err(AgentError::UnexpectedResponse),
            }
        }
    }

    /// Stop and delete a running container.
    pub fn container_stop(&mut self, name: &str) -> Result<(), AgentError> {
        let req = Request::ContainerStop {
            name: name.to_string(),
        };
        match self.send_request(&req)? {
            RawResponse::ContainerStopResult { ok, error } => {
                if ok {
                    Ok(())
                } else {
                    Err(AgentError::Remote(error))
                }
            }
            _ => Err(AgentError::UnexpectedResponse),
        }
    }

    /// List all running containers inside the guest.
    pub fn container_list(&mut self) -> Result<ContainerListResponse, AgentError> {
        match self.send_request(&Request::ContainerList)? {
            RawResponse::ContainerListResult { containers } => {
                Ok(ContainerListResponse { containers })
            }
            _ => Err(AgentError::UnexpectedResponse),
        }
    }

    /// Block until a container's init process exits. Returns the exit code.
    pub fn container_wait(&mut self, name: &str) -> Result<ContainerWaitResponse, AgentError> {
        let req = Request::ContainerWait {
            name: name.to_string(),
        };
        match self.send_request(&req)? {
            RawResponse::ContainerWaitResult {
                ok,
                exit_code,
                error,
            } => {
                if ok {
                    Ok(ContainerWaitResponse { exit_code })
                } else {
                    Err(AgentError::Remote(error))
                }
            }
            _ => Err(AgentError::UnexpectedResponse),
        }
    }

    /// Non-blocking probe for a container's natural exit (internal notes
    /// Inc 2). `Ok(None)` while the init process runs, `Ok(Some(code))`
    /// once it exited — the real exit code, reaped by the agent
    /// (guest PID 1) via `waitpid`.
    pub fn container_wait_poll(&mut self, name: &str) -> Result<Option<i32>, AgentError> {
        let req = Request::ContainerWaitPoll {
            name: name.to_string(),
        };
        match self.send_request(&req)? {
            RawResponse::ContainerWaitPollResult {
                ok: false, error, ..
            } => Err(AgentError::Remote(error)),
            RawResponse::ContainerWaitPollResult {
                done: true,
                exit_code,
                ..
            } => Ok(Some(exit_code)),
            RawResponse::ContainerWaitPollResult { .. } => Ok(None),
            _ => Err(AgentError::UnexpectedResponse),
        }
    }

    /// Send a signal to a container's init process.
    pub fn container_signal(&mut self, name: &str, signal: i32) -> Result<(), AgentError> {
        let req = Request::ContainerSignal {
            name: name.to_string(),
            signal,
        };
        match self.send_request(&req)? {
            RawResponse::ContainerSignalResult { ok, error } => {
                if ok {
                    Ok(())
                } else {
                    Err(AgentError::Remote(error))
                }
            }
            _ => Err(AgentError::UnexpectedResponse),
        }
    }

    /// internal notes: open a dedicated PTY exec session (interactive
    /// `kubectl exec -it`). Establishes its own vsock connection,
    /// performs the `container_exec_pty` handshake, and returns the
    /// streaming session. Vsock only — PTY exec is not supported over
    /// the serial fallback transport.
    #[allow(clippy::too_many_arguments)]
    pub fn connect_pty_exec(
        guest_cid: u64,
        timeout: Duration,
        name: &str,
        exec_id: &str,
        args: &[&str],
        term: &str,
        rows: u16,
        cols: u16,
    ) -> Result<PtyExecSession, AgentError> {
        let client = Self::connect_vsock(guest_cid, timeout)?;
        let Transport::Vsock {
            read_file,
            mut write_file,
        } = client.transport
        else {
            return Err(AgentError::Remote(
                "PTY exec requires the vsock transport".to_string(),
            ));
        };

        let req = Request::ContainerExecPty {
            name: name.to_string(),
            id: exec_id.to_string(),
            args: args.iter().copied().map(String::from).collect(),
            term: term.to_string(),
            rows,
            cols,
        };
        let mut json = serde_json::to_string(&req)?;
        json.push('\n');
        write_file.write_all(json.as_bytes())?;

        let mut session = PtyExecSession {
            read: read_file,
            pending: Vec::new(),
            writer: PtyExecWriter {
                write: Arc::new(Mutex::new(write_file)),
            },
        };
        let line = session.read_line()?;
        match serde_json::from_str::<RawResponse>(line.trim())? {
            RawResponse::ContainerExecPtyResult { ok: true, .. } => Ok(session),
            RawResponse::ContainerExecPtyResult { ok: false, error } => {
                Err(AgentError::Remote(error))
            }
            _ => Err(AgentError::UnexpectedResponse),
        }
    }

    /// Read stdout/stderr from a container's main process, starting at
    /// byte `offset` and reading up to `limit` bytes. Use offset=0 and
    /// limit=0 (agent defaults to 1 MiB) for a simple read.
    pub fn container_output(
        &mut self,
        name: &str,
        offset: u64,
        limit: usize,
    ) -> Result<ContainerOutputResponse, AgentError> {
        let req = Request::ContainerOutput {
            name: name.to_string(),
            offset,
            limit,
        };
        match self.send_request(&req)? {
            RawResponse::ContainerOutputResult {
                ok,
                stdout,
                stderr,
                error,
            } => {
                if ok {
                    Ok(ContainerOutputResponse { stdout, stderr })
                } else {
                    Err(AgentError::Remote(error))
                }
            }
            _ => Err(AgentError::UnexpectedResponse),
        }
    }
}

/// internal notes: event streamed from a PTY exec session.
#[derive(Debug)]
pub enum PtyEvent {
    /// Bytes the exec process wrote to its terminal.
    Stdout(Vec<u8>),
    /// The exec process exited (128+signal for signal deaths). Final
    /// event — the agent sends nothing after it.
    Exit(i32),
}

/// Agent → client streaming messages of a PTY exec session.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum PtyStreamMsg {
    #[serde(rename = "stdout")]
    Stdout { data: String },
    #[serde(rename = "exit")]
    Exit { code: i32 },
}

/// internal notes: thread-safe write handle of a PTY exec session. Cloneable
/// so e.g. the shim's `ResizePty` handler can inject `winch` messages
/// while the bridge thread pumps stdin.
#[derive(Clone)]
pub struct PtyExecWriter {
    write: Arc<Mutex<std::fs::File>>,
}

impl PtyExecWriter {
    fn send_value(&self, value: &serde_json::Value) -> Result<(), AgentError> {
        let mut s = value.to_string();
        s.push('\n');
        let mut w = self.write.lock().unwrap();
        w.write_all(s.as_bytes())?;
        w.flush()?;
        Ok(())
    }

    /// Write keystrokes to the exec process's PTY.
    pub fn send_stdin(&self, bytes: &[u8]) -> Result<(), AgentError> {
        self.send_value(&serde_json::json!({"type": "stdin", "data": base64_encode(bytes)}))
    }

    /// Resize the exec process's PTY (delivers SIGWINCH in the guest).
    pub fn send_winch(&self, rows: u16, cols: u16) -> Result<(), AgentError> {
        self.send_value(&serde_json::json!({"type": "winch", "rows": rows, "cols": cols}))
    }

    /// Detach: the agent hangs the session up (SIGHUP to the PTY's
    /// foreground process group, SIGKILL fallback after 2s).
    pub fn send_eof(&self) -> Result<(), AgentError> {
        self.send_value(&serde_json::json!({"type": "eof"}))
    }
}

/// internal notes: a live PTY exec session (post-handshake). Owns the read
/// half of the dedicated vsock connection; writes go through the
/// shared [`PtyExecWriter`].
pub struct PtyExecSession {
    read: std::fs::File,
    /// Bytes received but not yet consumed as a full line. Preserved
    /// across [`AgentError::Timeout`] returns so no data is lost when
    /// a read timeout fires mid-line.
    pending: Vec<u8>,
    writer: PtyExecWriter,
}

impl PtyExecSession {
    /// Clone the thread-safe write handle.
    #[must_use]
    pub fn writer(&self) -> PtyExecWriter {
        self.writer.clone()
    }

    /// Write keystrokes to the exec process's PTY.
    pub fn send_stdin(&self, bytes: &[u8]) -> Result<(), AgentError> {
        self.writer.send_stdin(bytes)
    }

    /// Resize the exec process's PTY.
    pub fn send_winch(&self, rows: u16, cols: u16) -> Result<(), AgentError> {
        self.writer.send_winch(rows, cols)
    }

    /// Detach from the session (agent hangs it up).
    pub fn send_eof(&self) -> Result<(), AgentError> {
        self.writer.send_eof()
    }

    /// Set (or clear) a receive timeout on the session socket.
    /// [`Self::read_event`] returns [`AgentError::Timeout`] when it
    /// fires; buffered partial data is preserved, so callers can just
    /// retry.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<(), AgentError> {
        use std::os::unix::io::AsRawFd;
        let (secs, micros) = timeout.map_or((0, 0), |d| (d.as_secs(), d.subsec_micros()));
        #[allow(clippy::cast_possible_wrap)]
        let tv = libc::timeval {
            tv_sec: secs as libc::time_t,
            tv_usec: libc::suseconds_t::from(micros),
        };
        // SAFETY: the fd is a valid connected socket owned by `read`;
        // SO_RCVTIMEO reads a properly initialized timeval.
        let rc = unsafe {
            libc::setsockopt(
                self.read.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const tv).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(AgentError::Io(io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Read one complete line from the stream, preserving partial data
    /// across timeouts.
    fn read_line(&mut self) -> Result<String, AgentError> {
        loop {
            if let Some(pos) = self.pending.iter().position(|&b| b == b'\n') {
                let rest = self.pending.split_off(pos + 1);
                let mut line_bytes = std::mem::replace(&mut self.pending, rest);
                line_bytes.pop(); // trailing '\n'
                return String::from_utf8(line_bytes).map_err(|_| {
                    AgentError::Io(io::Error::new(io::ErrorKind::InvalidData, "invalid utf8"))
                });
            }
            let mut buf = [0u8; 8192];
            match self.read.read(&mut buf) {
                Ok(0) => {
                    return Err(AgentError::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "PTY exec stream closed by agent",
                    )));
                }
                Ok(n) => self.pending.extend_from_slice(&buf[..n]),
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    return Err(AgentError::Timeout);
                }
                Err(e) => return Err(AgentError::Io(e)),
            }
        }
    }

    /// Read the next event from the session. The socket carries a 1s
    /// receive timeout (set at connect), so this returns
    /// [`AgentError::Timeout`] periodically when the stream is idle —
    /// callers just retry. Override via [`Self::set_read_timeout`].
    pub fn read_event(&mut self) -> Result<PtyEvent, AgentError> {
        loop {
            let line = self.read_line()?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<PtyStreamMsg>(line.trim())? {
                PtyStreamMsg::Stdout { data } => {
                    let bytes = base64_decode(&data)
                        .map_err(|e| AgentError::Remote(format!("bad stdout base64: {e}")))?;
                    return Ok(PtyEvent::Stdout(bytes));
                }
                PtyStreamMsg::Exit { code } => return Ok(PtyEvent::Exit(code)),
            }
        }
    }
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        out.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[allow(clippy::many_single_char_names)]
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    fn val(c: u8) -> Result<u32, String> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'+' => Ok(62),
            b'/' => Ok(63),
            b'=' => Ok(0),
            _ => Err(format!("invalid base64 char: {c}")),
        }
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        if chunk.len() < 4 {
            break;
        }
        let b0 = val(chunk[0])?;
        let b1 = val(chunk[1])?;
        let b2 = val(chunk[2])?;
        let b3 = val(chunk[3])?;
        let triple = (b0 << 18) | (b1 << 12) | (b2 << 6) | b3;
        out.push(((triple >> 16) & 0xFF) as u8);
        if chunk[2] != b'=' {
            out.push(((triple >> 8) & 0xFF) as u8);
        }
        if chunk[3] != b'=' {
            out.push((triple & 0xFF) as u8);
        }
    }
    Ok(out)
}
