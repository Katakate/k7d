//! Host-side agent client — vsock or serial transport.

use std::io::{self, Read, Write};
use std::os::unix::io::FromRawFd;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
    /// Interactive PTY exec handshake. After the agent's
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
    /// Non-blocking exit probe — the shim's exit
    /// watcher polls this (the blocking `container_wait` cannot outlive
    /// the 30s per-request read deadline for long-running containers).
    #[serde(rename = "container_wait_poll")]
    ContainerWaitPoll { name: String },
    #[serde(rename = "container_signal")]
    ContainerSignal { name: String, signal: i32 },
    #[serde(rename = "container_usage")]
    ContainerUsage { name: String },
    /// Mount a virtio-blk device whose backing file
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
    /// Supervised guest services. Empty on older agents.
    #[serde(default)]
    pub services: Vec<ServiceInfo>,
}

/// One supervised guest service reported on `Pong`.
#[derive(Debug, Clone, Deserialize)]
pub struct ServiceInfo {
    /// Service name (`docker`).
    pub name: String,
    /// Supervisor pid, or 0 if none.
    #[serde(default)]
    pub pid: u32,
    /// Ready probe passed (overlay2 for docker).
    #[serde(default)]
    pub ready: bool,
    /// Supervisor restart count.
    #[serde(default)]
    pub restarts: u32,
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

/// A container's writable-layer usage as measured inside the
/// guest, from [`AgentClient::container_usage`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainerUsage {
    /// Bytes the container's writable layer occupies right now.
    pub used_bytes: u64,
    /// Capacity of the filesystem holding that layer.
    pub capacity_bytes: u64,
    /// Whether that capacity is the container's alone. `false` means
    /// the pod's shared scratch disk, so `capacity_bytes` is a
    /// pod-level number and NOT a limit on this container — give the
    /// container its own image
    /// (`k7d.katakate.org/container-scratch-size`) to make it one.
    pub dedicated: bool,
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
    Pong {
        version: String,
        #[serde(default)]
        services: Vec<ServiceInfo>,
    },
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
    #[serde(rename = "container_usage_result")]
    ContainerUsageResult {
        ok: bool,
        used_bytes: u64,
        capacity_bytes: u64,
        dedicated: bool,
        error: String,
    },
    #[serde(rename = "mount_blk_result")]
    MountBlkResult { ok: bool, error: String },
}

/// Largest legitimate agent response is a `read_file` payload (base64
/// of a guest file). 64 MiB is well above any file we currently serve
/// and still a hard cap so a compromised guest cannot force unbounded
/// host allocation.
pub const MAX_AGENT_LINE_BYTES: usize = 64 << 20;

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
    /// Guest sent a line longer than [`MAX_AGENT_LINE_BYTES`]. The
    /// session is poisoned — framing is lost.
    #[error("agent response line exceeded {bytes} bytes")]
    Oversized { bytes: usize },
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
    /// Firecracker's vsock Unix-socket proxy. Byte-identical
    /// to [`Transport::Vsock`] once the `CONNECT`/`OK` handshake is
    /// done; it is a separate variant so a failure names the transport
    /// the VM actually has.
    FcUds {
        read_file: std::fs::File,
        write_file: std::fs::File,
        /// Where to redial. Firecracker resets every vsock connection
        /// at each `PUT /snapshot/create`, so a client
        /// of a fork source sees EOF once per fork and reconnects.
        uds_path: std::path::PathBuf,
        port: u32,
    },
}

/// Redials an FC vsock proxy after the EOF a snapshot causes: how many
/// times one request is retried before the error is the caller's.
const FC_RECONNECT_ATTEMPTS: usize = 3;
/// How long each redial waits for the guest agent to accept again.
const FC_RECONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// A connection to the guest agent.
pub struct AgentClient {
    transport: Transport,
    /// Bytes received past a newline, or a partial line. Needed once
    /// `read_response_line` reads in chunks instead of one byte at a time.
    leftover: Vec<u8>,
    /// Times an FC vsock proxy was redialled after a snapshot reset.
    fc_reconnects: u32,
}

impl AgentClient {
    /// How many times this client transparently redialled a Firecracker
    /// vsock proxy after the guest was snapshotted — what a test uses to
    /// prove the reset happened *and* was survived.
    #[must_use]
    pub fn fc_reconnects(&self) -> u32 {
        self.fc_reconnects
    }

    /// Create an agent client over the COM2 serial pipe.
    pub fn new(
        agent_serial: Arc<Mutex<PipeSerialDevice>>,
        _timeout: Duration,
    ) -> Result<Self, AgentError> {
        let read_fd = agent_serial.lock().unwrap().read_fd;
        // SAFETY: read_fd is a valid pipe fd from PipeSerialDevice;
        // F_DUPFD_CLOEXEC returns a new fd (CLOEXEC — a plain `dup` would
        // strip the flag the pipe was created with) that we take
        // ownership of via File::from_raw_fd.
        let dup_fd = unsafe { libc::fcntl(read_fd, libc::F_DUPFD_CLOEXEC, 0) };
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
            leftover: Vec::new(),
            fc_reconnects: 0,
        })
    }

    /// Connect to the agent however this guest's backend publishes it.
    ///
    /// The one call every client should use: a shim, or the daemon's
    /// own reattach liveness probe, knows which sandbox it wants and
    /// not which VMM booted it. `AF_VSOCK` for native guests,
    /// Firecracker's vsock-UDS proxy for jailed ones.
    pub fn connect_endpoint(
        endpoint: &crate::guest::AgentEndpoint,
        timeout: Duration,
    ) -> Result<Self, AgentError> {
        match endpoint {
            crate::guest::AgentEndpoint::Vsock { cid } => Self::connect_vsock(*cid, timeout),
            crate::guest::AgentEndpoint::FcUds { path } => {
                Self::connect_fc_uds(std::path::Path::new(path), AGENT_VSOCK_PORT, timeout)
            }
        }
    }

    /// Connect to the agent via `AF_VSOCK`.
    ///
    /// CIDs 0–2 are hypervisor / local / host — never a guest. Firecracker
    /// VMs publish `guest_cid = 0` (`NO_HOST_CID`) plus `FcUds`; dialling
    /// that over `AF_VSOCK` hangs in a blocking `connect()` with no timeout
    /// (k7-forked CHALLENGES #15). Fail loud instead of waiting on kubelet's
    /// exec deadline.
    pub fn connect_vsock(guest_cid: u64, timeout: Duration) -> Result<Self, AgentError> {
        if guest_cid < crate::vsock::DEFAULT_GUEST_CID {
            return Err(AgentError::Remote(format!(
                "refusing AF_VSOCK CID {guest_cid}: CIDs 0–2 are hypervisor/local/host, \
                 never a guest — Firecracker guests must be dialled via FcUds"
            )));
        }
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
        let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
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
            leftover: Vec::new(),
            fc_reconnects: 0,
        })
    }

    /// Connect to the agent through Firecracker's vsock Unix socket.
    ///
    /// Firecracker multiplexes guest vsock ports over one host UDS: the
    /// host connects to `uds_path`, sends `CONNECT <port>\n`, and gets
    /// `OK <host-side port>\n` back once the guest has accepted. If
    /// nothing is listening on that guest port, Firecracker closes the
    /// connection instead of answering — which is exactly what a VM
    /// whose agent has not come up yet looks like, so the whole
    /// handshake is retried until `timeout`.
    pub fn connect_fc_uds(
        uds_path: &std::path::Path,
        port: u32,
        timeout: Duration,
    ) -> Result<Self, AgentError> {
        let deadline = Instant::now() + timeout;
        loop {
            match Self::try_fc_uds_connect(uds_path, port) {
                Ok(client) => return Ok(client),
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn try_fc_uds_connect(uds_path: &std::path::Path, port: u32) -> Result<Self, AgentError> {
        let mut stream = std::os::unix::net::UnixStream::connect(uds_path)?;
        // Same 1s receive timeout as the vsock transport: the read loops
        // treat `WouldBlock` as "poll again until the deadline", and a
        // guest that stops answering must not wedge the caller forever.
        stream.set_read_timeout(Some(Duration::from_secs(1)))?;
        stream.write_all(format!("CONNECT {port}\n").as_bytes())?;
        stream.flush()?;

        // Read exactly the handshake line — one byte at a time, because
        // anything read past the newline belongs to the agent's NDJSON
        // stream and there is nowhere to put it back.
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match stream.read(&mut byte) {
                Ok(0) => {
                    return Err(AgentError::Remote(format!(
                        "firecracker closed the vsock proxy at {}: nothing is listening \
                         on guest port {port}",
                        uds_path.display()
                    )))
                }
                Ok(_) if byte[0] == b'\n' => break,
                Ok(_) => line.push(byte[0]),
                Err(e) => return Err(AgentError::Io(e)),
            }
            if line.len() > 64 {
                return Err(AgentError::Remote(
                    "firecracker vsock handshake line is too long".to_string(),
                ));
            }
        }
        let reply = String::from_utf8_lossy(&line).trim().to_string();
        if !reply.starts_with("OK ") {
            return Err(AgentError::Remote(format!(
                "firecracker vsock handshake answered {reply:?}, wanted \"OK <port>\""
            )));
        }

        let read_file = std::fs::File::from(std::os::unix::io::OwnedFd::from(stream));
        let write_file = read_file.try_clone()?;
        Ok(Self {
            transport: Transport::FcUds {
                read_file,
                write_file,
                uds_path: uds_path.to_path_buf(),
                port,
            },
            leftover: Vec::new(),
            fc_reconnects: 0,
        })
    }

    /// Redial an FC vsock proxy in place. `None` for other transports.
    fn reconnect_fc(&mut self) -> Option<Result<(), AgentError>> {
        let Transport::FcUds { uds_path, port, .. } = &self.transport else {
            return None;
        };
        let (uds_path, port) = (uds_path.clone(), *port);
        log::info!(
            "agent: vsock proxy {} closed (snapshot reset) — reconnecting",
            uds_path.display()
        );
        Some(
            Self::connect_fc_uds(&uds_path, port, FC_RECONNECT_TIMEOUT).map(|fresh| {
                self.transport = fresh.transport;
                self.leftover.clear();
                self.fc_reconnects += 1;
            }),
        )
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
            Transport::Vsock { write_file, .. } | Transport::FcUds { write_file, .. } => {
                let _ = write_file.write_all(data);
            }
        }
    }

    fn read_response_line(&mut self, timeout: Duration) -> Result<String, AgentError> {
        let deadline = Instant::now() + timeout;
        // On Firecracker's proxy `read` returning 0 is the peer
        // hanging up, which is exactly what a snapshot of this guest
        // does to every connection — waiting the deadline out on it
        // would turn every fork into a 30 s stall for the parent's
        // clients. The other transports keep their poll-to-deadline
        // behaviour (and the `Timeout` their callers match on).
        let (read_file, eof_fatal) = match &mut self.transport {
            Transport::Serial { read_file, .. } | Transport::Vsock { read_file, .. } => {
                (read_file as &mut dyn Read, false)
            }
            Transport::FcUds { read_file, .. } => (read_file as &mut dyn Read, true),
        };
        read_capped_line(read_file, &mut self.leftover, Some(deadline), eof_fatal)
    }

    /// One request/response round trip. On an FC vsock proxy, an EOF
    /// (the reset Firecracker sends at every snapshot of this guest) is
    /// answered by redialling and **re-sending the request**, up to
    /// [`FC_RECONNECT_ATTEMPTS`] times; a request that was mid-flight
    /// when the source was snapshotted is therefore delivered twice if
    /// the agent got the first copy. k7d only snapshots a guest while
    /// no daemon request is in flight against it, so that case is a
    /// client racing its own fork, which the spec accepts.
    fn send_request(&mut self, req: &Request) -> Result<RawResponse, AgentError> {
        let mut json = serde_json::to_string(req)?;
        json.push('\n');
        let mut attempts = 0;
        loop {
            self.send_bytes(json.as_bytes());
            match self.read_response_line(Duration::from_secs(30)) {
                Ok(line) => return Ok(serde_json::from_str(line.trim())?),
                Err(AgentError::Io(e))
                    if e.kind() == io::ErrorKind::UnexpectedEof
                        && attempts < FC_RECONNECT_ATTEMPTS =>
                {
                    let Some(reconnected) = self.reconnect_fc() else {
                        return Err(AgentError::Io(e));
                    };
                    reconnected?;
                    attempts += 1;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Ping the agent and get version info.
    pub fn ping(&mut self) -> Result<PongResponse, AgentError> {
        match self.send_request(&Request::Ping)? {
            RawResponse::Pong { version, services } => Ok(PongResponse { version, services }),
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

    /// Mount a virtio-blk device inside the guest (image-slot
    /// attach): the agent flushes the device's buffer
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

    /// Non-blocking probe for a container's natural exit.
    /// `Ok(None)` while the init process runs, `Ok(Some(code))`
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

    /// Writable-layer usage of a container, measured inside
    /// the guest.
    ///
    /// This is the surface that makes ephemeral-storage usage
    /// observable from outside the guest: any host process that knows
    /// the VM's vsock CID (`k7d::control::Request::ListVms` reports it)
    /// can ask. It deliberately does not ride the CRI stats path —
    /// containerd only decodes a cgroups `Metrics` payload there, and
    /// that message has no field for filesystem usage.
    pub fn container_usage(&mut self, name: &str) -> Result<ContainerUsage, AgentError> {
        let req = Request::ContainerUsage {
            name: name.to_string(),
        };
        match self.send_request(&req)? {
            RawResponse::ContainerUsageResult {
                ok,
                used_bytes,
                capacity_bytes,
                dedicated,
                error,
            } => {
                if ok {
                    Ok(ContainerUsage {
                        used_bytes,
                        capacity_bytes,
                        dedicated,
                    })
                } else {
                    Err(AgentError::Remote(error))
                }
            }
            _ => Err(AgentError::UnexpectedResponse),
        }
    }

    /// Open a dedicated PTY exec session (interactive
    /// `kubectl exec -it`). Establishes its own connection to the
    /// guest, performs the `container_exec_pty` handshake, and returns
    /// the streaming session.
    ///
    /// Needs a socket transport (`AF_VSOCK` or Firecracker's vsock
    /// UDS), because the session splits the connection into an
    /// independent reader and writer; the serial fallback multiplexes
    /// one FIFO and cannot.
    #[allow(clippy::too_many_arguments)]
    pub fn connect_pty_exec(
        endpoint: &crate::guest::AgentEndpoint,
        timeout: Duration,
        name: &str,
        exec_id: &str,
        args: &[&str],
        term: &str,
        rows: u16,
        cols: u16,
    ) -> Result<PtyExecSession, AgentError> {
        let client = Self::connect_endpoint(endpoint, timeout)?;
        let (Transport::Vsock {
            read_file,
            mut write_file,
        }
        | Transport::FcUds {
            read_file,
            mut write_file,
            ..
        }) = client.transport
        else {
            return Err(AgentError::Remote(
                "PTY exec requires a socket transport".to_string(),
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

/// Event streamed from a PTY exec session.
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

/// Thread-safe write handle of a PTY exec session. Cloneable
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

/// A live PTY exec session (post-handshake). Owns the read
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
        if let Some(line) = take_complete_line(&mut self.pending)? {
            return Ok(line);
        }
        loop {
            let mut buf = [0u8; 8192];
            match self.read.read(&mut buf) {
                Ok(0) => {
                    return Err(AgentError::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "PTY exec stream closed by agent",
                    )));
                }
                Ok(n) => {
                    if append_capped(&mut self.pending, &buf[..n])? {
                        if let Some(line) = take_complete_line(&mut self.pending)? {
                            return Ok(line);
                        }
                    }
                }
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

/// Pull a newline-terminated line out of `pending` if one is complete.
/// The line itself is never longer than [`MAX_AGENT_LINE_BYTES`].
fn take_complete_line(pending: &mut Vec<u8>) -> Result<Option<String>, AgentError> {
    let Some(pos) = pending.iter().position(|&b| b == b'\n') else {
        if pending.len() > MAX_AGENT_LINE_BYTES {
            pending.clear();
            return Err(AgentError::Oversized {
                bytes: MAX_AGENT_LINE_BYTES,
            });
        }
        return Ok(None);
    };
    if pos > MAX_AGENT_LINE_BYTES {
        pending.clear();
        return Err(AgentError::Oversized {
            bytes: MAX_AGENT_LINE_BYTES,
        });
    }
    let rest = pending.split_off(pos + 1);
    let mut line = std::mem::replace(pending, rest);
    line.pop();
    String::from_utf8(line)
        .map(Some)
        .map_err(|_| AgentError::Io(io::Error::new(io::ErrorKind::InvalidData, "invalid utf8")))
}

/// Append `chunk` without letting the current line grow past the cap.
/// Leftover after a newline stays in `pending` for the next call.
/// Returns whether `chunk` contained a newline (caller must not rescan
/// `pending` on every chunk — that is O(n²) on a 64 MiB flood).
fn append_capped(pending: &mut Vec<u8>, chunk: &[u8]) -> Result<bool, AgentError> {
    if let Some(nl) = chunk.iter().position(|&b| b == b'\n') {
        if pending.len() + nl > MAX_AGENT_LINE_BYTES {
            pending.clear();
            return Err(AgentError::Oversized {
                bytes: MAX_AGENT_LINE_BYTES,
            });
        }
        pending.extend_from_slice(chunk);
        return Ok(true);
    }
    if pending.len() + chunk.len() > MAX_AGENT_LINE_BYTES {
        pending.clear();
        return Err(AgentError::Oversized {
            bytes: MAX_AGENT_LINE_BYTES,
        });
    }
    pending.extend_from_slice(chunk);
    Ok(false)
}

/// Chunked, capped line read. `deadline` is the poll loop used by
/// `read_response_line` (serial / vsock). `Ok(0)` is unexpected EOF
/// when `eof_fatal` is set or there is no deadline (the PTY path
/// handles that itself); otherwise it is polled until the deadline.
fn read_capped_line(
    reader: &mut dyn Read,
    pending: &mut Vec<u8>,
    deadline: Option<Instant>,
    eof_fatal: bool,
) -> Result<String, AgentError> {
    const CHUNK: usize = 8192;
    if let Some(line) = take_complete_line(pending)? {
        return Ok(line);
    }
    loop {
        let mut buf = [0u8; CHUNK];
        match reader.read(&mut buf) {
            Ok(0) if !eof_fatal && deadline.is_some_and(|d| Instant::now() >= d) => {
                return Err(AgentError::Timeout);
            }
            Ok(0) if !eof_fatal && deadline.is_some() => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(0) => {
                return Err(AgentError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "agent stream closed",
                )));
            }
            Ok(n) => {
                if append_capped(pending, &buf[..n])? {
                    if let Some(line) = take_complete_line(pending)? {
                        return Ok(line);
                    }
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                if deadline.is_some_and(|d| Instant::now() >= d) {
                    return Err(AgentError::Timeout);
                }
                if deadline.is_none() {
                    return Err(AgentError::Timeout);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) if deadline.is_some_and(|d| Instant::now() >= d) => {
                return Err(AgentError::Timeout);
            }
            Err(e) => return Err(AgentError::Io(e)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Generates `remaining` bytes of `x` without storing them.
    struct RepeatByte {
        remaining: usize,
    }

    impl Read for RepeatByte {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = buf.len().min(self.remaining);
            buf[..n].fill(b'x');
            self.remaining -= n;
            Ok(n)
        }
    }

    #[test]
    fn connect_vsock_refuses_hypervisor_local_host_cids() {
        for cid in [0_u64, 1, 2] {
            let started = Instant::now();
            let err = match AgentClient::connect_vsock(cid, Duration::from_secs(30)) {
                Err(e) => e,
                Ok(_) => panic!("CIDs 0–2 must fail immediately, not hang in connect()"),
            };
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "CID {cid} took {:?}; a blocking vsock connect would hang",
                started.elapsed()
            );
            let msg = format!("{err}");
            assert!(
                msg.contains(&format!("CID {cid}")) && msg.contains("FcUds"),
                "CID {cid} error should name the cid and FcUds, got {msg}"
            );
        }
    }

    #[test]
    fn read_capped_line_rejects_100mib_without_newline() {
        let mut pending = Vec::new();
        let err = read_capped_line(
            &mut RepeatByte {
                remaining: 100 << 20,
            },
            &mut pending,
            Some(Instant::now() + Duration::from_secs(5)),
            false,
        )
        .expect_err("100 MiB without a newline must not succeed");
        assert!(
            matches!(err, AgentError::Oversized { bytes } if bytes == MAX_AGENT_LINE_BYTES),
            "expected Oversized at the cap, got {err:?}"
        );
        assert!(
            pending.len() <= MAX_AGENT_LINE_BYTES,
            "peak pending {} exceeded the cap",
            pending.len()
        );
    }

    #[test]
    fn read_capped_line_accepts_8mib_read_file() {
        let payload = vec![b'A'; 8 << 20];
        let b64 = base64_encode(&payload);
        let mut line =
            format!(r#"{{"type":"read_file_result","ok":true,"data":"{b64}","error":""}}"#);
        line.push('\n');
        let mut pending = Vec::new();
        let got = read_capped_line(
            &mut Cursor::new(line.into_bytes()),
            &mut pending,
            Some(Instant::now() + Duration::from_secs(5)),
            false,
        )
        .expect("8 MiB read_file line must fit under the cap");
        match serde_json::from_str::<RawResponse>(got.trim()).expect("parse") {
            RawResponse::ReadFileResult { ok: true, data, .. } => {
                let decoded = base64_decode(&data).expect("base64");
                assert_eq!(decoded, payload);
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }
}
