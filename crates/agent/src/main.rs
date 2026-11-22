#![deny(unsafe_op_in_unsafe_fn)]
#![warn(clippy::undocumented_unsafe_blocks)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::cast_lossless)]

mod container;
mod exec;
mod health;
mod service;

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader};
use std::os::unix::io::FromRawFd;
use std::process::Command;
use std::sync::Arc;
use std::thread;

use container::ContainerManager;
use serde::{Deserialize, Serialize};
use service::{ServiceStatus, Supervisor};

const AGENT_VERSION: &str = "0.1.0";
const SERIAL_DEVICE: &str = "/dev/ttyS1";
const VSOCK_PORT: u32 = 1024;
const DEFAULT_OUTPUT_LIMIT: usize = 1024 * 1024; // 1 MiB

#[derive(Debug, Deserialize)]
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
    /// Interactive PTY exec. Handled by the connection loop
    /// (not `handle_request`) — after the handshake the connection is
    /// consumed by [`exec::run_pty_session`] for streaming.
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
        #[serde(default)]
        offset: u64,
        #[serde(default)]
        limit: usize,
    },
    #[serde(rename = "container_wait")]
    ContainerWait { name: String },
    /// Non-blocking exit probe. The shim's per-container
    /// exit watcher polls this over its own vsock connection (the
    /// blocking `container_wait` would outlive the client's 30s read
    /// deadline for any long-running container).
    #[serde(rename = "container_wait_poll")]
    ContainerWaitPoll { name: String },
    #[serde(rename = "container_signal")]
    ContainerSignal { name: String, signal: i32 },
    /// How much writable space this container is using, and
    /// out of what capacity. Measured in the guest because the host
    /// sees only the sparse image's allocated blocks, which never
    /// shrink on delete and say nothing per container.
    #[serde(rename = "container_usage")]
    ContainerUsage { name: String },
    /// Mount a virtio-blk device whose backing file
    /// the host filled AFTER boot (spare image slot). `BLKFLSBUF`
    /// first — the kernel partition-scanned a few sectors of the
    /// then-empty device at probe time and those stale cached pages
    /// must be dropped before the filesystem mounts.
    #[serde(rename = "mount_blk")]
    MountBlk {
        device: String,
        fstype: String,
        mountpoint: String,
        ro: bool,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
enum Response {
    #[serde(rename = "pong")]
    Pong {
        version: String,
        services: Vec<PongService>,
    },
    #[serde(rename = "exec_result")]
    ExecResult {
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
    ContainerExecResult { ok: bool, id: String, error: String },
    #[serde(rename = "container_wait_exec_result")]
    ContainerWaitExecResult {
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
        /// The capacity is this container's alone, i.e. a real limit.
        dedicated: bool,
        error: String,
    },
    #[serde(rename = "mount_blk_result")]
    MountBlkResult { ok: bool, error: String },
}

#[derive(Debug, Serialize)]
struct PongService {
    name: String,
    pid: u32,
    ready: bool,
    restarts: u32,
}

impl From<ServiceStatus> for PongService {
    fn from(s: ServiceStatus) -> Self {
        Self {
            name: s.name,
            pid: s.pid,
            ready: s.ready,
            restarts: s.restarts,
        }
    }
}

pub(crate) fn base64_encode(data: &[u8]) -> String {
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
pub(crate) fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
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

#[allow(clippy::too_many_lines)]
fn handle_request(
    req: Request,
    containers: &ContainerManager,
    supervisor: &Supervisor,
) -> Response {
    match req {
        Request::Ping => Response::Pong {
            version: AGENT_VERSION.to_string(),
            services: supervisor
                .status()
                .into_iter()
                .map(PongService::from)
                .collect(),
        },
        Request::Exec { id, args } => {
            if args.is_empty() {
                return Response::ExecResult {
                    id,
                    exit_code: -1,
                    stdout: String::new(),
                    stderr: "empty command".to_string(),
                };
            }
            match Command::new(&args[0]).args(&args[1..]).output() {
                Ok(output) => Response::ExecResult {
                    id,
                    exit_code: output.status.code().unwrap_or(-1),
                    stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                    stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                },
                Err(e) => Response::ExecResult {
                    id,
                    exit_code: -1,
                    stdout: String::new(),
                    stderr: format!("exec failed: {e}"),
                },
            }
        }
        Request::WriteFile { path, data } => match base64_decode(&data) {
            Ok(bytes) => {
                if let Some(parent) = std::path::Path::new(&path).parent() {
                    let _ = fs::create_dir_all(parent);
                }
                match fs::write(&path, &bytes) {
                    Ok(()) => Response::WriteFileResult {
                        ok: true,
                        error: String::new(),
                    },
                    Err(e) => Response::WriteFileResult {
                        ok: false,
                        error: format!("{e}"),
                    },
                }
            }
            Err(e) => Response::WriteFileResult {
                ok: false,
                error: format!("base64 decode: {e}"),
            },
        },
        Request::ReadFile { path } => match fs::read(&path) {
            Ok(bytes) => Response::ReadFileResult {
                ok: true,
                data: base64_encode(&bytes),
                error: String::new(),
            },
            Err(e) => Response::ReadFileResult {
                ok: false,
                data: String::new(),
                error: format!("{e}"),
            },
        },
        Request::ContainerStart { name, bundle } => {
            if supervisor.watches_docker() {
                if let Err(e) = supervisor.wait_ready(std::time::Duration::from_secs(60)) {
                    return Response::ContainerStartResult {
                        ok: false,
                        error: format!("docker not ready: {e}"),
                    };
                }
            }
            match containers.start(&name, &bundle) {
                Ok(()) => Response::ContainerStartResult {
                    ok: true,
                    error: String::new(),
                },
                Err(e) => Response::ContainerStartResult {
                    ok: false,
                    error: e,
                },
            }
        }
        Request::ContainerExecPty { .. } => {
            unreachable!("container_exec_pty is handled by the connection loop")
        }
        Request::ContainerExec { name, id, args } => match containers.exec(&name, &id, &args) {
            Ok(()) => Response::ContainerExecResult {
                ok: true,
                id,
                error: String::new(),
            },
            Err(e) => Response::ContainerExecResult {
                ok: false,
                id,
                error: e,
            },
        },
        Request::ContainerWaitExec { id } => match containers.wait_exec(&id) {
            Some(output) => Response::ContainerWaitExecResult {
                id,
                done: true,
                exit_code: output.exit_code,
                stdout: output.stdout,
                stderr: output.stderr,
            },
            None => Response::ContainerWaitExecResult {
                id,
                done: false,
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            },
        },
        Request::ContainerStop { name } => match containers.stop(&name) {
            Ok(()) => Response::ContainerStopResult {
                ok: true,
                error: String::new(),
            },
            Err(e) => Response::ContainerStopResult {
                ok: false,
                error: e,
            },
        },
        Request::ContainerList => Response::ContainerListResult {
            containers: containers.list(),
        },
        Request::ContainerOutput {
            name,
            offset,
            limit,
        } => {
            let limit = if limit == 0 {
                DEFAULT_OUTPUT_LIMIT
            } else {
                limit
            };
            match containers.output(&name, offset, limit) {
                Ok(output) => Response::ContainerOutputResult {
                    ok: true,
                    stdout: output.stdout,
                    stderr: output.stderr,
                    error: String::new(),
                },
                Err(e) => Response::ContainerOutputResult {
                    ok: false,
                    stdout: String::new(),
                    stderr: String::new(),
                    error: e,
                },
            }
        }
        Request::ContainerWait { name } => match containers.wait(&name) {
            Ok(exit_code) => Response::ContainerWaitResult {
                ok: true,
                exit_code,
                error: String::new(),
            },
            Err(e) => Response::ContainerWaitResult {
                ok: false,
                exit_code: -1,
                error: e,
            },
        },
        Request::ContainerWaitPoll { name } => match containers.poll_exit(&name) {
            Ok(Some(code)) => Response::ContainerWaitPollResult {
                ok: true,
                done: true,
                exit_code: code,
                error: String::new(),
            },
            Ok(None) => Response::ContainerWaitPollResult {
                ok: true,
                done: false,
                exit_code: 0,
                error: String::new(),
            },
            Err(e) => Response::ContainerWaitPollResult {
                ok: false,
                done: false,
                exit_code: -1,
                error: e,
            },
        },
        Request::ContainerSignal { name, signal } => match containers.signal(&name, signal) {
            Ok(()) => Response::ContainerSignalResult {
                ok: true,
                error: String::new(),
            },
            Err(e) => Response::ContainerSignalResult {
                ok: false,
                error: e,
            },
        },
        Request::ContainerUsage { name } => match containers.usage(&name) {
            Ok(u) => Response::ContainerUsageResult {
                ok: true,
                used_bytes: u.used_bytes,
                capacity_bytes: u.capacity_bytes,
                dedicated: u.dedicated,
                error: String::new(),
            },
            Err(e) => Response::ContainerUsageResult {
                ok: false,
                used_bytes: 0,
                capacity_bytes: 0,
                dedicated: false,
                error: e,
            },
        },
        Request::MountBlk {
            device,
            fstype,
            mountpoint,
            ro,
        } => match mount_blk_request(&device, &fstype, &mountpoint, ro) {
            Ok(()) => Response::MountBlkResult {
                ok: true,
                error: String::new(),
            },
            Err(e) => Response::MountBlkResult {
                ok: false,
                error: e,
            },
        },
    }
}

/// `_IO(0x12, 97)` — flush the block-layer buffer cache for a device.
const BLKFLSBUF: u64 = 0x1261;

/// Handle a `mount_blk` request: validate, flush the
/// device's stale cache with `BLKFLSBUF` (the host rewrote the backing
/// file after the boot-time probe), then mount. Fail-loud: every error
/// travels back to the shim verbatim.
fn mount_blk_request(device: &str, fstype: &str, mountpoint: &str, ro: bool) -> Result<(), String> {
    if device.is_empty() || device.contains('/') {
        return Err(format!("invalid device name {device:?}"));
    }
    if !mountpoint.starts_with('/') {
        return Err(format!("mountpoint {mountpoint:?} must be absolute"));
    }
    let dev_path = format!("/dev/{device}");
    if !std::path::Path::new(&dev_path).exists() {
        return Err(format!(
            "{dev_path} does not exist — image slots are boot-time declarations; \
             is the slot index right?"
        ));
    }
    {
        use std::os::unix::io::AsRawFd;
        let dev = fs::File::open(&dev_path).map_err(|e| format!("open {dev_path}: {e}"))?;
        // SAFETY: dev is a valid open fd for the duration of the call;
        // BLKFLSBUF takes no argument.
        let rc = unsafe { libc::ioctl(dev.as_raw_fd(), BLKFLSBUF as _) };
        if rc < 0 {
            return Err(format!(
                "BLKFLSBUF {dev_path}: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    fs::create_dir_all(mountpoint).map_err(|e| format!("create {mountpoint}: {e}"))?;
    let mut args: Vec<&str> = vec!["-t", fstype];
    if ro {
        args.extend(["-o", "ro"]);
    }
    args.extend([dev_path.as_str(), mountpoint]);
    let output = Command::new("mount")
        .args(&args)
        .output()
        .map_err(|e| format!("mount command failed: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "mount {dev_path} ({fstype}) at {mountpoint}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    eprintln!(
        "k7-agent: mount_blk {dev_path} ({fstype}) at {mountpoint} ({})",
        if ro { "ro" } else { "rw" }
    );
    Ok(())
}

fn handle_connection<R, W>(
    read: R,
    mut write: W,
    containers: &ContainerManager,
    supervisor: &Supervisor,
) where
    R: std::io::Read,
    W: std::io::Write + Send + 'static,
{
    let mut reader = BufReader::new(read);
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                eprintln!("k7-agent: read error: {e}");
                break;
            }
        }
        if line.trim().is_empty() {
            continue;
        }
        let req: Request = match serde_json::from_str(line.trim()) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("k7-agent: bad request: {e}");
                continue;
            }
        };
        // A PTY exec handshake switches this connection into
        // streaming mode — the session consumes reader and writer.
        if let Request::ContainerExecPty {
            name,
            id,
            args,
            term,
            rows,
            cols,
        } = req
        {
            exec::run_pty_session(
                reader,
                write,
                containers,
                &exec::PtyExecParams {
                    name,
                    id,
                    args,
                    term,
                    rows,
                    cols,
                },
            );
            return;
        }
        let resp = handle_request(req, containers, supervisor);
        let mut resp_json = serde_json::to_string(&resp).unwrap();
        resp_json.push('\n');
        if write.write_all(resp_json.as_bytes()).is_err() {
            break;
        }
    }
}

fn try_vsock_listener(
    containers: &Arc<ContainerManager>,
    supervisor: &Arc<Supervisor>,
) -> Result<(), std::io::Error> {
    // SAFETY: creating an AF_VSOCK stream socket; no preconditions.
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let addr = libc::sockaddr_vm {
        svm_family: libc::AF_VSOCK as u16,
        svm_reserved1: 0,
        svm_port: VSOCK_PORT,
        svm_cid: libc::VMADDR_CID_ANY,
        svm_zero: [0u8; 4],
    };

    // SAFETY: fd is a valid socket; addr is a properly initialized sockaddr_vm.
    if unsafe {
        libc::bind(
            fd,
            (&raw const addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_vm>() as u32,
        )
    } < 0
    {
        let err = std::io::Error::last_os_error();
        // SAFETY: fd is a valid socket fd we just created.
        unsafe { libc::close(fd) };
        return Err(err);
    }

    // SAFETY: fd is a valid bound socket; backlog of 4 is reasonable.
    if unsafe { libc::listen(fd, 4) } < 0 {
        let err = std::io::Error::last_os_error();
        // SAFETY: fd is a valid socket fd.
        unsafe { libc::close(fd) };
        return Err(err);
    }

    eprintln!("k7-agent: listening on vsock port {VSOCK_PORT}");

    loop {
        // SAFETY: fd is a valid listening socket; null args mean we don't need peer address.
        let client_fd = unsafe { libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if client_fd < 0 {
            eprintln!(
                "k7-agent: accept failed: {}",
                std::io::Error::last_os_error()
            );
            continue;
        }
        eprintln!("k7-agent: vsock connection accepted");
        // SAFETY: client_fd is a valid accepted socket fd; File takes ownership.
        let read_file = unsafe { std::fs::File::from_raw_fd(client_fd) };
        let write_file = read_file.try_clone().unwrap();
        let cm = Arc::clone(containers);
        let sup = Arc::clone(supervisor);
        thread::spawn(move || {
            handle_connection(read_file, write_file, &cm, &sup);
            eprintln!("k7-agent: vsock connection closed");
        });
    }
}

fn run_serial_listener(
    containers: &ContainerManager,
    supervisor: &Supervisor,
) -> std::io::Result<()> {
    eprintln!("k7-agent v{AGENT_VERSION}: opening {SERIAL_DEVICE}");
    let read_file = File::open(SERIAL_DEVICE)?;
    let write_file = OpenOptions::new().write(true).open(SERIAL_DEVICE)?;
    eprintln!("k7-agent: listening on {SERIAL_DEVICE}");

    handle_connection(read_file, write_file, containers, supervisor);
    Ok(())
}

/// Parsed virtiofs share spec from the `k7d.virtiofs=` kernel cmdline param.
///
/// Host-side encoding (see `crates/k7d/src/vm.rs` build loop):
/// `k7d.virtiofs=<tag>:<mount>:<ro|rw>,<tag>:<mount>:<ro|rw>,…`
struct VirtiofsShareSpec {
    tag: String,
    mount: String,
    readonly: bool,
}

/// Pull the `k7d.virtiofs=` param out of `cmdline` and return the
/// parsed shares. Returns `None` if the param is absent (legacy
/// host).
fn parse_virtiofs_shares(cmdline: &str) -> Option<Vec<VirtiofsShareSpec>> {
    let raw = cmdline
        .split_ascii_whitespace()
        .find_map(|tok| tok.strip_prefix("k7d.virtiofs="))?;
    let mut shares = Vec::new();
    for spec in raw.split(',') {
        let mut parts = spec.splitn(3, ':');
        let tag = parts.next()?.to_string();
        let mount = parts.next()?.to_string();
        let mode = parts.next().unwrap_or("rw");
        if tag.is_empty() || mount.is_empty() {
            continue;
        }
        shares.push(VirtiofsShareSpec {
            tag,
            mount,
            readonly: mode == "ro",
        });
    }
    Some(shares)
}

fn mount_one_virtiofs_share(share: &VirtiofsShareSpec) {
    let _ = fs::create_dir_all(&share.mount);
    let mut args: Vec<&str> = vec!["-t", "virtiofs"];
    if share.readonly {
        args.push("-o");
        args.push("ro");
    }
    args.push(&share.tag);
    args.push(&share.mount);
    let result = Command::new("mount").args(&args).output();
    match result {
        Ok(output) if output.status.success() => {
            eprintln!(
                "k7-agent: mounted virtiofs tag={} at {} ({})",
                share.tag,
                share.mount,
                if share.readonly { "ro" } else { "rw" }
            );
        }
        Ok(output) => {
            eprintln!(
                "k7-agent: virtiofs mount failed for tag={} at {}: {}",
                share.tag,
                share.mount,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Err(e) => {
            eprintln!(
                "k7-agent: mount command failed for tag={} at {}: {e}",
                share.tag, share.mount
            );
        }
    }
}

fn try_mount_virtiofs() {
    // Prefer the explicit `k7d.virtiofs=` cmdline param,
    // which carries per-share (tag, mount, ro/rw) triples. Fall back
    // to the historical hardcoded single-share `mount -t virtiofs
    // k7fs /mnt/state` when the param is absent (= legacy host or
    // no shares configured).
    let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
    if let Some(shares) = parse_virtiofs_shares(&cmdline) {
        if shares.is_empty() {
            eprintln!("k7-agent: k7d.virtiofs= present but parsed 0 shares; nothing to mount");
            return;
        }
        for share in &shares {
            mount_one_virtiofs_share(share);
        }
        return;
    }

    // Legacy fallback: single share tagged `k7fs` mounted r/w at
    // `/mnt/state`. Matches what the legacy host's single-share
    // build path expected.
    let _ = fs::create_dir_all("/mnt/state");
    let result = Command::new("mount")
        .args(["-t", "virtiofs", "k7fs", "/mnt/state"])
        .output();

    match result {
        Ok(output) if output.status.success() => {
            eprintln!("k7-agent: mounted virtiofs at /mnt/state (legacy fallback)");
        }
        Ok(output) => {
            eprintln!(
                "k7-agent: virtiofs mount failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Err(e) => {
            eprintln!("k7-agent: mount command failed: {e}");
        }
    }
}

/// Parsed block-device mount spec from the `k7d.blk=` kernel cmdline
/// param, mirroring `k7d.virtiofs=`:
/// `k7d.blk=<dev>:<mount>:<fstype>:<ro|rw>,…` where `<dev>` is the
/// guest device name (`vda`, `vdb`, …) in declaration order.
pub(crate) struct BlkMountSpec {
    dev: String,
    pub(crate) mount: String,
    fstype: String,
    readonly: bool,
}

/// Pull the `k7d.blk=` param out of `cmdline` and return the parsed
/// mounts. Returns `None` if the param is absent (no agent-mounted
/// block devices configured).
///
/// Also reads this from [`crate::container`]: the presence of
/// a mount at the scratch mount point is the host's *promise* of a
/// host-backed writable layer, which turns a missing mount into a hard
/// error instead of a silent RAM-backed fallback.
pub(crate) fn parse_blk_mounts(cmdline: &str) -> Option<Vec<BlkMountSpec>> {
    let raw = cmdline
        .split_ascii_whitespace()
        .find_map(|tok| tok.strip_prefix("k7d.blk="))?;
    let mut mounts = Vec::new();
    for spec in raw.split(',') {
        let mut parts = spec.splitn(4, ':');
        let dev = parts.next()?.to_string();
        let mount = parts.next()?.to_string();
        let fstype = parts.next()?.to_string();
        let mode = parts.next().unwrap_or("rw");
        if dev.is_empty() || mount.is_empty() || fstype.is_empty() {
            continue;
        }
        mounts.push(BlkMountSpec {
            dev,
            mount,
            fstype,
            readonly: mode == "ro",
        });
    }
    Some(mounts)
}

fn mount_one_blk(spec: &BlkMountSpec) {
    // The virtio-blk probe can still be settling when the agent starts:
    // wait (bounded) for the device node before mounting, loud on
    // timeout — a rootfs that silently fails to mount would surface as
    // an inscrutable runc error later.
    let dev_path = format!("/dev/{}", spec.dev);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !std::path::Path::new(&dev_path).exists() {
        if std::time::Instant::now() >= deadline {
            eprintln!(
                "k7-agent: block device {dev_path} never appeared; cannot mount at {}",
                spec.mount
            );
            return;
        }
        thread::sleep(std::time::Duration::from_millis(50));
    }
    let _ = fs::create_dir_all(&spec.mount);
    let mut args: Vec<&str> = vec!["-t", &spec.fstype];
    if spec.readonly {
        args.push("-o");
        args.push("ro");
    }
    args.push(&dev_path);
    args.push(&spec.mount);
    match Command::new("mount").args(&args).output() {
        Ok(output) if output.status.success() => {
            eprintln!(
                "k7-agent: mounted {} ({}) at {} ({})",
                dev_path,
                spec.fstype,
                spec.mount,
                if spec.readonly { "ro" } else { "rw" }
            );
        }
        Ok(output) => {
            eprintln!(
                "k7-agent: block mount failed for {} at {}: {}",
                dev_path,
                spec.mount,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Err(e) => {
            eprintln!(
                "k7-agent: mount command failed for {} at {}: {e}",
                dev_path, spec.mount
            );
        }
    }
}

/// Pull the `k7d.mkdir=` param out of `cmdline` and return the
/// comma-separated absolute directories to create (guest tmpfs
/// directories for emptyDir volumes). Returns `None` if
/// the param is absent. Relative entries are skipped loudly at
/// creation time, matching the host-side builder validation.
fn parse_mkdir_dirs(cmdline: &str) -> Option<Vec<String>> {
    let raw = cmdline
        .split_ascii_whitespace()
        .find_map(|tok| tok.strip_prefix("k7d.mkdir="))?;
    Some(
        raw.split(',')
            .filter(|d| !d.is_empty())
            .map(str::to_string)
            .collect(),
    )
}

/// Create every directory listed in `k7d.mkdir=` before containers
/// start. The guest rootfs is the initramfs tmpfs, so these are
/// RAM-backed directories that fork with the memory `CoW` for free —
/// Uses them as emptyDir volume backing.
fn try_mkdir_dirs() {
    let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let Some(dirs) = parse_mkdir_dirs(&cmdline) else {
        return;
    };
    for dir in &dirs {
        if !dir.starts_with('/') {
            eprintln!("k7-agent: skipping non-absolute k7d.mkdir entry {dir:?}");
            continue;
        }
        match fs::create_dir_all(dir) {
            Ok(()) => eprintln!("k7-agent: created guest dir {dir}"),
            Err(e) => eprintln!("k7-agent: create_dir_all({dir}) failed: {e}"),
        }
    }
}

/// Mount every device listed in `k7d.blk=` before containers start —
/// the same discipline as the virtiofs loop.
fn try_mount_blk() {
    let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let Some(mounts) = parse_blk_mounts(&cmdline) else {
        return;
    };
    if mounts.is_empty() {
        eprintln!("k7-agent: k7d.blk= present but parsed 0 mounts; nothing to mount");
        return;
    }
    for spec in &mounts {
        mount_one_blk(spec);
    }
}

/// Bring the loopback interface up. Containers of a
/// pod share the guest's root netns (the shim strips the OCI network
/// namespace), so `127.0.0.1` is the pod-local loopback — with `lo`
/// down, in-pod and cross-container localhost connects hang.
fn bring_lo_up() {
    match Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .output()
    {
        Ok(output) if output.status.success() => {}
        Ok(output) => eprintln!(
            "k7-agent: ip link set lo up failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        Err(e) => eprintln!("k7-agent: ip link set lo up failed: {e}"),
    }
}

fn main() {
    eprintln!("k7-agent v{AGENT_VERSION} starting");
    let _ = fs::create_dir_all("/mnt/state");

    bring_lo_up();
    try_mount_virtiofs();
    try_mount_blk();
    try_mkdir_dirs();

    let containers = Arc::new(ContainerManager::new());
    let supervisor = Supervisor::new();
    if Supervisor::docker_enabled() {
        eprintln!("k7-agent: k7d.docker=1 — supervising dockerd");
        supervisor.start_docker();
    }

    // On virtio-mmio the devices are named on the cmdline; on
    // virtio-pci the guest probes the bus and the only trace is the
    // transport's own `/dev/vsock` (vhost-vsock in the guest).
    let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let has_vsock_device =
        cmdline.contains("virtio_mmio.device=") || std::path::Path::new("/dev/vsock").exists();
    match if has_vsock_device {
        try_vsock_listener(&containers, &supervisor)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no virtio-mmio devices and no /dev/vsock",
        ))
    } {
        Ok(()) => {}
        Err(e) => {
            eprintln!("k7-agent: vsock unavailable ({e}), falling back to serial");
            if let Err(e) = run_serial_listener(&containers, &supervisor) {
                eprintln!("k7-agent: serial listener failed: {e}");
                std::process::exit(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_blk_mounts, parse_mkdir_dirs, parse_virtiofs_shares};

    #[test]
    fn parse_mkdir_dirs_absent() {
        assert!(parse_mkdir_dirs("console=ttyS0 panic=1").is_none());
    }

    #[test]
    fn parse_mkdir_dirs_multi() {
        let dirs = parse_mkdir_dirs(
            "foo k7d.mkdir=/run/k7d/emptydir/emptydir-scratch,/run/k7d/emptydir/emptydir-cache bar",
        )
        .expect("present");
        assert_eq!(
            dirs,
            vec![
                "/run/k7d/emptydir/emptydir-scratch".to_string(),
                "/run/k7d/emptydir/emptydir-cache".to_string(),
            ]
        );
    }

    #[test]
    fn parse_mkdir_dirs_skips_empty_entries() {
        let dirs = parse_mkdir_dirs("k7d.mkdir=/a,,/b").expect("present");
        assert_eq!(dirs, vec!["/a".to_string(), "/b".to_string()]);
    }

    #[test]
    fn parse_virtiofs_shares_absent() {
        assert!(parse_virtiofs_shares("console=ttyS0 panic=1").is_none());
    }

    #[test]
    fn parse_virtiofs_shares_single() {
        let shares =
            parse_virtiofs_shares("foo k7d.virtiofs=k7fs:/mnt/state:rw bar").expect("present");
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].tag, "k7fs");
        assert_eq!(shares[0].mount, "/mnt/state");
        assert!(!shares[0].readonly);
    }

    #[test]
    fn parse_virtiofs_shares_multi_mixed_ro_rw() {
        let shares = parse_virtiofs_shares(
            "console=ttyS0 k7d.virtiofs=k7fs:/mnt/state:rw,k7fs1:/mnt/cfg:ro,k7fs2:/mnt/data:rw",
        )
        .expect("present");
        assert_eq!(shares.len(), 3);
        assert_eq!(shares[0].tag, "k7fs");
        assert_eq!(shares[0].mount, "/mnt/state");
        assert!(!shares[0].readonly);
        assert_eq!(shares[1].tag, "k7fs1");
        assert_eq!(shares[1].mount, "/mnt/cfg");
        assert!(shares[1].readonly);
        assert_eq!(shares[2].tag, "k7fs2");
        assert_eq!(shares[2].mount, "/mnt/data");
        assert!(!shares[2].readonly);
    }

    #[test]
    fn parse_virtiofs_shares_default_mode_is_rw() {
        // Bare "tag:mount" with no third field defaults to rw.
        let shares = parse_virtiofs_shares("k7d.virtiofs=k7fs:/mnt/state").expect("present");
        assert_eq!(shares.len(), 1);
        assert!(!shares[0].readonly);
    }

    #[test]
    fn parse_blk_mounts_absent() {
        assert!(parse_blk_mounts("console=ttyS0 panic=1").is_none());
    }

    #[test]
    fn parse_blk_mounts_single_ro() {
        let mounts =
            parse_blk_mounts("foo k7d.blk=vda:/run/k7d/rootfs:erofs:ro bar").expect("present");
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].dev, "vda");
        assert_eq!(mounts[0].mount, "/run/k7d/rootfs");
        assert_eq!(mounts[0].fstype, "erofs");
        assert!(mounts[0].readonly);
    }

    #[test]
    fn parse_blk_mounts_multi_default_rw() {
        let mounts = parse_blk_mounts(
            "k7d.blk=vda:/run/k7d/rootfs:erofs:ro,vdb:/mnt/data:ext4,vdc:/mnt/scratch:xfs:rw",
        )
        .expect("present");
        assert_eq!(mounts.len(), 3);
        assert!(mounts[0].readonly);
        assert_eq!(mounts[1].dev, "vdb");
        assert_eq!(mounts[1].fstype, "ext4");
        assert!(!mounts[1].readonly, "missing mode defaults to rw");
        assert!(!mounts[2].readonly);
    }

    #[test]
    fn parse_blk_mounts_skips_malformed_entries() {
        let mounts = parse_blk_mounts(
            "k7d.blk=vda:/run/k7d/rootfs:erofs:ro,:/bad:ext4:rw,vdb::ext4:rw,vdc:/ok:",
        )
        .expect("present");
        assert_eq!(mounts.len(), 1, "empty dev/mount/fstype entries dropped");
        assert_eq!(mounts[0].dev, "vda");
    }

    #[test]
    fn parse_virtiofs_shares_skips_malformed_entries() {
        // Empty tag / empty mount entries are dropped, valid ones kept.
        let shares = parse_virtiofs_shares(
            "k7d.virtiofs=k7fs:/mnt/state:rw,:/mnt/bad:rw,k7fsX::ro,k7fs1:/mnt/ok:ro",
        )
        .expect("present");
        assert_eq!(shares.len(), 2);
        assert_eq!(shares[0].tag, "k7fs");
        assert_eq!(shares[1].tag, "k7fs1");
        assert_eq!(shares[1].mount, "/mnt/ok");
        assert!(shares[1].readonly);
    }
}
