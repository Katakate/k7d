//! Container lifecycle via runc inside the VM.
//!
//! Design decisions:
//! - `start`: uses `runc run --detach` so the agent returns immediately.
//! - `exec`: spawns `runc exec` in a background thread. Returns an exec ID
//!   instantly. The host polls `wait_exec(id)` for the result, so the
//!   connection is never blocked by a long-running exec.
//! - `output`: reads container stdout/stderr from files with byte offset,
//!   so the host can incrementally tail logs without loading everything.
//! - `stop`: `runc kill SIGTERM`, brief wait, `runc delete --force`.
//!   No busy-poll loop — runc delete --force handles cleanup regardless
//!   of whether the process has exited.

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

const CONTAINER_RUN_DIR: &str = "/run/k7/containers";
const RUNC_VIRTIOFS: &str = "/mnt/state/bin/runc";
/// internal notes: the shim attaches a cached "tools" erofs image
/// (containing the static runc) as a read-only virtio-blk device
/// mounted here, so block-path pods carry no virtiofs share at all.
const RUNC_BLOCK_TOOLS: &str = "/run/k7d/tools/runc";
const RUNC_LOCAL: &str = "/usr/local/bin/runc";

pub(crate) fn runc_path() -> &'static str {
    if std::path::Path::new(RUNC_VIRTIOFS).exists() {
        RUNC_VIRTIOFS
    } else if std::path::Path::new(RUNC_BLOCK_TOOLS).exists() {
        RUNC_BLOCK_TOOLS
    } else {
        RUNC_LOCAL
    }
}

/// Tracks running containers managed by runc.
pub struct ContainerManager {
    containers: Mutex<HashMap<String, ContainerState>>,
    execs: Arc<Mutex<HashMap<String, ExecState>>>,
}

#[allow(clippy::struct_field_names)]
struct ContainerState {
    _bundle_path: String,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    /// Overlay rootfs mounts to tear down when the container goes away
    ///.
    overlay: Option<OverlayMounts>,
    /// The container init pid (from runc's `--pid-file`). The agent is
    /// guest PID 1, so `runc run --detach` reparents init to us and its
    /// real exit status is collectable via `waitpid`.
    init_pid: libc::pid_t,
    /// Cached exit code once the init process has been reaped, so every
    /// later `poll_exit`/`wait` caller observes the same code.
    exit_code: Option<i32>,
}

/// Mounts backing an overlay container rootfs, unmounted in order on
/// cleanup: first the overlay (`merged`), then the tmpfs holding
/// upper/work (`tmpfs`).
struct OverlayMounts {
    merged: PathBuf,
    tmpfs: PathBuf,
}

fn cleanup_overlay(overlay: &OverlayMounts) {
    for mnt in [&overlay.merged, &overlay.tmpfs] {
        let out = Command::new("umount").arg(mnt).output();
        if let Ok(out) = out {
            if !out.status.success() {
                eprintln!(
                    "k7-agent: umount {} failed: {}",
                    mnt.display(),
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
        }
    }
}

/// Filesystem type of the mount that `path` lives on, per
/// `/proc/mounts` (longest mountpoint prefix wins). `None` when the
/// path resolves to no mount (should not happen — `/` always matches).
fn mount_fstype_of(path: &Path) -> Option<String> {
    let mounts = fs::read_to_string("/proc/mounts").ok()?;
    let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let mut best: Option<(usize, String)> = None;
    for line in mounts.lines() {
        let mut fields = line.split_whitespace();
        let (Some(_dev), Some(mnt), Some(fstype)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let mnt_path = Path::new(mnt);
        if path.starts_with(mnt_path) && best.as_ref().is_none_or(|(len, _)| mnt.len() >= *len) {
            best = Some((mnt.len(), fstype.to_string()));
        }
    }
    best.map(|(_, fstype)| fstype)
}

/// internal notes: when the bundle's rootfs lives on a read-only erofs
/// block mount, runc cannot use it directly (no upper layer to write
/// to). Assemble `overlay(lower=<erofs rootfs>, upper+work=tmpfs)`
/// under `run_dir` and return a patched bundle whose `root.path` is
/// the overlay's merged dir. Returns the bundle to hand runc plus the
/// mounts to tear down; `(original bundle, None)` when the rootfs is
/// not on erofs.
fn prepare_rootfs_overlay(
    bundle: &Path,
    run_dir: &Path,
) -> Result<(PathBuf, Option<OverlayMounts>), String> {
    let config_raw = fs::read_to_string(bundle.join("config.json"))
        .map_err(|e| format!("read config.json: {e}"))?;
    let mut config: serde_json::Value =
        serde_json::from_str(&config_raw).map_err(|e| format!("parse config.json: {e}"))?;
    let root_path = config
        .get("root")
        .and_then(|r| r.get("path"))
        .and_then(|p| p.as_str())
        .unwrap_or("rootfs");
    let rootfs = if root_path.starts_with('/') {
        PathBuf::from(root_path)
    } else {
        bundle.join(root_path)
    };
    if mount_fstype_of(&rootfs).as_deref() != Some("erofs") {
        return Ok((bundle.to_path_buf(), None));
    }

    // upper + work must live on the same writable fs: a fresh tmpfs.
    let tmpfs = run_dir.join("overlay");
    fs::create_dir_all(&tmpfs).map_err(|e| format!("create {}: {e}", tmpfs.display()))?;
    let out = Command::new("mount")
        .args(["-t", "tmpfs", "tmpfs"])
        .arg(&tmpfs)
        .output()
        .map_err(|e| format!("mount tmpfs: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "mount tmpfs at {}: {}",
            tmpfs.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let overlay = OverlayMounts {
        merged: tmpfs.join("merged"),
        tmpfs,
    };
    let result = (|| {
        let upper = overlay.tmpfs.join("upper");
        let work = overlay.tmpfs.join("work");
        for d in [&upper, &work, &overlay.merged] {
            fs::create_dir_all(d).map_err(|e| format!("create {}: {e}", d.display()))?;
        }
        let opts = format!(
            "lowerdir={},upperdir={},workdir={}",
            rootfs.display(),
            upper.display(),
            work.display()
        );
        let out = Command::new("mount")
            .args(["-t", "overlay", "overlay", "-o", &opts])
            .arg(&overlay.merged)
            .output()
            .map_err(|e| format!("mount overlay: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "mount overlay ({opts}): {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }

        // Patched bundle: same config, root.path = the merged dir.
        let patched_bundle = run_dir.join("bundle");
        fs::create_dir_all(&patched_bundle)
            .map_err(|e| format!("create {}: {e}", patched_bundle.display()))?;
        config["root"]["path"] =
            serde_json::Value::String(overlay.merged.to_string_lossy().into_owned());
        fs::write(
            patched_bundle.join("config.json"),
            serde_json::to_string(&config).map_err(|e| format!("serialize config: {e}"))?,
        )
        .map_err(|e| format!("write patched config.json: {e}"))?;
        eprintln!(
            "k7-agent: erofs rootfs {} overlaid at {} (tmpfs upper)",
            rootfs.display(),
            overlay.merged.display()
        );
        Ok(patched_bundle)
    })();
    match result {
        Ok(patched_bundle) => Ok((patched_bundle, Some(overlay))),
        Err(e) => {
            cleanup_overlay(&overlay);
            Err(e)
        }
    }
}

enum ExecState {
    Running,
    Done(ExecOutput),
}

/// Result of a container exec operation.
pub struct ExecOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Captured output from a container's main process.
pub struct ContainerOutput {
    pub stdout: String,
    pub stderr: String,
}

fn container_dir(name: &str) -> PathBuf {
    PathBuf::from(CONTAINER_RUN_DIR).join(name)
}

fn read_from_offset(path: &Path, offset: u64, limit: usize) -> String {
    let Ok(mut f) = fs::File::open(path) else {
        return String::new();
    };
    if f.seek(SeekFrom::Start(offset)).is_err() {
        return String::new();
    }
    let mut buf = vec![0u8; limit];
    let n = f.read(&mut buf).unwrap_or(0);
    buf.truncate(n);
    String::from_utf8_lossy(&buf).to_string()
}

impl ContainerManager {
    pub fn new() -> Self {
        Self {
            containers: Mutex::new(HashMap::new()),
            execs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Start a container from an OCI bundle at `bundle_path`.
    /// The bundle must contain a `config.json` and a `rootfs/` directory.
    ///
    /// Uses `runc run --detach` so this returns as soon as runc forks the
    /// container init process. Stdout/stderr are captured to files under
    /// `/run/k7/containers/{name}/`.
    pub fn start(&self, name: &str, bundle_path: &str) -> Result<(), String> {
        {
            let containers = self.containers.lock().unwrap();
            if containers.contains_key(name) {
                return Err(format!("container {name} already exists"));
            }
        }

        let bundle = Path::new(bundle_path);
        if !bundle.join("config.json").exists() {
            return Err(format!("no config.json in bundle at {bundle_path}"));
        }

        let run_dir = container_dir(name);
        fs::create_dir_all(&run_dir)
            .map_err(|e| format!("failed to create run dir {}: {e}", run_dir.display()))?;

        // internal notes: rootfs on a read-only erofs block mount gets an
        // overlay with a tmpfs upper; runc receives the patched bundle.
        let (runc_bundle, overlay) = match prepare_rootfs_overlay(bundle, &run_dir) {
            Ok(v) => v,
            Err(e) => {
                let _ = fs::remove_dir_all(&run_dir);
                return Err(format!("prepare rootfs overlay: {e}"));
            }
        };
        let runc_bundle_str = runc_bundle.to_string_lossy().into_owned();

        let stdout_path = run_dir.join("stdout");
        let stderr_path = run_dir.join("stderr");
        // internal notes: runc writes the init pid here at create time,
        // BEFORE start — reliable even for containers that exit
        // instantly (`runc state` would already report pid 0).
        let pid_file = run_dir.join("pid");

        let result = (|| {
            let stdout_file =
                fs::File::create(&stdout_path).map_err(|e| format!("create stdout file: {e}"))?;
            let stderr_file =
                fs::File::create(&stderr_path).map_err(|e| format!("create stderr file: {e}"))?;

            let child = Command::new(runc_path())
                .args([
                    "run",
                    "--detach",
                    "--no-pivot",
                    "--pid-file",
                    &pid_file.to_string_lossy(),
                    "--bundle",
                    &runc_bundle_str,
                    name,
                ])
                .stdin(Stdio::null())
                .stdout(stdout_file)
                .stderr(stderr_file)
                .spawn()
                .map_err(|e| format!("failed to spawn runc run: {e}"))?;

            // `runc run --detach` forks the container init and exits quickly.
            let output = child
                .wait_with_output()
                .map_err(|e| format!("runc run wait failed: {e}"))?;

            if !output.status.success() {
                let err_detail = fs::read_to_string(&stderr_path).unwrap_or_default();
                let _ = Command::new(runc_path())
                    .args(["delete", "--force", name])
                    .output();
                return Err(format!("runc run failed: {err_detail}"));
            }

            // Fail loud when the pid is unreadable: exit-code observation
            // is a correctness feature — restartPolicy
            // and init-container sequencing depend on it.
            let pid: libc::pid_t = fs::read_to_string(&pid_file)
                .map_err(|e| format!("read runc pid-file {}: {e}", pid_file.display()))?
                .trim()
                .parse()
                .map_err(|e| format!("parse runc pid-file {}: {e}", pid_file.display()))?;
            Ok(pid)
        })();
        let init_pid = match result {
            Ok(pid) => pid,
            Err(e) => {
                if let Some(ref ov) = overlay {
                    cleanup_overlay(ov);
                }
                let _ = fs::remove_dir_all(&run_dir);
                return Err(e);
            }
        };

        let mut containers = self.containers.lock().unwrap();
        containers.insert(
            name.to_string(),
            ContainerState {
                _bundle_path: bundle_path.to_string(),
                stdout_path,
                stderr_path,
                overlay,
                init_pid,
                exit_code: None,
            },
        );

        Ok(())
    }

    /// Execute a command inside a running container.
    ///
    /// Spawns `runc exec` in a background thread and returns immediately.
    /// The caller gets back an exec ID to poll with `wait_exec`.
    pub fn exec(&self, name: &str, exec_id: &str, args: &[String]) -> Result<(), String> {
        {
            let containers = self.containers.lock().unwrap();
            if !containers.contains_key(name) {
                return Err(format!("container {name} not found"));
            }
        }

        if args.is_empty() {
            return Err("empty command".to_string());
        }

        {
            let mut execs = self.execs.lock().unwrap();
            execs.insert(exec_id.to_string(), ExecState::Running);
        }

        let name = name.to_string();
        let exec_id = exec_id.to_string();
        let args: Vec<String> = args.to_vec();
        let execs = Arc::clone(&self.execs);

        thread::spawn(move || {
            let mut cmd = Command::new(runc_path());
            cmd.args(["exec", &name]);
            for arg in &args {
                cmd.arg(arg);
            }

            let result = match cmd.output() {
                Ok(output) => ExecOutput {
                    exit_code: output.status.code().unwrap_or(-1),
                    stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                    stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                },
                Err(e) => ExecOutput {
                    exit_code: -1,
                    stdout: String::new(),
                    stderr: format!("failed to run runc exec: {e}"),
                },
            };

            let mut execs = execs.lock().unwrap();
            execs.insert(exec_id, ExecState::Done(result));
        });

        Ok(())
    }

    /// Poll for the result of a background exec. Returns `None` if still
    /// running, `Some(ExecOutput)` if finished (consuming the result).
    pub fn wait_exec(&self, exec_id: &str) -> Option<ExecOutput> {
        let mut execs = self.execs.lock().unwrap();
        match execs.get(exec_id) {
            Some(ExecState::Running) => None,
            Some(ExecState::Done(_)) => {
                let ExecState::Done(output) = execs.remove(exec_id).unwrap() else {
                    unreachable!()
                };
                Some(output)
            }
            None => Some(ExecOutput {
                exit_code: -1,
                stdout: String::new(),
                stderr: format!("exec {exec_id} not found"),
            }),
        }
    }

    /// Read stdout/stderr from a container's main process, starting at
    /// byte `offset` and reading up to `limit` bytes.
    pub fn output(&self, name: &str, offset: u64, limit: usize) -> Result<ContainerOutput, String> {
        let containers = self.containers.lock().unwrap();
        let state = containers
            .get(name)
            .ok_or_else(|| format!("container {name} not found"))?;

        let stdout = read_from_offset(&state.stdout_path, offset, limit);
        let stderr = read_from_offset(&state.stderr_path, offset, limit);

        Ok(ContainerOutput { stdout, stderr })
    }

    /// Stop and delete a running container.
    ///
    /// Sends SIGTERM, waits briefly for graceful exit, then force-deletes.
    /// `runc delete --force` kills and removes the container regardless of
    /// its current state.
    pub fn stop(&self, name: &str) -> Result<(), String> {
        {
            let containers = self.containers.lock().unwrap();
            if !containers.contains_key(name) {
                return Err(format!("container {name} not found"));
            }
        }

        // SIGTERM for graceful shutdown
        let _ = Command::new(runc_path())
            .args(["kill", name, "SIGTERM"])
            .output();

        // Brief grace period, then force-delete
        thread::sleep(std::time::Duration::from_millis(200));

        let output = Command::new(runc_path())
            .args(["delete", "--force", name])
            .output()
            .map_err(|e| format!("failed to run runc delete: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("runc delete warning: {stderr}");
        }

        let mut containers = self.containers.lock().unwrap();
        if let Some(state) = containers.remove(name) {
            if let Some(ref ov) = state.overlay {
                cleanup_overlay(ov);
            }
            let _ = fs::remove_dir_all(state.stdout_path.parent().unwrap_or(Path::new("/")));
        }

        // internal notes: container stop is the durability point for
        // writable virtio-blk volumes (k7d RWO disk images). The VM is
        // torn down without a guest-side unmount, so anything still in
        // the guest page cache when the vCPUs stop would be lost —
        // flush it to the device now.
        // SAFETY: sync(2) takes no arguments and cannot fail.
        unsafe { libc::sync() };

        Ok(())
    }

    /// Whether a container with this name is tracked (internal notes: PTY
    /// exec handshake validation).
    pub fn contains(&self, name: &str) -> bool {
        self.containers.lock().unwrap().contains_key(name)
    }

    /// List all running container names.
    pub fn list(&self) -> Vec<String> {
        let containers = self.containers.lock().unwrap();
        containers.keys().cloned().collect()
    }

    /// Non-blocking exit probe. Returns `Ok(None)`
    /// while the init process runs, `Ok(Some(code))` once it exited.
    ///
    /// The agent is guest PID 1, so a detached container's init
    /// reparents to us when runc exits — a targeted
    /// `waitpid(pid, WNOHANG)` reaps it and yields the REAL exit code
    /// (`runc state` only ever says "stopped"). The first reap is
    /// cached so every later caller observes the same code. Killed by
    /// signal follows the shell convention: `128 + signum`.
    pub fn poll_exit(&self, name: &str) -> Result<Option<i32>, String> {
        let mut containers = self.containers.lock().unwrap();
        let state = containers
            .get_mut(name)
            .ok_or_else(|| format!("container {name} not found"))?;
        if let Some(code) = state.exit_code {
            return Ok(Some(code));
        }
        let mut status: libc::c_int = 0;
        // SAFETY: init_pid is our reparented child; WNOHANG makes this
        // non-blocking and status is a valid out-pointer.
        let ret = unsafe { libc::waitpid(state.init_pid, &raw mut status, libc::WNOHANG) };
        if ret == 0 {
            return Ok(None);
        }
        if ret != state.init_pid {
            // ECHILD etc. — the init was never (or is no longer) our
            // child. Loud: silently reporting Running-forever would
            // reintroduce the exact bug this exists to fix.
            return Err(format!(
                "waitpid({}) for container {name}: {}",
                state.init_pid,
                std::io::Error::last_os_error()
            ));
        }
        let code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else if libc::WIFSIGNALED(status) {
            128 + libc::WTERMSIG(status)
        } else {
            -1
        };
        state.exit_code = Some(code);
        Ok(Some(code))
    }

    /// Block until a container's init process exits. Returns the real
    /// exit code (internal notes� previously this polled `runc state`
    /// and always returned 0).
    pub fn wait(&self, name: &str) -> Result<i32, String> {
        loop {
            if let Some(code) = self.poll_exit(name)? {
                return Ok(code);
            }
            thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    /// Send a signal to a container's init process.
    pub fn signal(&self, name: &str, signal: i32) -> Result<(), String> {
        {
            let containers = self.containers.lock().unwrap();
            if !containers.contains_key(name) {
                return Err(format!("container {name} not found"));
            }
        }

        let sig_name = match signal {
            1 => "SIGHUP",
            2 => "SIGINT",
            9 => "SIGKILL",
            15 => "SIGTERM",
            _ => return Err(format!("unsupported signal: {signal}")),
        };

        let output = Command::new(runc_path())
            .args(["kill", name, sig_name])
            .output()
            .map_err(|e| format!("runc kill failed: {e}"))?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("runc kill failed: {stderr}"))
        }
    }
}

impl Drop for ContainerManager {
    fn drop(&mut self) {
        let containers = self.containers.get_mut().unwrap();
        for (name, state) in containers.drain() {
            let _ = Command::new(runc_path())
                .args(["kill", &name, "SIGKILL"])
                .output();
            let _ = Command::new(runc_path())
                .args(["delete", "--force", &name])
                .output();
            if let Some(ref ov) = state.overlay {
                cleanup_overlay(ov);
            }
            let _ = fs::remove_dir_all(state.stdout_path.parent().unwrap_or(Path::new("/")));
        }
    }
}
