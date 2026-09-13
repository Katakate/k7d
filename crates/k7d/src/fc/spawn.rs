//! Spawning Firecracker under the stock jailer.
//!
//! The command line is the documented one, verbatim except for one deviation
//! named below:
//!
//! ```text
//! jailer --id <vm_id> --exec-file <fc-binary> \
//!        --uid u --gid u --chroot-base-dir <base> \
//!        --new-pid-ns --cgroup-version 2 --parent-cgroup k7d/<vm_id> \
//!        --cgroup cpu.max=<quota> <period> \
//!        --cgroup memory.max=<bytes> \
//!        -- --api-sock /run/firecracker.socket
//! ```
//!
//! * No `--daemonize`: k7d wants the jailer in its own session and its
//!   stdio, not `/dev/null`.
//! * No `--netns`: TAPs are made in the root/cluster netns by
//!   `network.rs` and moved by name.
//! * The parent spec's `--seccomp-level default` is **not** passed: the
//!   flag was removed from Firecracker long before the pinned v1.16.1
//!   (`--no-seccomp` / `--seccomp-filter` replaced it) and the default
//!   filters are on unless one of those is given. Passing it would be
//!   an immediate exit-1, not a stricter jail.
//!
//! ## The jailer is not the process k7d supervises
//!
//! With `--new-pid-ns` the jailer `clone(CLONE_NEWPID)`s, writes the
//! child's (host-namespace) pid to `<chroot>/<exec-name>.pid`, and
//! `exit(0)`s immediately. So the [`std::process::Child`] k7d spawned
//! is the *jailer*, which is reaped here, and the Firecracker process
//! is an orphan k7d tracks by pid — it cannot be `wait`ed on, only
//! signalled and polled. That is what [`super::FcVm`]'s `Drop` does.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use super::{FcError, CHROOT_API_SOCKET};

/// How long to wait for the API socket after the jailer returns.
const SOCKET_WAIT: Duration = Duration::from_secs(5);

/// Chroot-relative name of the file the jailer's (and then
/// Firecracker's) stderr is written to. [`crate::guest::Guest::serial_output`]
/// dumps this file for a live Firecracker VM.
pub const STDERR_FILE: &str = "stderr.log";

/// Host RAM a Firecracker process needs on top of the guest's, for the
/// VMM's own heap, the KVM structures, and the vsock buffers.
///
/// Measured on the bare-metal node with the busybox guest: a 512 MiB VM's
/// Firecracker RSS settles at ~530 MiB shortly after the agent answers
/// `ping`, i.e. ~18 MiB of VMM on top of touched guest pages. 128 MiB
/// is that with room for a guest that touches all of its RAM plus the
/// page cache of the staged kernel; a `memory.max` too tight would OOM
/// the VMM rather than the guest, which is the confusing failure.
pub const MEMORY_OVERHEAD_BYTES: u64 = 128 * 1024 * 1024;

/// CFS period used when the caller set no CPU cap. `cpu.max = "max
/// <period>"` is cgroup v2 for "uncapped" — the cgroup still exists so
/// every FC VM has one place its limits are read from.
const DEFAULT_CPU_PERIOD_US: u64 = 100_000;

/// Everything the jailer needs for one microVM.
#[derive(Debug)]
pub struct JailerArgs<'a> {
    /// VM identity — the jailer's `--id` and the chroot leaf.
    pub vm_id: &'a str,
    /// Firecracker binary the jailer execs (and copies into the chroot).
    pub exec_file: &'a Path,
    /// Jailer binary.
    pub jailer: &'a Path,
    /// Chroot base dir (`--chroot-base-dir`).
    pub chroot_base: &'a Path,
    /// uid == gid for this VM.
    pub uid: u32,
    /// Guest RAM in MiB — `memory.max` is this plus
    /// [`MEMORY_OVERHEAD_BYTES`].
    pub memory_mb: u64,
    /// Pod CFS quota in µs, when the caller set one.
    pub cpu_quota_us: Option<u64>,
    /// Pod CFS period in µs, paired with `cpu_quota_us`.
    pub cpu_period_us: Option<u64>,
}

/// Result of a successful spawn.
#[derive(Debug)]
pub struct Spawned {
    /// Host pid of the Firecracker process (pid 1 in its own pid ns).
    pub pid: u32,
    /// cgroup v2 directory the jailer put that process in.
    pub cgroup_dir: PathBuf,
}

/// The cgroup v2 path (relative to the unified root) the jailer creates:
/// `<parent-cgroup>/<id>`.
#[must_use]
pub fn cgroup_rel_path(vm_id: &str) -> String {
    format!("k7d/{vm_id}/{vm_id}")
}

/// Run the jailer, reap it, and return the Firecracker pid once its API
/// socket accepts.
pub fn spawn(args: &JailerArgs<'_>, chroot: &super::stage::Chroot) -> Result<Spawned, FcError> {
    let exec_name = exec_file_name(args.exec_file)?;
    let (quota, period) = match (args.cpu_quota_us, args.cpu_period_us) {
        (Some(q), Some(p)) if q > 0 && p > 0 => (q.to_string(), p),
        (Some(q), p) => {
            return Err(FcError::Config {
                message: format!("invalid CPU cap: quota={q:?} period={p:?} (both must be > 0)"),
            })
        }
        (None, _) => ("max".to_string(), DEFAULT_CPU_PERIOD_US),
    };
    let memory_max = memory_max_bytes(args.memory_mb);

    // The jailer's stderr goes to a file, not a pipe. `--new-pid-ns`
    // makes the jailer exit as soon as it has cloned Firecracker, but
    // Firecracker inherits its stderr, so the pipe's write end stays
    // open for the life of the VM: `wait_with_output` would block until
    // the guest shut down (CHALLENGES #214).
    //
    // For the same reason the file lives *inside* the chroot: the fd
    // outlives the jailer, and a jailed process holding a writable
    // descriptor to a host path outside its own root is an escape
    // surface the jail exists to close.
    let stderr_path = chroot.root().join(STDERR_FILE);
    let stderr_file = std::fs::File::create(&stderr_path).map_err(|e| FcError::Spawn {
        message: format!("create {}: {e}", stderr_path.display()),
    })?;

    let mut cmd = Command::new(args.jailer);
    cmd.arg("--id")
        .arg(args.vm_id)
        .arg("--exec-file")
        .arg(args.exec_file)
        .arg("--uid")
        .arg(args.uid.to_string())
        .arg("--gid")
        .arg(args.uid.to_string())
        .arg("--chroot-base-dir")
        .arg(args.chroot_base)
        .arg("--new-pid-ns")
        .arg("--cgroup-version")
        .arg("2")
        .arg("--parent-cgroup")
        .arg(format!("k7d/{}", args.vm_id))
        .arg("--cgroup")
        .arg(format!("cpu.max={quota} {period}"))
        .arg("--cgroup")
        .arg(format!("memory.max={memory_max}"))
        .arg("--")
        .arg("--api-sock")
        .arg(CHROOT_API_SOCKET)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr_file));

    let mut child = cmd.spawn().map_err(|e| FcError::Spawn {
        message: format!("spawn {}: {e}", args.jailer.display()),
    })?;
    let status = child.wait().map_err(|e| FcError::Spawn {
        message: format!("wait for jailer: {e}"),
    })?;
    if !status.success() {
        return Err(FcError::Spawn {
            message: format!(
                "jailer exited {status}: {}",
                std::fs::read_to_string(&stderr_path)
                    .unwrap_or_default()
                    .trim()
            ),
        });
    }

    let pid_file = chroot.pid_file(&exec_name);
    let pid = std::fs::read_to_string(&pid_file)
        .map_err(|e| FcError::Spawn {
            message: format!("read jailer pid file {}: {e}", pid_file.display()),
        })?
        .trim()
        .parse::<u32>()
        .map_err(|e| FcError::Spawn {
            message: format!("malformed pid in {}: {e}", pid_file.display()),
        })?;

    let socket = chroot.api_socket();
    if let Err(e) = super::api::wait_for_socket(&socket, SOCKET_WAIT) {
        // The process is already running under an unprivileged uid in
        // its own pid ns; leaving it behind because its socket was slow
        // would leak a VM with no handle on it.
        super::kill_and_wait(pid);
        return Err(e);
    }

    Ok(Spawned {
        pid,
        cgroup_dir: PathBuf::from("/sys/fs/cgroup").join(cgroup_rel_path(args.vm_id)),
    })
}

/// The `memory.max` written for a guest of `memory_mb`: its RAM plus
/// [`MEMORY_OVERHEAD_BYTES`] for the VMM itself.
#[must_use]
pub fn memory_max_bytes(memory_mb: u64) -> u64 {
    memory_mb
        .saturating_mul(1024 * 1024)
        .saturating_add(MEMORY_OVERHEAD_BYTES)
}

/// File name the jailer derives the chroot level (and the pid file)
/// from.
pub fn exec_file_name(exec_file: &Path) -> Result<String, FcError> {
    exec_file
        .file_name()
        .and_then(|n| n.to_str())
        .map(ToString::to_string)
        .ok_or_else(|| FcError::Config {
            message: format!("--exec-file {} has no file name", exec_file.display()),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_path_is_under_the_vm_scope() {
        assert_eq!(cgroup_rel_path("vm-7-0"), "k7d/vm-7-0/vm-7-0");
    }

    #[test]
    fn exec_file_name_is_loud_without_one() {
        assert_eq!(
            exec_file_name(Path::new("/usr/local/bin/firecracker")).unwrap(),
            "firecracker"
        );
        assert!(exec_file_name(Path::new("/")).is_err());
    }

    #[test]
    fn memory_max_covers_guest_ram_plus_overhead() {
        assert_eq!(memory_max_bytes(512), 512 * 1024 * 1024 + 128 * 1024 * 1024);
        // A `memory.max` at or below the guest's RAM would OOM-kill the
        // VMM rather than the workload, so the headroom is the point.
        assert!(memory_max_bytes(0) > 0);
        assert!(memory_max_bytes(u64::MAX) > u64::MAX / 2);
    }
}
