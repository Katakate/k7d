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
//! `exit(0)`s immediately. So the [`crate::spawner::Child`] k7d asked
//! for is the *jailer*, which is reaped here, and the Firecracker process
//! is an orphan k7d tracks by pid — it cannot be `wait`ed on, only
//! signalled and polled. That is what [`super::FcVm`]'s `Drop` does.

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{FcError, CHROOT_API_SOCKET};
use crate::spawner::Stdio;

/// How long to wait for the API socket after the jailer returns.
const SOCKET_WAIT: Duration = Duration::from_secs(5);

/// `umask` the jailer — and therefore Firecracker — runs under.
///
/// Firecracker binds `firecracker.socket` and `v.sock` with a plain
/// `UnixListener::bind`, which creates them `0777 & ~umask`, and it
/// never `chmod`s them afterwards. Connecting to a Unix socket needs
/// **write** permission on the socket file, so the default `0022` makes
/// them `srwxr-xr-x` — reachable by root and by the jail uid and by
/// nobody else. Under `K7D_PRIVSEP` the process driving that API is uid
/// `k7d`, which is neither.
///
/// `0007` gives `srwxrwx---`: the jail uid, the socket's *group*, and
/// nobody else. The group is `k7d` because the node broker sets the
/// setgid bit on `<root>/run` (`broker::jail`), which is what makes
/// this work for `v.sock` too — that one is bound minutes later, at the
/// VM broker's `PUT /vsock`, when no verb is in flight to re-mode it.
///
/// Unsplit, this is strictly tighter than the default and changes
/// nothing: root reaches the sockets either way.
pub const JAIL_UMASK: u32 = 0o007;

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
    /// Network namespace to run Firecracker in (`--netns`): the one its
    /// TAP was placed in, since it opens the TAP by name (the
    /// per-network netns spec).
    pub netns: Option<&'a Path>,
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

    let mut cmd = crate::spawner::command(args.jailer);
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
        .arg(format!("memory.max={memory_max}"));
    if let Some(ns) = args.netns {
        cmd.arg("--netns").arg(ns);
    }
    cmd.arg("--")
        .arg("--api-sock")
        .arg(CHROOT_API_SOCKET)
        .stdin(Stdio::Null)
        .stdout(Stdio::Null)
        // The log file crosses to the jailer as an `SCM_RIGHTS`
        // descriptor and is closed here, so the only process holding it
        // is the one whose stderr it is. Same file, same fd number, one
        // hop further away.
        .stderr(Stdio::Fd(stderr_file.into()))
        // Without `--daemonize` the jailer asks `getsid(0)` whether it
        // already leads a session and `setsid()`s if not; the spawner
        // does it between fork and exec so the jailer's own call is the
        // no-op it expects (CHALLENGES #214).
        .setsid(true)
        .umask(JAIL_UMASK);

    let fail_pidfile = test_hook_fail_pidfile()?;

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

    // From here on a Firecracker process runs as `uid` inside the
    // chroot, and every `?` below is a path that must kill it first.
    let pid_file = chroot.pid_file(&exec_name);
    let cgroup_dir = PathBuf::from("/sys/fs/cgroup").join(cgroup_rel_path(args.vm_id));
    let mut reaper = SpawnReaper {
        vm_id: args.vm_id,
        uid: args.uid,
        pid_file: pid_file.clone(),
        cgroup_dir: cgroup_dir.clone(),
        pid: None,
        armed: true,
    };

    if fail_pidfile {
        log::error!(
            "fc: {TEST_HOOK_FAIL_PIDFILE} is set — hiding {} to force a post-jailer spawn failure",
            pid_file.display()
        );
        let hidden = pid_file.with_extension("pid.test-hidden");
        std::fs::rename(&pid_file, &hidden).map_err(|e| FcError::Spawn {
            message: format!(
                "{TEST_HOOK_FAIL_PIDFILE}: rename {}: {e}",
                pid_file.display()
            ),
        })?;
    }

    let pid = read_pid_file(&pid_file)?;
    reaper.pid = Some(pid);

    let socket = chroot.api_socket();
    super::api::wait_for_socket(&socket, SOCKET_WAIT)?;

    reaper.armed = false;
    Ok(Spawned { pid, cgroup_dir })
}

/// Test-only hook: when set, `spawn` renames the jailer's pid file
/// away before reading it, so the read fails **after** the jailer has
/// cloned Firecracker — the exact path bug-candidates #51 / #32
/// describe, which no real input reaches on purpose. Honoured only in
/// debug builds (what `cargo test` runs); a release daemon that finds
/// it set refuses every Firecracker create rather than silently
/// running a fault-injection hook in production.
pub const TEST_HOOK_FAIL_PIDFILE: &str = "K7D_FC_TEST_FAIL_PIDFILE";

fn test_hook_fail_pidfile() -> Result<bool, FcError> {
    match std::env::var_os(TEST_HOOK_FAIL_PIDFILE) {
        None => Ok(false),
        Some(v) if v.is_empty() || v == "0" => Ok(false),
        Some(_) if cfg!(debug_assertions) => Ok(true),
        Some(_) => Err(FcError::Config {
            message: format!(
                "{TEST_HOOK_FAIL_PIDFILE} is set in a release build — it is a test-only \
                 fault-injection hook; unset it"
            ),
        }),
    }
}

fn read_pid_file(pid_file: &Path) -> Result<u32, FcError> {
    std::fs::read_to_string(pid_file)
        .map_err(|e| FcError::Spawn {
            message: format!("read jailer pid file {}: {e}", pid_file.display()),
        })?
        .trim()
        .parse::<u32>()
        .map_err(|e| FcError::Spawn {
            message: format!("malformed pid in {}: {e}", pid_file.display()),
        })
}

/// Every pid whose **real** uid is `uid`, from `/proc`.
///
/// The jailer's per-VM uid is exclusive to one Firecracker process by
/// construction, so this is how the reaper finds an orphan whose pid
/// file it could not read — and how it proves, afterwards, that nothing
/// runs as that uid any more.
#[must_use]
pub fn pids_owned_by(uid: u32) -> Vec<u32> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let want = uid.to_string();
    entries
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| {
            std::fs::read_to_string(format!("/proc/{pid}/status")).is_ok_and(|s| {
                s.lines().any(|l| {
                    l.strip_prefix("Uid:")
                        .is_some_and(|rest| rest.split_whitespace().next() == Some(want.as_str()))
                })
            })
        })
        .collect()
}

/// Armed the instant the jailer returns 0; disarmed only when the
/// caller takes the pid to hand to an `FcVm`. On any other exit from
/// [`spawn`] it kills the Firecracker process — by the pid it read, or
/// by scanning `/proc` for the VM's uid when the pid file was the thing
/// that failed — waits for it to disappear, and removes the jailer's
/// cgroup.
///
/// **Why a guard inside `spawn` and not a lease carried in the error:**
/// the reaper is a local of `spawn`, so it drops before `spawn`
/// returns, i.e. before the `UidLease` and `Chroot` that
/// `spawn_unconfigured` holds can unwind. Its `Drop` does not return
/// until either no process runs as the uid (verified from `/proc`, not
/// inferred from `kill` succeeding) or the uid has been retired via
/// [`super::stage::quarantine_uid`]. Either way the lease that drops
/// next is safe to release: it is recycling a uid nothing runs as, or
/// it is releasing a uid the allocator will refuse to hand out. That
/// keeps the lease type out of `FcError` and needs no `ManuallyDrop`
/// choreography in the caller.
struct SpawnReaper<'a> {
    vm_id: &'a str,
    uid: u32,
    pid_file: PathBuf,
    cgroup_dir: PathBuf,
    pid: Option<u32>,
    armed: bool,
}

impl Drop for SpawnReaper<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let pid = self.pid.or_else(|| read_pid_file(&self.pid_file).ok());
        log::error!(
            "fc: spawn of {} failed after the jailer cloned firecracker (uid {}, pid {}) — \
             killing the orphan before its uid, chroot and cgroup are released",
            self.vm_id,
            self.uid,
            pid.map_or_else(|| "unknown".to_string(), |p| p.to_string())
        );
        // Three views of the same process, cheapest first: the pid file,
        // the jailer's cgroup (`cgroup.procs` lists exactly what it
        // cloned), and a `/proc` scan for the uid restricted to this
        // VM's cgroup — a process on this uid *outside* it belongs to
        // someone else and is not ours to kill.
        let mut targets: Vec<u32> = pid.into_iter().collect();
        targets.extend(cgroup_procs(&self.cgroup_dir));
        targets.extend(
            pids_owned_by(self.uid)
                .into_iter()
                .filter(|p| in_vm_cgroup(*p, self.vm_id)),
        );
        targets.sort_unstable();
        targets.dedup();
        for p in &targets {
            super::kill_and_wait(*p);
        }
        // Verified from /proc, not inferred from kill(2) returning 0.
        let survivors = pids_owned_by(self.uid);
        if survivors.is_empty() {
            super::remove_cgroup(&self.cgroup_dir);
        } else {
            log::error!(
                "fc: {} process(es) still run as uid {} after reaping {}: {survivors:?}",
                survivors.len(),
                self.uid,
                self.vm_id
            );
            super::stage::quarantine_uid(self.uid);
        }
    }
}

/// pids listed in `<cgroup_dir>/cgroup.procs`, or none if the cgroup is
/// gone.
fn cgroup_procs(cgroup_dir: &Path) -> Vec<u32> {
    std::fs::read_to_string(cgroup_dir.join("cgroup.procs"))
        .map(|s| s.lines().filter_map(|l| l.trim().parse().ok()).collect())
        .unwrap_or_default()
}

/// Whether `pid`'s cgroup is under this VM's `k7d/<vm_id>/` scope.
fn in_vm_cgroup(pid: u32, vm_id: &str) -> bool {
    let want = format!("k7d/{vm_id}/");
    std::fs::read_to_string(format!("/proc/{pid}/cgroup")).is_ok_and(|s| s.contains(&want))
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
