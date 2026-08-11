//! Host-side CPU capping for VM vCPU threads.
//!
//! The pod's CFS quota must constrain the **vCPU threads**, which live
//! in the k7d daemon process — containerd places the *shim* elsewhere
//! (`system.slice/k3s.service` on k3s), so constraining the shim
//! constrains nothing. cgroup v2 forbids moving a single thread into a
//! foreign domain cgroup (all threads of a process must stay within one
//! threaded domain), so the pod's own `kubepods-…` slice cannot host
//! the vCPU threads either. Instead each capped VM gets a dedicated
//! **threaded** sub-cgroup under the daemon's own cgroup:
//!
//! ```text
//! /sys/fs/cgroup/system.slice/k7d.service/          (domain threaded)
//! └── vm-<vm_id>/                                   (threaded)
//!     ├── cgroup.type     = threaded
//!     ├── cgroup.threads  = <vCPU kernel TID>
//!     └── cpu.max         = "<quota> <period>"      (pod's CFS quota)
//! ```
//!
//! Writing `threaded` to the child's `cgroup.type` converts the daemon
//! cgroup into a *domain threaded* root, after which the `cpu`
//! controller (a threaded controller, exempt from the no-internal-
//! process constraint) can be enabled in its `cgroup.subtree_control`
//! and individual TIDs can be written to the child's `cgroup.threads`.

use std::path::{Path, PathBuf};

use thiserror::Error;

/// Failures while wiring a VM's CPU cgroup. Every variant carries the
/// path involved — cgroupfs errors are useless without it.
#[derive(Debug, Error)]
pub enum CgroupError {
    /// `/proc/self/cgroup` unreadable or not in the `0::<path>` v2 form.
    #[error("resolve own cgroup from /proc/self/cgroup: {0}")]
    SelfCgroup(String),
    /// Creating the per-VM cgroup directory failed.
    #[error("create cgroup dir {path}: {source}")]
    CreateDir {
        /// Directory we tried to create.
        path: PathBuf,
        /// Underlying IO error.
        source: std::io::Error,
    },
    /// Writing a cgroupfs control file failed.
    #[error("write {value:?} to {path}: {source}")]
    Write {
        /// Control file we tried to write.
        path: PathBuf,
        /// Value we tried to write.
        value: String,
        /// Underlying IO error.
        source: std::io::Error,
    },
}

/// One VM's threaded CPU sub-cgroup. Dropping it moves any remaining
/// threads back to the parent and removes the directory — hold it in
/// the VM's registry entry *after* the `Vm` itself so the vCPU thread
/// is already joined when the removal runs.
#[derive(Debug)]
pub struct VmCpuCgroup {
    dir: PathBuf,
    parent: PathBuf,
}

impl VmCpuCgroup {
    /// Create `vm-{vm_id}` under the calling process's own cgroup,
    /// mark it threaded, enable the `cpu` controller on the parent,
    /// and set `cpu.max` to `"{quota_us} {period_us}"`.
    pub fn create(vm_id: &str, quota_us: u64, period_us: u64) -> Result<Self, CgroupError> {
        let parent = self_cgroup_dir()?;
        let dir = parent.join(format!("vm-{vm_id}"));
        std::fs::create_dir(&dir).map_err(|source| CgroupError::CreateDir {
            path: dir.clone(),
            source,
        })?;
        let cg = Self { dir, parent };
        // Order matters: the child must be threaded before `+cpu` can
        // be enabled on a parent that has member processes (the
        // internal-process constraint is waived only for threaded
        // controllers in threaded subtrees), and `cpu.max` only exists
        // in the child once the parent delegates the controller.
        write_control_file(&cg.dir.join("cgroup.type"), "threaded")?;
        write_control_file(&cg.parent.join("cgroup.subtree_control"), "+cpu")?;
        write_control_file(&cg.dir.join("cpu.max"), &format!("{quota_us} {period_us}"))?;
        Ok(cg)
    }

    /// Move one kernel thread (by TID) into this cgroup.
    pub fn add_thread(&self, tid: u32) -> Result<(), CgroupError> {
        write_control_file(&self.dir.join("cgroup.threads"), &tid.to_string())
    }

    /// This cgroup's directory (tests read `cpu.max` / `cpu.stat`).
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

/// Write one cgroupfs control file, wrapping failures with the path
/// and value (cgroupfs errors are useless without them).
fn write_control_file(path: &Path, value: &str) -> Result<(), CgroupError> {
    std::fs::write(path, value).map_err(|source| CgroupError::Write {
        path: path.to_path_buf(),
        value: value.to_string(),
        source,
    })
}

impl Drop for VmCpuCgroup {
    fn drop(&mut self) {
        // A live thread in the cgroup makes rmdir fail with EBUSY —
        // move stragglers back to the parent first. Normally the vCPU
        // thread has already exited (the `Vm` drops before this does),
        // so the loop is empty.
        if let Ok(threads) = std::fs::read_to_string(self.dir.join("cgroup.threads")) {
            for tid in threads.split_whitespace() {
                if let Err(e) = std::fs::write(self.parent.join("cgroup.threads"), tid) {
                    log::error!("move thread {tid} back to {}: {e}", self.parent.display());
                }
            }
        }
        match std::fs::remove_dir(&self.dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => log::error!("remove cgroup {}: {e}", self.dir.display()),
        }
    }
}

/// Remove empty `vm-*` cgroups a crashed previous daemon left under
/// this process's cgroup. Called once at daemon startup; failures are
/// logged loudly but never stop the daemon (a stale empty directory is
/// harmless, a wedged startup is not).
pub fn clean_stale_vm_cgroups() {
    let own = match self_cgroup_dir() {
        Ok(dir) => dir,
        Err(e) => {
            log::error!("clean_stale_vm_cgroups: {e}");
            return;
        }
    };
    let Ok(entries) = std::fs::read_dir(&own) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_stale_vm_dir = path.is_dir()
            && path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("vm-"));
        if is_stale_vm_dir {
            match std::fs::remove_dir(&path) {
                Ok(()) => log::warn!("removed stale VM cgroup {}", path.display()),
                Err(e) => log::error!("remove stale VM cgroup {}: {e}", path.display()),
            }
        }
    }
}

/// Resolve the calling process's cgroup v2 directory from
/// `/proc/self/cgroup` (the single `0::<path>` line on a v2 host).
fn self_cgroup_dir() -> Result<PathBuf, CgroupError> {
    let content = std::fs::read_to_string("/proc/self/cgroup")
        .map_err(|e| CgroupError::SelfCgroup(e.to_string()))?;
    let rel = content
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| {
            CgroupError::SelfCgroup(format!("no cgroup v2 (`0::`) entry in {content:?}"))
        })?;
    Ok(PathBuf::from("/sys/fs/cgroup").join(rel.trim().trim_start_matches('/')))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    #[test]
    fn test_self_cgroup_dir_resolves() {
        let dir = self_cgroup_dir().expect("cgroup v2 path");
        assert!(dir.starts_with("/sys/fs/cgroup"), "{dir:?}");
        assert!(dir.exists(), "{dir:?} should exist");
    }

    /// End-to-end on the test process's own cgroup: cap a spawned
    /// busy-loop thread at 20% of a core and verify `cpu.stat` in the
    /// VM cgroup accounts (and bounds) its usage.
    #[test]
    fn test_cpu_cgroup_caps_thread() {
        let cg = VmCpuCgroup::create("cgtest", 20_000, 100_000).expect("create cgroup");
        assert_eq!(
            std::fs::read_to_string(cg.dir().join("cpu.max"))
                .unwrap()
                .trim(),
            "20000 100000"
        );

        let stop = Arc::new(AtomicBool::new(false));
        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let handle = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                // SAFETY: gettid has no preconditions.
                tid_tx.send(unsafe { libc::gettid() } as u32).unwrap();
                while !stop.load(Ordering::Relaxed) {
                    std::hint::spin_loop();
                }
            })
        };
        let tid = tid_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        cg.add_thread(tid).expect("move thread into cgroup");

        let usage = |cg: &VmCpuCgroup| -> u64 {
            std::fs::read_to_string(cg.dir().join("cpu.stat"))
                .unwrap()
                .lines()
                .find_map(|l| l.strip_prefix("usage_usec "))
                .unwrap()
                .trim()
                .parse()
                .unwrap()
        };
        let start_usage = usage(&cg);
        let start = Instant::now();
        std::thread::sleep(Duration::from_secs(3));
        let used = usage(&cg) - start_usage;
        let elapsed = start.elapsed().as_micros() as u64;
        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();

        let util = used as f64 / elapsed as f64;
        assert!(
            util <= 0.25,
            "busy thread used {util:.2} of a core, cap was 0.20"
        );
        assert!(
            util >= 0.10,
            "busy thread used only {util:.2} of a core — was it even running?"
        );
        drop(cg); // must rmdir cleanly with the thread already joined
    }
}
