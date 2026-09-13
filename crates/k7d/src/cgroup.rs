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

/// Threads one live VM is allowed inside a tree's threaded cgroup:
/// vCPUs plus the userspace virtio workers (net RX/TX, block) and a
/// little headroom. Multiplied by `TreeBudget::max_live_vms` to get the
/// tree's `pids.max`.
const THREADS_PER_VM: usize = 64;

/// Floor for a tree's `pids.max`. A budget of one VM still needs room
/// for the daemon's own bookkeeping threads to touch the cgroup.
const MIN_TREE_PIDS: usize = 128;

/// Parent of every tree's helper-process cgroup. Deliberately *not*
/// under `system.slice`: that subtree belongs to systemd, and
/// deliberately not under the daemon's own cgroup either, which
/// `VmCpuCgroup` has already converted into a *domain threaded* root
/// (a threaded root may only have threaded children, and `memory` is a
/// domain-only controller).
const HELPER_ROOT: &str = "/sys/fs/cgroup/k7d-jail";

/// One tree's cgroup jail.
///
/// k7d is a single process, so a tree's VMs are *threads*: cgroup v2
/// charges memory per process, and a threaded subtree may only enable
/// threaded controllers (`cpu`, `cpuset`, `pids`, `perf_event`) — a
/// per-tree `memory.max` over guest RAM is therefore not expressible
/// without a process per tree, which would break the in-process
/// `MAP_PRIVATE` warm fork. What *is* expressible is what this builds:
///
/// ```text
/// <daemon cgroup>/tree-<id>/     threaded: pids.max, the tree's own threads
/// /sys/fs/cgroup/k7d-jail/tree-<id>/  domain: memory.max + pids.max,
///                                     the tree's virtiofsd helpers
/// ```
///
/// Both limits are derived from the tree's [`TreeBudget`], so no new
/// budget fields (and no change to the verified `tree_model.rs`).
#[derive(Debug)]
pub struct TreeCgroup {
    threads: PathBuf,
    parent: PathBuf,
    helpers: PathBuf,
}

impl TreeCgroup {
    /// Create both cgroups for `tree_id`, sized from `budget`.
    /// Returns `Ok(None)` when `K7D_TREE_CGROUP=off`.
    ///
    /// The directory name carries a process-unique suffix: a
    /// `SnapshotTree`'s own `tree_id` is derived from the daemon's PID
    /// and is therefore shared by every single-VM tree in one daemon,
    /// which would make two trees fight over one directory.
    pub fn create(
        tree_id: &str,
        budget: crate::tree_model::TreeBudget,
    ) -> Result<Option<Self>, CgroupError> {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self::create_named(&format!("{tree_id}-{seq}"), budget)
    }

    /// Create both cgroups under an exact `name` (tests pin it).
    fn create_named(
        name: &str,
        budget: crate::tree_model::TreeBudget,
    ) -> Result<Option<Self>, CgroupError> {
        let tree_id = name;
        if !tree_cgroup_enforced()? {
            log::warn!("K7D_TREE_CGROUP=off: tree {tree_id} runs without a cgroup jail");
            return Ok(None);
        }
        let pids_max = budget
            .max_live_vms
            .saturating_mul(THREADS_PER_VM)
            .max(MIN_TREE_PIDS);

        let parent = self_cgroup_dir()?;
        let threads = parent.join(format!("tree-{tree_id}"));
        create_dir(&threads)?;
        let helpers = PathBuf::from(HELPER_ROOT).join(format!("tree-{tree_id}"));
        let cg = Self {
            threads,
            parent,
            helpers,
        };
        // Same ordering constraint as `VmCpuCgroup`: threaded first,
        // then the parent delegates, then the limit file exists.
        write_control_file(&cg.threads.join("cgroup.type"), "threaded")?;
        write_control_file(&cg.parent.join("cgroup.subtree_control"), "+pids")?;
        write_control_file(&cg.threads.join("pids.max"), &pids_max.to_string())?;

        create_dir(Path::new(HELPER_ROOT))?;
        write_control_file(
            &Path::new(HELPER_ROOT).join("cgroup.subtree_control"),
            "+memory +pids",
        )?;
        create_dir(&cg.helpers)?;
        write_control_file(
            &cg.helpers.join("memory.max"),
            &budget.max_live_ram_bytes.to_string(),
        )?;
        write_control_file(&cg.helpers.join("pids.max"), &pids_max.to_string())?;
        log::info!(
            "tree {tree_id} jailed: {} (pids.max={pids_max}), {} (memory.max={})",
            cg.threads.display(),
            cg.helpers.display(),
            budget.max_live_ram_bytes
        );
        Ok(Some(cg))
    }

    /// Move one kernel thread (by TID) into the tree's threaded cgroup.
    /// Fails once the tree is over its `pids.max` — that is the point.
    pub fn add_thread(&self, tid: u32) -> Result<(), CgroupError> {
        write_control_file(&self.threads.join("cgroup.threads"), &tid.to_string())
    }

    /// Move one helper *process* (virtiofsd) into the tree's domain
    /// cgroup, where `memory.max` applies to it.
    pub fn add_process(&self, pid: u32) -> Result<(), CgroupError> {
        write_control_file(&self.helpers.join("cgroup.procs"), &pid.to_string())
    }

    /// Enroll one live VM: its vCPU threads go into the threaded half,
    /// its virtiofsd helpers into the domain half.
    ///
    /// A VM whose vCPU threads have not published their TIDs yet (or
    /// that is not running) contributes nothing — the tree's own state
    /// machine, not this call, decides whether that is legal, and a
    /// suspended node has no threads to jail by definition.
    pub fn add_vm(&self, vm: &crate::vm::Vm) -> Result<(), CgroupError> {
        if let Some(tids) = vm.vcpu_kernel_tids(std::time::Duration::from_secs(5)) {
            for tid in tids {
                self.add_thread(tid)?;
            }
        }
        for pid in vm.virtiofsd_pids() {
            self.add_process(pid)?;
        }
        Ok(())
    }

    /// Directory holding the tree's threads (tests read `pids.max`).
    #[must_use]
    pub fn threads_dir(&self) -> &Path {
        &self.threads
    }

    /// Directory holding the tree's helper processes (tests read
    /// `memory.max`).
    #[must_use]
    pub fn helpers_dir(&self) -> &Path {
        &self.helpers
    }
}

impl Drop for TreeCgroup {
    fn drop(&mut self) {
        move_out_and_remove(&self.threads, &self.parent, "cgroup.threads");
        // Helper processes are children of this daemon; by the time a
        // tree drops, its `VirtiofsdProcess`es have been killed and
        // reaped, so the loop is normally empty.
        move_out_and_remove(&self.helpers, Path::new(HELPER_ROOT), "cgroup.procs");
    }
}

/// Whether per-tree cgroups are enforced (`K7D_TREE_CGROUP`).
fn tree_cgroup_enforced() -> Result<bool, CgroupError> {
    match std::env::var("K7D_TREE_CGROUP") {
        Err(_) => Ok(true),
        Ok(v) => match v.trim() {
            "" | "enforce" => Ok(true),
            "off" => Ok(false),
            other => Err(CgroupError::SelfCgroup(format!(
                "K7D_TREE_CGROUP={other:?} is not one of enforce|off"
            ))),
        },
    }
}

/// `mkdir` one cgroup, treating "already there" as success — a tree id
/// can be re-created after a crash that left the directory behind.
fn create_dir(path: &Path) -> Result<(), CgroupError> {
    match std::fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(source) => Err(CgroupError::CreateDir {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Evacuate `dir` into `parent` through `file` (`cgroup.threads` or
/// `cgroup.procs`) and remove it. A live member makes `rmdir` fail with
/// `EBUSY`, so stragglers move out first.
fn move_out_and_remove(dir: &Path, parent: &Path, file: &str) {
    if let Ok(members) = std::fs::read_to_string(dir.join(file)) {
        for id in members.split_whitespace() {
            if let Err(e) = std::fs::write(parent.join(file), id) {
                log::error!("move {id} back to {}: {e}", parent.display());
            }
        }
    }
    match std::fs::remove_dir(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => log::error!("remove cgroup {}: {e}", dir.display()),
    }
}

/// Remove empty `tree-*` cgroups a crashed previous daemon left behind,
/// in both the threaded parent and the helper root. Same contract as
/// [`clean_stale_vm_cgroups`]: loud logs, never fatal.
pub fn clean_stale_tree_cgroups() {
    let mut roots = Vec::new();
    match self_cgroup_dir() {
        Ok(dir) => roots.push(dir),
        Err(e) => log::error!("clean_stale_tree_cgroups: {e}"),
    }
    roots.push(PathBuf::from(HELPER_ROOT));
    for root in roots {
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let is_tree_dir = path.is_dir()
                && path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("tree-"));
            if is_tree_dir {
                match std::fs::remove_dir(&path) {
                    Ok(()) => log::warn!("removed stale tree cgroup {}", path.display()),
                    Err(e) => log::error!("remove stale tree cgroup {}: {e}", path.display()),
                }
            }
        }
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

    fn test_budget() -> crate::tree_model::TreeBudget {
        crate::tree_model::TreeBudget {
            max_live_vms: 4,
            max_live_ram_bytes: 512 * 1024 * 1024,
            max_disk_bytes: 1024 * 1024 * 1024,
            max_chain_depth: 1,
        }
    }

    /// Both halves of the tree jail carry the budget's limits, accept a
    /// member, and `rmdir` cleanly on drop.
    #[test]
    fn test_tree_cgroup_applies_budget_and_cleans_up() {
        let budget = test_budget();
        let cg = TreeCgroup::create_named("cgtest", budget)
            .expect("create tree cgroup")
            .expect("enforced by default");
        let expected_pids = (budget.max_live_vms * THREADS_PER_VM).max(MIN_TREE_PIDS);
        assert_eq!(
            read_trimmed(&cg.threads_dir().join("pids.max")),
            expected_pids.to_string()
        );
        assert_eq!(
            read_trimmed(&cg.helpers_dir().join("memory.max")),
            budget.max_live_ram_bytes.to_string()
        );

        let stop = Arc::new(AtomicBool::new(false));
        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let handle = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                // SAFETY: gettid has no preconditions.
                tid_tx.send(unsafe { libc::gettid() } as u32).unwrap();
                while !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(10));
                }
            })
        };
        let tid = tid_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        cg.add_thread(tid).expect("move thread into tree cgroup");
        assert!(read_trimmed(&cg.threads_dir().join("cgroup.threads")).contains(&tid.to_string()));

        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();
        let threads_dir = cg.threads_dir().to_path_buf();
        let helpers_dir = cg.helpers_dir().to_path_buf();
        drop(cg);
        assert!(!threads_dir.exists(), "{threads_dir:?} should be gone");
        assert!(!helpers_dir.exists(), "{helpers_dir:?} should be gone");
    }

    #[test]
    fn test_tree_cgroup_mode_is_total_and_loud() {
        let key = "K7D_TREE_CGROUP";
        let prev = std::env::var(key).ok();
        std::env::set_var(key, "off");
        assert!(TreeCgroup::create("cgoff", test_budget())
            .expect("off is a valid mode")
            .is_none());
        std::env::set_var(key, "sometimes");
        assert!(
            TreeCgroup::create("cgbad", test_budget()).is_err(),
            "unknown mode must fail loudly"
        );
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    /// An empty leftover from a crashed daemon is reaped at startup.
    #[test]
    fn test_clean_stale_tree_cgroups() {
        let stale = self_cgroup_dir().unwrap().join("tree-cgstale");
        std::fs::create_dir(&stale).expect("create stale tree cgroup");
        clean_stale_tree_cgroups();
        assert!(!stale.exists(), "{stale:?} should have been reaped");
    }

    fn read_trimmed(path: &Path) -> String {
        std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
            .trim()
            .to_string()
    }
}
