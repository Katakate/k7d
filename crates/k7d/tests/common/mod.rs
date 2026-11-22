//! Shared integration-test teardown for k7.
//!
//! Each integration-test binary (`test_volumes`, `test_cni`,
//! `test_shim`, …) is a separate crate, so this module is pulled in
//! with `mod common;` and only some helpers are used per binary —
//! hence the crate-level `dead_code` allowance.
//!
//! **Teardown is best-effort, NOT fail-loud.** kubectl / pkill /
//! umount failures are swallowed (optionally surfaced via
//! `eprintln!`) so a test's own cleanup can never mask the test
//! result. This is the test-only counterpart to the fail-loud
//! product wiring in `crates/k7d/src/volumes.rs` and the shim's
//! `Create` path — do **not** copy this
//! best-effort style into product code.
#![allow(dead_code)]

pub mod coreos;
pub mod ml_platform;
pub mod tree_fork_budget;
pub mod ubuntu;
pub mod ubuntu_helm;
pub mod ubuntu_k3s;
pub mod warp;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// A snapshot-tree root on the node's reflink XFS, removed on Drop.
///
/// Incremental keyframes `FICLONE` their ancestor's
/// `memory.bin`, which needs source and destination on one
/// reflink-capable filesystem. The node's root FS — where
/// `tempfile::tempdir()` lands — is ext4 and cannot clone at all, so a
/// test that means to exercise the incremental path has to ask for the
/// XFS explicitly, exactly as the deploy does.
///
/// Fails loud rather than silently falling back to `/tmp`: a test that
/// quietly ran the full-dump path would assert nothing about the
/// feature it is named after.
pub struct ReflinkTreeRoot {
    path: PathBuf,
}

impl ReflinkTreeRoot {
    /// Provision (or reuse) the XFS and mint an empty tree root under it.
    ///
    /// Deliberately goes to `DISKS_DIR/trees` rather than following
    /// `/var/lib/k7d/trees`: on a node whose old ext4 tree root still
    /// has trees in it, `ensure_reflink_tree_root` refuses to move them
    /// and hands back the ext4 path. That is the right call for the
    /// operator's data and the wrong one for a test that exists to
    /// exercise `FICLONE`.
    pub fn new(tag: &str) -> Self {
        k7d::disks::ensure_loopback_xfs(
            Path::new(k7d::disks::DISKS_IMAGE),
            Path::new(k7d::disks::DISKS_DIR),
            k7d::disks::DISKS_IMAGE_SIZE,
        )
        .unwrap_or_else(|e| {
            panic!(
                "the snapshot tree needs a reflink-capable tree root on this node, and \
                 provisioning the XFS loopback failed: {e}"
            )
        });
        let trees = Path::new(k7d::disks::DISKS_DIR).join(k7d::disks::TREES_SUBDIR);
        std::fs::create_dir_all(&trees).expect("create trees dir on the XFS");
        let path = trees.join(format!("t-{tag}-{}-{}", std::process::id(), run_id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create reflink tree root");
        k7d::disks::assert_reflink_capable(&path)
            .expect("the tree root we just made on the XFS must be reflink-capable");
        mark_test_tree_dir(&path);
        Self { path }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ReflinkTreeRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Bytes in use on the filesystem holding `path`.
///
/// This, sampled either side of an operation, is the only honest way to
/// price a reflink: a cloned file reports its whole logical length from
/// `stat`, and `du` re-counts a shared extent in full on every
/// invocation that sees it. Neither says whether the extents were
/// actually shared. Free space does.
#[must_use]
pub fn fs_used_bytes(path: &Path) -> u64 {
    let mut buf: libc::statvfs = unsafe { std::mem::zeroed() };
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).expect("path has no NUL");
    // SAFETY: `c` outlives the call and `buf` is a valid, owned statvfs.
    let rc = unsafe { libc::statvfs(c.as_ptr(), &raw mut buf) };
    assert!(rc == 0, "statvfs({}) failed", path.display());
    let frsize = buf.f_frsize;
    frsize * (buf.f_blocks - buf.f_bfree)
}

/// Bytes free (available to an unprivileged caller) on the filesystem
/// holding `path`. Same `statvfs` as [`fs_used_bytes`].
#[must_use]
pub fn fs_free_bytes(path: &Path) -> u64 {
    let mut buf: libc::statvfs = unsafe { std::mem::zeroed() };
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).expect("path has no NUL");
    // SAFETY: `c` outlives the call and `buf` is a valid, owned statvfs.
    let rc = unsafe { libc::statvfs(c.as_ptr(), &raw mut buf) };
    assert!(rc == 0, "statvfs({}) failed", path.display());
    buf.f_frsize * buf.f_bavail
}

/// Idempotent, best-effort cleanup of host-side k7 runtime leaks left
/// by a prior integration test: orphan `virtiofsd` / shim processes,
/// stale `/tmp/k7d-shim-*` tmpfs/bind mounts, and the scratch socket
/// dirs under `/tmp`.
///
/// Safe to call at the start of each `ensure_shim_installed()` and
/// between tests: the full suite runs single-threaded
/// (`--test-threads=1`) and cargo runs test binaries sequentially, so
/// there is no concurrent shim/sandbox to disturb. Every failure is
/// ignored on purpose (see module docs).
pub fn cleanup_k7_runtime_leaks() {
    // Orphan virtiofsd children: a multi-share pod spawns up to three
    // (`k7fs`, `k7fs1`, `k7fs2`) per sandbox and they are not always
    // reparented/reaped cleanly when a sandbox crashes mid-start.
    let _ = Command::new("pkill").args(["-9", "virtiofsd"]).status();
    // Stale shim processes (also frees vsock CIDs held by dead VMs).
    let _ = Command::new("pkill")
        .args(["-9", "-f", "containerd-shim-k7-v1"])
        .status();

    // Lazy-unmount leftover hostPath / shim binds BEFORE restarting
    // k7d. ProtectSystem=strict clones the host mount table into the
    // service ns; ~10k leaked nested `/var/lib/k7d/pods/...` binds
    // make systemd-executor spin and never exec (CHALLENGES #244).
    // Reverse-length order so nested mounts detach first. `umount -l`
    // so a still-busy mount detaches.
    let _ = Command::new("sh")
        .arg("-c")
        .arg(
            "findmnt -rn -o TARGET 2>/dev/null | grep -E '^(/tmp/k7d|/var/lib/k7d/pods/)' \
             | awk '{print length, $0}' | sort -nr | while read -r _ t; do \
                 umount -l \"$t\" 2>/dev/null; done; \
             rm -rf /tmp/k7d-shim-* /tmp/k7d-virtiofs-* /tmp/k7d-fork-* \
                    /tmp/k7d-vol-* /tmp/k7d-voltest-* /tmp/k7d-test-* 2>/dev/null",
        )
        .status();

    let _ = Command::new("/usr/local/libexec/k7d-mount-disks").status();

    // Restart after the mount table is sane so leaked VMs drop cleanly.
    let _ = Command::new("systemctl")
        .args(["try-restart", "k7d"])
        .status();

    // `/tmp/k7d-fork-*` (fork/snapshot memory files, ~1.8 GB per
    // SIGKILLed daemon) is safe to sweep here: the daemon was just
    // restarted above, so no live VM maps them — leaving them behind
    // fills the 32 GB tmpfs after a few dozen aborted runs and every
    // later snapshot fails with ENOSPC (collateral).

    // Give kubelet/containerd a beat to observe the teardown before
    // the next pod is created.
    std::thread::sleep(Duration::from_millis(1500));

    // Once per test binary: reap stranded host leftovers and
    // age-gated cluster resources from crashed prior runs. After the
    // daemon restart above there are no live VMs on this node, so
    // leftover bridges / TAPs / disk images are safe to collect.
    maybe_hygiene_once();
}

/// RAII guard returned by each test's `ensure_shim_installed()`.
///
/// Runs [`cleanup_k7_runtime_leaks`] again when it drops — including
/// on a test panic, since the std test harness unwinds and drops
/// locals — so a failing test reclaims its orphan virtiofsd/shim
/// processes and stale mounts before the next test runs instead of
/// poisoning it (the cascade seen in where the 7th volume
/// pod's crash took the 8th and 9th down with it).
#[must_use = "bind it (e.g. `let _g = ensure_shim_installed();`) so cleanup runs at test end"]
pub struct LeakGuard;

impl Drop for LeakGuard {
    fn drop(&mut self) {
        cleanup_k7_runtime_leaks();
    }
}

/// Ensure the shim binary is built (release), installed, containerd config
/// has the k7 runtime, RuntimeClass exists, and k3s is running.
/// This is idempotent — safe to call before every kubectl test.
pub fn ensure_shim_installed() -> LeakGuard {
    // Best-effort teardown of orphan
    // virtiofsd/shim processes and stale /tmp/k7d-shim mounts left by
    // earlier tests/binaries before we (re)install the shim.
    cleanup_k7_runtime_leaks();

    let shim_src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("target/release/containerd-shim-k7-v1");

    // Always build: cargo no-ops in ~a second when the binary is
    // fresh, and skipping the build when `shim_src` merely *exists*
    // deploys a stale shim after source edits (bit us twice — the
    // crash-recovery hooks were first tested against a stale
    // binary; see `ensure_k7d_daemon_running` for the
    // first time).
    let status = Command::new("cargo")
        .args(["build", "--release", "-p", "containerd-shim-k7-v1"])
        .status()
        .expect("cargo build should run");
    assert!(status.success(), "shim build failed");

    let installed = Path::new("/usr/local/bin/containerd-shim-k7-v1");
    let need_install = if installed.exists() {
        let src_meta = std::fs::metadata(&shim_src).unwrap();
        let dst_meta = std::fs::metadata(installed).unwrap();
        src_meta.len() != dst_meta.len()
            || src_meta.modified().unwrap() > dst_meta.modified().unwrap()
    } else {
        true
    };

    if need_install {
        eprintln!("  installing shim to /usr/local/bin/");
        let _ = Command::new("pkill")
            .args(["-9", "-f", "containerd-shim-k7-v1"])
            .status();
        std::thread::sleep(Duration::from_millis(500));
        // Unlink first: copying over a binary some straggler shim still
        // executes fails with ETXTBSY; a fresh inode never does.
        let _ = std::fs::remove_file(installed);
        std::fs::copy(&shim_src, installed).expect("copy shim binary");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(installed, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let _ = Command::new("systemctl").args(["restart", "k3s"]).status();
        wait_for_k3s_ready();
    }

    let rc_check = Command::new("kubectl")
        .args(["get", "runtimeclass", "k7"])
        .output()
        .expect("kubectl should run");
    if !rc_check.status.success() {
        eprintln!("  creating RuntimeClass k7");
        let _ = Command::new("kubectl")
            .args(["apply", "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child.stdin.as_mut().unwrap().write_all(
                    b"apiVersion: node.k8s.io/v1\nkind: RuntimeClass\nmetadata:\n  name: k7\nhandler: k7\n",
                ).unwrap();
                child.wait()
            })
            .expect("create RuntimeClass");
    }

    // The shim's sandbox Create now requires a running k7d
    // daemon (it owns the VMs); install and start it.
    ensure_k7d_daemon_running();

    LeakGuard
}

/// The directory per-VM cgroups are created in.
///
/// Un-split that is the service cgroup itself, since the daemon makes
/// them beside its own process. With privilege separation on it is the delegated
/// `vm/` subtree: the VM broker has no capabilities and can only write
/// in a directory systemd handed to uid `k7d`, so `vm-<id>` moved one
/// level down. Resolved by looking rather than by reading
/// `K7D_PRIVSEP`, because what a test wants to know is where the
/// *running* daemon puts them.
pub fn vm_cgroup_root() -> PathBuf {
    let out = Command::new("systemctl")
        .args(["show", "-p", "MainPID", "--value", "k7d"])
        .output()
        .expect("systemctl show k7d");
    let pid: u32 = String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("k7d MainPID");
    assert!(pid > 0, "k7d.service has no main PID — is it running?");
    let cg = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).expect("read k7d cgroup");
    let rel = cg
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .expect("cgroup v2 entry")
        .trim();
    let main = PathBuf::from("/sys/fs/cgroup").join(rel.trim_start_matches('/'));
    // MainPID is the node broker, which vacates the service cgroup into
    // `node/` so the controllers can be enabled for the delegated
    // sibling (cgroup v2's no-internal-process rule). So the service
    // cgroup is its parent, not its own directory.
    let service = if main.file_name().and_then(|n| n.to_str()) == Some(k7d::broker::NODE_SUBDIR) {
        main.parent().expect("node/ has a parent").to_path_buf()
    } else {
        main
    };
    let delegated = service.join(k7d::broker::DELEGATED_SUBDIR);
    if delegated.is_dir() {
        delegated
    } else {
        service
    }
}

/// Install `/usr/local/bin/k7d`, register it as the
/// `k7d.service` systemd unit, and make sure it is running with its
/// control socket up. Idempotent — kubectl-driven integration tests
/// call this from `ensure_shim_installed()` because the shim's
/// sandbox `Create` now requires a live daemon.
pub fn ensure_k7d_daemon_running() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("target/release/k7d");

    // Always build: cargo no-ops in ~a second when the binary is fresh,
    // and skipping the build when `src` merely *exists* deploys a stale
    // daemon after source edits (bit us once — a network fix tested
    // against the previous binary).
    let status = Command::new("cargo")
        .args(["build", "--release", "-p", "k7d", "--bin", "k7d"])
        .status()
        .expect("cargo build should run");
    assert!(status.success(), "k7d build failed");

    let installed = Path::new("/usr/local/bin/k7d");
    let need_install = if installed.exists() {
        let src_meta = std::fs::metadata(&src).unwrap();
        let dst_meta = std::fs::metadata(installed).unwrap();
        src_meta.len() != dst_meta.len()
            || src_meta.modified().unwrap() > dst_meta.modified().unwrap()
    } else {
        true
    };
    if need_install {
        eprintln!("  installing k7d to /usr/local/bin/");
        // Copy via a temp file + rename so a running daemon's text
        // isn't overwritten in place (ETXTBSY).
        let tmp = installed.with_extension("new");
        std::fs::copy(&src, &tmp).expect("copy k7d binary");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::fs::rename(&tmp, installed).expect("install k7d binary");
    }

    let guest_refreshed = install_workspace_guest();
    install_k7d_mount_disks();
    provision_vm_broker_identity();
    // RequiresMountsFor=/var/lib/k7d/disks waits on a host mount unit.
    // Mount in the host ns *before* systemd evaluates that, so the
    // first restart on a node without fstab does not hang.
    let mount_status = Command::new("/usr/local/libexec/k7d-mount-disks")
        .status()
        .expect("run k7d-mount-disks");
    assert!(
        mount_status.success(),
        "k7d-mount-disks failed: {mount_status}"
    );

    let unit = Path::new("/etc/systemd/system/k7d.service");
    let unit_body = k7d_service_unit_body(
        Path::new("/usr/local/bin/k7d"),
        &share_guest_paths().0,
        &share_guest_paths().1,
    );
    let need_unit = match std::fs::read_to_string(unit) {
        Ok(existing) => existing != unit_body,
        Err(_) => true,
    };
    if need_unit {
        eprintln!("  writing k7d.service systemd unit");
        std::fs::write(unit, &unit_body).expect("write k7d.service");
        let _ = Command::new("systemctl").args(["daemon-reload"]).status();
    }
    if need_unit || guest_refreshed {
        // Must take effect even when the binary was already current —
        // otherwise a long-lived daemon keeps booting the guest it
        // resolved at startup, which is the whole failure mode here.
        let _ = Command::new("systemctl").args(["restart", "k7d"]).status();
    }

    if need_install {
        let _ = Command::new("systemctl")
            .args(["enable", "--now", "k7d"])
            .status();
        let _ = Command::new("systemctl").args(["restart", "k7d"]).status();
    } else {
        // Idempotent when already active.
        let _ = Command::new("systemctl")
            .args(["enable", "--now", "k7d"])
            .status();
    }

    // systemd merges drop-ins over the unit, so the file just written
    // is not necessarily what the daemon was started with. Ask systemd
    // what it actually passed: a stray
    // /etc/systemd/system/k7d.service.d/*.conf pinning K7D_KERNEL
    // elsewhere would otherwise show up much later as a pod booting a
    // guest nobody in this repo built.
    let shown = Command::new("systemctl")
        .args(["show", "k7d", "-p", "Environment", "--value"])
        .output()
        .expect("systemctl show k7d");
    let effective = String::from_utf8_lossy(&shown.stdout);
    for (var, want) in [
        ("K7D_KERNEL", share_guest_paths().0),
        ("K7D_INITRD", share_guest_paths().1),
    ] {
        let expected = format!("{var}={}", want.display());
        assert!(
            effective.split_whitespace().any(|kv| kv == expected),
            "k7d.service runs with a different guest than the suite installed: \
             wanted {expected}, systemd reports {}. Check for drop-ins under \
             /etc/systemd/system/k7d.service.d/",
            effective.trim()
        );
    }

    // Fail loudly if the control socket never accepts — every
    // subsequent kubectl test would otherwise fail with a confusing
    // "connect to k7d daemon" error from inside the shim. Probe with a
    // real connect (not just file existence) so a stale socket file
    // from a daemon mid-restart doesn't fool us.
    let socket = "/run/k7d/k7d.sock";
    // 60s: a unit rewrite (`need_unit`) restarts k7d, and rehydrating
    // leftover trees on a dirty node exceeded the old 10s window
    // (CHALLENGES #244 — test_volumes after SETPCAP).
    let deadline = Instant::now() + Duration::from_secs(60);
    while std::os::unix::net::UnixStream::connect(socket).is_err() {
        assert!(
            Instant::now() < deadline,
            "k7d control socket {socket} did not accept within 60s \
             (check `journalctl -u k7d`)"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Install the pinned Firecracker + jailer via the same script a node
/// setup runs (`utils/install-firecracker.sh`), and hand back the
/// pinned version.
///
/// Idempotent and cheap on a node that already has them: the script's
/// fast path is two sha256 digests. Deliberately the *script* and not a
/// Rust reimplementation — a suite that installed the binaries some
/// other way would prove nothing about the thing operators run, and the
/// sha check is the whole point of the pin.
pub fn ensure_firecracker_installed() -> String {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf();
    let script = repo.join("utils/install-firecracker.sh");
    assert!(script.is_file(), "missing {}", script.display());
    let out = Command::new("bash")
        .arg(&script)
        .output()
        .expect("run install-firecracker.sh");
    assert!(
        out.status.success(),
        "install-firecracker.sh failed ({}): {}{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    firecracker_pin("FIRECRACKER_VERSION")
}

/// One value out of `guest/fc/pins.env`.
pub fn firecracker_pin(key: &str) -> String {
    let pins = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("guest/fc/pins.env");
    let text = std::fs::read_to_string(&pins).expect("read guest/fc/pins.env");
    text.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}=")))
        .unwrap_or_else(|| panic!("{key} is not set in {}", pins.display()))
        .trim()
        .to_string()
}

/// Installed guest artifact paths — the layout `packaging/install.sh`
/// writes and `k7d.service` points at.
fn share_guest_paths() -> (PathBuf, PathBuf) {
    let share = PathBuf::from("/usr/local/share/k7d");
    (share.join("vmlinux"), share.join("initramfs.cpio.gz"))
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

/// Render `packaging/k7d.service.in` — the same body `install.sh` and
/// `setup-node-after-reset.sh` consume. One template so the three
/// cannot drift.
pub fn k7d_service_unit_body(bin: &Path, kernel: &Path, initrd: &Path) -> String {
    let template = include_str!("../../../../packaging/k7d.service.in");
    template
        .replace("@K7D_BIN@", &bin.display().to_string())
        .replace("@KERNEL@", &kernel.display().to_string())
        .replace("@INITRD@", &initrd.display().to_string())
}

/// Install the `ExecStartPre=+` mount helper the unit names.
fn install_k7d_mount_disks() {
    let src = workspace_root().join("packaging/k7d-mount-disks.sh");
    assert!(src.is_file(), "missing {}", src.display());
    let dest = Path::new("/usr/local/libexec/k7d-mount-disks");
    std::fs::create_dir_all("/usr/local/libexec").expect("create /usr/local/libexec");
    let tmp = dest.with_extension("new");
    std::fs::copy(&src, &tmp).expect("copy k7d-mount-disks");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::fs::rename(&tmp, dest).expect("install k7d-mount-disks");
}

/// Create the `k7d` account, install `60-k7d.rules` and hand the state
/// directories over — the packaging half of privilege separation, run by the suite
/// so a node the tests provisioned matches one `install.sh` provisioned.
///
/// Self-sufficient on purpose (the `ensure_shim_installed` rule): the
/// `privsep:` doctor section asserts the account and the device group,
/// and a test that skipped when they were missing would assert nothing on
/// exactly the node that regressed. The script is idempotent, so this
/// runs on every invocation rather than guessing at freshness.
fn provision_vm_broker_identity() {
    let root = workspace_root();
    let script = root.join("packaging/k7d-account.sh");
    let rules = root.join("packaging/60-k7d.rules");
    assert!(script.is_file(), "missing {}", script.display());
    assert!(rules.is_file(), "missing {}", rules.display());
    let out = Command::new("bash")
        .arg("-c")
        .arg(format!(
            "set -euo pipefail; source {}; k7d_provision_vm_broker_identity {}",
            script.display(),
            rules.display()
        ))
        .output()
        .expect("run k7d-account.sh");
    assert!(
        out.status.success(),
        "provisioning the k7d account failed: {}\nstdout={}\nstderr={}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The guest kernel `k7d.service` tells the daemon to boot — the only
/// path a pod's VM is allowed to come up on.
pub fn daemon_kernel_path() -> String {
    share_guest_paths().0.to_string_lossy().into_owned()
}

/// Copy the guest kernel and initramfs this workspace built into the
/// installed location the daemon boots from, and report whether either
/// changed (the caller restarts the daemon if so).
///
/// The suite deliberately runs the *installed* layout rather than
/// booting straight out of the checkout: that is how a k7 node runs,
/// and it is the only arrangement in which the daemon's guest path and
/// the workspace path differ — which is what lets the kernel-path
/// assertion in `test_kubectl_create_pod_with_k7_runtime` notice if
/// anything ever starts guessing at guest artifacts again
/// (CHALLENGES #72).
///
/// Copying on every run keeps entry #68's rule intact: `make test`
/// rebuilds the agent and initramfs first precisely so no test can
/// boot yesterday's guest.
fn install_workspace_guest() -> bool {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let built = [
        (
            workspace.join("guest/kernel/vmlinux"),
            share_guest_paths().0,
            "make build-guest-kernel",
        ),
        (
            workspace.join("guest/rootfs/initramfs.cpio.gz"),
            share_guest_paths().1,
            "make build-guest-rootfs",
        ),
    ];

    let mut refreshed = false;
    for (src, dst, how) in built {
        assert!(
            src.is_file(),
            "{} is missing — run `{how}` before the suite; the daemon boots \
             what this workspace built, never a leftover install",
            src.display()
        );
        let stale = match (std::fs::metadata(&src), std::fs::metadata(&dst)) {
            (Ok(s), Ok(d)) => s.len() != d.len() || s.modified().unwrap() > d.modified().unwrap(),
            _ => true,
        };
        if !stale {
            continue;
        }
        eprintln!("  installing {} → {}", src.display(), dst.display());
        std::fs::create_dir_all(dst.parent().unwrap()).expect("create guest share dir");
        // Via a temp file + rename: a running daemon has the current
        // kernel open, and overwriting it in place would rewrite the
        // bytes under it.
        let tmp = dst.with_extension("new");
        std::fs::copy(&src, &tmp).expect("copy guest artifact");
        std::fs::rename(&tmp, &dst).expect("install guest artifact");
        refreshed = true;
    }
    refreshed
}

/// Wait for k3s to actually converge after a `systemctl restart k3s`.
/// A fixed sleep is not enough: flannel/kube-proxy
/// take tens of seconds to reprogram the host dataplane, and the
/// block path reaches Running fast enough that the first kubectl pod
/// of a suite lands inside that window — host→pod TCP times out while
/// the pod's own netns dataplane is already fine. CoreDNS Ready is
/// the convergence signal: kubelet's readiness probe is an HTTP GET
/// from the host netns to the pod IP, i.e. exactly the path that
/// breaks during convergence.
pub fn wait_for_k3s_ready() {
    // Older cilium tests used `ip route replace 10.42.0.0/24 via
    // 10.200…` in the main table. When the k7 bridge dropped, host
    // cni0's connected route was gone and CoreDNS probes timed out.
    k7d::network::purge_main_table_guest_via_routes();
    k7d::network::restore_host_cni_connected_route()
        .unwrap_or_else(|e| panic!("restore host cni0 before k3s ready wait: {e}"));
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let api_ok = Command::new("kubectl")
            .args(["get", "--raw", "/readyz"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        let dns_ready = Command::new("kubectl")
            .args([
                "-n",
                "kube-system",
                "get",
                "pods",
                "-l",
                "k8s-app=kube-dns",
                "-o",
                "jsonpath={.items[*].status.conditions[?(@.type=='Ready')].status}",
            ])
            .output()
            .map(|o| {
                let s = String::from_utf8_lossy(&o.stdout);
                o.status.success() && !s.is_empty() && s.split_whitespace().all(|c| c == "True")
            })
            .unwrap_or(false);
        if api_ok && dns_ready {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "k3s did not converge within 180s after restart \
             (apiserver ready={api_ok}, coredns ready={dns_ready})"
        );
        std::thread::sleep(Duration::from_secs(2));
    }
}

/// Make containerd forward `k7d.katakate.org/*` pod
/// annotations into the sandbox OCI spec (`pod_annotations` in the k7
/// runtime config). Without it the shim never sees `cluster-id` /
/// `image-slots` / `fork-vm-index` on kubectl-deployed pods.
/// Idempotent: patches the k3s containerd config template only when
/// the line is missing, then restarts k3s and waits for full
/// convergence (apiserver + coredns Ready).
pub fn ensure_pod_annotations_forwarded() {
    const CANDIDATES: [&str; 2] = [
        "/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.tmpl",
        "/var/lib/rancher/k3s/agent/etc/containerd/config.toml.tmpl",
    ];
    const MARKER: &str = "runtime_type = \"io.containerd.k7.v1\"";
    let mut found = false;
    let mut patched = false;
    for path in CANDIDATES {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        if !text.contains("runtimes.k7]") {
            continue;
        }
        found = true;
        if text.contains("pod_annotations") {
            continue;
        }
        assert!(
            text.contains(MARKER),
            "k7 runtime block in {path} has no `{MARKER}` line to anchor the patch"
        );
        let new = text.replace(
            MARKER,
            &format!("{MARKER}\n  pod_annotations = [\"k7d.katakate.org/*\"]"),
        );
        std::fs::write(path, new).unwrap_or_else(|e| panic!("write {path}: {e}"));
        eprintln!("  patched {path} with pod_annotations forwarding");
        patched = true;
    }
    assert!(
        found,
        "no containerd config template with a k7 runtime block found (node not set up?)"
    );
    if patched {
        let _ = Command::new("systemctl").args(["restart", "k3s"]).status();
        // Full convergence wait (apiserver + coredns Ready) — a plain
        // node-Ready check returns before flannel/kube-proxy have
        // reprogrammed the host dataplane.
        wait_for_k3s_ready();
    }
}

/// Shim toml the `k7-fc` containerd runtime's `ConfigPath` points at.
pub const SHIM_FC_CONFIG_PATH: &str = "/etc/k7d/shim-k7-fc.toml";

/// Memory overhead for the `k7-fc` class. Method and the
/// busybox / Ubuntu measurements live in `OVERHEAD.md`.
pub const K7_FC_OVERHEAD_MEMORY: &str = "32Mi";

/// CPU overhead for the `k7-fc` class.
pub const K7_FC_OVERHEAD_CPU: &str = "50m";

const K7_FC_RUNTIME_BLOCK: &str = r#"
[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.k7-fc]
  runtime_type = "io.containerd.k7.v1"
  pod_annotations = ["k7d.katakate.org/*"]
  privileged_without_host_devices = true
  snapshotter = "overlayfs"
  [plugins."io.containerd.cri.v1.runtime".containerd.runtimes.k7-fc.options]
    ConfigPath = "/etc/k7d/shim-k7-fc.toml"
"#;

fn k7_fc_runtimeclass_yaml() -> String {
    // Do not use `\ ` line continuations here: Rust strips the next
    // line's indent, so `  name: k7-fc` became a top-level `name:` and
    // kubectl applied a RuntimeClass with an empty metadata.name
    // (CHALLENGES #229).
    format!(
        r#"apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: k7-fc
handler: k7-fc
overhead:
  podFixed:
    cpu: {K7_FC_OVERHEAD_CPU}
    memory: {K7_FC_OVERHEAD_MEMORY}
"#
    )
}

/// Register containerd `runtimes.k7-fc` (`ConfigPath`, no `BinaryName`)
/// and the `k7-fc` class with the measured `PodOverhead`.
///
/// Idempotent. Restarts k3s only when the containerd template changed.
/// This node's k3s/containerd 2.3.3 does not stamp
/// `io.kubernetes.cri.runtime-handler` on the sandbox OCI spec, so the
/// `ConfigPath` toml is the signal that puts a `k7-fc` pod on Firecracker
/// (CHALLENGES #228).
pub fn ensure_k7_fc_runtime_registered() {
    std::fs::create_dir_all("/etc/k7d").expect("mkdir /etc/k7d");
    let toml = "backend = \"firecracker\"\n";
    let need_toml = std::fs::read_to_string(SHIM_FC_CONFIG_PATH)
        .map(|t| t != toml)
        .unwrap_or(true);
    if need_toml {
        std::fs::write(SHIM_FC_CONFIG_PATH, toml).expect("write shim-k7-fc.toml");
    }

    const CANDIDATES: [&str; 2] = [
        "/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.tmpl",
        "/var/lib/rancher/k3s/agent/etc/containerd/config.toml.tmpl",
    ];
    let mut found = false;
    let mut patched = false;
    for path in CANDIDATES {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        found = true;
        if let Some(err) = k7_fc_block_binary_name_error(&text) {
            panic!("{err}");
        }
        if text.contains("runtimes.k7-fc]") && text.contains("shim-k7-fc.toml") {
            continue;
        }
        let new = if text.contains("runtimes.k7-fc]") {
            // Block exists but `ConfigPath` does not — refuse to guess a
            // `BinaryName`-shaped `[options]` table. Append the options
            // table next to the existing block.
            format!(
                "{text}\n  [plugins.\"io.containerd.cri.v1.runtime\".containerd.runtimes.k7-fc.options]\n    ConfigPath = \"{SHIM_FC_CONFIG_PATH}\"\n"
            )
        } else {
            format!("{text}\n{K7_FC_RUNTIME_BLOCK}")
        };
        std::fs::write(path, new).unwrap_or_else(|e| panic!("write {path}: {e}"));
        eprintln!("  patched {path} with runtimes.k7-fc (ConfigPath, no BinaryName)");
        patched = true;
    }
    assert!(
        found,
        "no k3s containerd config template found (node not set up?)"
    );
    if patched {
        let _ = Command::new("systemctl").args(["restart", "k3s"]).status();
        wait_for_k3s_ready();
    }

    let yaml = k7_fc_runtimeclass_yaml();
    let output = Command::new("kubectl")
        .args(["apply", "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            {
                let mut stdin = child.stdin.take().expect("kubectl stdin");
                stdin.write_all(yaml.as_bytes())?;
            }
            child.wait_with_output()
        })
        .expect("kubectl apply RuntimeClass k7-fc");
    assert!(
        output.status.success(),
        "kubectl apply RuntimeClass k7-fc failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `BinaryName` in the k7-fc options table leaks into the cgroup path
/// the same way it did for `runtimes.k7` (CHALLENGES on `BinaryName`).
fn k7_fc_block_binary_name_error(text: &str) -> Option<String> {
    let start = text.find("runtimes.k7-fc]")?;
    let rest = &text[start..];
    let end = rest[1..].find("\n[").map(|i| i + 1).unwrap_or(rest.len());
    let section = &rest[..end];
    if section.contains("BinaryName") {
        Some("k7-fc runtime block must not set BinaryName (breaks shim cgroup path)".to_string())
    } else {
        None
    }
}

/// Block-path VM facts reported by the daemon's
/// `vm_status` for assertions (zero-virtiofs invariant, explicit
/// virtiofs fallback, CoW-vs-full-copy fork memory).
pub struct PodVmState {
    pub vm_id: String,
    pub virtiofs_shares: usize,
    pub block_devices: usize,
    pub fork_memory_full_copy: bool,
    /// The guest kernel the VM booted — the daemon's answer, which is
    /// the only one there should be (CHALLENGES #72).
    pub kernel: String,
}

/// Resolve a kubectl pod name to its CRI sandbox id via k3s'
/// embedded crictl. Fails loudly when the pod has no sandbox.
pub fn pod_sandbox_id(pod: &str) -> String {
    let out = Command::new("k3s")
        // `--name` is a regex: unanchored, `foo` also matches `foo-pool-x`.
        .args(["crictl", "pods", "-q", "--name", &format!("^{pod}$")])
        .output()
        .expect("k3s crictl pods should run");
    let sandbox_id = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    assert!(
        !sandbox_id.is_empty(),
        "no CRI sandbox found for pod {pod}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    sandbox_id
}

/// Resolve a kubectl pod to its k7d daemon VM id.
pub fn pod_vm_id(pod: &str) -> String {
    let sandbox_id = pod_sandbox_id(pod);
    let mut client = k7d::control::Client::connect_env().expect("connect k7d daemon");
    match client
        .call(&k7d::control::Request::LookupSandbox {
            sandbox_id: sandbox_id.clone(),
        })
        .expect("lookup_sandbox")
    {
        k7d::control::Response::SandboxFound { vm_id, .. } => vm_id,
        other => panic!("daemon has no VM for pod {pod} (sandbox {sandbox_id}): {other:?}"),
    }
}

/// The daemon's network view of kubectl pod `pod`:
/// `(cluster_id, vm_index, pod_netns_attached)`.
pub fn pod_vm_network(pod: &str) -> (Option<String>, Option<u32>, bool) {
    let sandbox_id = pod_sandbox_id(pod);
    let mut client = k7d::control::Client::connect_env().expect("connect k7d daemon");
    match client
        .call(&k7d::control::Request::LookupSandbox {
            sandbox_id: sandbox_id.clone(),
        })
        .expect("lookup_sandbox")
    {
        k7d::control::Response::SandboxFound {
            cluster_id,
            vm_index,
            pod_netns_attached,
            ..
        } => (cluster_id, vm_index, pod_netns_attached),
        other => panic!("daemon has no VM for pod {pod} (sandbox {sandbox_id}): {other:?}"),
    }
}

/// Assert kubectl pod `pod` reaches the internet by raw IP (no DNS in
/// the way). Busybox `wget` in the pod's first container; the verdict
/// is an echoed sentinel, not the exec exit code. Three tries absorb a
/// cold neighbour table, nothing more.
pub fn assert_pod_egress(pod: &str, what: &str) {
    let probe = "wget -q -T 5 -O /dev/null http://1.1.1.1/ && echo EGRESS_OK || echo EGRESS_FAIL";
    let mut last = String::new();
    for _ in 0..3 {
        let out = Command::new("kubectl")
            .args(["exec", pod, "--", "sh", "-c", probe])
            .output()
            .expect("kubectl exec should run");
        last = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        if last.contains("EGRESS_OK") {
            return;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    panic!("{what}: pod {pod} has no internet egress (http://1.1.1.1/): {last}");
}

/// Query the daemon's `vm_status` for the VM backing kubectl pod
/// `pod` (block-path assertions).
pub fn pod_vm_state(pod: &str) -> PodVmState {
    let vm_id = pod_vm_id(pod);
    vm_state(&vm_id)
}

/// Query the daemon's `vm_status` for `vm_id`.
pub fn vm_state(vm_id: &str) -> PodVmState {
    let mut client = k7d::control::Client::connect_env().expect("connect k7d daemon");
    match client
        .call(&k7d::control::Request::VmStatus {
            vm_id: vm_id.to_string(),
        })
        .expect("vm_status")
    {
        k7d::control::Response::VmState {
            vm_id,
            virtiofs_shares,
            block_devices,
            fork_memory_full_copy,
            kernel,
            ..
        } => PodVmState {
            vm_id,
            virtiofs_shares,
            block_devices,
            fork_memory_full_copy,
            kernel,
        },
        other => panic!("unexpected vm_status response for {vm_id}: {other:?}"),
    }
}

/// Kernel hostname — matches `kubernetes.io/hostname` on k3s nodes.
pub fn current_hostname() -> String {
    let out = Command::new("hostname")
        .output()
        .expect("hostname should run");
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .to_ascii_lowercase()
}

/// Pin a pod manifest to this node so kubelet never schedules onto a
/// peer without the k7 runtime registered in containerd.
///
/// Matches `runtimeClassName: k7` and `k7-fc` separately — a naive
/// `k7` prefix replace would also rewrite `k7-fc`.
pub fn pin_to_local_node(pod_yaml: &str) -> String {
    let host = current_hostname();
    let pin = |yaml: String, rc: &str| {
        yaml.replace(
            &format!("  runtimeClassName: {rc}\n"),
            &format!(
                "  nodeSelector:\n    kubernetes.io/hostname: \"{host}\"\n  runtimeClassName: {rc}\n"
            ),
        )
    };
    pin(pin(pod_yaml.to_string(), "k7-fc"), "k7")
}

/// Label key stamped on every cluster-scoped resource a test creates.
pub const TEST_RUN_LABEL: &str = "k7-test-run";

/// Age after which a leftover `k7-test-run` resource is treated as
/// stranded (crashed prior run) rather than a live concurrent suite.
pub const STALE_AGE: Duration = Duration::from_secs(30 * 60);

/// Empty file written into every test-created tree directory. The
/// stranded-tree sweep reaps **only** dirs that carry this marker —
/// never by id prefix. An operator's suspended tree looks identical
/// to an old test tree without it.
pub const TEST_TREE_MARKER: &str = ".k7d-test-tree";

/// Default free-space floor on [`k7d::disks::DISKS_DIR`] after the
/// sweep (24 GiB). The kafka fork-under-load arm needs ~that much to
/// keyframe a ~2.9 GB parent and sibling. Override with
/// `K7D_MIN_FREE_DISK` (integer bytes).
pub const DEFAULT_MIN_FREE_DISK: u64 = 24 * 1024 * 1024 * 1024;

/// Per-process test-run id: 6 hex chars from pid XOR boot-time nanos.
///
/// Stable for the life of this test binary so every resource this
/// process creates shares one selector. Distinct processes (two
/// concurrent `make check` runs) get distinct ids.
pub fn run_id() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| {
        let pid = u64::from(std::process::id());
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        format!(
            "{:06x}",
            (pid.wrapping_mul(0x9E37_79B9) ^ nanos) & 0x00ff_ffff
        )
    })
}

/// `{base}-{run_id}` — every cluster-scoped name a test creates.
pub fn unique_name(base: &str) -> String {
    let name = format!("{base}-{}", run_id());
    assert!(
        name.len() <= 63,
        "unique name {name} exceeds the 63-char Kubernetes DNS-1123 limit"
    );
    name
}

/// Suffix `metadata.name` values that start with `test-` and inject
/// `k7-test-run: <run_id>` into every resource. Idempotent when the
/// name is already suffixed or the label is already present.
pub fn isolate_manifest(yaml: &str) -> String {
    stamp_test_labels(&suffix_test_names(yaml))
}

/// `kubectl apply -f -` that always isolates the manifest (unique
/// `test-*` names + `k7-test-run` label).
pub fn kubectl_apply(yaml: &str) -> Result<(), String> {
    let yaml = isolate_manifest(yaml);
    let output = Command::new("kubectl")
        .args(["apply", "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(yaml.as_bytes())
                .unwrap();
            child.wait_with_output()
        })
        .map_err(|e| format!("kubectl apply failed: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

fn leading_spaces(s: &str) -> usize {
    s.chars().take_while(|&c| c == ' ').count()
}

fn suffix_test_names(yaml: &str) -> String {
    let rid = run_id();
    let suffix = format!("-{rid}");
    let mut out = Vec::new();
    let lines: Vec<&str> = yaml.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if line.trim() == "metadata:" {
            out.push(line.to_string());
            let meta_indent = leading_spaces(line);
            let key_indent = meta_indent + 2;
            i += 1;
            while i < lines.len() {
                let l = lines[i];
                if !l.trim().is_empty() && leading_spaces(l) <= meta_indent {
                    break;
                }
                if leading_spaces(l) == key_indent {
                    if let Some(name) = l.trim().strip_prefix("name:") {
                        let name = name.trim();
                        if name.starts_with("test-") && !name.ends_with(&suffix) {
                            let pad = " ".repeat(key_indent);
                            out.push(format!("{pad}name: {name}{suffix}"));
                            i += 1;
                            continue;
                        }
                    }
                }
                out.push(l.to_string());
                i += 1;
            }
            continue;
        }
        out.push(line.to_string());
        i += 1;
    }
    let mut s = out.join("\n");
    if yaml.ends_with('\n') {
        s.push('\n');
    }
    s
}

/// Inject `k7-test-run: <run_id>` into every resource `metadata` block.
pub fn stamp_test_labels(yaml: &str) -> String {
    let rid = run_id();
    let mut parts = Vec::new();
    for (idx, doc) in yaml.split("---").enumerate() {
        if idx > 0 {
            parts.push("---".to_string());
        }
        parts.push(stamp_one_doc(doc, rid));
    }
    parts.join("")
}

fn stamp_one_doc(doc: &str, rid: &str) -> String {
    if !doc.contains("metadata:") || doc.contains("k7-test-run:") {
        return doc.to_string();
    }
    let lines: Vec<&str> = doc.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        out.push(lines[i].to_string());
        if lines[i].trim() == "metadata:" {
            let meta_indent = leading_spaces(lines[i]);
            let key_indent = meta_indent + 2;
            let label_indent = key_indent + 2;
            i += 1;
            let mut block = Vec::new();
            while i < lines.len() {
                if !lines[i].trim().is_empty() && leading_spaces(lines[i]) <= meta_indent {
                    break;
                }
                block.push(lines[i].to_string());
                i += 1;
            }
            let has_labels = block
                .iter()
                .any(|l| leading_spaces(l) == key_indent && l.trim() == "labels:");
            if has_labels {
                for l in &block {
                    out.push(l.clone());
                    if leading_spaces(l) == key_indent && l.trim() == "labels:" {
                        out.push(format!(
                            "{}k7-test-run: \"{rid}\"",
                            " ".repeat(label_indent)
                        ));
                    }
                }
            } else if block
                .iter()
                .any(|l| leading_spaces(l) == key_indent && l.trim().starts_with("name:"))
            {
                for l in &block {
                    out.push(l.clone());
                    if leading_spaces(l) == key_indent && l.trim().starts_with("name:") {
                        out.push(format!("{}labels:", " ".repeat(key_indent)));
                        out.push(format!(
                            "{}k7-test-run: \"{rid}\"",
                            " ".repeat(label_indent)
                        ));
                    }
                }
            } else {
                out.push(format!("{}labels:", " ".repeat(key_indent)));
                out.push(format!(
                    "{}k7-test-run: \"{rid}\"",
                    " ".repeat(label_indent)
                ));
                out.extend(block);
            }
            continue;
        }
        i += 1;
    }
    let mut s = out.join("\n");
    if doc.ends_with('\n') {
        s.push('\n');
    }
    s
}

fn maybe_hygiene_once() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        let _ = sweep_stranded_resources();
        assert_disks_have_headroom();
    });
}

/// Sweep stranded leftovers, then fail loud if [`k7d::disks::DISKS_DIR`]
/// is under [`DEFAULT_MIN_FREE_DISK`]. Every test binary that goes
/// through [`ensure_k7d_daemon_running`] / [`cleanup_k7_runtime_leaks`]
/// hits this once.
pub fn hygiene_once() {
    maybe_hygiene_once();
}

/// Fail the test binary if free space on [`k7d::disks::DISKS_DIR`] is
/// below `K7D_MIN_FREE_DISK` (default [`DEFAULT_MIN_FREE_DISK`]). Hard
/// failure — not a warning, not a skip.
pub fn assert_disks_have_headroom() {
    let need = min_free_disk_bytes();
    let dir = Path::new(k7d::disks::DISKS_DIR);
    let free = fs_free_bytes(dir);
    if free < need {
        let free_gib = free / (1024 * 1024 * 1024);
        let need_gib = need / (1024 * 1024 * 1024);
        panic!(
            "DISKS_DIR {}: {free_gib} GiB free, need {need_gib} GiB.\n\
             Run `make remote-node-reclaim`.",
            dir.display()
        );
    }
}

fn min_free_disk_bytes() -> u64 {
    match std::env::var("K7D_MIN_FREE_DISK") {
        Ok(s) => s
            .parse::<u64>()
            .unwrap_or_else(|_| panic!("K7D_MIN_FREE_DISK={s} is not an integer byte count")),
        Err(_) => DEFAULT_MIN_FREE_DISK,
    }
}

/// Stamp [`TEST_TREE_MARKER`] into the on-disk tree dir.
///
/// Tries [`k7d::control::tree_root_dir`] (symlink `/var/lib/k7d/trees`
/// or `K7D_TREE_ROOT`) and [`k7d::disks::DISKS_DIR`]/[`k7d::disks::TREES_SUBDIR`].
/// Panics if neither directory exists — a successful `tree_create*`
/// always leaves one.
pub fn mark_test_tree(tree_id: &str) {
    assert!(!tree_id.is_empty(), "mark_test_tree: empty tree_id");
    let via_root = k7d::control::tree_root_dir().join(tree_id);
    let via_disks = Path::new(k7d::disks::DISKS_DIR)
        .join(k7d::disks::TREES_SUBDIR)
        .join(tree_id);
    let mut marked = false;
    for dir in [&via_root, &via_disks] {
        if dir.is_dir() {
            mark_test_tree_dir(dir);
            marked = true;
        }
    }
    assert!(
        marked,
        "mark_test_tree: no directory for {tree_id} at {} or {}",
        via_root.display(),
        via_disks.display()
    );
}

/// Stamp [`TEST_TREE_MARKER`] into an already-created tree directory.
pub fn mark_test_tree_dir(dir: &Path) {
    assert!(
        dir.is_dir(),
        "mark_test_tree_dir: {} is not a directory",
        dir.display()
    );
    std::fs::write(dir.join(TEST_TREE_MARKER), b"").unwrap_or_else(|e| {
        panic!("write {}/{}: {e}", dir.display(), TEST_TREE_MARKER);
    });
}

/// Mark the tree if `resp` is a successful `tree_create*` / adopt.
pub fn mark_if_tree_created(resp: &k7d::control::Response) {
    if let k7d::control::Response::TreeCreated { tree_id, .. } = resp {
        mark_test_tree(tree_id);
    }
}

/// Network `name`'s namespace (the per-network netns spec), as a path
/// this process can enter: `/run/netns/<name>` when this process or a
/// daemon it spawned made it, else through the root of the k7d process
/// that did — under systemd k7d mounts its namespaces in a private
/// mount namespace.
pub fn k7_netns(name: &str) -> Option<PathBuf> {
    let mut candidates = vec![PathBuf::from("/run/netns").join(name)];
    if let Ok(procs) = std::fs::read_dir("/proc") {
        for p in procs.flatten() {
            let comm = std::fs::read_to_string(p.path().join("comm")).unwrap_or_default();
            if comm.starts_with("k7d") {
                candidates.push(p.path().join("root/run/netns").join(name));
            }
        }
    }
    candidates
        .into_iter()
        .find(|c| k7d::network::is_mounted_netns(c))
}

/// Ports on network `name`'s bridge (0 when it has no namespace).
pub fn k7_bridge_port_count(name: &str) -> usize {
    let Some(ns) = k7_netns(name) else {
        return 0;
    };
    Command::new("nsenter")
        .arg(format!("--net={}", ns.display()))
        .args(["ip", "-o", "link", "show", "master", name])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().count())
        .unwrap_or(0)
}

/// Loud stranded-resource sweep. Cleans and prints one line per
/// resource reaped. A sweep that finds nothing prints nothing.
///
/// Reaps: `k7*` bridges with no live owning VM (delegates `k7-br-*`
/// to [`k7d::network::cleanup_stale_k7_bridges`]), TAP devices
/// matching our naming with no attached fd, disk images under
/// `/var/lib/k7d/disks` not referenced by any live VM, marked
/// on-disk trees older than [`STALE_AGE`] with zero live VMs, and
/// `test-*` / `k7-test-run` cluster resources older than [`STALE_AGE`].
pub fn sweep_stranded_resources() -> Vec<String> {
    let mut report = Vec::new();
    sweep_bridges(&mut report);
    sweep_taps(&mut report);
    sweep_disks(&mut report);
    sweep_trees(&mut report);
    report.extend(cleanup_stale_labeled_resources());
    report
}

fn live_vm_ids() -> Vec<String> {
    let mut client = match k7d::control::Client::connect_env() {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    match client.call(&k7d::control::Request::ListVms) {
        Ok(k7d::control::Response::VmList { vms }) => vms.into_iter().map(|v| v.vm_id).collect(),
        _ => Vec::new(),
    }
}

fn k7d_main_pid() -> Option<u32> {
    let out = Command::new("systemctl")
        .args(["show", "k7d", "-p", "MainPID", "--value"])
        .output()
        .ok()?;
    let pid: u32 = String::from_utf8_lossy(&out.stdout).trim().parse().ok()?;
    if pid == 0 {
        None
    } else {
        Some(pid)
    }
}

fn held_tap_names() -> HashSet<String> {
    let mut names = HashSet::new();
    let Some(pid) = k7d_main_pid() else {
        return names;
    };
    let dir = format!("/proc/{pid}/fdinfo");
    let Ok(entries) = std::fs::read_dir(dir) else {
        return names;
    };
    for entry in entries.flatten() {
        let Ok(text) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        for line in text.lines() {
            if let Some(name) = line.trim().strip_prefix("iff:") {
                let name = name.trim();
                if !name.is_empty() {
                    names.insert(name.to_string());
                }
            }
        }
    }
    names
}

fn list_links_with_prefix(prefix: &str) -> Vec<String> {
    let out = Command::new("ip").args(["-o", "link", "show"]).output();
    let Ok(out) = out else {
        return Vec::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let after_idx = line.split(':').nth(1)?;
            let name = after_idx.trim().split('@').next()?.trim();
            if name.starts_with(prefix) {
                Some(name.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn is_bridge(name: &str) -> bool {
    Path::new(&format!("/sys/class/net/{name}/bridge")).is_dir()
}

fn bridge_has_held_tap(bridge: &str, held: &HashSet<String>) -> bool {
    let dir = format!("/sys/class/net/{bridge}/brif");
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries
        .flatten()
        .any(|e| held.contains(&e.file_name().to_string_lossy().into_owned()))
}

fn delete_link(name: &str) {
    let _ = Command::new("ip")
        .args(["link", "set", "dev", name, "down"])
        .output();
    let _ = Command::new("ip").args(["link", "delete", name]).output();
}

fn sweep_bridges(report: &mut Vec<String>) {
    let live = live_vm_ids();
    let held = held_tap_names();
    if live.is_empty() {
        for b in k7d::network::cleanup_stale_k7_bridges() {
            reap(report, "bridge", &b);
        }
    }
    for name in list_links_with_prefix("k7") {
        if !is_bridge(&name) {
            continue;
        }
        if name.starts_with("k7-br-") && !live.is_empty() {
            continue;
        }
        if bridge_has_held_tap(&name, &held) {
            continue;
        }
        delete_link(&name);
        reap(report, "bridge", &name);
    }
}

fn is_k7_tap_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix('t') else {
        return false;
    };
    let Some((tag, idx)) = rest.split_once('t') else {
        return false;
    };
    tag.len() == 5
        && tag.chars().all(|c| c.is_ascii_hexdigit())
        && !idx.is_empty()
        && idx.chars().all(|c| c.is_ascii_digit())
}

fn sweep_taps(report: &mut Vec<String>) {
    let held = held_tap_names();
    for name in list_links_with_prefix("t") {
        if !is_k7_tap_name(&name) || held.contains(&name) {
            continue;
        }
        delete_link(&name);
        reap(report, "tap", &name);
    }
}

fn live_disk_paths() -> HashSet<PathBuf> {
    let mut out = HashSet::new();
    if let Some(pid) = k7d_main_pid() {
        let dir = format!("/proc/{pid}/fd");
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                if let Ok(target) = std::fs::read_link(entry.path()) {
                    if target.starts_with(k7d::disks::DISKS_DIR) {
                        out.insert(target);
                    }
                }
            }
        }
    }
    for id in live_vm_ids() {
        out.insert(PathBuf::from(k7d::disks::DISKS_DIR).join(format!("scratch-{id}.img")));
    }
    out
}

fn sweep_disks(report: &mut Vec<String>) {
    let live = live_disk_paths();
    let dir = Path::new(k7d::disks::DISKS_DIR);
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("img") {
            continue;
        }
        if live.contains(&path) {
            continue;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => reap(report, "disk", &path.display().to_string()),
            Err(e) => eprintln!("sweep: failed to remove {}: {e}", path.display()),
        }
    }
    sweep_data_disks(&live, report);
}

/// Reap **named persistent** data disks left behind by
/// a run that died.
///
/// Deliberately not the same rule as the loop above: a data disk's whole
/// contract is that it outlives the VM, so "no live VM holds it open" is
/// exactly the state a correctly retained disk is in between two VMs.
/// The gate is therefore age, like the labeled-resource reap — nothing
/// younger than [`STALE_AGE`] is touched, which is safe against a
/// concurrent run and still cleans up after a crashed one.
fn sweep_data_disks(live: &HashSet<PathBuf>, report: &mut Vec<String>) {
    let dir = k7d::disks::data_disks_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("img") || live.contains(&path) {
            continue;
        }
        let age = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|m| m.elapsed().ok());
        match age {
            Some(age) if age >= STALE_AGE => {}
            Some(_) => continue,
            // An unreadable or future mtime is not evidence of an
            // orphan; deleting on "don't know" would eat a live run's
            // data disk.
            None => {
                eprintln!("sweep: cannot age {} — leaving it alone", path.display());
                continue;
            }
        }
        match std::fs::remove_file(&path) {
            Ok(()) => reap(report, "data-disk", &path.display().to_string()),
            Err(e) => eprintln!("sweep: failed to remove {}: {e}", path.display()),
        }
    }
}

fn tree_live_vm_counts() -> HashMap<String, usize> {
    let mut client = match k7d::control::Client::connect_env() {
        Ok(c) => c,
        Err(_) => return HashMap::new(),
    };
    match client.call(&k7d::control::Request::TreeList) {
        Ok(k7d::control::Response::TreeList { trees }) => trees
            .into_iter()
            .map(|t| (t.tree_id, t.usage.live_vm_count))
            .collect(),
        _ => HashMap::new(),
    }
}

/// Reap on-disk trees under [`k7d::disks::TREES_SUBDIR`] that a test
/// created and a crashed run left behind.
///
/// Same argument as [`sweep_data_disks`]: a tree's contract is to
/// outlive its VMs (`tree_drop` keeps the dir so `tree_open` can
/// re-adopt it), so "no live VM" is the state a correctly retained
/// tree is in. The gates are therefore **marker + age + zero live
/// VMs**. Unmarked dirs are never touched — an operator's suspended
/// tree is indistinguishable from an old test tree by id.
fn sweep_trees(report: &mut Vec<String>) {
    let dir = Path::new(k7d::disks::DISKS_DIR).join(k7d::disks::TREES_SUBDIR);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    let live = tree_live_vm_counts();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let marker = path.join(TEST_TREE_MARKER);
        if !marker.is_file() {
            continue;
        }
        let age = marker
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|m| m.elapsed().ok());
        match age {
            Some(age) if age >= STALE_AGE => {}
            Some(_) => continue,
            None => {
                eprintln!("sweep: cannot age {} — leaving it alone", marker.display());
                continue;
            }
        }
        let Some(tree_id) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if live.get(tree_id).copied().unwrap_or(0) > 0 {
            continue;
        }
        // Drop from the registry first so a later rehydrate cannot
        // resurrect a dir we are about to delete. "no such tree" is
        // the unknown-to-the-daemon case and still proceeds.
        if let Ok(mut client) = k7d::control::Client::connect_env() {
            match client.call(&k7d::control::Request::TreeDrop {
                tree_id: tree_id.to_string(),
            }) {
                Ok(k7d::control::Response::Ok) | Ok(k7d::control::Response::Error { .. }) => {}
                Ok(other) => {
                    eprintln!("sweep: tree_drop({tree_id}) unexpected {other:?} — leaving the dir");
                    continue;
                }
                Err(e) => {
                    eprintln!("sweep: tree_drop({tree_id}): {e} — leaving the dir");
                    continue;
                }
            }
        }
        match std::fs::remove_dir_all(&path) {
            Ok(()) => reap(report, "tree", tree_id),
            Err(e) => eprintln!("sweep: failed to remove {}: {e}", path.display()),
        }
    }
}

/// Delete `k7-test-run` resources (and unlabeled `test-*` pods) older
/// than [`STALE_AGE`]. Safe against a live concurrent run: those
/// resources are younger than 30 minutes.
pub fn cleanup_stale_labeled_resources() -> Vec<String> {
    let mut report = Vec::new();
    reap_stale_labeled(&mut report);
    reap_stale_unlabeled_test_pods(&mut report);
    report
}

fn reap_stale_labeled(report: &mut Vec<String>) {
    let out = Command::new("kubectl")
        .args([
            "get",
            "pods,configmaps,secrets,persistentvolumeclaims",
            "-A",
            "-l",
            TEST_RUN_LABEL,
            "-o",
            "json",
        ])
        .output();
    let Ok(out) = out else {
        return;
    };
    if !out.status.success() {
        return;
    }
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&out.stdout) else {
        return;
    };
    let Some(items) = v.get("items").and_then(|i| i.as_array()) else {
        return;
    };
    for item in items {
        let Some(meta) = item.get("metadata") else {
            continue;
        };
        let name = meta.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let ns = meta
            .get("namespace")
            .and_then(|n| n.as_str())
            .unwrap_or("default");
        let created = meta
            .get("creationTimestamp")
            .and_then(|t| t.as_str())
            .unwrap_or("");
        if !is_older_than(created, STALE_AGE) {
            continue;
        }
        let kind = item.get("kind").and_then(|k| k.as_str()).unwrap_or("pod");
        delete_k8s(ns, kind, name);
        reap(report, kind, &format!("{ns}/{name}"));
    }
}

fn reap_stale_unlabeled_test_pods(report: &mut Vec<String>) {
    let out = Command::new("kubectl")
        .args(["get", "pods", "-A", "-o", "json"])
        .output();
    let Ok(out) = out else {
        return;
    };
    if !out.status.success() {
        return;
    }
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&out.stdout) else {
        return;
    };
    let Some(items) = v.get("items").and_then(|i| i.as_array()) else {
        return;
    };
    for item in items {
        let Some(meta) = item.get("metadata") else {
            continue;
        };
        let name = meta.get("name").and_then(|n| n.as_str()).unwrap_or("");
        if !name.starts_with("test-") {
            continue;
        }
        let labels = meta.get("labels").and_then(|l| l.as_object());
        if labels.is_some_and(|l| l.contains_key(TEST_RUN_LABEL)) {
            continue;
        }
        let ns = meta
            .get("namespace")
            .and_then(|n| n.as_str())
            .unwrap_or("default");
        if ns == "kube-system" {
            continue;
        }
        let created = meta
            .get("creationTimestamp")
            .and_then(|t| t.as_str())
            .unwrap_or("");
        if !is_older_than(created, STALE_AGE) {
            continue;
        }
        delete_k8s(ns, "pod", name);
        reap(report, "pod", &format!("{ns}/{name}"));
    }
}

fn delete_k8s(ns: &str, kind: &str, name: &str) {
    let _ = Command::new("kubectl")
        .args([
            "delete",
            kind,
            name,
            "-n",
            ns,
            "--ignore-not-found",
            "--wait=false",
            "--grace-period=1",
        ])
        .output();
}

fn is_older_than(creation: &str, age: Duration) -> bool {
    if creation.is_empty() {
        return false;
    }
    let out = Command::new("date")
        .args(["-u", "-d", creation, "+%s"])
        .output();
    let Ok(out) = out else {
        return false;
    };
    if !out.status.success() {
        return false;
    }
    let Ok(created) = String::from_utf8_lossy(&out.stdout).trim().parse::<u64>() else {
        return false;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now.saturating_sub(created) >= age.as_secs()
}

fn reap(report: &mut Vec<String>, kind: &str, name: &str) {
    let line = format!("sweep: reaped {kind} {name}");
    eprintln!("{line}");
    report.push(line);
}
