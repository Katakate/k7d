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

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

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
    // internal notes: the k7d daemon owns the VMs now. Restart it (if the
    // unit exists) so leaked VMs from a crashed/panicked test are
    // dropped cleanly — the daemon's shutdown path tears down vCPUs,
    // virtiofsd children, TAPs, and cluster bridges in order.
    let _ = Command::new("systemctl")
        .args(["try-restart", "k7d"])
        .status();

    // Orphan virtiofsd children: a multi-share pod spawns up to three
    // (`k7fs`, `k7fs1`, `k7fs2`) per sandbox and they are not always
    // reparented/reaped cleanly when a sandbox crashes mid-start.
    let _ = Command::new("pkill").args(["-9", "virtiofsd"]).status();
    // Stale shim processes (also frees vsock CIDs held by dead VMs).
    let _ = Command::new("pkill")
        .args(["-9", "-f", "containerd-shim-k7-v1"])
        .status();

    // Lazy-unmount leftover per-shim tmpfs/bind mounts (reverse-sorted
    // so nested mounts detach before their parents), then drop the
    // scratch socket dirs. `umount -l` so a still-busy mount detaches.
    // `/tmp/k7d-fork-*` (fork/snapshot memory files, ~1.8 GB per
    // SIGKILLed daemon) is safe to sweep here: the daemon was just
    // restarted above, so no live VM maps them — leaving them behind
    // fills the 32 GB tmpfs after a few dozen aborted runs and every
    // later snapshot fails with ENOSPC.
    let _ = Command::new("sh")
        .arg("-c")
        .arg(
            "mount | awk '/k7d-shim/ {print $3}' | sort -ru | xargs -r umount -l 2>/dev/null; \
             rm -rf /tmp/k7d-shim-* /tmp/k7d-virtiofs-* /tmp/k7d-fork-* 2>/dev/null",
        )
        .status();

    // Give kubelet/containerd a beat to observe the teardown before
    // the next pod is created.
    std::thread::sleep(Duration::from_millis(1500));
}

/// RAII guard returned by each test's `ensure_shim_installed()`.
///
/// Runs [`cleanup_k7_runtime_leaks`] again when it drops — including
/// on a test panic, since the std test harness unwinds and drops
/// locals — so a failing test reclaims its orphan virtiofsd/shim
/// processes and stale mounts before the next test runs instead of
/// poisoning it (the cascade seen in internal notes
/// pod's crash took the 8th and 9th down with it).
#[must_use = "bind it (e.g. `let _g = ensure_shim_installed();`) so cleanup runs at test end"]
pub struct LeakGuard;

impl Drop for LeakGuard {
    fn drop(&mut self) {
        cleanup_k7_runtime_leaks();
    }
}

/// internal notes: install `/usr/local/bin/k7d`, register it as the
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

    let unit = Path::new("/etc/systemd/system/k7d.service");
    const UNIT_BODY: &str = "[Unit]\n\
Description=k7d microVM runtime daemon\n\
After=network.target\n\n\
[Service]\n\
ExecStart=/usr/local/bin/k7d\n\
Restart=on-failure\n\
Environment=RUST_LOG=info\n\
# Soft default without this is 1024 — far too low for multi-cluster\n\
# fork batches (EMFILE on /dev/vhost-vsock; CHALLENGES #49).\n\
LimitNOFILE=524288\n\n\
[Install]\n\
WantedBy=multi-user.target\n";
    let need_unit = match std::fs::read_to_string(unit) {
        Ok(existing) => !existing.contains("LimitNOFILE="),
        Err(_) => true,
    };
    if need_unit {
        eprintln!("  writing k7d.service systemd unit (LimitNOFILE=524288)");
        std::fs::write(unit, UNIT_BODY).expect("write k7d.service");
        let _ = Command::new("systemctl").args(["daemon-reload"]).status();
        // Unit change must take effect even when the binary was already
        // current — otherwise a long-lived daemon keeps soft=1024.
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

    // Fail loudly if the control socket never accepts — every
    // subsequent kubectl test would otherwise fail with a confusing
    // "connect to k7d daemon" error from inside the shim. Probe with a
    // real connect (not just file existence) so a stale socket file
    // from a daemon mid-restart doesn't fool us.
    let socket = "/run/k7d/k7d.sock";
    let deadline = Instant::now() + Duration::from_secs(10);
    while std::os::unix::net::UnixStream::connect(socket).is_err() {
        assert!(
            Instant::now() < deadline,
            "k7d control socket {socket} did not accept within 10s \
             (check `journalctl -u k7d`)"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Wait for k3s to actually converge after a `systemctl restart k3s`
///. A fixed sleep is not enough: flannel/kube-proxy
/// take tens of seconds to reprogram the host dataplane, and the
/// block path reaches Running fast enough that the first kubectl pod
/// of a suite lands inside that window — host→pod TCP times out while
/// the pod's own netns dataplane is already fine. CoreDNS Ready is
/// the convergence signal: kubelet's readiness probe is an HTTP GET
/// from the host netns to the pod IP, i.e. exactly the path that
/// breaks during convergence.
pub fn wait_for_k3s_ready() {
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

/// internal notes: make containerd forward `k7d.katakate.org/*` pod
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

/// internal notes: block-path VM facts reported by the daemon's
/// `vm_status` for assertions (zero-virtiofs invariant, explicit
/// virtiofs fallback, CoW-vs-full-copy fork memory).
pub struct PodVmState {
    pub vm_id: String,
    pub virtiofs_shares: usize,
    pub block_devices: usize,
    pub fork_memory_full_copy: bool,
}

/// Resolve a kubectl pod name to its CRI sandbox id via k3s'
/// embedded crictl. Fails loudly when the pod has no sandbox.
pub fn pod_sandbox_id(pod: &str) -> String {
    let out = Command::new("k3s")
        .args(["crictl", "pods", "-q", "--name", pod])
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

/// Query the daemon's `vm_status` for the VM backing kubectl pod
/// `pod`.
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
            ..
        } => PodVmState {
            vm_id,
            virtiofs_shares,
            block_devices,
            fork_memory_full_copy,
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
pub fn pin_to_local_node(pod_yaml: &str) -> String {
    let host = current_hostname();
    let inject = format!(
        "  nodeSelector:\n    kubernetes.io/hostname: \"{host}\"\n  runtimeClassName: k7\n"
    );
    pod_yaml.replace("  runtimeClassName: k7\n", &inject)
}
