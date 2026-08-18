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

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    // The k7d daemon owns the VMs now. Restart it (if the
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
    // later snapshot fails with ENOSPC (collateral).
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

    let unit = Path::new("/etc/systemd/system/k7d.service");
    let unit_body = format!(
        "[Unit]\n\
Description=k7d microVM runtime daemon\n\
After=network.target\n\n\
[Service]\n\
ExecStart=/usr/local/bin/k7d\n\
Restart=on-failure\n\
Environment=RUST_LOG=info\n\
# The daemon is the only process that decides which guest a VM boots\n\
# (CHALLENGES #72), so these two are what the suite is testing.\n\
Environment=K7D_KERNEL={}\n\
Environment=K7D_INITRD={}\n\
# Soft default without this is 1024 — far too low for multi-cluster\n\
# fork batches (EMFILE on /dev/vhost-vsock; CHALLENGES #49).\n\
LimitNOFILE=524288\n\n\
[Install]\n\
WantedBy=multi-user.target\n",
        share_guest_paths().0.display(),
        share_guest_paths().1.display(),
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

/// Installed guest artifact paths — the layout `packaging/install.sh`
/// writes and `k7d.service` points at.
fn share_guest_paths() -> (PathBuf, PathBuf) {
    let share = PathBuf::from("/usr/local/share/k7d");
    (share.join("vmlinux"), share.join("initramfs.cpio.gz"))
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
pub fn pin_to_local_node(pod_yaml: &str) -> String {
    let host = current_hostname();
    let inject = format!(
        "  nodeSelector:\n    kubernetes.io/hostname: \"{host}\"\n  runtimeClassName: k7\n"
    );
    pod_yaml.replace("  runtimeClassName: k7\n", &inject)
}

/// Label key stamped on every cluster-scoped resource a test creates.
pub const TEST_RUN_LABEL: &str = "k7-test-run";

/// Age after which a leftover `k7-test-run` resource is treated as
/// stranded (crashed prior run) rather than a live concurrent suite.
pub const STALE_AGE: Duration = Duration::from_secs(30 * 60);

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
    });
}

/// Loud stranded-resource sweep. Cleans and prints one line per
/// resource reaped. A sweep that finds nothing prints nothing.
///
/// Reaps: `k7*` bridges with no live owning VM (delegates `k7-br-*`
/// to [`k7d::network::cleanup_stale_k7_bridges`]), TAP devices
/// matching our naming with no attached fd, disk images under
/// `/var/lib/k7d/disks` not referenced by any live VM, and `test-*`
/// / `k7-test-run` cluster resources older than [`STALE_AGE`].
pub fn sweep_stranded_resources() -> Vec<String> {
    let mut report = Vec::new();
    sweep_bridges(&mut report);
    sweep_taps(&mut report);
    sweep_disks(&mut report);
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
