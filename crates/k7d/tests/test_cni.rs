//! internal notes: end-to-end regression coverage.
//!
//! This file codifies the four traffic flows from internal notes's
//! "Success criteria" section that the PR #27 bring-up validated by
//! hand on a live k3s cluster:
//!
//! 1. `kubectl get pod -o wide` shows the CNI-assigned pod IP for
//!    k7 pods (= pod-IP visibility / `attach_to_pod_netns` ran).
//! 2. Host → pod-IP via `curl http://<pod_ip>/` returns HTTP 200.
//! 3. VM → host gateway (ping `10.42.0.1` or whatever cni0 advertises
//!    inside the pod netns) succeeds.
//! 4. VM → cluster Service IP (TCP open to CoreDNS at `10.43.0.10:53`)
//!    succeeds — kube-proxy DNAT + our pod-netns NAT compose
//!    correctly.
//! 5. VM → internet (TCP open to `1.1.1.1:443`) succeeds — egress
//!    SNAT through cni0+flannel reaches the open internet.
//!
//! Each of these was a concrete failure during the spec-10a bring-up
//! (SIGCHLD race with Tokio, missing in-guest IP/route/ARP, eth0
//! enslaved to the in-netns bridge hairpinning replies). Without
//! these tests, any future refactor of `attach_to_pod_netns` or the
//! in-netns bridge topology can silently regress one of them and the
//! breakage only shows up by re-running the live-cluster debugging
//! loop from scratch.
//!
//! Like `test_shim.rs`, this file is **kubectl-based** — it relies
//! on the bare-metal node's running k3s, the `k7` `RuntimeClass`, and
//! the shim binary at `/usr/local/bin/containerd-shim-k7-v1`. The
//! `ensure_shim_installed` helper takes care of installing the
//! freshly-built shim and registering the `RuntimeClass` if missing,
//! same as the test_shim suite.

use std::time::{Duration, Instant};

/// Single nginx pod we deploy for all of these checks. Using one pod
/// across the file (rather than one per #[test]) keeps the runtime
/// down — boot + virtiofs setup is the dominant cost (~30s) and the
/// per-flow probes are sub-second.
const POD_NAME: &str = "test-cni-nginx";

const POD_YAML: &str = r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-cni-nginx
spec:
  runtimeClassName: k7
  containers:
  - name: web
    image: docker.io/library/nginx:1.27-alpine
    ports:
    - containerPort: 80
"#;

// ---- shim/kubectl plumbing (mirror of test_shim.rs helpers) ----

mod common;

fn ensure_shim_installed() -> common::LeakGuard {
    use std::process::Command;

    // internal notes, Milestone 2: best-effort teardown of orphan
    // virtiofsd/shim processes and stale /tmp/k7d-shim mounts left by
    // earlier tests/binaries before we (re)install the shim.
    common::cleanup_k7_runtime_leaks();

    let shim_src = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("target/release/containerd-shim-k7-v1");

    // Always build: skipping when `shim_src` merely exists deploys a
    // stale shim after source edits (see test_shim.rs).
    let status = Command::new("cargo")
        .args(["build", "--release", "-p", "containerd-shim-k7-v1"])
        .status()
        .expect("cargo build should run");
    assert!(status.success(), "shim build failed");

    let installed = std::path::Path::new("/usr/local/bin/containerd-shim-k7-v1");
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
        common::wait_for_k3s_ready();
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

    // internal notes: the shim's sandbox Create now requires a running k7d
    // daemon (it owns the VMs); install and start it.
    common::ensure_k7d_daemon_running();

    common::LeakGuard
}

fn kubectl_apply(yaml: &str) -> Result<(), String> {
    let output = std::process::Command::new("kubectl")
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
        .map_err(|e| format!("kubectl apply: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Graceful pod delete used by every CNI test. See the spec-10h
/// equivalent in `test_volumes.rs::kubectl_delete_pod` for the
/// full rationale: `--force --grace-period=0` removes the API
/// object but leaves containerd's node-side sandbox + our shim +
/// virtiofsd alive to be torn down asynchronously, which the
/// next test's `cleanup_k7_runtime_leaks()` then `pkill -9`s
/// mid-shutdown, orphaning sandboxes and starving later pods.
/// Graceful delete + wait-for-NotFound lets containerd reap the
/// shim cleanly on the success path.
fn kubectl_delete_pod(name: &str) {
    let graceful = std::process::Command::new("kubectl")
        .args([
            "delete",
            "pod",
            name,
            "--ignore-not-found",
            "--wait=true",
            "--timeout=30s",
            "--grace-period=1",
        ])
        .output();
    let wait_ok = graceful.as_ref().is_ok_and(|o| o.status.success());

    if wait_ok {
        let poll_deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < poll_deadline {
            let probe = std::process::Command::new("kubectl")
                .args(["get", "pod", name, "--ignore-not-found", "-o", "name"])
                .output();
            match probe {
                Ok(o) if o.status.success() && o.stdout.is_empty() => break,
                _ => std::thread::sleep(Duration::from_millis(250)),
            }
        }
    } else {
        let _ = std::process::Command::new("kubectl")
            .args([
                "delete",
                "pod",
                name,
                "--ignore-not-found",
                "--force",
                "--grace-period=0",
            ])
            .output();
    }
}

fn kubectl_exec(pod: &str, cmd: &[&str]) -> Result<String, String> {
    let mut args = vec!["exec", pod, "--"];
    args.extend_from_slice(cmd);
    let output = std::process::Command::new("kubectl")
        .args(&args)
        .output()
        .map_err(|e| format!("kubectl exec: {e}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(format!(
            "exit {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

/// `nc -z host port` inside the pod, trusting only the exit code.
/// Returns true iff `nc` exits 0 (TCP three-way handshake completed).
/// BusyBox nc puts its "open"/"succeeded" message on stderr and
/// leaves stdout empty on success, so parsing stdout is unreliable
/// across distros — exit code is the source of truth.
fn tcp_open_via_nc(pod: &str, host: &str, port: &str) -> bool {
    let status = std::process::Command::new("kubectl")
        .args(["exec", pod, "--", "nc", "-w", "3", "-z", host, port])
        .status();
    matches!(status, Ok(s) if s.success())
}

/// Wait until `kubectl get pod -o jsonpath='{.status.podIP}'` returns
/// a non-empty value, AND `{.status.phase}` is `Running`. Returns
/// the pod IP. Times out with a helpful error after `timeout`.
fn wait_for_pod_ip(name: &str, timeout: Duration) -> Result<String, String> {
    let start = Instant::now();
    let deadline = start + timeout;
    while Instant::now() < deadline {
        let phase = std::process::Command::new("kubectl")
            .args(["get", "pod", name, "-o", "jsonpath={.status.phase}"])
            .output()
            .map_err(|e| format!("{e}"))?;
        let ip = std::process::Command::new("kubectl")
            .args(["get", "pod", name, "-o", "jsonpath={.status.podIP}"])
            .output()
            .map_err(|e| format!("{e}"))?;
        if String::from_utf8_lossy(&phase.stdout) == "Running" {
            let ip_str = String::from_utf8_lossy(&ip.stdout).to_string();
            if !ip_str.is_empty() {
                return Ok(ip_str);
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Err(format!("pod {name} not Running with IP within {timeout:?}"))
}

// ---- the actual CNI smoke test ----

/// End-to-end CNI regression test. Deploys one `runtimeClassName: k7`
/// nginx pod and walks through every flow internal notes
/// of them breaks, this test fails — which is exactly what we want
/// after the half-day of live-cluster debugging that PR #27 took.
///
/// Combined into one #[test] because boot+virtiofs setup dominates
/// the cost (~30s) and we'd pay it once per flow if these were
/// separate.
#[test]
fn test_cni_pod_traffic_flows() {
    let _leak_guard = ensure_shim_installed();

    // Best-effort cleanup from prior runs.
    kubectl_delete_pod(POD_NAME);
    std::thread::sleep(Duration::from_secs(2));

    kubectl_apply(&common::pin_to_local_node(POD_YAML)).expect("kubectl apply test-cni-nginx");

    // Flow 1 — pod-IP visible. `wait_for_pod_ip` enforces both
    // "Running" status AND a non-empty `.status.podIP`. If
    // `attach_to_pod_netns` had silently failed (Bug 1 in PR #27's
    // commit log), the pod would still come up but the shim's
    // pod-netns assertions would not fire.
    let pod_ip = wait_for_pod_ip(POD_NAME, Duration::from_secs(60))
        .expect("Flow 1 (pod-IP visible) — pod did not get a pod IP");
    eprintln!("Flow 1: pod IP {pod_ip}");
    assert!(
        pod_ip.starts_with("10.42.") || pod_ip.starts_with("10."),
        "Flow 1: expected flannel-style pod IP, got {pod_ip:?}"
    );

    // Give nginx a beat to actually start listening on :80 inside
    // the VM. The pod is "Running" the moment the container is
    // created; nginx itself usually wins the race but a 2s grace
    // makes the test stable.
    std::thread::sleep(Duration::from_secs(2));

    // Flow 2 — host → pod_ip. This is the path Kubernetes uses for
    // probes, port-forward, kubectl exec when it falls back, etc.
    // Poll instead of single-shot: when `ensure_shim_installed`
    // reinstalled the shim it restarted k3s moments ago, and the
    // block path reaches Running fast enough to land
    // inside flannel/kube-proxy's post-restart convergence window —
    // host→pod SYNs are dropped on the host for a while even though
    // the pod's own dataplane (netns DNAT → bridge → TAP → guest) is
    // already fine. A regression in OUR path never heals, so polling
    // still catches it; steady-state this succeeds on the first try
    // (~2 ms).
    let flow2_deadline = Instant::now() + Duration::from_secs(90);
    let host_curl_code = loop {
        let out = std::process::Command::new("curl")
            .args([
                "-sS",
                "-m",
                "5",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                &format!("http://{}/", pod_ip.trim()),
            ])
            .output()
            .expect("curl runs");
        let code = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if code == "200" {
            break code;
        }
        assert!(
            Instant::now() < flow2_deadline,
            "Flow 2 (host -> pod_ip): expected HTTP 200 within 90s, \
             got code={code:?} stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        std::thread::sleep(Duration::from_secs(2));
    };
    eprintln!("Flow 2: host -> pod_ip OK (HTTP {host_curl_code})");

    // Flow 3 — VM → host gateway. We exec inside the guest VM via
    // the shim's agent (which kubectl exec proxies to). The
    // gateway is whatever address the pod netns's `eth0` has as
    // its `link` route — we grab that from inside the guest by
    // reading the static-ARP'd `10.200.0.1` gateway we configured.
    // A working ping proves both directions of the bridge and the
    // SNAT path are alive.
    let ping_out = kubectl_exec(POD_NAME, &["ping", "-c", "2", "-W", "2", "10.200.0.1"])
        .expect("Flow 3 (VM -> host gateway): kubectl exec ping");
    assert!(
        ping_out.contains("2 received") || ping_out.contains("2 packets received"),
        "Flow 3 (VM -> host gateway): expected 2 received in ping output, got: {ping_out}"
    );
    eprintln!("Flow 3: VM -> 10.200.0.1 (gateway) OK");

    // Flow 4 — VM → cluster Service IP (CoreDNS at 10.43.0.10:53).
    // We use `nc -z` (zero-IO scan): nc exits 0 if the TCP
    // three-way handshake completes, non-zero on RST or timeout.
    // BusyBox nc routes "open" / progress messages to stderr and
    // returns empty stdout on success, so we deliberately ignore
    // stdout content and trust only the exit code via
    // `tcp_open_via_nc`. A successful open proves the full chain:
    // VM eth0 -> bridge -> kernel route -> POSTROUTING SNAT
    // (10.200.0.2 -> pod_ip) -> cni0 -> kube-proxy DNAT (Service
    // IP -> backend pod IP) -> wherever CoreDNS lives. If
    // kube-proxy sees our SNAT'd source incorrectly, the SYN-ACK
    // can't come back and the connect times out.
    assert!(
        tcp_open_via_nc(POD_NAME, "10.43.0.10", "53"),
        "Flow 4 (VM -> Service IP 10.43.0.10:53): TCP connect did not succeed"
    );
    eprintln!("Flow 4: VM -> 10.43.0.10:53 (Service IP) OK");

    // Flow 5 — VM → internet. Pick a stable third-party endpoint
    // (1.1.1.1:443). We're only asserting TCP reachability — no
    // TLS, no HTTP, just that the SYN-ACK comes back.
    assert!(
        tcp_open_via_nc(POD_NAME, "1.1.1.1", "443"),
        "Flow 5 (VM -> internet 1.1.1.1:443): TCP connect did not succeed"
    );
    eprintln!("Flow 5: VM -> 1.1.1.1:443 (internet egress) OK");

    eprintln!("\nAll five spec-10a CNI flows green for {POD_NAME} (pod_ip={pod_ip})\n");

    // Cleanup. Don't fail the test if delete hits a transient
    // kubectl issue — the next run's pre-test cleanup will catch
    // it.
    kubectl_delete_pod(POD_NAME);
}
