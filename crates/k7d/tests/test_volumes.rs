//! internal notes+ 2b.1: kubelet volume support end-to-end.
//!
//! Boots `runtimeClassName: k7` pods with real Kubernetes
//! volumes via `kubectl apply` and asserts the volume contents
//! reach the right paths inside the container — exactly the
//! runtime contract every off-the-shelf workload expects.
//!
//! ## Coverage
//!
//! Chunk 2a (PR #31) shipped:
//! - `configMap` ro at a mount path, RO enforcement
//! - `emptyDir` shared rw between two containers in the same pod
//!
//! Chunk 2b.1 (this file) adds:
//! - `secret` (same materialization shape as configMap — ro)
//! - `downwardAPI` (kubelet writes pod metadata to files)
//! - `projected` (combined sources, including `serviceAccountToken`
//!   which every well-behaved pod uses)
//!
//! Chunk 2b.2 deferred: `hostPath`, `local-path` PVCs (different
//! enumeration path — kubelet doesn't materialize them under
//! `volumes/`).
//!
//! Pattern matches `tests/test_shim.rs` and `tests/test_cni.rs` —
//! `ensure_shim_installed` + `pin_to_local_node` so kubelet
//! schedules these pods onto the local node (the only one with the
//! k7 runtime registered in containerd) and the test is hermetic
//! against the rest of the cluster.
//!
//! Pattern matches `tests/test_shim.rs` and `tests/test_cni.rs` —
//! `ensure_shim_installed` + `pin_to_local_node` so kubelet
//! schedules these pods onto the local node (the only one with the
//! k7 runtime registered in containerd) and the test is hermetic
//! against the rest of the cluster.

use std::time::{Duration, Instant};

mod common;

const POD_CFGMAP: &str = "test-vol-configmap";
const POD_EMPTYDIR: &str = "test-vol-emptydir";
const CONFIGMAP_NAME: &str = "test-vol-configmap-cfg";
const POD_SECRET: &str = "test-vol-secret";
const SECRET_NAME: &str = "test-vol-secret-creds";
const POD_DOWNWARD: &str = "test-vol-downward";
const POD_PROJECTED: &str = "test-vol-projected";
const PROJECTED_CFGMAP: &str = "test-vol-projected-cfg";
const PROJECTED_SECRET: &str = "test-vol-projected-secret";
const POD_DNS: &str = "test-vol-dns";
const POD_HOSTPATH_FILE: &str = "test-vol-hostpath-file";
const POD_HOSTPATH_DIR: &str = "test-vol-hostpath-dir";
const POD_PVC: &str = "test-vol-pvc";
const PVC_NAME: &str = "test-vol-pvc-claim";
const POD_K7D_DISK: &str = "test-vol-k7d-disk";
const POD_K7D_DISK_2: &str = "test-vol-k7d-disk-2";

fn ensure_shim_installed() -> common::LeakGuard {
    use std::process::Command;

    // internal notes, Milestone 2: shared best-effort teardown of orphan
    // virtiofsd/shim processes and stale /tmp/k7d-shim mounts left by
    // earlier tests (replaces the old local cleanup_orphan_k7_processes).
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

/// Graceful pod delete used at the end of every kubectl-driven
/// test in this binary. internal notes, Phase B0 — defence-in-depth on
/// top of the spec-10h product fix that unblocks the volume trio.
///
/// The old `--force --grace-period=0` form **removes the API
/// object immediately** but leaves containerd's node-side sandbox
/// + our shim + virtiofsd children alive to be torn down
/// asynchronously. When the next test's `ensure_shim_installed`
/// then `pkill -9 -f containerd-shim-k7-v1`s (via
/// `common::cleanup_k7_runtime_leaks`), it kills shims containerd
/// still owns, orphaning sandboxes and triggering kubelet's
/// `CreatePodSandbox` retry storm. The retry storm starved later
/// volume pods of virtiofsd socket budget and wedged the node in
/// the original 10g bring-up.
///
/// Graceful semantics:
///   1. `kubectl delete pod <name> --ignore-not-found --wait=true
///      --timeout=30s --grace-period=1` — asks kubelet to
///      terminate the pod with a 1-second `SIGTERM`-to-`SIGKILL`
///      grace window (overrides the pod's default 30 s
///      `terminationGracePeriodSeconds`; the test pods are all
///      `sleep infinity` and don't need a graceful shutdown of
///      their own) and BLOCKS until the API object is gone, which
///      only happens after kubelet has stopped every container and
///      torn the sandbox down via the shim's `Stop` + `Delete`
///      ttrpc handlers. Capping per-pod teardown latency at ~30 s
///      keeps the full `test_volumes` wall-clock under a couple of
///      minutes.
///   2. Poll `kubectl get pod <name>` until it returns `NotFound`
///      as a belt-and-braces check (some kubectl versions return 0
///      from `--wait` before the GET returns NotFound).
///   3. **If** the graceful path times out (rare — only happens if
///      the shim itself is wedged), fall back to `--force
///      --grace-period=0` so the test never hangs forever. The
///      shim teardown is still asynchronous in that case, which is
///      the original bug, but at least we don't deadlock.
///
/// Test-only, best-effort: ignored errors are fine here, the
/// product code's fail-loud rule from internal notes
/// every required volume bind / shim Create on the production
/// path.
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
        // Belt-and-braces: poll until GET returns NotFound. Each
        // iteration is cheap and the loop bounds at ~10 s, which is
        // dwarfed by even a single-pod test's normal wait_for_pod
        // wall-clock budget.
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
        // Graceful delete failed or timed out (shim wedged?).
        // Last-resort force delete so the harness doesn't hang. We
        // intentionally don't `pkill -9` here — the panic-path
        // `LeakGuard` from internal notes, and doing it
        // on every test boundary is what historically triggered the
        // sandbox-state cascade we're trying to avoid.
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

fn kubectl_delete_configmap(name: &str) {
    let _ = std::process::Command::new("kubectl")
        .args(["delete", "configmap", name, "--ignore-not-found"])
        .output();
}

fn kubectl_delete_secret(name: &str) {
    let _ = std::process::Command::new("kubectl")
        .args(["delete", "secret", name, "--ignore-not-found"])
        .output();
}

fn kubectl_delete_pvc(name: &str) {
    let _ = std::process::Command::new("kubectl")
        .args(["delete", "pvc", name, "--ignore-not-found"])
        .output();
}

/// Exec a command in a specific container (defaults to the first
/// container if `container` is `None`). Returns `(exit_code, stdout)`.
fn kubectl_exec_in(pod: &str, container: Option<&str>, cmd: &[&str]) -> (i32, String, String) {
    let mut args: Vec<String> = vec!["exec".into()];
    if let Some(c) = container {
        args.push("-c".into());
        args.push(c.into());
    }
    args.push(pod.into());
    args.push("--".into());
    args.extend(cmd.iter().map(|s| (*s).to_string()));
    let output = std::process::Command::new("kubectl")
        .args(&args)
        .output()
        .expect("kubectl exec runs");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

fn wait_for_pod_running(name: &str, timeout: Duration) -> Result<(), String> {
    let start = Instant::now();
    let deadline = start + timeout;
    while Instant::now() < deadline {
        let phase = std::process::Command::new("kubectl")
            .args(["get", "pod", name, "-o", "jsonpath={.status.phase}"])
            .output()
            .map_err(|e| format!("{e}"))?;
        if String::from_utf8_lossy(&phase.stdout) == "Running" {
            // Also wait for containers Ready so `kubectl exec` works.
            let ready = std::process::Command::new("kubectl")
                .args([
                    "get",
                    "pod",
                    name,
                    "-o",
                    "jsonpath={.status.containerStatuses[*].ready}",
                ])
                .output()
                .map_err(|e| format!("{e}"))?;
            let s = String::from_utf8_lossy(&ready.stdout);
            if !s.is_empty() && s.split_ascii_whitespace().all(|w| w == "true") {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Err(format!("pod {name} not Running+Ready within {timeout:?}"))
}

// ----------------------------------------------------------------
// Tests
// ----------------------------------------------------------------

/// `ConfigMap` mounted ro: the file kubelet wrote on the host must
/// appear at the spec'd container path with the same content, and
/// writes from the container must fail with `EROFS`.
#[test]
fn test_configmap_mount_ro_and_readable() {
    let _leak_guard = ensure_shim_installed();
    kubectl_delete_configmap(CONFIGMAP_NAME);
    kubectl_delete_pod(POD_CFGMAP);
    std::thread::sleep(Duration::from_secs(2));

    // Apply ConfigMap first so kubelet has the source materialized
    // before the pod schedules. `data:` puts the values into
    // discrete files under the volume's mount path.
    kubectl_apply(&format!(
        r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: {CONFIGMAP_NAME}
data:
  greeting: "hello from configmap"
  app.yaml: |
    mode: production
    workers: 4
"#
    ))
    .expect("kubectl apply ConfigMap");

    kubectl_apply(&common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {POD_CFGMAP}
spec:
  runtimeClassName: k7
  containers:
  - name: app
    image: alpine:3.20
    command: ["sleep", "infinity"]
    volumeMounts:
    - name: cfg
      mountPath: /etc/app
      readOnly: true
  volumes:
  - name: cfg
    configMap:
      name: {CONFIGMAP_NAME}
"#
    )))
    .expect("kubectl apply pod");

    wait_for_pod_running(POD_CFGMAP, Duration::from_secs(90))
        .expect("pod should reach Running+Ready");

    // internal notes: configMap rides the block path (packed erofs
    // image on virtio-blk) — the pod must carry ZERO virtiofs shares.
    let vm = common::pod_vm_state(POD_CFGMAP);
    assert_eq!(
        vm.virtiofs_shares, 0,
        "configMap pod must be block-backed (zero virtiofs shares)"
    );
    assert!(
        vm.block_devices >= 3,
        "expected tools + rootfs + packed-RO-volumes erofs devices, got {}",
        vm.block_devices
    );

    // Flow 1: greeting file is readable with the expected content.
    let (rc, stdout, stderr) = kubectl_exec_in(POD_CFGMAP, None, &["cat", "/etc/app/greeting"]);
    assert_eq!(
        rc, 0,
        "cat /etc/app/greeting should succeed: stderr={stderr}"
    );
    assert_eq!(stdout, "hello from configmap");

    // Flow 2: multi-line yaml file mounted correctly.
    let (rc, stdout, _) = kubectl_exec_in(POD_CFGMAP, None, &["cat", "/etc/app/app.yaml"]);
    assert_eq!(rc, 0);
    assert!(
        stdout.contains("workers: 4") && stdout.contains("mode: production"),
        "app.yaml unexpected content: {stdout}"
    );

    // Flow 3: writes to the ro mount must be refused. We use `sh
    // -c` so the failing redirect propagates as a non-zero exit.
    // Either the kernel EROFS or the FUSE-layer denial is fine;
    // we just assert "no, you can't write here".
    let (rc, _, stderr) = kubectl_exec_in(
        POD_CFGMAP,
        None,
        &["sh", "-c", "echo nope > /etc/app/greeting"],
    );
    assert_ne!(
        rc, 0,
        "write to ro ConfigMap mount should have failed; stderr={stderr}"
    );

    // Cleanup.
    kubectl_delete_pod(POD_CFGMAP);
    kubectl_delete_configmap(CONFIGMAP_NAME);
}

/// `emptyDir` shared between two containers in the same pod: the
/// writer's bytes show up in the reader. This is the canonical
/// sidecar-shares-scratch pattern and exercises both the rw share
/// plumbing and the per-pod multi-container OCI mount rewriting
/// (each container's `config.json` independently goes through
/// `copy_and_fix_oci_config` with the same rewrite map).
#[test]
fn test_emptydir_shared_between_two_containers() {
    let _leak_guard = ensure_shim_installed();
    kubectl_delete_pod(POD_EMPTYDIR);
    std::thread::sleep(Duration::from_secs(2));

    kubectl_apply(&common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {POD_EMPTYDIR}
spec:
  runtimeClassName: k7
  containers:
  - name: writer
    image: alpine:3.20
    command: ["sh", "-c", "echo shared-bytes > /shared/msg && sleep infinity"]
    volumeMounts:
    - {{ name: scratch, mountPath: /shared }}
  - name: reader
    image: alpine:3.20
    command: ["sleep", "infinity"]
    volumeMounts:
    - {{ name: scratch, mountPath: /shared }}
  volumes:
  - name: scratch
    emptyDir: {{}}
"#
    )))
    .expect("kubectl apply pod");

    wait_for_pod_running(POD_EMPTYDIR, Duration::from_secs(90))
        .expect("pod should reach Running+Ready");

    // The writer's command races with kubelet's "container started"
    // notification; give the echo a beat to land on disk before the
    // reader reads.
    std::thread::sleep(Duration::from_secs(1));

    let (rc, stdout, stderr) =
        kubectl_exec_in(POD_EMPTYDIR, Some("reader"), &["cat", "/shared/msg"]);
    assert_eq!(
        rc, 0,
        "reader should see writer's file via emptyDir; stderr={stderr}"
    );
    assert_eq!(
        stdout.trim(),
        "shared-bytes",
        "reader should see what writer wrote (stdout={stdout:?})"
    );

    // Reader's writes are also visible to writer — rw is rw both
    // directions, this confirms it's the same backing dir not two
    // independent copies.
    let (rc, _, stderr) = kubectl_exec_in(
        POD_EMPTYDIR,
        Some("reader"),
        &["sh", "-c", "echo reader-was-here > /shared/reply"],
    );
    assert_eq!(
        rc, 0,
        "reader should be able to write to emptyDir: {stderr}"
    );
    let (rc, stdout, _) = kubectl_exec_in(POD_EMPTYDIR, Some("writer"), &["cat", "/shared/reply"]);
    assert_eq!(rc, 0);
    assert_eq!(stdout.trim(), "reader-was-here");

    kubectl_delete_pod(POD_EMPTYDIR);
}

// ----------------------------------------------------------------
// Chunk 2b.1 — Secret, downwardAPI, projected.
//
// Materialization-wise these are identical to ConfigMap (kubelet
// writes files into `/var/lib/kubelet/pods/<uid>/volumes/
// kubernetes.io~<plugin>/<name>/`), so chunk 2a's existing
// enumeration + rewrite path already handles them — the
// `classify_kubelet_plugin` enum was wired for all four
// classes from day one. These tests just exercise the contract
// end-to-end via real kubectl, which is the only way to catch
// "kubelet's actual layout matches what we assumed" surprises.
// ----------------------------------------------------------------

/// `Secret` mounted ro: same shape as ConfigMap but kubelet uses
/// a different plugin dir (`kubernetes.io~secret`). Catches any
/// case where the rewrite map distinguishes between plugins it
/// shouldn't (or vice versa).
#[test]
fn test_secret_mount_ro_and_readable() {
    let _leak_guard = ensure_shim_installed();
    kubectl_delete_secret(SECRET_NAME);
    kubectl_delete_pod(POD_SECRET);
    std::thread::sleep(Duration::from_secs(2));

    kubectl_apply(&format!(
        r#"
apiVersion: v1
kind: Secret
metadata:
  name: {SECRET_NAME}
type: Opaque
stringData:
  api-key: "sk-test-1234567890"
  db-password: "hunter2"
"#
    ))
    .expect("kubectl apply Secret");

    kubectl_apply(&common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {POD_SECRET}
spec:
  runtimeClassName: k7
  containers:
  - name: app
    image: alpine:3.20
    command: ["sleep", "infinity"]
    volumeMounts:
    - name: creds
      mountPath: /run/creds
      readOnly: true
  volumes:
  - name: creds
    secret:
      secretName: {SECRET_NAME}
"#
    )))
    .expect("kubectl apply pod");

    wait_for_pod_running(POD_SECRET, Duration::from_secs(90))
        .expect("pod should reach Running+Ready");

    // The two Secret keys land as files under the mount path.
    let (rc, stdout, stderr) = kubectl_exec_in(POD_SECRET, None, &["cat", "/run/creds/api-key"]);
    assert_eq!(rc, 0, "cat /run/creds/api-key should succeed: {stderr}");
    assert_eq!(stdout, "sk-test-1234567890");

    let (rc, stdout, _) = kubectl_exec_in(POD_SECRET, None, &["cat", "/run/creds/db-password"]);
    assert_eq!(rc, 0);
    assert_eq!(stdout, "hunter2");

    // RO enforcement — same VFS-layer EROFS path as ConfigMap.
    let (rc, _, _) = kubectl_exec_in(
        POD_SECRET,
        None,
        &["sh", "-c", "echo nope > /run/creds/api-key"],
    );
    assert_ne!(rc, 0, "write to ro Secret mount should have failed");

    kubectl_delete_pod(POD_SECRET);
    kubectl_delete_secret(SECRET_NAME);
}

/// `downwardAPI` volume: kubelet writes pod-metadata files into
/// the volume directory based on the `items[].fieldRef` /
/// `items[].resourceFieldRef` projections in the pod spec. The
/// canonical case is "pod name as a file the container can read".
/// Catches the failure mode where kubelet's plugin dir name has
/// drifted (it's `kubernetes.io~downward-api` — note the dash,
/// not an underscore).
#[test]
fn test_downwardapi_pod_name_and_namespace_visible() {
    let _leak_guard = ensure_shim_installed();
    kubectl_delete_pod(POD_DOWNWARD);
    std::thread::sleep(Duration::from_secs(2));

    kubectl_apply(&common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {POD_DOWNWARD}
spec:
  runtimeClassName: k7
  containers:
  - name: app
    image: alpine:3.20
    command: ["sleep", "infinity"]
    volumeMounts:
    - name: dapi
      mountPath: /etc/podinfo
  volumes:
  - name: dapi
    downwardAPI:
      items:
      - path: pod-name
        fieldRef: {{ fieldPath: metadata.name }}
      - path: pod-namespace
        fieldRef: {{ fieldPath: metadata.namespace }}
"#
    )))
    .expect("kubectl apply pod");

    wait_for_pod_running(POD_DOWNWARD, Duration::from_secs(90))
        .expect("pod should reach Running+Ready");

    let (rc, stdout, stderr) =
        kubectl_exec_in(POD_DOWNWARD, None, &["cat", "/etc/podinfo/pod-name"]);
    assert_eq!(rc, 0, "cat /etc/podinfo/pod-name should succeed: {stderr}");
    assert_eq!(stdout.trim(), POD_DOWNWARD);

    let (rc, stdout, _) =
        kubectl_exec_in(POD_DOWNWARD, None, &["cat", "/etc/podinfo/pod-namespace"]);
    assert_eq!(rc, 0);
    assert_eq!(stdout.trim(), "default");

    kubectl_delete_pod(POD_DOWNWARD);
}

/// `projected` volume combining a `configMap` source and a
/// `secret` source into one tree.
///
/// Why this is more than a sum-of-its-parts test: kubelet
/// materializes projected volumes under a SINGLE plugin
/// directory (`kubernetes.io~projected/<name>/`) regardless of
/// how many sources the projection has. The whole projection
/// shows up as one volume from the shim's perspective, not three
/// independent volumes. If the rewrite map or virtiofs share
/// plumbing accidentally treated each source as its own thing,
/// this test would fail with "no such file" on the second source.
///
/// Critically, the projection also implicitly tests the
/// `serviceAccountToken` injection that EVERY default k8s pod
/// receives (kubelet auto-injects a `kube-api-access-*` projected
/// volume on every pod creation). If projected volumes are broken,
/// almost no real-world workload starts cleanly.
#[test]
fn test_projected_combines_configmap_and_secret() {
    let _leak_guard = ensure_shim_installed();
    kubectl_delete_pod(POD_PROJECTED);
    kubectl_delete_configmap(PROJECTED_CFGMAP);
    kubectl_delete_secret(PROJECTED_SECRET);
    std::thread::sleep(Duration::from_secs(2));

    kubectl_apply(&format!(
        r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: {PROJECTED_CFGMAP}
data:
  greeting: "hello from projected cm"
---
apiVersion: v1
kind: Secret
metadata:
  name: {PROJECTED_SECRET}
type: Opaque
stringData:
  token: "tk-projected-001"
"#
    ))
    .expect("kubectl apply ConfigMap + Secret fixtures");

    kubectl_apply(&common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {POD_PROJECTED}
spec:
  runtimeClassName: k7
  containers:
  - name: app
    image: alpine:3.20
    command: ["sleep", "infinity"]
    volumeMounts:
    - name: combined
      mountPath: /etc/combined
      readOnly: true
  volumes:
  - name: combined
    projected:
      sources:
      - configMap:
          name: {PROJECTED_CFGMAP}
          items:
          - key: greeting
            path: cm-greeting
      - secret:
          name: {PROJECTED_SECRET}
          items:
          - key: token
            path: secret-token
"#
    )))
    .expect("kubectl apply pod");

    wait_for_pod_running(POD_PROJECTED, Duration::from_secs(90))
        .expect("pod should reach Running+Ready");

    let (rc, stdout, stderr) =
        kubectl_exec_in(POD_PROJECTED, None, &["cat", "/etc/combined/cm-greeting"]);
    assert_eq!(
        rc, 0,
        "cat /etc/combined/cm-greeting should succeed: {stderr}"
    );
    assert_eq!(stdout.trim(), "hello from projected cm");

    let (rc, stdout, _) =
        kubectl_exec_in(POD_PROJECTED, None, &["cat", "/etc/combined/secret-token"]);
    assert_eq!(rc, 0);
    assert_eq!(stdout.trim(), "tk-projected-001");

    kubectl_delete_pod(POD_PROJECTED);
    kubectl_delete_configmap(PROJECTED_CFGMAP);
    kubectl_delete_secret(PROJECTED_SECRET);
}

/// DNS in the guest VM — the long-deferred spec-10a follow-up.
///
/// Kubelet writes per-pod `/etc/hosts` to `/var/lib/kubelet/pods/
/// <uid>/etc-hosts` and containerd CRI writes per-sandbox
/// `/etc/resolv.conf` + `/etc/hostname` to its own sandbox dir,
/// then bind-mounts both into the workload container at the
/// canonical container paths. Pre-10b.1 the shim's strip pass
/// dropped these silently, so any DNS lookup inside the guest
/// failed and the container saw `/etc/resolv.conf: No such file
/// or directory`.
///
/// internal notes's etc-files whitelist
/// ([`k7d::volumes::PodVolumes::add_etc_files_for_workload`])
/// bind-mounts each of those host paths into the per-pod
/// `volumes-ro` scratch tree and inserts a rewrite-map entry, so
/// the strip pass's `/mnt/...` carve-out keeps them in the
/// surviving mount list. This test exercises the whole chain by:
///
/// 1. Reading `/etc/resolv.conf` inside the guest — must exist
///    with a `nameserver` line (CoreDNS at the cluster IP).
/// 2. Reading `/etc/hostname` inside the guest — must match the
///    pod name.
/// 3. Resolving `kubernetes.default.svc.cluster.local` from
///    inside the guest — proves the in-cluster DNS path
///    end-to-end (resolver knows the nameserver, nameserver
///    reachable via the spec-10a CNI path, CoreDNS resolves the
///    name to a Service IP).
///
/// Why this matters: the k3s-agent sidecar pattern from spec
/// 10b's design needs in-guest DNS to find the inner control
/// plane's API server by name. Without 10b.1, the inner cluster
/// can't form. internal notes's milestone-11 end-to-end test
/// (boot inner k3s + fork it) is gated on this test passing.
#[test]
fn test_dns_resolution_inside_guest() {
    let _leak_guard = ensure_shim_installed();
    kubectl_delete_pod(POD_DNS);
    std::thread::sleep(Duration::from_secs(2));

    kubectl_apply(&common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {POD_DNS}
spec:
  runtimeClassName: k7
  containers:
  - name: probe
    image: alpine:3.20
    command: ["sleep", "infinity"]
"#
    )))
    .expect("kubectl apply pod");

    wait_for_pod_running(POD_DNS, Duration::from_secs(90)).expect("pod should reach Running+Ready");

    // Step 1: /etc/resolv.conf is visible AND contains a
    // `nameserver` directive.
    let (rc, resolv, stderr) = kubectl_exec_in(POD_DNS, None, &["cat", "/etc/resolv.conf"]);
    assert_eq!(
        rc, 0,
        "cat /etc/resolv.conf should succeed inside guest: stderr={stderr}"
    );
    assert!(
        resolv.lines().any(|l| l.starts_with("nameserver ")),
        "/etc/resolv.conf must have at least one nameserver, got: {resolv}"
    );
    eprintln!("guest /etc/resolv.conf:\n{resolv}");

    // Step 2: /etc/hostname matches the pod name. kubelet sets
    // hostname to the pod name unless `spec.hostname` overrides it.
    let (rc, hostname, _) = kubectl_exec_in(POD_DNS, None, &["cat", "/etc/hostname"]);
    assert_eq!(rc, 0);
    assert_eq!(
        hostname.trim(),
        POD_DNS,
        "guest /etc/hostname should be the pod name, got: {hostname:?}"
    );

    // Step 3: in-cluster DNS resolution works end-to-end. Use
    // `nslookup` from busybox alpine — exits non-zero if the
    // resolver couldn't reach the nameserver OR the name didn't
    // resolve. Either way, that's a real DNS failure for the
    // workload's purposes.
    //
    // `kubernetes.default.svc.cluster.local` always exists in a
    // healthy cluster (CoreDNS auto-serves it as the API server
    // Service). If this resolves, every other k8s in-cluster
    // name resolution path also works.
    let (rc, stdout, stderr) = kubectl_exec_in(
        POD_DNS,
        None,
        &["nslookup", "kubernetes.default.svc.cluster.local"],
    );
    eprintln!("nslookup stdout:\n{stdout}\nnslookup stderr:\n{stderr}");
    assert_eq!(
        rc, 0,
        "nslookup kubernetes.default.svc.cluster.local must succeed inside the guest \
         (this is the cluster-DNS unblock check for internal notes's k3s-agent sidecar \
         pattern)"
    );
    // The output should contain the Service IP (10.43.0.1 by
    // default for k3s/flannel — but we don't pin the IP, just
    // verify it parsed to something Address-looking).
    assert!(
        stdout.contains("Address") || stdout.contains("Server"),
        "nslookup output should mention an Address or Server line: {stdout}"
    );

    kubectl_delete_pod(POD_DNS);
}

// ----------------------------------------------------------------
// Chunk 2b.2 — hostPath + local-path PVC.
//
// hostPath volumes are user-supplied bind mounts of arbitrary host
// paths. Unlike ConfigMap/Secret/etc., kubelet doesn't materialize
// them under `/var/lib/kubelet/pods/<uid>/volumes/` — it just emits
// an OCI bind with the user's path as `source`. The chunk-2b.2
// enumerator in `PodVolumes::add_hostpath_mounts_for_workload`
// walks workload mounts at Create time and binds anything that
// isn't otherwise accounted for.
// ----------------------------------------------------------------

/// `hostPath` mounting a single host FILE read-only. The container
/// reads the host content; writes are refused.
///
/// This is the smallest possible hostPath surface: a single regular
/// file. internal notes� exercises the
/// file-staging branch of `prepare_ro_hostpath_images` (mkfs.erofs
/// packs directories, so the file is staged into one first).
#[test]
fn test_hostpath_file_ro() {
    let _leak_guard = ensure_shim_installed();
    kubectl_delete_pod(POD_HOSTPATH_FILE);
    std::thread::sleep(Duration::from_secs(2));

    // Per-test host file under /tmp so concurrent test runs and
    // node restarts don't collide. PID suffix keeps it unique.
    let host_path = format!("/tmp/k7d-test-hostpath-file-{}.txt", std::process::id());
    let content = "host-side-content\n";
    std::fs::write(&host_path, content).expect("write host fixture file");

    kubectl_apply(&common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {POD_HOSTPATH_FILE}
spec:
  runtimeClassName: k7
  containers:
  - name: app
    image: alpine:3.20
    command: ["sleep", "infinity"]
    volumeMounts:
    - name: hp
      mountPath: /host/file.txt
      readOnly: true
  volumes:
  - name: hp
    hostPath:
      path: {host_path}
      type: File
"#
    )))
    .expect("kubectl apply pod");

    wait_for_pod_running(POD_HOSTPATH_FILE, Duration::from_secs(90))
        .expect("pod should reach Running+Ready");

    // internal notes: a `readOnly: true` hostPath rides the block
    // path — the file is staged and packed into a cached erofs image
    // on virtio-blk, so the pod carries ZERO virtiofs shares and
    // stays CoW-forkable. Asserted loudly so a silent regression to
    // the virtiofs fallback (slow-fork) is caught.
    let vm = common::pod_vm_state(POD_HOSTPATH_FILE);
    assert_eq!(
        vm.virtiofs_shares, 0,
        "RO hostPath must ride an erofs image on virtio-blk, not the virtiofs fallback"
    );
    assert!(
        vm.block_devices >= 3,
        "expected tools + rootfs + RO-hostPath erofs devices, got {}",
        vm.block_devices
    );

    // Host content visible inside the container at the requested
    // mount path (via the erofs image's guest mount).
    let (rc, stdout, stderr) = kubectl_exec_in(POD_HOSTPATH_FILE, None, &["cat", "/host/file.txt"]);
    assert_eq!(
        rc, 0,
        "cat /host/file.txt inside container should succeed: {stderr}"
    );
    assert_eq!(stdout, content);

    // RO enforced — erofs is a read-only filesystem; the write dies
    // with EROFS inside the guest.
    let (rc, _, _) = kubectl_exec_in(
        POD_HOSTPATH_FILE,
        None,
        &["sh", "-c", "echo nope > /host/file.txt"],
    );
    assert_ne!(rc, 0, "write to ro hostPath should have failed");

    // Cleanup.
    kubectl_delete_pod(POD_HOSTPATH_FILE);
    let _ = std::fs::remove_file(&host_path);
}

/// `hostPath` mounting a host DIRECTORY read-write. Container
/// writes a file, host reads it back.
///
/// Exercises the dir→dir `mount --bind` path AND the rw scratch-
/// tree placement (chunk 2a's `host_volumes_rw` instead of
/// `host_volumes_ro`).
#[test]
fn test_hostpath_directory_rw() {
    let _leak_guard = ensure_shim_installed();
    kubectl_delete_pod(POD_HOSTPATH_DIR);
    std::thread::sleep(Duration::from_secs(2));

    let host_dir = format!("/tmp/k7d-test-hostpath-dir-{}", std::process::id());
    let _ = std::fs::remove_dir_all(&host_dir);
    std::fs::create_dir_all(&host_dir).expect("mkdir host fixture dir");
    std::fs::write(format!("{host_dir}/from-host.txt"), "pre-existing\n")
        .expect("seed file from host");

    kubectl_apply(&common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {POD_HOSTPATH_DIR}
spec:
  runtimeClassName: k7
  containers:
  - name: app
    image: alpine:3.20
    command: ["sleep", "infinity"]
    volumeMounts:
    - name: hp
      mountPath: /shared
  volumes:
  - name: hp
    hostPath:
      path: {host_dir}
      type: Directory
"#
    )))
    .expect("kubectl apply pod");

    wait_for_pod_running(POD_HOSTPATH_DIR, Duration::from_secs(90))
        .expect("pod should reach Running+Ready");

    // internal notes: hostPath RW = explicit virtiofs fallback,
    // slow-fork (asserted loudly; see test_hostpath_file_ro).
    let vm = common::pod_vm_state(POD_HOSTPATH_DIR);
    assert_eq!(
        vm.virtiofs_shares, 2,
        "hostPath-RW pod must carry the two explicit virtiofs fallback shares"
    );

    // Host → container: seeded file shows up.
    let (rc, stdout, _) =
        kubectl_exec_in(POD_HOSTPATH_DIR, None, &["cat", "/shared/from-host.txt"]);
    assert_eq!(rc, 0);
    assert_eq!(stdout, "pre-existing\n");

    // Container → host: write inside the container, read on host.
    let (rc, _, stderr) = kubectl_exec_in(
        POD_HOSTPATH_DIR,
        None,
        &[
            "sh",
            "-c",
            "echo from-container > /shared/from-container.txt",
        ],
    );
    assert_eq!(
        rc, 0,
        "container should be able to write to rw hostPath dir: {stderr}"
    );
    let host_content = std::fs::read_to_string(format!("{host_dir}/from-container.txt"))
        .expect("host should see container's write");
    assert_eq!(host_content.trim(), "from-container");

    kubectl_delete_pod(POD_HOSTPATH_DIR);
    let _ = std::fs::remove_dir_all(&host_dir);
}

/// `local-path` PVC — k3s' default storage class. Backed by
/// `hostPath` mounts under `/var/lib/rancher/k3s/storage/<pvc>/`,
/// which is the path the chunk-2b.2 `add_hostpath_mounts_for_workload`
/// enumerator carves out from the CRI-internal filter
/// (`is_cri_internal_source`'s `/var/lib/rancher/k3s/storage/`
/// special case).
///
/// **This is the chunk-2b.2 closer test**: it proves the whole
/// volume-support pipeline composes for the de facto "Kubernetes
/// stateful workload" pattern (PVC + PV + StorageClass), and is
/// the test the milestone-11 "boot inner k3s + fork it"
/// integration depends on (k3s itself stores etcd / leader-
/// election state on local-path PVCs in single-node setups).
#[test]
fn test_local_path_pvc_works() {
    let _leak_guard = ensure_shim_installed();
    kubectl_delete_pod(POD_PVC);
    kubectl_delete_pvc(PVC_NAME);
    std::thread::sleep(Duration::from_secs(2));

    kubectl_apply(&format!(
        r#"
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: {PVC_NAME}
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 50Mi
  storageClassName: local-path
"#
    ))
    .expect("kubectl apply PVC");

    kubectl_apply(&common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {POD_PVC}
spec:
  runtimeClassName: k7
  containers:
  - name: app
    image: alpine:3.20
    command: ["sh", "-c", "echo pvc-bytes > /data/marker && sleep infinity"]
    volumeMounts:
    - name: d
      mountPath: /data
  volumes:
  - name: d
    persistentVolumeClaim:
      claimName: {PVC_NAME}
"#
    )))
    .expect("kubectl apply pod");

    // local-path PVC bind can take longer than a normal pod boot
    // because `local-path-provisioner` runs a helper pod to
    // create the backing directory. Give it 180 s.
    wait_for_pod_running(POD_PVC, Duration::from_secs(180))
        .expect("pod should reach Running+Ready");

    // internal notes: local-path PVCs are hostPath-backed
    // (arbitrary host dirs under /var/lib/rancher/k3s/storage/) —
    // the explicit virtiofs fallback, slow-fork.
    let vm = common::pod_vm_state(POD_PVC);
    assert_eq!(
        vm.virtiofs_shares, 2,
        "local-path PVC pod must be on the explicit virtiofs fallback"
    );

    // Give the writer's `echo` a beat after Ready.
    std::thread::sleep(Duration::from_secs(2));

    let (rc, stdout, stderr) = kubectl_exec_in(POD_PVC, None, &["cat", "/data/marker"]);
    assert_eq!(
        rc, 0,
        "PVC content should be readable inside the container: {stderr}"
    );
    assert_eq!(stdout.trim(), "pvc-bytes");

    // Round-trip write to prove rw works end-to-end.
    let (rc, _, stderr) = kubectl_exec_in(
        POD_PVC,
        None,
        &[
            "sh",
            "-c",
            "echo extra >> /data/marker && wc -l /data/marker",
        ],
    );
    assert_eq!(rc, 0, "container should be able to append to PVC: {stderr}");

    kubectl_delete_pod(POD_PVC);
    kubectl_delete_pvc(PVC_NAME);
}

/// internal notes: k7d-provisioned RWO disk volume. A hostPath under
/// `/var/lib/k7d/disks/<name>` opts into a raw ext4 image on the
/// reflink loopback XFS attached read-write as a virtio-blk device —
/// NOT a virtiofs share, so the pod stays on the CoW fork path.
/// The image outlives the pod: a second pod mounting the same name
/// sees the first pod's data (the RWO "PVC outlives the pod"
/// semantic, statically provisioned).
#[test]
fn test_k7d_disk_rwo_volume_block_backed_and_persistent() {
    let _leak_guard = ensure_shim_installed();
    kubectl_delete_pod(POD_K7D_DISK);
    kubectl_delete_pod(POD_K7D_DISK_2);
    std::thread::sleep(Duration::from_secs(2));

    // Fresh volume per run: remove the backing image AND the
    // convention dir kubelet's DirectoryOrCreate makes.
    let vol_name = format!("testdisk-{}", std::process::id());
    let _ = std::fs::remove_file(format!("/var/lib/k7d/disks/{vol_name}.img"));
    let _ = std::fs::remove_dir_all(format!("/var/lib/k7d/disks/{vol_name}"));

    let pod_yaml = |pod: &str, cmd: &str| {
        common::pin_to_local_node(&format!(
            r#"
apiVersion: v1
kind: Pod
metadata:
  name: {pod}
spec:
  runtimeClassName: k7
  containers:
  - name: app
    image: alpine:3.20
    command: ["sh", "-c", "{cmd}"]
    volumeMounts:
    - name: disk
      mountPath: /data
  volumes:
  - name: disk
    hostPath:
      path: /var/lib/k7d/disks/{vol_name}
      type: DirectoryOrCreate
"#
        ))
    };

    kubectl_apply(&pod_yaml(
        POD_K7D_DISK,
        "echo disk-bytes > /data/marker && sleep infinity",
    ))
    .expect("kubectl apply pod 1");
    wait_for_pod_running(POD_K7D_DISK, Duration::from_secs(90))
        .expect("pod 1 should reach Running+Ready");

    // Block-backed, not virtiofs: the k7d disk must NOT force the
    // fallback (that's the whole point of the convention).
    let vm = common::pod_vm_state(POD_K7D_DISK);
    assert_eq!(
        vm.virtiofs_shares, 0,
        "k7d disk volume must be a virtio-blk ext4 image, not a virtiofs share"
    );
    assert!(
        vm.block_devices >= 3,
        "expected tools + rootfs + disk devices, got {}",
        vm.block_devices
    );

    std::thread::sleep(Duration::from_secs(2));
    let (rc, stdout, stderr) = kubectl_exec_in(POD_K7D_DISK, None, &["cat", "/data/marker"]);
    assert_eq!(rc, 0, "read own write on the k7d disk: {stderr}");
    assert_eq!(stdout.trim(), "disk-bytes");

    // The backing image exists on the loopback XFS.
    assert!(
        std::path::Path::new(&format!("/var/lib/k7d/disks/{vol_name}.img")).exists(),
        "ext4 backing image should exist under /var/lib/k7d/disks"
    );

    // Persistence: pod 2 reattaches the same image and reads pod 1's
    // data (ext4 on the image, untouched by pod teardown).
    kubectl_delete_pod(POD_K7D_DISK);
    kubectl_apply(&pod_yaml(POD_K7D_DISK_2, "sleep infinity")).expect("kubectl apply pod 2");
    wait_for_pod_running(POD_K7D_DISK_2, Duration::from_secs(90))
        .expect("pod 2 should reach Running+Ready");
    let (rc, stdout, stderr) = kubectl_exec_in(POD_K7D_DISK_2, None, &["cat", "/data/marker"]);
    assert_eq!(rc, 0, "pod 2 should see pod 1's data: {stderr}");
    assert_eq!(stdout.trim(), "disk-bytes");

    kubectl_delete_pod(POD_K7D_DISK_2);
    let _ = std::fs::remove_file(format!("/var/lib/k7d/disks/{vol_name}.img"));
    let _ = std::fs::remove_dir_all(format!("/var/lib/k7d/disks/{vol_name}"));
}
