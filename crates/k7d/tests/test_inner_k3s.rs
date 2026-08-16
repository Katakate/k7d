//! Inner k3s / sidecar CRI socket over emptyDir.
//!
//! Two containers share `/cri` via emptyDir; sidecar runs a
//! real containerd; main talks to it with `ctr --address /cri/containerd.sock`.
//!
//! The main container runs a full `k3s server` against the
//! sidecar containerd (`--container-runtime-endpoint`) and the inner node
//! goes Ready.
//!
//! Three outer pods (same `k7d.katakate.org/cluster-id`,
//! `fork-vm-index` 0/1/2 → guest IPs 10.200.0.2/.3/.4 on one shared L2
//! bridge) run a 3-node inner cluster — `k3s server` + two `k3s agent`s —
//! with flannel host-gw and kube-proxy enabled on the netfilter/veth/
//! bridge-capable guest kernel, and an inner pause pod on an agent node
//! is reachable from the server node.
//!
//! Adopt the live three-pod cluster as a `ClusterSnapshotTree`
//! root via `TreeAdoptCluster`, warm-fork it under
//! `FORK_INNER_K3S_CLUSTER_3VM` while a host-side TLS probe against the
//! source inner API server stays alive, and assert the fork shows 3
//! Ready nodes at the same guest IPs.
//!
//! Same adopt + fork, but driven by kubectl — a trigger
//! pod carrying the `k7d.katakate.org/tree-*` annotations makes the
//! shim call `TreeAdoptCluster` + `TreeFork` during its sandbox
//! Create; the daemon socket is only used for discovery/teardown.

mod common;

use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use k7d::control::{Client, Request, Response};
use k7d::latency::FORK_INNER_K3S_CLUSTER_3VM;
use k7d::tree::TreeBudget;

/// Pinned rancher/k3s image that ships `/bin/containerd` + `/bin/ctr`.
/// Digested so the test never floats on `:latest`.
const K3S_IMAGE: &str = "docker.io/rancher/k3s:v1.32.5-k3s1@sha256:b75eac801bbc91b4584769c840f346683c7740d72f83e630088370f8e1eb2c8a";

const POD_NAME: &str = "test-inner-k3s-cri-emptydir";

/// / — memory limit of the `k3s server` container.
/// A full k3s server (apiserver + kine/sqlite + scheduler +
/// controller-manager + kubelet) plus the in-guest tmpfs holding its data
/// dir does not fit the 256 MB BestEffort default; the floor here is
/// >= 2 Gi of VM budget. Adopt adds ~300 MB: the k3s binary
/// is copied to tmpfs so warm forks never fault it in from virtiofs
/// (see `inner3_pod_yaml`).
const INNER_K3S_MEMORY_MB: u32 = 2560;
/// Memory limit of the containerd sidecar (+192 MB tmpfs for the
/// containerd + runc-shim binaries, same warm-fork reason). Pod-level
/// sandbox memory (10c) is the sum of container limits, so the VM boots
/// with `2560 + 640 + 64 MB` overhead = 3264 MB.
const INNER_K3S_SIDECAR_MEMORY_MB: u32 = 640;

const K3S_POD_NAME: &str = "test-inner-k3s-single-node";

// ──: 3-node inner cluster ──

/// Shared cluster identity: all three outer pods carry this
/// `k7d.katakate.org/cluster-id`, so the k7d daemon puts their TAPs on
/// one `k7-br-…` bridge and each guest keeps its sticky
/// `10.200.0.{2 + vm_index}` IP (cluster mode).
const INNER3_CLUSTER_ID: &str = "inner3";
/// Pre-shared k3s join token (test-only cluster on an isolated bridge).
const INNER3_TOKEN: &str = "k7-inner3-token";
/// Outer pod names, indexed by `vm_index`.
const INNER3_PODS: [&str; 3] = [
    "test-inner-k3s-3n-server",
    "test-inner-k3s-3n-agent-0",
    "test-inner-k3s-3n-agent-1",
];
/// Inner node names, indexed by `vm_index`.
const INNER3_NODES: [&str; 3] = ["inner-server", "inner-agent-0", "inner-agent-1"];
/// Stable guest IPs on the shared bridge, indexed by `vm_index`.
const INNER3_GUEST_IPS: [&str; 3] = ["10.200.0.2", "10.200.0.3", "10.200.0.4"];

/// Sandbox/pause image for the *inner* containerd. The guests sit on an
/// isolated L2 bridge with no registry access, so the test stages this
/// image as an airgap tar (exported from the host's containerd) on a
/// hostPath the sidecar imports at startup. Digest-pinned like
/// [`K3S_IMAGE`].
const INNER3_PAUSE_IMAGE: &str = "docker.io/rancher/mirrored-pause:3.6@sha256:74c4244427b7312c5b901fe0f67cbc53683d06f4f24c6faee65d4182bf0fa893";
/// The un-digested ref the inner containerd config + inner pod specs
/// use (`ctr images import` preserves the tag from the export).
const INNER3_PAUSE_REF: &str = "docker.io/rancher/mirrored-pause:3.6";
/// Host directory (hostPath-mounted into the sidecars) holding the
/// airgap `pause.tar`. dirties via a pause Deployment + API
/// churn (needs guest `CONFIG_CFS_BANDWIDTH` — CHALLENGES #51).
const INNER3_AIRGAP_DIR: &str = "/tmp/k7-inner3-airgap";

fn ensure_shim_installed() -> common::LeakGuard {
    common::cleanup_k7_runtime_leaks();

    let shim_src = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("target/release/containerd-shim-k7-v1");

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
        thread::sleep(Duration::from_millis(500));
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
                child
                    .stdin
                    .as_mut()
                    .unwrap()
                    .write_all(
                        b"apiVersion: node.k8s.io/v1\nkind: RuntimeClass\nmetadata:\n  name: k7\nhandler: k7\n",
                    )
                    .unwrap();
                child.wait()
            })
            .expect("create RuntimeClass");
    }

    common::ensure_k7d_daemon_running();
    common::LeakGuard
}

fn kubectl_apply(yaml: &str) {
    let status = Command::new("kubectl")
        .args(["apply", "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(yaml.as_bytes())?;
            }
            child.wait_with_output()
        })
        .expect("kubectl apply failed to run");
    assert!(
        status.status.success(),
        "kubectl apply failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
}

fn kubectl_delete_pod(name: &str) {
    let _ = Command::new("kubectl")
        .args(["delete", "pod", name, "--ignore-not-found", "--wait=false"])
        .output();
}

/// `kubectl exec` with a hard 120 s wall clock. kubectl has no client
/// timeout of its own: one wedged exec stream (seen once against a
/// heavily loaded 1-vCPU inner-k3s guest) blocks a poll loop forever
/// instead of surfacing as an `Err` the caller can retry.
fn kubectl_exec_in(pod: &str, container: &str, cmd: &str) -> Result<String, String> {
    let output = Command::new("timeout")
        .args([
            "120", "kubectl", "exec", pod, "-c", container, "--", "sh", "-c", cmd,
        ])
        .output()
        .map_err(|e| format!("kubectl exec failed: {e}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(format!(
            "exit {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// [`kubectl_exec_in`] with a few retries — for one-shot queries whose
/// single exec stream may time out against a busy guest.
fn kubectl_exec_retry(
    pod: &str,
    container: &str,
    cmd: &str,
    attempts: u32,
) -> Result<String, String> {
    let mut last = Err("no attempts".to_string());
    for _ in 0..attempts {
        last = kubectl_exec_in(pod, container, cmd);
        if last.is_ok() {
            return last;
        }
        thread::sleep(Duration::from_secs(2));
    }
    last
}

fn wait_for_pod_running(name: &str, timeout: Duration) {
    let start = Instant::now();
    loop {
        let output = Command::new("kubectl")
            .args(["get", "pod", name, "-o", "jsonpath={.status.phase}"])
            .output()
            .expect("kubectl get pod");
        let phase = String::from_utf8_lossy(&output.stdout);
        if phase == "Running" {
            return;
        }
        if start.elapsed() > timeout {
            let describe = Command::new("kubectl")
                .args(["describe", "pod", name])
                .output()
                .expect("kubectl describe");
            panic!(
                "pod {name} not Running after {timeout:?} (phase={phase}):\n{}",
                String::from_utf8_lossy(&describe.stdout)
            );
        }
        thread::sleep(Duration::from_secs(2));
    }
}

/// Warm the node image cache so k7 pods never race an image pull.
fn pull_k3s_image() {
    let pull = Command::new("ctr")
        .args(["-n", "k8s.io", "images", "pull", K3S_IMAGE])
        .output()
        .expect("ctr images pull");
    assert!(
        pull.status.success(),
        "failed to pull {K3S_IMAGE}: {}",
        String::from_utf8_lossy(&pull.stderr)
    );
}

/// Sidecar containerd CRI socket via emptyDir.
#[test]
fn test_sidecar_containerd_socket_via_emptydir() {
    let _leak_guard = ensure_shim_installed();
    pull_k3s_image();

    kubectl_delete_pod(POD_NAME);
    thread::sleep(Duration::from_secs(2));

    // Sidecar: real containerd listening on the shared emptyDir socket.
    // Main: wait for the socket, then `ctr version` against it and write
    // a marker file so the host can poll without scraping container logs.
    // Combined memory limits = 1Gi (/ 10c floor).
    //
    // containerd's root must be tmpfs (bolt databases need writable shared
    // mmap, which virtiofs `--cache never` rejects with ENODEV) and `lo`
    // must be up (the CRI stream server binds 127.0.0.1) — see
    // CHALLENGES.md.
    let yaml = common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {POD_NAME}
spec:
  runtimeClassName: k7
  restartPolicy: Never
  containers:
  - name: containerd
    image: {K3S_IMAGE}
    imagePullPolicy: IfNotPresent
    command: ["/bin/sh", "-c"]
    args:
    - |
      set -e
      ip link set lo up
      mkdir -p /var/lib/containerd /run/containerd /cri
      mount -t tmpfs -o size=256m tmpfs /var/lib/containerd
      mount -t tmpfs -o size=64m tmpfs /run/containerd
      mkdir -p /sys/fs/cgroup/init
      xargs -rn1 < /sys/fs/cgroup/cgroup.procs > /sys/fs/cgroup/init/cgroup.procs || true
      sed -e 's/ / +/g' -e 's/^/+/' < /sys/fs/cgroup/cgroup.controllers \
        > /sys/fs/cgroup/cgroup.subtree_control
      exec /bin/containerd \
        --address /cri/containerd.sock \
        --root /var/lib/containerd \
        --state /run/containerd
    securityContext:
      privileged: true
    resources:
      limits:
        memory: 512Mi
    volumeMounts:
    - name: cri
      mountPath: /cri
  - name: main
    image: {K3S_IMAGE}
    imagePullPolicy: IfNotPresent
    command: ["/bin/sh", "-c"]
    args:
    - |
      set -e
      for i in $(seq 1 90); do
        if [ -S /cri/containerd.sock ]; then
          break
        fi
        sleep 1
      done
      test -S /cri/containerd.sock
      /bin/ctr --address /cri/containerd.sock version > /cri/ctr-version.txt
      echo CTR_OK > /cri/ctr-ok
      sleep infinity
    resources:
      limits:
        memory: 512Mi
    volumeMounts:
    - name: cri
      mountPath: /cri
  volumes:
  - name: cri
    emptyDir: {{}}
"#
    ));

    kubectl_apply(&yaml);

    wait_for_pod_running(POD_NAME, Duration::from_secs(180));

    // Poll the marker written into the shared emptyDir.
    let start = Instant::now();
    let mut last_err;
    loop {
        match kubectl_exec_in(
            POD_NAME,
            "main",
            "cat /cri/ctr-ok 2>/dev/null && cat /cri/ctr-version.txt",
        ) {
            Ok(text) if text.contains("CTR_OK") => {
                // "Server:" only appears when ctr actually connected over
                // the shared socket — "Client:" is printed even when the
                // connect fails, which let an earlier version of this
                // test pass with a dead containerd (see CHALLENGES.md).
                assert!(
                    text.contains("Server:"),
                    "ctr version output missing Server section (socket connect failed?):\n{text}"
                );
                kubectl_delete_pod(POD_NAME);
                return;
            }
            Ok(text) => last_err = format!("unexpected marker content: {text}"),
            Err(e) => last_err = e,
        }
        if start.elapsed() > Duration::from_secs(120) {
            let cd_logs = Command::new("kubectl")
                .args(["logs", POD_NAME, "-c", "containerd", "--tail=80"])
                .output()
                .expect("kubectl logs containerd");
            let main_logs = Command::new("kubectl")
                .args(["logs", POD_NAME, "-c", "main", "--tail=80"])
                .output()
                .expect("kubectl logs main");
            kubectl_delete_pod(POD_NAME);
            panic!(
                "main never wrote /cri/ctr-ok: {last_err}\ncontainerd logs:\n{}\nmain logs:\n{}",
                String::from_utf8_lossy(&cd_logs.stdout),
                String::from_utf8_lossy(&main_logs.stdout)
            );
        }
        thread::sleep(Duration::from_secs(2));
    }
}

/// Single-node inner k3s goes Ready against the
/// sidecar containerd's CRI socket over the shared `/cri` emptyDir.
///
/// Guest-environment constraints encoded in the entrypoints (found the
/// hard way; see CHALLENGES.md):
/// - Every shared filesystem in the guest is virtiofs with `--cache never`,
///   which rejects writable shared mmap (ENODEV). containerd's bolt
///   databases and kine's sqlite WAL both need it, so containerd's root
///   and k3s's data dir live on in-guest tmpfs.
/// - The guest kernel has no overlayfs -> containerd uses the `native`
///   snapshotter.
/// - The guest kernel has no netfilter -> flannel and kube-proxy are
///   disabled; a static bridge CNI conf on `/cri/cni/net.d` satisfies the
///   CRI NetworkReady condition (no inner pods are scheduled here; real
///   inner-pod networking comes later).
/// - The guest brings up `eth0` but leaves `lo` down; both containerd's
///   CRI stream server and the k3s apiserver bind 127.0.0.1.
/// - kubelet needs `/dev/kmsg` and a mounted cgroup2 hierarchy with the
///   cpuset controller (CONFIG_CPUSETS in the guest kernel).
#[test]
fn test_inner_k3s_single_node_ready() {
    let _leak_guard = ensure_shim_installed();
    pull_k3s_image();

    kubectl_delete_pod(K3S_POD_NAME);
    thread::sleep(Duration::from_secs(2));

    let yaml = common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {K3S_POD_NAME}
spec:
  runtimeClassName: k7
  restartPolicy: Never
  containers:
  - name: containerd
    image: {K3S_IMAGE}
    imagePullPolicy: IfNotPresent
    command: ["/bin/sh", "-c"]
    args:
    - |
      set -x
      ip link set lo up
      mkdir -p /var/lib/containerd /run/containerd /cri/cni/net.d
      mount -t tmpfs -o size=256m tmpfs /var/lib/containerd || exit 1
      mount -t tmpfs -o size=64m tmpfs /run/containerd || exit 1
      mkdir -p /sys/fs/cgroup/init
      xargs -rn1 < /sys/fs/cgroup/cgroup.procs > /sys/fs/cgroup/init/cgroup.procs || true
      sed -e 's/ / +/g' -e 's/^/+/' < /sys/fs/cgroup/cgroup.controllers \
        > /sys/fs/cgroup/cgroup.subtree_control || exit 1
      cat > /cri/cni/net.d/10-inner.conflist <<EOF
      {{
        "cniVersion": "1.0.0",
        "name": "inner",
        "plugins": [
          {{
            "type": "bridge",
            "bridge": "cni0",
            "isGateway": true,
            "ipMasq": false,
            "ipam": {{
              "type": "host-local",
              "ranges": [[{{"subnet": "10.60.0.0/24"}}]]
            }}
          }}
        ]
      }}
      EOF
      cat > /tmp/containerd-config.toml <<EOF
      version = 2
      [plugins."io.containerd.grpc.v1.cri".containerd]
        snapshotter = "native"
      [plugins."io.containerd.grpc.v1.cri".cni]
        conf_dir = "/cri/cni/net.d"
        bin_dir = "/bin"
      EOF
      exec /bin/containerd \
        --config /tmp/containerd-config.toml \
        --address /cri/containerd.sock \
        --root /var/lib/containerd \
        --state /run/containerd
    securityContext:
      privileged: true
    resources:
      limits:
        memory: {INNER_K3S_SIDECAR_MEMORY_MB}Mi
    volumeMounts:
    - name: cri
      mountPath: /cri
  - name: k3s
    image: {K3S_IMAGE}
    imagePullPolicy: IfNotPresent
    command: ["/bin/sh", "-c"]
    args:
    - |
      set -x
      ip link set lo up
      mkdir -p /var/lib/rancher /var/lib/kubelet
      mkdir -p /sys/fs/cgroup/init
      xargs -rn1 < /sys/fs/cgroup/cgroup.procs > /sys/fs/cgroup/init/cgroup.procs || true
      sed -e 's/ / +/g' -e 's/^/+/' < /sys/fs/cgroup/cgroup.controllers \
        > /sys/fs/cgroup/cgroup.subtree_control || exit 1
      mount -t tmpfs -o size=768m tmpfs /var/lib/rancher || exit 1
      mount -t tmpfs -o size=128m tmpfs /var/lib/kubelet || exit 1
      if ! [ -e /dev/kmsg ]; then
        mknod /dev/kmsg c 1 11 || exit 1
      fi
      i=0
      while [ ! -S /cri/containerd.sock ]; do
        i=$((i+1))
        if [ "$i" -gt 120 ]; then echo "no containerd socket"; exit 1; fi
        sleep 1
      done
      NODE_IP=$(ip -4 -o addr show eth0 | head -1 | tr -s " " | cut -d" " -f4 | cut -d/ -f1)
      if [ -z "$NODE_IP" ]; then echo "no eth0 ip"; exit 1; fi
      exec /bin/k3s server \
        --container-runtime-endpoint=unix:///cri/containerd.sock \
        --cluster-cidr=10.60.0.0/16 \
        --service-cidr=10.61.0.0/16 \
        --flannel-backend=none \
        --disable-kube-proxy \
        --disable-network-policy \
        --disable-cloud-controller \
        --disable-helm-controller \
        --disable=coredns,traefik,servicelb,metrics-server,local-storage \
        --node-ip="$NODE_IP" \
        --node-name=inner-server \
        --write-kubeconfig-mode=644
    securityContext:
      privileged: true
    resources:
      limits:
        memory: {INNER_K3S_MEMORY_MB}Mi
    volumeMounts:
    - name: cri
      mountPath: /cri
  volumes:
  - name: cri
    emptyDir: {{}}
"#
    ));

    kubectl_apply(&yaml);

    wait_for_pod_running(K3S_POD_NAME, Duration::from_secs(180));

    // Poll `kubectl get nodes` inside the k3s container until the inner
    // node reports Ready. k3s server on 1 vCPU in a nested VM needs a
    // couple of minutes.
    let start = Instant::now();
    loop {
        let attempt = kubectl_exec_in(
            K3S_POD_NAME,
            "k3s",
            "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl get nodes --no-headers 2>&1",
        );
        if let Ok(ref text) = attempt {
            let ready = text.lines().any(|l| {
                let mut cols = l.split_whitespace();
                cols.next() == Some("inner-server") && cols.next() == Some("Ready")
            });
            if ready {
                break;
            }
        }
        if start.elapsed() > Duration::from_secs(300) {
            let k3s_logs = Command::new("kubectl")
                .args(["logs", K3S_POD_NAME, "-c", "k3s", "--tail=120"])
                .output()
                .expect("kubectl logs k3s");
            let cd_logs = Command::new("kubectl")
                .args(["logs", K3S_POD_NAME, "-c", "containerd", "--tail=40"])
                .output()
                .expect("kubectl logs containerd");
            kubectl_delete_pod(K3S_POD_NAME);
            panic!(
                "inner node never went Ready (last attempt: {attempt:?})\n\
                 k3s logs:\n{}\ncontainerd logs:\n{}",
                String::from_utf8_lossy(&k3s_logs.stdout),
                String::from_utf8_lossy(&cd_logs.stdout)
            );
        }
        thread::sleep(Duration::from_secs(3));
    }

    // The pinned inner CIDRs must have taken effect: pod CIDR allocated
    // from 10.60.0.0/16 and the kubernetes Service VIP from 10.61.0.0/16
    // (neither collides with the outer cluster's 10.42/10.43 defaults).
    // The nodeipam controller assigns podCIDR asynchronously (it can lag
    // the first Ready by a while on 1 vCPU), so poll until it appears.
    let start = Instant::now();
    let pod_cidr = loop {
        let cidr = kubectl_exec_in(
            K3S_POD_NAME,
            "k3s",
            "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl get node inner-server \
             -o jsonpath='{.spec.podCIDR}'",
        )
        .expect("query inner node podCIDR");
        if !cidr.is_empty() {
            break cidr;
        }
        assert!(
            start.elapsed() < Duration::from_secs(120),
            "inner node never got a podCIDR from the nodeipam controller"
        );
        thread::sleep(Duration::from_secs(3));
    };
    assert!(
        pod_cidr.starts_with("10.60."),
        "inner podCIDR {pod_cidr} not allocated from --cluster-cidr=10.60.0.0/16"
    );
    let svc_ip = kubectl_exec_in(
        K3S_POD_NAME,
        "k3s",
        "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl get svc kubernetes \
         -o jsonpath='{.spec.clusterIP}'",
    )
    .expect("query kubernetes service ClusterIP");
    assert!(
        svc_ip.starts_with("10.61."),
        "kubernetes Service VIP {svc_ip} not allocated from --service-cidr=10.61.0.0/16"
    );

    kubectl_delete_pod(K3S_POD_NAME);
}

/// Pull + export one image into [`INNER3_AIRGAP_DIR`] as `{name}.tar`.
fn stage_airgap_tar(pull_ref: &str, plain_ref: &str, tar_name: &str) {
    let pull = Command::new("ctr")
        .args(["-n", "k8s.io", "images", "pull", pull_ref])
        .output()
        .unwrap_or_else(|e| panic!("ctr images pull {pull_ref}: {e}"));
    assert!(
        pull.status.success(),
        "failed to pull {pull_ref}: {}",
        String::from_utf8_lossy(&pull.stderr)
    );
    // Re-tag to the plain ref so the export (and the guest-side import)
    // carries the name the inner CRI config / inner pod specs use.
    let _ = Command::new("ctr")
        .args([
            "-n", "k8s.io", "images", "tag", "--force", pull_ref, plain_ref,
        ])
        .output();
    std::fs::create_dir_all(INNER3_AIRGAP_DIR).expect("create airgap dir");
    let tar = format!("{INNER3_AIRGAP_DIR}/{tar_name}");
    let _ = std::fs::remove_file(&tar);
    let export = Command::new("ctr")
        .args([
            "-n",
            "k8s.io",
            "images",
            "export",
            "--platform",
            "linux/amd64",
            &tar,
            plain_ref,
        ])
        .output()
        .unwrap_or_else(|e| panic!("ctr images export {plain_ref}: {e}"));
    assert!(
        export.status.success(),
        "failed to export {plain_ref}: {}",
        String::from_utf8_lossy(&export.stderr)
    );
}

/// Stage pause airgap tar. Inner containerds sit on an isolated bridge
/// with no registry access.
fn stage_pause_airgap() {
    stage_airgap_tar(INNER3_PAUSE_IMAGE, INNER3_PAUSE_REF, "pause.tar");
}

/// Pod manifest for inner-cluster member `idx` (0 = server, 1-2 =
/// agents). All three share [`INNER3_CLUSTER_ID`] (one L2 bridge) and
/// pin `fork-vm-index` = `idx` so the guest IPs are the stable
/// [`INNER3_GUEST_IPS`].
///
/// Cross-container file contracts (all plain files, virtiofs-safe; the
/// mmap-hungry state stays on in-guest tmpfs per CHALLENGES.md #34):
/// - `/cri/containerd.sock` — CRI socket.
/// - `/cri/cni/net.d` — flannel writes the CNI conflist from the k3s
///   container (bind of k3s's `agent/etc/cni/net.d`); the sidecar
///   containerd reads it as its CNI `conf_dir`.
/// - `/cri/run-flannel` — flannel's `subnet.env`, written by k3s and
///   read by the flannel CNI plugin execing under the sidecar (both
///   bind it to `/run/flannel`).
/// - `/cri/kubelet-pods` — kubelet's pods dir (`/var/lib/kubelet/pods`
///   in both containers): kubelet writes etc-hosts / termination-log
///   files there and the inner runc (running under the sidecar) binds
///   them into inner containers.
/// - `/cri/log-pods` — `/var/log/pods` in both: kubelet creates the
///   pod log dirs, the sidecar containerd writes the container logs.
fn inner3_pod_yaml(idx: usize) -> String {
    let pod = INNER3_PODS[idx];
    let node = INNER3_NODES[idx];
    // `/bin/k3s` directly: moved the container rootfs
    // off virtiofs onto an erofs virtio-blk device (overlay with a
    // guest-tmpfs upper), so mmap'd binary pages fault in from the
    // block device — which survives forks (both CoW warm forks and
    // the slow full-copy path recreate the device over the same
    // immutable image file). The old `/tmpbin` tmpfs-exec copies
    // (CHALLENGES.md #41: fresh post-fork FUSE sessions EBADF'd
    // stale mmap file handles → SIGBUS) are dead code on the block
    // path; `test_inner_k3s_cluster_warm_fork_via_annotation` proves
    // the fork survives execing straight from the image rootfs.
    let k3s_cmd = if idx == 0 {
        format!(
            "exec /bin/k3s server \\\n\
             \x20       --token={INNER3_TOKEN} \\\n\
             \x20       --container-runtime-endpoint=unix:///cri/containerd.sock \\\n\
             \x20       --cluster-cidr=10.60.0.0/16 \\\n\
             \x20       --service-cidr=10.61.0.0/16 \\\n\
             \x20       --flannel-backend=host-gw \\\n\
             \x20       --disable-network-policy \\\n\
             \x20       --disable-cloud-controller \\\n\
             \x20       --disable-helm-controller \\\n\
             \x20       --disable=coredns,traefik,servicelb,metrics-server,local-storage \\\n\
             \x20       --node-ip=\"$NODE_IP\" \\\n\
             \x20       --node-name={node} \\\n\
             \x20       --write-kubeconfig-mode=644"
        )
    } else {
        format!(
            "exec /bin/k3s agent \\\n\
             \x20       --server=https://{server_ip}:6443 \\\n\
             \x20       --token={INNER3_TOKEN} \\\n\
             \x20       --container-runtime-endpoint=unix:///cri/containerd.sock \\\n\
             \x20       --node-ip=\"$NODE_IP\" \\\n\
             \x20       --node-name={node}",
            server_ip = INNER3_GUEST_IPS[0]
        )
    };
    common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {pod}
  annotations:
    k7d.katakate.org/cluster-id: {INNER3_CLUSTER_ID}
    k7d.katakate.org/fork-vm-index: "{idx}"
spec:
  runtimeClassName: k7
  restartPolicy: Never
  containers:
  - name: containerd
    image: {K3S_IMAGE}
    imagePullPolicy: IfNotPresent
    command: ["/bin/sh", "-c"]
    args:
    - |
      set -x
      ip link set lo up
      mkdir -p /var/lib/containerd /run/containerd /var/lib/cni /var/log/pods \
        /var/lib/kubelet /cri/cni/net.d /cri/run-flannel /cri/kubelet-pods \
        /cri/log-pods /run/flannel
      mount -t tmpfs -o size=512m tmpfs /var/lib/containerd || exit 1
      mount -t tmpfs -o size=64m tmpfs /run/containerd || exit 1
      mount -t tmpfs -o size=16m tmpfs /var/lib/cni || exit 1
      mkdir -p /sys/fs/cgroup/init
      xargs -rn1 < /sys/fs/cgroup/cgroup.procs > /sys/fs/cgroup/init/cgroup.procs || true
      sed -e 's/ / +/g' -e 's/^/+/' < /sys/fs/cgroup/cgroup.controllers \
        > /sys/fs/cgroup/cgroup.subtree_control || exit 1
      mount --bind /cri/run-flannel /run/flannel || exit 1
      mkdir -p /var/lib/kubelet/pods
      mount --bind /cri/kubelet-pods /var/lib/kubelet/pods || exit 1
      mount --bind /cri/log-pods /var/log/pods || exit 1
      cat > /tmp/containerd-config.toml <<EOF
      version = 2
      [plugins."io.containerd.grpc.v1.cri"]
        sandbox_image = "{INNER3_PAUSE_REF}"
      [plugins."io.containerd.grpc.v1.cri".containerd]
        snapshotter = "overlayfs"
      [plugins."io.containerd.grpc.v1.cri".cni]
        conf_dir = "/cri/cni/net.d"
        bin_dir = "/bin"
      EOF
      /bin/containerd \
        --config /tmp/containerd-config.toml \
        --address /cri/containerd.sock \
        --root /var/lib/containerd \
        --state /run/containerd &
      CD=$!
      i=0
      while [ ! -S /cri/containerd.sock ]; do
        i=$((i+1))
        if [ $i -gt 60 ]; then echo "no containerd socket"; exit 1; fi
        sleep 1
      done
      /bin/ctr --address /cri/containerd.sock -n k8s.io images import /airgap/pause.tar || exit 1
      touch /cri/pause-imported
      wait $CD
    securityContext:
      privileged: true
    resources:
      limits:
        memory: {INNER_K3S_SIDECAR_MEMORY_MB}Mi
    volumeMounts:
    - name: cri
      mountPath: /cri
    - name: airgap
      mountPath: /airgap
      readOnly: true
  - name: k3s
    image: {K3S_IMAGE}
    imagePullPolicy: IfNotPresent
    command: ["/bin/sh", "-c"]
    args:
    - |
      set -x
      ip link set lo up
      mkdir -p /var/lib/rancher /var/lib/kubelet /var/log/pods \
        /cri/cni/net.d /cri/run-flannel /cri/kubelet-pods /cri/log-pods /run/flannel
      mkdir -p /sys/fs/cgroup/init
      xargs -rn1 < /sys/fs/cgroup/cgroup.procs > /sys/fs/cgroup/init/cgroup.procs || true
      sed -e 's/ / +/g' -e 's/^/+/' < /sys/fs/cgroup/cgroup.controllers \
        > /sys/fs/cgroup/cgroup.subtree_control || exit 1
      mount -t tmpfs -o size=768m tmpfs /var/lib/rancher || exit 1
      mount -t tmpfs -o size=128m tmpfs /var/lib/kubelet || exit 1
      mkdir -p /var/lib/kubelet/pods /var/lib/rancher/k3s/agent/etc/cni/net.d
      mount --bind /cri/kubelet-pods /var/lib/kubelet/pods || exit 1
      mount --bind /cri/log-pods /var/log/pods || exit 1
      mount --bind /cri/run-flannel /run/flannel || exit 1
      mount --bind /cri/cni/net.d /var/lib/rancher/k3s/agent/etc/cni/net.d || exit 1
      if ! [ -e /dev/kmsg ]; then
        mknod /dev/kmsg c 1 11 || exit 1
      fi
      i=0
      while [ ! -S /cri/containerd.sock ]; do
        i=$((i+1))
        if [ $i -gt 120 ]; then echo "no containerd socket"; exit 1; fi
        sleep 1
      done
      i=0
      NODE_IP=""
      while [ -z "$NODE_IP" ]; do
        NODE_IP=$(ip -4 -o addr show eth0 | head -1 | tr -s " " | cut -d" " -f4 | cut -d/ -f1)
        if [ -n "$NODE_IP" ]; then break; fi
        i=$((i+1))
        if [ $i -gt 60 ]; then echo "no eth0 ip"; exit 1; fi
        sleep 1
      done
      {k3s_cmd}
    securityContext:
      privileged: true
    resources:
      limits:
        memory: {INNER_K3S_MEMORY_MB}Mi
    volumeMounts:
    - name: cri
      mountPath: /cri
  volumes:
  - name: cri
    emptyDir: {{}}
  - name: airgap
    hostPath:
      path: {INNER3_AIRGAP_DIR}
      type: Directory
"#
    ))
}

fn delete_inner3_pods() {
    for pod in INNER3_PODS {
        kubectl_delete_pod(pod);
    }
}

/// Collect the k3s + containerd logs of all three pods for panic
/// messages.
fn inner3_logs() -> String {
    let mut out = String::new();
    for pod in INNER3_PODS {
        for container in ["k3s", "containerd"] {
            let logs = Command::new("kubectl")
                .args(["logs", pod, "-c", container, "--tail=80"])
                .output();
            if let Ok(logs) = logs {
                out.push_str(&format!(
                    "--- {pod}/{container} ---\n{}{}\n",
                    String::from_utf8_lossy(&logs.stdout),
                    String::from_utf8_lossy(&logs.stderr)
                ));
            }
        }
    }
    out
}

/// 3-node inner k3s cluster on one shared
/// cluster-mode bridge: server + two agents, flannel host-gw +
/// kube-proxy on the netfilter/veth/bridge guest kernel, and an inner
/// pause pod on an agent node reachable from the server node.
#[test]
fn test_inner_k3s_three_node_cluster_ready() {
    let _leak_guard = ensure_shim_installed();
    common::ensure_pod_annotations_forwarded();
    pull_k3s_image();
    stage_pause_airgap();

    delete_inner3_pods();
    thread::sleep(Duration::from_secs(3));

    for idx in 0..INNER3_PODS.len() {
        kubectl_apply(&inner3_pod_yaml(idx));
    }
    for pod in INNER3_PODS {
        wait_for_pod_running(pod, Duration::from_secs(300));
    }

    let server_pod = INNER3_PODS[0];
    let inner_kubectl = "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl";

    // 1. All three inner nodes Ready. Three single-vCPU nested VMs
    //    bootstrap slowly — budget generously.
    let start = Instant::now();
    loop {
        let attempt = kubectl_exec_in(
            server_pod,
            "k3s",
            &format!("{inner_kubectl} get nodes --no-headers 2>&1"),
        );
        if let Ok(ref text) = attempt {
            let all_ready = INNER3_NODES.iter().all(|node| {
                text.lines().any(|l| {
                    let mut cols = l.split_whitespace();
                    cols.next() == Some(*node) && cols.next() == Some("Ready")
                })
            });
            if all_ready {
                break;
            }
        }
        if start.elapsed() > Duration::from_secs(600) {
            let logs = inner3_logs();
            delete_inner3_pods();
            panic!("3 inner nodes never all Ready (last attempt: {attempt:?})\n{logs}");
        }
        thread::sleep(Duration::from_secs(5));
    }

    // 2. Inner node identities are the stable cluster-mode guest IPs.
    for (idx, node) in INNER3_NODES.iter().enumerate() {
        let ip = kubectl_exec_retry(
            server_pod,
            "k3s",
            &format!(
                "{inner_kubectl} get node {node} \
                 -o jsonpath='{{.status.addresses[?(@.type==\"InternalIP\")].address}}'"
            ),
            3,
        )
        .expect("query inner node InternalIP");
        assert_eq!(
            ip, INNER3_GUEST_IPS[idx],
            "inner node {node} InternalIP {ip} != stable guest IP {}",
            INNER3_GUEST_IPS[idx]
        );
    }
    // Each guest's eth0 carries its 10.200.0.x address directly.
    for (idx, pod) in INNER3_PODS.iter().enumerate() {
        let eth0 =
            kubectl_exec_retry(pod, "k3s", "ip -4 -o addr show eth0", 3).expect("guest eth0");
        assert!(
            eth0.contains(INNER3_GUEST_IPS[idx]),
            "pod {pod} guest eth0 missing {}: {eth0}",
            INNER3_GUEST_IPS[idx]
        );
    }

    // 3. Outer pod IPs are CNI-assigned and all differ (the shared
    //    bridge preserves guest identity; it does not collapse the
    //    outer pods into one address).
    let mut outer_ips = Vec::new();
    for pod in INNER3_PODS {
        let out = Command::new("kubectl")
            .args(["get", "pod", pod, "-o", "jsonpath={.status.podIP}"])
            .output()
            .expect("kubectl get pod IP");
        let ip = String::from_utf8_lossy(&out.stdout).trim().to_string();
        assert!(!ip.is_empty(), "outer pod {pod} has no podIP");
        outer_ips.push(ip);
    }
    for i in 0..outer_ips.len() {
        for j in (i + 1)..outer_ips.len() {
            assert_ne!(
                outer_ips[i], outer_ips[j],
                "outer pods {} and {} share pod IP {}",
                INNER3_PODS[i], INNER3_PODS[j], outer_ips[i]
            );
        }
    }

    // 4. Pinned inner CIDRs re-verified at 3 nodes: every podCIDR from
    //    10.60/16, the kubernetes Service VIP from 10.61/16.
    let cidrs = kubectl_exec_retry(
        server_pod,
        "k3s",
        &format!("{inner_kubectl} get nodes -o jsonpath='{{.items[*].spec.podCIDR}}'"),
        3,
    )
    .expect("query inner podCIDRs");
    let cidr_list: Vec<&str> = cidrs.split_whitespace().collect();
    assert_eq!(cidr_list.len(), 3, "expected 3 inner podCIDRs: {cidrs}");
    for cidr in &cidr_list {
        assert!(
            cidr.starts_with("10.60."),
            "inner podCIDR {cidr} not from --cluster-cidr=10.60.0.0/16"
        );
    }
    let svc_ip = kubectl_exec_retry(
        server_pod,
        "k3s",
        &format!("{inner_kubectl} get svc kubernetes -o jsonpath='{{.spec.clusterIP}}'"),
        3,
    )
    .expect("query kubernetes service ClusterIP");
    assert!(
        svc_ip.starts_with("10.61."),
        "kubernetes Service VIP {svc_ip} not from --service-cidr=10.61.0.0/16"
    );

    // 5. Schedule an inner pause pod on an agent node. No SA token
    //    automount: projected-token volumes are tmpfs mounts in the
    //    k3s container's mount ns, invisible to the sidecar's runc.
    let apply_pause = kubectl_exec_retry(
        server_pod,
        "k3s",
        &format!(
            "cat > /tmp/inner-pause.yaml <<EOF\n\
             apiVersion: v1\n\
             kind: Pod\n\
             metadata:\n\
             \x20 name: inner-pause\n\
             spec:\n\
             \x20 nodeSelector:\n\
             \x20   kubernetes.io/hostname: {agent}\n\
             \x20 automountServiceAccountToken: false\n\
             \x20 containers:\n\
             \x20 - name: pause\n\
             \x20   image: {INNER3_PAUSE_REF}\n\
             \x20   imagePullPolicy: Never\n\
             EOF\n\
             {inner_kubectl} apply -f /tmp/inner-pause.yaml",
            agent = INNER3_NODES[1]
        ),
        3,
    );
    assert!(
        apply_pause.is_ok(),
        "inner pause apply failed: {apply_pause:?}"
    );

    let start = Instant::now();
    let pause_ip = loop {
        let status = kubectl_exec_in(
            server_pod,
            "k3s",
            &format!(
                "{inner_kubectl} get pod inner-pause \
                 -o jsonpath='{{.status.phase}} {{.status.podIP}} {{.spec.nodeName}}' 2>&1"
            ),
        );
        if let Ok(ref text) = status {
            let mut cols = text.split_whitespace();
            if cols.next() == Some("Running") {
                let ip = cols.next().unwrap_or("").to_string();
                let node = cols.next().unwrap_or("");
                assert_eq!(
                    node, INNER3_NODES[1],
                    "inner pause pod scheduled on {node}, expected {}",
                    INNER3_NODES[1]
                );
                if !ip.is_empty() {
                    break ip;
                }
            }
        }
        if start.elapsed() > Duration::from_secs(300) {
            let describe = kubectl_exec_in(
                server_pod,
                "k3s",
                &format!("{inner_kubectl} describe pod inner-pause 2>&1 | tail -40"),
            );
            let logs = inner3_logs();
            delete_inner3_pods();
            panic!(
                "inner pause pod never Running (last: {status:?})\ndescribe: {describe:?}\n{logs}"
            );
        }
        thread::sleep(Duration::from_secs(5));
    };
    assert!(
        pause_ip.starts_with("10.60."),
        "inner pause pod IP {pause_ip} not from the inner cluster CIDR 10.60.0.0/16"
    );

    // 6. The pause pod on the agent node is reachable from the server
    //    node over the inner CNI path (flannel host-gw route via the
    //    shared L2 bridge into the agent guest's cni0). Routes can lag
    //    the pod start, so poll briefly.
    let start = Instant::now();
    loop {
        let ping = kubectl_exec_in(
            server_pod,
            "k3s",
            &format!("ping -c 2 -W 3 {pause_ip} 2>&1"),
        );
        if ping.is_ok() {
            break;
        }
        if start.elapsed() > Duration::from_secs(60) {
            let routes = kubectl_exec_in(server_pod, "k3s", "ip route 2>&1");
            let logs = inner3_logs();
            delete_inner3_pods();
            panic!(
                "inner pause pod {pause_ip} unreachable from server node: {ping:?}\n\
                 server guest routes: {routes:?}\n{logs}"
            );
        }
        thread::sleep(Duration::from_secs(3));
    }

    delete_inner3_pods();
}

// ──: warm cluster fork without restart ──

/// Drive-path note (parent status log): this test talks to the running
/// k7d daemon over `/run/k7d/k7d.sock` directly (`Client::connect_env`)
/// — it exercises the raw `TreeAdoptCluster` + `TreeFork` primitives.
/// The operator-facing kubectl-annotation route over the same
/// primitives is
/// `test_inner_k3s_cluster_warm_fork_via_annotation` (below).

/// Generous tree budget for 2 live 3-VM inner-k3s payloads (root + fork).
/// Default daemon budget is sized for 256 MiB busybox guests.
fn inner3_tree_budget() -> TreeBudget {
    TreeBudget {
        max_live_vms: 16,
        max_live_ram_bytes: 64 * 1024 * 1024 * 1024,
        max_disk_bytes: 128 * 1024 * 1024 * 1024,
        max_chain_depth: 8,
    }
}

/// Resolve the three live `inner3` sandbox VMs (sorted by `vm_index`).
fn discover_inner3_vm_ids(client: &mut Client) -> Vec<String> {
    let Response::VmList { vms } = client.call(&Request::ListVms).expect("ListVms") else {
        panic!("ListVms returned unexpected response");
    };
    let mut found: Vec<(u32, String)> = Vec::new();
    for vm in vms {
        let Some(sandbox_id) = vm.sandbox_id else {
            continue;
        };
        match client.call(&Request::LookupSandbox { sandbox_id }) {
            Ok(Response::SandboxFound {
                vm_id,
                cluster_id: Some(cid),
                vm_index: Some(idx),
                ..
            }) if cid == INNER3_CLUSTER_ID => {
                found.push((idx, vm_id));
            }
            Ok(_) => {}
            Err(e) => panic!("LookupSandbox failed: {e}"),
        }
    }
    found.sort_by_key(|(idx, _)| *idx);
    assert_eq!(
        found.len(),
        3,
        "expected 3 live VMs on cluster_id={INNER3_CLUSTER_ID}, found {found:?}"
    );
    for (i, (idx, _)) in found.iter().enumerate() {
        assert_eq!(*idx, i as u32, "vm_index gap in {found:?}");
    }
    found.into_iter().map(|(_, id)| id).collect()
}

/// Host directory holding the inner cluster's client TLS material,
/// extracted from the server pod's kubeconfig before adopt.
const INNER3_CERTS_DIR: &str = "/tmp/k7-inner3-certs";

/// Extract the admin client cert/key from the inner kubeconfig into
/// [`INNER3_CERTS_DIR`]. Probes/assertions authenticate with these
/// against the guest IPs directly (anonymous `/readyz` is rejected
/// with 401), and — crucially — from the host: only `curl
/// --interface <bridge>` can disambiguate the source and fork
/// clusters, which carry the *same* guest IPs on two bridges.
///
/// Historical note: this originally *had* to run pre-adopt because the
/// prepare swap killed virtiofs in the source (CHALLENGES.md #39). The
/// #39 fix keeps virtiofs-backed sources running in place, so in-guest
/// exec now survives adopt (asserted by the annotation test) —
/// extracting pre-adopt is merely the natural point in the flow.
fn extract_inner_certs() {
    let yaml = kubectl_exec_retry(INNER3_PODS[0], "k3s", "cat /etc/rancher/k3s/k3s.yaml", 5)
        .expect("read inner kubeconfig from server pod");
    let field = |key: &str| -> Vec<u8> {
        let line = yaml
            .lines()
            .find(|l| l.trim_start().starts_with(key))
            .unwrap_or_else(|| panic!("no {key} in inner kubeconfig"));
        let b64 = line
            .split_whitespace()
            .nth(1)
            .expect("kubeconfig field value");
        let out = Command::new("base64")
            .arg("-d")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut c| {
                use std::io::Write;
                c.stdin.as_mut().unwrap().write_all(b64.as_bytes())?;
                c.wait_with_output()
            })
            .expect("base64 -d");
        assert!(out.status.success(), "base64 -d failed for {key}");
        out.stdout
    };
    std::fs::create_dir_all(INNER3_CERTS_DIR).expect("create certs dir");
    std::fs::write(
        format!("{INNER3_CERTS_DIR}/client.pem"),
        field("client-certificate-data:"),
    )
    .expect("write client.pem");
    std::fs::write(
        format!("{INNER3_CERTS_DIR}/client-key.pem"),
        field("client-key-data:"),
    )
    .expect("write client-key.pem");
}

/// Authenticated HTTPS GET against an inner API server at
/// `10.200.0.2:6443`, egressing through `bridge_dev`. Three twists:
/// - `--interface` is load-bearing: source and fork clusters carry the
///   **same** guest IPs on two host bridges, so routing is ambiguous.
/// - `-k` (skip server-cert verification) is required: the guest mints
///   its PKI with the 1999 in-guest clock (CHALLENGES.md #37), so the
///   2026 host sees "certificate has expired". Client-cert auth still
///   runs — the server validates our cert against *its* clock — so
///   every sample is a full mutual-TLS round trip.
/// - Timeouts are sized ABOVE the fork's source-pause window (~6-7 s
///   for 3 × 2.6 GiB full copies): a connection opened mid-pause must
///   be allowed to complete via SYN retransmit after resume — that is
///   the survival property under test, not sub-pause latency.
fn curl_inner_api(bridge_dev: &str, path: &str) -> Result<String, String> {
    let url = format!("https://{}:6443{path}", INNER3_GUEST_IPS[0]);
    let out = Command::new("curl")
        .args([
            "-sSk",
            "--max-time",
            "30",
            "--connect-timeout",
            "20",
            "--interface",
            bridge_dev,
            "--cert",
            &format!("{INNER3_CERTS_DIR}/client.pem"),
            "--key",
            &format!("{INNER3_CERTS_DIR}/client-key.pem"),
            &url,
        ])
        .output()
        .map_err(|e| format!("spawn curl: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "curl {url} via {bridge_dev} exit {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Names of the `k7-br-*` bridges currently on the host.
fn list_k7_bridges() -> Vec<String> {
    let out = Command::new("sh")
        .args(["-c", "ip -o link show | awk -F': ' '{print $2}'"])
        .output()
        .expect("ip link show");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.split('@').next().unwrap_or(l).trim().to_string())
        .filter(|n| n.starts_with("k7-br-"))
        .collect()
}

/// Long-lived watch stream against the source API server — one held
/// TCP/TLS session that must survive the fork (the 9d headline).
/// `curl -N …?watch=true` blocks streaming events until killed; if the
/// connection resets, curl exits on its own.
fn start_held_watch(bridge_dev: &str) -> std::process::Child {
    Command::new("curl")
        .args([
            "-sNk",
            "--max-time",
            "600",
            "--interface",
            bridge_dev,
            "--cert",
            &format!("{INNER3_CERTS_DIR}/client.pem"),
            "--key",
            &format!("{INNER3_CERTS_DIR}/client-key.pem"),
            &format!(
                "https://{}:6443/api/v1/nodes?watch=true",
                INNER3_GUEST_IPS[0]
            ),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn held watch curl")
}

/// Poll `/api/v1/nodes` through `bridge_dev` until all three inner
/// nodes report `Ready` with their stable guest-IP identities.
fn assert_three_ready_nodes_via(bridge_dev: &str, label: &str) {
    let start = Instant::now();
    loop {
        let last = curl_inner_api(bridge_dev, "/api/v1/nodes");
        if let Ok(ref body) = last {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                let empty = Vec::new();
                let items = json["items"].as_array().unwrap_or(&empty);
                let mut ready = 0;
                let mut ip_ok = 0;
                for (idx, node) in INNER3_NODES.iter().enumerate() {
                    let Some(item) = items
                        .iter()
                        .find(|i| i["metadata"]["name"].as_str() == Some(node))
                    else {
                        continue;
                    };
                    let is_ready = item["status"]["conditions"]
                        .as_array()
                        .unwrap_or(&empty)
                        .iter()
                        .any(|c| {
                            c["type"].as_str() == Some("Ready")
                                && c["status"].as_str() == Some("True")
                        });
                    if is_ready {
                        ready += 1;
                    }
                    let has_ip = item["status"]["addresses"]
                        .as_array()
                        .unwrap_or(&empty)
                        .iter()
                        .any(|a| {
                            a["type"].as_str() == Some("InternalIP")
                                && a["address"].as_str() == Some(INNER3_GUEST_IPS[idx])
                        });
                    if has_ip {
                        ip_ok += 1;
                    }
                }
                if ready == 3 && ip_ok == 3 {
                    return;
                }
            }
        }
        if start.elapsed() > Duration::from_secs(240) {
            let brief = match &last {
                // char-based truncation: slicing bytes could split a
                // UTF-8 code point in a k8s error message and panic.
                Ok(b) => format!("body: {}", b.chars().take(2000).collect::<String>()),
                Err(e) => format!("error: {e}"),
            };
            panic!(
                "{label}: 3 Ready nodes at stable IPs never observed via {bridge_dev} ({brief})"
            );
        }
        thread::sleep(Duration::from_secs(3));
    }
}

/// Deploy a pause Deployment and churn the API so the warm
/// fork copies real dirty pages. HostNetwork www images fail nested
/// etc-hosts binds (CHALLENGES #50); nested runc needs guest
/// `CONFIG_CFS_BANDWIDTH` for `cpu.max` (CHALLENGES #51). Post-fork we
/// assert via the apiserver on each bridge.
fn deploy_inner_workload_and_churn() {
    let server_pod = INNER3_PODS[0];
    let inner_kubectl = "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl";

    let apply = kubectl_exec_retry(
        server_pod,
        "k3s",
        &format!(
            r#"cat > /tmp/inner-load.yaml <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: inner-load
spec:
  replicas: 3
  selector:
    matchLabels:
      app: inner-load
  template:
    metadata:
      labels:
        app: inner-load
    spec:
      automountServiceAccountToken: false
      containers:
      - name: pause
        image: {INNER3_PAUSE_REF}
        imagePullPolicy: Never
EOF
{inner_kubectl} apply -f /tmp/inner-load.yaml && \
{inner_kubectl} rollout status deploy/inner-load --timeout=180s && echo deploy-ok
"#
        ),
        3,
    );
    assert!(
        matches!(apply, Ok(ref s) if s.contains("deploy-ok")),
        "inner-load Deployment failed: {apply:?}"
    );

    // Churn: scale up/down + ConfigMap storm + short-lived pause pods.
    let scale = kubectl_exec_retry(
        server_pod,
        "k3s",
        &format!(
            "{inner_kubectl} scale deploy/inner-load --replicas=6 && \
             {inner_kubectl} rollout status deploy/inner-load --timeout=120s && \
             {inner_kubectl} scale deploy/inner-load --replicas=3 && \
             {inner_kubectl} rollout status deploy/inner-load --timeout=120s && \
             for i in $(seq 1 12); do \
               {inner_kubectl} create configmap churn-cm-$i --from-literal=k=$i || true; \
             done && echo scale-ok"
        ),
        2,
    );
    assert!(
        matches!(scale, Ok(ref s) if s.contains("scale-ok")),
        "inner-load scale/ConfigMap churn failed: {scale:?}"
    );
    for i in 1..=8 {
        let _ = kubectl_exec_in(
            server_pod,
            "k3s",
            &format!(
                "cat > /tmp/pause-{i}.yaml <<EOF\n\
                 apiVersion: v1\n\
                 kind: Pod\n\
                 metadata:\n\
                 \x20 name: churn-pause-{i}\n\
                 spec:\n\
                 \x20 automountServiceAccountToken: false\n\
                 \x20 containers:\n\
                 \x20 - name: pause\n\
                 \x20   image: {INNER3_PAUSE_REF}\n\
                 \x20   imagePullPolicy: Never\n\
                 EOF\n\
                 {inner_kubectl} apply -f /tmp/pause-{i}.yaml"
            ),
        );
    }
    thread::sleep(Duration::from_secs(3));
    for i in 1..=8 {
        let _ = kubectl_exec_in(
            server_pod,
            "k3s",
            &format!("{inner_kubectl} delete pod churn-pause-{i} --force --grace-period=0"),
        );
    }
    for i in 1..=12 {
        let _ = kubectl_exec_in(
            server_pod,
            "k3s",
            &format!("{inner_kubectl} delete configmap churn-cm-{i} --ignore-not-found"),
        );
    }
    eprintln!("  inner workload + churn ready (pause Deployment scale + API storm)");
}

/// Ready replicas of `inner-load` via the authenticated apiserver on
/// `bridge` (works for source and fork — same guest VIP, different L2).
fn assert_inner_load_ready_via(bridge: &str, label: &str) {
    let path = "/apis/apps/v1/namespaces/default/deployments/inner-load";
    let start = Instant::now();
    loop {
        match curl_inner_api(bridge, path) {
            Ok(body) => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                    let ready = v["status"]["readyReplicas"].as_u64().unwrap_or(0);
                    let desired = v["spec"]["replicas"].as_u64().unwrap_or(0);
                    if ready >= 3 && desired >= 3 {
                        eprintln!("  {label}: inner-load readyReplicas={ready}/{desired}");
                        return;
                    }
                    eprintln!(
                        "  {label}: inner-load not ready yet ready={ready} desired={desired}"
                    );
                }
            }
            Err(e) => eprintln!("  {label}: deploy get via {bridge}: {e}"),
        }
        if start.elapsed() > Duration::from_secs(60) {
            panic!("{label}: inner-load never showed ≥3 readyReplicas via {bridge}");
        }
        thread::sleep(Duration::from_secs(2));
    }
}

/// Bring the three-pod fixture to "3 Ready nodes", deploy the dirtier
/// workload, and leave the pods running for adopt/fork.
fn bring_up_inner3_cluster() {
    common::ensure_pod_annotations_forwarded();
    pull_k3s_image();
    stage_pause_airgap();
    delete_inner3_pods();
    thread::sleep(Duration::from_secs(3));

    for idx in 0..INNER3_PODS.len() {
        kubectl_apply(&inner3_pod_yaml(idx));
    }
    for pod in INNER3_PODS {
        wait_for_pod_running(pod, Duration::from_secs(300));
    }

    // The airgap RO hostPath rides a cached erofs
    // image on virtio-blk, so cluster pods must carry ZERO virtiofs
    // shares — that is what puts adopt/fork on the CoW path. Assert
    // BEFORE adopt: the daemon drops the sandbox records at adopt,
    // after which vm_status can no longer see these VMs.
    for pod in INNER3_PODS {
        let vm = common::pod_vm_state(pod);
        assert_eq!(
            vm.virtiofs_shares, 0,
            "{pod}: cluster pods must be share-less (RO hostPath on virtio-blk); \
             a virtiofs share here silently degrades the fork to full-copy"
        );
        assert!(
            vm.block_devices >= 3,
            "{pod}: expected tools + rootfs + airgap erofs devices, got {}",
            vm.block_devices
        );
    }
    // The airgap dir must be readable in-guest from the erofs image
    // (the sidecar already imported pause.tar from it to get here, but
    // assert the mount explicitly so a regression is pinpointed).
    let airgap = kubectl_exec_retry(
        INNER3_PODS[0],
        "containerd",
        "test -f /airgap/pause.tar && echo airgap-ok",
        5,
    );
    assert!(
        matches!(airgap, Ok(ref out) if out.contains("airgap-ok")),
        "airgap hostPath not readable in-guest from the erofs image: {airgap:?}"
    );

    let server_pod = INNER3_PODS[0];
    let inner_kubectl = "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl";
    let start = Instant::now();
    loop {
        let attempt = kubectl_exec_in(
            server_pod,
            "k3s",
            &format!("{inner_kubectl} get nodes --no-headers 2>&1"),
        );
        if let Ok(ref text) = attempt {
            let all_ready = INNER3_NODES.iter().all(|node| {
                text.lines().any(|l| {
                    let mut cols = l.split_whitespace();
                    cols.next() == Some(*node) && cols.next() == Some("Ready")
                })
            });
            if all_ready {
                deploy_inner_workload_and_churn();
                return;
            }
        }
        if start.elapsed() > Duration::from_secs(600) {
            let logs = inner3_logs();
            delete_inner3_pods();
            panic!("cluster bring-up: 3 inner nodes never Ready (last: {attempt:?})\n{logs}");
        }
        thread::sleep(Duration::from_secs(5));
    }
}

/// Warm-fork the live 3-VM inner-k3s cluster
/// without restarting the source control plane.
#[test]
fn test_inner_k3s_cluster_warm_fork_no_restart() {
    let _leak_guard = ensure_shim_installed();
    bring_up_inner3_cluster();

    // Certs come out pre-adopt. (Historical: adopt/prepare used to
    // kill in-guest exec by re-CIDing the source — CHALLENGES.md #39.
    // Preserves the CID, proven post-fork below; the
    // pre-adopt extraction simply keeps this test's probe path
    // independent of that fix.)
    extract_inner_certs();
    // `cluster_id = "inner3"` (≤ 9 chars) maps to this bridge name
    // deterministically; stale bridges from crashed runs may coexist.
    let source_bridge = "k7-br-inner3".to_string();
    let bridges_before = list_k7_bridges();
    assert!(
        bridges_before.contains(&source_bridge),
        "inner3 bridge missing: {bridges_before:?}"
    );
    // Pre-adopt sanity: the authenticated host-side path works.
    let ready = curl_inner_api(&source_bridge, "/readyz").expect("pre-adopt /readyz");
    assert!(ready.contains("ok"), "pre-adopt /readyz not ok: {ready}");

    let mut client = Client::connect_env().expect("connect k7d daemon");
    let vm_ids = discover_inner3_vm_ids(&mut client);
    eprintln!("  discovered inner3 vm_ids={vm_ids:?}");

    // Adopt first (prepare_fork_source pauses each member for seconds
    // to snapshot 2.6 GiB — a probe started before adopt would
    // false-fail). Required order: prepare → probe → fork.
    let tree_id = format!("inner3-adopt-{}", std::process::id());
    let (tree_id, root_id, root_cids) = match client.call(&Request::TreeAdoptCluster {
        vm_ids,
        budget: Some(inner3_tree_budget()),
        tree_id: Some(tree_id),
    }) {
        Ok(Response::TreeCreated {
            tree_id,
            root_id,
            guest_cids,
        }) => {
            assert_eq!(guest_cids.len(), 3, "adopted root must have 3 members");
            (tree_id, root_id, guest_cids)
        }
        Ok(other) => {
            delete_inner3_pods();
            panic!("unexpected TreeAdoptCluster response: {other:?}");
        }
        Err(e) => {
            delete_inner3_pods();
            panic!("TreeAdoptCluster transport error: {e}");
        }
    };
    eprintln!("  adopted tree={tree_id} root_cids={root_cids:?}");

    // A `TreeDrop`-based teardown for every failure exit below.
    let teardown = |client: &mut Client| {
        let _ = client.call(&Request::TreeDrop {
            tree_id: tree_id.clone(),
        });
        delete_inner3_pods();
        let _ = std::fs::remove_dir_all(format!("/var/lib/k7d/trees/{tree_id}"));
    };

    // Wait for the source API server to answer again post-prepare.
    let start = Instant::now();
    loop {
        if matches!(curl_inner_api(&source_bridge, "/readyz"), Ok(ref b) if b.contains("ok")) {
            break;
        }
        if start.elapsed() > Duration::from_secs(120) {
            let last = curl_inner_api(&source_bridge, "/readyz");
            teardown(&mut client);
            panic!("source API never recovered after adopt/prepare (last: {last:?})");
        }
        thread::sleep(Duration::from_secs(2));
    }

    // Held watch stream: one TCP/TLS session that must survive the fork
    // (the 9d headline). New /readyz connections during the ~8 s source
    // pause can flake — do not sample those; poll explicitly after resume
    // (CHALLENGES #42).
    let mut watch = start_held_watch(&source_bridge);
    thread::sleep(Duration::from_secs(1));
    assert!(
        watch.try_wait().expect("watch try_wait").is_none(),
        "held watch stream died before the fork"
    );

    let fork_start = Instant::now();
    let (fork_node, fork_cids) = match client.call(&Request::TreeFork {
        tree_id: tree_id.clone(),
        source_id: root_id.clone(),
        label: "warm".to_string(),
    }) {
        Ok(Response::TreeForked {
            node_id,
            guest_cids,
            fork_memory_full_copy,
        }) => {
            assert_eq!(guest_cids.len(), 3, "fork must clone every member");
            // Share-less cluster members must ride the
            // CoW path — a full memfd copy anywhere is a regression to
            // the slow fork (and would blow the < 1 s budget below).
            assert_eq!(
                fork_memory_full_copy,
                vec![false; 3],
                "inner-k3s cluster fork must be CoW on every member"
            );
            (node_id, guest_cids)
        }
        Ok(other) => {
            let _ = watch.kill();
            teardown(&mut client);
            panic!("unexpected TreeFork response: {other:?}");
        }
        Err(e) => {
            let _ = watch.kill();
            teardown(&mut client);
            panic!("TreeFork transport error: {e}");
        }
    };
    let fork_elapsed = fork_start.elapsed();
    eprintln!(
        "  TreeFork node={fork_node} cids={fork_cids:?} elapsed={fork_elapsed:?} \
         budget={FORK_INNER_K3S_CLUSTER_3VM:?}"
    );
    // Surface the daemon's per-member memfd copy and
    // materialise timings (plus the cluster total) in the test output so
    // budget regressions are diagnosable from the test log alone.
    if let Ok(journal) = Command::new("journalctl")
        .args(["-u", "k7d", "--no-pager", "--since", "-3min"])
        .output()
    {
        for line in String::from_utf8_lossy(&journal.stdout)
            .lines()
            .filter(|l| l.contains("full memfd copy") || l.contains("fork_cluster_warm"))
        {
            eprintln!("  daemon: {line}");
        }
    }
    assert!(
        fork_elapsed <= FORK_INNER_K3S_CLUSTER_3VM,
        "inner-k3s cluster TreeFork took {fork_elapsed:?} > budget {FORK_INNER_K3S_CLUSTER_3VM:?}"
    );

    // The fork's bridge is the one that appeared during TreeFork.
    let fork_bridge = list_k7_bridges()
        .into_iter()
        .find(|b| !bridges_before.contains(b))
        .expect("fork bridge appeared");
    eprintln!("  source bridge={source_bridge} fork bridge={fork_bridge}");

    let watch_alive = watch.try_wait().expect("watch try_wait").is_none();
    let watch_kill = watch.kill();
    assert!(
        watch_alive,
        "held watch TCP/TLS session against the source broke across the fork"
    );
    let _ = watch_kill;

    // Explicit post-resume /readyz (not a background sampler that can
    // classify a mid-pause handshake failure as the only "post" sample).
    let resume = Instant::now();
    loop {
        if matches!(curl_inner_api(&source_bridge, "/readyz"), Ok(ref b) if b.contains("ok")) {
            break;
        }
        if resume.elapsed() > Duration::from_secs(60) {
            let last = curl_inner_api(&source_bridge, "/readyz");
            teardown(&mut client);
            panic!("source /readyz never recovered after TreeFork resume (last: {last:?})");
        }
        thread::sleep(Duration::from_millis(500));
    }

    // CID stability: adopt swapped each share-less
    // source for a restored copy on the SAME vsock CID, so the member
    // pods' shims (which cached that CID at Create and dial it fresh
    // per exec) must still reach their guests.
    let echo = kubectl_exec_retry(INNER3_PODS[0], "k3s", "echo post-fork-exec-ok", 5);
    match echo {
        Ok(ref out) if out.contains("post-fork-exec-ok") => {}
        other => {
            teardown(&mut client);
            panic!("post-fork exec into the source server pod failed: {other:?}");
        }
    }

    // Source still healthy; fork independently shows the same 3 Ready
    // nodes at the preserved guest IPs (interface-bound: same IPs on
    // two bridges).
    assert_three_ready_nodes_via(&source_bridge, "source");
    assert_three_ready_nodes_via(&fork_bridge, "fork");

    // Dirtier fixture — pause Deployment must still report
    // ≥3 readyReplicas on both bridges (workload state, not just /readyz).
    assert_inner_load_ready_via(&source_bridge, "source");
    assert_inner_load_ready_via(&fork_bridge, "fork");

    // Teardown: tree drop tears down both live payloads + bridges;
    // pod delete is best-effort (StopVm → "no such VM"); wipe on-disk
    // tree state so 3×~2.6 GiB base.mem files don't fill the node.
    // Set `K7_KEEP_INNER3=1` to leave the outer pods for the demo.
    if std::env::var_os("K7_KEEP_INNER3").is_some() {
        let _ = client.call(&Request::TreeDrop {
            tree_id: tree_id.clone(),
        });
        let _ = std::fs::remove_dir_all(format!("/var/lib/k7d/trees/{tree_id}"));
        eprintln!("  K7_KEEP_INNER3 set — outer pods left running for demo");
    } else {
        teardown(&mut client);
    }
}

// ──: annotation-driven cluster fork ──

/// Fork-trigger pod: its `k7d.katakate.org/tree-*`
/// annotations make the shim adopt the live inner3 cluster and fork it
/// during this pod's own sandbox Create.
const INNER3_TRIGGER_POD: &str = "test-inner3-fork-trigger";

/// Manifest for the fork-trigger pod. A plain BestEffort k7 pod (its
/// own VM and bridge — deliberately NOT on [`INNER3_CLUSTER_ID`]; the
/// shim rejects a trigger that is a member of the cluster it adopts)
/// whose annotations carry the whole contract: adopt `inner3`
/// as the root of `tree_id`, then fork `root` under label `warm`.
/// The pod reaching Running IS the success signal — the shim fails
/// sandbox Create loudly when adopt or fork fails.
fn fork_trigger_pod_yaml(tree_id: &str) -> String {
    let budget = serde_json::to_string(&inner3_tree_budget()).expect("serialize TreeBudget");
    common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {INNER3_TRIGGER_POD}
  annotations:
    k7d.katakate.org/tree-id: "{tree_id}"
    k7d.katakate.org/tree-adopt-cluster: "{INNER3_CLUSTER_ID}"
    k7d.katakate.org/tree-fork-from: "root"
    k7d.katakate.org/tree-fork-label: "warm"
    k7d.katakate.org/tree-budget: '{budget}'
spec:
  runtimeClassName: k7
  restartPolicy: Never
  containers:
  - name: trigger
    image: {K3S_IMAGE}
    imagePullPolicy: IfNotPresent
    command: ["/bin/sh", "-c", "sleep infinity"]
"#
    ))
}

/// Number of ports attached to a Linux bridge (0 for a non-bridge or
/// missing device). Disambiguates the 3-TAP fork bridge from the
/// trigger pod's own single-TAP bridge among the bridges that appear
/// during the trigger pod's Create.
fn bridge_port_count(name: &str) -> usize {
    std::fs::read_dir(format!("/sys/class/net/{name}/brif"))
        .map(|d| d.count())
        .unwrap_or(0)
}

/// The warm fork driven entirely by
/// kubectl: a trigger pod's `k7d.katakate.org/tree-*` annotations make
/// the shim call `TreeAdoptCluster` + `TreeFork`. No
/// `Client::connect_env` for the fork itself — the daemon socket is
/// only used for teardown (`TreeDrop`), which is allowed.
///
/// The held watch stream starts BEFORE the trigger pod is applied and
/// must survive both the adopt pause (root snapshot) and the fork
/// pause — unlike the socket-driven route there is no gap between the two
/// to start a probe in, which makes this the stronger survival claim.
#[test]
fn test_inner_k3s_cluster_warm_fork_via_annotation() {
    let _leak_guard = ensure_shim_installed();
    bring_up_inner3_cluster();

    // Certs come out pre-adopt as before (host-side authenticated
    // probes are the assertion path either way).
    extract_inner_certs();
    let source_bridge = "k7-br-inner3".to_string();
    let bridges_before = list_k7_bridges();
    assert!(
        bridges_before.contains(&source_bridge),
        "inner3 bridge missing: {bridges_before:?}"
    );
    let ready = curl_inner_api(&source_bridge, "/readyz").expect("pre-fork /readyz");
    assert!(ready.contains("ok"), "pre-fork /readyz not ok: {ready}");

    kubectl_delete_pod(INNER3_TRIGGER_POD);
    thread::sleep(Duration::from_secs(2));

    // One held TCP/TLS session against the source API server across
    // the whole annotation-driven adopt + fork (the 9d headline).
    let mut watch = start_held_watch(&source_bridge);
    thread::sleep(Duration::from_secs(1));
    assert!(
        watch.try_wait().expect("watch try_wait").is_none(),
        "held watch stream died before the trigger pod was applied"
    );

    let tree_id = format!("inner3-ann-{}", std::process::id());
    let teardown = || {
        // Socket use here is teardown-only (allowed).
        if let Ok(mut client) = Client::connect_env() {
            let _ = client.call(&Request::TreeDrop {
                tree_id: tree_id.clone(),
            });
        }
        kubectl_delete_pod(INNER3_TRIGGER_POD);
        delete_inner3_pods();
        let _ = std::fs::remove_dir_all(format!("/var/lib/k7d/trees/{tree_id}"));
    };

    // The kubectl drive path: apply the trigger pod; its sandbox
    // Create performs adopt + fork. Running == both succeeded.
    kubectl_apply(&fork_trigger_pod_yaml(&tree_id));
    wait_for_pod_running(INNER3_TRIGGER_POD, Duration::from_secs(420));

    // The held session must still be alive after adopt + fork.
    let watch_alive = watch.try_wait().expect("watch try_wait").is_none();
    let _ = watch.kill();
    if !watch_alive {
        teardown();
        panic!("held watch TCP/TLS session against the source broke across the annotation fork");
    }

    // Source /readyz recovers after the resume.
    let resume = Instant::now();
    loop {
        if matches!(curl_inner_api(&source_bridge, "/readyz"), Ok(ref b) if b.contains("ok")) {
            break;
        }
        if resume.elapsed() > Duration::from_secs(60) {
            let last = curl_inner_api(&source_bridge, "/readyz");
            teardown();
            panic!("source /readyz never recovered after the annotation fork (last: {last:?})");
        }
        thread::sleep(Duration::from_millis(500));
    }

    // Criterion "shim CIDs still valid / exec still works": the
    // member pods' shims still dial their cached vsock CIDs (the shim
    // failed the trigger Create if adopt changed any CID).
    // The members are share-less, so prepare swapped each for a
    // restored copy on the SAME CID — this exec proves the preserved
    // CID answers.
    let echo = kubectl_exec_retry(INNER3_PODS[0], "k3s", "echo post-adopt-exec-ok", 5);
    match echo {
        Ok(ref out) if out.contains("post-adopt-exec-ok") => {}
        other => {
            teardown();
            panic!("post-adopt exec into the source server pod failed: {other:?}");
        }
    }

    // The fork bridge is the new 3-port bridge (the trigger pod's own
    // bridge also appeared, but it carries a single TAP).
    let fork_bridge = list_k7_bridges()
        .into_iter()
        .filter(|b| !bridges_before.contains(b))
        .find(|b| bridge_port_count(b) == 3);
    let Some(fork_bridge) = fork_bridge else {
        teardown();
        panic!("no new 3-port fork bridge appeared");
    };
    eprintln!("  source bridge={source_bridge} fork bridge={fork_bridge}");

    // Source still healthy; the fork independently shows the same 3
    // Ready nodes at the preserved guest IPs.
    assert_three_ready_nodes_via(&source_bridge, "source");
    assert_three_ready_nodes_via(&fork_bridge, "fork");

    teardown();
}
