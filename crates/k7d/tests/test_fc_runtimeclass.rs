//! RuntimeClass `k7-fc`: handler/ConfigPath selects Firecracker without the
//! pod annotation, and CRI exec / kube Ready work the
//! same as native `k7`.
//!
//! This node's k3s 1.36 / containerd 2.3.3 does not stamp
//! `io.kubernetes.cri.runtime-handler` on the sandbox OCI spec
//! (CHALLENGES #228). `ensure_k7_fc_runtime_registered` therefore
//! registers `runtimes.k7-fc` with a ConfigPath toml
//! (`backend = "firecracker"`) and no `BinaryName`.

mod common;

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

/// Pods on this backend cold-boot a VM — same budget as `test_fc_pod`.
const POD_READY: Duration = Duration::from_secs(240);

fn ensure_fc_runtimeclass_node() -> common::LeakGuard {
    common::ensure_firecracker_installed();
    common::ensure_pod_annotations_forwarded();
    let guard = common::ensure_shim_installed();
    common::ensure_k7_fc_runtime_registered();
    guard
}

struct PodGuard(String);

impl Drop for PodGuard {
    fn drop(&mut self) {
        let _ = Command::new("kubectl")
            .args([
                "delete",
                "pod",
                &self.0,
                "--ignore-not-found",
                "--wait=true",
                "--timeout=60s",
                "--grace-period=1",
            ])
            .output();
    }
}

fn kubectl_apply(yaml: &str) -> Result<(), String> {
    common::kubectl_apply(&common::pin_to_local_node(yaml))
}

fn kubectl_delete_pod(name: &str) {
    let _ = Command::new("kubectl")
        .args([
            "delete",
            "pod",
            name,
            "--ignore-not-found",
            "--wait=true",
            "--timeout=60s",
            "--grace-period=1",
        ])
        .output();
}

fn wait_for_containers_ready(name: &str, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        let out = Command::new("kubectl")
            .args([
                "get",
                "pod",
                name,
                "-o",
                "jsonpath={.status.containerStatuses[*].ready}",
            ])
            .output()
            .map_err(|e| e.to_string())?;
        let ready = String::from_utf8_lossy(&out.stdout);
        let flags: Vec<&str> = ready.split_whitespace().collect();
        if !flags.is_empty() && flags.iter().all(|f| *f == "true") {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "pod {name} containers not Ready within {timeout:?} (ready={ready}): {}",
                pod_diagnosis(name)
            ));
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn kubectl_exec_echo_hello(pod: &str, container: &str) -> Result<String, String> {
    let out = Command::new("timeout")
        .args([
            "15", "kubectl", "exec", pod, "-c", container, "--", "echo", "hello",
        ])
        .output()
        .map_err(|e| format!("kubectl exec: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    if out.status.success() {
        return Ok(stdout);
    }
    let code = out.status.code().unwrap_or(-1);
    Err(format!(
        "kubectl exec {pod} -c {container} -- echo hello failed (exit {code}): {stderr}{stdout}"
    ))
}

fn wait_for_pod_ready(name: &str, timeout: Duration) -> Result<Duration, String> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        let out = Command::new("kubectl")
            .args(["get", "pod", name, "-o", "jsonpath={.status.phase}"])
            .output()
            .map_err(|e| e.to_string())?;
        match String::from_utf8_lossy(&out.stdout).trim() {
            "Running" => return Ok(start.elapsed()),
            "Failed" => return Err(format!("pod {name} went Failed: {}", pod_diagnosis(name))),
            _ => std::thread::sleep(Duration::from_secs(1)),
        }
    }
    Err(format!(
        "pod {name} not Running within {timeout:?}: {}",
        pod_diagnosis(name)
    ))
}

fn pod_diagnosis(name: &str) -> String {
    let describe = Command::new("kubectl")
        .args(["describe", "pod", name])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let events: Vec<&str> = describe
        .lines()
        .skip_while(|l| !l.starts_with("Events:"))
        .take(20)
        .collect();
    let journal = Command::new("journalctl")
        .args(["-u", "k7d", "-n", "40", "--no-pager"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    format!("\n{}\n--- k7d ---\n{journal}", events.join("\n"))
}

fn fc_vm_info(pod: &str) -> k7d::control::VmInfo {
    let vm_id = common::pod_vm_id(pod);
    let mut client = k7d::control::Client::connect_env().expect("connect k7d daemon");
    let k7d::control::Response::VmList { vms } = client
        .call(&k7d::control::Request::ListVms)
        .expect("list_vms")
    else {
        panic!("unexpected list_vms response");
    };
    vms.into_iter()
        .find(|v| v.vm_id == vm_id)
        .unwrap_or_else(|| panic!("daemon does not list {vm_id} for pod {pod}"))
}

fn assert_on_firecracker(pod: &str) -> k7d::control::VmInfo {
    let info = fc_vm_info(pod);
    assert_eq!(
        info.backend,
        k7d::guest::Backend::Firecracker,
        "pod {pod} is runtimeClassName k7-fc but the daemon booted it on {:?}",
        info.backend
    );
    let jail = info
        .jail
        .as_ref()
        .unwrap_or_else(|| panic!("Firecracker VM {} reports no jail", info.vm_id));
    assert!(
        Path::new(&format!("/proc/{}", jail.pid)).is_dir(),
        "jailed pid {} is not alive",
        jail.pid
    );
    info
}

fn kubectl_jsonpath(kind: &str, name: &str, path: &str) -> String {
    let out = Command::new("kubectl")
        .args(["get", kind, name, "-o", &format!("jsonpath={path}")])
        .output()
        .unwrap_or_else(|e| panic!("kubectl get {kind} {name}: {e}"));
    assert!(
        out.status.success(),
        "kubectl get {kind} {name} {path} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// `ensure_k7_fc_runtime_registered` is idempotent: a second call does
/// not rewrite the containerd template (so it does not restart k3s).
#[test]
fn test_k7_fc_runtime_registered_idempotent() {
    let _guard = ensure_fc_runtimeclass_node();

    let tmpl = "/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.tmpl";
    let before = std::fs::read_to_string(tmpl).expect("read containerd template");
    assert!(
        before.contains("runtimes.k7-fc]"),
        "k7-fc runtime block missing after first register:\n{before}"
    );
    assert!(
        before.contains("/etc/k7d/shim-k7-fc.toml"),
        "k7-fc ConfigPath missing after first register"
    );
    let k7_fc_section = before
        .split("runtimes.k7-fc]")
        .nth(1)
        .unwrap_or("")
        .split("\n[")
        .next()
        .unwrap_or("");
    assert!(
        !k7_fc_section.contains("BinaryName"),
        "k7-fc block must not set BinaryName:\n{k7_fc_section}"
    );
    let toml = std::fs::read_to_string(common::SHIM_FC_CONFIG_PATH).expect("read shim-k7-fc.toml");
    assert!(
        toml.contains("backend = \"firecracker\""),
        "shim-k7-fc.toml: {toml:?}"
    );

    let mtime_before = std::fs::metadata(tmpl).unwrap().modified().unwrap();
    common::ensure_k7_fc_runtime_registered();
    let after = std::fs::read_to_string(tmpl).expect("re-read containerd template");
    assert_eq!(
        before, after,
        "second register rewrote the containerd template"
    );
    let mtime_after = std::fs::metadata(tmpl).unwrap().modified().unwrap();
    assert_eq!(
        mtime_before, mtime_after,
        "second register touched the containerd template mtime (would restart k3s)"
    );

    let yaml = Command::new("kubectl")
        .args(["get", "runtimeclass", "k7-fc", "-o", "yaml"])
        .output()
        .expect("kubectl get runtimeclass k7-fc");
    assert!(yaml.status.success(), "RuntimeClass k7-fc missing");
    let text = String::from_utf8_lossy(&yaml.stdout);
    assert!(
        text.contains("handler: k7-fc"),
        "RuntimeClass k7-fc handler:\n{text}"
    );
    assert!(
        text.contains(common::K7_FC_OVERHEAD_MEMORY),
        "RuntimeClass k7-fc memory overhead {} missing:\n{text}",
        common::K7_FC_OVERHEAD_MEMORY
    );
    assert!(
        text.contains(common::K7_FC_OVERHEAD_CPU),
        "RuntimeClass k7-fc cpu overhead {} missing:\n{text}",
        common::K7_FC_OVERHEAD_CPU
    );
}

/// CRI exec and the kubelet exec readiness probe work on `k7-fc` the
/// same way they do on native `k7`.
/// Do not drop the probe: Ready is the signal.
#[test]
fn test_k7_fc_exec_probe_ready_and_native_exec() {
    let _guard = ensure_fc_runtimeclass_node();

    let fc_pod = common::unique_name("test-k7-fc-exec");
    kubectl_delete_pod(&fc_pod);
    let _fc = PodGuard(fc_pod.clone());
    kubectl_apply(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-k7-fc-exec
spec:
  runtimeClassName: k7-fc
  containers:
  - name: sandbox
    image: busybox:1.36
    command: ["sh", "-c", "sleep infinity"]
    readinessProbe:
      exec:
        command: ["/bin/sh", "-c", "true"]
      initialDelaySeconds: 0
      periodSeconds: 10
      timeoutSeconds: 5
      failureThreshold: 6
"#,
    )
    .unwrap();
    wait_for_pod_ready(&fc_pod, POD_READY).unwrap();
    wait_for_containers_ready(&fc_pod, Duration::from_secs(120))
        .expect("k7-fc exec readiness probe must flip Ready");
    assert_on_firecracker(&fc_pod);
    let hello = kubectl_exec_echo_hello(&fc_pod, "sandbox")
        .expect("k7-fc kubectl exec must return within 15s");
    assert!(hello.contains("hello"), "k7-fc exec stdout: {hello:?}");

    let native_pod = common::unique_name("test-k7-native-exec");
    kubectl_delete_pod(&native_pod);
    let _native = PodGuard(native_pod.clone());
    kubectl_apply(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-k7-native-exec
spec:
  runtimeClassName: k7
  containers:
  - name: sandbox
    image: busybox:1.36
    command: ["sh", "-c", "sleep infinity"]
    readinessProbe:
      exec:
        command: ["/bin/sh", "-c", "true"]
      initialDelaySeconds: 0
      periodSeconds: 10
      timeoutSeconds: 5
      failureThreshold: 6
"#,
    )
    .unwrap();
    wait_for_pod_ready(&native_pod, POD_READY).unwrap();
    wait_for_containers_ready(&native_pod, Duration::from_secs(120))
        .expect("native k7 exec readiness probe must still flip Ready");
    let native = kubectl_exec_echo_hello(&native_pod, "sandbox")
        .expect("native k7 kubectl exec must still return within 15s");
    assert!(
        native.contains("hello"),
        "native k7 exec stdout: {native:?}"
    );
}

/// `runtimeClassName: k7-fc` with no backend annotation boots Firecracker;
/// `runtimeClassName: k7` with no annotation stays native.
#[test]
fn test_k7_fc_pod_without_annotation_is_firecracker_k7_stays_native() {
    let _guard = ensure_fc_runtimeclass_node();

    let fc_pod = common::unique_name("test-k7-fc-rc");
    kubectl_delete_pod(&fc_pod);
    let _fc = PodGuard(fc_pod.clone());
    kubectl_apply(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-k7-fc-rc
spec:
  runtimeClassName: k7-fc
  containers:
  - name: main
    image: busybox:1.36
    command: ["sh", "-c", "sleep infinity"]
"#,
    )
    .unwrap();
    wait_for_pod_ready(&fc_pod, POD_READY).unwrap();
    assert_on_firecracker(&fc_pod);

    let native_pod = common::unique_name("test-k7-native-rc");
    kubectl_delete_pod(&native_pod);
    let _native = PodGuard(native_pod.clone());
    kubectl_apply(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-k7-native-rc
spec:
  runtimeClassName: k7
  containers:
  - name: main
    image: busybox:1.36
    command: ["sh", "-c", "sleep infinity"]
"#,
    )
    .unwrap();
    wait_for_pod_ready(&native_pod, POD_READY).unwrap();
    let info = fc_vm_info(&native_pod);
    assert_eq!(
        info.backend,
        k7d::guest::Backend::Native,
        "runtimeClassName: k7 with no annotation must stay native, got {:?}",
        info.backend
    );
    assert!(
        info.jail.is_none(),
        "native VM {} unexpectedly reports a jail",
        info.vm_id
    );
}

/// Explicit `backend: native` on a `k7-fc` pod is a loud Create error.
#[test]
fn test_k7_fc_plus_native_annotation_contradicts() {
    let _guard = ensure_fc_runtimeclass_node();
    let pod = common::unique_name("test-k7-fc-contradict");
    kubectl_delete_pod(&pod);
    let _pod = PodGuard(pod.clone());
    kubectl_apply(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-k7-fc-contradict
  annotations:
    k7d.katakate.org/backend: native
spec:
  runtimeClassName: k7-fc
  containers:
  - name: main
    image: busybox:1.36
    command: ["sh", "-c", "sleep infinity"]
"#,
    )
    .unwrap();

    let deadline = Instant::now() + Duration::from_secs(120);
    let mut saw = false;
    while Instant::now() < deadline {
        let describe = Command::new("kubectl")
            .args(["describe", "pod", &pod])
            .output()
            .expect("kubectl describe");
        let text = String::from_utf8_lossy(&describe.stdout);
        if text.contains("contradicts") {
            saw = true;
            break;
        }
        let phase = Command::new("kubectl")
            .args(["get", "pod", &pod, "-o", "jsonpath={.status.phase}"])
            .output()
            .expect("kubectl get");
        assert_ne!(
            String::from_utf8_lossy(&phase.stdout).trim(),
            "Running",
            "k7-fc + backend=native reached Running — the contradiction was silent"
        );
        std::thread::sleep(Duration::from_secs(2));
    }
    assert!(
        saw,
        "k7-fc + native annotation must fail Create with 'contradicts': {}",
        pod_diagnosis(&pod)
    );
}

/// k7-fc overhead is on the class object and on a scheduled pod.
#[test]
fn test_k7_fc_podoverhead_on_runtimeclass_and_pod() {
    let _guard = ensure_fc_runtimeclass_node();

    let rc_mem = kubectl_jsonpath("runtimeclass", "k7-fc", "{.overhead.podFixed.memory}");
    let rc_cpu = kubectl_jsonpath("runtimeclass", "k7-fc", "{.overhead.podFixed.cpu}");
    assert_eq!(
        rc_mem,
        common::K7_FC_OVERHEAD_MEMORY,
        "RuntimeClass k7-fc memory overhead"
    );
    assert_eq!(
        rc_cpu,
        common::K7_FC_OVERHEAD_CPU,
        "RuntimeClass k7-fc cpu overhead"
    );

    let pod = common::unique_name("test-k7-fc-oh");
    kubectl_delete_pod(&pod);
    let _pod = PodGuard(pod.clone());
    kubectl_apply(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-k7-fc-oh
spec:
  runtimeClassName: k7-fc
  containers:
  - name: main
    image: busybox:1.36
    command: ["sh", "-c", "sleep infinity"]
    resources:
      requests:
        cpu: "100m"
        memory: "64Mi"
      limits:
        cpu: "100m"
        memory: "64Mi"
"#,
    )
    .unwrap();
    wait_for_pod_ready(&pod, POD_READY).unwrap();

    let overhead_mem = kubectl_jsonpath("pod", &pod, "{.spec.overhead.memory}");
    let overhead_cpu = kubectl_jsonpath("pod", &pod, "{.spec.overhead.cpu}");
    assert_eq!(
        overhead_mem,
        common::K7_FC_OVERHEAD_MEMORY,
        "pod spec.overhead.memory"
    );
    assert_eq!(
        overhead_cpu,
        common::K7_FC_OVERHEAD_CPU,
        "pod spec.overhead.cpu"
    );
    let qos = kubectl_jsonpath("pod", &pod, "{.status.qosClass}");
    assert!(
        qos == "Burstable" || qos == "Guaranteed",
        "pod qosClass {qos:?} — expected Burstable or Guaranteed once overhead is applied"
    );
    assert_on_firecracker(&pod);
}

/// `fork-source-*` on a `k7-fc` pod goes through `ForkVm`, not native
/// VMM access (CHALLENGES #231).
#[test]
fn test_k7_fc_fork_source_annotation_adopts_child() {
    let _guard = ensure_fc_runtimeclass_node();

    let src = common::unique_name("test-k7-fc-fsrc");
    let fork = common::unique_name("test-k7-fc-fdst");
    kubectl_delete_pod(&src);
    kubectl_delete_pod(&fork);
    let _src = PodGuard(src.clone());
    let _fork = PodGuard(fork.clone());

    kubectl_apply(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-k7-fc-fsrc
spec:
  runtimeClassName: k7-fc
  containers:
  - name: main
    image: busybox:1.36
    command: ["sh", "-c", "sleep infinity"]
"#,
    )
    .unwrap();
    wait_for_pod_ready(&src, POD_READY).unwrap();
    let src_info = assert_on_firecracker(&src);
    let src_sandbox = common::pod_sandbox_id(&src);

    let mut client = k7d::control::Client::connect_env().expect("connect k7d daemon");
    let cluster_id = match client
        .call(&k7d::control::Request::LookupSandbox {
            sandbox_id: src_sandbox.clone(),
        })
        .expect("lookup_sandbox")
    {
        k7d::control::Response::SandboxFound { cluster_id, .. } => {
            cluster_id.unwrap_or_else(|| src_sandbox.clone())
        }
        other => panic!("lookup_sandbox: {other:?}"),
    };

    kubectl_apply(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-k7-fc-fdst
  annotations:
    k7d.katakate.org/fork-source-cluster: {cluster_id}
    k7d.katakate.org/fork-source-vm: {src_sandbox}
spec:
  runtimeClassName: k7-fc
  restartPolicy: Never
  containers:
  - name: main
    image: busybox:1.36
    command: ["sh", "-c", "sleep infinity"]
"#
    ))
    .unwrap();
    wait_for_pod_ready(&fork, POD_READY).unwrap();
    let fork_info = assert_on_firecracker(&fork);
    assert_ne!(
        fork_info.vm_id, src_info.vm_id,
        "fork must be a distinct VM"
    );
}
