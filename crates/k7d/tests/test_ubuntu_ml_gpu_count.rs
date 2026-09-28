//! Configurable `FAKE_GPU_COUNT` on the fake GPU plugin.
//!
//! Default stays 2 (the JobSet Capacity=2 contract). This test patches the
//! DaemonSet to 8: an 8-GPU pod fits a node; two 1-GPU pods with
//! hostname anti-affinity fragment the leftover nodes; a second
//! 8-GPU pod stays Pending (Insufficient nvidia.com/gpu).
//!
//! Mock only — not CUDA, not DeepSpeed, not GPU Operator, not VFIO.
//! Reuses `bring_up_cluster` (Flannel). Does not touch `crates/k7d/src`.

mod common;

use std::path::Path;
use std::time::{Duration, Instant};

use common::ml_platform::{
    apply_fixture, build_fake_gpu_plugin, fixture, gpu_diagnostics, install_plugin_binary,
    wait_gpu_registered_n, FIXTURE_READY, GPU_PER_NODE, RESOURCE,
};
use common::ubuntu_k3s::{apply_yaml, bring_up_cluster, kubectl, pod_phase, CHURN_PAUSE};

const GPU_COUNT: u32 = 8;
const FIT: &str = "gpu-fit-8";
const WAIT: &str = "gpu-wait-8";
const FRAG: [&str; 2] = ["gpu-frag-0", "gpu-frag-1"];
const FRAG_LABEL: &str = "gpu-frag";

fn gpu_pod_yaml(name: &str, gpus: u32) -> String {
    format!(
        r#"apiVersion: v1
kind: Pod
metadata:
  name: {name}
  namespace: default
spec:
  restartPolicy: Always
  containers:
  - name: pause
    image: {CHURN_PAUSE}
    imagePullPolicy: IfNotPresent
    resources:
      limits:
        {RESOURCE}: "{gpus}"
"#
    )
}

fn frag_pod_yaml(name: &str) -> String {
    format!(
        r#"apiVersion: v1
kind: Pod
metadata:
  name: {name}
  namespace: default
  labels:
    app: {FRAG_LABEL}
spec:
  restartPolicy: Always
  affinity:
    podAntiAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
      - labelSelector:
          matchLabels:
            app: {FRAG_LABEL}
        topologyKey: kubernetes.io/hostname
  containers:
  - name: pause
    image: {CHURN_PAUSE}
    imagePullPolicy: IfNotPresent
    resources:
      limits:
        {RESOURCE}: "1"
"#
    )
}

fn wait_pod_phase(kubeconfig: &Path, name: &str, want: &str, ceiling: Duration) {
    let start = Instant::now();
    loop {
        let phase = pod_phase(kubeconfig, name);
        if phase == want {
            eprintln!("ml-gpu-count: {name} {want} after {:?}", start.elapsed());
            return;
        }
        if start.elapsed() > ceiling {
            panic!(
                "{name} never {want} after {ceiling:?} (phase={phase})\n{}",
                gpu_diagnostics(kubeconfig)
            );
        }
        eprintln!("ml-gpu-count: {name} phase {phase} want {want}");
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn scheduled_reason_message(kubeconfig: &Path, name: &str) -> (String, String) {
    let reason = kubectl(
        kubeconfig,
        &[
            "get",
            "pod",
            name,
            "-o",
            "jsonpath={.status.conditions[?(@.type==\"PodScheduled\")].reason}",
        ],
    )
    .unwrap_or_default();
    let msg = kubectl(
        kubeconfig,
        &[
            "get",
            "pod",
            name,
            "-o",
            "jsonpath={.status.conditions[?(@.type==\"PodScheduled\")].message}",
        ],
    )
    .unwrap_or_default();
    (reason, msg)
}

fn wait_unschedulable_gpu(kubeconfig: &Path, name: &str, ceiling: Duration) {
    let start = Instant::now();
    loop {
        let phase = pod_phase(kubeconfig, name);
        let (reason, msg) = scheduled_reason_message(kubeconfig, name);
        if phase == "Pending" && reason.contains("Unschedulable") && msg.contains(RESOURCE) {
            eprintln!(
                "ml-gpu-count: {name} Unschedulable ({RESOURCE}) after {:?}: {msg}",
                start.elapsed()
            );
            return;
        }
        if phase == "Running" {
            panic!(
                "{name} became Running — leftover nodes were not fragments\n{}",
                gpu_diagnostics(kubeconfig)
            );
        }
        if start.elapsed() > ceiling {
            panic!(
                "{name} never Unschedulable/{RESOURCE} after {ceiling:?} \
                 (phase={phase} reason={reason} msg={msg})\n{}",
                gpu_diagnostics(kubeconfig)
            );
        }
        eprintln!("ml-gpu-count: {name} phase={phase} reason={reason} msg={msg}");
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn set_fake_gpu_count(kubeconfig: &Path, n: u32) {
    kubectl(
        kubeconfig,
        &[
            "set",
            "env",
            "ds/fake-gpu-plugin",
            &format!("FAKE_GPU_COUNT={n}"),
        ],
    )
    .unwrap_or_else(|e| {
        panic!(
            "set FAKE_GPU_COUNT={n}: {e}\n{}",
            gpu_diagnostics(kubeconfig)
        )
    });
    kubectl(
        kubeconfig,
        &["rollout", "status", "ds/fake-gpu-plugin", "--timeout=180s"],
    )
    .unwrap_or_else(|e| {
        panic!(
            "fake-gpu-plugin rollout after FAKE_GPU_COUNT={n}: {e}\n{}",
            gpu_diagnostics(kubeconfig)
        )
    });
}

/// 3-node Ubuntu k3s + FAKE_GPU_COUNT=8: whole-node fit, then fragments.
#[test]
fn test_ubuntu_ml_gpu_count_eight_fits_and_fragments() {
    let _ = env_logger::builder().is_test(true).try_init();

    let ds = std::fs::read_to_string(fixture("device-plugin-ds.yaml")).expect("ds yaml");
    assert!(
        ds.contains("FAKE_GPU_COUNT") && ds.contains("value: \"2\""),
        "device-plugin DaemonSet must default FAKE_GPU_COUNT to \"2\"\n{ds}"
    );
    assert_eq!(GPU_PER_NODE, 2, "default GPU_PER_NODE must stay 2");

    let mut cluster = bring_up_cluster();
    let plugin = build_fake_gpu_plugin();
    install_plugin_binary(&mut cluster, &plugin);
    let kube = cluster.kubeconfig.clone();
    apply_fixture(&kube, "device-plugin-ds.yaml");
    apply_fixture(&kube, "dcgm-exporter.yaml");
    set_fake_gpu_count(&kube, GPU_COUNT);
    kubectl(
        &kube,
        &["rollout", "status", "ds/dcgm-exporter", "--timeout=180s"],
    )
    .unwrap_or_else(|e| panic!("dcgm-exporter rollout: {e}\n{}", gpu_diagnostics(&kube)));

    let names = cluster.names();
    let gpu = wait_gpu_registered_n(&kube, &names, GPU_COUNT, FIXTURE_READY);
    assert_eq!(gpu.capacity.len(), 3);
    for name in &names {
        assert_eq!(
            gpu.capacity.get(name),
            Some(&GPU_COUNT),
            "{name} Capacity {:?} want {GPU_COUNT}",
            gpu.capacity.get(name)
        );
    }

    apply_yaml(&kube, FIT, &gpu_pod_yaml(FIT, GPU_COUNT));
    wait_pod_phase(&kube, FIT, "Running", FIXTURE_READY);

    for name in FRAG {
        apply_yaml(&kube, name, &frag_pod_yaml(name));
    }
    for name in FRAG {
        wait_pod_phase(&kube, name, "Running", FIXTURE_READY);
    }

    apply_yaml(&kube, WAIT, &gpu_pod_yaml(WAIT, GPU_COUNT));
    wait_unschedulable_gpu(&kube, WAIT, FIXTURE_READY);
    std::thread::sleep(Duration::from_secs(8));
    assert_eq!(
        pod_phase(&kube, WAIT),
        "Pending",
        "{WAIT} left Pending after fragments; got {}\n{}",
        pod_phase(&kube, WAIT),
        gpu_diagnostics(&kube)
    );
    eprintln!("ml-gpu-count: {FIT} Running; {WAIT} stays Pending on 8-GPU fragments");
}
