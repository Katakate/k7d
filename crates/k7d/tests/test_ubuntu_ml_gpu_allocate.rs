//! `Allocate` injects assigned fake GPU IDs into the container.
//!
//! A 2-GPU pod sees exactly those IDs in `NVIDIA_VISIBLE_DEVICES`,
//! and they match the kubelet pod-resources API on the node.
//!
//! Mock only — not CUDA, not NVML, not `/dev/nvidia*`.
//! Reuses `bring_up_cluster` (Flannel). Does not touch `crates/k7d/src`.

mod common;

use std::collections::BTreeSet;
use std::path::Path;
use std::time::{Duration, Instant};

use common::ml_platform::{
    apply_fixture, build_fake_gpu_plugin, fixture, gpu_diagnostics, install_plugin_binary,
    parse_pod_resource_devices, pod_resource_gpu_ids, wait_gpu_registered, FIXTURE_READY,
    GPU_PER_NODE, RESOURCE,
};
use common::ubuntu_k3s::{apply_yaml, bring_up_cluster, kubectl, pod_phase, BUSYBOX};

const POD: &str = "gpu-allocate-2";
const CONTAINER: &str = "busybox";

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
  - name: {CONTAINER}
    image: {BUSYBOX}
    imagePullPolicy: IfNotPresent
    command: ["sleep", "3600"]
    resources:
      limits:
        {RESOURCE}: "{gpus}"
"#
    )
}

fn wait_pod_phase(kubeconfig: &Path, name: &str, want: &str, ceiling: Duration) {
    let start = Instant::now();
    loop {
        let phase = pod_phase(kubeconfig, name);
        if phase == want {
            eprintln!("ml-gpu-allocate: {name} {want} after {:?}", start.elapsed());
            return;
        }
        if start.elapsed() > ceiling {
            panic!(
                "{name} never {want} after {ceiling:?} (phase={phase})\n{}",
                gpu_diagnostics(kubeconfig)
            );
        }
        eprintln!("ml-gpu-allocate: {name} phase {phase} want {want}");
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn parse_visible_ids(raw: &str) -> Vec<String> {
    let mut ids: Vec<String> = raw
        .trim()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

fn nvidia_visible_devices(kubeconfig: &Path, pod: &str) -> String {
    kubectl(
        kubeconfig,
        &[
            "exec",
            pod,
            "-c",
            CONTAINER,
            "--",
            "printenv",
            "NVIDIA_VISIBLE_DEVICES",
        ],
    )
    .unwrap_or_else(|e| {
        panic!(
            "exec {pod} printenv NVIDIA_VISIBLE_DEVICES: {e}\n{}",
            gpu_diagnostics(kubeconfig)
        )
    })
}

#[test]
fn parse_pod_resource_devices_keeps_named_gpu_rows() {
    let body = r#"[{"namespace":"default","name":"gpu-allocate-2","container":"busybox","resource":"nvidia.com/gpu","ids":["fake-gpu-1","fake-gpu-0"]},{"namespace":"default","name":"other","container":"busybox","resource":"nvidia.com/gpu","ids":["fake-gpu-0"]}]"#;
    let rows = parse_pod_resource_devices(body, "default", POD, RESOURCE);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].ids, vec!["fake-gpu-1", "fake-gpu-0"]);
}

/// 3-node Ubuntu k3s: a 2-GPU pod sees exactly its assigned fake IDs.
#[test]
fn test_ubuntu_ml_gpu_allocate_two_ids_match_pod_resources() {
    let _ = env_logger::builder().is_test(true).try_init();

    let src = std::fs::read_to_string(fixture("fake-gpu-plugin/main.go")).expect("plugin src");
    assert!(
        src.contains("NVIDIA_VISIBLE_DEVICES") && src.contains("DevicesIDs"),
        "Allocate must set NVIDIA_VISIBLE_DEVICES from DevicesIDs\n{src}"
    );
    assert!(
        src.contains("-list-pod-resources"),
        "plugin must list kubelet pod-resources for the test helper\n{src}"
    );
    assert_eq!(GPU_PER_NODE, 2, "default GPU_PER_NODE must stay 2");

    let mut cluster = bring_up_cluster();
    let plugin = build_fake_gpu_plugin();
    install_plugin_binary(&mut cluster, &plugin);
    let kube = cluster.kubeconfig.clone();
    apply_fixture(&kube, "device-plugin-ds.yaml");
    kubectl(
        &kube,
        &["rollout", "status", "ds/fake-gpu-plugin", "--timeout=180s"],
    )
    .unwrap_or_else(|e| panic!("fake-gpu-plugin rollout: {e}\n{}", gpu_diagnostics(&kube)));

    let names = cluster.names();
    wait_gpu_registered(&kube, &names, FIXTURE_READY);

    apply_yaml(&kube, POD, &gpu_pod_yaml(POD, GPU_PER_NODE));
    wait_pod_phase(&kube, POD, "Running", FIXTURE_READY);

    let env_raw = nvidia_visible_devices(&kube, POD);
    let env_ids = parse_visible_ids(&env_raw);
    assert_eq!(
        env_ids.len(),
        GPU_PER_NODE as usize,
        "{POD} NVIDIA_VISIBLE_DEVICES={env_raw:?} must have exactly {GPU_PER_NODE} ids\n{}",
        gpu_diagnostics(&kube)
    );
    let want: BTreeSet<String> = ["fake-gpu-0", "fake-gpu-1"]
        .into_iter()
        .map(str::to_string)
        .collect();
    let env_set: BTreeSet<String> = env_ids.iter().cloned().collect();
    assert_eq!(
        env_set,
        want,
        "{POD} NVIDIA_VISIBLE_DEVICES={env_raw:?} want {want:?}\n{}",
        gpu_diagnostics(&kube)
    );

    let pr_ids = pod_resource_gpu_ids(&mut cluster, &kube, "default", POD);
    let pr_set: BTreeSet<String> = pr_ids.iter().cloned().collect();
    assert_eq!(
        pr_set,
        env_set,
        "{POD} pod-resources {pr_ids:?} != NVIDIA_VISIBLE_DEVICES {env_ids:?}\n{}",
        gpu_diagnostics(&kube)
    );
    eprintln!(
        "ml-gpu-allocate: {POD} NVIDIA_VISIBLE_DEVICES={env_raw} matches pod-resources {pr_ids:?}"
    );
}
