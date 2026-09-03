//! Fake `nvidia.com/gpu` + dcgm-exporter-shaped scrape on a 25a-inc2
//! Ubuntu flannel cluster, then a warm fork .
//!
//! Mock only — not CUDA, not DeepSpeed, not GPU Operator, not VFIO.
//! Reuses `bring_up_cluster` (Flannel) and `FORK_UBUNTU_K3S_CLUSTER_3VM`.
//! Does not touch `crates/k7d/src`.

mod common;

use std::path::Path;
use std::time::{Duration, Instant};

use k7d::fork::fork_cluster_warm;
use k7d::latency::FORK_UBUNTU_K3S_CLUSTER_3VM;
use k7d::vm::Vm;

use common::ml_platform::{
    apply_gpu_dcgm_fixture, assert_dcgm_metrics, assert_gpu_consistent, fixture, gpu_diagnostics,
    gpu_used_via_bridge, gpu_used_via_kubectl, gpu_via_bridge, scrape_dcgm, sum,
    wait_gpu_registered, wait_gpu_used, BUSYBOX, FIXTURE_READY, GPU_PER_NODE,
    K3S_DEVICE_PLUGIN_DIR, KUBELET_DEVICE_PLUGIN_DIR, MODEL_NAME, RESOURCE,
};
use common::ubuntu::{failed_units, NODE_MEMORY_MB};
use common::ubuntu_k3s::{
    assert_no_restarts, bring_up_cluster, curl_api, curl_get, kubectl, nodes_ready_via,
    snapshot_via_bridge, snapshot_via_kubectl, wait_nodes_ready, wait_pod_phase_via, CHURN_PAUSE,
    CONVERGE,
};

const GPU_POD: &str = "gpu-pause";
const GPU_POD_CHILD: &str = "gpu-pause-child-extra";

fn gpu_pod_yaml(name: &str) -> String {
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
        {RESOURCE}: "1"
"#
    )
}

fn apply_pod(kubeconfig: &Path, name: &str, yaml: &str) {
    let path = format!("/tmp/k7d-ubuntu-ml-{name}-{}.yaml", std::process::id());
    std::fs::write(&path, yaml).unwrap_or_else(|e| panic!("write {name}: {e}"));
    kubectl(kubeconfig, &["apply", "-f", &path]).unwrap_or_else(|e| panic!("apply {name}: {e}"));
    let _ = std::fs::remove_file(&path);
}

fn wait_pod_running(kubeconfig: &Path, name: &str, ceiling: Duration) {
    let start = Instant::now();
    loop {
        match kubectl(
            kubeconfig,
            &["get", "pod", name, "-o", "jsonpath={.status.phase}"],
        ) {
            Ok(phase) if phase.trim() == "Running" => {
                eprintln!("ml-mocks: {name} Running after {:?}", start.elapsed());
                return;
            }
            Ok(phase) => eprintln!("ml-mocks: {name} phase {}", phase.trim()),
            Err(e) => eprintln!("ml-mocks: get {name}: {e}"),
        }
        if start.elapsed() > ceiling {
            panic!(
                "{name} never Running after {ceiling:?}\n{}",
                gpu_diagnostics(kubeconfig)
            );
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

/// 3-node Ubuntu k3s + fake GPU + DCGM fixture, then warm-fork and diverge.
#[test]
fn test_ubuntu_ml_mocks_gpu_dcgm_fork() {
    let _ = env_logger::builder().is_test(true).try_init();

    let ds = std::fs::read_to_string(fixture("device-plugin-ds.yaml")).expect("ds yaml");
    assert!(
        ds.contains(K3S_DEVICE_PLUGIN_DIR) && ds.contains(KUBELET_DEVICE_PLUGIN_DIR),
        "device-plugin DaemonSet must mount both kubelet device-plugin dirs \
         ({KUBELET_DEVICE_PLUGIN_DIR} is live on k3s v1.32.5; {K3S_DEVICE_PLUGIN_DIR} \
         is the spec-31a name — CHALLENGES #146)"
    );
    assert!(
        ds.contains("PLUGIN_SOCK_DIR"),
        "device-plugin DaemonSet must set PLUGIN_SOCK_DIR"
    );
    assert!(
        ds.contains(BUSYBOX),
        "device-plugin DaemonSet must use the digest-pinned busybox"
    );
    let dcgm = std::fs::read_to_string(fixture("dcgm-exporter.yaml")).expect("dcgm yaml");
    assert!(dcgm.contains("DCGM_FI_DEV_GPU_UTIL") && dcgm.contains("DCGM_FI_DEV_FB_USED"));
    assert!(dcgm.contains("9400") && dcgm.contains(MODEL_NAME));
    assert!(dcgm.contains(BUSYBOX));

    let mut cluster = bring_up_cluster();
    let before_pod = apply_gpu_dcgm_fixture(&mut cluster);
    let kube = cluster.kubeconfig.clone();
    let names = cluster.names();
    assert_eq!(before_pod.capacity.len(), 3);
    let used0 = gpu_used_via_kubectl(&kube);
    assert_gpu_consistent(&before_pod, &used0, &names, 0, "source before gpu-pause");

    apply_pod(&kube, GPU_POD, &gpu_pod_yaml(GPU_POD));
    wait_pod_running(&kube, GPU_POD, FIXTURE_READY);
    let after_pod = wait_gpu_registered(&kube, &names, Duration::from_secs(30));
    let used = wait_gpu_used(&kube, 1, Duration::from_secs(60), "source after gpu-pause");
    assert_gpu_consistent(&after_pod, &used, &names, 1, "source after gpu-pause");

    let src_bridge = cluster.bridge().to_string();
    let metrics = scrape_dcgm(&src_bridge, cluster.server_ip)
        .unwrap_or_else(|e| panic!("source DCGM scrape: {e}\n{}", gpu_diagnostics(&kube)));
    assert_dcgm_metrics(&metrics, "source");
    eprintln!("ml-mocks: source DCGM scrape ok ({} B)", metrics.len());

    wait_nodes_ready(&kube, &names, Duration::from_secs(120));
    let before = snapshot_via_kubectl(&kube);
    assert!(
        before.keys().any(|k| k.ends_with(&format!("/{GPU_POD}"))),
        "gpu pause pod missing from restart snapshot: {before:?}"
    );
    assert!(
        before
            .keys()
            .filter(|k| k.contains("fake-gpu-plugin-"))
            .count()
            >= 3,
        "expected a restart-count entry per fake-gpu-plugin pod: {before:?}"
    );

    cluster
        .server
        .prepare_fork_source()
        .expect("prepare server");
    cluster
        .agent1
        .prepare_fork_source()
        .expect("prepare agent-1");
    cluster
        .agent2
        .prepare_fork_source()
        .expect("prepare agent-2");

    let bridges_before: Vec<String> = std::fs::read_dir("/sys/class/net")
        .expect("net")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("k7-br-"))
        .collect();

    let mut sources: Vec<(&mut Vm, u32)> = vec![
        (&mut cluster.server, 0),
        (&mut cluster.agent1, 1),
        (&mut cluster.agent2, 2),
    ];
    let fork_start = Instant::now();
    let (fork_net, mut forks) = fork_cluster_warm(
        &cluster.net,
        &mut sources,
        "ubmlf",
        &[None, None, None],
        &[None, None, None],
        &["ubuntu-ml-0", "ubuntu-ml-1", "ubuntu-ml-2"],
    )
    .expect("warm fork of the Ubuntu ML-mock cluster");
    let fork_latency = fork_start.elapsed();
    eprintln!(
        "MEASUREMENT ubuntu ml-mocks cluster warm fork (3 × {NODE_MEMORY_MB} MB): {fork_latency:?} \
         target=1s budget={FORK_UBUNTU_K3S_CLUSTER_3VM:?}"
    );
    if fork_latency >= Duration::from_secs(1) {
        eprintln!(
            "FINDING the referenced work: cluster fork {fork_latency:?} missed the sub-second target"
        );
    }
    assert!(
        fork_latency < FORK_UBUNTU_K3S_CLUSTER_3VM,
        "cluster fork {fork_latency:?} over {FORK_UBUNTU_K3S_CLUSTER_3VM:?} — \
         do not widen FORK_UBUNTU_K3S_CLUSTER_3VM"
    );

    let child_bridge = fork_net.bridge_name().to_string();
    assert!(
        !bridges_before.contains(&child_bridge),
        "child bridge should be new: {child_bridge} in {bridges_before:?}"
    );
    assert_eq!(forks.len(), 3, "fork must clone every member");
    assert_eq!(
        forks[0].guest_ip(),
        Some(cluster.server_ip),
        "child server keeps the source guest IP on its own bridge"
    );

    for (i, child) in forks.iter_mut().enumerate() {
        child
            .start()
            .unwrap_or_else(|e| panic!("child-{i} start: {e}"));
        let mut ag = child
            .connect_agent(Duration::from_secs(90))
            .unwrap_or_else(|e| panic!("child-{i} agent: {e}"));
        let child_failed = failed_units(&mut ag, &format!("child-{i}"));
        let newly: Vec<_> = child_failed.difference(&cluster.source_failed[i]).collect();
        assert!(
            newly.is_empty(),
            "child-{i}: units failed that were fine on the source: {newly:?}"
        );
    }

    let certs = cluster.certs_dir.clone();
    let start = Instant::now();
    loop {
        let src_pods = snapshot_via_bridge(&src_bridge, &certs)
            .unwrap_or_else(|e| panic!("source pods via {src_bridge}: {e}"));
        let child_pods = snapshot_via_bridge(&child_bridge, &certs)
            .unwrap_or_else(|e| panic!("child pods via {child_bridge}: {e}"));
        assert_no_restarts(&before, &src_pods, "source");
        assert_no_restarts(&before, &child_pods, "child");
        let src_ready = nodes_ready_via(&src_bridge, &certs, &names);
        let child_ready = nodes_ready_via(&child_bridge, &certs, &names);
        let src_gpu = gpu_via_bridge(&src_bridge, &certs).ok();
        let child_gpu = gpu_via_bridge(&child_bridge, &certs).ok();
        let src_used = gpu_used_via_bridge(&src_bridge, &certs).ok();
        let child_used = gpu_used_via_bridge(&child_bridge, &certs).ok();
        let gpu_ok = src_gpu.as_ref().is_some_and(|g| {
            g.capacity.len() == 3 && g.capacity.values().all(|c| *c == GPU_PER_NODE)
        }) && child_gpu.as_ref().is_some_and(|g| {
            g.capacity.len() == 3 && g.capacity.values().all(|c| *c == GPU_PER_NODE)
        }) && src_used.as_ref().is_some_and(|u| sum(u) == 1)
            && child_used.as_ref().is_some_and(|u| sum(u) == 1);
        if src_ready && child_ready && gpu_ok && start.elapsed() >= Duration::from_secs(5) {
            eprintln!(
                "fork: both clusters Ready, {RESOURCE} Capacity+used consistent, \
                 zero restarts across {:?}",
                start.elapsed()
            );
            break;
        }
        if start.elapsed() > CONVERGE {
            panic!(
                "fork: clusters did not converge Ready+Capacity+used in {CONVERGE:?} \
                 (src_ready={src_ready} child_ready={child_ready} \
                 src_gpu={src_gpu:?} child_gpu={child_gpu:?} \
                 src_used={src_used:?} child_used={child_used:?})"
            );
        }
        std::thread::sleep(Duration::from_secs(2));
    }

    wait_pod_phase_via(
        &child_bridge,
        &certs,
        "default",
        GPU_POD,
        "Running",
        Duration::from_secs(60),
    );
    let child_gpu =
        gpu_via_bridge(&child_bridge, &certs).unwrap_or_else(|e| panic!("child nodes: {e}"));
    let child_used = gpu_used_via_bridge(&child_bridge, &certs)
        .unwrap_or_else(|e| panic!("child gpu used: {e}"));
    assert_gpu_consistent(&child_gpu, &child_used, &names, 1, "child");
    let src_gpu =
        gpu_via_bridge(&src_bridge, &certs).unwrap_or_else(|e| panic!("source nodes: {e}"));
    let src_used =
        gpu_used_via_bridge(&src_bridge, &certs).unwrap_or_else(|e| panic!("source gpu used: {e}"));
    assert_gpu_consistent(&src_gpu, &src_used, &names, 1, "source-after-fork");

    let child_metrics = scrape_dcgm(&child_bridge, cluster.server_ip)
        .unwrap_or_else(|e| panic!("child DCGM scrape: {e}"));
    assert_dcgm_metrics(&child_metrics, "child");
    eprintln!("ml-mocks: child DCGM scrape ok ({} B)", child_metrics.len());

    let child_pod = format!(
        r#"{{"apiVersion":"v1","kind":"Pod","metadata":{{"name":"{GPU_POD_CHILD}"}},"spec":{{"restartPolicy":"Always","containers":[{{"name":"pause","image":"{CHURN_PAUSE}","imagePullPolicy":"IfNotPresent","resources":{{"limits":{{"{RESOURCE}":"1"}}}}}}]}}}}"#
    );
    curl_api(
        &child_bridge,
        &certs,
        "POST",
        "/api/v1/namespaces/default/pods",
        Some(&child_pod),
    )
    .expect("create child-only GPU pod");
    wait_pod_phase_via(
        &child_bridge,
        &certs,
        "default",
        GPU_POD_CHILD,
        "Running",
        FIXTURE_READY,
    );
    let child_after = gpu_via_bridge(&child_bridge, &certs)
        .unwrap_or_else(|e| panic!("child nodes after extra pod: {e}"));
    let child_used_after = gpu_used_via_bridge(&child_bridge, &certs)
        .unwrap_or_else(|e| panic!("child gpu used after extra: {e}"));
    assert_gpu_consistent(
        &child_after,
        &child_used_after,
        &names,
        2,
        "child-after-extra-gpu-pod",
    );

    let src_after = gpu_via_bridge(&src_bridge, &certs)
        .unwrap_or_else(|e| panic!("source nodes after child extra pod: {e}"));
    let src_used_after = gpu_used_via_bridge(&src_bridge, &certs)
        .unwrap_or_else(|e| panic!("source gpu used after child extra: {e}"));
    assert_gpu_consistent(
        &src_after,
        &src_used_after,
        &names,
        1,
        "source-must-not-see-child-gpu",
    );
    let src_see = curl_get(
        &src_bridge,
        &certs,
        &format!("/api/v1/namespaces/default/pods/{GPU_POD_CHILD}"),
    );
    assert!(
        src_see
            .as_ref()
            .map(|b| b.contains("NotFound") || b.contains("not found"))
            .unwrap_or(true)
            || src_see
                .as_ref()
                .err()
                .map(|e| e.contains("404") || e.contains("NotFound"))
                .unwrap_or(false),
        "source cluster saw the child-only extra GPU pod: {src_see:?}"
    );
    eprintln!(
        "fork: source {RESOURCE} used still 1; child-only {GPU_POD_CHILD} is invisible on source"
    );

    for child in &mut forks {
        child.shutdown();
    }
    drop(fork_net);
}
