//! KubeRay on the fake GPU fixture, then a warm fork.
//!
//! CPU-head RayCluster plus one worker that requests
//! `nvidia.com/gpu: 1` and schedules on the mock. Operand is
//! digest-pinned busybox (not `rayproject/ray`, not CUDA, not Ray
//! Train). RayJob is skipped: it needs a live Ray dashboard, which
//! this mock operand does not provide. Reuses `bring_up_cluster`
//! (Flannel) and `FORK_UBUNTU_K3S_CLUSTER_3VM`. Does not touch
//! `crates/k7d/src`.

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use k7d::fork::fork_cluster_warm;
use k7d::latency::FORK_UBUNTU_K3S_CLUSTER_3VM;
use k7d::vm::Vm;

use common::ml_platform::{
    apply_gpu_dcgm_fixture, assert_dcgm_metrics, assert_gpu_consistent, fixture, gpu_diagnostics,
    gpu_used_via_bridge, gpu_used_via_kubectl, gpu_via_bridge, gpu_via_kubectl, scrape_dcgm, sum,
    wait_gpu_used, BUSYBOX, FIXTURE_READY, RESOURCE,
};
use common::ubuntu::{failed_units, NODE_MEMORY_MB};
use common::ubuntu_helm::ensure_helm;
use common::ubuntu_k3s::{
    assert_no_restarts, bring_up_cluster, curl_api, curl_get, kubectl, nodes_ready_via,
    snapshot_pods_json, snapshot_via_bridge, snapshot_via_kubectl, wait_nodes_ready, CONVERGE,
};

const KUBERAY_VERSION: &str = "1.7.0";
const KUBERAY_CHART_URL: &str =
    "https://github.com/ray-project/kuberay-helm/releases/download/kuberay-operator-1.7.0/kuberay-operator-1.7.0.tgz";
const KUBERAY_CHART_SHA256: &str =
    "1a2a8087da487f9ff5c82f1a2bb227b2aff0acfd8d9a9249514db3daf61d0334";
const KUBERAY_IMAGE_UNPINNED: &str = "quay.io/kuberay/operator:v1.7.0";
const KUBERAY_IMAGE: &str = "quay.io/kuberay/operator:v1.7.0@sha256:4a779237ef1c5262a63840ccf42d0d67f0b74e911158fbcaee4478fb1560bce6";

const KUBERAY_NS: &str = "kuberay-system";
const RAYCLUSTER: &str = "gpu-raycluster";
const RAYCLUSTER_CHILD: &str = "gpu-raycluster-child";
const KUBERAY_READY: Duration = Duration::from_secs(300);
const OVERWRITE_CMD: &str = "ray.io/overwrite-container-cmd";

fn sha256_file(path: &Path) -> String {
    let out = Command::new("sha256sum")
        .arg(path)
        .output()
        .expect("sha256sum");
    assert!(out.status.success(), "sha256sum {path:?} failed");
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string()
}

fn fetch_kuberay_chart() -> PathBuf {
    let dest = PathBuf::from(format!(
        "/tmp/k7d-kuberay-operator-{KUBERAY_VERSION}-{}.tgz",
        std::process::id()
    ));
    let status = Command::new("curl")
        .args(["-fsSL", "-o"])
        .arg(&dest)
        .arg(KUBERAY_CHART_URL)
        .status()
        .expect("spawn curl kuberay chart");
    assert!(
        status.success(),
        "download {KUBERAY_CHART_URL} failed — refuse to apply an unpinned KubeRay"
    );
    let got = sha256_file(&dest);
    assert_eq!(
        got, KUBERAY_CHART_SHA256,
        "KubeRay {KUBERAY_VERSION} chart sha256 mismatch: got {got}, \
         want {KUBERAY_CHART_SHA256}"
    );
    dest
}

fn pin_kuberay_manifests(text: &str) -> String {
    for line in text.lines() {
        let t = line.trim();
        let Some(img) = t.strip_prefix("image:") else {
            continue;
        };
        let img = img.trim().trim_matches('"');
        if img.is_empty() {
            continue;
        }
        assert!(
            !img.ends_with(":latest") && !img.contains(":latest@"),
            "KubeRay {KUBERAY_VERSION} container image uses latest: {img}"
        );
    }
    assert!(
        text.contains(KUBERAY_IMAGE_UNPINNED),
        "templated chart missing {KUBERAY_IMAGE_UNPINNED}"
    );
    let pinned = text.replace(KUBERAY_IMAGE_UNPINNED, KUBERAY_IMAGE);
    assert!(
        pinned.contains("@sha256:4a779237ef1c5262a63840ccf42d0d67f0b74e911158fbcaee4478fb1560bce6"),
        "KubeRay operator image was not rewritten to a digest pin"
    );
    assert!(
        !pinned.contains(&format!("{KUBERAY_IMAGE_UNPINNED}\n"))
            && !pinned.contains(&format!("{KUBERAY_IMAGE_UNPINNED}\"")),
        "unpinned KubeRay image remains after rewrite"
    );
    pinned
}

fn install_kuberay(kubeconfig: &Path) {
    let helm = ensure_helm();
    let chart = fetch_kuberay_chart();
    kubectl(kubeconfig, &["create", "ns", KUBERAY_NS]).ok();
    let values = PathBuf::from(format!(
        "/tmp/k7d-kuberay-values-{}.yaml",
        std::process::id()
    ));
    std::fs::write(
        &values,
        r#"image:
  repository: quay.io/kuberay/operator
  tag: v1.7.0
env:
  - name: ENABLE_INIT_CONTAINER_INJECTION
    value: "false"
  - name: ENABLE_PROBES_INJECTION
    value: "false"
"#,
    )
    .expect("write kuberay values");
    let out = Command::new(&helm)
        .args([
            "template",
            "kuberay-operator",
            &chart.to_string_lossy(),
            "--namespace",
            KUBERAY_NS,
            "--include-crds",
            "-f",
            &values.to_string_lossy(),
        ])
        .output()
        .expect("helm template kuberay-operator");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "helm template KubeRay {KUBERAY_VERSION} failed: {stderr}{stdout}"
    );
    assert!(
        stdout.contains("ENABLE_INIT_CONTAINER_INJECTION")
            && stdout.contains("ENABLE_PROBES_INJECTION"),
        "templated operator is missing the GCS/probe injection opt-out:\n{stdout}"
    );
    let pinned = pin_kuberay_manifests(&stdout);
    let dest = PathBuf::from(format!(
        "/tmp/k7d-kuberay-{KUBERAY_VERSION}-{}.yaml",
        std::process::id()
    ));
    std::fs::write(&dest, pinned).expect("write pinned kuberay manifests");
    kubectl(
        kubeconfig,
        &["apply", "--server-side", "-f", &dest.to_string_lossy()],
    )
    .unwrap_or_else(|e| panic!("kubectl apply --server-side KubeRay {KUBERAY_VERSION}: {e}"));
    let start = Instant::now();
    loop {
        let crd = kubectl(
            kubeconfig,
            &[
                "get",
                "crd",
                "rayclusters.ray.io",
                "-o",
                "jsonpath={.status.conditions[?(@.type==\"Established\")].status}",
            ],
        )
        .unwrap_or_default();
        let deploy = kubectl(
            kubeconfig,
            &[
                "rollout",
                "status",
                "deploy/kuberay-operator",
                "-n",
                KUBERAY_NS,
                "--timeout=15s",
            ],
        );
        if crd.trim() == "True" && deploy.is_ok() {
            eprintln!(
                "ml-kuberay: KubeRay {KUBERAY_VERSION} operator Ready + RayCluster CRD after {:?}",
                start.elapsed()
            );
            return;
        }
        if start.elapsed() > KUBERAY_READY {
            panic!(
                "KubeRay {KUBERAY_VERSION} never Ready after {KUBERAY_READY:?} \
                 (crd={:?} deploy={:?})\n{}",
                crd.trim(),
                deploy.as_ref().err(),
                gpu_diagnostics(kubeconfig)
            );
        }
        eprintln!(
            "ml-kuberay: waiting for KubeRay operator (crd={})",
            crd.trim()
        );
        std::thread::sleep(Duration::from_secs(3));
    }
}

fn apply_raycluster(kubeconfig: &Path, name: &str) {
    let path = fixture(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
    assert!(
        text.contains("@sha256:") && !text.contains(":latest"),
        "{name} must pin images by digest"
    );
    assert!(
        text.contains(OVERWRITE_CMD),
        "{name} must set {OVERWRITE_CMD} so KubeRay does not inject `ray start` \
         into the busybox operand (CHALLENGES #157)"
    );
    let start = Instant::now();
    loop {
        match kubectl(kubeconfig, &["apply", "-f", &path.to_string_lossy()]) {
            Ok(_) => {
                eprintln!("ml-kuberay: applied {name} after {:?}", start.elapsed());
                return;
            }
            Err(e) if start.elapsed() < Duration::from_secs(90) => {
                eprintln!(
                    "ml-kuberay: apply {name} failed (CRD/operator not ready?): {e}; retry {:?}",
                    start.elapsed()
                );
                std::thread::sleep(Duration::from_secs(3));
            }
            Err(e) => panic!(
                "apply {name} failed for 90s (KubeRay operator?): {e}\n{}",
                gpu_diagnostics(kubeconfig)
            ),
        }
    }
}

fn wait_ray_pods_running(kubeconfig: &Path, cluster: &str, want_workers: usize, ceiling: Duration) {
    let start = Instant::now();
    let selector = format!("ray.io/cluster={cluster}");
    loop {
        let body = kubectl(kubeconfig, &["get", "pods", "-l", &selector, "-o", "json"])
            .unwrap_or_default();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap_or(serde_json::json!({}));
        let empty = Vec::new();
        let mut heads = 0usize;
        let mut workers = 0usize;
        let mut summary = Vec::new();
        for p in v["items"].as_array().unwrap_or(&empty) {
            let name = p["metadata"]["name"].as_str().unwrap_or("");
            let kind = p["metadata"]["labels"]["ray.io/node-type"]
                .as_str()
                .unwrap_or("");
            let phase = p["status"]["phase"].as_str().unwrap_or("");
            summary.push(format!("{name} type={kind} phase={phase}"));
            if phase != "Running" {
                continue;
            }
            match kind {
                "head" => heads += 1,
                "worker" => workers += 1,
                _ => {}
            }
        }
        if heads >= 1 && workers >= want_workers {
            eprintln!(
                "ml-kuberay: {cluster} head+{workers} GPU workers Running after {:?}",
                start.elapsed()
            );
            return;
        }
        if start.elapsed() > ceiling {
            panic!(
                "{cluster}: expected 1 head + {want_workers} Running workers after {ceiling:?} \
                 (pods={summary:?}). Worker must request {RESOURCE}: 1. If pods CrashLoop, \
                 KubeRay injected `ray start` — set {OVERWRITE_CMD} (CHALLENGES #157).\n{}",
                gpu_diagnostics(kubeconfig)
            );
        }
        eprintln!("ml-kuberay: {cluster} pods {summary:?}");
        std::thread::sleep(Duration::from_secs(3));
    }
}

fn snapshot_with_kuberay(kubeconfig: &Path) -> BTreeMap<String, (String, BTreeMap<String, u64>)> {
    let mut all = snapshot_via_kubectl(kubeconfig);
    if let Ok(body) = kubectl(kubeconfig, &["get", "pods", "-n", KUBERAY_NS, "-o", "json"]) {
        all.extend(snapshot_pods_json(&body));
    }
    all
}

fn snapshot_with_kuberay_via(
    bridge: &str,
    certs: &Path,
) -> Result<BTreeMap<String, (String, BTreeMap<String, u64>)>, String> {
    let mut all = snapshot_via_bridge(bridge, certs)?;
    if let Ok(body) = curl_get(
        bridge,
        certs,
        &format!("/api/v1/namespaces/{KUBERAY_NS}/pods"),
    ) {
        all.extend(snapshot_pods_json(&body));
    }
    Ok(all)
}

fn raycluster_via_bridge(
    bridge: &str,
    certs: &Path,
    name: &str,
) -> Result<serde_json::Value, String> {
    let body = curl_get(
        bridge,
        certs,
        &format!("/apis/ray.io/v1/namespaces/default/rayclusters/{name}"),
    )?;
    serde_json::from_str(&body).map_err(|e| format!("raycluster json {name}: {e}: {body}"))
}

fn child_raycluster_json() -> String {
    serde_json::json!({
        "apiVersion": "ray.io/v1",
        "kind": "RayCluster",
        "metadata": {
            "name": RAYCLUSTER_CHILD,
            "namespace": "default",
            "annotations": {OVERWRITE_CMD: "true"}
        },
        "spec": {
            "rayVersion": "2.47.1",
            "headGroupSpec": {
                "rayStartParams": {},
                "template": {
                    "spec": {
                        "containers": [{
                            "name": "ray-head",
                            "image": BUSYBOX,
                            "imagePullPolicy": "IfNotPresent",
                            "command": ["sleep", "86400"],
                            "resources": {
                                "requests": {"cpu": "50m", "memory": "64Mi"},
                                "limits": {"cpu": "200m", "memory": "128Mi"}
                            }
                        }]
                    }
                }
            },
            "workerGroupSpecs": [{
                "groupName": "gpu-group",
                "replicas": 1,
                "minReplicas": 1,
                "maxReplicas": 1,
                "rayStartParams": {},
                "template": {
                    "spec": {
                        "containers": [{
                            "name": "ray-worker",
                            "image": BUSYBOX,
                            "imagePullPolicy": "IfNotPresent",
                            "command": ["sleep", "86400"],
                            "resources": {
                                "limits": {RESOURCE: "1", "cpu": "200m", "memory": "128Mi"},
                                "requests": {RESOURCE: "1", "cpu": "50m", "memory": "64Mi"}
                            }
                        }]
                    }
                }
            }]
        }
    })
    .to_string()
}

fn assert_source_missing_child(bridge: &str, certs: &Path) {
    let src_see = curl_get(
        bridge,
        certs,
        &format!("/apis/ray.io/v1/namespaces/default/rayclusters/{RAYCLUSTER_CHILD}"),
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
        "source cluster saw the child-only RayCluster {RAYCLUSTER_CHILD}: {src_see:?}"
    );
}

/// 3-node Ubuntu k3s + GPU fixture + KubeRay, then warm-fork and diverge.
#[test]
fn test_ubuntu_ml_kuberay_gpu_fork() {
    let _ = env_logger::builder().is_test(true).try_init();

    let yaml = std::fs::read_to_string(fixture("kuberay/gpu-raycluster.yaml")).expect("raycluster");
    assert!(
        yaml.contains("@sha256:") && !yaml.contains(":latest"),
        "gpu-raycluster.yaml must pin images by digest"
    );
    assert!(
        yaml.contains(&format!("{RESOURCE}: \"1\"")),
        "gpu-raycluster.yaml worker must request exactly {RESOURCE}: 1"
    );
    assert!(
        !yaml.contains("rayproject/ray") && !yaml.contains("nvidia/cuda"),
        "gpu-raycluster.yaml must not pull a CUDA / Ray runtime image"
    );
    assert!(
        yaml.contains(OVERWRITE_CMD),
        "gpu-raycluster.yaml must set {OVERWRITE_CMD} (CHALLENGES #157)"
    );

    let mut cluster = bring_up_cluster();
    let gpu0 = apply_gpu_dcgm_fixture(&mut cluster);
    let kube = cluster.kubeconfig.clone();
    let names = cluster.names();
    assert_eq!(gpu0.capacity.len(), 3);
    let used0 = gpu_used_via_kubectl(&kube);
    assert_gpu_consistent(&gpu0, &used0, &names, 0, "source before KubeRay");

    install_kuberay(&kube);
    apply_raycluster(&kube, "kuberay/gpu-raycluster.yaml");
    wait_ray_pods_running(&kube, RAYCLUSTER, 1, FIXTURE_READY);
    let used_run = wait_gpu_used(&kube, 1, Duration::from_secs(60), "source RayCluster");
    let gpu_run = gpu_via_kubectl(&kube);
    assert_gpu_consistent(&gpu_run, &used_run, &names, 1, "source RayCluster");

    let src_bridge = cluster.bridge().to_string();
    let metrics = scrape_dcgm(&src_bridge, cluster.server_ip)
        .unwrap_or_else(|e| panic!("source DCGM scrape: {e}\n{}", gpu_diagnostics(&kube)));
    assert_dcgm_metrics(&metrics, "source");

    wait_nodes_ready(&kube, &names, Duration::from_secs(120));
    let before = snapshot_with_kuberay(&kube);
    assert!(
        before.keys().any(|k| k.contains("kuberay-operator")),
        "KubeRay operator missing from restart snapshot: {before:?}"
    );
    assert!(
        before
            .keys()
            .any(|k| k.contains(RAYCLUSTER) && k.contains("head")),
        "RayCluster head missing from snapshot: {before:?}"
    );
    assert!(
        before
            .keys()
            .any(|k| k.contains(RAYCLUSTER) && k.contains("worker")),
        "RayCluster GPU worker missing from snapshot: {before:?}"
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
        "ubkrf",
        &[None, None, None],
        &[None, None, None],
        &["ubuntu-kr-0", "ubuntu-kr-1", "ubuntu-kr-2"],
    )
    .expect("warm fork of the Ubuntu KubeRay cluster");
    let fork_latency = fork_start.elapsed();
    eprintln!(
        "MEASUREMENT ubuntu ml-kuberay cluster warm fork (3 × {NODE_MEMORY_MB} MB): {fork_latency:?} \
         target=1s budget={FORK_UBUNTU_K3S_CLUSTER_3VM:?}"
    );
    if fork_latency >= Duration::from_secs(1) {
        eprintln!("FINDING cluster fork {fork_latency:?} missed the sub-second target");
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
        let src_pods = snapshot_with_kuberay_via(&src_bridge, &certs)
            .unwrap_or_else(|e| panic!("source pods via {src_bridge}: {e}"));
        let child_pods = snapshot_with_kuberay_via(&child_bridge, &certs)
            .unwrap_or_else(|e| panic!("child pods via {child_bridge}: {e}"));
        assert_no_restarts(&before, &src_pods, "source");
        assert_no_restarts(&before, &child_pods, "child");
        let src_ready = nodes_ready_via(&src_bridge, &certs, &names);
        let child_ready = nodes_ready_via(&child_bridge, &certs, &names);
        let child_rc = raycluster_via_bridge(&child_bridge, &certs, RAYCLUSTER).ok();
        let child_used = gpu_used_via_bridge(&child_bridge, &certs).ok();
        let rc_ok = child_rc.is_some() && child_used.as_ref().is_some_and(|u| sum(u) == 1);
        if src_ready && child_ready && rc_ok && start.elapsed() >= Duration::from_secs(5) {
            eprintln!(
                "fork: both clusters Ready, RayCluster present, \
                 {RESOURCE} used=1, zero restarts across {:?}",
                start.elapsed()
            );
            break;
        }
        if start.elapsed() > CONVERGE {
            panic!(
                "fork: clusters did not converge Ready+RayCluster+used in {CONVERGE:?} \
                 (src_ready={src_ready} child_ready={child_ready} \
                 child_rc={child_rc:?} child_used={child_used:?})"
            );
        }
        std::thread::sleep(Duration::from_secs(2));
    }

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

    let child_rc = raycluster_via_bridge(&child_bridge, &certs, RAYCLUSTER)
        .unwrap_or_else(|e| panic!("child {RAYCLUSTER}: {e}"));
    assert_eq!(
        child_rc["metadata"]["name"].as_str(),
        Some(RAYCLUSTER),
        "child lost {RAYCLUSTER}"
    );

    let child_metrics = scrape_dcgm(&child_bridge, cluster.server_ip)
        .unwrap_or_else(|e| panic!("child DCGM scrape: {e}"));
    assert_dcgm_metrics(&child_metrics, "child");
    eprintln!(
        "ml-kuberay: child DCGM scrape ok ({} B)",
        child_metrics.len()
    );

    let create_start = Instant::now();
    loop {
        match curl_api(
            &child_bridge,
            &certs,
            "POST",
            "/apis/ray.io/v1/namespaces/default/rayclusters",
            Some(&child_raycluster_json()),
        ) {
            Ok(body) if !body.contains("Failure") && !body.contains("error") => {
                eprintln!(
                    "ml-kuberay: child-only {RAYCLUSTER_CHILD} created after {:?}",
                    create_start.elapsed()
                );
                break;
            }
            other if create_start.elapsed() < Duration::from_secs(90) => {
                eprintln!(
                    "ml-kuberay: child RayCluster create retry ({other:?}) {:?}",
                    create_start.elapsed()
                );
                std::thread::sleep(Duration::from_secs(3));
            }
            other => panic!(
                "child RayCluster create failed for 90s: {other:?}. \
                 KubeRay operator may have died across the fork."
            ),
        }
    }

    let wait_child = Instant::now();
    loop {
        let child_js = raycluster_via_bridge(&child_bridge, &certs, RAYCLUSTER_CHILD).ok();
        let used = gpu_used_via_bridge(&child_bridge, &certs).ok();
        if child_js.is_some() && used.as_ref().is_some_and(|u| sum(u) == 2) {
            eprintln!(
                "ml-kuberay: child-only RayCluster using +1 GPU after {:?}",
                wait_child.elapsed()
            );
            break;
        }
        if wait_child.elapsed() > FIXTURE_READY {
            panic!(
                "child-only {RAYCLUSTER_CHILD} never reached GPU used=2 \
                 (rc={child_js:?} used={used:?})"
            );
        }
        std::thread::sleep(Duration::from_secs(3));
    }

    let child_after = gpu_via_bridge(&child_bridge, &certs)
        .unwrap_or_else(|e| panic!("child nodes after extra RayCluster: {e}"));
    let child_used_after = gpu_used_via_bridge(&child_bridge, &certs)
        .unwrap_or_else(|e| panic!("child gpu used after extra: {e}"));
    assert_gpu_consistent(
        &child_after,
        &child_used_after,
        &names,
        2,
        "child-after-extra-raycluster",
    );

    let src_after = gpu_via_bridge(&src_bridge, &certs)
        .unwrap_or_else(|e| panic!("source nodes after child extra RayCluster: {e}"));
    let src_used_after = gpu_used_via_bridge(&src_bridge, &certs)
        .unwrap_or_else(|e| panic!("source gpu used after child extra: {e}"));
    assert_gpu_consistent(
        &src_after,
        &src_used_after,
        &names,
        1,
        "source-must-not-see-child-raycluster",
    );
    assert_source_missing_child(&src_bridge, &certs);
    eprintln!(
        "fork: source {RESOURCE} used still 1; child-only {RAYCLUSTER_CHILD} is invisible on source"
    );

    for child in &mut forks {
        child.shutdown();
    }
    drop(fork_net);
}
