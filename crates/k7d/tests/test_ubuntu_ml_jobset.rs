//! JobSet on the 31a-inc1 fake GPU fixture, then a warm fork
//! .
//!
//! Two workers each request `nvidia.com/gpu: 1` and rendezvous over
//! JobSet headless DNS with a CPU/Gloo-shaped script. Not CUDA, not
//! DeepSpeed, not GPU Operator, not VFIO. Reuses `bring_up_cluster`
//! (Flannel) and `FORK_UBUNTU_K3S_CLUSTER_3VM`. Does not touch
//! `crates/k7d/src`.
//!
//! TrainJob / Kubeflow Trainer is parked for inc2b: the documented
//! install is a second controller + webhook, not a thin CRD on JobSet.

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
use common::ubuntu_k3s::{
    assert_no_restarts, bring_up_cluster, curl_api, curl_get, kubectl, nodes_ready_via,
    snapshot_pods_json, snapshot_via_bridge, snapshot_via_kubectl, wait_nodes_ready, CONVERGE,
};

const JOBSET_VERSION: &str = "v0.12.0";
const JOBSET_MANIFESTS_URL: &str =
    "https://github.com/kubernetes-sigs/jobset/releases/download/v0.12.0/manifests.yaml";
const JOBSET_MANIFESTS_SHA256: &str =
    "a41aaf12dd0b7b0a3d626b8d6107f32c3dc889d7e7830adc46b8cdb77a8963bb";
const JOBSET_IMAGE_UNPINNED: &str = "registry.k8s.io/jobset/jobset:v0.12.0";
const JOBSET_IMAGE: &str = "registry.k8s.io/jobset/jobset:v0.12.0@sha256:e75536f1135b7bb2f19f8c3b620782fbdd9091d73398e3a272f9a5fed322980d";

const JOBSET_NS: &str = "jobset-system";
const JOBSET_DONE: &str = "gpu-jobset-done";
const JOBSET_RUN: &str = "gpu-jobset-run";
const JOBSET_CHILD: &str = "gpu-jobset-child";
const JOBSET_READY: Duration = Duration::from_secs(300);

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

fn fetch_jobset_manifests() -> PathBuf {
    let dest = PathBuf::from(format!(
        "/tmp/k7d-jobset-{JOBSET_VERSION}-{}.yaml",
        std::process::id()
    ));
    let status = Command::new("curl")
        .args(["-fsSL", "-o"])
        .arg(&dest)
        .arg(JOBSET_MANIFESTS_URL)
        .status()
        .expect("spawn curl jobset manifests");
    assert!(
        status.success(),
        "download {JOBSET_MANIFESTS_URL} failed — refuse to apply an unpinned JobSet"
    );
    let got = sha256_file(&dest);
    assert_eq!(
        got, JOBSET_MANIFESTS_SHA256,
        "JobSet {JOBSET_VERSION} manifests sha256 mismatch: got {got}, \
         want {JOBSET_MANIFESTS_SHA256}"
    );
    let text = std::fs::read_to_string(&dest).expect("read jobset manifests");
    // CRD OpenAPI text mentions the ":latest tag" in imagePullPolicy
    // docs. Only refuse a real `image: …:latest` container line.
    for line in text.lines() {
        let t = line.trim();
        let Some(img) = t.strip_prefix("image:") else {
            continue;
        };
        let img = img.trim();
        if img.is_empty() {
            continue;
        }
        assert!(
            !img.ends_with(":latest") && !img.contains(":latest@"),
            "JobSet {JOBSET_VERSION} container image uses latest: {img}"
        );
    }
    assert!(
        text.contains(JOBSET_IMAGE_UNPINNED),
        "manifests missing {JOBSET_IMAGE_UNPINNED}"
    );
    let pinned = text.replace(
        &format!("image: {JOBSET_IMAGE_UNPINNED}"),
        &format!("image: {JOBSET_IMAGE}"),
    );
    assert!(
        pinned.contains("@sha256:e75536f1135b7bb2f19f8c3b620782fbdd9091d73398e3a272f9a5fed322980d"),
        "JobSet controller image was not rewritten to a digest pin"
    );
    assert!(
        !pinned.contains(&format!("image: {JOBSET_IMAGE_UNPINNED}\n")),
        "unpinned JobSet image remains after rewrite"
    );
    std::fs::write(&dest, pinned).expect("write pinned jobset manifests");
    dest
}

fn install_jobset(kubeconfig: &Path) {
    let manifests = fetch_jobset_manifests();
    kubectl(
        kubeconfig,
        &["apply", "--server-side", "-f", &manifests.to_string_lossy()],
    )
    .unwrap_or_else(|e| panic!("kubectl apply --server-side JobSet {JOBSET_VERSION}: {e}"));
    let start = Instant::now();
    loop {
        let crd = kubectl(
            kubeconfig,
            &[
                "get",
                "crd",
                "jobsets.jobset.x-k8s.io",
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
                "deploy/jobset-controller-manager",
                "-n",
                JOBSET_NS,
                "--timeout=15s",
            ],
        );
        let ca = kubectl(
            kubeconfig,
            &[
                "get",
                "validatingwebhookconfiguration",
                "jobset-validating-webhook-configuration",
                "-o",
                "jsonpath={.webhooks[0].clientConfig.caBundle}",
            ],
        )
        .unwrap_or_default();
        if crd.trim() == "True" && deploy.is_ok() && !ca.trim().is_empty() {
            eprintln!(
                "ml-jobset: JobSet {JOBSET_VERSION} controller Ready + webhook CA after {:?}",
                start.elapsed()
            );
            return;
        }
        if start.elapsed() > JOBSET_READY {
            panic!(
                "JobSet {JOBSET_VERSION} never Ready after {JOBSET_READY:?} \
                 (crd={:?} deploy={:?} ca_len={})\n{}",
                crd.trim(),
                deploy.as_ref().err(),
                ca.trim().len(),
                gpu_diagnostics(kubeconfig)
            );
        }
        eprintln!(
            "ml-jobset: waiting for JobSet controller (crd={} ca_len={})",
            crd.trim(),
            ca.trim().len()
        );
        std::thread::sleep(Duration::from_secs(3));
    }
}

fn apply_jobset_cr(kubeconfig: &Path, name: &str) {
    let path = fixture(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
    assert!(
        text.contains("@sha256:") && !text.contains(":latest"),
        "{name} must pin images by digest"
    );
    let start = Instant::now();
    loop {
        match kubectl(kubeconfig, &["apply", "-f", &path.to_string_lossy()]) {
            Ok(_) => {
                eprintln!("ml-jobset: applied {name} after {:?}", start.elapsed());
                return;
            }
            Err(e) if start.elapsed() < Duration::from_secs(90) => {
                eprintln!(
                    "ml-jobset: apply {name} failed (webhook not ready?): {e}; retry {:?}",
                    start.elapsed()
                );
                std::thread::sleep(Duration::from_secs(3));
            }
            Err(e) => panic!(
                "apply {name} failed for 90s (JobSet webhook?): {e}\n{}",
                gpu_diagnostics(kubeconfig)
            ),
        }
    }
}

fn jobset_terminal(kubeconfig: &Path, name: &str) -> String {
    kubectl(
        kubeconfig,
        &[
            "get",
            "jobset",
            name,
            "-o",
            "jsonpath={.status.terminalState}",
        ],
    )
    .unwrap_or_default()
    .trim()
    .to_string()
}

fn wait_jobset_completed(kubeconfig: &Path, name: &str, ceiling: Duration) {
    let start = Instant::now();
    loop {
        let state = jobset_terminal(kubeconfig, name);
        if state == "Completed" {
            eprintln!("ml-jobset: {name} Completed after {:?}", start.elapsed());
            return;
        }
        if state == "Failed" {
            panic!(
                "{name} Failed (expected Completed). Rendezvous must resolve \
                 JobSet headless hostnames.\n{}",
                gpu_diagnostics(kubeconfig)
            );
        }
        if start.elapsed() > ceiling {
            panic!(
                "{name} never Completed after {ceiling:?} (terminalState={state:?})\n{}",
                gpu_diagnostics(kubeconfig)
            );
        }
        eprintln!("ml-jobset: {name} terminalState={state:?}");
        std::thread::sleep(Duration::from_secs(3));
    }
}

fn wait_jobset_workers_running(kubeconfig: &Path, name: &str, want: usize, ceiling: Duration) {
    let start = Instant::now();
    let selector = format!("jobset.sigs.k8s.io/jobset-name={name}");
    loop {
        let body = kubectl(
            kubeconfig,
            &[
                "get",
                "pods",
                "-l",
                &selector,
                "-o",
                "jsonpath={.items[*].status.phase}",
            ],
        )
        .unwrap_or_default();
        let running = body.split_whitespace().filter(|p| *p == "Running").count();
        if running >= want {
            eprintln!(
                "ml-jobset: {name} {running} workers Running after {:?}",
                start.elapsed()
            );
            return;
        }
        if start.elapsed() > ceiling {
            panic!(
                "{name}: expected {want} Running workers after {ceiling:?} \
                 (phases={:?}). GPU request must be {RESOURCE}: 1.\n{}",
                body.trim(),
                gpu_diagnostics(kubeconfig)
            );
        }
        eprintln!("ml-jobset: {name} worker phases {}", body.trim());
        std::thread::sleep(Duration::from_secs(3));
    }
}

fn snapshot_with_jobset(kubeconfig: &Path) -> BTreeMap<String, (String, BTreeMap<String, u64>)> {
    let mut all = snapshot_via_kubectl(kubeconfig);
    if let Ok(body) = kubectl(kubeconfig, &["get", "pods", "-n", JOBSET_NS, "-o", "json"]) {
        all.extend(snapshot_pods_json(&body));
    }
    all
}

fn snapshot_with_jobset_via(
    bridge: &str,
    certs: &Path,
) -> Result<BTreeMap<String, (String, BTreeMap<String, u64>)>, String> {
    let mut all = snapshot_via_bridge(bridge, certs)?;
    if let Ok(body) = curl_get(
        bridge,
        certs,
        &format!("/api/v1/namespaces/{JOBSET_NS}/pods"),
    ) {
        all.extend(snapshot_pods_json(&body));
    }
    Ok(all)
}

fn jobset_via_bridge(bridge: &str, certs: &Path, name: &str) -> Result<serde_json::Value, String> {
    let body = curl_get(
        bridge,
        certs,
        &format!("/apis/jobset.x-k8s.io/v1alpha2/namespaces/default/jobsets/{name}"),
    )?;
    serde_json::from_str(&body).map_err(|e| format!("jobset json {name}: {e}: {body}"))
}

fn jobset_terminal_from(v: &serde_json::Value) -> &str {
    v["status"]["terminalState"].as_str().unwrap_or("")
}

fn child_jobset_json() -> String {
    serde_json::json!({
        "apiVersion": "jobset.x-k8s.io/v1alpha2",
        "kind": "JobSet",
        "metadata": {"name": JOBSET_CHILD, "namespace": "default"},
        "spec": {
            "replicatedJobs": [{
                "name": "workers",
                "replicas": 1,
                "template": {
                    "spec": {
                        "parallelism": 1,
                        "completions": 1,
                        "template": {
                            "spec": {
                                "restartPolicy": "Never",
                                "containers": [{
                                    "name": "train",
                                    "image": BUSYBOX,
                                    "imagePullPolicy": "IfNotPresent",
                                    "command": ["sleep", "86400"],
                                    "resources": {
                                        "limits": {RESOURCE: "1"},
                                        "requests": {RESOURCE: "1"}
                                    }
                                }]
                            }
                        }
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
        &format!("/apis/jobset.x-k8s.io/v1alpha2/namespaces/default/jobsets/{JOBSET_CHILD}"),
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
        "source cluster saw the child-only JobSet {JOBSET_CHILD}: {src_see:?}"
    );
}

/// 3-node Ubuntu k3s + GPU fixture + JobSet, then warm-fork and diverge.
#[test]
fn test_ubuntu_ml_jobset_gpu_fork() {
    let _ = env_logger::builder().is_test(true).try_init();

    let done_yaml = std::fs::read_to_string(fixture("jobset/gpu-jobset-done.yaml")).expect("done");
    let run_yaml = std::fs::read_to_string(fixture("jobset/gpu-jobset-run.yaml")).expect("run");
    for (name, text) in [
        ("gpu-jobset-done.yaml", &done_yaml),
        ("gpu-jobset-run.yaml", &run_yaml),
    ] {
        assert!(
            text.contains("@sha256:") && !text.contains(":latest"),
            "{name} must pin images by digest"
        );
        assert!(
            text.contains(&format!("{RESOURCE}: \"1\"")),
            "{name} workers must request exactly {RESOURCE}: 1"
        );
    }
    assert!(
        done_yaml
            .contains("gpu-jobset-done-workers-0-0.gpu-jobset-done.default.svc.cluster.local",)
            && done_yaml
                .contains("gpu-jobset-done-workers-1-0.gpu-jobset-done.default.svc.cluster.local",),
        "completed JobSet must rendezvous on JobSet headless FQDNs \
         (busybox nslookup does not apply search domains; CHALLENGES #148)"
    );
    assert!(
        done_yaml.contains("cpu-gloo"),
        "train script must be named CPU/Gloo-shaped (not CUDA)"
    );

    let mut cluster = bring_up_cluster();
    let gpu0 = apply_gpu_dcgm_fixture(&mut cluster);
    let kube = cluster.kubeconfig.clone();
    let names = cluster.names();
    assert_eq!(gpu0.capacity.len(), 3);
    let used0 = gpu_used_via_kubectl(&kube);
    assert_gpu_consistent(&gpu0, &used0, &names, 0, "source before JobSet");

    install_jobset(&kube);
    apply_jobset_cr(&kube, "jobset/gpu-jobset-done.yaml");
    wait_jobset_workers_running(&kube, JOBSET_DONE, 2, FIXTURE_READY);
    wait_gpu_used(&kube, 2, Duration::from_secs(60), "source during done");
    wait_jobset_completed(&kube, JOBSET_DONE, JOBSET_READY);
    wait_gpu_used(
        &kube,
        0,
        Duration::from_secs(60),
        "source after done Complete",
    );

    apply_jobset_cr(&kube, "jobset/gpu-jobset-run.yaml");
    wait_jobset_workers_running(&kube, JOBSET_RUN, 2, FIXTURE_READY);
    let used_run = wait_gpu_used(&kube, 2, Duration::from_secs(60), "source in-flight");
    let gpu_run = gpu_via_kubectl(&kube);
    assert_gpu_consistent(&gpu_run, &used_run, &names, 2, "source in-flight");
    assert_eq!(
        jobset_terminal(&kube, JOBSET_RUN),
        "",
        "{JOBSET_RUN} must still be in-flight"
    );

    let src_bridge = cluster.bridge().to_string();
    let metrics = scrape_dcgm(&src_bridge, cluster.server_ip)
        .unwrap_or_else(|e| panic!("source DCGM scrape: {e}\n{}", gpu_diagnostics(&kube)));
    assert_dcgm_metrics(&metrics, "source");

    wait_nodes_ready(&kube, &names, Duration::from_secs(120));
    let before = snapshot_with_jobset(&kube);
    assert!(
        before
            .keys()
            .any(|k| k.contains("jobset-controller-manager")),
        "JobSet controller missing from restart snapshot: {before:?}"
    );
    assert!(
        before
            .keys()
            .filter(|k| k.contains("gpu-jobset-run-workers-"))
            .count()
            >= 2,
        "in-flight JobSet workers missing from snapshot: {before:?}"
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
        "ubjsf",
        &[None, None, None],
        &[None, None, None],
        &["ubuntu-js-0", "ubuntu-js-1", "ubuntu-js-2"],
    )
    .expect("warm fork of the Ubuntu JobSet cluster");
    let fork_latency = fork_start.elapsed();
    eprintln!(
        "MEASUREMENT ubuntu ml-jobset cluster warm fork (3 × {NODE_MEMORY_MB} MB): {fork_latency:?} \
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
        let src_pods = snapshot_with_jobset_via(&src_bridge, &certs)
            .unwrap_or_else(|e| panic!("source pods via {src_bridge}: {e}"));
        let child_pods = snapshot_with_jobset_via(&child_bridge, &certs)
            .unwrap_or_else(|e| panic!("child pods via {child_bridge}: {e}"));
        assert_no_restarts(&before, &src_pods, "source");
        assert_no_restarts(&before, &child_pods, "child");
        let src_ready = nodes_ready_via(&src_bridge, &certs, &names);
        let child_ready = nodes_ready_via(&child_bridge, &certs, &names);
        let child_done = jobset_via_bridge(&child_bridge, &certs, JOBSET_DONE).ok();
        let child_run = jobset_via_bridge(&child_bridge, &certs, JOBSET_RUN).ok();
        let child_used = gpu_used_via_bridge(&child_bridge, &certs).ok();
        let js_ok = child_done
            .as_ref()
            .is_some_and(|v| jobset_terminal_from(v) == "Completed")
            && child_run
                .as_ref()
                .is_some_and(|v| jobset_terminal_from(v).is_empty())
            && child_used.as_ref().is_some_and(|u| sum(u) == 2);
        if src_ready && child_ready && js_ok && start.elapsed() >= Duration::from_secs(5) {
            eprintln!(
                "fork: both clusters Ready, JobSet Complete+Running, \
                 {RESOURCE} used=2, zero restarts across {:?}",
                start.elapsed()
            );
            break;
        }
        if start.elapsed() > CONVERGE {
            panic!(
                "fork: clusters did not converge Ready+JobSet+used in {CONVERGE:?} \
                 (src_ready={src_ready} child_ready={child_ready} \
                 child_done={child_done:?} child_run={child_run:?} \
                 child_used={child_used:?})"
            );
        }
        std::thread::sleep(Duration::from_secs(2));
    }

    let child_gpu =
        gpu_via_bridge(&child_bridge, &certs).unwrap_or_else(|e| panic!("child nodes: {e}"));
    let child_used = gpu_used_via_bridge(&child_bridge, &certs)
        .unwrap_or_else(|e| panic!("child gpu used: {e}"));
    assert_gpu_consistent(&child_gpu, &child_used, &names, 2, "child");
    let src_gpu =
        gpu_via_bridge(&src_bridge, &certs).unwrap_or_else(|e| panic!("source nodes: {e}"));
    let src_used =
        gpu_used_via_bridge(&src_bridge, &certs).unwrap_or_else(|e| panic!("source gpu used: {e}"));
    assert_gpu_consistent(&src_gpu, &src_used, &names, 2, "source-after-fork");

    let child_done = jobset_via_bridge(&child_bridge, &certs, JOBSET_DONE)
        .unwrap_or_else(|e| panic!("child {JOBSET_DONE}: {e}"));
    assert_eq!(
        jobset_terminal_from(&child_done),
        "Completed",
        "child lost {JOBSET_DONE} Complete"
    );
    let child_run = jobset_via_bridge(&child_bridge, &certs, JOBSET_RUN)
        .unwrap_or_else(|e| panic!("child {JOBSET_RUN}: {e}"));
    assert_eq!(
        jobset_terminal_from(&child_run),
        "",
        "child {JOBSET_RUN} should still be in-flight"
    );

    let child_metrics = scrape_dcgm(&child_bridge, cluster.server_ip)
        .unwrap_or_else(|e| panic!("child DCGM scrape: {e}"));
    assert_dcgm_metrics(&child_metrics, "child");
    eprintln!(
        "ml-jobset: child DCGM scrape ok ({} B)",
        child_metrics.len()
    );

    let create_start = Instant::now();
    loop {
        match curl_api(
            &child_bridge,
            &certs,
            "POST",
            "/apis/jobset.x-k8s.io/v1alpha2/namespaces/default/jobsets",
            Some(&child_jobset_json()),
        ) {
            Ok(body) if !body.contains("Failure") && !body.contains("error") => {
                eprintln!(
                    "ml-jobset: child-only {JOBSET_CHILD} created after {:?}",
                    create_start.elapsed()
                );
                break;
            }
            other if create_start.elapsed() < Duration::from_secs(90) => {
                eprintln!(
                    "ml-jobset: child JobSet create retry ({other:?}) {:?}",
                    create_start.elapsed()
                );
                std::thread::sleep(Duration::from_secs(3));
            }
            other => panic!(
                "child JobSet webhook/create failed for 90s: {other:?}. \
                 JobSet webhook CA / service may have died across the fork."
            ),
        }
    }

    let wait_child = Instant::now();
    loop {
        let child_js = jobset_via_bridge(&child_bridge, &certs, JOBSET_CHILD).ok();
        let used = gpu_used_via_bridge(&child_bridge, &certs).ok();
        if child_js.is_some() && used.as_ref().is_some_and(|u| sum(u) == 3) {
            eprintln!(
                "ml-jobset: child-only JobSet using +1 GPU after {:?}",
                wait_child.elapsed()
            );
            break;
        }
        if wait_child.elapsed() > FIXTURE_READY {
            panic!(
                "child-only {JOBSET_CHILD} never reached GPU used=3 \
                 (js={child_js:?} used={used:?})"
            );
        }
        std::thread::sleep(Duration::from_secs(3));
    }

    let child_after = gpu_via_bridge(&child_bridge, &certs)
        .unwrap_or_else(|e| panic!("child nodes after extra JobSet: {e}"));
    let child_used_after = gpu_used_via_bridge(&child_bridge, &certs)
        .unwrap_or_else(|e| panic!("child gpu used after extra: {e}"));
    assert_gpu_consistent(
        &child_after,
        &child_used_after,
        &names,
        3,
        "child-after-extra-jobset",
    );

    let src_after = gpu_via_bridge(&src_bridge, &certs)
        .unwrap_or_else(|e| panic!("source nodes after child extra JobSet: {e}"));
    let src_used_after = gpu_used_via_bridge(&src_bridge, &certs)
        .unwrap_or_else(|e| panic!("source gpu used after child extra: {e}"));
    assert_gpu_consistent(
        &src_after,
        &src_used_after,
        &names,
        2,
        "source-must-not-see-child-jobset",
    );
    assert_source_missing_child(&src_bridge, &certs);
    eprintln!(
        "fork: source {RESOURCE} used still 2; child-only {JOBSET_CHILD} is invisible on source"
    );

    for child in &mut forks {
        child.shutdown();
    }
    drop(fork_net);
}
