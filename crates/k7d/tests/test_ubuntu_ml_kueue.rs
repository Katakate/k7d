//! Kueue on the 31a-inc1 fake GPU fixture, then a warm fork
//! .
//!
//! Digest-pinned Kueue v0.19.2, a ClusterQueue whose
//! `nvidia.com/gpu` quota is 1, a LocalQueue, and two busybox Jobs
//! each requesting one fake GPU. One admits and Runs; the other
//! stays Pending (Kueue admission, not kube-scheduler). Queues +
//! split survive a warm fork; a child-only LocalQueue stays
//! invisible on the source. Reuses `bring_up_cluster` (Flannel) and
//! `FORK_UBUNTU_K3S_CLUSTER_3VM`. Does not touch `crates/k7d/src`.
//!
//! Kueue on mocks — not a production batch scheduler, not CUDA.

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

const KUEUE_VERSION: &str = "v0.19.2";
const KUEUE_MANIFESTS_URL: &str =
    "https://github.com/kubernetes-sigs/kueue/releases/download/v0.19.2/manifests.yaml";
const KUEUE_MANIFESTS_SHA256: &str =
    "88881eb50734eb920b67486ebc2aa978ed325e1b12d99b22fc51a6d7e9e4d370";
const KUEUE_IMAGE_UNPINNED: &str = "registry.k8s.io/kueue/kueue:v0.19.2";
const KUEUE_IMAGE: &str = "registry.k8s.io/kueue/kueue:v0.19.2@sha256:8a77be2df3d441d1a99b60eb1625c835b5f4feda5db02ece26818cf2a30c4d86";
const KUEUE_DIGEST: &str =
    "sha256:8a77be2df3d441d1a99b60eb1625c835b5f4feda5db02ece26818cf2a30c4d86";

const KUEUE_NS: &str = "kueue-system";
const KUEUE_API: &str = "kueue.x-k8s.io/v1beta2";
const QUEUE_LABEL: &str = "kueue.x-k8s.io/queue-name";
const LOCAL_QUEUE: &str = "user-queue";
const CLUSTER_QUEUE: &str = "cluster-queue";
const JOB_RUN: &str = "gpu-job-run";
const JOB_WAIT: &str = "gpu-job-wait";
const QUEUE_CHILD: &str = "child-only-queue";
const KUEUE_READY: Duration = Duration::from_secs(300);

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

fn refuse_latest_images(text: &str, whose: &str) {
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
            "{whose} container image uses latest: {img}"
        );
    }
}

fn fetch_kueue_manifests() -> PathBuf {
    let dest = PathBuf::from(format!(
        "/tmp/k7d-kueue-{KUEUE_VERSION}-{}.yaml",
        std::process::id()
    ));
    let status = Command::new("curl")
        .args(["-fsSL", "-o"])
        .arg(&dest)
        .arg(KUEUE_MANIFESTS_URL)
        .status()
        .expect("spawn curl kueue manifests");
    assert!(
        status.success(),
        "download {KUEUE_MANIFESTS_URL} failed — refuse to apply an unpinned Kueue"
    );
    let got = sha256_file(&dest);
    assert_eq!(
        got, KUEUE_MANIFESTS_SHA256,
        "Kueue {KUEUE_VERSION} manifests sha256 mismatch: got {got}, \
         want {KUEUE_MANIFESTS_SHA256}"
    );
    let text = std::fs::read_to_string(&dest).expect("read kueue manifests");
    refuse_latest_images(&text, &format!("Kueue {KUEUE_VERSION}"));
    assert!(
        text.contains(KUEUE_IMAGE_UNPINNED),
        "manifests missing {KUEUE_IMAGE_UNPINNED}"
    );
    let pinned = text.replace(
        &format!("image: {KUEUE_IMAGE_UNPINNED}"),
        &format!("image: {KUEUE_IMAGE}"),
    );
    assert!(
        pinned.contains(&format!("@{KUEUE_DIGEST}")),
        "Kueue controller image was not rewritten to a digest pin"
    );
    assert!(
        !pinned.contains(&format!("image: {KUEUE_IMAGE_UNPINNED}\n")),
        "unpinned Kueue image remains after rewrite"
    );
    std::fs::write(&dest, pinned).expect("write pinned kueue manifests");
    dest
}

fn crd_established(kubeconfig: &Path, crd: &str) -> bool {
    kubectl(
        kubeconfig,
        &[
            "get",
            "crd",
            crd,
            "-o",
            "jsonpath={.status.conditions[?(@.type==\"Established\")].status}",
        ],
    )
    .unwrap_or_default()
    .trim()
        == "True"
}

fn install_kueue(kubeconfig: &Path) {
    let manifests = fetch_kueue_manifests();
    kubectl(
        kubeconfig,
        &["apply", "--server-side", "-f", &manifests.to_string_lossy()],
    )
    .unwrap_or_else(|e| panic!("kubectl apply --server-side Kueue {KUEUE_VERSION}: {e}"));
    let start = Instant::now();
    loop {
        let crds = [
            "clusterqueues.kueue.x-k8s.io",
            "localqueues.kueue.x-k8s.io",
            "resourceflavors.kueue.x-k8s.io",
            "workloads.kueue.x-k8s.io",
        ]
        .iter()
        .all(|c| crd_established(kubeconfig, c));
        let deploy = kubectl(
            kubeconfig,
            &[
                "rollout",
                "status",
                "deploy/kueue-controller-manager",
                "-n",
                KUEUE_NS,
                "--timeout=15s",
            ],
        );
        let ca = kubectl(
            kubeconfig,
            &[
                "get",
                "validatingwebhookconfiguration",
                "kueue-validating-webhook-configuration",
                "-o",
                "jsonpath={.webhooks[0].clientConfig.caBundle}",
            ],
        )
        .unwrap_or_default();
        if crds && deploy.is_ok() && !ca.trim().is_empty() {
            eprintln!(
                "ml-kueue: Kueue {KUEUE_VERSION} controller Ready + webhook CA after {:?}",
                start.elapsed()
            );
            return;
        }
        if start.elapsed() > KUEUE_READY {
            panic!(
                "Kueue {KUEUE_VERSION} never Ready after {KUEUE_READY:?} \
                 (crds={crds} deploy={:?} ca_len={})\n{}",
                deploy.as_ref().err(),
                ca.trim().len(),
                gpu_diagnostics(kubeconfig)
            );
        }
        eprintln!(
            "ml-kueue: waiting for Kueue controller (crds={crds} ca_len={})",
            ca.trim().len()
        );
        std::thread::sleep(Duration::from_secs(3));
    }
}

fn apply_yaml(kubeconfig: &Path, name: &str) {
    let path = fixture(name);
    let start = Instant::now();
    loop {
        match kubectl(kubeconfig, &["apply", "-f", &path.to_string_lossy()]) {
            Ok(_) => {
                eprintln!("ml-kueue: applied {name} after {:?}", start.elapsed());
                return;
            }
            Err(e) if start.elapsed() < Duration::from_secs(90) => {
                eprintln!(
                    "ml-kueue: apply {name} failed (webhook not ready?): {e}; retry {:?}",
                    start.elapsed()
                );
                std::thread::sleep(Duration::from_secs(3));
            }
            Err(e) => panic!(
                "apply {name} failed for 90s (Kueue webhook?): {e}\n{}",
                gpu_diagnostics(kubeconfig)
            ),
        }
    }
}

fn job_json(kubeconfig: &Path, name: &str) -> Result<serde_json::Value, String> {
    let body = kubectl(kubeconfig, &["get", "job", name, "-o", "json"])?;
    serde_json::from_str(&body).map_err(|e| format!("job json {name}: {e}: {body}"))
}

fn job_suspended(job: &serde_json::Value) -> bool {
    job["spec"]["suspend"].as_bool().unwrap_or(false)
}

fn job_via_bridge(bridge: &str, certs: &Path, name: &str) -> Result<serde_json::Value, String> {
    let body = curl_get(
        bridge,
        certs,
        &format!("/apis/batch/v1/namespaces/default/jobs/{name}"),
    )?;
    serde_json::from_str(&body).map_err(|e| format!("job json {name}: {e}: {body}"))
}

fn workloads_json(kubeconfig: &Path) -> serde_json::Value {
    let body = kubectl(
        kubeconfig,
        &["get", "workloads.kueue.x-k8s.io", "-o", "json"],
    )
    .unwrap_or_else(|_| "{}".into());
    serde_json::from_str(&body).unwrap_or(serde_json::json!({}))
}

fn workloads_via_bridge(bridge: &str, certs: &Path) -> Result<serde_json::Value, String> {
    let body = curl_get(
        bridge,
        certs,
        "/apis/kueue.x-k8s.io/v1beta2/namespaces/default/workloads",
    )?;
    serde_json::from_str(&body).map_err(|e| format!("workloads json: {e}: {body}"))
}

fn workload_for<'a>(workloads: &'a serde_json::Value, job: &str) -> Option<&'a serde_json::Value> {
    let items = workloads["items"].as_array()?;
    items.iter().find(|w| {
        let owned = w["metadata"]["ownerReferences"]
            .as_array()
            .is_some_and(|arr| {
                arr.iter()
                    .any(|o| o["kind"].as_str() == Some("Job") && o["name"].as_str() == Some(job))
            });
        owned
            || w["metadata"]["name"]
                .as_str()
                .is_some_and(|n| n.contains(job))
    })
}

fn admitted(workload: &serde_json::Value) -> Option<bool> {
    let empty = Vec::new();
    for c in workload["status"]["conditions"]
        .as_array()
        .unwrap_or(&empty)
    {
        if c["type"].as_str() == Some("Admitted") {
            return Some(c["status"].as_str() == Some("True"));
        }
    }
    None
}

fn admitted_reason(workload: &serde_json::Value) -> String {
    let empty = Vec::new();
    for c in workload["status"]["conditions"]
        .as_array()
        .unwrap_or(&empty)
    {
        if c["type"].as_str() == Some("Admitted") {
            return format!(
                "status={} reason={} message={}",
                c["status"].as_str().unwrap_or(""),
                c["reason"].as_str().unwrap_or(""),
                c["message"].as_str().unwrap_or("")
            );
        }
    }
    "Admitted condition missing".into()
}

fn job_pods(kubeconfig: &Path, job: &str) -> serde_json::Value {
    let sel = format!("job-name={job}");
    let body = kubectl(kubeconfig, &["get", "pods", "-l", &sel, "-o", "json"])
        .unwrap_or_else(|_| "{}".into());
    serde_json::from_str(&body).unwrap_or(serde_json::json!({}))
}

fn job_pods_via_bridge(bridge: &str, certs: &Path, job: &str) -> Result<serde_json::Value, String> {
    let body = curl_get(
        bridge,
        certs,
        &format!("/api/v1/namespaces/default/pods?labelSelector=job-name%3D{job}"),
    )?;
    serde_json::from_str(&body).map_err(|e| format!("pods {job}: {e}: {body}"))
}

fn running_count(pods: &serde_json::Value) -> usize {
    let empty = Vec::new();
    pods["items"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter(|p| p["status"]["phase"].as_str() == Some("Running"))
        .count()
}

/// Fail loud if the waiter is Pending for a kube-scheduler reason
/// (Insufficient nvidia.com/gpu, Unschedulable) instead of Kueue quota.
fn assert_kueue_pending(
    pods: &serde_json::Value,
    workload: Option<&serde_json::Value>,
    whose: &str,
) {
    let empty = Vec::new();
    for p in pods["items"].as_array().unwrap_or(&empty) {
        let name = p["metadata"]["name"].as_str().unwrap_or("?");
        let phase = p["status"]["phase"].as_str().unwrap_or("");
        if phase == "Running" {
            panic!(
                "{whose}: waiter pod {name} is Running — ClusterQueue \
                 nvidia.com/gpu quota of 1 is fiction"
            );
        }
        for c in p["status"]["conditions"].as_array().unwrap_or(&empty) {
            let reason = c["reason"].as_str().unwrap_or("");
            let msg = c["message"].as_str().unwrap_or("");
            if reason == "Unschedulable"
                || msg.contains("Insufficient")
                || msg.contains("didn't match")
            {
                panic!(
                    "{whose}: waiter pod {name} is Pending for a non-Kueue \
                     reason ({reason}: {msg}). Kueue must suspend the Job \
                     before kube-scheduler sees it."
                );
            }
        }
    }
    if let Some(w) = workload {
        if admitted(w) == Some(true) {
            panic!(
                "{whose}: waiter Workload is Admitted — quota of 1 is fiction \
                 ({})",
                admitted_reason(w)
            );
        }
    }
}

#[derive(Debug)]
struct AdmissionSplit {
    run_suspended: bool,
    wait_suspended: bool,
    run_running: usize,
    wait_running: usize,
    run_admitted: Option<bool>,
    wait_admitted: Option<bool>,
}

fn split_from(
    run: &serde_json::Value,
    wait: &serde_json::Value,
    run_pods: &serde_json::Value,
    wait_pods: &serde_json::Value,
    workloads: &serde_json::Value,
) -> AdmissionSplit {
    AdmissionSplit {
        run_suspended: job_suspended(run),
        wait_suspended: job_suspended(wait),
        run_running: running_count(run_pods),
        wait_running: running_count(wait_pods),
        run_admitted: workload_for(workloads, JOB_RUN).and_then(admitted),
        wait_admitted: workload_for(workloads, JOB_WAIT).and_then(admitted),
    }
}

fn split_ok(s: &AdmissionSplit) -> bool {
    !s.run_suspended
        && s.run_running >= 1
        && s.run_admitted == Some(true)
        && s.wait_suspended
        && s.wait_running == 0
        && s.wait_admitted != Some(true)
}

fn wait_admission_split(kubeconfig: &Path, ceiling: Duration, whose: &str) {
    let start = Instant::now();
    loop {
        let run = job_json(kubeconfig, JOB_RUN).ok();
        let wait = job_json(kubeconfig, JOB_WAIT).ok();
        let run_pods = job_pods(kubeconfig, JOB_RUN);
        let wait_pods = job_pods(kubeconfig, JOB_WAIT);
        let workloads = workloads_json(kubeconfig);
        if let (Some(run), Some(wait)) = (run.as_ref(), wait.as_ref()) {
            let s = split_from(run, wait, &run_pods, &wait_pods, &workloads);
            if split_ok(&s) {
                assert_kueue_pending(&wait_pods, workload_for(&workloads, JOB_WAIT), whose);
                eprintln!(
                    "ml-kueue: {whose} Admitted/Pending split after {:?} \
                     (run Running={} wait suspend={} wait_admitted={:?})",
                    start.elapsed(),
                    s.run_running,
                    s.wait_suspended,
                    s.wait_admitted
                );
                return;
            }
            if start.elapsed() > ceiling {
                if s.run_running >= 1 && s.wait_running >= 1 {
                    panic!(
                        "{whose}: both GPU Jobs are Running — ClusterQueue \
                         nvidia.com/gpu quota of 1 is fiction\n{}",
                        gpu_diagnostics(kubeconfig)
                    );
                }
                assert_kueue_pending(&wait_pods, workload_for(&workloads, JOB_WAIT), whose);
                panic!(
                    "{whose}: never reached one Admitted Running + one \
                     Kueue-Pending after {ceiling:?} \
                     (run_suspend={} run_pods={} run_adm={:?} \
                     wait_suspend={} wait_pods={} wait_adm={:?})\n{}",
                    s.run_suspended,
                    s.run_running,
                    s.run_admitted,
                    s.wait_suspended,
                    s.wait_running,
                    s.wait_admitted,
                    gpu_diagnostics(kubeconfig)
                );
            }
        } else if start.elapsed() > ceiling {
            panic!(
                "{whose}: Jobs missing after {ceiling:?} (run={run:?} wait={wait:?})\n{}",
                gpu_diagnostics(kubeconfig)
            );
        }
        eprintln!("ml-kueue: {whose} waiting for Admitted/Pending split");
        std::thread::sleep(Duration::from_secs(3));
    }
}

fn snapshot_with_kueue(kubeconfig: &Path) -> BTreeMap<String, (String, BTreeMap<String, u64>)> {
    let mut all = snapshot_via_kubectl(kubeconfig);
    if let Ok(body) = kubectl(kubeconfig, &["get", "pods", "-n", KUEUE_NS, "-o", "json"]) {
        all.extend(snapshot_pods_json(&body));
    }
    all
}

#[allow(clippy::type_complexity)]
fn snapshot_with_kueue_via(
    bridge: &str,
    certs: &Path,
) -> Result<BTreeMap<String, (String, BTreeMap<String, u64>)>, String> {
    let mut all = snapshot_via_bridge(bridge, certs)?;
    if let Ok(body) = curl_get(
        bridge,
        certs,
        &format!("/api/v1/namespaces/{KUEUE_NS}/pods"),
    ) {
        all.extend(snapshot_pods_json(&body));
    }
    Ok(all)
}

fn localqueue_via_bridge(
    bridge: &str,
    certs: &Path,
    name: &str,
) -> Result<serde_json::Value, String> {
    let body = curl_get(
        bridge,
        certs,
        &format!("/apis/kueue.x-k8s.io/v1beta2/namespaces/default/localqueues/{name}"),
    )?;
    serde_json::from_str(&body).map_err(|e| format!("localqueue {name}: {e}: {body}"))
}

fn clusterqueue_via_bridge(bridge: &str, certs: &Path) -> Result<serde_json::Value, String> {
    let body = curl_get(
        bridge,
        certs,
        &format!("/apis/kueue.x-k8s.io/v1beta2/clusterqueues/{CLUSTER_QUEUE}"),
    )?;
    serde_json::from_str(&body).map_err(|e| format!("clusterqueue: {e}: {body}"))
}

fn child_localqueue_json() -> String {
    serde_json::json!({
        "apiVersion": KUEUE_API,
        "kind": "LocalQueue",
        "metadata": {"name": QUEUE_CHILD, "namespace": "default"},
        "spec": {"clusterQueue": CLUSTER_QUEUE}
    })
    .to_string()
}

fn assert_source_missing_child(bridge: &str, certs: &Path) {
    let src_see = curl_get(
        bridge,
        certs,
        &format!("/apis/kueue.x-k8s.io/v1beta2/namespaces/default/localqueues/{QUEUE_CHILD}"),
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
        "source cluster saw the child-only LocalQueue {QUEUE_CHILD}: {src_see:?}"
    );
}

fn assert_split_via(bridge: &str, certs: &Path, whose: &str) -> Result<AdmissionSplit, String> {
    let run = job_via_bridge(bridge, certs, JOB_RUN)?;
    let wait = job_via_bridge(bridge, certs, JOB_WAIT)?;
    let run_pods = job_pods_via_bridge(bridge, certs, JOB_RUN)?;
    let wait_pods = job_pods_via_bridge(bridge, certs, JOB_WAIT)?;
    let workloads = workloads_via_bridge(bridge, certs)?;
    let s = split_from(&run, &wait, &run_pods, &wait_pods, &workloads);
    if !split_ok(&s) {
        return Err(format!(
            "{whose}: split run_suspend={} run_pods={} run_adm={:?} \
             wait_suspend={} wait_pods={} wait_adm={:?}",
            s.run_suspended,
            s.run_running,
            s.run_admitted,
            s.wait_suspended,
            s.wait_running,
            s.wait_admitted
        ));
    }
    assert_kueue_pending(&wait_pods, workload_for(&workloads, JOB_WAIT), whose);
    Ok(s)
}

/// 3-node Ubuntu k3s + GPU fixture + Kueue quota, then warm-fork and diverge.
#[test]
fn test_ubuntu_ml_kueue_gpu_fork() {
    let _ = env_logger::builder().is_test(true).try_init();

    let queues = std::fs::read_to_string(fixture("kueue/queues.yaml")).expect("queues");
    let run_yaml = std::fs::read_to_string(fixture("kueue/gpu-job-run.yaml")).expect("run");
    let wait_yaml = std::fs::read_to_string(fixture("kueue/gpu-job-wait.yaml")).expect("wait");
    assert!(
        queues.contains(RESOURCE)
            && queues.contains("nominalQuota: 1")
            && !queues.contains(":latest"),
        "ClusterQueue must nominate {RESOURCE} with quota 1"
    );
    for (name, text) in [
        ("gpu-job-run.yaml", &run_yaml),
        ("gpu-job-wait.yaml", &wait_yaml),
    ] {
        assert!(
            text.contains("@sha256:") && !text.contains(":latest"),
            "{name} must pin images by digest"
        );
        assert!(
            text.contains(&format!("{RESOURCE}: \"1\"")),
            "{name} must request exactly {RESOURCE}: 1"
        );
        assert!(
            text.contains(QUEUE_LABEL) && text.contains(LOCAL_QUEUE),
            "{name} must target LocalQueue {LOCAL_QUEUE}"
        );
        assert!(
            text.contains(BUSYBOX),
            "{name} operand must be the inc1 busybox pin"
        );
    }

    let mut cluster = bring_up_cluster();
    let gpu0 = apply_gpu_dcgm_fixture(&mut cluster);
    let kube = cluster.kubeconfig.clone();
    let names = cluster.names();
    assert_eq!(gpu0.capacity.len(), 3);
    let used0 = gpu_used_via_kubectl(&kube);
    assert_gpu_consistent(&gpu0, &used0, &names, 0, "source before Kueue");

    install_kueue(&kube);
    apply_yaml(&kube, "kueue/queues.yaml");
    apply_yaml(&kube, "kueue/gpu-job-run.yaml");
    wait_gpu_used(&kube, 1, FIXTURE_READY, "source after admitted Job");
    apply_yaml(&kube, "kueue/gpu-job-wait.yaml");
    wait_admission_split(&kube, FIXTURE_READY, "source");
    let used_run = wait_gpu_used(&kube, 1, Duration::from_secs(60), "source split");
    let gpu_run = gpu_via_kubectl(&kube);
    assert_gpu_consistent(&gpu_run, &used_run, &names, 1, "source split");

    let src_bridge = cluster.bridge().to_string();
    let metrics = scrape_dcgm(&src_bridge, cluster.server_ip)
        .unwrap_or_else(|e| panic!("source DCGM scrape: {e}\n{}", gpu_diagnostics(&kube)));
    assert_dcgm_metrics(&metrics, "source");

    wait_nodes_ready(&kube, &names, Duration::from_secs(120));
    let before = snapshot_with_kueue(&kube);
    assert!(
        before
            .keys()
            .any(|k| k.contains("kueue-controller-manager")),
        "Kueue controller missing from restart snapshot: {before:?}"
    );
    assert!(
        before.keys().any(|k| k.contains("gpu-job-run-")),
        "admitted Job pod missing from snapshot: {before:?}"
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
        "ubkuf",
        &[None, None, None],
        &[None, None, None],
        &["ubuntu-ku-0", "ubuntu-ku-1", "ubuntu-ku-2"],
    )
    .expect("warm fork of the Ubuntu Kueue cluster");
    let fork_latency = fork_start.elapsed();
    eprintln!(
        "MEASUREMENT ubuntu ml-kueue cluster warm fork (3 × {NODE_MEMORY_MB} MB): {fork_latency:?} \
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
        let src_pods = snapshot_with_kueue_via(&src_bridge, &certs)
            .unwrap_or_else(|e| panic!("source pods via {src_bridge}: {e}"));
        let child_pods = snapshot_with_kueue_via(&child_bridge, &certs)
            .unwrap_or_else(|e| panic!("child pods via {child_bridge}: {e}"));
        assert_no_restarts(&before, &src_pods, "source");
        assert_no_restarts(&before, &child_pods, "child");
        let src_ready = nodes_ready_via(&src_bridge, &certs, &names);
        let child_ready = nodes_ready_via(&child_bridge, &certs, &names);
        let child_split = assert_split_via(&child_bridge, &certs, "child").ok();
        let child_used = gpu_used_via_bridge(&child_bridge, &certs).ok();
        let child_cq = clusterqueue_via_bridge(&child_bridge, &certs).ok();
        let child_lq = localqueue_via_bridge(&child_bridge, &certs, LOCAL_QUEUE).ok();
        let ok = src_ready
            && child_ready
            && child_split.is_some()
            && child_used.as_ref().is_some_and(|u| sum(u) == 1)
            && child_cq.is_some()
            && child_lq.is_some();
        if ok && start.elapsed() >= Duration::from_secs(5) {
            eprintln!(
                "fork: both clusters Ready, Kueue Admitted/Pending split, \
                 {RESOURCE} used=1, zero restarts across {:?}",
                start.elapsed()
            );
            break;
        }
        if start.elapsed() > CONVERGE {
            panic!(
                "fork: clusters did not converge Ready+Kueue+used in {CONVERGE:?} \
                 (src_ready={src_ready} child_ready={child_ready} \
                 child_split={child_split:?} child_used={child_used:?} \
                 child_cq={} child_lq={})",
                child_cq.is_some(),
                child_lq.is_some()
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
    assert_split_via(&src_bridge, &certs, "source-after-fork").unwrap_or_else(|e| panic!("{e}"));
    assert_split_via(&child_bridge, &certs, "child-after-converge")
        .unwrap_or_else(|e| panic!("{e}"));

    let child_metrics = scrape_dcgm(&child_bridge, cluster.server_ip)
        .unwrap_or_else(|e| panic!("child DCGM scrape: {e}"));
    assert_dcgm_metrics(&child_metrics, "child");
    eprintln!("ml-kueue: child DCGM scrape ok ({} B)", child_metrics.len());

    let create_start = Instant::now();
    loop {
        match curl_api(
            &child_bridge,
            &certs,
            "POST",
            "/apis/kueue.x-k8s.io/v1beta2/namespaces/default/localqueues",
            Some(&child_localqueue_json()),
        ) {
            Ok(body) if !body.contains("Failure") && !body.contains("error") => {
                eprintln!(
                    "ml-kueue: child-only {QUEUE_CHILD} created after {:?}",
                    create_start.elapsed()
                );
                break;
            }
            other if create_start.elapsed() < Duration::from_secs(90) => {
                eprintln!(
                    "ml-kueue: child LocalQueue create retry ({other:?}) {:?}",
                    create_start.elapsed()
                );
                std::thread::sleep(Duration::from_secs(3));
            }
            other => panic!(
                "child LocalQueue webhook/create failed for 90s: {other:?}. \
                 Kueue webhook CA / service may have died across the fork."
            ),
        }
    }

    let wait_child = Instant::now();
    loop {
        if localqueue_via_bridge(&child_bridge, &certs, QUEUE_CHILD).is_ok() {
            eprintln!(
                "ml-kueue: child-only LocalQueue visible on child after {:?}",
                wait_child.elapsed()
            );
            break;
        }
        if wait_child.elapsed() > Duration::from_secs(30) {
            panic!("child-only {QUEUE_CHILD} never appeared on the child");
        }
        std::thread::sleep(Duration::from_secs(2));
    }

    let src_after = gpu_via_bridge(&src_bridge, &certs)
        .unwrap_or_else(|e| panic!("source nodes after child extra queue: {e}"));
    let src_used_after = gpu_used_via_bridge(&src_bridge, &certs)
        .unwrap_or_else(|e| panic!("source gpu used after child extra: {e}"));
    assert_gpu_consistent(
        &src_after,
        &src_used_after,
        &names,
        1,
        "source-must-not-see-child-queue",
    );
    assert_split_via(&src_bridge, &certs, "source-after-child-queue")
        .unwrap_or_else(|e| panic!("{e}"));
    assert_source_missing_child(&src_bridge, &certs);
    eprintln!(
        "fork: source {RESOURCE} used still 1; child-only {QUEUE_CHILD} is invisible on source"
    );

    for child in &mut forks {
        child.shutdown();
    }
    drop(fork_net);
}
