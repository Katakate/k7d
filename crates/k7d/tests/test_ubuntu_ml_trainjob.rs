//! TrainJob / Kubeflow Trainer on the fake GPU fixture, then
//! a warm fork.
//!
//! JobSet (pinned) plus digest-pinned Trainer v2.2.1, a custom
//! busybox TrainingRuntime (PlainML — not torch, not CUDA), and a
//! 2-worker TrainJob each requesting `nvidia.com/gpu: 1`. Workers
//! rendezvous over Trainer/JobSet DNS and stay Running so the fork
//! has an in-flight object. Reuses `bring_up_cluster` (Flannel) and
//! `FORK_UBUNTU_K3S_CLUSTER_3VM`. Does not touch `crates/k7d/src`.

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

const JOBSET_VERSION: &str = "v0.12.0";
const JOBSET_MANIFESTS_URL: &str =
    "https://github.com/kubernetes-sigs/jobset/releases/download/v0.12.0/manifests.yaml";
const JOBSET_MANIFESTS_SHA256: &str =
    "a41aaf12dd0b7b0a3d626b8d6107f32c3dc889d7e7830adc46b8cdb77a8963bb";
const JOBSET_IMAGE_UNPINNED: &str = "registry.k8s.io/jobset/jobset:v0.12.0";
const JOBSET_IMAGE: &str = "registry.k8s.io/jobset/jobset:v0.12.0@sha256:e75536f1135b7bb2f19f8c3b620782fbdd9091d73398e3a272f9a5fed322980d";

const TRAINER_VERSION: &str = "2.2.1";
const TRAINER_CHART_REF: &str = "oci://ghcr.io/kubeflow/charts/kubeflow-trainer";
const TRAINER_CHART_SHA256: &str =
    "24d97c59888fd4a1d8d4ba50ce4df2c4ef9ddb40e81634bb8d84188389a0c13d";
const TRAINER_IMAGE_UNPINNED: &str = "ghcr.io/kubeflow/trainer/trainer-controller-manager:v2.2.1";
const TRAINER_IMAGE: &str = "ghcr.io/kubeflow/trainer/trainer-controller-manager:v2.2.1@sha256:85ff57895fe677fcc2eef11b431cb176f5925b61b742447252392ca0efe242f7";

const JOBSET_NS: &str = "jobset-system";
const TRAINER_NS: &str = "kubeflow-system";
const TRAINJOB: &str = "gpu-trainjob-run";
const TRAINJOB_CHILD: &str = "gpu-trainjob-child";
const RUNTIME: &str = "busybox-cpu-gloo";
const TRAINER_READY: Duration = Duration::from_secs(300);
const JOBSET_READY: Duration = Duration::from_secs(300);
const WORKER_FQDN_0: &str = "gpu-trainjob-run-node-0-0.gpu-trainjob-run.default.svc.cluster.local";
const WORKER_FQDN_1: &str = "gpu-trainjob-run-node-0-1.gpu-trainjob-run.default.svc.cluster.local";

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
    refuse_latest_images(&text, &format!("JobSet {JOBSET_VERSION}"));
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
                "ml-trainjob: JobSet {JOBSET_VERSION} controller Ready + webhook CA after {:?}",
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
            "ml-trainjob: waiting for JobSet controller (crd={} ca_len={})",
            crd.trim(),
            ca.trim().len()
        );
        std::thread::sleep(Duration::from_secs(3));
    }
}

fn fetch_trainer_chart() -> PathBuf {
    let helm = ensure_helm();
    let dest_dir = PathBuf::from(format!(
        "/tmp/k7d-trainer-chart-{}-{}",
        TRAINER_VERSION,
        std::process::id()
    ));
    std::fs::create_dir_all(&dest_dir).expect("trainer chart dir");
    let out = Command::new(&helm)
        .args([
            "pull",
            TRAINER_CHART_REF,
            "--version",
            TRAINER_VERSION,
            "--destination",
            &dest_dir.to_string_lossy(),
        ])
        .output()
        .expect("helm pull kubeflow-trainer");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "helm pull {TRAINER_CHART_REF}:{TRAINER_VERSION} failed — refuse to \
         apply an unpinned Trainer: {stderr}{stdout}"
    );
    let dest = dest_dir.join(format!("kubeflow-trainer-{TRAINER_VERSION}.tgz"));
    assert!(
        dest.is_file(),
        "helm pull did not write {}: {stdout}{stderr}",
        dest.display()
    );
    let got = sha256_file(&dest);
    assert_eq!(
        got, TRAINER_CHART_SHA256,
        "Trainer {TRAINER_VERSION} chart sha256 mismatch: got {got}, \
         want {TRAINER_CHART_SHA256}"
    );
    dest
}

fn pin_trainer_manifests(text: &str) -> String {
    refuse_latest_images(text, &format!("Trainer {TRAINER_VERSION}"));
    assert!(
        !text.contains("jobset-controller-manager")
            && !text.contains("registry.k8s.io/jobset/jobset"),
        "templated Trainer chart installed JobSet — keep the pinned \
         jobset-system pin and set jobset.install=false"
    );
    assert!(
        text.contains(TRAINER_IMAGE_UNPINNED),
        "templated chart missing {TRAINER_IMAGE_UNPINNED}"
    );
    let pinned = text.replace(TRAINER_IMAGE_UNPINNED, TRAINER_IMAGE);
    assert!(
        pinned.contains("@sha256:85ff57895fe677fcc2eef11b431cb176f5925b61b742447252392ca0efe242f7"),
        "Trainer controller image was not rewritten to a digest pin"
    );
    assert!(
        !pinned.contains(&format!("{TRAINER_IMAGE_UNPINNED}\n"))
            && !pinned.contains(&format!("{TRAINER_IMAGE_UNPINNED}\"")),
        "unpinned Trainer image remains after rewrite"
    );
    for line in pinned.lines() {
        let t = line.trim();
        let Some(img) = t.strip_prefix("image:") else {
            continue;
        };
        let img = img.trim().trim_matches('"');
        if img.is_empty() {
            continue;
        }
        assert!(
            img.contains("@sha256:"),
            "Trainer {TRAINER_VERSION} image is not digest-pinned: {img}"
        );
    }
    pinned
}

fn install_trainer(kubeconfig: &Path) {
    let helm = ensure_helm();
    let chart = fetch_trainer_chart();
    kubectl(kubeconfig, &["create", "ns", TRAINER_NS]).ok();
    let values = PathBuf::from(format!(
        "/tmp/k7d-trainer-values-{}.yaml",
        std::process::id()
    ));
    std::fs::write(
        &values,
        r#"jobset:
  install: false
runtimes:
  defaultEnabled: false
image:
  registry: ghcr.io
  repository: kubeflow/trainer/trainer-controller-manager
  tag: v2.2.1
"#,
    )
    .expect("write trainer values");
    let out = Command::new(&helm)
        .args([
            "template",
            "kubeflow-trainer",
            &chart.to_string_lossy(),
            "--namespace",
            TRAINER_NS,
            "--include-crds",
            "-f",
            &values.to_string_lossy(),
        ])
        .output()
        .expect("helm template kubeflow-trainer");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "helm template Trainer {TRAINER_VERSION} failed: {stderr}{stdout}"
    );
    let pinned = pin_trainer_manifests(&stdout);
    let dest = PathBuf::from(format!(
        "/tmp/k7d-trainer-{TRAINER_VERSION}-{}.yaml",
        std::process::id()
    ));
    std::fs::write(&dest, pinned).expect("write pinned trainer manifests");
    kubectl(
        kubeconfig,
        &["apply", "--server-side", "-f", &dest.to_string_lossy()],
    )
    .unwrap_or_else(|e| panic!("kubectl apply --server-side Trainer {TRAINER_VERSION}: {e}"));
    let start = Instant::now();
    loop {
        let crd = kubectl(
            kubeconfig,
            &[
                "get",
                "crd",
                "trainjobs.trainer.kubeflow.org",
                "-o",
                "jsonpath={.status.conditions[?(@.type==\"Established\")].status}",
            ],
        )
        .unwrap_or_default();
        let runtime_crd = kubectl(
            kubeconfig,
            &[
                "get",
                "crd",
                "trainingruntimes.trainer.kubeflow.org",
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
                "deploy/kubeflow-trainer-controller-manager",
                "-n",
                TRAINER_NS,
                "--timeout=15s",
            ],
        );
        let ca = kubectl(
            kubeconfig,
            &[
                "get",
                "validatingwebhookconfiguration",
                "validator.trainer.kubeflow.org",
                "-o",
                "jsonpath={.webhooks[0].clientConfig.caBundle}",
            ],
        )
        .unwrap_or_default();
        if crd.trim() == "True"
            && runtime_crd.trim() == "True"
            && deploy.is_ok()
            && !ca.trim().is_empty()
        {
            eprintln!(
                "ml-trainjob: Trainer {TRAINER_VERSION} controller Ready + webhook CA after {:?}",
                start.elapsed()
            );
            return;
        }
        if start.elapsed() > TRAINER_READY {
            panic!(
                "Trainer {TRAINER_VERSION} never Ready after {TRAINER_READY:?} \
                 (crd={:?} runtime_crd={:?} deploy={:?} ca_len={})\n{}",
                crd.trim(),
                runtime_crd.trim(),
                deploy.as_ref().err(),
                ca.trim().len(),
                gpu_diagnostics(kubeconfig)
            );
        }
        eprintln!(
            "ml-trainjob: waiting for Trainer controller (crd={} runtime_crd={} ca_len={})",
            crd.trim(),
            runtime_crd.trim(),
            ca.trim().len()
        );
        std::thread::sleep(Duration::from_secs(3));
    }
}

fn apply_cr(kubeconfig: &Path, name: &str) {
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
                eprintln!("ml-trainjob: applied {name} after {:?}", start.elapsed());
                return;
            }
            Err(e) if start.elapsed() < Duration::from_secs(90) => {
                eprintln!(
                    "ml-trainjob: apply {name} failed (webhook not ready?): {e}; retry {:?}",
                    start.elapsed()
                );
                std::thread::sleep(Duration::from_secs(3));
            }
            Err(e) => panic!(
                "apply {name} failed for 90s (Trainer webhook?): {e}\n{}",
                gpu_diagnostics(kubeconfig)
            ),
        }
    }
}

fn trainjob_condition(kubeconfig: &Path, name: &str, cond: &str) -> String {
    kubectl(
        kubeconfig,
        &[
            "get",
            "trainjob",
            name,
            "-o",
            &format!("jsonpath={{.status.conditions[?(@.type==\"{cond}\")].status}}"),
        ],
    )
    .unwrap_or_default()
    .trim()
    .to_string()
}

fn wait_trainjob_workers_running(kubeconfig: &Path, name: &str, want: usize, ceiling: Duration) {
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
                "ml-trainjob: {name} {running} workers Running after {:?}",
                start.elapsed()
            );
            return;
        }
        if trainjob_condition(kubeconfig, name, "Failed") == "True" {
            panic!(
                "{name} Failed while waiting for {want} Running workers \
                 (phases={:?}). If pods CrashLoop, Trainer injected \
                 torchrun — use a PlainML runtime and trainer.command \
                 overwrite.\n{}",
                body.trim(),
                gpu_diagnostics(kubeconfig)
            );
        }
        if start.elapsed() > ceiling {
            panic!(
                "{name}: expected {want} Running workers after {ceiling:?} \
                 (phases={:?}). GPU request must be {RESOURCE}: 1.\n{}",
                body.trim(),
                gpu_diagnostics(kubeconfig)
            );
        }
        eprintln!("ml-trainjob: {name} worker phases {}", body.trim());
        std::thread::sleep(Duration::from_secs(3));
    }
}

fn snapshot_with_trainer(kubeconfig: &Path) -> BTreeMap<String, (String, BTreeMap<String, u64>)> {
    let mut all = snapshot_via_kubectl(kubeconfig);
    for ns in [JOBSET_NS, TRAINER_NS] {
        if let Ok(body) = kubectl(kubeconfig, &["get", "pods", "-n", ns, "-o", "json"]) {
            all.extend(snapshot_pods_json(&body));
        }
    }
    all
}

fn snapshot_with_trainer_via(
    bridge: &str,
    certs: &Path,
) -> Result<BTreeMap<String, (String, BTreeMap<String, u64>)>, String> {
    let mut all = snapshot_via_bridge(bridge, certs)?;
    for ns in [JOBSET_NS, TRAINER_NS] {
        if let Ok(body) = curl_get(bridge, certs, &format!("/api/v1/namespaces/{ns}/pods")) {
            all.extend(snapshot_pods_json(&body));
        }
    }
    Ok(all)
}

fn trainjob_via_bridge(
    bridge: &str,
    certs: &Path,
    name: &str,
) -> Result<serde_json::Value, String> {
    let body = curl_get(
        bridge,
        certs,
        &format!("/apis/trainer.kubeflow.org/v1alpha1/namespaces/default/trainjobs/{name}"),
    )?;
    serde_json::from_str(&body).map_err(|e| format!("trainjob json {name}: {e}: {body}"))
}

fn condition_status<'a>(v: &'a serde_json::Value, cond: &str) -> &'a str {
    v["status"]["conditions"]
        .as_array()
        .and_then(|cs| {
            cs.iter()
                .find(|c| c["type"].as_str() == Some(cond))
                .and_then(|c| c["status"].as_str())
        })
        .unwrap_or("")
}

fn child_trainjob_json() -> String {
    serde_json::json!({
        "apiVersion": "trainer.kubeflow.org/v1alpha1",
        "kind": "TrainJob",
        "metadata": {"name": TRAINJOB_CHILD, "namespace": "default"},
        "spec": {
            "runtimeRef": {
                "apiGroup": "trainer.kubeflow.org",
                "kind": "TrainingRuntime",
                "name": RUNTIME
            },
            "trainer": {
                "image": BUSYBOX,
                "numNodes": 1,
                "resourcesPerNode": {
                    "limits": {RESOURCE: "1"},
                    "requests": {RESOURCE: "1"}
                },
                "command": ["/bin/sh", "-c"],
                "args": ["sleep 86400"]
            }
        }
    })
    .to_string()
}

fn assert_source_missing_child(bridge: &str, certs: &Path) {
    let src_see = curl_get(
        bridge,
        certs,
        &format!(
            "/apis/trainer.kubeflow.org/v1alpha1/namespaces/default/trainjobs/{TRAINJOB_CHILD}"
        ),
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
        "source cluster saw the child-only TrainJob {TRAINJOB_CHILD}: {src_see:?}"
    );
}

/// 3-node Ubuntu k3s + GPU fixture + JobSet + Trainer, then warm-fork.
#[test]
fn test_ubuntu_ml_trainjob_gpu_fork() {
    let _ = env_logger::builder().is_test(true).try_init();

    let runtime_yaml =
        std::fs::read_to_string(fixture("trainjob/busybox-runtime.yaml")).expect("runtime");
    let job_yaml =
        std::fs::read_to_string(fixture("trainjob/gpu-trainjob-run.yaml")).expect("trainjob");
    for (name, text) in [
        ("busybox-runtime.yaml", &runtime_yaml),
        ("gpu-trainjob-run.yaml", &job_yaml),
    ] {
        assert!(
            text.contains("@sha256:") && !text.contains(":latest"),
            "{name} must pin images by digest"
        );
        assert!(
            text.contains(&format!("{RESOURCE}: \"1\"")),
            "{name} workers must request exactly {RESOURCE}: 1"
        );
        assert!(
            !text.contains("pytorch/")
                && !text.contains("nvidia/cuda")
                && !text.contains("ghcr.io/kubeflow/trainer/"),
            "{name} must not pull a CUDA / Trainer runtime image"
        );
    }
    assert!(
        runtime_yaml.contains("mlPolicy")
            && !runtime_yaml.contains("torch:")
            && !runtime_yaml.contains("mpi:"),
        "TrainingRuntime must be PlainML (no torch/MPI — those inject torchrun/mpirun)"
    );
    assert!(
        job_yaml.contains("kind: TrainingRuntime") && job_yaml.contains(RUNTIME),
        "TrainJob must reference the custom busybox TrainingRuntime"
    );
    assert!(
        job_yaml.contains(WORKER_FQDN_0) && job_yaml.contains(WORKER_FQDN_1),
        "TrainJob must rendezvous on Trainer/JobSet headless FQDNs \
         (busybox nslookup does not apply search domains; CHALLENGES #148)"
    );
    assert!(
        job_yaml.contains("cpu-gloo") && runtime_yaml.contains("cpu-gloo"),
        "train script must be named CPU/Gloo-shaped (not CUDA / not PyTorch)"
    );
    assert!(
        job_yaml.contains("command:")
            && job_yaml.contains("/bin/sh")
            && job_yaml.contains("image:"),
        "TrainJob must set trainer.image + trainer.command so Trainer cannot \
         inject torchrun or a CUDA runtime image"
    );

    let mut cluster = bring_up_cluster();
    let gpu0 = apply_gpu_dcgm_fixture(&mut cluster);
    let kube = cluster.kubeconfig.clone();
    let names = cluster.names();
    assert_eq!(gpu0.capacity.len(), 3);
    let used0 = gpu_used_via_kubectl(&kube);
    assert_gpu_consistent(&gpu0, &used0, &names, 0, "source before TrainJob");

    install_jobset(&kube);
    install_trainer(&kube);
    apply_cr(&kube, "trainjob/busybox-runtime.yaml");
    apply_cr(&kube, "trainjob/gpu-trainjob-run.yaml");
    wait_trainjob_workers_running(&kube, TRAINJOB, 2, FIXTURE_READY);
    let used_run = wait_gpu_used(&kube, 2, Duration::from_secs(60), "source TrainJob");
    let gpu_run = gpu_via_kubectl(&kube);
    assert_gpu_consistent(&gpu_run, &used_run, &names, 2, "source TrainJob");
    assert_ne!(
        trainjob_condition(&kube, TRAINJOB, "Failed"),
        "True",
        "{TRAINJOB} Failed on the source"
    );
    assert_ne!(
        trainjob_condition(&kube, TRAINJOB, "Complete"),
        "True",
        "{TRAINJOB} must still be in-flight (workers sleep after the CPU/Gloo barrier)"
    );

    let src_bridge = cluster.bridge().to_string();
    let metrics = scrape_dcgm(&src_bridge, cluster.server_ip)
        .unwrap_or_else(|e| panic!("source DCGM scrape: {e}\n{}", gpu_diagnostics(&kube)));
    assert_dcgm_metrics(&metrics, "source");

    wait_nodes_ready(&kube, &names, Duration::from_secs(120));
    let before = snapshot_with_trainer(&kube);
    assert!(
        before
            .keys()
            .any(|k| k.contains("kubeflow-trainer-controller-manager")),
        "Trainer controller missing from restart snapshot: {before:?}"
    );
    assert!(
        before
            .keys()
            .any(|k| k.contains("jobset-controller-manager")),
        "JobSet controller missing from restart snapshot: {before:?}"
    );
    assert!(
        before
            .keys()
            .filter(|k| k.contains("gpu-trainjob-run-node-"))
            .count()
            >= 2,
        "in-flight TrainJob workers missing from snapshot: {before:?}"
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
        "ubtjf",
        &[None, None, None],
        &[None, None, None],
        &["ubuntu-tj-0", "ubuntu-tj-1", "ubuntu-tj-2"],
    )
    .expect("warm fork of the Ubuntu TrainJob cluster");
    let fork_latency = fork_start.elapsed();
    eprintln!(
        "MEASUREMENT ubuntu ml-trainjob cluster warm fork (3 × {NODE_MEMORY_MB} MB): {fork_latency:?} \
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
        let src_pods = snapshot_with_trainer_via(&src_bridge, &certs)
            .unwrap_or_else(|e| panic!("source pods via {src_bridge}: {e}"));
        let child_pods = snapshot_with_trainer_via(&child_bridge, &certs)
            .unwrap_or_else(|e| panic!("child pods via {child_bridge}: {e}"));
        assert_no_restarts(&before, &src_pods, "source");
        assert_no_restarts(&before, &child_pods, "child");
        let src_ready = nodes_ready_via(&src_bridge, &certs, &names);
        let child_ready = nodes_ready_via(&child_bridge, &certs, &names);
        let child_job = trainjob_via_bridge(&child_bridge, &certs, TRAINJOB).ok();
        let child_used = gpu_used_via_bridge(&child_bridge, &certs).ok();
        let tj_ok = child_job.as_ref().is_some_and(|v| {
            condition_status(v, "Failed") != "True"
                && condition_status(v, "Complete") != "True"
                && v["metadata"]["name"].as_str() == Some(TRAINJOB)
        }) && child_used.as_ref().is_some_and(|u| sum(u) == 2);
        if src_ready && child_ready && tj_ok && start.elapsed() >= Duration::from_secs(5) {
            eprintln!(
                "fork: both clusters Ready, TrainJob still Running, \
                 {RESOURCE} used=2, zero restarts across {:?}",
                start.elapsed()
            );
            break;
        }
        if start.elapsed() > CONVERGE {
            panic!(
                "fork: clusters did not converge Ready+TrainJob+used in {CONVERGE:?} \
                 (src_ready={src_ready} child_ready={child_ready} \
                 child_job={child_job:?} child_used={child_used:?})"
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

    let child_job = trainjob_via_bridge(&child_bridge, &certs, TRAINJOB)
        .unwrap_or_else(|e| panic!("child {TRAINJOB}: {e}"));
    assert_ne!(
        condition_status(&child_job, "Failed"),
        "True",
        "child lost {TRAINJOB} or marked it Failed"
    );
    assert_ne!(
        condition_status(&child_job, "Complete"),
        "True",
        "child {TRAINJOB} should still be in-flight"
    );

    let child_metrics = scrape_dcgm(&child_bridge, cluster.server_ip)
        .unwrap_or_else(|e| panic!("child DCGM scrape: {e}"));
    assert_dcgm_metrics(&child_metrics, "child");
    eprintln!(
        "ml-trainjob: child DCGM scrape ok ({} B)",
        child_metrics.len()
    );

    let create_start = Instant::now();
    loop {
        match curl_api(
            &child_bridge,
            &certs,
            "POST",
            "/apis/trainer.kubeflow.org/v1alpha1/namespaces/default/trainjobs",
            Some(&child_trainjob_json()),
        ) {
            Ok(body) if !body.contains("Failure") && !body.contains("error") => {
                eprintln!(
                    "ml-trainjob: child-only {TRAINJOB_CHILD} created after {:?}",
                    create_start.elapsed()
                );
                break;
            }
            other if create_start.elapsed() < Duration::from_secs(90) => {
                eprintln!(
                    "ml-trainjob: child TrainJob create retry ({other:?}) {:?}",
                    create_start.elapsed()
                );
                std::thread::sleep(Duration::from_secs(3));
            }
            other => panic!(
                "child TrainJob webhook/create failed for 90s: {other:?}. \
                 Trainer webhook CA / service may have died across the fork."
            ),
        }
    }

    let wait_child = Instant::now();
    loop {
        let child_js = trainjob_via_bridge(&child_bridge, &certs, TRAINJOB_CHILD).ok();
        let used = gpu_used_via_bridge(&child_bridge, &certs).ok();
        if child_js.is_some() && used.as_ref().is_some_and(|u| sum(u) == 3) {
            eprintln!(
                "ml-trainjob: child-only TrainJob using +1 GPU after {:?}",
                wait_child.elapsed()
            );
            break;
        }
        if wait_child.elapsed() > FIXTURE_READY {
            panic!(
                "child-only {TRAINJOB_CHILD} never reached GPU used=3 \
                 (js={child_js:?} used={used:?})"
            );
        }
        std::thread::sleep(Duration::from_secs(3));
    }

    let child_after = gpu_via_bridge(&child_bridge, &certs)
        .unwrap_or_else(|e| panic!("child nodes after extra TrainJob: {e}"));
    let child_used_after = gpu_used_via_bridge(&child_bridge, &certs)
        .unwrap_or_else(|e| panic!("child gpu used after extra: {e}"));
    assert_gpu_consistent(
        &child_after,
        &child_used_after,
        &names,
        3,
        "child-after-extra-trainjob",
    );

    let src_after = gpu_via_bridge(&src_bridge, &certs)
        .unwrap_or_else(|e| panic!("source nodes after child extra TrainJob: {e}"));
    let src_used_after = gpu_used_via_bridge(&src_bridge, &certs)
        .unwrap_or_else(|e| panic!("source gpu used after child extra: {e}"));
    assert_gpu_consistent(
        &src_after,
        &src_used_after,
        &names,
        2,
        "source-must-not-see-child-trainjob",
    );
    assert_source_missing_child(&src_bridge, &certs);
    eprintln!(
        "fork: source {RESOURCE} used still 2; child-only {TRAINJOB_CHILD} is invisible on source"
    );

    for child in &mut forks {
        child.shutdown();
    }
    drop(fork_net);
}
