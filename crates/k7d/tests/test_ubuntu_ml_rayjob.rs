//! RayJob on the fake GPU fixture with a digest-pinned CPU Ray image.
//!
//! Official `rayproject/ray:2.47.1-py311` (not busybox) on 8 GiB /
//! 4 vCPU Ubuntu nodes. A RayJob whose worker requests
//! `nvidia.com/gpu: 1` reaches SUCCEEDED. `ray status` is recorded
//! with and without `rayStartParams.num-gpus`. There is no NVML on
//! the mock; KubeRay still injects `--num-gpus` from the
//! `nvidia.com/gpu` request, so Ray reports **1 GPU** either way.
//! That is a resource count, not CUDA / placement-group hardware.
//!
//! Reuses the KubeRay v1.7.0 Helm pin. Does **not** set
//! `ray.io/overwrite-container-cmd` (that is the busybox opt-out,
//! CHALLENGES #157). Does not edit `test_ubuntu_ml_kuberay.rs` or
//! `NODE_MEMORY_MB` / `NodeSize::DEFAULT`. Does not touch
//! `crates/k7d/src`.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use common::ml_platform::{
    apply_gpu_dcgm_fixture, fixture, gpu_diagnostics, wait_gpu_used, FIXTURE_READY, RESOURCE,
};
use common::ubuntu::{host_mem_available_kb, NodeSize};
use common::ubuntu_helm::ensure_helm;
use common::ubuntu_k3s::{bring_up_cluster_sized, kubectl, UbuntuCni};

const KUBERAY_VERSION: &str = "1.7.0";
const KUBERAY_CHART_URL: &str =
    "https://github.com/ray-project/kuberay-helm/releases/download/kuberay-operator-1.7.0/kuberay-operator-1.7.0.tgz";
const KUBERAY_CHART_SHA256: &str =
    "1a2a8087da487f9ff5c82f1a2bb227b2aff0acfd8d9a9249514db3daf61d0334";
const KUBERAY_IMAGE_UNPINNED: &str = "quay.io/kuberay/operator:v1.7.0";
const KUBERAY_IMAGE: &str = "quay.io/kuberay/operator:v1.7.0@sha256:4a779237ef1c5262a63840ccf42d0d67f0b74e911158fbcaee4478fb1560bce6";

const RAY_IMAGE: &str = "docker.io/rayproject/ray:2.47.1-py311@sha256:a2d5da8d5becaf5369309d0cc30a848094ce2c596b2536201f6dfb66679d42d3";
const OVERWRITE_CMD: &str = "ray.io/overwrite-container-cmd";

const KUBERAY_NS: &str = "kuberay-system";
const RAYJOB: &str = "gpu-rayjob";
const RAYJOB_NO_NUM_GPUS: &str = "gpu-rayjob-no-num-gpus";
const KUBERAY_READY: Duration = Duration::from_secs(300);
/// First RayJob pays for the multi-GB image pull on every node.
const RAYJOB_READY: Duration = Duration::from_secs(1200);
const RAYJOB_READY_CACHED: Duration = Duration::from_secs(600);

/// Official Ray needs more than the 2 GB / 2 vCPU default.
/// The floor is 8 GiB / 4 vCPU.
const RAY_NODE: NodeSize = NodeSize {
    memory_mb: 8192,
    vcpus: 4,
    dilation: 1,
};
const RAY_NODE_COMPACT: NodeSize = NodeSize {
    memory_mb: 4096,
    vcpus: 4,
    dilation: 1,
};

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
                "rayjobs.ray.io",
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
                "ml-rayjob: KubeRay {KUBERAY_VERSION} operator Ready + RayJob CRD after {:?}",
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
            "ml-rayjob: waiting for KubeRay operator (crd={})",
            crd.trim()
        );
        std::thread::sleep(Duration::from_secs(3));
    }
}

/// 8 GiB / 4 vCPU unless host `MemAvailable` cannot hold 3×8 GiB.
/// Compact fallback is 4 GiB / 4 vCPU plus `object-store-memory`.
fn choose_ray_node() -> (NodeSize, bool) {
    let avail = host_mem_available_kb();
    let need = 3 * RAY_NODE.memory_mb * 1024 + 2 * 1024 * 1024;
    if avail >= need {
        eprintln!(
            "ml-rayjob: MemAvailable {avail} KiB holds 3×{} MiB; using RAY_NODE",
            RAY_NODE.memory_mb
        );
        (RAY_NODE, false)
    } else {
        eprintln!(
            "ml-rayjob: MemAvailable {avail} KiB < {need} KiB (3×8 GiB + 2 GiB slack); \
             falling back to 4096/4 + object-store-memory=400000000"
        );
        (RAY_NODE_COMPACT, true)
    }
}

fn patch_object_store(yaml: &str) -> String {
    yaml.replace(
        "dashboard-host: \"0.0.0.0\"",
        "dashboard-host: \"0.0.0.0\"\n        object-store-memory: \"400000000\"",
    )
    .replace(
        "num-gpus: \"1\"",
        "num-gpus: \"1\"\n          object-store-memory: \"400000000\"",
    )
}

fn rayjob_yaml(compact: bool) -> String {
    let path = fixture("kuberay/gpu-rayjob.yaml");
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read gpu-rayjob.yaml: {e}"));
    assert!(
        text.contains("@sha256:") && !text.contains(":latest"),
        "gpu-rayjob.yaml must pin images by digest"
    );
    assert!(
        text.contains(RAY_IMAGE),
        "gpu-rayjob.yaml must use the digest-pinned CPU Ray image"
    );
    assert!(
        !text.lines().any(|l| {
            let t = l.trim();
            !t.starts_with('#') && t.contains(OVERWRITE_CMD)
        }),
        "gpu-rayjob.yaml must not set {OVERWRITE_CMD} (busybox opt-out, CHALLENGES #157)"
    );
    assert!(
        text.contains("num-gpus: \"1\""),
        "gpu-rayjob.yaml worker must set rayStartParams.num-gpus"
    );
    assert!(
        text.contains(&format!("{RESOURCE}: \"1\"")),
        "gpu-rayjob.yaml worker must request exactly {RESOURCE}: 1"
    );
    assert!(
        text.contains("dashboard-host: \"0.0.0.0\""),
        "gpu-rayjob.yaml head must expose the dashboard"
    );
    if compact {
        patch_object_store(&text)
    } else {
        text
    }
}

fn rayjob_without_num_gpus(src: &str) -> String {
    let mut out = String::new();
    for line in src.lines() {
        if line.contains("num-gpus:") {
            continue;
        }
        if line.contains(&format!("name: {RAYJOB}")) && !line.contains("RAYJOB") {
            out.push_str(&line.replace(RAYJOB, RAYJOB_NO_NUM_GPUS));
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    assert!(
        !out.contains("num-gpus:"),
        "stripped RayJob still has num-gpus:\n{out}"
    );
    assert!(
        out.contains(&format!("name: {RAYJOB_NO_NUM_GPUS}")),
        "stripped RayJob name was not rewritten"
    );
    out
}

fn apply_yaml(kubeconfig: &Path, name: &str, yaml: &str) {
    let dest = PathBuf::from(format!("/tmp/k7d-{name}-{}.yaml", std::process::id()));
    std::fs::write(&dest, yaml).expect("write rayjob yaml");
    let start = Instant::now();
    loop {
        match kubectl(kubeconfig, &["apply", "-f", &dest.to_string_lossy()]) {
            Ok(_) => {
                eprintln!("ml-rayjob: applied {name} after {:?}", start.elapsed());
                return;
            }
            Err(e) if start.elapsed() < Duration::from_secs(90) => {
                eprintln!(
                    "ml-rayjob: apply {name} failed (CRD/operator not ready?): {e}; retry {:?}",
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

struct RayJobTerminal {
    status: String,
    deploy: String,
    message: String,
    elapsed: Duration,
    timed_out: bool,
}

fn rayjob_fail_text(name: &str, err: &RayJobTerminal) -> String {
    if err.timed_out {
        format!(
            "{name}: RayJob never SUCCEEDED after {:?} \
             (jobStatus={:?} deploy={} message={})",
            err.elapsed, err.status, err.deploy, err.message
        )
    } else {
        format!(
            "{name}: RayJob {} after {:?} (deploy={} message={})",
            err.status, err.elapsed, err.deploy, err.message
        )
    }
}

/// GCS dropped the worker on late raylet heartbeats while the k8s
/// nodes stayed Ready (CHALLENGES #281). A real job failure does not
/// carry this text, so it still fails on the first sighting.
fn rayjob_heartbeat_flake(message: &str) -> bool {
    message.contains("missing too many heartbeats")
        || (message.contains("actor died unexpectedly") && message.contains("The actor never ran"))
}

fn poll_rayjob(kubeconfig: &Path, name: &str, ceiling: Duration) -> Result<(), RayJobTerminal> {
    let start = Instant::now();
    loop {
        let status = kubectl(
            kubeconfig,
            &["get", "rayjob", name, "-o", "jsonpath={.status.jobStatus}"],
        )
        .unwrap_or_default();
        let deploy = kubectl(
            kubeconfig,
            &[
                "get",
                "rayjob",
                name,
                "-o",
                "jsonpath={.status.jobDeploymentStatus}",
            ],
        )
        .unwrap_or_default();
        let message = kubectl(
            kubeconfig,
            &["get", "rayjob", name, "-o", "jsonpath={.status.message}"],
        )
        .unwrap_or_default();
        let status = status.trim().to_string();
        let deploy = deploy.trim().to_string();
        let message = message.trim().to_string();
        if status == "SUCCEEDED" {
            eprintln!(
                "ml-rayjob: {name} SUCCEEDED after {:?} (deploy={deploy})",
                start.elapsed()
            );
            return Ok(());
        }
        if status == "FAILED" || status == "STOPPED" {
            return Err(RayJobTerminal {
                status,
                deploy,
                message,
                elapsed: start.elapsed(),
                timed_out: false,
            });
        }
        if start.elapsed() > ceiling {
            return Err(RayJobTerminal {
                status,
                deploy,
                message,
                elapsed: start.elapsed(),
                timed_out: true,
            });
        }
        eprintln!(
            "ml-rayjob: {name} jobStatus={status:?} deploy={deploy} ({:?})",
            start.elapsed()
        );
        std::thread::sleep(Duration::from_secs(5));
    }
}

/// Head and worker Ray logs, including the exited container. The
/// heartbeat flake's `ExitCode: 1` was only visible in the KubeRay
/// operator log; raylet's own stderr was not in `gpu_diagnostics`.
fn ray_container_logs(kubeconfig: &Path) -> String {
    let mut out = String::new();
    for (title, extra) in [
        (
            "ray pods",
            vec!["get", "pods", "-l", "ray.io/node-type", "-o", "wide"],
        ),
        (
            "ray logs",
            vec![
                "logs",
                "-l",
                "ray.io/node-type",
                "--all-containers",
                "--prefix",
                "--tail=80",
            ],
        ),
        (
            "ray logs previous",
            vec![
                "logs",
                "-l",
                "ray.io/node-type",
                "--previous",
                "--all-containers",
                "--prefix",
                "--tail=80",
            ],
        ),
    ] {
        out.push_str(&format!("--- {title} ---\n"));
        match kubectl(kubeconfig, &extra) {
            Ok(text) => out.push_str(&text),
            Err(e) => out.push_str(&e),
        }
        if !out.ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

fn fail_rayjob(kubeconfig: &Path, name: &str, err: &RayJobTerminal) -> ! {
    panic!(
        "{}\n{}\n{}",
        rayjob_fail_text(name, err),
        ray_container_logs(kubeconfig),
        gpu_diagnostics(kubeconfig)
    );
}

fn wait_rayjob_succeeded(kubeconfig: &Path, name: &str, ceiling: Duration) {
    if let Err(err) = poll_rayjob(kubeconfig, name, ceiling) {
        fail_rayjob(kubeconfig, name, &err);
    }
}

/// Apply `yaml`, and on the heartbeat flake delete and apply once more.
fn apply_and_wait_rayjob(kubeconfig: &Path, name: &str, yaml: &str, ceiling: Duration) {
    apply_yaml(kubeconfig, name, yaml);
    let Err(err) = poll_rayjob(kubeconfig, name, ceiling) else {
        return;
    };
    if err.timed_out || !rayjob_heartbeat_flake(&err.message) {
        fail_rayjob(kubeconfig, name, &err);
    }
    eprintln!(
        "ml-rayjob: {name} heartbeat flake after {:?}; deleting and reapplying once\n{}\n{}",
        err.elapsed,
        err.message,
        ray_container_logs(kubeconfig)
    );
    delete_rayjob(kubeconfig, name);
    apply_yaml(kubeconfig, name, yaml);
    wait_rayjob_succeeded(kubeconfig, name, ceiling);
}

fn rayjob_cluster_name(kubeconfig: &Path, name: &str) -> String {
    let cluster = kubectl(
        kubeconfig,
        &[
            "get",
            "rayjob",
            name,
            "-o",
            "jsonpath={.status.rayClusterName}",
        ],
    )
    .unwrap_or_default();
    let cluster = cluster.trim();
    assert!(
        !cluster.is_empty(),
        "{name}: RayJob has no status.rayClusterName\n{}",
        gpu_diagnostics(kubeconfig)
    );
    cluster.to_string()
}

fn head_pod_name(kubeconfig: &Path, cluster: &str) -> String {
    let selector = format!("ray.io/cluster={cluster},ray.io/node-type=head");
    let name = kubectl(
        kubeconfig,
        &[
            "get",
            "pods",
            "-l",
            &selector,
            "-o",
            "jsonpath={.items[0].metadata.name}",
        ],
    )
    .unwrap_or_default();
    let name = name.trim();
    assert!(
        !name.is_empty(),
        "no Running head pod for cluster {cluster}\n{}",
        gpu_diagnostics(kubeconfig)
    );
    name.to_string()
}

fn exec_head(kubeconfig: &Path, pod: &str, argv: &[&str]) -> Result<String, String> {
    let mut args = vec!["exec", pod, "-c", "ray-head", "--"];
    args.extend_from_slice(argv);
    kubectl(kubeconfig, &args)
}

/// `ray status` GPU line plus `ray.cluster_resources()['GPU']`.
fn record_ray_gpus(kubeconfig: &Path, job: &str) -> (String, f64) {
    let cluster = rayjob_cluster_name(kubeconfig, job);
    let pod = head_pod_name(kubeconfig, &cluster);
    let status = exec_head(kubeconfig, &pod, &["ray", "status"]).unwrap_or_else(|e| {
        panic!(
            "{job}: `ray status` on {pod} failed: {e}\n{}",
            gpu_diagnostics(kubeconfig)
        )
    });
    let gpu_line = status
        .lines()
        .find(|l| l.contains("GPU"))
        .map(|l| l.trim().to_string())
        .unwrap_or_else(|| "(no GPU line in `ray status`)".to_string());
    let resources = exec_head(
        kubeconfig,
        &pod,
        &[
            "python",
            "-c",
            "import ray; ray.init(address='auto'); print(ray.cluster_resources().get('GPU', 0))",
        ],
    )
    .unwrap_or_else(|e| {
        panic!(
            "{job}: cluster_resources on {pod} failed: {e}\n{}",
            gpu_diagnostics(kubeconfig)
        )
    });
    let gpus: f64 = resources
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("{job}: GPU count not a number: {resources:?}"));
    eprintln!(
        "ml-rayjob: {job} ray status GPU line: {gpu_line:?}; \
         cluster_resources GPU={gpus} (cluster={cluster} pod={pod})"
    );
    eprintln!("ml-rayjob: {job} full `ray status`:\n{status}");
    (gpu_line, gpus)
}

fn worker_start_cmdline(kubeconfig: &Path, cluster: &str) -> String {
    let selector = format!("ray.io/cluster={cluster},ray.io/node-type=worker");
    let command = kubectl(
        kubeconfig,
        &[
            "get",
            "pods",
            "-l",
            &selector,
            "-o",
            "jsonpath={.items[0].spec.containers[0].command}",
        ],
    )
    .unwrap_or_default();
    let args = kubectl(
        kubeconfig,
        &[
            "get",
            "pods",
            "-l",
            &selector,
            "-o",
            "jsonpath={.items[0].spec.containers[0].args}",
        ],
    )
    .unwrap_or_default();
    format!("{} {}", command.trim(), args.trim())
}

fn delete_rayjob(kubeconfig: &Path, name: &str) {
    let _ = kubectl(
        kubeconfig,
        &["delete", "rayjob", name, "--wait=true", "--timeout=180s"],
    );
}

/// 3-node Ubuntu k3s (Flannel) + GPU fixture + KubeRay + real CPU Ray.
#[test]
fn test_ubuntu_ml_rayjob_gpu_succeeded() {
    let _ = env_logger::builder().is_test(true).try_init();

    let pinned = std::fs::read_to_string(fixture("kuberay/PINNED")).expect("PINNED");
    assert!(
        pinned.contains(RAY_IMAGE),
        "kuberay/PINNED must record the digest-pinned CPU Ray image"
    );

    let (size, compact) = choose_ray_node();
    let yaml = rayjob_yaml(compact);

    let mut cluster = bring_up_cluster_sized(UbuntuCni::Flannel, "ubray", None, size);
    let gpu0 = apply_gpu_dcgm_fixture(&mut cluster);
    let kube = cluster.kubeconfig.clone();
    assert_eq!(gpu0.capacity.len(), 3);

    install_kuberay(&kube);
    apply_and_wait_rayjob(&kube, RAYJOB, &yaml, RAYJOB_READY);
    let used = wait_gpu_used(&kube, 1, Duration::from_secs(60), "source RayJob");
    let used_sum: u32 = used.values().sum();
    assert_eq!(
        used_sum, 1,
        "RayJob worker must consume exactly one {RESOURCE}, used={used:?}"
    );

    let (line_with, gpus_with) = record_ray_gpus(&kube, RAYJOB);
    let cluster_with = rayjob_cluster_name(&kube, RAYJOB);
    let cmd_with = worker_start_cmdline(&kube, &cluster_with);
    assert!(
        cmd_with.contains("num-gpus"),
        "explicit num-gpus worker must start with --num-gpus: {cmd_with}"
    );
    assert_eq!(
        gpus_with, 1.0,
        "with num-gpus=1, Ray reports 1 GPU (ray status {line_with:?}). \
         Resource count only — not NVML / CUDA / placement-group hardware."
    );

    delete_rayjob(&kube, RAYJOB);
    let _ = wait_gpu_used(&kube, 0, FIXTURE_READY, "after delete RayJob");

    let yaml_no_gpus = rayjob_without_num_gpus(&yaml);
    apply_and_wait_rayjob(
        &kube,
        RAYJOB_NO_NUM_GPUS,
        &yaml_no_gpus,
        RAYJOB_READY_CACHED,
    );
    let (line_without, gpus_without) = record_ray_gpus(&kube, RAYJOB_NO_NUM_GPUS);
    let cluster_without = rayjob_cluster_name(&kube, RAYJOB_NO_NUM_GPUS);
    let cmd_without = worker_start_cmdline(&kube, &cluster_without);
    assert!(
        cmd_without.contains("num-gpus"),
        "KubeRay injects --num-gpus from nvidia.com/gpu even when \
         rayStartParams omits it: {cmd_without}"
    );
    assert_eq!(
        gpus_without, 1.0,
        "without rayStartParams.num-gpus Ray still reports 1 GPU \
         (ray status {line_without:?}) because KubeRay copies the \
         worker nvidia.com/gpu request into --num-gpus. No NVML."
    );

    eprintln!(
        "MEASUREMENT ubuntu ml-rayjob `ray status` GPUs: \
         with num-gpus=1 → {gpus_with} ({line_with}); \
         without num-gpus → {gpus_without} ({line_without}); \
         worker cmdline still has --num-gpus (KubeRay inferred)"
    );
}
