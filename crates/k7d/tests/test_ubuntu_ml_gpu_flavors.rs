//! Configurable GPU identity on fake-GPU nodes, two Kueue flavors, and
//! one required topology block.
//!
//! The plugin labels each node (`nvidia.com/gpu.product`, `gpu.count`,
//! `gpu.present`, block, rack). Env defaults are the homogeneous pool;
//! ConfigMap `fake-gpu-identity` overrides per node. ResourceFlavors
//! `fake-h100` and `fake-l40s` route one Job each onto matching nodes.
//! A second Job asks Kueue for required topology level
//! `k7d.katakate.org/topology-block`; both pods land in `block-0`.
//!
//! Does not edit `kueue/queues.yaml` or `Allocate`. Mock only — not
//! CUDA, not a batch scheduler. Reuses `bring_up_cluster` (Flannel).

mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use common::ml_platform::{
    apply_fixture, build_fake_gpu_plugin, fixture, gpu_diagnostics, install_plugin_binary,
    wait_gpu_registered, wait_gpu_used, BUSYBOX, FIXTURE_READY, GPU_PER_NODE, RESOURCE,
};
use common::ubuntu_k3s::{apply_yaml, bring_up_cluster, kubectl};

const DEFAULT_PRODUCT: &str = "Fake-A100";
const DEFAULT_BLOCK: &str = "block-0";
const DEFAULT_RACK: &str = "rack-0";
const H100: &str = "NVIDIA-H100-80GB-HBM3";
const L40S: &str = "NVIDIA-L40S";
const PRODUCT_LABEL: &str = "nvidia.com/gpu.product";
const COUNT_LABEL: &str = "nvidia.com/gpu.count";
const PRESENT_LABEL: &str = "nvidia.com/gpu.present";
const BLOCK_LABEL: &str = "k7d.katakate.org/topology-block";
const RACK_LABEL: &str = "k7d.katakate.org/topology-rack";
const HOSTNAME_LABEL: &str = "kubernetes.io/hostname";

const H100_JOB: &str = "gpu-job-h100";
const L40S_JOB: &str = "gpu-job-l40s";
const TAS_JOB: &str = "gpu-job-tas-block";
const H100_QUEUE: &str = "h100-queue";
const L40S_QUEUE: &str = "l40s-queue";

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
const KUEUE_READY: Duration = Duration::from_secs(300);
const ANN_REQUIRED: &str = "kueue.x-k8s.io/podset-required-topology";
const ANN_UNCONSTRAINED: &str = "kueue.x-k8s.io/podset-unconstrained-topology";

struct NodeId {
    product: &'static str,
    block: &'static str,
    rack: &'static str,
}

struct Assignment {
    levels: Vec<String>,
    domains: Vec<(Vec<String>, u32)>,
}

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
        "Kueue {KUEUE_VERSION} manifests sha256 mismatch: got {got}, want {KUEUE_MANIFESTS_SHA256}"
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
            "topologies.kueue.x-k8s.io",
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
                "ml-gpu-flavors: Kueue {KUEUE_VERSION} Ready + webhook CA after {:?}",
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
                diag(kubeconfig)
            );
        }
        std::thread::sleep(Duration::from_secs(3));
    }
}

fn diag(kubeconfig: &Path) -> String {
    let logs = kubectl(
        kubeconfig,
        &[
            "logs",
            "-l",
            "app=fake-gpu-plugin",
            "--tail=40",
            "--prefix=true",
        ],
    )
    .unwrap_or_else(|e| e);
    let workloads = kubectl(
        kubeconfig,
        &["get", "workloads.kueue.x-k8s.io", "-o", "yaml"],
    )
    .unwrap_or_else(|e| e);
    let nodes = kubectl(kubeconfig, &["get", "nodes", "--show-labels"]).unwrap_or_else(|e| e);
    format!(
        "{}\n--- plugin logs ---\n{logs}\n--- workloads ---\n{workloads}\n--- nodes ---\n{nodes}",
        gpu_diagnostics(kubeconfig)
    )
}

fn nodes_json(kubeconfig: &Path) -> serde_json::Value {
    let body = kubectl(kubeconfig, &["get", "nodes", "-o", "json"])
        .unwrap_or_else(|e| panic!("get nodes: {e}\n{}", diag(kubeconfig)));
    serde_json::from_str(&body).unwrap_or_else(|e| panic!("nodes json: {e}: {body}"))
}

fn label_of(nodes: &serde_json::Value, name: &str, key: &str) -> String {
    let empty = Vec::new();
    for n in nodes["items"].as_array().unwrap_or(&empty) {
        if n["metadata"]["name"].as_str() == Some(name) {
            return n["metadata"]["labels"][key]
                .as_str()
                .unwrap_or("")
                .to_string();
        }
    }
    String::new()
}

fn rollout_plugin(kubeconfig: &Path) {
    kubectl(
        kubeconfig,
        &["rollout", "status", "ds/fake-gpu-plugin", "--timeout=180s"],
    )
    .unwrap_or_else(|e| panic!("fake-gpu-plugin rollout: {e}\n{}", diag(kubeconfig)));
}

fn wait_identity(kubeconfig: &Path, names: &[String], expect: &[NodeId], ceiling: Duration) {
    assert_eq!(names.len(), expect.len());
    let start = Instant::now();
    loop {
        let nodes = nodes_json(kubeconfig);
        let ok = names.iter().zip(expect).all(|(name, id)| {
            label_of(&nodes, name, PRODUCT_LABEL) == id.product
                && label_of(&nodes, name, BLOCK_LABEL) == id.block
                && label_of(&nodes, name, RACK_LABEL) == id.rack
                && label_of(&nodes, name, COUNT_LABEL) == GPU_PER_NODE.to_string()
                && label_of(&nodes, name, PRESENT_LABEL) == "true"
                && !label_of(&nodes, name, HOSTNAME_LABEL).is_empty()
        });
        if ok {
            eprintln!(
                "ml-gpu-flavors: node identity matched after {:?}",
                start.elapsed()
            );
            return;
        }
        if start.elapsed() > ceiling {
            let mut got = String::new();
            for name in names {
                got.push_str(&format!(
                    "{name} product={} block={} rack={} count={} present={}\n",
                    label_of(&nodes, name, PRODUCT_LABEL),
                    label_of(&nodes, name, BLOCK_LABEL),
                    label_of(&nodes, name, RACK_LABEL),
                    label_of(&nodes, name, COUNT_LABEL),
                    label_of(&nodes, name, PRESENT_LABEL),
                ));
            }
            panic!(
                "node identity never matched after {ceiling:?}\n{got}\n{}",
                diag(kubeconfig)
            );
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn identity_configmap(names: &[String; 3]) -> String {
    let (a, b, c) = (&names[0], &names[1], &names[2]);
    format!(
        r#"apiVersion: v1
kind: ConfigMap
metadata:
  name: fake-gpu-identity
  namespace: default
data:
  {a}: "product={H100},block=block-0,rack=rack-0"
  {b}: "product={H100},block=block-0,rack=rack-1"
  {c}: "product={L40S},block=block-1,rack=rack-0"
"#
    )
}

fn apply_generated(kubeconfig: &Path, tag: &str, yaml: &str) {
    let path = PathBuf::from(format!("/tmp/k7d-{tag}-{}.yaml", std::process::id()));
    std::fs::write(&path, yaml).unwrap_or_else(|e| panic!("write {tag}: {e}"));
    apply_with_retry(kubeconfig, tag, &path);
    let _ = std::fs::remove_file(&path);
}

fn apply_with_retry(kubeconfig: &Path, tag: &str, path: &Path) {
    let start = Instant::now();
    loop {
        match kubectl(kubeconfig, &["apply", "-f", &path.to_string_lossy()]) {
            Ok(_) => {
                eprintln!("ml-gpu-flavors: applied {tag} after {:?}", start.elapsed());
                return;
            }
            Err(e) if start.elapsed() < Duration::from_secs(90) => {
                eprintln!("ml-gpu-flavors: apply {tag} failed ({e}); retry");
                std::thread::sleep(Duration::from_secs(3));
            }
            Err(e) => panic!("apply {tag} failed for 90s: {e}\n{}", diag(kubeconfig)),
        }
    }
}

fn gpu_job(
    name: &str,
    queue: &str,
    parallelism: u32,
    gpus: u32,
    ann: &str,
    ann_val: &str,
) -> String {
    format!(
        r#"apiVersion: batch/v1
kind: Job
metadata:
  name: {name}
  namespace: default
  labels:
    kueue.x-k8s.io/queue-name: {queue}
spec:
  backoffLimit: 0
  parallelism: {parallelism}
  completions: {parallelism}
  template:
    metadata:
      annotations:
        {ann}: "{ann_val}"
    spec:
      restartPolicy: Never
      tolerations:
      - key: node-role.kubernetes.io/control-plane
        operator: Exists
      - key: node-role.kubernetes.io/master
        operator: Exists
      containers:
      - name: sleep
        image: {BUSYBOX}
        imagePullPolicy: IfNotPresent
        command: ["sleep", "86400"]
        resources:
          limits:
            {RESOURCE}: "{gpus}"
          requests:
            cpu: "100m"
            memory: 64Mi
            {RESOURCE}: "{gpus}"
"#
    )
}

fn job_pods(kubeconfig: &Path, job: &str) -> serde_json::Value {
    let sel = format!("job-name={job}");
    let body = kubectl(kubeconfig, &["get", "pods", "-l", &sel, "-o", "json"])
        .unwrap_or_else(|_| "{}".into());
    serde_json::from_str(&body).unwrap_or(serde_json::json!({}))
}

fn workloads_json(kubeconfig: &Path) -> serde_json::Value {
    let body = kubectl(
        kubeconfig,
        &["get", "workloads.kueue.x-k8s.io", "-o", "json"],
    )
    .unwrap_or_else(|_| "{}".into());
    serde_json::from_str(&body).unwrap_or(serde_json::json!({}))
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

enum PodWait {
    Pending(String),
    Failed(String),
    Ready(Vec<String>),
}

fn pod_wait(pods: &serde_json::Value, want: usize) -> PodWait {
    let empty = Vec::new();
    let items = pods["items"].as_array().unwrap_or(&empty);
    if items.len() != want {
        return PodWait::Pending(format!("{} pods, want {want}", items.len()));
    }
    let mut nodes = Vec::new();
    for p in items {
        let phase = p["status"]["phase"].as_str().unwrap_or("");
        let pod = p["metadata"]["name"].as_str().unwrap_or("");
        if phase == "Failed" || phase == "Succeeded" {
            return PodWait::Failed(format!("{pod} phase {phase}"));
        }
        if phase != "Running" {
            return PodWait::Pending(format!("{pod} phase {phase}"));
        }
        let node = p["spec"]["nodeName"].as_str().unwrap_or("");
        if node.is_empty() {
            return PodWait::Pending(format!("{pod} Running without nodeName"));
        }
        nodes.push(node.to_string());
    }
    nodes.sort();
    PodWait::Ready(nodes)
}

fn wait_job_nodes(kubeconfig: &Path, job: &str, want: usize, ceiling: Duration) -> Vec<String> {
    let start = Instant::now();
    loop {
        match pod_wait(&job_pods(kubeconfig, job), want) {
            PodWait::Ready(nodes) => {
                eprintln!(
                    "ml-gpu-flavors: {job} {want} Running on {nodes:?} after {:?}",
                    start.elapsed()
                );
                return nodes;
            }
            PodWait::Failed(msg) => {
                panic!("{job} failed: {msg}\n{}", diag(kubeconfig));
            }
            PodWait::Pending(msg) => {
                if start.elapsed() > ceiling {
                    let wl = workloads_json(kubeconfig);
                    let why = workload_for(&wl, job)
                        .map(|w| w.to_string())
                        .unwrap_or_else(|| "no workload".into());
                    panic!(
                        "{job} never Running ({want} pods) after {ceiling:?}: {msg}\n{why}\n{}",
                        diag(kubeconfig)
                    );
                }
                eprintln!("ml-gpu-flavors: {job} waiting: {msg}");
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    }
}

fn wait_job_gone(kubeconfig: &Path, job: &str, ceiling: Duration) {
    let start = Instant::now();
    loop {
        let pods = job_pods(kubeconfig, job);
        let n = pods["items"].as_array().map(|a| a.len()).unwrap_or(0);
        let workloads = workloads_json(kubeconfig);
        let wl = workload_for(&workloads, job);
        if n == 0 && wl.is_none() {
            eprintln!("ml-gpu-flavors: {job} gone after {:?}", start.elapsed());
            return;
        }
        if start.elapsed() > ceiling {
            panic!(
                "{job} still present after {ceiling:?} (pods={n})\n{}",
                diag(kubeconfig)
            );
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn json_u32(v: &serde_json::Value) -> Result<u32, String> {
    if let Some(n) = v.as_u64() {
        return u32::try_from(n).map_err(|e| e.to_string());
    }
    if let Some(s) = v.as_str() {
        return s
            .parse()
            .map_err(|e: std::num::ParseIntError| e.to_string());
    }
    Err(format!("not a count: {v}"))
}

fn values_at_level(level: &serde_json::Value, n: usize) -> Result<Vec<String>, String> {
    if let Some(u) = level.get("universal").filter(|v| !v.is_null()) {
        let s = u
            .as_str()
            .ok_or_else(|| format!("universal value not a string: {u}"))?;
        return Ok(vec![s.to_string(); n]);
    }
    let ind = level
        .get("individual")
        .ok_or_else(|| format!("level missing universal and individual: {level}"))?;
    let prefix = ind["prefix"].as_str().unwrap_or("");
    let suffix = ind["suffix"].as_str().unwrap_or("");
    let roots = ind["roots"]
        .as_array()
        .ok_or_else(|| format!("roots missing: {ind}"))?;
    if roots.len() != n {
        return Err(format!("roots {} != domainCount {n}", roots.len()));
    }
    let mut out = Vec::with_capacity(n);
    for r in roots {
        let root = r
            .as_str()
            .ok_or_else(|| format!("root not a string: {r}"))?;
        out.push(format!("{prefix}{root}{suffix}"));
    }
    Ok(out)
}

fn pod_count_at(slice: &serde_json::Value, i: usize) -> Result<u32, String> {
    let pc = &slice["podCounts"];
    if let Some(u) = pc.get("universal").filter(|v| !v.is_null()) {
        return json_u32(u);
    }
    let arr = pc
        .get("individual")
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("podCounts missing: {pc}"))?;
    let v = arr
        .get(i)
        .ok_or_else(|| format!("podCounts shorter than domain {i}"))?;
    json_u32(v)
}

fn decode_topology_assignment(ta: &serde_json::Value) -> Result<Assignment, String> {
    if !ta.is_object() {
        return Err(format!("missing topologyAssignment: {ta}"));
    }
    let levels: Vec<String> = ta["levels"]
        .as_array()
        .ok_or_else(|| format!("levels missing: {ta}"))?
        .iter()
        .map(|v| v.as_str().unwrap_or("").to_string())
        .collect();
    if levels.is_empty() || levels.iter().any(|l| l.is_empty()) {
        return Err(format!("empty topology level: {ta}"));
    }
    if ta.get("slices").is_none() {
        if let Some(domains) = ta.get("domains").and_then(|d| d.as_array()) {
            return decode_legacy_domains(&levels, domains);
        }
    }
    let slices = ta["slices"]
        .as_array()
        .ok_or_else(|| format!("no slices in {ta}"))?;
    let mut domains = Vec::new();
    for slice in slices {
        let n = usize::try_from(
            slice["domainCount"]
                .as_u64()
                .ok_or_else(|| format!("domainCount missing: {slice}"))?,
        )
        .map_err(|e| e.to_string())?;
        let per_level = slice["valuesPerLevel"]
            .as_array()
            .ok_or_else(|| format!("valuesPerLevel missing: {slice}"))?;
        if per_level.len() != levels.len() {
            return Err(format!(
                "valuesPerLevel {} != levels {}",
                per_level.len(),
                levels.len()
            ));
        }
        let mut columns = Vec::with_capacity(per_level.len());
        for level in per_level {
            columns.push(values_at_level(level, n)?);
        }
        for i in 0..n {
            let count = pod_count_at(slice, i)?;
            let values = columns.iter().map(|col| col[i].clone()).collect();
            domains.push((values, count));
        }
    }
    if domains.is_empty() {
        return Err(format!("topologyAssignment has no domains: {ta}"));
    }
    Ok(Assignment { levels, domains })
}

fn decode_legacy_domains(
    levels: &[String],
    domains: &[serde_json::Value],
) -> Result<Assignment, String> {
    let mut out = Vec::new();
    for d in domains {
        let values: Vec<String> = d["values"]
            .as_array()
            .ok_or_else(|| format!("legacy domain values missing: {d}"))?
            .iter()
            .map(|v| v.as_str().unwrap_or("").to_string())
            .collect();
        if values.len() != levels.len() {
            return Err(format!("legacy domain width {} != levels", values.len()));
        }
        let count = json_u32(&d["count"])?;
        out.push((values, count));
    }
    if out.is_empty() {
        return Err("legacy topologyAssignment has no domains".into());
    }
    Ok(Assignment {
        levels: levels.to_vec(),
        domains: out,
    })
}

fn assigned_values(a: &Assignment, level: &str) -> Option<Vec<String>> {
    let idx = a.levels.iter().position(|l| l == level)?;
    let mut vals = Vec::new();
    for (values, count) in &a.domains {
        if *count == 0 {
            continue;
        }
        let v = values.get(idx)?.clone();
        for _ in 0..*count {
            vals.push(v.clone());
        }
    }
    vals.sort();
    Some(vals)
}

fn assert_one_block(
    kubeconfig: &Path,
    names: &[String; 3],
    pod_nodes: &[String],
    workload: &serde_json::Value,
) {
    let want: BTreeSet<&str> = [&names[0], &names[1]]
        .into_iter()
        .map(String::as_str)
        .collect();
    let got: BTreeSet<&str> = pod_nodes.iter().map(String::as_str).collect();
    assert_eq!(
        got, want,
        "TAS pods {pod_nodes:?} want the two {H100} nodes in {DEFAULT_BLOCK} ({:?}), not {}",
        names, names[2]
    );
    let nodes = nodes_json(kubeconfig);
    for n in pod_nodes {
        assert_eq!(
            label_of(&nodes, n, BLOCK_LABEL),
            DEFAULT_BLOCK,
            "{n} block label"
        );
        assert_eq!(label_of(&nodes, n, PRODUCT_LABEL), H100, "{n} product");
    }
    let ta = &workload["status"]["admission"]["podSetAssignments"][0]["topologyAssignment"];
    let assignment = decode_topology_assignment(ta)
        .unwrap_or_else(|e| panic!("TAS assignment: {e}\n{workload}\n{}", diag(kubeconfig)));
    if let Some(blocks) = assigned_values(&assignment, BLOCK_LABEL) {
        assert!(
            blocks.iter().all(|b| b == DEFAULT_BLOCK),
            "assignment blocks {blocks:?} want {DEFAULT_BLOCK}"
        );
    }
    if let Some(hosts) = assigned_values(&assignment, HOSTNAME_LABEL) {
        assert_eq!(
            hosts,
            pod_nodes.to_vec(),
            "assignment hostnames {hosts:?} != pod nodes {pod_nodes:?}"
        );
    } else if assigned_values(&assignment, BLOCK_LABEL).is_none() {
        panic!(
            "topologyAssignment has neither {BLOCK_LABEL} nor {HOSTNAME_LABEL}: {ta}\n{}",
            diag(kubeconfig)
        );
    }
    eprintln!(
        "ml-gpu-flavors: TAS required {BLOCK_LABEL} landed in {DEFAULT_BLOCK} on {pod_nodes:?}"
    );
}

#[test]
fn test_decode_topology_assignment_slices() {
    let hostname = serde_json::json!({
        "levels": [HOSTNAME_LABEL],
        "slices": [{
            "domainCount": 2,
            "podCounts": {"individual": [1, 1]},
            "valuesPerLevel": [{
                "individual": {"prefix": "k7d-", "roots": ["a", "b"]}
            }]
        }]
    });
    let a = decode_topology_assignment(&hostname).expect("hostname slice");
    assert_eq!(
        assigned_values(&a, HOSTNAME_LABEL).as_deref(),
        Some(["k7d-a".to_string(), "k7d-b".to_string()].as_slice())
    );

    let block = serde_json::json!({
        "levels": [BLOCK_LABEL, RACK_LABEL],
        "slices": [{
            "domainCount": 2,
            "podCounts": {"universal": 1},
            "valuesPerLevel": [
                {"universal": DEFAULT_BLOCK},
                {"individual": {"prefix": "rack-", "roots": ["0", "1"]}}
            ]
        }]
    });
    let b = decode_topology_assignment(&block).expect("block slice");
    let blocks = assigned_values(&b, BLOCK_LABEL).expect("block level");
    assert!(blocks.iter().all(|v| v == DEFAULT_BLOCK), "{blocks:?}");
    assert_eq!(
        assigned_values(&b, RACK_LABEL).as_deref(),
        Some(["rack-0".to_string(), "rack-1".to_string()].as_slice())
    );
}

/// Homogeneous env labels, then per-node ConfigMap. Two flavors route
/// Jobs; a required-block TAS Job stays inside `block-0`.
#[test]
fn test_ubuntu_ml_gpu_flavors() {
    let _ = env_logger::builder().is_test(true).try_init();

    let ds = std::fs::read_to_string(fixture("device-plugin-ds.yaml")).expect("ds yaml");
    assert!(
        ds.contains("FAKE_GPU_COUNT") && ds.contains("value: \"2\""),
        "device-plugin DaemonSet must default FAKE_GPU_COUNT to \"2\"\n{ds}"
    );
    assert!(
        ds.contains("FAKE_GPU_PRODUCT") && ds.contains(&format!("value: \"{DEFAULT_PRODUCT}\"")),
        "device-plugin DaemonSet must default FAKE_GPU_PRODUCT to {DEFAULT_PRODUCT}"
    );
    assert!(
        ds.contains("FAKE_GPU_TOPOLOGY_BLOCK")
            && ds.contains(&format!("value: \"{DEFAULT_BLOCK}\"")),
        "device-plugin DaemonSet must default the topology block"
    );
    assert!(
        ds.contains("FAKE_GPU_TOPOLOGY_RACK") && ds.contains(&format!("value: \"{DEFAULT_RACK}\"")),
        "device-plugin DaemonSet must default the topology rack"
    );
    assert_eq!(GPU_PER_NODE, 2, "default GPU_PER_NODE must stay 2");
    let queues = std::fs::read_to_string(fixture("kueue/queues.yaml")).expect("queues yaml");
    assert!(
        queues.contains("name: default-flavor") && !queues.contains("fake-h100"),
        "kueue/queues.yaml must stay the default-flavor queue"
    );
    let flavors = std::fs::read_to_string(fixture("kueue/gpu-flavors.yaml")).expect("flavors");
    assert!(flavors.contains("name: fake-h100") && flavors.contains("name: fake-l40s"));
    assert!(flavors.contains(BLOCK_LABEL) && flavors.contains(HOSTNAME_LABEL));
    assert!(flavors.contains("topologyName: fake-gpu"));

    let mut cluster = bring_up_cluster();
    let plugin = build_fake_gpu_plugin();
    install_plugin_binary(&mut cluster, &plugin);
    let kube = cluster.kubeconfig.clone();
    let names = cluster.names();
    apply_fixture(&kube, "device-plugin-ds.yaml");
    rollout_plugin(&kube);
    let homogeneous = [
        NodeId {
            product: DEFAULT_PRODUCT,
            block: DEFAULT_BLOCK,
            rack: DEFAULT_RACK,
        },
        NodeId {
            product: DEFAULT_PRODUCT,
            block: DEFAULT_BLOCK,
            rack: DEFAULT_RACK,
        },
        NodeId {
            product: DEFAULT_PRODUCT,
            block: DEFAULT_BLOCK,
            rack: DEFAULT_RACK,
        },
    ];
    wait_identity(&kube, &names, &homogeneous, FIXTURE_READY);
    let gpu = wait_gpu_registered(&kube, &names, FIXTURE_READY);
    assert_eq!(gpu.capacity.len(), 3);

    apply_yaml(&kube, "fake-gpu-identity", &identity_configmap(&names));
    kubectl(&kube, &["rollout", "restart", "ds/fake-gpu-plugin"])
        .unwrap_or_else(|e| panic!("restart fake-gpu-plugin: {e}\n{}", diag(&kube)));
    rollout_plugin(&kube);
    let mixed = [
        NodeId {
            product: H100,
            block: "block-0",
            rack: "rack-0",
        },
        NodeId {
            product: H100,
            block: "block-0",
            rack: "rack-1",
        },
        NodeId {
            product: L40S,
            block: "block-1",
            rack: "rack-0",
        },
    ];
    wait_identity(&kube, &names, &mixed, FIXTURE_READY);
    wait_gpu_registered(&kube, &names, FIXTURE_READY);

    install_kueue(&kube);
    apply_with_retry(&kube, "gpu-flavors", &fixture("kueue/gpu-flavors.yaml"));

    apply_generated(
        &kube,
        H100_JOB,
        &gpu_job(H100_JOB, H100_QUEUE, 1, 1, ANN_UNCONSTRAINED, "true"),
    );
    apply_generated(
        &kube,
        L40S_JOB,
        &gpu_job(L40S_JOB, L40S_QUEUE, 1, 1, ANN_UNCONSTRAINED, "true"),
    );
    let h100_nodes = wait_job_nodes(&kube, H100_JOB, 1, FIXTURE_READY);
    let l40s_nodes = wait_job_nodes(&kube, L40S_JOB, 1, FIXTURE_READY);
    let nodes = nodes_json(&kube);
    assert!(
        h100_nodes == [names[0].clone()] || h100_nodes == [names[1].clone()],
        "{H100_JOB} landed on {h100_nodes:?}, want an {H100} node"
    );
    assert_eq!(
        label_of(&nodes, &h100_nodes[0], PRODUCT_LABEL),
        H100,
        "{H100_JOB} node product"
    );
    assert_eq!(
        l40s_nodes,
        vec![names[2].clone()],
        "{L40S_JOB} want {}",
        names[2]
    );
    assert_eq!(
        label_of(&nodes, &l40s_nodes[0], PRODUCT_LABEL),
        L40S,
        "{L40S_JOB} node product"
    );
    eprintln!(
        "ml-gpu-flavors: {H100_JOB} -> {} ({H100}), {L40S_JOB} -> {} ({L40S})",
        h100_nodes[0], l40s_nodes[0]
    );

    kubectl(
        &kube,
        &[
            "delete",
            "job",
            H100_JOB,
            L40S_JOB,
            "--wait=true",
            "--ignore-not-found=true",
        ],
    )
    .unwrap_or_else(|e| panic!("delete flavor jobs: {e}\n{}", diag(&kube)));
    wait_job_gone(&kube, H100_JOB, FIXTURE_READY);
    wait_job_gone(&kube, L40S_JOB, FIXTURE_READY);
    wait_gpu_used(&kube, 0, FIXTURE_READY, "after flavor jobs");

    apply_generated(
        &kube,
        TAS_JOB,
        &gpu_job(TAS_JOB, H100_QUEUE, 2, 2, ANN_REQUIRED, BLOCK_LABEL),
    );
    let tas_nodes = wait_job_nodes(&kube, TAS_JOB, 2, FIXTURE_READY);
    let wl = workloads_json(&kube);
    let workload = workload_for(&wl, TAS_JOB)
        .unwrap_or_else(|| panic!("no workload for {TAS_JOB}\n{}", diag(&kube)))
        .clone();
    let admitted = workload["status"]["conditions"]
        .as_array()
        .and_then(|cs| cs.iter().find(|c| c["type"].as_str() == Some("Admitted")))
        .map(|c| c["status"].as_str() == Some("True"))
        .unwrap_or(false);
    assert!(admitted, "{TAS_JOB} workload not Admitted\n{workload}");
    assert_one_block(&kube, &names, &tas_nodes, &workload);
}
