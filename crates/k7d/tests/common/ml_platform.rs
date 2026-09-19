//! Shared GPU / DCGM fixture helpers.
//!
//! Applies the digest-pinned fake `nvidia.com/gpu` plugin and
//! dcgm-exporter-shaped scrape. Does not copy `bring_up_cluster`.
//! Mock only — not CUDA, not DeepSpeed, not GPU Operator.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use k7d::vm::Vm;

use super::ubuntu::{connect_or_dump, sh_ok, workspace_path};
use super::ubuntu_k3s::{kubectl, UbuntuCluster};

/// The ML fixture pins this k3s path. k3s v1.32.5+k3s1 keeps
/// kubelet.sock at the stock kubelet dir (CHALLENGES #146).
pub const K3S_DEVICE_PLUGIN_DIR: &str = "/var/lib/rancher/k3s/agent/kubelet/device-plugins";
pub const KUBELET_DEVICE_PLUGIN_DIR: &str = "/var/lib/kubelet/device-plugins";
pub const RESOURCE: &str = "nvidia.com/gpu";
pub const WRONG_RESOURCE: &str = "example.com/resource";
pub const GPU_PER_NODE: u32 = 2;

pub const BUSYBOX: &str = "docker.io/library/busybox:1.36.1@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";

pub const DCGM_NODEPORT: u16 = 30400;
const PLUGIN_GUEST_DIR: &str = "/opt/k7d-ml";
const PLUGIN_GUEST_BIN: &str = "/opt/k7d-ml/fake-gpu-plugin";

const GO_VERSION: &str = "1.23.6";
const GO_TARBALL: &str = "go1.23.6.linux-amd64.tar.gz";
const GO_SHA256: &str = "9379441ea310de000f33a4dc767bd966e72ab2826270e038e78b2c53c2e7802d";
const GO_URL: &str = "https://go.dev/dl/go1.23.6.linux-amd64.tar.gz";

pub const FIXTURE_READY: Duration = Duration::from_secs(180);
pub const MODEL_NAME: &str = "Fake-A100";

#[derive(Debug)]
pub struct GpuCounts {
    pub capacity: BTreeMap<String, u32>,
    pub allocatable: BTreeMap<String, u32>,
    pub leftover_example: Vec<String>,
}

pub fn fixture(name: &str) -> PathBuf {
    workspace_path(&format!("crates/k7d/tests/fixtures/ml-platform/{name}"))
}

pub fn apply_fixture(kubeconfig: &Path, name: &str) {
    let path = fixture(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
    assert!(
        !text.contains(":latest") && !text.contains("latest\n"),
        "{name} must not use the latest tag"
    );
    assert!(
        text.contains("@sha256:"),
        "{name} must pin images by digest"
    );
    kubectl(kubeconfig, &["apply", "-f", &path.to_string_lossy()])
        .unwrap_or_else(|e| panic!("apply {name}: {e}"));
}

fn go_at_least_1_23(version: &str) -> bool {
    let rest = version.trim().trim_start_matches("go");
    let mut parts = rest.split('.');
    let major: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    major > 1 || (major == 1 && minor >= 23)
}

fn install_pinned_go() -> PathBuf {
    let root = PathBuf::from(format!("/tmp/k7d-go-{GO_VERSION}"));
    let bin = root.join("go/bin/go");
    if bin.is_file() {
        return bin;
    }
    std::fs::create_dir_all(&root).expect("go root");
    let tar = root.join(GO_TARBALL);
    if !tar.is_file() {
        let status = Command::new("curl")
            .args(["-fsSL", "-o"])
            .arg(&tar)
            .arg(GO_URL)
            .status()
            .expect("spawn curl go tarball");
        assert!(status.success(), "download {GO_URL} failed");
    }
    let sum = Command::new("sha256sum")
        .arg(&tar)
        .output()
        .expect("sha256sum");
    assert!(sum.status.success(), "sha256sum failed");
    let got = String::from_utf8_lossy(&sum.stdout);
    let got = got.split_whitespace().next().unwrap_or("");
    assert_eq!(
        got, GO_SHA256,
        "go tarball sha256 mismatch: got {got}, want {GO_SHA256}"
    );
    let status = Command::new("tar")
        .args(["-C"])
        .arg(&root)
        .arg("-xzf")
        .arg(&tar)
        .status()
        .expect("tar xf go");
    assert!(status.success(), "tar xf {tar:?} failed");
    assert!(
        bin.is_file(),
        "pinned go missing after extract: {}",
        bin.display()
    );
    bin
}

fn go_bin() -> PathBuf {
    if let Ok(out) = Command::new("go").args(["env", "GOVERSION"]).output() {
        let v = String::from_utf8_lossy(&out.stdout);
        if out.status.success() && go_at_least_1_23(v.trim()) {
            return PathBuf::from("go");
        }
        eprintln!("host go is {} — installing pinned {GO_VERSION}", v.trim());
    }
    install_pinned_go()
}

pub fn build_fake_gpu_plugin() -> Vec<u8> {
    let src = fixture("fake-gpu-plugin");
    let out = PathBuf::from(format!("/tmp/k7d-fake-gpu-plugin-{}", std::process::id()));
    let go = go_bin();
    let status = Command::new(&go)
        // `-buildvcs=false`: the fixture is content-addressed by the
        // test, and default VCS stamping runs `git status` in the
        // workspace — which fails on a node where the rsynced tree and
        // its `.git` have different owners ("dubious ownership").
        .args([
            "build",
            "-mod=mod",
            "-trimpath",
            "-buildvcs=false",
            "-ldflags=-s -w",
            "-o",
        ])
        .arg(&out)
        .arg(".")
        .current_dir(&src)
        .env("CGO_ENABLED", "0")
        .env("GOOS", "linux")
        .env("GOARCH", "amd64")
        .status()
        .unwrap_or_else(|e| panic!("spawn go build: {e}"));
    assert!(
        status.success(),
        "go build fake-gpu-plugin failed (go={})",
        go.display()
    );
    let bytes = std::fs::read(&out).expect("read plugin binary");
    assert!(
        bytes.len() > 1024,
        "plugin binary is suspiciously small: {} B",
        bytes.len()
    );
    eprintln!(
        "ml-platform: built fake-gpu-plugin ({} B) with {}",
        bytes.len(),
        go.display()
    );
    bytes
}

pub fn install_plugin_binary(cluster: &mut UbuntuCluster, bytes: &[u8]) {
    // 15 MiB static Go binary: serve it on the cluster gateway rather
    // than base64-ing it through the agent JSON line.
    let dir = format!("/tmp/k7d-ml-plugin-{}", std::process::id());
    std::fs::create_dir_all(&dir).expect("plugin serve dir");
    std::fs::write(format!("{dir}/fake-gpu-plugin"), bytes).expect("write plugin for serve");
    let mut srv = Command::new("python3")
        .args([
            "-m",
            "http.server",
            "18765",
            "--bind",
            "0.0.0.0",
            "--directory",
            &dir,
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("python3 http.server on 10.200.0.1:18765");
    std::thread::sleep(Duration::from_millis(400));
    let url = "http://10.200.0.1:18765/fake-gpu-plugin";
    let vms: [(&mut Vm, &str); 3] = [
        (&mut cluster.server, "server"),
        (&mut cluster.agent1, "agent-1"),
        (&mut cluster.agent2, "agent-2"),
    ];
    for (vm, whose) in vms {
        let mut ag = connect_or_dump(vm, whose);
        sh_ok(
            &mut ag,
            &format!(
                "mkdir -p {PLUGIN_GUEST_DIR} && \
                 curl -fsSL --max-time 60 -o {PLUGIN_GUEST_BIN} {url} && \
                 chmod 755 {PLUGIN_GUEST_BIN} && \
                 test -x {PLUGIN_GUEST_BIN}"
            ),
        );
        let probe = sh_ok(&mut ag, &format!("wc -c < {PLUGIN_GUEST_BIN}"));
        eprintln!(
            "ml-platform: {whose} has {PLUGIN_GUEST_BIN} ({} B)",
            probe.trim()
        );
    }
    let _ = srv.kill();
    let _ = srv.wait();
}

fn parse_qty(v: &serde_json::Value) -> Option<u32> {
    v.as_str()
        .and_then(|s| s.parse().ok())
        .or_else(|| v.as_u64().map(|n| n as u32))
}

fn parse_node_gpu(body: &str) -> GpuCounts {
    let v: serde_json::Value =
        serde_json::from_str(body).unwrap_or_else(|e| panic!("nodes json: {e}: {body}"));
    let empty = Vec::new();
    let mut capacity = BTreeMap::new();
    let mut allocatable = BTreeMap::new();
    let mut leftover_example = Vec::new();
    for n in v["items"].as_array().unwrap_or(&empty) {
        let name = n["metadata"]["name"].as_str().unwrap_or("").to_string();
        if name.is_empty() {
            continue;
        }
        if parse_qty(&n["status"]["capacity"][WRONG_RESOURCE]).is_some() {
            leftover_example.push(name.clone());
        }
        if let Some(c) = parse_qty(&n["status"]["capacity"][RESOURCE]) {
            capacity.insert(name.clone(), c);
        }
        if let Some(a) = parse_qty(&n["status"]["allocatable"][RESOURCE]) {
            allocatable.insert(name, a);
        }
    }
    GpuCounts {
        capacity,
        allocatable,
        leftover_example,
    }
}

pub fn gpu_via_kubectl(kubeconfig: &Path) -> GpuCounts {
    let body = kubectl(kubeconfig, &["get", "nodes", "-o", "json"])
        .unwrap_or_else(|e| panic!("kubectl get nodes -o json: {e}"));
    parse_node_gpu(&body)
}

pub fn gpu_via_bridge(bridge: &str, certs: &Path) -> Result<GpuCounts, String> {
    let body = super::ubuntu_k3s::curl_get(bridge, certs, "/api/v1/nodes")?;
    Ok(parse_node_gpu(&body))
}

pub fn sum(map: &BTreeMap<String, u32>) -> u32 {
    map.values().copied().sum()
}

/// Device-plugin consumption is pod requests. On k3s v1.32.5
/// `status.allocatable[nvidia.com/gpu]` stays equal to Capacity (the
/// healthy device count); `kubectl describe node` "Allocated resources"
/// is the drop the spec means.
fn gpu_used_from_pods(body: &str) -> BTreeMap<String, u32> {
    let v: serde_json::Value =
        serde_json::from_str(body).unwrap_or_else(|e| panic!("pods json: {e}: {body}"));
    let empty = Vec::new();
    let mut used = BTreeMap::new();
    for p in v["items"].as_array().unwrap_or(&empty) {
        let node = p["spec"]["nodeName"].as_str().unwrap_or("");
        if node.is_empty() {
            continue;
        }
        let phase = p["status"]["phase"].as_str().unwrap_or("");
        if phase != "Running" {
            continue;
        }
        let mut n = 0u32;
        for c in p["spec"]["containers"].as_array().unwrap_or(&empty) {
            n += parse_qty(&c["resources"]["requests"][RESOURCE]).unwrap_or(0);
            if n == 0 {
                n += parse_qty(&c["resources"]["limits"][RESOURCE]).unwrap_or(0);
            }
        }
        if n > 0 {
            *used.entry(node.to_string()).or_insert(0) += n;
        }
    }
    used
}

pub fn gpu_used_via_kubectl(kubeconfig: &Path) -> BTreeMap<String, u32> {
    let body = kubectl(kubeconfig, &["get", "pods", "-A", "-o", "json"])
        .unwrap_or_else(|e| panic!("kubectl get pods -A: {e}"));
    gpu_used_from_pods(&body)
}

pub fn gpu_used_via_bridge(bridge: &str, certs: &Path) -> Result<BTreeMap<String, u32>, String> {
    let mut used = BTreeMap::new();
    for ns in [
        "default",
        "kube-system",
        "jobset-system",
        "kuberay-system",
        "kubeflow-system",
        "kueue-system",
    ] {
        let body = match super::ubuntu_k3s::curl_get(
            bridge,
            certs,
            &format!("/api/v1/namespaces/{ns}/pods"),
        ) {
            Ok(b) => b,
            Err(_)
                if ns == "jobset-system"
                    || ns == "kuberay-system"
                    || ns == "kubeflow-system"
                    || ns == "kueue-system" =>
            {
                continue
            }
            Err(e) => return Err(e),
        };
        for (k, v) in gpu_used_from_pods(&body) {
            *used.entry(k).or_insert(0) += v;
        }
    }
    Ok(used)
}

fn gpu_free(gpu: &GpuCounts, used: &BTreeMap<String, u32>) -> BTreeMap<String, u32> {
    let mut free = BTreeMap::new();
    for (n, cap) in &gpu.capacity {
        let u = used.get(n).copied().unwrap_or(0);
        free.insert(n.clone(), cap.saturating_sub(u));
    }
    free
}

pub fn gpu_diagnostics(kubeconfig: &Path) -> String {
    let mut out = String::new();
    for args in [
        vec!["get", "nodes", "-o", "wide"],
        vec!["describe", "nodes"],
        vec!["get", "ds,deploy,pods,svc", "-A", "-o", "wide"],
        vec!["get", "jobsets.jobset.x-k8s.io", "-A", "-o", "wide"],
        vec!["get", "rayclusters.ray.io", "-A", "-o", "wide"],
        vec!["get", "trainjobs.trainer.kubeflow.org", "-A", "-o", "wide"],
        vec![
            "get",
            "trainingruntimes.trainer.kubeflow.org,clustertrainingruntimes.trainer.kubeflow.org",
            "-A",
            "-o",
            "wide",
        ],
        vec![
            "get",
            "clusterqueues.kueue.x-k8s.io,localqueues.kueue.x-k8s.io,resourceflavors.kueue.x-k8s.io,workloads.kueue.x-k8s.io,jobs",
            "-A",
            "-o",
            "wide",
        ],
        vec!["get", "events", "-A", "--sort-by=.lastTimestamp"],
        vec![
            "logs",
            "-l",
            "app=fake-gpu-plugin",
            "--all-containers",
            "--prefix",
            "--tail=80",
        ],
        vec![
            "logs",
            "-l",
            "app=fake-gpu-plugin",
            "--previous",
            "--prefix",
            "--tail=40",
        ],
        vec!["logs", "-l", "app=dcgm-exporter", "--tail=40"],
        vec![
            "logs",
            "-n",
            "jobset-system",
            "-l",
            "control-plane=controller-manager",
            "--tail=80",
        ],
        vec![
            "logs",
            "-n",
            "kuberay-system",
            "-l",
            "app.kubernetes.io/name=kuberay-operator",
            "--tail=80",
        ],
        vec![
            "logs",
            "-n",
            "kubeflow-system",
            "-l",
            "app.kubernetes.io/component=manager",
            "--tail=80",
        ],
        vec![
            "logs",
            "-n",
            "kueue-system",
            "-l",
            "control-plane=controller-manager",
            "--tail=80",
        ],
    ] {
        let got = kubectl(kubeconfig, &args).unwrap_or_else(|e| e);
        out.push_str(&format!("--- kubectl {} ---\n{got}\n", args.join(" ")));
    }
    out
}

/// Wait until every named node has `nvidia.com/gpu` Capacity **and**
/// `status.allocatable` = 2. Allocatable here is the healthy device
/// count (CHALLENGES #147); it does **not** drop when a pod requests
/// a GPU.
pub fn wait_gpu_registered(kubeconfig: &Path, names: &[String], ceiling: Duration) -> GpuCounts {
    let start = Instant::now();
    loop {
        let gpu = gpu_via_kubectl(kubeconfig);
        if !gpu.leftover_example.is_empty() {
            panic!(
                "registered {WRONG_RESOURCE} on {} — refuse to silently rename; \
                 resource must be exactly {RESOURCE}\n{}",
                gpu.leftover_example.join(","),
                gpu_diagnostics(kubeconfig)
            );
        }
        let cap_ok = names
            .iter()
            .all(|n| gpu.capacity.get(n) == Some(&GPU_PER_NODE));
        let alloc_ok = names
            .iter()
            .all(|n| gpu.allocatable.get(n) == Some(&GPU_PER_NODE));
        if cap_ok && alloc_ok {
            eprintln!(
                "ml-platform: {RESOURCE} Capacity={GPU_PER_NODE}/node \
                 status.allocatable={GPU_PER_NODE}/node after {:?}",
                start.elapsed()
            );
            return gpu;
        }
        if start.elapsed() > ceiling {
            let cap_sum = sum(&gpu.capacity);
            let alloc_sum = sum(&gpu.allocatable);
            let diag = gpu_diagnostics(kubeconfig);
            if cap_sum > 0 && alloc_sum == 0 {
                panic!(
                    "{RESOURCE} Capacity sum={cap_sum} but status.allocatable stayed 0 \
                     after {ceiling:?}. kubelet.sock was not in the mounted \
                     device-plugin dir. On k3s v1.32.5 the live socket is \
                     {KUBELET_DEVICE_PLUGIN_DIR}/kubelet.sock, not \
                     {K3S_DEVICE_PLUGIN_DIR}/kubelet.sock (CHALLENGES #146).\n{diag}"
                );
            }
            panic!(
                "{RESOURCE} never reached Capacity={GPU_PER_NODE}/node and \
                 status.allocatable={GPU_PER_NODE}/node after {ceiling:?} \
                 (capacity={:?} allocatable={:?})\n{diag}",
                gpu.capacity, gpu.allocatable
            );
        }
        eprintln!(
            "ml-platform: waiting for {RESOURCE} cap={:?} alloc={:?}",
            gpu.capacity, gpu.allocatable
        );
        std::thread::sleep(Duration::from_secs(3));
    }
}

pub fn wait_gpu_used(
    kubeconfig: &Path,
    want_used_sum: u32,
    ceiling: Duration,
    whose: &str,
) -> BTreeMap<String, u32> {
    let start = Instant::now();
    loop {
        let used = gpu_used_via_kubectl(kubeconfig);
        if sum(&used) == want_used_sum {
            eprintln!(
                "ml-platform: {whose} {RESOURCE} used={used:?} sum={want_used_sum} after {:?}",
                start.elapsed()
            );
            return used;
        }
        if start.elapsed() > ceiling {
            panic!(
                "{whose}: {RESOURCE} pod-request used sum never reached {want_used_sum} \
                 after {ceiling:?} (used={used:?}). scheduler consumes Capacity via \
                 pod requests, not by dropping status.allocatable (CHALLENGES #147).\n{}",
                gpu_diagnostics(kubeconfig)
            );
        }
        eprintln!("ml-platform: {whose} waiting for {RESOURCE} used={used:?} want {want_used_sum}");
        std::thread::sleep(Duration::from_secs(2));
    }
}

pub fn scrape_dcgm(bridge: &str, ip: Ipv4Addr) -> Result<String, String> {
    let url = format!("http://{ip}:{DCGM_NODEPORT}/metrics");
    let out = Command::new("curl")
        .args([
            "-sS",
            "--max-time",
            "15",
            "--connect-timeout",
            "10",
            "--interface",
            bridge,
            &url,
        ])
        .output()
        .map_err(|e| format!("spawn curl: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    if !out.status.success() {
        return Err(format!(
            "curl {url} via {bridge} exit {}: {}{stdout}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(stdout)
}

pub fn assert_dcgm_metrics(body: &str, whose: &str) {
    assert!(
        body.contains("DCGM_FI_DEV_GPU_UTIL"),
        "{whose}: DCGM scrape missing DCGM_FI_DEV_GPU_UTIL (HTTP body was not an empty 200):\n{body}"
    );
    assert!(
        body.contains("DCGM_FI_DEV_FB_USED"),
        "{whose}: DCGM scrape missing DCGM_FI_DEV_FB_USED:\n{body}"
    );
    assert!(
        body.contains(MODEL_NAME),
        "{whose}: DCGM scrape missing modelName={MODEL_NAME}:\n{body}"
    );
}

pub fn assert_gpu_consistent(
    gpu: &GpuCounts,
    used: &BTreeMap<String, u32>,
    names: &[String],
    want_used_sum: u32,
    whose: &str,
) {
    assert!(
        gpu.leftover_example.is_empty(),
        "{whose}: leftover {WRONG_RESOURCE} on {:?}",
        gpu.leftover_example
    );
    for n in names {
        assert_eq!(
            gpu.capacity.get(n),
            Some(&GPU_PER_NODE),
            "{whose}: {n} Capacity {:?} want {GPU_PER_NODE} (resource must be {RESOURCE})",
            gpu.capacity.get(n)
        );
    }
    let free = gpu_free(gpu, used);
    assert_eq!(
        sum(used),
        want_used_sum,
        "{whose}: GPU pod requests sum {used:?} want {want_used_sum} \
         (status.allocatable stays at Capacity={:?}; consumption is pod requests)",
        gpu.allocatable
    );
    assert_eq!(
        sum(&free),
        3 * GPU_PER_NODE - want_used_sum,
        "{whose}: free GPUs {free:?} (capacity - pod requests)"
    );
}

/// Build the plugin, copy it onto every node, apply the DaemonSet
/// + DCGM scrape, wait Capacity=2/node.
pub fn apply_gpu_dcgm_fixture(cluster: &mut UbuntuCluster) -> GpuCounts {
    let plugin = build_fake_gpu_plugin();
    install_plugin_binary(cluster, &plugin);
    let kube = cluster.kubeconfig.clone();
    apply_fixture(&kube, "device-plugin-ds.yaml");
    apply_fixture(&kube, "dcgm-exporter.yaml");
    kubectl(
        &kube,
        &["rollout", "status", "ds/fake-gpu-plugin", "--timeout=180s"],
    )
    .unwrap_or_else(|e| panic!("fake-gpu-plugin rollout: {e}\n{}", gpu_diagnostics(&kube)));
    kubectl(
        &kube,
        &[
            "rollout",
            "status",
            "deploy/dcgm-exporter",
            "--timeout=180s",
        ],
    )
    .unwrap_or_else(|e| panic!("dcgm-exporter rollout: {e}\n{}", gpu_diagnostics(&kube)));
    let names = cluster.names();
    wait_gpu_registered(&kube, &names, FIXTURE_READY)
}
