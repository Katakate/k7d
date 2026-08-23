//! Host Helm helpers for the Ubuntu k3s fixture .
//!
//! Helm stays a host tool — never baked into the guest. Cilium install
//! flags are the load-bearing inc3 set (native routing + kubernetes
//! IPAM); Tetragon reuses them so it does not copy `bring_up_cluster`
//! or drift the CNI.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use super::ubuntu_k3s::{kubectl, POD_CIDR, POD_CIDR_PREFIX};

/// Pinned so a node with some other helm cannot silently change the
/// chart renderer. Same pin as the referenced work.
pub const HELM_VERSION: &str = "v3.16.4";
const HELM_TGZ: &str = "helm-v3.16.4-linux-amd64.tar.gz";
const HELM_URL: &str = "https://get.helm.sh/helm-v3.16.4-linux-amd64.tar.gz";

/// Pinned to 24a-inc3 / 25a-inc3 so the two substrates stay comparable.
pub const CILIUM_CHART: &str = "1.16.10";
pub const CILIUM_NS: &str = "kube-system";
/// Cilium must be told the same pod CIDR k3s was given, or it
/// masquerades pod-to-pod traffic instead of routing it natively.
pub const NATIVE_CIDR: &str = POD_CIDR;

pub fn ensure_helm() -> PathBuf {
    let dest_dir = PathBuf::from(format!("/usr/local/lib/k7d-helm/{HELM_VERSION}"));
    let helm = dest_dir.join("helm");
    if helm.is_file() {
        if let Ok(out) = Command::new(&helm).args(["version", "--short"]).output() {
            let v = String::from_utf8_lossy(&out.stdout);
            if v.contains(HELM_VERSION) {
                return helm;
            }
        }
    }

    let cache = PathBuf::from("/var/cache/k7d-helm");
    std::fs::create_dir_all(&cache).expect("helm cache dir");
    let tgz = cache.join(HELM_TGZ);
    let sum = cache.join(format!("{HELM_TGZ}.sha256sum"));
    if !tgz.is_file() {
        eprintln!("host: downloading pinned helm {HELM_VERSION}");
        let st = Command::new("curl")
            .args(["-fsSL", "-o", &tgz.to_string_lossy(), HELM_URL])
            .status()
            .expect("curl helm tarball");
        assert!(st.success(), "curl {HELM_URL} failed");
    }
    if !sum.is_file() {
        let st = Command::new("curl")
            .args([
                "-fsSL",
                "-o",
                &sum.to_string_lossy(),
                &format!("{HELM_URL}.sha256sum"),
            ])
            .status()
            .expect("curl helm checksum");
        assert!(st.success(), "curl helm sha256sum failed");
    }
    let check = Command::new("sha256sum")
        .args(["-c", &sum.to_string_lossy()])
        .current_dir(&cache)
        .output()
        .expect("sha256sum -c");
    assert!(
        check.status.success(),
        "helm tarball digest mismatch: {}{}",
        String::from_utf8_lossy(&check.stderr),
        String::from_utf8_lossy(&check.stdout)
    );

    std::fs::create_dir_all(&dest_dir).expect("helm dest");
    let st = Command::new("tar")
        .args([
            "-xzf",
            &tgz.to_string_lossy(),
            "-C",
            &dest_dir.to_string_lossy(),
            "--strip-components=1",
            "linux-amd64/helm",
        ])
        .status()
        .expect("tar helm");
    assert!(st.success(), "extract helm failed");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&helm, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let out = Command::new(&helm)
        .args(["version", "--short"])
        .output()
        .expect("helm version");
    let v = String::from_utf8_lossy(&out.stdout);
    assert!(
        v.contains(HELM_VERSION),
        "pinned helm reports {v}, want {HELM_VERSION}"
    );
    eprintln!("host: helm {HELM_VERSION} at {}", helm.display());
    helm
}

pub fn helm_install_cilium(helm: &Path, kubeconfig: &Path, server_ip: Ipv4Addr) {
    let status = kubectl(
        kubeconfig,
        &["get", "ns", CILIUM_NS, "-o", "jsonpath={.metadata.name}"],
    );
    assert_eq!(
        status.ok().as_deref().map(str::trim),
        Some(CILIUM_NS),
        "kube-system must exist before helm talks to it"
    );

    let out = Command::new(helm)
        .args([
            "install",
            "cilium",
            "cilium",
            "--version",
            CILIUM_CHART,
            "--repo",
            "https://helm.cilium.io/",
            "--namespace",
            CILIUM_NS,
            "--kubeconfig",
            &kubeconfig.to_string_lossy(),
            "--set",
            "operator.replicas=1",
            "--set",
            "routingMode=native",
            "--set",
            &format!("ipv4NativeRoutingCIDR={NATIVE_CIDR}"),
            "--set",
            "autoDirectNodeRoutes=true",
            "--set",
            "kubeProxyReplacement=true",
            // Userspace virtio-net: Cilium auto-enables host-legacy
            // routing, so pod-to-pod is a host FORWARD. Per-endpoint
            // routes send that through the guest stack (the path
            // host-ns curl already proved) instead of bpf_redirect.
            "--set",
            "endpointRoutes.enabled=true",
            "--set",
            "bpf.hostLegacyRouting=true",
            // Cilium L2 neigh discovery stores the remote *lxc* MAC in
            // ipcache. SYN-ACK is then dest'd to that MAC, which is not
            // on the k7 bridge, so the host FDB never delivers it to the
            // client TAP (CHALLENGES.md #117). Host-ns replies use the
            // node MAC and complete. Fail closed: do not resolve pod MACs.
            "--set",
            "l2NeighDiscovery.enabled=false",
            "--set",
            "ipam.mode=kubernetes",
            "--set",
            "k8s.requireIPv4PodCIDR=true",
            "--set",
            &format!("k8sServiceHost={server_ip}"),
            "--set",
            "k8sServicePort=6443",
        ])
        .output()
        .expect("spawn helm install");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "helm install cilium {CILIUM_CHART} failed: {stderr}{stdout}"
    );
    eprintln!("helm: installed cilium {CILIUM_CHART}\n{stdout}");
}

pub fn wait_cilium_ready(kubeconfig: &Path, ceiling: Duration) -> Duration {
    let start = Instant::now();
    loop {
        let agents = kubectl(
            kubeconfig,
            &[
                "-n",
                CILIUM_NS,
                "get",
                "ds",
                "cilium",
                "-o",
                "jsonpath={.status.numberReady}",
            ],
        )
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0);
        let operator = kubectl(
            kubeconfig,
            &[
                "-n",
                CILIUM_NS,
                "get",
                "deploy",
                "cilium-operator",
                "-o",
                "jsonpath={.status.readyReplicas}",
            ],
        )
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0);
        if agents == 3 && operator >= 1 {
            let elapsed = start.elapsed();
            eprintln!("Cilium ready: 3/3 agents + operator after {elapsed:?}");
            return elapsed;
        }
        if start.elapsed() > ceiling {
            let diag = cilium_diagnostics(kubeconfig);
            panic!(
                "Cilium never Ready in {ceiling:?} (agents={agents}/3 operator={operator})\n{diag}"
            );
        }
        eprintln!("Cilium not ready yet: agents={agents}/3 operator={operator}");
        std::thread::sleep(Duration::from_secs(5));
    }
}

pub fn cilium_diagnostics(kubeconfig: &Path) -> String {
    let mut out = String::new();
    for args in [
        vec!["-n", CILIUM_NS, "get", "pods", "-o", "wide"],
        vec!["get", "nodes", "-o", "wide"],
        vec!["-n", CILIUM_NS, "get", "events", "--sort-by=.lastTimestamp"],
        vec![
            "-n",
            CILIUM_NS,
            "logs",
            "-l",
            "k8s-app=cilium",
            "--all-containers",
            "--prefix",
            "--tail=80",
        ],
        vec![
            "-n",
            CILIUM_NS,
            "logs",
            "-l",
            "name=cilium-operator",
            "--tail=40",
        ],
    ] {
        let got = kubectl(kubeconfig, &args).unwrap_or_else(|e| e);
        out.push_str(&format!("--- kubectl {} ---\n{got}\n", args.join(" ")));
    }
    out
}

/// `(name, podCIDR, InternalIP)` for every node. Guest overlay routes
/// on the k7 gateway need these (CHALLENGES.md #117).
pub fn node_pod_cidrs(kubeconfig: &Path) -> Vec<(String, String, String)> {
    let body = kubectl(kubeconfig, &["get", "nodes", "-o", "json"])
        .unwrap_or_else(|e| panic!("get nodes json: {e}"));
    let v: serde_json::Value =
        serde_json::from_str(&body).unwrap_or_else(|e| panic!("nodes json: {e}"));
    let empty = Vec::new();
    let mut out = Vec::new();
    for n in v["items"].as_array().unwrap_or(&empty) {
        let name = n["metadata"]["name"].as_str().unwrap_or("").to_string();
        let cidr = n["spec"]["podCIDR"]
            .as_str()
            .unwrap_or_else(|| panic!("node {name} has no spec.podCIDR"))
            .to_string();
        assert!(
            cidr.starts_with(POD_CIDR_PREFIX),
            "node {name} podCIDR {cidr} is outside the cluster CIDR {NATIVE_CIDR}"
        );
        let ip = n["status"]["addresses"]
            .as_array()
            .unwrap_or(&empty)
            .iter()
            .find(|a| a["type"].as_str() == Some("InternalIP"))
            .and_then(|a| a["address"].as_str())
            .unwrap_or_else(|| panic!("node {name} has no InternalIP"))
            .to_string();
        out.push((name, cidr, ip));
    }
    assert_eq!(out.len(), 3, "expected 3 nodes with podCIDRs: {out:?}");
    out
}

/// Policy-table overlay routes so the k7 gateway forwards guest
/// podCIDR / ClusterIP without `replace`ing host `cni0` (CHALLENGES.md #117).
pub fn ensure_host_pod_routes(bridge: &str, cidrs: &[(String, String, String)]) {
    k7d::network::restore_host_cni_connected_route()
        .unwrap_or_else(|e| panic!("restore host cni0 before overlay routes: {e}"));
    let mut routes: Vec<(&str, &str)> = cidrs
        .iter()
        .map(|(_, cidr, via)| (cidr.as_str(), via.as_str()))
        .collect();
    let via0 = cidrs[0].2.as_str();
    routes.push((k7d::network::GUEST_SERVICE_OVERLAY, via0));
    k7d::network::install_guest_overlay_routes(bridge, &routes).unwrap_or_else(|e| {
        panic!("guest overlay routes on {bridge}: {e}");
    });
    for (name, cidr, via) in cidrs {
        eprintln!(
            "host table {}: {cidr} via {via} dev {bridge} ({name})",
            k7d::network::GUEST_OVERLAY_TABLE
        );
    }
    eprintln!(
        "host table {}: {} via {via0} dev {bridge} (ClusterIP)",
        k7d::network::GUEST_OVERLAY_TABLE,
        k7d::network::GUEST_SERVICE_OVERLAY
    );
}
