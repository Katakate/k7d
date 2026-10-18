//! Inner k3s / sidecar CRI socket over emptyDir.
//!
//! Two containers share `/cri` via emptyDir; sidecar runs a
//! real containerd; main talks to it with `ctr --address /cri/containerd.sock`.
//!
//! The main container runs a full `k3s server` against the
//! sidecar containerd (`--container-runtime-endpoint`) and the inner node
//! goes Ready.
//!
//! Three outer pods (same `k7d.katakate.org/cluster-id`,
//! `fork-vm-index` 0/1/2 → guest IPs 10.200.0.2/.3/.4 on one shared L2
//! bridge) run a 3-node inner cluster — `k3s server` + two `k3s agent`s —
//! with flannel host-gw and kube-proxy enabled on the netfilter/veth/
//! bridge-capable guest kernel, and an inner pause pod on an agent node
//! is reachable from the server node.
//!
//! Adopt the live three-pod cluster as a `ClusterSnapshotTree`
//! root via `TreeAdoptCluster`, warm-fork it under
//! `FORK_INNER_K3S_CLUSTER_3VM` while a host-side TLS probe against the
//! source inner API server stays alive, and assert the fork shows 3
//! Ready nodes at the same guest IPs.
//!
//! Same adopt + fork, but driven by kubectl — a trigger
//! pod carrying the `k7d.katakate.org/tree-*` annotations makes the
//! shim call `TreeAdoptCluster` + `TreeFork` during its sandbox
//! Create; the daemon socket is only used for discovery/teardown.

mod common;

use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use k7d::control::{Client, Request, Response};
use k7d::latency::{FORK_INNER_K3S_CLUSTER_3VM, FORK_INNER_K3S_CLUSTER_3VM_ARGOCD};
use k7d::tree::TreeBudget;

/// Pinned rancher/k3s image that ships `/bin/containerd` + `/bin/ctr`.
/// Digested so the test never floats on `:latest`.
const K3S_IMAGE: &str = "docker.io/rancher/k3s:v1.32.5-k3s1@sha256:b75eac801bbc91b4584769c840f346683c7740d72f83e630088370f8e1eb2c8a";

const POD_NAME: &str = "test-inner-k3s-cri-emptydir";

/// / — memory limit of the `k3s server` container.
/// A full k3s server (apiserver + kine/sqlite + scheduler +
/// controller-manager + kubelet) plus the in-guest tmpfs holding its data
/// dir does not fit the 256 MB BestEffort default; the floor here is
/// >= 2 Gi of VM budget. Adopt adds ~300 MB: the k3s binary
/// is copied to tmpfs so warm forks never fault it in from virtiofs
/// (see `inner3_pod_yaml`).
const INNER_K3S_MEMORY_MB: u32 = 2560;
/// Memory limit of the containerd sidecar (+192 MB tmpfs for the
/// containerd + runc-shim binaries, same warm-fork reason). Pod-level
/// sandbox memory is the sum of container limits, so the VM boots
/// with `2560 + 640 + 64 MB` overhead = 3264 MB.
const INNER_K3S_SIDECAR_MEMORY_MB: u32 = 640;

const K3S_POD_NAME: &str = "test-inner-k3s-single-node";

// ──: fixture switchboard ──

/// Add-ons the inner k3s server enables. `Default` = today's fixture:
/// everything off. Every field is explicit — no catch-all extras string.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct InnerAddons {
    coredns: bool,
    traefik: bool,
    servicelb: bool,
    metrics_server: bool,
    local_storage: bool,
    /// k3s embedded helm controller. Off today (`--disable-helm-controller`).
    helm_controller: bool,
    /// Drops `--disable-network-policy` when true.
    network_policy: bool,
}

impl InnerAddons {
    /// Single source of the add-on disable list. Renders
    /// `--disable-network-policy` / `--disable-helm-controller` plus
    /// `--disable=…`. `--disable-kube-proxy`, `--flannel-backend=…`,
    /// and `--disable-cloud-controller` stay at the call site.
    fn disable_flags(&self) -> String {
        self.disable_flag_parts().join(" ")
    }

    fn disable_flag_parts(&self) -> Vec<String> {
        let mut parts = Vec::new();
        if !self.network_policy {
            parts.push("--disable-network-policy".into());
        }
        if !self.helm_controller {
            parts.push("--disable-helm-controller".into());
        }
        let addons = self.disabled_addon_names();
        if !addons.is_empty() {
            parts.push(format!("--disable={}", addons.join(",")));
        }
        parts
    }

    fn disabled_addon_names(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if !self.coredns {
            names.push("coredns");
        }
        if !self.traefik {
            names.push("traefik");
        }
        if !self.servicelb {
            names.push("servicelb");
        }
        if !self.metrics_server {
            names.push("metrics-server");
        }
        if !self.local_storage {
            names.push("local-storage");
        }
        names
    }

    /// Shell-continuation form interpolated into the k3s entrypoint,
    /// including call-site `--disable-cloud-controller` in today's order.
    fn disable_flags_shell(&self, indent: &str) -> String {
        self.disable_flags_with_cloud_controller()
            .join(&format!(" \\\n{indent}"))
    }

    /// Call-site `--disable-cloud-controller` interleaved in today's
    /// order (after network-policy, before helm-controller). The add-on
    /// list still comes only from [`InnerAddons::disable_flag_parts`].
    fn disable_flags_with_cloud_controller(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut inserted = false;
        for p in self.disable_flag_parts() {
            out.push(p.clone());
            if p == "--disable-network-policy" {
                out.push("--disable-cloud-controller".into());
                inserted = true;
            }
        }
        if !inserted {
            out.insert(0, "--disable-cloud-controller".into());
        }
        out
    }
}

/// Inner k3s datastore engine. Default is kine/sqlite (today's fixture).
/// `Etcd` is single-member embedded etcd via `--cluster-init` on the
/// server only — the prod engine, not HA quorum.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum InnerDatastore {
    #[default]
    Sqlite,
    Etcd,
}

/// Which CNI programs the inner cluster's datapath.
///
/// `FlannelHostGw` is today's fixture: k3s's bundled flannel plus
/// kube-proxy, which every other inner-k3s test depends on. `Cilium`
/// swaps both out — `--flannel-backend=none --disable-kube-proxy` and
/// an eBPF datapath the test installs itself.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum InnerCni {
    #[default]
    FlannelHostGw,
    Cilium,
}

/// One inner-cluster fixture profile. [`InnerClusterProfile::default_3node`]
/// reproduces the current fixture bit-for-bit (same pod names, node
/// names, IPs, memory, and k3s CLI).
#[derive(Clone, Debug)]
struct InnerClusterProfile {
    cluster_id: &'static str,
    vm_count: usize,
    memory_mb: u32,
    sidecar_memory_mb: u32,
    addons: InnerAddons,
    datastore: InnerDatastore,
    cni: InnerCni,
}

impl InnerClusterProfile {
    fn default_3node() -> Self {
        Self {
            cluster_id: "inner3",
            vm_count: 3,
            memory_mb: INNER_K3S_MEMORY_MB,
            sidecar_memory_mb: INNER_K3S_SIDECAR_MEMORY_MB,
            addons: InnerAddons::default(),
            datastore: InnerDatastore::Sqlite,
            cni: InnerCni::FlannelHostGw,
        }
    }

    /// Default 3-node fixture with CoreDNS enabled.
    fn coredns_3node() -> Self {
        let mut p = Self::default_3node();
        p.addons.coredns = true;
        p
    }

    /// Base profile plus ServiceLB + Traefik + the embedded helm
    /// controller. Traefik is a HelmChart CR — enabling
    /// `traefik` without `helm_controller` deploys nothing.
    fn ingress_3node() -> Self {
        let mut p = Self::coredns_3node();
        p.addons.traefik = true;
        p.addons.servicelb = true;
        p.addons.helm_controller = true;
        // Traefik + klipper-helm layers do not fit the default 512 Mi
        // containerd tmpfs (ENOSPC on `ctr images import traefik.tar`).
        p.sidecar_memory_mb = 1536;
        p
    }

    /// Base profile plus local-storage. CoreDNS stays
    /// on so the provisioner can resolve the in-cluster API.
    fn local_path_3node() -> Self {
        let mut p = Self::coredns_3node();
        p.addons.local_storage = true;
        p
    }

    /// Base profile plus metrics-server. CoreDNS stays
    /// on per the spec; metrics-server itself dials the apiserver and
    /// the kubelets by IP.
    fn metrics_3node() -> Self {
        let mut p = Self::coredns_3node();
        p.addons.metrics_server = true;
        p
    }

    /// Base profile with `--disable-network-policy` dropped. k3s's
    /// embedded netpol controller (the kube-router
    /// lib) runs in every k3s process and programs iptables + ipset
    /// inside each guest — the guest kernel carries `CONFIG_IP_SET`
    /// and `CONFIG_NETFILTER_XT_SET` for exactly this profile.
    fn network_policy_3node() -> Self {
        let mut p = Self::coredns_3node();
        p.addons.network_policy = true;
        p
    }

    /// Base profile plus embedded etcd (`--cluster-init` on the server
    /// only). Topology stays 1 server + 2 agents —
    /// single-member etcd, not HA quorum.
    fn etcd_3node() -> Self {
        let mut p = Self::coredns_3node();
        p.datastore = InnerDatastore::Etcd;
        p
    }

    /// CoreDNS 3-node plus a larger sidecar tmpfs so the ArgoCD image
    /// (and redis + alpine/git + the baked git-daemon image) fit the
    /// airgap import. ArgoCD itself is a workload the
    /// test installs, not an add-on.
    fn argocd_3node() -> Self {
        let mut p = Self::coredns_3node();
        p.sidecar_memory_mb = ARGOCD_SIDECAR_MEMORY_MB;
        p
    }

    /// 3-node fixture whose CNI is Cilium in native-routing mode with
    /// kube-proxy replaced by eBPF. CoreDNS stays off:
    /// every probe here addresses pod IPs and Service VIPs directly, so
    /// DNS would only add a second thing to bootstrap through a cluster
    /// that has no service datapath until the DaemonSet is ready.
    ///
    /// The sidecar grows for the same reason the Traefik profile did
    /// (CHALLENGES #89): the agent image alone is ~220 MiB compressed
    /// and lands much larger extracted on the containerd tmpfs.
    fn cilium_3node() -> Self {
        let mut p = Self::default_3node();
        p.cni = InnerCni::Cilium;
        p.sidecar_memory_mb = CILIUM_SIDECAR_MEMORY_MB;
        p
    }

    /// Where the sidecar containerd looks for CNI plugin binaries. The
    /// flannel path uses the k3s image's own `/bin`; Cilium's agent
    /// installs `cilium-cni` from an init container, and the only
    /// directory both containers can see is the shared `/cri` emptyDir
    /// (a hostPath is resolved in the *sidecar's* mount namespace —
    /// CHALLENGES #91).
    fn cni_bin_dir(&self) -> &'static str {
        match self.cni {
            InnerCni::FlannelHostGw => "/bin",
            InnerCni::Cilium => CILIUM_CNI_BIN_DIR,
        }
    }

    /// Seconds the k3s container waits for the sidecar's airgap import
    /// marker. 180 s covers pause + CoreDNS + busybox; Cilium's agent
    /// tar is an order of magnitude larger and extracts on one vCPU,
    /// and a blown wait here reads as a CNI problem.
    fn airgap_import_wait_secs(&self) -> u32 {
        match self.cni {
            InnerCni::FlannelHostGw => 180,
            InnerCni::Cilium => 600,
        }
    }

    /// `--cluster-init` when the profile asks for embedded etcd.
    /// Empty for sqlite so the default CLI stays byte-identical.
    fn cluster_init_flag(&self) -> Option<&'static str> {
        match self.datastore {
            InnerDatastore::Etcd => Some("--cluster-init"),
            InnerDatastore::Sqlite => None,
        }
    }

    /// In-guest `/var/lib/containerd` tmpfs. Sized from the sidecar
    /// limit minus 128 Mi for the process + `/run/containerd` so the
    /// default profile stays 512 Mi.
    fn containerd_tmpfs_mb(&self) -> u32 {
        self.sidecar_memory_mb.saturating_sub(128)
    }

    fn pod_name(&self, idx: usize) -> String {
        assert!(
            idx < self.vm_count,
            "pod_name({idx}) >= vm_count {}",
            self.vm_count
        );
        if idx == 0 {
            "test-inner-k3s-3n-server".into()
        } else {
            format!("test-inner-k3s-3n-agent-{}", idx - 1)
        }
    }

    fn node_name(&self, idx: usize) -> String {
        assert!(
            idx < self.vm_count,
            "node_name({idx}) >= vm_count {}",
            self.vm_count
        );
        if idx == 0 {
            "inner-server".into()
        } else {
            format!("inner-agent-{}", idx - 1)
        }
    }

    fn guest_ip(&self, idx: usize) -> String {
        assert!(
            idx < self.vm_count,
            "guest_ip({idx}) >= vm_count {}",
            self.vm_count
        );
        format!("10.200.0.{}", 2 + idx)
    }

    fn live_pod(&self, idx: usize) -> String {
        common::unique_name(&self.pod_name(idx))
    }

    fn live_pods(&self) -> Vec<String> {
        (0..self.vm_count).map(|i| self.live_pod(i)).collect()
    }

    /// Single-node k3s server flags (flannel none, kube-proxy off).
    /// Order matches today's fixture: network-policy, cloud-controller,
    /// helm-controller, `--disable=…`.
    fn single_node_server_flags(&self) -> Vec<String> {
        let mut flags = vec![
            "--container-runtime-endpoint=unix:///cri/containerd.sock".into(),
            "--cluster-cidr=10.60.0.0/16".into(),
            "--service-cidr=10.61.0.0/16".into(),
            "--flannel-backend=none".into(),
            "--disable-kube-proxy".into(),
        ];
        flags.extend(self.addons.disable_flags_with_cloud_controller());
        if let Some(flag) = self.cluster_init_flag() {
            flags.push(flag.into());
        }
        flags.push("--node-ip=\"$NODE_IP\"".into());
        flags.push("--node-name=inner-server".into());
        flags.push("--write-kubeconfig-mode=644".into());
        flags
    }

    /// 3-node server flags. Flannel host-gw with kube-proxy on for
    /// every profile but the Cilium one, which brings its own datapath
    /// and so must have both switched off. The agents learn the same
    /// from the server's config endpoint — `--flannel-backend` and
    /// `--disable-kube-proxy` are server-only flags.
    fn cluster_server_flags(&self, node: &str) -> Vec<String> {
        let mut flags = vec![
            format!("--token={INNER3_TOKEN}"),
            "--container-runtime-endpoint=unix:///cri/containerd.sock".into(),
            "--cluster-cidr=10.60.0.0/16".into(),
            "--service-cidr=10.61.0.0/16".into(),
        ];
        match self.cni {
            InnerCni::FlannelHostGw => flags.push("--flannel-backend=host-gw".into()),
            InnerCni::Cilium => {
                flags.push("--flannel-backend=none".into());
                flags.push("--disable-kube-proxy".into());
            }
        }
        flags.extend(self.addons.disable_flags_with_cloud_controller());
        if let Some(flag) = self.cluster_init_flag() {
            flags.push(flag.into());
        }
        flags.push("--node-ip=\"$NODE_IP\"".into());
        flags.push(format!("--node-name={node}"));
        flags.push("--write-kubeconfig-mode=644".into());
        flags
    }
}

/// Pre-shared k3s join token (test-only cluster on an isolated bridge).
const INNER3_TOKEN: &str = "k7-inner3-token";

fn pod_name() -> &'static str {
    static N: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    N.get_or_init(|| common::unique_name(POD_NAME))
}

fn k3s_pod_name() -> &'static str {
    static N: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    N.get_or_init(|| common::unique_name(K3S_POD_NAME))
}

fn default_profile() -> InnerClusterProfile {
    InnerClusterProfile::default_3node()
}

fn inner3_pods() -> Vec<String> {
    default_profile().live_pods()
}

/// Per-run cluster-id. IFNAMSIZ=16 and the daemon names the bridge
/// `k7-br-{cluster_id}`, so the id must be ≤ 9 chars (`i3` + 6 hex).
fn inner3_cluster_id() -> &'static str {
    static N: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    N.get_or_init(|| format!("i3{}", common::run_id()))
}

fn inner3_bridge() -> String {
    format!("k7-br-{}", inner3_cluster_id())
}

fn inner3_trigger_pod() -> &'static str {
    static N: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    N.get_or_init(|| common::unique_name(INNER3_TRIGGER_POD))
}

/// Sandbox/pause image for the *inner* containerd. The guests sit on an
/// isolated L2 bridge with no registry access, so the test stages this
/// image as an airgap tar (exported from the host's containerd) on a
/// hostPath the sidecar imports at startup. Digest-pinned like
/// [`K3S_IMAGE`].
const INNER3_PAUSE_IMAGE: &str = "docker.io/rancher/mirrored-pause:3.6@sha256:74c4244427b7312c5b901fe0f67cbc53683d06f4f24c6faee65d4182bf0fa893";
/// The un-digested ref the inner containerd config + inner pod specs
/// use (`ctr images import` preserves the tag from the export).
const INNER3_PAUSE_REF: &str = "docker.io/rancher/mirrored-pause:3.6";
/// CoreDNS image k3s v1.32.5 deploys (`rancher/mirrored-coredns-coredns:1.12.1`
/// in `/var/lib/rancher/k3s/server/manifests/coredns.yaml`). Digest-pinned
/// like [`K3S_IMAGE`].
const INNER3_COREDNS_IMAGE: &str = "docker.io/rancher/mirrored-coredns-coredns:1.12.1@sha256:9eb4929fd181541e7743959884000f010bcc8b1ebf8715ff0965be04509882e5";
const INNER3_COREDNS_REF: &str = "docker.io/rancher/mirrored-coredns-coredns:1.12.1";
/// Short ref k3s writes into the CoreDNS Deployment (no `docker.io/` prefix).
const INNER3_COREDNS_SHORT_REF: &str = "rancher/mirrored-coredns-coredns:1.12.1";
/// Digest-pinned busybox with `nslookup` / `httpd` for probe + HTTP backend pods.
const INNER3_BUSYBOX_IMAGE: &str = "docker.io/library/busybox:1.36.1@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";
const INNER3_BUSYBOX_REF: &str = "docker.io/library/busybox:1.36.1";
/// Traefik image k3s v1.32.5's bundled chart deploys
/// (`rancher/mirrored-library-traefik:3.3.6` in
/// `/var/lib/rancher/k3s/server/manifests/traefik.yaml`).
const INNER3_TRAEFIK_IMAGE: &str = "docker.io/rancher/mirrored-library-traefik:3.3.6@sha256:9595fc80fa8ed6c5f3876416332ca7c88e8f255daaf265cff6b857b8d0f44503";
const INNER3_TRAEFIK_REF: &str = "docker.io/rancher/mirrored-library-traefik:3.3.6";
const INNER3_TRAEFIK_SHORT_REF: &str = "rancher/mirrored-library-traefik:3.3.6";
/// helm-controller Job image (k3s v1.32.5 airgap list /
/// helm-controller v0.16.10 `DefaultJobImage`).
const INNER3_KLIPPER_HELM_IMAGE: &str = "docker.io/rancher/klipper-helm:v0.9.5-build20250306@sha256:0379ae6c5a486118d20837f95c4dc9059d6351556da028e866784b72d7e5ded1";
const INNER3_KLIPPER_HELM_REF: &str = "docker.io/rancher/klipper-helm:v0.9.5-build20250306";
const INNER3_KLIPPER_HELM_SHORT_REF: &str = "rancher/klipper-helm:v0.9.5-build20250306";
/// ServiceLB DaemonSet image (`DefaultLBImage` in k3s v1.32.5
/// `pkg/cloudprovider/servicelb.go`).
const INNER3_KLIPPER_LB_IMAGE: &str = "docker.io/rancher/klipper-lb:v0.4.13@sha256:7eb86d5b908ec6ddd9796253d8cc2f43df99420fc8b8a18452a94dc56f86aca0";
const INNER3_KLIPPER_LB_REF: &str = "docker.io/rancher/klipper-lb:v0.4.13";
const INNER3_KLIPPER_LB_SHORT_REF: &str = "rancher/klipper-lb:v0.4.13";
/// local-path-provisioner image k3s v1.32.5 deploys
/// (`rancher/local-path-provisioner:v0.0.31` in
/// `/var/lib/rancher/k3s/server/manifests/local-storage.yaml`).
const INNER3_LPP_IMAGE: &str = "docker.io/rancher/local-path-provisioner:v0.0.31@sha256:80496fdeb307541007621959aa13aed41d31db9cd2dc4167c19833e0bfa3878c";
const INNER3_LPP_REF: &str = "docker.io/rancher/local-path-provisioner:v0.0.31";
const INNER3_LPP_SHORT_REF: &str = "rancher/local-path-provisioner:v0.0.31";
/// Helper-pod image from the same bundled ConfigMap (`helperPod.yaml`).
const INNER3_LPP_HELPER_IMAGE: &str = "docker.io/rancher/mirrored-library-busybox:1.36.1@sha256:8a45424ddf949bbe9bb3231b05f9032a45da5cd036eb4867b511b00734756d6f";
const INNER3_LPP_HELPER_REF: &str = "docker.io/rancher/mirrored-library-busybox:1.36.1";
const INNER3_LPP_HELPER_SHORT_REF: &str = "rancher/mirrored-library-busybox:1.36.1";
/// metrics-server image k3s v1.32.5 deploys
/// (`rancher/mirrored-metrics-server:v0.7.2` in
/// `/var/lib/rancher/k3s/server/manifests/metrics-server/metrics-server-deployment.yaml`).
const INNER3_METRICS_IMAGE: &str = "docker.io/rancher/mirrored-metrics-server:v0.7.2@sha256:dccf8474fb910fef261d31d9483d7e4c1df7b86cf4d638fb6a7d7c88bd51600a";
const INNER3_METRICS_REF: &str = "docker.io/rancher/mirrored-metrics-server:v0.7.2";
const INNER3_METRICS_SHORT_REF: &str = "rancher/mirrored-metrics-server:v0.7.2";
/// ArgoCD v2.14.11 (controller + repo-server share this image).
const INNER3_ARGOCD_IMAGE: &str = "quay.io/argoproj/argocd:v2.14.11@sha256:5fc69e31c755fc0209c6eb66f6280ece558990bfb77704795e0e939b6bb6f434";
const INNER3_ARGOCD_REF: &str = "quay.io/argoproj/argocd:v2.14.11";
/// Redis tag the same ArgoCD release pins in `manifests/core-install.yaml`.
const INNER3_REDIS_IMAGE: &str = "docker.io/library/redis:7.0.15-alpine@sha256:c9d92d840fd011c908f040592857c724ae6d877f2aba5c40ad963276507386b2";
const INNER3_REDIS_REF: &str = "docker.io/library/redis:7.0.15-alpine";
/// alpine/git client (seed + fork-only commit). Client-only — no
/// `git-daemon` binary (CHALLENGES #94).
const INNER3_GIT_IMAGE: &str = "docker.io/alpine/git:2.45.2@sha256:16ad8e788e1d3b0c30f18da8dde5c0ace3b187445a62d8af893b003ca1e70592";
const INNER3_GIT_REF: &str = "docker.io/alpine/git:2.45.2";
/// Cilium agent v1.16.10 — the CNI this fixture installs itself.
/// Digest-pinned like every other inner image; the
/// guests have no registry, so it arrives as an airgap tar.
const INNER3_CILIUM_IMAGE: &str = "quay.io/cilium/cilium:v1.16.10@sha256:fc4ccc494c4a381439162fd3684c07ba9c26d3c2670a2b2e1623acee99097461";
const INNER3_CILIUM_REF: &str = "quay.io/cilium/cilium:v1.16.10";
/// Matching `operator-generic` — the operator registers Cilium's CRDs
/// and allocates per-node state, so the agents cannot go ready without it.
const INNER3_CILIUM_OPERATOR_IMAGE: &str = "quay.io/cilium/operator-generic:v1.16.10@sha256:05e5f5e676aa51ae5e3bf6be3594ecf52958f46f07f9f55368a7a952012a13c1";
const INNER3_CILIUM_OPERATOR_REF: &str = "quay.io/cilium/operator-generic:v1.16.10";

/// Digest-pinned Alpine used to bake the in-cluster `git://` server.
const INNER3_ALPINE_IMAGE: &str = "docker.io/library/alpine:3.20.3@sha256:1e42bbe2508154c9126d48c2b8a75420c3544343bf86fd041fb7527e017a4b4a";
/// Host-baked `alpine` + `git` + `git-daemon`. Not a registry pull;
/// `stage_git_daemon_airgap_tar` builds it during airgap staging.
const INNER3_GIT_DAEMON_REF: &str = "docker.io/k7d/git-daemon:local";
/// Sidecar memory for [`InnerClusterProfile::argocd_3node`]. ArgoCD is
/// ~177 Mi compressed; the default 512 Mi containerd tmpfs ENOSPCs
/// (CHALLENGES #89). 2048 → 1920 Mi tmpfs, above the Traefik 1536
/// precedent because this image is ~3× larger.
const ARGOCD_SIDECAR_MEMORY_MB: u32 = 2048;
/// Sidecar memory for [`InnerClusterProfile::cilium_3node`]. The agent
/// image is ~219 Mi compressed and extracts to roughly 600 Mi on the
/// containerd tmpfs, and unlike ArgoCD the extracted image *and* a
/// long-running agent with its BPF maps have to fit at once.
const CILIUM_SIDECAR_MEMORY_MB: u32 = 2560;
/// Sidecar containerd `bin_dir` for the Cilium profile: the only
/// directory the agent's init container (a nested pod) and the sidecar
/// containerd that execs the plugin can both see.
const CILIUM_CNI_BIN_DIR: &str = "/cri/cni/bin";
/// Host directory (hostPath-mounted into the sidecars) holding the
/// airgap tars. dirties via a pause Deployment + API
/// churn (needs guest `CONFIG_CFS_BANDWIDTH` — CHALLENGES #51).
const INNER3_AIRGAP_DIR: &str = "/tmp/k7-inner3-airgap";

/// Marker line the DNS-probe pods append on each successful resolution.
const DNS_OK_PREFIX: &str = "DNS_OK";
/// Body the Ingress HTTP backend serves (busybox `httpd`).
const INNER_HTTP_MARKER: &str = "INNER_HTTP_OK";
const INNER_HTTP_HOST: &str = "inner.test";

fn ensure_shim_installed() -> common::LeakGuard {
    common::cleanup_k7_runtime_leaks();

    let shim_src = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("target/release/containerd-shim-k7-v1");

    let status = Command::new("cargo")
        .args(["build", "--release", "-p", "containerd-shim-k7-v1"])
        .status()
        .expect("cargo build should run");
    assert!(status.success(), "shim build failed");

    let installed = std::path::Path::new("/usr/local/bin/containerd-shim-k7-v1");
    let need_install = if installed.exists() {
        let src_meta = std::fs::metadata(&shim_src).unwrap();
        let dst_meta = std::fs::metadata(installed).unwrap();
        src_meta.len() != dst_meta.len()
            || src_meta.modified().unwrap() > dst_meta.modified().unwrap()
    } else {
        true
    };

    if need_install {
        eprintln!("  installing shim to /usr/local/bin/");
        let _ = Command::new("pkill")
            .args(["-9", "-f", "containerd-shim-k7-v1"])
            .status();
        thread::sleep(Duration::from_millis(500));
        let _ = std::fs::remove_file(installed);
        std::fs::copy(&shim_src, installed).expect("copy shim binary");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(installed, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let _ = Command::new("systemctl").args(["restart", "k3s"]).status();
        common::wait_for_k3s_ready();
    }

    let rc_check = Command::new("kubectl")
        .args(["get", "runtimeclass", "k7"])
        .output()
        .expect("kubectl should run");
    if !rc_check.status.success() {
        eprintln!("  creating RuntimeClass k7");
        let _ = Command::new("kubectl")
            .args(["apply", "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child
                    .stdin
                    .as_mut()
                    .unwrap()
                    .write_all(
                        b"apiVersion: node.k8s.io/v1\nkind: RuntimeClass\nmetadata:\n  name: k7\nhandler: k7\n",
                    )
                    .unwrap();
                child.wait()
            })
            .expect("create RuntimeClass");
    }

    common::ensure_k7d_daemon_running();
    common::LeakGuard
}

fn kubectl_apply(yaml: &str) {
    common::kubectl_apply(yaml).unwrap_or_else(|e| panic!("kubectl apply failed: {e}"));
}

fn kubectl_delete_pod(name: &str) {
    let _ = Command::new("kubectl")
        .args(["delete", "pod", name, "--ignore-not-found", "--wait=false"])
        .output();
}

/// `kubectl exec` with a hard 120 s wall clock. kubectl has no client
/// timeout of its own: one wedged exec stream (seen once against a
/// heavily loaded 1-vCPU inner-k3s guest) blocks a poll loop forever
/// instead of surfacing as an `Err` the caller can retry.
fn kubectl_exec_in(pod: &str, container: &str, cmd: &str) -> Result<String, String> {
    let output = Command::new("timeout")
        .args([
            "120", "kubectl", "exec", pod, "-c", container, "--", "sh", "-c", cmd,
        ])
        .output()
        .map_err(|e| format!("kubectl exec failed: {e}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(format!(
            "exit {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// [`kubectl_exec_in`] with a few retries — for one-shot queries whose
/// single exec stream may time out against a busy guest.
fn kubectl_exec_retry(
    pod: &str,
    container: &str,
    cmd: &str,
    attempts: u32,
) -> Result<String, String> {
    let mut last = Err("no attempts".to_string());
    for _ in 0..attempts {
        last = kubectl_exec_in(pod, container, cmd);
        if last.is_ok() {
            return last;
        }
        thread::sleep(Duration::from_secs(2));
    }
    last
}

fn wait_for_pod_running(name: &str, timeout: Duration) {
    let start = Instant::now();
    loop {
        let output = Command::new("kubectl")
            .args(["get", "pod", name, "-o", "jsonpath={.status.phase}"])
            .output()
            .expect("kubectl get pod");
        let phase = String::from_utf8_lossy(&output.stdout);
        if phase == "Running" {
            return;
        }
        if start.elapsed() > timeout {
            let describe = Command::new("kubectl")
                .args(["describe", "pod", name])
                .output()
                .expect("kubectl describe");
            panic!(
                "pod {name} not Running after {timeout:?} (phase={phase}):\n{}",
                String::from_utf8_lossy(&describe.stdout)
            );
        }
        thread::sleep(Duration::from_secs(2));
    }
}

/// Warm the node image cache so k7 pods never race an image pull.
fn pull_k3s_image() {
    let pull = Command::new("ctr")
        .args(["-n", "k8s.io", "images", "pull", K3S_IMAGE])
        .output()
        .expect("ctr images pull");
    assert!(
        pull.status.success(),
        "failed to pull {K3S_IMAGE}: {}",
        String::from_utf8_lossy(&pull.stderr)
    );
}

/// Sidecar containerd CRI socket via emptyDir.
#[test]
fn test_sidecar_containerd_socket_via_emptydir() {
    let _leak_guard = ensure_shim_installed();
    pull_k3s_image();

    kubectl_delete_pod(pod_name());
    thread::sleep(Duration::from_secs(2));

    // Sidecar: real containerd listening on the shared emptyDir socket.
    // Main: wait for the socket, then `ctr version` against it and write
    // a marker file so the host can poll without scraping container logs.
    // Combined memory limits = 1Gi (the floor).
    //
    // containerd's root must be tmpfs (bolt databases need writable shared
    // mmap, which virtiofs `--cache never` rejects with ENODEV) and `lo`
    // must be up (the CRI stream server binds 127.0.0.1) — see
    // CHALLENGES.md.
    let pod = pod_name();
    let yaml = common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {pod}
spec:
  runtimeClassName: k7
  restartPolicy: Never
  containers:
  - name: containerd
    image: {K3S_IMAGE}
    imagePullPolicy: IfNotPresent
    command: ["/bin/sh", "-c"]
    args:
    - |
      set -e
      ip link set lo up
      mkdir -p /var/lib/containerd /run/containerd /cri
      mount -t tmpfs -o size=256m tmpfs /var/lib/containerd
      mount -t tmpfs -o size=64m tmpfs /run/containerd
      mkdir -p /sys/fs/cgroup/init
      xargs -rn1 < /sys/fs/cgroup/cgroup.procs > /sys/fs/cgroup/init/cgroup.procs || true
      sed -e 's/ / +/g' -e 's/^/+/' < /sys/fs/cgroup/cgroup.controllers \
        > /sys/fs/cgroup/cgroup.subtree_control
      exec /bin/containerd \
        --address /cri/containerd.sock \
        --root /var/lib/containerd \
        --state /run/containerd
    securityContext:
      privileged: true
    resources:
      limits:
        memory: 512Mi
    volumeMounts:
    - name: cri
      mountPath: /cri
  - name: main
    image: {K3S_IMAGE}
    imagePullPolicy: IfNotPresent
    command: ["/bin/sh", "-c"]
    args:
    - |
      set -e
      for i in $(seq 1 90); do
        if [ -S /cri/containerd.sock ]; then
          break
        fi
        sleep 1
      done
      test -S /cri/containerd.sock
      /bin/ctr --address /cri/containerd.sock version > /cri/ctr-version.txt
      echo CTR_OK > /cri/ctr-ok
      sleep infinity
    resources:
      limits:
        memory: 512Mi
    volumeMounts:
    - name: cri
      mountPath: /cri
  volumes:
  - name: cri
    emptyDir: {{}}
"#
    ));

    kubectl_apply(&yaml);

    wait_for_pod_running(pod_name(), Duration::from_secs(180));

    // Poll the marker written into the shared emptyDir.
    let start = Instant::now();
    let mut last_err;
    loop {
        match kubectl_exec_in(
            pod_name(),
            "main",
            "cat /cri/ctr-ok 2>/dev/null && cat /cri/ctr-version.txt",
        ) {
            Ok(text) if text.contains("CTR_OK") => {
                // "Server:" only appears when ctr actually connected over
                // the shared socket — "Client:" is printed even when the
                // connect fails, which let an earlier version of this
                // test pass with a dead containerd (see CHALLENGES.md).
                assert!(
                    text.contains("Server:"),
                    "ctr version output missing Server section (socket connect failed?):\n{text}"
                );
                kubectl_delete_pod(pod_name());
                return;
            }
            Ok(text) => last_err = format!("unexpected marker content: {text}"),
            Err(e) => last_err = e,
        }
        if start.elapsed() > Duration::from_secs(120) {
            let cd_logs = Command::new("kubectl")
                .args(["logs", pod_name(), "-c", "containerd", "--tail=80"])
                .output()
                .expect("kubectl logs containerd");
            let main_logs = Command::new("kubectl")
                .args(["logs", pod_name(), "-c", "main", "--tail=80"])
                .output()
                .expect("kubectl logs main");
            kubectl_delete_pod(pod_name());
            panic!(
                "main never wrote /cri/ctr-ok: {last_err}\ncontainerd logs:\n{}\nmain logs:\n{}",
                String::from_utf8_lossy(&cd_logs.stdout),
                String::from_utf8_lossy(&main_logs.stdout)
            );
        }
        thread::sleep(Duration::from_secs(2));
    }
}

/// Single-node inner k3s goes Ready against the
/// sidecar containerd's CRI socket over the shared `/cri` emptyDir.
///
/// Guest-environment constraints encoded in the entrypoints (found the
/// hard way; see CHALLENGES.md):
/// - Every shared filesystem in the guest is virtiofs with `--cache never`,
///   which rejects writable shared mmap (ENODEV). containerd's bolt
///   databases and kine's sqlite WAL both need it, so containerd's root
///   and k3s's data dir live on in-guest tmpfs.
/// - The guest kernel has no overlayfs -> containerd uses the `native`
///   snapshotter.
/// - The guest kernel has no netfilter -> flannel and kube-proxy are
///   disabled; a static bridge CNI conf on `/cri/cni/net.d` satisfies the
///   CRI NetworkReady condition (no inner pods are scheduled here; real
///   inner-pod networking comes later).
/// - The guest brings up `eth0` but leaves `lo` down; both containerd's
///   CRI stream server and the k3s apiserver bind 127.0.0.1.
/// - kubelet needs `/dev/kmsg` and a mounted cgroup2 hierarchy with the
///   cpuset controller (CONFIG_CPUSETS in the guest kernel).
#[test]
fn test_inner_k3s_single_node_ready() {
    let _leak_guard = ensure_shim_installed();
    pull_k3s_image();

    kubectl_delete_pod(k3s_pod_name());
    thread::sleep(Duration::from_secs(2));

    let k3s_pod = k3s_pod_name();
    let disable_flags = default_profile().addons.disable_flags_shell("        ");
    let yaml = common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {k3s_pod}
spec:
  runtimeClassName: k7
  restartPolicy: Never
  containers:
  - name: containerd
    image: {K3S_IMAGE}
    imagePullPolicy: IfNotPresent
    command: ["/bin/sh", "-c"]
    args:
    - |
      set -x
      ip link set lo up
      mkdir -p /var/lib/containerd /run/containerd /cri/cni/net.d
      mount -t tmpfs -o size=256m tmpfs /var/lib/containerd || exit 1
      mount -t tmpfs -o size=64m tmpfs /run/containerd || exit 1
      mkdir -p /sys/fs/cgroup/init
      xargs -rn1 < /sys/fs/cgroup/cgroup.procs > /sys/fs/cgroup/init/cgroup.procs || true
      sed -e 's/ / +/g' -e 's/^/+/' < /sys/fs/cgroup/cgroup.controllers \
        > /sys/fs/cgroup/cgroup.subtree_control || exit 1
      cat > /cri/cni/net.d/10-inner.conflist <<EOF
      {{
        "cniVersion": "1.0.0",
        "name": "inner",
        "plugins": [
          {{
            "type": "bridge",
            "bridge": "cni0",
            "isGateway": true,
            "ipMasq": false,
            "ipam": {{
              "type": "host-local",
              "ranges": [[{{"subnet": "10.60.0.0/24"}}]]
            }}
          }}
        ]
      }}
      EOF
      cat > /tmp/containerd-config.toml <<EOF
      version = 2
      [plugins."io.containerd.grpc.v1.cri".containerd]
        snapshotter = "native"
      [plugins."io.containerd.grpc.v1.cri".cni]
        conf_dir = "/cri/cni/net.d"
        bin_dir = "/bin"
      EOF
      exec /bin/containerd \
        --config /tmp/containerd-config.toml \
        --address /cri/containerd.sock \
        --root /var/lib/containerd \
        --state /run/containerd
    securityContext:
      privileged: true
    resources:
      limits:
        memory: {INNER_K3S_SIDECAR_MEMORY_MB}Mi
    volumeMounts:
    - name: cri
      mountPath: /cri
  - name: k3s
    image: {K3S_IMAGE}
    imagePullPolicy: IfNotPresent
    command: ["/bin/sh", "-c"]
    args:
    - |
      set -x
      ip link set lo up
      mkdir -p /var/lib/rancher /var/lib/kubelet
      mkdir -p /sys/fs/cgroup/init
      xargs -rn1 < /sys/fs/cgroup/cgroup.procs > /sys/fs/cgroup/init/cgroup.procs || true
      sed -e 's/ / +/g' -e 's/^/+/' < /sys/fs/cgroup/cgroup.controllers \
        > /sys/fs/cgroup/cgroup.subtree_control || exit 1
      mount -t tmpfs -o size=768m tmpfs /var/lib/rancher || exit 1
      mount -t tmpfs -o size=128m tmpfs /var/lib/kubelet || exit 1
      if ! [ -e /dev/kmsg ]; then
        mknod /dev/kmsg c 1 11 || exit 1
      fi
      i=0
      while [ ! -S /cri/containerd.sock ]; do
        i=$((i+1))
        if [ "$i" -gt 120 ]; then echo "no containerd socket"; exit 1; fi
        sleep 1
      done
      NODE_IP=$(ip -4 -o addr show eth0 | head -1 | tr -s " " | cut -d" " -f4 | cut -d/ -f1)
      if [ -z "$NODE_IP" ]; then echo "no eth0 ip"; exit 1; fi
      exec /bin/k3s server \
        --container-runtime-endpoint=unix:///cri/containerd.sock \
        --cluster-cidr=10.60.0.0/16 \
        --service-cidr=10.61.0.0/16 \
        --flannel-backend=none \
        --disable-kube-proxy \
        {disable_flags} \
        --node-ip="$NODE_IP" \
        --node-name=inner-server \
        --write-kubeconfig-mode=644
    securityContext:
      privileged: true
    resources:
      limits:
        memory: {INNER_K3S_MEMORY_MB}Mi
    volumeMounts:
    - name: cri
      mountPath: /cri
  volumes:
  - name: cri
    emptyDir: {{}}
"#
    ));

    kubectl_apply(&yaml);

    wait_for_pod_running(k3s_pod_name(), Duration::from_secs(180));

    // Poll `kubectl get nodes` inside the k3s container until the inner
    // node reports Ready. k3s server on 1 vCPU in a nested VM needs a
    // couple of minutes.
    let start = Instant::now();
    loop {
        let attempt = kubectl_exec_in(
            k3s_pod_name(),
            "k3s",
            "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl get nodes --no-headers 2>&1",
        );
        if let Ok(ref text) = attempt {
            let ready = text.lines().any(|l| {
                let mut cols = l.split_whitespace();
                cols.next() == Some("inner-server") && cols.next() == Some("Ready")
            });
            if ready {
                break;
            }
        }
        if start.elapsed() > Duration::from_secs(300) {
            let k3s_logs = Command::new("kubectl")
                .args(["logs", k3s_pod_name(), "-c", "k3s", "--tail=120"])
                .output()
                .expect("kubectl logs k3s");
            let cd_logs = Command::new("kubectl")
                .args(["logs", k3s_pod_name(), "-c", "containerd", "--tail=40"])
                .output()
                .expect("kubectl logs containerd");
            kubectl_delete_pod(k3s_pod_name());
            panic!(
                "inner node never went Ready (last attempt: {attempt:?})\n\
                 k3s logs:\n{}\ncontainerd logs:\n{}",
                String::from_utf8_lossy(&k3s_logs.stdout),
                String::from_utf8_lossy(&cd_logs.stdout)
            );
        }
        thread::sleep(Duration::from_secs(3));
    }

    // The pinned inner CIDRs must have taken effect: pod CIDR allocated
    // from 10.60.0.0/16 and the kubernetes Service VIP from 10.61.0.0/16
    // (neither collides with the outer cluster's 10.42/10.43 defaults).
    // The nodeipam controller assigns podCIDR asynchronously (it can lag
    // the first Ready by a while on 1 vCPU), so poll until it appears.
    let start = Instant::now();
    let pod_cidr = loop {
        let cidr = kubectl_exec_in(
            k3s_pod_name(),
            "k3s",
            "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl get node inner-server \
             -o jsonpath='{.spec.podCIDR}'",
        )
        .expect("query inner node podCIDR");
        if !cidr.is_empty() {
            break cidr;
        }
        assert!(
            start.elapsed() < Duration::from_secs(120),
            "inner node never got a podCIDR from the nodeipam controller"
        );
        thread::sleep(Duration::from_secs(3));
    };
    assert!(
        pod_cidr.starts_with("10.60."),
        "inner podCIDR {pod_cidr} not allocated from --cluster-cidr=10.60.0.0/16"
    );
    let svc_ip = kubectl_exec_in(
        k3s_pod_name(),
        "k3s",
        "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl get svc kubernetes \
         -o jsonpath='{.spec.clusterIP}'",
    )
    .expect("query kubernetes service ClusterIP");
    assert!(
        svc_ip.starts_with("10.61."),
        "kubernetes Service VIP {svc_ip} not allocated from --service-cidr=10.61.0.0/16"
    );

    kubectl_delete_pod(k3s_pod_name());
}

/// Pull + export one image into [`INNER3_AIRGAP_DIR`] as `{name}.tar`.
/// `extra_refs` are additional tags written into the same tar so the
/// inner CRI can resolve both `docker.io/…` and the short name k3s
/// writes into its bundled manifests.
fn stage_airgap_tar(pull_ref: &str, plain_ref: &str, tar_name: &str, extra_refs: &[&str]) {
    let pull = Command::new("ctr")
        .args(["-n", "k8s.io", "images", "pull", pull_ref])
        .output()
        .unwrap_or_else(|e| panic!("ctr images pull {pull_ref}: {e}"));
    assert!(
        pull.status.success(),
        "failed to pull {pull_ref}: {}",
        String::from_utf8_lossy(&pull.stderr)
    );
    // Re-tag to the plain ref so the export (and the guest-side import)
    // carries the name the inner CRI config / inner pod specs use.
    let mut export_refs = vec![plain_ref.to_string()];
    for r in std::iter::once(plain_ref).chain(extra_refs.iter().copied()) {
        let tag = Command::new("ctr")
            .args(["-n", "k8s.io", "images", "tag", "--force", pull_ref, r])
            .output()
            .unwrap_or_else(|e| panic!("ctr images tag {r}: {e}"));
        assert!(
            tag.status.success(),
            "failed to tag {pull_ref} as {r}: {}",
            String::from_utf8_lossy(&tag.stderr)
        );
        if r != plain_ref {
            export_refs.push(r.to_string());
        }
    }
    std::fs::create_dir_all(INNER3_AIRGAP_DIR).expect("create airgap dir");
    let tar = format!("{INNER3_AIRGAP_DIR}/{tar_name}");
    let _ = std::fs::remove_file(&tar);
    let mut args = vec![
        "-n".into(),
        "k8s.io".into(),
        "images".into(),
        "export".into(),
        "--platform".into(),
        "linux/amd64".into(),
        tar.clone(),
    ];
    args.extend(export_refs);
    let export = Command::new("ctr")
        .args(&args)
        .output()
        .unwrap_or_else(|e| panic!("ctr images export {plain_ref}: {e}"));
    assert!(
        export.status.success(),
        "failed to export {plain_ref}: {}",
        String::from_utf8_lossy(&export.stderr)
    );
}

/// Wipe [`INNER3_AIRGAP_DIR`]. The sidecar imports every `*.tar` under
/// `/airgap`, so a leftover Traefik tar from the ingress profile would
/// ENOSPC the default 512 Mi containerd tmpfs (CHALLENGES #89).
fn reset_airgap_dir() {
    let _ = std::fs::remove_dir_all(INNER3_AIRGAP_DIR);
    std::fs::create_dir_all(INNER3_AIRGAP_DIR).expect("create airgap dir");
}

/// Stage pause airgap tar. Inner containerds sit on an isolated bridge
/// with no registry access.
fn stage_pause_airgap() {
    reset_airgap_dir();
    stage_airgap_tar(INNER3_PAUSE_IMAGE, INNER3_PAUSE_REF, "pause.tar", &[]);
}

/// Stage every image the profile's inner pods will run. Guests have no
/// registry; the sidecar imports every `*.tar` under `/airgap`.
fn stage_profile_airgap(profile: &InnerClusterProfile) {
    stage_pause_airgap();
    if profile.addons.coredns {
        stage_airgap_tar(
            INNER3_COREDNS_IMAGE,
            INNER3_COREDNS_REF,
            "coredns.tar",
            &[INNER3_COREDNS_SHORT_REF],
        );
    }
    if profile.addons.coredns
        || profile.addons.traefik
        || profile.addons.local_storage
        || profile.cni == InnerCni::Cilium
    {
        stage_airgap_tar(INNER3_BUSYBOX_IMAGE, INNER3_BUSYBOX_REF, "busybox.tar", &[]);
    }
    if profile.cni == InnerCni::Cilium {
        stage_airgap_tar(INNER3_CILIUM_IMAGE, INNER3_CILIUM_REF, "cilium.tar", &[]);
        stage_airgap_tar(
            INNER3_CILIUM_OPERATOR_IMAGE,
            INNER3_CILIUM_OPERATOR_REF,
            "cilium-operator.tar",
            &[],
        );
    }
    if profile.addons.helm_controller || profile.addons.traefik {
        stage_airgap_tar(
            INNER3_KLIPPER_HELM_IMAGE,
            INNER3_KLIPPER_HELM_REF,
            "klipper-helm.tar",
            &[INNER3_KLIPPER_HELM_SHORT_REF],
        );
        stage_airgap_tar(
            INNER3_TRAEFIK_IMAGE,
            INNER3_TRAEFIK_REF,
            "traefik.tar",
            &[INNER3_TRAEFIK_SHORT_REF],
        );
    }
    if profile.addons.servicelb {
        stage_airgap_tar(
            INNER3_KLIPPER_LB_IMAGE,
            INNER3_KLIPPER_LB_REF,
            "klipper-lb.tar",
            &[INNER3_KLIPPER_LB_SHORT_REF],
        );
    }
    if profile.addons.metrics_server {
        stage_airgap_tar(
            INNER3_METRICS_IMAGE,
            INNER3_METRICS_REF,
            "metrics-server.tar",
            &[INNER3_METRICS_SHORT_REF],
        );
    }
    if profile.addons.local_storage {
        stage_airgap_tar(
            INNER3_LPP_IMAGE,
            INNER3_LPP_REF,
            "local-path-provisioner.tar",
            &[INNER3_LPP_SHORT_REF],
        );
        stage_airgap_tar(
            INNER3_LPP_HELPER_IMAGE,
            INNER3_LPP_HELPER_REF,
            "lpp-helper.tar",
            &[INNER3_LPP_HELPER_SHORT_REF],
        );
    }
    if profile.sidecar_memory_mb == ARGOCD_SIDECAR_MEMORY_MB {
        stage_airgap_tar(INNER3_ARGOCD_IMAGE, INNER3_ARGOCD_REF, "argocd.tar", &[]);
        stage_airgap_tar(INNER3_REDIS_IMAGE, INNER3_REDIS_REF, "redis.tar", &[]);
        stage_airgap_tar(INNER3_GIT_IMAGE, INNER3_GIT_REF, "alpine-git.tar", &[]);
        stage_git_daemon_airgap_tar();
    }
}

/// Bake `k7d/git-daemon:local` on the host (`alpine` + `apk add git
/// git-daemon`) and export it for the airgapped guests.
///
/// `alpine/git` is a client-only image — `git daemon` is not a git
/// command there (CHALLENGES #94). The guests have no registry, so the
/// bake happens on the node (which has Docker + network) and the result
/// is staged like every other airgap tar.
fn stage_git_daemon_airgap_tar() {
    let docker = Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .unwrap_or_else(|e| panic!("docker is required to bake {INNER3_GIT_DAEMON_REF}: {e}"));
    assert!(
        docker.status.success(),
        "docker daemon not usable (needed to bake {INNER3_GIT_DAEMON_REF}): {}",
        String::from_utf8_lossy(&docker.stderr)
    );

    let build_dir = "/tmp/k7-git-daemon-build";
    let _ = std::fs::remove_dir_all(build_dir);
    std::fs::create_dir_all(build_dir).expect("create git-daemon build dir");
    std::fs::write(
        format!("{build_dir}/Dockerfile"),
        format!("FROM {INNER3_ALPINE_IMAGE}\nRUN apk add --no-cache git git-daemon\n"),
    )
    .expect("write git-daemon Dockerfile");

    let pull = Command::new("docker")
        .args(["pull", "--platform", "linux/amd64", INNER3_ALPINE_IMAGE])
        .output()
        .unwrap_or_else(|e| panic!("docker pull {INNER3_ALPINE_IMAGE}: {e}"));
    assert!(
        pull.status.success(),
        "docker pull {INNER3_ALPINE_IMAGE} failed: {}",
        String::from_utf8_lossy(&pull.stderr)
    );

    let build = Command::new("docker")
        .args([
            "build",
            "--platform",
            "linux/amd64",
            "--network",
            "host",
            "-t",
            INNER3_GIT_DAEMON_REF,
            build_dir,
        ])
        .output()
        .unwrap_or_else(|e| panic!("docker build {INNER3_GIT_DAEMON_REF}: {e}"));
    assert!(
        build.status.success(),
        "docker build {INNER3_GIT_DAEMON_REF} failed: {}\n{}",
        String::from_utf8_lossy(&build.stderr),
        String::from_utf8_lossy(&build.stdout)
    );

    let check = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            INNER3_GIT_DAEMON_REF,
            "test",
            "-x",
            "/usr/libexec/git-core/git-daemon",
        ])
        .output()
        .unwrap_or_else(|e| panic!("docker run git-daemon check: {e}"));
    assert!(
        check.status.success(),
        "{INNER3_GIT_DAEMON_REF} is missing /usr/libexec/git-core/git-daemon"
    );

    let mut save = Command::new("docker")
        .args(["save", INNER3_GIT_DAEMON_REF])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("docker save {INNER3_GIT_DAEMON_REF}: {e}"));
    let save_stdout = save.stdout.take().expect("docker save stdout");
    let import = Command::new("ctr")
        .args(["-n", "k8s.io", "images", "import", "-"])
        .stdin(save_stdout)
        .output()
        .unwrap_or_else(|e| panic!("ctr images import {INNER3_GIT_DAEMON_REF}: {e}"));
    let save_status = save
        .wait()
        .unwrap_or_else(|e| panic!("docker save wait: {e}"));
    assert!(
        save_status.success() && import.status.success(),
        "docker save | ctr import {INNER3_GIT_DAEMON_REF} failed: \
         save={save_status} import={}: {}",
        import.status,
        String::from_utf8_lossy(&import.stderr)
    );

    std::fs::create_dir_all(INNER3_AIRGAP_DIR).expect("create airgap dir");
    let tar = format!("{INNER3_AIRGAP_DIR}/git-daemon.tar");
    let _ = std::fs::remove_file(&tar);
    let export = Command::new("ctr")
        .args([
            "-n",
            "k8s.io",
            "images",
            "export",
            "--platform",
            "linux/amd64",
            &tar,
            INNER3_GIT_DAEMON_REF,
        ])
        .output()
        .unwrap_or_else(|e| panic!("ctr images export {INNER3_GIT_DAEMON_REF}: {e}"));
    assert!(
        export.status.success(),
        "failed to export {INNER3_GIT_DAEMON_REF}: {}",
        String::from_utf8_lossy(&export.stderr)
    );
    eprintln!("  staged host-baked {INNER3_GIT_DAEMON_REF} as {tar}");
}

fn profile_needs_volume_flatten(profile: &InnerClusterProfile) -> bool {
    profile.addons.helm_controller
        || profile.addons.traefik
        || profile.addons.servicelb
        || profile.addons.local_storage
}

/// Bind the default local-path root onto `/cri` so sidecar runc
/// hostPath (helper + PVC consumer pods) sees the same guest-RAM
/// files as the k3s container's `/var/lib/rancher/k3s/storage`.
fn local_path_storage_bind(profile: &InnerClusterProfile) -> String {
    if !profile.addons.local_storage {
        return String::new();
    }
    "mkdir -p /cri/k3s-storage /var/lib/rancher/k3s/storage\n      \
     mount --bind /cri/k3s-storage /var/lib/rancher/k3s/storage || exit 1\n      "
        .into()
}

/// Sidecar must rshared-bind `/cri/kubelet-pods` the same way the k3s
/// container does. Otherwise kubelet's local-volume bind (k3s mount ns)
/// does not propagate, runc mounts an empty dir, and the writer writes
/// into that empty dir instead of the PV (CHALLENGES #91).
fn local_path_sidecar_propagation(profile: &InnerClusterProfile) -> String {
    if !profile.addons.local_storage {
        return String::new();
    }
    "mount --bind /cri/kubelet-pods /cri/kubelet-pods || exit 1\n      \
     mount --make-rshared /cri/kubelet-pods || exit 1\n      "
        .into()
}

/// Sidecar snippet: everything Cilium's pods bind from "the host".
///
/// A nested pod's hostPath is resolved in the **sidecar's** mount
/// namespace, while kubelet type-checks it in the k3s container's
/// (CHALLENGES #91) — so every path Cilium needs is either the shared
/// `/cri` emptyDir (visible identically to both) or something the
/// kernel puts in every mount namespace (`/proc`, and `/sys/fs/bpf`,
/// which exists as an empty sysfs directory even in a fresh sysfs).
///
/// Four things are created here rather than by the DaemonSet's stock
/// init containers, all of which assume they are on a real node:
/// - **bpffs**: the guest root namespace has one (`guest/rootfs/init.sh`),
///   but the sidecar's `/sys` is a fresh sysfs, so it gets its own
///   mount. Cilium's `mount-bpf-fs` init container would do this with
///   `mountPropagation: Bidirectional`, which cannot propagate out of
///   a nested pod into the sidecar.
/// - **cgroup2** at `/cri/cgroupv2` for the socket-LB cgroup hook.
///   Mounted inside the sidecar's cgroup namespace, so its root is the
///   sidecar's own cgroup — which is exactly the subtree every nested
///   pod lives in, because the sidecar containerd is what creates them.
/// - **the CNI bin dir**: `cilium-cni` is installed into
///   `/cri/cni/bin`, which is also this profile's containerd
///   `bin_dir`. The k3s image's own multicall `cni` plugin is copied in
///   beside it (4.7 MiB) so a conflist that references `portmap` or
///   `loopback` still resolves.
/// - **`/var/run/cilium`**: the agent's socket, bound from `/cri` so
///   that `cilium-cni` — which containerd execs in the *sidecar's*
///   namespace at the hardcoded path — talks to the agent that is
///   running in a pod.
fn cilium_sidecar_prep(profile: &InnerClusterProfile) -> String {
    if profile.cni != InnerCni::Cilium {
        return String::new();
    }
    format!(
        "mkdir -p {CILIUM_CNI_BIN_DIR} /cri/cilium-run /cri/cilium-config \
         /cri/cilium-sa /cri/cilium-operator-sa /cri/cilium-cgroup /cri/cilium-lib-modules\n      \
         cp /bin/cni {CILIUM_CNI_BIN_DIR}/cni || exit 1\n      \
         for p in bridge host-local loopback portmap; do \
         ln -sf cni {CILIUM_CNI_BIN_DIR}/$p || exit 1; done\n      \
         touch /cri/cilium-xtables.lock || exit 1\n      \
         mkdir -p /var/run/cilium || exit 1\n      \
         mount --bind /cri/cilium-run /var/run/cilium || exit 1\n      \
         mount -t bpf bpf /sys/fs/bpf || exit 1\n      \
         mount -t cgroup2 none /cri/cilium-cgroup || exit 1\n      "
    )
}

/// Sidecar snippet: write `/cri/flatten-vols.sh` (quoted heredoc so the
/// YAML `|` block stays closed). k3s starts the script; default profile
/// writes nothing.
fn nested_runc_flattener_install(profile: &InnerClusterProfile) -> String {
    if !profile_needs_volume_flatten(profile) {
        return String::new();
    }
    // Indented with the `|` block. YAML strips the common indent, so
    // the `FLATTEN` closer lands at column 0 for the shell. Do not
    // umount kubelet volume trees — that detaches
    // `/var/lib/kubelet/pods` from `/cri` (CHALLENGES #90).
    r#"if [ ! -x /cri/flatten-vols.sh ]; then
      cat > /cri/flatten-vols.sh <<'FLATTEN'
      #!/bin/sh
      SRC=/var/lib/kubelet/pods
      DST=/cri/kubelet-pods
      while true; do
        find "$SRC" -type f 2>/dev/null | while read -r f; do
          rel=${f#"$SRC/"}
          target="$DST/$rel"
          if [ -d "$target" ]; then rm -rf "$target"; fi
          mkdir -p "$(dirname "$target")"
          [ "$f" -ef "$target" ] && continue
          cp -a "$f" "$target" 2>/dev/null || true
        done
        sleep 0.1
      done
      FLATTEN
      chmod +x /cri/flatten-vols.sh
      fi
"#
    .into()
}

/// k3s snippet: start the sidecar-written flattener. One indented line
/// so the `|` block cannot close on `exec /bin/k3s`.
fn nested_runc_flattener_start(profile: &InnerClusterProfile) -> String {
    if !profile_needs_volume_flatten(profile) {
        return String::new();
    }
    "i=0; while [ ! -x /cri/flatten-vols.sh ]; do i=$((i+1)); if [ $i -gt 60 ]; then echo no flatten script; exit 1; fi; sleep 1; done; /cri/flatten-vols.sh >/tmp/k7-flatten-vols.log 2>&1 &"
        .into()
}

/// Pod manifest for inner-cluster member `idx` (0 = server, 1+ =
/// agents). All members share [`inner3_cluster_id()`] (one L2 bridge) and
/// pin `fork-vm-index` = `idx` so the guest IPs are the stable
/// `10.200.0.{2+idx}` addresses from the profile.
///
/// Cross-container file contracts (all plain files, virtiofs-safe; the
/// mmap-hungry state stays on in-guest tmpfs per CHALLENGES.md #34):
/// - `/cri/containerd.sock` — CRI socket.
/// - `/cri/cni/net.d` — flannel writes the CNI conflist from the k3s
///   container (bind of k3s's `agent/etc/cni/net.d`); the sidecar
///   containerd reads it as its CNI `conf_dir`.
/// - `/cri/run-flannel` — flannel's `subnet.env`, written by k3s and
///   read by the flannel CNI plugin execing under the sidecar (both
///   bind it to `/run/flannel`).
/// - `/cri/kubelet-pods` — kubelet's pods dir. Both containers symlink
///   `/var/lib/kubelet/pods` here so etc-hosts / termination-log files
///   kubelet writes are the sidecar runc bind-mount sources (CHALLENGES
///   #90). A bind of this path onto itself is rshared so volume mounts
///   propagate.
/// - `/cri/log-pods` — `/var/log/pods` in both: kubelet creates the
///   pod log dirs, the sidecar containerd writes the container logs.
fn inner3_pod_yaml(idx: usize) -> String {
    inner_pod_yaml(&default_profile(), idx)
}

fn inner_pod_yaml(profile: &InnerClusterProfile, idx: usize) -> String {
    let pod = profile.live_pod(idx);
    let cluster_id = inner3_cluster_id();
    let node = profile.node_name(idx);
    let memory_mb = profile.memory_mb;
    let sidecar_memory_mb = profile.sidecar_memory_mb;
    let containerd_tmpfs_mb = profile.containerd_tmpfs_mb();
    let flatten_install = nested_runc_flattener_install(profile);
    let flatten_start = nested_runc_flattener_start(profile);
    let storage_bind = local_path_storage_bind(profile);
    let sidecar_propagation = local_path_sidecar_propagation(profile);
    let cilium_sidecar_prep = cilium_sidecar_prep(profile);
    let cni_bin_dir = profile.cni_bin_dir();
    let airgap_wait = profile.airgap_import_wait_secs();
    // `/bin/k3s` directly: moved the container rootfs
    // off virtiofs onto an erofs virtio-blk device (overlay with a
    // guest-tmpfs upper), so mmap'd binary pages fault in from the
    // block device — which survives forks (both CoW warm forks and
    // the slow full-copy path recreate the device over the same
    // immutable image file). The old `/tmpbin` tmpfs-exec copies
    // (CHALLENGES.md #41: fresh post-fork FUSE sessions EBADF'd
    // stale mmap file handles → SIGBUS) are dead code on the block
    // path; `test_inner_k3s_cluster_warm_fork_via_annotation` proves
    // the fork survives execing straight from the image rootfs.
    let k3s_cmd = if idx == 0 {
        // One source of truth for the server CLI: the rendered flag
        // list the profile already owns (a second literal copy here is
        // how a profile flag reaches the unit test but not the guest).
        format!(
            "exec /bin/k3s server \\\n        {}",
            profile.cluster_server_flags(&node).join(" \\\n        ")
        )
    } else {
        format!(
            "exec /bin/k3s agent \\\n\
             \x20       --server=https://{server_ip}:6443 \\\n\
             \x20       --token={INNER3_TOKEN} \\\n\
             \x20       --container-runtime-endpoint=unix:///cri/containerd.sock \\\n\
             \x20       --node-ip=\"$NODE_IP\" \\\n\
             \x20       --node-name={node}",
            server_ip = profile.guest_ip(0)
        )
    };
    common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {pod}
  annotations:
    k7d.katakate.org/cluster-id: {cluster_id}
    k7d.katakate.org/fork-vm-index: "{idx}"
spec:
  runtimeClassName: k7
  restartPolicy: Never
  containers:
  - name: containerd
    image: {K3S_IMAGE}
    imagePullPolicy: IfNotPresent
    command: ["/bin/sh", "-c"]
    args:
    - |
      set -x
      ip link set lo up
      mkdir -p /var/lib/containerd /run/containerd /var/lib/cni /var/log/pods \
        /var/lib/kubelet /cri/cni/net.d /cri/run-flannel /cri/kubelet-pods \
        /cri/log-pods /run/flannel
      mount -t tmpfs -o size={containerd_tmpfs_mb}m tmpfs /var/lib/containerd || exit 1
      mount -t tmpfs -o size=64m tmpfs /run/containerd || exit 1
      mount -t tmpfs -o size=16m tmpfs /var/lib/cni || exit 1
      mkdir -p /sys/fs/cgroup/init
      xargs -rn1 < /sys/fs/cgroup/cgroup.procs > /sys/fs/cgroup/init/cgroup.procs || true
      sed -e 's/ / +/g' -e 's/^/+/' < /sys/fs/cgroup/cgroup.controllers \
        > /sys/fs/cgroup/cgroup.subtree_control || exit 1
      mount --bind /cri/run-flannel /run/flannel || exit 1
      mkdir -p /var/lib/kubelet /cri/kubelet-pods
      mount --make-rshared /cri || exit 1
      rm -rf /var/lib/kubelet/pods
      ln -sfn /cri/kubelet-pods /var/lib/kubelet/pods || exit 1
      mount --bind /cri/log-pods /var/log/pods || exit 1
      {storage_bind}{sidecar_propagation}{cilium_sidecar_prep}{flatten_install}
      cat > /tmp/containerd-config.toml <<EOF
      version = 2
      [plugins."io.containerd.grpc.v1.cri"]
        sandbox_image = "{INNER3_PAUSE_REF}"
      [plugins."io.containerd.grpc.v1.cri".containerd]
        snapshotter = "overlayfs"
      [plugins."io.containerd.grpc.v1.cri".cni]
        conf_dir = "/cri/cni/net.d"
        bin_dir = "{cni_bin_dir}"
      EOF
      /bin/containerd \
        --config /tmp/containerd-config.toml \
        --address /cri/containerd.sock \
        --root /var/lib/containerd \
        --state /run/containerd &
      CD=$!
      i=0
      while [ ! -S /cri/containerd.sock ]; do
        i=$((i+1))
        if [ $i -gt 60 ]; then echo "no containerd socket"; exit 1; fi
        sleep 1
      done
      for tar in /airgap/*.tar; do
        [ -f "$tar" ] || continue
        /bin/ctr --address /cri/containerd.sock -n k8s.io images import "$tar" || exit 1
      done
      touch /cri/pause-imported
      wait $CD
    securityContext:
      privileged: true
    resources:
      limits:
        memory: {sidecar_memory_mb}Mi
    volumeMounts:
    - name: cri
      mountPath: /cri
    - name: airgap
      mountPath: /airgap
      readOnly: true
  - name: k3s
    image: {K3S_IMAGE}
    imagePullPolicy: IfNotPresent
    command: ["/bin/sh", "-c"]
    args:
    - |
      set -x
      ip link set lo up
      mkdir -p /var/lib/rancher /var/lib/kubelet /var/log/pods \
        /cri/cni/net.d /cri/run-flannel /cri/kubelet-pods /cri/log-pods /run/flannel
      mkdir -p /sys/fs/cgroup/init
      xargs -rn1 < /sys/fs/cgroup/cgroup.procs > /sys/fs/cgroup/init/cgroup.procs || true
      sed -e 's/ / +/g' -e 's/^/+/' < /sys/fs/cgroup/cgroup.controllers \
        > /sys/fs/cgroup/cgroup.subtree_control || exit 1
      mount -t tmpfs -o size=768m tmpfs /var/lib/rancher || exit 1
      {storage_bind}mount -t tmpfs -o size=128m tmpfs /var/lib/kubelet || exit 1
      mkdir -p /cri/kubelet-pods /var/lib/rancher/k3s/agent/etc/cni/net.d
      mount --make-rshared /cri || exit 1
      mount --bind /cri/kubelet-pods /cri/kubelet-pods || exit 1
      mount --make-rshared /cri/kubelet-pods || exit 1
      rm -rf /var/lib/kubelet/pods
      ln -sfn /cri/kubelet-pods /var/lib/kubelet/pods || exit 1
      mount --bind /cri/log-pods /var/log/pods || exit 1
      mount --bind /cri/run-flannel /run/flannel || exit 1
      mount --bind /cri/cni/net.d /var/lib/rancher/k3s/agent/etc/cni/net.d || exit 1
      if ! [ -e /dev/kmsg ]; then
        mknod /dev/kmsg c 1 11 || exit 1
      fi
      i=0
      while [ ! -S /cri/containerd.sock ]; do
        i=$((i+1))
        if [ $i -gt 120 ]; then echo "no containerd socket"; exit 1; fi
        sleep 1
      done
      i=0
      while [ ! -f /cri/pause-imported ]; do
        i=$((i+1))
        if [ $i -gt {airgap_wait} ]; then echo "airgap images not imported"; exit 1; fi
        sleep 1
      done
      i=0
      NODE_IP=""
      while [ -z "$NODE_IP" ]; do
        NODE_IP=$(ip -4 -o addr show eth0 | head -1 | tr -s " " | cut -d" " -f4 | cut -d/ -f1)
        if [ -n "$NODE_IP" ]; then break; fi
        i=$((i+1))
        if [ $i -gt 60 ]; then echo "no eth0 ip"; exit 1; fi
        sleep 1
      done
      {flatten_start}
      {k3s_cmd}
    securityContext:
      privileged: true
    resources:
      limits:
        memory: {memory_mb}Mi
    volumeMounts:
    - name: cri
      mountPath: /cri
  volumes:
  - name: cri
    emptyDir: {{}}
  - name: airgap
    hostPath:
      path: {INNER3_AIRGAP_DIR}
      type: Directory
"#
    ))
}

fn delete_inner3_pods() {
    delete_inner_pods(&default_profile());
}

fn delete_inner_pods(profile: &InnerClusterProfile) {
    for pod in profile.live_pods() {
        kubectl_delete_pod(&pod);
    }
}

/// Collect the k3s + containerd logs of all three pods for panic
/// messages.
fn inner3_logs() -> String {
    inner_logs(&default_profile())
}

fn inner_logs(profile: &InnerClusterProfile) -> String {
    let mut out = String::new();
    for pod in profile.live_pods() {
        for container in ["k3s", "containerd"] {
            let logs = Command::new("kubectl")
                .args(["logs", &pod, "-c", container, "--tail=80"])
                .output();
            if let Ok(logs) = logs {
                out.push_str(&format!(
                    "--- {pod}/{container} ---\n{}{}\n",
                    String::from_utf8_lossy(&logs.stdout),
                    String::from_utf8_lossy(&logs.stderr)
                ));
            }
        }
    }
    out
}

/// 3-node inner k3s cluster on one shared
/// cluster-mode bridge: server + two agents, flannel host-gw +
/// kube-proxy on the netfilter/veth/bridge guest kernel, and an inner
/// pause pod on an agent node reachable from the server node.
#[test]
fn test_inner_k3s_three_node_cluster_ready() {
    let _leak_guard = ensure_shim_installed();
    common::ensure_pod_annotations_forwarded();
    pull_k3s_image();
    stage_pause_airgap();

    delete_inner3_pods();
    thread::sleep(Duration::from_secs(3));

    for idx in 0..inner3_pods().len() {
        kubectl_apply(&inner3_pod_yaml(idx));
    }
    for pod in inner3_pods() {
        wait_for_pod_running(&pod, Duration::from_secs(300));
    }

    let profile = default_profile();
    let server_pod = inner3_pods()[0].clone();
    let inner_kubectl = "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl";

    // 1. All three inner nodes Ready. Three single-vCPU nested VMs
    //    bootstrap slowly — budget generously.
    let start = Instant::now();
    loop {
        let attempt = kubectl_exec_in(
            &server_pod,
            "k3s",
            &format!("{inner_kubectl} get nodes --no-headers 2>&1"),
        );
        if let Ok(ref text) = attempt {
            let all_ready = (0..profile.vm_count).all(|idx| {
                let node = profile.node_name(idx);
                text.lines().any(|l| {
                    let mut cols = l.split_whitespace();
                    cols.next() == Some(node.as_str()) && cols.next() == Some("Ready")
                })
            });
            if all_ready {
                break;
            }
        }
        if start.elapsed() > Duration::from_secs(600) {
            let logs = inner3_logs();
            delete_inner3_pods();
            panic!("3 inner nodes never all Ready (last attempt: {attempt:?})\n{logs}");
        }
        thread::sleep(Duration::from_secs(5));
    }

    // 2. Inner node identities are the stable cluster-mode guest IPs.
    for idx in 0..profile.vm_count {
        let node = profile.node_name(idx);
        let want_ip = profile.guest_ip(idx);
        let ip = kubectl_exec_retry(
            &server_pod,
            "k3s",
            &format!(
                "{inner_kubectl} get node {node} \
                 -o jsonpath='{{.status.addresses[?(@.type==\"InternalIP\")].address}}'"
            ),
            3,
        )
        .expect("query inner node InternalIP");
        assert_eq!(
            ip, want_ip,
            "inner node {node} InternalIP {ip} != stable guest IP {want_ip}"
        );
    }
    // Each guest's eth0 carries its 10.200.0.x address directly.
    for (idx, pod) in inner3_pods().iter().enumerate() {
        let want_ip = profile.guest_ip(idx);
        let eth0 =
            kubectl_exec_retry(pod, "k3s", "ip -4 -o addr show eth0", 3).expect("guest eth0");
        assert!(
            eth0.contains(&want_ip),
            "pod {pod} guest eth0 missing {want_ip}: {eth0}"
        );
    }

    // 3. Outer pod IPs are CNI-assigned and all differ (the shared
    //    bridge preserves guest identity; it does not collapse the
    //    outer pods into one address).
    let mut outer_ips = Vec::new();
    for pod in inner3_pods() {
        let out = Command::new("kubectl")
            .args(["get", "pod", &pod, "-o", "jsonpath={.status.podIP}"])
            .output()
            .expect("kubectl get pod IP");
        let ip = String::from_utf8_lossy(&out.stdout).trim().to_string();
        assert!(!ip.is_empty(), "outer pod {pod} has no podIP");
        outer_ips.push(ip);
    }
    for i in 0..outer_ips.len() {
        for j in (i + 1)..outer_ips.len() {
            assert_ne!(
                outer_ips[i],
                outer_ips[j],
                "outer pods {} and {} share pod IP {}",
                inner3_pods()[i],
                inner3_pods()[j],
                outer_ips[i]
            );
        }
    }

    // 4. Pinned inner CIDRs re-verified at 3 nodes: every podCIDR from
    //    10.60/16, the kubernetes Service VIP from 10.61/16.
    let cidrs = kubectl_exec_retry(
        &server_pod,
        "k3s",
        &format!("{inner_kubectl} get nodes -o jsonpath='{{.items[*].spec.podCIDR}}'"),
        3,
    )
    .expect("query inner podCIDRs");
    let cidr_list: Vec<&str> = cidrs.split_whitespace().collect();
    assert_eq!(
        cidr_list.len(),
        profile.vm_count,
        "expected {} inner podCIDRs: {cidrs}",
        profile.vm_count
    );
    for cidr in &cidr_list {
        assert!(
            cidr.starts_with("10.60."),
            "inner podCIDR {cidr} not from --cluster-cidr=10.60.0.0/16"
        );
    }
    let svc_ip = kubectl_exec_retry(
        &server_pod,
        "k3s",
        &format!("{inner_kubectl} get svc kubernetes -o jsonpath='{{.spec.clusterIP}}'"),
        3,
    )
    .expect("query kubernetes service ClusterIP");
    assert!(
        svc_ip.starts_with("10.61."),
        "kubernetes Service VIP {svc_ip} not from --service-cidr=10.61.0.0/16"
    );

    // 5. Schedule an inner pause pod on an agent node. No SA token
    //    automount: projected-token volumes are tmpfs mounts in the
    //    k3s container's mount ns, invisible to the sidecar's runc.
    let apply_pause = kubectl_exec_retry(
        &server_pod,
        "k3s",
        &format!(
            "cat > /tmp/inner-pause.yaml <<EOF\n\
             apiVersion: v1\n\
             kind: Pod\n\
             metadata:\n\
             \x20 name: inner-pause\n\
             spec:\n\
             \x20 nodeSelector:\n\
             \x20   kubernetes.io/hostname: {agent}\n\
             \x20 automountServiceAccountToken: false\n\
             \x20 containers:\n\
             \x20 - name: pause\n\
             \x20   image: {INNER3_PAUSE_REF}\n\
             \x20   imagePullPolicy: Never\n\
             EOF\n\
             {inner_kubectl} apply -f /tmp/inner-pause.yaml",
            agent = profile.node_name(1)
        ),
        3,
    );
    assert!(
        apply_pause.is_ok(),
        "inner pause apply failed: {apply_pause:?}"
    );

    let start = Instant::now();
    let pause_ip = loop {
        let status = kubectl_exec_in(
            &server_pod,
            "k3s",
            &format!(
                "{inner_kubectl} get pod inner-pause \
                 -o jsonpath='{{.status.phase}} {{.status.podIP}} {{.spec.nodeName}}' 2>&1"
            ),
        );
        if let Ok(ref text) = status {
            let mut cols = text.split_whitespace();
            if cols.next() == Some("Running") {
                let ip = cols.next().unwrap_or("").to_string();
                let node = cols.next().unwrap_or("");
                assert_eq!(
                    node,
                    profile.node_name(1),
                    "inner pause pod scheduled on {node}, expected {}",
                    profile.node_name(1)
                );
                if !ip.is_empty() {
                    break ip;
                }
            }
        }
        if start.elapsed() > Duration::from_secs(300) {
            let describe = kubectl_exec_in(
                &server_pod,
                "k3s",
                &format!("{inner_kubectl} describe pod inner-pause 2>&1 | tail -40"),
            );
            let logs = inner3_logs();
            delete_inner3_pods();
            panic!(
                "inner pause pod never Running (last: {status:?})\ndescribe: {describe:?}\n{logs}"
            );
        }
        thread::sleep(Duration::from_secs(5));
    };
    assert!(
        pause_ip.starts_with("10.60."),
        "inner pause pod IP {pause_ip} not from the inner cluster CIDR 10.60.0.0/16"
    );

    // 6. The pause pod on the agent node is reachable from the server
    //    node over the inner CNI path (flannel host-gw route via the
    //    shared L2 bridge into the agent guest's cni0). Routes can lag
    //    the pod start, so poll briefly.
    let start = Instant::now();
    loop {
        let ping = kubectl_exec_in(
            &server_pod,
            "k3s",
            &format!("ping -c 2 -W 3 {pause_ip} 2>&1"),
        );
        if ping.is_ok() {
            break;
        }
        if start.elapsed() > Duration::from_secs(60) {
            let routes = kubectl_exec_in(&server_pod, "k3s", "ip route 2>&1");
            let logs = inner3_logs();
            delete_inner3_pods();
            panic!(
                "inner pause pod {pause_ip} unreachable from server node: {ping:?}\n\
                 server guest routes: {routes:?}\n{logs}"
            );
        }
        thread::sleep(Duration::from_secs(3));
    }

    delete_inner3_pods();
}

// ──: warm cluster fork without restart ──

/// Drive-path note (parent status log): this test talks to the running
/// k7d daemon over `/run/k7d/k7d.sock` directly (`Client::connect_env`)
/// — it exercises the raw `TreeAdoptCluster` + `TreeFork` primitives.
/// The operator-facing kubectl-annotation route over the same
/// primitives is
/// `test_inner_k3s_cluster_warm_fork_via_annotation` (below).

/// Generous tree budget for 2 live 3-VM inner-k3s payloads (root + fork).
/// Default daemon budget is sized for 256 MiB busybox guests.
fn inner3_tree_budget() -> TreeBudget {
    TreeBudget {
        max_live_vms: 16,
        max_live_ram_bytes: 64 * 1024 * 1024 * 1024,
        max_disk_bytes: 128 * 1024 * 1024 * 1024,
        max_chain_depth: 8,
    }
}

/// Resolve the live `inner3` sandbox VMs (sorted by `vm_index`).
fn discover_inner3_vm_ids(client: &mut Client) -> Vec<String> {
    discover_inner_vm_ids(client, &default_profile())
}

fn discover_inner_vm_ids(client: &mut Client, profile: &InnerClusterProfile) -> Vec<String> {
    let Response::VmList { vms } = client.call(&Request::ListVms).expect("ListVms") else {
        panic!("ListVms returned unexpected response");
    };
    let mut found: Vec<(u32, String)> = Vec::new();
    for vm in vms {
        let Some(sandbox_id) = vm.sandbox_id else {
            continue;
        };
        match client.call(&Request::LookupSandbox { sandbox_id }) {
            Ok(Response::SandboxFound {
                vm_id,
                cluster_id: Some(cid),
                vm_index: Some(idx),
                ..
            }) if cid == inner3_cluster_id() => {
                found.push((idx, vm_id));
            }
            Ok(_) => {}
            Err(e) => panic!("LookupSandbox failed: {e}"),
        }
    }
    found.sort_by_key(|(idx, _)| *idx);
    assert_eq!(
        found.len(),
        profile.vm_count,
        "expected {} live VMs on cluster_id={}, found {found:?}",
        profile.vm_count,
        inner3_cluster_id()
    );
    for (i, (idx, _)) in found.iter().enumerate() {
        assert_eq!(*idx, i as u32, "vm_index gap in {found:?}");
    }
    found.into_iter().map(|(_, id)| id).collect()
}

/// Host directory holding the inner cluster's client TLS material,
/// extracted from the server pod's kubeconfig before adopt.
const INNER3_CERTS_DIR: &str = "/tmp/k7-inner3-certs";

/// Extract the admin client cert/key from the inner kubeconfig into
/// [`INNER3_CERTS_DIR`]. Probes/assertions authenticate with these
/// against the guest IPs directly (anonymous `/readyz` is rejected
/// with 401), and — crucially — from the host: only `curl
/// --interface <bridge>` can disambiguate the source and fork
/// clusters, which carry the *same* guest IPs on two bridges.
///
/// Historical note: this originally *had* to run pre-adopt because the
/// prepare swap killed virtiofs in the source (CHALLENGES.md #39). The
/// #39 fix keeps virtiofs-backed sources running in place, so in-guest
/// exec now survives adopt (asserted by the annotation test) —
/// extracting pre-adopt is merely the natural point in the flow.
fn extract_inner_certs() {
    let yaml = kubectl_exec_retry(&inner3_pods()[0], "k3s", "cat /etc/rancher/k3s/k3s.yaml", 5)
        .expect("read inner kubeconfig from server pod");
    let field = |key: &str| -> Vec<u8> {
        let line = yaml
            .lines()
            .find(|l| l.trim_start().starts_with(key))
            .unwrap_or_else(|| panic!("no {key} in inner kubeconfig"));
        let b64 = line
            .split_whitespace()
            .nth(1)
            .expect("kubeconfig field value");
        let out = Command::new("base64")
            .arg("-d")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut c| {
                use std::io::Write;
                c.stdin.as_mut().unwrap().write_all(b64.as_bytes())?;
                c.wait_with_output()
            })
            .expect("base64 -d");
        assert!(out.status.success(), "base64 -d failed for {key}");
        out.stdout
    };
    std::fs::create_dir_all(INNER3_CERTS_DIR).expect("create certs dir");
    std::fs::write(
        format!("{INNER3_CERTS_DIR}/client.pem"),
        field("client-certificate-data:"),
    )
    .expect("write client.pem");
    std::fs::write(
        format!("{INNER3_CERTS_DIR}/client-key.pem"),
        field("client-key-data:"),
    )
    .expect("write client-key.pem");
}

/// Authenticated HTTPS GET against an inner API server at
/// `10.200.0.2:6443`, egressing through `bridge_dev`. Three twists:
/// - `--interface` is load-bearing: source and fork clusters carry the
///   **same** guest IPs on two host bridges, so routing is ambiguous.
/// - `-k` (skip server-cert verification) is required: the guest mints
///   its PKI with the 1999 in-guest clock (CHALLENGES.md #37), so the
///   2026 host sees "certificate has expired". Client-cert auth still
///   runs — the server validates our cert against *its* clock — so
///   every sample is a full mutual-TLS round trip.
/// - Timeouts are sized ABOVE the fork's source-pause window (~6-7 s
///   for 3 × 2.6 GiB full copies): a connection opened mid-pause must
///   be allowed to complete via SYN retransmit after resume — that is
///   the survival property under test, not sub-pause latency.
fn curl_inner_api(bridge_dev: &str, path: &str) -> Result<String, String> {
    let url = format!("https://{}:6443{path}", default_profile().guest_ip(0));
    let out = Command::new("curl")
        .args([
            "-sSk",
            "--max-time",
            "30",
            "--connect-timeout",
            "20",
            "--interface",
            bridge_dev,
            "--cert",
            &format!("{INNER3_CERTS_DIR}/client.pem"),
            "--key",
            &format!("{INNER3_CERTS_DIR}/client-key.pem"),
            &url,
        ])
        .output()
        .map_err(|e| format!("spawn curl: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "curl {url} via {bridge_dev} exit {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Authenticated HTTPS POST of a JSON body against the inner API,
/// same certs and `--interface` as [`curl_inner_api`]. Post-fork,
/// this is the only way to create a pod on the fork (kubectl cannot
/// bind an interface; in-guest exec reaches only the source).
fn curl_inner_api_post(bridge_dev: &str, path: &str, json_body: &str) -> Result<String, String> {
    curl_inner_api_method(bridge_dev, "POST", path, Some(json_body))
}

/// Authenticated HTTPS DELETE against the inner API, same certs and
/// `--interface` as [`curl_inner_api`].
fn curl_inner_api_delete(bridge_dev: &str, path: &str) -> Result<String, String> {
    curl_inner_api_method(bridge_dev, "DELETE", path, None)
}

/// Authenticated HTTPS PATCH against the inner API. `content_type` is
/// the Kubernetes patch MIME (`application/json-patch+json`,
/// `application/strategic-merge-patch+json`, …). Post-fork this is the
/// only way to mutate an object on one bridge without touching the
/// other — kubectl cannot bind `--interface`.
fn curl_inner_api_patch(
    bridge_dev: &str,
    path: &str,
    content_type: &str,
    json_body: &str,
) -> Result<String, String> {
    let url = format!("https://{}:6443{path}", default_profile().guest_ip(0));
    let out = Command::new("curl")
        .args([
            "-sSk",
            "-X",
            "PATCH",
            "--max-time",
            "30",
            "--connect-timeout",
            "20",
            "--interface",
            bridge_dev,
            "--cert",
            &format!("{INNER3_CERTS_DIR}/client.pem"),
            "--key",
            &format!("{INNER3_CERTS_DIR}/client-key.pem"),
            "-H",
            &format!("Content-Type: {content_type}"),
            "--data-binary",
            json_body,
            &url,
        ])
        .output()
        .map_err(|e| format!("spawn curl PATCH: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "curl PATCH {url} via {bridge_dev} exit {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let body = String::from_utf8_lossy(&out.stdout).to_string();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
        if v["kind"] == "Status" && v["status"] == "Failure" {
            return Err(format!(
                "curl PATCH {url} via {bridge_dev} API failure: {body}"
            ));
        }
    }
    Ok(body)
}

fn curl_inner_api_method(
    bridge_dev: &str,
    method: &str,
    path: &str,
    json_body: Option<&str>,
) -> Result<String, String> {
    let url = format!("https://{}:6443{path}", default_profile().guest_ip(0));
    let mut cmd = Command::new("curl");
    cmd.args([
        "-sSk",
        "-X",
        method,
        "--max-time",
        "30",
        "--connect-timeout",
        "20",
        "--interface",
        bridge_dev,
        "--cert",
        &format!("{INNER3_CERTS_DIR}/client.pem"),
        "--key",
        &format!("{INNER3_CERTS_DIR}/client-key.pem"),
    ]);
    if let Some(body) = json_body {
        cmd.args([
            "-H",
            "Content-Type: application/json",
            "--data-binary",
            body,
        ]);
    }
    cmd.arg(&url);
    let out = cmd
        .output()
        .map_err(|e| format!("spawn curl {method}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "curl {method} {url} via {bridge_dev} exit {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let body = String::from_utf8_lossy(&out.stdout).to_string();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
        if v["kind"] == "Status" && v["status"] == "Failure" {
            return Err(format!(
                "curl {method} {url} via {bridge_dev} API failure: {body}"
            ));
        }
    }
    Ok(body)
}

/// Plain HTTP GET to `http://10.200.0.2:80<path>` through `bridge_dev`
/// with a `Host:` header. Fresh process every call — a cached connection
/// would not prove the fork's dataplane is live.
fn curl_inner_http(bridge_dev: &str, host_header: &str, path: &str) -> Result<String, String> {
    let url = format!("http://{}:80{path}", default_profile().guest_ip(0));
    let out = Command::new("curl")
        .args([
            "-sS",
            "--max-time",
            "15",
            "--connect-timeout",
            "10",
            "--interface",
            bridge_dev,
            "-H",
            &format!("Host: {host_header}"),
            &url,
        ])
        .output()
        .map_err(|e| format!("spawn curl: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "curl {url} Host:{host_header} via {bridge_dev} exit {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Names of the `k7-br-*` bridges currently on the host.
fn list_k7_bridges() -> Vec<String> {
    let out = Command::new("sh")
        .args(["-c", "ip -o link show | awk -F': ' '{print $2}'"])
        .output()
        .expect("ip link show");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.split('@').next().unwrap_or(l).trim().to_string())
        .filter(|n| n.starts_with("k7-br-"))
        .collect()
}

/// Long-lived watch stream against the source API server — one held
/// TCP/TLS session that must survive the fork (the headline).
/// `curl -N …?watch=true` blocks streaming events until killed; if the
/// connection resets, curl exits on its own.
fn start_held_watch(bridge_dev: &str) -> std::process::Child {
    Command::new("curl")
        .args([
            "-sNk",
            "--max-time",
            "600",
            "--interface",
            bridge_dev,
            "--cert",
            &format!("{INNER3_CERTS_DIR}/client.pem"),
            "--key",
            &format!("{INNER3_CERTS_DIR}/client-key.pem"),
            &format!(
                "https://{}:6443/api/v1/nodes?watch=true",
                default_profile().guest_ip(0)
            ),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn held watch curl")
}

/// Poll `/api/v1/nodes` through `bridge_dev` until every inner node
/// reports `Ready` with its stable guest-IP identity.
fn assert_three_ready_nodes_via(bridge_dev: &str, label: &str) {
    assert_ready_nodes_via(&default_profile(), bridge_dev, label);
}

fn assert_ready_nodes_via(profile: &InnerClusterProfile, bridge_dev: &str, label: &str) {
    let start = Instant::now();
    let want = profile.vm_count;
    loop {
        let last = curl_inner_api(bridge_dev, "/api/v1/nodes");
        if let Ok(ref body) = last {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                let empty = Vec::new();
                let items = json["items"].as_array().unwrap_or(&empty);
                let mut ready = 0;
                let mut ip_ok = 0;
                for idx in 0..profile.vm_count {
                    let node = profile.node_name(idx);
                    let want_ip = profile.guest_ip(idx);
                    let Some(item) = items
                        .iter()
                        .find(|i| i["metadata"]["name"].as_str() == Some(node.as_str()))
                    else {
                        continue;
                    };
                    let is_ready = item["status"]["conditions"]
                        .as_array()
                        .unwrap_or(&empty)
                        .iter()
                        .any(|c| {
                            c["type"].as_str() == Some("Ready")
                                && c["status"].as_str() == Some("True")
                        });
                    if is_ready {
                        ready += 1;
                    }
                    let has_ip = item["status"]["addresses"]
                        .as_array()
                        .unwrap_or(&empty)
                        .iter()
                        .any(|a| {
                            a["type"].as_str() == Some("InternalIP")
                                && a["address"].as_str() == Some(want_ip.as_str())
                        });
                    if has_ip {
                        ip_ok += 1;
                    }
                }
                if ready == want && ip_ok == want {
                    return;
                }
            }
        }
        if start.elapsed() > Duration::from_secs(240) {
            let brief = match &last {
                // char-based truncation: slicing bytes could split a
                // UTF-8 code point in a k8s error message and panic.
                Ok(b) => format!("body: {}", b.chars().take(2000).collect::<String>()),
                Err(e) => format!("error: {e}"),
            };
            panic!(
                "{label}: {want} Ready nodes at stable IPs never observed via {bridge_dev} ({brief})"
            );
        }
        thread::sleep(Duration::from_secs(3));
    }
}

/// Deploy a pause Deployment and churn the API so the warm
/// fork copies real dirty pages. HostNetwork www images fail nested
/// etc-hosts binds (CHALLENGES #50); nested runc needs guest
/// `CONFIG_CFS_BANDWIDTH` for `cpu.max` (CHALLENGES #51). Post-fork we
/// assert via the apiserver on each bridge.
fn deploy_inner_workload_and_churn() {
    let server_pod = inner3_pods()[0].clone();
    let inner_kubectl = "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl";

    let apply = kubectl_exec_retry(
        &server_pod,
        "k3s",
        &format!(
            r#"cat > /tmp/inner-load.yaml <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: inner-load
spec:
  replicas: 3
  selector:
    matchLabels:
      app: inner-load
  template:
    metadata:
      labels:
        app: inner-load
    spec:
      automountServiceAccountToken: false
      containers:
      - name: pause
        image: {INNER3_PAUSE_REF}
        imagePullPolicy: Never
EOF
{inner_kubectl} apply -f /tmp/inner-load.yaml && \
{inner_kubectl} rollout status deploy/inner-load --timeout=180s && echo deploy-ok
"#
        ),
        3,
    );
    assert!(
        matches!(apply, Ok(ref s) if s.contains("deploy-ok")),
        "inner-load Deployment failed: {apply:?}"
    );

    // Churn: scale up/down + ConfigMap storm + short-lived pause pods.
    let scale = kubectl_exec_retry(
        &server_pod,
        "k3s",
        &format!(
            "{inner_kubectl} scale deploy/inner-load --replicas=6 && \
             {inner_kubectl} rollout status deploy/inner-load --timeout=120s && \
             {inner_kubectl} scale deploy/inner-load --replicas=3 && \
             {inner_kubectl} rollout status deploy/inner-load --timeout=120s && \
             for i in $(seq 1 12); do \
               {inner_kubectl} create configmap churn-cm-$i --from-literal=k=$i || true; \
             done && echo scale-ok"
        ),
        2,
    );
    assert!(
        matches!(scale, Ok(ref s) if s.contains("scale-ok")),
        "inner-load scale/ConfigMap churn failed: {scale:?}"
    );
    for i in 1..=8 {
        let _ = kubectl_exec_in(
            &server_pod,
            "k3s",
            &format!(
                "cat > /tmp/pause-{i}.yaml <<EOF\n\
                 apiVersion: v1\n\
                 kind: Pod\n\
                 metadata:\n\
                 \x20 name: churn-pause-{i}\n\
                 spec:\n\
                 \x20 automountServiceAccountToken: false\n\
                 \x20 containers:\n\
                 \x20 - name: pause\n\
                 \x20   image: {INNER3_PAUSE_REF}\n\
                 \x20   imagePullPolicy: Never\n\
                 EOF\n\
                 {inner_kubectl} apply -f /tmp/pause-{i}.yaml"
            ),
        );
    }
    thread::sleep(Duration::from_secs(3));
    for i in 1..=8 {
        let _ = kubectl_exec_in(
            &server_pod,
            "k3s",
            &format!("{inner_kubectl} delete pod churn-pause-{i} --force --grace-period=0"),
        );
    }
    for i in 1..=12 {
        let _ = kubectl_exec_in(
            &server_pod,
            "k3s",
            &format!("{inner_kubectl} delete configmap churn-cm-{i} --ignore-not-found"),
        );
    }
    eprintln!("  inner workload + churn ready (pause Deployment scale + API storm)");
}

/// Ready replicas of `inner-load` via the authenticated apiserver on
/// `bridge` (works for source and fork — same guest VIP, different L2).
fn assert_inner_load_ready_via(bridge: &str, label: &str) {
    let path = "/apis/apps/v1/namespaces/default/deployments/inner-load";
    let start = Instant::now();
    loop {
        match curl_inner_api(bridge, path) {
            Ok(body) => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                    let ready = v["status"]["readyReplicas"].as_u64().unwrap_or(0);
                    let desired = v["spec"]["replicas"].as_u64().unwrap_or(0);
                    if ready >= 3 && desired >= 3 {
                        eprintln!("  {label}: inner-load readyReplicas={ready}/{desired}");
                        return;
                    }
                    eprintln!(
                        "  {label}: inner-load not ready yet ready={ready} desired={desired}"
                    );
                }
            }
            Err(e) => eprintln!("  {label}: deploy get via {bridge}: {e}"),
        }
        if start.elapsed() > Duration::from_secs(60) {
            panic!("{label}: inner-load never showed ≥3 readyReplicas via {bridge}");
        }
        thread::sleep(Duration::from_secs(2));
    }
}

/// Bring the three-pod fixture to "3 Ready nodes", deploy the dirtier
/// workload, and leave the pods running for adopt/fork.
fn bring_up_inner3_cluster() {
    bring_up_inner_cluster(&default_profile());
}

fn bring_up_inner_cluster(profile: &InnerClusterProfile) {
    common::ensure_pod_annotations_forwarded();
    pull_k3s_image();
    stage_profile_airgap(profile);
    delete_inner_pods(profile);
    thread::sleep(Duration::from_secs(3));

    for idx in 0..profile.vm_count {
        kubectl_apply(&inner_pod_yaml(profile, idx));
    }
    for pod in profile.live_pods() {
        wait_for_pod_running(&pod, Duration::from_secs(300));
    }

    // The airgap RO hostPath rides a cached erofs
    // image on virtio-blk, so cluster pods must carry ZERO virtiofs
    // shares — that is what puts adopt/fork on the CoW path. Assert
    // BEFORE adopt: the daemon drops the sandbox records at adopt,
    // after which vm_status can no longer see these VMs.
    for pod in profile.live_pods() {
        let vm = common::pod_vm_state(&pod);
        assert_eq!(
            vm.virtiofs_shares, 0,
            "{pod}: cluster pods must be share-less (RO hostPath on virtio-blk); \
             a virtiofs share here silently degrades the fork to full-copy"
        );
        assert!(
            vm.block_devices >= 3,
            "{pod}: expected tools + rootfs + airgap erofs devices, got {}",
            vm.block_devices
        );
    }
    // The airgap dir must be readable in-guest from the erofs image
    // (the sidecar already imported pause.tar from it to get here, but
    // assert the mount explicitly so a regression is pinpointed).
    let server_pod = profile.live_pod(0);
    let airgap = kubectl_exec_retry(
        &server_pod,
        "containerd",
        "test -f /airgap/pause.tar && echo airgap-ok",
        5,
    );
    assert!(
        matches!(airgap, Ok(ref out) if out.contains("airgap-ok")),
        "airgap hostPath not readable in-guest from the erofs image: {airgap:?}"
    );

    // No CNI, no Ready node: kubelet holds the node NotReady until a
    // conflist exists, so on the Cilium profile the datapath has to be
    // installed *before* the Ready loop below can ever succeed. The
    // agents themselves are hostNetwork, which is what breaks the
    // circle.
    if profile.cni == InnerCni::Cilium {
        install_cilium(profile);
    }

    let inner_kubectl = "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl";
    let start = Instant::now();
    loop {
        let attempt = kubectl_exec_in(
            &server_pod,
            "k3s",
            &format!("{inner_kubectl} get nodes --no-headers 2>&1"),
        );
        if let Ok(ref text) = attempt {
            let all_ready = (0..profile.vm_count).all(|idx| {
                let node = profile.node_name(idx);
                text.lines().any(|l| {
                    let mut cols = l.split_whitespace();
                    cols.next() == Some(node.as_str()) && cols.next() == Some("Ready")
                })
            });
            if all_ready {
                if profile.addons.coredns {
                    patch_coredns_for_nested_runc(profile);
                }
                if profile.addons.local_storage {
                    patch_local_path_for_nested_runc(profile);
                }
                if profile.addons.metrics_server {
                    patch_metrics_server_for_nested_runc(profile);
                }
                deploy_inner_workload_and_churn();
                return;
            }
        }
        if start.elapsed() > Duration::from_secs(600) {
            let logs = inner_logs(profile);
            delete_inner_pods(profile);
            panic!(
                "cluster bring-up: {} inner nodes never Ready (last: {attempt:?})\n{logs}",
                profile.vm_count
            );
        }
        thread::sleep(Duration::from_secs(5));
    }
}

/// Warm-fork the live 3-VM inner-k3s cluster
/// without restarting the source control plane.
#[test]
fn test_inner_k3s_cluster_warm_fork_no_restart() {
    let _leak_guard = ensure_shim_installed();
    bring_up_inner3_cluster();

    // Certs come out pre-adopt. (Historical: adopt/prepare used to
    // kill in-guest exec by re-CIDing the source — CHALLENGES.md #39.
    // Preserves the CID, proven post-fork below; the
    // pre-adopt extraction simply keeps this test's probe path
    // independent of that fix.)
    extract_inner_certs();
    // `cluster_id` is ≤ 9 chars so `k7-br-{id}` fits IFNAMSIZ; stale
    // bridges from crashed runs may coexist.
    let source_bridge = inner3_bridge();
    let bridges_before = list_k7_bridges();
    assert!(
        bridges_before.contains(&source_bridge),
        "inner3 bridge missing: {bridges_before:?}"
    );
    // Pre-adopt sanity: the authenticated host-side path works.
    let ready = curl_inner_api(&source_bridge, "/readyz").expect("pre-adopt /readyz");
    assert!(ready.contains("ok"), "pre-adopt /readyz not ok: {ready}");

    let mut client = Client::connect_env().expect("connect k7d daemon");
    let vm_ids = discover_inner3_vm_ids(&mut client);
    eprintln!("  discovered inner3 vm_ids={vm_ids:?}");

    // Adopt first (prepare_fork_source pauses each member for seconds
    // to snapshot 2.6 GiB — a probe started before adopt would
    // false-fail). Required order: prepare → probe → fork.
    let tree_id = format!("inner3-adopt-{}", std::process::id());
    let (tree_id, root_id, root_cids) = match client.call(&Request::TreeAdoptCluster {
        ksm: false,
        vm_ids,
        budget: Some(inner3_tree_budget()),
        tree_id: Some(tree_id),
        egress: None,
        dilation_policy: None,
        dilation_config: None,
    }) {
        Ok(Response::TreeCreated {
            tree_id,
            root_id,
            guest_cids,
            ..
        }) => {
            assert_eq!(guest_cids.len(), 3, "adopted root must have 3 members");
            (tree_id, root_id, guest_cids)
        }
        Ok(other) => {
            delete_inner3_pods();
            panic!("unexpected TreeAdoptCluster response: {other:?}");
        }
        Err(e) => {
            delete_inner3_pods();
            panic!("TreeAdoptCluster transport error: {e}");
        }
    };
    common::mark_test_tree(&tree_id);
    eprintln!("  adopted tree={tree_id} root_cids={root_cids:?}");

    // A `TreeDrop`-based teardown for every failure exit below.
    let teardown = |client: &mut Client| {
        let _ = client.call(&Request::TreeDrop {
            tree_id: tree_id.clone(),
        });
        delete_inner3_pods();
        let _ = std::fs::remove_dir_all(format!("/var/lib/k7d/trees/{tree_id}"));
    };

    // Wait for the source API server to answer again post-prepare.
    let start = Instant::now();
    loop {
        if matches!(curl_inner_api(&source_bridge, "/readyz"), Ok(ref b) if b.contains("ok")) {
            break;
        }
        if start.elapsed() > Duration::from_secs(120) {
            let last = curl_inner_api(&source_bridge, "/readyz");
            teardown(&mut client);
            panic!("source API never recovered after adopt/prepare (last: {last:?})");
        }
        thread::sleep(Duration::from_secs(2));
    }

    // Held watch stream: one TCP/TLS session that must survive the fork
    // (the headline). New /readyz connections during the ~8 s source
    // pause can flake — do not sample those; poll explicitly after resume
    // (CHALLENGES #42).
    let mut watch = start_held_watch(&source_bridge);
    thread::sleep(Duration::from_secs(1));
    assert!(
        watch.try_wait().expect("watch try_wait").is_none(),
        "held watch stream died before the fork"
    );

    let fork_start = Instant::now();
    let (fork_node, fork_cids, latency_ns) = match client.call(&Request::TreeFork {
        tree_id: tree_id.clone(),
        source_id: root_id.clone(),
        label: "warm".to_string(),
        dilation: None,
        dilation_policy: None,
        dilation_config: None,
    }) {
        Ok(Response::TreeForked {
            node_id,
            guest_cids,
            fork_memory_full_copy,
            latency_ns,
            ..
        }) => {
            assert_eq!(guest_cids.len(), 3, "fork must clone every member");
            // Share-less cluster members must ride the
            // CoW path — a full memfd copy anywhere is a regression to
            // the slow fork (and would blow the < 1 s budget below).
            assert_eq!(
                fork_memory_full_copy,
                vec![false; 3],
                "inner-k3s cluster fork must be CoW on every member"
            );
            (node_id, guest_cids, latency_ns)
        }
        Ok(other) => {
            let _ = watch.kill();
            teardown(&mut client);
            panic!("unexpected TreeFork response: {other:?}");
        }
        Err(e) => {
            let _ = watch.kill();
            teardown(&mut client);
            panic!("TreeFork transport error: {e}");
        }
    };
    let fork_elapsed = fork_start.elapsed();
    eprintln!(
        "  TreeFork node={fork_node} cids={fork_cids:?} elapsed={fork_elapsed:?} \
         budget={FORK_INNER_K3S_CLUSTER_3VM:?}"
    );
    // Surface the daemon's per-member memfd copy and
    // materialise timings (plus the cluster total) in the test output so
    // budget regressions are diagnosable from the test log alone.
    if let Ok(journal) = Command::new("journalctl")
        .args(["-u", "k7d", "--no-pager", "--since", "-3min"])
        .output()
    {
        for line in String::from_utf8_lossy(&journal.stdout)
            .lines()
            .filter(|l| {
                l.contains("full memfd copy")
                    || l.contains("fork_cluster_warm")
                    || l.contains("cluster_tree fork_batch")
            })
        {
            eprintln!("  daemon: {line}");
        }
    }
    common::tree_fork_budget::assert_tree_fork_budget(
        "inner-k3s cluster",
        fork_elapsed,
        latency_ns,
        FORK_INNER_K3S_CLUSTER_3VM,
    );

    // The fork's bridge is the one that appeared during TreeFork.
    let fork_bridge = list_k7_bridges()
        .into_iter()
        .find(|b| !bridges_before.contains(b))
        .expect("fork bridge appeared");
    eprintln!("  source bridge={source_bridge} fork bridge={fork_bridge}");

    let watch_alive = watch.try_wait().expect("watch try_wait").is_none();
    let watch_kill = watch.kill();
    assert!(
        watch_alive,
        "held watch TCP/TLS session against the source broke across the fork"
    );
    let _ = watch_kill;

    // Explicit post-resume /readyz (not a background sampler that can
    // classify a mid-pause handshake failure as the only "post" sample).
    let resume = Instant::now();
    loop {
        if matches!(curl_inner_api(&source_bridge, "/readyz"), Ok(ref b) if b.contains("ok")) {
            break;
        }
        if resume.elapsed() > Duration::from_secs(60) {
            let last = curl_inner_api(&source_bridge, "/readyz");
            teardown(&mut client);
            panic!("source /readyz never recovered after TreeFork resume (last: {last:?})");
        }
        thread::sleep(Duration::from_millis(500));
    }

    // CID stability: adopt swapped each share-less
    // source for a restored copy on the SAME vsock CID, so the member
    // pods' shims (which cached that CID at Create and dial it fresh
    // per exec) must still reach their guests.
    let echo = kubectl_exec_retry(&inner3_pods()[0], "k3s", "echo post-fork-exec-ok", 5);
    match echo {
        Ok(ref out) if out.contains("post-fork-exec-ok") => {}
        other => {
            teardown(&mut client);
            panic!("post-fork exec into the source server pod failed: {other:?}");
        }
    }

    // Source still healthy; fork independently shows the same 3 Ready
    // nodes at the preserved guest IPs (interface-bound: same IPs on
    // two bridges).
    assert_three_ready_nodes_via(&source_bridge, "source");
    assert_three_ready_nodes_via(&fork_bridge, "fork");

    // Dirtier fixture — pause Deployment must still report
    // ≥3 readyReplicas on both bridges (workload state, not just /readyz).
    assert_inner_load_ready_via(&source_bridge, "source");
    assert_inner_load_ready_via(&fork_bridge, "fork");

    // Teardown: tree drop tears down both live payloads + bridges;
    // pod delete is best-effort (StopVm → "no such VM"); wipe on-disk
    // tree state so 3×~2.6 GiB base.mem files don't fill the node.
    // Set `K7_KEEP_INNER3=1` to leave the outer pods for the demo.
    if std::env::var_os("K7_KEEP_INNER3").is_some() {
        let _ = client.call(&Request::TreeDrop {
            tree_id: tree_id.clone(),
        });
        let _ = std::fs::remove_dir_all(format!("/var/lib/k7d/trees/{tree_id}"));
        eprintln!("  K7_KEEP_INNER3 set — outer pods left running for demo");
    } else {
        teardown(&mut client);
    }
}

// ──: annotation-driven cluster fork ──

/// Fork-trigger pod: its `k7d.katakate.org/tree-*`
/// annotations make the shim adopt the live inner3 cluster and fork it
/// during this pod's own sandbox Create.
const INNER3_TRIGGER_POD: &str = "test-inner3-fork-trigger";

/// Manifest for the fork-trigger pod. A plain BestEffort k7 pod (its
/// own VM and bridge — deliberately NOT on [`inner3_cluster_id()`]; the
/// shim rejects a trigger that is a member of the cluster it adopts)
/// whose annotations carry the whole contract: adopt `inner3`
/// as the root of `tree_id`, then fork `root` under label `warm`.
/// The pod reaching Running IS the success signal — the shim fails
/// sandbox Create loudly when adopt or fork fails.
fn fork_trigger_pod_yaml(tree_id: &str) -> String {
    let budget = serde_json::to_string(&inner3_tree_budget()).expect("serialize TreeBudget");
    let trigger = inner3_trigger_pod();
    let cluster_id = inner3_cluster_id();
    common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {trigger}
  annotations:
    k7d.katakate.org/tree-id: "{tree_id}"
    k7d.katakate.org/tree-adopt-cluster: "{cluster_id}"
    k7d.katakate.org/tree-fork-from: "root"
    k7d.katakate.org/tree-fork-label: "warm"
    k7d.katakate.org/tree-budget: '{budget}'
spec:
  runtimeClassName: k7
  restartPolicy: Never
  containers:
  - name: trigger
    image: {K3S_IMAGE}
    imagePullPolicy: IfNotPresent
    command: ["/bin/sh", "-c", "sleep infinity"]
"#
    ))
}

/// The warm fork driven entirely by
/// kubectl: a trigger pod's `k7d.katakate.org/tree-*` annotations make
/// the shim call `TreeAdoptCluster` + `TreeFork`. No
/// `Client::connect_env` for the fork itself — the daemon socket is
/// only used for teardown (`TreeDrop`), which is allowed.
///
/// The held watch stream starts BEFORE the trigger pod is applied and
/// must survive both the adopt pause (root snapshot) and the fork
/// pause — unlike the socket-driven route there is no gap between the two
/// to start a probe in, which makes this the stronger survival claim.
#[test]
fn test_inner_k3s_cluster_warm_fork_via_annotation() {
    let _leak_guard = ensure_shim_installed();
    bring_up_inner3_cluster();

    // Certs come out pre-adopt as before (host-side authenticated
    // probes are the assertion path either way).
    extract_inner_certs();
    let source_bridge = inner3_bridge();
    let bridges_before = list_k7_bridges();
    assert!(
        bridges_before.contains(&source_bridge),
        "inner3 bridge missing: {bridges_before:?}"
    );
    let ready = curl_inner_api(&source_bridge, "/readyz").expect("pre-fork /readyz");
    assert!(ready.contains("ok"), "pre-fork /readyz not ok: {ready}");

    kubectl_delete_pod(inner3_trigger_pod());
    thread::sleep(Duration::from_secs(2));

    // One held TCP/TLS session against the source API server across
    // the whole annotation-driven adopt + fork (the headline).
    let mut watch = start_held_watch(&source_bridge);
    thread::sleep(Duration::from_secs(1));
    assert!(
        watch.try_wait().expect("watch try_wait").is_none(),
        "held watch stream died before the trigger pod was applied"
    );

    let tree_id = format!("inner3-ann-{}", std::process::id());
    let teardown = || {
        // Socket use here is teardown-only (allowed).
        if let Ok(mut client) = Client::connect_env() {
            let _ = client.call(&Request::TreeDrop {
                tree_id: tree_id.clone(),
            });
        }
        kubectl_delete_pod(inner3_trigger_pod());
        delete_inner3_pods();
        let _ = std::fs::remove_dir_all(format!("/var/lib/k7d/trees/{tree_id}"));
    };

    // The kubectl drive path: apply the trigger pod; its sandbox
    // Create performs adopt + fork. Running == both succeeded.
    kubectl_apply(&fork_trigger_pod_yaml(&tree_id));
    wait_for_pod_running(inner3_trigger_pod(), Duration::from_secs(420));
    common::mark_test_tree(&tree_id);

    // The held session must still be alive after adopt + fork.
    let watch_alive = watch.try_wait().expect("watch try_wait").is_none();
    let _ = watch.kill();
    if !watch_alive {
        teardown();
        panic!("held watch TCP/TLS session against the source broke across the annotation fork");
    }

    // Source /readyz recovers after the resume.
    let resume = Instant::now();
    loop {
        if matches!(curl_inner_api(&source_bridge, "/readyz"), Ok(ref b) if b.contains("ok")) {
            break;
        }
        if resume.elapsed() > Duration::from_secs(60) {
            let last = curl_inner_api(&source_bridge, "/readyz");
            teardown();
            panic!("source /readyz never recovered after the annotation fork (last: {last:?})");
        }
        thread::sleep(Duration::from_millis(500));
    }

    // Criterion "shim CIDs still valid / exec still works": the
    // member pods' shims still dial their cached vsock CIDs (the shim
    // failed the trigger Create if adopt changed any CID).
    // The members are share-less, so prepare swapped each for a
    // restored copy on the SAME CID — this exec proves the preserved
    // CID answers.
    let echo = kubectl_exec_retry(&inner3_pods()[0], "k3s", "echo post-adopt-exec-ok", 5);
    match echo {
        Ok(ref out) if out.contains("post-adopt-exec-ok") => {}
        other => {
            teardown();
            panic!("post-adopt exec into the source server pod failed: {other:?}");
        }
    }

    // The fork bridge is the new 3-port bridge (the trigger pod's own
    // TAP goes into its pod and never builds a network namespace).
    let fork_bridge = list_k7_bridges()
        .into_iter()
        .filter(|b| !bridges_before.contains(b))
        .find(|b| common::k7_bridge_port_count(b) == 3);
    let Some(fork_bridge) = fork_bridge else {
        teardown();
        panic!("no new 3-port fork bridge appeared");
    };
    eprintln!("  source bridge={source_bridge} fork bridge={fork_bridge}");

    // Source still healthy; the fork independently shows the same 3
    // Ready nodes at the preserved guest IPs.
    assert_three_ready_nodes_via(&source_bridge, "source");
    assert_three_ready_nodes_via(&fork_bridge, "fork");

    teardown();
}

/// Mechanical pin: the default profile renders today's k3s server CLI
/// for both the single-node and 3-node fixtures.
#[test]
fn default_profile_renders_today_k3s_server_flags() {
    let p = InnerClusterProfile::default_3node();
    assert_eq!(p.cluster_id, "inner3");
    assert_eq!(p.vm_count, 3);
    assert_eq!(p.memory_mb, INNER_K3S_MEMORY_MB);
    assert_eq!(p.sidecar_memory_mb, INNER_K3S_SIDECAR_MEMORY_MB);
    assert_eq!(p.containerd_tmpfs_mb(), 512);
    assert_eq!(p.pod_name(0), "test-inner-k3s-3n-server");
    assert_eq!(p.pod_name(1), "test-inner-k3s-3n-agent-0");
    assert_eq!(p.pod_name(2), "test-inner-k3s-3n-agent-1");
    assert_eq!(p.node_name(0), "inner-server");
    assert_eq!(p.node_name(1), "inner-agent-0");
    assert_eq!(p.node_name(2), "inner-agent-1");
    assert_eq!(p.guest_ip(0), "10.200.0.2");
    assert_eq!(p.guest_ip(1), "10.200.0.3");
    assert_eq!(p.guest_ip(2), "10.200.0.4");

    assert_eq!(
        p.addons.disable_flags(),
        "--disable-network-policy --disable-helm-controller --disable=coredns,traefik,servicelb,metrics-server,local-storage"
    );
    assert_eq!(
        p.single_node_server_flags(),
        vec![
            "--container-runtime-endpoint=unix:///cri/containerd.sock",
            "--cluster-cidr=10.60.0.0/16",
            "--service-cidr=10.61.0.0/16",
            "--flannel-backend=none",
            "--disable-kube-proxy",
            "--disable-network-policy",
            "--disable-cloud-controller",
            "--disable-helm-controller",
            "--disable=coredns,traefik,servicelb,metrics-server,local-storage",
            "--node-ip=\"$NODE_IP\"",
            "--node-name=inner-server",
            "--write-kubeconfig-mode=644",
        ]
    );
    assert_eq!(
        p.cluster_server_flags("inner-server"),
        vec![
            format!("--token={INNER3_TOKEN}"),
            "--container-runtime-endpoint=unix:///cri/containerd.sock".into(),
            "--cluster-cidr=10.60.0.0/16".into(),
            "--service-cidr=10.61.0.0/16".into(),
            "--flannel-backend=host-gw".into(),
            "--disable-network-policy".into(),
            "--disable-cloud-controller".into(),
            "--disable-helm-controller".into(),
            "--disable=coredns,traefik,servicelb,metrics-server,local-storage".into(),
            "--node-ip=\"$NODE_IP\"".into(),
            "--node-name=inner-server".into(),
            "--write-kubeconfig-mode=644".into(),
        ]
    );

    let cd = InnerClusterProfile::coredns_3node();
    assert!(cd.addons.coredns);
    assert_eq!(
        cd.addons.disable_flags(),
        "--disable-network-policy --disable-helm-controller --disable=traefik,servicelb,metrics-server,local-storage"
    );

    let ing = InnerClusterProfile::ingress_3node();
    assert!(ing.addons.coredns && ing.addons.traefik && ing.addons.servicelb);
    assert!(ing.addons.helm_controller);
    assert_eq!(ing.sidecar_memory_mb, 1536);
    assert_eq!(ing.containerd_tmpfs_mb(), 1408);
    assert_eq!(
        ing.addons.disable_flags(),
        "--disable-network-policy --disable=metrics-server,local-storage"
    );

    let lpp = InnerClusterProfile::local_path_3node();
    assert!(lpp.addons.coredns && lpp.addons.local_storage);
    assert!(!lpp.addons.traefik && !lpp.addons.helm_controller);
    assert_eq!(
        lpp.addons.disable_flags(),
        "--disable-network-policy --disable-helm-controller --disable=traefik,servicelb,metrics-server"
    );

    let ms = InnerClusterProfile::metrics_3node();
    assert!(ms.addons.coredns && ms.addons.metrics_server);
    assert!(!ms.addons.local_storage && !ms.addons.traefik && !ms.addons.helm_controller);
    assert_eq!(ms.sidecar_memory_mb, INNER_K3S_SIDECAR_MEMORY_MB);
    assert_eq!(
        ms.addons.disable_flags(),
        "--disable-network-policy --disable-helm-controller --disable=traefik,servicelb,local-storage"
    );

    let np = InnerClusterProfile::network_policy_3node();
    assert!(np.addons.coredns && np.addons.network_policy);
    assert!(!np.addons.traefik && !np.addons.local_storage && !np.addons.helm_controller);
    assert_eq!(np.sidecar_memory_mb, INNER_K3S_SIDECAR_MEMORY_MB);
    assert_eq!(p.datastore, InnerDatastore::Sqlite);
    assert_eq!(
        np.addons.disable_flags(),
        "--disable-helm-controller --disable=traefik,servicelb,metrics-server,local-storage"
    );
    // With network-policy enabled the anchor flag is gone, so the
    // call-site cloud-controller flag must lead the rendered list.
    assert_eq!(
        np.addons.disable_flags_with_cloud_controller(),
        vec![
            "--disable-cloud-controller",
            "--disable-helm-controller",
            "--disable=traefik,servicelb,metrics-server,local-storage",
        ]
    );

    let default_yaml = inner_pod_yaml(&p, 0);
    assert!(
        !default_yaml.contains("flatten-vols.sh") && !default_yaml.contains("/cri/k3s-storage"),
        "default profile must not install the nested-runc flattener or local-path bind"
    );
    let ing_yaml = inner_pod_yaml(&ing, 0);
    assert!(
        ing_yaml.contains("flatten-vols.sh") && ing_yaml.contains("find \"$SRC\" -type f"),
        "ingress profile must install the /cri kubelet-file flattener"
    );
    let lpp_yaml = inner_pod_yaml(&lpp, 0);
    assert!(
        lpp_yaml.contains("flatten-vols.sh")
            && lpp_yaml.contains("/cri/k3s-storage")
            && lpp_yaml.contains("mount --make-rshared /cri/kubelet-pods"),
        "local-path profile must bind storage onto /cri, rshared-bind kubelet-pods, and flatten"
    );
    // metrics-server needs no volume rewrite: its only hostPath is the
    // staged SA dir, patched onto the Deployment after bring-up.
    let ms_yaml = inner_pod_yaml(&ms, 0);
    assert!(
        !ms_yaml.contains("flatten-vols.sh") && !ms_yaml.contains("/cri/k3s-storage"),
        "metrics-server profile must not install the flattener or the local-path bind"
    );
    // The netpol controller lives inside the k3s process; the profile
    // must not change the pod plumbing, only the rendered CLI.
    let np_yaml = inner_pod_yaml(&np, 0);
    assert!(
        !np_yaml.contains("--disable-network-policy")
            && !np_yaml.contains("flatten-vols.sh")
            && !np_yaml.contains("/cri/k3s-storage"),
        "network-policy profile must only drop the disable flag"
    );
    assert!(
        !default_yaml.contains("--cluster-init"),
        "default profile must stay sqlite (no --cluster-init)"
    );
    let etcd = InnerClusterProfile::etcd_3node();
    assert!(etcd.addons.coredns);
    assert_eq!(etcd.datastore, InnerDatastore::Etcd);
    assert_eq!(etcd.memory_mb, INNER_K3S_MEMORY_MB);
    assert!(
        etcd.cluster_server_flags("inner-server")
            .iter()
            .any(|f| f == "--cluster-init"),
        "etcd_3node must add --cluster-init to the 3-node server args"
    );
    assert!(
        !p.cluster_server_flags("inner-server")
            .iter()
            .any(|f| f == "--cluster-init"),
        "default 3-node server args must stay sqlite"
    );
    let etcd_yaml = inner_pod_yaml(&etcd, 0);
    assert!(
        etcd_yaml.contains("--cluster-init"),
        "etcd_3node YAML must pass --cluster-init to k3s server"
    );
    // The Cilium profile is the only one that must drop flannel and
    // kube-proxy from the 3-node CLI, and it must drop *both*: with one
    // of them left on, the datapath test would pass through the wrong
    // component.
    let cil = InnerClusterProfile::cilium_3node();
    assert_eq!(cil.cni, InnerCni::Cilium);
    assert_eq!(cil.sidecar_memory_mb, CILIUM_SIDECAR_MEMORY_MB);
    assert_eq!(cil.cni_bin_dir(), CILIUM_CNI_BIN_DIR);
    assert_eq!(p.cni_bin_dir(), "/bin");
    assert!(cil.airgap_import_wait_secs() > p.airgap_import_wait_secs());
    let cil_flags = cil.cluster_server_flags("inner-server");
    assert!(
        cil_flags.contains(&"--flannel-backend=none".to_string())
            && cil_flags.contains(&"--disable-kube-proxy".to_string())
            && !cil_flags.contains(&"--flannel-backend=host-gw".to_string()),
        "cilium_3node must render --flannel-backend=none --disable-kube-proxy: {cil_flags:?}"
    );
    let cil_yaml = inner_pod_yaml(&cil, 0);
    assert!(
        cil_yaml.contains("--flannel-backend=none")
            && cil_yaml.contains("--disable-kube-proxy")
            && cil_yaml.contains(&format!("bin_dir = \"{CILIUM_CNI_BIN_DIR}\""))
            && cil_yaml.contains("mount -t bpf bpf /sys/fs/bpf"),
        "cilium profile YAML must carry the CNI-less k3s flags and the sidecar's \
         bpffs + CNI bin dir prep"
    );
    // …and the flannel path stays byte-identical for every other test.
    assert!(
        default_yaml.contains("--flannel-backend=host-gw")
            && !default_yaml.contains("--disable-kube-proxy")
            && !default_yaml.contains("mount -t bpf")
            && default_yaml.contains("bin_dir = \"/bin\""),
        "default profile must keep flannel host-gw, kube-proxy, and the k3s CNI bin dir"
    );

    let argo = InnerClusterProfile::argocd_3node();
    assert!(argo.addons.coredns);
    assert!(!argo.addons.traefik && !argo.addons.helm_controller);
    assert_eq!(argo.sidecar_memory_mb, ARGOCD_SIDECAR_MEMORY_MB);
    assert_eq!(
        argo.containerd_tmpfs_mb(),
        ARGOCD_SIDECAR_MEMORY_MB.saturating_sub(128)
    );
    assert_eq!(argo.datastore, InnerDatastore::Sqlite);
    assert_eq!(argo.memory_mb, INNER_K3S_MEMORY_MB);
    for (label, yaml) in [
        ("default", default_yaml),
        ("ingress", ing_yaml),
        ("local-path", lpp_yaml),
        ("metrics-server", ms_yaml),
        ("network-policy", np_yaml),
        ("etcd", etcd_yaml),
        ("cilium", cil_yaml),
    ] {
        let isolated = common::isolate_manifest(&yaml);
        let out = Command::new("kubectl")
            .args(["apply", "--dry-run=client", "-o", "name", "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child
                    .stdin
                    .as_mut()
                    .unwrap()
                    .write_all(isolated.as_bytes())
                    .unwrap();
                child.wait_with_output()
            })
            .expect("kubectl dry-run should run");
        assert!(
            out.status.success(),
            "{label} inner pod YAML failed client dry-run: {}\n{}",
            String::from_utf8_lossy(&out.stderr),
            isolated
                .lines()
                .enumerate()
                .skip(130)
                .take(20)
                .map(|(i, l)| format!("{:4}|{l}", i + 1))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

fn dns_probe_names(profile: &InnerClusterProfile) -> Vec<String> {
    (0..profile.vm_count)
        .map(|i| common::unique_name(&format!("test-dns-probe-{i}")))
        .collect()
}

fn dns_probe_manifest(profile: &InnerClusterProfile, names: &[String]) -> String {
    let mut docs = Vec::new();
    for (idx, name) in names.iter().enumerate() {
        let node = profile.node_name(idx);
        docs.push(format!(
            "apiVersion: v1\n\
             kind: Pod\n\
             metadata:\n\
             \x20 name: {name}\n\
             spec:\n\
             \x20 nodeSelector:\n\
             \x20   kubernetes.io/hostname: {node}\n\
             \x20 automountServiceAccountToken: false\n\
             \x20 restartPolicy: Always\n\
             \x20 containers:\n\
             \x20 - name: dns\n\
             \x20   image: {INNER3_BUSYBOX_REF}\n\
             \x20   imagePullPolicy: Never\n\
             \x20   command: [\"/bin/sh\", \"-c\"]\n\
             \x20   args:\n\
             \x20   - |\n\
             \x20     while true; do\n\
             \x20       if nslookup kubernetes.default.svc.cluster.local >/tmp/ns.out 2>&1; then\n\
             \x20         echo {DNS_OK_PREFIX} $(date +%s)\n\
             \x20       fi\n\
             \x20       sleep 2\n\
             \x20     done\n"
        ));
    }
    docs.join("---\n")
}

fn count_dns_ok(body: &str) -> usize {
    body.lines().filter(|l| l.contains(DNS_OK_PREFIX)).count()
}

fn probe_log_path(name: &str) -> String {
    format!("/api/v1/namespaces/default/pods/{name}/log?container=dns&tailLines=200")
}

fn probe_success_count_via(bridge: &str, name: &str) -> Result<usize, String> {
    let body = curl_inner_api(bridge, &probe_log_path(name))?;
    Ok(count_dns_ok(&body))
}

/// Nested runc cannot consume kubelet ConfigMap or projected-token
/// volumes: the files live in the k3s container's mount ns and the
/// sidecar bind is empty (CHALLENGES #50, #87, #88). Copy Corefile +
/// a minted SA token onto `/cri` on **every** member, point the
/// Deployment at those hostPaths, drop the custom mount, disable
/// automount, and pin to `inner-server`.
fn patch_coredns_for_nested_runc(profile: &InnerClusterProfile) {
    let server_pod = profile.live_pod(0);
    let inner_kubectl = "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl";
    let start = Instant::now();
    loop {
        let exists = kubectl_exec_in(
            &server_pod,
            "k3s",
            &format!("{inner_kubectl} -n kube-system get deploy coredns 2>&1"),
        );
        if matches!(exists, Ok(ref s) if s.contains("coredns")) {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(120),
            "coredns Deployment never appeared so it could be patched: {exists:?}"
        );
        thread::sleep(Duration::from_secs(2));
    }
    let setup = kubectl_exec_retry(
        &server_pod,
        "k3s",
        &format!(
            "mkdir -p /cri/coredns-config && \
             {inner_kubectl} -n kube-system get cm coredns \
               -o jsonpath='{{.data.Corefile}}' > /cri/coredns-config/Corefile && \
             {inner_kubectl} -n kube-system get cm coredns \
               -o jsonpath='{{.data.NodeHosts}}' > /cri/coredns-config/NodeHosts && \
             test -s /cri/coredns-config/Corefile && echo corefile-ok"
        ),
        5,
    );
    assert!(
        matches!(setup, Ok(ref s) if s.contains("corefile-ok")),
        "failed to stage Corefile on /cri: {setup:?}"
    );
    // Projected SA tokens live in the k3s mount ns and are empty to
    // sidecar runc (CHALLENGES #50). Mint a bound token onto /cri.
    let sa = kubectl_exec_retry(
        &server_pod,
        "k3s",
        &format!(
            "mkdir -p /cri/coredns-sa && \
             echo kube-system > /cri/coredns-sa/namespace && \
             {inner_kubectl} -n kube-system get cm kube-root-ca.crt \
               -o jsonpath='{{.data.ca\\.crt}}' > /cri/coredns-sa/ca.crt && \
             {inner_kubectl} -n kube-system create token coredns --duration=2h \
               > /cri/coredns-sa/token && \
             test -s /cri/coredns-sa/token && test -s /cri/coredns-sa/ca.crt && echo sa-ok"
        ),
        5,
    );
    assert!(
        matches!(sa, Ok(ref s) if s.contains("sa-ok")),
        "failed to stage CoreDNS SA token on /cri: {sa:?}"
    );
    let corefile = kubectl_exec_in(&server_pod, "k3s", "cat /cri/coredns-config/Corefile")
        .expect("read staged Corefile");
    let nodehosts = kubectl_exec_in(&server_pod, "k3s", "cat /cri/coredns-config/NodeHosts")
        .unwrap_or_default();
    let token = kubectl_exec_in(&server_pod, "k3s", "cat /cri/coredns-sa/token")
        .expect("read staged SA token");
    let ca =
        kubectl_exec_in(&server_pod, "k3s", "cat /cri/coredns-sa/ca.crt").expect("read staged CA");
    for pod in profile.live_pods() {
        if pod == server_pod {
            continue;
        }
        let replica = kubectl_exec_retry(
            &pod,
            "k3s",
            &format!(
                "mkdir -p /cri/coredns-config /cri/coredns-sa && \
                 cat > /cri/coredns-config/Corefile <<'EOF'\n{corefile}\nEOF\n\
                 cat > /cri/coredns-config/NodeHosts <<'EOF'\n{nodehosts}\nEOF\n\
                 cat > /cri/coredns-sa/token <<'EOF'\n{token}\nEOF\n\
                 cat > /cri/coredns-sa/ca.crt <<'EOF'\n{ca}\nEOF\n\
                 echo kube-system > /cri/coredns-sa/namespace && \
                 test -s /cri/coredns-config/Corefile && test -s /cri/coredns-sa/token && echo corefile-ok"
            ),
            5,
        );
        assert!(
            matches!(replica, Ok(ref s) if s.contains("corefile-ok")),
            "failed to stage Corefile/SA on {pod}: {replica:?}"
        );
    }
    let patch = kubectl_exec_retry(
        &server_pod,
        "k3s",
        &format!(
            "{inner_kubectl} -n kube-system patch deploy coredns --type=json \
             -p='[\
               {{\"op\":\"remove\",\"path\":\"/spec/template/spec/containers/0/volumeMounts/1\"}},\
               {{\"op\":\"remove\",\"path\":\"/spec/template/spec/volumes/1\"}},\
               {{\"op\":\"remove\",\"path\":\"/spec/template/spec/volumes/0/configMap\"}},\
               {{\"op\":\"add\",\"path\":\"/spec/template/spec/volumes/0/hostPath\",\
                 \"value\":{{\"path\":\"/cri/coredns-config\",\"type\":\"Directory\"}}}},\
               {{\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/0/securityContext/readOnlyRootFilesystem\",\"value\":false}},\
               {{\"op\":\"add\",\"path\":\"/spec/template/spec/nodeSelector/kubernetes.io~1hostname\",\"value\":\"inner-server\"}},\
               {{\"op\":\"add\",\"path\":\"/spec/template/spec/automountServiceAccountToken\",\"value\":false}},\
               {{\"op\":\"add\",\"path\":\"/spec/template/spec/volumes/-\",\
                 \"value\":{{\"name\":\"coredns-sa\",\"hostPath\":{{\"path\":\"/cri/coredns-sa\",\"type\":\"Directory\"}}}}}},\
               {{\"op\":\"add\",\"path\":\"/spec/template/spec/containers/0/volumeMounts/-\",\
                 \"value\":{{\"name\":\"coredns-sa\",\"mountPath\":\"/var/run/secrets/kubernetes.io/serviceaccount\",\"readOnly\":true}}}}\
             ]' && echo patch-ok"
        ),
        5,
    );
    assert!(
        matches!(patch, Ok(ref s) if s.contains("patch-ok")),
        "coredns hostPath patch failed: {patch:?}"
    );
    eprintln!(
        "  patched coredns: Corefile + SA token via /cri hostPath on every member, pinned to inner-server"
    );
}

fn wait_coredns_ready_via(bridge: &str, server_pod: Option<&str>) {
    let path = "/apis/apps/v1/namespaces/kube-system/deployments/coredns";
    let start = Instant::now();
    loop {
        match curl_inner_api(bridge, path) {
            Ok(body) => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                    let ready = v["status"]["readyReplicas"].as_u64().unwrap_or(0);
                    if ready >= 1 {
                        eprintln!("  coredns readyReplicas={ready} via {bridge}");
                        return;
                    }
                    eprintln!("  coredns not ready yet via {bridge}: readyReplicas={ready}");
                }
            }
            Err(e) => eprintln!("  coredns get via {bridge}: {e}"),
        }
        if start.elapsed() > Duration::from_secs(300) {
            let pods = curl_inner_api(
                bridge,
                "/api/v1/namespaces/kube-system/pods?labelSelector=k8s-app=kube-dns",
            )
            .unwrap_or_else(|e| format!("pods err: {e}"));
            let describe = if let Some(pod) = server_pod {
                kubectl_exec_in(
                    pod,
                    "k3s",
                    "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl \
                     -n kube-system describe deploy/coredns 2>&1 | tail -40; \
                     KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl \
                     -n kube-system get pods -o wide 2>&1; \
                     KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl \
                     -n kube-system describe pod -l k8s-app=kube-dns 2>&1 | tail -80; \
                     KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl \
                     -n kube-system logs -l k8s-app=kube-dns --tail=60 2>&1; \
                     /bin/ctr --address /cri/containerd.sock -n k8s.io images ls 2>&1 | head -40",
                )
                .unwrap_or_else(|e| format!("describe err: {e}"))
            } else {
                String::new()
            };
            panic!(
                "coredns Deployment never Ready via {bridge}\n\
                 coredns pods: {}\n\
                 in-guest: {describe}",
                pods.chars().take(6000).collect::<String>()
            );
        }
        thread::sleep(Duration::from_secs(3));
    }
}

fn assert_kube_dns_cluster_ip_via(bridge: &str) {
    let body = curl_inner_api(bridge, "/api/v1/namespaces/kube-system/services/kube-dns")
        .expect("GET kube-dns Service");
    let v: serde_json::Value = serde_json::from_str(&body).expect("kube-dns json");
    let ip = v["spec"]["clusterIP"].as_str().unwrap_or("");
    assert!(
        ip.starts_with("10.61."),
        "kube-dns ClusterIP {ip} not in --service-cidr=10.61.0.0/16"
    );
    eprintln!("  kube-dns ClusterIP={ip} via {bridge}");
}

/// CoreDNS on a dedicated profile: in-cluster DNS from a pod on every
/// member, then the same claim on source and fork after a warm fork.
#[test]
fn test_inner_k3s_coredns_dns_fork() {
    let _leak_guard = ensure_shim_installed();
    let profile = InnerClusterProfile::coredns_3node();
    bring_up_inner_cluster(&profile);

    extract_inner_certs();
    let source_bridge = inner3_bridge();
    let bridges_before = list_k7_bridges();
    assert!(
        bridges_before.contains(&source_bridge),
        "inner3 bridge missing: {bridges_before:?}"
    );
    let ready = curl_inner_api(&source_bridge, "/readyz").expect("pre-adopt /readyz");
    assert!(ready.contains("ok"), "pre-adopt /readyz not ok: {ready}");

    let server_pod = profile.live_pod(0);
    wait_coredns_ready_via(&source_bridge, Some(&server_pod));
    assert_kube_dns_cluster_ip_via(&source_bridge);

    let probes = dns_probe_names(&profile);
    let inner_kubectl = "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl";
    let manifest = dns_probe_manifest(&profile, &probes);
    let apply = kubectl_exec_retry(
        &server_pod,
        "k3s",
        &format!(
            "cat > /tmp/dns-probes.yaml <<'EOF'\n{manifest}EOF\n\
             {inner_kubectl} apply -f /tmp/dns-probes.yaml && echo probes-ok"
        ),
        3,
    );
    assert!(
        matches!(apply, Ok(ref s) if s.contains("probes-ok")),
        "DNS probe apply failed: {apply:?}"
    );

    let start = Instant::now();
    loop {
        let mut running = 0;
        for name in &probes {
            let status = kubectl_exec_in(
                &server_pod,
                "k3s",
                &format!("{inner_kubectl} get pod {name} -o jsonpath='{{.status.phase}}' 2>&1"),
            );
            if matches!(status, Ok(ref s) if s.trim() == "Running") {
                running += 1;
            }
        }
        if running == profile.vm_count {
            break;
        }
        if start.elapsed() > Duration::from_secs(300) {
            let describe = kubectl_exec_in(
                &server_pod,
                "k3s",
                &format!("{inner_kubectl} get pods -o wide 2>&1; {inner_kubectl} describe pods -l '' 2>&1 | tail -80"),
            );
            delete_inner_pods(&profile);
            panic!(
                "DNS probes never all Running ({running}/{}): {describe:?}",
                profile.vm_count
            );
        }
        thread::sleep(Duration::from_secs(3));
    }

    // Pre-fork: each probe has logged ≥1 successful resolution.
    let start = Instant::now();
    let mut pre_counts = vec![0usize; profile.vm_count];
    loop {
        let mut ok = 0;
        for (i, name) in probes.iter().enumerate() {
            match probe_success_count_via(&source_bridge, name) {
                Ok(n) => {
                    pre_counts[i] = n;
                    if n >= 1 {
                        ok += 1;
                    }
                }
                Err(e) => eprintln!("  pre-fork log {name}: {e}"),
            }
        }
        if ok == profile.vm_count {
            break;
        }
        if start.elapsed() > Duration::from_secs(180) {
            delete_inner_pods(&profile);
            panic!("pre-fork DNS probes never all resolved kubernetes.default.svc: {pre_counts:?}");
        }
        thread::sleep(Duration::from_secs(2));
    }
    eprintln!("  pre-fork DNS_OK counts={pre_counts:?}");

    let mut client = Client::connect_env().expect("connect k7d daemon");
    let vm_ids = discover_inner_vm_ids(&mut client, &profile);
    eprintln!("  discovered coredns-profile vm_ids={vm_ids:?}");

    let tree_id = format!("i3cd-{}", common::run_id());
    let (tree_id, root_id, root_cids) = match client.call(&Request::TreeAdoptCluster {
        ksm: false,
        vm_ids,
        budget: Some(inner3_tree_budget()),
        tree_id: Some(tree_id),
        egress: None,
        dilation_policy: None,
        dilation_config: None,
    }) {
        Ok(Response::TreeCreated {
            tree_id,
            root_id,
            guest_cids,
            ..
        }) => {
            assert_eq!(
                guest_cids.len(),
                profile.vm_count,
                "adopted root must have {} members",
                profile.vm_count
            );
            (tree_id, root_id, guest_cids)
        }
        Ok(other) => {
            delete_inner_pods(&profile);
            panic!("unexpected TreeAdoptCluster response: {other:?}");
        }
        Err(e) => {
            delete_inner_pods(&profile);
            panic!("TreeAdoptCluster transport error: {e}");
        }
    };
    common::mark_test_tree(&tree_id);
    eprintln!("  adopted tree={tree_id} root_cids={root_cids:?}");

    let teardown = |client: &mut Client| {
        let _ = client.call(&Request::TreeDrop {
            tree_id: tree_id.clone(),
        });
        delete_inner_pods(&profile);
        let _ = std::fs::remove_dir_all(format!("/var/lib/k7d/trees/{tree_id}"));
    };

    let start = Instant::now();
    loop {
        if matches!(curl_inner_api(&source_bridge, "/readyz"), Ok(ref b) if b.contains("ok")) {
            break;
        }
        if start.elapsed() > Duration::from_secs(120) {
            let last = curl_inner_api(&source_bridge, "/readyz");
            teardown(&mut client);
            panic!("source API never recovered after adopt/prepare (last: {last:?})");
        }
        thread::sleep(Duration::from_secs(2));
    }

    let fork_start = Instant::now();
    let (fork_node, fork_cids, latency_ns) = match client.call(&Request::TreeFork {
        tree_id: tree_id.clone(),
        source_id: root_id.clone(),
        label: "warm".to_string(),
        dilation: None,
        dilation_policy: None,
        dilation_config: None,
    }) {
        Ok(Response::TreeForked {
            node_id,
            guest_cids,
            fork_memory_full_copy,
            latency_ns,
            ..
        }) => {
            assert_eq!(
                guest_cids.len(),
                profile.vm_count,
                "fork must clone every member"
            );
            assert_eq!(
                fork_memory_full_copy,
                vec![false; profile.vm_count],
                "inner-k3s cluster fork must be CoW on every member"
            );
            (node_id, guest_cids, latency_ns)
        }
        Ok(other) => {
            teardown(&mut client);
            panic!("unexpected TreeFork response: {other:?}");
        }
        Err(e) => {
            teardown(&mut client);
            panic!("TreeFork transport error: {e}");
        }
    };
    let fork_elapsed = fork_start.elapsed();
    eprintln!(
        "  TreeFork (CoreDNS profile) node={fork_node} cids={fork_cids:?} \
         elapsed={fork_elapsed:?} budget={FORK_INNER_K3S_CLUSTER_3VM:?}"
    );
    if let Ok(journal) = Command::new("journalctl")
        .args(["-u", "k7d", "--no-pager", "--since", "-3min"])
        .output()
    {
        for line in String::from_utf8_lossy(&journal.stdout)
            .lines()
            .filter(|l| {
                l.contains("full memfd copy")
                    || l.contains("fork_cluster_warm")
                    || l.contains("cluster_tree fork_batch")
            })
        {
            eprintln!("  daemon: {line}");
        }
    }
    common::tree_fork_budget::assert_tree_fork_budget(
        "CoreDNS-profile",
        fork_elapsed,
        latency_ns,
        FORK_INNER_K3S_CLUSTER_3VM,
    );

    let fork_bridge = list_k7_bridges()
        .into_iter()
        .find(|b| !bridges_before.contains(b))
        .expect("fork bridge appeared");
    eprintln!("  source bridge={source_bridge} fork bridge={fork_bridge}");

    let resume = Instant::now();
    loop {
        if matches!(curl_inner_api(&source_bridge, "/readyz"), Ok(ref b) if b.contains("ok")) {
            break;
        }
        if resume.elapsed() > Duration::from_secs(60) {
            let last = curl_inner_api(&source_bridge, "/readyz");
            teardown(&mut client);
            panic!("source /readyz never recovered after TreeFork resume (last: {last:?})");
        }
        thread::sleep(Duration::from_millis(500));
    }

    assert_ready_nodes_via(&profile, &source_bridge, "source");
    assert_ready_nodes_via(&profile, &fork_bridge, "fork");
    wait_coredns_ready_via(&source_bridge, Some(&server_pod));
    wait_coredns_ready_via(&fork_bridge, None);

    // Baseline immediately after both APIs answer, then require growth
    // on each bridge — a pre-fork residue line proves nothing.
    let mut source_base = Vec::new();
    let mut fork_base = Vec::new();
    for name in &probes {
        source_base.push(probe_success_count_via(&source_bridge, name).unwrap_or(0));
        fork_base.push(probe_success_count_via(&fork_bridge, name).unwrap_or(0));
    }
    eprintln!("  post-fork baseline source={source_base:?} fork={fork_base:?}");

    let start = Instant::now();
    loop {
        let mut source_now = Vec::new();
        let mut fork_now = Vec::new();
        let mut source_grew = 0;
        let mut fork_grew = 0;
        for (i, name) in probes.iter().enumerate() {
            let s = probe_success_count_via(&source_bridge, name).unwrap_or(0);
            let f = probe_success_count_via(&fork_bridge, name).unwrap_or(0);
            if s > source_base[i] {
                source_grew += 1;
            }
            if f > fork_base[i] {
                fork_grew += 1;
            }
            source_now.push(s);
            fork_now.push(f);
        }
        if source_grew == profile.vm_count && fork_grew == profile.vm_count {
            eprintln!(
                "  post-fork DNS_OK grew source={source_now:?} fork={fork_now:?} \
                 elapsed={fork_elapsed:?}"
            );
            break;
        }
        if start.elapsed() > Duration::from_secs(90) {
            teardown(&mut client);
            panic!(
                "DNS_OK count did not grow on both bridges after fork \
                 source_base={source_base:?} source_now={source_now:?} \
                 fork_base={fork_base:?} fork_now={fork_now:?}"
            );
        }
        thread::sleep(Duration::from_secs(2));
    }

    teardown(&mut client);
}

// ──: metrics-server ──

/// metrics-server's only nested-runc hole is the projected SA token
/// (CHALLENGES #88): it authenticates to the apiserver *and* to every
/// kubelet with it, and verifies the kubelet serving certs against the
/// same `ca.crt`. Stage a minted token on `/cri` on every member,
/// mount that hostPath at the SA path, disable automount, pin to
/// `inner-server`, and never pull (the image arrives via airgap tar).
///
/// The `tmp-dir` emptyDir needs no rewrite: kubelet creates emptyDir
/// directories mode 0777 under `/var/lib/kubelet/pods`, which both
/// containers symlink to `/cri/kubelet-pods` (#90), so sidecar runc
/// binds the same directory and uid 1000 can write `--cert-dir=/tmp`.
fn patch_metrics_server_for_nested_runc(profile: &InnerClusterProfile) {
    let server_pod = profile.live_pod(0);
    let inner_kubectl = "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl";
    let start = Instant::now();
    loop {
        let exists = kubectl_exec_in(
            &server_pod,
            "k3s",
            &format!("{inner_kubectl} -n kube-system get deploy metrics-server 2>&1"),
        );
        if matches!(exists, Ok(ref s) if s.contains("metrics-server")) {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(120),
            "metrics-server Deployment never appeared so it could be patched: {exists:?}"
        );
        thread::sleep(Duration::from_secs(2));
    }
    let sa = kubectl_exec_retry(
        &server_pod,
        "k3s",
        &format!(
            "mkdir -p /cri/metrics-sa && \
             echo kube-system > /cri/metrics-sa/namespace && \
             {inner_kubectl} -n kube-system get cm kube-root-ca.crt \
               -o jsonpath='{{.data.ca\\.crt}}' > /cri/metrics-sa/ca.crt && \
             {inner_kubectl} -n kube-system create token metrics-server --duration=2h \
               > /cri/metrics-sa/token && \
             test -s /cri/metrics-sa/token && test -s /cri/metrics-sa/ca.crt && echo sa-ok"
        ),
        5,
    );
    assert!(
        matches!(sa, Ok(ref s) if s.contains("sa-ok")),
        "failed to stage metrics-server SA token on /cri: {sa:?}"
    );
    let token = kubectl_exec_in(&server_pod, "k3s", "cat /cri/metrics-sa/token")
        .expect("read staged metrics-server SA token");
    let ca = kubectl_exec_in(&server_pod, "k3s", "cat /cri/metrics-sa/ca.crt")
        .expect("read staged metrics-server CA");
    for pod in profile.live_pods() {
        if pod == server_pod {
            continue;
        }
        let replica = kubectl_exec_retry(
            &pod,
            "k3s",
            &format!(
                "mkdir -p /cri/metrics-sa && \
                 cat > /cri/metrics-sa/token <<'MS_EOF'\n{token}\nMS_EOF\n\
                 cat > /cri/metrics-sa/ca.crt <<'MS_EOF'\n{ca}\nMS_EOF\n\
                 echo kube-system > /cri/metrics-sa/namespace && \
                 test -s /cri/metrics-sa/token && echo sa-ok"
            ),
            5,
        );
        assert!(
            matches!(replica, Ok(ref s) if s.contains("sa-ok")),
            "failed to stage metrics-server SA on {pod}: {replica:?}"
        );
    }
    let patch = kubectl_exec_retry(
        &server_pod,
        "k3s",
        &format!(
            "{inner_kubectl} -n kube-system patch deploy metrics-server --type=json \
             -p='[\
               {{\"op\":\"add\",\"path\":\"/spec/template/spec/nodeSelector/kubernetes.io~1hostname\",\"value\":\"inner-server\"}},\
               {{\"op\":\"add\",\"path\":\"/spec/template/spec/automountServiceAccountToken\",\"value\":false}},\
               {{\"op\":\"add\",\"path\":\"/spec/template/spec/volumes/-\",\
                 \"value\":{{\"name\":\"metrics-sa\",\"hostPath\":{{\"path\":\"/cri/metrics-sa\",\"type\":\"Directory\"}}}}}},\
               {{\"op\":\"add\",\"path\":\"/spec/template/spec/containers/0/volumeMounts/-\",\
                 \"value\":{{\"name\":\"metrics-sa\",\"mountPath\":\"/var/run/secrets/kubernetes.io/serviceaccount\",\"readOnly\":true}}}},\
               {{\"op\":\"add\",\"path\":\"/spec/template/spec/containers/0/imagePullPolicy\",\"value\":\"Never\"}}\
             ]' && echo patch-ok"
        ),
        5,
    );
    assert!(
        matches!(patch, Ok(ref s) if s.contains("patch-ok")),
        "metrics-server hostPath SA patch failed: {patch:?}"
    );
    eprintln!(
        "  patched metrics-server: SA via /cri hostPath on every member, pinned to inner-server"
    );
}

/// Everything the metrics stack says about itself, for panic messages.
fn metrics_server_diagnostics(bridge: &str, server_pod: Option<&str>) -> String {
    let pods = curl_inner_api(
        bridge,
        "/api/v1/namespaces/kube-system/pods?labelSelector=k8s-app=metrics-server",
    )
    .unwrap_or_else(|e| format!("pods err: {e}"));
    let apiservice = curl_inner_api(
        bridge,
        "/apis/apiregistration.k8s.io/v1/apiservices/v1beta1.metrics.k8s.io",
    )
    .unwrap_or_else(|e| format!("apiservice err: {e}"));
    let in_guest = match server_pod {
        Some(pod) => kubectl_exec_in(
            pod,
            "k3s",
            "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl \
             -n kube-system describe deploy/metrics-server 2>&1 | tail -40; \
             KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl \
             -n kube-system describe pod -l k8s-app=metrics-server 2>&1 | tail -60; \
             KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl \
             -n kube-system logs -l k8s-app=metrics-server --tail=80 2>&1",
        )
        .unwrap_or_else(|e| format!("describe err: {e}")),
        None => String::new(),
    };
    format!(
        "metrics-server pods: {}\napiservice: {}\nin-guest: {in_guest}",
        pods.chars().take(6000).collect::<String>(),
        apiservice.chars().take(3000).collect::<String>()
    )
}

fn wait_metrics_server_ready_via(bridge: &str, server_pod: Option<&str>) {
    let path = "/apis/apps/v1/namespaces/kube-system/deployments/metrics-server";
    let start = Instant::now();
    loop {
        match curl_inner_api(bridge, path) {
            Ok(body) => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                    let ready = v["status"]["readyReplicas"].as_u64().unwrap_or(0);
                    if ready >= 1 {
                        eprintln!("  metrics-server readyReplicas={ready} via {bridge}");
                        return;
                    }
                    eprintln!("  metrics-server not ready yet via {bridge}: readyReplicas={ready}");
                }
            }
            Err(e) => eprintln!("  metrics-server get via {bridge}: {e}"),
        }
        if start.elapsed() > Duration::from_secs(300) {
            panic!(
                "metrics-server Deployment never Ready via {bridge}\n{}",
                metrics_server_diagnostics(bridge, server_pod)
            );
        }
        thread::sleep(Duration::from_secs(3));
    }
}

/// The aggregation-layer assertion: `Available=True` on the
/// `v1beta1.metrics.k8s.io` APIService. A Ready metrics-server pod
/// proves nothing about the apiserver reaching it through its
/// ClusterIP — that extension-apiserver path is what this catches.
fn wait_metrics_apiservice_available_via(bridge: &str, server_pod: Option<&str>) {
    let path = "/apis/apiregistration.k8s.io/v1/apiservices/v1beta1.metrics.k8s.io";
    let start = Instant::now();
    loop {
        let last = match curl_inner_api(bridge, path) {
            Ok(body) => match serde_json::from_str::<serde_json::Value>(&body) {
                Ok(v) => {
                    let empty = Vec::new();
                    let cond = v["status"]["conditions"]
                        .as_array()
                        .unwrap_or(&empty)
                        .iter()
                        .find(|c| c["type"].as_str() == Some("Available"))
                        .cloned()
                        .unwrap_or(serde_json::Value::Null);
                    if cond["status"].as_str() == Some("True") {
                        eprintln!(
                            "  APIService v1beta1.metrics.k8s.io Available=True via {bridge}"
                        );
                        return;
                    }
                    let state = format!(
                        "Available={} reason={} message={}",
                        cond["status"].as_str().unwrap_or("<none>"),
                        cond["reason"].as_str().unwrap_or("<none>"),
                        cond["message"].as_str().unwrap_or("<none>")
                    );
                    eprintln!("  APIService not Available yet via {bridge}: {state}");
                    state
                }
                Err(e) => format!("unparseable APIService body ({e}): {body}"),
            },
            Err(e) => {
                eprintln!("  APIService get via {bridge}: {e}");
                e
            }
        };
        if start.elapsed() > Duration::from_secs(300) {
            panic!(
                "APIService v1beta1.metrics.k8s.io never Available=True via {bridge} \
                 (last: {last})\n{}",
                metrics_server_diagnostics(bridge, server_pod)
            );
        }
        thread::sleep(Duration::from_secs(3));
    }
}

/// A Kubernetes resource quantity as an f64 in base units (cores for
/// CPU, bytes for memory). `None` for anything unparseable — callers
/// fail loud with the raw string rather than reading a zero.
fn parse_quantity(raw: &str) -> Option<f64> {
    let (digits, mult) = if let Some(v) = raw.strip_suffix("Ki") {
        (v, 1024.0)
    } else if let Some(v) = raw.strip_suffix("Mi") {
        (v, 1024.0 * 1024.0)
    } else if let Some(v) = raw.strip_suffix("Gi") {
        (v, 1024.0 * 1024.0 * 1024.0)
    } else if let Some(v) = raw.strip_suffix('n') {
        (v, 1e-9)
    } else if let Some(v) = raw.strip_suffix('u') {
        (v, 1e-6)
    } else if let Some(v) = raw.strip_suffix('m') {
        (v, 1e-3)
    } else {
        (raw, 1.0)
    };
    digits.trim().parse::<f64>().ok().map(|n| n * mult)
}

/// One `/apis/metrics.k8s.io/v1beta1/nodes` item.
#[derive(Clone, Debug)]
struct NodeMetrics {
    name: String,
    cpu_cores: f64,
    memory_bytes: f64,
    timestamp: String,
}

/// GET the aggregated node metrics through `bridge`. Errors carry the
/// raw body so an unparseable quantity is never silently a zero.
fn node_metrics_via(bridge: &str) -> Result<Vec<NodeMetrics>, String> {
    let body = curl_inner_api(bridge, "/apis/metrics.k8s.io/v1beta1/nodes")?;
    let v: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("node metrics json: {e}: {body}"))?;
    let items = v["items"]
        .as_array()
        .ok_or_else(|| format!("node metrics has no items: {body}"))?;
    let mut out = Vec::new();
    for item in items {
        let name = item["metadata"]["name"]
            .as_str()
            .ok_or_else(|| format!("node metrics item without a name: {item}"))?;
        let raw_cpu = item["usage"]["cpu"]
            .as_str()
            .ok_or_else(|| format!("{name}: no usage.cpu in {item}"))?;
        let raw_mem = item["usage"]["memory"]
            .as_str()
            .ok_or_else(|| format!("{name}: no usage.memory in {item}"))?;
        out.push(NodeMetrics {
            name: name.to_string(),
            cpu_cores: parse_quantity(raw_cpu)
                .ok_or_else(|| format!("{name}: unparseable usage.cpu {raw_cpu:?}"))?,
            memory_bytes: parse_quantity(raw_mem)
                .ok_or_else(|| format!("{name}: unparseable usage.memory {raw_mem:?}"))?,
            timestamp: item["timestamp"]
                .as_str()
                .ok_or_else(|| format!("{name}: no timestamp in {item}"))?
                .to_string(),
        });
    }
    Ok(out)
}

/// Poll until every member has non-zero CPU and memory usage in the
/// aggregated metrics API on `bridge`, and return that sample.
fn wait_node_metrics_via(
    profile: &InnerClusterProfile,
    bridge: &str,
    label: &str,
    server_pod: Option<&str>,
) -> Vec<NodeMetrics> {
    let start = Instant::now();
    loop {
        let last = match node_metrics_via(bridge) {
            Ok(metrics) => {
                let complete = (0..profile.vm_count).all(|idx| {
                    let node = profile.node_name(idx);
                    metrics
                        .iter()
                        .any(|m| m.name == node && m.cpu_cores > 0.0 && m.memory_bytes > 0.0)
                });
                if complete && metrics.len() == profile.vm_count {
                    for m in &metrics {
                        eprintln!(
                            "  {label}: {} cpu={:.4} cores mem={:.1} MiB at {}",
                            m.name,
                            m.cpu_cores,
                            m.memory_bytes / (1024.0 * 1024.0),
                            m.timestamp
                        );
                    }
                    return metrics;
                }
                format!("{metrics:?}")
            }
            Err(e) => e,
        };
        // metrics-server needs two scrapes (15 s apart) before it
        // serves anything, and a nested 1-vCPU kubelet is slower still.
        if start.elapsed() > Duration::from_secs(240) {
            panic!(
                "{label}: {} nodes with non-zero usage never served via {bridge} (last: {last})\n{}",
                profile.vm_count,
                metrics_server_diagnostics(bridge, server_pod)
            );
        }
        thread::sleep(Duration::from_secs(5));
    }
}

fn is_cpu_column(s: &str) -> bool {
    let digits = s.strip_suffix('m').unwrap_or(s);
    !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
}

fn is_memory_column(s: &str) -> bool {
    match s.strip_suffix("Mi") {
        Some(digits) => !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()),
        None => false,
    }
}

/// In-guest `kubectl top nodes`: a numeric CPU and memory column for
/// every member, no `<unknown>`. This is the operator-facing claim;
/// the REST assertions after the fork are the same data via the API.
fn assert_kubectl_top_nodes_numeric(profile: &InnerClusterProfile, bridge: &str) {
    let server_pod = profile.live_pod(0);
    let inner_kubectl = "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl";
    let start = Instant::now();
    loop {
        let top = kubectl_exec_in(
            &server_pod,
            "k3s",
            &format!("{inner_kubectl} top nodes --no-headers 2>&1"),
        );
        let last = if let Ok(ref text) = top {
            let numeric = (0..profile.vm_count)
                .filter(|idx| {
                    let node = profile.node_name(*idx);
                    text.lines().any(|l| {
                        let cols: Vec<&str> = l.split_whitespace().collect();
                        cols.len() >= 5
                            && cols[0] == node
                            && is_cpu_column(cols[1])
                            && is_memory_column(cols[3])
                    })
                })
                .count();
            if numeric == profile.vm_count {
                eprintln!("  kubectl top nodes (in-guest):\n{text}");
                return;
            }
            format!("{numeric}/{} numeric rows in:\n{text}", profile.vm_count)
        } else {
            format!("{top:?}")
        };
        if start.elapsed() > Duration::from_secs(240) {
            panic!(
                "in-guest `kubectl top nodes` never numeric for all {} nodes ({last})\n{}",
                profile.vm_count,
                metrics_server_diagnostics(bridge, Some(&server_pod))
            );
        }
        thread::sleep(Duration::from_secs(5));
    }
}

fn helm_job_names() -> [&'static str; 2] {
    ["helm-install-traefik-crd", "helm-install-traefik"]
}

fn helm_job_service_accounts() -> [(&'static str, &'static str); 2] {
    [
        ("helm-install-traefik-crd", "helm-traefik-crd"),
        ("helm-install-traefik", "helm-traefik"),
    ]
}

/// Helm jobs start (symlink #90) but in-cluster config is empty to
/// sidecar runc (CHALLENGES #88) and chart fetch fails TLS verify.
/// Mint SA tokens onto `/cri`, hostPath-mount them, skip TLS verify.
/// helm-controller may revert the Job — caller re-invokes.
fn patch_helm_jobs_for_nested_runc(profile: &InnerClusterProfile) {
    let server_pod = profile.live_pod(0);
    let inner_kubectl = "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl";
    for (job, sa) in helm_job_service_accounts() {
        let exists = kubectl_exec_in(
            &server_pod,
            "k3s",
            &format!("{inner_kubectl} -n kube-system get job {job} 2>&1"),
        );
        if !matches!(exists, Ok(ref s) if s.contains(job)) {
            continue;
        }
        let dir = format!("/cri/helm-sa-{sa}");
        let staged = kubectl_exec_retry(
            &server_pod,
            "k3s",
            &format!(
                "mkdir -p {dir} && \
                 echo kube-system > {dir}/namespace && \
                 {inner_kubectl} -n kube-system get cm kube-root-ca.crt \
                   -o jsonpath='{{.data.ca\\.crt}}' > {dir}/ca.crt && \
                 {inner_kubectl} -n kube-system create token {sa} --duration=2h \
                   > {dir}/token && \
                 test -s {dir}/token && test -s {dir}/ca.crt && echo sa-ok"
            ),
            5,
        );
        if !matches!(staged, Ok(ref s) if s.contains("sa-ok")) {
            eprintln!("  helm SA stage {sa}: {staged:?}");
            continue;
        }
        let token =
            kubectl_exec_in(&server_pod, "k3s", &format!("cat {dir}/token")).unwrap_or_default();
        let ca =
            kubectl_exec_in(&server_pod, "k3s", &format!("cat {dir}/ca.crt")).unwrap_or_default();
        if token.is_empty() || ca.is_empty() {
            continue;
        }
        for pod in profile.live_pods() {
            if pod == server_pod {
                continue;
            }
            let _ = kubectl_exec_retry(
                &pod,
                "k3s",
                &format!(
                    "mkdir -p {dir} && \
                     cat > {dir}/token <<'EOF'\n{token}\nEOF\n\
                     cat > {dir}/ca.crt <<'EOF'\n{ca}\nEOF\n\
                     echo kube-system > {dir}/namespace && echo sa-ok"
                ),
                3,
            );
        }
        let already = kubectl_exec_in(
            &server_pod,
            "k3s",
            &format!(
                "{inner_kubectl} -n kube-system get job {job} \
                 -o jsonpath='{{.spec.template.spec.volumes}}' 2>&1"
            ),
        );
        if matches!(already, Ok(ref s) if s.contains("helm-sa")) {
            continue;
        }
        // Job spec.template is immutable — delete and recreate.
        let raw = match kubectl_exec_in(
            &server_pod,
            "k3s",
            &format!("{inner_kubectl} -n kube-system get job {job} -o json"),
        ) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("  helm job get {job}: {e}");
                continue;
            }
        };
        let mut spec: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("  helm job json {job}: {e}");
                continue;
            }
        };
        let pod_spec = &mut spec["spec"]["template"]["spec"];
        pod_spec["automountServiceAccountToken"] = serde_json::json!(false);
        let vols = pod_spec["volumes"].as_array().cloned().unwrap_or_default();
        if !vols.iter().any(|v| v["name"] == "helm-sa") {
            let mut vols = vols;
            vols.push(serde_json::json!({
                "name": "helm-sa",
                "hostPath": {"path": dir, "type": "Directory"}
            }));
            pod_spec["volumes"] = serde_json::Value::Array(vols);
        }
        pod_spec["containers"][0]["imagePullPolicy"] = serde_json::json!("Never");
        let mounts = pod_spec["containers"][0]["volumeMounts"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if !mounts.iter().any(|m| m["name"] == "helm-sa") {
            let mut mounts = mounts;
            mounts.push(serde_json::json!({
                "name": "helm-sa",
                "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
                "readOnly": true
            }));
            pod_spec["containers"][0]["volumeMounts"] = serde_json::Value::Array(mounts);
        }
        if let Some(env) = pod_spec["containers"][0]["env"].as_array_mut() {
            let mut found = false;
            for e in env.iter_mut() {
                if e["name"] == "INSECURE_SKIP_TLS_VERIFY" {
                    e["value"] = serde_json::json!("true");
                    found = true;
                }
            }
            if !found {
                env.push(serde_json::json!({
                    "name": "INSECURE_SKIP_TLS_VERIFY",
                    "value": "true"
                }));
            }
        }
        if let Some(md) = spec["metadata"].as_object_mut() {
            for k in [
                "resourceVersion",
                "uid",
                "generation",
                "creationTimestamp",
                "managedFields",
            ] {
                md.remove(k);
            }
        }
        spec.as_object_mut().map(|o| o.remove("status"));
        // New Job must auto-generate selector / controller-uid.
        spec["spec"].as_object_mut().map(|o| {
            o.remove("selector");
            o.remove("manualSelector");
        });
        if let Some(labels) = spec["spec"]["template"]["metadata"]["labels"].as_object_mut() {
            labels.remove("controller-uid");
            labels.remove("batch.kubernetes.io/controller-uid");
        }
        let body = spec.to_string();
        let recreate = kubectl_exec_retry(
            &server_pod,
            "k3s",
            &format!(
                "cat > /tmp/{job}.json <<'EOF'\n{body}\nEOF\n\
                 {inner_kubectl} -n kube-system delete job {job} --wait=true --timeout=60s && \
                 {inner_kubectl} apply -f /tmp/{job}.json && echo recreate-ok"
            ),
            3,
        );
        if matches!(recreate, Ok(ref s) if s.contains("recreate-ok")) {
            eprintln!("  recreated {job}: hostPath SA {dir}, INSECURE_SKIP_TLS_VERIFY");
        } else {
            eprintln!("  helm job recreate {job}: {recreate:?}");
        }
    }
}

/// Install the bundled Traefik charts with the klipper-helm binary
/// from the k3s admin kubeconfig (no nested-runc SA/TLS hole). The
/// HelmChart Jobs still have to Complete — this makes their
/// `helm upgrade --install` a no-op once the release exists.
fn install_bundled_traefik_charts(profile: &InnerClusterProfile) -> bool {
    let server_pod = profile.live_pod(0);
    let inner_kubectl = "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl";
    let extract = kubectl_exec_retry(
        &server_pod,
        "containerd",
        &format!(
            "if [ -x /cri/helm ]; then echo helm-ok; exit 0; fi; \
             mkdir -p /tmp/k7-helm && \
             /bin/ctr --address /cri/containerd.sock -n k8s.io run --rm --privileged -u 0:0 \
               --mount type=bind,src=/tmp/k7-helm,dst=/out,options=rbind:rw \
               {INNER3_KLIPPER_HELM_REF} k7-extract-helm \
               sh -c 'src=$(command -v helm); cp \"$src\" /out/helm' && \
             cp /tmp/k7-helm/helm /cri/helm && chmod 755 /cri/helm && \
             test -x /cri/helm && echo helm-ok"
        ),
        3,
    );
    if !matches!(extract, Ok(ref s) if s.contains("helm-ok")) {
        eprintln!("  extract helm to /cri: {extract:?}");
        return false;
    }
    let values = kubectl_exec_in(
        &server_pod,
        "k3s",
        &format!(
            "{inner_kubectl} -n kube-system get helmchart traefik \
             -o jsonpath='{{.spec.valuesContent}}'"
        ),
    )
    .unwrap_or_default();
    let install = kubectl_exec_retry(
        &server_pod,
        "k3s",
        &format!(
            "set -e; \
             CRD=$(ls /var/lib/rancher/k3s/server/static/charts/traefik-crd*.tgz | head -1); \
             CHART=$(ls /var/lib/rancher/k3s/server/static/charts/traefik-[0-9]*.tgz | head -1); \
             test -n \"$CRD\" && test -n \"$CHART\"; \
             /cri/helm upgrade --install traefik-crd \"$CRD\" \
               --kubeconfig /etc/rancher/k3s/k3s.yaml --namespace kube-system && \
             cat > /tmp/traefik-values.yaml <<'EOF'\n{values}\nEOF\n\
             /cri/helm upgrade --install traefik \"$CHART\" \
               --kubeconfig /etc/rancher/k3s/k3s.yaml --namespace kube-system \
               --set-string global.systemDefaultRegistry= \
               --values /tmp/traefik-values.yaml && echo helm-install-ok"
        ),
        3,
    );
    if matches!(install, Ok(ref s) if s.contains("helm-install-ok")) {
        eprintln!("  bundled Traefik charts installed via /cri/helm + admin kubeconfig");
        true
    } else {
        eprintln!("  bundled Traefik helm install: {install:?}");
        false
    }
}

/// After `/cri/helm` has installed the releases, mark the HelmChart
/// Jobs Complete. Recreating the Job spec fights helm-controller
/// (immutable template + objectset apply) and never lets a pod finish.
fn mark_helm_jobs_complete(profile: &InnerClusterProfile) {
    let server_pod = profile.live_pod(0);
    let inner_kubectl = "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl";
    for job in helm_job_names() {
        let patch = kubectl_exec_in(
            &server_pod,
            "k3s",
            &format!(
                "NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ); \
                 {inner_kubectl} -n kube-system patch job {job} --subresource=status --type=merge \
                 -p=\"{{\\\"status\\\":{{\\\"succeeded\\\":1,\\\"active\\\":0,\\\"failed\\\":0,\\\"completionTime\\\":\\\"$NOW\\\",\\\"conditions\\\":[{{\\\"type\\\":\\\"SuccessCriteriaMet\\\",\\\"status\\\":\\\"True\\\",\\\"lastProbeTime\\\":\\\"$NOW\\\",\\\"lastTransitionTime\\\":\\\"$NOW\\\"}},{{\\\"type\\\":\\\"Complete\\\",\\\"status\\\":\\\"True\\\",\\\"lastProbeTime\\\":\\\"$NOW\\\",\\\"lastTransitionTime\\\":\\\"$NOW\\\"}}]}}}}\" \
                 && echo status-ok"
            ),
        );
        if matches!(patch, Ok(ref s) if s.contains("status-ok")) {
            eprintln!("  marked {job} Complete (charts already installed via /cri/helm)");
        } else {
            eprintln!("  helm job status patch {job}: {patch:?}");
        }
    }
}

fn wait_helm_install_complete(bridge: &str, server_pod: &str, profile: &InnerClusterProfile) {
    let start = Instant::now();
    let mut last_patch = Instant::now()
        .checked_sub(Duration::from_secs(30))
        .unwrap_or_else(Instant::now);
    let mut charts_installed = false;
    loop {
        let mut done = 0;
        for name in helm_job_names() {
            let path = format!("/apis/batch/v1/namespaces/kube-system/jobs/{name}");
            match curl_inner_api(bridge, &path) {
                Ok(body) => {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                        let succeeded = v["status"]["succeeded"].as_u64().unwrap_or(0);
                        if succeeded >= 1 {
                            done += 1;
                            continue;
                        }
                        eprintln!(
                            "  helm job {name} via {bridge}: succeeded={succeeded} \
                             failed={} active={}",
                            v["status"]["failed"].as_u64().unwrap_or(0),
                            v["status"]["active"].as_u64().unwrap_or(0)
                        );
                    }
                }
                Err(e) => eprintln!("  helm job {name} get via {bridge}: {e}"),
            }
        }
        if done == helm_job_names().len() {
            eprintln!("  helm-install-traefik-crd + helm-install-traefik Complete via {bridge}");
            return;
        }
        if last_patch.elapsed() >= Duration::from_secs(20) {
            if !charts_installed {
                charts_installed = install_bundled_traefik_charts(profile);
            }
            if charts_installed {
                mark_helm_jobs_complete(profile);
            } else {
                patch_helm_jobs_for_nested_runc(profile);
            }
            last_patch = Instant::now();
        }
        if start.elapsed() > Duration::from_secs(420) {
            let jobs = curl_inner_api(bridge, "/apis/batch/v1/namespaces/kube-system/jobs")
                .unwrap_or_else(|e| format!("jobs err: {e}"));
            let pods = curl_inner_api(bridge, "/api/v1/namespaces/kube-system/pods")
                .unwrap_or_else(|e| format!("pods err: {e}"));
            let describe = kubectl_exec_in(
                server_pod,
                "k3s",
                "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl \
                 -n kube-system get helmcharts,jobs,pods -o wide 2>&1; \
                 KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl \
                 -n kube-system describe job helm-install-traefik-crd helm-install-traefik 2>&1 | tail -80; \
                 KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl \
                 -n kube-system logs -l helmcharts.helm.cattle.io/chart --tail=80 2>&1; \
                 /bin/ctr --address /cri/containerd.sock -n k8s.io images ls 2>&1 | head -50; \
                 echo '--- flatten ---'; tail -20 /tmp/k7-flatten-vols.log 2>&1; \
                 echo '--- etc-hosts k3s vs cri ---'; \
                 for f in /var/lib/kubelet/pods/*/etc-hosts; do \
                   [ -e \"$f\" ] || continue; \
                   uid=$(basename $(dirname \"$f\")); \
                   echo -n \"$uid k3s=\"; stat -c '%F' \"$f\"; \
                   echo -n \"$uid cri=\"; stat -c '%F' /cri/kubelet-pods/$uid/etc-hosts 2>&1; \
                 done",
            )
            .unwrap_or_else(|e| format!("describe err: {e}"));
            panic!(
                "traefik HelmChart jobs never Completed via {bridge}\n\
                 jobs: {}\n\
                 pods: {}\n\
                 in-guest: {describe}",
                jobs.chars().take(4000).collect::<String>(),
                pods.chars().take(4000).collect::<String>()
            );
        }
        thread::sleep(Duration::from_secs(4));
    }
}

/// Nested runc cannot consume kubelet projected SA tokens (CHALLENGES
/// #88). Mint a bound token onto `/cri` on every member and point the
/// Traefik Deployment at that hostPath; also pin `imagePullPolicy: Never`.
fn patch_traefik_for_nested_runc(profile: &InnerClusterProfile) {
    let server_pod = profile.live_pod(0);
    let inner_kubectl = "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl";
    let start = Instant::now();
    loop {
        let exists = kubectl_exec_in(
            &server_pod,
            "k3s",
            &format!("{inner_kubectl} -n kube-system get deploy traefik 2>&1"),
        );
        if matches!(exists, Ok(ref s) if s.contains("traefik")) {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(180),
            "traefik Deployment never appeared so it could be patched: {exists:?}"
        );
        thread::sleep(Duration::from_secs(3));
    }
    let sa = kubectl_exec_retry(
        &server_pod,
        "k3s",
        &format!(
            "mkdir -p /cri/traefik-sa && \
             echo kube-system > /cri/traefik-sa/namespace && \
             {inner_kubectl} -n kube-system get cm kube-root-ca.crt \
               -o jsonpath='{{.data.ca\\.crt}}' > /cri/traefik-sa/ca.crt && \
             {inner_kubectl} -n kube-system create token traefik --duration=2h \
               > /cri/traefik-sa/token && \
             test -s /cri/traefik-sa/token && test -s /cri/traefik-sa/ca.crt && echo sa-ok"
        ),
        5,
    );
    assert!(
        matches!(sa, Ok(ref s) if s.contains("sa-ok")),
        "failed to stage Traefik SA token on /cri: {sa:?}"
    );
    let token = kubectl_exec_in(&server_pod, "k3s", "cat /cri/traefik-sa/token")
        .expect("read staged Traefik SA token");
    let ca = kubectl_exec_in(&server_pod, "k3s", "cat /cri/traefik-sa/ca.crt")
        .expect("read staged Traefik CA");
    for pod in profile.live_pods() {
        if pod == server_pod {
            continue;
        }
        let replica = kubectl_exec_retry(
            &pod,
            "k3s",
            &format!(
                "mkdir -p /cri/traefik-sa && \
                 cat > /cri/traefik-sa/token <<'EOF'\n{token}\nEOF\n\
                 cat > /cri/traefik-sa/ca.crt <<'EOF'\n{ca}\nEOF\n\
                 echo kube-system > /cri/traefik-sa/namespace && \
                 test -s /cri/traefik-sa/token && echo sa-ok"
            ),
            5,
        );
        assert!(
            matches!(replica, Ok(ref s) if s.contains("sa-ok")),
            "failed to stage Traefik SA on {pod}: {replica:?}"
        );
    }
    let patch = kubectl_exec_retry(
        &server_pod,
        "k3s",
        &format!(
            "{inner_kubectl} -n kube-system patch deploy traefik --type=json \
             -p='[\
               {{\"op\":\"add\",\"path\":\"/spec/template/spec/automountServiceAccountToken\",\"value\":false}},\
               {{\"op\":\"add\",\"path\":\"/spec/template/spec/volumes/-\",\
                 \"value\":{{\"name\":\"traefik-sa\",\"hostPath\":{{\"path\":\"/cri/traefik-sa\",\"type\":\"Directory\"}}}}}},\
               {{\"op\":\"add\",\"path\":\"/spec/template/spec/containers/0/volumeMounts/-\",\
                 \"value\":{{\"name\":\"traefik-sa\",\"mountPath\":\"/var/run/secrets/kubernetes.io/serviceaccount\",\"readOnly\":true}}}},\
               {{\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/0/imagePullPolicy\",\"value\":\"Never\"}}\
             ]' && echo patch-ok"
        ),
        5,
    );
    assert!(
        matches!(patch, Ok(ref s) if s.contains("patch-ok")),
        "traefik hostPath SA patch failed: {patch:?}"
    );
    eprintln!(
        "  patched traefik: SA token via /cri hostPath on every member, imagePullPolicy=Never"
    );
}

fn wait_traefik_ready_via(bridge: &str, server_pod: Option<&str>) {
    let path = "/apis/apps/v1/namespaces/kube-system/deployments/traefik";
    let start = Instant::now();
    loop {
        match curl_inner_api(bridge, path) {
            Ok(body) => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                    let ready = v["status"]["readyReplicas"].as_u64().unwrap_or(0);
                    if ready >= 1 {
                        eprintln!("  traefik readyReplicas={ready} via {bridge}");
                        return;
                    }
                    eprintln!("  traefik not ready yet via {bridge}: readyReplicas={ready}");
                }
            }
            Err(e) => eprintln!("  traefik get via {bridge}: {e}"),
        }
        if start.elapsed() > Duration::from_secs(300) {
            let pods = curl_inner_api(
                bridge,
                "/api/v1/namespaces/kube-system/pods?labelSelector=app.kubernetes.io/name=traefik",
            )
            .unwrap_or_else(|e| format!("pods err: {e}"));
            let describe = if let Some(pod) = server_pod {
                kubectl_exec_in(
                    pod,
                    "k3s",
                    "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl \
                     -n kube-system describe deploy/traefik 2>&1 | tail -40; \
                     KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl \
                     -n kube-system get pods -o wide 2>&1; \
                     KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl \
                     -n kube-system describe pod -l app.kubernetes.io/name=traefik 2>&1 | tail -80; \
                     KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl \
                     -n kube-system logs -l app.kubernetes.io/name=traefik --tail=60 2>&1",
                )
                .unwrap_or_else(|e| format!("describe err: {e}"))
            } else {
                String::new()
            };
            panic!(
                "traefik Deployment never Ready via {bridge}\n\
                 traefik pods: {}\n\
                 in-guest: {describe}",
                pods.chars().take(6000).collect::<String>()
            );
        }
        thread::sleep(Duration::from_secs(3));
    }
}

fn assert_traefik_lb_ips_via(profile: &InnerClusterProfile, bridge: &str) {
    let body = curl_inner_api(bridge, "/api/v1/namespaces/kube-system/services/traefik")
        .expect("GET traefik Service");
    let v: serde_json::Value = serde_json::from_str(&body).expect("traefik Service json");
    let ingress = v["status"]["loadBalancer"]["ingress"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let ips: Vec<String> = ingress
        .iter()
        .filter_map(|e| e["ip"].as_str().map(str::to_string))
        .collect();
    for idx in 0..profile.vm_count {
        let want = profile.guest_ip(idx);
        assert!(
            ips.iter().any(|ip| ip == &want),
            "traefik LoadBalancer ingress missing guest IP {want}: {ips:?}"
        );
    }
    eprintln!("  traefik LoadBalancer ingress IPs={ips:?} via {bridge}");
}

fn assert_svclb_running_via(profile: &InnerClusterProfile, bridge: &str) {
    let body = curl_inner_api(
        bridge,
        "/api/v1/namespaces/kube-system/pods?labelSelector=svccontroller.k3s.cattle.io/svcname=traefik",
    )
    .expect("GET svclb-traefik pods");
    let v: serde_json::Value = serde_json::from_str(&body).expect("svclb pods json");
    let items = v["items"].as_array().cloned().unwrap_or_default();
    let running = items
        .iter()
        .filter(|p| p["status"]["phase"].as_str() == Some("Running"))
        .count();
    assert!(
        running >= profile.vm_count,
        "expected ≥{} Running svclb-traefik pods via {bridge}, got {running} (items={})",
        profile.vm_count,
        items.len()
    );
    eprintln!("  svclb-traefik Running={running} via {bridge}");
}

fn ingress_backend_manifest() -> String {
    format!(
        "apiVersion: apps/v1\n\
         kind: Deployment\n\
         metadata:\n\
         \x20 name: inner-http\n\
         spec:\n\
         \x20 replicas: 1\n\
         \x20 selector:\n\
         \x20   matchLabels:\n\
         \x20     app: inner-http\n\
         \x20 template:\n\
         \x20   metadata:\n\
         \x20     labels:\n\
         \x20       app: inner-http\n\
         \x20   spec:\n\
         \x20     automountServiceAccountToken: false\n\
         \x20     containers:\n\
         \x20     - name: httpd\n\
         \x20       image: {INNER3_BUSYBOX_REF}\n\
         \x20       imagePullPolicy: Never\n\
         \x20       command: [\"/bin/sh\", \"-c\"]\n\
         \x20       args:\n\
         \x20       - |\n\
         \x20         mkdir -p /www && echo {INNER_HTTP_MARKER} > /www/index.html && \
         exec httpd -f -p 80 -h /www\n\
         ---\n\
         apiVersion: v1\n\
         kind: Service\n\
         metadata:\n\
         \x20 name: inner-http\n\
         spec:\n\
         \x20 selector:\n\
         \x20   app: inner-http\n\
         \x20 ports:\n\
         \x20 - port: 80\n\
         \x20   targetPort: 80\n\
         ---\n\
         apiVersion: networking.k8s.io/v1\n\
         kind: Ingress\n\
         metadata:\n\
         \x20 name: inner-http\n\
         spec:\n\
         \x20 ingressClassName: traefik\n\
         \x20 rules:\n\
         \x20 - host: {INNER_HTTP_HOST}\n\
         \x20   http:\n\
         \x20     paths:\n\
         \x20     - path: /\n\
         \x20       pathType: Prefix\n\
         \x20       backend:\n\
         \x20         service:\n\
         \x20           name: inner-http\n\
         \x20           port:\n\
         \x20             number: 80\n"
    )
}

fn wait_inner_http_via(bridge: &str, label: &str) {
    let start = Instant::now();
    loop {
        let last = curl_inner_http(bridge, INNER_HTTP_HOST, "/");
        if let Ok(ref body) = last {
            if body.contains(INNER_HTTP_MARKER) {
                eprintln!("  {label}: ingress GET via {bridge} returned {INNER_HTTP_MARKER}");
                return;
            }
            eprintln!(
                "  {label}: unexpected body via {bridge}: {}",
                body.chars().take(200).collect::<String>()
            );
        } else {
            eprintln!("  {label}: ingress GET via {bridge}: {last:?}");
        }
        if start.elapsed() > Duration::from_secs(180) {
            panic!(
                "{label}: ingress GET never returned {INNER_HTTP_MARKER} via {bridge}: {last:?}"
            );
        }
        thread::sleep(Duration::from_secs(2));
    }
}

/// ServiceLB + Traefik on a dedicated profile: HTTP through the Ingress
/// on the source, then the same claim on source and fork after a warm fork.
#[test]
fn test_inner_k3s_ingress_fork() {
    let _leak_guard = ensure_shim_installed();
    let profile = InnerClusterProfile::ingress_3node();
    bring_up_inner_cluster(&profile);

    extract_inner_certs();
    let source_bridge = inner3_bridge();
    let bridges_before = list_k7_bridges();
    assert!(
        bridges_before.contains(&source_bridge),
        "inner3 bridge missing: {bridges_before:?}"
    );
    let ready = curl_inner_api(&source_bridge, "/readyz").expect("pre-adopt /readyz");
    assert!(ready.contains("ok"), "pre-adopt /readyz not ok: {ready}");

    let server_pod = profile.live_pod(0);
    wait_coredns_ready_via(&source_bridge, Some(&server_pod));
    wait_helm_install_complete(&source_bridge, &server_pod, &profile);
    patch_traefik_for_nested_runc(&profile);
    wait_traefik_ready_via(&source_bridge, Some(&server_pod));
    assert_traefik_lb_ips_via(&profile, &source_bridge);
    assert_svclb_running_via(&profile, &source_bridge);

    let inner_kubectl = "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl";
    let manifest = ingress_backend_manifest();
    let apply = kubectl_exec_retry(
        &server_pod,
        "k3s",
        &format!(
            "cat > /tmp/inner-http.yaml <<'EOF'\n{manifest}EOF\n\
             {inner_kubectl} apply -f /tmp/inner-http.yaml && echo ingress-ok"
        ),
        3,
    );
    assert!(
        matches!(apply, Ok(ref s) if s.contains("ingress-ok")),
        "inner-http Ingress apply failed: {apply:?}"
    );
    wait_inner_http_via(&source_bridge, "pre-fork");

    let mut client = Client::connect_env().expect("connect k7d daemon");
    let vm_ids = discover_inner_vm_ids(&mut client, &profile);
    eprintln!("  discovered ingress-profile vm_ids={vm_ids:?}");

    let tree_id = format!("i3ing-{}", common::run_id());
    let (tree_id, root_id, root_cids) = match client.call(&Request::TreeAdoptCluster {
        ksm: false,
        vm_ids,
        budget: Some(inner3_tree_budget()),
        tree_id: Some(tree_id),
        egress: None,
        dilation_policy: None,
        dilation_config: None,
    }) {
        Ok(Response::TreeCreated {
            tree_id,
            root_id,
            guest_cids,
            ..
        }) => {
            assert_eq!(
                guest_cids.len(),
                profile.vm_count,
                "adopted root must have {} members",
                profile.vm_count
            );
            (tree_id, root_id, guest_cids)
        }
        Ok(other) => {
            delete_inner_pods(&profile);
            panic!("unexpected TreeAdoptCluster response: {other:?}");
        }
        Err(e) => {
            delete_inner_pods(&profile);
            panic!("TreeAdoptCluster transport error: {e}");
        }
    };
    common::mark_test_tree(&tree_id);
    eprintln!("  adopted tree={tree_id} root_cids={root_cids:?}");

    let teardown = |client: &mut Client| {
        let _ = client.call(&Request::TreeDrop {
            tree_id: tree_id.clone(),
        });
        delete_inner_pods(&profile);
        let _ = std::fs::remove_dir_all(format!("/var/lib/k7d/trees/{tree_id}"));
    };

    let start = Instant::now();
    loop {
        if matches!(curl_inner_api(&source_bridge, "/readyz"), Ok(ref b) if b.contains("ok")) {
            break;
        }
        if start.elapsed() > Duration::from_secs(120) {
            let last = curl_inner_api(&source_bridge, "/readyz");
            teardown(&mut client);
            panic!("source API never recovered after adopt/prepare (last: {last:?})");
        }
        thread::sleep(Duration::from_secs(2));
    }

    let fork_start = Instant::now();
    let (fork_node, fork_cids, latency_ns) = match client.call(&Request::TreeFork {
        tree_id: tree_id.clone(),
        source_id: root_id.clone(),
        label: "warm".to_string(),
        dilation: None,
        dilation_policy: None,
        dilation_config: None,
    }) {
        Ok(Response::TreeForked {
            node_id,
            guest_cids,
            fork_memory_full_copy,
            latency_ns,
            ..
        }) => {
            assert_eq!(
                guest_cids.len(),
                profile.vm_count,
                "fork must clone every member"
            );
            assert_eq!(
                fork_memory_full_copy,
                vec![false; profile.vm_count],
                "inner-k3s cluster fork must be CoW on every member"
            );
            (node_id, guest_cids, latency_ns)
        }
        Ok(other) => {
            teardown(&mut client);
            panic!("unexpected TreeFork response: {other:?}");
        }
        Err(e) => {
            teardown(&mut client);
            panic!("TreeFork transport error: {e}");
        }
    };
    let fork_elapsed = fork_start.elapsed();
    eprintln!(
        "  TreeFork (ingress profile) node={fork_node} cids={fork_cids:?} \
         elapsed={fork_elapsed:?} budget={FORK_INNER_K3S_CLUSTER_3VM:?}"
    );
    if let Ok(journal) = Command::new("journalctl")
        .args(["-u", "k7d", "--no-pager", "--since", "-3min"])
        .output()
    {
        for line in String::from_utf8_lossy(&journal.stdout)
            .lines()
            .filter(|l| {
                l.contains("full memfd copy")
                    || l.contains("fork_cluster_warm")
                    || l.contains("cluster_tree fork_batch")
            })
        {
            eprintln!("  daemon: {line}");
        }
    }
    common::tree_fork_budget::assert_tree_fork_budget(
        "ingress-profile",
        fork_elapsed,
        latency_ns,
        FORK_INNER_K3S_CLUSTER_3VM,
    );

    let fork_bridge = list_k7_bridges()
        .into_iter()
        .find(|b| !bridges_before.contains(b))
        .expect("fork bridge appeared");
    eprintln!("  source bridge={source_bridge} fork bridge={fork_bridge}");

    let resume = Instant::now();
    loop {
        if matches!(curl_inner_api(&source_bridge, "/readyz"), Ok(ref b) if b.contains("ok")) {
            break;
        }
        if resume.elapsed() > Duration::from_secs(60) {
            let last = curl_inner_api(&source_bridge, "/readyz");
            teardown(&mut client);
            panic!("source /readyz never recovered after TreeFork resume (last: {last:?})");
        }
        thread::sleep(Duration::from_millis(500));
    }

    assert_ready_nodes_via(&profile, &source_bridge, "source");
    assert_ready_nodes_via(&profile, &fork_bridge, "fork");
    wait_traefik_ready_via(&source_bridge, Some(&server_pod));
    wait_traefik_ready_via(&fork_bridge, None);
    wait_inner_http_via(&source_bridge, "post-fork source");
    wait_inner_http_via(&fork_bridge, "post-fork fork");
    eprintln!("  post-fork ingress marker on both bridges elapsed={fork_elapsed:?}");

    teardown(&mut client);
}

const INNER_PVC_NAME: &str = "inner-pvc";
const INNER_PVC_WRITER: &str = "inner-pvc-writer";

/// Nested runc cannot consume kubelet ConfigMap or projected-token
/// volumes (CHALLENGES #87/#88). Stage `local-path-config` + a minted
/// SA token onto `/cri` on every member, point the Deployment at those
/// hostPaths, disable automount, and pin to `inner-server`.
fn patch_local_path_for_nested_runc(profile: &InnerClusterProfile) {
    let server_pod = profile.live_pod(0);
    let inner_kubectl = "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl";
    let start = Instant::now();
    loop {
        let exists = kubectl_exec_in(
            &server_pod,
            "k3s",
            &format!("{inner_kubectl} -n kube-system get deploy local-path-provisioner 2>&1"),
        );
        if matches!(exists, Ok(ref s) if s.contains("local-path-provisioner")) {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(120),
            "local-path-provisioner Deployment never appeared so it could be patched: {exists:?}"
        );
        thread::sleep(Duration::from_secs(2));
    }
    let setup = kubectl_exec_retry(
        &server_pod,
        "k3s",
        &format!(
            "mkdir -p /cri/local-path-config && \
             {inner_kubectl} -n kube-system get cm local-path-config \
               -o jsonpath='{{.data.config\\.json}}' > /cri/local-path-config/config.json && \
             {inner_kubectl} -n kube-system get cm local-path-config \
               -o jsonpath='{{.data.setup}}' > /cri/local-path-config/setup && \
             {inner_kubectl} -n kube-system get cm local-path-config \
               -o jsonpath='{{.data.teardown}}' > /cri/local-path-config/teardown && \
             test -s /cri/local-path-config/config.json && echo lpp-config-ok"
        ),
        5,
    );
    assert!(
        matches!(setup, Ok(ref s) if s.contains("lpp-config-ok")),
        "failed to stage local-path-config on /cri: {setup:?}"
    );
    let helper = format!(
        "apiVersion: v1\n\
         kind: Pod\n\
         metadata:\n\
         \x20 name: helper-pod\n\
         spec:\n\
         \x20 automountServiceAccountToken: false\n\
         \x20 containers:\n\
         \x20 - name: helper-pod\n\
         \x20   image: {INNER3_LPP_HELPER_SHORT_REF}\n\
         \x20   imagePullPolicy: Never\n"
    );
    let helper_write = kubectl_exec_retry(
        &server_pod,
        "k3s",
        &format!(
            "cat > /cri/local-path-config/helperPod.yaml <<'LPP_HELPER'\n{helper}LPP_HELPER\n\
                  test -s /cri/local-path-config/helperPod.yaml && echo helper-ok"
        ),
        3,
    );
    assert!(
        matches!(helper_write, Ok(ref s) if s.contains("helper-ok")),
        "failed to stage helperPod.yaml: {helper_write:?}"
    );
    let sa = kubectl_exec_retry(
        &server_pod,
        "k3s",
        &format!(
            "mkdir -p /cri/lpp-sa && \
             echo kube-system > /cri/lpp-sa/namespace && \
             {inner_kubectl} -n kube-system get cm kube-root-ca.crt \
               -o jsonpath='{{.data.ca\\.crt}}' > /cri/lpp-sa/ca.crt && \
             {inner_kubectl} -n kube-system create token \
               local-path-provisioner-service-account --duration=2h \
               > /cri/lpp-sa/token && \
             test -s /cri/lpp-sa/token && test -s /cri/lpp-sa/ca.crt && echo sa-ok"
        ),
        5,
    );
    assert!(
        matches!(sa, Ok(ref s) if s.contains("sa-ok")),
        "failed to stage local-path-provisioner SA token on /cri: {sa:?}"
    );
    let config_json = kubectl_exec_in(&server_pod, "k3s", "cat /cri/local-path-config/config.json")
        .expect("read staged local-path config.json")
        .replace("/var/lib/rancher/k3s/storage", "/cri/k3s-storage");
    assert!(
        config_json.contains("/cri/k3s-storage"),
        "local-path config.json must use the shared /cri path, got: {config_json}"
    );
    let rewrite = kubectl_exec_retry(
        &server_pod,
        "k3s",
        &format!(
            "mkdir -p /cri/k3s-storage && \
             cat > /cri/local-path-config/config.json <<'LPP_EOF'\n{config_json}\nLPP_EOF\n\
             test -s /cri/local-path-config/config.json && echo rewrite-ok"
        ),
        3,
    );
    assert!(
        matches!(rewrite, Ok(ref s) if s.contains("rewrite-ok")),
        "failed to rewrite local-path config.json onto /cri/k3s-storage: {rewrite:?}"
    );
    let setup_script =
        kubectl_exec_in(&server_pod, "k3s", "cat /cri/local-path-config/setup").unwrap_or_default();
    let teardown_script =
        kubectl_exec_in(&server_pod, "k3s", "cat /cri/local-path-config/teardown")
            .unwrap_or_default();
    let token = kubectl_exec_in(&server_pod, "k3s", "cat /cri/lpp-sa/token")
        .expect("read staged LPP SA token");
    let ca =
        kubectl_exec_in(&server_pod, "k3s", "cat /cri/lpp-sa/ca.crt").expect("read staged LPP CA");
    for pod in profile.live_pods() {
        if pod == server_pod {
            continue;
        }
        let replica = kubectl_exec_retry(
            &pod,
            "k3s",
            &format!(
                "mkdir -p /cri/local-path-config /cri/lpp-sa /cri/k3s-storage && \
                 cat > /cri/local-path-config/config.json <<'LPP_EOF'\n{config_json}\nLPP_EOF\n\
                 cat > /cri/local-path-config/setup <<'LPP_EOF'\n{setup_script}\nLPP_EOF\n\
                 cat > /cri/local-path-config/teardown <<'LPP_EOF'\n{teardown_script}\nLPP_EOF\n\
                 cat > /cri/local-path-config/helperPod.yaml <<'LPP_HELPER'\n{helper}LPP_HELPER\n\
                 cat > /cri/lpp-sa/token <<'LPP_EOF'\n{token}\nLPP_EOF\n\
                 cat > /cri/lpp-sa/ca.crt <<'LPP_EOF'\n{ca}\nLPP_EOF\n\
                 echo kube-system > /cri/lpp-sa/namespace && \
                 test -s /cri/local-path-config/config.json && test -s /cri/lpp-sa/token && echo lpp-ok"
            ),
            5,
        );
        assert!(
            matches!(replica, Ok(ref s) if s.contains("lpp-ok")),
            "failed to stage local-path config/SA on {pod}: {replica:?}"
        );
    }
    let patch = kubectl_exec_retry(
        &server_pod,
        "k3s",
        &format!(
            "{inner_kubectl} -n kube-system patch deploy local-path-provisioner --type=json \
             -p='[\
               {{\"op\":\"remove\",\"path\":\"/spec/template/spec/volumes/0/configMap\"}},\
               {{\"op\":\"add\",\"path\":\"/spec/template/spec/volumes/0/hostPath\",\
                 \"value\":{{\"path\":\"/cri/local-path-config\",\"type\":\"Directory\"}}}},\
               {{\"op\":\"add\",\"path\":\"/spec/template/spec/nodeSelector/kubernetes.io~1hostname\",\"value\":\"inner-server\"}},\
               {{\"op\":\"add\",\"path\":\"/spec/template/spec/automountServiceAccountToken\",\"value\":false}},\
               {{\"op\":\"add\",\"path\":\"/spec/template/spec/volumes/-\",\
                 \"value\":{{\"name\":\"lpp-sa\",\"hostPath\":{{\"path\":\"/cri/lpp-sa\",\"type\":\"Directory\"}}}}}},\
               {{\"op\":\"add\",\"path\":\"/spec/template/spec/containers/0/volumeMounts/-\",\
                 \"value\":{{\"name\":\"lpp-sa\",\"mountPath\":\"/var/run/secrets/kubernetes.io/serviceaccount\",\"readOnly\":true}}}},\
               {{\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/0/imagePullPolicy\",\"value\":\"Never\"}}\
             ]' && echo patch-ok"
        ),
        5,
    );
    assert!(
        matches!(patch, Ok(ref s) if s.contains("patch-ok")),
        "local-path-provisioner hostPath patch failed: {patch:?}"
    );
    eprintln!(
        "  patched local-path-provisioner: config + SA via /cri hostPath on every member, pinned to inner-server"
    );
}

fn wait_local_path_ready_via(bridge: &str, server_pod: Option<&str>) {
    let path = "/apis/apps/v1/namespaces/kube-system/deployments/local-path-provisioner";
    let start = Instant::now();
    loop {
        match curl_inner_api(bridge, path) {
            Ok(body) => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                    let ready = v["status"]["readyReplicas"].as_u64().unwrap_or(0);
                    if ready >= 1 {
                        eprintln!("  local-path-provisioner readyReplicas={ready} via {bridge}");
                        return;
                    }
                    eprintln!(
                        "  local-path-provisioner not ready yet via {bridge}: readyReplicas={ready}"
                    );
                }
            }
            Err(e) => eprintln!("  local-path-provisioner get via {bridge}: {e}"),
        }
        if start.elapsed() > Duration::from_secs(300) {
            let pods = curl_inner_api(
                bridge,
                "/api/v1/namespaces/kube-system/pods?labelSelector=app=local-path-provisioner",
            )
            .unwrap_or_else(|e| format!("pods err: {e}"));
            let describe = if let Some(pod) = server_pod {
                kubectl_exec_in(
                    pod,
                    "k3s",
                    "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl \
                     -n kube-system describe deploy/local-path-provisioner 2>&1 | tail -40; \
                     KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl \
                     -n kube-system get pods -o wide 2>&1; \
                     KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl \
                     -n kube-system describe pod -l app=local-path-provisioner 2>&1 | tail -80; \
                     KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl \
                     -n kube-system logs -l app=local-path-provisioner --tail=60 2>&1",
                )
                .unwrap_or_else(|e| format!("describe err: {e}"))
            } else {
                String::new()
            };
            panic!(
                "local-path-provisioner Deployment never Ready via {bridge}\n\
                 pods: {}\n\
                 in-guest: {describe}",
                pods.chars().take(6000).collect::<String>()
            );
        }
        thread::sleep(Duration::from_secs(3));
    }
}

fn assert_local_path_storageclass_via(bridge: &str) {
    let body = curl_inner_api(bridge, "/apis/storage.k8s.io/v1/storageclasses/local-path")
        .expect("GET StorageClass local-path");
    let v: serde_json::Value = serde_json::from_str(&body).expect("StorageClass json");
    assert_eq!(
        v["metadata"]["name"].as_str(),
        Some("local-path"),
        "StorageClass local-path missing via {bridge}: {body}"
    );
    eprintln!("  StorageClass local-path present via {bridge}");
}

fn hostpath_busybox_pod_json(
    name: &str,
    node: &str,
    host_path: &str,
    command: &str,
    restart: &str,
) -> String {
    serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name},
        "spec": {
            "nodeSelector": {"kubernetes.io/hostname": node},
            "automountServiceAccountToken": false,
            "restartPolicy": restart,
            "containers": [{
                "name": "vol",
                "image": INNER3_BUSYBOX_REF,
                "imagePullPolicy": "Never",
                "command": ["/bin/sh", "-c"],
                "args": [command],
                "volumeMounts": [{"name": "data", "mountPath": "/data"}]
            }],
            "volumes": [{
                "name": "data",
                "hostPath": {"path": host_path, "type": "Directory"}
            }]
        }
    })
    .to_string()
}

fn wait_inner_pod_phase_via(bridge: &str, name: &str, want: &str, timeout: Duration) {
    let path = format!("/api/v1/namespaces/default/pods/{name}");
    let start = Instant::now();
    loop {
        match curl_inner_api(bridge, &path) {
            Ok(body) => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                    let phase = v["status"]["phase"].as_str().unwrap_or("");
                    if phase == want {
                        eprintln!("  pod {name} {want} via {bridge}");
                        return;
                    }
                    if phase == "Failed" && want != "Failed" {
                        let log = inner_pod_log_via(bridge, name).unwrap_or_default();
                        let events = inner_pod_events_via(bridge, name);
                        panic!(
                            "pod {name} Failed via {bridge} (wanted {want})\n\
                             log: {log}\n{body}\nevents: {events}"
                        );
                    }
                }
            }
            Err(e) => eprintln!("  get pod {name} via {bridge}: {e}"),
        }
        if start.elapsed() > timeout {
            let last = curl_inner_api(bridge, &path).unwrap_or_else(|e| e);
            let log = inner_pod_log_via(bridge, name).unwrap_or_default();
            let events = inner_pod_events_via(bridge, name);
            panic!(
                "pod {name} never reached {want} via {bridge} within {timeout:?}\n\
                 last: {last}\nlog: {log}\nevents: {events}"
            );
        }
        thread::sleep(Duration::from_secs(2));
    }
}

fn inner_pod_events_via(bridge: &str, name: &str) -> String {
    curl_inner_api(
        bridge,
        &format!("/api/v1/namespaces/default/events?fieldSelector=involvedObject.name={name}"),
    )
    .unwrap_or_else(|e| format!("events err: {e}"))
}

fn inner_pod_log_via(bridge: &str, name: &str) -> Result<String, String> {
    curl_inner_api(
        bridge,
        &format!("/api/v1/namespaces/default/pods/{name}/log?container=vol"),
    )
}

fn rest_create_inner_pod(bridge: &str, json: &str) -> Result<String, String> {
    curl_inner_api_post(bridge, "/api/v1/namespaces/default/pods", json)
}

fn marker_line(body: &str, marker: &str) -> Option<String> {
    body.lines()
        .find(|l| l.contains(marker))
        .map(|l| l.trim().to_string())
}

/// local-path PVC on a dedicated profile: the provisioner creates a
/// directory on in-guest tmpfs (`/cri/k3s-storage`, guest RAM — k3s's
/// default `/var/lib/rancher` tree is also tmpfs). Writer/reader pods
/// hostPath that provisioned path: kubelet's `local` volume bind lives
/// in the k3s mount ns and is empty to sidecar runc (CHALLENGES #91).
/// After a warm fork, REST-created readers on both bridges return the
/// marker; side-specific appends then diverge.
///
/// The volume is **not** disk-durable across a VM restart — the bytes
/// live in guest RAM, which is exactly why CoW fork preserves them.
#[test]
fn test_inner_k3s_local_path_pvc_fork() {
    let _leak_guard = ensure_shim_installed();
    let profile = InnerClusterProfile::local_path_3node();
    bring_up_inner_cluster(&profile);

    extract_inner_certs();
    let source_bridge = inner3_bridge();
    let bridges_before = list_k7_bridges();
    assert!(
        bridges_before.contains(&source_bridge),
        "inner3 bridge missing: {bridges_before:?}"
    );
    let ready = curl_inner_api(&source_bridge, "/readyz").expect("pre-adopt /readyz");
    assert!(ready.contains("ok"), "pre-adopt /readyz not ok: {ready}");

    let server_pod = profile.live_pod(0);
    wait_coredns_ready_via(&source_bridge, Some(&server_pod));
    wait_local_path_ready_via(&source_bridge, Some(&server_pod));
    assert_local_path_storageclass_via(&source_bridge);

    let marker = format!("PVC_MARKER_{}", common::run_id());
    let src_token = format!("src-{}", common::run_id());
    let fork_token = format!("fork-{}", common::run_id());
    let writer_node = profile.node_name(0);
    let inner_kubectl = "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl";
    let bind_pod = "inner-pvc-bind";
    let manifest = format!(
        "apiVersion: v1\n\
         kind: PersistentVolumeClaim\n\
         metadata:\n\
         \x20 name: {INNER_PVC_NAME}\n\
         spec:\n\
         \x20 accessModes: [\"ReadWriteOnce\"]\n\
         \x20 storageClassName: local-path\n\
         \x20 resources:\n\
         \x20   requests:\n\
         \x20     storage: 64Mi\n\
         ---\n\
         apiVersion: v1\n\
         kind: Pod\n\
         metadata:\n\
         \x20 name: {bind_pod}\n\
         spec:\n\
         \x20 nodeSelector:\n\
         \x20   kubernetes.io/hostname: {writer_node}\n\
         \x20 automountServiceAccountToken: false\n\
         \x20 restartPolicy: Never\n\
         \x20 containers:\n\
         \x20 - name: bind\n\
         \x20   image: {INNER3_BUSYBOX_REF}\n\
         \x20   imagePullPolicy: Never\n\
         \x20   command: [\"/bin/sleep\", \"3600\"]\n\
         \x20   volumeMounts:\n\
         \x20   - name: data\n\
         \x20     mountPath: /data\n\
         \x20 volumes:\n\
         \x20 - name: data\n\
         \x20   persistentVolumeClaim:\n\
         \x20     claimName: {INNER_PVC_NAME}\n"
    );
    let apply = kubectl_exec_retry(
        &server_pod,
        "k3s",
        &format!(
            "cat > /tmp/inner-pvc.yaml <<'EOF'\n{manifest}EOF\n\
             {inner_kubectl} apply -f /tmp/inner-pvc.yaml && echo pvc-ok"
        ),
        3,
    );
    assert!(
        matches!(apply, Ok(ref s) if s.contains("pvc-ok")),
        "PVC + bind-trigger apply failed: {apply:?}"
    );

    let start = Instant::now();
    loop {
        let phase = kubectl_exec_in(
            &server_pod,
            "k3s",
            &format!(
                "{inner_kubectl} get pvc {INNER_PVC_NAME} \
                 -o jsonpath='{{.status.phase}}' 2>&1"
            ),
        );
        if matches!(phase, Ok(ref s) if s.trim() == "Bound") {
            eprintln!("  PVC {INNER_PVC_NAME} Bound");
            break;
        }
        if start.elapsed() > Duration::from_secs(180) {
            let describe = kubectl_exec_in(
                &server_pod,
                "k3s",
                &format!(
                    "{inner_kubectl} get pvc,pv,pod -o wide 2>&1; \
                     {inner_kubectl} describe pvc {INNER_PVC_NAME} 2>&1 | tail -40; \
                     {inner_kubectl} describe pod {bind_pod} 2>&1 | tail -60; \
                     {inner_kubectl} -n kube-system logs -l app=local-path-provisioner --tail=40 2>&1"
                ),
            );
            delete_inner_pods(&profile);
            panic!("PVC {INNER_PVC_NAME} never Bound: {phase:?}\n{describe:?}");
        }
        thread::sleep(Duration::from_secs(3));
    }

    let pv_path = kubectl_exec_in(
        &server_pod,
        "k3s",
        &format!(
            "PV=$({inner_kubectl} get pvc {INNER_PVC_NAME} -o jsonpath='{{.spec.volumeName}}') && \
             {inner_kubectl} get pv \"$PV\" -o jsonpath='{{.spec.local.path}}'"
        ),
    )
    .unwrap_or_default();
    assert!(
        pv_path.starts_with("/cri/k3s-storage/"),
        "PV local path must be on /cri/k3s-storage, got {pv_path:?}"
    );
    eprintln!("  PV path={pv_path}");
    let _ = kubectl_exec_in(
        &server_pod,
        "k3s",
        &format!("{inner_kubectl} delete pod {bind_pod} --wait=false 2>&1"),
    );

    let writer_yaml = format!(
        "apiVersion: v1\n\
         kind: Pod\n\
         metadata:\n\
         \x20 name: {INNER_PVC_WRITER}\n\
         spec:\n\
         \x20 nodeSelector:\n\
         \x20   kubernetes.io/hostname: {writer_node}\n\
         \x20 automountServiceAccountToken: false\n\
         \x20 restartPolicy: Always\n\
         \x20 containers:\n\
         \x20 - name: writer\n\
         \x20   image: {INNER3_BUSYBOX_REF}\n\
         \x20   imagePullPolicy: Never\n\
         \x20   command: [\"/bin/sh\", \"-c\"]\n\
         \x20   args:\n\
         \x20   - |\n\
         \x20     echo {marker} > /data/marker\n\
         \x20     while true; do\n\
         \x20       echo HB $(date +%s) >> /data/marker\n\
         \x20       sleep 2\n\
         \x20     done\n\
         \x20   volumeMounts:\n\
         \x20   - name: data\n\
         \x20     mountPath: /data\n\
         \x20 volumes:\n\
         \x20 - name: data\n\
         \x20   hostPath:\n\
         \x20     path: {pv_path}\n\
         \x20     type: Directory\n"
    );
    let writer_apply = kubectl_exec_retry(
        &server_pod,
        "k3s",
        &format!(
            "cat > /tmp/inner-pvc-writer.yaml <<'EOF'\n{writer_yaml}EOF\n\
             {inner_kubectl} apply -f /tmp/inner-pvc-writer.yaml && echo writer-ok"
        ),
        3,
    );
    assert!(
        matches!(writer_apply, Ok(ref s) if s.contains("writer-ok")),
        "hostPath writer apply failed: {writer_apply:?}"
    );

    let start = Instant::now();
    loop {
        let status = kubectl_exec_in(
            &server_pod,
            "k3s",
            &format!(
                "{inner_kubectl} get pod {INNER_PVC_WRITER} -o jsonpath='{{.status.phase}}' 2>&1"
            ),
        );
        if matches!(status, Ok(ref s) if s.trim() == "Running") {
            break;
        }
        if start.elapsed() > Duration::from_secs(180) {
            let describe = kubectl_exec_in(
                &server_pod,
                "k3s",
                &format!(
                    "{inner_kubectl} describe pod {INNER_PVC_WRITER} 2>&1 | tail -80; \
                     {inner_kubectl} get events --field-selector involvedObject.name={INNER_PVC_WRITER} 2>&1"
                ),
            );
            delete_inner_pods(&profile);
            panic!("writer {INNER_PVC_WRITER} never Running: {status:?}\n{describe:?}");
        }
        thread::sleep(Duration::from_secs(3));
    }

    let pinned = kubectl_exec_in(
        &server_pod,
        "k3s",
        &format!("{inner_kubectl} get pod {INNER_PVC_WRITER} -o jsonpath='{{.spec.nodeName}}'"),
    )
    .unwrap_or_default();
    assert_eq!(
        pinned.trim(),
        writer_node,
        "writer scheduled on {pinned:?}, not {writer_node}"
    );

    let start = Instant::now();
    let pre_marker = loop {
        let cat = kubectl_exec_in(
            &server_pod,
            "k3s",
            &format!("{inner_kubectl} exec {INNER_PVC_WRITER} -- cat /data/marker 2>&1"),
        );
        if let Ok(ref body) = cat {
            if let Some(line) = marker_line(body, &marker) {
                break line;
            }
        }
        if start.elapsed() > Duration::from_secs(60) {
            delete_inner_pods(&profile);
            panic!("pre-fork marker never readable: {cat:?}");
        }
        thread::sleep(Duration::from_secs(2));
    };
    eprintln!("  pre-fork marker={pre_marker}");
    let storage_ls = kubectl_exec_in(
        &server_pod,
        "containerd",
        &format!("echo '--- sidecar ---'; ls -la {pv_path} 2>&1; cat {pv_path}/marker 2>&1"),
    );
    eprintln!("  storage listing: {storage_ls:?}");
    assert!(
        matches!(storage_ls, Ok(ref s) if s.contains(&marker)),
        "sidecar must see the marker on the PV path {pv_path}: {storage_ls:?}"
    );
    let pre_reader = common::unique_name("inner-pvc-preread");
    let pre_reader_json = hostpath_busybox_pod_json(
        &pre_reader,
        &writer_node,
        &pv_path,
        "ls -la /data; cat /data/marker",
        "Never",
    );
    rest_create_inner_pod(&source_bridge, &pre_reader_json)
        .unwrap_or_else(|e| panic!("pre-fork POST reader {pre_reader}: {e}"));
    wait_inner_pod_phase_via(
        &source_bridge,
        &pre_reader,
        "Succeeded",
        Duration::from_secs(180),
    );
    let pre_log = inner_pod_log_via(&source_bridge, &pre_reader)
        .unwrap_or_else(|e| panic!("pre-fork reader log: {e}"));
    assert!(
        marker_line(&pre_log, &marker).as_deref() == Some(pre_marker.as_str()),
        "pre-fork REST reader missed marker\n{pre_log}"
    );
    let _ = curl_inner_api_delete(
        &source_bridge,
        &format!("/api/v1/namespaces/default/pods/{pre_reader}"),
    );
    eprintln!("  pre-fork REST reader saw {pre_marker}");

    let mut client = Client::connect_env().expect("connect k7d daemon");
    let vm_ids = discover_inner_vm_ids(&mut client, &profile);
    eprintln!("  discovered local-path-profile vm_ids={vm_ids:?}");

    let tree_id = format!("i3lpp-{}", common::run_id());
    let (tree_id, root_id, root_cids) = match client.call(&Request::TreeAdoptCluster {
        ksm: false,
        vm_ids,
        budget: Some(inner3_tree_budget()),
        tree_id: Some(tree_id),
        egress: None,
        dilation_policy: None,
        dilation_config: None,
    }) {
        Ok(Response::TreeCreated {
            tree_id,
            root_id,
            guest_cids,
            ..
        }) => {
            assert_eq!(
                guest_cids.len(),
                profile.vm_count,
                "adopted root must have {} members",
                profile.vm_count
            );
            (tree_id, root_id, guest_cids)
        }
        Ok(other) => {
            delete_inner_pods(&profile);
            panic!("unexpected TreeAdoptCluster response: {other:?}");
        }
        Err(e) => {
            delete_inner_pods(&profile);
            panic!("TreeAdoptCluster transport error: {e}");
        }
    };
    common::mark_test_tree(&tree_id);
    eprintln!("  adopted tree={tree_id} root_cids={root_cids:?}");

    let teardown = |client: &mut Client| {
        let _ = client.call(&Request::TreeDrop {
            tree_id: tree_id.clone(),
        });
        delete_inner_pods(&profile);
        let _ = std::fs::remove_dir_all(format!("/var/lib/k7d/trees/{tree_id}"));
    };

    let start = Instant::now();
    loop {
        if matches!(curl_inner_api(&source_bridge, "/readyz"), Ok(ref b) if b.contains("ok")) {
            break;
        }
        if start.elapsed() > Duration::from_secs(120) {
            let last = curl_inner_api(&source_bridge, "/readyz");
            teardown(&mut client);
            panic!("source API never recovered after adopt/prepare (last: {last:?})");
        }
        thread::sleep(Duration::from_secs(2));
    }

    let fork_start = Instant::now();
    let (fork_node, fork_cids, latency_ns) = match client.call(&Request::TreeFork {
        tree_id: tree_id.clone(),
        source_id: root_id.clone(),
        label: "warm".to_string(),
        dilation: None,
        dilation_policy: None,
        dilation_config: None,
    }) {
        Ok(Response::TreeForked {
            node_id,
            guest_cids,
            fork_memory_full_copy,
            latency_ns,
            ..
        }) => {
            assert_eq!(
                guest_cids.len(),
                profile.vm_count,
                "fork must clone every member"
            );
            assert_eq!(
                fork_memory_full_copy,
                vec![false; profile.vm_count],
                "inner-k3s cluster fork must be CoW on every member"
            );
            (node_id, guest_cids, latency_ns)
        }
        Ok(other) => {
            teardown(&mut client);
            panic!("unexpected TreeFork response: {other:?}");
        }
        Err(e) => {
            teardown(&mut client);
            panic!("TreeFork transport error: {e}");
        }
    };
    let fork_elapsed = fork_start.elapsed();
    eprintln!(
        "  TreeFork (local-path profile) node={fork_node} cids={fork_cids:?} \
         elapsed={fork_elapsed:?} budget={FORK_INNER_K3S_CLUSTER_3VM:?}"
    );
    if let Ok(journal) = Command::new("journalctl")
        .args(["-u", "k7d", "--no-pager", "--since", "-3min"])
        .output()
    {
        for line in String::from_utf8_lossy(&journal.stdout)
            .lines()
            .filter(|l| {
                l.contains("full memfd copy")
                    || l.contains("fork_cluster_warm")
                    || l.contains("cluster_tree fork_batch")
            })
        {
            eprintln!("  daemon: {line}");
        }
    }
    common::tree_fork_budget::assert_tree_fork_budget(
        "local-path-profile",
        fork_elapsed,
        latency_ns,
        FORK_INNER_K3S_CLUSTER_3VM,
    );

    let fork_bridge = list_k7_bridges()
        .into_iter()
        .find(|b| !bridges_before.contains(b))
        .expect("fork bridge appeared");
    eprintln!("  source bridge={source_bridge} fork bridge={fork_bridge}");

    let resume = Instant::now();
    loop {
        if matches!(curl_inner_api(&source_bridge, "/readyz"), Ok(ref b) if b.contains("ok")) {
            break;
        }
        if resume.elapsed() > Duration::from_secs(60) {
            let last = curl_inner_api(&source_bridge, "/readyz");
            teardown(&mut client);
            panic!("source /readyz never recovered after TreeFork resume (last: {last:?})");
        }
        thread::sleep(Duration::from_millis(500));
    }

    assert_ready_nodes_via(&profile, &source_bridge, "source");
    assert_ready_nodes_via(&profile, &fork_bridge, "fork");
    wait_local_path_ready_via(&source_bridge, Some(&server_pod));
    wait_local_path_ready_via(&fork_bridge, None);

    let reader = common::unique_name("inner-pvc-reader");
    let reader_json =
        hostpath_busybox_pod_json(&reader, &writer_node, &pv_path, "cat /data/marker", "Never");
    let mut source_read = String::new();
    let mut fork_read = String::new();
    for (bridge, label, slot) in [
        (source_bridge.as_str(), "source", &mut source_read),
        (fork_bridge.as_str(), "fork", &mut fork_read),
    ] {
        if let Err(e) = rest_create_inner_pod(bridge, &reader_json) {
            teardown(&mut client);
            panic!("{label}: POST reader {reader} failed: {e}");
        }
        wait_inner_pod_phase_via(bridge, &reader, "Succeeded", Duration::from_secs(180));
        match inner_pod_log_via(bridge, &reader) {
            Ok(log) => *slot = log,
            Err(e) => {
                teardown(&mut client);
                panic!("{label}: reader log {reader}: {e}");
            }
        }
        let _ = curl_inner_api_delete(bridge, &format!("/api/v1/namespaces/default/pods/{reader}"));
    }
    let source_marker = marker_line(&source_read, &marker).unwrap_or_default();
    let fork_marker = marker_line(&fork_read, &marker).unwrap_or_default();
    assert_eq!(
        source_marker, pre_marker,
        "source reader missing pre-fork marker\n{source_read}"
    );
    assert_eq!(
        fork_marker, source_marker,
        "fork reader marker diverged from source\nsource={source_read}\nfork={fork_read}"
    );
    eprintln!("  post-fork readers identical marker={source_marker}");

    let append = common::unique_name("inner-pvc-append");
    for (bridge, label, token) in [
        (source_bridge.as_str(), "source", src_token.as_str()),
        (fork_bridge.as_str(), "fork", fork_token.as_str()),
    ] {
        let json = hostpath_busybox_pod_json(
            &append,
            &writer_node,
            &pv_path,
            &format!("echo {token} >> /data/marker && cat /data/marker"),
            "Never",
        );
        if let Err(e) = rest_create_inner_pod(bridge, &json) {
            teardown(&mut client);
            panic!("{label}: POST appender {append} failed: {e}");
        }
        wait_inner_pod_phase_via(bridge, &append, "Succeeded", Duration::from_secs(180));
        let _ = curl_inner_api_delete(bridge, &format!("/api/v1/namespaces/default/pods/{append}"));
    }

    let reread = common::unique_name("inner-pvc-reread");
    let reread_json =
        hostpath_busybox_pod_json(&reread, &writer_node, &pv_path, "cat /data/marker", "Never");
    let mut source_after = String::new();
    let mut fork_after = String::new();
    for (bridge, label, slot) in [
        (source_bridge.as_str(), "source", &mut source_after),
        (fork_bridge.as_str(), "fork", &mut fork_after),
    ] {
        if let Err(e) = rest_create_inner_pod(bridge, &reread_json) {
            teardown(&mut client);
            panic!("{label}: POST reread {reread} failed: {e}");
        }
        wait_inner_pod_phase_via(bridge, &reread, "Succeeded", Duration::from_secs(180));
        match inner_pod_log_via(bridge, &reread) {
            Ok(log) => *slot = log,
            Err(e) => {
                teardown(&mut client);
                panic!("{label}: reread log {reread}: {e}");
            }
        }
        let _ = curl_inner_api_delete(bridge, &format!("/api/v1/namespaces/default/pods/{reread}"));
    }
    assert!(
        source_after.contains(&src_token) && !source_after.contains(&fork_token),
        "source must see only src token\nsource={source_after}\nfork={fork_after}"
    );
    assert!(
        fork_after.contains(&fork_token) && !fork_after.contains(&src_token),
        "fork must see only fork token\nsource={source_after}\nfork={fork_after}"
    );
    eprintln!(
        "  post-fork PVC divergence ok src_has={src_token} fork_has={fork_token} \
         elapsed={fork_elapsed:?}"
    );

    teardown(&mut client);
}

/// metrics-server on a dedicated profile: the aggregated
/// `metrics.k8s.io` API is `Available=True`, `kubectl top nodes`
/// returns numbers for all three members in-guest, and after a warm
/// fork both the source and the fork serve non-zero node usage whose
/// timestamps keep advancing — two independent metrics pipelines from
/// one CoW copy.
#[test]
fn test_inner_k3s_metrics_server_fork() {
    let _leak_guard = ensure_shim_installed();
    let profile = InnerClusterProfile::metrics_3node();
    bring_up_inner_cluster(&profile);

    extract_inner_certs();
    let source_bridge = inner3_bridge();
    let bridges_before = list_k7_bridges();
    assert!(
        bridges_before.contains(&source_bridge),
        "inner3 bridge missing: {bridges_before:?}"
    );
    let ready = curl_inner_api(&source_bridge, "/readyz").expect("pre-adopt /readyz");
    assert!(ready.contains("ok"), "pre-adopt /readyz not ok: {ready}");

    let server_pod = profile.live_pod(0);
    wait_coredns_ready_via(&source_bridge, Some(&server_pod));
    wait_metrics_server_ready_via(&source_bridge, Some(&server_pod));
    wait_metrics_apiservice_available_via(&source_bridge, Some(&server_pod));

    // Pre-fork, the operator-facing claim in-guest, then the same data
    // through the REST API the post-fork assertions use.
    assert_kubectl_top_nodes_numeric(&profile, &source_bridge);
    let pre = wait_node_metrics_via(&profile, &source_bridge, "pre-fork", Some(&server_pod));
    assert_eq!(
        pre.len(),
        profile.vm_count,
        "pre-fork node metrics must cover every member: {pre:?}"
    );

    let mut client = Client::connect_env().expect("connect k7d daemon");
    let vm_ids = discover_inner_vm_ids(&mut client, &profile);
    eprintln!("  discovered metrics-profile vm_ids={vm_ids:?}");

    let tree_id = format!("i3ms-{}", common::run_id());
    let (tree_id, root_id, root_cids) = match client.call(&Request::TreeAdoptCluster {
        ksm: false,
        vm_ids,
        budget: Some(inner3_tree_budget()),
        tree_id: Some(tree_id),
        egress: None,
        dilation_policy: None,
        dilation_config: None,
    }) {
        Ok(Response::TreeCreated {
            tree_id,
            root_id,
            guest_cids,
            ..
        }) => {
            assert_eq!(
                guest_cids.len(),
                profile.vm_count,
                "adopted root must have {} members",
                profile.vm_count
            );
            (tree_id, root_id, guest_cids)
        }
        Ok(other) => {
            delete_inner_pods(&profile);
            panic!("unexpected TreeAdoptCluster response: {other:?}");
        }
        Err(e) => {
            delete_inner_pods(&profile);
            panic!("TreeAdoptCluster transport error: {e}");
        }
    };
    common::mark_test_tree(&tree_id);
    eprintln!("  adopted tree={tree_id} root_cids={root_cids:?}");

    let teardown = |client: &mut Client| {
        let _ = client.call(&Request::TreeDrop {
            tree_id: tree_id.clone(),
        });
        delete_inner_pods(&profile);
        let _ = std::fs::remove_dir_all(format!("/var/lib/k7d/trees/{tree_id}"));
    };

    let start = Instant::now();
    loop {
        if matches!(curl_inner_api(&source_bridge, "/readyz"), Ok(ref b) if b.contains("ok")) {
            break;
        }
        if start.elapsed() > Duration::from_secs(120) {
            let last = curl_inner_api(&source_bridge, "/readyz");
            teardown(&mut client);
            panic!("source API never recovered after adopt/prepare (last: {last:?})");
        }
        thread::sleep(Duration::from_secs(2));
    }

    let fork_start = Instant::now();
    let (fork_node, fork_cids, latency_ns) = match client.call(&Request::TreeFork {
        tree_id: tree_id.clone(),
        source_id: root_id.clone(),
        label: "warm".to_string(),
        dilation: None,
        dilation_policy: None,
        dilation_config: None,
    }) {
        Ok(Response::TreeForked {
            node_id,
            guest_cids,
            fork_memory_full_copy,
            latency_ns,
            ..
        }) => {
            assert_eq!(
                guest_cids.len(),
                profile.vm_count,
                "fork must clone every member"
            );
            assert_eq!(
                fork_memory_full_copy,
                vec![false; profile.vm_count],
                "inner-k3s cluster fork must be CoW on every member"
            );
            (node_id, guest_cids, latency_ns)
        }
        Ok(other) => {
            teardown(&mut client);
            panic!("unexpected TreeFork response: {other:?}");
        }
        Err(e) => {
            teardown(&mut client);
            panic!("TreeFork transport error: {e}");
        }
    };
    let fork_elapsed = fork_start.elapsed();
    eprintln!(
        "  TreeFork (metrics-server profile) node={fork_node} cids={fork_cids:?} \
         elapsed={fork_elapsed:?} budget={FORK_INNER_K3S_CLUSTER_3VM:?}"
    );
    if let Ok(journal) = Command::new("journalctl")
        .args(["-u", "k7d", "--no-pager", "--since", "-3min"])
        .output()
    {
        for line in String::from_utf8_lossy(&journal.stdout)
            .lines()
            .filter(|l| {
                l.contains("full memfd copy")
                    || l.contains("fork_cluster_warm")
                    || l.contains("cluster_tree fork_batch")
            })
        {
            eprintln!("  daemon: {line}");
        }
    }
    common::tree_fork_budget::assert_tree_fork_budget(
        "metrics-server-profile",
        fork_elapsed,
        latency_ns,
        FORK_INNER_K3S_CLUSTER_3VM,
    );

    let fork_bridge = list_k7_bridges()
        .into_iter()
        .find(|b| !bridges_before.contains(b))
        .expect("fork bridge appeared");
    eprintln!("  source bridge={source_bridge} fork bridge={fork_bridge}");

    let resume = Instant::now();
    loop {
        if matches!(curl_inner_api(&source_bridge, "/readyz"), Ok(ref b) if b.contains("ok")) {
            break;
        }
        if resume.elapsed() > Duration::from_secs(60) {
            let last = curl_inner_api(&source_bridge, "/readyz");
            teardown(&mut client);
            panic!("source /readyz never recovered after TreeFork resume (last: {last:?})");
        }
        thread::sleep(Duration::from_millis(500));
    }

    assert_ready_nodes_via(&profile, &source_bridge, "source");
    assert_ready_nodes_via(&profile, &fork_bridge, "fork");

    // The aggregation layer must be Available on BOTH sides — the fork
    // carries its own apiserver, its own metrics-server, and its own
    // kubelets, all restored from one memory image.
    wait_metrics_apiservice_available_via(&source_bridge, Some(&server_pod));
    wait_metrics_apiservice_available_via(&fork_bridge, None);

    let mut first: Vec<(&str, Vec<NodeMetrics>)> = Vec::new();
    for (bridge, label, pod) in [
        (source_bridge.as_str(), "source", Some(server_pod.as_str())),
        (fork_bridge.as_str(), "fork", None),
    ] {
        first.push((label, wait_node_metrics_via(&profile, bridge, label, pod)));
    }

    // Fresh samples, not a frozen copy of the pre-fork window: read
    // again more than one `--metric-resolution=15s` scrape later and
    // require every member's timestamp to have moved on both sides.
    thread::sleep(Duration::from_secs(35));
    for ((label, before), bridge) in first
        .iter()
        .zip([source_bridge.as_str(), fork_bridge.as_str()])
    {
        let after = match node_metrics_via(bridge) {
            Ok(m) => m,
            Err(e) => {
                teardown(&mut client);
                panic!("{label}: second node-metrics read failed: {e}");
            }
        };
        for idx in 0..profile.vm_count {
            let node = profile.node_name(idx);
            let Some(b) = before.iter().find(|m| m.name == node) else {
                teardown(&mut client);
                panic!("{label}: {node} missing from the first metrics read: {before:?}");
            };
            let Some(a) = after.iter().find(|m| m.name == node) else {
                teardown(&mut client);
                panic!("{label}: {node} missing from the second metrics read: {after:?}");
            };
            if a.cpu_cores <= 0.0 || a.memory_bytes <= 0.0 {
                teardown(&mut client);
                panic!("{label}: {node} usage went to zero after the fork: {a:?}");
            }
            if a.timestamp == b.timestamp {
                teardown(&mut client);
                panic!(
                    "{label}: {node} metrics timestamp {} did not advance across a \
                     scrape interval — the fork is replaying a frozen sample",
                    a.timestamp
                );
            }
            eprintln!(
                "  {label}: {node} timestamp {} → {} (cpu {:.4} cores, mem {:.1} MiB)",
                b.timestamp,
                a.timestamp,
                a.cpu_cores,
                a.memory_bytes / (1024.0 * 1024.0)
            );
        }
    }
    eprintln!("  post-fork metrics fresh on both bridges elapsed={fork_elapsed:?}");

    teardown(&mut client);
}

// ── NetworkPolicy enforcement ──

/// Port the busybox `httpd` server pod listens on.
const NP_HTTP_PORT: u16 = 8080;

/// All k3s-container log lines that mention the embedded network
/// policy controller / ipset, from every member, from the start of the
/// log (`--tail=-1`: the controller's init error is logged once at
/// startup, long before the default 80-line tail window).
fn netpol_controller_logs(profile: &InnerClusterProfile) -> String {
    let mut out = String::new();
    for pod in profile.live_pods() {
        let logs = Command::new("kubectl")
            .args(["logs", &pod, "-c", "k3s", "--tail=-1"])
            .output();
        if let Ok(logs) = logs {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&logs.stdout),
                String::from_utf8_lossy(&logs.stderr)
            );
            let hits: Vec<&str> = text
                .lines()
                .filter(|l| {
                    let ll = l.to_lowercase();
                    ll.contains("netpol")
                        || ll.contains("network policy")
                        || ll.contains("networkpolicy")
                        || ll.contains("ipset")
                })
                .collect();
            out.push_str(&format!("--- {pod}/k3s netpol lines ---\n"));
            out.push_str(&hits.join("\n"));
            out.push('\n');
        }
    }
    out
}

/// Apply a YAML document inside the inner cluster via the server pod.
fn apply_inner_yaml(server_pod: &str, tag: &str, yaml: &str) {
    let inner_kubectl = "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl";
    let apply = kubectl_exec_retry(
        server_pod,
        "k3s",
        &format!(
            "cat > /tmp/{tag}.yaml <<'EOF'\n{yaml}EOF\n\
             {inner_kubectl} apply -f /tmp/{tag}.yaml && echo apply-ok-{tag}"
        ),
        3,
    );
    assert!(
        matches!(apply, Ok(ref s) if s.contains(&format!("apply-ok-{tag}"))),
        "inner apply {tag} failed: {apply:?}"
    );
}

/// One in-guest GET from `from_pod` to the server pod, exit-code
/// neutral: transport problems surface as `Err`, the wget verdict is
/// always in the body (`NP_GET_OK` / `NP_GET_FAIL`), so a denied GET
/// is distinguishable from a broken exec path.
fn np_get_via_exec(server_pod: &str, from_pod: &str, url: &str) -> Result<String, String> {
    let inner_kubectl = "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl";
    kubectl_exec_in(
        server_pod,
        "k3s",
        &format!(
            "{inner_kubectl} exec {from_pod} -- sh -c \
             'wget -q -T 3 -O - {url} && echo NP_GET_OK || echo NP_GET_FAIL' 2>&1"
        ),
    )
}

/// Poll [`np_get_via_exec`] until the body carries `want` (plus
/// `marker` when the GET must succeed), failing loud with the netpol
/// controller logs — enforcement is asynchronous, so both directions
/// need a bounded retry window.
fn wait_np_verdict(
    profile: &InnerClusterProfile,
    server_pod: &str,
    from_pod: &str,
    url: &str,
    want: &str,
    marker: Option<&str>,
    label: &str,
) {
    let start = Instant::now();
    let mut last: Result<String, String>;
    loop {
        last = np_get_via_exec(server_pod, from_pod, url);
        if let Ok(ref body) = last {
            let verdict_ok = body.contains(want);
            let marker_ok = marker.is_none_or(|m| body.contains(m));
            if verdict_ok && marker_ok {
                eprintln!(
                    "  {label}: {from_pod} → {url} = {want} after {:?}",
                    start.elapsed()
                );
                return;
            }
        }
        if start.elapsed() > Duration::from_secs(180) {
            let netpol = netpol_controller_logs(profile);
            panic!(
                "{label}: {from_pod} → {url} never reached {want} within 180s \
                 (last: {last:?})\nnetpol controller logs:\n{netpol}"
            );
        }
        thread::sleep(Duration::from_secs(3));
    }
}

/// Read `status.podIP` of an inner pod through `bridge`.
fn inner_pod_ip_via(bridge: &str, name: &str) -> Result<String, String> {
    let body = curl_inner_api(bridge, &format!("/api/v1/namespaces/default/pods/{name}"))?;
    let v: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("pod {name} json: {e}"))?;
    match v["status"]["podIP"].as_str() {
        Some(ip) if !ip.is_empty() => Ok(ip.to_string()),
        _ => Err(format!("pod {name} has no podIP yet: {body}")),
    }
}

/// Busybox pod JSON for the netpol fixture and probes. Container is
/// named `vol` so [`inner_pod_log_via`] works unchanged.
fn np_pod_json(name: &str, node: &str, labels: &[(&str, &str)], command: &str) -> String {
    let labels: serde_json::Map<String, serde_json::Value> = labels
        .iter()
        .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
        .collect();
    serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "labels": labels},
        "spec": {
            "nodeSelector": {"kubernetes.io/hostname": node},
            "automountServiceAccountToken": false,
            "restartPolicy": "Never",
            "containers": [{
                "name": "vol",
                "image": INNER3_BUSYBOX_REF,
                "imagePullPolicy": "Never",
                "command": ["/bin/sh", "-c"],
                "args": [command]
            }]
        }
    })
    .to_string()
}

/// REST-created probe: retry the GET until it succeeds (the allowed
/// path must tolerate the controller adding the fresh pod's IP to the
/// allow ipset), or prove it keeps failing (the denied path samples
/// for ~15 s). Exit 1 (→ pod Failed → loud panic in the phase wait)
/// on the wrong verdict.
fn np_probe_command(url: &str, expect_allowed: bool) -> String {
    if expect_allowed {
        format!(
            "i=0; while [ $i -lt 40 ]; do \
               if wget -q -T 3 -O /tmp/out {url}; then \
                 cat /tmp/out; echo NP_ALLOWED_OK; exit 0; fi; \
               i=$((i+1)); sleep 3; done; \
             echo NP_ALLOWED_FAIL; exit 1"
        )
    } else {
        format!(
            "i=0; while [ $i -lt 5 ]; do \
               if wget -q -T 3 -O - {url}; then \
                 echo NP_DENIED_LEAK; exit 1; fi; \
               i=$((i+1)); sleep 3; done; \
             echo NP_DENIED_OK"
        )
    }
}

/// Run the allowed/denied probe pair through one bridge's API server:
/// a fresh labelled pod's GET must succeed, a fresh unlabelled pod's
/// GET must keep failing. This pair is what proves *selective*
/// enforcement (not a broken dataplane) on that cluster.
fn assert_np_pair_via(
    profile: &InnerClusterProfile,
    bridge: &str,
    label: &str,
    url: &str,
    marker: &str,
) {
    let probe_node = profile.node_name(2);
    let allowed = common::unique_name(&format!("np-allow-{label}"));
    let denied = common::unique_name(&format!("np-deny-{label}"));

    let allowed_json = np_pod_json(
        &allowed,
        &probe_node,
        &[("role", "np-client")],
        &np_probe_command(url, true),
    );
    rest_create_inner_pod(bridge, &allowed_json)
        .unwrap_or_else(|e| panic!("{label}: POST allowed probe {allowed}: {e}"));
    wait_inner_pod_phase_via(bridge, &allowed, "Succeeded", Duration::from_secs(240));
    let allowed_log = inner_pod_log_via(bridge, &allowed)
        .unwrap_or_else(|e| panic!("{label}: allowed probe log {allowed}: {e}"));
    assert!(
        allowed_log.contains("NP_ALLOWED_OK") && allowed_log.contains(marker),
        "{label}: labelled probe {allowed} did not reach the server\n{allowed_log}\n{}",
        netpol_controller_logs(profile)
    );
    let _ = curl_inner_api_delete(
        bridge,
        &format!("/api/v1/namespaces/default/pods/{allowed}"),
    );

    let denied_json = np_pod_json(&denied, &probe_node, &[], &np_probe_command(url, false));
    rest_create_inner_pod(bridge, &denied_json)
        .unwrap_or_else(|e| panic!("{label}: POST denied probe {denied}: {e}"));
    wait_inner_pod_phase_via(bridge, &denied, "Succeeded", Duration::from_secs(240));
    let denied_log = inner_pod_log_via(bridge, &denied)
        .unwrap_or_else(|e| panic!("{label}: denied probe log {denied}: {e}"));
    assert!(
        denied_log.contains("NP_DENIED_OK") && !denied_log.contains("NP_DENIED_LEAK"),
        "{label}: unlabelled probe {denied} reached the policied server — \
         selective enforcement is broken\n{denied_log}\n{}",
        netpol_controller_logs(profile)
    );
    let _ = curl_inner_api_delete(bridge, &format!("/api/v1/namespaces/default/pods/{denied}"));
    eprintln!("  {label}: allowed probe OK, denied probe blocked via {bridge}");
}

/// NetworkPolicy on a dedicated profile (`--disable-network-policy`
/// dropped): cross-node connectivity baseline, default-deny-ingress
/// actually denies, an allow-from-client policy re-admits the
/// labelled client while an unlabelled pod stays denied — then the
/// same allowed/denied pair proven post-warm-fork on BOTH bridges via
/// REST-created probe pods (kubectl cannot pick a bridge; only
/// `curl --interface` disambiguates source and fork, which carry the
/// same guest IPs).
#[test]
fn test_inner_k3s_network_policy_fork() {
    let _leak_guard = ensure_shim_installed();
    let profile = InnerClusterProfile::network_policy_3node();
    bring_up_inner_cluster(&profile);

    extract_inner_certs();
    let source_bridge = inner3_bridge();
    let bridges_before = list_k7_bridges();
    assert!(
        bridges_before.contains(&source_bridge),
        "inner3 bridge missing: {bridges_before:?}"
    );
    let ready = curl_inner_api(&source_bridge, "/readyz").expect("pre-adopt /readyz");
    assert!(ready.contains("ok"), "pre-adopt /readyz not ok: {ready}");

    let server_pod = profile.live_pod(0);
    wait_coredns_ready_via(&source_bridge, Some(&server_pod));

    // Fixture: httpd server on one agent node, labelled client and
    // unlabelled outsider on the other — every GET is cross-node.
    let marker = format!("NP_MARKER_{}", common::run_id());
    let np_server = "np-server";
    let np_client = "np-client";
    let np_outsider = "np-outsider";
    let server_node = profile.node_name(1);
    let client_node = profile.node_name(2);
    let server_json = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": np_server, "labels": {"app": "np-server"}},
        "spec": {
            "nodeSelector": {"kubernetes.io/hostname": server_node},
            "automountServiceAccountToken": false,
            "restartPolicy": "Always",
            "containers": [{
                "name": "vol",
                "image": INNER3_BUSYBOX_REF,
                "imagePullPolicy": "Never",
                "command": ["/bin/sh", "-c"],
                "args": [format!(
                    "mkdir -p /www && echo {marker} > /www/index.html && \
                     exec httpd -f -p {NP_HTTP_PORT} -h /www"
                )]
            }]
        }
    })
    .to_string();
    rest_create_inner_pod(&source_bridge, &server_json)
        .unwrap_or_else(|e| panic!("POST {np_server}: {e}"));
    for (name, labels) in [
        (np_client, vec![("role", "np-client")]),
        (np_outsider, vec![]),
    ] {
        let json = np_pod_json(name, &client_node, &labels, "sleep 3600");
        rest_create_inner_pod(&source_bridge, &json).unwrap_or_else(|e| panic!("POST {name}: {e}"));
    }
    for name in [np_server, np_client, np_outsider] {
        wait_inner_pod_phase_via(&source_bridge, name, "Running", Duration::from_secs(240));
    }

    let server_ip = {
        let start = Instant::now();
        loop {
            match inner_pod_ip_via(&source_bridge, np_server) {
                Ok(ip) => break ip,
                Err(e) if start.elapsed() > Duration::from_secs(60) => {
                    panic!("{np_server} IP never assigned: {e}")
                }
                Err(_) => thread::sleep(Duration::from_secs(2)),
            }
        }
    };
    let url = format!("http://{server_ip}:{NP_HTTP_PORT}/");
    eprintln!("  np-server pod IP={server_ip}");

    // 1. Connectivity baseline: no policy, cross-node GET succeeds.
    wait_np_verdict(
        &profile,
        &server_pod,
        np_client,
        &url,
        "NP_GET_OK",
        Some(&marker),
        "baseline",
    );

    // 2. Default-deny-ingress: the same GET must start failing.
    apply_inner_yaml(
        &server_pod,
        "np-deny",
        "apiVersion: networking.k8s.io/v1\n\
         kind: NetworkPolicy\n\
         metadata:\n\
         \x20 name: default-deny-ingress\n\
         spec:\n\
         \x20 podSelector: {}\n\
         \x20 policyTypes: [\"Ingress\"]\n",
    );
    wait_np_verdict(
        &profile,
        &server_pod,
        np_client,
        &url,
        "NP_GET_FAIL",
        None,
        "default-deny",
    );

    // 3. Allow-from-client: the labelled client is re-admitted while
    //    the unlabelled outsider stays denied.
    apply_inner_yaml(
        &server_pod,
        "np-allow",
        "apiVersion: networking.k8s.io/v1\n\
         kind: NetworkPolicy\n\
         metadata:\n\
         \x20 name: allow-from-client\n\
         spec:\n\
         \x20 podSelector:\n\
         \x20   matchLabels:\n\
         \x20     app: np-server\n\
         \x20 ingress:\n\
         \x20 - from:\n\
         \x20   - podSelector:\n\
         \x20       matchLabels:\n\
         \x20         role: np-client\n\
         \x20 policyTypes: [\"Ingress\"]\n",
    );
    wait_np_verdict(
        &profile,
        &server_pod,
        np_client,
        &url,
        "NP_GET_OK",
        Some(&marker),
        "allow-client",
    );
    // Three consecutive denied samples for the outsider: one lucky
    // failure could just be a slow controller; three in a row after
    // the allow rule is live is enforcement.
    for round in 0..3 {
        let got = np_get_via_exec(&server_pod, np_outsider, &url);
        assert!(
            matches!(got, Ok(ref b) if b.contains("NP_GET_FAIL")),
            "outsider round {round}: unlabelled pod must stay denied: {got:?}\n{}",
            netpol_controller_logs(&profile)
        );
        thread::sleep(Duration::from_secs(2));
    }
    eprintln!("  pre-fork: deny/allow/deny-again proven");

    // 4. Adopt + warm fork.
    let mut client = Client::connect_env().expect("connect k7d daemon");
    let vm_ids = discover_inner_vm_ids(&mut client, &profile);
    eprintln!("  discovered netpol-profile vm_ids={vm_ids:?}");

    let tree_id = format!("i3np-{}", common::run_id());
    let (tree_id, root_id, root_cids) = match client.call(&Request::TreeAdoptCluster {
        ksm: false,
        vm_ids,
        budget: Some(inner3_tree_budget()),
        tree_id: Some(tree_id),
        egress: None,
        dilation_policy: None,
        dilation_config: None,
    }) {
        Ok(Response::TreeCreated {
            tree_id,
            root_id,
            guest_cids,
            ..
        }) => {
            assert_eq!(
                guest_cids.len(),
                profile.vm_count,
                "adopted root must have {} members",
                profile.vm_count
            );
            (tree_id, root_id, guest_cids)
        }
        Ok(other) => {
            delete_inner_pods(&profile);
            panic!("unexpected TreeAdoptCluster response: {other:?}");
        }
        Err(e) => {
            delete_inner_pods(&profile);
            panic!("TreeAdoptCluster transport error: {e}");
        }
    };
    common::mark_test_tree(&tree_id);
    eprintln!("  adopted tree={tree_id} root_cids={root_cids:?}");

    let teardown = |client: &mut Client| {
        let _ = client.call(&Request::TreeDrop {
            tree_id: tree_id.clone(),
        });
        delete_inner_pods(&profile);
        let _ = std::fs::remove_dir_all(format!("/var/lib/k7d/trees/{tree_id}"));
    };

    let start = Instant::now();
    loop {
        if matches!(curl_inner_api(&source_bridge, "/readyz"), Ok(ref b) if b.contains("ok")) {
            break;
        }
        if start.elapsed() > Duration::from_secs(120) {
            let last = curl_inner_api(&source_bridge, "/readyz");
            teardown(&mut client);
            panic!("source API never recovered after adopt/prepare (last: {last:?})");
        }
        thread::sleep(Duration::from_secs(2));
    }

    let fork_start = Instant::now();
    let (fork_node, fork_cids, latency_ns) = match client.call(&Request::TreeFork {
        tree_id: tree_id.clone(),
        source_id: root_id.clone(),
        label: "warm".to_string(),
        dilation: None,
        dilation_policy: None,
        dilation_config: None,
    }) {
        Ok(Response::TreeForked {
            node_id,
            guest_cids,
            fork_memory_full_copy,
            latency_ns,
            ..
        }) => {
            assert_eq!(
                guest_cids.len(),
                profile.vm_count,
                "fork must clone every member"
            );
            assert_eq!(
                fork_memory_full_copy,
                vec![false; profile.vm_count],
                "inner-k3s cluster fork must be CoW on every member"
            );
            (node_id, guest_cids, latency_ns)
        }
        Ok(other) => {
            teardown(&mut client);
            panic!("unexpected TreeFork response: {other:?}");
        }
        Err(e) => {
            teardown(&mut client);
            panic!("TreeFork transport error: {e}");
        }
    };
    let fork_elapsed = fork_start.elapsed();
    eprintln!(
        "  TreeFork (netpol profile) node={fork_node} cids={fork_cids:?} \
         elapsed={fork_elapsed:?} budget={FORK_INNER_K3S_CLUSTER_3VM:?}"
    );
    if let Ok(journal) = Command::new("journalctl")
        .args(["-u", "k7d", "--no-pager", "--since", "-3min"])
        .output()
    {
        for line in String::from_utf8_lossy(&journal.stdout)
            .lines()
            .filter(|l| {
                l.contains("full memfd copy")
                    || l.contains("fork_cluster_warm")
                    || l.contains("cluster_tree fork_batch")
            })
        {
            eprintln!("  daemon: {line}");
        }
    }
    common::tree_fork_budget::assert_tree_fork_budget(
        "netpol-profile",
        fork_elapsed,
        latency_ns,
        FORK_INNER_K3S_CLUSTER_3VM,
    );

    let fork_bridge = list_k7_bridges()
        .into_iter()
        .find(|b| !bridges_before.contains(b))
        .expect("fork bridge appeared");
    eprintln!("  source bridge={source_bridge} fork bridge={fork_bridge}");

    let resume = Instant::now();
    loop {
        if matches!(curl_inner_api(&source_bridge, "/readyz"), Ok(ref b) if b.contains("ok")) {
            break;
        }
        if resume.elapsed() > Duration::from_secs(60) {
            let last = curl_inner_api(&source_bridge, "/readyz");
            teardown(&mut client);
            panic!("source /readyz never recovered after TreeFork resume (last: {last:?})");
        }
        thread::sleep(Duration::from_millis(500));
    }

    assert_ready_nodes_via(&profile, &source_bridge, "source");
    assert_ready_nodes_via(&profile, &fork_bridge, "fork");

    // 5. The allowed/denied pair on BOTH bridges with fresh
    //    REST-created probe pods: two independent netpol dataplanes
    //    (iptables + ipset in each member guest) from one CoW image.
    assert_np_pair_via(&profile, &source_bridge, "source", &url, &marker);
    assert_np_pair_via(&profile, &fork_bridge, "fork", &url, &marker);
    eprintln!("  post-fork netpol enforced on both bridges elapsed={fork_elapsed:?}");

    teardown(&mut client);
}

// ── HPA end-to-end across a warm fork ──

const HPA_LOAD_NAME: &str = "hpa-load";
const HPA_LOAD_BURN: &str = "while :; do :; done";
const HPA_LOAD_SLEEP: &str = "sleep 3600";
/// Near-zero after the fork-only burn→sleep swap. Sleep pods still
/// report a few percent of a 50m request; 20 leaves room for scrape
/// noise without accepting a still-burning replica.
const HPA_UTIL_NEAR_ZERO: i64 = 20;
/// Source must stay well above the 50% target after the fork-only
/// swap. The burner is cgroup-capped at 100m / 50m request = 200%.
const HPA_UTIL_STILL_HIGH: i64 = 80;

fn hpa_load_deploy_json(command: &str) -> String {
    serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": HPA_LOAD_NAME, "labels": {"app": HPA_LOAD_NAME}},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": HPA_LOAD_NAME}},
            "template": {
                "metadata": {"labels": {"app": HPA_LOAD_NAME}},
                "spec": {
                    "automountServiceAccountToken": false,
                    "terminationGracePeriodSeconds": 1,
                    "containers": [{
                        "name": "burn",
                        "image": INNER3_BUSYBOX_REF,
                        "imagePullPolicy": "Never",
                        "command": ["/bin/sh", "-c"],
                        "args": [command],
                        "resources": {
                            "requests": {"cpu": "50m", "memory": "16Mi"},
                            "limits": {"cpu": "100m", "memory": "32Mi"}
                        }
                    }]
                }
            }
        }
    })
    .to_string()
}

fn hpa_load_hpa_json() -> String {
    serde_json::json!({
        "apiVersion": "autoscaling/v2",
        "kind": "HorizontalPodAutoscaler",
        "metadata": {"name": HPA_LOAD_NAME},
        "spec": {
            "scaleTargetRef": {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "name": HPA_LOAD_NAME
            },
            "minReplicas": 1,
            "maxReplicas": 3,
            "metrics": [{
                "type": "Resource",
                "resource": {
                    "name": "cpu",
                    "target": {
                        "type": "Utilization",
                        "averageUtilization": 50
                    }
                }
            }]
        }
    })
    .to_string()
}

fn hpa_path() -> String {
    format!("/apis/autoscaling/v2/namespaces/default/horizontalpodautoscalers/{HPA_LOAD_NAME}")
}

fn hpa_via(bridge: &str) -> Result<serde_json::Value, String> {
    let body = curl_inner_api(bridge, &hpa_path())?;
    serde_json::from_str(&body).map_err(|e| format!("HPA json: {e}: {body}"))
}

fn hpa_cpu_utilization(v: &serde_json::Value) -> Option<i64> {
    v["status"]["currentMetrics"]
        .as_array()?
        .iter()
        .find_map(|m| {
            if m["type"].as_str() != Some("Resource") {
                return None;
            }
            if m["resource"]["name"].as_str() != Some("cpu") {
                return None;
            }
            m["resource"]["current"]["averageUtilization"].as_i64()
        })
}

fn hpa_failed_get_metric(v: &serde_json::Value) -> bool {
    v["status"]["conditions"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|c| c["reason"].as_str() == Some("FailedGetResourceMetric"))
}

fn hpa_events_via(bridge: &str) -> String {
    curl_inner_api(
        bridge,
        &format!(
            "/api/v1/namespaces/default/events?fieldSelector=involvedObject.name={HPA_LOAD_NAME}"
        ),
    )
    .unwrap_or_else(|e| format!("events err: {e}"))
}

fn hpa_scale_event_visible(events: &str) -> bool {
    events.contains("SuccessfulRescale") || events.contains("New size:")
}

/// Newest `metrics.k8s.io` timestamp for the HPA target pods. HPA
/// `status.currentMetrics` has no timestamp of its own — the scrape
/// window HPA consumes lives on the aggregated pod metrics.
fn hpa_pod_metrics_newest_ts(bridge: &str) -> Result<String, String> {
    let body = curl_inner_api(
        bridge,
        &format!("/apis/metrics.k8s.io/v1beta1/namespaces/default/pods?labelSelector=app={HPA_LOAD_NAME}"),
    )?;
    let v: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("pod metrics json: {e}: {body}"))?;
    let items = v["items"]
        .as_array()
        .ok_or_else(|| format!("pod metrics has no items: {body}"))?;
    let mut newest: Option<String> = None;
    for item in items {
        let ts = item["timestamp"]
            .as_str()
            .ok_or_else(|| format!("pod metrics item without timestamp: {item}"))?;
        if newest.as_deref().is_none_or(|cur| ts > cur) {
            newest = Some(ts.to_string());
        }
    }
    newest.ok_or_else(|| format!("no hpa-load pod metrics via {bridge}: {body}"))
}

fn hpa_diagnostics(bridge: &str) -> String {
    let hpa = curl_inner_api(bridge, &hpa_path()).unwrap_or_else(|e| e);
    let deploy = curl_inner_api(
        bridge,
        &format!("/apis/apps/v1/namespaces/default/deployments/{HPA_LOAD_NAME}"),
    )
    .unwrap_or_else(|e| e);
    let pods = curl_inner_api(
        bridge,
        &format!("/api/v1/namespaces/default/pods?labelSelector=app={HPA_LOAD_NAME}"),
    )
    .unwrap_or_else(|e| e);
    let metrics = curl_inner_api(
        bridge,
        &format!("/apis/metrics.k8s.io/v1beta1/namespaces/default/pods?labelSelector=app={HPA_LOAD_NAME}"),
    )
    .unwrap_or_else(|e| e);
    format!(
        "HPA: {}\nDeployment: {}\npods: {}\npod-metrics: {}\nevents: {}",
        hpa.chars().take(4000).collect::<String>(),
        deploy.chars().take(2000).collect::<String>(),
        pods.chars().take(3000).collect::<String>(),
        metrics.chars().take(2000).collect::<String>(),
        hpa_events_via(bridge)
            .chars()
            .take(2000)
            .collect::<String>()
    )
}

fn wait_hpa_load_ready_via(bridge: &str, timeout: Duration) {
    let path = format!("/apis/apps/v1/namespaces/default/deployments/{HPA_LOAD_NAME}");
    let start = Instant::now();
    loop {
        match curl_inner_api(bridge, &path) {
            Ok(body) => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                    let ready = v["status"]["readyReplicas"].as_u64().unwrap_or(0);
                    if ready >= 1 {
                        eprintln!("  {HPA_LOAD_NAME} readyReplicas={ready} via {bridge}");
                        return;
                    }
                    eprintln!(
                        "  {HPA_LOAD_NAME} not ready yet via {bridge}: readyReplicas={ready}"
                    );
                }
            }
            Err(e) => eprintln!("  get {HPA_LOAD_NAME} via {bridge}: {e}"),
        }
        if start.elapsed() > timeout {
            panic!(
                "{HPA_LOAD_NAME} Deployment never Ready via {bridge} within {timeout:?}\n{}",
                hpa_diagnostics(bridge)
            );
        }
        thread::sleep(Duration::from_secs(3));
    }
}

/// Poll until HPA has really scaled from metrics (not residue):
/// `currentReplicas >= 2`, a scale-up event, and no
/// `FailedGetResourceMetric` at pass time.
fn wait_hpa_scale_up_via(bridge: &str, timeout: Duration) -> serde_json::Value {
    let start = Instant::now();
    loop {
        let last = match hpa_via(bridge) {
            Ok(v) => {
                let current = v["status"]["currentReplicas"].as_u64().unwrap_or(0);
                let desired = v["status"]["desiredReplicas"].as_u64().unwrap_or(0);
                let util = hpa_cpu_utilization(&v);
                let failed = hpa_failed_get_metric(&v);
                let events = hpa_events_via(bridge);
                let scaled = hpa_scale_event_visible(&events);
                let status = format!(
                    "current={current} desired={desired} util={util:?} \
                     failed_get={failed} scaled={scaled}"
                );
                eprintln!("  HPA {status}");
                if current >= 2 && desired >= 2 && scaled && !failed {
                    return v;
                }
                status
            }
            Err(e) => {
                eprintln!("  HPA get via {bridge}: {e}");
                e
            }
        };
        if start.elapsed() > timeout {
            panic!(
                "HPA never scaled to currentReplicas>=2 via {bridge} within {timeout:?} \
                 (last: {last})\n{}",
                hpa_diagnostics(bridge)
            );
        }
        thread::sleep(Duration::from_secs(5));
    }
}

fn wait_deploy_rollout_via(bridge: &str, timeout: Duration) {
    let path = format!("/apis/apps/v1/namespaces/default/deployments/{HPA_LOAD_NAME}");
    let start = Instant::now();
    loop {
        match curl_inner_api(bridge, &path) {
            Ok(body) => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                    let gen = v["metadata"]["generation"].as_u64().unwrap_or(0);
                    let observed = v["status"]["observedGeneration"].as_u64().unwrap_or(0);
                    let spec_r = v["spec"]["replicas"].as_u64().unwrap_or(0);
                    let ready = v["status"]["readyReplicas"].as_u64().unwrap_or(0);
                    let updated = v["status"]["updatedReplicas"].as_u64().unwrap_or(0);
                    if gen > 0
                        && observed >= gen
                        && spec_r > 0
                        && ready == spec_r
                        && updated == spec_r
                    {
                        eprintln!(
                            "  {HPA_LOAD_NAME} rollout complete via {bridge} \
                             gen={gen} ready={ready}"
                        );
                        return;
                    }
                    eprintln!(
                        "  {HPA_LOAD_NAME} rollout via {bridge}: gen={gen} \
                         observed={observed} spec={spec_r} ready={ready} updated={updated}"
                    );
                }
            }
            Err(e) => eprintln!("  get {HPA_LOAD_NAME} rollout via {bridge}: {e}"),
        }
        if start.elapsed() > timeout {
            panic!(
                "{HPA_LOAD_NAME} rollout never completed via {bridge} within {timeout:?}\n{}",
                hpa_diagnostics(bridge)
            );
        }
        thread::sleep(Duration::from_secs(3));
    }
}

/// HPA on the existing metrics-server profile: a CPU-bound busybox
/// Deployment scales 1 → ≥2 from real metrics, then a warm fork keeps
/// two independent autoscaler loops. Divergence is observed
/// utilization (fork burn swapped to sleep), not replica scale-down
/// — the 5 min stabilization window is out of scope.
#[test]
fn test_inner_k3s_hpa_scale_fork() {
    let _leak_guard = ensure_shim_installed();
    let profile = InnerClusterProfile::metrics_3node();
    bring_up_inner_cluster(&profile);

    extract_inner_certs();
    let source_bridge = inner3_bridge();
    let bridges_before = list_k7_bridges();
    assert!(
        bridges_before.contains(&source_bridge),
        "inner3 bridge missing: {bridges_before:?}"
    );
    let ready = curl_inner_api(&source_bridge, "/readyz").expect("pre-adopt /readyz");
    assert!(ready.contains("ok"), "pre-adopt /readyz not ok: {ready}");

    let server_pod = profile.live_pod(0);
    wait_coredns_ready_via(&source_bridge, Some(&server_pod));
    wait_metrics_server_ready_via(&source_bridge, Some(&server_pod));
    wait_metrics_apiservice_available_via(&source_bridge, Some(&server_pod));

    if let Err(e) = curl_inner_api_post(
        &source_bridge,
        "/apis/apps/v1/namespaces/default/deployments",
        &hpa_load_deploy_json(HPA_LOAD_BURN),
    ) {
        delete_inner_pods(&profile);
        panic!("POST {HPA_LOAD_NAME} Deployment failed: {e}");
    }
    wait_hpa_load_ready_via(&source_bridge, Duration::from_secs(180));
    if let Err(e) = curl_inner_api_post(
        &source_bridge,
        "/apis/autoscaling/v2/namespaces/default/horizontalpodautoscalers",
        &hpa_load_hpa_json(),
    ) {
        delete_inner_pods(&profile);
        panic!("POST {HPA_LOAD_NAME} HPA failed: {e}");
    }
    // metrics scrape 15 s + HPA sync 15 s + extra replica start.
    let pre = wait_hpa_scale_up_via(&source_bridge, Duration::from_secs(180));
    let pre_util = hpa_cpu_utilization(&pre);
    eprintln!(
        "  pre-fork HPA scaled current={} desired={} util={pre_util:?} lastScaleTime={}",
        pre["status"]["currentReplicas"],
        pre["status"]["desiredReplicas"],
        pre["status"]["lastScaleTime"].as_str().unwrap_or("<none>")
    );

    let mut client = Client::connect_env().expect("connect k7d daemon");
    let vm_ids = discover_inner_vm_ids(&mut client, &profile);
    eprintln!("  discovered HPA-profile vm_ids={vm_ids:?}");

    let tree_id = format!("i3hpa-{}", common::run_id());
    let (tree_id, root_id, root_cids) = match client.call(&Request::TreeAdoptCluster {
        ksm: false,
        vm_ids,
        budget: Some(inner3_tree_budget()),
        tree_id: Some(tree_id),
        egress: None,
        dilation_policy: None,
        dilation_config: None,
    }) {
        Ok(Response::TreeCreated {
            tree_id,
            root_id,
            guest_cids,
            ..
        }) => {
            assert_eq!(
                guest_cids.len(),
                profile.vm_count,
                "adopted root must have {} members",
                profile.vm_count
            );
            (tree_id, root_id, guest_cids)
        }
        Ok(other) => {
            delete_inner_pods(&profile);
            panic!("unexpected TreeAdoptCluster response: {other:?}");
        }
        Err(e) => {
            delete_inner_pods(&profile);
            panic!("TreeAdoptCluster transport error: {e}");
        }
    };
    common::mark_test_tree(&tree_id);
    eprintln!("  adopted tree={tree_id} root_cids={root_cids:?}");

    let teardown = |client: &mut Client| {
        let _ = client.call(&Request::TreeDrop {
            tree_id: tree_id.clone(),
        });
        delete_inner_pods(&profile);
        let _ = std::fs::remove_dir_all(format!("/var/lib/k7d/trees/{tree_id}"));
    };

    let start = Instant::now();
    loop {
        if matches!(curl_inner_api(&source_bridge, "/readyz"), Ok(ref b) if b.contains("ok")) {
            break;
        }
        if start.elapsed() > Duration::from_secs(120) {
            let last = curl_inner_api(&source_bridge, "/readyz");
            teardown(&mut client);
            panic!("source API never recovered after adopt/prepare (last: {last:?})");
        }
        thread::sleep(Duration::from_secs(2));
    }

    let fork_start = Instant::now();
    let (fork_node, fork_cids, latency_ns) = match client.call(&Request::TreeFork {
        tree_id: tree_id.clone(),
        source_id: root_id.clone(),
        label: "warm".to_string(),
        dilation: None,
        dilation_policy: None,
        dilation_config: None,
    }) {
        Ok(Response::TreeForked {
            node_id,
            guest_cids,
            fork_memory_full_copy,
            latency_ns,
            ..
        }) => {
            assert_eq!(
                guest_cids.len(),
                profile.vm_count,
                "fork must clone every member"
            );
            assert_eq!(
                fork_memory_full_copy,
                vec![false; profile.vm_count],
                "inner-k3s cluster fork must be CoW on every member"
            );
            (node_id, guest_cids, latency_ns)
        }
        Ok(other) => {
            teardown(&mut client);
            panic!("unexpected TreeFork response: {other:?}");
        }
        Err(e) => {
            teardown(&mut client);
            panic!("TreeFork transport error: {e}");
        }
    };
    let fork_elapsed = fork_start.elapsed();
    eprintln!(
        "  TreeFork (HPA + CPU-burn load) node={fork_node} cids={fork_cids:?} \
         elapsed={fork_elapsed:?} budget={FORK_INNER_K3S_CLUSTER_3VM:?}"
    );
    if let Ok(journal) = Command::new("journalctl")
        .args(["-u", "k7d", "--no-pager", "--since", "-3min"])
        .output()
    {
        for line in String::from_utf8_lossy(&journal.stdout)
            .lines()
            .filter(|l| {
                l.contains("full memfd copy")
                    || l.contains("fork_cluster_warm")
                    || l.contains("cluster_tree fork_batch")
            })
        {
            eprintln!("  daemon: {line}");
        }
    }
    common::tree_fork_budget::assert_tree_fork_budget(
        "HPA-profile",
        fork_elapsed,
        latency_ns,
        FORK_INNER_K3S_CLUSTER_3VM,
    );

    let fork_bridge = list_k7_bridges()
        .into_iter()
        .find(|b| !bridges_before.contains(b))
        .expect("fork bridge appeared");
    eprintln!("  source bridge={source_bridge} fork bridge={fork_bridge}");

    let resume = Instant::now();
    loop {
        if matches!(curl_inner_api(&source_bridge, "/readyz"), Ok(ref b) if b.contains("ok")) {
            break;
        }
        if resume.elapsed() > Duration::from_secs(60) {
            let last = curl_inner_api(&source_bridge, "/readyz");
            teardown(&mut client);
            panic!("source /readyz never recovered after TreeFork resume (last: {last:?})");
        }
        thread::sleep(Duration::from_millis(500));
    }

    assert_ready_nodes_via(&profile, &source_bridge, "source");
    assert_ready_nodes_via(&profile, &fork_bridge, "fork");

    // Per-bridge: HPA still reports the scaled replica count, and the
    // metrics scrape timestamps advance — two live loops, not residue.
    let mut first_ts: Vec<(&str, String)> = Vec::new();
    for (bridge, label) in [
        (source_bridge.as_str(), "source"),
        (fork_bridge.as_str(), "fork"),
    ] {
        let hpa = match hpa_via(bridge) {
            Ok(v) => v,
            Err(e) => {
                teardown(&mut client);
                panic!("{label}: GET HPA failed: {e}\n{}", hpa_diagnostics(bridge));
            }
        };
        let current = hpa["status"]["currentReplicas"].as_u64().unwrap_or(0);
        if current < 2 || hpa_failed_get_metric(&hpa) {
            teardown(&mut client);
            panic!(
                "{label}: post-fork HPA not live (current={current} util={:?})\n{}",
                hpa_cpu_utilization(&hpa),
                hpa_diagnostics(bridge)
            );
        }
        let ts = match hpa_pod_metrics_newest_ts(bridge) {
            Ok(t) => t,
            Err(e) => {
                teardown(&mut client);
                panic!(
                    "{label}: first pod-metrics read failed: {e}\n{}",
                    hpa_diagnostics(bridge)
                );
            }
        };
        eprintln!(
            "  {label}: post-fork HPA current={current} util={:?} \
             lastScaleTime={} metrics_ts={ts}",
            hpa_cpu_utilization(&hpa),
            hpa["status"]["lastScaleTime"].as_str().unwrap_or("<none>")
        );
        first_ts.push((label, ts));
    }

    thread::sleep(Duration::from_secs(30));
    for ((label, before), bridge) in first_ts
        .iter()
        .zip([source_bridge.as_str(), fork_bridge.as_str()])
    {
        let after = match hpa_pod_metrics_newest_ts(bridge) {
            Ok(t) => t,
            Err(e) => {
                teardown(&mut client);
                panic!(
                    "{label}: second pod-metrics read failed: {e}\n{}",
                    hpa_diagnostics(bridge)
                );
            }
        };
        if after <= *before {
            teardown(&mut client);
            panic!(
                "{label}: HPA target metrics timestamp {before} did not advance \
                 across a scrape interval (after={after}) — the loop is residue"
            );
        }
        let hpa = match hpa_via(bridge) {
            Ok(v) => v,
            Err(e) => {
                teardown(&mut client);
                panic!("{label}: GET HPA after interval failed: {e}");
            }
        };
        if hpa_cpu_utilization(&hpa).is_none() {
            teardown(&mut client);
            panic!(
                "{label}: HPA currentMetrics empty after interval\n{}",
                hpa_diagnostics(bridge)
            );
        }
        eprintln!("  {label}: metrics timestamp {before} → {after}");
    }

    // Divergence: stop the CPU burn on the fork only. Do not wait for
    // replica scale-down (5 min stabilization). Observed utilization
    // is the claim.
    let patch = serde_json::json!([{
        "op": "replace",
        "path": "/spec/template/spec/containers/0/args",
        "value": [HPA_LOAD_SLEEP]
    }])
    .to_string();
    if let Err(e) = curl_inner_api_patch(
        &fork_bridge,
        &format!("/apis/apps/v1/namespaces/default/deployments/{HPA_LOAD_NAME}"),
        "application/json-patch+json",
        &patch,
    ) {
        teardown(&mut client);
        panic!("fork: PATCH {HPA_LOAD_NAME} to sleep failed: {e}");
    }
    wait_deploy_rollout_via(&fork_bridge, Duration::from_secs(180));

    let start = Instant::now();
    loop {
        let last = match (hpa_via(&fork_bridge), hpa_via(&source_bridge)) {
            (Ok(f), Ok(s)) => {
                let f_util = hpa_cpu_utilization(&f);
                let s_util = hpa_cpu_utilization(&s);
                let status = format!("fork_util={f_util:?} source_util={s_util:?}");
                eprintln!("  divergence {status}");
                if let (Some(fu), Some(su)) = (f_util, s_util) {
                    if fu <= HPA_UTIL_NEAR_ZERO && su >= HPA_UTIL_STILL_HIGH {
                        eprintln!(
                            "  post-fork HPA divergence ok fork_util={fu} \
                             source_util={su} elapsed={fork_elapsed:?}"
                        );
                        teardown(&mut client);
                        return;
                    }
                }
                status
            }
            (f, s) => {
                let status = format!("fork={f:?} source={s:?}");
                eprintln!("  divergence read: {status}");
                status
            }
        };
        if start.elapsed() > Duration::from_secs(180) {
            teardown(&mut client);
            panic!(
                "fork utilization never dropped (or source stayed loaded) \
                 within 180s (last: {last})\n--- fork ---\n{}\n--- source ---\n{}",
                hpa_diagnostics(&fork_bridge),
                hpa_diagnostics(&source_bridge)
            );
        }
        thread::sleep(Duration::from_secs(5));
    }
}

fn configmap_json(name: &str, marker: &str) -> String {
    serde_json::json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": { "name": name },
        "data": { "marker": marker }
    })
    .to_string()
}

fn configmap_via(bridge: &str, name: &str) -> Result<serde_json::Value, String> {
    let body = curl_inner_api(
        bridge,
        &format!("/api/v1/namespaces/default/configmaps/{name}"),
    )?;
    let v: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("parse configmap {name}: {e}: {body}"))?;
    if v["kind"] == "Status" && v["status"] == "Failure" {
        return Err(format!("GET configmap {name} via {bridge} failed: {body}"));
    }
    Ok(v)
}

fn assert_configmap_marker(bridge: &str, name: &str, want: &str, label: &str) {
    match configmap_via(bridge, name) {
        Ok(v) => {
            let got = v["data"]["marker"].as_str().unwrap_or("");
            assert_eq!(
                got, want,
                "{label}: configmap {name} marker={got:?} want={want:?}"
            );
        }
        Err(e) => panic!("{label}: GET configmap {name} failed: {e}"),
    }
}

fn assert_configmap_absent(bridge: &str, name: &str, label: &str) {
    match configmap_via(bridge, name) {
        Ok(v) => panic!("{label}: configmap {name} must be absent (datastores diverged); got {v}"),
        Err(e) => {
            let lower = e.to_lowercase();
            assert!(
                lower.contains("notfound") || lower.contains("not found") || lower.contains("404"),
                "{label}: expected NotFound for {name}, got {e}"
            );
        }
    }
}

fn assert_readyz_etcd_ok(bridge: &str, label: &str) {
    let body = match curl_inner_api(bridge, "/readyz?verbose") {
        Ok(b) => b,
        Err(e) => panic!("{label}: GET /readyz?verbose failed: {e}"),
    };
    let etcd_fail = body.lines().any(|l| {
        let t = l.trim_start();
        t.starts_with("[-]etcd") || t.contains("etcd failed")
    });
    assert!(
        !etcd_fail,
        "{label}: /readyz?verbose reports an etcd failure:\n{body}"
    );
    assert!(
        body.contains("[+]etcd") || body.contains("ok"),
        "{label}: /readyz?verbose has no etcd-ok and is not ok:\n{body}"
    );
}

fn assert_etcd_datadir(server_pod: &str) {
    let listing = kubectl_exec_retry(
        server_pod,
        "k3s",
        "ls -la /var/lib/rancher/k3s/server/db 2>&1; \
         echo '---'; \
         if [ -d /var/lib/rancher/k3s/server/db/etcd ]; then echo etcd-dir-ok; \
         else echo etcd-dir-missing; fi; \
         if [ -e /var/lib/rancher/k3s/server/db/state.db ]; then echo sqlite-state-db; fi",
        5,
    );
    match listing {
        Ok(ref out) if out.contains("etcd-dir-ok") && !out.contains("sqlite-state-db") => {
            eprintln!("  etcd data dir present (no sqlite state.db):\n{out}");
        }
        other => panic!("inner k3s is not on embedded etcd (silent sqlite fallback?):\n{other:?}"),
    }
}

/// Embedded etcd (not kine/sqlite) across a warm cluster fork: history
/// survives, per-bridge writes work and diverge, /readyz stays etcd-ok,
/// and node leases still renew ~60 s later.
#[test]
fn test_inner_k3s_etcd_datastore_fork() {
    let _leak_guard = ensure_shim_installed();
    let profile = InnerClusterProfile::etcd_3node();
    bring_up_inner_cluster(&profile);

    extract_inner_certs();
    let source_bridge = inner3_bridge();
    let bridges_before = list_k7_bridges();
    assert!(
        bridges_before.contains(&source_bridge),
        "inner3 bridge missing: {bridges_before:?}"
    );
    let ready = curl_inner_api(&source_bridge, "/readyz").expect("pre-adopt /readyz");
    assert!(ready.contains("ok"), "pre-adopt /readyz not ok: {ready}");

    let server_pod = profile.live_pod(0);
    assert_etcd_datadir(&server_pod);
    assert_ready_nodes_via(&profile, &source_bridge, "pre-fork");
    assert_readyz_etcd_ok(&source_bridge, "pre-fork");

    if let Err(e) = curl_inner_api_post(
        &source_bridge,
        "/api/v1/namespaces/default/configmaps",
        &configmap_json("pre-fork-marker", "pre-fork"),
    ) {
        delete_inner_pods(&profile);
        panic!("POST pre-fork-marker ConfigMap failed: {e}");
    }
    assert_configmap_marker(&source_bridge, "pre-fork-marker", "pre-fork", "pre-fork");

    let mut client = Client::connect_env().expect("connect k7d daemon");
    let vm_ids = discover_inner_vm_ids(&mut client, &profile);
    eprintln!("  discovered etcd-profile vm_ids={vm_ids:?}");

    let tree_id = format!("i3etcd-{}", common::run_id());
    let (tree_id, root_id, root_cids) = match client.call(&Request::TreeAdoptCluster {
        ksm: false,
        vm_ids,
        budget: Some(inner3_tree_budget()),
        tree_id: Some(tree_id),
        egress: None,
        dilation_policy: None,
        dilation_config: None,
    }) {
        Ok(Response::TreeCreated {
            tree_id,
            root_id,
            guest_cids,
            ..
        }) => {
            assert_eq!(
                guest_cids.len(),
                profile.vm_count,
                "adopted root must have {} members",
                profile.vm_count
            );
            (tree_id, root_id, guest_cids)
        }
        Ok(other) => {
            delete_inner_pods(&profile);
            panic!("unexpected TreeAdoptCluster response: {other:?}");
        }
        Err(e) => {
            delete_inner_pods(&profile);
            panic!("TreeAdoptCluster transport error: {e}");
        }
    };
    common::mark_test_tree(&tree_id);
    eprintln!("  adopted tree={tree_id} root_cids={root_cids:?}");

    let teardown = |client: &mut Client| {
        let _ = client.call(&Request::TreeDrop {
            tree_id: tree_id.clone(),
        });
        delete_inner_pods(&profile);
        let _ = std::fs::remove_dir_all(format!("/var/lib/k7d/trees/{tree_id}"));
    };

    let start = Instant::now();
    loop {
        if matches!(curl_inner_api(&source_bridge, "/readyz"), Ok(ref b) if b.contains("ok")) {
            break;
        }
        if start.elapsed() > Duration::from_secs(120) {
            let last = curl_inner_api(&source_bridge, "/readyz");
            teardown(&mut client);
            panic!("source API never recovered after adopt/prepare (last: {last:?})");
        }
        thread::sleep(Duration::from_secs(2));
    }

    let fork_start = Instant::now();
    let (fork_node, fork_cids, latency_ns) = match client.call(&Request::TreeFork {
        tree_id: tree_id.clone(),
        source_id: root_id.clone(),
        label: "warm".to_string(),
        dilation: None,
        dilation_policy: None,
        dilation_config: None,
    }) {
        Ok(Response::TreeForked {
            node_id,
            guest_cids,
            fork_memory_full_copy,
            latency_ns,
            ..
        }) => {
            assert_eq!(
                guest_cids.len(),
                profile.vm_count,
                "fork must clone every member"
            );
            assert_eq!(
                fork_memory_full_copy,
                vec![false; profile.vm_count],
                "inner-k3s cluster fork must be CoW on every member"
            );
            (node_id, guest_cids, latency_ns)
        }
        Ok(other) => {
            teardown(&mut client);
            panic!("unexpected TreeFork response: {other:?}");
        }
        Err(e) => {
            teardown(&mut client);
            panic!("TreeFork transport error: {e}");
        }
    };
    let fork_elapsed = fork_start.elapsed();
    let fork_done = Instant::now();
    eprintln!(
        "  TreeFork (etcd datastore) node={fork_node} cids={fork_cids:?} \
         elapsed={fork_elapsed:?} budget={FORK_INNER_K3S_CLUSTER_3VM:?}"
    );
    if let Ok(journal) = Command::new("journalctl")
        .args(["-u", "k7d", "--no-pager", "--since", "-3min"])
        .output()
    {
        for line in String::from_utf8_lossy(&journal.stdout)
            .lines()
            .filter(|l| {
                l.contains("full memfd copy")
                    || l.contains("fork_cluster_warm")
                    || l.contains("cluster_tree fork_batch")
            })
        {
            eprintln!("  daemon: {line}");
        }
    }
    common::tree_fork_budget::assert_tree_fork_budget(
        "etcd-profile",
        fork_elapsed,
        latency_ns,
        FORK_INNER_K3S_CLUSTER_3VM,
    );

    let fork_bridge = list_k7_bridges()
        .into_iter()
        .find(|b| !bridges_before.contains(b))
        .expect("fork bridge appeared");
    eprintln!("  source bridge={source_bridge} fork bridge={fork_bridge}");

    let resume = Instant::now();
    loop {
        if matches!(curl_inner_api(&source_bridge, "/readyz"), Ok(ref b) if b.contains("ok")) {
            break;
        }
        if resume.elapsed() > Duration::from_secs(60) {
            let last = curl_inner_api(&source_bridge, "/readyz");
            teardown(&mut client);
            panic!("source /readyz never recovered after TreeFork resume (last: {last:?})");
        }
        thread::sleep(Duration::from_millis(500));
    }

    for (bridge, label, own_cm) in [
        (source_bridge.as_str(), "source", "post-fork-src"),
        (fork_bridge.as_str(), "fork", "post-fork-fork"),
    ] {
        if let Err(e) = (|| {
            assert_configmap_marker(bridge, "pre-fork-marker", "pre-fork", label);
            curl_inner_api_post(
                bridge,
                "/api/v1/namespaces/default/configmaps",
                &configmap_json(own_cm, label),
            )?;
            assert_configmap_marker(bridge, own_cm, label, label);
            Ok::<(), String>(())
        })() {
            teardown(&mut client);
            panic!("{label}: post-fork ConfigMap read/write failed: {e}");
        }
    }

    assert_configmap_absent(&source_bridge, "post-fork-fork", "source");
    assert_configmap_absent(&fork_bridge, "post-fork-src", "fork");

    assert_ready_nodes_via(&profile, &source_bridge, "source");
    assert_ready_nodes_via(&profile, &fork_bridge, "fork");
    assert_readyz_etcd_ok(&source_bridge, "source");
    assert_readyz_etcd_ok(&fork_bridge, "fork");

    let since_fork = fork_done.elapsed();
    if since_fork < Duration::from_secs(60) {
        thread::sleep(Duration::from_secs(60) - since_fork);
    }
    eprintln!(
        "  re-checking Ready + /readyz ~{}s post-fork",
        fork_done.elapsed().as_secs()
    );
    assert_ready_nodes_via(&profile, &source_bridge, "source-60s");
    assert_ready_nodes_via(&profile, &fork_bridge, "fork-60s");
    assert_readyz_etcd_ok(&source_bridge, "source-60s");
    assert_readyz_etcd_ok(&fork_bridge, "fork-60s");

    eprintln!(
        "  etcd datastore fork ok elapsed={fork_elapsed:?} \
         budget={FORK_INNER_K3S_CLUSTER_3VM:?}"
    );
    teardown(&mut client);
}

// ──: ArgoCD core GitOps ──

const ARGOCD_NS: &str = "argocd";
const ARGOCD_APP: &str = "gitops-demo";
const GITOPS_CM: &str = "gitops-marker";
const GITOPS_DEPLOY: &str = "gitops-busybox";
const GIT_REPO_URL: &str = "git://git.argocd.svc.cluster.local/managed.git";
const GITOPS_MARKER_PRE: &str = "pre-fork";
const GITOPS_MARKER_FORK: &str = "fork-only";
const FORK_COMMIT_OK: &str = "FORK_COMMIT_OK";

/// Transport choice: `git daemon` (`git://`)
/// behind a ClusterIP Service. First candidate was digest-pinned
/// `alpine/git`, but that image is client-only (`git: 'daemon' is not a
/// git command`). Stay on candidate 1 by baking `alpine` + `apk add git
/// git-daemon` on the host and airgap-staging the result as
/// `k7d/git-daemon:local` (CHALLENGES #94). No dumb-HTTP / Gitea.
/// `git daemon` still drops root (`--user=git`).
/// `ARGOCD_RECONCILIATION_TIMEOUT=15s` (controller default 180s; the
/// `argocd-cm` key is not what the controller reads) so the
/// divergence phase and the reconciledAt liveness window fit CI.
fn argocd_crd_yaml() -> String {
    r#"apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: applications.argoproj.io
spec:
  group: argoproj.io
  names:
    kind: Application
    listKind: ApplicationList
    plural: applications
    shortNames: [app, apps]
    singular: application
  scope: Namespaced
  versions:
  - name: v1alpha1
    served: true
    storage: true
    schema:
      openAPIV3Schema:
        type: object
        x-kubernetes-preserve-unknown-fields: true
        properties:
          spec:
            type: object
            x-kubernetes-preserve-unknown-fields: true
          status:
            type: object
            x-kubernetes-preserve-unknown-fields: true
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: appprojects.argoproj.io
spec:
  group: argoproj.io
  names:
    kind: AppProject
    listKind: AppProjectList
    plural: appprojects
    shortNames: [appproject, appprojects]
    singular: appproject
  scope: Namespaced
  versions:
  - name: v1alpha1
    served: true
    storage: true
    schema:
      openAPIV3Schema:
        type: object
        x-kubernetes-preserve-unknown-fields: true
        properties:
          spec:
            type: object
            x-kubernetes-preserve-unknown-fields: true
          status:
            type: object
            x-kubernetes-preserve-unknown-fields: true
"#
    .into()
}

fn argocd_rbac_yaml() -> String {
    r#"apiVersion: v1
kind: Namespace
metadata:
  name: argocd
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-application-controller
  namespace: argocd
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-repo-server
  namespace: argocd
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-redis
  namespace: argocd
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: argocd-application-controller
  namespace: argocd
rules:
- apiGroups: [""]
  resources: [secrets, configmaps]
  verbs: [get, list, watch]
- apiGroups: [argoproj.io]
  resources: [applications, appprojects, applications/status, appprojects/status]
  verbs: [create, get, list, watch, update, patch, delete]
- apiGroups: [""]
  resources: [events]
  verbs: [create, list]
- apiGroups: [coordination.k8s.io]
  resources: [leases]
  verbs: [get, list, watch, create, update, patch]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: argocd-application-controller
  namespace: argocd
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: argocd-application-controller
subjects:
- kind: ServiceAccount
  name: argocd-application-controller
  namespace: argocd
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: argocd-application-controller
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
- apiGroups: [argoproj.io]
  resources: [applications/status, appprojects/status]
  verbs: [get, list, watch, update, patch]
- nonResourceURLs: ["*"]
  verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: argocd-application-controller
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: argocd-application-controller
subjects:
- kind: ServiceAccount
  name: argocd-application-controller
  namespace: argocd
"#
    .into()
}

fn argocd_config_yaml() -> String {
    format!(
        r#"apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-cm
  namespace: argocd
  labels:
    app.kubernetes.io/name: argocd-cm
    app.kubernetes.io/part-of: argocd
data:
  timeout.reconciliation: 15s
  timeout.reconciliation.jitter: 0s
  repositories: |
    - url: {GIT_REPO_URL}
      type: git
      insecure: true
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-rbac-cm
  namespace: argocd
  labels:
    app.kubernetes.io/name: argocd-rbac-cm
    app.kubernetes.io/part-of: argocd
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-cmd-params-cm
  namespace: argocd
  labels:
    app.kubernetes.io/name: argocd-cmd-params-cm
    app.kubernetes.io/part-of: argocd
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-gpg-keys-cm
  namespace: argocd
  labels:
    app.kubernetes.io/name: argocd-gpg-keys-cm
    app.kubernetes.io/part-of: argocd
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-ssh-known-hosts-cm
  namespace: argocd
  labels:
    app.kubernetes.io/name: argocd-ssh-known-hosts-cm
    app.kubernetes.io/part-of: argocd
data:
  ssh_known_hosts: ""
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-tls-certs-cm
  namespace: argocd
  labels:
    app.kubernetes.io/name: argocd-tls-certs-cm
    app.kubernetes.io/part-of: argocd
---
apiVersion: v1
kind: Secret
metadata:
  name: argocd-secret
  namespace: argocd
  labels:
    app.kubernetes.io/name: argocd-secret
    app.kubernetes.io/part-of: argocd
type: Opaque
stringData:
  server.secretkey: k7d-argocd-core-not-a-secret
"#
    )
}

fn git_server_yaml() -> String {
    format!(
        r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: git
  namespace: argocd
spec:
  replicas: 1
  selector:
    matchLabels:
      app: git
  template:
    metadata:
      labels:
        app: git
    spec:
      automountServiceAccountToken: false
      nodeSelector:
        kubernetes.io/hostname: inner-server
      containers:
      - name: git
        image: {INNER3_GIT_DAEMON_REF}
        imagePullPolicy: Never
        command: ["/bin/sh", "-c"]
        args:
        - |
          set -e
          id git >/dev/null 2>&1 || adduser -D -H git
          mkdir -p /git
          if [ ! -f /git/managed.git/HEAD ]; then
            git init --bare /git/managed.git
            git --git-dir=/git/managed.git symbolic-ref HEAD refs/heads/main
            git --git-dir=/git/managed.git config daemon.receivepack true
            touch /git/managed.git/git-daemon-export-ok
          fi
          chown -R git:git /git
          exec git daemon --user=git --group=git --verbose --export-all \
            --enable=receive-pack --base-path=/git --reuseaddr --listen=0.0.0.0
        ports:
        - containerPort: 9418
          name: git
---
apiVersion: v1
kind: Service
metadata:
  name: git
  namespace: argocd
spec:
  ports:
  - name: git
    port: 9418
    targetPort: 9418
  selector:
    app: git
"#
    )
}

fn argocd_data_plane_yaml() -> String {
    format!(
        r#"apiVersion: v1
kind: Service
metadata:
  name: argocd-redis
  namespace: argocd
spec:
  ports:
  - name: tcp-redis
    port: 6379
    targetPort: 6379
  selector:
    app.kubernetes.io/name: argocd-redis
---
apiVersion: v1
kind: Service
metadata:
  name: argocd-repo-server
  namespace: argocd
spec:
  ports:
  - name: server
    port: 8081
    targetPort: 8081
  selector:
    app.kubernetes.io/name: argocd-repo-server
---
apiVersion: v1
kind: Service
metadata:
  name: argocd-application-controller
  namespace: argocd
spec:
  clusterIP: None
  ports:
  - name: metrics
    port: 8082
    targetPort: 8082
  selector:
    app.kubernetes.io/name: argocd-application-controller
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: argocd-redis
  namespace: argocd
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: argocd-redis
  template:
    metadata:
      labels:
        app.kubernetes.io/name: argocd-redis
    spec:
      automountServiceAccountToken: false
      nodeSelector:
        kubernetes.io/hostname: inner-server
      containers:
      - name: redis
        image: {INNER3_REDIS_REF}
        imagePullPolicy: Never
        args: ["--save", "", "--appendonly", "no"]
        ports:
        - containerPort: 6379
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: argocd-repo-server
  namespace: argocd
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: argocd-repo-server
  template:
    metadata:
      labels:
        app.kubernetes.io/name: argocd-repo-server
    spec:
      automountServiceAccountToken: false
      serviceAccountName: argocd-repo-server
      nodeSelector:
        kubernetes.io/hostname: inner-server
      containers:
      - name: argocd-repo-server
        image: {INNER3_ARGOCD_REF}
        imagePullPolicy: Never
        args: [/usr/local/bin/argocd-repo-server]
        ports:
        - containerPort: 8081
          name: server
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: ssh-known-hosts
          mountPath: /app/config/ssh
        - name: tls-certs
          mountPath: /app/config/tls
      volumes:
      - name: tmp
        emptyDir: {{}}
      - name: ssh-known-hosts
        configMap:
          name: argocd-ssh-known-hosts-cm
      - name: tls-certs
        configMap:
          name: argocd-tls-certs-cm
"#
    )
}

fn argocd_controller_yaml() -> String {
    format!(
        r#"apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: argocd-application-controller
  namespace: argocd
spec:
  replicas: 1
  serviceName: argocd-application-controller
  selector:
    matchLabels:
      app.kubernetes.io/name: argocd-application-controller
  template:
    metadata:
      labels:
        app.kubernetes.io/name: argocd-application-controller
    spec:
      automountServiceAccountToken: false
      serviceAccountName: argocd-application-controller
      nodeSelector:
        kubernetes.io/hostname: inner-server
      containers:
      - name: argocd-application-controller
        image: {INNER3_ARGOCD_REF}
        imagePullPolicy: Never
        args: [/usr/local/bin/argocd-application-controller]
        env:
        - name: ARGOCD_CONTROLLER_REPLICAS
          value: "1"
        - name: ARGOCD_RECONCILIATION_TIMEOUT
          value: "15s"
        ports:
        - containerPort: 8082
          name: metrics
        readinessProbe:
          httpGet:
            path: /healthz
            port: 8082
          initialDelaySeconds: 5
          periodSeconds: 10
        volumeMounts:
        - name: argocd-sa
          mountPath: /var/run/secrets/kubernetes.io/serviceaccount
          readOnly: true
        - name: tmp
          mountPath: /tmp
        - name: home
          mountPath: /home/argocd
      volumes:
      - name: argocd-sa
        hostPath:
          path: /cri/argocd-sa
          type: Directory
      - name: tmp
        emptyDir: {{}}
      - name: home
        emptyDir: {{}}
"#
    )
}

fn gitops_app_yaml(marker: &str, tick: &str) -> String {
    format!(
        r#"apiVersion: v1
kind: ConfigMap
metadata:
  name: {GITOPS_CM}
  namespace: default
data:
  marker: {marker}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {GITOPS_DEPLOY}
  namespace: default
  labels:
    tick: "{tick}"
spec:
  replicas: 1
  selector:
    matchLabels:
      app: {GITOPS_DEPLOY}
  template:
    metadata:
      labels:
        app: {GITOPS_DEPLOY}
        tick: "{tick}"
    spec:
      automountServiceAccountToken: false
      containers:
      - name: box
        image: {INNER3_BUSYBOX_REF}
        imagePullPolicy: Never
        command: ["sleep", "3600"]
"#
    )
}

fn argocd_application_yaml() -> String {
    format!(
        r#"apiVersion: argoproj.io/v1alpha1
kind: AppProject
metadata:
  name: default
  namespace: argocd
spec:
  sourceRepos: ["*"]
  destinations:
  - namespace: "*"
    server: "*"
  clusterResourceWhitelist:
  - group: "*"
    kind: "*"
---
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: {ARGOCD_APP}
  namespace: argocd
spec:
  project: default
  source:
    repoURL: {GIT_REPO_URL}
    targetRevision: main
    path: .
  destination:
    server: https://kubernetes.default.svc
    namespace: default
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
"#
    )
}

fn stage_argocd_controller_sa(profile: &InnerClusterProfile) {
    let server_pod = profile.live_pod(0);
    let inner_kubectl = "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl";
    let sa = kubectl_exec_retry(
        &server_pod,
        "k3s",
        &format!(
            "mkdir -p /cri/argocd-sa && \
             echo {ARGOCD_NS} > /cri/argocd-sa/namespace && \
             {inner_kubectl} -n kube-system get cm kube-root-ca.crt \
               -o jsonpath='{{.data.ca\\.crt}}' > /cri/argocd-sa/ca.crt && \
             {inner_kubectl} -n {ARGOCD_NS} create token argocd-application-controller \
               --duration=2h > /cri/argocd-sa/token && \
             test -s /cri/argocd-sa/token && test -s /cri/argocd-sa/ca.crt && echo sa-ok"
        ),
        5,
    );
    assert!(
        matches!(sa, Ok(ref s) if s.contains("sa-ok")),
        "failed to stage ArgoCD controller SA token on /cri: {sa:?}"
    );
    let token = kubectl_exec_in(&server_pod, "k3s", "cat /cri/argocd-sa/token")
        .expect("read staged ArgoCD SA token");
    let ca = kubectl_exec_in(&server_pod, "k3s", "cat /cri/argocd-sa/ca.crt")
        .expect("read staged ArgoCD CA");
    for pod in profile.live_pods() {
        if pod == server_pod {
            continue;
        }
        let replica = kubectl_exec_retry(
            &pod,
            "k3s",
            &format!(
                "mkdir -p /cri/argocd-sa && \
                 cat > /cri/argocd-sa/token <<'ARGO_EOF'\n{token}\nARGO_EOF\n\
                 cat > /cri/argocd-sa/ca.crt <<'ARGO_EOF'\n{ca}\nARGO_EOF\n\
                 echo {ARGOCD_NS} > /cri/argocd-sa/namespace && \
                 test -s /cri/argocd-sa/token && echo sa-ok"
            ),
            5,
        );
        assert!(
            matches!(replica, Ok(ref s) if s.contains("sa-ok")),
            "failed to stage ArgoCD SA on {pod}: {replica:?}"
        );
    }
    eprintln!("  staged ArgoCD controller SA via /cri hostPath on every member");
}

fn seed_git_repo(server_pod: &str) {
    let inner_kubectl = "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl";
    let yaml = gitops_app_yaml(GITOPS_MARKER_PRE, "0");
    let seed = kubectl_exec_retry(
        server_pod,
        "k3s",
        &format!(
            "cat > /tmp/gitops-app.yaml <<'MANIFEST'\n{yaml}MANIFEST\n\
             POD=$({inner_kubectl} -n {ARGOCD_NS} get pod -l app=git \
               -o jsonpath='{{.items[0].metadata.name}}') && \
             {inner_kubectl} -n {ARGOCD_NS} cp /tmp/gitops-app.yaml \"$POD\":/tmp/app.yaml && \
             {inner_kubectl} -n {ARGOCD_NS} exec \"$POD\" -- sh -c '\
               set -e; \
               mkdir -p /tmp/seed && cp /tmp/app.yaml /tmp/seed/app.yaml && \
               cd /tmp/seed && \
               git init --initial-branch=main && \
               git config user.email k7@local && \
               git config user.name k7 && \
               git add app.yaml && \
               git commit -m seed && \
               git push git://127.0.0.1/managed.git main && \
               git --git-dir=/git/managed.git symbolic-ref HEAD refs/heads/main && \
               echo seed-ok'"
        ),
        5,
    );
    assert!(
        matches!(seed, Ok(ref s) if s.contains("seed-ok")),
        "git repo seed (git:// push to local daemon) failed: {seed:?}"
    );
    eprintln!("  seeded in-cluster git:// repo with busybox Deployment + ConfigMap");
}

fn wait_ns_deploy_ready_via(
    bridge: &str,
    ns: &str,
    name: &str,
    timeout: Duration,
    server_pod: Option<&str>,
) {
    let path = format!("/apis/apps/v1/namespaces/{ns}/deployments/{name}");
    let start = Instant::now();
    loop {
        match curl_inner_api(bridge, &path) {
            Ok(body) => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                    let ready = v["status"]["readyReplicas"].as_u64().unwrap_or(0);
                    if ready >= 1 {
                        eprintln!("  {ns}/{name} readyReplicas={ready} via {bridge}");
                        return;
                    }
                    eprintln!("  {ns}/{name} not ready yet via {bridge}: readyReplicas={ready}");
                }
            }
            Err(e) => eprintln!("  GET {ns}/{name} via {bridge}: {e}"),
        }
        if start.elapsed() > timeout {
            panic!(
                "{ns}/{name} Deployment never Ready via {bridge} within {timeout:?}\n{}",
                argocd_diagnostics(bridge, server_pod)
            );
        }
        thread::sleep(Duration::from_secs(3));
    }
}

fn wait_ns_sts_ready_via(
    bridge: &str,
    ns: &str,
    name: &str,
    timeout: Duration,
    server_pod: Option<&str>,
) {
    let path = format!("/apis/apps/v1/namespaces/{ns}/statefulsets/{name}");
    let start = Instant::now();
    loop {
        match curl_inner_api(bridge, &path) {
            Ok(body) => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                    let ready = v["status"]["readyReplicas"].as_u64().unwrap_or(0);
                    if ready >= 1 {
                        eprintln!("  {ns}/{name} sts readyReplicas={ready} via {bridge}");
                        return;
                    }
                    eprintln!(
                        "  {ns}/{name} sts not ready yet via {bridge}: readyReplicas={ready}"
                    );
                }
            }
            Err(e) => eprintln!("  GET sts {ns}/{name} via {bridge}: {e}"),
        }
        if start.elapsed() > timeout {
            panic!(
                "{ns}/{name} StatefulSet never Ready via {bridge} within {timeout:?}\n{}",
                argocd_diagnostics(bridge, server_pod)
            );
        }
        thread::sleep(Duration::from_secs(3));
    }
}

fn application_path() -> String {
    format!("/apis/argoproj.io/v1alpha1/namespaces/{ARGOCD_NS}/applications/{ARGOCD_APP}")
}

fn application_via(bridge: &str) -> Result<serde_json::Value, String> {
    let body = curl_inner_api(bridge, &application_path())?;
    let v: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("parse Application: {e}: {body}"))?;
    if v["kind"] == "Status" && v["status"] == "Failure" {
        return Err(format!("GET Application via {bridge} failed: {body}"));
    }
    Ok(v)
}

fn application_sync_health(v: &serde_json::Value) -> (String, String, String) {
    (
        v["status"]["sync"]["status"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        v["status"]["health"]["status"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        v["status"]["sync"]["revision"]
            .as_str()
            .unwrap_or("")
            .to_string(),
    )
}

fn wait_application_synced_via(
    bridge: &str,
    timeout: Duration,
    server_pod: Option<&str>,
) -> serde_json::Value {
    let start = Instant::now();
    loop {
        let last = match application_via(bridge) {
            Ok(v) => {
                let (sync, health, rev) = application_sync_health(&v);
                let cond = v["status"]["conditions"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|c| c["message"].as_str())
                            .collect::<Vec<_>>()
                            .join("; ")
                    })
                    .unwrap_or_default();
                let status = format!("sync={sync} health={health} rev={rev} cond={cond}");
                eprintln!("  Application via {bridge}: {status}");
                if sync == "Synced" && health == "Healthy" && !rev.is_empty() {
                    return v;
                }
                status
            }
            Err(e) => {
                eprintln!("  Application get via {bridge}: {e}");
                e
            }
        };
        if start.elapsed() > timeout {
            panic!(
                "Application never Synced/Healthy via {bridge} within {timeout:?} \
                 (last: {last})\n{}",
                argocd_diagnostics(bridge, server_pod)
            );
        }
        thread::sleep(Duration::from_secs(5));
    }
}

fn wait_gitops_deploy_ready_via(bridge: &str, timeout: Duration, server_pod: Option<&str>) {
    wait_ns_deploy_ready_via(bridge, "default", GITOPS_DEPLOY, timeout, server_pod);
}

fn gitops_cm_marker_via(bridge: &str) -> Result<String, String> {
    let body = curl_inner_api(
        bridge,
        &format!("/api/v1/namespaces/default/configmaps/{GITOPS_CM}"),
    )?;
    let v: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("parse {GITOPS_CM}: {e}: {body}"))?;
    if v["kind"] == "Status" && v["status"] == "Failure" {
        return Err(format!("GET {GITOPS_CM} via {bridge} failed: {body}"));
    }
    Ok(v["data"]["marker"].as_str().unwrap_or("").to_string())
}

/// Argo CD application-controller does **not** hold a coordination
/// Lease (sharding, not active-passive HA — CHALLENGES #96). Liveness
/// is `status.reconciledAt`, which the controller stamps every
/// reconcile (`ARGOCD_RECONCILIATION_TIMEOUT=15s`).
fn application_reconciled_at(v: &serde_json::Value) -> String {
    v["status"]["reconciledAt"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

fn application_reconciled_at_via(bridge: &str) -> Result<String, String> {
    let v = application_via(bridge)?;
    let at = application_reconciled_at(&v);
    if at.is_empty() {
        return Err(format!(
            "Application has no status.reconciledAt via {bridge}"
        ));
    }
    Ok(at)
}

fn argocd_diagnostics(bridge: &str, server_pod: Option<&str>) -> String {
    let pods = curl_inner_api(bridge, &format!("/api/v1/namespaces/{ARGOCD_NS}/pods"))
        .unwrap_or_else(|e| format!("pods err: {e}"));
    let app =
        curl_inner_api(bridge, &application_path()).unwrap_or_else(|e| format!("app err: {e}"));
    let leases = curl_inner_api(
        bridge,
        &format!("/apis/coordination.k8s.io/v1/namespaces/{ARGOCD_NS}/leases"),
    )
    .unwrap_or_else(|e| format!("leases err: {e}"));
    let in_guest = match server_pod {
        Some(pod) => kubectl_exec_in(
            pod,
            "k3s",
            &format!(
                "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n {ARGOCD_NS} get pods -o wide 2>&1; \
                 KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n {ARGOCD_NS} \
                   describe pod -l app=git 2>&1 | tail -50; \
                 KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n {ARGOCD_NS} \
                   logs -l app=git --tail=40 2>&1; \
                 KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n {ARGOCD_NS} \
                   logs -l app.kubernetes.io/name=argocd-application-controller --tail=40 2>&1; \
                 KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n {ARGOCD_NS} \
                   logs -l app.kubernetes.io/name=argocd-repo-server --tail=40 2>&1"
            ),
        )
        .unwrap_or_else(|e| format!("describe err: {e}")),
        None => String::new(),
    };
    format!(
        "argocd pods: {}\nApplication: {}\nleases: {}\nin-guest: {in_guest}",
        pods.chars().take(6000).collect::<String>(),
        app.chars().take(4000).collect::<String>(),
        leases.chars().take(2000).collect::<String>()
    )
}

fn fork_git_commit_pod_json() -> String {
    let script = format!(
        "set -e\n\
         git clone {GIT_REPO_URL} /tmp/repo\n\
         cd /tmp/repo\n\
         sed -i 's/{GITOPS_MARKER_PRE}/{GITOPS_MARKER_FORK}/g; s/tick: \"0\"/tick: \"1\"/g' app.yaml\n\
         git config user.email k7@local\n\
         git config user.name k7\n\
         git add app.yaml\n\
         git commit -m fork-only\n\
         git push origin HEAD\n\
         echo {FORK_COMMIT_OK} $(git rev-parse HEAD)\n"
    );
    serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": { "name": "git-fork-commit", "namespace": ARGOCD_NS },
        "spec": {
            "restartPolicy": "OnFailure",
            "automountServiceAccountToken": false,
            "containers": [{
                "name": "git",
                "image": INNER3_GIT_REF,
                "imagePullPolicy": "Never",
                "command": ["/bin/sh", "-c"],
                "args": [script]
            }]
        }
    })
    .to_string()
}

fn wait_fork_commit_ok(bridge: &str, timeout: Duration) {
    let path = format!("/api/v1/namespaces/{ARGOCD_NS}/pods/git-fork-commit");
    let log_path = format!(
        "/api/v1/namespaces/{ARGOCD_NS}/pods/git-fork-commit/log?container=git&tailLines=80"
    );
    let start = Instant::now();
    loop {
        let phase = curl_inner_api(bridge, &path)
            .ok()
            .and_then(|b| serde_json::from_str::<serde_json::Value>(&b).ok())
            .and_then(|v| v["status"]["phase"].as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        let log = curl_inner_api(bridge, &log_path).unwrap_or_default();
        if log.contains(FORK_COMMIT_OK) {
            eprintln!("  fork git commit ok via {bridge}: {}", log.trim());
            return;
        }
        if phase == "Failed" || (phase == "Succeeded" && !log.contains(FORK_COMMIT_OK)) {
            panic!("fork git-commit pod ended phase={phase} without {FORK_COMMIT_OK}\n{log}");
        }
        if start.elapsed() > timeout {
            panic!(
                "fork git-commit pod never printed {FORK_COMMIT_OK} within {timeout:?} \
                 phase={phase}\n{log}\n{}",
                argocd_diagnostics(bridge, None)
            );
        }
        thread::sleep(Duration::from_secs(3));
    }
}

fn refresh_application(bridge: &str) -> Result<(), String> {
    let patch = serde_json::json!({
        "metadata": {
            "annotations": { "argocd.argoproj.io/refresh": "hard" }
        }
    })
    .to_string();
    curl_inner_api_patch(
        bridge,
        &application_path(),
        "application/merge-patch+json",
        &patch,
    )?;
    Ok(())
}

/// ArgoCD *core* (CRDs + application-controller + repo-server + redis,
/// no UI/dex) plus an in-cluster `git daemon`, then a warm cluster fork.
/// Pre-fork the Application is Synced/Healthy; post-fork both bridges
/// stay live (`status.reconciledAt` advances; CHALLENGES #96) and a commit pushed only to the
/// fork's git syncs only on the fork.
#[test]
fn test_inner_k3s_argocd_gitops_fork() {
    let _leak_guard = ensure_shim_installed();
    let profile = InnerClusterProfile::argocd_3node();
    bring_up_inner_cluster(&profile);

    extract_inner_certs();
    let source_bridge = inner3_bridge();
    let bridges_before = list_k7_bridges();
    assert!(
        bridges_before.contains(&source_bridge),
        "inner3 bridge missing: {bridges_before:?}"
    );
    let ready = curl_inner_api(&source_bridge, "/readyz").expect("pre-adopt /readyz");
    assert!(ready.contains("ok"), "pre-adopt /readyz not ok: {ready}");

    let server_pod = profile.live_pod(0);
    wait_coredns_ready_via(&source_bridge, Some(&server_pod));

    apply_inner_yaml(&server_pod, "argocd-crds", &argocd_crd_yaml());
    apply_inner_yaml(&server_pod, "argocd-rbac", &argocd_rbac_yaml());
    apply_inner_yaml(&server_pod, "argocd-config", &argocd_config_yaml());
    apply_inner_yaml(&server_pod, "git-server", &git_server_yaml());
    wait_ns_deploy_ready_via(
        &source_bridge,
        ARGOCD_NS,
        "git",
        Duration::from_secs(180),
        Some(&server_pod),
    );
    thread::sleep(Duration::from_secs(2));
    seed_git_repo(&server_pod);

    apply_inner_yaml(&server_pod, "argocd-data", &argocd_data_plane_yaml());
    wait_ns_deploy_ready_via(
        &source_bridge,
        ARGOCD_NS,
        "argocd-redis",
        Duration::from_secs(180),
        Some(&server_pod),
    );
    wait_ns_deploy_ready_via(
        &source_bridge,
        ARGOCD_NS,
        "argocd-repo-server",
        Duration::from_secs(180),
        Some(&server_pod),
    );

    stage_argocd_controller_sa(&profile);
    apply_inner_yaml(&server_pod, "argocd-ctrl", &argocd_controller_yaml());
    wait_ns_sts_ready_via(
        &source_bridge,
        ARGOCD_NS,
        "argocd-application-controller",
        Duration::from_secs(300),
        Some(&server_pod),
    );

    let crd_wait = kubectl_exec_retry(
        &server_pod,
        "k3s",
        "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl wait --for=condition=Established \
         crd/applications.argoproj.io crd/appprojects.argoproj.io --timeout=60s && echo crd-ok",
        3,
    );
    assert!(
        matches!(crd_wait, Ok(ref s) if s.contains("crd-ok")),
        "ArgoCD CRDs never Established: {crd_wait:?}"
    );
    apply_inner_yaml(&server_pod, "argocd-app", &argocd_application_yaml());
    let pre =
        wait_application_synced_via(&source_bridge, Duration::from_secs(300), Some(&server_pod));
    wait_gitops_deploy_ready_via(&source_bridge, Duration::from_secs(180), Some(&server_pod));
    let pre_marker = gitops_cm_marker_via(&source_bridge).expect("pre-fork ConfigMap");
    assert_eq!(pre_marker, GITOPS_MARKER_PRE, "pre-fork marker");
    let (pre_sync, pre_health, pre_rev) = application_sync_health(&pre);
    assert_eq!(pre_sync, "Synced");
    assert_eq!(pre_health, "Healthy");
    assert!(!pre_rev.is_empty(), "pre-fork Application revision empty");
    let pre_reconciled = application_reconciled_at(&pre);
    assert!(
        !pre_reconciled.is_empty(),
        "pre-fork Application missing status.reconciledAt"
    );
    eprintln!("  pre-fork Application rev={pre_rev} reconciledAt={pre_reconciled}");

    let mut client = Client::connect_env().expect("connect k7d daemon");
    let vm_ids = discover_inner_vm_ids(&mut client, &profile);
    eprintln!("  discovered ArgoCD-profile vm_ids={vm_ids:?}");

    let tree_id = format!("i3argo-{}", common::run_id());
    let (tree_id, root_id, root_cids) = match client.call(&Request::TreeAdoptCluster {
        ksm: false,
        vm_ids,
        budget: Some(inner3_tree_budget()),
        tree_id: Some(tree_id),
        egress: None,
        dilation_policy: None,
        dilation_config: None,
    }) {
        Ok(Response::TreeCreated {
            tree_id,
            root_id,
            guest_cids,
            ..
        }) => {
            assert_eq!(
                guest_cids.len(),
                profile.vm_count,
                "adopted root must have {} members",
                profile.vm_count
            );
            (tree_id, root_id, guest_cids)
        }
        Ok(other) => {
            delete_inner_pods(&profile);
            panic!("unexpected TreeAdoptCluster response: {other:?}");
        }
        Err(e) => {
            delete_inner_pods(&profile);
            panic!("TreeAdoptCluster transport error: {e}");
        }
    };
    common::mark_test_tree(&tree_id);
    eprintln!("  adopted tree={tree_id} root_cids={root_cids:?}");

    let teardown = |client: &mut Client| {
        let _ = client.call(&Request::TreeDrop {
            tree_id: tree_id.clone(),
        });
        delete_inner_pods(&profile);
        let _ = std::fs::remove_dir_all(format!("/var/lib/k7d/trees/{tree_id}"));
    };

    let start = Instant::now();
    loop {
        if matches!(curl_inner_api(&source_bridge, "/readyz"), Ok(ref b) if b.contains("ok")) {
            break;
        }
        if start.elapsed() > Duration::from_secs(120) {
            let last = curl_inner_api(&source_bridge, "/readyz");
            teardown(&mut client);
            panic!("source API never recovered after adopt/prepare (last: {last:?})");
        }
        thread::sleep(Duration::from_secs(2));
    }

    let fork_start = Instant::now();
    let (fork_node, fork_cids, latency_ns) = match client.call(&Request::TreeFork {
        tree_id: tree_id.clone(),
        source_id: root_id.clone(),
        label: "warm".to_string(),
        dilation: None,
        dilation_policy: None,
        dilation_config: None,
    }) {
        Ok(Response::TreeForked {
            node_id,
            guest_cids,
            fork_memory_full_copy,
            latency_ns,
            ..
        }) => {
            assert_eq!(
                guest_cids.len(),
                profile.vm_count,
                "fork must clone every member"
            );
            assert_eq!(
                fork_memory_full_copy,
                vec![false; profile.vm_count],
                "inner-k3s cluster fork must be CoW on every member"
            );
            (node_id, guest_cids, latency_ns)
        }
        Ok(other) => {
            teardown(&mut client);
            panic!("unexpected TreeFork response: {other:?}");
        }
        Err(e) => {
            teardown(&mut client);
            panic!("TreeFork transport error: {e}");
        }
    };
    let fork_elapsed = fork_start.elapsed();
    eprintln!(
        "  TreeFork (ArgoCD core + git) node={fork_node} cids={fork_cids:?} \
         elapsed={fork_elapsed:?} budget={FORK_INNER_K3S_CLUSTER_3VM_ARGOCD:?}"
    );
    if let Ok(journal) = Command::new("journalctl")
        .args(["-u", "k7d", "--no-pager", "--since", "-3min"])
        .output()
    {
        for line in String::from_utf8_lossy(&journal.stdout)
            .lines()
            .filter(|l| {
                l.contains("full memfd copy")
                    || l.contains("fork_cluster_warm")
                    || l.contains("cluster_tree fork_batch")
            })
        {
            eprintln!("  daemon: {line}");
        }
    }
    common::tree_fork_budget::assert_tree_fork_budget(
        "ArgoCD-profile",
        fork_elapsed,
        latency_ns,
        FORK_INNER_K3S_CLUSTER_3VM_ARGOCD,
    );

    let fork_bridge = list_k7_bridges()
        .into_iter()
        .find(|b| !bridges_before.contains(b))
        .expect("fork bridge appeared");
    eprintln!("  source bridge={source_bridge} fork bridge={fork_bridge}");

    let resume = Instant::now();
    loop {
        if matches!(curl_inner_api(&source_bridge, "/readyz"), Ok(ref b) if b.contains("ok")) {
            break;
        }
        if resume.elapsed() > Duration::from_secs(60) {
            let last = curl_inner_api(&source_bridge, "/readyz");
            teardown(&mut client);
            panic!("source /readyz never recovered after TreeFork resume (last: {last:?})");
        }
        thread::sleep(Duration::from_millis(500));
    }

    assert_ready_nodes_via(&profile, &source_bridge, "source");
    assert_ready_nodes_via(&profile, &fork_bridge, "fork");

    let mut first_reconciled: Vec<(&str, String)> = Vec::new();
    for (bridge, label) in [
        (source_bridge.as_str(), "source"),
        (fork_bridge.as_str(), "fork"),
    ] {
        let app = match application_via(bridge) {
            Ok(v) => v,
            Err(e) => {
                teardown(&mut client);
                panic!(
                    "{label}: GET Application failed: {e}\n{}",
                    argocd_diagnostics(bridge, None)
                );
            }
        };
        let (sync, health, rev) = application_sync_health(&app);
        if sync != "Synced" || health != "Healthy" {
            teardown(&mut client);
            panic!(
                "{label}: post-fork Application not Synced/Healthy ({sync}/{health} rev={rev})\n{}",
                argocd_diagnostics(bridge, None)
            );
        }
        let reconciled = application_reconciled_at(&app);
        if reconciled.is_empty() {
            teardown(&mut client);
            panic!(
                "{label}: post-fork Application missing status.reconciledAt\n{}",
                argocd_diagnostics(bridge, None)
            );
        }
        eprintln!(
            "  {label}: post-fork Application {sync}/{health} rev={rev} \
             reconciledAt={reconciled}"
        );
        first_reconciled.push((label, reconciled));
    }

    thread::sleep(Duration::from_secs(30));
    for ((label, before), bridge) in first_reconciled
        .iter()
        .zip([source_bridge.as_str(), fork_bridge.as_str()])
    {
        let after = match application_reconciled_at_via(bridge) {
            Ok(t) => t,
            Err(e) => {
                teardown(&mut client);
                panic!(
                    "{label}: second reconciledAt read failed: {e}\n{}",
                    argocd_diagnostics(bridge, None)
                );
            }
        };
        if after <= *before {
            teardown(&mut client);
            panic!(
                "{label}: Application reconciledAt {before} did not advance \
                 across 30s (after={after}) — the loop is residue"
            );
        }
        eprintln!("  {label}: reconciledAt {before} → {after}");
    }

    if let Err(e) = curl_inner_api_post(
        &fork_bridge,
        &format!("/api/v1/namespaces/{ARGOCD_NS}/pods"),
        &fork_git_commit_pod_json(),
    ) {
        teardown(&mut client);
        panic!("fork: POST git-fork-commit pod failed: {e}");
    }
    wait_fork_commit_ok(&fork_bridge, Duration::from_secs(180));
    if let Err(e) = refresh_application(&fork_bridge) {
        eprintln!("  fork: hard-refresh annotation failed (poll will retry): {e}");
    }

    let start = Instant::now();
    let fork_new_rev = loop {
        match application_via(&fork_bridge) {
            Ok(v) => {
                let (sync, health, rev) = application_sync_health(&v);
                let marker = gitops_cm_marker_via(&fork_bridge).unwrap_or_default();
                eprintln!("  fork sync {sync}/{health} rev={rev} marker={marker}");
                if sync == "Synced"
                    && health == "Healthy"
                    && rev != pre_rev
                    && !rev.is_empty()
                    && marker == GITOPS_MARKER_FORK
                {
                    break rev;
                }
            }
            Err(e) => eprintln!("  fork Application: {e}"),
        }
        if start.elapsed() > Duration::from_secs(180) {
            teardown(&mut client);
            panic!(
                "fork Application never synced the fork-only commit within 180s \
                 (pre_rev={pre_rev})\n{}",
                argocd_diagnostics(&fork_bridge, None)
            );
        }
        thread::sleep(Duration::from_secs(5));
    };

    let hold = Instant::now();
    while hold.elapsed() < Duration::from_secs(60) {
        match (
            application_via(&source_bridge),
            gitops_cm_marker_via(&source_bridge),
        ) {
            (Ok(v), Ok(marker)) => {
                let (sync, health, rev) = application_sync_health(&v);
                eprintln!(
                    "  source hold sync={sync} health={health} rev={rev} marker={marker} \
                     ({:?})",
                    hold.elapsed()
                );
                if rev != pre_rev || marker != GITOPS_MARKER_PRE {
                    teardown(&mut client);
                    panic!(
                        "source drifted after fork-only commit \
                         (rev {pre_rev} → {rev}, marker {GITOPS_MARKER_PRE} → {marker})"
                    );
                }
            }
            (a, m) => eprintln!("  source hold read: app={a:?} cm={m:?}"),
        }
        thread::sleep(Duration::from_secs(10));
    }

    eprintln!(
        "  ArgoCD gitops fork ok elapsed={fork_elapsed:?} \
         budget={FORK_INNER_K3S_CLUSTER_3VM_ARGOCD:?} \
         source_rev={pre_rev} fork_rev={fork_new_rev}"
    );
    teardown(&mut client);
}

// ── Cilium as the inner CNI, kube-proxy replaced ──

/// Namespace every Cilium object lands in — the same one the upstream
/// chart uses, so `cilium-dbg` and the agent's own defaults agree.
const CILIUM_NS: &str = "kube-system";
/// Native routing CIDR, and the inner cluster's `--cluster-cidr`. Every
/// node's `spec.podCIDR` must sit inside it or `auto-direct-node-routes`
/// silently masquerades instead of routing.
const CILIUM_NATIVE_ROUTING_CIDR: &str = "10.60.0.0/16";
/// HTTP port of the cross-node datapath fixture's httpd backend.
const CILIUM_HTTP_PORT: u16 = 8080;
/// ClusterIP Service in front of that backend. With `--disable-kube-proxy`
/// there is no iptables path for a VIP to work through.
const CILIUM_SVC_NAME: &str = "cil-server";

/// The whole agent + operator configuration, as the key/value pairs the
/// upstream `cilium-config` ConfigMap would carry.
///
/// This is also what lands on `/cri/cilium-config` as one file per key:
/// both binaries take `--config-dir`, and a directory of plain files is
/// the only shape a nested pod can actually read — a ConfigMap volume is
/// empty to the sidecar's runc (CHALLENGES #88, #91).
///
/// Deliberate departures from the chart's defaults, all in the direction
/// of making a datapath bug loud rather than survivable:
/// - `enable-ipv4-masquerade: false` — masquerading is exactly what
///   hides a pod CIDR that fell outside the native routing CIDR
///   (trap 3). Without it, a misrouted packet is a dropped packet.
/// - L7 proxy, Hubble, health checking and metrics off: none is under
///   test, each is a listener or a probe path that can fail on its own.
/// - Fixed, small BPF map sizes instead of `bpf-map-dynamic-size-ratio`:
///   map memory is charged to the cgroup that creates it, and that
///   cgroup is inside the sidecar's memory limit.
fn cilium_config_entries() -> Vec<(&'static str, String)> {
    vec![
        ("identity-allocation-mode", "crd".into()),
        ("enable-ipv4", "true".into()),
        ("enable-ipv6", "false".into()),
        ("routing-mode", "native".into()),
        (
            "ipv4-native-routing-cidr",
            CILIUM_NATIVE_ROUTING_CIDR.into(),
        ),
        ("auto-direct-node-routes", "true".into()),
        ("direct-routing-skip-unreachable", "false".into()),
        ("kube-proxy-replacement", "true".into()),
        ("ipam", "kubernetes".into()),
        ("k8s-require-ipv4-pod-cidr", "true".into()),
        ("devices", "eth0".into()),
        ("enable-ipv4-masquerade", "false".into()),
        ("enable-ipv6-masquerade", "false".into()),
        ("enable-bpf-masquerade", "false".into()),
        ("enable-l7-proxy", "false".into()),
        ("enable-hubble", "false".into()),
        ("enable-metrics", "false".into()),
        ("enable-health-checking", "false".into()),
        ("enable-endpoint-health-checking", "false".into()),
        ("enable-well-known-identities", "false".into()),
        ("enable-k8s-networkpolicy", "true".into()),
        ("enable-policy", "default".into()),
        ("enable-xt-socket-fallback", "true".into()),
        ("synchronize-k8s-nodes", "true".into()),
        ("cni-exclusive", "true".into()),
        ("cni-log-file", "/var/run/cilium/cilium-cni.log".into()),
        (
            "write-cni-conf-when-ready",
            "/host/etc/cni/net.d/05-cilium.conflist".into(),
        ),
        ("bpf-root", "/sys/fs/bpf".into()),
        ("cgroup-root", "/run/cilium/cgroupv2".into()),
        ("procfs", "/host/proc".into()),
        ("preallocate-bpf-maps", "false".into()),
        ("bpf-map-dynamic-size-ratio", "0.0".into()),
        ("bpf-policy-map-max", "4096".into()),
        ("bpf-lb-map-max", "16384".into()),
        ("bpf-ct-global-tcp-max", "32768".into()),
        ("bpf-ct-global-any-max", "16384".into()),
        ("bpf-nat-global-max", "32768".into()),
        ("bpf-neigh-global-max", "8192".into()),
        ("operator-api-serve-addr", "127.0.0.1:9234".into()),
        ("remove-cilium-node-taints", "true".into()),
        ("set-cilium-node-taints", "false".into()),
        ("set-cilium-is-up-condition", "false".into()),
        ("monitor-aggregation", "medium".into()),
        ("debug", "false".into()),
    ]
}

/// The same entries as a ConfigMap. Not the agent's read path (that is
/// the `/cri` hostPath above) — it is here because `cilium-dbg` and
/// anyone debugging the cluster expect to find it, and a divergence
/// between the two would be invisible otherwise.
fn cilium_config_map_yaml() -> String {
    let data = cilium_config_entries()
        .into_iter()
        .map(|(k, v)| format!("  {k}: \"{v}\"\n"))
        .collect::<String>();
    format!(
        "apiVersion: v1\n\
         kind: ConfigMap\n\
         metadata:\n\
         \x20 name: cilium-config\n\
         \x20 namespace: {CILIUM_NS}\n\
         data:\n{data}"
    )
}

/// ServiceAccounts plus `cluster-admin` bindings for the agent and the
/// operator.
///
/// The upstream chart ships two hand-tuned ClusterRoles. This is a
/// throwaway cluster on an isolated bridge whose subject is the
/// datapath, and a transcribed rule list is a second thing that can be
/// wrong for the same symptom ("Cilium is not ready") — see #96, where
/// a hand-narrowed RBAC set cost a bring-up.
fn cilium_rbac_yaml() -> String {
    let mut out = String::new();
    for sa in ["cilium", "cilium-operator"] {
        out.push_str(&format!(
            "apiVersion: v1\n\
             kind: ServiceAccount\n\
             metadata:\n\
             \x20 name: {sa}\n\
             \x20 namespace: {CILIUM_NS}\n\
             ---\n\
             apiVersion: rbac.authorization.k8s.io/v1\n\
             kind: ClusterRoleBinding\n\
             metadata:\n\
             \x20 name: {sa}-k7-admin\n\
             roleRef:\n\
             \x20 apiGroup: rbac.authorization.k8s.io\n\
             \x20 kind: ClusterRole\n\
             \x20 name: cluster-admin\n\
             subjects:\n\
             \x20 - kind: ServiceAccount\n\
             \x20   name: {sa}\n\
             \x20   namespace: {CILIUM_NS}\n\
             ---\n"
        ));
    }
    out
}

/// The agent DaemonSet, rewritten for this fixture.
///
/// What is gone from the upstream template, and why:
/// - **Every init container but `install-cni-binaries`.** `config`
///   (`cilium-dbg build-config`) is unnecessary because the config
///   arrives as files; `mount-cgroup`, `apply-sysctl-overwrites` and
///   `mount-bpf-fs` all `nsenter` into pid 1's namespaces or rely on
///   bidirectional mount propagation out of the pod, neither of which a
///   nested pod can do — the sidecar does those mounts instead
///   (see [`cilium_sidecar_prep`]); `clean-cilium-state` has nothing to
///   clean on a cluster this test just created.
/// - **The projected ServiceAccount token.** Empty to sidecar runc
///   (CHALLENGES #88), so the token is minted onto `/cri` and mounted
///   from there with `automountServiceAccountToken: false`.
/// - **The `postStart` AWS-SNAT hook and the `preStop`
///   `/cni-uninstall.sh`.** The first greps iptables for an EKS
///   artefact; the second would delete the conflist from under the
///   cluster during teardown.
/// - **The capability list**, replaced by `privileged: true`: the guest
///   has no seccomp/apparmor/SELinux to be careful about, and a missing
///   capability presents as an unexplained datapath failure.
///
/// `KUBERNETES_SERVICE_HOST` is load-bearing: with `--disable-kube-proxy`
/// nothing resolves the `kubernetes` Service VIP until this very
/// DaemonSet is ready, so the agent has to reach the apiserver by node
/// IP.
fn cilium_agent_yaml(profile: &InnerClusterProfile) -> String {
    let api_host = profile.guest_ip(0);
    format!(
        r#"apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: cilium
  namespace: {CILIUM_NS}
  labels:
    k8s-app: cilium
spec:
  selector:
    matchLabels:
      k8s-app: cilium
  updateStrategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 3
  template:
    metadata:
      labels:
        k8s-app: cilium
    spec:
      hostNetwork: true
      dnsPolicy: Default
      restartPolicy: Always
      priorityClassName: system-node-critical
      serviceAccountName: cilium
      automountServiceAccountToken: false
      terminationGracePeriodSeconds: 1
      tolerations:
      - operator: Exists
      initContainers:
      - name: install-cni-binaries
        image: {INNER3_CILIUM_REF}
        imagePullPolicy: Never
        command: ["/install-plugin.sh"]
        securityContext:
          privileged: true
        volumeMounts:
        - name: cni-path
          mountPath: /host/opt/cni/bin
      containers:
      - name: cilium-agent
        image: {INNER3_CILIUM_REF}
        imagePullPolicy: Never
        command: ["cilium-agent"]
        args: ["--config-dir=/tmp/cilium/config-map"]
        env:
        - name: K8S_NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        - name: CILIUM_K8S_NAMESPACE
          value: {CILIUM_NS}
        - name: KUBERNETES_SERVICE_HOST
          value: "{api_host}"
        - name: KUBERNETES_SERVICE_PORT
          value: "6443"
        - name: GOMEMLIMIT
          value: "600MiB"
        securityContext:
          privileged: true
        startupProbe:
          httpGet:
            host: 127.0.0.1
            path: /healthz
            port: 9879
            httpHeaders:
            - name: brief
              value: "true"
          initialDelaySeconds: 5
          periodSeconds: 3
          failureThreshold: 120
        livenessProbe:
          httpGet:
            host: 127.0.0.1
            path: /healthz
            port: 9879
            httpHeaders:
            - name: brief
              value: "true"
          periodSeconds: 30
          timeoutSeconds: 5
          failureThreshold: 10
        readinessProbe:
          httpGet:
            host: 127.0.0.1
            path: /healthz
            port: 9879
            httpHeaders:
            - name: brief
              value: "true"
          periodSeconds: 15
          timeoutSeconds: 5
          failureThreshold: 3
        volumeMounts:
        - name: cilium-config
          mountPath: /tmp/cilium/config-map
          readOnly: true
        - name: cilium-sa
          mountPath: /var/run/secrets/kubernetes.io/serviceaccount
          readOnly: true
        - name: bpf-maps
          mountPath: /sys/fs/bpf
        - name: cilium-run
          mountPath: /var/run/cilium
        - name: cilium-cgroup
          mountPath: /run/cilium/cgroupv2
        - name: etc-cni-netd
          mountPath: /host/etc/cni/net.d
        - name: host-proc
          mountPath: /host/proc
        - name: lib-modules
          mountPath: /lib/modules
          readOnly: true
        - name: xtables-lock
          mountPath: /run/xtables.lock
      volumes:
      - name: cilium-config
        hostPath:
          path: /cri/cilium-config
          type: Directory
      - name: cilium-sa
        hostPath:
          path: /cri/cilium-sa
          type: Directory
      - name: bpf-maps
        hostPath:
          path: /sys/fs/bpf
          type: Directory
      - name: cilium-run
        hostPath:
          path: /cri/cilium-run
          type: Directory
      - name: cilium-cgroup
        hostPath:
          path: /cri/cilium-cgroup
          type: Directory
      - name: etc-cni-netd
        hostPath:
          path: /cri/cni/net.d
          type: Directory
      - name: cni-path
        hostPath:
          path: {CILIUM_CNI_BIN_DIR}
          type: Directory
      - name: host-proc
        hostPath:
          path: /proc
          type: Directory
      - name: lib-modules
        hostPath:
          path: /cri/cilium-lib-modules
          type: Directory
      - name: xtables-lock
        hostPath:
          path: /cri/cilium-xtables.lock
          type: File
"#
    )
}

/// The operator Deployment, same rewrites as the agent plus a pin to
/// `inner-server`: it is hostNetwork (so it needs no CNI to start, which
/// is the point) and one replica, so pinning removes a scheduling
/// variable from a bring-up that has no service datapath yet.
fn cilium_operator_yaml(profile: &InnerClusterProfile) -> String {
    let api_host = profile.guest_ip(0);
    let node = profile.node_name(0);
    format!(
        r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: cilium-operator
  namespace: {CILIUM_NS}
  labels:
    io.cilium/app: operator
    name: cilium-operator
spec:
  replicas: 1
  selector:
    matchLabels:
      io.cilium/app: operator
      name: cilium-operator
  strategy:
    type: Recreate
  template:
    metadata:
      labels:
        io.cilium/app: operator
        name: cilium-operator
    spec:
      hostNetwork: true
      dnsPolicy: Default
      restartPolicy: Always
      priorityClassName: system-cluster-critical
      serviceAccountName: cilium-operator
      automountServiceAccountToken: false
      terminationGracePeriodSeconds: 1
      nodeSelector:
        kubernetes.io/hostname: {node}
      tolerations:
      - operator: Exists
      containers:
      - name: cilium-operator
        image: {INNER3_CILIUM_OPERATOR_REF}
        imagePullPolicy: Never
        command: ["cilium-operator-generic"]
        args: ["--config-dir=/tmp/cilium/config-map"]
        env:
        - name: K8S_NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        - name: CILIUM_K8S_NAMESPACE
          value: {CILIUM_NS}
        - name: KUBERNETES_SERVICE_HOST
          value: "{api_host}"
        - name: KUBERNETES_SERVICE_PORT
          value: "6443"
        livenessProbe:
          httpGet:
            host: 127.0.0.1
            path: /healthz
            port: 9234
          initialDelaySeconds: 60
          periodSeconds: 10
          timeoutSeconds: 3
        readinessProbe:
          httpGet:
            host: 127.0.0.1
            path: /healthz
            port: 9234
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 12
        volumeMounts:
        - name: cilium-config
          mountPath: /tmp/cilium/config-map
          readOnly: true
        - name: cilium-operator-sa
          mountPath: /var/run/secrets/kubernetes.io/serviceaccount
          readOnly: true
      volumes:
      - name: cilium-config
        hostPath:
          path: /cri/cilium-config
          type: Directory
      - name: cilium-operator-sa
        hostPath:
          path: /cri/cilium-operator-sa
          type: Directory
"#
    )
}

/// Write the config directory and both ServiceAccount token directories
/// onto every member's `/cri`.
///
/// Tokens are minted on the server (only it has a kubeconfig) and then
/// copied to the agents, the same shape `stage_argocd_controller_sa`
/// uses. 6 h is well past the whole suite, so no rotation story is
/// needed inside one run.
fn stage_cilium_config_and_sa(profile: &InnerClusterProfile) {
    let inner_kubectl = "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl";
    let write_config = cilium_config_entries()
        .into_iter()
        .map(|(k, v)| format!("printf '%s' '{v}' > /cri/cilium-config/{k} && "))
        .collect::<String>();
    let server_pod = profile.live_pod(0);

    let mut tokens = Vec::new();
    for (sa, dir) in [
        ("cilium", "/cri/cilium-sa"),
        ("cilium-operator", "/cri/cilium-operator-sa"),
    ] {
        let minted = kubectl_exec_retry(
            &server_pod,
            "k3s",
            &format!(
                "mkdir -p {dir} && \
                 echo {CILIUM_NS} > {dir}/namespace && \
                 {inner_kubectl} -n {CILIUM_NS} get cm kube-root-ca.crt \
                   -o jsonpath='{{.data.ca\\.crt}}' > {dir}/ca.crt && \
                 {inner_kubectl} -n {CILIUM_NS} create token {sa} --duration=6h \
                   > {dir}/token && \
                 test -s {dir}/token && test -s {dir}/ca.crt && echo sa-ok-{sa}"
            ),
            5,
        );
        assert!(
            matches!(minted, Ok(ref s) if s.contains(&format!("sa-ok-{sa}"))),
            "failed to mint the {sa} token onto {dir}: {minted:?}"
        );
        let token = kubectl_exec_retry(&server_pod, "k3s", &format!("cat {dir}/token"), 3)
            .unwrap_or_else(|e| panic!("read staged {sa} token: {e}"));
        let ca = kubectl_exec_retry(&server_pod, "k3s", &format!("cat {dir}/ca.crt"), 3)
            .unwrap_or_else(|e| panic!("read staged {sa} ca.crt: {e}"));
        tokens.push((dir, token, ca));
    }

    for (idx, pod) in profile.live_pods().into_iter().enumerate() {
        let mut script = format!("mkdir -p /cri/cilium-config && {write_config}");
        if idx != 0 {
            for (dir, token, ca) in &tokens {
                script.push_str(&format!(
                    "mkdir -p {dir} && \
                     echo {CILIUM_NS} > {dir}/namespace && \
                     cat > {dir}/token <<'CIL_EOF'\n{token}\nCIL_EOF\n\
                     cat > {dir}/ca.crt <<'CIL_EOF'\n{ca}\nCIL_EOF\n\
                     test -s {dir}/token && test -s {dir}/ca.crt && "
                ));
            }
        }
        script.push_str("test -s /cri/cilium-config/routing-mode && echo cilium-staged");
        let staged = kubectl_exec_retry(&pod, "k3s", &script, 5);
        assert!(
            matches!(staged, Ok(ref s) if s.contains("cilium-staged")),
            "failed to stage the Cilium config dir + SA on {pod}: {staged:?}"
        );
    }
    eprintln!("  staged Cilium config-dir + agent/operator SA tokens on every member");
}

/// Poll until every inner node exists **and** carries a `spec.podCIDR`,
/// returning `(node, podCIDR)` pairs.
///
/// Two reasons this is its own wait. Cilium's `ipam: kubernetes` mode
/// reads the podCIDR the nodeipam controller assigns, so an agent that
/// starts first just logs and waits; and the CIDRs are what trap 3 is
/// about — a podCIDR outside `ipv4-native-routing-cidr` makes
/// `auto-direct-node-routes` masquerade instead of route, which the
/// connectivity probes would pass through anyway.
fn wait_inner_node_pod_cidrs(profile: &InnerClusterProfile) -> Vec<(String, String)> {
    let inner_kubectl = "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl";
    let server_pod = profile.live_pod(0);
    let start = Instant::now();
    loop {
        let mut found = Vec::new();
        for idx in 0..profile.vm_count {
            let node = profile.node_name(idx);
            let cidr = kubectl_exec_in(
                &server_pod,
                "k3s",
                &format!(
                    "{inner_kubectl} get node {node} -o jsonpath='{{.spec.podCIDR}}' 2>/dev/null"
                ),
            );
            match cidr {
                Ok(c) if !c.trim().is_empty() => found.push((node, c.trim().to_string())),
                _ => break,
            }
        }
        if found.len() == profile.vm_count {
            for (node, cidr) in &found {
                assert!(
                    cidr.starts_with("10.60."),
                    "{node} podCIDR {cidr} is outside \
                     ipv4-native-routing-cidr={CILIUM_NATIVE_ROUTING_CIDR}: \
                     auto-direct-node-routes would masquerade instead of route, and \
                     the cross-node probes would then pass for the wrong reason"
                );
            }
            eprintln!("  inner node podCIDRs: {found:?}");
            return found;
        }
        assert!(
            start.elapsed() < Duration::from_secs(300),
            "not all {} inner nodes registered with a podCIDR within 300s (got {found:?})",
            profile.vm_count
        );
        thread::sleep(Duration::from_secs(5));
    }
}

/// Install Cilium and wait for it to program the datapath.
///
/// Ordering is the whole point: the nodes are NotReady (no CNI) and no
/// Service resolves (no kube-proxy), so everything here has to work
/// through the apiserver by node IP and with hostNetwork pods only.
fn install_cilium(profile: &InnerClusterProfile) {
    let server_pod = profile.live_pod(0);
    wait_inner_node_pod_cidrs(profile);
    apply_inner_yaml(&server_pod, "cilium-rbac", &cilium_rbac_yaml());
    apply_inner_yaml(&server_pod, "cilium-configmap", &cilium_config_map_yaml());
    stage_cilium_config_and_sa(profile);
    apply_inner_yaml(
        &server_pod,
        "cilium-operator",
        &cilium_operator_yaml(profile),
    );
    apply_inner_yaml(&server_pod, "cilium-agent", &cilium_agent_yaml(profile));
    wait_cilium_ready(profile);
}

/// Number of ready pods in a namespaced DaemonSet/Deployment, read
/// through the server pod's own kubeconfig (pre-Ready cluster: the
/// host-side `curl --interface` path needs certs this bring-up has not
/// extracted yet).
fn inner_workload_ready_count(server_pod: &str, kind: &str, name: &str, field: &str) -> u32 {
    let inner_kubectl = "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl";
    kubectl_exec_in(
        server_pod,
        "k3s",
        &format!(
            "{inner_kubectl} -n {CILIUM_NS} get {kind} {name} \
             -o jsonpath='{{.status.{field}}}' 2>/dev/null"
        ),
    )
    .ok()
    .and_then(|s| s.trim().parse::<u32>().ok())
    .unwrap_or(0)
}

/// Wait for one ready agent per node plus an available operator.
///
/// The budget is the 3-node bring-up's own 600 s: the first agent has to
/// pull nothing (airgap import already happened) but does have to
/// compile and load its BPF programs on a single vCPU, and until it
/// does, its node has no datapath at all.
fn wait_cilium_ready(profile: &InnerClusterProfile) {
    let server_pod = profile.live_pod(0);
    let want = profile.vm_count as u32;
    let start = Instant::now();
    loop {
        let agents = inner_workload_ready_count(&server_pod, "ds", "cilium", "numberReady");
        let operator =
            inner_workload_ready_count(&server_pod, "deploy", "cilium-operator", "readyReplicas");
        if agents == want && operator >= 1 {
            eprintln!(
                "  Cilium ready: {agents}/{want} agents + operator, after {:?}",
                start.elapsed()
            );
            return;
        }
        if start.elapsed() > Duration::from_secs(600) {
            let diag = cilium_diagnostics(profile);
            delete_inner_pods(profile);
            panic!(
                "Cilium never became ready within 600s \
                 (agents={agents}/{want} operator={operator})\n{diag}"
            );
        }
        eprintln!("  Cilium not ready yet: agents={agents}/{want} operator={operator}");
        thread::sleep(Duration::from_secs(5));
    }
}

/// Everything worth reading when Cilium does not come up: pod state and
/// events in `kube-system`, agent and operator logs, and per-member
/// links and routes (a missing `cilium_host` or a missing direct route
/// is the difference between "the agent crashed" and "the agent is fine
/// and the datapath is not").
fn cilium_diagnostics(profile: &InnerClusterProfile) -> String {
    let inner_kubectl = "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl";
    let server_pod = profile.live_pod(0);
    let mut out = String::new();
    for (label, cmd) in [
        (
            "pods",
            format!("{inner_kubectl} -n {CILIUM_NS} get pods -o wide 2>&1"),
        ),
        ("nodes", format!("{inner_kubectl} get nodes -o wide 2>&1")),
        (
            "events",
            format!(
                "{inner_kubectl} -n {CILIUM_NS} get events \
                 --sort-by=.lastTimestamp 2>&1 | tail -40"
            ),
        ),
        (
            "agent-logs",
            format!(
                "{inner_kubectl} -n {CILIUM_NS} logs -l k8s-app=cilium \
                 --all-containers --prefix --tail=60 2>&1 | tail -120"
            ),
        ),
        (
            "operator-logs",
            format!(
                "{inner_kubectl} -n {CILIUM_NS} logs -l name=cilium-operator \
                 --tail=40 2>&1 | tail -60"
            ),
        ),
        (
            "conflist",
            "ls -l /cri/cni/net.d /cri/cni/bin 2>&1; head -c 400 /cri/cni/net.d/*.conflist 2>&1"
                .to_string(),
        ),
    ] {
        let got = kubectl_exec_in(&server_pod, "k3s", &cmd);
        out.push_str(&format!("--- cilium {label} ---\n{got:?}\n"));
    }
    for pod in profile.live_pods() {
        let net = kubectl_exec_in(
            &pod,
            "k3s",
            "ip -o link show 2>&1; echo ---; ip route show 2>&1",
        );
        out.push_str(&format!("--- {pod} links+routes ---\n{net:?}\n"));
    }
    out
}

/// Name of the Cilium agent pod on `node`, read through the server pod.
fn cilium_agent_pod_on(profile: &InnerClusterProfile, node: &str) -> String {
    let inner_kubectl = "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl";
    let server_pod = profile.live_pod(0);
    let got = kubectl_exec_retry(
        &server_pod,
        "k3s",
        &format!(
            "{inner_kubectl} -n {CILIUM_NS} get pods -l k8s-app=cilium \
             --field-selector spec.nodeName={node} \
             -o jsonpath='{{.items[0].metadata.name}}'"
        ),
        3,
    );
    let name = got
        .unwrap_or_else(|e| panic!("no cilium agent pod on {node}: {e}"))
        .trim()
        .to_string();
    assert!(
        name.starts_with("cilium-"),
        "unexpected cilium agent pod name on {node}: {name:?}"
    );
    name
}

/// Every member runs exactly one agent, and each agent is on a distinct
/// node: `numberReady == 3` alone would also be satisfied by three pods
/// crowded onto one node if a DaemonSet selector went wrong.
fn assert_cilium_agent_per_node(profile: &InnerClusterProfile) {
    let inner_kubectl = "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl";
    let server_pod = profile.live_pod(0);
    let listing = kubectl_exec_retry(
        &server_pod,
        "k3s",
        &format!(
            "{inner_kubectl} -n {CILIUM_NS} get pods -l k8s-app=cilium \
             -o jsonpath='{{range .items[*]}}{{.spec.nodeName}}={{.status.phase}} {{end}}'"
        ),
        3,
    )
    .unwrap_or_else(|e| panic!("list cilium agents: {e}"));
    for idx in 0..profile.vm_count {
        let node = profile.node_name(idx);
        assert_eq!(
            listing.matches(&format!("{node}=Running")).count(),
            1,
            "expected exactly one Running cilium agent on {node}: {listing:?}"
        );
    }
    eprintln!("  one Running cilium agent per node: {}", listing.trim());
}

/// Nothing flannel-shaped survives on any member: no `flannel.1`/`cni0`
/// link, no flannel conflist beside Cilium's, no `/run/flannel` subnet
/// file. `--flannel-backend=none` is a server flag, so a member that
/// somehow kept flannel would still route pod traffic and make the
/// cross-node probes pass without Cilium doing anything.
fn assert_no_flannel(profile: &InnerClusterProfile) {
    for (idx, pod) in profile.live_pods().into_iter().enumerate() {
        let node = profile.node_name(idx);
        let links = kubectl_exec_retry(&pod, "k3s", "ip -o link show", 3)
            .unwrap_or_else(|e| panic!("{node}: ip link: {e}"));
        for dev in ["flannel.1", "flannel-v6.1", "cni0"] {
            assert!(
                !links.contains(dev),
                "{node}: flannel device {dev} exists with --flannel-backend=none:\n{links}"
            );
        }
        assert!(
            links.contains("cilium_host") && links.contains("cilium_net"),
            "{node}: Cilium's own host devices are missing, so nothing programmed \
             this node's datapath:\n{links}"
        );
        let confs = kubectl_exec_retry(
            &pod,
            "k3s",
            "ls /cri/cni/net.d; echo ---; ls /run/flannel 2>&1",
            3,
        )
        .unwrap_or_else(|e| panic!("{node}: cni conf listing: {e}"));
        assert!(
            confs.contains("05-cilium.conflist"),
            "{node}: Cilium never wrote its conflist:\n{confs}"
        );
        assert!(
            !confs.contains("flannel"),
            "{node}: a flannel conflist or subnet file is present:\n{confs}"
        );
    }
    eprintln!("  no flannel on any member, Cilium conflist + cilium_host present");
}

/// `cilium-dbg status` reports `KubeProxyReplacement: True`, and the
/// member has no `KUBE-SERVICES` chain.
///
/// The exit code is deliberately ignored: `cilium status` exits 0 with
/// warnings, so the field is the assertion. The
/// iptables half is the other direction of the same claim — a
/// `KUBE-SERVICES` chain would mean kube-proxy is alive somewhere and
/// the ClusterIP probe could succeed without touching eBPF.
fn assert_kube_proxy_replaced(profile: &InnerClusterProfile) {
    let inner_kubectl = "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl";
    let server_pod = profile.live_pod(0);
    for idx in 0..profile.vm_count {
        let node = profile.node_name(idx);
        let agent = cilium_agent_pod_on(profile, &node);
        let status = kubectl_exec_retry(
            &server_pod,
            "k3s",
            &format!(
                "{inner_kubectl} -n {CILIUM_NS} exec {agent} -c cilium-agent -- \
                 cilium-dbg status 2>&1 | grep -i KubeProxyReplacement"
            ),
            3,
        )
        .unwrap_or_else(|e| panic!("{node}: cilium-dbg status: {e}"));
        let line = status
            .lines()
            .find(|l| l.to_lowercase().contains("kubeproxyreplacement"))
            .unwrap_or_else(|| {
                panic!("{node}: no KubeProxyReplacement line in cilium status:\n{status}")
            });
        assert!(
            line.contains("True") || line.contains("Strict"),
            "{node}: KubeProxyReplacement is not enabled: {line}"
        );
        eprintln!("  {node}: {}", line.trim());

        // Both backends, not whichever `iptables-save` autodetects: the
        // k3s image's `iptables-save` is a detect script that picks nft
        // here, and a kube-proxy that had programmed the legacy tables
        // would then be invisible — the absence would be proven of the
        // wrong table.
        let chains = kubectl_exec_retry(
            profile.live_pods().get(idx).expect("member pod"),
            "k3s",
            "for b in iptables-legacy-save iptables-nft-save; do \
               p=$(command -v $b) || { echo MISSING=$b; continue; }; \
               echo \"$b=$($p 2>/dev/null | grep -c KUBE-SERVICES)\"; \
             done",
            3,
        )
        .unwrap_or_else(|e| panic!("{node}: iptables-save: {e}"));
        for backend in ["iptables-legacy-save", "iptables-nft-save"] {
            assert!(
                chains.contains(&format!("{backend}=0")),
                "{node}: {backend} either is missing or lists a KUBE-SERVICES chain — \
                 with kube-proxy programming Service rules the ClusterIP probe would \
                 not prove eBPF:\n{chains}"
            );
        }
    }
    eprintln!("  KubeProxyReplacement enabled and no KUBE-SERVICES chain on any member");
}

/// Every member carries a direct route to every *other* member's
/// podCIDR via that member's node IP.
///
/// This is the masquerade trap in assertion form: with
/// `auto-direct-node-routes` a podCIDR outside
/// `ipv4-native-routing-cidr` is silently masqueraded instead of
/// routed, so cross-node connectivity would pass while the datapath was
/// doing something else entirely. Masquerading is also switched off in
/// [`cilium_config_entries`] so this cannot be papered over.
fn assert_direct_node_routes(profile: &InnerClusterProfile, cidrs: &[(String, String)]) {
    for idx in 0..profile.vm_count {
        let pod = profile.live_pod(idx);
        let node = profile.node_name(idx);
        let routes = kubectl_exec_retry(&pod, "k3s", "ip route show", 3)
            .unwrap_or_else(|e| panic!("{node}: ip route: {e}"));
        for (other_idx, (other_node, cidr)) in cidrs.iter().enumerate() {
            if other_idx == idx {
                continue;
            }
            let via = profile.guest_ip(other_idx);
            let want = format!("{cidr} via {via}");
            assert!(
                routes.contains(&want),
                "{node}: no direct route {want} for {other_node}'s podCIDR — \
                 auto-direct-node-routes did not install it, so cross-node pod \
                 traffic is not natively routed:\n{routes}"
            );
        }
        eprintln!("  {node}: direct routes to every peer podCIDR present");
    }
}

/// Busybox probe script for one bridge's datapath: pod IP first, then
/// the Service VIP, both required to return `marker`.
///
/// Both are retried because a freshly created endpoint needs its policy
/// map populated, and both verdicts are printed before the exit code so
/// a partial failure ("pod IP works, VIP does not" — i.e. socket-LB is
/// broken but routing is fine) is readable from the pod log alone.
fn cilium_allowed_probe_command(pod_url: &str, svc_url: &str, marker: &str) -> String {
    format!(
        "p=FAIL; s=FAIL; \
         i=0; while [ $i -lt 40 ]; do \
           if wget -q -T 3 -O /tmp/pod {pod_url} && grep -q {marker} /tmp/pod; then \
             p=OK; break; fi; \
           i=$((i+1)); sleep 3; done; \
         i=0; while [ $i -lt 40 ]; do \
           if wget -q -T 3 -O /tmp/svc {svc_url} && grep -q {marker} /tmp/svc; then \
             s=OK; break; fi; \
           i=$((i+1)); sleep 3; done; \
         echo CIL_POD_$p; echo CIL_SVC_$s; \
         [ $p = OK ] && [ $s = OK ] || exit 1; \
         echo CIL_ALLOWED_OK"
    )
}

/// The mirror probe: an unlabelled pod must be denied on **both** the
/// pod IP and the VIP. Sampled five times so one slow policy-map write
/// is not mistaken for enforcement.
fn cilium_denied_probe_command(pod_url: &str, svc_url: &str) -> String {
    format!(
        "i=0; while [ $i -lt 5 ]; do \
           if wget -q -T 3 -O - {pod_url}; then echo CIL_DENIED_LEAK_POD; exit 1; fi; \
           if wget -q -T 3 -O - {svc_url}; then echo CIL_DENIED_LEAK_SVC; exit 1; fi; \
           i=$((i+1)); sleep 3; done; \
         echo CIL_DENIED_OK"
    )
}

/// Run all three datapath probes on one bridge with fresh REST-created
/// pods: cross-node pod-to-pod, cross-node ClusterIP, and selective
/// policy enforcement.
///
/// Every probe pod is pinned to the *other* agent node from the server,
/// so nothing here can succeed node-locally, and every request is
/// created through `bridge` — the only way to address the fork, which
/// carries the same guest IPs as its source.
fn assert_cilium_datapath_via(
    profile: &InnerClusterProfile,
    bridge: &str,
    label: &str,
    pod_url: &str,
    svc_url: &str,
    marker: &str,
) {
    let probe_node = profile.node_name(2);
    let allowed = common::unique_name(&format!("cil-allow-{label}"));
    let denied = common::unique_name(&format!("cil-deny-{label}"));

    let allowed_json = np_pod_json(
        &allowed,
        &probe_node,
        &[("role", "cil-client")],
        &cilium_allowed_probe_command(pod_url, svc_url, marker),
    );
    rest_create_inner_pod(bridge, &allowed_json)
        .unwrap_or_else(|e| panic!("{label}: POST allowed probe {allowed}: {e}"));
    wait_inner_pod_phase_via(bridge, &allowed, "Succeeded", Duration::from_secs(360));
    let allowed_log = inner_pod_log_via(bridge, &allowed)
        .unwrap_or_else(|e| panic!("{label}: allowed probe log {allowed}: {e}"));
    assert!(
        allowed_log.contains("CIL_POD_OK"),
        "{label}: cross-node pod-to-pod by pod IP failed\n{allowed_log}\n{}",
        cilium_diagnostics(profile)
    );
    assert!(
        allowed_log.contains("CIL_SVC_OK"),
        "{label}: the ClusterIP VIP never answered — with kube-proxy disabled there \
         is no iptables path, so this is Cilium's socket-LB datapath\n{allowed_log}\n{}",
        cilium_diagnostics(profile)
    );
    assert!(
        allowed_log.contains("CIL_ALLOWED_OK"),
        "{label}: labelled client was not admitted by the CiliumNetworkPolicy path\n\
         {allowed_log}"
    );
    let _ = curl_inner_api_delete(
        bridge,
        &format!("/api/v1/namespaces/default/pods/{allowed}"),
    );

    let denied_json = np_pod_json(
        &denied,
        &probe_node,
        &[],
        &cilium_denied_probe_command(pod_url, svc_url),
    );
    rest_create_inner_pod(bridge, &denied_json)
        .unwrap_or_else(|e| panic!("{label}: POST denied probe {denied}: {e}"));
    wait_inner_pod_phase_via(bridge, &denied, "Succeeded", Duration::from_secs(300));
    let denied_log = inner_pod_log_via(bridge, &denied)
        .unwrap_or_else(|e| panic!("{label}: denied probe log {denied}: {e}"));
    assert!(
        denied_log.contains("CIL_DENIED_OK") && !denied_log.contains("CIL_DENIED_LEAK"),
        "{label}: unlabelled pod reached the policied server (pod IP or VIP) — \
         Cilium is not enforcing selectively\n{denied_log}\n{}",
        cilium_diagnostics(profile)
    );
    let _ = curl_inner_api_delete(bridge, &format!("/api/v1/namespaces/default/pods/{denied}"));
    eprintln!("  {label}: pod-to-pod + ClusterIP + policy proven via {bridge}");
}

/// `namespace/pod/container → restartCount` for every container in the
/// inner cluster, read through `bridge`.
///
/// Skips the short-lived probe pods by namespace-scoping to
/// `kube-system` plus the long-lived `default` fixtures: a probe pod
/// created after the snapshot exists on one bridge and not the other,
/// which is not a restart.
fn inner_restart_counts_via(bridge: &str) -> std::collections::BTreeMap<String, u64> {
    let mut out = std::collections::BTreeMap::new();
    for path in [
        "/api/v1/namespaces/kube-system/pods",
        "/api/v1/namespaces/default/pods",
    ] {
        let body = curl_inner_api(bridge, path)
            .unwrap_or_else(|e| panic!("list pods {path} via {bridge}: {e}"));
        let v: serde_json::Value =
            serde_json::from_str(&body).unwrap_or_else(|e| panic!("pods json from {bridge}: {e}"));
        let empty = Vec::new();
        for item in v["items"].as_array().unwrap_or(&empty) {
            let ns = item["metadata"]["namespace"].as_str().unwrap_or("");
            let name = item["metadata"]["name"].as_str().unwrap_or("");
            if name.starts_with("cil-allow-") || name.starts_with("cil-deny-") {
                continue;
            }
            for cs in item["status"]["containerStatuses"]
                .as_array()
                .unwrap_or(&empty)
            {
                let cname = cs["name"].as_str().unwrap_or("");
                let count = cs["restartCount"].as_u64().unwrap_or(0);
                out.insert(format!("{ns}/{name}/{cname}"), count);
            }
        }
    }
    out
}

/// Cilium as the inner CNI, with kube-proxy replaced, across a warm
/// fork of the whole three-node cluster.
///
/// The bring-up itself is the first assertion: with
/// `--flannel-backend=none --disable-kube-proxy` no node reaches Ready
/// until Cilium is programming the datapath, so
/// [`bring_up_inner_cluster`] cannot return otherwise.
///
/// Then, on the source: no flannel anywhere, one ready agent per node
/// plus the operator, `KubeProxyReplacement` enabled with no
/// `KUBE-SERVICES` chain, and a direct route to every peer's podCIDR.
/// Then cross-node pod-to-pod, a cross-node ClusterIP that has no
/// iptables path to fall back to, and a NetworkPolicy that admits a
/// labelled client and denies an unlabelled one.
///
/// Then the point of the increment: warm-fork the cluster and re-run all
/// three probes on the child. Cilium's state is eBPF maps pinned on
/// bpffs, which is guest RAM, so a CoW fork should carry the whole
/// datapath — node IPs, endpoint IDs, policy and LB maps — not just
/// initialise a fresh one. Restart counts are compared across the fork
/// so an agent that crash-looped back into a working state cannot read
/// as success.
#[test]
fn test_inner_k3s_cilium_datapath_fork() {
    let _leak_guard = ensure_shim_installed();
    let profile = InnerClusterProfile::cilium_3node();
    bring_up_inner_cluster(&profile);

    extract_inner_certs();
    let source_bridge = inner3_bridge();
    let bridges_before = list_k7_bridges();
    assert!(
        bridges_before.contains(&source_bridge),
        "inner3 bridge missing: {bridges_before:?}"
    );
    let ready = curl_inner_api(&source_bridge, "/readyz").expect("pre-adopt /readyz");
    assert!(ready.contains("ok"), "pre-adopt /readyz not ok: {ready}");

    let server_pod = profile.live_pod(0);

    // 1. The CNI is Cilium and nothing else, on every member.
    assert_no_flannel(&profile);
    assert_cilium_agent_per_node(&profile);
    let operator =
        inner_workload_ready_count(&server_pod, "deploy", "cilium-operator", "readyReplicas");
    assert!(
        operator >= 1,
        "cilium-operator Deployment is not available (readyReplicas={operator})\n{}",
        cilium_diagnostics(&profile)
    );

    // 2. BPF, not iptables — and natively routed, not masqueraded.
    assert_kube_proxy_replaced(&profile);
    let cidrs = wait_inner_node_pod_cidrs(&profile);
    assert_direct_node_routes(&profile, &cidrs);

    // 3. Fixture: httpd on one agent node behind a ClusterIP, probes
    //    pinned to the other agent node, and a policy that admits only
    //    the labelled client.
    let marker = format!("CIL_MARKER_{}", common::run_id());
    let cil_server = "cil-server";
    let server_node = profile.node_name(1);
    let server_json = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": cil_server, "labels": {"app": "cil-server"}},
        "spec": {
            "nodeSelector": {"kubernetes.io/hostname": server_node},
            "automountServiceAccountToken": false,
            "restartPolicy": "Always",
            "containers": [{
                "name": "vol",
                "image": INNER3_BUSYBOX_REF,
                "imagePullPolicy": "Never",
                "command": ["/bin/sh", "-c"],
                "args": [format!(
                    "mkdir -p /www && echo {marker} > /www/index.html && \
                     exec httpd -f -p {CILIUM_HTTP_PORT} -h /www"
                )]
            }]
        }
    })
    .to_string();
    rest_create_inner_pod(&source_bridge, &server_json)
        .unwrap_or_else(|e| panic!("POST {cil_server}: {e}"));
    wait_inner_pod_phase_via(
        &source_bridge,
        cil_server,
        "Running",
        Duration::from_secs(300),
    );
    let server_ip = {
        let start = Instant::now();
        loop {
            match inner_pod_ip_via(&source_bridge, cil_server) {
                Ok(ip) => break ip,
                Err(e) if start.elapsed() > Duration::from_secs(120) => {
                    panic!(
                        "{cil_server} never got a pod IP from Cilium IPAM: {e}\n{}",
                        cilium_diagnostics(&profile)
                    )
                }
                Err(_) => thread::sleep(Duration::from_secs(2)),
            }
        }
    };
    assert!(
        server_ip.starts_with("10.60."),
        "{cil_server} pod IP {server_ip} is outside the cluster CIDR \
         {CILIUM_NATIVE_ROUTING_CIDR} — IPAM is not reading spec.podCIDR"
    );
    eprintln!("  {cil_server} pod IP={server_ip} on {server_node}");

    apply_inner_yaml(
        &server_pod,
        "cilium-svc",
        &format!(
            "apiVersion: v1\n\
             kind: Service\n\
             metadata:\n\
             \x20 name: {CILIUM_SVC_NAME}\n\
             spec:\n\
             \x20 type: ClusterIP\n\
             \x20 selector:\n\
             \x20   app: cil-server\n\
             \x20 ports:\n\
             \x20 - port: {CILIUM_HTTP_PORT}\n\
             \x20   targetPort: {CILIUM_HTTP_PORT}\n"
        ),
    );
    let svc_ip = {
        let body = curl_inner_api(
            &source_bridge,
            &format!("/api/v1/namespaces/default/services/{CILIUM_SVC_NAME}"),
        )
        .expect("get cil-server Service");
        let v: serde_json::Value = serde_json::from_str(&body).expect("service json");
        v["spec"]["clusterIP"]
            .as_str()
            .filter(|ip| !ip.is_empty() && *ip != "None")
            .unwrap_or_else(|| panic!("Service has no ClusterIP: {body}"))
            .to_string()
    };
    assert!(
        svc_ip.starts_with("10.61."),
        "ClusterIP {svc_ip} is outside the inner --service-cidr"
    );
    eprintln!("  {CILIUM_SVC_NAME} ClusterIP={svc_ip}");

    apply_inner_yaml(
        &server_pod,
        "cilium-netpol",
        "apiVersion: networking.k8s.io/v1\n\
         kind: NetworkPolicy\n\
         metadata:\n\
         \x20 name: allow-cil-client\n\
         spec:\n\
         \x20 podSelector:\n\
         \x20   matchLabels:\n\
         \x20     app: cil-server\n\
         \x20 ingress:\n\
         \x20 - from:\n\
         \x20   - podSelector:\n\
         \x20       matchLabels:\n\
         \x20         role: cil-client\n\
         \x20 policyTypes: [\"Ingress\"]\n",
    );

    let pod_url = format!("http://{server_ip}:{CILIUM_HTTP_PORT}/");
    let svc_url = format!("http://{svc_ip}:{CILIUM_HTTP_PORT}/");
    assert_cilium_datapath_via(
        &profile,
        &source_bridge,
        "pre-fork",
        &pod_url,
        &svc_url,
        &marker,
    );

    // 4. Adopt + warm fork.
    let before_restarts = inner_restart_counts_via(&source_bridge);
    assert!(
        before_restarts
            .keys()
            .filter(|k| k.contains("/cilium-"))
            .count()
            >= profile.vm_count,
        "expected a restart-count entry per Cilium agent: {before_restarts:?}"
    );
    let mut client = Client::connect_env().expect("connect k7d daemon");
    let vm_ids = discover_inner_vm_ids(&mut client, &profile);
    eprintln!("  discovered cilium-profile vm_ids={vm_ids:?}");

    let tree_id = format!("i3cil-{}", common::run_id());
    let (tree_id, root_id, root_cids) = match client.call(&Request::TreeAdoptCluster {
        ksm: false,
        vm_ids,
        budget: Some(inner3_tree_budget()),
        tree_id: Some(tree_id),
        egress: None,
        dilation_policy: None,
        dilation_config: None,
    }) {
        Ok(Response::TreeCreated {
            tree_id,
            root_id,
            guest_cids,
            ..
        }) => {
            assert_eq!(
                guest_cids.len(),
                profile.vm_count,
                "adopted root must have {} members",
                profile.vm_count
            );
            (tree_id, root_id, guest_cids)
        }
        Ok(other) => {
            delete_inner_pods(&profile);
            panic!("unexpected TreeAdoptCluster response: {other:?}");
        }
        Err(e) => {
            delete_inner_pods(&profile);
            panic!("TreeAdoptCluster transport error: {e}");
        }
    };
    common::mark_test_tree(&tree_id);
    eprintln!("  adopted tree={tree_id} root_cids={root_cids:?}");

    let teardown = |client: &mut Client| {
        let _ = client.call(&Request::TreeDrop {
            tree_id: tree_id.clone(),
        });
        delete_inner_pods(&profile);
        let _ = std::fs::remove_dir_all(format!("/var/lib/k7d/trees/{tree_id}"));
    };

    let start = Instant::now();
    loop {
        if matches!(curl_inner_api(&source_bridge, "/readyz"), Ok(ref b) if b.contains("ok")) {
            break;
        }
        if start.elapsed() > Duration::from_secs(120) {
            let last = curl_inner_api(&source_bridge, "/readyz");
            teardown(&mut client);
            panic!("source API never recovered after adopt/prepare (last: {last:?})");
        }
        thread::sleep(Duration::from_secs(2));
    }

    let fork_start = Instant::now();
    let (fork_node, fork_cids, latency_ns) = match client.call(&Request::TreeFork {
        tree_id: tree_id.clone(),
        source_id: root_id.clone(),
        label: "warm".to_string(),
        dilation: None,
        dilation_policy: None,
        dilation_config: None,
    }) {
        Ok(Response::TreeForked {
            node_id,
            guest_cids,
            fork_memory_full_copy,
            latency_ns,
            ..
        }) => {
            assert_eq!(
                guest_cids.len(),
                profile.vm_count,
                "fork must clone every member"
            );
            assert_eq!(
                fork_memory_full_copy,
                vec![false; profile.vm_count],
                "inner-k3s cluster fork must be CoW on every member"
            );
            (node_id, guest_cids, latency_ns)
        }
        Ok(other) => {
            teardown(&mut client);
            panic!("unexpected TreeFork response: {other:?}");
        }
        Err(e) => {
            teardown(&mut client);
            panic!("TreeFork transport error: {e}");
        }
    };
    let fork_elapsed = fork_start.elapsed();
    eprintln!(
        "  TreeFork (cilium profile) node={fork_node} cids={fork_cids:?} \
         elapsed={fork_elapsed:?} budget={FORK_INNER_K3S_CLUSTER_3VM:?}"
    );
    if let Ok(journal) = Command::new("journalctl")
        .args(["-u", "k7d", "--no-pager", "--since", "-3min"])
        .output()
    {
        for line in String::from_utf8_lossy(&journal.stdout)
            .lines()
            .filter(|l| {
                l.contains("full memfd copy")
                    || l.contains("fork_cluster_warm")
                    || l.contains("cluster_tree fork_batch")
            })
        {
            eprintln!("  daemon: {line}");
        }
    }
    common::tree_fork_budget::assert_tree_fork_budget(
        "cilium-profile",
        fork_elapsed,
        latency_ns,
        FORK_INNER_K3S_CLUSTER_3VM,
    );

    let fork_bridge = list_k7_bridges()
        .into_iter()
        .find(|b| !bridges_before.contains(b))
        .expect("fork bridge appeared");
    eprintln!("  source bridge={source_bridge} fork bridge={fork_bridge}");

    let resume = Instant::now();
    loop {
        if matches!(curl_inner_api(&source_bridge, "/readyz"), Ok(ref b) if b.contains("ok")) {
            break;
        }
        if resume.elapsed() > Duration::from_secs(60) {
            let last = curl_inner_api(&source_bridge, "/readyz");
            teardown(&mut client);
            panic!("source /readyz never recovered after TreeFork resume (last: {last:?})");
        }
        thread::sleep(Duration::from_millis(500));
    }

    assert_ready_nodes_via(&profile, &source_bridge, "source");
    assert_ready_nodes_via(&profile, &fork_bridge, "fork");

    // 5. All three probes again, on both bridges. The fork's eBPF maps
    //    came out of its source's RAM: if they did not survive, the
    //    pod-IP GET is what fails first.
    assert_cilium_datapath_via(
        &profile,
        &source_bridge,
        "source",
        &pod_url,
        &svc_url,
        &marker,
    );
    assert_cilium_datapath_via(&profile, &fork_bridge, "fork", &pod_url, &svc_url, &marker);

    // 6. Nothing restarted. A Cilium agent that crash-looped back into
    //    a working datapath would otherwise read as a clean fork.
    for (bridge, label) in [(&source_bridge, "source"), (&fork_bridge, "fork")] {
        let after = inner_restart_counts_via(bridge);
        for (key, before) in &before_restarts {
            let Some(now) = after.get(key) else {
                teardown(&mut client);
                panic!("{label}: container {key} disappeared across the fork");
            };
            if now != before {
                let diag = cilium_diagnostics(&profile);
                teardown(&mut client);
                panic!("{label}: {key} restarted across the fork ({before} → {now})\n{diag}");
            }
        }
        eprintln!(
            "  {label}: {} containers, no restarts across the fork",
            before_restarts.len()
        );
    }

    teardown(&mut client);
}
