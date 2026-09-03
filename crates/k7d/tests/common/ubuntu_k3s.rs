//! Parameterised 3-node Ubuntu/k3s cluster fixture .
//!
//! Lifted out of `test_ubuntu_k3s.rs` so the Cilium increment can pass
//! `k7d.cni=none` without copying `bring_up_cluster`. Default
//! [`UbuntuCni::Flannel`] leaves the cmdline token off, so inc2 stays
//! the absent-`k7d.cni=` path.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use k7d::api::AgentClient;
use k7d::latency::BOOT_UBUNTU_K3S_CLUSTER_3NODE;
use k7d::network::{ClusterNetwork, TapDevice};
use k7d::vm::Vm;

use super::ubuntu::{
    assert_systemd_healthy, build_node_vm_sized, connect_or_dump, host_mem_available_kb,
    node_image, relax_guest_rp_filter, sh, sh_ok, NodeCmdlineExtra, NodeImage, NodeSize,
    TestDataDisk, VmDisk,
};

/// Pre-shared token on the cmdline. Nothing is read back out of the
/// server — agents join with this .
pub const K3S_TOKEN: &str = "K7dUbuntuClusterToken.inc2";

/// Pause image shipped in the airgap tarball — used only for the load
/// churn so the fork test is not also an image-pull test.
pub const CHURN_PAUSE: &str = "docker.io/rancher/mirrored-pause:3.6";

/// Busybox from the same airgap tarball, so a pod that only has to run
/// `sh` is not also an image-pull test.
pub const BUSYBOX: &str = "docker.io/rancher/mirrored-library-busybox:1.36.1";

pub const CONVERGE: Duration = Duration::from_secs(120);

/// What `k7d-k3sconfig` writes into the server's `config.yaml`, off k3s'
/// defaults because the host running these VMs is itself a k3s node on
/// 10.42.0.0/16 / 10.43.0.0/16 (CHALLENGES #121). Keep these three in
/// step with that script.
pub const POD_CIDR: &str = "10.244.0.0/16";
pub const POD_CIDR_PREFIX: &str = "10.244.";
pub const SERVICE_CIDR: &str = "10.245.0.0/16";
pub const SERVICE_CIDR_PREFIX: &str = "10.245.";
pub const CLUSTER_DNS: &str = "10.245.0.10";

/// Which CNI the server writes into `config.yaml` before k3s starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UbuntuCni {
    /// Absent `k7d.cni=` — today's inc2 flannel + kube-proxy path.
    Flannel,
    /// `k7d.cni=none` — `flannel-backend: none` + `disable-kube-proxy`
    /// + `disable-network-policy` (Cilium owns netpol).
    /// Nodes stay NotReady until a CNI is installed; do not wait for
    /// Ready in [`bring_up_cluster_ex`].
    None,
}

impl UbuntuCni {
    pub fn cmdline_token(self) -> Option<&'static str> {
        match self {
            UbuntuCni::Flannel => None,
            UbuntuCni::None => Some("none"),
        }
    }
}

/// A named persistent data disk  for every node of a
/// cluster: Longhorn's `/var/lib/longhorn` is the reason this exists.
///
/// One disk *per node*, never one shared between them — two live ext4
/// mounts of one image corrupt it, which is 24a-inc4a's trap 3.
#[derive(Clone, Copy, Debug)]
pub struct ClusterDataDisk {
    /// Absolute guest path each node mounts its own disk at.
    pub guest_mount: &'static str,
    /// Capacity of each node's disk.
    pub size_bytes: u64,
}

pub struct UbuntuCluster {
    pub image: NodeImage,
    pub _disks: [VmDisk; 3],
    /// Per-node persistent data disks, when the caller asked for them.
    /// Held so the images are deleted when the fixture goes away — the
    /// daemon deliberately never deletes them.
    pub data_disks: Vec<TestDataDisk>,
    pub net: ClusterNetwork,
    pub server: Vm,
    pub agent1: Vm,
    pub agent2: Vm,
    pub kubeconfig: PathBuf,
    pub certs_dir: PathBuf,
    pub server_ip: Ipv4Addr,
    pub boot_to_ready: Duration,
    pub source_failed: [BTreeSet<String>; 3],
    pub mem_before_kb: u64,
    pub mem_after_kb: u64,
    pub cni: UbuntuCni,
}

impl UbuntuCluster {
    pub fn bridge(&self) -> &str {
        self.net.bridge_name()
    }

    pub fn node_name(ip: Ipv4Addr) -> String {
        format!("k7d-{}", ip.to_string().replace('.', "-"))
    }

    pub fn node_names(server_ip: Ipv4Addr) -> [String; 3] {
        [
            Self::node_name(server_ip),
            Self::node_name(Ipv4Addr::new(10, 200, 0, 3)),
            Self::node_name(Ipv4Addr::new(10, 200, 0, 4)),
        ]
    }

    pub fn names(&self) -> [String; 3] {
        Self::node_names(self.server_ip)
    }
}

impl Drop for UbuntuCluster {
    fn drop(&mut self) {
        self.server.shutdown();
        self.agent1.shutdown();
        self.agent2.shutdown();
        let _ = std::fs::remove_file(&self.kubeconfig);
        let _ = std::fs::remove_dir_all(&self.certs_dir);
    }
}

fn k3s_spec(role: &str, server_ip: Ipv4Addr) -> String {
    format!("{role},{server_ip},{K3S_TOKEN}")
}

#[allow(clippy::too_many_arguments)]
fn boot_node(
    image: &NodeImage,
    disk: &VmDisk,
    tap: TapDevice,
    role: &str,
    server_ip: Ipv4Addr,
    cni: UbuntuCni,
    whose: &str,
    data: Option<&TestDataDisk>,
    size: NodeSize,
) -> (Vm, AgentClient, BTreeSet<String>) {
    let spec = k3s_spec(role, server_ip);
    let data_slice: Vec<k7d::disks::DataDisk> =
        data.map(|d| vec![d.disk.clone()]).unwrap_or_default();
    let mut vm = build_node_vm_sized(
        image,
        disk,
        tap,
        NodeCmdlineExtra {
            k3s: Some(&spec),
            cni: cni.cmdline_token(),
        },
        &data_slice,
        size,
    );
    vm.start()
        .unwrap_or_else(|e| panic!("{whose}: Ubuntu node VM should start: {e}"));
    let mut agent = connect_or_dump(&mut vm, whose);
    let failed = assert_systemd_healthy(&mut agent, whose);
    relax_guest_rp_filter(&mut agent, whose);
    (vm, agent, failed)
}

pub fn wait_guest_readyz(agent: &mut AgentClient, whose: &str, ceiling: Duration) {
    let start = Instant::now();
    loop {
        let (code, out, err) = sh(agent, "k3s kubectl get --raw=/readyz 2>&1 || true");
        if code == 0 && out.contains("ok") {
            eprintln!("{whose}: guest /readyz ok after {:?}", start.elapsed());
            return;
        }
        if start.elapsed() > ceiling {
            let logs = sh_ok(
                agent,
                "journalctl -u k3s -u k3s-agent -u k7d-k3s --no-pager -n 80 || true",
            );
            panic!(
                "{whose}: /readyz never ok after {ceiling:?} (last: {code} {out} {err})\n{logs}"
            );
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

pub fn write_host_kubeconfig(
    agent: &mut AgentClient,
    server_ip: Ipv4Addr,
    tag: &str,
) -> (PathBuf, PathBuf) {
    let yaml = sh_ok(agent, "cat /etc/rancher/k3s/k3s.yaml");
    assert!(
        yaml.contains("127.0.0.1") || yaml.contains("localhost"),
        "k3s.yaml does not point at loopback:\n{yaml}"
    );
    let rewritten = yaml
        .replace(
            "https://127.0.0.1:6443",
            &format!("https://{server_ip}:6443"),
        )
        .replace(
            "https://localhost:6443",
            &format!("https://{server_ip}:6443"),
        );
    let kubeconfig = PathBuf::from(format!(
        "/tmp/k7d-ubuntu-{tag}-{}.kubeconfig",
        std::process::id()
    ));
    std::fs::write(&kubeconfig, &rewritten).expect("write host kubeconfig");

    let certs_dir = PathBuf::from(format!(
        "/tmp/k7d-ubuntu-{tag}-certs-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&certs_dir).expect("certs dir");
    let field = |key: &str| -> Vec<u8> {
        let line = rewritten
            .lines()
            .find(|l| l.trim_start().starts_with(key))
            .unwrap_or_else(|| panic!("no {key} in kubeconfig"));
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
    std::fs::write(
        certs_dir.join("ca.crt"),
        field("certificate-authority-data:"),
    )
    .expect("ca.crt");
    std::fs::write(
        certs_dir.join("client.pem"),
        field("client-certificate-data:"),
    )
    .expect("client.pem");
    std::fs::write(certs_dir.join("client-key.pem"), field("client-key-data:"))
        .expect("client-key.pem");
    (kubeconfig, certs_dir)
}

pub fn kubectl(kubeconfig: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("kubectl")
        .arg("--kubeconfig")
        .arg(kubeconfig)
        .args(args)
        .output()
        .map_err(|e| format!("spawn kubectl: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if !out.status.success() {
        return Err(format!(
            "kubectl {} exit {}: {stderr}{stdout}",
            args.join(" "),
            out.status
        ));
    }
    Ok(stdout)
}

/// Quote one argv token for `sh -c`.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// `k3s kubectl` inside the server guest.
///
/// Host-side `kubectl` validates the serving cert against host time.
/// A dilated guest mints that cert from its own `CLOCK_REALTIME`, so
/// at large N the CA's `notBefore` sits in the host's future
/// (CHALLENGES #191). Talking to the API server from inside the guest
/// is the path that does not wait for the host to catch up.
pub fn guest_kubectl(agent: &mut AgentClient, args: &[&str]) -> Result<String, String> {
    // `--request-timeout` keeps the in-guest call inside the agent's
    // 30 s exec window. A blocking `rollout status --timeout=300s`
    // would look like a hung vsock (CHALLENGES #194).
    let mut cmd = String::from("k3s kubectl --request-timeout=20s");
    for a in args {
        cmd.push(' ');
        cmd.push_str(&sh_quote(a));
    }
    let out = agent
        .exec(&["sh", "-c", &cmd])
        .map_err(|e| format!("k3s kubectl {} failed to run: {e:?}", args.join(" ")))?;
    if out.exit_code != 0 {
        return Err(format!(
            "k3s kubectl {} exit {}: {}{}",
            args.join(" "),
            out.exit_code,
            out.stderr,
            out.stdout
        ));
    }
    Ok(out.stdout)
}

/// [`apply_yaml`] via [`guest_kubectl`].
pub fn guest_apply_yaml(agent: &mut AgentClient, tag: &str, yaml: &str) {
    let path = format!("/tmp/k7d-{tag}.yaml");
    let cmd = format!(
        "cat > {path} << 'K7D_YAML_EOF'\n{yaml}\nK7D_YAML_EOF\nk3s kubectl apply -f {path}"
    );
    sh_ok(agent, &cmd);
}

/// Are all `names` `Ready`, asked of the in-guest API server?
pub fn guest_nodes_ready(agent: &mut AgentClient, names: &[String]) -> bool {
    let Ok(text) = guest_kubectl(agent, &["get", "nodes", "--no-headers"]) else {
        return false;
    };
    names.iter().all(|n| {
        text.lines().any(|l| {
            let mut cols = l.split_whitespace();
            cols.next() == Some(n.as_str()) && cols.next() == Some("Ready")
        })
    })
}

/// [`wait_nodes_ready`] through [`guest_kubectl`] — the N≥12 path
/// (CHALLENGES #191).
pub fn wait_nodes_ready_via_guest(agent: &mut AgentClient, names: &[String], ceiling: Duration) {
    let start = Instant::now();
    loop {
        match guest_kubectl(agent, &["get", "nodes", "--no-headers"]) {
            Ok(text) => {
                let all = names.iter().all(|n| {
                    text.lines().any(|l| {
                        let mut cols = l.split_whitespace();
                        cols.next() == Some(n.as_str()) && cols.next() == Some("Ready")
                    })
                });
                if all {
                    eprintln!(
                        "cluster: {} Ready after {:?} (in-guest kubectl)\n{text}",
                        names.len(),
                        start.elapsed()
                    );
                    return;
                }
                eprintln!("cluster: waiting for nodes via guest:\n{text}");
            }
            Err(e) => eprintln!("cluster: k3s kubectl get nodes: {e}"),
        }
        if start.elapsed() > ceiling {
            panic!(
                "cluster: {} nodes never Ready via guest kubectl after {ceiling:?}",
                names.len()
            );
        }
        std::thread::sleep(Duration::from_secs(3));
    }
}

pub fn wait_nodes_ready(kubeconfig: &Path, names: &[String], ceiling: Duration) {
    wait_nodes(kubeconfig, names, ceiling, true);
}

/// `kubectl apply` an inline manifest, failing loudly.
pub fn apply_yaml(kubeconfig: &Path, tag: &str, yaml: &str) {
    let path = format!("/tmp/k7d-{tag}-{}.yaml", std::process::id());
    std::fs::write(&path, yaml).expect("write manifest");
    kubectl(kubeconfig, &["apply", "-f", &path]).unwrap_or_else(|e| panic!("apply {tag}: {e}"));
    let _ = std::fs::remove_file(&path);
}

/// `.status.phase` of a pod in `default`, empty when unknown.
pub fn pod_phase(kubeconfig: &Path, pod: &str) -> String {
    kubectl(
        kubeconfig,
        &["get", "pod", pod, "-o", "jsonpath={.status.phase}"],
    )
    .unwrap_or_default()
    .trim()
    .to_string()
}

/// `.status.containerStatuses[0].restartCount` of a pod in `default`.
pub fn pod_restarts(kubeconfig: &Path, pod: &str) -> u64 {
    kubectl(
        kubeconfig,
        &[
            "get",
            "pod",
            pod,
            "-o",
            "jsonpath={.status.containerStatuses[0].restartCount}",
        ],
    )
    .ok()
    .and_then(|s| s.trim().parse().ok())
    .unwrap_or(0)
}

/// Run one throwaway pod to completion before a test starts measuring.
///
/// The cluster is Ready ~40 s after boot, but each agent is still
/// unpacking k3s' airgap image tarball into its own containerd for a
/// while after that. A test that starts a pod before then measures the
/// unpack and blames itself for `ContainerCreating`.
pub fn settle_cluster(kubeconfig: &Path, tag: &str) {
    let pod = format!("{tag}-settle");
    apply_yaml(
        kubeconfig,
        &pod,
        &format!(
            r"apiVersion: v1
kind: Pod
metadata:
  name: {pod}
spec:
  restartPolicy: Never
  containers:
  - name: ok
    image: {BUSYBOX}
    imagePullPolicy: IfNotPresent
    command: ['sh', '-c', 'exit 0']
"
        ),
    );
    let started = Instant::now();
    loop {
        let phase = pod_phase(kubeconfig, &pod);
        if phase == "Succeeded" {
            eprintln!(
                "cluster settled: a pod ran to completion in {:?}",
                started.elapsed()
            );
            break;
        }
        assert!(
            started.elapsed() < CONVERGE * 3,
            "no pod could run before the test started (phase {phase:?}): {}",
            kubectl(kubeconfig, &["describe", "pod", &pod]).unwrap_or_else(|e| e)
        );
        std::thread::sleep(Duration::from_secs(3));
    }
    let _ = kubectl(kubeconfig, &["delete", "pod", &pod, "--ignore-not-found"]);
}

pub fn wait_nodes_present(kubeconfig: &Path, names: &[String], ceiling: Duration) {
    wait_nodes(kubeconfig, names, ceiling, false);
}

fn wait_nodes(kubeconfig: &Path, names: &[String], ceiling: Duration, ready: bool) {
    let start = Instant::now();
    loop {
        match kubectl(kubeconfig, &["get", "nodes", "--no-headers"]) {
            Ok(text) => {
                let all = names.iter().all(|n| {
                    text.lines().any(|l| {
                        let mut cols = l.split_whitespace();
                        let name = cols.next() == Some(n.as_str());
                        if !name {
                            return false;
                        }
                        if ready {
                            cols.next() == Some("Ready")
                        } else {
                            true
                        }
                    })
                });
                if all {
                    eprintln!(
                        "cluster: {} {} after {:?}\n{text}",
                        names.len(),
                        if ready { "Ready" } else { "registered" },
                        start.elapsed()
                    );
                    return;
                }
                eprintln!("cluster: waiting for nodes (ready={ready}):\n{text}");
            }
            Err(e) => eprintln!("cluster: kubectl get nodes: {e}"),
        }
        if start.elapsed() > ceiling {
            panic!(
                "cluster: {} nodes never {} after {ceiling:?}",
                names.len(),
                if ready { "Ready" } else { "registered" }
            );
        }
        std::thread::sleep(Duration::from_secs(3));
    }
}

/// inc2's default: flannel, wait for three Ready nodes.
pub fn bring_up_cluster() -> UbuntuCluster {
    bring_up_cluster_ex(UbuntuCni::Flannel, "ubk3s")
}

/// Bring up 1 server + 2 agents on one bridge.
///
/// [`UbuntuCni::Flannel`] waits for three Ready nodes (inc2).
/// [`UbuntuCni::None`] waits only until the three nodes are *registered*
/// — they cannot go Ready until a CNI is installed (the referenced work
/// trap 1). `tag` names the bridge, kubeconfig and per-VM disks.
pub fn bring_up_cluster_ex(cni: UbuntuCni, tag: &str) -> UbuntuCluster {
    bring_up_cluster_with_data(cni, tag, None)
}

/// Like [`bring_up_cluster_ex`], giving every node its **own** named
/// persistent data disk mounted at `data.guest_mount` before k3s starts
/// .
///
/// `None` is byte-identical to inc2–inc4's path: no extra virtio-blk
/// device, no extra mount.
pub fn bring_up_cluster_with_data(
    cni: UbuntuCni,
    tag: &str,
    data: Option<ClusterDataDisk>,
) -> UbuntuCluster {
    bring_up_cluster_sized(cni, tag, data, NodeSize::DEFAULT)
}

/// [`bring_up_cluster_with_data`] with an explicit node size. See
/// [`NodeSize`].
pub fn bring_up_cluster_sized(
    cni: UbuntuCni,
    tag: &str,
    data: Option<ClusterDataDisk>,
    size: NodeSize,
) -> UbuntuCluster {
    let _ = k7d::network::cleanup_stale_k7_bridges();
    let image = node_image();
    let mem_before_kb = host_mem_available_kb();
    let boot_start = Instant::now();

    let d0 = VmDisk::clone_of(&image.base_image(), &format!("{tag}-0"));
    let d1 = VmDisk::clone_of(&image.base_image(), &format!("{tag}-1"));
    let d2 = VmDisk::clone_of(&image.base_image(), &format!("{tag}-2"));
    let mut net = ClusterNetwork::create(tag).expect("cluster bridge");
    let t0 = net.add_tap().expect("tap0");
    let t1 = net.add_tap().expect("tap1");
    let t2 = net.add_tap().expect("tap2");
    let server_ip = t0.guest_ip();
    assert_eq!(server_ip, Ipv4Addr::new(10, 200, 0, 2));

    // One disk per node, minted before any VM boots so a provisioning
    // failure is loud before the cluster exists.
    let data_disks: Vec<TestDataDisk> = match data {
        Some(cfg) => (0..3)
            .map(|i| {
                TestDataDisk::attach(
                    &TestDataDisk::unique_id(&format!("{tag}-{i}")),
                    cfg.size_bytes,
                    cfg.guest_mount,
                )
            })
            .collect(),
        None => Vec::new(),
    };
    let node_data = |i: usize| data_disks.get(i);

    // Server first, then agents — trap 2: agents must not race TLS bootstrap.
    let (server, mut sag, sf) = boot_node(
        &image,
        &d0,
        t0,
        "server",
        server_ip,
        cni,
        "server",
        node_data(0),
        size,
    );
    wait_guest_readyz(&mut sag, "server", BOOT_UBUNTU_K3S_CLUSTER_3NODE);
    let (kubeconfig, certs_dir) = write_host_kubeconfig(&mut sag, server_ip, tag);

    let (a1, mut ag1, f1) = boot_node(
        &image,
        &d1,
        t1,
        "agent",
        server_ip,
        cni,
        "agent-1",
        node_data(1),
        size,
    );
    let (a2, mut ag2, f2) = boot_node(
        &image,
        &d2,
        t2,
        "agent",
        server_ip,
        cni,
        "agent-2",
        node_data(2),
        size,
    );
    for (ag, whose) in [(&mut ag1, "agent-1"), (&mut ag2, "agent-2")] {
        let active = sh_ok(ag, "systemctl is-active k3s-agent.service || true");
        assert_eq!(
            active.trim(),
            "active",
            "{whose}: k3s-agent is not active: {active}"
        );
    }

    let names = UbuntuCluster::node_names(server_ip);
    match cni {
        UbuntuCni::Flannel => {
            // Host-side kubectl validates the serving cert against host
            // time. A dilated guest mints that cert in the host's
            // future (CHALLENGES #191), so N>1 talks to the API server
            // from inside the guest rather than waiting for the host
            // clock to catch up.
            if size.dilation > 1 {
                wait_nodes_ready_via_guest(&mut sag, &names, BOOT_UBUNTU_K3S_CLUSTER_3NODE);
            } else {
                wait_nodes_ready(&kubeconfig, &names, BOOT_UBUNTU_K3S_CLUSTER_3NODE);
            }
        }
        UbuntuCni::None => {
            // Ready is a CNI assertion once kube-proxy and flannel are
            // off — the caller installs Cilium before waiting for it.
            wait_nodes_present(&kubeconfig, &names, BOOT_UBUNTU_K3S_CLUSTER_3NODE);
        }
    }
    let boot_to_ready = boot_start.elapsed();
    let mem_after_kb = host_mem_available_kb();
    eprintln!(
        "MEASUREMENT ubuntu k3s boot-to-cluster (cni={cni:?}): {boot_to_ready:?} \
         (ceiling {BOOT_UBUNTU_K3S_CLUSTER_3NODE:?})"
    );
    let ram_per_node = mem_before_kb.saturating_sub(mem_after_kb) / 3;
    eprintln!(
        "MEASUREMENT ubuntu k3s host RAM per node: {ram_per_node} KiB \
         (MemAvailable {mem_before_kb} → {mem_after_kb})"
    );
    assert!(
        boot_to_ready < BOOT_UBUNTU_K3S_CLUSTER_3NODE,
        "boot-to-cluster {boot_to_ready:?} over {BOOT_UBUNTU_K3S_CLUSTER_3NODE:?}"
    );

    drop((sag, ag1, ag2));

    UbuntuCluster {
        image,
        _disks: [d0, d1, d2],
        data_disks,
        net,
        server,
        agent1: a1,
        agent2: a2,
        kubeconfig,
        certs_dir,
        server_ip,
        boot_to_ready,
        source_failed: [sf, f1, f2],
        mem_before_kb,
        mem_after_kb,
        cni,
    }
}

pub fn curl_api(
    bridge: &str,
    certs: &Path,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<String, String> {
    let url = format!("https://10.200.0.2:6443{path}");
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
        bridge,
        "--cacert",
        &certs.join("ca.crt").to_string_lossy(),
        "--cert",
        &certs.join("client.pem").to_string_lossy(),
        "--key",
        &certs.join("client-key.pem").to_string_lossy(),
    ]);
    if let Some(b) = body {
        cmd.args(["-H", "Content-Type: application/json", "--data-binary", b]);
    }
    cmd.arg(&url);
    let out = cmd.output().map_err(|e| format!("spawn curl: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    if !out.status.success() {
        return Err(format!(
            "curl {method} {url} via {bridge} exit {}: {}{stdout}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(stdout)
}

pub fn curl_get(bridge: &str, certs: &Path, path: &str) -> Result<String, String> {
    curl_api(bridge, certs, "GET", path, None)
}

/// `namespace/pod → (uid, container → restartCount)` for long-lived pods.
pub fn snapshot_pods_json(body: &str) -> BTreeMap<String, (String, BTreeMap<String, u64>)> {
    let v: serde_json::Value =
        serde_json::from_str(body).unwrap_or_else(|e| panic!("pods json: {e}: {body}"));
    let empty = Vec::new();
    let mut out = BTreeMap::new();
    for item in v["items"].as_array().unwrap_or(&empty) {
        let ns = item["metadata"]["namespace"].as_str().unwrap_or("");
        let name = item["metadata"]["name"].as_str().unwrap_or("");
        // share-manager-* is Longhorn's RWX NFS pod: it exists only
        // while a workload has the volume attached, and Longhorn
        // deletes it asynchronously once the RWX probe pods Succeed.
        // Its disappearance across a fork is volume lifecycle, not a
        // restart.
        if name.starts_with("churn-pause-")
            || name.starts_with("cil-allow-")
            || name.starts_with("cil-deny-")
            || name.starts_with("tetra-")
            || name.starts_with("helm-install-")
            || name.starts_with("share-manager-")
        {
            continue;
        }
        let uid = item["metadata"]["uid"].as_str().unwrap_or("").to_string();
        let mut restarts = BTreeMap::new();
        for cs in item["status"]["containerStatuses"]
            .as_array()
            .unwrap_or(&empty)
        {
            let cname = cs["name"].as_str().unwrap_or("").to_string();
            restarts.insert(cname, cs["restartCount"].as_u64().unwrap_or(0));
        }
        out.insert(format!("{ns}/{name}"), (uid, restarts));
    }
    out
}

pub fn snapshot_via_kubectl(
    kubeconfig: &Path,
) -> BTreeMap<String, (String, BTreeMap<String, u64>)> {
    let mut all = BTreeMap::new();
    for ns in ["kube-system", "default"] {
        let body = kubectl(kubeconfig, &["get", "pods", "-n", ns, "-o", "json"])
            .unwrap_or_else(|e| panic!("kubectl get pods -n {ns}: {e}"));
        all.extend(snapshot_pods_json(&body));
    }
    all
}

pub fn snapshot_via_bridge(
    bridge: &str,
    certs: &Path,
) -> Result<BTreeMap<String, (String, BTreeMap<String, u64>)>, String> {
    let mut all = BTreeMap::new();
    for ns in ["kube-system", "default"] {
        let body = curl_get(bridge, certs, &format!("/api/v1/namespaces/{ns}/pods"))?;
        all.extend(snapshot_pods_json(&body));
    }
    Ok(all)
}

pub fn assert_no_restarts(
    before: &BTreeMap<String, (String, BTreeMap<String, u64>)>,
    now: &BTreeMap<String, (String, BTreeMap<String, u64>)>,
    whose: &str,
) {
    for (key, (uid, restarts)) in before {
        let (now_uid, now_restarts) = now
            .get(key)
            .unwrap_or_else(|| panic!("{whose}: pod {key} disappeared after the fork (UID {uid})"));
        assert_eq!(
            now_uid, uid,
            "{whose}: pod {key} UID changed {uid} → {now_uid} — the pod was recreated"
        );
        for (c, count) in restarts {
            let now_c = now_restarts.get(c).copied().unwrap_or(0);
            assert!(
                now_c <= *count,
                "{whose}: {key}/{c} restartCount {count} → {now_c} (must stay zero-delta across the convergence wait, not merely at the end)"
            );
        }
    }
}

pub fn nodes_ready_via(bridge: &str, certs: &Path, names: &[String]) -> bool {
    let Ok(body) = curl_get(bridge, certs, "/api/v1/nodes") else {
        return false;
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) else {
        return false;
    };
    let empty = Vec::new();
    names.iter().all(|want| {
        v["items"].as_array().unwrap_or(&empty).iter().any(|n| {
            n["metadata"]["name"].as_str() == Some(want.as_str())
                && n["status"]["conditions"]
                    .as_array()
                    .unwrap_or(&empty)
                    .iter()
                    .any(|c| {
                        c["type"].as_str() == Some("Ready") && c["status"].as_str() == Some("True")
                    })
        })
    })
}

pub fn deploy_churn(kubeconfig: &Path) {
    let yaml = format!(
        r#"apiVersion: apps/v1
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
      containers:
      - name: pause
        image: {CHURN_PAUSE}
        imagePullPolicy: IfNotPresent
"#
    );
    let manifest = format!("/tmp/k7d-ubuntu-inner-load-{}.yaml", std::process::id());
    std::fs::write(&manifest, yaml).expect("write inner-load");
    kubectl(kubeconfig, &["apply", "-f", &manifest]).expect("apply inner-load");
    kubectl(
        kubeconfig,
        &["rollout", "status", "deploy/inner-load", "--timeout=180s"],
    )
    .expect("inner-load rollout");
    kubectl(kubeconfig, &["scale", "deploy/inner-load", "--replicas=6"]).expect("scale up");
    kubectl(
        kubeconfig,
        &["rollout", "status", "deploy/inner-load", "--timeout=120s"],
    )
    .expect("scale-up rollout");
    kubectl(kubeconfig, &["scale", "deploy/inner-load", "--replicas=3"]).expect("scale down");
    kubectl(
        kubeconfig,
        &["rollout", "status", "deploy/inner-load", "--timeout=120s"],
    )
    .expect("scale-down rollout");
    for i in 1..=12 {
        let _ = kubectl(
            kubeconfig,
            &[
                "create",
                "configmap",
                &format!("churn-cm-{i}"),
                "--from-literal=k=v",
            ],
        );
    }
    for i in 1..=8 {
        let pod = format!(
            r#"apiVersion: v1
kind: Pod
metadata:
  name: churn-pause-{i}
spec:
  restartPolicy: Never
  containers:
  - name: pause
    image: {CHURN_PAUSE}
    imagePullPolicy: IfNotPresent
"#
        );
        let p = format!("/tmp/k7d-ubuntu-churn-{i}.yaml");
        std::fs::write(&p, pod).expect("write churn pod");
        let _ = kubectl(kubeconfig, &["apply", "-f", &p]);
    }
    std::thread::sleep(Duration::from_secs(3));
    for i in 1..=8 {
        let _ = kubectl(
            kubeconfig,
            &[
                "delete",
                "pod",
                &format!("churn-pause-{i}"),
                "--force",
                "--grace-period=0",
            ],
        );
    }
    for i in 1..=12 {
        let _ = kubectl(
            kubeconfig,
            &[
                "delete",
                "configmap",
                &format!("churn-cm-{i}"),
                "--ignore-not-found",
            ],
        );
    }
    let _ = std::fs::remove_file(&manifest);
    eprintln!("cluster: inner-load + API churn ready");
}

pub fn wait_pod_phase_via(
    bridge: &str,
    certs: &Path,
    ns: &str,
    name: &str,
    phase: &str,
    ceiling: Duration,
) {
    let start = Instant::now();
    let path = format!("/api/v1/namespaces/{ns}/pods/{name}");
    loop {
        match curl_get(bridge, certs, &path) {
            Ok(body) => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                    let got = v["status"]["phase"].as_str().unwrap_or("");
                    if got == phase {
                        eprintln!(
                            "{ns}/{name}: {phase} after {:?} via {bridge}",
                            start.elapsed()
                        );
                        return;
                    }
                    if matches!(got, "Failed" | "Succeeded") && got != phase {
                        let log = pod_log_via(bridge, certs, ns, name)
                            .unwrap_or_else(|e| format!("log: {e}"));
                        panic!(
                            "{ns}/{name}: terminal phase {got} (wanted {phase}) \
                             after {:?} via {bridge}\n{body}\n--- log ---\n{log}",
                            start.elapsed()
                        );
                    }
                }
            }
            Err(e) => eprintln!("{ns}/{name}: get via {bridge}: {e}"),
        }
        if start.elapsed() > ceiling {
            let dump =
                curl_get(bridge, certs, &path).unwrap_or_else(|e| format!("get failed: {e}"));
            let log = pod_log_via(bridge, certs, ns, name).unwrap_or_else(|e| format!("log: {e}"));
            panic!("{ns}/{name}: never {phase} via {bridge} after {ceiling:?}\n{dump}\n--- log ---\n{log}");
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

pub fn pod_log_via(bridge: &str, certs: &Path, ns: &str, name: &str) -> Result<String, String> {
    curl_get(
        bridge,
        certs,
        &format!("/api/v1/namespaces/{ns}/pods/{name}/log"),
    )
}

pub fn pod_ip_via(bridge: &str, certs: &Path, ns: &str, name: &str) -> Result<String, String> {
    let body = curl_get(
        bridge,
        certs,
        &format!("/api/v1/namespaces/{ns}/pods/{name}"),
    )?;
    let v: serde_json::Value = serde_json::from_str(&body).map_err(|e| format!("pod json: {e}"))?;
    v["status"]["podIP"]
        .as_str()
        .filter(|ip| !ip.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| format!("{ns}/{name} has no podIP: {body}"))
}
