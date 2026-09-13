//! Tetragon on Ubuntu Cilium k3s, then fork-and-diff.
//!
//! Reuses the Cilium cluster fixture (`UbuntuCni::None` + Helm Cilium
//! 1.16.10). Installs Tetragon the documented way (Helm, version-
//! pinned). Proves a kprobe sensor fires, and a BPF-LSM sensor if the
//! flavour lists `bpf` in `/sys/kernel/security/lsm`. Then warm-forks
//! under load churn, injects a known action on one branch,
//! and diffs the two event streams.
//!
//! Does not touch the minimal guest, `test_inner_k3s.rs`, the shim,
//! or any existing budget.

mod common;

use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use k7d::fork::fork_cluster_warm;
use k7d::latency::FORK_UBUNTU_K3S_CLUSTER_3VM;
use k7d::vm::Vm;

use common::ubuntu::{connect_or_dump, failed_units, physical_extents, sh_ok, NODE_MEMORY_MB};
use common::ubuntu_helm::{
    ensure_helm, ensure_host_pod_routes, helm_install_cilium, node_pod_cidrs, wait_cilium_ready,
};
use common::ubuntu_k3s::{
    assert_no_restarts, bring_up_cluster_ex, curl_api, curl_get, deploy_churn, kubectl,
    nodes_ready_via, snapshot_via_bridge, snapshot_via_kubectl, wait_nodes_ready, UbuntuCluster,
    UbuntuCni, CONVERGE, K3S_TOKEN,
};

/// Current stable Tetragon chart (2026-04-29). Recorded in the spec.
const TETRAGON_CHART: &str = "1.7.0";
const TETRAGON_NS: &str = "kube-system";
const TETRAGON_READY: Duration = Duration::from_secs(600);
const CILIUM_READY: Duration = Duration::from_secs(600);

/// Probe / inject image pulled through the bridge. Not Never, not airgap.
const BUSYBOX: &str = "docker.io/library/busybox:1.36.1";

const KPROBE_POLICY: &str = "k7d-kprobe-fd-install";
const KPROBE_MESSAGE: &str = "k7d-kprobe-fd-install";
const LSM_POLICY: &str = "k7d-lsm-file-open";
const LSM_MESSAGE: &str = "k7d-lsm-file-open";
const PATH_PREFIX: &str = "/tmp/k7d-tetra-";

/// Pin inject pods to one agent so the child's `IfNotPresent` hit is
/// the same containerd that already pulled busybox on the source.
/// Scheduling the child inject onto a node that never pulled the image
/// left it Pending for 180s (first run).
fn inject_node() -> String {
    UbuntuCluster::node_name(Ipv4Addr::new(10, 200, 0, 3))
}

fn helm_install_tetragon(helm: &Path, kubeconfig: &Path) {
    let out = Command::new(helm)
        .args([
            "install",
            "tetragon",
            "tetragon",
            "--version",
            TETRAGON_CHART,
            "--repo",
            "https://helm.cilium.io/",
            "--namespace",
            TETRAGON_NS,
            "--kubeconfig",
            &kubeconfig.to_string_lossy(),
            "--set",
            "tetragonOperator.replicas=1",
            "--set",
            "crds.installMethod=helm",
        ])
        .output()
        .expect("spawn helm install tetragon");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "helm install tetragon {TETRAGON_CHART} failed: {stderr}{stdout}"
    );
    eprintln!("helm: installed tetragon {TETRAGON_CHART}\n{stdout}");
}

fn wait_tetragon_ready(kubeconfig: &Path, ceiling: Duration) -> Duration {
    let start = Instant::now();
    loop {
        let agents = kubectl(
            kubeconfig,
            &[
                "-n",
                TETRAGON_NS,
                "get",
                "ds",
                "tetragon",
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
                TETRAGON_NS,
                "get",
                "deploy",
                "tetragon-operator",
                "-o",
                "jsonpath={.status.readyReplicas}",
            ],
        )
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0);
        if agents == 3 && operator >= 1 {
            let elapsed = start.elapsed();
            eprintln!("Tetragon ready: 3/3 agents + operator after {elapsed:?}");
            return elapsed;
        }
        if start.elapsed() > ceiling {
            let diag = tetragon_diagnostics(kubeconfig);
            panic!(
                "Tetragon never Ready in {ceiling:?} (agents={agents}/3 operator={operator})\n{diag}"
            );
        }
        eprintln!("Tetragon not ready yet: agents={agents}/3 operator={operator}");
        std::thread::sleep(Duration::from_secs(5));
    }
}

fn tetragon_diagnostics(kubeconfig: &Path) -> String {
    let mut out = String::new();
    for args in [
        vec!["-n", TETRAGON_NS, "get", "pods", "-o", "wide"],
        vec!["-n", TETRAGON_NS, "get", "ds,deploy", "-o", "wide"],
        vec!["get", "nodes", "-o", "wide"],
        vec![
            "-n",
            TETRAGON_NS,
            "get",
            "events",
            "--sort-by=.lastTimestamp",
        ],
        vec![
            "-n",
            TETRAGON_NS,
            "logs",
            "-l",
            "app.kubernetes.io/name=tetragon",
            "--all-containers",
            "--prefix",
            "--tail=80",
        ],
        vec![
            "-n",
            TETRAGON_NS,
            "logs",
            "-l",
            "app.kubernetes.io/name=tetragon-operator",
            "--tail=80",
        ],
        vec![
            "-n",
            TETRAGON_NS,
            "logs",
            "-l",
            "app.kubernetes.io/name=tetragon-operator",
            "--previous",
            "--tail=80",
        ],
    ] {
        let got = kubectl(kubeconfig, &args).unwrap_or_else(|e| e);
        out.push_str(&format!("--- kubectl {} ---\n{got}\n", args.join(" ")));
    }
    out
}

fn guest_lsm_lists_bpf(cluster: &mut UbuntuCluster) -> bool {
    let mut ag = connect_or_dump(&mut cluster.server, "server-lsm");
    let lsm = sh_ok(&mut ag, "cat /sys/kernel/security/lsm");
    let btf = sh_ok(
        &mut ag,
        "if [ -e /sys/kernel/btf/vmlinux ]; then echo BTF_OK; else echo BTF_MISSING; fi",
    );
    eprintln!("flavour LSM list: {}", lsm.trim());
    eprintln!("flavour BTF: {}", btf.trim());
    assert!(
        btf.contains("BTF_OK"),
        "flavour has no /sys/kernel/btf/vmlinux — Tetragon CO-RE cannot load: {btf}"
    );
    lsm.split(',').any(|s| s.trim() == "bpf")
}

fn apply_yaml(kubeconfig: &Path, name: &str, yaml: &str) {
    let path = format!("/tmp/k7d-ubuntu-tetra-{name}-{}.yaml", std::process::id());
    std::fs::write(&path, yaml).unwrap_or_else(|e| panic!("write {name}: {e}"));
    kubectl(kubeconfig, &["apply", "-f", &path]).unwrap_or_else(|e| panic!("apply {name}: {e}"));
    let _ = std::fs::remove_file(&path);
}

fn kprobe_policy_yaml() -> String {
    format!(
        r#"apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: {KPROBE_POLICY}
spec:
  kprobes:
  - call: "fd_install"
    syscall: false
    message: "{KPROBE_MESSAGE}"
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "file"
    selectors:
    - matchArgs:
      - index: 1
        operator: "Prefix"
        values:
        - "{PATH_PREFIX}"
"#
    )
}

fn lsm_policy_yaml() -> String {
    format!(
        r#"apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: {LSM_POLICY}
spec:
  lsmhooks:
  - hook: "file_open"
    message: "{LSM_MESSAGE}"
    args:
    - index: 0
      type: "file"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "{PATH_PREFIX}"
"#
    )
}

fn apply_tracing_policies(kubeconfig: &Path, want_lsm: bool) {
    let start = Instant::now();
    loop {
        match kubectl(kubeconfig, &["get", "crd", "tracingpolicies.cilium.io"]) {
            Ok(_) => break,
            Err(e) if start.elapsed() > Duration::from_secs(60) => {
                panic!("TracingPolicy CRD never appeared: {e}")
            }
            Err(e) => {
                eprintln!("waiting for TracingPolicy CRD: {e}");
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    }
    apply_yaml(kubeconfig, "kprobe-tp", &kprobe_policy_yaml());
    if want_lsm {
        apply_yaml(kubeconfig, "lsm-tp", &lsm_policy_yaml());
    }
    // Give the agent a beat to attach the sensors before the first
    // inject. A silent Ready DaemonSet with no events is a loud fail
    // later, not a pass here.
    std::thread::sleep(Duration::from_secs(5));
    let tps = kubectl(kubeconfig, &["get", "tracingpolicies"]).unwrap_or_default();
    assert!(
        tps.contains(KPROBE_POLICY),
        "kprobe TracingPolicy missing:\n{tps}"
    );
    if want_lsm {
        assert!(
            tps.contains(LSM_POLICY),
            "LSM TracingPolicy missing:\n{tps}"
        );
    }
    eprintln!("TracingPolicies applied:\n{tps}");
}

fn inject_pod_json(name: &str, path: &str) -> String {
    let node = inject_node();
    serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name},
        "spec": {
            "nodeName": node,
            "restartPolicy": "Never",
            "containers": [{
                "name": "inject",
                "image": BUSYBOX,
                "imagePullPolicy": "IfNotPresent",
                "command": ["/bin/sh", "-c"],
                "args": [format!("touch {path}; echo TETRA_OK")]
            }]
        }
    })
    .to_string()
}

fn inject_via_kubectl(kubeconfig: &Path, name: &str, path: &str) {
    let node = inject_node();
    apply_yaml(
        kubeconfig,
        name,
        &format!(
            r#"apiVersion: v1
kind: Pod
metadata:
  name: {name}
spec:
  nodeName: {node}
  restartPolicy: Never
  containers:
  - name: inject
    image: {BUSYBOX}
    imagePullPolicy: IfNotPresent
    command: ["/bin/sh", "-c"]
    args: ["touch {path}; echo TETRA_OK"]
"#
        ),
    );
    let start = Instant::now();
    loop {
        let phase = kubectl(
            kubeconfig,
            &["get", "pod", name, "-o", "jsonpath={.status.phase}"],
        )
        .unwrap_or_default();
        if phase.trim() == "Succeeded" {
            eprintln!(
                "inject {name} on {node}: Succeeded after {:?}",
                start.elapsed()
            );
            return;
        }
        if phase.trim() == "Failed" {
            let log = kubectl(kubeconfig, &["logs", name]).unwrap_or_default();
            panic!("{name} Failed on {node}:\n{log}");
        }
        if start.elapsed() > Duration::from_secs(360) {
            let desc = kubectl(kubeconfig, &["describe", "pod", name]).unwrap_or_default();
            panic!("{name} never Succeeded on {node} (phase={phase}):\n{desc}");
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn inject_via_bridge(bridge: &str, certs: &Path, name: &str, path: &str) {
    let node = inject_node();
    curl_api(
        bridge,
        certs,
        "POST",
        "/api/v1/namespaces/default/pods",
        Some(&inject_pod_json(name, path)),
    )
    .unwrap_or_else(|e| panic!("POST inject pod {name} via {bridge}: {e}"));
    let start = Instant::now();
    let pod_path = format!("/api/v1/namespaces/default/pods/{name}");
    loop {
        match curl_get(bridge, certs, &pod_path) {
            Ok(body) => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                    match v["status"]["phase"].as_str() {
                        Some("Succeeded") => {
                            eprintln!(
                                "inject {name} on {node} via {bridge}: Succeeded after {:?}",
                                start.elapsed()
                            );
                            return;
                        }
                        Some("Failed") => {
                            panic!("{name} Failed via {bridge} on {node}:\n{body}")
                        }
                        other => eprintln!(
                            "inject {name} via {bridge}: phase={other:?} after {:?}",
                            start.elapsed()
                        ),
                    }
                }
            }
            Err(e) => eprintln!("inject {name} get via {bridge}: {e}"),
        }
        if start.elapsed() > Duration::from_secs(360) {
            let events =
                curl_get(bridge, certs, "/api/v1/namespaces/default/events").unwrap_or_default();
            panic!(
                "{name} never Succeeded via {bridge} on {node} after 360s\n--- events ---\n{events}"
            );
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn tetragon_pod_names_kubectl(kubeconfig: &Path) -> Vec<String> {
    let text = kubectl(
        kubeconfig,
        &[
            "-n",
            TETRAGON_NS,
            "get",
            "pods",
            "-l",
            "app.kubernetes.io/name=tetragon",
            "-o",
            "jsonpath={.items[*].metadata.name}",
        ],
    )
    .unwrap_or_default();
    let names: Vec<String> = text.split_whitespace().map(str::to_string).collect();
    assert!(
        !names.is_empty(),
        "no tetragon pods (label app.kubernetes.io/name=tetragon)"
    );
    names
}

fn events_via_kubectl(kubeconfig: &Path) -> String {
    let mut all = String::new();
    for name in tetragon_pod_names_kubectl(kubeconfig) {
        for container in ["export-stdout", "tetragon"] {
            match kubectl(
                kubeconfig,
                &[
                    "-n",
                    TETRAGON_NS,
                    "logs",
                    &name,
                    "-c",
                    container,
                    "--tail=20000",
                ],
            ) {
                Ok(body) => {
                    all.push_str(&body);
                    all.push('\n');
                }
                Err(e) => eprintln!("logs {name}/{container}: {e}"),
            }
        }
    }
    all
}

fn tetragon_pod_names_via(bridge: &str, certs: &Path) -> Result<Vec<String>, String> {
    let body = curl_get(
        bridge,
        certs,
        "/api/v1/namespaces/kube-system/pods?labelSelector=app.kubernetes.io/name%3Dtetragon",
    )?;
    let v: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("tetragon pods json: {e}"))?;
    let empty = Vec::new();
    let names: Vec<String> = v["items"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter_map(|p| p["metadata"]["name"].as_str().map(str::to_string))
        .collect();
    if names.is_empty() {
        return Err(format!("no tetragon pods via {bridge}: {body}"));
    }
    Ok(names)
}

fn events_via_bridge(bridge: &str, certs: &Path) -> Result<String, String> {
    let names = tetragon_pod_names_via(bridge, certs)?;
    let mut all = String::new();
    for name in names {
        for container in ["export-stdout", "tetragon"] {
            let path = format!(
                "/api/v1/namespaces/kube-system/pods/{name}/log?container={container}&tailLines=20000"
            );
            match curl_get(bridge, certs, &path) {
                Ok(body) => {
                    all.push_str(&body);
                    all.push('\n');
                }
                Err(e) => eprintln!("logs {name}/{container} via {bridge}: {e}"),
            }
        }
    }
    Ok(all)
}

fn event_has_kprobe(events: &str, path: &str) -> bool {
    events.contains(path)
        && (events.contains(KPROBE_MESSAGE)
            || events.contains(KPROBE_POLICY)
            || events.contains("fd_install")
            || events.contains("process_kprobe"))
}

fn event_has_lsm(events: &str, path: &str) -> bool {
    events.contains(path)
        && (events.contains(LSM_MESSAGE)
            || events.contains(LSM_POLICY)
            || events.contains("file_open")
            || events.contains("process_lsm"))
}

fn wait_events_kubectl(
    kubeconfig: &Path,
    path: &str,
    want_lsm: bool,
    ceiling: Duration,
) -> (String, Duration) {
    let start = Instant::now();
    loop {
        let events = events_via_kubectl(kubeconfig);
        let kprobe = event_has_kprobe(&events, path);
        let lsm = !want_lsm || event_has_lsm(&events, path);
        if kprobe && lsm {
            return (events, start.elapsed());
        }
        if start.elapsed() > ceiling {
            panic!(
                "Tetragon DaemonSet is Ready but events never appeared for {path} \
                 (kprobe={kprobe} lsm_ok={lsm} want_lsm={want_lsm})\n\
                 --- events (tail) ---\n{}\n--- diag ---\n{}",
                tail(&events, 80),
                tetragon_diagnostics(kubeconfig)
            );
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn wait_events_bridge(
    bridge: &str,
    certs: &Path,
    path: &str,
    want_lsm: bool,
    ceiling: Duration,
) -> (String, Duration) {
    let start = Instant::now();
    loop {
        let events = events_via_bridge(bridge, certs).unwrap_or_else(|e| {
            eprintln!("events via {bridge}: {e}");
            String::new()
        });
        let kprobe = event_has_kprobe(&events, path);
        let lsm = !want_lsm || event_has_lsm(&events, path);
        if kprobe && lsm {
            return (events, start.elapsed());
        }
        if start.elapsed() > ceiling {
            panic!(
                "child/source via {bridge}: Tetragon events never appeared for {path} \
                 (kprobe={kprobe} lsm_ok={lsm} want_lsm={want_lsm})\n\
                 --- events (tail) ---\n{}",
                tail(&events, 80)
            );
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn tail(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.lines().collect();
    lines
        .iter()
        .rev()
        .take(n)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .copied()
        .collect::<Vec<_>>()
        .join("\n")
}

fn assert_cni_none_on_server(cluster: &mut UbuntuCluster) {
    let mut sag = connect_or_dump(&mut cluster.server, "server-cni");
    let cmd = sh_ok(&mut sag, "cat /proc/cmdline");
    assert!(
        cmd.contains("k7d.cni=none"),
        "server cmdline missing k7d.cni=none: {cmd}"
    );
    assert!(
        cmd.contains(&format!(
            "k7d.k3s=server,{},{}",
            cluster.server_ip, K3S_TOKEN
        )),
        "server cmdline missing k7d.k3s=: {cmd}"
    );
    let cfg = sh_ok(&mut sag, "cat /etc/rancher/k3s/config.yaml");
    assert!(
        cfg.contains("flannel-backend: none")
            && cfg.contains("disable-kube-proxy: true")
            && cfg.contains("disable-network-policy: true"),
        "server config.yaml did not get the cni=none flags:\n{cfg}"
    );
}

/// Tetragon 1.7.0 via Helm on the Ubuntu 3-node Cilium cluster, then
/// the fork-and-diff the Ubuntu ladder exists for.
#[test]
fn test_ubuntu_tetragon_fork_event_diff() {
    let _ = env_logger::builder().is_test(true).try_init();
    let boot_start = Instant::now();
    let mut cluster = bring_up_cluster_ex(UbuntuCni::None, "ubtet");
    assert_cni_none_on_server(&mut cluster);

    let kube = cluster.kubeconfig.clone();
    let names = cluster.names();
    let helm = ensure_helm();

    helm_install_cilium(&helm, &kube, cluster.server_ip);
    wait_cilium_ready(&kube, CILIUM_READY);
    wait_nodes_ready(&kube, &names, Duration::from_secs(180));
    let cidrs = node_pod_cidrs(&kube);
    ensure_host_pod_routes(cluster.bridge(), &cidrs);
    let nodes = kubectl(&kube, &["get", "nodes", "--no-headers"]).expect("get nodes");
    assert_eq!(
        nodes.lines().filter(|l| l.contains("Ready")).count(),
        3,
        "Cilium must stay the CNI — three nodes Ready before Tetragon:\n{nodes}"
    );
    eprintln!("Cilium cluster Ready; installing Tetragon {TETRAGON_CHART}");

    let tetra_start = Instant::now();
    helm_install_tetragon(&helm, &kube);
    let helm_apply = tetra_start.elapsed();
    eprintln!("MEASUREMENT tetragon helm apply: {helm_apply:?}");

    let pull_wait = wait_tetragon_ready(&kube, TETRAGON_READY);
    let boot_to_tetra = boot_start.elapsed();
    eprintln!(
        "MEASUREMENT ubuntu tetragon boot-to-Tetragon-Ready: {boot_to_tetra:?} \
         (helm-apply {helm_apply:?} + image-pull/ready {pull_wait:?})"
    );

    let want_lsm = guest_lsm_lists_bpf(&mut cluster);
    if want_lsm {
        eprintln!("flavour lists bpf in LSM — installing BPF-LSM TracingPolicy");
    } else {
        eprintln!(
            "FINDING /sys/kernel/security/lsm does not list bpf \
             — kprobe only; this is an image-package / flavour finding, not a \
             config-minimal rebuild"
        );
    }
    apply_tracing_policies(&kube, want_lsm);

    let src_path = format!("{PATH_PREFIX}src-{}", std::process::id());
    let inject_start = Instant::now();
    inject_via_kubectl(&kube, "tetra-src-probe", &src_path);
    let (src_events, event_latency) =
        wait_events_kubectl(&kube, &src_path, want_lsm, Duration::from_secs(90));
    let inject_to_event = inject_start.elapsed();
    eprintln!(
        "MEASUREMENT tetragon event-to-inject (source kprobe{}): wait {event_latency:?} \
         wall {inject_to_event:?}",
        if want_lsm { "+lsm" } else { "" }
    );
    assert!(
        event_has_kprobe(&src_events, &src_path),
        "kprobe sensor did not fire for {src_path}"
    );
    if want_lsm {
        assert!(
            event_has_lsm(&src_events, &src_path),
            "BPF-LSM sensor did not fire for {src_path} (lsm lists bpf)"
        );
    }

    deploy_churn(&kube);

    let src_bridge = cluster.bridge().to_string();
    let certs = cluster.certs_dir.clone();
    let before = snapshot_via_kubectl(&kube);
    assert!(
        before.keys().filter(|k| k.contains("/tetragon-")).count() >= 3,
        "expected a restart-count entry per Tetragon agent: {before:?}"
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
        "ubtetf",
        &[None, None, None],
        &[None, None, None],
        &["ubuntu-tet-0", "ubuntu-tet-1", "ubuntu-tet-2"],
    )
    .expect("warm fork of the Ubuntu Tetragon cluster");
    let fork_latency = fork_start.elapsed();
    eprintln!(
        "MEASUREMENT ubuntu tetragon cluster warm fork (3 × {NODE_MEMORY_MB} MB): {fork_latency:?} \
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
    ensure_host_pod_routes(&child_bridge, &cidrs);
    assert!(
        !bridges_before.contains(&child_bridge),
        "child bridge should be new: {child_bridge} in {bridges_before:?}"
    );
    assert_eq!(forks.len(), 3);
    assert_eq!(forks[0].guest_ip(), Some(cluster.server_ip));

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

    if let (Some(src_disk), Some(child_disk)) = (
        cluster
            .server
            .block_devices()
            .first()
            .map(|c| c.host_path.clone()),
        forks[0]
            .block_devices()
            .first()
            .map(|c| c.host_path.clone()),
    ) {
        let shared: Vec<u64> = physical_extents(&src_disk)
            .intersection(&physical_extents(&child_disk))
            .copied()
            .collect();
        eprintln!(
            "MEASUREMENT ubuntu tetragon post-fork CoW (root disk extents shared): {}",
            shared.len()
        );
        assert!(!shared.is_empty(), "child root shares no extents");
    }

    let start = Instant::now();
    loop {
        let src_pods = snapshot_via_bridge(&src_bridge, &certs)
            .unwrap_or_else(|e| panic!("source pods via {src_bridge}: {e}"));
        let child_pods = snapshot_via_bridge(&child_bridge, &certs)
            .unwrap_or_else(|e| panic!("child pods via {child_bridge}: {e}"));
        assert_no_restarts(&before, &src_pods, "source");
        assert_no_restarts(&before, &child_pods, "child");
        let src_ready = nodes_ready_via(&src_bridge, &certs, &names);
        let child_ready = nodes_ready_via(&child_bridge, &certs, &names);
        if src_ready && child_ready && start.elapsed() >= Duration::from_secs(5) {
            eprintln!(
                "fork: both clusters Ready, zero restarts across {:?}",
                start.elapsed()
            );
            break;
        }
        if start.elapsed() > CONVERGE {
            panic!(
                "fork: clusters did not converge Ready in {CONVERGE:?} \
                 (src_ready={src_ready} child_ready={child_ready})"
            );
        }
        std::thread::sleep(Duration::from_secs(2));
    }

    let ready = curl_get(&child_bridge, &certs, "/readyz").expect("child API via its own bridge");
    assert!(
        ready.contains("ok"),
        "child /readyz via {child_bridge} not ok: {ready}"
    );

    let child_path = format!("{PATH_PREFIX}child-{}", std::process::id());
    inject_via_bridge(&child_bridge, &certs, "tetra-child-inject", &child_path);
    let (child_events, child_event_latency) = wait_events_bridge(
        &child_bridge,
        &certs,
        &child_path,
        want_lsm,
        Duration::from_secs(90),
    );
    eprintln!("MEASUREMENT tetragon event-to-inject (child): {child_event_latency:?}");
    assert!(
        event_has_kprobe(&child_events, &child_path),
        "child did not see the inject kprobe for {child_path}"
    );

    let src_after = events_via_bridge(&src_bridge, &certs)
        .unwrap_or_else(|e| panic!("source events after child inject: {e}"));
    assert!(
        !src_after.contains(&child_path),
        "source Tetragon stream saw the child's inject {child_path} — streams did not diverge"
    );
    assert!(
        child_events.contains(&child_path),
        "child Tetragon stream missing the inject path {child_path}"
    );
    assert!(
        !child_events.contains(&format!("{PATH_PREFIX}src-ghost")),
        "unexpected ghost marker on child"
    );
    eprintln!("fork: Tetragon event streams diverge (child-only inject {child_path})");

    for child in &mut forks {
        child.shutdown();
    }
    drop(fork_net);
}
