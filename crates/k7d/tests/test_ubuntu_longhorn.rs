//! Longhorn CSI on Ubuntu Cilium k3s, then fork .
//!
//! Reuses inc3/inc4's cluster fixture (`UbuntuCni::None` + Helm Cilium
//! 1.16.10), now with a 24a-inc4a **persistent data disk** per node
//! mounted at `/var/lib/longhorn` — Longhorn's replica directory has to
//! outlive the VM that is the node, and each fork branch has to get its
//! own reflinked copy rather than two live ext4 mounts of one image.
//!
//! Longhorn is installed the documented way: Helm, version-pinned,
//! images pulled through the bridge. No static YAML, no airgap tar, no
//! `imagePullPolicy: Never`, no guest-kernel rebuild.
//!
//! What it proves: manager/CSI/instance-manager Ready, an RWO volume
//! written and read back, an RWX volume written on one node and read on
//! another (Longhorn's NFS share-manager), and then a warm fork under
//! inc2 load churn where the child sees the volumes and their markers,
//! the source never sees a child-only write, no pod restarts or is
//! recreated across the whole converge wait, the child's API answers on
//! its own bridge, and no systemd unit fails on a child that was fine on
//! its source.
//!
//! Does not touch the minimal guest, `test_inner_k3s.rs`, or any
//! existing budget.

mod common;

use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use k7d::fork::fork_cluster_warm;
use k7d::latency::FORK_UBUNTU_K3S_CLUSTER_3VM;
use k7d::vm::Vm;

use common::ubuntu::{connect_or_dump, failed_units, physical_extents, sh, sh_ok, NodeSize};
use common::ubuntu_helm::{ensure_helm, helm_install_cilium, wait_cilium_ready};
use common::ubuntu_k3s::{
    assert_no_restarts, bring_up_cluster_sized, curl_api, curl_get, deploy_churn, kubectl,
    nodes_ready_via, snapshot_pods_json, snapshot_via_bridge, snapshot_via_kubectl,
    wait_nodes_ready, ClusterDataDisk, UbuntuCluster, UbuntuCni, CONVERGE, K3S_TOKEN,
};

/// Current stable Longhorn chart (2026-08-14), `kubeVersion >=1.25.0-0`
/// against this cluster's k3s v1.32.5. Recorded in the spec.
const LONGHORN_CHART: &str = "1.12.1";
const LONGHORN_NS: &str = "longhorn-system";
const CILIUM_READY: Duration = Duration::from_secs(600);
/// Longhorn is ~10 images across manager, CSI sidecars, instance-manager
/// and share-manager, all pulled through the bridge on first install.
const LONGHORN_READY: Duration = Duration::from_secs(900);
const PVC_BOUND: Duration = Duration::from_secs(300);
const POD_PHASE: Duration = Duration::from_secs(420);

/// Where each node's persistent data disk is mounted — Longhorn's
/// `defaultDataPath`, set explicitly below so a chart default drift
/// cannot silently move replicas onto the ephemeral root disk.
const LONGHORN_DATA_PATH: &str = "/var/lib/longhorn";
/// 16 GiB, sparse: big enough that Longhorn's default reserved and
/// minimum-available percentages still leave the test volumes
/// schedulable, and it costs only what the guest writes.
const DATA_DISK_SIZE: u64 = 16 * 1024 * 1024 * 1024;

/// Longhorn documents 4 vCPU and 4 GB of RAM per storage node, so give
/// it that. inc2–inc4's 2 GB is demonstrably too little: manager, CSI
/// sidecar and node-driver-registrar containers are OOMKilled while ten
/// images are still being pulled and unpacked, which reads as a broken
/// Longhorn rather than as a node with no headroom (CHALLENGES #120).
/// Every other Ubuntu test keeps [`NodeSize::DEFAULT`].
const LONGHORN_NODE: NodeSize = NodeSize {
    memory_mb: 4096,
    vcpus: 4,
    dilation: 1,
};

/// Probe pods pull this through the bridge. Not Never, not airgap.
const BUSYBOX: &str = "docker.io/library/busybox:1.36.1";

const RWO_PVC: &str = "lh-rwo";
const RWX_PVC: &str = "lh-rwx";
const RWO_MARKER: &str = "k7d-longhorn-rwo-source-3d81";
const RWX_MARKER: &str = "k7d-longhorn-rwx-source-6b52";
const CHILD_MARKER: &str = "k7d-longhorn-child-only-9c07";
const LOOPBACK_MARKER: &str = "k7d-host-to-pod-ok-4f13";

/// Pin every workload pod that needs a pulled image to one agent, so the
/// child's `IfNotPresent` hit is the same containerd that pulled it on
/// the source (CHALLENGES #116).
fn pinned_node() -> String {
    UbuntuCluster::node_name(Ipv4Addr::new(10, 200, 0, 3))
}

/// The *other* agent, for the RWX cross-node read.
fn second_node() -> String {
    UbuntuCluster::node_name(Ipv4Addr::new(10, 200, 0, 4))
}

fn helm_install_longhorn(helm: &Path, kubeconfig: &Path) {
    let out = Command::new(helm)
        .args([
            "install",
            "longhorn",
            "longhorn",
            "--version",
            LONGHORN_CHART,
            "--repo",
            "https://charts.longhorn.io",
            "--namespace",
            LONGHORN_NS,
            "--create-namespace",
            "--kubeconfig",
            &kubeconfig.to_string_lossy(),
            // The data disk is the point: say so rather than trusting a
            // chart default that would put replicas on the root disk.
            "--set",
            &format!("defaultSettings.defaultDataPath={LONGHORN_DATA_PATH}"),
            // A 3-node cluster cannot honour the chart's default of 3
            // replicas per CSI sidecar deployment (anti-affinity plus
            // 2 GB nodes); one each is a documented value.
            "--set",
            "csi.attacherReplicaCount=1",
            "--set",
            "csi.provisionerReplicaCount=1",
            "--set",
            "csi.resizerReplicaCount=1",
            "--set",
            "csi.snapshotterReplicaCount=1",
            // No UI in a test, and no outbound version checks: both
            // would be pods and requests this increment does not measure.
            "--set",
            "longhornUI.replicas=0",
            // Longhorn 1.12's chart creates ingress-only NetworkPolicies
            // for its own components by default
            // (`networkPolicies.restrictInternalTraffic`, on even when
            // `networkPolicies.enabled` is false), and every `from:` in
            // the `instance-manager` policy is a `podSelector`. The
            // initiator in Longhorn's own loopback iSCSI attach is not a
            // pod: `iscsiadm` runs in the node's host namespace and,
            // under Cilium, arrives at the endpoint sourced from the
            // node's `cilium_host` router IP with identity `world`. So
            // the policy denies the one connection every V1 attach needs
            // — `drop (Policy denied) identity world->…  :3260 tcp SYN`
            // — and the engine sits in `starting` until CSI gives up
            // (CHALLENGES #121). Turning the internal policies off is
            // the chart's documented switch for managing that traffic
            // yourself.
            "--set",
            "networkPolicies.restrictInternalTraffic=false",
            "--set",
            "defaultSettings.upgradeChecker=false",
            "--set",
            "preUpgradeChecker.jobEnabled=false",
        ])
        .output()
        .expect("spawn helm install longhorn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "helm install longhorn {LONGHORN_CHART} failed: {stderr}{stdout}"
    );
    eprintln!("helm: installed longhorn {LONGHORN_CHART}\n{stdout}");
}

fn jsonpath(kubeconfig: &Path, args: &[&str]) -> u32 {
    kubectl(kubeconfig, args)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0)
}

fn ds_ready(kubeconfig: &Path, name: &str) -> u32 {
    jsonpath(
        kubeconfig,
        &[
            "-n",
            LONGHORN_NS,
            "get",
            "ds",
            name,
            "-o",
            "jsonpath={.status.numberReady}",
        ],
    )
}

fn deploy_ready(kubeconfig: &Path, name: &str) -> u32 {
    jsonpath(
        kubeconfig,
        &[
            "-n",
            LONGHORN_NS,
            "get",
            "deploy",
            name,
            "-o",
            "jsonpath={.status.readyReplicas}",
        ],
    )
}

/// One running instance-manager per node is what makes a V1 volume
/// attachable; the DaemonSets being Ready is not enough on its own.
fn instance_managers_running(kubeconfig: &Path) -> usize {
    kubectl(
        kubeconfig,
        &[
            "-n",
            LONGHORN_NS,
            "get",
            "pods",
            "-l",
            "longhorn.io/component=instance-manager",
            "-o",
            "jsonpath={.items[*].status.phase}",
        ],
    )
    .unwrap_or_default()
    .split_whitespace()
    .filter(|p| *p == "Running")
    .count()
}

fn wait_longhorn_ready(kubeconfig: &Path, ceiling: Duration) -> Result<Duration, String> {
    let start = Instant::now();
    loop {
        let manager = ds_ready(kubeconfig, "longhorn-manager");
        let csi = ds_ready(kubeconfig, "longhorn-csi-plugin");
        let attacher = deploy_ready(kubeconfig, "csi-attacher");
        let provisioner = deploy_ready(kubeconfig, "csi-provisioner");
        let ims = instance_managers_running(kubeconfig);
        let sc = kubectl(kubeconfig, &["get", "sc", "longhorn"]).is_ok();
        if manager == 3 && csi == 3 && attacher >= 1 && provisioner >= 1 && ims == 3 && sc {
            let elapsed = start.elapsed();
            eprintln!(
                "Longhorn ready after {elapsed:?}: manager 3/3, csi-plugin 3/3, \
                 instance-managers {ims}/3, StorageClass longhorn"
            );
            return Ok(elapsed);
        }
        if start.elapsed() > ceiling {
            return Err(format!(
                "Longhorn never Ready in {ceiling:?} (manager={manager}/3 csi={csi}/3 \
                 attacher={attacher} provisioner={provisioner} instance-managers={ims}/3 \
                 sc={sc})\n{}",
                longhorn_diagnostics(kubeconfig)
            ));
        }
        eprintln!(
            "Longhorn not ready yet: manager={manager}/3 csi={csi}/3 attacher={attacher} \
             provisioner={provisioner} instance-managers={ims}/3 sc={sc} \
             ({:?} elapsed)",
            start.elapsed()
        );
        std::thread::sleep(Duration::from_secs(10));
    }
}

fn longhorn_diagnostics(kubeconfig: &Path) -> String {
    let mut out = String::new();
    for args in [
        vec!["-n", LONGHORN_NS, "get", "pods", "-o", "wide"],
        // Longhorn's own pods are not the whole story: a manager that
        // cannot resolve its webhook is waiting on CoreDNS, whose pod is
        // in another namespace.
        vec!["get", "pods", "-A", "-o", "wide"],
        vec!["-n", LONGHORN_NS, "get", "ds,deploy"],
        vec!["-n", LONGHORN_NS, "get", "nodes.longhorn.io", "-o", "wide"],
        vec!["get", "sc"],
        vec!["get", "pvc,pv", "-A"],
        vec![
            "-n",
            LONGHORN_NS,
            "get",
            "events",
            "--sort-by=.lastTimestamp",
        ],
        // The volume/engine/replica CRs are where an attach that the CSI
        // layer only reports as `DeadlineExceeded` says what it was
        // actually waiting for.
        vec![
            "-n",
            LONGHORN_NS,
            "get",
            "volumes.longhorn.io,engines.longhorn.io,replicas.longhorn.io",
            "-o",
            "wide",
        ],
        vec![
            "-n",
            LONGHORN_NS,
            "get",
            "engines.longhorn.io",
            "-o",
            "yaml",
        ],
        // A restart in this namespace is nearly always OOMKilled on a
        // 2 GB node; the reason and exit code say so outright, where a
        // RESTARTS column only says something happened.
        vec![
            "-n",
            LONGHORN_NS,
            "get",
            "pods",
            "-o",
            "jsonpath={range .items[*]}{.metadata.name}{range .status.containerStatuses[*]}\
             {\" \"}{.name}{\"=\"}{.restartCount}{\" last=\"}{.lastState.terminated.reason}\
             {\":\"}{.lastState.terminated.exitCode}{end}{\"\\n\"}{end}",
        ],
        vec![
            "-n",
            LONGHORN_NS,
            "logs",
            "-l",
            "app=longhorn-manager",
            "--tail=60",
            "--prefix",
        ],
        vec![
            "-n",
            LONGHORN_NS,
            "logs",
            "-l",
            "longhorn.io/component=instance-manager",
            "--tail=120",
            "--prefix",
        ],
        vec![
            "-n",
            LONGHORN_NS,
            "logs",
            "-l",
            "app=longhorn-csi-plugin",
            "-c",
            "longhorn-csi-plugin",
            "--tail=80",
            "--prefix",
        ],
    ] {
        let got = kubectl(kubeconfig, &args).unwrap_or_else(|e| e);
        out.push_str(&format!("--- kubectl {} ---\n{got}\n", args.join(" ")));
    }
    // A container that exited already lost the reason from its live log,
    // and `--tail` on the running one shows the retry, not the fatal.
    let restarted = kubectl(
        kubeconfig,
        &[
            "-n",
            LONGHORN_NS,
            "get",
            "pods",
            "-o",
            "jsonpath={range .items[*]}{.metadata.name}{\"|\"}\
             {range .status.containerStatuses[*]}{.name}{\"=\"}{.restartCount}{\",\"}{end}\
             {\"\\n\"}{end}",
        ],
    )
    .unwrap_or_default();
    for line in restarted.lines() {
        let Some((pod, containers)) = line.trim().split_once('|') else {
            continue;
        };
        for spec in containers.split(',') {
            let Some((container, count)) = spec.split_once('=') else {
                continue;
            };
            if count.trim() == "0" {
                continue;
            }
            let got = kubectl(
                kubeconfig,
                &[
                    "-n",
                    LONGHORN_NS,
                    "logs",
                    pod,
                    "-c",
                    container,
                    "--previous",
                    "--tail=40",
                ],
            )
            .unwrap_or_else(|e| e);
            out.push_str(&format!(
                "--- {pod}/{container}: log of the container that exited ---\n{got}\n"
            ));
        }
    }
    // Whether the engine's tgt target exists at all. The host side sees
    // a missing target and a dropped packet the same way, so ask the pod
    // that is supposed to be listening.
    let ims = kubectl(
        kubeconfig,
        &[
            "-n",
            LONGHORN_NS,
            "get",
            "pods",
            "-l",
            "longhorn.io/component=instance-manager",
            "-o",
            "jsonpath={range .items[*]}{.metadata.name}{\"\\n\"}{end}",
        ],
    )
    .unwrap_or_default();
    for im in ims.lines().filter(|l| !l.trim().is_empty()) {
        let got = kubectl(
            kubeconfig,
            &[
                "-n",
                LONGHORN_NS,
                "exec",
                im.trim(),
                "--",
                "sh",
                "-c",
                "ss -tlnp 2>/dev/null || netstat -tlnp; echo ---; ps ax | grep -c tgtd; \
                 tgtadm --lld iscsi --mode target --op show 2>&1 | head -20",
            ],
        )
        .unwrap_or_else(|e| e);
        out.push_str(&format!(
            "--- {im}: listening sockets + tgt targets ---\n{got}\n"
        ));
    }
    out
}

fn apply_yaml(kubeconfig: &Path, name: &str, yaml: &str) {
    let path = format!("/tmp/k7d-ubuntu-lh-{name}-{}.yaml", std::process::id());
    std::fs::write(&path, yaml).unwrap_or_else(|e| panic!("write {name}: {e}"));
    kubectl(kubeconfig, &["apply", "-f", &path]).unwrap_or_else(|e| panic!("apply {name}: {e}"));
    let _ = std::fs::remove_file(&path);
}

fn pvc_yaml(name: &str, mode: &str) -> String {
    format!(
        r#"apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: {name}
spec:
  accessModes:
  - {mode}
  storageClassName: longhorn
  resources:
    requests:
      storage: 1Gi
"#
    )
}

fn wait_pvc_bound(kubeconfig: &Path, name: &str, ceiling: Duration) -> Duration {
    let start = Instant::now();
    loop {
        let phase = kubectl(
            kubeconfig,
            &["get", "pvc", name, "-o", "jsonpath={.status.phase}"],
        )
        .unwrap_or_default();
        if phase.trim() == "Bound" {
            eprintln!("PVC {name} Bound after {:?}", start.elapsed());
            return start.elapsed();
        }
        assert!(
            start.elapsed() <= ceiling,
            "PVC {name} never Bound in {ceiling:?} (phase={phase})\n{}",
            longhorn_diagnostics(kubeconfig)
        );
        std::thread::sleep(Duration::from_secs(3));
    }
}

/// A one-shot pod that mounts `pvc` at /data and runs `script`.
///
/// `restartPolicy: Never` plus a `Succeeded` wait is the assertion: the
/// script's own `set -e` failure surfaces as `Failed`, and its stdout is
/// what the caller checks the marker in.
fn probe_pod_yaml(name: &str, node: &str, pvc: &str, script: &str) -> String {
    format!(
        r#"apiVersion: v1
kind: Pod
metadata:
  name: {name}
spec:
  nodeName: {node}
  restartPolicy: Never
  containers:
  - name: probe
    image: {BUSYBOX}
    imagePullPolicy: IfNotPresent
    command: ["/bin/sh", "-c"]
    args: ["set -e; {script}"]
    volumeMounts:
    - name: vol
      mountPath: /data
  volumes:
  - name: vol
    persistentVolumeClaim:
      claimName: {pvc}
"#
    )
}

fn probe_pod_json(name: &str, node: &str, pvc: &str, script: &str) -> String {
    serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name},
        "spec": {
            "nodeName": node,
            "restartPolicy": "Never",
            "containers": [{
                "name": "probe",
                "image": BUSYBOX,
                "imagePullPolicy": "IfNotPresent",
                "command": ["/bin/sh", "-c"],
                "args": [format!("set -e; {script}")],
                "volumeMounts": [{"name": "vol", "mountPath": "/data"}]
            }],
            "volumes": [{"name": "vol", "persistentVolumeClaim": {"claimName": pvc}}]
        }
    })
    .to_string()
}

/// Run a probe pod through kubectl and return its stdout, or the reason
/// it never succeeded. The caller turns `Err` into a panic that also
/// carries the guest-side half of the attach path.
fn try_probe_kubectl(
    kubeconfig: &Path,
    name: &str,
    node: &str,
    pvc: &str,
    script: &str,
) -> Result<String, String> {
    apply_yaml(kubeconfig, name, &probe_pod_yaml(name, node, pvc, script));
    let start = Instant::now();
    loop {
        let phase = kubectl(
            kubeconfig,
            &["get", "pod", name, "-o", "jsonpath={.status.phase}"],
        )
        .unwrap_or_default();
        match phase.trim() {
            "Succeeded" => {
                let log = kubectl(kubeconfig, &["logs", name]).unwrap_or_default();
                eprintln!(
                    "probe {name} on {node} Succeeded after {:?}: {}",
                    start.elapsed(),
                    log.trim()
                );
                return Ok(log);
            }
            "Failed" => {
                let log = kubectl(kubeconfig, &["logs", name]).unwrap_or_default();
                return Err(format!(
                    "probe {name} Failed on {node}:\n{log}\n{}",
                    longhorn_diagnostics(kubeconfig)
                ));
            }
            other => {
                if start.elapsed() > POD_PHASE {
                    return Err(format!(
                        "probe {name} never Succeeded on {node} in {POD_PHASE:?} \
                         (phase={other})\n{}\n{}",
                        kubectl(kubeconfig, &["describe", "pod", name]).unwrap_or_default(),
                        longhorn_diagnostics(kubeconfig)
                    ));
                }
                std::thread::sleep(Duration::from_secs(3));
            }
        }
    }
}

/// `try_probe_kubectl`, and on failure the node's own view of the attach:
/// an iSCSI login that never completes leaves its trace in `iscsiadm`
/// and `iscsid`'s journal inside the guest, not in any Kubernetes object.
fn probe_or_dump(
    cluster: &mut UbuntuCluster,
    kubeconfig: &Path,
    name: &str,
    node: &str,
    pvc: &str,
    script: &str,
) -> String {
    match try_probe_kubectl(kubeconfig, name, node, pvc, script) {
        Ok(log) => log,
        Err(why) => panic!("{why}\n{}", guest_storage_diagnostics(cluster, kubeconfig)),
    }
}

/// The pod IP of `component`'s pod on `node`, which is what the host has
/// to be able to reach for Longhorn's loopback iSCSI path to work.
fn pod_ip_on(kubeconfig: &Path, selector: &str, node: &str) -> String {
    kubectl(
        kubeconfig,
        &[
            "-n",
            LONGHORN_NS,
            "get",
            "pods",
            "-l",
            selector,
            "--field-selector",
            &format!("spec.nodeName={node}"),
            "-o",
            "jsonpath={.items[0].status.podIP}",
        ],
    )
    .unwrap_or_default()
    .trim()
    .to_string()
}

/// What the nodes themselves say about iSCSI, the data disk, and — the
/// part no Kubernetes object shows — whether the host network namespace
/// can reach a pod on its own node at all.
///
/// Longhorn's V1 attach is a host-to-pod loopback iSCSI session: the
/// engine creates a tgt target in the instance-manager pod's netns and
/// then runs `iscsiadm` in the host's, against that pod's IP. So the two
/// `curl` probes below are the whole diagnosis — port 3260 alone failing
/// means tgtd, both failing means host-to-pod routing.
fn guest_storage_diagnostics(cluster: &mut UbuntuCluster, kubeconfig: &Path) -> String {
    let mut out = String::new();
    let vms: Vec<(&mut Vm, &str, String)> = vec![
        (&mut cluster.server, "server", cluster_node_name(0)),
        (&mut cluster.agent1, "agent-1", cluster_node_name(1)),
        (&mut cluster.agent2, "agent-2", cluster_node_name(2)),
    ];
    for (vm, whose, node_name) in vms {
        let im = pod_ip_on(
            kubeconfig,
            "longhorn.io/component=instance-manager",
            &node_name,
        );
        let mgr = pod_ip_on(kubeconfig, "app=longhorn-manager", &node_name);
        let mut ag = connect_or_dump(vm, whose);
        let mut cmds = vec![
            "free -m".to_string(),
            // A node with more runnable threads than vCPUs turns every
            // startup probe and DNS query into a timeout, and each of
            // those reads as a component-specific fault instead.
            "uptime; nproc; vmstat 1 3".to_string(),
            "cat /etc/iscsi/initiatorname.iscsi".to_string(),
            "iscsiadm -m session; iscsiadm -m node; iscsiadm -m iface".to_string(),
            "ls -l /dev/longhorn/ 2>&1".to_string(),
            "journalctl -u iscsid --no-pager -n 40".to_string(),
            format!("df -h {LONGHORN_DATA_PATH} /"),
            "ip -br addr; ip route".to_string(),
        ];
        if !im.is_empty() {
            cmds.push(format!("ip route get {im}"));
            cmds.push(format!(
                "curl -sS -m 5 -o /dev/null -w 'tgt-connect=%{{http_code}} rc-follows\\n' \
                 telnet://{im}:3260; echo rc=$?"
            ));
        }
        if !mgr.is_empty() {
            cmds.push(format!(
                "curl -sS -m 5 -o /dev/null -w 'mgr-http=%{{http_code}}\\n' \
                 http://{mgr}:9500/v1; echo rc=$?"
            ));
        }
        for cmd in &cmds {
            let (_, stdout, stderr) = sh(&mut ag, cmd);
            out.push_str(&format!("--- {whose}: {cmd} ---\n{stdout}{stderr}\n"));
        }
    }
    out
}

fn cluster_node_name(index: u8) -> String {
    UbuntuCluster::node_name(Ipv4Addr::new(10, 200, 0, 2 + index))
}

/// The same probe against a cluster reachable only over its own bridge —
/// after the fork, source and child answer on identical guest IPs, so
/// `curl --interface <bridge>` is the only way to address one of them
/// .
fn run_probe_bridge(
    bridge: &str,
    certs: &Path,
    name: &str,
    node: &str,
    pvc: &str,
    script: &str,
) -> String {
    curl_api(
        bridge,
        certs,
        "POST",
        "/api/v1/namespaces/default/pods",
        Some(&probe_pod_json(name, node, pvc, script)),
    )
    .unwrap_or_else(|e| panic!("POST probe {name} via {bridge}: {e}"));
    let pod_path = format!("/api/v1/namespaces/default/pods/{name}");
    let start = Instant::now();
    loop {
        let phase = curl_get(bridge, certs, &pod_path)
            .ok()
            .and_then(|body| serde_json::from_str::<serde_json::Value>(&body).ok())
            .and_then(|v| v["status"]["phase"].as_str().map(str::to_string))
            .unwrap_or_default();
        match phase.as_str() {
            "Succeeded" => {
                let log = curl_get(bridge, certs, &format!("{pod_path}/log")).unwrap_or_default();
                eprintln!(
                    "probe {name} via {bridge} Succeeded after {:?}: {}",
                    start.elapsed(),
                    log.trim()
                );
                return log;
            }
            "Failed" => {
                let log = curl_get(bridge, certs, &format!("{pod_path}/log")).unwrap_or_default();
                panic!("probe {name} Failed via {bridge} on {node}:\n{log}");
            }
            other => {
                if start.elapsed() > POD_PHASE {
                    let events = curl_get(bridge, certs, "/api/v1/namespaces/default/events")
                        .unwrap_or_default();
                    panic!(
                        "probe {name} never Succeeded via {bridge} in {POD_PHASE:?} \
                         (phase={other:?})\n--- events ---\n{events}"
                    );
                }
                std::thread::sleep(Duration::from_secs(3));
            }
        }
    }
}

/// Longhorn's own pods live in `longhorn-system`, which the shared
/// snapshot helpers do not cover — they walk `kube-system` and `default`.
fn longhorn_snapshot_via_bridge(
    bridge: &str,
    certs: &Path,
) -> Result<
    std::collections::BTreeMap<String, (String, std::collections::BTreeMap<String, u64>)>,
    String,
> {
    let body = curl_get(
        bridge,
        certs,
        &format!("/api/v1/namespaces/{LONGHORN_NS}/pods"),
    )?;
    Ok(snapshot_pods_json(&body))
}

fn longhorn_snapshot_via_kubectl(
    kubeconfig: &Path,
) -> std::collections::BTreeMap<String, (String, std::collections::BTreeMap<String, u64>)> {
    let body = kubectl(
        kubeconfig,
        &["get", "pods", "-n", LONGHORN_NS, "-o", "json"],
    )
    .unwrap_or_else(|e| panic!("kubectl get pods -n {LONGHORN_NS}: {e}"));
    snapshot_pods_json(&body)
}

/// Longhorn's two userspace prerequisites, and the data disk, checked
/// inside every node before Helm runs — an unschedulable CSI plugin ten
/// minutes later is a much worse way to learn the image lacks
/// `iscsiadm`.
fn assert_node_storage_prereqs(cluster: &mut UbuntuCluster) {
    let mounts: Vec<(&mut Vm, &str)> = vec![
        (&mut cluster.server, "server"),
        (&mut cluster.agent1, "agent-1"),
        (&mut cluster.agent2, "agent-2"),
    ];
    for (vm, whose) in mounts {
        let mut ag = connect_or_dump(vm, whose);
        let fstype = sh_ok(&mut ag, &format!("findmnt -no FSTYPE {LONGHORN_DATA_PATH}"));
        assert_eq!(
            fstype.trim(),
            "ext4",
            "{whose}: {LONGHORN_DATA_PATH} is not an ext4 mount — the data disk did not attach"
        );
        let src = sh_ok(&mut ag, &format!("findmnt -no SOURCE {LONGHORN_DATA_PATH}"));
        eprintln!("{whose}: {LONGHORN_DATA_PATH} is ext4 on {}", src.trim());
        for tool in ["iscsiadm", "mount.nfs"] {
            let found = sh_ok(&mut ag, &format!("command -v {tool} || echo MISSING"));
            assert!(
                !found.contains("MISSING"),
                "{whose}: {tool} missing from the node image — Longhorn cannot attach a volume"
            );
        }
        // `iscsid` must be *running*, not merely installed: Longhorn's
        // attach path talks to its socket. This image masks
        // `open-iscsi.service` (it waits on network-online.target, which
        // this image cannot reach — CHALLENGES #108) and clears that
        // ordering from `iscsid` instead, so this is the assertion that
        // the drop-in did its job.
        let (_, active, _) = sh(&mut ag, "systemctl is-active iscsid.service");
        assert_eq!(
            active.trim(),
            "active",
            "{whose}: iscsid is not active — Longhorn's iSCSI attach will fail"
        );
        // The modules the flavour ships as modules, loadable on demand.
        let mods = sh_ok(
            &mut ag,
            "modprobe iscsi_tcp; modprobe nfs; lsmod | grep -c -E '^(iscsi_tcp|nfs) ' || true",
        );
        assert!(
            mods.trim().parse::<u32>().unwrap_or(0) >= 2,
            "{whose}: iscsi_tcp / nfs modules did not load: {mods}"
        );
    }
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
}

/// A pod that serves one file over TCP on Longhorn's iSCSI port, so the
/// reachability test uses the same port and the same direction the
/// engine's `iscsiadm` will.
fn loopback_listener_yaml(name: &str, node: &str) -> String {
    format!(
        r#"apiVersion: v1
kind: Pod
metadata:
  name: {name}
spec:
  nodeName: {node}
  restartPolicy: Never
  containers:
  - name: listen
    image: {BUSYBOX}
    imagePullPolicy: IfNotPresent
    command: ["/bin/sh", "-c"]
    args: ["mkdir -p /www; echo {LOOPBACK_MARKER} > /www/probe; exec httpd -f -p 3260 -h /www"]
    ports:
    - containerPort: 3260
"#
    )
}

/// Start the listener pod on `node`, wait for it to run, and return its
/// pod IP. The caller deletes it.
fn start_loopback_listener(kubeconfig: &Path, name: &str, node: &str) -> String {
    apply_yaml(kubeconfig, name, &loopback_listener_yaml(name, node));
    let start = Instant::now();
    loop {
        let ip = kubectl(
            kubeconfig,
            &["get", "pod", name, "-o", "jsonpath={.status.podIP}"],
        )
        .unwrap_or_default();
        let phase = kubectl(
            kubeconfig,
            &["get", "pod", name, "-o", "jsonpath={.status.phase}"],
        )
        .unwrap_or_default();
        if phase.trim() == "Running" && !ip.trim().is_empty() {
            eprintln!(
                "loopback listener Running on {node} at {} after {:?}",
                ip.trim(),
                start.elapsed()
            );
            return ip.trim().to_string();
        }
        assert!(
            start.elapsed() <= POD_PHASE,
            "loopback listener never Running in {POD_PHASE:?} (phase={phase})\n{}",
            kubectl(kubeconfig, &["describe", "pod", name]).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_secs(3));
    }
}

/// Can `ag`'s host network namespace reach `pod_ip:3260`?
fn host_reaches_pod(ag: &mut k7d::api::AgentClient, pod_ip: &str) -> bool {
    let (_, out, _) = sh(ag, &format!("curl -sS -m 5 http://{pod_ip}:3260/probe"));
    out.contains(LOOPBACK_MARKER)
}

/// Did `ag`'s host network namespace complete a TCP handshake with
/// `ip:port`?
///
/// `tgtd` says nothing until an initiator speaks iSCSI, so a read
/// timeout is what success looks like here and `curl`'s exit code
/// cannot tell it apart from a dropped SYN — both are 28. Only the
/// verbose "Connected to" line distinguishes them.
fn host_connects_to(ag: &mut k7d::api::AgentClient, ip: &str, port: u16) -> (bool, String) {
    let (_, out, err) = sh(
        ag,
        &format!("curl -sS -v -m 5 telnet://{ip}:{port} </dev/null 2>&1; echo rc=$?"),
    );
    let log = format!("{out}{err}");
    (log.contains(&format!("Connected to {ip}")), log)
}

/// Why Cilium dropped the packets, in its own words.
///
/// A dropped SYN to a pod IP looks the same from the host whatever the
/// reason, so ask the agent on that node: watch its drop events while the
/// probe runs, and dump the policy objects and endpoint enforcement state
/// that would explain them.
fn cilium_drop_diagnostics(
    kubeconfig: &Path,
    node: &str,
    target_ip: &str,
    ag: &mut k7d::api::AgentClient,
) -> String {
    let mut out = String::new();
    for args in [
        vec!["get", "networkpolicies", "-A"],
        vec![
            "get",
            "ciliumnetworkpolicies,ciliumclusterwidenetworkpolicies",
            "-A",
        ],
    ] {
        let got = kubectl(kubeconfig, &args).unwrap_or_else(|e| e);
        out.push_str(&format!("--- kubectl {} ---\n{got}\n", args.join(" ")));
    }
    let agent = kubectl(
        kubeconfig,
        &[
            "-n",
            "kube-system",
            "get",
            "pods",
            "-l",
            "k8s-app=cilium",
            "--field-selector",
            &format!("spec.nodeName={node}"),
            "-o",
            "jsonpath={.items[0].metadata.name}",
        ],
    )
    .unwrap_or_default();
    let agent = agent.trim().to_string();
    if agent.is_empty() {
        out.push_str("--- no cilium agent pod found on {node} ---\n");
        return out;
    }
    let monitor = Command::new("kubectl")
        .arg("--kubeconfig")
        .arg(kubeconfig)
        .args([
            "-n",
            "kube-system",
            "exec",
            &agent,
            "-c",
            "cilium-agent",
            "--",
            "timeout",
            "12",
            "cilium-dbg",
            "monitor",
            "--type",
            "drop",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn cilium-dbg monitor");
    std::thread::sleep(Duration::from_secs(2));
    let (_, probe, perr) = sh(
        ag,
        &format!("curl -sS -m 6 telnet://{target_ip}:3260 </dev/null 2>&1; echo rc=$?"),
    );
    let mon = monitor.wait_with_output().expect("cilium-dbg monitor");
    out.push_str(&format!(
        "--- probe during monitor ---\n{probe}{perr}\n\
         --- cilium-dbg monitor --type drop on {node} ---\n{}{}\n",
        String::from_utf8_lossy(&mon.stdout),
        String::from_utf8_lossy(&mon.stderr)
    ));
    let eps = kubectl(
        kubeconfig,
        &[
            "-n",
            "kube-system",
            "exec",
            &agent,
            "-c",
            "cilium-agent",
            "--",
            "cilium-dbg",
            "endpoint",
            "list",
        ],
    )
    .unwrap_or_else(|e| e);
    out.push_str(&format!(
        "--- cilium-dbg endpoint list on {node} ---\n{eps}\n"
    ));
    out
}

/// Longhorn 1.12.1 via Helm on the Ubuntu 3-node Cilium cluster with a
/// persistent data disk per node, RWO + RWX proven, then the warm fork
/// the 25a ladder exists for.
#[test]
fn test_ubuntu_longhorn_fork_volumes() {
    let _ = env_logger::builder().is_test(true).try_init();
    let boot_start = Instant::now();
    let mut cluster = bring_up_cluster_sized(
        UbuntuCni::None,
        "ublh",
        Some(ClusterDataDisk {
            guest_mount: LONGHORN_DATA_PATH,
            size_bytes: DATA_DISK_SIZE,
        }),
        LONGHORN_NODE,
    );
    assert_cni_none_on_server(&mut cluster);
    assert_eq!(
        cluster.data_disks.len(),
        3,
        "every node must have its own data disk, never a shared one"
    );
    let data_images: Vec<std::path::PathBuf> = cluster
        .data_disks
        .iter()
        .map(|d| d.disk.path().to_path_buf())
        .collect();
    assert_node_storage_prereqs(&mut cluster);

    let kube = cluster.kubeconfig.clone();
    let names = cluster.names();
    let helm = ensure_helm();

    helm_install_cilium(&helm, &kube, cluster.server_ip);
    wait_cilium_ready(&kube, CILIUM_READY);
    wait_nodes_ready(&kube, &names, Duration::from_secs(180));
    let nodes = kubectl(&kube, &["get", "nodes", "--no-headers"]).expect("get nodes");
    assert_eq!(
        nodes.lines().filter(|l| l.contains("Ready")).count(),
        3,
        "Cilium must stay the CNI — three nodes Ready before Longhorn:\n{nodes}"
    );

    // ── Longhorn, the documented way ──
    let lh_start = Instant::now();
    helm_install_longhorn(&helm, &kube);
    let helm_apply = lh_start.elapsed();
    eprintln!("MEASUREMENT longhorn helm apply: {helm_apply:?}");
    let pull_wait = match wait_longhorn_ready(&kube, LONGHORN_READY) {
        Ok(waited) => waited,
        // Longhorn's own view of why it is not up is half the story: a
        // manager that exits 1 on one node usually did so because of what
        // that node's kernel, iSCSI userspace, or free memory looks like.
        Err(why) => panic!("{why}\n{}", guest_storage_diagnostics(&mut cluster, &kube)),
    };
    let boot_to_longhorn = boot_start.elapsed();
    eprintln!(
        "MEASUREMENT ubuntu longhorn boot-to-Longhorn-Ready: {boot_to_longhorn:?} \
         (helm-apply {helm_apply:?} + image-pull/ready {pull_wait:?})"
    );

    // Longhorn must have discovered the data disk as its default disk on
    // every node — a schedulable node whose disk is the root filesystem
    // would pass every volume assertion below and lose its replicas with
    // the VM.
    let lh_nodes = kubectl(
        &kube,
        &[
            "-n",
            LONGHORN_NS,
            "get",
            "nodes.longhorn.io",
            "-o",
            "jsonpath={range .items[*]}{.metadata.name}{\" \"}{.spec.disks}{\"\\n\"}{end}",
        ],
    )
    .expect("get longhorn nodes");
    assert_eq!(
        lh_nodes
            .lines()
            .filter(|l| l.contains(LONGHORN_DATA_PATH))
            .count(),
        3,
        "every Longhorn node's default disk must be {LONGHORN_DATA_PATH}:\n{lh_nodes}"
    );

    // ── the loopback iSCSI path, before asking for a volume ──
    //
    // The engine's frontend is the host's `iscsiadm` connecting to the
    // instance-manager pod's own IP on 3260. When that path is broken the
    // only symptom is an Engine stuck in `starting` and a CSI
    // `DeadlineExceeded` seven minutes later, so check it here, against
    // both a plain pod and the instance-manager that will really serve
    // the target (CHALLENGES #119).
    let node = pinned_node();
    let plain_ip = start_loopback_listener(&kube, "lh-loopback", &node);
    let im_ip = pod_ip_on(&kube, "longhorn.io/component=instance-manager", &node);
    // A plain pod reachable while the instance-manager is not is not a
    // routing problem — it is that endpoint's policy, so record which
    // policy objects survive the install.
    eprintln!(
        "--- networkpolicies after install ---\n{}",
        kubectl(&kube, &["get", "networkpolicies", "-A"]).unwrap_or_else(|e| e)
    );
    {
        let mut ag = connect_or_dump(&mut cluster.agent1, "agent-1");
        let plain = host_reaches_pod(&mut ag, &plain_ip);
        let (im_ok, im_probe) = host_connects_to(&mut ag, &im_ip, 3260);
        eprintln!(
            "loopback: plain pod {plain_ip} {}; instance-manager {im_ip}:3260 {}\n{}",
            if plain { "reachable" } else { "UNREACHABLE" },
            if im_ok { "reachable" } else { "UNREACHABLE" },
            im_probe.trim(),
        );
        if !plain || !im_ok {
            let (_, state, _) = sh(&mut ag, "ip -br addr; ip route; ip neigh");
            let drops = cilium_drop_diagnostics(&kube, &node, &im_ip, &mut ag);
            panic!(
                "{node} cannot reach {} from its host network namespace — Longhorn's \
                 loopback iSCSI attach cannot work here\n{state}\n{drops}",
                if plain {
                    "its instance-manager"
                } else {
                    "a pod on itself"
                }
            );
        }
    }
    let _ = kubectl(&kube, &["delete", "pod", "lh-loopback", "--wait=false"]);

    // ── RWO: bound, written, read back ──
    apply_yaml(&kube, "rwo-pvc", &pvc_yaml(RWO_PVC, "ReadWriteOnce"));
    let rwo_bound = wait_pvc_bound(&kube, RWO_PVC, PVC_BOUND);
    eprintln!("MEASUREMENT longhorn RWO PVC bound: {rwo_bound:?}");
    probe_or_dump(
        &mut cluster,
        &kube,
        "lh-rwo-write",
        &node,
        RWO_PVC,
        &format!("echo {RWO_MARKER} > /data/marker; sync; echo WROTE"),
    );
    let read = probe_or_dump(
        &mut cluster,
        &kube,
        "lh-rwo-read",
        &node,
        RWO_PVC,
        "cat /data/marker",
    );
    assert!(
        read.contains(RWO_MARKER),
        "RWO volume did not read back the marker: {read}"
    );

    // ── RWX: written on one node, read on another (share-manager NFS) ──
    apply_yaml(&kube, "rwx-pvc", &pvc_yaml(RWX_PVC, "ReadWriteMany"));
    let rwx_bound = wait_pvc_bound(&kube, RWX_PVC, PVC_BOUND);
    eprintln!("MEASUREMENT longhorn RWX PVC bound: {rwx_bound:?}");
    probe_or_dump(
        &mut cluster,
        &kube,
        "lh-rwx-write",
        &node,
        RWX_PVC,
        &format!("echo {RWX_MARKER} > /data/shared; sync; echo WROTE"),
    );
    let cross = probe_or_dump(
        &mut cluster,
        &kube,
        "lh-rwx-read",
        &second_node(),
        RWX_PVC,
        "cat /data/shared",
    );
    assert!(
        cross.contains(RWX_MARKER),
        "RWX volume did not cross nodes — {} could not read what {node} wrote: {cross}",
        second_node()
    );

    // ── load churn, then the fork ──
    deploy_churn(&kube);

    let src_bridge = cluster.bridge().to_string();
    let certs = cluster.certs_dir.clone();
    let before = snapshot_via_kubectl(&kube);
    let lh_before = longhorn_snapshot_via_kubectl(&kube);
    assert!(
        lh_before.keys().filter(|k| k.contains("longhorn-")).count() >= 3,
        "expected a restart-count entry per Longhorn pod: {lh_before:?}"
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
        "ublhf",
        &[None, None, None],
        &[None, None, None],
        &["ubuntu-lh-0", "ubuntu-lh-1", "ubuntu-lh-2"],
    )
    .expect("warm fork of the Ubuntu Longhorn cluster");
    let fork_latency = fork_start.elapsed();
    eprintln!(
        "MEASUREMENT ubuntu longhorn cluster warm fork (3 × {} MB / {} vCPU, \
         3 root + 3 data disks): {fork_latency:?} budget={FORK_UBUNTU_K3S_CLUSTER_3VM:?}",
        LONGHORN_NODE.memory_mb, LONGHORN_NODE.vcpus
    );
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
    assert_eq!(forks.len(), 3);

    // Each child's data disk is its **own** reflinked image: two live
    // ext4 mounts of one image is 24a-inc4a trap 3, and it would corrupt
    // both clusters' replicas.
    for (i, child) in forks.iter().enumerate() {
        let devices = child.block_devices();
        assert_eq!(
            devices.len(),
            2,
            "child-{i} should have a root disk and a data disk, got {devices:?}"
        );
        let child_data = devices[1].host_path.clone();
        assert_ne!(
            child_data, data_images[i],
            "child-{i} shares the source's data-disk image"
        );
        let shared: Vec<u64> = physical_extents(&data_images[i])
            .intersection(&physical_extents(&child_data))
            .copied()
            .collect();
        eprintln!(
            "child-{i} data disk {} shares {} extents with the source's {}",
            child_data.display(),
            shared.len(),
            data_images[i].display()
        );
        assert!(
            !shared.is_empty(),
            "child-{i}'s data disk shares no extents with the source's — it was copied, \
             not reflinked"
        );
    }

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
        let fstype = sh_ok(&mut ag, &format!("findmnt -no FSTYPE {LONGHORN_DATA_PATH}"));
        assert_eq!(
            fstype.trim(),
            "ext4",
            "child-{i}: {LONGHORN_DATA_PATH} is not mounted after the fork"
        );
    }

    // ── zero restarts, throughout the converge wait ──
    let start = Instant::now();
    loop {
        let src_pods = snapshot_via_bridge(&src_bridge, &certs)
            .unwrap_or_else(|e| panic!("source pods via {src_bridge}: {e}"));
        let child_pods = snapshot_via_bridge(&child_bridge, &certs)
            .unwrap_or_else(|e| panic!("child pods via {child_bridge}: {e}"));
        assert_no_restarts(&before, &src_pods, "source");
        assert_no_restarts(&before, &child_pods, "child");
        let src_lh = longhorn_snapshot_via_bridge(&src_bridge, &certs)
            .unwrap_or_else(|e| panic!("source longhorn pods via {src_bridge}: {e}"));
        let child_lh = longhorn_snapshot_via_bridge(&child_bridge, &certs)
            .unwrap_or_else(|e| panic!("child longhorn pods via {child_bridge}: {e}"));
        assert_no_restarts(&lh_before, &src_lh, "source-longhorn");
        assert_no_restarts(&lh_before, &child_lh, "child-longhorn");
        let src_ready = nodes_ready_via(&src_bridge, &certs, &names);
        let child_ready = nodes_ready_via(&child_bridge, &certs, &names);
        if src_ready && child_ready && start.elapsed() >= Duration::from_secs(5) {
            eprintln!(
                "fork: both clusters Ready, zero restarts across {:?}",
                start.elapsed()
            );
            break;
        }
        assert!(
            start.elapsed() <= CONVERGE,
            "fork: clusters did not converge Ready in {CONVERGE:?} \
             (src_ready={src_ready} child_ready={child_ready})"
        );
        std::thread::sleep(Duration::from_secs(2));
    }

    let ready = curl_get(&child_bridge, &certs, "/readyz").expect("child API via its own bridge");
    assert!(
        ready.contains("ok"),
        "child /readyz via {child_bridge} not ok: {ready}"
    );

    // ── the child sees the volumes; the source never sees a child write ──
    let child_pvcs = curl_get(
        &child_bridge,
        &certs,
        "/api/v1/namespaces/default/persistentvolumeclaims",
    )
    .expect("child PVCs");
    for pvc in [RWO_PVC, RWX_PVC] {
        assert!(
            child_pvcs.contains(pvc),
            "child cluster lost PVC {pvc}:\n{child_pvcs}"
        );
    }

    let child_read = run_probe_bridge(
        &child_bridge,
        &certs,
        "lh-child-rwo",
        &node,
        RWO_PVC,
        &format!("cat /data/marker; echo {CHILD_MARKER} > /data/child; sync"),
    );
    assert!(
        child_read.contains(RWO_MARKER),
        "the child's RWO volume lost the source's pre-fork marker: {child_read}"
    );

    let src_verify = run_probe_bridge(
        &src_bridge,
        &certs,
        "lh-src-verify",
        &node,
        RWO_PVC,
        "cat /data/marker; ls /data",
    );
    assert!(
        src_verify.contains(RWO_MARKER),
        "the source's RWO volume lost its own marker: {src_verify}"
    );
    assert!(
        !src_verify.contains("child"),
        "the child's write reached the source's volume — the data disks did not diverge: \
         {src_verify}"
    );
    assert!(
        !std::fs::read(&data_images[0])
            .map(|b| String::from_utf8_lossy(&b).contains(CHILD_MARKER))
            .unwrap_or(false),
        "the child's marker is in the source's data-disk image {}",
        data_images[0].display()
    );
    eprintln!("fork: Longhorn volumes diverge (child-only write {CHILD_MARKER})");

    for child in &mut forks {
        child.shutdown();
    }
    drop(fork_net);
}
