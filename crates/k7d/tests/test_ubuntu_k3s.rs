//! 3-node k3s on Ubuntu bare-VM nodes, then a warm fork of the running
//! cluster .
//!
//! This is the inner-k3s matrix on a substrate where the nodes are
//! ordinary Linux machines: one image, role from `k7d.k3s=` on the
//! cmdline, k3s' own packaged containerd, kubectl from the host over
//! the bridge. The sidecar-era workarounds (airgap tars for *workloads*,
//! hand-rendered YAML, `kubectl create token`, hostPath-instead-of-
//! ConfigMap) are the thing under test — they must not be needed.
//!
//! Does not touch the minimal guest, `test_inner_k3s.rs`, the shim, or
//! any existing budget.

mod common;

use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

use k7d::fork::fork_cluster_warm;
use k7d::latency::FORK_UBUNTU_K3S_CLUSTER_3VM;
use k7d::vm::Vm;

use common::ubuntu::{
    connect_or_dump, failed_units, host_mem_available_kb, physical_extents, sh, sh_ok, NodeImage,
    NODE_MEMORY_MB,
};
use common::ubuntu_k3s::{
    assert_no_restarts, bring_up_cluster, curl_api, curl_get, deploy_churn, kubectl,
    nodes_ready_via, snapshot_via_bridge, snapshot_via_kubectl, wait_nodes_ready, UbuntuCluster,
    CONVERGE, K3S_TOKEN,
};

/// Image pulled by containerd through the bridge. Not in the k3s airgap
/// (`rancher/mirrored-*` only) — that is the #89 assertion.
const PULL_IMAGE: &str = "docker.io/library/alpine:3.20.3";

const HOSTPATH_DIR: &str = "/var/lib/k7d-delivery";
const HOSTPATH_MARKER: &str = "k7d-ubuntu-hostpath-ok";
const CONFIGMAP_VALUE: &str = "k7d-ubuntu-configmap-ok";

fn manifest_str(image: &NodeImage, key: &str) -> String {
    image
        .manifest
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("manifest missing string {key}"))
        .to_string()
}

fn assert_image_records_offline_k3s(image: &NodeImage) {
    assert_eq!(manifest_str(image, "k3s_version"), "v1.32.5+k3s1");
    assert_eq!(
        manifest_str(image, "k3s_sha256"),
        "9624ef0534b1be432b4ce8dd94dcd7241ed02451d970a4d38943baccf5c60dce",
        "k3s binary digest drifted from the pin"
    );
    assert_eq!(
        manifest_str(image, "k3s_airgap_sha256"),
        "ac1f278f1b006851d95cd3236e9b909264872e9f6b5ffcf90d28198c6f2e913c",
        "k3s airgap digest drifted from the pin"
    );
    let disabled = image
        .manifest
        .get("k3s_units_disabled")
        .and_then(|v| v.as_array())
        .expect("manifest k3s_units_disabled");
    assert!(
        disabled.iter().any(|u| u.as_str() == Some("k3s.service"))
            && disabled
                .iter()
                .any(|u| u.as_str() == Some("k3s-agent.service")),
        "units are not recorded disabled: {disabled:?}"
    );
}

fn record_image_size(image: &NodeImage) {
    let path = image.base_image();
    let meta = std::fs::metadata(&path).expect("stat base image");
    let logical = meta.len();
    let on_disk = meta.blocks().saturating_mul(512);
    let used_kb = image
        .manifest
        .get("rootfs_used_kb")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    eprintln!(
        "MEASUREMENT ubuntu node image: logical {logical} B, on-disk {on_disk} B, \
         rootfs_used_kb {used_kb}"
    );
}

fn assert_role_from_cmdline(cluster: &mut UbuntuCluster) {
    let mut sag = connect_or_dump(&mut cluster.server, "server");
    let enabled_s = sh(&mut sag, "systemctl is-enabled k3s.service || true").1;
    let enabled_a = sh(&mut sag, "systemctl is-enabled k3s-agent.service || true").1;
    assert!(
        enabled_s.trim() == "disabled" || enabled_s.trim() == "static",
        "k3s.service must ship disabled, got {:?}",
        enabled_s.trim()
    );
    assert!(
        enabled_a.trim() == "disabled" || enabled_a.trim() == "static",
        "k3s-agent.service must ship disabled, got {:?}",
        enabled_a.trim()
    );
    assert_eq!(
        sh_ok(&mut sag, "systemctl is-active k3s.service").trim(),
        "active"
    );
    let cmd = sh_ok(&mut sag, "cat /proc/cmdline");
    assert!(
        cmd.contains(&format!(
            "k7d.k3s=server,{},{}",
            cluster.server_ip, K3S_TOKEN
        )),
        "server cmdline missing k7d.k3s= role: {cmd}"
    );
    assert!(
        !cmd.contains("k7d.cni="),
        "inc2 must leave k7d.cni= off the cmdline (absent == flannel): {cmd}"
    );
    let cfg = sh_ok(&mut sag, "cat /etc/rancher/k3s/config.yaml");
    assert!(
        !cfg.contains("flannel-backend: none")
            && !cfg.contains("disable-kube-proxy: true")
            && !cfg.contains("disable-network-policy: true"),
        "inc2 server config must not disable flannel/kube-proxy:\n{cfg}"
    );
    assert!(
        sh_ok(&mut sag, "test -x /usr/local/bin/k3s && echo ok").contains("ok"),
        "k3s binary missing"
    );
    assert!(
        sh_ok(
            &mut sag,
            "test -f /var/lib/rancher/k3s/agent/images/k3s-airgap-images-amd64.tar.zst && echo ok"
        )
        .contains("ok"),
        "airgap tarball missing from the image"
    );

    let server_ip = cluster.server_ip;
    for (i, vm) in [&mut cluster.agent1, &mut cluster.agent2]
        .into_iter()
        .enumerate()
    {
        let mut ag = connect_or_dump(vm, &format!("agent-{}", i + 1));
        assert_eq!(
            sh_ok(&mut ag, "systemctl is-active k3s-agent.service").trim(),
            "active",
            "agent-{} k3s-agent",
            i + 1
        );
        let acmd = sh_ok(&mut ag, "cat /proc/cmdline");
        assert!(
            acmd.contains(&format!("k7d.k3s=agent,{server_ip},{K3S_TOKEN}")),
            "agent-{} cmdline missing k7d.k3s=: {acmd}",
            i + 1
        );
    }
}

fn assert_deliveries(cluster: &mut UbuntuCluster) {
    let kube = cluster.kubeconfig.clone();
    let server_name = UbuntuCluster::node_name(cluster.server_ip);

    // hostPath file on the server node's own filesystem — not a sidecar ns.
    let mut sag = connect_or_dump(&mut cluster.server, "server-hp");
    sh_ok(
        &mut sag,
        &format!("mkdir -p {HOSTPATH_DIR} && echo {HOSTPATH_MARKER} > {HOSTPATH_DIR}/marker"),
    );
    let images_before = sh_ok(&mut sag, "k3s crictl images || k3s ctr -n k8s.io images ls");
    assert!(
        !images_before.contains("library/alpine"),
        "alpine was already in the node image — the pull would not prove #89:\n{images_before}"
    );
    let airgap_list = sh_ok(&mut sag, "cat /usr/local/share/k7d/k3s-images.txt");
    assert!(
        !airgap_list.contains("library/alpine"),
        "alpine is in the airgap list; pick another pull image"
    );

    let yaml = format!(
        r#"apiVersion: v1
kind: ConfigMap
metadata:
  name: delivery-cm
data:
  message: {CONFIGMAP_VALUE}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: delivery
spec:
  replicas: 1
  selector:
    matchLabels:
      app: delivery
  template:
    metadata:
      labels:
        app: delivery
    spec:
      nodeName: {server_name}
      containers:
      - name: box
        image: {PULL_IMAGE}
        imagePullPolicy: Always
        command: ["sleep", "3600"]
        volumeMounts:
        - name: cm
          mountPath: /cfg
        - name: hp
          mountPath: /hostpath
        - name: sa
          mountPath: /var/run/secrets/kubernetes.io/serviceaccount
      volumes:
      - name: cm
        configMap:
          name: delivery-cm
      - name: hp
        hostPath:
          path: {HOSTPATH_DIR}
          type: Directory
      - name: sa
        projected:
          sources:
          - serviceAccountToken:
              path: token
              expirationSeconds: 3600
          - configMap:
              name: kube-root-ca.crt
              items:
              - key: ca.crt
                path: ca.crt
          - downwardAPI:
              items:
              - path: namespace
                fieldRef:
                  fieldPath: metadata.namespace
"#
    );
    let path = format!("/tmp/k7d-ubuntu-delivery-{}.yaml", std::process::id());
    std::fs::write(&path, yaml).expect("write delivery manifest");
    kubectl(&kube, &["apply", "-f", &path]).expect("apply delivery");
    kubectl(
        &kube,
        &["rollout", "status", "deploy/delivery", "--timeout=180s"],
    )
    .unwrap_or_else(|e| panic!("delivery rollout (image pull through the bridge): {e}"));

    let pod = kubectl(
        &kube,
        &[
            "get",
            "pod",
            "-l",
            "app=delivery",
            "-o",
            "jsonpath={.items[0].metadata.name}",
        ],
    )
    .expect("delivery pod name");
    let pod = pod.trim().to_string();
    assert!(!pod.is_empty(), "delivery pod has no name");

    // CHALLENGES #87 / #91: ConfigMap is a first-class volume, not a
    // hostPath stand-in rendered by the test.
    let cm =
        kubectl(&kube, &["exec", &pod, "--", "cat", "/cfg/message"]).expect("exec cat ConfigMap");
    assert_eq!(
        cm.trim(),
        CONFIGMAP_VALUE,
        "CHALLENGES #87/#91: ConfigMap mount is empty or wrong (sidecar-era hole)"
    );
    eprintln!("CHALLENGES #87/#91 retired: ConfigMap mounted as a ConfigMap, value visible");

    // CHALLENGES #88: projected ServiceAccount token is a real projected
    // volume — no `kubectl create token`, no automount:false.
    let token = kubectl(
        &kube,
        &[
            "exec",
            &pod,
            "--",
            "cat",
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
        ],
    )
    .expect("exec cat SA token");
    assert!(
        token.trim().starts_with("eyJ") && token.trim().matches('.').count() >= 2,
        "CHALLENGES #88: projected SA token is empty or not a JWT (sidecar-era hole): {:?}",
        token.trim()
    );
    eprintln!("CHALLENGES #88 retired: projected ServiceAccount token is a JWT");

    // CHALLENGES #91: hostPath resolves on the node's own filesystem.
    let hp = kubectl(&kube, &["exec", &pod, "--", "cat", "/hostpath/marker"])
        .expect("exec cat hostPath");
    assert_eq!(
        hp.trim(),
        HOSTPATH_MARKER,
        "CHALLENGES #91: hostPath did not resolve on the node filesystem"
    );
    eprintln!("CHALLENGES #91 retired: hostPath is the node's path, not a sidecar mount ns");

    // CHALLENGES #89: containerd pulled the image through the bridge.
    let images_after = sh_ok(&mut sag, "k3s crictl images || k3s ctr -n k8s.io images ls");
    assert!(
        images_after.contains("alpine"),
        "CHALLENGES #89: alpine never appeared in containerd after Always pull:\n{images_after}"
    );
    let events = kubectl(
        &kube,
        &[
            "get",
            "events",
            "--field-selector",
            &format!("involvedObject.name={pod}"),
            "-o",
            "json",
        ],
    )
    .unwrap_or_default();
    assert!(
        events.contains("Pulled") || images_after.contains("alpine"),
        "CHALLENGES #89: no PullImage evidence (would mean the image was side-loaded)"
    );
    eprintln!("CHALLENGES #89 retired: alpine pulled by containerd through the bridge, not airgap-imported");
    let _ = std::fs::remove_file(&path);
}

/// 3-node cluster + the deliveries the sidecar model broke.
#[test]
fn test_ubuntu_k3s_three_node_cluster_deliveries() {
    let _ = env_logger::builder().is_test(true).try_init();
    let mut cluster = bring_up_cluster();
    assert_image_records_offline_k3s(&cluster.image);
    record_image_size(&cluster.image);
    assert_role_from_cmdline(&mut cluster);

    let nodes = kubectl(&cluster.kubeconfig, &["get", "nodes", "--no-headers"])
        .expect("plain kubectl over the bridge");
    assert_eq!(
        nodes.lines().filter(|l| l.contains("Ready")).count(),
        3,
        "plain kubectl did not see 3 Ready nodes:\n{nodes}"
    );

    assert_deliveries(&mut cluster);
    eprintln!(
        "MEASUREMENT ubuntu k3s boot-to-cluster-Ready (test): {:?} ; \
         host RAM {before} → {after} KiB ({per} KiB/node)",
        cluster.boot_to_ready,
        before = cluster.mem_before_kb,
        after = cluster.mem_after_kb,
        per = cluster.mem_before_kb.saturating_sub(cluster.mem_after_kb) / 3
    );
}

/// Warm-fork the running 3-node cluster under the inner-k3s load churn.
#[test]
fn test_ubuntu_k3s_cluster_warm_fork_no_restart() {
    let _ = env_logger::builder().is_test(true).try_init();
    let mut cluster = bring_up_cluster();
    deploy_churn(&cluster.kubeconfig);

    let names = cluster.names();
    wait_nodes_ready(&cluster.kubeconfig, &names, Duration::from_secs(120));
    let before = snapshot_via_kubectl(&cluster.kubeconfig);
    assert!(
        !before.is_empty(),
        "no long-lived pods to watch across the fork"
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
        "ubk3sf",
        &[None, None, None],
        &[None, None, None],
        &["ubuntu-k3s-0", "ubuntu-k3s-1", "ubuntu-k3s-2"],
    )
    .expect("warm fork of the Ubuntu k3s cluster");
    let fork_latency = fork_start.elapsed();
    eprintln!(
        "MEASUREMENT ubuntu k3s cluster warm fork (3 × {NODE_MEMORY_MB} MB): {fork_latency:?} \
         target=1s budget={FORK_UBUNTU_K3S_CLUSTER_3VM:?}"
    );
    if fork_latency >= Duration::from_secs(1) {
        eprintln!(
            "FINDING the referenced work: cluster fork {fork_latency:?} missed the sub-second target"
        );
    }
    assert!(
        fork_latency < FORK_UBUNTU_K3S_CLUSTER_3VM,
        "cluster fork {fork_latency:?} over {FORK_UBUNTU_K3S_CLUSTER_3VM:?}"
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

    // Shared extents on the server's root disk: CoW, not a copy.
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
            "MEASUREMENT ubuntu k3s post-fork CoW (root disk extents shared): {}",
            shared.len()
        );
        assert!(
            !shared.is_empty(),
            "child root disk shares no extents with the source"
        );
    }

    let certs = cluster.certs_dir.clone();
    let src_bridge = cluster.bridge().to_string();
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

    let ready =
        curl_get(&child_bridge, &certs, "/readyz").expect("child API server via its own bridge");
    assert!(
        ready.contains("ok"),
        "child /readyz via {child_bridge} not ok: {ready}"
    );

    // The two clusters diverge.
    let src_cm = r#"{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"only-on-source"}}"#;
    curl_api(
        &src_bridge,
        &certs,
        "POST",
        "/api/v1/namespaces/default/configmaps",
        Some(src_cm),
    )
    .expect("create CM on source");
    let child_see = curl_get(
        &child_bridge,
        &certs,
        "/api/v1/namespaces/default/configmaps/only-on-source",
    );
    assert!(
        child_see
            .as_ref()
            .map(|b| b.contains("NotFound") || b.contains("not found"))
            .unwrap_or(true)
            || child_see
                .as_ref()
                .err()
                .map(|e| e.contains("404") || e.contains("NotFound"))
                .unwrap_or(false),
        "source write was visible on the child: {child_see:?}"
    );
    let child_cm = r#"{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"only-on-child"}}"#;
    curl_api(
        &child_bridge,
        &certs,
        "POST",
        "/api/v1/namespaces/default/configmaps",
        Some(child_cm),
    )
    .expect("create CM on child");
    let src_see = curl_get(
        &src_bridge,
        &certs,
        "/api/v1/namespaces/default/configmaps/only-on-child",
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
        "child write was visible on the source: {src_see:?}"
    );
    eprintln!("fork: clusters diverge (source-only and child-only ConfigMaps)");

    let mem_after_fork = host_mem_available_kb();
    eprintln!(
        "MEASUREMENT ubuntu k3s host MemAvailable after fork: {mem_after_fork} KiB \
         (cluster was {} KiB)",
        cluster.mem_after_kb
    );

    for child in &mut forks {
        child.shutdown();
    }
    drop(fork_net);
}
