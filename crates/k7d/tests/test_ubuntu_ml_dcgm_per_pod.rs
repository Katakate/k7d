//! Per-pod fake DCGM: one series per `fake-gpu-N`, labeled from the
//! kubelet pod-resources API.
//!
//! Two GPU pods on one node produce two labeled series. Deleting one
//! drops its labels. The scrape survives a warm fork.
//!
//! Mock only — not NVML, not the GPU Operator. Does not touch
//! `crates/k7d/src`.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{Duration, Instant};

use k7d::fork::fork_cluster_warm;
use k7d::latency::FORK_UBUNTU_K3S_CLUSTER_3VM;
use k7d::vm::Vm;

use common::ml_platform::{
    apply_gpu_dcgm_fixture, assert_dcgm_metrics, fixture, gpu_diagnostics, pod_resource_gpu_ids,
    scrape_dcgm, BUSYBOX, FIXTURE_READY, GPU_PER_NODE, MODEL_NAME, RESOURCE,
};
use common::ubuntu::{failed_units, NODE_MEMORY_MB};
use common::ubuntu_k3s::{
    apply_yaml, bring_up_cluster, kubectl, nodes_ready_via, pod_phase, CONVERGE,
};

const POD_A: &str = "dcgm-pod-a";
const POD_B: &str = "dcgm-pod-b";
const CONTAINER: &str = "busybox";
const DEFAULT_UTIL: &str = "42";
const DEFAULT_FB: &str = "1024";
const OVERRIDE_UTIL: &str = "77";

struct Sample {
    labels: BTreeMap<String, String>,
    value: String,
}

struct Dev<'a> {
    id: &'a str,
    pod: Option<&'a str>,
    util: &'a str,
}

fn parse_prom_labels(inner: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let b = inner.as_bytes();
    let mut i = 0;
    while i < b.len() {
        while i < b.len() && (b[i] == b',' || b[i] == b' ') {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        let key_start = i;
        while i < b.len() && b[i] != b'=' {
            i += 1;
        }
        let key = inner[key_start..i].to_string();
        assert!(
            i + 1 < b.len() && b[i] == b'=' && b[i + 1] == b'"',
            "label {key} in {inner}"
        );
        i += 2;
        let val_start = i;
        while i < b.len() && b[i] != b'"' {
            i += 1;
        }
        assert!(i < b.len(), "unterminated label {key} in {inner}");
        out.insert(key, inner[val_start..i].to_string());
        i += 1;
    }
    out
}

fn samples(body: &str, metric: &str) -> Vec<Sample> {
    let mut out = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        let Some(brace) = line.find('{') else {
            continue;
        };
        if &line[..brace] != metric {
            continue;
        }
        let Some(end) = line.rfind('}') else {
            continue;
        };
        out.push(Sample {
            labels: parse_prom_labels(&line[brace + 1..end]),
            value: line[end + 1..].trim().to_string(),
        });
    }
    out
}

fn series<'a>(samples: &'a [Sample], metric: &str, id: &str) -> Result<&'a Sample, String> {
    let hits: Vec<_> = samples
        .iter()
        .filter(|s| s.labels.get("gpu").map(String::as_str) == Some(id))
        .collect();
    if hits.len() != 1 {
        return Err(format!("{metric} series for {id}: found {}", hits.len()));
    }
    Ok(hits[0])
}

fn pod_label(s: &Sample) -> Result<Option<String>, String> {
    let pod = s.labels.get("pod").cloned();
    let ns = s.labels.get("namespace").cloned();
    let container = s.labels.get("container").cloned();
    match (pod, ns, container) {
        (None, None, None) => Ok(None),
        (Some(pod), Some(ns), Some(container)) => {
            if ns != "default" || container != CONTAINER {
                return Err(format!(
                    "pod={pod} namespace={ns} container={container}, want default/{CONTAINER}"
                ));
            }
            Ok(Some(pod))
        }
        _ => Err(format!(
            "partial pod labels on gpu={:?}: pod={:?} namespace={:?} container={:?}",
            s.labels.get("gpu"),
            s.labels.get("pod"),
            s.labels.get("namespace"),
            s.labels.get("container")
        )),
    }
}

fn devices_match(body: &str, node: &str, devs: &[Dev]) -> Result<(), String> {
    if !body.contains("DCGM_FI_DEV_GPU_UTIL") || !body.contains(MODEL_NAME) {
        return Err("scrape missing DCGM metric or model".into());
    }
    let util = samples(body, "DCGM_FI_DEV_GPU_UTIL");
    let fb = samples(body, "DCGM_FI_DEV_FB_USED");
    if util.len() != devs.len() || fb.len() != devs.len() {
        return Err(format!(
            "series count util={} fb={} want {}",
            util.len(),
            fb.len(),
            devs.len()
        ));
    }
    for d in devs {
        for (metric, rows, want) in [
            ("DCGM_FI_DEV_GPU_UTIL", &util, d.util),
            ("DCGM_FI_DEV_FB_USED", &fb, DEFAULT_FB),
        ] {
            let s = series(rows, metric, d.id)?;
            if s.labels.get("Hostname").map(String::as_str) != Some(node) {
                return Err(format!(
                    "{metric} {id} Hostname {:?} want {node}",
                    s.labels.get("Hostname"),
                    id = d.id
                ));
            }
            if s.labels.get("modelName").map(String::as_str) != Some(MODEL_NAME) {
                return Err(format!(
                    "{metric} {} model {:?}",
                    d.id,
                    s.labels.get("modelName")
                ));
            }
            if s.value != want {
                return Err(format!("{metric} {} value {} want {want}", d.id, s.value));
            }
            let got = pod_label(s)?;
            if got.as_deref() != d.pod {
                return Err(format!("{metric} {} pod {got:?} want {:?}", d.id, d.pod));
            }
        }
    }
    Ok(())
}

fn assert_devices(body: &str, whose: &str, node: &str, devs: &[Dev]) {
    assert_dcgm_metrics(body, whose);
    devices_match(body, node, devs).unwrap_or_else(|e| panic!("{whose}: {e}\n{body}"));
}

fn gpu_pod_yaml(name: &str, node: &str) -> String {
    format!(
        r#"apiVersion: v1
kind: Pod
metadata:
  name: {name}
  namespace: default
spec:
  restartPolicy: Always
  nodeName: {node}
  tolerations:
  - operator: Exists
  containers:
  - name: {CONTAINER}
    image: {BUSYBOX}
    imagePullPolicy: IfNotPresent
    command: ["sleep", "3600"]
    resources:
      limits:
        {RESOURCE}: "1"
"#
    )
}

fn wait_pod_running(kubeconfig: &Path, name: &str, ceiling: Duration) {
    let start = Instant::now();
    loop {
        let phase = pod_phase(kubeconfig, name);
        if phase == "Running" {
            eprintln!("ml-dcgm: {name} Running after {:?}", start.elapsed());
            return;
        }
        if start.elapsed() > ceiling {
            panic!(
                "{name} never Running after {ceiling:?} (phase={phase})\n{}",
                gpu_diagnostics(kubeconfig)
            );
        }
        eprintln!("ml-dcgm: {name} phase {phase}");
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn wait_metrics(
    bridge: &str,
    ip: Ipv4Addr,
    node: &str,
    devs: &[Dev],
    ceiling: Duration,
    whose: &str,
    kube: Option<&Path>,
) -> String {
    let start = Instant::now();
    let mut last: String;
    loop {
        match scrape_dcgm(bridge, ip) {
            Ok(body) => {
                if devices_match(&body, node, devs).is_ok() {
                    eprintln!(
                        "ml-dcgm: {whose} scrape matched after {:?}",
                        start.elapsed()
                    );
                    return body;
                }
                eprintln!("ml-dcgm: {whose} scrape not ready ({} B)", body.len());
                last = body;
            }
            Err(e) => {
                eprintln!("ml-dcgm: {whose} scrape error: {e}");
                last = e;
            }
        }
        if start.elapsed() > ceiling {
            let diag = kube.map(gpu_diagnostics).unwrap_or_default();
            panic!("{whose}: scrape never matched after {ceiling:?}\nlast:\n{last}\n{diag}");
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn assert_dcgm_fixture_contract() {
    let dcgm = std::fs::read_to_string(fixture("dcgm-exporter.yaml")).expect("dcgm yaml");
    assert!(
        dcgm.contains("kind: DaemonSet"),
        "dcgm fixture must be a DaemonSet"
    );
    assert!(
        dcgm.contains("externalTrafficPolicy: Local"),
        "node scrape must hit that node's exporter"
    );
    assert!(dcgm.contains("-render-dcgm"));
    assert!(dcgm.contains("FAKE_DCGM_GPU_UTIL") && dcgm.contains("value: \"42\""));
    assert!(dcgm.contains("FAKE_DCGM_FB_USED") && dcgm.contains("value: \"1024\""));
    assert!(dcgm.contains("FAKE_GPU_COUNT") && dcgm.contains("value: \"2\""));
    assert!(dcgm.contains("k7d.katakate.org/fake-dcgm-gpu-util"));
    assert!(dcgm.contains("k7d.katakate.org/fake-dcgm-fb-used"));
    assert!(dcgm.contains("DCGM_FI_DEV_GPU_UTIL") && dcgm.contains("DCGM_FI_DEV_FB_USED"));
    assert!(dcgm.contains("9400") && dcgm.contains(MODEL_NAME));
    assert!(dcgm.contains(BUSYBOX));
    let src = std::fs::read_to_string(fixture("fake-gpu-plugin/main.go")).expect("plugin");
    assert!(src.contains("-render-dcgm"));
    let dcgm_go = std::fs::read_to_string(fixture("fake-gpu-plugin/dcgm.go")).expect("dcgm.go");
    assert!(dcgm_go.contains("k7d.katakate.org/fake-dcgm-gpu-util"));
    assert_eq!(GPU_PER_NODE, 2, "default GPU_PER_NODE must stay 2");
}

#[test]
fn dcgm_parser_reads_labeled_and_unlabeled_series() {
    let body = r#"
# TYPE DCGM_FI_DEV_GPU_UTIL gauge
DCGM_FI_DEV_GPU_UTIL{gpu="fake-gpu-0",UUID="GPU-fake-0",device="nvidia0",modelName="Fake-A100",Hostname="k7d-10-200-0-2",namespace="default",pod="dcgm-pod-a",container="busybox"} 77
DCGM_FI_DEV_GPU_UTIL{gpu="fake-gpu-1",UUID="GPU-fake-1",device="nvidia1",modelName="Fake-A100",Hostname="k7d-10-200-0-2"} 42
# TYPE DCGM_FI_DEV_FB_USED gauge
DCGM_FI_DEV_FB_USED{gpu="fake-gpu-0",UUID="GPU-fake-0",device="nvidia0",modelName="Fake-A100",Hostname="k7d-10-200-0-2",namespace="default",pod="dcgm-pod-a",container="busybox"} 1024
DCGM_FI_DEV_FB_USED{gpu="fake-gpu-1",UUID="GPU-fake-1",device="nvidia1",modelName="Fake-A100",Hostname="k7d-10-200-0-2"} 1024
"#;
    let node = "k7d-10-200-0-2";
    let devs = [
        Dev {
            id: "fake-gpu-0",
            pod: Some(POD_A),
            util: OVERRIDE_UTIL,
        },
        Dev {
            id: "fake-gpu-1",
            pod: None,
            util: DEFAULT_UTIL,
        },
    ];
    assert_devices(body, "parser", node, &devs);
    let dropped = [
        Dev {
            id: "fake-gpu-0",
            pod: None,
            util: DEFAULT_UTIL,
        },
        Dev {
            id: "fake-gpu-1",
            pod: None,
            util: DEFAULT_UTIL,
        },
    ];
    assert!(devices_match(body, node, &dropped).is_err());
}

#[test]
fn dcgm_fixture_contract_documents_defaults() {
    assert_dcgm_fixture_contract();
}

fn gpu_id_for_pod(body: &str, pod: &str) -> String {
    let hits: Vec<_> = samples(body, "DCGM_FI_DEV_GPU_UTIL")
        .into_iter()
        .filter(|s| s.labels.get("pod").map(String::as_str) == Some(pod))
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "{pod} should own one GPU_UTIL series\n{body}"
    );
    hits[0]
        .labels
        .get("gpu")
        .cloned()
        .unwrap_or_else(|| panic!("{pod} series has no gpu label\n{body}"))
}

/// Two GPU pods, per-device labels, drop on delete, scrape survives fork.
#[test]
fn test_ubuntu_ml_dcgm_per_pod() {
    let _ = env_logger::builder().is_test(true).try_init();
    assert_dcgm_fixture_contract();

    let mut cluster = bring_up_cluster();
    apply_gpu_dcgm_fixture(&mut cluster);
    let kube = cluster.kubeconfig.clone();
    let names = cluster.names();
    let node = names[0].clone();
    let src_bridge = cluster.bridge().to_string();
    let server_ip = cluster.server_ip;

    for pod in [POD_A, POD_B] {
        apply_yaml(&kube, pod, &gpu_pod_yaml(pod, &node));
    }
    for pod in [POD_A, POD_B] {
        wait_pod_running(&kube, pod, FIXTURE_READY);
    }

    let body = wait_until_pods_labeled(
        &src_bridge,
        server_ip,
        &node,
        Duration::from_secs(90),
        &kube,
    );
    let id_a = gpu_id_for_pod(&body, POD_A);
    let id_b = gpu_id_for_pod(&body, POD_B);
    let got: BTreeSet<_> = [&id_a, &id_b].into_iter().cloned().collect();
    let want: BTreeSet<_> = ["fake-gpu-0", "fake-gpu-1"]
        .into_iter()
        .map(str::to_string)
        .collect();
    assert_eq!(got, want, "series ids {got:?} want {want:?}\n{body}");
    let pr_a = pod_resource_gpu_ids(&mut cluster, &kube, "default", POD_A);
    let pr_b = pod_resource_gpu_ids(&mut cluster, &kube, "default", POD_B);
    assert_eq!(pr_a, vec![id_a.clone()], "pod-resources {POD_A}");
    assert_eq!(pr_b, vec![id_b.clone()], "pod-resources {POD_B}");
    assert_devices(
        &body,
        "both-default",
        &node,
        &[
            Dev {
                id: &id_a,
                pod: Some(POD_A),
                util: DEFAULT_UTIL,
            },
            Dev {
                id: &id_b,
                pod: Some(POD_B),
                util: DEFAULT_UTIL,
            },
        ],
    );

    kubectl(
        &kube,
        &[
            "annotate",
            "pod",
            POD_A,
            &format!("k7d.katakate.org/fake-dcgm-gpu-util={OVERRIDE_UTIL}"),
            "--overwrite",
        ],
    )
    .unwrap_or_else(|e| panic!("annotate {POD_A}: {e}\n{}", gpu_diagnostics(&kube)));
    let overridden = wait_metrics(
        &src_bridge,
        server_ip,
        &node,
        &[
            Dev {
                id: &id_a,
                pod: Some(POD_A),
                util: OVERRIDE_UTIL,
            },
            Dev {
                id: &id_b,
                pod: Some(POD_B),
                util: DEFAULT_UTIL,
            },
        ],
        Duration::from_secs(60),
        "annotated",
        Some(&kube),
    );
    assert_devices(
        &overridden,
        "annotated",
        &node,
        &[
            Dev {
                id: &id_a,
                pod: Some(POD_A),
                util: OVERRIDE_UTIL,
            },
            Dev {
                id: &id_b,
                pod: Some(POD_B),
                util: DEFAULT_UTIL,
            },
        ],
    );

    kubectl(
        &kube,
        &["delete", "pod", POD_A, "--wait=true", "--timeout=90s"],
    )
    .unwrap_or_else(|e| panic!("delete {POD_A}: {e}\n{}", gpu_diagnostics(&kube)));
    let after_delete = [
        Dev {
            id: &id_a,
            pod: None,
            util: DEFAULT_UTIL,
        },
        Dev {
            id: &id_b,
            pod: Some(POD_B),
            util: DEFAULT_UTIL,
        },
    ];
    let dropped = wait_metrics(
        &src_bridge,
        server_ip,
        &node,
        &after_delete,
        Duration::from_secs(90),
        "after-delete",
        Some(&kube),
    );
    assert_devices(&dropped, "after-delete", &node, &after_delete);
    assert!(
        !samples(&dropped, "DCGM_FI_DEV_GPU_UTIL").iter().any(|s| s
            .labels
            .get("pod")
            .map(String::as_str)
            == Some(POD_A)),
        "{POD_A} labels still present\n{dropped}"
    );

    let certs = cluster.certs_dir.clone();
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
    let mut sources: Vec<(&mut Vm, u32)> = vec![
        (&mut cluster.server, 0),
        (&mut cluster.agent1, 1),
        (&mut cluster.agent2, 2),
    ];
    let fork_start = Instant::now();
    let (fork_net, mut forks) = fork_cluster_warm(
        &cluster.net,
        &mut sources,
        "udcgm",
        &[None, None, None],
        &[None, None, None],
        &["ubuntu-dcgm-0", "ubuntu-dcgm-1", "ubuntu-dcgm-2"],
    )
    .expect("warm fork of the per-pod DCGM cluster");
    let fork_latency = fork_start.elapsed();
    eprintln!(
        "MEASUREMENT ubuntu dcgm-per-pod cluster warm fork (3 × {NODE_MEMORY_MB} MB): {fork_latency:?} \
         target=1s budget={FORK_UBUNTU_K3S_CLUSTER_3VM:?}"
    );
    assert!(
        fork_latency < FORK_UBUNTU_K3S_CLUSTER_3VM,
        "cluster fork {fork_latency:?} over {FORK_UBUNTU_K3S_CLUSTER_3VM:?} — \
         do not widen FORK_UBUNTU_K3S_CLUSTER_3VM"
    );
    let child_bridge = fork_net.bridge_name().to_string();
    assert_eq!(forks.len(), 3, "fork must clone every member");

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

    let start = Instant::now();
    loop {
        let src_ready = nodes_ready_via(&src_bridge, &certs, &names);
        let child_ready = nodes_ready_via(&child_bridge, &certs, &names);
        let src = scrape_dcgm(&src_bridge, server_ip);
        let child = scrape_dcgm(&child_bridge, server_ip);
        let scrapes_ok = src
            .as_ref()
            .ok()
            .is_some_and(|b| devices_match(b, &node, &after_delete).is_ok())
            && child
                .as_ref()
                .ok()
                .is_some_and(|b| devices_match(b, &node, &after_delete).is_ok());
        if src_ready && child_ready && scrapes_ok {
            let src = src.expect("src scrape");
            let child = child.expect("child scrape");
            assert_devices(&src, "source-after-fork", &node, &after_delete);
            assert_devices(&child, "child", &node, &after_delete);
            eprintln!(
                "ml-dcgm: source and child scrapes kept {POD_B} on {id_b} and dropped {POD_A} after {:?}",
                start.elapsed()
            );
            break;
        }
        if start.elapsed() > CONVERGE {
            panic!(
                "fork: scrape did not survive in {CONVERGE:?} \
                 (src_ready={src_ready} child_ready={child_ready} \
                 src={src:?} child={child:?})"
            );
        }
        std::thread::sleep(Duration::from_secs(2));
    }

    for child in &mut forks {
        child.shutdown();
    }
    drop(fork_net);
}

fn wait_until_pods_labeled(
    bridge: &str,
    ip: Ipv4Addr,
    node: &str,
    ceiling: Duration,
    kube: &Path,
) -> String {
    let start = Instant::now();
    let mut last: String;
    loop {
        match scrape_dcgm(bridge, ip) {
            Ok(body) => {
                let util = samples(&body, "DCGM_FI_DEV_GPU_UTIL");
                let pods: BTreeSet<_> = util
                    .iter()
                    .filter_map(|s| s.labels.get("pod").cloned())
                    .collect();
                let hostname_ok = util.iter().all(|s| {
                    s.labels.get("Hostname").map(String::as_str) == Some(node)
                        && s.value == DEFAULT_UTIL
                });
                if util.len() == GPU_PER_NODE as usize
                    && pods.contains(POD_A)
                    && pods.contains(POD_B)
                    && hostname_ok
                {
                    eprintln!("ml-dcgm: both pods labeled after {:?}", start.elapsed());
                    return body;
                }
                last = body;
                eprintln!(
                    "ml-dcgm: waiting for both pod labels (series={} pods={pods:?})",
                    util.len()
                );
            }
            Err(e) => {
                last = e;
                eprintln!("ml-dcgm: scrape while waiting for labels: {last}");
            }
        }
        if start.elapsed() > ceiling {
            panic!(
                "both pods never labeled after {ceiling:?}\nlast:\n{last}\n{}",
                gpu_diagnostics(kube)
            );
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}
