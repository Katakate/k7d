//! Cilium on Ubuntu bare-VM k3s, installed the documented way.
//!
//! Re-runs the inner-k3s probe set on the Ubuntu substrate: Helm talks
//! to the host kubeconfig, containerd pulls through the bridge, native
//! routing + kube-proxy replacement. None of the old workarounds
//! (static YAML, airgap tars, `imagePullPolicy: Never`, sidecar
//! memory, guest-kernel patches).
//!
//! Parameterises the cluster fixture with `k7d.cni=none`. Does not
//! touch the minimal guest, `test_inner_k3s.rs`, the shim, or any
//! existing budget.

mod common;

use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use k7d::api::AgentClient;
use k7d::fork::fork_cluster_warm;
use k7d::latency::FORK_UBUNTU_K3S_CLUSTER_3VM;
use k7d::vm::Vm;

use common::ubuntu::{
    connect_or_dump, failed_units, physical_extents, relax_guest_rp_filter, sh, sh_ok,
    NODE_MEMORY_MB,
};
use common::ubuntu_helm::{
    cilium_diagnostics, ensure_helm, ensure_host_pod_routes, helm_install_cilium, node_pod_cidrs,
    wait_cilium_ready, CILIUM_NS, NATIVE_CIDR,
};
use common::ubuntu_k3s::{
    assert_no_restarts, bring_up_cluster_ex, curl_api, curl_get, deploy_churn, kubectl,
    nodes_ready_via, pod_ip_via, pod_log_via, snapshot_via_bridge, snapshot_via_kubectl,
    wait_nodes_ready, wait_pod_phase_via, UbuntuCluster, UbuntuCni, CONVERGE, K3S_TOKEN,
    POD_CIDR_PREFIX, SERVICE_CIDR, SERVICE_CIDR_PREFIX,
};

const HTTP_PORT: u16 = 8080;
const SVC_NAME: &str = "cil-server";

/// Probe image pulled through the bridge. Not Never, not airgap.
const BUSYBOX: &str = "docker.io/library/busybox:1.36.1";

const CILIUM_READY: Duration = Duration::from_secs(600);

fn image_pull_elapsed(kubeconfig: &Path) -> Option<Duration> {
    let body = kubectl(
        kubeconfig,
        &["-n", CILIUM_NS, "get", "events", "-o", "json"],
    )
    .ok()?;
    let v: serde_json::Value = serde_json::from_str(&body).ok()?;
    let empty = Vec::new();
    let mut first_pulling: Option<String> = None;
    let mut last_pulled: Option<String> = None;
    for item in v["items"].as_array().unwrap_or(&empty) {
        let reason = item["reason"].as_str().unwrap_or("");
        let msg = item["message"].as_str().unwrap_or("");
        if !msg.contains("cilium") && !msg.contains("quay.io/cilium") {
            continue;
        }
        let ts = item["firstTimestamp"]
            .as_str()
            .or_else(|| item["eventTime"].as_str())
            .unwrap_or("");
        if ts.is_empty() {
            continue;
        }
        if reason == "Pulling" {
            if first_pulling.as_ref().is_none_or(|t| ts < t.as_str()) {
                first_pulling = Some(ts.to_string());
            }
        }
        if reason == "Pulled" {
            if last_pulled.as_ref().is_none_or(|t| ts > t.as_str()) {
                last_pulled = Some(ts.to_string());
            }
        }
    }
    let (a, b) = (first_pulling?, last_pulled?);
    let parse = |s: &str| -> Option<i64> {
        let out = Command::new("date")
            .args(["-u", "-d", s, "+%s"])
            .output()
            .ok()?;
        String::from_utf8_lossy(&out.stdout).trim().parse().ok()
    };
    let start = parse(&a)?;
    let end = parse(&b)?;
    Some(Duration::from_secs(end.saturating_sub(start) as u64))
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
    eprintln!(
        "k7d.cni=none: server config has flannel-backend none + \
         disable-kube-proxy + disable-network-policy"
    );
}

fn assert_no_flannel(cluster: &mut UbuntuCluster, kubeconfig: &Path) {
    let pods = kubectl(kubeconfig, &["get", "pods", "-A", "--no-headers"])
        .unwrap_or_else(|e| panic!("get pods: {e}"));
    for needle in ["flannel", "kube-proxy"] {
        assert!(
            !pods.lines().any(|l| l.contains(needle)),
            "flannel/kube-proxy still present with k7d.cni=none:\n{pods}"
        );
    }

    let vms: [(&mut Vm, &str); 3] = [
        (&mut cluster.server, "server"),
        (&mut cluster.agent1, "agent-1"),
        (&mut cluster.agent2, "agent-2"),
    ];
    for (vm, whose) in vms {
        let mut ag = connect_or_dump(vm, whose);
        let links = sh_ok(&mut ag, "ip -o link show");
        for dev in ["flannel.1", "flannel-v6.1", "cni0"] {
            assert!(
                !links.contains(dev),
                "{whose}: flannel device {dev} exists:\n{links}"
            );
        }
        assert!(
            links.contains("cilium_host") && links.contains("cilium_net"),
            "{whose}: Cilium host devices missing:\n{links}"
        );
        // Cilium's chart default is `/etc/cni/net.d`; k3s kubelet reads
        // `agent/etc/cni/net.d`. Accept either (and any `*cilium*.conflist`
        // name). Do not `ls /run/flannel` into the same string — the
        // "No such file" error contains the word flannel.
        let cilium = sh_ok(
            &mut ag,
            "find /var/lib/rancher/k3s/agent/etc/cni/net.d /etc/cni/net.d \
               -maxdepth 1 -name '*cilium*.conflist' 2>/dev/null || true",
        );
        assert!(
            cilium
                .lines()
                .any(|l| l.contains("cilium") && l.contains("conflist")),
            "{whose}: Cilium never wrote a conflist under the k3s or host CNI dir:\n{cilium}"
        );
        let flannel_files = sh_ok(
            &mut ag,
            "find /var/lib/rancher/k3s/agent/etc/cni/net.d /etc/cni/net.d \
               -maxdepth 1 -iname '*flannel*' 2>/dev/null || true",
        );
        assert!(
            flannel_files.trim().is_empty(),
            "{whose}: a flannel conflist is present:\n{flannel_files}"
        );
        let run_flannel = sh_ok(
            &mut ag,
            "if [ -e /run/flannel ]; then echo PRESENT; ls -la /run/flannel; else echo ABSENT; fi",
        );
        assert!(
            run_flannel.trim() == "ABSENT",
            "{whose}: /run/flannel still exists:\n{run_flannel}"
        );
    }
    eprintln!("no flannel/kube-proxy; Cilium conflist + cilium_host on every node");
}

fn cilium_agent_on(kubeconfig: &Path, node: &str) -> String {
    let name = kubectl(
        kubeconfig,
        &[
            "-n",
            CILIUM_NS,
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
    .unwrap_or_else(|e| panic!("cilium agent on {node}: {e}"));
    let name = name.trim().to_string();
    assert!(
        name.starts_with("cilium-"),
        "unexpected cilium agent on {node}: {name:?}"
    );
    name
}

fn assert_kube_proxy_replaced(cluster: &mut UbuntuCluster, kubeconfig: &Path) {
    let names = cluster.names();
    for node in &names {
        let agent = cilium_agent_on(kubeconfig, node);
        let status = kubectl(
            kubeconfig,
            &[
                "-n",
                CILIUM_NS,
                "exec",
                &agent,
                "-c",
                "cilium-agent",
                "--",
                "cilium-dbg",
                "status",
            ],
        )
        .unwrap_or_else(|e| panic!("{node}: cilium-dbg status: {e}"));
        let line = status
            .lines()
            .find(|l| l.to_lowercase().contains("kubeproxyreplacement"))
            .unwrap_or_else(|| panic!("{node}: no KubeProxyReplacement line:\n{status}"));
        assert!(
            line.contains("True") || line.contains("Strict"),
            "{node}: KubeProxyReplacement is not enabled: {line}"
        );
        eprintln!("  {node}: {}", line.trim());
    }

    let vms: [(&mut Vm, &str); 3] = [
        (&mut cluster.server, "server"),
        (&mut cluster.agent1, "agent-1"),
        (&mut cluster.agent2, "agent-2"),
    ];
    for (vm, whose) in vms {
        let mut ag = connect_or_dump(vm, whose);
        let chains = sh_ok(
            &mut ag,
            "for b in iptables-legacy-save iptables-nft-save; do \
               p=$(command -v $b) || { echo MISSING=$b; continue; }; \
               echo \"$b-svc=$($p 2>/dev/null | grep -c KUBE-SERVICES)\"; \
               echo \"$b-fw=$($p 2>/dev/null | grep -c KUBE-POD-FW)\"; \
             done",
        );
        for backend in ["iptables-legacy-save", "iptables-nft-save"] {
            assert!(
                chains.contains(&format!("{backend}-svc=0")),
                "{whose}: {backend} missing or lists KUBE-SERVICES — \
                 ClusterIP would not prove eBPF:\n{chains}"
            );
            assert!(
                chains.contains(&format!("{backend}-fw=0")),
                "{whose}: {backend} still has kube-router KUBE-POD-FW — \
                 k3s netpol must be disabled so Cilium owns NetworkPolicy:\n{chains}"
            );
        }
    }
    eprintln!("KubeProxyReplacement enabled; no KUBE-SERVICES on any node");
}

fn assert_direct_node_routes(cluster: &mut UbuntuCluster, cidrs: &[(String, String, String)]) {
    let mut agents: Vec<(AgentClient, String)> = Vec::new();
    for (vm, whose) in [
        (&mut cluster.server, "server"),
        (&mut cluster.agent1, "agent-1"),
        (&mut cluster.agent2, "agent-2"),
    ] {
        agents.push((connect_or_dump(vm, whose), whose.to_string()));
    }
    for (ag, whose) in &mut agents {
        let routes = sh_ok(ag, "ip route show");
        let own = cidrs
            .iter()
            .find(|(n, _, _)| {
                (whose == "server" && n.ends_with("10-200-0-2"))
                    || (whose == "agent-1" && n.ends_with("10-200-0-3"))
                    || (whose == "agent-2" && n.ends_with("10-200-0-4"))
            })
            .map(|(n, _, _)| n.as_str());
        for (other, cidr, via) in cidrs {
            if Some(other.as_str()) == own {
                continue;
            }
            let want = format!("{cidr} via {via}");
            assert!(
                routes.contains(&want),
                "{whose}: no direct route {want} — traffic would be masqueraded:\n{routes}"
            );
        }
        eprintln!("  {whose}: direct routes to every peer podCIDR present");
    }
}

fn apply_yaml(kubeconfig: &Path, name: &str, yaml: &str) {
    let path = format!("/tmp/k7d-ubuntu-cilium-{name}-{}.yaml", std::process::id());
    std::fs::write(&path, yaml).unwrap_or_else(|e| panic!("write {name}: {e}"));
    kubectl(kubeconfig, &["apply", "-f", &path]).unwrap_or_else(|e| panic!("apply {name}: {e}"));
    let _ = std::fs::remove_file(&path);
}

fn preadmit_live_dump(
    kube: &Path,
    cluster: &mut UbuntuCluster,
    probe_node: &str,
    server_node: &str,
    pod_url: &str,
) -> String {
    let mut out = String::new();
    for args in [
        vec!["get", "cep", "-A", "-o", "wide"],
        vec!["get", "ciliumidentities"],
        vec!["get", "ciliumnodes", "-o", "wide"],
        vec!["-n", CILIUM_NS, "get", "pods", "-o", "wide"],
    ] {
        let got = kubectl(kube, &args).unwrap_or_else(|e| e);
        out.push_str(&format!("--- kubectl {} ---\n{got}\n", args.join(" ")));
    }
    for node in [probe_node, server_node] {
        let sel = format!("spec.nodeName={node}");
        let agent = kubectl(
            kube,
            &[
                "-n",
                CILIUM_NS,
                "get",
                "pods",
                "-l",
                "k8s-app=cilium",
                "--field-selector",
                &sel,
                "-o",
                "jsonpath={.items[0].metadata.name}",
            ],
        )
        .unwrap_or_default();
        let name = agent.trim().to_string();
        if !name.starts_with("cilium-") {
            out.push_str(&format!("--- {node}: no cilium agent ---\n"));
            continue;
        }
        for extra in [
            vec!["cilium-dbg", "bpf", "ipcache", "list"],
            vec!["cilium-dbg", "status", "--brief"],
        ] {
            let mut args = vec![
                "-n",
                CILIUM_NS,
                "exec",
                name.as_str(),
                "-c",
                "cilium-agent",
                "--",
            ];
            args.extend(extra.iter().copied());
            let got = kubectl(kube, &args).unwrap_or_else(|e| e);
            out.push_str(&format!("--- {node} {} ---\n{got}\n", extra.join(" ")));
        }
    }
    for (vm, whose) in [
        (&mut cluster.agent1, "server-node"),
        (&mut cluster.agent2, "probe-node"),
    ] {
        let mut ag = connect_or_dump(vm, &format!("{whose}-preadmit"));
        let body = sh_ok(
            &mut ag,
            &format!(
                "echo '--- {whose} ---'; \
                 sysctl net.ipv4.ip_forward net.ipv4.conf.all.rp_filter; \
                 ip route show; \
                 iptables -L FORWARD -n -v | head -20; \
                 ethtool -k eth0 2>/dev/null | grep -E 'checksum|tcp-segmentation' || true; \
                 nstat -az TcpInErrs TcpInCsumErrors InCsumErrors 2>/dev/null || true; \
                 echo curl_again=$(curl -4 -sS --max-time 2 {pod_url} | head -c 40)"
            ),
        );
        out.push_str(&body);
        out.push('\n');
    }
    eprintln!("preadmit live dump:\n{out}");
    out
}

fn rest_create_pod(bridge: &str, certs: &Path, json: &str) {
    curl_api(
        bridge,
        certs,
        "POST",
        "/api/v1/namespaces/default/pods",
        Some(json),
    )
    .unwrap_or_else(|e| panic!("POST pod via {bridge}: {e}"));
}

fn rest_delete_pod(bridge: &str, certs: &Path, name: &str) {
    let _ = curl_api(
        bridge,
        certs,
        "DELETE",
        &format!("/api/v1/namespaces/default/pods/{name}"),
        None,
    );
}

fn allowed_probe_command(pod_url: &str, svc_url: &str, marker: &str) -> String {
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

fn denied_probe_command(pod_url: &str, svc_url: &str) -> String {
    format!(
        "i=0; while [ $i -lt 5 ]; do \
           if wget -q -T 3 -O - {pod_url}; then echo CIL_DENIED_LEAK_POD; exit 1; fi; \
           if wget -q -T 3 -O - {svc_url}; then echo CIL_DENIED_LEAK_SVC; exit 1; fi; \
           i=$((i+1)); sleep 3; done; \
         echo CIL_DENIED_OK"
    )
}

fn probe_pod_json(name: &str, node: &str, labels: &[(&str, &str)], cmd: &str) -> String {
    let mut label_map = serde_json::Map::new();
    for (k, v) in labels {
        label_map.insert((*k).into(), serde_json::Value::String((*v).into()));
    }
    serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "labels": label_map},
        "spec": {
            "nodeName": node,
            "restartPolicy": "Never",
            "containers": [{
                "name": "probe",
                "image": BUSYBOX,
                "imagePullPolicy": "IfNotPresent",
                "command": ["/bin/sh", "-c"],
                "args": [cmd]
            }]
        }
    })
    .to_string()
}

fn cep_via(bridge: &str, certs: &Path, name: &str) -> String {
    curl_get(
        bridge,
        certs,
        &format!("/apis/cilium.io/v2/namespaces/default/ciliumendpoints/{name}"),
    )
    .unwrap_or_else(|e| format!("cep get: {e}"))
}

fn dump_allow_state(
    kube: Option<&Path>,
    probe_node: &str,
    server_node: &str,
    client: &str,
    client_ip: &str,
    server_ip: &str,
) {
    let Some(kube) = kube else {
        return;
    };
    if let Ok(cep) = kubectl(kube, &["get", "cep", client, "-o", "wide"]) {
        eprintln!("allow-state cep {client}:\n{cep}");
    }
    for node in [probe_node, server_node] {
        let agent = match kubectl(
            kube,
            &[
                "-n",
                CILIUM_NS,
                "get",
                "pods",
                "-l",
                "k8s-app=cilium",
                "--field-selector",
                &format!("spec.nodeName={node}"),
                "-o",
                "jsonpath={.items[0].metadata.name}",
            ],
        ) {
            Ok(n) if n.trim().starts_with("cilium-") => n.trim().to_string(),
            other => {
                eprintln!("allow-state {node}: no agent ({other:?})");
                continue;
            }
        };
        for extra in [
            vec!["cilium-dbg", "bpf", "ipcache", "get", client_ip],
            vec!["cilium-dbg", "bpf", "ipcache", "get", server_ip],
        ] {
            let mut args = vec![
                "-n",
                CILIUM_NS,
                "exec",
                agent.as_str(),
                "-c",
                "cilium-agent",
                "--",
            ];
            args.extend(extra.iter().copied());
            let got = kubectl(kube, &args).unwrap_or_else(|e| e);
            eprintln!("allow-state {node} {}:\n{got}", extra.join(" "));
        }
    }
}

fn assert_datapath_via(
    kube: Option<&Path>,
    bridge: &str,
    certs: &Path,
    label: &str,
    probe_node: &str,
    server_node: &str,
    server_pod_ip: &str,
    pod_url: &str,
    svc_url: &str,
    marker: &str,
) {
    let allowed = format!("cil-allow-{label}");
    let denied = format!("cil-deny-{label}");

    rest_create_pod(
        bridge,
        certs,
        &probe_pod_json(
            &allowed,
            probe_node,
            &[("role", "cil-client")],
            &allowed_probe_command(pod_url, svc_url, marker),
        ),
    );
    let start = Instant::now();
    let mut dumped = false;
    loop {
        let cep = cep_via(bridge, certs, &allowed);
        let ip = pod_ip_via(bridge, certs, "default", &allowed).unwrap_or_default();
        if ip.starts_with(POD_CIDR_PREFIX) && !dumped {
            eprintln!(
                "allow-state {allowed}: ip={ip} elapsed={:?} cep={}",
                start.elapsed(),
                cep.chars().take(200).collect::<String>()
            );
            dump_allow_state(kube, probe_node, server_node, &allowed, &ip, server_pod_ip);
            dumped = true;
        }
        match curl_get(
            bridge,
            certs,
            &format!("/api/v1/namespaces/default/pods/{allowed}"),
        ) {
            Ok(body) => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                    match v["status"]["phase"].as_str().unwrap_or("") {
                        "Succeeded" => break,
                        "Failed" => {
                            if ip.starts_with(POD_CIDR_PREFIX) {
                                dump_allow_state(
                                    kube,
                                    probe_node,
                                    server_node,
                                    &allowed,
                                    &ip,
                                    server_pod_ip,
                                );
                            }
                            let log = pod_log_via(bridge, certs, "default", &allowed)
                                .unwrap_or_else(|e| format!("log: {e}"));
                            panic!(
                                "{label}: {allowed} Failed after {:?}\n{cep}\n--- log ---\n{log}",
                                start.elapsed()
                            );
                        }
                        _ => {}
                    }
                }
            }
            Err(e) => eprintln!("{allowed}: get: {e}"),
        }
        if start.elapsed() > Duration::from_secs(360) {
            let log = pod_log_via(bridge, certs, "default", &allowed)
                .unwrap_or_else(|e| format!("log: {e}"));
            panic!("{label}: {allowed} never Succeeded after 360s\n{cep}\n--- log ---\n{log}");
        }
        std::thread::sleep(Duration::from_secs(5));
    }
    let allowed_log = pod_log_via(bridge, certs, "default", &allowed)
        .unwrap_or_else(|e| panic!("{label}: allowed log: {e}"));
    assert!(
        allowed_log.contains("CIL_POD_OK"),
        "{label}: cross-node pod-to-pod by pod IP failed\n{allowed_log}"
    );
    assert!(
        allowed_log.contains("CIL_SVC_OK"),
        "{label}: ClusterIP VIP never answered — kube-proxy is off, so this is eBPF\n{allowed_log}"
    );
    assert!(
        allowed_log.contains("CIL_ALLOWED_OK"),
        "{label}: labelled client was not admitted\n{allowed_log}"
    );
    rest_delete_pod(bridge, certs, &allowed);

    rest_create_pod(
        bridge,
        certs,
        &probe_pod_json(
            &denied,
            probe_node,
            &[],
            &denied_probe_command(pod_url, svc_url),
        ),
    );
    wait_pod_phase_via(
        bridge,
        certs,
        "default",
        &denied,
        "Succeeded",
        Duration::from_secs(300),
    );
    let denied_log = pod_log_via(bridge, certs, "default", &denied)
        .unwrap_or_else(|e| panic!("{label}: denied log: {e}"));
    assert!(
        denied_log.contains("CIL_DENIED_OK") && !denied_log.contains("CIL_DENIED_LEAK"),
        "{label}: unlabelled pod reached the policied server\n{denied_log}"
    );
    rest_delete_pod(bridge, certs, &denied);
    eprintln!("  {label}: pod-to-pod + ClusterIP + policy proven via {bridge}");
}

fn assert_clusters_diverge(src_bridge: &str, child_bridge: &str, certs: &Path) {
    let src_cm = r#"{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"only-on-source"}}"#;
    curl_api(
        src_bridge,
        certs,
        "POST",
        "/api/v1/namespaces/default/configmaps",
        Some(src_cm),
    )
    .expect("create CM on source");
    let child_see = curl_get(
        child_bridge,
        certs,
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
        child_bridge,
        certs,
        "POST",
        "/api/v1/namespaces/default/configmaps",
        Some(child_cm),
    )
    .expect("create CM on child");
    let src_see = curl_get(
        src_bridge,
        certs,
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
}

/// Cilium 1.16.10 via Helm on the Ubuntu 3-node cluster, then the
/// full probe set across a warm fork.
#[test]
fn test_ubuntu_cilium_datapath_fork() {
    let _ = env_logger::builder().is_test(true).try_init();
    let boot_start = Instant::now();
    let mut cluster = bring_up_cluster_ex(UbuntuCni::None, "ubcil");
    assert_cni_none_on_server(&mut cluster);

    let kube = cluster.kubeconfig.clone();
    let names = cluster.names();
    let helm = ensure_helm();

    let install_start = Instant::now();
    helm_install_cilium(&helm, &kube, cluster.server_ip);
    let helm_apply = install_start.elapsed();
    eprintln!("MEASUREMENT cilium helm apply: {helm_apply:?}");

    let pull_wait = wait_cilium_ready(&kube, CILIUM_READY);
    let boot_to_cilium = boot_start.elapsed();
    eprintln!(
        "MEASUREMENT ubuntu cilium boot-to-Cilium-Ready: {boot_to_cilium:?} \
         (helm-apply {helm_apply:?} + image-pull/ready {pull_wait:?})"
    );
    if let Some(pull) = image_pull_elapsed(&kube) {
        eprintln!("MEASUREMENT ubuntu cilium image-pull (events Pulling→Pulled): {pull:?}");
    } else {
        eprintln!(
            "MEASUREMENT ubuntu cilium image-pull (wait after helm apply): {pull_wait:?} \
             (no Pulling/Pulled pair in events)"
        );
    }

    for (vm, whose) in [
        (&mut cluster.server, "server"),
        (&mut cluster.agent1, "agent-1"),
        (&mut cluster.agent2, "agent-2"),
    ] {
        let mut ag = connect_or_dump(vm, whose);
        relax_guest_rp_filter(&mut ag, &format!("{whose}-post-cilium"));
    }

    if let Ok(cfg) = kubectl(
        &kube,
        &[
            "-n",
            CILIUM_NS,
            "exec",
            "ds/cilium",
            "--",
            "cilium-dbg",
            "config",
            "get",
            "enable-host-legacy-routing",
        ],
    ) {
        eprintln!("MEASUREMENT cilium enable-host-legacy-routing={cfg}");
    } else {
        eprintln!("MEASUREMENT cilium enable-host-legacy-routing: exec failed");
    }

    wait_nodes_ready(&kube, &names, Duration::from_secs(180));
    let nodes = kubectl(&kube, &["get", "nodes", "--no-headers"]).expect("get nodes");
    assert_eq!(
        nodes.lines().filter(|l| l.contains("Ready")).count(),
        3,
        "three nodes Ready is a CNI assertion once flannel and kube-proxy are off:\n{nodes}"
    );

    let operator = kubectl(
        &kube,
        &[
            "-n",
            CILIUM_NS,
            "get",
            "deploy",
            "cilium-operator",
            "-o",
            "jsonpath={.status.availableReplicas}",
        ],
    )
    .unwrap_or_default();
    assert!(
        operator.trim() == "1" || operator.trim().parse::<u32>().unwrap_or(0) >= 1,
        "cilium-operator is not Available: {operator:?}\n{}",
        cilium_diagnostics(&kube)
    );

    assert_no_flannel(&mut cluster, &kube);
    assert_kube_proxy_replaced(&mut cluster, &kube);
    let cidrs = node_pod_cidrs(&kube);
    assert_direct_node_routes(&mut cluster, &cidrs);
    ensure_host_pod_routes(cluster.bridge(), &cidrs);
    let br = cluster.bridge();
    let out = std::process::Command::new("ip")
        .args(["-n", br, "-d", "link", "show", "dev", br])
        .output()
        .expect("ip -d link show");
    let link = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && link.contains("nf_call_iptables 0"),
        "{br} still calls iptables — bridged guest pod SYNs would hit netfilter:\n{link}"
    );

    let marker = format!("CIL_MARKER_{}", std::process::id());
    let server_node = UbuntuCluster::node_name(Ipv4Addr::new(10, 200, 0, 3));
    let probe_node = UbuntuCluster::node_name(Ipv4Addr::new(10, 200, 0, 4));
    apply_yaml(
        &kube,
        "cil-server",
        &format!(
            r#"apiVersion: v1
kind: Pod
metadata:
  name: {SVC_NAME}
  labels:
    app: cil-server
spec:
  nodeName: {server_node}
  restartPolicy: Always
  containers:
  - name: vol
    image: {BUSYBOX}
    imagePullPolicy: IfNotPresent
    command: ["/bin/sh", "-c"]
    args:
    - mkdir -p /www && echo {marker} > /www/index.html && exec httpd -f -p {HTTP_PORT} -h /www
"#
        ),
    );
    let start = Instant::now();
    loop {
        let phase = kubectl(
            &kube,
            &["get", "pod", SVC_NAME, "-o", "jsonpath={.status.phase}"],
        )
        .unwrap_or_default();
        if phase.trim() == "Running" {
            break;
        }
        if start.elapsed() > Duration::from_secs(180) {
            panic!("{SVC_NAME} never Running (busybox pull through the bridge): {phase}");
        }
        std::thread::sleep(Duration::from_secs(3));
    }
    let server_ip = {
        let start = Instant::now();
        loop {
            match kubectl(
                &kube,
                &["get", "pod", SVC_NAME, "-o", "jsonpath={.status.podIP}"],
            ) {
                Ok(ip) if ip.trim().starts_with(POD_CIDR_PREFIX) => break ip.trim().to_string(),
                Ok(ip) if start.elapsed() > Duration::from_secs(120) => {
                    panic!("{SVC_NAME} pod IP {ip:?} is not in {NATIVE_CIDR}")
                }
                Err(e) if start.elapsed() > Duration::from_secs(120) => {
                    panic!("{SVC_NAME} never got a pod IP: {e}")
                }
                _ => std::thread::sleep(Duration::from_secs(2)),
            }
        }
    };
    eprintln!("  {SVC_NAME} pod IP={server_ip} on {server_node}");

    apply_yaml(
        &kube,
        "cil-svc",
        &format!(
            r#"apiVersion: v1
kind: Service
metadata:
  name: {SVC_NAME}
spec:
  type: ClusterIP
  selector:
    app: cil-server
  ports:
  - port: {HTTP_PORT}
    targetPort: {HTTP_PORT}
"#
        ),
    );
    let svc_ip = kubectl(
        &kube,
        &["get", "svc", SVC_NAME, "-o", "jsonpath={.spec.clusterIP}"],
    )
    .expect("service clusterIP");
    let svc_ip = svc_ip.trim().to_string();
    assert!(
        svc_ip.starts_with(SERVICE_CIDR_PREFIX),
        "ClusterIP {svc_ip} is outside the service CIDR {SERVICE_CIDR}"
    );
    eprintln!("  {SVC_NAME} ClusterIP={svc_ip}");

    let pod_url_pre = format!("http://{server_ip}:{HTTP_PORT}/");
    let svc_url_pre = format!("http://{svc_ip}:{HTTP_PORT}/");
    // Before NetworkPolicy: host-ns curl of the server pod IP names
    // whether native routing works at all (bypasses the client pod).
    {
        let mut srv = connect_or_dump(&mut cluster.agent1, "srv-host");
        let local = sh(
            &mut srv,
            &format!("curl -4 -sS --max-time 5 {pod_url_pre} || echo LOCAL_CURL_FAIL"),
        );
        eprintln!(
            "MEASUREMENT server-node host-ns curl {pod_url_pre}: exit={} out={} err={}",
            local.0,
            local.1.trim(),
            local.2.trim()
        );
        let mut probe = connect_or_dump(&mut cluster.agent2, "probe-host");
        let remote = sh(
            &mut probe,
            &format!("curl -4 -sS --max-time 5 {pod_url_pre} || echo HOST_CURL_FAIL"),
        );
        eprintln!(
            "MEASUREMENT probe-node host-ns curl {pod_url_pre}: exit={} out={} err={}",
            remote.0,
            remote.1.trim(),
            remote.2.trim()
        );
        assert!(
            remote.1.contains(&marker),
            "probe-node host-ns cannot reach {pod_url_pre} before NetworkPolicy — \
             native routing is dead (not a cil-allow label issue)\n\
             local={:?}\nremote={:?}",
            (local.0, local.1, local.2),
            (remote.0, remote.1, remote.2)
        );
        let svc = sh(
            &mut probe,
            &format!("curl -4 -sS --max-time 5 {svc_url_pre} || echo HOST_SVC_FAIL"),
        );
        eprintln!(
            "MEASUREMENT probe-node host-ns curl {svc_url_pre}: exit={} out={} err={}",
            svc.0,
            svc.1.trim(),
            svc.2.trim()
        );
        assert!(
            svc.1.contains(&marker),
            "probe-node host-ns cannot reach ClusterIP {svc_url_pre} — \
             kube-proxy replacement or host {SERVICE_CIDR} route is dead\n\
             svc={:?}",
            (svc.0, svc.1, svc.2)
        );
    }

    // Unlabelled pod-to-pod before NetworkPolicy. Host-ns already works;
    // if this hangs, the black hole is Cilium's veth/BPF egress, not policy.
    let pre_bridge = cluster.bridge().to_string();
    let pre_certs = cluster.certs_dir.clone();
    let cap_path = format!("/tmp/k7d-preadmit-br-{}.txt", std::process::id());
    let cap_file = std::fs::File::create(&cap_path).expect("bridge tcpdump file");
    let mut cap = Command::new("timeout")
        .args([
            "25",
            "tcpdump",
            "-e",
            "-nn",
            "-l",
            "-i",
            &pre_bridge,
            "tcp",
            "port",
            &HTTP_PORT.to_string(),
        ])
        .stdout(std::process::Stdio::from(cap_file))
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("tcpdump on cluster bridge");
    rest_create_pod(
        &pre_bridge,
        &pre_certs,
        &probe_pod_json(
            "cil-preadmit",
            &probe_node,
            &[],
            &format!(
                "i=0; while [ $i -lt 8 ]; do \
                   if wget -q -T 2 -O - {pod_url_pre} | grep -q {marker}; then \
                     echo CIL_PREADMIT_OK; exit 0; fi; \
                   i=$((i+1)); sleep 1; done; echo CIL_PREADMIT_FAIL"
            ),
        ),
    );
    wait_pod_phase_via(
        &pre_bridge,
        &pre_certs,
        "default",
        "cil-preadmit",
        "Succeeded",
        Duration::from_secs(90),
    );
    let preadmit = pod_log_via(&pre_bridge, &pre_certs, "default", "cil-preadmit")
        .unwrap_or_else(|e| panic!("cil-preadmit log: {e}"));
    let _ = cap.kill();
    let br_cap = std::fs::read_to_string(&cap_path).unwrap_or_default();
    let _ = std::fs::remove_file(&cap_path);
    eprintln!("MEASUREMENT host bridge tcpdump tcp/{HTTP_PORT}:\n{br_cap}");
    rest_create_pod(
        &pre_bridge,
        &pre_certs,
        &probe_pod_json(
            "cil-preadmit-local",
            &server_node,
            &[],
            &format!(
                "wget -q -T 8 -O - {pod_url_pre} | grep -q {marker} \
                 && echo CIL_PREADMIT_LOCAL_OK || echo CIL_PREADMIT_LOCAL_FAIL"
            ),
        ),
    );
    wait_pod_phase_via(
        &pre_bridge,
        &pre_certs,
        "default",
        "cil-preadmit-local",
        "Succeeded",
        Duration::from_secs(90),
    );
    let preadmit_local = pod_log_via(&pre_bridge, &pre_certs, "default", "cil-preadmit-local")
        .unwrap_or_else(|e| panic!("cil-preadmit-local log: {e}"));
    rest_delete_pod(&pre_bridge, &pre_certs, "cil-preadmit-local");
    if !preadmit.contains("CIL_PREADMIT_OK") {
        let live = preadmit_live_dump(&kube, &mut cluster, &probe_node, &server_node, &pod_url_pre);
        panic!(
            "unlabelled pod-to-pod failed before NetworkPolicy — \
             Cilium BPF egress is the black hole, not policy\n\
             cross-node ({probe_node}): {preadmit}\n\
             same-node ({server_node}): {preadmit_local}\n\
             live dump:\n{live}\n\
             host bridge tcpdump tcp/{HTTP_PORT}:\n{br_cap}"
        );
    }
    rest_delete_pod(&pre_bridge, &pre_certs, "cil-preadmit");
    eprintln!("MEASUREMENT unlabelled pod-to-pod before NetworkPolicy: ok");

    apply_yaml(
        &kube,
        "cil-netpol",
        r#"apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-cil-client
spec:
  podSelector:
    matchLabels:
      app: cil-server
  ingress:
  - from:
    - podSelector:
        matchLabels:
          role: cil-client
  policyTypes: ["Ingress"]
"#,
    );

    deploy_churn(&kube);

    let src_bridge = cluster.bridge().to_string();
    let certs = cluster.certs_dir.clone();
    let pod_url = format!("http://{server_ip}:{HTTP_PORT}/");
    let svc_url = format!("http://{svc_ip}:{HTTP_PORT}/");
    assert_datapath_via(
        Some(&kube),
        &src_bridge,
        &certs,
        "pre",
        &probe_node,
        &server_node,
        &server_ip,
        &pod_url,
        &svc_url,
        &marker,
    );

    let before = snapshot_via_kubectl(&kube);
    assert!(
        before.keys().filter(|k| k.contains("/cilium-")).count() >= 3,
        "expected a restart-count entry per Cilium agent: {before:?}"
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
        "ubcilf",
        &[None, None, None],
        &[None, None, None],
        &["ubuntu-cil-0", "ubuntu-cil-1", "ubuntu-cil-2"],
    )
    .expect("warm fork of the Ubuntu Cilium cluster");
    let fork_latency = fork_start.elapsed();
    eprintln!(
        "MEASUREMENT ubuntu cilium cluster warm fork (3 × {NODE_MEMORY_MB} MB): {fork_latency:?} \
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
            "MEASUREMENT ubuntu cilium post-fork CoW (root disk extents shared): {}",
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
    let child_server_ip = {
        let start = Instant::now();
        loop {
            match pod_ip_via(&child_bridge, &certs, "default", SVC_NAME) {
                Ok(ip) if ip.starts_with(POD_CIDR_PREFIX) => break ip,
                other if start.elapsed() > Duration::from_secs(60) => {
                    panic!("child {SVC_NAME} pod IP: {other:?}")
                }
                _ => std::thread::sleep(Duration::from_secs(2)),
            }
        }
    };
    assert_eq!(
        child_server_ip, server_ip,
        "child inherited a different cil-server pod IP"
    );

    assert_datapath_via(
        Some(&kube),
        &src_bridge,
        &certs,
        "src",
        &probe_node,
        &server_node,
        &server_ip,
        &pod_url,
        &svc_url,
        &marker,
    );
    assert_datapath_via(
        None,
        &child_bridge,
        &certs,
        "child",
        &probe_node,
        &server_node,
        &server_ip,
        &pod_url,
        &svc_url,
        &marker,
    );

    assert_clusters_diverge(&src_bridge, &child_bridge, &certs);

    for child in &mut forks {
        child.shutdown();
    }
    drop(fork_net);
}
