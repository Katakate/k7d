//! Soft-RoCE (`rdma_rxe`) on an Ubuntu flannel cluster, then
//! a warm fork.
//!
//! Verbs device only — not NCCL, not GPUDirect, not CUDA. A real NCCL
//! job would set `NCCL_SOCKET_IFNAME=eth0` `NCCL_IB_HCA=<rxe device>`
//! `NCCL_IB_DISABLE=0`; this test does **not** run NCCL and does not
//! prove those env vars. Reuses `bring_up_cluster` (Flannel) and
//! `FORK_UBUNTU_K3S_CLUSTER_3VM`. Does not touch `crates/k7d/src`.

mod common;

use std::time::{Duration, Instant};

use k7d::api::AgentClient;
use k7d::fork::fork_cluster_warm;
use k7d::latency::FORK_UBUNTU_K3S_CLUSTER_3VM;
use k7d::vm::Vm;

use common::ubuntu::{failed_units, sh, sh_ok, NODE_MEMORY_MB};
use common::ubuntu_k3s::{bring_up_cluster, nodes_ready_via, wait_nodes_ready, CONVERGE};

/// A real NCCL job would wire Soft-RoCE with these. We document them
/// and do not run NCCL.
const NCCL_SOCKET_IFNAME: &str = "eth0";
const NCCL_IB_DISABLE: &str = "0";

fn connect(vm: &Vm, whose: &str) -> AgentClient {
    vm.connect_agent(Duration::from_secs(90))
        .unwrap_or_else(|e| panic!("{whose} agent: {e}"))
}

fn probe_rxe_userspace(ag: &mut AgentClient, whose: &str) {
    let (find_code, found, find_err) = sh(ag, "find /lib/modules -name 'rdma_rxe.ko*' -print");
    assert_eq!(find_code, 0, "{whose}: find rdma_rxe.ko failed\n{find_err}");
    assert!(
        !found.trim().is_empty(),
        "{whose}: rdma_rxe.ko missing from linux-image-extra-virtual — \
         write CHALLENGES and stop; do not patch guest/kernel/config-minimal. \
         find stdout empty"
    );
    let info = sh_ok(ag, "modinfo rdma_rxe");
    assert!(
        info.contains("rdma_rxe") || info.contains("Soft RDMA") || info.contains("filename:"),
        "{whose}: modinfo rdma_rxe did not describe the module:\n{info}"
    );
    let rdma = sh_ok(ag, "command -v rdma");
    assert!(
        rdma.contains("rdma"),
        "{whose}: `rdma` missing (iproute2 should ship it): {rdma}"
    );
    let (ibv_code, ibv, ibv_err) = sh(ag, "command -v ibv_devinfo");
    assert_eq!(
        ibv_code, 0,
        "{whose}: ibv_devinfo missing — Ubuntu ships it in ibverbs-utils \
         (rdma-core source package; binary package rdma-core is udev only). \
         Add ibverbs-utils to APT_PACKAGES (CHALLENGES #150).\n{ibv_err}"
    );
    assert!(
        ibv.contains("ibv_devinfo"),
        "{whose}: command -v ibv_devinfo: {ibv}"
    );
}

fn create_rxe0(ag: &mut AgentClient, whose: &str) -> String {
    sh_ok(ag, "modprobe rdma_rxe");
    let existing = sh_ok(ag, "rdma link show || true");
    if !link_has(&existing, "rxe0") {
        let (code, out, err) = sh(ag, "rdma link add rxe0 type rxe netdev eth0");
        assert_eq!(
            code, 0,
            "{whose}: `rdma link add rxe0 type rxe netdev eth0` failed \
             (syntax may have changed — fail loud, do not guess).\n\
             stdout: {out}\nstderr: {err}\nexisting:\n{existing}"
        );
    }
    wait_rxe_device(ag, whose, "rxe0")
}

fn wait_rxe_device(ag: &mut AgentClient, whose: &str, name: &str) -> String {
    let start = Instant::now();
    loop {
        let link = sh_ok(ag, "rdma link show || true");
        let (code, info, err) = sh(ag, "ibv_devinfo");
        if link_has(&link, name) && code == 0 && hca_names(&info).iter().any(|h| h == name) {
            eprintln!("{whose}: rdma link +\n{link}\nibv_devinfo hca={name}\n{info}");
            return info;
        }
        if start.elapsed() > Duration::from_secs(20) {
            panic!(
                "{whose}: {name} not visible to rdma link / ibv_devinfo after {:?}\n\
                 rdma link:\n{link}\nibv_devinfo exit={code}\n{info}\n{err}",
                start.elapsed()
            );
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn link_has(rdma_link: &str, name: &str) -> bool {
    rdma_link
        .split_whitespace()
        .any(|tok| tok == name || tok.starts_with(&format!("{name}/")))
}

fn hca_names(ibv: &str) -> Vec<String> {
    ibv.lines()
        .filter_map(|l| {
            let t = l.trim();
            let rest = t.strip_prefix("hca_id:")?;
            let name = rest.trim();
            if name.is_empty() {
                None
            } else {
                Some(name.to_string())
            }
        })
        .collect()
}

fn assert_no_link(rdma_link: &str, name: &str, whose: &str) {
    assert!(
        !link_has(rdma_link, name),
        "{whose}: rdma link must not show {name}:\n{rdma_link}"
    );
}

fn add_child_only_rxe1(ag: &mut AgentClient, whose: &str) {
    sh_ok(
        ag,
        "modprobe dummy && ip link add dummy0 type dummy && ip link set dummy0 up",
    );
    let (code, out, err) = sh(ag, "rdma link add rxe1 type rxe netdev dummy0");
    assert_eq!(
        code, 0,
        "{whose}: child-only `rdma link add rxe1 type rxe netdev dummy0` failed\n\
         stdout: {out}\nstderr: {err}"
    );
    wait_rxe_device(ag, whose, "rxe1");
}

/// 3-node Ubuntu k3s + Soft-RoCE on eth0, then warm-fork and diverge.
#[test]
fn test_ubuntu_ml_rdma_soft_roce_fork() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut cluster = bring_up_cluster();
    let names = cluster.names();

    let mut src_info = Vec::new();
    for (vm, whose) in [
        (&mut cluster.server, "server"),
        (&mut cluster.agent1, "agent-1"),
    ] {
        let mut ag = connect(vm, whose);
        probe_rxe_userspace(&mut ag, whose);
        let info = create_rxe0(&mut ag, whose);
        let hcas = hca_names(&info);
        assert!(
            hcas.iter().any(|h| h == "rxe0"),
            "{whose}: ibv_devinfo must list hca_id rxe0, got {hcas:?}\n{info}"
        );
        src_info.push(info);
        drop(ag);
    }
    let hca = "rxe0";
    eprintln!(
        "ml-rdma: NCCL wiring (documented, not run): \
         NCCL_SOCKET_IFNAME={NCCL_SOCKET_IFNAME} NCCL_IB_HCA={hca} \
         NCCL_IB_DISABLE={NCCL_IB_DISABLE} — this test does not run NCCL"
    );
    assert_eq!(src_info.len(), 2, "rxe0 on server + one agent");

    wait_nodes_ready(&cluster.kubeconfig, &names, Duration::from_secs(120));

    // The rest of this lab — k3s convergence, the warm fork,
    // the rxe1 divergence — runs under a realistic Whitelist policy,
    // proving the jail posture is usable for a multi-node RDMA lab, not
    // just restrictive. Intra-tree traffic (k3s control plane, RoCEv2
    // between the nodes) is exempt by design; the allow set names
    // UDP/TCP 4791 toward the guest subnet as an ML lab whitelist
    // would, plus the gateway resolver.
    let whitelist = k7d::netjail::EgressPolicy {
        mode: k7d::netjail::EgressMode::Whitelist,
        allow: vec![k7d::netjail::CidrPort {
            cidr: "10.200.0.0/24".to_string(),
            port: 4791,
        }],
        allow_dns: Some("10.200.0.1".parse().expect("gateway ip")),
    };
    cluster
        .net
        .set_egress(whitelist.clone())
        .expect("flip source tree to Whitelist");
    assert!(
        nodes_ready_via(cluster.bridge(), &cluster.certs_dir, &names),
        "cluster must stay Ready under the Whitelist egress policy"
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
        "ubrxe",
        &[None, None, None],
        &[None, None, None],
        &["ubuntu-rxe-0", "ubuntu-rxe-1", "ubuntu-rxe-2"],
    )
    .expect("warm fork of the Ubuntu Soft-RoCE cluster");
    let fork_latency = fork_start.elapsed();
    eprintln!(
        "MEASUREMENT ubuntu ml-rdma cluster warm fork (3 × {NODE_MEMORY_MB} MB): {fork_latency:?} \
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

    // A contained tree must not mint an Open child — the fork inherits
    // the source's Whitelist posture.
    assert_eq!(
        fork_net.egress(),
        &whitelist,
        "warm fork must inherit the source tree's egress policy"
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
        let mut ag = connect(child, &format!("child-{i}"));
        let child_failed = failed_units(&mut ag, &format!("child-{i}"));
        let newly: Vec<_> = child_failed.difference(&cluster.source_failed[i]).collect();
        assert!(
            newly.is_empty(),
            "child-{i}: units failed that were fine on the source: {newly:?}"
        );
        if i < 2 {
            wait_rxe_device(&mut ag, &format!("child-{i}"), "rxe0");
        }
    }

    let certs = cluster.certs_dir.clone();
    let src_bridge = cluster.bridge().to_string();
    let start = Instant::now();
    loop {
        let src_ready = nodes_ready_via(&src_bridge, &certs, &names);
        let child_ready = nodes_ready_via(&child_bridge, &certs, &names);
        if src_ready && child_ready && start.elapsed() >= Duration::from_secs(5) {
            eprintln!("fork: both clusters Ready across {:?}", start.elapsed());
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

    {
        let mut child0 = connect(&forks[0], "child-0");
        add_child_only_rxe1(&mut child0, "child-0");
        let child_link = sh_ok(&mut child0, "rdma link show");
        assert!(
            link_has(&child_link, "rxe0") && link_has(&child_link, "rxe1"),
            "child-0 should show rxe0 + child-only rxe1:\n{child_link}"
        );
    }

    let mut src_server = connect(&cluster.server, "source-server-after-fork");
    let src_link = sh_ok(&mut src_server, "rdma link show");
    assert!(
        link_has(&src_link, "rxe0"),
        "source server lost rxe0 after fork:\n{src_link}"
    );
    assert_no_link(&src_link, "rxe1", "source-server");
    let src_ibv = sh_ok(&mut src_server, "ibv_devinfo");
    let src_hcas = hca_names(&src_ibv);
    assert!(
        src_hcas.iter().any(|h| h == "rxe0"),
        "source ibv_devinfo lost rxe0: {src_hcas:?}\n{src_ibv}"
    );
    assert!(
        !src_hcas.iter().any(|h| h == "rxe1"),
        "source must not see child-only rxe1: {src_hcas:?}\n{src_ibv}"
    );
    eprintln!("fork: source rdma link still rxe0 only; child-only rxe1 is invisible on source");

    for child in &mut forks {
        child.shutdown();
    }
    drop(fork_net);
}
