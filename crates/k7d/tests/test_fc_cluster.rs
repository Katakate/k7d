//! Firecracker cluster fork, suspend/resume, auto-evict, and pool.
//!
//! In-flight intra-cluster frames at the pause-skew boundary can be
//! lost — unlike native lockstep. The TCP test asserts bytes recover,
//! not that no frame is dropped.
//!
//! DaemonGuard TreeDrops every tree (and StopVms leftover create_vm
//! guests) before killing the daemon: a jailed VMM is not the daemon's
//! child (CHALLENGES #223).

mod common;

use std::io::{BufRead, BufReader, Write};
use std::net::Ipv4Addr;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use k7d::api::AgentClient;
use k7d::control::{Client, Request, Response, VmConfig};
use k7d::guest::{AgentEndpoint, Backend};
use k7d::tree::{NodeState, TreeBudget};

const GUEST_MB: u64 = 256;
const CHILD_READY: Duration = Duration::from_secs(10);
const SKEW_RUNS: usize = 20;
/// Loud regression bound on pause skew p99 (spec: escalate if > 10 ms
/// for a reason that needs Firecracker source; 50 ms is "the pause
/// is not parallel").
const SKEW_P99_CEILING: Duration = Duration::from_millis(50);

fn workspace_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join(relative)
}

fn guest_ip(vm_index: u32) -> Ipv4Addr {
    Ipv4Addr::new(
        10,
        200,
        0,
        2 + u8::try_from(vm_index).expect("vm_index fits octet"),
    )
}

/// Drops trees through the API, then remaining create_vm guests, then
/// kills the daemon (CHALLENGES #223).
struct DaemonGuard {
    child: Child,
    socket: PathBuf,
    sandbox_root: PathBuf,
    tree_root: PathBuf,
    trees: std::cell::RefCell<Vec<String>>,
    vms: std::cell::RefCell<Vec<String>>,
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        for tree_id in self.trees.borrow().iter() {
            if let Ok(mut client) = Client::connect(&self.socket.to_string_lossy()) {
                let _ = client.call(&Request::TreeDrop {
                    tree_id: tree_id.clone(),
                });
            }
        }
        for vm_id in self.vms.borrow().iter() {
            if let Ok(mut client) = Client::connect(&self.socket.to_string_lossy()) {
                let _ = client.call(&Request::StopVm {
                    vm_id: vm_id.clone(),
                });
            }
        }
        // SIGTERM so the daemon's serve loop exits and `shutdown_all`
        // drops the warm pool (template + idle). SIGKILL leaked
        // jailed pool VMs (CHALLENGES #223, #226).
        let pid = self.child.id();
        let _ = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                _ => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break;
                }
            }
        }
        // Let KVM reclaim slots after jailer teardown before `test_fork`.
        std::thread::sleep(Duration::from_millis(500));
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_dir_all(&self.sandbox_root);
        let _ = std::fs::remove_dir_all(&self.tree_root);
    }
}

fn spawn_daemon(tag: &str, envs: &[(&str, &str)]) -> DaemonGuard {
    common::ensure_firecracker_installed();
    let pid = std::process::id();
    let socket = std::env::temp_dir().join(format!("k7d-fcc-{tag}-{pid}.sock"));
    let sandbox_root = std::env::temp_dir().join(format!("k7d-fcc-sandboxes-{tag}-{pid}"));
    let tree_root = std::env::temp_dir().join(format!("k7d-fcc-trees-{tag}-{pid}"));
    let _ = std::fs::remove_file(&socket);

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_k7d"));
    cmd.arg("--socket")
        .arg(&socket)
        .env("RUST_LOG", "info")
        .env("K7D_KERNEL", workspace_path("guest/kernel/vmlinux"))
        .env(
            "K7D_INITRD",
            workspace_path("guest/rootfs/initramfs.cpio.gz"),
        )
        .env("K7D_SANDBOX_ROOT", &sandbox_root)
        .env("K7D_TREE_ROOT", &tree_root);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let child = cmd.spawn().expect("spawn k7d daemon");
    let guard = DaemonGuard {
        child,
        socket,
        sandbox_root,
        tree_root,
        trees: std::cell::RefCell::new(Vec::new()),
        vms: std::cell::RefCell::new(Vec::new()),
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while !guard.socket.exists() {
        assert!(Instant::now() < deadline, "daemon socket never appeared");
        std::thread::sleep(Duration::from_millis(50));
    }
    guard
}

fn call(guard: &DaemonGuard, req: &Request) -> Response {
    let mut client = Client::connect(guard.socket.to_str().expect("utf8 socket path"))
        .expect("connect control socket");
    client.call(req).expect("control-plane call")
}

fn cluster_budget(max_live_vms: usize) -> TreeBudget {
    TreeBudget {
        max_live_vms,
        max_live_ram_bytes: u64::MAX,
        max_disk_bytes: u64::MAX,
        max_chain_depth: 1,
    }
}

fn fc_config() -> VmConfig {
    VmConfig {
        memory_mb: GUEST_MB,
        vcpus: 1,
        backend: Backend::Firecracker,
        ..VmConfig::default()
    }
}

fn create_cluster(
    guard: &DaemonGuard,
    tag: &str,
    vm_count: u32,
    max_live_vms: usize,
) -> (String, Vec<AgentEndpoint>) {
    match call(
        guard,
        &Request::TreeCreateCluster {
            ksm: false,
            vm_count,
            config: fc_config(),
            budget: Some(cluster_budget(max_live_vms)),
            tree_id: Some(common::unique_name(&format!("fcc-{tag}"))),
            egress: None,
            dilation_policy: None,
            dilation_config: None,
        },
    ) {
        Response::TreeCreated {
            tree_id,
            guest_cids,
            agent_endpoints,
            ..
        } => {
            assert!(
                guest_cids.is_empty(),
                "Firecracker cluster has no AF_VSOCK CIDs, got {guest_cids:?}"
            );
            assert_eq!(
                agent_endpoints.len(),
                vm_count as usize,
                "{agent_endpoints:?}"
            );
            guard.trees.borrow_mut().push(tree_id.clone());
            (tree_id, agent_endpoints)
        }
        other => panic!("tree_create_cluster firecracker: {other:?}"),
    }
}

fn agent(ep: &AgentEndpoint, timeout: Duration) -> AgentClient {
    AgentClient::connect_endpoint(ep, timeout)
        .unwrap_or_else(|e| panic!("connect agent at {ep:?}: {e}"))
}

fn sh(a: &mut AgentClient, cmd: &str) -> String {
    let out = a
        .exec(&["sh", "-c", cmd])
        .unwrap_or_else(|e| panic!("exec {cmd:?}: {e}"));
    assert_eq!(
        out.exit_code, 0,
        "{cmd:?} failed: {}{}",
        out.stdout, out.stderr
    );
    out.stdout
}

fn present(a: &mut AgentClient, path: &str) -> bool {
    let out = a
        .exec(&[
            "sh",
            "-c",
            &format!("test -e {path} && echo yes || echo no"),
        ])
        .unwrap_or_else(|e| panic!("exec test -e {path}: {e}"));
    out.stdout.trim() == "yes"
}

fn configure_eth0(a: &mut AgentClient, ip: Ipv4Addr) {
    let r = a
        .exec(&[
            "ifconfig",
            "eth0",
            &ip.to_string(),
            "netmask",
            "255.255.255.0",
            "up",
        ])
        .expect("ifconfig eth0");
    assert_eq!(r.exit_code, 0, "ifconfig eth0 failed: {}", r.stderr);
}

fn configure_members(eps: &[AgentEndpoint]) {
    for (i, ep) in eps.iter().enumerate() {
        let mut a = agent(ep, Duration::from_secs(10));
        configure_eth0(&mut a, guest_ip(u32::try_from(i).unwrap()));
    }
}

fn ping_ok(a: &mut AgentClient, ip: Ipv4Addr) -> bool {
    let r = a
        .exec(&["ping", "-c", "1", "-W", "2", &ip.to_string()])
        .expect("ping");
    r.exit_code == 0
}

fn wait_ping(a: &mut AgentClient, ip: Ipv4Addr) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if ping_ok(a, ip) {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("ping {ip} never succeeded");
}

fn fork_batch(
    guard: &DaemonGuard,
    tree_id: &str,
    source: &str,
    labels: &[&str],
) -> (Vec<(String, Vec<AgentEndpoint>)>, u64, Option<u64>) {
    match call(
        guard,
        &Request::TreeForkBatch {
            tree_id: tree_id.to_string(),
            source_id: source.to_string(),
            labels: labels.iter().map(ToString::to_string).collect(),
            dilation: None,
            dilation_policy: None,
            dilation_config: None,
        },
    ) {
        Response::TreeForkBatch {
            forks,
            latency_ns,
            pause_skew_ns,
        } => {
            assert_eq!(forks.len(), labels.len());
            let out = forks
                .into_iter()
                .map(|f| {
                    assert!(
                        f.fork_memory_full_copy.iter().all(|c| !c),
                        "{}: memory reported as a full copy",
                        f.node_id
                    );
                    (f.node_id, f.agent_endpoints)
                })
                .collect();
            (out, latency_ns, pause_skew_ns)
        }
        other => panic!("tree_fork_batch: {other:?}"),
    }
}

fn prune(guard: &DaemonGuard, tree_id: &str, node_id: &str) {
    assert!(matches!(
        call(
            guard,
            &Request::TreePrune {
                tree_id: tree_id.to_string(),
                node_id: node_id.to_string(),
            },
        ),
        Response::Ok
    ));
}

fn vm_dir_of(ep: &AgentEndpoint) -> PathBuf {
    let AgentEndpoint::FcUds { path } = ep else {
        panic!("not a Firecracker endpoint: {ep:?}");
    };
    Path::new(path)
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .expect("v.sock lives at <vm_dir>/root/run/v.sock")
        .to_path_buf()
}

fn firecracker_pid(vm_dir: &Path) -> u32 {
    let root = vm_dir.join("root");
    let pid_file = std::fs::read_dir(&root)
        .unwrap_or_else(|e| panic!("read {}: {e}", root.display()))
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|x| x == "pid"))
        .unwrap_or_else(|| panic!("no jailer pid file in {}", root.display()));
    std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

fn private_dirty(pid: u32) -> Option<u64> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/smaps_rollup")).ok()?;
    text.lines()
        .find_map(|l| l.strip_prefix("Private_Dirty:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|kb| kb.parse::<u64>().ok())
        .map(|kb| kb * 1024)
}

fn node_state(guard: &DaemonGuard, tree_id: &str, node_id: &str) -> NodeState {
    match call(
        guard,
        &Request::TreeNodes {
            tree_id: tree_id.to_string(),
        },
    ) {
        Response::TreeNodeList { nodes, .. } => {
            nodes
                .into_iter()
                .find(|n| n.id == node_id)
                .unwrap_or_else(|| panic!("no node {node_id}"))
                .state
        }
        other => panic!("tree_nodes: {other:?}"),
    }
}

fn tcp_oneshot(
    server: &mut AgentClient,
    client: &mut AgentClient,
    server_ip: Ipv4Addr,
    port: u16,
    marker: &str,
) {
    let listen =
        format!("nc -l -p {port} </dev/null > /tmp/oneshot-{port} 2>/dev/null & echo LISTENING");
    server.exec(&["sh", "-c", &listen]).expect("oneshot listen");
    std::thread::sleep(Duration::from_millis(300));
    let send = format!("echo {marker} | nc -w 5 {server_ip} {port}");
    let sent = client.exec(&["sh", "-c", &send]).expect("oneshot send");
    assert_eq!(
        sent.exit_code, 0,
        "oneshot TCP failed: stdout={} stderr={}",
        sent.stdout, sent.stderr
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let got = server
            .exec(&["cat", &format!("/tmp/oneshot-{port}")])
            .expect("oneshot cat");
        if got.stdout.contains(marker) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "oneshot TCP did not deliver {marker:?}; got {:?}",
            got.stdout
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn watch_snapshot_skew(guard: &DaemonGuard, tree_id: &str) -> Option<u64> {
    let mut watch = UnixStream::connect(&guard.socket).expect("watch connect");
    let req = serde_json::json!({"op": "tree_watch", "tree_id": tree_id});
    watch
        .write_all(format!("{req}\n").as_bytes())
        .and_then(|()| watch.flush())
        .expect("write tree_watch");
    let mut reader = BufReader::new(watch);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read TreeWatching");
    match serde_json::from_str::<Response>(line.trim()).expect("parse TreeWatching") {
        Response::TreeWatching { trees } => trees.into_iter().next().and_then(|t| t.pause_skew_ns),
        other => panic!("expected TreeWatching, got {other:?}"),
    }
}

/// 3-member FC cluster: child members ping each other; source
/// unaffected; pause_skew_ns on the fork result and tree_watch; p99
/// over 20 runs under the ceiling.
#[test]
fn test_fc_cluster_fork_ping_and_skew_p99() {
    let guard = spawn_daemon("fork", &[]);
    let (tree_id, root_eps) = create_cluster(&guard, "fork", 3, 12);
    configure_members(&root_eps);

    let mut skews: Vec<u64> = Vec::with_capacity(SKEW_RUNS);
    let mut last_child: Option<(String, Vec<AgentEndpoint>)> = None;
    for i in 0..SKEW_RUNS {
        let (forks, latency_ns, pause_skew_ns) =
            fork_batch(&guard, &tree_id, "root", &[&format!("c{i}")]);
        let skew = pause_skew_ns.expect("FC cluster fork must record pause_skew_ns");
        println!(
            "FC-LATENCY cluster fork n=1 3-member: latency={latency_ns}ns pause_skew={skew}ns"
        );
        skews.push(skew);
        let (id, eps) = forks.into_iter().next().unwrap();
        if let Some((prev, _)) = last_child.take() {
            prune(&guard, &tree_id, &prev);
        }
        last_child = Some((id, eps));
    }
    let last_run_skew = *skews.last().expect("ran at least one fork");
    skews.sort_unstable();
    let p50 = skews[SKEW_RUNS / 2];
    let p99 = skews[SKEW_RUNS - 1];
    println!("FC-LATENCY cluster pause_skew p50={p50}ns p99={p99}ns over {SKEW_RUNS} runs");
    assert!(
        Duration::from_nanos(p99) < SKEW_P99_CEILING,
        "pause_skew p99 {p99} ns exceeds {:?}",
        SKEW_P99_CEILING
    );

    let watch_skew = watch_snapshot_skew(&guard, &tree_id);
    assert_eq!(
        watch_skew,
        Some(last_run_skew),
        "tree_watch snapshot must carry the last pause_skew_ns"
    );

    let (child_id, child_eps) = last_child.expect("last child");
    assert_eq!(child_eps.len(), 3);
    let mut c0 = agent(&child_eps[0], CHILD_READY);
    wait_ping(&mut c0, guest_ip(1));
    wait_ping(&mut c0, guest_ip(2));
    let mut c1 = agent(&child_eps[1], CHILD_READY);
    wait_ping(&mut c1, guest_ip(0));

    // Source still pings on its own bridge (same IPs, isolated L2).
    let mut s0 = agent(&root_eps[0], Duration::from_secs(10));
    wait_ping(&mut s0, guest_ip(1));
    sh(&mut s0, "echo src-alive > /tmp/src-alive");
    assert!(
        !present(&mut c0, "/tmp/src-alive"),
        "child sees a source memory write after the fork"
    );
    let _ = child_id;
}

/// Dual-child isolation at cluster level (busybox).
#[test]
fn test_fc_cluster_dual_child_isolation() {
    let guard = spawn_daemon("iso", &[]);
    let (tree_id, root_eps) = create_cluster(&guard, "iso", 3, 12);
    configure_members(&root_eps);
    let mut root0 = agent(&root_eps[0], Duration::from_secs(10));
    sh(&mut root0, "echo src-only > /tmp/src-mark");

    let (forks, _, skew) = fork_batch(&guard, &tree_id, "root", &["alice", "bob"]);
    assert!(skew.is_some(), "dual-child fork must record pause_skew_ns");
    assert_eq!(forks.len(), 2);
    let (alice_id, alice_eps) = &forks[0];
    let (bob_id, bob_eps) = &forks[1];
    assert_ne!(alice_id, bob_id);

    let mut alice = agent(&alice_eps[0], CHILD_READY);
    let mut bob = agent(&bob_eps[0], CHILD_READY);
    sh(&mut alice, "echo alice-only > /tmp/alice-mark");
    sh(&mut bob, "echo bob-only > /tmp/bob-mark");

    assert!(present(&mut alice, "/tmp/alice-mark"));
    assert!(!present(&mut alice, "/tmp/bob-mark"));
    assert!(
        present(&mut alice, "/tmp/src-mark"),
        "alice lost the pre-fork source mark"
    );
    assert!(present(&mut bob, "/tmp/src-mark"));
    assert!(!present(&mut bob, "/tmp/alice-mark"));
    assert!(present(&mut bob, "/tmp/bob-mark"));
    assert!(!present(&mut root0, "/tmp/alice-mark"));
    assert!(!present(&mut root0, "/tmp/bob-mark"));
    assert!(present(&mut root0, "/tmp/src-mark"));
}

/// TCP between two members survives a cluster fork (bytes, not frames).
#[test]
fn test_fc_cluster_tcp_survives_fork() {
    let guard = spawn_daemon("tcp", &[]);
    let (tree_id, root_eps) = create_cluster(&guard, "tcp", 2, 8);
    configure_members(&root_eps);
    let mut a0 = agent(&root_eps[0], Duration::from_secs(10));
    let mut a1 = agent(&root_eps[1], Duration::from_secs(10));
    wait_ping(&mut a0, guest_ip(1));
    tcp_oneshot(&mut a1, &mut a0, guest_ip(1), 9997, "before-fork");

    let (forks, _, skew) = fork_batch(&guard, &tree_id, "root", &["child"]);
    assert!(skew.is_some());
    let child_eps = &forks[0].1;
    let mut c0 = agent(&child_eps[0], CHILD_READY);
    let mut c1 = agent(&child_eps[1], CHILD_READY);
    wait_ping(&mut c0, guest_ip(1));
    tcp_oneshot(&mut c1, &mut c0, guest_ip(1), 9998, "after-fork");

    // Source still exchanges bytes after the skew window.
    let mut s0 = agent(&root_eps[0], Duration::from_secs(10));
    let mut s1 = agent(&root_eps[1], Duration::from_secs(10));
    wait_ping(&mut s0, guest_ip(1));
    tcp_oneshot(&mut s1, &mut s0, guest_ip(1), 9999, "source-after");
}

/// suspend frees FC processes and Private_Dirty; resume restores state
/// and wall-clock (`clock_realtime`).
#[test]
fn test_fc_cluster_suspend_resume() {
    let guard = spawn_daemon("susp", &[]);
    let (tree_id, root_eps) = create_cluster(&guard, "susp", 2, 8);
    configure_members(&root_eps);
    let mut a0 = agent(&root_eps[0], Duration::from_secs(10));
    sh(&mut a0, "echo survived > /tmp/survived");
    let dirs: Vec<PathBuf> = root_eps.iter().map(vm_dir_of).collect();
    let pids: Vec<u32> = dirs.iter().map(|d| firecracker_pid(d)).collect();
    for pid in &pids {
        assert!(k7d::fc::process_alive(*pid), "pid {pid} should be live");
        assert!(
            private_dirty(*pid).unwrap_or(0) > 0,
            "live FC VM {pid} should have Private_Dirty"
        );
    }

    let t0 = Instant::now();
    assert!(matches!(
        call(
            &guard,
            &Request::TreeSuspend {
                tree_id: tree_id.clone(),
                node_id: "root".into(),
            },
        ),
        Response::Ok
    ));
    let suspend_ns = t0.elapsed();
    println!("FC-LATENCY cluster suspend 2-member: {suspend_ns:?}");

    for pid in &pids {
        let deadline = Instant::now() + Duration::from_secs(10);
        while k7d::fc::process_alive(*pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            !k7d::fc::process_alive(*pid),
            "pid {pid} still alive after suspend"
        );
        assert!(
            private_dirty(*pid).is_none(),
            "Private_Dirty still readable for {pid} after suspend"
        );
    }
    assert_eq!(node_state(&guard, &tree_id, "root"), NodeState::Suspended);

    std::thread::sleep(Duration::from_secs(3));

    let t1 = Instant::now();
    let resumed = match call(
        &guard,
        &Request::TreeResume {
            tree_id: tree_id.clone(),
            node_id: "root".into(),
            clock: k7d::fork::ClockMode::Wall,
        },
    ) {
        Response::TreeResumed {
            agent_endpoints, ..
        } => agent_endpoints,
        other => panic!("tree_resume: {other:?}"),
    };
    let resume_ns = t1.elapsed();
    println!("FC-LATENCY cluster resume 2-member: {resume_ns:?}");
    assert_eq!(resumed.len(), 2);
    let mut r0 = agent(&resumed[0], Duration::from_secs(15));
    assert!(
        present(&mut r0, "/tmp/survived"),
        "state lost across suspend"
    );
    let host_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    let guest_now: f64 = sh(&mut r0, "date +%s")
        .trim()
        .parse()
        .expect("guest date +%s");
    let skew = (guest_now - host_now).abs();
    assert!(
        skew <= 2.0,
        "resumed wall clock is {skew:.1}s off the host — clock_realtime did not take"
    );
    configure_eth0(&mut r0, guest_ip(0));
    let mut r1 = agent(&resumed[1], Duration::from_secs(15));
    configure_eth0(&mut r1, guest_ip(1));
    wait_ping(&mut r0, guest_ip(1));
}

/// auto_evict under a tight budget evicts FC leaves by the same policy
/// as native (`test_cluster_tree_auto_evict_lru`): fork b from root
/// with max_live_vms = 6 (2 × 3) suspends LRU child `a`.
#[test]
fn test_fc_cluster_auto_evict_lru() {
    let guard = spawn_daemon("evict", &[]);
    let (tree_id, root_eps) = create_cluster(&guard, "evict", 3, 6);
    configure_members(&root_eps);

    let (forks_a, _, _) = fork_batch(&guard, &tree_id, "root", &["a"]);
    let a_id = &forks_a[0].0;
    assert_eq!(node_state(&guard, &tree_id, "root"), NodeState::Live);
    assert_eq!(node_state(&guard, &tree_id, a_id), NodeState::Live);

    let (forks_b, _, _) = fork_batch(&guard, &tree_id, "root", &["b"]);
    let b_id = &forks_b[0].0;
    assert_eq!(node_state(&guard, &tree_id, "root"), NodeState::Live);
    assert_eq!(
        node_state(&guard, &tree_id, a_id),
        NodeState::Suspended,
        "LRU child a must be suspended to make headroom (native parity)"
    );
    assert_eq!(node_state(&guard, &tree_id, b_id), NodeState::Live);

    match call(
        &guard,
        &Request::TreeNodes {
            tree_id: tree_id.clone(),
        },
    ) {
        Response::TreeNodeList { usage, .. } => {
            assert!(
                usage.live_vm_count <= 6,
                "live_vm_count {} exceeds budget 6",
                usage.live_vm_count
            );
        }
        other => panic!("tree_nodes: {other:?}"),
    }
}

/// `K7D_POOL_BACKEND=firecracker` pre-boots N FC VMs; a compatible
/// create_vm acquires one (`pooled: true`) and it is jailed.
#[test]
fn test_fc_pool_acquire() {
    let guard = spawn_daemon(
        "pool",
        &[
            ("K7D_POOL_SIZE", "1"),
            ("K7D_POOL_BACKEND", "firecracker"),
            ("K7D_POOL_MEMORY_MB", "256"),
        ],
    );
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        match call(&guard, &Request::PoolStatus) {
            Response::PoolStatus { size, idle, .. } => {
                assert_eq!(size, 1, "pool target must reflect K7D_POOL_SIZE");
                if idle >= 1 {
                    break;
                }
            }
            other => panic!("pool_status: {other:?}"),
        }
        assert!(
            Instant::now() < deadline,
            "firecracker pool never reached 1 idle VM"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    let t0 = Instant::now();
    let (vm_id, pooled, jail) = match call(
        &guard,
        &Request::CreateVm {
            config: fc_config(),
        },
    ) {
        Response::VmCreated {
            vm_id,
            pooled,
            agent_endpoint,
            ..
        } => {
            assert!(pooled, "compatible FC create_vm must hit the pool");
            guard.vms.borrow_mut().push(vm_id.clone());
            let ep = agent_endpoint.expect("FC create_vm returns an agent endpoint");
            let mut a = agent(&ep, Duration::from_secs(10));
            assert_eq!(sh(&mut a, "echo pooled").trim(), "pooled");
            let jail = match call(&guard, &Request::ListVms) {
                Response::VmList { vms } => vms
                    .into_iter()
                    .find(|v| v.vm_id == vm_id)
                    .and_then(|v| v.jail),
                other => panic!("list_vms: {other:?}"),
            };
            (vm_id, pooled, jail)
        }
        other => panic!("create_vm pool: {other:?}"),
    };
    let acquire = t0.elapsed();
    println!("FC-LATENCY pool acquire: {acquire:?} pooled={pooled}");
    assert!(
        acquire < Duration::from_secs(2),
        "pool acquire took {acquire:?} — not a warm hand-off"
    );
    let jail = jail.expect("pooled FC VM must be jailed");
    assert!(jail.pid > 0, "{jail:?}");
    assert!(
        Path::new(&jail.chroot).is_dir(),
        "chroot {} missing",
        jail.chroot
    );
    let _ = vm_id;
}
