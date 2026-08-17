//! The k7d daemon control plane.
//!
//! Spawns the real `k7d` binary as a separate process, boots VMs
//! through its Unix-socket control plane, then — crucially — connects
//! to a VM's guest agent **over vsock from this test process**,
//! proving the daemon-owns-VM / client-talks-to-agent-directly seam
//! that the shim relies on (vsock CIDs are kernel-global).
//!
//! Daemon-owned networking: `create_vm` with a
//! `NetConfig` joins a refcounted shared cluster bridge, and the
//! bridge only disappears when the *last* VM on it stops (the shim-era
//! shared-bridge teardown race).

use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use k7d::api::AgentClient;
use k7d::control::{Client, NetConfig, Request, Response, VmConfig};
use k7d::tree::NodeState;

fn workspace_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join(relative)
}

/// Kills the daemon child on drop so a panicking assertion can't leak
/// the process (and its VMs).
struct DaemonGuard {
    child: Child,
    socket: PathBuf,
    tree_root: PathBuf,
    sandbox_root: PathBuf,
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket);
        // Tree state (base.mem checkpoints are 256 MiB each) — reclaim.
        let _ = std::fs::remove_dir_all(&self.tree_root);
        let _ = std::fs::remove_dir_all(&self.sandbox_root);
    }
}

/// Spawn a fresh daemon on a per-test socket and wait for it to bind.
fn spawn_daemon(tag: &str) -> DaemonGuard {
    let pid = std::process::id();
    let socket = std::env::temp_dir().join(format!("k7d-test-{tag}-{pid}.sock"));
    let tree_root = std::env::temp_dir().join(format!("k7d-test-trees-{tag}-{pid}"));
    let sandbox_root = std::env::temp_dir().join(format!("k7d-test-sandboxes-{tag}-{pid}"));
    let _ = std::fs::remove_file(&socket);

    let child = Command::new(env!("CARGO_BIN_EXE_k7d"))
        .arg("--socket")
        .arg(&socket)
        .env("RUST_LOG", "info")
        .env("K7D_TREE_ROOT", &tree_root)
        .env("K7D_SANDBOX_ROOT", &sandbox_root)
        .spawn()
        .expect("spawn k7d daemon");
    let guard = DaemonGuard {
        child,
        socket,
        tree_root,
        sandbox_root,
    };

    let deadline = Instant::now() + Duration::from_secs(10);
    while !guard.socket.exists() {
        assert!(Instant::now() < deadline, "daemon socket never appeared");
        std::thread::sleep(Duration::from_millis(50));
    }
    guard
}

/// Send one request, read one response, over a fresh connection.
fn call(guard: &DaemonGuard, req: &Request) -> Response {
    let mut client = Client::connect(guard.socket.to_str().expect("utf8 socket path"))
        .expect("connect control socket");
    client.call(req).expect("control-plane call")
}

fn default_config() -> VmConfig {
    let kernel = workspace_path("guest/kernel/vmlinux");
    let initrd = workspace_path("guest/rootfs/initramfs.cpio.gz");
    assert!(kernel.exists(), "guest kernel not found at {kernel:?}");
    assert!(initrd.exists(), "initramfs not found at {initrd:?}");
    VmConfig {
        kernel: Some(kernel.to_string_lossy().into_owned()),
        initrd: Some(initrd.to_string_lossy().into_owned()),
        // Default: 256 MB, 1 vCPU, uncapped, vsock on.
        ..VmConfig::default()
    }
}

fn create_vm(guard: &DaemonGuard, config: VmConfig) -> (String, u64, Option<u32>) {
    match call(guard, &Request::CreateVm { config }) {
        Response::VmCreated {
            vm_id,
            guest_cid,
            vm_index,
            ..
        } => (vm_id, guest_cid, vm_index),
        other => panic!("unexpected create_vm response: {other:?}"),
    }
}

/// `--version` and `--help` must answer and exit, not boot a daemon.
///
/// They used to fall through to the serve path, so `k7d --version` from an
/// operator's shell started a second daemon, took the control socket from
/// the running one, and unlinked it on exit — the node's whole runtime went
/// away because someone asked which version was installed.
#[test]
fn test_info_flags_do_not_start_a_daemon() {
    for flag in ["--version", "-V", "--help", "-h"] {
        let out = Command::new(env!("CARGO_BIN_EXE_k7d"))
            .arg(flag)
            .output()
            .expect("run k7d");
        assert!(out.status.success(), "{flag} should exit 0");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains(env!("CARGO_PKG_VERSION")),
            "{flag} should print the version, got: {stdout}"
        );
        // A daemon would still be running; an informational flag returns.
        assert!(
            !stdout.contains("listening on"),
            "{flag} must not start serving, got: {stdout}"
        );
    }
}

/// A second daemon must refuse the socket rather than displace the first.
///
/// `serve` used to unlink whatever was at the path, assuming it was stale.
/// That made the original daemon serve an unlinked listener no client could
/// reach, and let whichever process exited first delete the survivor's
/// socket.
#[test]
fn test_second_daemon_refuses_a_live_socket() {
    let first = spawn_daemon("addrinuse");

    let out = Command::new(env!("CARGO_BIN_EXE_k7d"))
        .arg("--socket")
        .arg(&first.socket)
        .env("RUST_LOG", "info")
        .output()
        .expect("run second k7d");

    assert!(
        !out.status.success(),
        "second daemon on a live socket must fail, exited {:?}",
        out.status.code()
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("already serving"),
        "should say another daemon owns it, got: {stderr}"
    );

    // The point of the fix: the first daemon is still reachable.
    assert!(first.socket.exists(), "first daemon's socket was removed");
    match call(&first, &Request::Ping) {
        Response::Pong { .. } => {}
        other => panic!("first daemon stopped answering: {other:?}"),
    }
}

fn bridge_exists(name: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", name])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn test_daemon_vm_lifecycle_and_cross_process_agent() {
    let _ = env_logger::builder().is_test(true).try_init();
    let guard = spawn_daemon("lifecycle");

    // Ping.
    match call(&guard, &Request::Ping) {
        Response::Pong { version } => assert_eq!(version, env!("CARGO_PKG_VERSION")),
        other => panic!("unexpected ping response: {other:?}"),
    }

    // Create a vsock-only VM (like test_vsock, but owned by the daemon).
    let mut config = default_config();
    config.sandbox_id = Some("test-sandbox".to_string());
    let (vm_id, guest_cid, _) = create_vm(&guard, config);
    assert!(
        guest_cid >= 3,
        "guest_cid should be a real CID, got {guest_cid}"
    );

    // The daemon owns the VM in another process; connect to its agent
    // over vsock from THIS process. This is the architectural claim.
    let mut agent = AgentClient::connect_vsock(guest_cid, Duration::from_secs(90))
        .expect("connect to guest agent over vsock from a different process");
    assert_eq!(agent.ping().expect("agent ping").version, "0.1.0");
    let exec = agent.exec(&["echo", "hello"]).expect("agent exec");
    assert_eq!(exec.exit_code, 0);
    assert_eq!(exec.stdout.trim(), "hello");

    // Status + list reflect the running VM.
    match call(
        &guard,
        &Request::VmStatus {
            vm_id: vm_id.clone(),
        },
    ) {
        Response::VmState {
            state,
            guest_cid: c,
            ..
        } => {
            assert_eq!(state, "running");
            assert_eq!(c, guest_cid);
        }
        other => panic!("unexpected vm_status response: {other:?}"),
    }
    match call(&guard, &Request::ListVms) {
        Response::VmList { vms } => {
            assert!(vms
                .iter()
                .any(|v| v.vm_id == vm_id && v.sandbox_id.as_deref() == Some("test-sandbox")));
        }
        other => panic!("unexpected list_vms response: {other:?}"),
    }

    // Stop it; status now errors.
    assert!(matches!(
        call(
            &guard,
            &Request::StopVm {
                vm_id: vm_id.clone()
            }
        ),
        Response::Ok
    ));
    assert!(matches!(
        call(&guard, &Request::VmStatus { vm_id }),
        Response::Error { .. }
    ));

    drop(guard);
}

/// Two VMs sharing one cluster bridge. The
/// bridge must survive the first VM's stop (refcount) and disappear
/// with the second — the exact shared-bridge teardown race the daemon
/// exists to fix (with per-shim ownership, the first pod deleted
/// destroyed its peers' bridge).
#[test]
fn test_daemon_bridge_refcount_across_vms() {
    let _ = env_logger::builder().is_test(true).try_init();
    // Sweep bridges leaked by earlier crashed tests so the existence
    // assertions below track only what THIS daemon does.
    let _ = k7d::network::cleanup_stale_k7_bridges();

    let guard = spawn_daemon("bridge");
    let cluster_id = "drefc";
    let bridge = format!("k7-br-{cluster_id}");
    assert!(
        !bridge_exists(&bridge),
        "stale {bridge} present before test"
    );

    let net = |idx: Option<u32>| {
        let mut c = default_config();
        c.network = Some(NetConfig {
            cluster_id: cluster_id.to_string(),
            vm_index: idx,
            pod_netns: None,
        });
        c
    };

    let (vm_a, cid_a, idx_a) = create_vm(&guard, net(None));
    assert!(bridge_exists(&bridge), "{bridge} should exist after VM A");
    assert_eq!(idx_a, Some(0), "first VM gets vm_index 0");

    let (vm_b, cid_b, idx_b) = create_vm(&guard, net(None));
    assert_eq!(idx_b, Some(1), "second VM on the bridge gets vm_index 1");
    assert_ne!(cid_a, cid_b, "each VM gets its own vsock CID");

    // Both guests are reachable while sharing the bridge.
    let mut agent_a =
        AgentClient::connect_vsock(cid_a, Duration::from_secs(90)).expect("connect to VM A agent");
    let mut agent_b =
        AgentClient::connect_vsock(cid_b, Duration::from_secs(90)).expect("connect to VM B agent");
    assert_eq!(
        agent_a.exec(&["echo", "a"]).expect("exec on A").exit_code,
        0
    );
    assert_eq!(
        agent_b.exec(&["echo", "b"]).expect("exec on B").exit_code,
        0
    );
    drop(agent_a);
    drop(agent_b);

    // Stopping the FIRST VM must not tear the shared bridge down.
    assert!(matches!(
        call(&guard, &Request::StopVm { vm_id: vm_a }),
        Response::Ok
    ));
    assert!(
        bridge_exists(&bridge),
        "{bridge} must survive while VM B still uses it (refcount)"
    );

    // The freed vm_index 0 is reusable on the surviving bridge.
    let (vm_c, _, idx_c) = create_vm(&guard, net(Some(0)));
    assert_eq!(idx_c, Some(0), "freed vm_index should be reusable");
    assert!(matches!(
        call(&guard, &Request::StopVm { vm_id: vm_c }),
        Response::Ok
    ));
    assert!(bridge_exists(&bridge), "{bridge} still refcounted by VM B");

    // Last VM out turns off the lights.
    assert!(matches!(
        call(&guard, &Request::StopVm { vm_id: vm_b }),
        Response::Ok
    ));
    assert!(
        !bridge_exists(&bridge),
        "{bridge} must be destroyed when the last VM stops"
    );

    drop(guard);
}

/// Exec a command in a guest via its agent, asserting exit code 0, and
/// return trimmed stdout.
fn guest_exec(cid: u64, argv: &[&str]) -> String {
    let mut agent =
        AgentClient::connect_vsock(cid, Duration::from_secs(90)).expect("connect guest agent");
    let out = agent.exec(argv).expect("agent exec");
    assert_eq!(out.exit_code, 0, "exec {argv:?} failed: {}", out.stderr);
    out.stdout.trim().to_string()
}

/// `fork_vm` — warm-fork a plain daemon VM. The
/// first fork prepares the source (swaps it for a restored fork-ready
/// copy on the SAME vsock CID —); both source and fork
/// must be independently reachable afterwards.
#[test]
fn test_daemon_fork_vm() {
    let _ = env_logger::builder().is_test(true).try_init();
    let guard = spawn_daemon("forkvm");

    let (src_id, orig_cid, _) = create_vm(&guard, default_config());
    // Let the guest agent come up before we snapshot it as a fork source.
    guest_exec(orig_cid, &["echo", "ready"]);

    let (fork_id, fork_cid, src_cid) = match call(
        &guard,
        &Request::ForkVm {
            vm_id: src_id.clone(),
            sandbox_id: None,
        },
    ) {
        Response::VmForked {
            vm_id,
            guest_cid,
            source_guest_cid,
        } => (vm_id, guest_cid, source_guest_cid),
        other => panic!("unexpected fork_vm response: {other:?}"),
    };
    assert_ne!(fork_cid, src_cid, "fork must get its own CID");
    assert_eq!(
        src_cid, orig_cid,
        "prepare must preserve the source's CID across the restore swap \
         (the pod's shim caches it)"
    );

    // Both VMs answer on their (new) CIDs.
    assert_eq!(guest_exec(src_cid, &["echo", "src"]), "src");
    assert_eq!(guest_exec(fork_cid, &["echo", "fork"]), "fork");

    // Both appear in list_vms; stopping both leaves the daemon empty.
    match call(&guard, &Request::ListVms) {
        Response::VmList { vms } => {
            assert_eq!(vms.len(), 2, "source + fork expected: {vms:?}");
        }
        other => panic!("unexpected list_vms response: {other:?}"),
    }
    assert!(matches!(
        call(&guard, &Request::StopVm { vm_id: fork_id }),
        Response::Ok
    ));
    assert!(matches!(
        call(&guard, &Request::StopVm { vm_id: src_id }),
        Response::Ok
    ));

    drop(guard);
}

/// The single-VM snapshot tree lifecycle over
/// the control plane — create, fork (CoW independence proven through
/// guest state), suspend, resume (state survives, CID changes), prune,
/// drop. Runs against the real `k7d` binary in another process.
#[test]
fn test_daemon_tree_lifecycle() {
    let _ = env_logger::builder().is_test(true).try_init();
    let guard = spawn_daemon("tree");

    let (tree_id, root_id, root_cid) = match call(
        &guard,
        &Request::TreeCreate {
            config: default_config(),
            budget: None,
            tree_id: Some("dtree".to_string()),
        },
    ) {
        Response::TreeCreated {
            tree_id,
            root_id,
            guest_cids,
        } => {
            assert_eq!(guest_cids.len(), 1, "single-VM tree has one member");
            (tree_id, root_id, guest_cids[0])
        }
        other => panic!("unexpected tree_create response: {other:?}"),
    };
    assert_eq!(tree_id, "dtree");
    assert_eq!(root_id, "root");

    // Plant pre-fork state in the root guest (tmpfs = guest RAM, so
    // this is exactly the CoW memory the fork must inherit).
    guest_exec(root_cid, &["sh", "-c", "echo prefork > /tmp/state"]);

    let fork_start = Instant::now();
    let (fork_node, fork_cid) = match call(
        &guard,
        &Request::TreeFork {
            tree_id: tree_id.clone(),
            source_id: root_id.clone(),
            label: "branch-a".to_string(),
        },
    ) {
        Response::TreeForked {
            node_id,
            guest_cids,
            ..
        } => {
            assert_eq!(guest_cids.len(), 1);
            (node_id, guest_cids[0])
        }
        other => panic!("unexpected tree_fork response: {other:?}"),
    };
    let fork_elapsed = fork_start.elapsed();
    eprintln!("daemon tree fork round-trip: {fork_elapsed:?}");
    assert!(
        fork_elapsed < k7d::latency::DAEMON_TREE_FORK,
        "daemon tree fork should be <{:?}, was {fork_elapsed:?}",
        k7d::latency::DAEMON_TREE_FORK,
    );

    // Fork inherited the pre-fork state; its writes don't leak back.
    assert_eq!(guest_exec(fork_cid, &["cat", "/tmp/state"]), "prefork");
    guest_exec(fork_cid, &["sh", "-c", "echo forked > /tmp/state"]);
    assert_eq!(
        guest_exec(root_cid, &["cat", "/tmp/state"]),
        "prefork",
        "fork writes must not leak into the source (CoW)"
    );

    // Suspend the fork; tree_nodes reflects the state change.
    assert!(matches!(
        call(
            &guard,
            &Request::TreeSuspend {
                tree_id: tree_id.clone(),
                node_id: fork_node.clone(),
            }
        ),
        Response::Ok
    ));
    match call(
        &guard,
        &Request::TreeNodes {
            tree_id: tree_id.clone(),
        },
    ) {
        Response::TreeNodeList { nodes } => {
            let fork_info = nodes
                .iter()
                .find(|n| n.id == fork_node)
                .expect("fork node listed");
            assert_eq!(fork_info.state, NodeState::Suspended);
            assert_eq!(fork_info.parent.as_deref(), Some("root"));
        }
        other => panic!("unexpected tree_nodes response: {other:?}"),
    }

    // Resume: fresh CID, and the fork's post-fork state survived the
    // delta round-trip to disk.
    let resumed_cid = match call(
        &guard,
        &Request::TreeResume {
            tree_id: tree_id.clone(),
            node_id: fork_node.clone(),
        },
    ) {
        Response::TreeResumed { guest_cids, .. } => {
            assert_eq!(guest_cids.len(), 1);
            guest_cids[0]
        }
        other => panic!("unexpected tree_resume response: {other:?}"),
    };
    assert_ne!(resumed_cid, fork_cid, "resume allocates a fresh CID");
    assert_eq!(
        guest_exec(resumed_cid, &["cat", "/tmp/state"]),
        "forked",
        "suspend/resume must preserve the fork's own state"
    );

    // Under budget, auto-evict is a no-op.
    match call(
        &guard,
        &Request::TreeAutoEvict {
            tree_id: tree_id.clone(),
        },
    ) {
        Response::TreeEvicted { evicted } => assert!(evicted.is_empty(), "evicted: {evicted:?}"),
        other => panic!("unexpected tree_auto_evict response: {other:?}"),
    }

    // Prune the whole tree from the root, then drop it.
    assert!(matches!(
        call(
            &guard,
            &Request::TreePrune {
                tree_id: tree_id.clone(),
                node_id: root_id,
            }
        ),
        Response::Ok
    ));
    assert!(matches!(
        call(
            &guard,
            &Request::TreeDrop {
                tree_id: tree_id.clone(),
            }
        ),
        Response::Ok
    ));
    match call(&guard, &Request::TreeList) {
        Response::TreeList { trees } => assert!(trees.is_empty(), "trees: {trees:?}"),
        other => panic!("unexpected tree_list response: {other:?}"),
    }
    assert!(matches!(
        call(
            &guard,
            &Request::TreeFork {
                tree_id,
                source_id: "root".to_string(),
                label: "zombie".to_string(),
            }
        ),
        Response::Error { .. }
    ));

    drop(guard);
}

/// Control-plane RL verbs — `tree_fork_batch`, `tree_rollback`,
/// `tree_protect` / `tree_unprotect`. Smoke against the real daemon binary.
#[test]
fn test_daemon_tree_rl_verbs() {
    let _ = env_logger::builder().is_test(true).try_init();
    let guard = spawn_daemon("treerl");

    let (tree_id, root_id, root_cid) = match call(
        &guard,
        &Request::TreeCreate {
            config: default_config(),
            budget: None,
            tree_id: Some("rl-tree".to_string()),
        },
    ) {
        Response::TreeCreated {
            tree_id,
            root_id,
            guest_cids,
        } => (tree_id, root_id, guest_cids[0]),
        other => panic!("unexpected tree_create response: {other:?}"),
    };
    guest_exec(root_cid, &["sh", "-c", "echo checkpoint > /tmp/state"]);

    // Empty batch is loud — never a silent no-op.
    assert!(matches!(
        call(
            &guard,
            &Request::TreeForkBatch {
                tree_id: tree_id.clone(),
                source_id: root_id.clone(),
                labels: vec![],
            }
        ),
        Response::Error { .. }
    ));

    let forks = match call(
        &guard,
        &Request::TreeForkBatch {
            tree_id: tree_id.clone(),
            source_id: root_id.clone(),
            labels: vec!["a".into(), "b".into(), "c".into()],
        },
    ) {
        Response::TreeForkBatch { forks } => forks,
        other => panic!("unexpected tree_fork_batch response: {other:?}"),
    };
    assert_eq!(forks.len(), 3, "batch must return one branch per label");
    for f in &forks {
        assert_eq!(f.guest_cids.len(), 1);
        assert_eq!(
            f.fork_memory_full_copy,
            vec![false],
            "share-less tree forks must be CoW"
        );
        assert_eq!(
            guest_exec(f.guest_cids[0], &["cat", "/tmp/state"]),
            "checkpoint"
        );
    }

    // Mutate branch a, then rollback from root — new branch sees checkpoint.
    guest_exec(
        forks[0].guest_cids[0],
        &["sh", "-c", "echo mutated > /tmp/state"],
    );
    let rolled = match call(
        &guard,
        &Request::TreeRollback {
            tree_id: tree_id.clone(),
            node_id: root_id.clone(),
            label: "from-root".into(),
        },
    ) {
        Response::TreeForked {
            node_id,
            guest_cids,
            ..
        } => {
            assert_eq!(guest_cids.len(), 1);
            (node_id, guest_cids[0])
        }
        other => panic!("unexpected tree_rollback response: {other:?}"),
    };
    assert_eq!(guest_exec(rolled.1, &["cat", "/tmp/state"]), "checkpoint");
    assert_eq!(
        guest_exec(forks[0].guest_cids[0], &["cat", "/tmp/state"]),
        "mutated",
        "rollback must not disturb the mutated sibling"
    );

    // Protect the rollback winner; TreeNodes must reflect it.
    assert!(matches!(
        call(
            &guard,
            &Request::TreeProtect {
                tree_id: tree_id.clone(),
                node_id: rolled.0.clone(),
            }
        ),
        Response::Ok
    ));
    match call(
        &guard,
        &Request::TreeNodes {
            tree_id: tree_id.clone(),
        },
    ) {
        Response::TreeNodeList { nodes } => {
            let n = nodes
                .iter()
                .find(|n| n.id == rolled.0)
                .expect("rollback node listed");
            assert!(n.protected, "tree_protect must stick");
        }
        other => panic!("unexpected tree_nodes response: {other:?}"),
    }
    assert!(matches!(
        call(
            &guard,
            &Request::TreeUnprotect {
                tree_id: tree_id.clone(),
                node_id: rolled.0,
            }
        ),
        Response::Ok
    ));
    // Unknown node is loud.
    assert!(matches!(
        call(
            &guard,
            &Request::TreeProtect {
                tree_id: tree_id.clone(),
                node_id: "no-such-node".into(),
            }
        ),
        Response::Error { .. }
    ));

    assert!(matches!(
        call(&guard, &Request::TreeDrop { tree_id }),
        Response::Ok
    ));
    drop(guard);
}

/// Cluster snapshot tree over the control plane
/// — a 2-member cluster forks as one unit and every member of source
/// and fork stays independently reachable over vsock.
#[test]
fn test_daemon_cluster_tree_fork() {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = k7d::network::cleanup_stale_k7_bridges();
    let guard = spawn_daemon("ctree");

    let (tree_id, root_id, root_cids) = match call(
        &guard,
        &Request::TreeCreateCluster {
            vm_count: 2,
            config: default_config(),
            budget: None,
            tree_id: Some("dctree".to_string()),
        },
    ) {
        Response::TreeCreated {
            tree_id,
            root_id,
            guest_cids,
        } => (tree_id, root_id, guest_cids),
        other => panic!("unexpected tree_create_cluster response: {other:?}"),
    };
    assert_eq!(root_cids.len(), 2, "cluster root has two members");
    assert_ne!(root_cids[0], root_cids[1]);

    let (fork_node, fork_cids) = match call(
        &guard,
        &Request::TreeFork {
            tree_id: tree_id.clone(),
            source_id: root_id.clone(),
            label: "twin".to_string(),
        },
    ) {
        Response::TreeForked {
            node_id,
            guest_cids,
            fork_memory_full_copy,
        } => {
            // Share-less tree members ride the CoW path.
            assert_eq!(
                fork_memory_full_copy,
                vec![false; guest_cids.len()],
                "share-less cluster fork must be CoW, not full memfd copies"
            );
            (node_id, guest_cids)
        }
        other => panic!("unexpected cluster tree_fork response: {other:?}"),
    };
    assert_eq!(fork_cids.len(), 2, "cluster fork clones every member");

    // All four VMs (2 source members + 2 fork members) answer.
    for (i, cid) in root_cids.iter().chain(fork_cids.iter()).enumerate() {
        let tag = format!("m{i}");
        assert_eq!(guest_exec(*cid, &["echo", &tag]), tag);
    }

    match call(
        &guard,
        &Request::TreeNodes {
            tree_id: tree_id.clone(),
        },
    ) {
        Response::TreeNodeList { nodes } => {
            assert_eq!(nodes.len(), 2, "root + fork: {nodes:?}");
            assert!(nodes.iter().all(|n| n.vm_count == 2));
            let fork_info = nodes
                .iter()
                .find(|n| n.id == fork_node)
                .expect("fork node listed");
            assert_eq!(fork_info.parent.as_deref(), Some("root"));
        }
        other => panic!("unexpected tree_nodes response: {other:?}"),
    }

    assert!(matches!(
        call(
            &guard,
            &Request::TreePrune {
                tree_id: tree_id.clone(),
                node_id: root_id,
            }
        ),
        Response::Ok
    ));
    assert!(matches!(
        call(&guard, &Request::TreeDrop { tree_id }),
        Response::Ok
    ));

    drop(guard);
}

/// `tree_adopt_cluster` — live sandbox VMs on one
/// shared bridge become a cluster-tree root that can fork; validation
/// failures leave the registry untouched.
#[test]
fn test_daemon_tree_adopt_cluster() {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = k7d::network::cleanup_stale_k7_bridges();
    let guard = spawn_daemon("adopt");

    // Unknown VM id fails loud.
    assert!(matches!(
        call(
            &guard,
            &Request::TreeAdoptCluster {
                vm_ids: vec!["vm-nope".to_string()],
                budget: None,
                tree_id: None,
            }
        ),
        Response::Error { .. }
    ));

    // An unbridged VM cannot be adopted — and survives the rejection
    // (validation puts it back in the registry).
    let (lone_id, lone_cid, _) = create_vm(&guard, default_config());
    guest_exec(lone_cid, &["echo", "ready"]);
    assert!(matches!(
        call(
            &guard,
            &Request::TreeAdoptCluster {
                vm_ids: vec![lone_id.clone()],
                budget: None,
                tree_id: None,
            }
        ),
        Response::Error { .. }
    ));
    assert_eq!(guest_exec(lone_cid, &["echo", "alive"]), "alive");
    assert!(matches!(
        call(&guard, &Request::StopVm { vm_id: lone_id }),
        Response::Ok
    ));

    // Two VMs on one cluster bridge adopt into a tree root — passed in
    // reverse order to prove the handler sorts by vm_index.
    let net = |idx: u32| {
        let mut c = default_config();
        c.network = Some(NetConfig {
            cluster_id: "dadopt".to_string(),
            vm_index: Some(idx),
            pod_netns: None,
        });
        c
    };
    let (id0, cid0, _) = create_vm(&guard, net(0));
    let (id1, cid1, _) = create_vm(&guard, net(1));
    guest_exec(cid0, &["echo", "ready"]);
    guest_exec(cid1, &["echo", "ready"]);

    let (tree_id, root_id, root_cids) = match call(
        &guard,
        &Request::TreeAdoptCluster {
            vm_ids: vec![id1, id0],
            budget: None,
            tree_id: Some("dadopt-tree".to_string()),
        },
    ) {
        Response::TreeCreated {
            tree_id,
            root_id,
            guest_cids,
        } => (tree_id, root_id, guest_cids),
        other => panic!("unexpected tree_adopt_cluster response: {other:?}"),
    };
    assert_eq!(root_cids.len(), 2, "adopted root keeps both members");

    // The adopted VMs left the sandbox registry (tree owns them now).
    match call(&guard, &Request::ListVms) {
        Response::VmList { vms } => assert!(vms.is_empty(), "registry not empty: {vms:?}"),
        other => panic!("unexpected list_vms response: {other:?}"),
    }

    // Members answer on their post-prepare CIDs; a fork clones state
    // written after adopt (i.e. the adopted root is a live fork source).
    guest_exec(root_cids[0], &["sh", "-c", "echo adopted > /tmp/state"]);
    let fork_cids = match call(
        &guard,
        &Request::TreeFork {
            tree_id: tree_id.clone(),
            source_id: root_id,
            label: "twin".to_string(),
        },
    ) {
        Response::TreeForked { guest_cids, .. } => guest_cids,
        other => panic!("unexpected tree_fork response: {other:?}"),
    };
    assert_eq!(fork_cids.len(), 2, "fork clones every member");
    assert_eq!(guest_exec(fork_cids[0], &["cat", "/tmp/state"]), "adopted");

    assert!(matches!(
        call(&guard, &Request::TreeDrop { tree_id }),
        Response::Ok
    ));
    drop(guard);
}

/// A sandbox-carrying `create_vm` persists an
/// atomic reattach record, `lookup_sandbox` / `reattach_sandbox`
/// resolve it while the VM lives, and `stop_vm` erases both the index
/// entry and the file so a reattach after intentional delete fails
/// loudly.
#[test]
fn test_daemon_sandbox_persist_and_lookup() {
    let _ = env_logger::builder().is_test(true).try_init();
    let guard = spawn_daemon("sbpersist");

    let sandbox_id = "sb-persist-test";
    let mut config = default_config();
    config.sandbox_id = Some(sandbox_id.to_string());
    let (vm_id, guest_cid, _) = create_vm(&guard, config);

    // The record exists on disk, atomically written (no .tmp left).
    let record_path = guard.sandbox_root.join(format!("{sandbox_id}.json"));
    assert!(record_path.exists(), "record {record_path:?} not written");
    assert!(
        !guard
            .sandbox_root
            .join(format!("{sandbox_id}.json.tmp"))
            .exists(),
        "tmp file must not survive the atomic rename"
    );
    let record: k7d::control::SandboxRecord =
        serde_json::from_str(&std::fs::read_to_string(&record_path).expect("read record"))
            .expect("parse record");
    assert_eq!(record.sandbox_id, sandbox_id);
    assert_eq!(record.vm_id, vm_id);
    assert_eq!(record.guest_cid, guest_cid);
    assert_eq!(record.vcpus, 1, "default config is 1 vCPU");
    assert!(record.cpu_quota.is_none());
    assert!(record.created_at_unix > 0);

    // lookup_sandbox resolves to the same VM.
    match call(
        &guard,
        &Request::LookupSandbox {
            sandbox_id: sandbox_id.to_string(),
        },
    ) {
        Response::SandboxFound {
            vm_id: v,
            guest_cid: c,
            ..
        } => {
            assert_eq!(v, vm_id);
            assert_eq!(c, guest_cid);
        }
        other => panic!("unexpected lookup_sandbox response: {other:?}"),
    }

    // Let the guest agent come up, then reattach_sandbox must verify
    // liveness and return the same VM.
    guest_exec(guest_cid, &["echo", "ready"]);
    match call(
        &guard,
        &Request::ReattachSandbox {
            sandbox_id: sandbox_id.to_string(),
        },
    ) {
        Response::SandboxFound {
            vm_id: v,
            guest_cid: c,
            ..
        } => {
            assert_eq!(v, vm_id);
            assert_eq!(c, guest_cid);
        }
        other => panic!("unexpected reattach_sandbox response: {other:?}"),
    }

    // A VM created WITHOUT a sandbox_id writes no record.
    let (anon_vm, _, _) = create_vm(&guard, default_config());
    let files = std::fs::read_dir(&guard.sandbox_root)
        .expect("sandbox root readable")
        .count();
    assert_eq!(files, 1, "anonymous VM must not write a sandbox record");
    assert!(matches!(
        call(&guard, &Request::StopVm { vm_id: anon_vm }),
        Response::Ok
    ));

    // stop_vm removes the record and the index entry; both lookup and
    // reattach then fail loudly.
    assert!(matches!(
        call(&guard, &Request::StopVm { vm_id }),
        Response::Ok
    ));
    assert!(
        !record_path.exists(),
        "stop_vm must remove the sandbox record"
    );
    assert!(matches!(
        call(
            &guard,
            &Request::LookupSandbox {
                sandbox_id: sandbox_id.to_string(),
            }
        ),
        Response::Error { .. }
    ));
    assert!(matches!(
        call(
            &guard,
            &Request::ReattachSandbox {
                sandbox_id: sandbox_id.to_string(),
            }
        ),
        Response::Error { .. }
    ));

    drop(guard);
}

/// A multi-vCPU sandbox create persists `vcpus` (and the CFS
/// cap) on the reattach record and surfaces the count via
/// `lookup_sandbox` — crash-recovery metadata must not silently assume
/// 1 vCPU on the annotation/kubectl route.
#[test]
fn test_daemon_sandbox_record_carries_vcpus() {
    let _ = env_logger::builder().is_test(true).try_init();
    let guard = spawn_daemon("sbvcpus");

    let sandbox_id = "sb-2vcpu";
    let mut config = default_config();
    config.sandbox_id = Some(sandbox_id.to_string());
    config.vcpus = 2;
    config.cpu_quota = Some(200_000);
    config.cpu_period = Some(100_000);
    let (vm_id, guest_cid, _) = create_vm(&guard, config);
    guest_exec(guest_cid, &["echo", "ready"]);

    let record_path = guard.sandbox_root.join(format!("{sandbox_id}.json"));
    let record: k7d::control::SandboxRecord =
        serde_json::from_str(&std::fs::read_to_string(&record_path).expect("read record"))
            .expect("parse record");
    assert_eq!(record.vcpus, 2);
    assert_eq!(record.cpu_quota, Some(200_000));
    assert_eq!(record.cpu_period, Some(100_000));

    // Legacy records without the field still deserialize as 1 vCPU.
    let legacy = r#"{"sandbox_id":"x","vm_id":"y","guest_cid":1,"created_at_unix":1}"#;
    let legacy_rec: k7d::control::SandboxRecord =
        serde_json::from_str(legacy).expect("legacy record");
    assert_eq!(legacy_rec.vcpus, 1);

    match call(
        &guard,
        &Request::LookupSandbox {
            sandbox_id: sandbox_id.to_string(),
        },
    ) {
        Response::SandboxFound {
            vm_id: v, vcpus, ..
        } => {
            assert_eq!(v, vm_id);
            assert_eq!(vcpus, 2);
        }
        other => panic!("unexpected lookup_sandbox response: {other:?}"),
    }

    assert!(matches!(
        call(&guard, &Request::StopVm { vm_id }),
        Response::Ok
    ));
    drop(guard);
}

/// `reattach_sandbox` must not resurrect a dead
/// VM from JSON alone. A stale record (its VM died with a previous
/// daemon) is garbage-collected by the reattach that trips over it —
/// and a daemon restart's startup scan sweeps whatever records remain.
#[test]
fn test_daemon_reattach_verifies_live_vm() {
    let _ = env_logger::builder().is_test(true).try_init();
    let guard = spawn_daemon("sbstale");

    // Inject a stale record: no VM in this daemon ever carried it.
    let ghost = k7d::control::SandboxRecord {
        sandbox_id: "sb-ghost".to_string(),
        vm_id: "vm-99999-42".to_string(),
        guest_cid: 4242,
        vcpus: 1,
        cpu_quota: None,
        cpu_period: None,
        vm_index: None,
        cluster_id: None,
        pod_netns: None,
        created_at_unix: 1,
    };
    std::fs::create_dir_all(&guard.sandbox_root).expect("create sandbox root");
    let ghost_path = guard.sandbox_root.join("sb-ghost.json");
    std::fs::write(&ghost_path, serde_json::to_string(&ghost).unwrap()).expect("write ghost");

    // Reattach must fail AND delete the stale record.
    match call(
        &guard,
        &Request::ReattachSandbox {
            sandbox_id: "sb-ghost".to_string(),
        },
    ) {
        Response::Error { message } => {
            assert!(
                message.contains("stale"),
                "error should mention the stale record: {message}"
            );
        }
        other => panic!("unexpected reattach_sandbox response: {other:?}"),
    }
    assert!(
        !ghost_path.exists(),
        "reattach must remove the stale record"
    );

    // Startup scan: create a live sandbox VM, kill the daemon without
    // teardown (records survive), then a fresh daemon on the same
    // root must sweep them (its registry is empty — the VMs died).
    let mut config = default_config();
    config.sandbox_id = Some("sb-dies-with-daemon".to_string());
    let (_vm_id, _cid, _) = create_vm(&guard, config);
    let record_path = guard.sandbox_root.join("sb-dies-with-daemon.json");
    assert!(record_path.exists(), "record should exist while VM lives");

    let mut guard = guard;
    let _ = guard.child.kill();
    let _ = guard.child.wait();
    let _ = std::fs::remove_file(&guard.socket);
    assert!(
        record_path.exists(),
        "record must survive a daemon crash (SIGKILL)"
    );

    // Fresh daemon, same sandbox root: its startup scan must sweep the
    // orphan (no VM in its registry can match).
    guard.child = Command::new(env!("CARGO_BIN_EXE_k7d"))
        .arg("--socket")
        .arg(guard.socket.as_os_str())
        .env("RUST_LOG", "info")
        .env("K7D_SANDBOX_ROOT", &guard.sandbox_root)
        .spawn()
        .expect("respawn k7d daemon");
    let deadline = Instant::now() + Duration::from_secs(10);
    while record_path.exists() {
        assert!(
            Instant::now() < deadline,
            "startup scan should sweep the orphan record"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(matches!(
        call(
            &guard,
            &Request::LookupSandbox {
                sandbox_id: "sb-dies-with-daemon".to_string(),
            }
        ),
        Response::Error { .. }
    ));

    drop(guard);
}
