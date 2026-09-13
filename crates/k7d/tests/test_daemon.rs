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

mod common;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    socket_dir: PathBuf,
    tree_root: PathBuf,
    sandbox_root: PathBuf,
    log_path: Option<PathBuf>,
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_dir_all(&self.socket_dir);
        // Tree state (base.mem checkpoints are 256 MiB each) — reclaim.
        let _ = std::fs::remove_dir_all(&self.tree_root);
        let _ = std::fs::remove_dir_all(&self.sandbox_root);
        if let Some(ref log) = self.log_path {
            let _ = std::fs::remove_file(log);
        }
    }
}

/// Spawn a fresh daemon on a per-test socket and wait for it to bind.
fn spawn_daemon(tag: &str) -> DaemonGuard {
    spawn_daemon_env(tag, &[], false)
}

/// Like [`spawn_daemon`], with extra env and optional stderr capture.
fn spawn_daemon_env(tag: &str, extra: &[(&str, &str)], capture_log: bool) -> DaemonGuard {
    let pid = std::process::id();
    let socket_dir = std::env::temp_dir().join(format!("k7d-test-{tag}-{pid}"));
    let _ = std::fs::remove_dir_all(&socket_dir);
    std::fs::create_dir_all(&socket_dir).expect("create socket parent");
    let socket = socket_dir.join("k7d.sock");
    let tree_root = std::env::temp_dir().join(format!("k7d-test-trees-{tag}-{pid}"));
    let sandbox_root = std::env::temp_dir().join(format!("k7d-test-sandboxes-{tag}-{pid}"));
    let log_path = capture_log.then(|| socket_dir.join("k7d.log"));

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_k7d"));
    cmd.arg("--socket")
        .arg(&socket)
        .env("RUST_LOG", "info")
        .env("K7D_TREE_ROOT", &tree_root)
        .env("K7D_SANDBOX_ROOT", &sandbox_root);
    for (k, v) in extra {
        cmd.env(k, v);
    }
    if let Some(ref log) = log_path {
        cmd.stderr(std::fs::File::create(log).expect("daemon log"));
        cmd.stdout(Stdio::null());
    }
    let child = cmd.spawn().expect("spawn k7d daemon");
    let guard = DaemonGuard {
        child,
        socket,
        socket_dir,
        tree_root,
        sandbox_root,
        log_path,
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

/// Control socket is `0660`, parent `0750`. `K7D_ALLOWED_UIDS` excluding
/// this process refuses the connection and logs it; without the env,
/// root (k7's Python client path) still works.
#[test]
fn test_control_socket_mode_and_allowed_uids() {
    let _ = env_logger::builder().is_test(true).try_init();
    let allowed = spawn_daemon("sockmode");
    let sock_mode = std::fs::metadata(&allowed.socket)
        .expect("socket metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(sock_mode, 0o660, "socket must be 0660, got {sock_mode:o}");
    let parent_mode = std::fs::metadata(&allowed.socket_dir)
        .expect("parent metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        parent_mode, 0o750,
        "socket parent must be 0750, got {parent_mode:o}"
    );
    match call(&allowed, &Request::Ping) {
        Response::Pong { .. } => {}
        other => panic!("root must still connect without an allowlist, got {other:?}"),
    }
    drop(allowed);

    // SAFETY: getuid has no preconditions.
    let me = unsafe { libc::getuid() };
    let other = if me == 0 { 1 } else { 0 };
    let denied = spawn_daemon_env(
        "sockdeny",
        &[("K7D_ALLOWED_UIDS", &other.to_string())],
        true,
    );
    // Accept may succeed and then the daemon drops the stream, or
    // connect itself fails. Either is a refusal (`call` and `connect`
    // have different error types, so they cannot share `and_then`).
    let refused = match Client::connect(denied.socket.to_str().expect("utf8")) {
        Ok(mut c) => c.call(&Request::Ping).is_err(),
        Err(_) => true,
    };
    assert!(
        refused,
        "uid {me} must be refused when allowlist is {other}"
    );
    let log_path = denied.log_path.as_ref().expect("captured log");
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut log = String::new();
    loop {
        log = std::fs::read_to_string(log_path).unwrap_or_default();
        if log.contains("K7D_ALLOWED_UIDS") || Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        log.contains("K7D_ALLOWED_UIDS") && log.contains(&format!("uid={me}")),
        "refusal must be logged with the peer uid, got: {log}"
    );
    drop(denied);
}

fn bridge_exists(name: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", name])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Host TAP/TUN names (`ip -o link show type tun`). Used to assert a
/// failed CNI attach did not leak the TAP `acquire_network` created.
fn tun_names() -> Vec<String> {
    let out = Command::new("ip")
        .args(["-o", "link", "show", "type", "tun"])
        .output()
        .expect("ip link show type tun");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            line.split_whitespace()
                .nth(1)
                .map(|n| n.trim_end_matches(':').to_string())
        })
        .collect()
}

#[test]
fn test_daemon_vm_lifecycle_and_cross_process_agent() {
    let _ = env_logger::builder().is_test(true).try_init();
    let guard = spawn_daemon("lifecycle");

    // Ping.
    match call(&guard, &Request::Ping) {
        Response::Pong { version, .. } => assert_eq!(version, env!("CARGO_PKG_VERSION")),
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

/// A requested CNI attach that cannot complete must fail `create_vm`
/// (bug-candidates #38). The VM must not boot on the
/// host bridge with an IP kubelet never programmed.
#[test]
fn test_daemon_bogus_pod_netns_fails_create_loud() {
    let _ = env_logger::builder().is_test(true).try_init();
    let cluster_id = format!("n{}", std::process::id() % 99_999_999);
    let bridge = format!("k7-br-{cluster_id}");
    // Residue from a crashed previous run of *this* test only —
    // do not sweep other `k7-br-*` (bug-candidates #64).
    if bridge_exists(&bridge) {
        let _ = Command::new("ip")
            .args(["link", "delete", &bridge])
            .status();
    }
    assert!(
        !bridge_exists(&bridge),
        "stale {bridge} present before test"
    );

    let guard = spawn_daemon("cnifl");
    let taps_before = tun_names();
    let mut config = default_config();
    config.network = Some(NetConfig {
        cluster_id,
        vm_index: None,
        pod_netns: Some("/var/run/netns/does-not-exist".to_string()),
    });

    match call(&guard, &Request::CreateVm { config }) {
        Response::Error { message } => {
            assert!(
                message.contains("CNI attach"),
                "error must name the CNI attach, not a missing kernel: {message}"
            );
            assert!(
                message.contains("does-not-exist"),
                "error must name the bogus netns path: {message}"
            );
            assert!(
                !message.to_lowercase().contains("kernel"),
                "must not look like a kernel-path error: {message}"
            );
        }
        other => panic!("bogus pod_netns must not create a VM: {other:?}"),
    }

    match call(&guard, &Request::ListVms) {
        Response::VmList { vms } => {
            assert!(vms.is_empty(), "failed CNI attach left a VM: {vms:?}");
        }
        other => panic!("unexpected list_vms response: {other:?}"),
    }
    assert!(
        !bridge_exists(&bridge),
        "{bridge} must not survive a failed CNI attach"
    );
    let leftover: Vec<_> = tun_names()
        .into_iter()
        .filter(|n| !taps_before.contains(n))
        .collect();
    assert!(
        leftover.is_empty(),
        "leftover TAP after failed CNI attach: {leftover:?}"
    );
    drop(guard);
}

/// The `warp_clock` op: every VM on one cluster bridge
/// gets the same forward jump, under pause, in one call.
///
/// The mechanism's correctness on a real workload is
/// `test_warp_clock.rs`'s job (a live Ubuntu k3s cluster, a
/// CrashLoopBackOff pod firing early). This is the control-plane half:
/// the op finds the cluster's VMs by `cluster_id`, both guests' clocks
/// actually move, the daemon reports its own latency, and the two ways
/// to ask for nothing — a zero delta, an unknown cluster — are loud
/// errors rather than quiet successes.
#[test]
fn test_daemon_warp_clock_moves_every_vm_on_a_cluster() {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = k7d::network::cleanup_stale_k7_bridges();
    let guard = spawn_daemon("warp");
    let cluster_id = "warpc";

    let on_cluster = || {
        let mut c = default_config();
        c.network = Some(NetConfig {
            cluster_id: cluster_id.to_string(),
            vm_index: None,
            pod_netns: None,
        });
        c
    };
    let (vm_a, cid_a, _) = create_vm(&guard, on_cluster());
    let (vm_b, cid_b, _) = create_vm(&guard, on_cluster());
    // A VM on no cluster must not be dragged along.
    let (vm_lone, cid_lone, _) = create_vm(&guard, default_config());

    // Wait for all three agents before reading any clock: a guest still
    // booting has not derived its wall clock from kvmclock yet.
    for cid in [cid_a, cid_b, cid_lone] {
        guest_exec(cid, &["echo", "ready"]);
    }
    let guest_epoch = |cid: u64| -> i64 {
        guest_exec(cid, &["sh", "-c", "date +%s"])
            .parse()
            .expect("guest `date +%s` prints a number")
    };
    let host_epoch = || -> i64 {
        i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("host clock is past the epoch")
                .as_secs(),
        )
        .expect("host epoch fits in i64")
    };
    let ahead = |cid: u64| guest_epoch(cid) - host_epoch();
    let before = [ahead(cid_a), ahead(cid_b), ahead(cid_lone)];

    // Forward-only, never a no-op: both ways of asking for nothing fail.
    assert!(matches!(
        call(
            &guard,
            &Request::WarpClock {
                cluster_id: cluster_id.to_string(),
                delta_ms: 0,
            }
        ),
        Response::Error { .. }
    ));
    assert!(matches!(
        call(
            &guard,
            &Request::WarpClock {
                cluster_id: "no-such-cluster".to_string(),
                delta_ms: 120_000,
            }
        ),
        Response::Error { .. }
    ));

    let delta_ms = 120_000;
    match call(
        &guard,
        &Request::WarpClock {
            cluster_id: cluster_id.to_string(),
            delta_ms,
        },
    ) {
        Response::Warped {
            cluster_id: cid,
            vm_ids,
            delta_ms: echoed,
            latency_ns,
        } => {
            assert_eq!(cid, cluster_id);
            assert_eq!(echoed, delta_ms);
            assert_eq!(
                vm_ids,
                vec![vm_a.clone(), vm_b.clone()],
                "the op must warp exactly the cluster's VMs, in vm_index order"
            );
            assert!(latency_ns > 0, "the daemon must report its own latency");
            eprintln!(
                "MEASUREMENT daemon warp_clock 2 VMs: {:.1}ms",
                latency_ns as f64 / 1e6
            );
        }
        other => panic!("unexpected warp_clock response: {other:?}"),
    }

    // 1 s of `date` granularity either side of a 120 s jump.
    let jumped = |what: &str, cid: u64, was: i64| -> i64 {
        let now = ahead(cid);
        eprintln!("{what}: guest was {was}s off the host, now {now}s");
        now - was
    };
    for (what, cid, was) in [("VM A", cid_a, before[0]), ("VM B", cid_b, before[1])] {
        let moved = jumped(what, cid, was);
        assert!(
            (moved - 120).abs() <= 3,
            "{what}'s clock moved {moved}s, wanted 120s"
        );
    }
    let lone_moved = jumped("the off-cluster VM", cid_lone, before[2]);
    assert!(
        lone_moved.abs() <= 3,
        "a VM on no cluster must not be warped, but its clock moved {lone_moved}s"
    );

    // Warped VMs are running VMs: the resume is part of the op.
    for cid in [cid_a, cid_b] {
        assert_eq!(guest_exec(cid, &["echo", "alive"]), "alive");
    }

    for vm_id in [vm_a, vm_b, vm_lone] {
        assert!(matches!(
            call(&guard, &Request::StopVm { vm_id }),
            Response::Ok
        ));
    }
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

/// `create_vm` with a **named persistent** data disk:
/// the agent mounts it, `stop_vm` retains the image, `delete_data_disk`
/// refuses while a live VM holds it, and a tree payload cannot have one.
///
/// The lifetime rules are the whole primitive, so every one of them is
/// checked through the real daemon rather than the library: a disk the
/// daemon deletes at teardown, or deletes out from under a live guest,
/// would look exactly like a working disk in a single-VM library test.
#[test]
fn test_data_disk_lifetime_through_the_daemon() {
    let guard = spawn_daemon("datadisk");
    let id = format!("test-daemon-{}", std::process::id());
    let image = k7d::disks::data_disk_path(&id);
    let _ = std::fs::remove_file(&image);

    let config = VmConfig {
        data_disks: vec![k7d::control::DataDiskConfig {
            id: id.clone(),
            size_bytes: 64 * 1024 * 1024,
            guest_mount: "/run/k7d/data".to_string(),
        }],
        ..default_config()
    };
    let (vm_id, guest_cid, _) = create_vm(&guard, config.clone());
    assert!(
        image.exists(),
        "create_vm must provision {}",
        image.display()
    );
    assert_eq!(
        guest_exec(guest_cid, &["sh", "-c", "cat /proc/mounts"])
            .lines()
            .filter(|l| l.contains(" /run/k7d/data "))
            .count(),
        1,
        "the agent must mount the data disk exactly once"
    );
    guest_exec(
        guest_cid,
        &["sh", "-c", "echo daemon-marker > /run/k7d/data/m && sync"],
    );

    // Deleting a disk a live VM is writing is CHALLENGES #63's bug.
    match call(&guard, &Request::DeleteDataDisk { id: id.clone() }) {
        Response::Error { message } => assert!(
            message.contains(&vm_id),
            "the refusal must name the holding VM, got: {message}"
        ),
        other => panic!("delete of an attached data disk must be refused, got {other:?}"),
    }

    // Teardown retains it, and a second VM with the same id reads it back.
    assert!(matches!(
        call(&guard, &Request::StopVm { vm_id }),
        Response::Ok
    ));
    assert!(
        image.exists(),
        "stop_vm removed {} — a data disk must outlive its VM",
        image.display()
    );
    let (vm_id2, cid2, _) = create_vm(&guard, config);
    assert_eq!(
        guest_exec(cid2, &["cat", "/run/k7d/data/m"]),
        "daemon-marker",
        "the second VM did not see the first VM's write"
    );
    assert!(matches!(
        call(&guard, &Request::StopVm { vm_id: vm_id2 }),
        Response::Ok
    ));

    // A tree payload is forked repeatedly; a disk with one identity has
    // no meaning there, and the refusal says so rather than dropping it.
    let payload = VmConfig {
        data_disks: vec![k7d::control::DataDiskConfig {
            id: id.clone(),
            size_bytes: 64 * 1024 * 1024,
            guest_mount: "/run/k7d/data".to_string(),
        }],
        ..default_config()
    };
    match call(
        &guard,
        &Request::TreeCreate {
            config: payload,
            budget: None,
            tree_id: Some("datadisk-tree".to_string()),
        },
    ) {
        Response::Error { message } => assert!(
            message.contains("data_disks"),
            "the refusal must name the field, got: {message}"
        ),
        other => panic!("a tree payload with a data disk must be refused, got {other:?}"),
    }

    // Now nothing holds it, so the explicit delete is the thing that
    // removes it.
    assert!(matches!(
        call(&guard, &Request::DeleteDataDisk { id: id.clone() }),
        Response::Ok
    ));
    assert!(!image.exists(), "delete left {} behind", image.display());
    drop(guard);
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
            dilation: None,
        },
    ) {
        Response::VmForked {
            vm_id,
            guest_cid,
            source_guest_cid,
            ..
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
            ..
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
    let (fork_node, fork_cid, latency_ns) = match call(
        &guard,
        &Request::TreeFork {
            tree_id: tree_id.clone(),
            source_id: root_id.clone(),
            label: "branch-a".to_string(),
            dilation: None,
        },
    ) {
        Response::TreeForked {
            node_id,
            guest_cids,
            latency_ns,
            ..
        } => {
            assert_eq!(guest_cids.len(), 1);
            (node_id, guest_cids[0], latency_ns)
        }
        other => panic!("unexpected tree_fork response: {other:?}"),
    };
    let fork_elapsed = fork_start.elapsed();
    common::tree_fork_budget::assert_tree_fork_budget(
        "daemon tree",
        fork_elapsed,
        latency_ns,
        k7d::latency::DAEMON_TREE_FORK,
    );

    match call(
        &guard,
        &Request::DumpSerial {
            vm_id: None,
            guest_cid: Some(fork_cid),
        },
    ) {
        Response::SerialDump {
            vm_id,
            guest_cid,
            console: _,
        } => {
            assert_eq!(guest_cid, fork_cid, "dump_serial echoes the CID");
            assert!(
                vm_id.contains(&fork_node),
                "tree member vm_id should name the node, got {vm_id}"
            );
        }
        other => panic!("dump_serial by fork cid: {other:?}"),
    }
    match call(
        &guard,
        &Request::DumpSerial {
            vm_id: Some(format!("{tree_id}/{fork_node}")),
            guest_cid: None,
        },
    ) {
        Response::SerialDump { guest_cid, .. } => {
            assert_eq!(guest_cid, fork_cid, "dump_serial by tree/node id");
        }
        other => panic!("dump_serial by composite id: {other:?}"),
    }

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
        Response::TreeNodeList {
            nodes,
            usage,
            budget,
            live_guest_cids,
            ..
        } => {
            let fork_info = nodes
                .iter()
                .find(|n| n.id == fork_node)
                .expect("fork node listed");
            assert_eq!(fork_info.state, NodeState::Suspended);
            assert_eq!(fork_info.parent.as_deref(), Some("root"));
            assert_eq!(usage.total_nodes, nodes.len());
            assert_eq!(usage.live_vm_count, 1, "only root is live after suspend");
            assert_eq!(budget.max_live_vms, 8);
            assert_eq!(
                live_guest_cids.get(&fork_node).map(Vec::as_slice),
                Some([].as_slice()),
                "suspended node must not keep a stale CID"
            );
            assert_eq!(
                live_guest_cids.get("root").map(|c| c.as_slice()),
                Some([root_cid].as_slice())
            );
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
                dilation: None,
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
            ..
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
                dilation: None,
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
            dilation: None,
        },
    ) {
        Response::TreeForkBatch {
            forks, latency_ns, ..
        } => {
            assert!(
                latency_ns > 0,
                "tree_fork_batch must report latency_ns, got {latency_ns}"
            );
            for f in &forks {
                assert_eq!(f.latency_ns, latency_ns);
            }
            forks
        }
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
        Response::TreeNodeList { nodes, .. } => {
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
            egress: None,
        },
    ) {
        Response::TreeCreated {
            tree_id,
            root_id,
            guest_cids,
            ..
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
            dilation: None,
        },
    ) {
        Response::TreeForked {
            node_id,
            guest_cids,
            fork_memory_full_copy,
            latency_ns,
            dilation,
            ..
        } => {
            assert_eq!(dilation, 1, "undilated source forks at 1");
            assert!(
                latency_ns > 0,
                "cluster tree_fork must report latency_ns, got {latency_ns}"
            );
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
        match call(
            &guard,
            &Request::DumpSerial {
                vm_id: None,
                guest_cid: Some(*cid),
            },
        ) {
            Response::SerialDump { guest_cid, .. } => {
                assert_eq!(guest_cid, *cid, "dump_serial finds cluster member {i}");
            }
            other => panic!("dump_serial cluster member {i} cid {cid}: {other:?}"),
        }
    }

    match call(
        &guard,
        &Request::TreeNodes {
            tree_id: tree_id.clone(),
        },
    ) {
        Response::TreeNodeList { nodes, .. } => {
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

    let (grand_node, _) = match call(
        &guard,
        &Request::TreeFork {
            tree_id: tree_id.clone(),
            source_id: fork_node.clone(),
            label: "grand".to_string(),
            dilation: None,
        },
    ) {
        Response::TreeForked {
            node_id,
            guest_cids,
            ..
        } => (node_id, guest_cids),
        other => panic!("unexpected grandchild tree_fork response: {other:?}"),
    };
    match call(
        &guard,
        &Request::TreeNodes {
            tree_id: tree_id.clone(),
        },
    ) {
        Response::TreeNodeList { nodes, .. } => {
            let grand_info = nodes
                .iter()
                .find(|n| n.id == grand_node)
                .expect("grandchild listed");
            assert_eq!(
                grand_info.parent.as_deref(),
                Some(fork_node.as_str()),
                "grandchild parent must be the child, not root"
            );
            let child_info = nodes
                .iter()
                .find(|n| n.id == fork_node)
                .expect("child listed");
            assert!(
                !child_info.has_base_snapshot,
                "fork from child inherits the ancestor keyframe; no new memory.bin"
            );
        }
        other => panic!("unexpected tree_nodes after grandchild: {other:?}"),
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

/// `tree_open` of a just-`tree_drop`ped cluster returns
/// nodes Suspended. Missing / already-in-memory / unparseable are loud
/// and never delete the on-disk dir.
#[test]
fn test_daemon_tree_open_after_drop() {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = k7d::network::cleanup_stale_k7_bridges();
    let guard = spawn_daemon("topen");

    let (tree_id, root_id, _) = match call(
        &guard,
        &Request::TreeCreateCluster {
            vm_count: 1,
            config: default_config(),
            budget: None,
            tree_id: Some("topen-drop".to_string()),
            egress: None,
        },
    ) {
        Response::TreeCreated {
            tree_id,
            root_id,
            guest_cids,
            ..
        } => {
            assert_eq!(guest_cids.len(), 1);
            (tree_id, root_id, guest_cids)
        }
        other => panic!("unexpected tree_create_cluster response: {other:?}"),
    };

    assert!(matches!(
        call(
            &guard,
            &Request::TreeOpen {
                tree_id: tree_id.clone(),
            }
        ),
        Response::Error { .. }
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
        other => panic!("unexpected tree_list after drop: {other:?}"),
    }

    match call(
        &guard,
        &Request::TreeOpen {
            tree_id: tree_id.clone(),
        },
    ) {
        Response::TreeOpened {
            tree_id: opened,
            root_id: rid,
            nodes,
        } => {
            assert_eq!(opened, tree_id);
            assert_eq!(rid, root_id);
            assert!(!nodes.is_empty(), "opened tree has no nodes");
            assert!(
                nodes.iter().all(|n| n.state == NodeState::Suspended),
                "open() must force Suspended, got {nodes:?}"
            );
        }
        other => panic!("unexpected tree_open response: {other:?}"),
    }

    assert!(matches!(
        call(
            &guard,
            &Request::TreeOpen {
                tree_id: "no-such-tree".to_string(),
            }
        ),
        Response::Error { .. }
    ));

    let bad = guard.tree_root.join("bad-unparse");
    std::fs::create_dir_all(&bad).expect("bad tree dir");
    std::fs::write(bad.join("tree.json"), b"{not-json").expect("bad tree.json");
    match call(
        &guard,
        &Request::TreeOpen {
            tree_id: "bad-unparse".to_string(),
        },
    ) {
        Response::Error { message } => {
            assert!(
                message.contains("tree_open")
                    || message.contains("JSON")
                    || message.contains("json"),
                "unparseable open must be loud, got {message}"
            );
        }
        other => panic!("unparseable tree_open: {other:?}"),
    }
    assert!(
        bad.join("tree.json").is_file(),
        "must not delete an unparseable tree dir"
    );

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
                egress: None,
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
                egress: None,
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
            egress: None,
        },
    ) {
        Response::TreeCreated {
            tree_id,
            root_id,
            guest_cids,
            ..
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
            dilation: None,
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
        backend: k7d::guest::Backend::Native,
        agent_endpoint: Some(k7d::guest::AgentEndpoint::Vsock { cid: 4242 }),
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
    // orphan (no VM in its registry can match). Pin K7D_TREE_ROOT so
    // rehydrate_trees_from_disk does not open leftover trees under
    // /var/lib/k7d/trees and delay the bind past the
    // record-sweep proxy this test used to treat as "ready".
    guard.child = Command::new(env!("CARGO_BIN_EXE_k7d"))
        .arg("--socket")
        .arg(guard.socket.as_os_str())
        .env("RUST_LOG", "info")
        .env("K7D_TREE_ROOT", &guard.tree_root)
        .env("K7D_SANDBOX_ROOT", &guard.sandbox_root)
        .spawn()
        .expect("respawn k7d daemon");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !guard.socket.exists() {
        assert!(
            Instant::now() < deadline,
            "respawned daemon socket never appeared"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
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

/// Inc 2 observer protocol: `tree_watch` streams a snapshot then
/// mutation events; `latency_ns` is on the fork event.
#[test]
fn test_daemon_tree_watch() {
    let _ = env_logger::builder().is_test(true).try_init();
    let guard = spawn_daemon("twatch");

    let (tree_id, root_id, _root_cid) = match call(
        &guard,
        &Request::TreeCreate {
            config: default_config(),
            budget: None,
            tree_id: Some("watch-tree".to_string()),
        },
    ) {
        Response::TreeCreated {
            tree_id,
            root_id,
            guest_cids,
            ..
        } => {
            assert_eq!(guest_cids.len(), 1);
            (tree_id, root_id, guest_cids[0])
        }
        other => panic!("unexpected tree_create response: {other:?}"),
    };

    match call(&guard, &Request::TreeList) {
        Response::TreeList { trees } => {
            assert_eq!(trees.len(), 1);
            assert_eq!(trees[0].usage.live_vm_count, 1);
            assert_eq!(trees[0].budget.max_live_vms, 8);
            assert_eq!(trees[0].kind, "vm");
        }
        other => panic!("unexpected tree_list response: {other:?}"),
    }

    let path = guard.socket.to_str().expect("utf8 socket");
    let mut watch = UnixStream::connect(path).expect("watch connect");
    watch
        .write_all(b"{\"op\":\"tree_watch\",\"tree_id\":\"watch-tree\"}\n")
        .and_then(|()| watch.flush())
        .expect("write tree_watch");
    let mut reader = BufReader::new(watch);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read TreeWatching");
    let snap: Response = serde_json::from_str(line.trim()).expect("parse TreeWatching");
    match snap {
        Response::TreeWatching { trees } => {
            assert_eq!(trees.len(), 1);
            assert_eq!(trees[0].tree_id, "watch-tree");
            assert_eq!(trees[0].usage.live_node_count, 1);
            assert_eq!(trees[0].live_guest_cids.get("root").map(Vec::len), Some(1));
        }
        other => panic!("expected TreeWatching, got {other:?}"),
    }

    let forked = call(
        &guard,
        &Request::TreeFork {
            tree_id: tree_id.clone(),
            source_id: root_id,
            label: "watched".to_string(),
            dilation: None,
        },
    );
    let (node_id, latency_ns) = match forked {
        Response::TreeForked {
            node_id,
            latency_ns,
            ..
        } => (node_id, latency_ns),
        other => panic!("unexpected tree_fork response: {other:?}"),
    };
    assert!(latency_ns > 0);

    line.clear();
    reader.read_line(&mut line).expect("read TreeEvent");
    let ev: Response = serde_json::from_str(line.trim()).expect("parse TreeEvent");
    match ev {
        Response::TreeEvent {
            tree_id: tid,
            op,
            node_id: ev_node,
            latency_ns: ev_lat,
            ..
        } => {
            assert_eq!(tid, "watch-tree");
            assert_eq!(op, "fork");
            assert_eq!(ev_node.as_deref(), Some(node_id.as_str()));
            assert_eq!(ev_lat, Some(latency_ns));
        }
        other => panic!("expected TreeEvent, got {other:?}"),
    }

    assert!(matches!(
        call(&guard, &Request::TreeDrop { tree_id }),
        Response::Ok
    ));
    drop(guard);
}

/// `k7d doctor` must exit without binding a control socket.
#[test]
fn test_doctor_cli_does_not_start_a_daemon() {
    let out = Command::new(env!("CARGO_BIN_EXE_k7d"))
        .arg("doctor")
        .output()
        .expect("run k7d doctor");
    assert!(
        out.status.success(),
        "doctor should exit 0 on this KVM host, got {:?}\nstdout={}\nstderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("kvm"), "missing kvm line: {stdout}");
    assert!(
        stdout.contains("vhost_vsock"),
        "missing vhost_vsock line: {stdout}"
    );
    assert!(stdout.contains("tun"), "missing tun line: {stdout}");
    assert!(
        stdout.contains("cgroup_v2"),
        "missing cgroup_v2 line: {stdout}"
    );
    assert!(
        stdout.contains("doctor: ok"),
        "doctor summary missing: {stdout}"
    );
    assert!(
        !stdout.contains("listening on"),
        "doctor must not start serving, got: {stdout}"
    );
}

/// The `doctor` control verb reports the same four host checks, plus
/// the advisory Firecracker section that must not change
/// `ok`.
#[test]
fn test_doctor_verb_reports_host() {
    let _ = env_logger::builder().is_test(true).try_init();
    let guard = spawn_daemon("doctor");
    match call(&guard, &Request::Doctor) {
        Response::Doctor {
            kvm,
            vhost_vsock,
            tun,
            cgroup_v2,
            ok,
            fc_fork_mode,
            details,
        } => {
            assert!(kvm, "kvm");
            assert!(vhost_vsock, "vhost_vsock");
            assert!(tun, "tun");
            assert!(cgroup_v2, "cgroup_v2");
            assert!(ok, "ok");
            let expected_mode =
                std::env::var("K7D_FC_FORK_SNAPSHOT").unwrap_or_else(|_| "diff".to_string());
            assert_eq!(fc_fork_mode, expected_mode, "FC fork mode");
            let host: Vec<&String> = details.iter().filter(|d| !d.contains("  fc_")).collect();
            assert_eq!(host.len(), 4, "{details:?}");
            // A node with no Firecracker installed is still a healthy
            // node, so the backend's lines are reported but never
            // decide `ok`.
            assert!(
                details.iter().any(|d| d.contains("  fc_firecracker  ")),
                "doctor must report the Firecracker backend: {details:?}"
            );
        }
        other => panic!("unexpected doctor response: {other:?}"),
    }
}

/// Five-minute try path: busybox 3-node tree + 4 CoW forks, clocks printed.
#[test]
fn test_quickstart_busybox_four_forks() {
    let _ = env_logger::builder().is_test(true).try_init();
    let guard = spawn_daemon("qstart");
    let mut client = k7d::control::Client::connect(guard.socket.to_str().expect("utf8 socket"))
        .expect("connect");
    let kernel = workspace_path("guest/kernel/vmlinux");
    let initrd = workspace_path("guest/rootfs/initramfs.cpio.gz");
    let tree_id = format!("qs-test-{}", std::process::id());
    let clocks = k7d::quickstart::run_busybox_demo(
        &mut client,
        &tree_id,
        4,
        false,
        Some(kernel.to_str().expect("utf8 kernel")),
        Some(initrd.to_str().expect("utf8 initrd")),
    )
    .expect("quickstart demo");
    assert_eq!(clocks.branches.len(), 4, "{clocks:?}");
    assert!(
        clocks.create_ms > 0,
        "create wall-clock must be measured: {}",
        clocks.create_ms
    );
    assert!(
        clocks.fork_ms > 0,
        "fork wall-clock must be measured: {}",
        clocks.fork_ms
    );
    assert!(
        clocks.fork_daemon_ms > 0,
        "daemon fork latency must be measured: {}",
        clocks.fork_daemon_ms
    );
    assert!(!clocks.kept);
    k7d::quickstart::print_clocks(&clocks);
}

/// On stock modules: `dilation: Some(8)` is refused
/// naming the patch, `Some(0)` is refused, `None` / `Some(1)` inherit
/// the undilated source.
#[test]
fn test_daemon_tree_fork_dilation_override_on_stock_host() {
    let _ = env_logger::builder().is_test(true).try_init();
    let guard = spawn_daemon("dild0");

    let (tree_id, root_id, _root_cid) = match call(
        &guard,
        &Request::TreeCreate {
            config: default_config(),
            budget: None,
            tree_id: Some("dild0".to_string()),
        },
    ) {
        Response::TreeCreated {
            tree_id,
            root_id,
            guest_cids,
            ..
        } => (tree_id, root_id, guest_cids[0]),
        other => panic!("unexpected tree_create: {other:?}"),
    };

    match call(
        &guard,
        &Request::TreeFork {
            tree_id: tree_id.clone(),
            source_id: root_id.clone(),
            label: "zero".to_string(),
            dilation: Some(0),
        },
    ) {
        Response::Error { message } => {
            assert!(
                message.contains("dilation 0"),
                "dilation 0 must be a loud error, got {message}"
            );
        }
        other => panic!("dilation: Some(0) must be an error, got {other:?}"),
    }

    match call(
        &guard,
        &Request::TreeFork {
            tree_id: tree_id.clone(),
            source_id: root_id.clone(),
            label: "x8".to_string(),
            dilation: Some(8),
        },
    ) {
        Response::Error { message } => {
            assert!(
                message.contains("utils/kvm-dilation"),
                "stock host must name the patch, got {message}"
            );
        }
        other => panic!("dilation: Some(8) on stock must be an error, got {other:?}"),
    }

    match call(
        &guard,
        &Request::TreeFork {
            tree_id: tree_id.clone(),
            source_id: root_id.clone(),
            label: "one".to_string(),
            dilation: Some(1),
        },
    ) {
        Response::TreeForked { dilation, .. } => {
            assert_eq!(dilation, 1);
        }
        other => panic!("dilation: Some(1) must succeed, got {other:?}"),
    }

    match call(
        &guard,
        &Request::TreeFork {
            tree_id: tree_id.clone(),
            source_id: root_id,
            label: "inherit".to_string(),
            dilation: None,
        },
    ) {
        Response::TreeForked { dilation, .. } => {
            assert_eq!(dilation, 1);
        }
        other => panic!("dilation: None must inherit, got {other:?}"),
    }

    assert!(matches!(
        call(&guard, &Request::TreeDrop { tree_id }),
        Response::Ok
    ));
}
