//! Integration test: the warm VM pool.
//!
//! Spawns the real `k7d` binary with `K7D_POOL_SIZE` set, waits for the
//! background filler to pre-warm the pool, and proves:
//! * a pool-compatible `create_vm` is served from the pool
//!   (`pooled: true`) within [`k7d::latency::POOL_ACQUIRE`], with a
//!   live agent and full sandbox persistence;
//! * the pool refills in the background after an acquire;
//! * an incompatible request cold-boots (`pooled: false`) and still
//!   works;
//! * a daemon without `K7D_POOL_SIZE` has no pool and cold-boots
//!   everything, exactly as it did before the pool existed.

use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use k7d::api::AgentClient;
use k7d::control::{Client, Request, Response, VmConfig};

fn workspace_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join(relative)
}

fn kernel_path() -> PathBuf {
    let p = workspace_path("guest/kernel/vmlinux");
    assert!(p.exists(), "guest kernel not found at {p:?}");
    p
}

fn initrd_path() -> PathBuf {
    let p = workspace_path("guest/rootfs/initramfs.cpio.gz");
    assert!(p.exists(), "initramfs not found at {p:?}");
    p
}

/// Kills the daemon child on drop so a panicking assertion can't leak
/// the process (and its VMs, pool included).
struct DaemonGuard {
    child: Child,
    socket: PathBuf,
    sandbox_root: PathBuf,
    tree_root: PathBuf,
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_dir_all(&self.sandbox_root);
        let _ = std::fs::remove_dir_all(&self.tree_root);
    }
}

/// Spawn a fresh daemon on a per-test socket with `K7D_KERNEL` /
/// `K7D_INITRD` set (the pool template resolves them from env) plus
/// any extra `envs`, and wait for the control socket to bind.
fn spawn_daemon(tag: &str, envs: &[(&str, &str)]) -> DaemonGuard {
    let pid = std::process::id();
    let socket = std::env::temp_dir().join(format!("k7d-pool-{tag}-{pid}.sock"));
    let sandbox_root = std::env::temp_dir().join(format!("k7d-pool-sandboxes-{tag}-{pid}"));
    let tree_root = std::env::temp_dir().join(format!("k7d-pool-trees-{tag}-{pid}"));
    let _ = std::fs::remove_file(&socket);

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_k7d"));
    cmd.arg("--socket")
        .arg(&socket)
        .env("RUST_LOG", "info")
        .env("K7D_KERNEL", kernel_path())
        .env("K7D_INITRD", initrd_path())
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

/// Pool-compatible request: vsock-only, no shares, no network, same
/// kernel/initrd/memory as the pool template.
fn pool_config() -> VmConfig {
    VmConfig {
        kernel: Some(kernel_path().to_string_lossy().into_owned()),
        initrd: Some(initrd_path().to_string_lossy().into_owned()),
        // Default: 256 MB, 1 vCPU, uncapped, vsock on.
        ..VmConfig::default()
    }
}

fn pool_status(guard: &DaemonGuard) -> (usize, usize, u64, u64) {
    match call(guard, &Request::PoolStatus) {
        Response::PoolStatus {
            size,
            idle,
            hits,
            misses,
        } => (size, idle, hits, misses),
        other => panic!("unexpected pool_status response: {other:?}"),
    }
}

/// Poll `pool_status` until `idle == want` (template boot + prepare +
/// fork are all background work, so this is the pre-warm barrier).
fn wait_for_idle(guard: &DaemonGuard, want: usize) {
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let (_, idle, _, _) = pool_status(guard);
        if idle == want {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "pool never reached {want} idle VMs (currently {idle})"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// `create_vm` returning `(vm_id, guest_cid, pooled)`.
fn create_vm(guard: &DaemonGuard, config: VmConfig) -> (String, u64, bool) {
    match call(guard, &Request::CreateVm { config }) {
        Response::VmCreated {
            vm_id,
            guest_cid,
            pooled,
            ..
        } => (vm_id, guest_cid, pooled),
        other => panic!("unexpected create_vm response: {other:?}"),
    }
}

fn stop_vm(guard: &DaemonGuard, vm_id: String) {
    assert!(matches!(
        call(guard, &Request::StopVm { vm_id }),
        Response::Ok
    ));
}

/// Ping a guest agent over vsock, proving the VM is alive and ready.
fn ping_agent(guest_cid: u64) {
    let mut agent = AgentClient::connect_vsock(guest_cid, Duration::from_secs(30))
        .expect("connect guest agent over vsock");
    agent.ping().expect("agent ping");
}

/// The pool pre-warms to target in the
/// background, and a pool-compatible `create_vm` (carrying a
/// sandbox_id — reattach persistence must work identically for
/// pooled VMs) returns `pooled: true` within `POOL_ACQUIRE` with a
/// live, agent-ready guest.
#[test]
fn test_pool_fills_and_acquire_is_fast() {
    let _ = env_logger::builder().is_test(true).try_init();
    let guard = spawn_daemon("fast", &[("K7D_POOL_SIZE", "2")]);

    let (size, _, _, _) = pool_status(&guard);
    assert_eq!(size, 2, "pool target must reflect K7D_POOL_SIZE");
    wait_for_idle(&guard, 2);

    let sandbox_id = "sb-pooled";
    let mut config = pool_config();
    config.sandbox_id = Some(sandbox_id.to_string());

    let start = Instant::now();
    let (vm_id, guest_cid, pooled) = create_vm(&guard, config);
    let elapsed = start.elapsed();
    eprintln!("pooled create_vm round-trip: {elapsed:?}");
    assert!(pooled, "pool was full — the request must be served from it");
    assert!(
        elapsed < k7d::latency::POOL_ACQUIRE,
        "pooled create_vm should be <{:?}, was {elapsed:?}",
        k7d::latency::POOL_ACQUIRE,
    );

    // The pooled VM is agent-ready right now — no boot wait.
    ping_agent(guest_cid);

    // Reattach bookkeeping is identical to cold boot: on-disk
    // record + lookup, both erased by stop_vm.
    let record_path = guard.sandbox_root.join(format!("{sandbox_id}.json"));
    assert!(
        record_path.exists(),
        "pooled create must persist the sandbox record"
    );
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
    stop_vm(&guard, vm_id);
    assert!(
        !record_path.exists(),
        "stop_vm must remove the pooled VM's sandbox record"
    );

    drop(guard);
}

/// After an acquire the pool refills to target
/// in the background, and the hit/miss counters are loud about what
/// happened.
#[test]
fn test_pool_refills_in_background() {
    let _ = env_logger::builder().is_test(true).try_init();
    let guard = spawn_daemon("refill", &[("K7D_POOL_SIZE", "1")]);
    wait_for_idle(&guard, 1);

    let (vm_a, cid_a, pooled) = create_vm(&guard, pool_config());
    assert!(pooled, "first acquire must hit the warm pool");
    ping_agent(cid_a);

    // Background refill returns idle to target without any client call.
    wait_for_idle(&guard, 1);
    let (_, _, hits, misses) = pool_status(&guard);
    assert_eq!(hits, 1, "one pool hit so far");
    assert_eq!(misses, 0, "no misses: every request was compatible");

    // The refilled VM is just as acquirable.
    let (vm_b, cid_b, pooled) = create_vm(&guard, pool_config());
    assert!(pooled, "refilled VM must serve the next request");
    assert_ne!(cid_a, cid_b, "each pooled VM has its own CID");
    ping_agent(cid_b);
    let (_, _, hits, _) = pool_status(&guard);
    assert_eq!(hits, 2);

    stop_vm(&guard, vm_a);
    stop_vm(&guard, vm_b);
    drop(guard);
}

/// A pool-incompatible request (different
/// memory size) bypasses the pool, cold-boots, still works — and the
/// pool is untouched (idle count unchanged, miss counted).
#[test]
fn test_pool_miss_falls_back_to_cold_boot() {
    let _ = env_logger::builder().is_test(true).try_init();
    let guard = spawn_daemon("miss", &[("K7D_POOL_SIZE", "1")]);
    wait_for_idle(&guard, 1);

    let mut config = pool_config();
    config.memory_mb = 128; // template is 256 — incompatible
    let (vm_id, guest_cid, pooled) = create_vm(&guard, config);
    assert!(
        !pooled,
        "incompatible request must not be served from the pool"
    );
    ping_agent(guest_cid);

    let (_, idle, hits, misses) = pool_status(&guard);
    assert_eq!(idle, 1, "the idle warm VM must not have been consumed");
    assert_eq!(hits, 0);
    assert_eq!(misses, 1, "the incompatible request counts as a miss");

    stop_vm(&guard, vm_id);
    drop(guard);
}

/// A pool prefilled with `K7D_POOL_VCPUS=2` serves a
/// `vcpus: 2` request from the pool and misses a `vcpus: 1` request;
/// the default (1-vCPU) pool does the mirror image. The pooled 2-vCPU
/// VM's guest must actually see 2 CPUs.
#[test]
fn test_pool_multi_vcpu_config() {
    let _ = env_logger::builder().is_test(true).try_init();

    // 2-vCPU pool: vcpus:2 hits, vcpus:1 (the default config) misses.
    {
        let guard = spawn_daemon("smp", &[("K7D_POOL_SIZE", "1"), ("K7D_POOL_VCPUS", "2")]);
        wait_for_idle(&guard, 1);

        let mut config = pool_config();
        config.vcpus = 2;
        let (vm_id, guest_cid, pooled) = create_vm(&guard, config);
        assert!(pooled, "vcpus:2 request must hit the 2-vCPU pool");
        let mut agent = AgentClient::connect_vsock(guest_cid, Duration::from_secs(30))
            .expect("connect pooled 2-vCPU guest");
        let nproc = agent
            .exec(&["sh", "-c", "grep -c ^processor /proc/cpuinfo"])
            .expect("cpu count");
        assert_eq!(nproc.stdout.trim(), "2", "pooled guest must see 2 CPUs");
        stop_vm(&guard, vm_id);

        wait_for_idle(&guard, 1);
        let (vm_id, guest_cid, pooled) = create_vm(&guard, pool_config());
        assert!(!pooled, "vcpus:1 request must miss the 2-vCPU pool");
        ping_agent(guest_cid);
        let (_, idle, hits, misses) = pool_status(&guard);
        assert_eq!(idle, 1, "the idle 2-vCPU warm VM must not be consumed");
        assert_eq!((hits, misses), (1, 1));
        stop_vm(&guard, vm_id);
        drop(guard);
    }

    // Default (1-vCPU) pool: vcpus:2 misses.
    {
        let guard = spawn_daemon("smpdef", &[("K7D_POOL_SIZE", "1")]);
        wait_for_idle(&guard, 1);

        let mut config = pool_config();
        config.vcpus = 2;
        let (vm_id, guest_cid, pooled) = create_vm(&guard, config);
        assert!(!pooled, "vcpus:2 request must miss the default 1-vCPU pool");
        ping_agent(guest_cid);
        let (_, idle, hits, misses) = pool_status(&guard);
        assert_eq!(idle, 1);
        assert_eq!((hits, misses), (0, 1));
        stop_vm(&guard, vm_id);
        drop(guard);
    }
}

/// Without `K7D_POOL_SIZE` there is no pool —
/// `pool_status` reports size 0 and `create_vm` cold-boots exactly as
/// it did before the pool existed (no counters move, `pooled: false`).
#[test]
fn test_pool_disabled_by_default() {
    let _ = env_logger::builder().is_test(true).try_init();
    let guard = spawn_daemon("off", &[]);

    assert_eq!(pool_status(&guard), (0, 0, 0, 0), "no pool by default");

    let (vm_id, guest_cid, pooled) = create_vm(&guard, pool_config());
    assert!(!pooled, "disabled pool must cold-boot");
    ping_agent(guest_cid);
    assert_eq!(
        pool_status(&guard),
        (0, 0, 0, 0),
        "a disabled pool counts nothing"
    );

    stop_vm(&guard, vm_id);
    drop(guard);
}
