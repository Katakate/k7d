//! Integration tests: snapshot trees on Firecracker nodes —
//! `tree_create`, `prepare_fork_source`, `fork_batch`,
//! `rollback`, `prune` against `backend: firecracker`, through the
//! daemon API.
//!
//! What is being proved is not "Firecracker can snapshot" but that a
//! fork here is a **fork** in the sense the native backend means it:
//! children are live within the latency budget, their memory is
//! copy-on-write of the parent's restore point (`FIEMAP`, not `du`),
//! the disk they see is the disk as of the same paused instant as the
//! memory, nothing written on one side after the point is visible on
//! the other, and the source's own agent connection survives the vsock
//! reset every `PUT /snapshot/create` causes.
//!
//! The whole suite runs twice: once in the default `diff` mode and
//! once with `K7D_FC_FORK_SNAPSHOT=full`, because the two produce the
//! same `restore-N.mem` by different means and only the tests say so.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use k7d::api::AgentClient;
use k7d::control::{BlockDeviceConfig, Client, Request, Response, VmConfig};
use k7d::fc::snapshot::{extent_sharing, is_cow};
use k7d::guest::{AgentEndpoint, Backend};
use k7d::tree::TreeBudget;

/// A forked child must answer `ping` this soon after `fork_batch`
/// returns.
const CHILD_READY: Duration = Duration::from_millis(500);

/// Per-child wall-time ceiling for a batch fork (spec: < 500 ms each,
/// target 100–300 ms).
const PER_CHILD_BUDGET: Duration = Duration::from_millis(500);

/// Guest RAM of every tree here. Small enough that eleven live
/// children fit the node comfortably, large enough that a full copy
/// instead of a reflink would show in the numbers.
const GUEST_MB: u64 = 256;

/// Where the guest mounts its writable disk.
const DISK_MOUNT: &str = "/mnt/d";

fn workspace_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join(relative)
}

/// Drops every tree it created and then kills the daemon, so a failing
/// assertion cannot leak a tree of jailed Firecracker processes into
/// the next test. The order matters: a jailed VMM is **not** the
/// daemon's child (the jailer `clone`s and exits), so `kill -9` on the
/// daemon alone leaves every VM of every tree running until reboot
/// (CHALLENGES #223) — the drop has to go through the API while the
/// daemon is still there to run `FcVm::drop`.
struct DaemonGuard {
    child: Child,
    socket: PathBuf,
    sandbox_root: PathBuf,
    tree_root: PathBuf,
    disk_dir: PathBuf,
    trees: std::cell::RefCell<Vec<String>>,
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
        // SIGTERM so shutdown_all drops any jailed VMM TreeDrop raced
        // (CHALLENGES #223, #226). SIGKILL leaves the jailer orphaned.
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
        // Let KVM reclaim slots after jailer teardown before the next
        // binary (`test_fork` follows this one in `make check`).
        std::thread::sleep(Duration::from_millis(300));
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_dir_all(&self.sandbox_root);
        let _ = std::fs::remove_dir_all(&self.tree_root);
        let _ = std::fs::remove_dir_all(&self.disk_dir);
    }
}

/// Spawn a private daemon. `fork_mode` is `K7D_FC_FORK_SNAPSHOT`; the
/// test binary's own environment is deliberately *not* inherited for
/// that variable, so `make remote-check` with it set still runs both
/// halves of the suite as named.
fn spawn_daemon(tag: &str, fork_mode: Option<&str>) -> DaemonGuard {
    common::ensure_firecracker_installed();
    let pid = std::process::id();
    let socket = std::env::temp_dir().join(format!("k7d-fct-{tag}-{pid}.sock"));
    let sandbox_root = std::env::temp_dir().join(format!("k7d-fct-sandboxes-{tag}-{pid}"));
    let tree_root = std::env::temp_dir().join(format!("k7d-fct-trees-{tag}-{pid}"));
    // Writable disks must live on the jail's filesystem (the reflink
    // XFS) — the staging is a hard link plus, at every point, a reflink.
    let disk_dir = Path::new(k7d::disks::DISKS_DIR).join(format!("fct-{tag}-{pid}"));
    let _ = std::fs::remove_file(&socket);
    std::fs::create_dir_all(&disk_dir).expect("create the test disk dir on the reflink XFS");

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
        .env("K7D_TREE_ROOT", &tree_root)
        .env_remove("K7D_FC_FORK_SNAPSHOT");
    if let Some(mode) = fork_mode {
        cmd.env("K7D_FC_FORK_SNAPSHOT", mode);
    }
    let child = cmd.spawn().expect("spawn k7d daemon");
    let guard = DaemonGuard {
        child,
        socket,
        sandbox_root,
        tree_root,
        disk_dir,
        trees: std::cell::RefCell::new(Vec::new()),
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

/// A raw ext4 image of `mb` MiB in the daemon's test disk dir.
fn make_ext4_image(guard: &DaemonGuard, name: &str, mb: u64) -> PathBuf {
    let img = guard.disk_dir.join(name);
    let f = std::fs::File::create(&img).unwrap();
    f.set_len(mb * 1024 * 1024).unwrap();
    drop(f);
    let out = Command::new("mkfs.ext4")
        .args(["-F", "-q"])
        .arg(&img)
        .output()
        .expect("mkfs.ext4 should be installed on the node");
    assert!(
        out.status.success(),
        "mkfs.ext4 failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    img
}

fn budget() -> TreeBudget {
    TreeBudget {
        // Root + children, without asking the tree to evict.
        max_live_vms: 16,
        ..k7d::control::default_tree_budget()
    }
}

/// `tree_create` on Firecracker with one writable ext4 disk; returns
/// `(tree_id, root agent endpoint)`.
fn create_tree(guard: &DaemonGuard, tag: &str) -> (String, AgentEndpoint) {
    let disk = make_ext4_image(guard, &format!("{tag}.ext4"), 64);
    let config = VmConfig {
        memory_mb: GUEST_MB,
        vcpus: 1,
        backend: Backend::Firecracker,
        block_devices: vec![BlockDeviceConfig {
            host_path: disk.to_string_lossy().into_owned(),
            readonly: false,
            guest_mount: Some(DISK_MOUNT.to_string()),
            fstype: Some("ext4".to_string()),
        }],
        ..VmConfig::default()
    };
    match call(
        guard,
        &Request::TreeCreate {
            config,
            budget: Some(budget()),
            tree_id: Some(common::unique_name(&format!("fct-{tag}"))),
        },
    ) {
        Response::TreeCreated {
            tree_id,
            guest_cids,
            mut agent_endpoints,
            ..
        } => {
            assert!(
                guest_cids.is_empty(),
                "a Firecracker root has no AF_VSOCK CID, got {guest_cids:?}"
            );
            assert_eq!(agent_endpoints.len(), 1, "{agent_endpoints:?}");
            let ep = agent_endpoints.remove(0);
            assert!(matches!(ep, AgentEndpoint::FcUds { .. }), "{ep:?}");
            guard.trees.borrow_mut().push(tree_id.clone());
            (tree_id, ep)
        }
        other => panic!("tree_create on Firecracker: {other:?}"),
    }
}

fn agent(ep: &AgentEndpoint, timeout: Duration) -> AgentClient {
    AgentClient::connect_endpoint(ep, timeout)
        .unwrap_or_else(|e| panic!("connect agent at {ep:?}: {e}"))
}

/// Run `cmd` through the guest's `sh`, returning stdout and asserting
/// exit 0 — a marker that failed to be written must not read as
/// "absent".
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

/// Whether `path` exists in the guest.
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

/// Write `text` to `path` in the guest and flush it to the disk, so
/// the disk clone at the next point carries it independently of the
/// (also snapshotted) page cache.
fn write_marker(a: &mut AgentClient, path: &str, text: &str) {
    sh(a, &format!("echo {text} > {path} && sync"));
}

/// `<base>/<exec>/<vm_id>` for the VM behind `ep` — the directory
/// whose `snap/` holds k7d's root-owned point files.
fn vm_dir_of(ep: &AgentEndpoint) -> PathBuf {
    let AgentEndpoint::FcUds { path } = ep else {
        panic!("not a Firecracker endpoint: {ep:?}");
    };
    // <vm_dir>/root/run/v.sock
    Path::new(path)
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .expect("v.sock lives at <vm_dir>/root/run/v.sock")
        .to_path_buf()
}

/// The current `restore-N.mem` of a fork source.
fn restore_mem_of(vm_dir: &Path) -> PathBuf {
    let snap = vm_dir.join(k7d::fc::stage::SNAP_SUBDIR);
    let mut found: Vec<PathBuf> = std::fs::read_dir(&snap)
        .unwrap_or_else(|e| panic!("read {}: {e}", snap.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("restore-"))
        })
        .collect();
    assert_eq!(
        found.len(),
        1,
        "exactly one restore point is kept per source, found {found:?}"
    );
    found.remove(0)
}

fn fork_batch(
    guard: &DaemonGuard,
    tree_id: &str,
    source: &str,
    labels: &[&str],
) -> (Vec<(String, AgentEndpoint)>, Duration) {
    match call(
        guard,
        &Request::TreeForkBatch {
            tree_id: tree_id.to_string(),
            source_id: source.to_string(),
            labels: labels.iter().map(ToString::to_string).collect(),
            dilation: None,
        },
    ) {
        Response::TreeForkBatch {
            forks, latency_ns, ..
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
                    assert_eq!(f.agent_endpoints.len(), 1, "{f:?}");
                    (f.node_id, f.agent_endpoints[0].clone())
                })
                .collect();
            (out, Duration::from_nanos(latency_ns))
        }
        other => panic!("tree_fork_batch {labels:?}: {other:?}"),
    }
}

fn rollback(
    guard: &DaemonGuard,
    tree_id: &str,
    node: &str,
    label: &str,
) -> (String, AgentEndpoint, Duration) {
    match call(
        guard,
        &Request::TreeRollback {
            tree_id: tree_id.to_string(),
            node_id: node.to_string(),
            label: label.to_string(),
        },
    ) {
        Response::TreeForked {
            node_id,
            mut agent_endpoints,
            fork_memory_full_copy,
            latency_ns,
            ..
        } => {
            assert!(fork_memory_full_copy.iter().all(|c| !c), "{node_id}");
            assert_eq!(agent_endpoints.len(), 1);
            (
                node_id,
                agent_endpoints.remove(0),
                Duration::from_nanos(latency_ns),
            )
        }
        other => panic!("tree_rollback {node}: {other:?}"),
    }
}

fn prepare(guard: &DaemonGuard, tree_id: &str, node: &str) -> (bool, u64, Duration) {
    match call(
        guard,
        &Request::TreePrepareForkSource {
            tree_id: tree_id.to_string(),
            node_id: node.to_string(),
        },
    ) {
        Response::TreePrepared {
            wrote_base,
            base_disk_bytes,
            latency_ns,
            ..
        } => (
            wrote_base,
            base_disk_bytes,
            Duration::from_nanos(latency_ns),
        ),
        other => panic!("tree_prepare_fork_source {node}: {other:?}"),
    }
}

/// Connect + `ping` each child, asserting the spec's readiness budget.
fn assert_children_ready(children: &[(String, AgentEndpoint)]) -> Vec<Duration> {
    let returned = Instant::now();
    children
        .iter()
        .map(|(id, ep)| {
            let mut a = agent(ep, CHILD_READY);
            a.ping().unwrap_or_else(|e| panic!("ping {id}: {e}"));
            let took = returned.elapsed();
            assert!(
                took < CHILD_READY,
                "{id} answered ping {took:?} after fork_batch returned (budget {CHILD_READY:?})"
            );
            took
        })
        .collect()
}

/// The child's memory is a reflink of the parent's restore point: every
/// allocated extent of its `load.mem` is shared, and what it owns
/// exclusively is nowhere near guest RAM. `du` cannot say this — a
/// reflinked file's `st_blocks` reads as the whole file
/// (CHALLENGES #152) — so the check is `FIEMAP`'s per-extent flag.
fn assert_memory_cow(child_ep: &AgentEndpoint, parent_restore: &Path) {
    let load = vm_dir_of(child_ep)
        .join(k7d::fc::stage::SNAP_SUBDIR)
        .join("load.mem");
    assert!(load.is_file(), "{} missing", load.display());
    assert_eq!(
        std::fs::metadata(&load).unwrap().len(),
        std::fs::metadata(parent_restore).unwrap().len(),
        "load.mem and the parent's restore point differ in size"
    );
    assert!(
        is_cow(&load).unwrap(),
        "{} shares no extents with {} — a copy, not copy-on-write",
        load.display(),
        parent_restore.display()
    );
    let (shared, exclusive) = extent_sharing(&load).unwrap();
    let (p_shared, _) = extent_sharing(parent_restore).unwrap();
    assert!(
        shared > 0 && p_shared > 0,
        "neither side reports shared extents (child {shared}, parent {p_shared})"
    );
    assert!(
        exclusive * 16 < GUEST_MB * 1024 * 1024,
        "child owns {exclusive} exclusive bytes of a {GUEST_MB} MiB guest — not CoW"
    );
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

// ── The suite, run per fork mode ─────────────────────────────────────

#[allow(clippy::too_many_lines)]
fn fork_suite(mode: Option<&str>) {
    let tag = mode.unwrap_or("diff");
    let guard = spawn_daemon(tag, mode);
    let (tree_id, root_ep) = create_tree(&guard, tag);
    let root_dir = vm_dir_of(&root_ep);

    // This connection predates every point the tree will take; every
    // one of them resets it. The caller must never notice.
    let mut root = agent(&root_ep, Duration::from_secs(10));
    assert!(
        present(&mut root, DISK_MOUNT),
        "disk not mounted at {DISK_MOUNT}"
    );
    write_marker(&mut root, &format!("{DISK_MOUNT}/pre-fork"), "pre");
    write_marker(&mut root, "/tmp/pre-fork", "pre");

    // 1. fork_batch a, b — live within budget.
    let (children, batch) = fork_batch(&guard, &tree_id, "root", &["a", "b"]);
    let ready = assert_children_ready(&children);
    let per_child = batch / 2;
    println!(
        "FC-LATENCY mode={tag} fork n=2: batch {batch:?}, per child {per_child:?}, \
         ping after return {ready:?}"
    );
    // The per-child ceiling is the Diff mechanism's. A Full point
    // writes the whole guest RAM on every fork by design (0.6–1.0 s
    // for 256 MiB, load-dependent); the mode exists to cross-check
    // the Diff path's restore image, not to meet its budget, so in
    // `full` the number is recorded and not asserted (LATENCY_BUDGETS).
    if mode.is_none() {
        assert!(
            per_child < PER_CHILD_BUDGET,
            "fork_batch n=2 took {batch:?} ({per_child:?} per child)"
        );
    }
    let (a_id, a_ep) = &children[0];
    let (b_id, b_ep) = &children[1];
    let mut a = agent(a_ep, Duration::from_secs(5));
    let mut b = agent(b_ep, Duration::from_secs(5));

    // 2. CoW.
    let restore = restore_mem_of(&root_dir);
    assert_memory_cow(a_ep, &restore);
    assert_memory_cow(b_ep, &restore);

    // 3. Same instant: written on the source before the fork, on disk
    //    and in memory, visible on both children.
    for (who, c) in [("a", &mut a), ("b", &mut b)] {
        assert!(
            present(c, &format!("{DISK_MOUNT}/pre-fork")),
            "{who}: disk write from before the fork is missing — the disk clone is \
             not from the paused instant"
        );
        assert!(present(c, "/tmp/pre-fork"), "{who}: memory state lost");
    }

    // 4. Isolation between siblings and against the source.
    write_marker(&mut a, &format!("{DISK_MOUNT}/a-only"), "a");
    write_marker(&mut a, "/tmp/a-only", "a");
    // 5. Parent reconnect: this is the pre-fork connection, on which
    //    Firecracker closed the vsock at the point. Nothing was done
    //    to it.
    assert_eq!(root.fc_reconnects(), 0);
    write_marker(&mut root, &format!("{DISK_MOUNT}/root-after"), "after");
    write_marker(&mut root, "/tmp/root-after", "after");
    assert!(
        root.fc_reconnects() >= 1,
        "the source's pre-fork agent connection was never reset by the snapshot — \
         the reconnect path this test exists to prove did not run"
    );
    for path in ["a-only"] {
        assert!(
            !present(&mut b, &format!("{DISK_MOUNT}/{path}")),
            "b sees a's disk write"
        );
        assert!(
            !present(&mut b, &format!("/tmp/{path}")),
            "b sees a's memory"
        );
        assert!(
            !present(&mut root, &format!("{DISK_MOUNT}/{path}")),
            "source sees a's disk write — the child writes into the source's disk"
        );
        assert!(!present(&mut root, &format!("/tmp/{path}")));
    }
    for (who, c) in [("a", &mut a), ("b", &mut b)] {
        assert!(
            !present(c, &format!("{DISK_MOUNT}/root-after")),
            "{who} sees a disk write the source made after the fork"
        );
        assert!(
            !present(c, "/tmp/root-after"),
            "{who} sees post-fork source memory"
        );
    }
    assert!(present(&mut a, &format!("{DISK_MOUNT}/a-only")));

    // 6. Prune a: the jailed process and its chroot are gone, b is not.
    let a_dir = vm_dir_of(a_ep);
    let a_pid = firecracker_pid(&a_dir);
    assert!(matches!(
        call(
            &guard,
            &Request::TreePrune {
                tree_id: tree_id.clone(),
                node_id: a_id.clone(),
            },
        ),
        Response::Ok
    ));
    let deadline = Instant::now() + Duration::from_secs(10);
    while k7d::fc::process_alive(a_pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        !k7d::fc::process_alive(a_pid),
        "pruned {a_id}'s Firecracker {a_pid} lives"
    );
    assert!(
        !a_dir.exists(),
        "pruned {a_id}'s chroot {} remains",
        a_dir.display()
    );
    b.ping().expect("b still answers after a was pruned");
    root.ping().expect("root still answers after a was pruned");

    match call(
        &guard,
        &Request::TreeNodes {
            tree_id: tree_id.clone(),
        },
    ) {
        Response::TreeNodeList {
            nodes,
            live_agent_endpoints,
            live_guest_cids,
            ..
        } => {
            let ids: Vec<&str> = nodes.iter().map(|n| n.id.as_str()).collect();
            assert_eq!(nodes.len(), 2, "{ids:?}");
            assert!(!ids.contains(&a_id.as_str()), "{ids:?}");
            assert!(
                live_agent_endpoints.contains_key(b_id),
                "{live_agent_endpoints:?}"
            );
            assert!(
                live_guest_cids.values().all(Vec::is_empty),
                "Firecracker nodes have no CIDs: {live_guest_cids:?}"
            );
        }
        other => panic!("tree_nodes: {other:?}"),
    }
    drop(guard);
}

#[test]
fn test_fc_tree_fork_cow_isolation_diff() {
    fork_suite(None);
}

#[test]
fn test_fc_tree_fork_cow_isolation_full() {
    fork_suite(Some("full"));
}

// ── Rollback, clock_realtime, prepare idempotence ────────────────────

/// `rollback` yields the **point**, not the source: a marker written
/// after `prepare_fork_source` is absent on the rolled-back child, and
/// a child loaded from a point taken 30 s ago wakes up with the host's
/// wall clock (`clock_realtime`), not the point's.
#[test]
fn test_fc_tree_rollback_is_the_point_and_clock_is_realtime() {
    let guard = spawn_daemon("rollback", None);
    let (tree_id, root_ep) = create_tree(&guard, "rollback");
    let mut root = agent(&root_ep, Duration::from_secs(10));

    write_marker(&mut root, &format!("{DISK_MOUNT}/before-point"), "before");
    write_marker(&mut root, "/tmp/before-point", "before");
    let (wrote, bytes, took) = prepare(&guard, &tree_id, "root");
    assert!(
        wrote,
        "the source dirtied pages; the point must be re-taken"
    );
    assert!(bytes > 0, "a point costs its diff's data bytes, got 0");
    println!("FC-LATENCY prepare: {took:?} ({bytes} bytes)");

    // Nothing dirtied between two prepares is the one idempotent case
    // — and only in diff mode is it detectable; this daemon is in diff.
    let (wrote_again, _, again) = prepare(&guard, &tree_id, "root");
    println!("FC-LATENCY prepare (unchanged): {again:?} wrote={wrote_again}");

    write_marker(&mut root, &format!("{DISK_MOUNT}/after-point"), "after");
    write_marker(&mut root, "/tmp/after-point", "after");

    // The point ages 30 s while the source keeps running.
    std::thread::sleep(Duration::from_secs(30));

    let (child_id, child_ep, took) = rollback(&guard, &tree_id, "root", "again");
    println!("FC-LATENCY rollback: {took:?}");
    assert!(took < PER_CHILD_BUDGET, "rollback took {took:?}");
    let mut child = agent(&child_ep, CHILD_READY);
    let host_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    let guest_now: f64 = sh(&mut child, "date +%s")
        .trim()
        .parse()
        .expect("guest date +%s");
    let skew = (guest_now - host_now).abs();
    assert!(
        skew <= 1.5,
        "rolled-back {child_id} wall clock is {skew:.1}s off the host — clock_realtime \
         did not take (a 30 s-old point would read ≈30 s behind)"
    );

    assert!(present(&mut child, &format!("{DISK_MOUNT}/before-point")));
    assert!(present(&mut child, "/tmp/before-point"));
    assert!(
        !present(&mut child, &format!("{DISK_MOUNT}/after-point")),
        "{child_id} sees a disk write made after the point — rollback forked the \
         source, not the point"
    );
    assert!(
        !present(&mut child, "/tmp/after-point"),
        "{child_id} sees memory from after the point"
    );
    // The source itself is unchanged by the rollback.
    assert!(present(&mut root, "/tmp/after-point"));

    // A point on the child: it was loaded, so its first Diff is applied
    // onto a reflink of what it loaded. Its child must see both layers.
    write_marker(&mut child, "/tmp/grandchild-sees-me", "yes");
    let (grandchildren, _) = fork_batch(&guard, &tree_id, &child_id, &["deeper"]);
    assert_children_ready(&grandchildren);
    let mut g = agent(&grandchildren[0].1, Duration::from_secs(5));
    assert!(
        present(&mut g, "/tmp/before-point"),
        "grandchild lost the loaded base"
    );
    assert!(
        present(&mut g, "/tmp/grandchild-sees-me"),
        "grandchild lost its parent's diff"
    );
    assert!(!present(&mut g, "/tmp/after-point"));
    assert_memory_cow(&grandchildren[0].1, &restore_mem_of(&vm_dir_of(&child_ep)));
}

// ── Latency table (LATENCY_BUDGETS.md, FC section) ───────────────────

/// The four numbers the FC table in `LATENCY_BUDGETS.md` carries, as
/// the daemon measures them (`latency_ns`), plus the readiness of every
/// child. Eight children of one point in one batch must each fit the
/// per-child budget.
#[test]
fn test_fc_tree_latency_table() {
    let guard = spawn_daemon("latency", None);
    let (tree_id, root_ep) = create_tree(&guard, "latency");
    let mut root = agent(&root_ep, Duration::from_secs(10));
    write_marker(&mut root, "/tmp/warm", "warm");

    let (_, bytes, prepare_t) = prepare(&guard, &tree_id, "root");
    let (one, fork1_t) = fork_batch(&guard, &tree_id, "root", &["one"]);
    let ready1 = assert_children_ready(&one);
    let labels: Vec<String> = (0..8).map(|i| format!("c{i}")).collect();
    let labels: Vec<&str> = labels.iter().map(String::as_str).collect();
    let (eight, fork8_t) = fork_batch(&guard, &tree_id, "root", &labels);
    let ready8 = assert_children_ready(&eight);
    let (_, _, rollback_t) = rollback(&guard, &tree_id, "root", "rb");

    println!(
        "FC-LATENCY table ({GUEST_MB} MiB guest, point {bytes} bytes): prepare {prepare_t:?} | \
         fork n=1 {fork1_t:?} (ping {:?}) | fork n=8 {fork8_t:?} = {:?} per child (max ping \
         {:?}) | rollback {rollback_t:?}",
        ready1[0],
        fork8_t / 8,
        ready8.iter().max().unwrap()
    );
    assert!(fork1_t < PER_CHILD_BUDGET, "fork n=1 {fork1_t:?}");
    assert!(fork8_t / 8 < PER_CHILD_BUDGET, "fork n=8 {fork8_t:?}");
    assert!(rollback_t < PER_CHILD_BUDGET, "rollback {rollback_t:?}");
    // Every child of one point shares that point's extents.
    let restore = restore_mem_of(&vm_dir_of(&root_ep));
    for (_, ep) in &eight {
        assert_memory_cow(ep, &restore);
    }
}

// ── Refusals ─────────────────────────────────────────────────────────

/// Suspend and dilation have no Firecracker implementation;
/// both must fail naming the backend rather than degrade.
#[test]
fn test_fc_tree_refuses_suspend_and_dilation() {
    let guard = spawn_daemon("refuse", None);
    let (tree_id, _) = create_tree(&guard, "refuse");
    match call(
        &guard,
        &Request::TreeSuspend {
            tree_id: tree_id.clone(),
            node_id: "root".to_string(),
        },
    ) {
        Response::Error { message } => assert!(
            message.contains("Firecracker") && message.contains("suspend"),
            "{message}"
        ),
        other => panic!("suspend of an FC node must be refused: {other:?}"),
    }
    match call(
        &guard,
        &Request::TreeFork {
            tree_id,
            source_id: "root".to_string(),
            label: "slow".to_string(),
            dilation: Some(4),
        },
    ) {
        Response::Error { message } => assert!(
            message.contains("Firecracker") && message.contains("dilation"),
            "{message}"
        ),
        other => panic!("dilation on an FC node must be refused: {other:?}"),
    }
}

/// Composite `{tree}/{node}` dump looks up the live guest by node id,
/// not CID. Firecracker `node_cids` is empty.
#[test]
fn test_fc_dump_serial_by_tree_node_id() {
    let guard = spawn_daemon("dumpser", None);
    let (tree_id, _) = create_tree(&guard, "dump");
    match call(
        &guard,
        &Request::DumpSerial {
            vm_id: Some(format!("{tree_id}/root")),
            guest_cid: None,
        },
    ) {
        Response::SerialDump {
            vm_id,
            guest_cid,
            console: _,
        } => {
            assert_eq!(vm_id, format!("{tree_id}/root"));
            assert_eq!(
                guest_cid, 0,
                "Firecracker tree member has no host vsock CID"
            );
        }
        other => panic!("dump_serial by tree/node must return SerialDump, got {other:?}"),
    }
}
