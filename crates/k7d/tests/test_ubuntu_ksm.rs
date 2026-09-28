//! Opt-in KSM on Ubuntu bare-VM cluster trees.
//!
//! Forks siblings with `ksm` on while host `ksmd` is scanning, and a
//! twin tree with `ksm` off. Merged pages must rise only on the opted-in
//! tree. A write after that merge must still reach a grandchild through
//! the dirty log (`apply_dirty_bitmap_memcpy`), which is guest RAM on
//! `/dev/shm` — a synced disk file would show up without the dirty log.
//!
//! This test is the only thing that writes `/sys/kernel/mm/ksm`. It
//! restores every knob it changed, including when the assertion panics.

mod common;

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use k7d::api::AgentClient;
use k7d::control::{BlockDeviceConfig, Client, Request, Response, VmConfig};
use k7d::tree::TreeBudget;

use common::ubuntu::{node_cmdline, node_image, VmDisk, NODE_MEMORY_MB, NODE_VCPUS};

/// Identical non-zero pages, so `use_zero_pages` cannot swallow the blob
/// and every page matches its siblings.
const BLOB_MIB: u64 = 512;
/// Floor: a scan that merged nothing must fail the test.
const MERGE_FLOOR_PAGES: u64 = 128 * 1024 * 1024 / 4096;
const SCAN_WAIT: Duration = Duration::from_secs(180);

struct KsmdGuard {
    run: String,
    pages_to_scan: String,
    sleep_millisecs: String,
    advisor_mode: Option<String>,
}

impl KsmdGuard {
    /// Speed `ksmd` up for the test. The product never does this.
    fn enable_fast() -> Self {
        let run_path = Path::new("/sys/kernel/mm/ksm/run");
        assert!(
            run_path.is_file(),
            "this kernel has no /sys/kernel/mm/ksm/run — KSM is not built in"
        );
        let guard = Self {
            run: read_knob("run"),
            pages_to_scan: read_knob("pages_to_scan"),
            sleep_millisecs: read_knob("sleep_millisecs"),
            advisor_mode: std::fs::read_to_string("/sys/kernel/mm/ksm/advisor_mode")
                .ok()
                .map(|s| active_advisor_mode(&s)),
        };
        eprintln!(
            "ksmd before: run={} pages_to_scan={} sleep_millisecs={} advisor_mode={}",
            guard.run.trim(),
            guard.pages_to_scan.trim(),
            guard.sleep_millisecs.trim(),
            guard
                .advisor_mode
                .as_deref()
                .map(str::trim)
                .unwrap_or("<absent>")
        );
        if guard.advisor_mode.is_some() {
            write_knob("advisor_mode", "none\n");
        }
        write_knob("pages_to_scan", "10000\n");
        write_knob("sleep_millisecs", "1\n");
        write_knob("run", "1\n");
        guard
    }
}

impl Drop for KsmdGuard {
    fn drop(&mut self) {
        // Stop the fast scan first, then put the tunables back.
        restore_knob("run", &self.run);
        restore_knob("pages_to_scan", &self.pages_to_scan);
        restore_knob("sleep_millisecs", &self.sleep_millisecs);
        if let Some(ref mode) = self.advisor_mode {
            // The show string is a choice list (`[none] scan-time`).
            // Writing that back returns EINVAL; the stored value is the
            // bracketed token.
            restore_knob("advisor_mode", &format!("{mode}\n"));
        }
        let knob = |name: &str| {
            std::fs::read_to_string(format!("/sys/kernel/mm/ksm/{name}"))
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|e| format!("<unread: {e}>"))
        };
        eprintln!(
            "ksmd restored: run={} pages_to_scan={} sleep_millisecs={} advisor_mode={}",
            knob("run"),
            knob("pages_to_scan"),
            knob("sleep_millisecs"),
            knob("advisor_mode")
        );
    }
}

/// `advisor_mode` prints every choice and brackets the active one
/// (`[none] scan-time`). Only that token is a legal write.
fn active_advisor_mode(display: &str) -> String {
    let trimmed = display.trim();
    if let Some(start) = trimmed.find('[') {
        if let Some(rel) = trimmed[start + 1..].find(']') {
            let token = trimmed[start + 1..start + 1 + rel].trim();
            if !token.is_empty() && !token.contains(char::is_whitespace) {
                return token.to_string();
            }
        }
    }
    trimmed
        .split_whitespace()
        .next()
        .unwrap_or(trimmed)
        .to_string()
}

fn read_knob(name: &str) -> String {
    let path = format!("/sys/kernel/mm/ksm/{name}");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

fn write_knob(name: &str, value: &str) {
    let path = format!("/sys/kernel/mm/ksm/{name}");
    std::fs::write(&path, value).unwrap_or_else(|e| panic!("write {path} = {value:?}: {e}"));
}

fn restore_knob(name: &str, value: &str) {
    let path = format!("/sys/kernel/mm/ksm/{name}");
    if let Err(e) = std::fs::write(&path, value) {
        eprintln!("ERROR restoring {path} to {value:?}: {e}");
    }
}

struct DaemonGuard {
    child: Child,
    socket: PathBuf,
    socket_dir: PathBuf,
    tree_root: PathBuf,
    sandbox_root: PathBuf,
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_dir_all(&self.socket_dir);
        let _ = std::fs::remove_dir_all(&self.tree_root);
        let _ = std::fs::remove_dir_all(&self.sandbox_root);
    }
}

fn spawn_daemon() -> DaemonGuard {
    let pid = std::process::id();
    let socket_dir = std::env::temp_dir().join(format!("k7d-test-ksm-{pid}"));
    let _ = std::fs::remove_dir_all(&socket_dir);
    std::fs::create_dir_all(&socket_dir).expect("create socket parent");
    let socket = socket_dir.join("k7d.sock");
    let tree_root = std::env::temp_dir().join(format!("k7d-test-trees-ksm-{pid}"));
    let sandbox_root = std::env::temp_dir().join(format!("k7d-test-sandboxes-ksm-{pid}"));
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
        socket_dir,
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

fn call(guard: &DaemonGuard, req: &Request) -> Response {
    let mut client = Client::connect(guard.socket.to_str().expect("utf8 socket path"))
        .expect("connect control socket");
    client.call(req).expect("control-plane call")
}

fn guest_exec(cid: u64, argv: &[&str]) -> String {
    let mut agent =
        AgentClient::connect_vsock(cid, Duration::from_secs(90)).expect("connect guest agent");
    let out = agent.exec(argv).expect("agent exec");
    assert_eq!(
        out.exit_code, 0,
        "exec {argv:?} failed: stderr={}",
        out.stderr
    );
    out.stdout.trim().to_string()
}

fn budget() -> TreeBudget {
    TreeBudget {
        max_live_vms: 8,
        max_live_ram_bytes: 32 * 1024 * 1024 * 1024,
        max_disk_bytes: 64 * 1024 * 1024 * 1024,
        max_chain_depth: 4,
    }
}

struct Tree {
    id: String,
    root_id: String,
    root_cid: u64,
}

fn create_tree(guard: &DaemonGuard, tag: &str, kernel: &Path, disk: &Path, ksm: bool) -> Tree {
    let config = VmConfig {
        kernel: Some(kernel.to_string_lossy().into_owned()),
        initrd: None,
        cmdline: Some(node_cmdline(Ipv4Addr::new(10, 200, 0, 2))),
        memory_mb: NODE_MEMORY_MB,
        vcpus: NODE_VCPUS,
        block_devices: vec![BlockDeviceConfig {
            host_path: disk.to_string_lossy().into_owned(),
            readonly: false,
            guest_mount: None,
            fstype: None,
        }],
        ..VmConfig::default()
    };
    match call(
        guard,
        &Request::TreeCreateCluster {
            vm_count: 1,
            config,
            budget: Some(budget()),
            tree_id: Some(format!("ksm-{tag}-{}", std::process::id())),
            egress: None,
            dilation_policy: None,
            dilation_config: None,
            ksm,
        },
    ) {
        Response::TreeCreated {
            tree_id,
            root_id,
            guest_cids,
            ..
        } => {
            assert_eq!(guest_cids.len(), 1, "{tag} root member count");
            Tree {
                id: tree_id,
                root_id,
                root_cid: guest_cids[0],
            }
        }
        other => panic!("tree_create_cluster {tag} ksm={ksm}: {other:?}"),
    }
}

/// 512 MiB of identical `'K'` pages, built by doubling so the exec
/// stays inside the agent's response window.
fn plant_blob(cid: u64) {
    guest_exec(
        cid,
        &[
            "sh",
            "-c",
            "printf '%4096s' '' | tr ' ' K > /dev/shm/ksm-blob \
             && for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17; do \
                  cat /dev/shm/ksm-blob /dev/shm/ksm-blob > /dev/shm/ksm-next \
                  && mv /dev/shm/ksm-next /dev/shm/ksm-blob; \
                done \
             && stat -c %s /dev/shm/ksm-blob",
        ],
    );
    let size = guest_exec(cid, &["stat", "-c", "%s", "/dev/shm/ksm-blob"]);
    assert_eq!(
        size.parse::<u64>().expect("blob size"),
        BLOB_MIB * 1024 * 1024,
        "guest blob is not {BLOB_MIB} MiB"
    );
}

fn fork_two(guard: &DaemonGuard, tree: &Tree) -> Vec<(String, u64)> {
    match call(
        guard,
        &Request::TreeForkBatch {
            tree_id: tree.id.clone(),
            source_id: tree.root_id.clone(),
            labels: vec!["sib-a".into(), "sib-b".into()],
            dilation: None,
            dilation_policy: None,
            dilation_config: None,
        },
    ) {
        Response::TreeForkBatch { forks, .. } => {
            assert_eq!(forks.len(), 2);
            forks
                .into_iter()
                .map(|f| {
                    assert!(
                        f.fork_memory_full_copy.iter().all(|c| !c),
                        "{} forked with a full memfd copy: {:?}",
                        f.node_id,
                        f.fork_memory_full_copy
                    );
                    assert_eq!(f.guest_cids.len(), 1);
                    (f.node_id, f.guest_cids[0])
                })
                .collect()
        }
        other => panic!("tree_fork_batch {}: {other:?}", tree.id),
    }
}

fn merging_of(guard: &DaemonGuard, tree_id: &str, nodes: &[String]) -> Vec<u64> {
    match call(
        guard,
        &Request::TreeNodes {
            tree_id: tree_id.to_string(),
        },
    ) {
        Response::TreeNodeList { live_ksm, .. } => nodes
            .iter()
            .map(|id| {
                let members = live_ksm.get(id).unwrap_or_else(|| {
                    panic!("{tree_id} node {id} missing from live_ksm (keys {live_ksm:?})")
                });
                assert_eq!(members.len(), 1, "{id} member count");
                assert_ne!(
                    members[0].ksm_stat.ksm_merge_any, "yes",
                    "k7d must not set PR_SET_MEMORY_MERGE"
                );
                members[0].ksm_merging_pages
            })
            .collect(),
        other => panic!("tree_nodes {tree_id}: {other:?}"),
    }
}

fn gib(pages: u64) -> f64 {
    pages as f64 * 4096.0 / 1024.0 / 1024.0 / 1024.0
}

#[test]
fn advisor_mode_display_is_not_written_back() {
    assert_eq!(active_advisor_mode("[none] scan-time\n"), "none");
    assert_eq!(active_advisor_mode("none [scan-time]\n"), "scan-time");
    assert_eq!(active_advisor_mode("none\n"), "none");
}

/// Same-tenant opt-in: siblings merge, a ksm-off tree does not, and a
/// post-merge guest write still arrives in the grandchild.
#[test]
fn test_ubuntu_ksm_merges_siblings_and_keeps_dirty_log() {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ksmd = KsmdGuard::enable_fast();
    let guard = spawn_daemon();

    match call(&guard, &Request::Doctor) {
        Response::Doctor {
            ksm_run,
            details,
            ok,
            ..
        } => {
            assert!(ok, "doctor host checks");
            assert_eq!(ksm_run, Some(1), "doctor must see ksmd scanning");
            assert!(
                details
                    .iter()
                    .any(|l| l.contains("ksmd") && l.contains("running")),
                "doctor details missing a running ksmd line: {details:?}"
            );
        }
        other => panic!("doctor: {other:?}"),
    }

    let image = node_image();
    let disk_off = VmDisk::clone_of(&image.base_image(), "ksm-off");
    let disk_on = VmDisk::clone_of(&image.base_image(), "ksm-on");
    let off = create_tree(&guard, "off", &image.kernel(), &disk_off.path, false);
    let on = create_tree(&guard, "on", &image.kernel(), &disk_on.path, true);

    // After the create keyframe, so the blob is in the dirty set the
    // fork copies into private anonymous pages ksmd can merge.
    plant_blob(off.root_cid);
    plant_blob(on.root_cid);
    let off_sibs = fork_two(&guard, &off);
    let on_sibs = fork_two(&guard, &on);
    let off_ids: Vec<String> = off_sibs.iter().map(|(id, _)| id.clone()).collect();
    let on_ids: Vec<String> = on_sibs.iter().map(|(id, _)| id.clone()).collect();

    let deadline = Instant::now() + SCAN_WAIT;
    let (on_pages, off_pages) = loop {
        let pages = merging_of(&guard, &on.id, &on_ids);
        let quiet = merging_of(&guard, &off.id, &off_ids);
        eprintln!(
            "ksm scan on={pages:?} ({:.3} / {:.3} GiB) off={quiet:?}",
            gib(pages.first().copied().unwrap_or(0)),
            gib(pages.get(1).copied().unwrap_or(0))
        );
        assert!(
            quiet.iter().all(|p| *p == 0),
            "ksm off merged while ksmd was scanning: {quiet:?}"
        );
        if pages.iter().all(|p| *p >= MERGE_FLOOR_PAGES) {
            break (pages, quiet);
        }
        assert!(
            Instant::now() < deadline,
            "opt-in siblings did not reach {MERGE_FLOOR_PAGES} merged pages in {SCAN_WAIT:?}: {pages:?}"
        );
        std::thread::sleep(Duration::from_secs(2));
    };

    let marker = format!("ksm-dirty-{}", std::process::id());
    let (sib_id, sib_cid) = &on_sibs[0];
    guest_exec(
        *sib_cid,
        &[
            "sh",
            "-c",
            &format!("printf '%s\\n' '{marker}' > /dev/shm/ksm-dirty"),
        ],
    );
    let (grand_id, grand_cid) = match call(
        &guard,
        &Request::TreeFork {
            tree_id: on.id.clone(),
            source_id: sib_id.clone(),
            label: "grand".into(),
            dilation: None,
            dilation_policy: None,
            dilation_config: None,
        },
    ) {
        Response::TreeForked {
            node_id,
            guest_cids,
            fork_memory_full_copy,
            ..
        } => {
            assert!(
                fork_memory_full_copy.iter().all(|c| !c),
                "grandchild full-copied: {fork_memory_full_copy:?}"
            );
            assert_eq!(guest_cids.len(), 1);
            (node_id, guest_cids[0])
        }
        other => panic!("tree_fork grandchild: {other:?}"),
    };
    let seen = guest_exec(grand_cid, &["cat", "/dev/shm/ksm-dirty"]);
    assert_eq!(
        seen, marker,
        "grandchild {grand_id} missed the post-merge write; dirty log did not carry it"
    );

    eprintln!(
        "MEASUREMENT ksm merged GiB per sibling on={:.3},{:.3} off={:.3},{:.3} \
         pages_on={on_pages:?} pages_off={off_pages:?}",
        gib(on_pages[0]),
        gib(on_pages[1]),
        gib(off_pages[0]),
        gib(off_pages[1])
    );

    for id in [&on.id, &off.id] {
        match call(
            &guard,
            &Request::TreeDrop {
                tree_id: id.clone(),
            },
        ) {
            Response::Ok => {}
            other => panic!("tree_drop {id}: {other:?}"),
        }
    }
}
