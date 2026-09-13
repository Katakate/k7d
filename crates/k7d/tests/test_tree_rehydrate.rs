//! Daemon crash mid-tree — Ubuntu rehydrate.
//!
//! Runs `gym/tree_rehydrate.py` against the live systemd k7d. This test
//! owns `k7d.service` for the duration (kill -9 + restart). No `#[ignore]`.

mod common;

use std::fs::File;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use k7d::control::{Client, Request, Response};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn k7d_sock() -> &'static str {
    "/run/k7d/k7d.sock"
}

fn wipe_tree(tree_id: &str) {
    let mut c = match Client::connect(k7d_sock()) {
        Ok(c) => c,
        Err(_) => return,
    };
    let _ = c.call(&Request::TreePrune {
        tree_id: tree_id.to_string(),
        node_id: "root".to_string(),
    });
    let _ = c.call(&Request::TreeDrop {
        tree_id: tree_id.to_string(),
    });
}

fn wipe_stale_rh_via_daemon() {
    let mut c = match Client::connect(k7d_sock()) {
        Ok(c) => c,
        Err(_) => return,
    };
    let trees = match c.call(&Request::TreeList) {
        Ok(Response::TreeList { trees }) => trees,
        _ => return,
    };
    for t in trees {
        if t.tree_id.starts_with("rh-") {
            wipe_tree(&t.tree_id);
        }
    }
}

fn wipe_stale_rh_on_disk() {
    // Cannot wipe mid-crash; this is the on-the-way-in sweep of leftover
    // dirs a previous kill -9 left when tree_list was empty.
    let trees = PathBuf::from("/var/lib/k7d/trees");
    if let Ok(rd) = std::fs::read_dir(&trees) {
        for e in rd.flatten() {
            let name = e.file_name();
            if name.to_string_lossy().starts_with("rh-") {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
    let disks = PathBuf::from("/var/lib/k7d/disks");
    if let Ok(rd) = std::fs::read_dir(&disks) {
        for e in rd.flatten() {
            let name = e.file_name();
            if name.to_string_lossy().starts_with("ubuntu-ful-rh-") {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

fn ensure_musl_agent() {
    let agent = workspace_root().join("target/x86_64-unknown-linux-musl/release/k7-agent");
    if agent.is_file() {
        return;
    }
    let status = Command::new("make")
        .arg("build-agent")
        .current_dir(workspace_root())
        .status()
        .expect("make build-agent");
    assert!(status.success(), "make build-agent failed");
    assert!(
        agent.is_file(),
        "k7-agent still missing at {}",
        agent.display()
    );
}

#[test]
fn test_tree_rehydrate_after_daemon_kill() {
    let _ = env_logger::builder().is_test(true).try_init();
    common::ensure_k7d_daemon_running();
    ensure_musl_agent();
    wipe_stale_rh_via_daemon();
    wipe_stale_rh_on_disk();

    let root = workspace_root();
    let tree_id = format!("rh-{}", std::process::id());
    let out = std::env::temp_dir().join(format!("k7-tree-rehydrate-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&out);
    let log_path = out.join("harness.log");
    let log = File::create(&log_path).expect("harness log");

    let t0 = Instant::now();
    let status = Command::new("python3")
        .arg(root.join("gym/tree_rehydrate.py"))
        .arg("--tree-id")
        .arg(&tree_id)
        .current_dir(&root)
        .stdout(Stdio::from(log.try_clone().expect("clone log")))
        .stderr(Stdio::from(log))
        .status()
        .expect("spawn gym/tree_rehydrate.py");
    let elapsed = t0.elapsed();
    let log_text = std::fs::read_to_string(&log_path).unwrap_or_default();
    eprintln!(
        "---- rehydrate harness {} ({elapsed:?}) ----\n{log_text}\n---- end rehydrate ----",
        log_path.display()
    );
    assert!(
        status.success(),
        "gym/tree_rehydrate.py failed (status {status}); see {}",
        log_path.display()
    );
    assert!(
        elapsed < Duration::from_secs(240),
        "harness took {elapsed:?} — wall budget is 240 s cache-hit"
    );
    assert!(
        log_text.contains("RH_MEASURE ok"),
        "harness did not print RH_MEASURE ok; see {}",
        log_path.display()
    );

    // Later suite tests still need a daemon (this test owns the unit).
    common::ensure_k7d_daemon_running();
    wipe_tree(&tree_id);
    wipe_stale_rh_via_daemon();
    wipe_stale_rh_on_disk();
}
