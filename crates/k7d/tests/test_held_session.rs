//! Held Ubuntu apiserver watch + ClusterIP TCP across
//! `tree_fork_batch`. A new curl after the pause is not this assertion
//! (CHALLENGES #42). No `#[ignore]`.

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

fn wipe_stale_hs_trees() {
    let mut c = match Client::connect(k7d_sock()) {
        Ok(c) => c,
        Err(_) => return,
    };
    let trees = match c.call(&Request::TreeList) {
        Ok(Response::TreeList { trees }) => trees,
        _ => return,
    };
    for t in trees {
        if t.tree_id.starts_with("hs-") {
            wipe_tree(&t.tree_id);
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
fn test_held_session_ubuntu_watch_and_clusterip() {
    let _ = env_logger::builder().is_test(true).try_init();
    common::ensure_k7d_daemon_running();
    ensure_musl_agent();
    wipe_stale_hs_trees();

    let root = workspace_root();
    let tree_id = format!("hs-{}", std::process::id());
    let out = std::env::temp_dir().join(format!("k7-hs-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&out);
    let log_path = out.join("harness.log");
    let log = File::create(&log_path).expect("harness log");

    let t0 = Instant::now();
    let status = Command::new("python3")
        .arg(root.join("gym/held_session.py"))
        .arg("--tree-id")
        .arg(&tree_id)
        .current_dir(&root)
        .stdout(Stdio::from(log.try_clone().expect("clone log")))
        .stderr(Stdio::from(log))
        .status()
        .expect("spawn gym/held_session.py");
    let elapsed = t0.elapsed();
    let log_text = std::fs::read_to_string(&log_path).unwrap_or_default();
    eprintln!(
        "---- held-session harness {} ({elapsed:?}) ----\n{log_text}\n---- end held-session ----",
        log_path.display()
    );
    assert!(
        status.success(),
        "gym/held_session.py failed (status {status}); see {}",
        log_path.display()
    );
    assert!(
        log_text.contains("HS_MEASURE watch_ok") && log_text.contains("HS_MEASURE tcp_ok"),
        "harness did not print HS_MEASURE watch_ok and tcp_ok"
    );
    assert!(
        elapsed < Duration::from_secs(180),
        "harness took {elapsed:?} — cache-hit wall is 180s (CHALLENGES #42, not a new curl)"
    );

    wipe_tree(&tree_id);
}
