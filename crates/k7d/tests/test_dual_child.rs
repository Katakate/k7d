//! Dual-child write isolation at Ubuntu cluster fidelity.
//!
//! Runs `gym/dual_child.py` against the live daemon on an Ubuntu bare-VM
//! 3-node cluster. No `#[ignore]`. No new `crates/k7d/src` primitives.

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

fn wipe_stale_dci_trees() {
    let mut c = match Client::connect(k7d_sock()) {
        Ok(c) => c,
        Err(_) => return,
    };
    let trees = match c.call(&Request::TreeList) {
        Ok(Response::TreeList { trees }) => trees,
        _ => return,
    };
    for t in trees {
        if t.tree_id.starts_with("dci-") {
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
fn test_dual_child_ubuntu_isolation() {
    let _ = env_logger::builder().is_test(true).try_init();
    common::ensure_k7d_daemon_running();
    ensure_musl_agent();
    wipe_stale_dci_trees();

    let root = workspace_root();
    let tree_id = format!("dci-{}", std::process::id());
    let out = std::env::temp_dir().join(format!("k7-dual-child-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&out);
    let log_path = out.join("harness.log");
    let log = File::create(&log_path).expect("harness log");

    let t0 = Instant::now();
    let status = Command::new("python3")
        .arg(root.join("gym/dual_child.py"))
        .arg("--out")
        .arg(&out)
        .arg("--tree-id")
        .arg(&tree_id)
        .current_dir(&root)
        .stdout(Stdio::from(log.try_clone().expect("clone log")))
        .stderr(Stdio::from(log))
        .status()
        .expect("spawn gym/dual_child.py");
    let elapsed = t0.elapsed();
    let log_text = std::fs::read_to_string(&log_path).unwrap_or_default();
    eprintln!(
        "---- dual-child harness {} ({elapsed:?}) ----\n{log_text}\n---- end dual-child harness ----",
        log_path.display()
    );
    assert!(
        status.success(),
        "gym/dual_child.py failed (status {status}); see {}",
        log_path.display()
    );
    assert!(
        elapsed < Duration::from_secs(180),
        "harness took {elapsed:?} — hung image pull or Ready wait?"
    );
    assert!(
        log_text.contains("DCI_MEASURE ok"),
        "harness did not print DCI_MEASURE ok; see {}",
        log_path.display()
    );

    let summary = out.join("dual_child.json");
    assert!(summary.is_file(), "missing {summary:?}");
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&summary).expect("dual_child.json"))
            .expect("dual_child.json parse");
    assert_eq!(v["ok"], true, "dual_child.json ok=false");
    assert!(
        v["fork_batch_ms"].as_f64().is_some(),
        "dual_child.json missing fork_batch_ms"
    );
    let bridges = v["bridges"].as_object().expect("bridges object");
    assert_eq!(bridges.len(), 3, "expected three bridge entries");
    let uniq: std::collections::BTreeSet<&str> =
        bridges.values().filter_map(|b| b.as_str()).collect();
    assert_eq!(uniq.len(), 3, "bridges must be distinct: {bridges:?}");

    wipe_tree(&tree_id);
}
