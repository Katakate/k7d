//! Fork-under-load correctness + dirty-page divergence.
//!
//! Runs `gym/fork_under_load.py` against the live daemon on an Ubuntu
//! bare-VM cluster. No `#[ignore]`. No new `crates/k7d/src` primitives.

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

fn wipe_stale_ful_trees() {
    let mut c = match Client::connect(k7d_sock()) {
        Ok(c) => c,
        Err(_) => return,
    };
    let trees = match c.call(&Request::TreeList) {
        Ok(Response::TreeList { trees }) => trees,
        _ => return,
    };
    for t in trees {
        if t.tree_id.starts_with("ful-") {
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
fn test_fork_under_load_ubuntu_k8s_kafka_divergence() {
    let _ = env_logger::builder().is_test(true).try_init();
    common::ensure_k7d_daemon_running();
    ensure_musl_agent();
    wipe_stale_ful_trees();

    let root = workspace_root();
    let tree_id = format!("ful-{}", std::process::id());
    let out = std::env::temp_dir().join(format!("k7-ful-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&out);
    let log_path = out.join("harness.log");
    let log = File::create(&log_path).expect("harness log");

    let t0 = Instant::now();
    let status = Command::new("python3")
        .arg(root.join("gym/fork_under_load.py"))
        .arg("--out")
        .arg(&out)
        .arg("--tree-id")
        .arg(&tree_id)
        .arg("--sample-s")
        .arg("30")
        .arg("--interval-s")
        .arg("2")
        .current_dir(&root)
        .stdout(Stdio::from(log.try_clone().expect("clone log")))
        .stderr(Stdio::from(log))
        .status()
        .expect("spawn gym/fork_under_load.py");
    let elapsed = t0.elapsed();
    let log_text = std::fs::read_to_string(&log_path).unwrap_or_default();
    eprintln!(
        "---- fork-under-load harness {} ({elapsed:?}) ----\n{log_text}\n---- end fork-under-load harness ----",
        log_path.display()
    );
    assert!(
        status.success(),
        "gym/fork_under_load.py failed (status {status}); see {}",
        log_path.display()
    );
    assert!(
        elapsed < Duration::from_secs(900),
        "harness took {elapsed:?} — hung image pull or Ready wait?"
    );

    let jsonl = out.join("divergence.jsonl");
    let svg = out.join("divergence.svg");
    let sib_svg = out.join("sibling_div.svg");
    let summary = out.join("summary.json");
    assert!(jsonl.is_file(), "missing {jsonl:?}");
    assert!(svg.is_file(), "missing {svg:?}");
    assert!(sib_svg.is_file(), "missing {sib_svg:?}");
    assert!(summary.is_file(), "missing {summary:?}");
    let svg_text = std::fs::read_to_string(&svg).expect("svg");
    assert!(svg_text.contains("idle") && svg_text.contains("k8s") && svg_text.contains("kafka"));
    let sib_text = std::fs::read_to_string(&sib_svg).expect("sibling svg");
    assert!(
        sib_text.contains("parent") && sib_text.contains("child"),
        "sibling_div.svg missing parent/child series"
    );

    let mut saw_idle = false;
    let mut saw_k8s = false;
    let mut saw_kafka = false;
    let mut sibling_by_wl: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut n = 0usize;
    for line in std::fs::read_to_string(&jsonl).expect("jsonl").lines() {
        if line.is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(line).expect("jsonl row");
        assert!(
            v["usage"]["live_ram_bytes"].as_u64().is_some(),
            "row missing usage.live_ram_bytes: {line}"
        );
        match v["workload"].as_str() {
            Some("idle") => saw_idle = true,
            Some("k8s") => saw_k8s = true,
            Some("kafka") => saw_kafka = true,
            other => panic!("unexpected workload {other:?}"),
        }
        if v["phase"].as_str() == Some("sibling_div") {
            assert!(
                v["parent_dirty_bytes"].as_u64().is_some()
                    && v["child_dirty_bytes"].as_u64().is_some(),
                "sibling_div row missing parent/child dirty bytes: {line}"
            );
            if let Some(wl) = v["workload"].as_str() {
                *sibling_by_wl.entry(wl.to_string()).or_default() += 1;
            }
        }
        n += 1;
    }
    assert!(n >= 12, "too few usage samples: {n}");
    assert!(
        saw_idle && saw_k8s && saw_kafka,
        "missing a workload in jsonl"
    );
    for wl in ["idle", "k8s", "kafka"] {
        let got = sibling_by_wl.get(wl).copied().unwrap_or(0);
        assert!(
            got >= 3,
            "workload {wl} has {got} sibling_div samples, want >= 3"
        );
    }
    assert!(
        log_text.contains("FUL_MEASURE idle_ok")
            && log_text.contains("FUL_MEASURE k8s_ok")
            && log_text.contains("FUL_MEASURE kafka_ok")
            && log_text.contains("FUL_MEASURE sibling"),
        "harness did not print all FUL_MEASURE ok/sibling lines"
    );

    wipe_tree(&tree_id);
}
