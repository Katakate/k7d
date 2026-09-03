//! the referenced work: what an incremental keyframe costs on a real Ubuntu cluster.
//!
//! Runs `gym/keyframe_cost.py` against the live daemon on an Ubuntu
//! 3x2 GiB bare-VM cluster at the 28a divergence levels, and pins the
//! result: every child keyframe must clone, must land inside the
//! latency budget, and must cost a small fraction of the full dump the
//! root pays. No `#[ignore]`.

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

fn wipe_stale_keyframe_trees() {
    let Ok(mut c) = Client::connect("/run/k7d/k7d.sock") else {
        return;
    };
    let Ok(Response::TreeList { trees }) = c.call(&Request::TreeList) else {
        return;
    };
    for t in trees {
        if t.tree_id.starts_with("kf-30b-") {
            let _ = c.call(&Request::TreePrune {
                tree_id: t.tree_id.clone(),
                node_id: "root".to_string(),
            });
            let _ = c.call(&Request::TreeDrop { tree_id: t.tree_id });
        }
    }
}

#[test]
fn test_keyframe_cost_ubuntu_divergence_levels() {
    let _ = env_logger::builder().is_test(true).try_init();
    common::ensure_k7d_daemon_running();
    wipe_stale_keyframe_trees();

    let root = workspace_root();
    let out = std::env::temp_dir().join(format!("k7-30b-{}", std::process::id()));
    std::fs::create_dir_all(&out).expect("out dir");
    let log_path = out.join("harness.log");
    let log = File::create(&log_path).expect("harness log");

    let started = Instant::now();
    let status = Command::new("python3")
        .arg(root.join("gym/keyframe_cost.py"))
        .arg("--out")
        .arg(&out)
        .arg("--tree-id")
        .arg(format!("kf-30b-{}", std::process::id()))
        .arg("--diverge-s")
        .arg("30")
        .current_dir(&root)
        .stdout(Stdio::from(log.try_clone().expect("clone log")))
        .stderr(Stdio::from(log))
        .status()
        .expect("spawn gym/keyframe_cost.py");
    let elapsed = started.elapsed();
    let log_text = std::fs::read_to_string(&log_path).unwrap_or_default();
    eprintln!("---- 30b harness ({elapsed:?}) ----\n{log_text}\n---- end ----");
    assert!(
        status.success(),
        "gym/keyframe_cost.py failed (status {status}); see {}",
        log_path.display()
    );

    let rows: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(out.join("keyframe_cost.json")).unwrap())
            .expect("keyframe_cost.json");

    let baseline = rows
        .iter()
        .find(|r| r["workload"] == "root-full-dump")
        .expect("baseline row");
    assert_eq!(
        baseline["incremental"], false,
        "the root has no ancestor to clone; its prepare must be a full dump"
    );
    let full_bytes = baseline["keyframe_disk_bytes"]
        .as_u64()
        .expect("baseline disk");
    let full_took = Duration::from_secs_f64(
        baseline["prepare_wall_s"]
            .as_f64()
            .expect("baseline prepare_wall_s"),
    );

    // A keyframe costs its node's divergence, so the ceiling is a
    // property of the workload, not of the code: 30 s of page-cache
    // churn on three k3s nodes dirties a quarter of guest RAM even when
    // the cluster is doing nothing, and over half of it under Kafka
    // . These are ~1.5x the measured shares.
    let share_ceiling = [("idle", 0.35), ("k8s", 0.50), ("kafka", 0.80)];

    for (workload, ceiling) in share_ceiling {
        let row = rows
            .iter()
            .find(|r| r["workload"] == workload)
            .unwrap_or_else(|| panic!("missing {workload} row in {rows:?}"));
        assert_eq!(row["incremental"], true, "{workload} must clone");

        let cost = row["keyframe_disk_bytes"]
            .as_u64()
            .expect("keyframe_disk_bytes");
        let share = cost as f64 / full_bytes as f64;
        assert!(
            share < ceiling,
            "{workload}: an incremental keyframe cost {cost} B, {share:.3} of the \
             {full_bytes} B full dump — ceiling is {ceiling}"
        );

        let took = Duration::from_secs_f64(row["prepare_latency_s"].as_f64().expect("latency"));
        let budget = k7d::latency::PREPARE_KEYFRAME_INCREMENTAL_CLUSTER_3VM;
        assert!(
            took <= budget,
            "{workload}: incremental keyframe took {took:?}, budget is {budget:?} \
             — see LATENCY_BUDGETS.md"
        );
        // The point of the whole increment: a fork point below the root
        // must be cheaper than re-dumping the cluster.
        assert!(
            took < full_took,
            "{workload}: incremental keyframe took {took:?}, but the root's full \
             dump of the same cluster took {full_took:?} — the clone is not paying \
             for itself"
        );
    }

    assert!(
        elapsed < Duration::from_secs(2400),
        "harness took {elapsed:?} — hung image pull or Ready wait?"
    );
    wipe_stale_keyframe_trees();
}
