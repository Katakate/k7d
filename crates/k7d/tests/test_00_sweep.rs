//! Loud stranded-resource sweep + per-run isolation helpers.
//!
//! This binary sorts first (`test_00_*`) so a suite run reaps leftovers
//! before any kubectl test creates new ones. The plant test is the
//! contract: a stranded `k7*` bridge and an orphan disk image must be
//! reported and removed.

mod common;

use std::path::Path;
use std::process::Command;

#[test]
fn test_run_id_is_stable_hex() {
    common::hygiene_once();
    let a = common::run_id();
    let b = common::run_id();
    assert_eq!(a, b, "run_id must be stable for the process");
    assert_eq!(a.len(), 6, "run_id must be 6 hex chars, got {a}");
    assert!(
        a.chars().all(|c| c.is_ascii_hexdigit()),
        "run_id must be hex, got {a}"
    );
    let name = common::unique_name("test-k7d-shim");
    assert_eq!(name, format!("test-k7d-shim-{a}"));
}

#[test]
fn test_stamp_test_labels_and_suffix_names() {
    let yaml = "\
apiVersion: v1
kind: Pod
metadata:
  name: test-k7d-shim
spec:
  containers: []
";
    let isolated = common::isolate_manifest(yaml);
    let rid = common::run_id();
    assert!(
        isolated.contains(&format!("name: test-k7d-shim-{rid}")),
        "metadata.name must be suffixed: {isolated}"
    );
    assert!(
        isolated.contains(&format!("k7-test-run: \"{rid}\"")),
        "k7-test-run label missing: {isolated}"
    );
    // Idempotent: running twice must not double-suffix.
    let again = common::isolate_manifest(&isolated);
    assert_eq!(
        again.matches(&format!("-{rid}")).count(),
        isolated.matches(&format!("-{rid}")).count()
    );
}

#[test]
fn test_stranded_resource_sweep_reports_and_removes() {
    let bridge = "k7stale0";
    let _ = Command::new("ip").args(["link", "delete", bridge]).output();
    let add = Command::new("ip")
        .args(["link", "add", bridge, "type", "bridge"])
        .output()
        .expect("ip link add should run");
    assert!(
        add.status.success(),
        "failed to plant bridge {bridge}: {}",
        String::from_utf8_lossy(&add.stderr)
    );

    let disks = Path::new(k7d::disks::DISKS_DIR);
    std::fs::create_dir_all(disks).expect("create disks dir");
    let orphan = disks.join("k7-orphan-sweep.img");
    std::fs::write(&orphan, b"orphan-sweep").expect("plant orphan disk");

    let report = common::sweep_stranded_resources();
    let joined = report.join("\n");
    assert!(
        report.iter().any(|l| l.contains(bridge)),
        "sweep must report planted bridge {bridge}: {joined}"
    );
    assert!(
        report.iter().any(|l| l.contains("k7-orphan-sweep.img")),
        "sweep must report planted disk: {joined}"
    );

    let still = Command::new("ip")
        .args(["link", "show", bridge])
        .output()
        .expect("ip link show");
    assert!(
        !still.status.success(),
        "planted bridge {bridge} must be gone after sweep"
    );
    assert!(
        !orphan.exists(),
        "planted disk {} must be gone after sweep",
        orphan.display()
    );
}

/// Persistent data disks are reaped by **age**, not by
/// "no live VM holds it": between two VMs, a correctly retained disk is
/// held by nobody, so the ephemeral rule would delete exactly the disks
/// the primitive exists to keep.
#[test]
fn test_sweep_reaps_orphan_data_disks_and_spares_fresh_ones() {
    let dir = k7d::disks::data_disks_dir();
    std::fs::create_dir_all(&dir).expect("create data-disks dir");

    let stale = dir.join("test-sweep-stale.img");
    let fresh = dir.join("test-sweep-fresh.img");
    std::fs::write(&stale, b"stale-data-disk").expect("plant stale data disk");
    std::fs::write(&fresh, b"fresh-data-disk").expect("plant fresh data disk");
    // An hour back: past the sweep's 30-minute staleness gate, so this
    // stands in for a run that died without deleting its disk.
    let aged = Command::new("touch")
        .args(["-d", "-1 hour"])
        .arg(&stale)
        .status()
        .expect("touch runs");
    assert!(aged.success(), "failed to age {}", stale.display());

    let report = common::sweep_stranded_resources();
    let joined = report.join("\n");
    assert!(
        report.iter().any(|l| l.contains("test-sweep-stale.img")),
        "sweep must report the aged data disk: {joined}"
    );
    assert!(
        !stale.exists(),
        "aged data disk {} must be gone after sweep",
        stale.display()
    );
    assert!(
        fresh.exists(),
        "sweep deleted {} — a data disk younger than the staleness gate belongs to a \
         possibly-live run",
        fresh.display()
    );
    std::fs::remove_file(&fresh).expect("clean up the fresh data disk");
}

fn trees_dir() -> std::path::PathBuf {
    std::path::Path::new(k7d::disks::DISKS_DIR).join(k7d::disks::TREES_SUBDIR)
}

fn age_an_hour(path: &Path) {
    let st = Command::new("touch")
        .args(["-d", "-1 hour"])
        .arg(path)
        .status()
        .expect("touch runs");
    assert!(st.success(), "failed to age {}", path.display());
}

fn plant_tree_dir(name: &str) -> std::path::PathBuf {
    let dir = trees_dir().join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("plant tree dir");
    dir
}

/// Marked tree older than `STALE_AGE`, unknown to the daemon → swept.
#[test]
fn test_sweep_reaps_marked_stale_tree() {
    let dir = plant_tree_dir(&format!("marked-stale-{}", common::run_id()));
    common::mark_test_tree_dir(&dir);
    age_an_hour(&dir.join(common::TEST_TREE_MARKER));

    let report = common::sweep_stranded_resources();
    let joined = report.join("\n");
    let name = dir.file_name().unwrap().to_string_lossy();
    assert!(
        report.iter().any(|l| l.contains(name.as_ref())),
        "sweep must report the marked stale tree: {joined}"
    );
    assert!(
        !dir.exists(),
        "marked stale tree {} must be gone after sweep",
        dir.display()
    );
}

/// Marked tree younger than `STALE_AGE` → untouched.
#[test]
fn test_sweep_spares_marked_fresh_tree() {
    let dir = plant_tree_dir(&format!("marked-fresh-{}", common::run_id()));
    common::mark_test_tree_dir(&dir);

    let report = common::sweep_stranded_resources();
    let name = dir.file_name().unwrap().to_string_lossy();
    assert!(
        !report.iter().any(|l| l.contains(name.as_ref())),
        "sweep must not reap a fresh marked tree: {}",
        report.join("\n")
    );
    assert!(
        dir.exists(),
        "fresh marked tree {} must survive the sweep",
        dir.display()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Unmarked dir with a valid `tree.json`, arbitrarily old → untouched.
/// Operator-safety: never infer "test tree" from age or id.
#[test]
fn test_sweep_spares_unmarked_old_tree() {
    let dir = plant_tree_dir(&format!("unmarked-op-{}", common::run_id()));
    let json = dir.join("tree.json");
    std::fs::write(&json, b"{\"tree_id\":\"operator\"}\n").expect("plant tree.json");
    age_an_hour(&json);

    let report = common::sweep_stranded_resources();
    let name = dir.file_name().unwrap().to_string_lossy();
    assert!(
        !report.iter().any(|l| l.contains(name.as_ref())),
        "sweep must not reap an unmarked tree: {}",
        report.join("\n")
    );
    assert!(
        dir.exists() && json.exists(),
        "unmarked tree {} and its tree.json must survive the sweep",
        dir.display()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `tree_drop` then sweep leaves neither a registry entry nor a dir.
#[test]
fn test_tree_drop_then_sweep_agrees_with_registry() {
    common::ensure_k7d_daemon_running();
    let tree_id = format!("swdrop-{}", common::run_id());
    let dir = plant_tree_dir(&tree_id);
    std::fs::write(dir.join("tree.json"), b"{}\n").expect("plant tree.json");
    common::mark_test_tree_dir(&dir);
    age_an_hour(&dir.join(common::TEST_TREE_MARKER));

    let mut c = k7d::control::Client::connect_env().expect("connect k7d");
    // Unknown to the daemon: drop is a no-op error; sweep still reaps.
    let _ = c.call(&k7d::control::Request::TreeDrop {
        tree_id: tree_id.clone(),
    });
    let report = common::sweep_stranded_resources();
    assert!(
        report.iter().any(|l| l.contains(&tree_id)),
        "sweep must report dropped tree {tree_id}: {}",
        report.join("\n")
    );
    assert!(!dir.exists(), "dir {} must be gone", dir.display());
    match c.call(&k7d::control::Request::TreeList) {
        Ok(k7d::control::Response::TreeList { trees }) => {
            assert!(
                trees.iter().all(|t| t.tree_id != tree_id),
                "tree_list still has {tree_id}: {trees:?}"
            );
        }
        other => panic!("tree_list: {other:?}"),
    }
}

/// Marked tree with a live VM stays until the VM is gone and the marker ages out.
#[test]
fn test_sweep_spares_marked_tree_with_live_vm() {
    common::ensure_k7d_daemon_running();
    let tree_id = format!("swlive-{}", common::run_id());
    let mut c = k7d::control::Client::connect_env().expect("connect k7d");
    let created = c
        .call(&k7d::control::Request::TreeCreate {
            config: k7d::control::VmConfig::default(),
            budget: None,
            tree_id: Some(tree_id.clone()),
            dilation_policy: None,
            dilation_config: None,
        })
        .expect("tree_create");
    let tree_id = match created {
        k7d::control::Response::TreeCreated { tree_id, .. } => {
            common::mark_test_tree(&tree_id);
            tree_id
        }
        other => panic!("tree_create: {other:?}"),
    };
    struct ReapTree(String);
    impl Drop for ReapTree {
        fn drop(&mut self) {
            if let Ok(mut c) = k7d::control::Client::connect_env() {
                let _ = c.call(&k7d::control::Request::TreeDrop {
                    tree_id: self.0.clone(),
                });
            }
            let _ = std::fs::remove_dir_all(k7d::control::tree_root_dir().join(&self.0));
        }
    }
    let _reap = ReapTree(tree_id.clone());
    let dir = k7d::control::tree_root_dir().join(&tree_id);
    assert!(dir.is_dir(), "tree dir missing: {}", dir.display());
    age_an_hour(&dir.join(common::TEST_TREE_MARKER));

    let report = common::sweep_stranded_resources();
    assert!(
        !report.iter().any(|l| l.contains(&tree_id)),
        "sweep must not reap a marked tree with a live VM: {}",
        report.join("\n")
    );
    assert!(
        dir.exists(),
        "live marked tree {} must survive the sweep",
        dir.display()
    );

    match c.call(&k7d::control::Request::TreeDrop {
        tree_id: tree_id.clone(),
    }) {
        Ok(k7d::control::Response::Ok) => {}
        other => panic!("tree_drop: {other:?}"),
    }
    assert!(
        dir.exists(),
        "tree_drop must keep the on-disk tree (retention contract): {}",
        dir.display()
    );

    let report = common::sweep_stranded_resources();
    assert!(
        report.iter().any(|l| l.contains(&tree_id)),
        "sweep must reap the marked tree once the VM is gone: {}",
        report.join("\n")
    );
    assert!(
        !dir.exists(),
        "dir {} must be gone after drop+sweep",
        dir.display()
    );
    match c.call(&k7d::control::Request::TreeList) {
        Ok(k7d::control::Response::TreeList { trees }) => {
            assert!(
                trees.iter().all(|t| t.tree_id != tree_id),
                "tree_list still has {tree_id} after drop+sweep: {trees:?}"
            );
        }
        other => panic!("tree_list: {other:?}"),
    }
}

/// Preflight fails immediately with free/needed numbers and the reclaim hint.
#[test]
fn test_z_preflight_fails_loud_with_numbers() {
    common::hygiene_once();
    // SAFETY: test binaries run `--test-threads=1`; this env is restored
    // before the next test (and before any later hygiene_once).
    std::env::set_var("K7D_MIN_FREE_DISK", u64::MAX.to_string());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        common::assert_disks_have_headroom,
    ));
    std::env::remove_var("K7D_MIN_FREE_DISK");
    let err = result.expect_err("preflight must hard-fail, not skip or warn");
    let msg = err
        .downcast_ref::<String>()
        .map(|s| s.as_str())
        .or_else(|| err.downcast_ref::<&str>().copied())
        .unwrap_or("");
    assert!(
        msg.contains("GiB free") && msg.contains("need") && msg.contains("GiB"),
        "preflight must print free vs needed GiB, got: {msg}"
    );
    assert!(
        msg.contains("make remote-node-reclaim"),
        "preflight must hint `make remote-node-reclaim`, got: {msg}"
    );
    assert!(
        msg.contains(k7d::disks::DISKS_DIR),
        "preflight must name DISKS_DIR, got: {msg}"
    );
}
