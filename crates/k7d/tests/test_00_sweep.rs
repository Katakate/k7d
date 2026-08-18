//! the referenced work: loud stranded-resource sweep + per-run isolation helpers.
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
