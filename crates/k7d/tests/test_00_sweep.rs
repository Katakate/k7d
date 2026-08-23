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

/// Persistent data disks  are reaped by **age**, not by
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
