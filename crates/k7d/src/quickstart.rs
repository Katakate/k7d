//! `k7d quickstart`: boot a busybox 3-node tree, fork 4 branches, print clocks.
//!
//! Host checks live in [`crate::doctor`]. Fetching a release tarball is
//! `scripts/quickstart.sh` — this verb talks to a running daemon.

use std::time::Instant;

use crate::control::{Client, Request, Response, TreeForkedBranch, VmConfig};
use crate::tree::TreeBudget;

/// Wall-clocks from one quickstart run.
#[derive(Debug, Clone)]
pub struct QuickstartClocks {
    /// Tree id used for this run.
    pub tree_id: String,
    /// Root node id.
    pub root_id: String,
    /// `tree_create_cluster` wall time, milliseconds.
    pub create_ms: u64,
    /// `tree_fork_batch` wall time (client Instant), milliseconds.
    pub fork_ms: u64,
    /// Daemon-reported batch latency, milliseconds.
    pub fork_daemon_ms: u64,
    /// New branch node ids, in label order.
    pub branches: Vec<String>,
    /// Whether the tree was left in place.
    pub kept: bool,
}

/// Budget for 3 source VMs + 4 × 3-VM forks. Loud, not a silent default
/// — the daemon's 8-VM default would reject the batch.
fn quickstart_budget() -> TreeBudget {
    TreeBudget {
        max_live_vms: 32,
        max_live_ram_bytes: 16 * 1024 * 1024 * 1024,
        max_disk_bytes: 64 * 1024 * 1024 * 1024,
        max_chain_depth: 8,
    }
}

fn elapsed_ms(t0: Instant) -> u64 {
    u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn drop_tree(client: &mut Client, tree_id: &str) {
    let _ = client.call(&Request::TreeDrop {
        tree_id: tree_id.to_string(),
    });
}

fn parse_created(resp: Response) -> Result<(String, Vec<u64>), String> {
    match resp {
        Response::TreeCreated {
            root_id,
            guest_cids,
            ..
        } => Ok((root_id, guest_cids)),
        Response::Error { message } => Err(format!("tree_create_cluster: {message}")),
        other => Err(format!("tree_create_cluster: unexpected {other:?}")),
    }
}

fn parse_batch(
    resp: Response,
    branches: usize,
    tree_id: &str,
    client: &mut Client,
) -> Result<(Vec<TreeForkedBranch>, u64), String> {
    match resp {
        Response::TreeForkBatch { forks, latency_ns } => {
            if forks.len() != branches {
                drop_tree(client, tree_id);
                return Err(format!(
                    "tree_fork_batch: expected {branches} branches, got {}",
                    forks.len()
                ));
            }
            for f in &forks {
                if f.guest_cids.len() != 3 {
                    drop_tree(client, tree_id);
                    return Err(format!(
                        "{}: expected 3 guest CIDs, got {}",
                        f.node_id,
                        f.guest_cids.len()
                    ));
                }
                if f.fork_memory_full_copy.iter().any(|full| *full) {
                    drop_tree(client, tree_id);
                    return Err(format!(
                        "{}: expected CoW fork, got fork_memory_full_copy={:?}",
                        f.node_id, f.fork_memory_full_copy
                    ));
                }
            }
            Ok((forks, latency_ns / 1_000_000))
        }
        Response::Error { message } => {
            drop_tree(client, tree_id);
            Err(format!("tree_fork_batch: {message}"))
        }
        other => {
            drop_tree(client, tree_id);
            Err(format!("tree_fork_batch: unexpected {other:?}"))
        }
    }
}

/// Busybox 3-node create + 4-branch fork against a live daemon.
///
/// Guest paths come from `kernel`/`initrd` or `K7D_KERNEL`/`K7D_INITRD`.
/// Drops the tree unless `keep` is set.
pub fn run_busybox_demo(
    client: &mut Client,
    tree_id: &str,
    branches: usize,
    keep: bool,
    kernel: Option<&str>,
    initrd: Option<&str>,
) -> Result<QuickstartClocks, String> {
    if branches < 1 {
        return Err("quickstart: branches must be >= 1".to_string());
    }
    let (kernel, initrd) = crate::config::resolve_guest_paths(kernel, initrd)?;
    let config = VmConfig {
        kernel: Some(kernel),
        initrd: Some(initrd),
        ..VmConfig::default()
    };

    let t0 = Instant::now();
    let created = client.call(&Request::TreeCreateCluster {
        vm_count: 3,
        config,
        budget: Some(quickstart_budget()),
        tree_id: Some(tree_id.to_string()),
        egress: None,
    })?;
    let create_ms = elapsed_ms(t0);
    let (root_id, guest_cids) = parse_created(created)?;
    if guest_cids.len() != 3 {
        drop_tree(client, tree_id);
        return Err(format!(
            "tree_create_cluster: expected 3 guest CIDs, got {}",
            guest_cids.len()
        ));
    }

    let labels: Vec<String> = (0..branches).map(|i| format!("qs-{i}")).collect();
    let t1 = Instant::now();
    let batch = client.call(&Request::TreeForkBatch {
        tree_id: tree_id.to_string(),
        source_id: root_id.clone(),
        labels,
        dilation: None,
    })?;
    let fork_ms = elapsed_ms(t1);
    let (forks, fork_daemon_ms) = parse_batch(batch, branches, tree_id, client)?;
    let clocks = QuickstartClocks {
        tree_id: tree_id.to_string(),
        root_id,
        create_ms,
        fork_ms,
        fork_daemon_ms,
        branches: forks.into_iter().map(|f| f.node_id).collect(),
        kept: keep,
    };

    if !keep {
        if let Err(e) = client.call(&Request::TreeDrop {
            tree_id: tree_id.to_string(),
        }) {
            return Err(format!("tree_drop {}: {e}", clocks.tree_id));
        }
    }
    Ok(clocks)
}

/// Print the clocks the way the HN try-path should look.
pub fn print_clocks(clocks: &QuickstartClocks) {
    println!(
        "quickstart: tree_create_cluster 3-node busybox  {:>8} ms",
        clocks.create_ms
    );
    println!(
        "quickstart: tree_fork_batch n={}                {:>8} ms  (daemon {} ms)",
        clocks.branches.len(),
        clocks.fork_ms,
        clocks.fork_daemon_ms
    );
    println!(
        "quickstart: branches {}  (CoW, {})",
        clocks.branches.join(", "),
        if clocks.kept { "kept" } else { "dropped" }
    );
    println!();
    println!("Two clocks (this box ran the first row):");
    println!("  minimal CI guest (this demo)     ~105 ms / fork   test-enforced 1 s budget");
    println!("  Ubuntu k3s+Cilium+Tetragon       ~1.1 s / fork    48 s source bring-up");
}
