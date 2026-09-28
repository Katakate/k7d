//! Refresh an adopted Ubuntu node's keyframe in place of the dirty set.
//!
//! `new_cluster` is the adopt cut: one full keyframe, dirty bitmap
//! zeroed. After the guest dirties a known chunk, `prepare_fork_source`
//! with `refresh` writes a new generation (the old `memory.bin` stays,
//! because the child re-opens it by path) and the next fork's memcpy
//! drops to about what was dirtied after that refresh.

mod common;

use std::time::Duration;

use k7d::api::AgentClient;
use k7d::cluster_tree::{ClusterPayload, ClusterSnapshotTree};
use k7d::guest::Guest;
use k7d::network::ClusterNetwork;
use k7d::tree::{NodeId, NodeState, TreeBudget};

use common::ubuntu::{build_node_vm, node_image, sh_ok, VmDisk, BOOT_TO_AGENT_CEILING};

const DIRTY_MIB: u64 = 768;

fn budget() -> TreeBudget {
    TreeBudget {
        max_live_vms: 8,
        max_live_ram_bytes: 32 * 1024 * 1024 * 1024,
        max_disk_bytes: 64 * 1024 * 1024 * 1024,
        max_chain_depth: 1,
    }
}

fn agent(tree: &ClusterSnapshotTree, id: &NodeId) -> AgentClient {
    tree.get_payload(id)
        .unwrap_or_else(|| panic!("{id} has no live payload"))
        .members
        .first()
        .unwrap_or_else(|| panic!("{id} has no member"))
        .connect_agent(BOOT_TO_AGENT_CEILING)
        .unwrap_or_else(|e| panic!("{id}: agent: {e}"))
}

fn marker(tree: &ClusterSnapshotTree, id: &NodeId) -> String {
    let mut client = agent(tree, id);
    sh_ok(&mut client, "cat /dev/shm/marker").trim().to_string()
}

fn base_path(tree: &ClusterSnapshotTree, id: &NodeId) -> std::path::PathBuf {
    tree.get_payload(id)
        .unwrap_or_else(|| panic!("{id} has no live payload"))
        .members[0]
        .as_native()
        .expect("native")
        .fork_source_base_path()
        .unwrap_or_else(|| panic!("{id} has no keyframe path"))
        .to_path_buf()
}

fn copied_pages(tree: &ClusterSnapshotTree) -> u64 {
    tree.last_fork_copied_pages().iter().sum()
}

/// Adopt, dirty, fork, refresh, fork again. The second copy is the
/// post-refresh dirty set. The child forked before the refresh still
/// sees its marker after the root has moved on, including across a
/// suspend that happens after the refresh.
#[test]
#[allow(clippy::too_many_lines)]
fn test_ubuntu_keyframe_refresh_shrinks_the_next_fork() {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = k7d::network::cleanup_stale_k7_bridges();

    // Disk first so it outlives the tree: the root VM keeps this file
    // open, and Drop removes it.
    let image = node_image();
    let disk = VmDisk::clone_of(&image.base_image(), "kf-refresh");
    let root_dir = common::ReflinkTreeRoot::new("ubu-kf");

    let mut net = ClusterNetwork::create("ukf").expect("bridge");
    let tap = net.add_tap().expect("tap");
    let mut vm = build_node_vm(&image, &disk, tap);
    vm.start().expect("start");
    {
        let mut booted = match vm.connect_agent(BOOT_TO_AGENT_CEILING) {
            Ok(a) => a,
            Err(e) => panic!(
                "no agent within {BOOT_TO_AGENT_CEILING:?}: {e}\n--- serial ---\n{}",
                vm.serial_output(Duration::from_secs(1))
            ),
        };
        sh_ok(&mut booted, "echo booted > /dev/shm/marker");
    }

    let (mut tree, root) = ClusterSnapshotTree::new_cluster(
        ClusterPayload {
            network: net,
            members: vec![Guest::from(vm)],
        },
        root_dir.path().to_path_buf(),
        budget(),
    )
    .expect("adopt");
    let adopt = tree.root_cut().expect("adopt cut").clone();
    eprintln!(
        "MEASUREMENT keyframe adopt pause_ns {:?} max_pause_ns {}",
        adopt.pause_ns(),
        adopt.max_pause_ns()
    );
    assert!(adopt.is_consistent(), "adopt cut: {adopt:?}");
    assert_eq!(tree.get_node(&root).expect("root").base_identity, 1);

    // The swap replaced the VM. Reconnect, then dirty a known set.
    {
        let mut guest = agent(&tree, &root);
        sh_ok(
            &mut guest,
            &format!(
                "dd if=/dev/zero of=/dev/shm/dirty bs=1M count={DIRTY_MIB} status=none \
                 && echo PRE > /dev/shm/marker && sync"
            ),
        );
    }
    // `accumulated_dirty_pages` is the harvested bitmap, still zero until
    // a fork or a keyframe drains the KVM log. The memcpy count is that drain.
    let pre = tree.fork(&root, "pre").expect("fork before refresh");
    let copied_before = copied_pages(&tree);
    let before_bytes = copied_before.saturating_mul(4096);
    eprintln!("MEASUREMENT keyframe fork_copy_before pages {copied_before} bytes {before_bytes}");
    assert!(
        before_bytes > (DIRTY_MIB - 64) * 1024 * 1024,
        "first fork copied {before_bytes} bytes, expected about the {DIRTY_MIB} MiB dirty set"
    );
    assert_eq!(marker(&tree, &pre), "PRE");

    let old_mem = root_dir
        .path()
        .join("nodes")
        .join(&root)
        .join("members")
        .join("0")
        .join("memory.bin");
    assert!(old_mem.is_file(), "first keyframe {}", old_mem.display());
    assert_eq!(base_path(&tree, &pre), old_mem);

    let refreshed = tree.prepare_fork_source_with(&root, true).expect("refresh");
    assert!(refreshed.wrote_base, "{refreshed:?}");
    assert!(
        refreshed.incremental,
        "refresh of an adopted root must be incremental against its own keyframe: {refreshed:?}"
    );
    let span = 2048 * 1024 * 1024;
    assert!(
        refreshed.disk_bytes < span * 3 / 4,
        "refresh wrote {} bytes, a full {}-byte dump",
        refreshed.disk_bytes,
        span
    );
    assert!(
        refreshed.disk_bytes > (DIRTY_MIB - 128) * 1024 * 1024,
        "incremental refresh recorded only {} bytes for a {DIRTY_MIB} MiB dirty set",
        refreshed.disk_bytes
    );
    let refresh_cut = tree.prepare_cut().expect("refresh cut").clone();
    eprintln!(
        "MEASUREMENT keyframe refresh pause_ns {:?} max_pause_ns {} incremental {} disk_bytes {}",
        refresh_cut.pause_ns(),
        refresh_cut.max_pause_ns(),
        refreshed.incremental,
        refreshed.disk_bytes
    );
    assert!(refresh_cut.is_consistent(), "refresh cut: {refresh_cut:?}");
    assert!(refresh_cut.members.iter().all(|m| m.incremental));
    assert_eq!(tree.get_node(&root).expect("root").base_identity, 2);
    assert!(
        tree.get_node(&root)
            .expect("root")
            .retained_keyframes
            .iter()
            .any(|g| g.identity == 1),
        "generation 1 must stay accounted while children map it"
    );

    let new_mem = base_path(&tree, &root);
    assert!(
        new_mem
            .components()
            .any(|c| c.as_os_str().to_string_lossy().starts_with("gen-")),
        "refreshed root maps {}, not a new generation file",
        new_mem.display()
    );
    assert_ne!(new_mem, old_mem);
    assert!(new_mem.is_file(), "{}", new_mem.display());
    // The child still names the file it was forked from.
    assert_eq!(base_path(&tree, &pre), old_mem);
    assert_eq!(marker(&tree, &pre), "PRE");

    {
        let mut guest = agent(&tree, &root);
        sh_ok(&mut guest, "echo POST > /dev/shm/marker");
    }
    let post = tree.fork(&root, "post").expect("fork after refresh");
    let copied_after = copied_pages(&tree);
    let after_bytes = copied_after.saturating_mul(4096);
    eprintln!("MEASUREMENT keyframe fork_copy_after pages {copied_after} bytes {after_bytes}");
    assert!(
        after_bytes.saturating_mul(4) < before_bytes,
        "fork copy did not drop: before {before_bytes} after {after_bytes}"
    );
    // The post-refresh dirty set is the POST marker plus whatever the
    // guest wrote after the swap, not the 768 MiB file already in the
    // new keyframe.
    assert!(
        after_bytes < 128 * 1024 * 1024,
        "after-refresh fork copied {after_bytes} bytes; expected the small post-refresh dirty set"
    );
    assert_eq!(marker(&tree, &post), "POST");
    assert_eq!(base_path(&tree, &post), new_mem);
    assert_eq!(marker(&tree, &pre), "PRE");

    // Suspend after the refresh: the pack must name generation 1, and
    // resume must open the old file rather than the root's new one.
    tree.suspend(&pre).expect("suspend pre-refresh child");
    assert_eq!(
        tree.get_node(&pre).expect("pre").state,
        NodeState::Suspended
    );
    tree.resume(&pre).expect("resume pre-refresh child");
    assert_eq!(marker(&tree, &pre), "PRE");
    assert_eq!(base_path(&tree, &pre), old_mem);
    assert!(
        old_mem.is_file(),
        "old keyframe removed while a child still maps it"
    );
    assert_eq!(marker(&tree, &post), "POST");

    let again = tree
        .prepare_fork_source_with(&root, false)
        .expect("idempotent prepare");
    assert!(
        !again.wrote_base,
        "refresh=false rewrote a keyframe: {again:?}"
    );
    assert_eq!(base_path(&tree, &root), new_mem);

    tree.prune(&root).expect("prune");
    // `disk` is declared before `tree`, so it drops after the VMs close.
    drop(tree);
    drop(disk);
}
