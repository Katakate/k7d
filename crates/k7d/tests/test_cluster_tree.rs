//! Integration tests for the cluster snapshot tree.
//!
//! Requires KVM, /dev/vhost-vsock, /dev/net/tun, virtiofsd, and the built
//! guest kernel + initramfs.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use k7d::cluster_tree::{ClusterPayload, ClusterSnapshotTree};
use k7d::network::ClusterNetwork;
use k7d::tree::{NodeState, TreeBudget};
use k7d::vm::Vm;

fn workspace_path(relative: &str) -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join(relative)
}

fn build_cluster(label: &str, n: usize) -> ClusterPayload {
    // Test-setup hygiene: see k7d::network::cleanup_stale_k7_bridges.
    let _ = k7d::network::cleanup_stale_k7_bridges();
    let kernel = workspace_path("guest/kernel/vmlinux");
    let initrd = workspace_path("guest/rootfs/initramfs.cpio.gz");
    let mut net = ClusterNetwork::create(label).expect("bridge");
    let mut members: Vec<Vm> = Vec::with_capacity(n);
    for _ in 0..n {
        let tap = net.add_tap().expect("tap");
        let mut vm = Vm::builder()
            .kernel(&kernel)
            .initrd(&initrd)
            .memory_mb(256)
            .vsock(true)
            .guest_cid(k7d::vsock::allocate_cid())
            .network(tap)
            .build()
            .expect("vm build");
        vm.start().expect("vm start");
        let _ = vm
            .connect_agent(Duration::from_secs(90))
            .expect("agent ready");
        members.push(vm);
    }
    ClusterPayload {
        network: net,
        members,
    }
}

fn cluster_tree_budget() -> TreeBudget {
    TreeBudget {
        max_live_vms: 12, // 4 cluster nodes × 3 VMs
        max_live_ram_bytes: 4 * 1024 * 1024 * 1024,
        max_disk_bytes: 20 * 1024 * 1024 * 1024,
        max_chain_depth: 1,
    }
}

/// internal notes"Integration tests" — cluster fork preserves topology and
/// is independent from the source.
#[test]
fn test_cluster_tree_fork_preserves_topology() {
    let _ = env_logger::builder().is_test(true).try_init();

    let root = build_cluster("ct-fork-root", 2);
    let root_topology: Vec<(u32, std::net::Ipv4Addr, [u8; 6])> = root
        .network
        .entries()
        .map(|e| (e.vm_index, e.guest_ip, e.guest_mac))
        .collect();

    let dir = tempfile::tempdir().expect("tempdir");
    let (mut tree, root_id) =
        ClusterSnapshotTree::new_cluster(root, dir.path().to_path_buf(), cluster_tree_budget())
            .expect("new_cluster");

    assert_eq!(tree.get_node(&root_id).unwrap().vm_count, 2);

    // Fork — every member of the cluster forks atomically.
    let a = tree.fork(&root_id, "branch-a").expect("fork");
    assert_eq!(tree.get_node(&root_id).unwrap().children, vec![a.clone()]);
    let a_info = tree.get_node(&a).expect("branch-a info");
    assert_eq!(a_info.vm_count, 2);
    assert_eq!(a_info.state, NodeState::Live);

    // Forked cluster lives on a different bridge with the SAME per-VM
    // (vm_index, guest_ip, guest_mac) tuples — that's the contract spec
    // 9d's fork_cluster_warm provides and that this tree node inherits.
    let fork_payload = tree.get_payload(&a).expect("branch-a payload");
    assert_ne!(
        fork_payload.network.bridge_name(),
        tree.get_payload(&root_id)
            .expect("root payload")
            .network
            .bridge_name(),
        "fork bridge must differ from source bridge"
    );
    let fork_topology: Vec<(u32, std::net::Ipv4Addr, [u8; 6])> = fork_payload
        .network
        .entries()
        .map(|e| (e.vm_index, e.guest_ip, e.guest_mac))
        .collect();
    let mut sorted_root = root_topology.clone();
    sorted_root.sort_by_key(|(idx, _, _)| *idx);
    let mut sorted_fork = fork_topology;
    sorted_fork.sort_by_key(|(idx, _, _)| *idx);
    assert_eq!(
        sorted_fork, sorted_root,
        "fork must reproduce per-VM identity tuples on its own bridge"
    );

    // Cleanup
    tree.prune(&root_id).expect("prune");
}

/// internal notes"Integration tests" — suspend / resume round-trip rebuilds
/// the bridge with the same per-VM identity tuples. Doubles as the
/// budget assertion for `SUSPEND_CLUSTER_TREE_3VM` /
/// `RESUME_CLUSTER_TREE_3VM` (uses 2 VMs to keep total wall-clock
/// reasonable while still exercising the per-member parallelism).
#[test]
fn test_cluster_tree_suspend_resume_preserves_topology() {
    let _ = env_logger::builder().is_test(true).try_init();

    let root = build_cluster("ct-sr-root", 2);
    let root_topology: Vec<(u32, std::net::Ipv4Addr, [u8; 6])> = root
        .network
        .entries()
        .map(|e| (e.vm_index, e.guest_ip, e.guest_mac))
        .collect();

    let dir = tempfile::tempdir().expect("tempdir");
    let (mut tree, root_id) =
        ClusterSnapshotTree::new_cluster(root, dir.path().to_path_buf(), cluster_tree_budget())
            .expect("new_cluster");

    let suspend_start = Instant::now();
    tree.suspend(&root_id).expect("suspend root");
    let suspend_elapsed = suspend_start.elapsed();
    eprintln!("2-VM cluster-tree suspend: {suspend_elapsed:?}");
    assert!(
        suspend_elapsed < k7d::latency::SUSPEND_CLUSTER_TREE_3VM,
        "cluster-tree suspend should be <{:?}, was {suspend_elapsed:?}",
        k7d::latency::SUSPEND_CLUSTER_TREE_3VM,
    );
    assert_eq!(tree.get_node(&root_id).unwrap().state, NodeState::Suspended);
    assert!(
        tree.get_payload(&root_id).is_none(),
        "suspended cluster must have no live payload"
    );

    let resume_start = Instant::now();
    tree.resume(&root_id).expect("resume root");
    let resume_elapsed = resume_start.elapsed();
    eprintln!("2-VM cluster-tree resume: {resume_elapsed:?}");
    assert!(
        resume_elapsed < k7d::latency::RESUME_CLUSTER_TREE_3VM,
        "cluster-tree resume should be <{:?}, was {resume_elapsed:?}",
        k7d::latency::RESUME_CLUSTER_TREE_3VM,
    );
    assert_eq!(tree.get_node(&root_id).unwrap().state, NodeState::Live);
    let resumed = tree.get_payload(&root_id).expect("resumed root payload");
    let mut sorted_root = root_topology.clone();
    sorted_root.sort_by_key(|(idx, _, _)| *idx);
    let mut resumed_topology: Vec<(u32, std::net::Ipv4Addr, [u8; 6])> = resumed
        .network
        .entries()
        .map(|e| (e.vm_index, e.guest_ip, e.guest_mac))
        .collect();
    resumed_topology.sort_by_key(|(idx, _, _)| *idx);
    assert_eq!(
        resumed_topology, sorted_root,
        "resume must rebuild the bridge with the same per-VM identity tuples"
    );

    tree.prune(&root_id).expect("prune");
}

/// internal notes� shared-pause batch scales to 50× 3-VM cluster forks.
///
/// Asserts CoW on every member, distinct bridges, and wall-clock under
/// [`k7d::latency::FORK_CLUSTER_TREE_BATCH_50`]. Also requires the batch
/// to beat `50 × FORK_CLUSTER_TREE_3VM` (otherwise we gained nothing over
/// N independent tree forks at the single-fork ceiling).
#[test]
fn test_cluster_tree_fork_batch_50() {
    let _ = env_logger::builder().is_test(true).try_init();

    const N: usize = 50;
    let budget = TreeBudget {
        max_live_vms: 200, // root 3 + 50×3 = 153
        max_live_ram_bytes: 64 * 1024 * 1024 * 1024,
        max_disk_bytes: 64 * 1024 * 1024 * 1024,
        max_chain_depth: 1,
    };
    let root = build_cluster("ct-batch50", 3);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut tree, root_id) =
        ClusterSnapshotTree::new_cluster(root, dir.path().to_path_buf(), budget)
            .expect("new_cluster");

    let labels_owned: Vec<String> = (0..N).map(|i| format!("b{i}")).collect();
    let labels: Vec<&str> = labels_owned.iter().map(String::as_str).collect();

    let start = Instant::now();
    let ids = tree.fork_batch(&root_id, &labels).expect("fork_batch 50");
    let elapsed = start.elapsed();
    eprintln!(
        "cluster-tree fork_batch {N}×3-VM: {elapsed:?} ({:.1} ms/cluster)",
        elapsed.as_secs_f64() * 1000.0 / N as f64
    );

    assert_eq!(ids.len(), N);
    assert!(
        elapsed < k7d::latency::FORK_CLUSTER_TREE_BATCH_50,
        "fork_batch({N}) took {elapsed:?} > budget {:?}",
        k7d::latency::FORK_CLUSTER_TREE_BATCH_50
    );
    assert!(
        elapsed < k7d::latency::FORK_CLUSTER_TREE_3VM.saturating_mul(N as u32),
        "fork_batch({N}) took {elapsed:?}; must beat N× single-fork ceiling {:?}",
        k7d::latency::FORK_CLUSTER_TREE_3VM.saturating_mul(N as u32)
    );

    let mut bridges = std::collections::HashSet::new();
    for id in &ids {
        let payload = tree.get_payload(id).expect("live payload");
        assert_eq!(payload.members.len(), 3);
        for vm in &payload.members {
            assert!(
                !vm.fork_memory_is_full_copy(),
                "batch fork {id} member must be CoW"
            );
        }
        assert!(
            bridges.insert(payload.network.bridge_name().to_string()),
            "duplicate bridge {}",
            payload.network.bridge_name()
        );
    }
    assert_eq!(tree.get_node(&root_id).unwrap().children.len(), N);

    tree.prune(&root_id).expect("prune");
}

/// internal notes"Latency expectations" — 3-VM cluster fork ≤ 75 ms (50 ms
/// for internal notes's fork_cluster_warm + ~25 ms tree bookkeeping).
#[test]
fn test_cluster_tree_fork_under_75ms() {
    let _ = env_logger::builder().is_test(true).try_init();

    let root = build_cluster("ct-bench", 3);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut tree, root_id) =
        ClusterSnapshotTree::new_cluster(root, dir.path().to_path_buf(), cluster_tree_budget())
            .expect("new_cluster");

    let start = Instant::now();
    let fork_id = tree.fork(&root_id, "bench").expect("fork");
    let elapsed = start.elapsed();
    eprintln!("3-VM cluster-tree fork: {elapsed:?}");
    assert!(
        elapsed < k7d::latency::FORK_CLUSTER_TREE_3VM,
        "cluster-tree fork should be <{:?}, was {elapsed:?}",
        k7d::latency::FORK_CLUSTER_TREE_3VM,
    );
    assert_eq!(tree.get_node(&fork_id).unwrap().vm_count, 3);

    tree.prune(&root_id).expect("prune");
}

/// internal notes"Eviction policy edge cases" — auto-evict accounts for
/// `vm_count` against `max_live_vms`. Budget fits 2 of 3 cluster nodes
/// at 3 VMs each (=6 underlying VMs); forking a third triggers
/// auto-evict on the LRU cluster node.
#[test]
fn test_cluster_tree_auto_evict_lru() {
    let _ = env_logger::builder().is_test(true).try_init();

    let budget = TreeBudget {
        max_live_vms: 6, // 2 clusters × 3 VMs
        max_live_ram_bytes: u64::MAX,
        max_disk_bytes: u64::MAX,
        max_chain_depth: 1,
    };
    let root = build_cluster("ct-evict", 3);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut tree, root_id) =
        ClusterSnapshotTree::new_cluster(root, dir.path().to_path_buf(), budget)
            .expect("new_cluster");

    let _a = tree.fork(&root_id, "a").expect("fork a"); // root + a = 6 VMs (full)
    let _b = tree.fork(&root_id, "b").expect("fork b"); // forces auto-evict

    let live_vm_count: u32 = tree
        .list_nodes()
        .iter()
        .filter(|n| matches!(n.state, NodeState::Live))
        .map(|n| n.vm_count)
        .sum();
    assert!(
        live_vm_count <= 6,
        "cluster-aware auto-evict must keep Σ vm_count ≤ max_live_vms; was {live_vm_count}"
    );

    tree.prune(&root_id).expect("prune");
}

/// internal notes"Integration tests" — persistence round-trip:
/// open a tree from disk and observe the right node states + vm_count.
#[test]
fn test_cluster_tree_persistence_roundtrip() {
    let _ = env_logger::builder().is_test(true).try_init();

    let root = build_cluster("ct-persist", 2);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut tree, root_id) =
        ClusterSnapshotTree::new_cluster(root, dir.path().to_path_buf(), cluster_tree_budget())
            .expect("new_cluster");
    let a = tree.fork(&root_id, "branch-a").expect("fork");
    tree.suspend(&a).expect("suspend a");

    // Drop the tree (live payloads released, tree.json on disk).
    let root_dir = dir.path().to_path_buf();
    drop(tree);

    // Re-open from disk: tree.json + cluster.json must re-hydrate.
    let tree2 = ClusterSnapshotTree::open(root_dir).expect("open");
    // Live nodes downgrade to Suspended on open (their payloads are gone).
    assert_eq!(
        tree2.get_node(&root_id).unwrap().state,
        NodeState::Suspended,
        "live root must downgrade to suspended after open"
    );
    assert_eq!(
        tree2.get_node(&a).unwrap().state,
        NodeState::Suspended,
        "branch-a was already suspended"
    );
    assert_eq!(tree2.get_node(&a).unwrap().vm_count, 2);
    assert_eq!(tree2.get_node(&root_id).unwrap().vm_count, 2);
}
