//! Integration test for part 2: snapshot tree.
//! Requires KVM, /dev/vhost-vsock, built guest kernel + initramfs.

use std::time::Duration;

use k7d::tree::{NodeState, SnapshotTree, TreeBudget};
use k7d::vm::Vm;

fn create_test_vm() -> Vm {
    create_test_vm_with_vcpus(1)
}

fn create_test_vm_with_vcpus(vcpus: u32) -> Vm {
    Vm::builder()
        .kernel_and_initrd()
        .memory_mb(256)
        .vcpus(vcpus)
        .vsock(true)
        .build()
        .expect("VM should build")
}

fn default_budget() -> TreeBudget {
    TreeBudget {
        max_live_vms: 10,
        max_live_ram_bytes: 2 * 1024 * 1024 * 1024,
        max_disk_bytes: 10 * 1024 * 1024 * 1024,
        max_chain_depth: 1,
    }
}

#[test]
fn test_tree_fork_and_rollback() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut vm = create_test_vm();
    vm.start().unwrap();
    let mut agent = vm.connect_agent(Duration::from_secs(90)).unwrap();
    agent
        .exec(&["sh", "-c", "echo 'root-state' > /tmp/marker"])
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let (mut tree, root_id) =
        SnapshotTree::new(vm, dir.path().to_path_buf(), default_budget()).unwrap();

    // Reconnect to the root VM (prepare_fork_source replaces vsock).
    {
        let vm_root = tree.get_vm_mut(&root_id).unwrap();
        let mut root_agent = vm_root.connect_agent(Duration::from_secs(30)).unwrap();
        root_agent.ping().unwrap();
    }

    // Fork two branches from root.
    let a = tree.fork(&root_id, "branch-a").unwrap();
    let b = tree.fork(&root_id, "branch-b").unwrap();
    assert_eq!(tree.get_node(&root_id).unwrap().children.len(), 2);
    assert_eq!(tree.get_node(&a).unwrap().parent, Some(root_id.clone()));
    assert_eq!(tree.get_node(&b).unwrap().parent, Some(root_id.clone()));

    // Mutate branch A.
    {
        let vm_a = tree.get_vm_mut(&a).unwrap();
        let mut agent_a = vm_a.connect_agent(Duration::from_secs(30)).unwrap();
        agent_a
            .exec(&["sh", "-c", "echo 'branch-a' > /tmp/marker"])
            .unwrap();
    }

    // Suspend branch A.
    tree.suspend(&a).unwrap();
    assert_eq!(tree.get_node(&a).unwrap().state, NodeState::Suspended);
    assert!(tree.get_vm(&a).is_none(), "suspended VM should not be live");

    // Rollback to root — creates a new branch C from root's state.
    let c = tree.rollback(&root_id, "branch-c").unwrap();
    {
        let vm_c = tree.get_vm(&c).unwrap();
        let mut agent_c = vm_c.connect_agent(Duration::from_secs(30)).unwrap();
        let result = agent_c.exec(&["cat", "/tmp/marker"]).unwrap();
        assert_eq!(
            result.stdout.trim(),
            "root-state",
            "rollback should see root state, not A's mutation"
        );
    }

    // Resume A — should have A's mutation.
    tree.resume(&a).unwrap();
    assert_eq!(tree.get_node(&a).unwrap().state, NodeState::Live);
    {
        let vm_a = tree.get_vm(&a).unwrap();
        let mut agent_a = vm_a.connect_agent(Duration::from_secs(30)).unwrap();
        let result_a = agent_a.exec(&["cat", "/tmp/marker"]).unwrap();
        assert_eq!(
            result_a.stdout.trim(),
            "branch-a",
            "resumed A should see its own mutation"
        );
    }

    // Prune B — it's gone from the tree.
    tree.prune(&b).unwrap();
    assert!(tree.get_node(&b).is_none());
}

/// A child is not a fork source until prepared. `fork_batch` must
/// checkpoint it so a grandchild's parent is the child, not root.
#[test]
fn test_tree_fork_from_child() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut vm = create_test_vm();
    vm.start().unwrap();
    vm.connect_agent(Duration::from_secs(90)).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let (mut tree, root_id) =
        SnapshotTree::new(vm, dir.path().to_path_buf(), default_budget()).unwrap();

    let child = tree.fork(&root_id, "child").unwrap();
    assert_eq!(
        tree.get_node(&child).unwrap().parent.as_deref(),
        Some("root")
    );
    assert!(!tree.get_node(&child).unwrap().has_base_snapshot);

    // Graph depth 2 under `max_chain_depth: 1` must succeed —
    // `max_chain_depth` caps the restore chain (delta hops to the nearest
    // checkpoint), NOT tree-graph depth (the referenced work regression guard:
    // a naive graph-depth check would fail this fork).
    assert_eq!(default_budget().max_chain_depth, 1);
    let grand = tree.fork(&child, "grand").unwrap();
    assert_eq!(
        tree.get_node(&grand).unwrap().parent.as_deref(),
        Some(child.as_str())
    );
    assert!(tree.get_node(&child).unwrap().has_base_snapshot);
    assert!(tree
        .get_vm(&child)
        .unwrap()
        .fork_source_base_path()
        .is_some());

    // The grandchild's restore chain is 1 hop (its delta on the child's
    // memory.bin), so suspend/resume must pass the max_chain_depth guard.
    tree.suspend(&grand).unwrap();
    tree.resume(&grand).unwrap();
    assert_eq!(tree.get_node(&grand).unwrap().state, NodeState::Live);

    tree.prune(&root_id).unwrap();
}

/// the referenced work: `prepare_fork_source` must check the disk budget BEFORE
/// writing a new `memory.bin`, failing loud (`BudgetExhausted`) when there
/// is no headroom and nothing evictable — not silently blowing
/// `max_disk_bytes` until the next auto_evict.
#[test]
fn test_tree_prepare_disk_budget_loud() {
    let _ = env_logger::builder().is_test(true).try_init();

    // Room for the root's 256 MiB base only; a child prepare would need
    // another 256 MiB and nothing is evictable (no suspended subtrees).
    let budget = TreeBudget {
        max_live_vms: 10,
        max_live_ram_bytes: u64::MAX,
        max_disk_bytes: 320 * 1024 * 1024,
        max_chain_depth: 1,
    };
    let dir = tempfile::tempdir().unwrap();
    let mut vm = create_test_vm();
    vm.start().unwrap();
    vm.connect_agent(Duration::from_secs(90)).unwrap();

    let (mut tree, root) = SnapshotTree::new(vm, dir.path().to_path_buf(), budget).unwrap();
    let a = tree.fork(&root, "a").unwrap(); // root already prepared: no new base

    let err = tree
        .fork(&a, "grand")
        .expect_err("fork from unprepared child must refuse to blow the disk budget");
    assert!(
        matches!(err, k7d::tree::TreeError::BudgetExhausted { .. }),
        "expected BudgetExhausted, got: {err}"
    );
    // The failed prepare must not have half-written a base or broken the tree.
    assert!(!tree.get_node(&a).unwrap().has_base_snapshot);
    assert_eq!(tree.get_node(&a).unwrap().state, NodeState::Live);

    tree.prune(&root).unwrap();
}

#[test]
fn test_tree_auto_evict_lru() {
    let _ = env_logger::builder().is_test(true).try_init();

    let budget = TreeBudget {
        max_live_vms: 2, // only 2 live VMs allowed
        max_live_ram_bytes: u64::MAX,
        max_disk_bytes: u64::MAX,
        max_chain_depth: 1,
    };
    let dir = tempfile::tempdir().unwrap();
    let mut vm = create_test_vm();
    vm.start().unwrap();
    vm.connect_agent(Duration::from_secs(90)).unwrap();

    let (mut tree, root) = SnapshotTree::new(vm, dir.path().to_path_buf(), budget).unwrap();
    {
        let vm_root = tree.get_vm_mut(&root).unwrap();
        vm_root.connect_agent(Duration::from_secs(30)).unwrap();
    }

    let _a = tree.fork(&root, "a").unwrap();
    // root + a = 2 live VMs. Budget full. Adding a third triggers auto-evict.
    let _b = tree.fork(&root, "b").unwrap();

    let live_count = tree
        .list_nodes()
        .iter()
        .filter(|n| matches!(n.state, NodeState::Live))
        .count();
    assert!(
        live_count <= 2,
        "auto-evict should keep live count <= budget, was {live_count}"
    );
}

#[test]
fn test_tree_disk_eviction() {
    let _ = env_logger::builder().is_test(true).try_init();

    // The root is protected by default (no — protection is opt-in), but it
    // has children (a, b) so it's NOT an evictable leaf subtree. The
    // suspended leaves (a, b) are evictable. Set the disk budget smaller than
    // root's 256 MB base + deltas so auto_evict must drop delta.pack of
    // at least one leaf.
    let budget = TreeBudget {
        max_live_vms: 10,
        max_live_ram_bytes: u64::MAX,
        max_disk_bytes: 256 * 1024 * 1024 + 1024, // only room for root base
        max_chain_depth: 1,
    };
    let dir = tempfile::tempdir().unwrap();
    let mut vm = create_test_vm();
    vm.start().unwrap();
    vm.connect_agent(Duration::from_secs(90)).unwrap();

    let (mut tree, root) = SnapshotTree::new(vm, dir.path().to_path_buf(), budget).unwrap();
    {
        let vm_root = tree.get_vm_mut(&root).unwrap();
        vm_root.connect_agent(Duration::from_secs(30)).unwrap();
    }

    // Dirty a bunch of pages before suspending, so the deltas are non-trivial.
    {
        let vm_root = tree.get_vm_mut(&root).unwrap();
        let mut agent = vm_root.connect_agent(Duration::from_secs(30)).unwrap();
        agent
            .exec(&["dd", "if=/dev/urandom", "of=/tmp/dirty", "bs=1M", "count=4"])
            .unwrap();
    }

    let a = tree.fork(&root, "a").unwrap();
    tree.suspend(&a).unwrap();
    let b = tree.fork(&root, "b").unwrap();
    tree.suspend(&b).unwrap();

    let disk_before = tree.usage().disk_bytes;
    let _affected = tree.auto_evict().unwrap();
    let usage = tree.usage();
    eprintln!(
        "disk eviction: {} B -> {} B (budget {} B)",
        disk_before, usage.disk_bytes, budget.max_disk_bytes
    );
    assert!(
        usage.disk_bytes <= budget.max_disk_bytes,
        "disk usage {}B should be within budget {}B after eviction",
        usage.disk_bytes,
        budget.max_disk_bytes,
    );
}

#[test]
fn test_tree_protection() {
    let _ = env_logger::builder().is_test(true).try_init();

    let budget = TreeBudget {
        max_live_vms: 2,
        max_live_ram_bytes: u64::MAX,
        max_disk_bytes: u64::MAX,
        max_chain_depth: 1,
    };
    let dir = tempfile::tempdir().unwrap();
    let mut vm = create_test_vm();
    vm.start().unwrap();
    vm.connect_agent(Duration::from_secs(90)).unwrap();

    let (mut tree, root) = SnapshotTree::new(vm, dir.path().to_path_buf(), budget).unwrap();
    {
        let vm_root = tree.get_vm_mut(&root).unwrap();
        vm_root.connect_agent(Duration::from_secs(30)).unwrap();
    }

    let a = tree.fork(&root, "a").unwrap(); // budget now full: root + a
    tree.protect(&a);

    // Forking b needs headroom for 1 incoming VM : fork_batch
    // evicts BEFORE forking, exempting the source (root). The only candidate
    // is "a", which is protected → deterministic loud BudgetExhausted; the
    // fork must NOT silently overshoot max_live_vms.
    let err = tree
        .fork(&root, "b")
        .expect_err("fork with only protected eviction candidates must fail loud");
    assert!(
        matches!(err, k7d::tree::TreeError::BudgetExhausted { .. }),
        "expected BudgetExhausted, got: {err}"
    );

    // The protected node was never suspended to make room.
    assert_eq!(
        tree.get_node(&a).unwrap().state,
        NodeState::Live,
        "protected node should never be auto-evicted"
    );
    assert_eq!(tree.get_node(&root).unwrap().state, NodeState::Live);
}

/// Checkpoint → fork → rollback a 2-vCPU VM through the
/// snapshot tree, plus suspend + resume. Every materialised VM must
/// still see 2 CPUs (per-vCPU state travels through capture,
/// delta.pack replay, and `build_vm_from_state_and_mem`).
#[test]
fn test_tree_checkpoint_multi_vcpu() {
    let _ = env_logger::builder().is_test(true).try_init();

    fn assert_two_cpus(agent: &mut k7d::api::AgentClient, who: &str) {
        let nproc = agent
            .exec(&["sh", "-c", "grep -c ^processor /proc/cpuinfo"])
            .expect("cpu count should run");
        assert_eq!(nproc.stdout.trim(), "2", "{who} must see 2 CPUs");
    }

    let mut vm = create_test_vm_with_vcpus(2);
    vm.start().unwrap();
    let mut agent = vm.connect_agent(Duration::from_secs(90)).unwrap();
    assert_two_cpus(&mut agent, "2-vCPU root before tree");
    agent
        .exec(&["sh", "-c", "echo 'smp-root' > /tmp/marker"])
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let (mut tree, root_id) =
        SnapshotTree::new(vm, dir.path().to_path_buf(), default_budget()).unwrap();
    {
        let vm_root = tree.get_vm_mut(&root_id).unwrap();
        assert_eq!(vm_root.vcpu_count(), 2, "root must keep 2 vCPUs");
        let mut root_agent = vm_root.connect_agent(Duration::from_secs(30)).unwrap();
        assert_two_cpus(&mut root_agent, "root after prepare_fork_source");
    }

    // Fork: the branch inherits root's state on both CPUs.
    let a = tree.fork(&root_id, "smp-a").unwrap();
    {
        let vm_a = tree.get_vm_mut(&a).unwrap();
        assert_eq!(vm_a.vcpu_count(), 2, "fork must keep 2 vCPUs");
        let mut agent_a = vm_a.connect_agent(Duration::from_secs(30)).unwrap();
        assert_two_cpus(&mut agent_a, "forked branch");
        let marker = agent_a.exec(&["cat", "/tmp/marker"]).unwrap();
        assert_eq!(marker.stdout.trim(), "smp-root");
        agent_a
            .exec(&["sh", "-c", "echo 'smp-a' > /tmp/marker"])
            .unwrap();
    }

    // Suspend + resume A (delta.pack write + replay of a 2-vCPU VM).
    tree.suspend(&a).unwrap();
    assert_eq!(tree.get_node(&a).unwrap().state, NodeState::Suspended);
    tree.resume(&a).unwrap();
    {
        let vm_a = tree.get_vm_mut(&a).unwrap();
        assert_eq!(vm_a.vcpu_count(), 2, "resumed VM must keep 2 vCPUs");
        let mut agent_a = vm_a.connect_agent(Duration::from_secs(30)).unwrap();
        assert_two_cpus(&mut agent_a, "resumed branch");
        let marker = agent_a.exec(&["cat", "/tmp/marker"]).unwrap();
        assert_eq!(marker.stdout.trim(), "smp-a", "resume must keep A's state");
    }

    // Rollback to root — new branch sees root's pre-fork state on 2 CPUs.
    let c = tree.rollback(&root_id, "smp-c").unwrap();
    {
        let vm_c = tree.get_vm_mut(&c).unwrap();
        assert_eq!(vm_c.vcpu_count(), 2, "rollback must keep 2 vCPUs");
        let mut agent_c = vm_c.connect_agent(Duration::from_secs(30)).unwrap();
        assert_two_cpus(&mut agent_c, "rollback branch");
        let marker = agent_c.exec(&["cat", "/tmp/marker"]).unwrap();
        assert_eq!(marker.stdout.trim(), "smp-root");
    }
}

#[test]
fn test_tree_delta_format_roundtrip() {
    // Pure in-memory test: no KVM required.
    use k7d::tree::{apply_delta, write_delta};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("delta.pack");

    // 16 KiB source region, 4 pages, mark pages 0 and 2 as dirty.
    let mem_size: u64 = 16 * 1024;
    let src: Vec<u8> = (0..mem_size).map(|i| (i & 0xff) as u8).collect();
    let src_addr = src.as_ptr() as u64;
    let mut bitmap = vec![0u64; 1];
    bitmap[0] |= 1 << 0;
    bitmap[0] |= 1 << 2;

    let page_count = write_delta(&path, &bitmap, src_addr, mem_size, String::new()).unwrap();
    assert_eq!(page_count, 2);

    // Apply delta into a zeroed region.
    let mut dst = vec![0u8; mem_size as usize];
    let dst_addr = dst.as_mut_ptr() as u64;
    let applied = apply_delta(&path, dst_addr, mem_size).unwrap();
    assert_eq!(applied, 2);

    // Page 0 (0..4096) and page 2 (8192..12288) should match src; the rest
    // should still be zero.
    assert_eq!(&dst[0..4096], &src[0..4096]);
    assert!(dst[4096..8192].iter().all(|&b| b == 0));
    assert_eq!(&dst[8192..12288], &src[8192..12288]);
    assert!(dst[12288..].iter().all(|&b| b == 0));
}

/// Regression for CHALLENGES.md #130 on the single-VM tree: fork-of-fork
/// and suspend/resume of a fork child with a **read-write block device**.
///
/// A forked VM runs on a reflinked RW image it owns (`fork_state_dir`,
/// removed on Drop). Pre-fix, preparing a fork child as a fork source
/// dropped the husk that owned the child's image (the next FICLONE hit
/// ENOENT), and suspending a fork child deleted its image outright, so
/// resume's reflink hit the same ENOENT.
#[test]
fn test_tree_fork_of_fork_with_rw_disk() {
    use std::path::Path;

    use k7d::disks::{ensure_loopback_xfs, DISKS_DIR, DISKS_IMAGE, DISKS_IMAGE_SIZE};

    let _ = env_logger::builder().is_test(true).try_init();
    ensure_loopback_xfs(
        Path::new(DISKS_IMAGE),
        Path::new(DISKS_DIR),
        DISKS_IMAGE_SIZE,
    )
    .expect("reflink XFS at /var/lib/k7d/disks");

    let img = Path::new(DISKS_DIR).join(format!("tree-fof-{}.img", std::process::id()));
    std::fs::write(&img, vec![0u8; 4 * 1024 * 1024]).expect("write RW image");

    let mut vm = Vm::builder()
        .kernel_and_initrd()
        .memory_mb(256)
        .vsock(true)
        .block_device(&img, false)
        .build()
        .expect("VM should build");
    vm.start().unwrap();
    let _ = vm.connect_agent(Duration::from_secs(90)).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let budget = TreeBudget {
        max_live_vms: 10,
        max_live_ram_bytes: 4 * 1024 * 1024 * 1024,
        max_disk_bytes: 10 * 1024 * 1024 * 1024,
        max_chain_depth: 8,
    };
    let (mut tree, root_id) = SnapshotTree::new(vm, dir.path().to_path_buf(), budget).unwrap();

    let disk_of = |tree: &SnapshotTree, id: &String| {
        let vm = tree.get_vm(id).expect("live vm");
        vm.block_devices()
            .first()
            .expect("has a block device")
            .host_path
            .clone()
    };

    let child = tree.fork(&root_id, "child").expect("fork from root");
    assert!(disk_of(&tree, &child).exists(), "child image deleted");
    let grand = tree
        .fork(&child, "grand")
        .expect("fork-of-fork with a RW disk (CHALLENGES #130)");
    assert!(disk_of(&tree, &child).exists(), "child image deleted");
    assert!(disk_of(&tree, &grand).exists(), "grand image deleted");

    // Suspend/resume of the fork child: image parked, reflinked, reaped.
    tree.suspend(&grand).expect("suspend fork child");
    let parked = tree.get_node(&grand).unwrap().parked_disk_dirs.clone();
    assert!(
        !parked.is_empty(),
        "suspended fork child must park its RW disk-clone dir"
    );
    assert!(parked.iter().all(|d| d.exists()));
    tree.resume(&grand).expect("resume fork child with RW disk");
    assert!(tree.get_node(&grand).unwrap().parked_disk_dirs.is_empty());
    assert!(parked.iter().all(|d| !d.exists()), "resume must reap");
    assert!(disk_of(&tree, &grand).exists(), "resumed image missing");

    // Prune of a suspended fork child reaps the parked image.
    tree.suspend(&grand).expect("suspend for prune");
    let parked2 = tree.get_node(&grand).unwrap().parked_disk_dirs.clone();
    assert!(!parked2.is_empty());
    tree.prune(&grand).expect("prune suspended child");
    assert!(parked2.iter().all(|d| !d.exists()), "prune must reap");

    tree.prune(&root_id).expect("prune");
    let _ = std::fs::remove_file(&img);
}
