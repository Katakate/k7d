//! Integration test for part 2: snapshot tree.
//! Requires KVM, /dev/vhost-vsock, built guest kernel + initramfs.

use std::time::Duration;

use k7d::tree::{NodeState, SnapshotTree, TreeBudget, TreeError};
use k7d::vm::Vm;

mod common;

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

/// A child is not a checkpoint until prepared. `fork_batch` inherits
/// the ancestor keyframe so a grandchild's parent is still the child.
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
    // checkpoint), NOT tree-graph depth (regression guard:
    // a naive graph-depth check would fail this fork).
    assert_eq!(default_budget().max_chain_depth, 1);
    let grand = tree.fork(&child, "grand").unwrap();
    assert_eq!(
        tree.get_node(&grand).unwrap().parent.as_deref(),
        Some(child.as_str())
    );
    assert!(
        !tree.get_node(&child).unwrap().has_base_snapshot,
        "fork from child inherits the ancestor keyframe; no new memory.bin"
    );
    assert!(tree
        .get_vm(&child)
        .unwrap()
        .as_native()
        .unwrap()
        .fork_source_base_path()
        .is_some());

    // Grandchild packs against the root checkpoint (one delta.pack).
    // Unprepared hops on the parent path are not extra packs.
    tree.suspend(&grand).unwrap();
    tree.resume(&grand).unwrap();
    assert_eq!(tree.get_node(&grand).unwrap().state, NodeState::Live);

    tree.prune(&root_id).unwrap();
}

/// Graph depth 3 still inherits one ancestor file. Resume applies one
/// pack. No intermediate keyframe.
#[test]
fn test_tree_fork_from_grandchild_without_prepare() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut vm = create_test_vm();
    vm.start().unwrap();
    vm.connect_agent(Duration::from_secs(90)).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let (mut tree, root_id) =
        SnapshotTree::new(vm, dir.path().to_path_buf(), default_budget()).unwrap();

    let child = tree.fork(&root_id, "child").unwrap();
    let grand = tree.fork(&child, "grand").unwrap();
    let great = tree.fork(&grand, "great").unwrap();
    assert_eq!(
        tree.get_node(&great).unwrap().parent.as_deref(),
        Some(grand.as_str())
    );
    for id in [&child, &grand, &great] {
        assert!(
            !tree.get_node(id).unwrap().has_base_snapshot,
            "{id} must inherit, not own a keyframe"
        );
        assert!(
            tree.get_vm(id)
                .unwrap()
                .as_native()
                .unwrap()
                .fork_source_base_path()
                .is_some(),
            "{id} must be forkable against the ancestor file"
        );
    }

    tree.suspend(&great).unwrap();
    tree.resume(&great).unwrap();
    assert_eq!(tree.get_node(&great).unwrap().state, NodeState::Live);
    assert!(
        !tree.get_node(&great).unwrap().has_base_snapshot,
        "resume of an unprepared node must not mint a keyframe"
    );
    assert!(tree
        .get_vm(&great)
        .unwrap()
        .as_native()
        .unwrap()
        .fork_source_base_path()
        .is_some());

    tree.prune(&root_id).unwrap();
}

/// `prepare_fork_source` must check the disk budget BEFORE
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
    let a = tree.fork(&root, "a").unwrap(); // inherit: no new base
    let grand = tree.fork(&a, "grand").unwrap(); // inherit: still no new base
    assert!(!tree.get_node(&a).unwrap().has_base_snapshot);
    assert!(!tree.get_node(&grand).unwrap().has_base_snapshot);

    let err = tree
        .prepare_fork_source(&a)
        .expect_err("explicit prepare on a child must refuse to blow the disk budget");
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

    // Forking b needs headroom for 1 incoming VM: fork_batch
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

    let base_identity: u64 = 7;
    let page_count = write_delta(&path, &bitmap, src_addr, mem_size, base_identity).unwrap();
    assert_eq!(page_count, 2);

    // Apply delta into a zeroed region.
    let mut dst = vec![0u8; mem_size as usize];
    let dst_addr = dst.as_mut_ptr() as u64;
    let applied = apply_delta(&path, dst_addr, mem_size, base_identity).unwrap();
    assert_eq!(applied.page_count, 2);
    // The applied bitmap is what a resumed VM seeds its fresh dirty
    // bitmap with (CHALLENGES #143), so it must name exactly the pages
    // the pack carried.
    assert_eq!(applied.bitmap, vec![0b101u64]);

    // A pack minted against a different known generation must not be
    // applied onto this base (CHALLENGES #144).
    let mut wrong = vec![0u8; mem_size as usize];
    let wrong_addr = wrong.as_mut_ptr() as u64;
    let err = apply_delta(&path, wrong_addr, mem_size, base_identity + 1)
        .expect_err("a pack must not apply onto a different base generation");
    assert!(
        err.to_string().contains("base generation"),
        "base-identity mismatch must say so, got: {err}"
    );
    assert!(
        wrong.iter().all(|&b| b == 0),
        "a rejected pack must not have written anything"
    );

    // Identity 0 on either side is legacy metadata: it loads.
    let legacy = dir.path().join("legacy.pack");
    write_delta(&legacy, &bitmap, src_addr, mem_size, 0).unwrap();
    let mut dst0 = vec![0u8; mem_size as usize];
    apply_delta(&legacy, dst0.as_mut_ptr() as u64, mem_size, 99)
        .expect("an identity-0 pack applies onto any base");
    assert_eq!(&dst0[0..4096], &src[0..4096]);

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
        vm.as_native()
            .unwrap()
            .block_devices()
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

    // Disk-tier eviction of a suspended fork child must reap parked
    // clones too (bug-candidates #52). Resume of an Evicted node still
    // fails — evicted ≠ suspended.
    let victim = tree
        .fork(&child, "evict-victim")
        .expect("fork victim for disk eviction");
    tree.suspend(&victim).expect("suspend for eviction");
    let parked3 = tree.get_node(&victim).unwrap().parked_disk_dirs.clone();
    assert!(
        !parked3.is_empty(),
        "suspended victim must park its RW disk-clone dir"
    );
    assert!(parked3.iter().all(|d| d.exists()));
    let mut disk_budget = tree.budget();
    disk_budget.max_disk_bytes = tree.usage().disk_bytes.saturating_sub(1);
    tree.set_budget(disk_budget);
    tree.auto_evict().expect("disk-tier eviction");
    let info = tree.get_node(&victim).unwrap();
    assert_eq!(info.state, NodeState::Evicted);
    assert!(
        info.parked_disk_dirs.is_empty(),
        "evicted record must clear parked_disk_dirs"
    );
    assert!(
        parked3.iter().all(|d| !d.exists()),
        "evict must reap parked dirs"
    );
    let err = tree
        .resume(&victim)
        .expect_err("resume of an evicted node must fail");
    assert!(
        matches!(err, TreeError::BadState(_, NodeState::Evicted, _)),
        "resume of evicted must fail as BadState, got {err}"
    );

    tree.prune(&root_id).expect("prune");
    let _ = std::fs::remove_file(&img);
}

// --- reflink keyframes -------------------------------------

/// The 4 KiB page the marker tests write into, chosen well past the
/// kernel's own text so a stale clone shows up as the *old* bytes rather
/// than a crash.
fn write_marker(tree: &mut SnapshotTree, node: &String, text: &str) {
    let vm = tree.get_vm_mut(node).expect("live vm");
    let mut agent = vm.connect_agent(Duration::from_secs(30)).unwrap();
    agent
        .exec(&["sh", "-c", &format!("echo '{text}' > /tmp/marker")])
        .unwrap();
}

fn read_marker(tree: &mut SnapshotTree, node: &String) -> String {
    let vm = tree.get_vm_mut(node).expect("live vm");
    let mut agent = vm.connect_agent(Duration::from_secs(30)).unwrap();
    agent
        .exec(&["cat", "/tmp/marker"])
        .unwrap()
        .stdout
        .trim()
        .to_string()
}

fn live_root_tree(dir: &std::path::Path, budget: TreeBudget) -> (SnapshotTree, String) {
    let mut vm = create_test_vm();
    vm.start().unwrap();
    vm.connect_agent(Duration::from_secs(90)).unwrap();
    let (mut tree, root) = SnapshotTree::new(vm, dir.to_path_buf(), budget).unwrap();
    // prepare_fork_source swapped the root's vsock backend.
    tree.get_vm_mut(&root)
        .unwrap()
        .connect_agent(Duration::from_secs(30))
        .unwrap();
    (tree, root)
}

/// A child's keyframe is a `FICLONE` of its parent's plus its dirty
/// pages — same guest state, a fraction of the disk.
#[test]
fn test_tree_prepare_incremental() {
    let _ = env_logger::builder().is_test(true).try_init();
    let root_dir = common::ReflinkTreeRoot::new("prep-inc");
    let (mut tree, root) = live_root_tree(root_dir.path(), default_budget());
    write_marker(&mut tree, &root, "root-state");

    let child = tree.fork(&root, "child").unwrap();
    write_marker(&mut tree, &child, "child-state");

    let before = common::fs_used_bytes(root_dir.path());
    let outcome = tree.prepare_fork_source(&child).unwrap();
    let grew = common::fs_used_bytes(root_dir.path()).saturating_sub(before);
    assert!(outcome.wrote_base, "the child was not a fork source yet");
    assert!(
        outcome.incremental,
        "a child with a checkpoint ancestor on a reflink FS must clone it, \
         not dump {} MiB of guest RAM",
        256
    );

    // The clone is a real, complete keyframe: a grandchild forked off it
    // boots with the child's state, not the root's.
    let grand = tree.fork(&child, "grand").unwrap();
    assert_eq!(
        read_marker(&mut tree, &grand),
        "child-state",
        "a grandchild of an incremental keyframe must see the child's state"
    );
    // And the guest is healthy on it, not merely readable.
    {
        let vm = tree.get_vm_mut(&grand).unwrap();
        let mut agent = vm.connect_agent(Duration::from_secs(30)).unwrap();
        agent.ping().expect("grandchild agent must answer");
        let out = agent.exec(&["sh", "-c", "echo alive"]).unwrap();
        assert_eq!(out.stdout.trim(), "alive");
    }

    // Extent sharing actually happened: the child's keyframe reports the
    // full logical span but the filesystem only grew by its dirt.
    let child_mem = root_dir
        .path()
        .join("nodes")
        .join(&child)
        .join("memory.bin");
    let span = std::fs::metadata(&child_mem).unwrap().len();
    eprintln!("incremental keyframe grew the XFS by {grew} B of a {span} B span");
    assert!(
        grew < span / 2,
        "an incremental keyframe must share its ancestor's extents: the \
         filesystem grew {grew} B for a {span} B keyframe"
    );

    // The tree's disk budget must count that physical cost, not the
    // logical length — otherwise auto-evict fires on paper.
    let recorded = tree.get_node(&child).unwrap().base_disk_bytes;
    assert!(
        recorded.is_some_and(|b| b < span / 2),
        "base_disk_bytes must record the dirt written, got {recorded:?} for a \
         {span}-byte span"
    );

    tree.prune(&root).unwrap();
}

/// CHALLENGES #101 class: the `TRANSPORT_RESET` the snapshot
/// injects is a *host* write into guest RAM that KVM's dirty log cannot
/// see. An incremental keyframe that patched only the KVM-visible dirt
/// would ship its ancestor's stale vsock event ring, and the guest
/// driver would never tear down the connections it inherited — so a
/// fork off that keyframe could not be dialled.
#[test]
fn test_keyframe_includes_vsock_reset() {
    let _ = env_logger::builder().is_test(true).try_init();
    let root_dir = common::ReflinkTreeRoot::new("vsock-reset");
    let (mut tree, root) = live_root_tree(root_dir.path(), default_budget());

    let child = tree.fork(&root, "child").unwrap();
    // Hold a live agent connection across the prepare: this is what
    // makes the guest's event ring non-empty, and what the injected
    // TRANSPORT_RESET has to tell the resumed driver to abandon.
    {
        let vm = tree.get_vm_mut(&child).unwrap();
        let mut agent = vm.connect_agent(Duration::from_secs(30)).unwrap();
        agent.ping().unwrap();
    }
    let outcome = tree.prepare_fork_source(&child).unwrap();
    assert!(
        outcome.incremental,
        "this test must exercise the clone path"
    );

    // Two generations of forks off the incremental keyframe: each must
    // be dialable, which is only true if the reset reached the clone.
    for label in ["reset-a", "reset-b"] {
        let fork = tree.fork(&child, label).unwrap();
        let vm = tree.get_vm_mut(&fork).unwrap();
        let mut agent = vm
            .connect_agent(Duration::from_secs(30))
            .unwrap_or_else(|e| panic!("vsock dead on a fork of an incremental keyframe: {e}"));
        agent.ping().expect("agent ping over a fresh vsock");
    }

    tree.prune(&root).unwrap();
}

/// The full-dump fallback is loud and complete, never silent.
///
/// A tree on ext4 (the node's root FS, where `tempfile::tempdir()`
/// lands) cannot `FICLONE`, so every keyframe must be a full dump —
/// correct, just expensive — and the wire flag must say so.
#[test]
fn test_tree_prepare_falls_back_on_non_reflink_fs() {
    let _ = env_logger::builder().is_test(true).try_init();
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, root) = live_root_tree(dir.path(), default_budget());
    write_marker(&mut tree, &root, "root-state");

    let child = tree.fork(&root, "child").unwrap();
    write_marker(&mut tree, &child, "child-state");
    let outcome = tree.prepare_fork_source(&child).unwrap();
    assert!(outcome.wrote_base);
    assert!(
        !outcome.incremental,
        "a tree on ext4 must not claim an incremental keyframe"
    );

    // Full dump: logical length, and the recorded cost is the whole span.
    let child_mem = dir.path().join("nodes").join(&child).join("memory.bin");
    let span = std::fs::metadata(&child_mem).unwrap().len();
    assert_eq!(
        tree.get_node(&child).unwrap().base_disk_bytes,
        Some(span),
        "a full dump costs its whole span"
    );

    // And it is a correct keyframe.
    let grand = tree.fork(&child, "grand").unwrap();
    assert_eq!(read_marker(&mut tree, &grand), "child-state");

    tree.prune(&root).unwrap();
}

/// N incremental keyframes must fit a `max_disk_bytes`
/// that N full dumps would blow.
///
/// The budget counts `base_disk_bytes` (what the keyframe physically
/// cost) rather than `metadata().len()` (the reflink's full logical
/// span), so cheap keyframes must not trip disk eviction.
#[test]
fn test_tree_incremental_keyframes_fit_a_full_dump_budget() {
    let _ = env_logger::builder().is_test(true).try_init();
    let root_dir = common::ReflinkTreeRoot::new("disk-budget");
    // Room for the root's own 320 MiB span and not much else: three
    // more full dumps would need ~1 GiB.
    let budget = TreeBudget {
        max_live_vms: 16,
        max_live_ram_bytes: u64::MAX,
        max_disk_bytes: 420 * 1024 * 1024,
        max_chain_depth: 1,
    };
    let (mut tree, root) = live_root_tree(root_dir.path(), budget);

    let mut chain = root.clone();
    for gen in 0..3 {
        let child = tree
            .fork(&chain, &format!("gen{gen}"))
            .unwrap_or_else(|e| panic!("generation {gen} must fit the disk budget: {e}"));
        // Forking off the child prepares it — an incremental keyframe.
        let outcome = tree.prepare_fork_source(&child).unwrap();
        assert!(
            outcome.incremental,
            "generation {gen} keyframe must be incremental"
        );
        chain = child;
    }

    // Nothing was evicted to pay for those keyframes.
    for info in tree.list_nodes() {
        assert_ne!(
            info.state,
            NodeState::Evicted,
            "node '{}' was disk-evicted, but three incremental keyframes \
             cost far less than the budget",
            info.id
        );
    }
    let usage = tree.usage();
    assert!(
        usage.disk_bytes <= tree.budget().max_disk_bytes,
        "counted disk {} must stay inside the {} byte budget",
        usage.disk_bytes,
        tree.budget().max_disk_bytes
    );

    tree.prune(&root).unwrap();
}

/// CHALLENGES #143: a page dirtied before the first suspend must
/// survive suspend → resume → suspend → resume.
///
/// A resumed node's KVM dirty tracking restarts empty. Without seeding
/// it from the pack that was just applied, the second suspend writes a
/// pack covering only what the guest touched after the resume, and every
/// page the first pack restored silently reverts to the base.
#[test]
fn test_suspend_resume_suspend_is_complete() {
    let _ = env_logger::builder().is_test(true).try_init();
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, root) = live_root_tree(dir.path(), default_budget());
    write_marker(&mut tree, &root, "root-state");

    let child = tree.fork(&root, "child").unwrap();
    write_marker(&mut tree, &child, "before-first-suspend");

    tree.suspend(&child).unwrap();
    tree.resume(&child).unwrap();
    assert_eq!(
        read_marker(&mut tree, &child),
        "before-first-suspend",
        "the first resume must restore the pre-suspend page"
    );

    // Second cycle: the guest does NOT rewrite the marker, so only the
    // re-seeded bitmap can carry it into the second pack.
    tree.suspend(&child).unwrap();
    tree.resume(&child).unwrap();
    assert_eq!(
        read_marker(&mut tree, &child),
        "before-first-suspend",
        "a page dirtied before the first suspend must survive a second \
         suspend/resume cycle (CHALLENGES #143)"
    );

    tree.prune(&root).unwrap();
}

/// CHALLENGES #152: a `delta.pack` names the base generation
/// it was diffed against, and a resume onto a different generation fails
/// loud.
///
/// Two halves. First: a resumed checkpoint keeps `fork_source_base_path`
/// and `has_base_snapshot`, so a later fork reuses that file instead of
/// writing a new keyframe under suspended descendants. The daemon stopped
/// auto-preparing on `fork_batch`, so mid is prepared **explicitly** —
/// otherwise the leaf pack names the root generation and this test
/// asserts `mid.base_identity != 0` against 0. Then the backstop: when
/// a pack names a generation this `memory.bin` is not, resume refuses.
#[test]
fn test_resume_rejects_stale_base() {
    let _ = env_logger::builder().is_test(true).try_init();
    let dir = tempfile::tempdir().unwrap();
    let (mut tree, root) = live_root_tree(dir.path(), default_budget());

    let mid = tree.fork(&root, "mid").unwrap();
    tree.prepare_fork_source(&mid)
        .expect("explicit prepare so mid owns a keyframe");
    let leaf = tree.fork(&mid, "leaf").unwrap();
    let mid_gen = tree.get_node(&mid).unwrap().base_identity;
    assert_ne!(mid_gen, 0, "a prepared node must carry a base generation");

    tree.suspend(&leaf).unwrap();
    tree.suspend(&mid).unwrap();
    tree.resume(&mid).unwrap();

    // The resumed checkpoint knows it is one, so the fork below reuses
    // its existing keyframe instead of minting a new generation under
    // the suspended leaf.
    assert!(
        tree.get_vm(&mid)
            .unwrap()
            .as_native()
            .unwrap()
            .fork_source_base_path()
            .is_some(),
        "a resumed checkpoint must keep its fork_source_base_path \
         (CHALLENGES #144)"
    );
    let sibling = tree.fork(&mid, "sibling").unwrap();
    assert_eq!(
        tree.get_node(&mid).unwrap().base_identity,
        mid_gen,
        "forking a resumed checkpoint must not roll its base generation"
    );
    tree.resume(&leaf)
        .expect("the leaf's pack still names the generation on disk");
    tree.suspend(&leaf).unwrap();
    tree.prune(&sibling).unwrap();

    // Now the backstop. With the fix above, the tree API can no longer
    // produce the skew — so stage it the other way the trap arrives:
    // metadata that says the pack was diffed against a generation this
    // `memory.bin` is not. The K7DL header's base identity is the
    // trailing u64 of its 28-byte header.
    let pack = dir.path().join("nodes").join(&leaf).join("delta.pack");
    let mut bytes = std::fs::read(&pack).unwrap();
    let stale = mid_gen.wrapping_add(1000);
    bytes[20..28].copy_from_slice(&stale.to_le_bytes());
    std::fs::write(&pack, &bytes).unwrap();

    let err = tree
        .resume(&leaf)
        .expect_err("resuming onto a base the pack does not name must fail loud, not corrupt");
    assert!(
        err.to_string().contains("base generation"),
        "expected a base-identity mismatch, got: {err}"
    );
    assert_eq!(
        tree.get_node(&leaf).unwrap().state,
        NodeState::Suspended,
        "a refused resume must leave the node suspended"
    );

    tree.prune(&root).unwrap();
}
