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
        max_live_vms: 1,
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

    let a = tree.fork(&root, "a").unwrap();
    tree.protect(&a);

    // Forking b triggers auto-evict (budget=1 live VM). "a" is protected and
    // "root" is its ancestor so implicitly protected. Only candidate to evict
    // would be root, but it's protected → auto_evict suspends something else,
    // or returns the error. Since root is implicitly protected as ancestor of
    // "a", and "a" is protected, auto_evict must pick root-or-a but both are
    // protected → it should return BudgetExhausted OR evict nothing.
    //
    // In practice auto_evict runs BEFORE the fork in fork_batch, and at that
    // point live = {root, a}. So we must suspend one of those. Both are
    // implicitly protected → auto_evict returns Err.
    let b_result = tree.fork(&root, "b");

    // Either: the fork succeeded (e.g. budget_exhausted not yet triggered), or
    // it failed with BudgetExhausted. In both cases "a" must still be live.
    assert_eq!(
        tree.get_node(&a).unwrap().state,
        NodeState::Live,
        "protected node should never be auto-evicted"
    );

    // If fork succeeded, clean up b.
    if let Ok(b) = b_result {
        assert_eq!(tree.get_node(&b).unwrap().state, NodeState::Live);
    }
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
