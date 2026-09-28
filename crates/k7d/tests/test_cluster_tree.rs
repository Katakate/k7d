//! Integration tests for the cluster snapshot tree.
//!
//! Requires KVM, /dev/vhost-vsock, /dev/net/tun, virtiofsd, and the built
//! guest kernel + initramfs.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use k7d::cluster_tree::{ClusterPayload, ClusterSnapshotTree};
use k7d::guest::Guest;
use k7d::network::ClusterNetwork;
use k7d::tree::{NodeState, TreeBudget, TreeError};
use k7d::vm::Vm;

mod common;

fn workspace_path(relative: &str) -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join(relative)
}

fn build_cluster(label: &str, n: usize) -> ClusterPayload {
    build_cluster_sized(label, n, 256)
}

fn build_cluster_sized(label: &str, n: usize, memory_mb: u64) -> ClusterPayload {
    build_cluster_sizes(label, &vec![memory_mb; n])
}

fn build_cluster_sizes(label: &str, sizes_mb: &[u64]) -> ClusterPayload {
    // Test-setup hygiene: see k7d::network::cleanup_stale_k7_bridges.
    let _ = k7d::network::cleanup_stale_k7_bridges();
    let kernel = workspace_path("guest/kernel/vmlinux");
    let initrd = workspace_path("guest/rootfs/initramfs.cpio.gz");
    let mut net = ClusterNetwork::create(label).expect("bridge");
    let mut members: Vec<Guest> = Vec::with_capacity(sizes_mb.len());
    for &memory_mb in sizes_mb {
        let tap = net.add_tap().expect("tap");
        let mut vm = Vm::builder()
            .kernel(&kernel)
            .initrd(&initrd)
            .memory_mb(memory_mb)
            .vsock(true)
            .guest_cid(k7d::vsock::allocate_cid())
            .network(tap)
            .build()
            .expect("vm build");
        vm.start().expect("vm start");
        let _ = vm
            .connect_agent(Duration::from_secs(90))
            .expect("agent ready");
        members.push(Guest::from(vm));
    }
    ClusterPayload {
        network: net,
        members,
    }
}

/// The root keyframe is one coordinated cut: every member is paused
/// before any dump starts and stays paused until every dump is done,
/// and the dumps overlap — the longest per-member pause is well under
/// what writing the same keyframes one member at a time costs.
///
/// The sequential baseline is each member's own `Vm::snapshot` (pause,
/// dump, resume) — the dump half of the old per-member prepare loop,
/// without its restore-swap, so it understates the old freeze.
#[test]
fn test_cluster_tree_root_keyframe_is_one_cut() {
    const N: usize = 3;
    let _ = env_logger::builder().is_test(true).try_init();

    let mut root = build_cluster_sized("ct-cut-root", N, 1024);
    for (i, vm) in root.members.iter_mut().enumerate() {
        let mut agent = vm.connect_agent(Duration::from_secs(30)).expect("agent");
        agent
            .exec(&["sh", "-c", &format!("echo member-{i} > /tmp/who")])
            .expect("write marker");
    }

    // Two sequential passes; the first also faults in guest RAM, so
    // keep the faster of the two per member.
    let seq_dir = tempfile::tempdir().expect("seq tempdir");
    let mut seq = [u64::MAX; N];
    for pass in 0..2 {
        for (i, vm) in root.members.iter_mut().enumerate() {
            let dir = seq_dir.path().join(format!("{pass}-{i}"));
            let t = Instant::now();
            vm.as_native_mut()
                .unwrap()
                .snapshot(&dir)
                .expect("sequential snapshot");
            seq[i] = seq[i].min(u64::try_from(t.elapsed().as_nanos()).unwrap());
            std::fs::remove_dir_all(&dir).expect("rm seq keyframe");
        }
    }
    let seq_sum: u64 = seq.iter().sum();

    let dir = tempfile::tempdir().expect("tempdir");
    let budget = TreeBudget {
        max_live_ram_bytes: 8 * 1024 * 1024 * 1024,
        ..cluster_tree_budget()
    };
    let (mut tree, root_id) =
        ClusterSnapshotTree::new_cluster(root, dir.path().to_path_buf(), budget)
            .expect("new_cluster");
    let cut = tree
        .root_cut()
        .expect("native root records its cut")
        .clone();
    let dumps: Vec<u64> = cut.members.iter().map(|m| m.dump_ns()).collect();
    eprintln!(
        "cluster cut ({N} × 1024 MB): pause_ns {:?} max {} | parallel dump_ns {dumps:?} | \
         sequential snapshot_ns {seq:?} sum {seq_sum}",
        cut.pause_ns(),
        cut.max_pause_ns()
    );

    assert_eq!(cut.members.len(), N);
    assert!(
        cut.is_consistent(),
        "every dump must run while every member is paused: {cut:?}"
    );
    assert!(cut.pause_ns().iter().all(|&p| p > 0), "{cut:?}");
    // Ideal is about (dump + swap) / (3 × dump) ≈ ½; a serialized
    // cut would be ≥ 1.
    assert!(
        cut.max_pause_ns() * 3 < seq_sum * 2,
        "dumps did not overlap: max pause {} ns vs sequential sum {seq_sum} ns",
        cut.max_pause_ns()
    );

    // Each member was swapped onto its own keyframe, not a neighbour's.
    for (i, vm) in tree
        .get_payload_mut(&root_id)
        .expect("root payload")
        .members
        .iter_mut()
        .enumerate()
    {
        let mut agent = vm.connect_agent(Duration::from_secs(30)).expect("agent");
        let who = agent.exec(&["cat", "/tmp/who"]).expect("read marker");
        assert_eq!(who.stdout.trim(), format!("member-{i}"));
    }

    tree.prune(&root_id).expect("prune");
}

/// Host `MemAvailable` in MiB.
fn host_mem_available_mb() -> u64 {
    let meminfo = std::fs::read_to_string("/proc/meminfo").expect("read /proc/meminfo");
    let kib: u64 = meminfo
        .lines()
        .find_map(|l| l.strip_prefix("MemAvailable:"))
        .and_then(|r| r.trim().trim_end_matches("kB").trim().parse().ok())
        .expect("MemAvailable in /proc/meminfo");
    kib / 1024
}

/// The pause of a pre-copied cut does not grow with guest RAM.
/// One member is as big as the node allows (≤ 48 GiB) with
/// most of its RAM touched and a writer dirtying memory throughout; the
/// other is small. The cut must stay one consistent instant, pause the
/// big member far less than its own full paused dump takes, keep the
/// writer's pre-cut data, and fork correctly.
#[test]
fn test_cluster_tree_root_keyframe_precopy_large() {
    let _ = env_logger::builder().is_test(true).try_init();

    // Half of what the host has free: the guest's memfd and the live
    // phase's dirty page cache peak together; after the swap the member
    // runs on reclaimable page cache of its keyframe.
    let big_mb = (host_mem_available_mb() / 2 / 1024 * 1024).min(48 * 1024);
    assert!(
        big_mb >= 8 * 1024,
        "node has too little free RAM for a large member: {big_mb} MiB"
    );
    let fill_mb = big_mb * 3 / 4;
    eprintln!("precopy_large: booting a {big_mb} MiB member");
    let root = build_cluster_sizes("ct-precopy", &[big_mb, 512]);
    eprintln!("precopy_large: booted");

    let mut root = root;
    let precious_md5 = {
        let mut agent = root.members[0]
            .connect_agent(Duration::from_secs(30))
            .expect("agent");
        let t = Instant::now();
        let mut sh = |cmd: &str| {
            let out = agent.exec(&["sh", "-c", cmd]).expect("exec");
            assert_eq!(out.exit_code, 0, "{cmd}: {}", out.stderr);
            out
        };
        sh("mount -o remount,size=90% /tmp");
        // One GiB per exec: a single exec is bounded by the agent's reply
        // timeout.
        for gib in 0..fill_mb / 1024 {
            eprintln!("precopy_large: fill GiB {gib} at {:?}", t.elapsed());
            sh(&format!(
                "dd if=/dev/zero of=/tmp/fill.{gib} bs=1M count=1024 2>/dev/null"
            ));
        }
        let out = sh(
            "dd if=/dev/urandom of=/tmp/precious bs=1M count=64 2>/dev/null && \
             md5sum /tmp/precious",
        );
        eprintln!(
            "filled {fill_mb} MiB of a {big_mb} MiB guest in {:?}",
            t.elapsed()
        );
        agent
            .exec(&[
                "sh",
                "-c",
                "i=0; while true; do i=$((i+1)); echo $i > /tmp/tick; \
                 dd if=/dev/urandom of=/tmp/churn bs=1M count=32 2>/dev/null; done \
                 </dev/null >/dev/null 2>&1 & echo started",
            ])
            .expect("start writer");
        out.stdout.trim().to_string()
    };
    for (i, vm) in root.members.iter_mut().enumerate() {
        let mut agent = vm.connect_agent(Duration::from_secs(30)).expect("agent");
        agent
            .exec(&["sh", "-c", &format!("echo member-{i} > /tmp/who")])
            .expect("write marker");
    }

    // The daemon's tree root: child keyframes `FICLONE` their ancestor.
    let dir = common::ReflinkTreeRoot::new("ct-precopy");
    let big = big_mb * 1024 * 1024;
    let budget = TreeBudget {
        max_live_vms: 6,
        max_live_ram_bytes: 4 * big,
        max_disk_bytes: 4 * big,
        max_chain_depth: 2,
    };
    let t = Instant::now();
    let (mut tree, root_id) =
        ClusterSnapshotTree::new_cluster(root, dir.path().to_path_buf(), budget)
            .expect("new_cluster");
    let prepare = t.elapsed();
    let cut = tree
        .root_cut()
        .expect("native root records its cut")
        .clone();
    let m = cut.members[0];

    let read = |tree: &mut ClusterSnapshotTree, id: &String, i: usize, cmd: &str| -> String {
        let vm = &mut tree.get_payload_mut(id).expect("payload").members[i];
        let mut agent = vm.connect_agent(Duration::from_secs(30)).expect("agent");
        let out = agent.exec(&["sh", "-c", cmd]).expect("exec");
        assert_eq!(out.exit_code, 0, "{cmd}: {}", out.stderr);
        out.stdout.trim().to_string()
    };
    for i in 0..2 {
        assert_eq!(
            read(&mut tree, &root_id, i, "cat /tmp/who"),
            format!("member-{i}")
        );
    }
    assert_eq!(
        read(&mut tree, &root_id, 0, "md5sum /tmp/precious"),
        precious_md5,
        "pre-cut data changed across the swap"
    );
    let tick0: u64 = read(&mut tree, &root_id, 0, "cat /tmp/tick")
        .parse()
        .expect("tick");
    std::thread::sleep(Duration::from_secs(3));
    let tick1: u64 = read(&mut tree, &root_id, 0, "cat /tmp/tick")
        .parse()
        .expect("tick");

    let child = tree.fork(&root_id, "child").expect("fork");
    assert_eq!(
        read(&mut tree, &child, 0, "md5sum /tmp/precious"),
        precious_md5,
        "fork of the pre-copied keyframe lost pre-cut data"
    );
    assert_eq!(read(&mut tree, &child, 1, "cat /tmp/who"), "member-1");

    // A child keyframe: incremental over the root's, pre-copied too. The
    // root's writer runs on in the child (its RAM was forked).
    let child_md5 = read(
        &mut tree,
        &child,
        0,
        "dd if=/dev/urandom of=/tmp/child bs=1M count=256 2>/dev/null && md5sum /tmp/child",
    );
    let t = Instant::now();
    let outcome = tree.prepare_fork_source(&child).expect("child keyframe");
    let child_prepare = t.elapsed();
    let ccut = tree.last_child_cut().expect("child cut").clone();
    let grand = tree.fork(&child, "grand").expect("fork of child");
    assert_eq!(
        read(&mut tree, &grand, 0, "md5sum /tmp/child"),
        child_md5,
        "fork of the pre-copied child keyframe lost pre-cut data"
    );
    assert_eq!(
        read(&mut tree, &grand, 0, "md5sum /tmp/precious"),
        precious_md5
    );
    assert_eq!(read(&mut tree, &grand, 1, "cat /tmp/who"), "member-1");

    // Baseline: the same member's full paused dump, after the cut so its
    // read faults could not fill the memfd holes pass 0 skips.
    let seq_dir = tempfile::tempdir().expect("baseline tempdir");
    let t = Instant::now();
    tree.get_payload_mut(&root_id)
        .expect("root payload")
        .members[0]
        .as_native_mut()
        .unwrap()
        .snapshot(seq_dir.path())
        .expect("full snapshot");
    let full_ns = u64::try_from(t.elapsed().as_nanos()).unwrap();
    drop(seq_dir);

    eprintln!(
        "MEASUREMENT precopy cut ({big_mb} MiB + 512 MiB, {fill_mb} MiB touched): \
         max pause {:.3} s, big member pause {:.3} s (paused write {:.3} s, {} MiB), \
         live {} MiB, arm stop {:.3} s, prepare wall {prepare:?} | full paused dump {:.3} s",
        cut.max_pause_ns() as f64 / 1e9,
        m.pause_ns() as f64 / 1e9,
        m.dump_ns() as f64 / 1e9,
        m.final_bytes >> 20,
        m.precopied_bytes >> 20,
        m.arm_pause_ns as f64 / 1e9,
        full_ns as f64 / 1e9,
    );
    eprintln!(
        "MEASUREMENT precopy child cut: max pause {:.3} s, live MiB {:?}, paused MiB {:?}, \
         disk MiB {:?}, prepare wall {child_prepare:?}",
        ccut.max_pause_ns() as f64 / 1e9,
        ccut.members
            .iter()
            .map(|c| c.precopied_bytes >> 20)
            .collect::<Vec<_>>(),
        ccut.members
            .iter()
            .map(|c| c.final_bytes >> 20)
            .collect::<Vec<_>>(),
        ccut.members
            .iter()
            .map(|c| c.disk_bytes >> 20)
            .collect::<Vec<_>>(),
    );
    assert!(cut.is_consistent(), "not one cut: {cut:?}");
    assert!(cut.members.iter().all(|c| c.precopied()), "{cut:?}");
    assert!(
        m.precopied_bytes >= fill_mb << 20,
        "pass 0 did not carry the touched RAM: {m:?}"
    );
    assert!(
        m.final_bytes * 8 < m.precopied_bytes,
        "the paused residual is not small next to the live copy: {m:?}"
    );
    assert!(
        cut.max_pause_ns() * 5 < full_ns,
        "pause {} ns is not far below the full dump {full_ns} ns",
        cut.max_pause_ns()
    );
    assert!(
        m.arm_pause_ns * 5 < full_ns,
        "arm stop {} ns is not far below the full dump {full_ns} ns",
        m.arm_pause_ns
    );
    assert!(
        tick1 > tick0,
        "writer stopped after the cut: {tick0} -> {tick1}"
    );

    assert!(
        outcome.incremental,
        "child keyframe not incremental: {ccut:?}"
    );
    assert!(ccut.is_consistent(), "child: not one cut: {ccut:?}");
    assert!(ccut.members.iter().all(|c| c.precopied()), "{ccut:?}");
    assert!(
        ccut.members[0].disk_bytes >= 256 << 20 && ccut.members[0].disk_bytes < big / 4,
        "child keyframe cost is not its divergence: {ccut:?}"
    );
    assert!(
        ccut.max_pause_ns() * 5 < full_ns,
        "child pause {} ns is not far below the full dump {full_ns} ns",
        ccut.max_pause_ns()
    );

    tree.prune(&root_id).expect("prune");
}

/// Like [`build_cluster`] but every member gets a **read-write** block
/// device on the reflink-capable loopback XFS — the ingredient that made
/// fork-of-fork fail before CHALLENGES.md #130 (forked members run on
/// reflinked images whose directory the `Vm` owns and removes on Drop).
/// Returns the root images too; the tree never deletes a root's original
/// images (they are unowned, like the daemon's adopted disks), so the
/// test unlinks them at the end.
fn build_cluster_with_rw_disks(label: &str, n: usize) -> (ClusterPayload, Vec<PathBuf>) {
    use k7d::disks::{ensure_loopback_xfs, DISKS_DIR, DISKS_IMAGE, DISKS_IMAGE_SIZE};
    ensure_loopback_xfs(
        Path::new(DISKS_IMAGE),
        Path::new(DISKS_DIR),
        DISKS_IMAGE_SIZE,
    )
    .expect("reflink XFS at /var/lib/k7d/disks");

    let _ = k7d::network::cleanup_stale_k7_bridges();
    let kernel = workspace_path("guest/kernel/vmlinux");
    let initrd = workspace_path("guest/rootfs/initramfs.cpio.gz");
    let mut net = ClusterNetwork::create(label).expect("bridge");
    let mut members: Vec<Guest> = Vec::with_capacity(n);
    let mut images: Vec<PathBuf> = Vec::with_capacity(n);
    for i in 0..n {
        let img =
            Path::new(DISKS_DIR).join(format!("ct-rw-{label}-{}-{i}.img", std::process::id()));
        std::fs::write(&img, vec![0u8; 4 * 1024 * 1024]).expect("write RW image");
        images.push(img.clone());
        let tap = net.add_tap().expect("tap");
        let mut vm = Vm::builder()
            .kernel(&kernel)
            .initrd(&initrd)
            .memory_mb(256)
            .vsock(true)
            .guest_cid(k7d::vsock::allocate_cid())
            .network(tap)
            .block_device(&img, false)
            .build()
            .expect("vm build");
        vm.start().expect("vm start");
        let _ = vm
            .connect_agent(Duration::from_secs(90))
            .expect("agent ready");
        members.push(Guest::from(vm));
    }
    (
        ClusterPayload {
            network: net,
            members,
        },
        images,
    )
}

/// Every live member's RW image must exist on the host — the loud
/// version of the silent hole CHALLENGES.md #130 fixed (an unlinked
/// image keeps working through the open fd until the next reflink).
fn assert_member_disks_exist(tree: &ClusterSnapshotTree, id: &String) {
    let payload = tree.get_payload(id).expect("live payload");
    for (i, vm) in payload.members.iter().enumerate() {
        let path = &vm
            .as_native()
            .unwrap()
            .block_devices()
            .first()
            .unwrap_or_else(|| panic!("{id}/{i} has no block device"))
            .host_path;
        assert!(
            path.exists(),
            "{id}/{i}: RW image {} was deleted under the live guest",
            path.display()
        );
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

/// Cluster fork preserves topology and
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
    // (vm_index, guest_ip, guest_mac) tuples — that's the contract
    // `fork_cluster_warm` provides and that this tree node inherits.
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

/// Children are not checkpoints at fork. The next fork from a child
/// inherits the ancestor keyframe + dirty bitmap — no new memory.bin.
#[test]
fn test_cluster_tree_fork_from_child() {
    let _ = env_logger::builder().is_test(true).try_init();

    let budget = TreeBudget {
        max_live_vms: 12,
        max_live_ram_bytes: 8 * 1024 * 1024 * 1024,
        max_disk_bytes: 20 * 1024 * 1024 * 1024,
        max_chain_depth: 8,
    };
    let root = build_cluster("ct-depth", 2);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut tree, root_id) =
        ClusterSnapshotTree::new_cluster(root, dir.path().to_path_buf(), budget)
            .expect("new_cluster");

    let child = tree.fork(&root_id, "child").expect("fork from root");
    let child_info = tree.get_node(&child).expect("child info");
    assert_eq!(child_info.parent.as_deref(), Some("root"));
    assert!(
        !child_info.has_base_snapshot,
        "fresh child is not a checkpoint"
    );

    let grand = tree.fork(&child, "grand").expect("fork from child");
    let grand_info = tree.get_node(&grand).expect("grand info");
    assert_eq!(
        grand_info.parent.as_deref(),
        Some(child.as_str()),
        "grandchild parent must be the child, not root"
    );
    assert!(
        !tree.get_node(&child).unwrap().has_base_snapshot,
        "fork from child inherits the ancestor keyframe; no new memory.bin"
    );
    assert!(tree
        .get_payload(&child)
        .expect("child live")
        .members
        .iter()
        .all(|vm| vm.as_native().unwrap().fork_source_base_path().is_some()));

    tree.suspend(&grand).expect("suspend grand");
    tree.resume(&grand).expect("resume grand");
    assert!(
        !tree.get_node(&grand).unwrap().has_base_snapshot,
        "resume of an inherited grandchild must not mint a keyframe"
    );

    tree.prune(&root_id).expect("prune");
}

/// Suspend / resume round-trip rebuilds
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

/// Shared-pause batch scales to 50× 3-VM cluster forks.
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
    let ids = tree
        .fork_batch(&root_id, &labels, None)
        .expect("fork_batch 50");
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
                !vm.as_native().unwrap().fork_memory_is_full_copy(),
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

/// 3-VM cluster fork ≤ 75 ms (50 ms
/// for fork_cluster_warm + ~25 ms tree bookkeeping).
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

/// Auto-evict accounts for
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

/// CHALLENGES #115: `fork_batch` must make headroom for the
/// incoming forks (`labels.len() × vm_count`) instead of hanging on the
/// control socket or silently exceeding `max_live_vms`. With the budget
/// full, forking from a child suspends the LRU non-source node (root) and
/// proceeds. The graph also deepens (b.parent == a) under
/// `max_chain_depth: 1` — proving the field is a restore-chain cap, not a
/// graph-depth cap.
#[test]
fn test_cluster_tree_fork_batch_evicts_for_incoming() {
    let _ = env_logger::builder().is_test(true).try_init();

    let budget = TreeBudget {
        max_live_vms: 4, // 2 cluster nodes × 2 VMs
        max_live_ram_bytes: u64::MAX,
        max_disk_bytes: 20 * 1024 * 1024 * 1024,
        max_chain_depth: 1,
    };
    let root = build_cluster("ct-incoming", 2);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut tree, root_id) =
        ClusterSnapshotTree::new_cluster(root, dir.path().to_path_buf(), budget)
            .expect("new_cluster");

    let a = tree.fork(&root_id, "a").expect("fork a"); // budget now full: 4/4

    // Forking from `a` needs 2 more live VMs. The tree must suspend the LRU
    // non-source node (root) BEFORE forking — no hang, no overshoot.
    let b = tree
        .fork(&a, "b")
        .expect("fork from child must evict for incoming");

    assert_eq!(
        tree.get_node(&b).unwrap().parent.as_deref(),
        Some(a.as_str()),
        "grandchild parent must be the child, not root"
    );
    assert_eq!(
        tree.get_node(&a).unwrap().state,
        NodeState::Live,
        "fork source must stay live"
    );
    assert_eq!(
        tree.get_node(&root_id).unwrap().state,
        NodeState::Suspended,
        "LRU root must have been suspended to make headroom"
    );
    let live_vm_count: u32 = tree
        .list_nodes()
        .iter()
        .filter(|n| matches!(n.state, NodeState::Live))
        .map(|n| n.vm_count)
        .sum();
    assert!(
        live_vm_count <= 4,
        "Σ live vm_count must stay ≤ max_live_vms; was {live_vm_count}"
    );

    tree.prune(&root_id).expect("prune");
}

/// Persistence round-trip:
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

/// Regression for CHALLENGES.md #130: fork-of-fork (and suspend/resume
/// of a fork child) with **read-write block devices**.
///
/// A forked member runs on reflinked RW images owned by its `Vm`
/// (`fork_state_dir`, removed on Drop). Three code paths used to drop a
/// `Vm` whose images a successor still needs:
///   1. `prepare_fork_source_in`'s husk swap (fork-of-fork) — the next
///      FICLONE hit ENOENT: `fork error: IO error: No such file or
///      directory`;
///   2. `suspend` (resume's reflink hit the same ENOENT);
///   3. prune of a suspended fork child (must reap the parked images).
/// The busybox fork-from-child test above stays green without disks —
/// this one pins the disk-ownership contract.
#[test]
fn test_cluster_tree_fork_of_fork_with_rw_disks() {
    let _ = env_logger::builder().is_test(true).try_init();

    let budget = TreeBudget {
        max_live_vms: 8, // 4 nodes × 2 members
        max_live_ram_bytes: 8 * 1024 * 1024 * 1024,
        max_disk_bytes: 20 * 1024 * 1024 * 1024,
        max_chain_depth: 8,
    };
    let (root, root_images) = build_cluster_with_rw_disks("ct-fof", 2);
    let dir = tempfile::tempdir().expect("tempdir");
    let (mut tree, root_id) =
        ClusterSnapshotTree::new_cluster(root, dir.path().to_path_buf(), budget)
            .expect("new_cluster");

    // Depth 1 → 2 → 3: each fork prepares its source (swapping in a
    // restored copy) and reflinks the source's CURRENT images. Pre-fix,
    // the depth-2 fork failed because preparing the child dropped the
    // husk that owned the child's images.
    let child = tree.fork(&root_id, "child").expect("fork from root");
    assert_member_disks_exist(&tree, &child);
    let grand = tree
        .fork(&child, "grand")
        .expect("fork-of-fork with RW disks (CHALLENGES #130)");
    assert_member_disks_exist(&tree, &child);
    assert_member_disks_exist(&tree, &grand);
    // `great` must outlive the eviction the `after-resume` fork below
    // forces (live budget full, `grand` exempt as the source).
    // `last_active_at_unix` is whole seconds and `nodes` is a HashMap,
    // so if root, child and `great` land in the same second the LRU
    // tie-break is hash order and `great` is sometimes the victim.
    // Make `great` strictly newer than its ancestors.
    std::thread::sleep(Duration::from_millis(1100));
    let great = tree.fork(&grand, "great").expect("depth-3 fork");
    assert_member_disks_exist(&tree, &great);
    assert_eq!(
        tree.get_node(&great).unwrap().parent.as_deref(),
        Some(grand.as_str())
    );

    // Suspend a fork child: its images must be parked on the node
    // record, not deleted with the payload; resume reflinks from them,
    // then reaps them.
    tree.suspend(&grand).expect("suspend fork child");
    let parked = tree.get_node(&grand).unwrap().parked_disk_dirs.clone();
    assert!(
        !parked.is_empty(),
        "suspended fork child must park its RW disk-clone dirs"
    );
    for dir in &parked {
        assert!(
            dir.exists(),
            "parked disk dir {} deleted at suspend",
            dir.display()
        );
    }
    tree.resume(&grand)
        .expect("resume fork child with RW disks");
    assert!(
        tree.get_node(&grand).unwrap().parked_disk_dirs.is_empty(),
        "resume must clear the parked dirs"
    );
    for dir in &parked {
        assert!(
            !dir.exists(),
            "resume must reap the parked dir {} after reflinking",
            dir.display()
        );
    }
    assert_member_disks_exist(&tree, &grand);
    let after_resume = tree
        .fork(&grand, "after-resume")
        .expect("fork from a resumed fork child");
    assert_member_disks_exist(&tree, &after_resume);

    // Prune of a *suspended* fork child must reap its parked images.
    tree.suspend(&after_resume).expect("suspend for prune");
    let parked_pruned = tree
        .get_node(&after_resume)
        .unwrap()
        .parked_disk_dirs
        .clone();
    assert!(!parked_pruned.is_empty());
    tree.prune(&after_resume).expect("prune suspended child");
    for dir in &parked_pruned {
        assert!(
            !dir.exists(),
            "prune must reap the parked dir {}",
            dir.display()
        );
    }

    // Disk-tier eviction of a suspended fork child must reap parked
    // member disks too (bug-candidates #52). Resume of an Evicted node
    // still fails — evicted ≠ suspended. Suspend `great` (already a
    // leaf with RW disks) rather than forking another cluster: the
    // live budget is already full.
    tree.suspend(&great).expect("suspend for eviction");
    let parked_evict = tree.get_node(&great).unwrap().parked_disk_dirs.clone();
    assert!(
        !parked_evict.is_empty(),
        "suspended victim must park its RW disk-clone dirs"
    );
    for dir in &parked_evict {
        assert!(
            dir.exists(),
            "parked disk dir {} deleted at suspend",
            dir.display()
        );
    }
    let mut disk_budget = tree.budget();
    disk_budget.max_disk_bytes = tree.usage().disk_bytes.saturating_sub(1);
    tree.set_budget(disk_budget);
    tree.auto_evict().expect("disk-tier eviction");
    let info = tree.get_node(&great).unwrap();
    assert_eq!(info.state, NodeState::Evicted);
    assert!(
        info.parked_disk_dirs.is_empty(),
        "evicted record must clear parked_disk_dirs"
    );
    for dir in &parked_evict {
        assert!(
            !dir.exists(),
            "evict must reap the parked dir {}",
            dir.display()
        );
    }
    let err = tree
        .resume(&great)
        .expect_err("resume of an evicted node must fail");
    assert!(
        matches!(err, TreeError::BadState(_, NodeState::Evicted, _)),
        "resume of evicted must fail as BadState, got {err}"
    );

    tree.prune(&root_id).expect("prune");
    for img in &root_images {
        let _ = std::fs::remove_file(img);
    }
}

/// Reflink keyframes on the cluster tree: preparing a cluster child clones each
/// member's keyframe from that member's own ancestor keyframe.
///
/// This is the shape GRPO actually runs — a generation is N cluster
/// children of one parent, and before this each child's checkpoint cost
/// `members × guest RAM` of dump. The per-member bookkeeping is the part
/// that can go wrong quietly: clone member 2 from member 1's keyframe
/// and the cluster still boots, it just has two copies of one node's
/// memory, so the assertions below check identity per member and not
/// merely that the cluster came up.
#[test]
fn test_cluster_tree_prepare_incremental() {
    let _ = env_logger::builder().is_test(true).try_init();

    let root = build_cluster("ct-inc-root", 2);
    let root_dir = common::ReflinkTreeRoot::new("ct-inc");
    let (mut tree, root_id) = ClusterSnapshotTree::new_cluster(
        root,
        root_dir.path().to_path_buf(),
        cluster_tree_budget(),
    )
    .expect("new_cluster");

    // Give each member a distinct marker, so a keyframe cloned from the
    // wrong member's ancestor is visible rather than merely wasteful.
    let child = tree.fork(&root_id, "child").expect("fork");
    for (idx, vm) in tree
        .get_payload_mut(&child)
        .expect("child payload")
        .members
        .iter_mut()
        .enumerate()
    {
        let mut agent = vm.connect_agent(Duration::from_secs(30)).expect("agent");
        agent
            .exec(&[
                "sh",
                "-c",
                &format!("echo 'member-{idx}' > /tmp/who; echo child > /tmp/gen"),
            ])
            .expect("write marker");
    }

    let before = common::fs_used_bytes(root_dir.path());
    let started = Instant::now();
    let outcome = tree.prepare_fork_source(&child).expect("prepare");
    let elapsed = started.elapsed();
    let grew = common::fs_used_bytes(root_dir.path()).saturating_sub(before);
    assert!(outcome.wrote_base);
    assert!(
        outcome.incremental,
        "every member of a cluster child on a reflink FS must clone its \
         own ancestor keyframe"
    );

    let span: u64 = (0..tree.get_node(&child).unwrap().vm_count)
        .map(|i| {
            let mem = root_dir
                .path()
                .join("nodes")
                .join(&child)
                .join("members")
                .join(i.to_string())
                .join("memory.bin");
            std::fs::metadata(&mem).expect("member keyframe").len()
        })
        .sum();
    eprintln!(
        "cluster: prepare {:?}, XFS grew {grew} B of a {span} B cluster keyframe",
        elapsed
    );
    assert!(
        grew < span / 2,
        "a cluster's incremental keyframe must share extents: grew {grew} B \
         for a {span} B cluster span"
    );

    // Every member of a grandchild sees its OWN member's state.
    let grand = tree.fork(&child, "grand").expect("fork of child");
    for (idx, vm) in tree
        .get_payload_mut(&grand)
        .expect("grand payload")
        .members
        .iter_mut()
        .enumerate()
    {
        let mut agent = vm.connect_agent(Duration::from_secs(30)).expect("agent");
        let who = agent.exec(&["cat", "/tmp/who"]).expect("read marker");
        assert_eq!(
            who.stdout.trim(),
            format!("member-{idx}"),
            "member {idx} of a grandchild booted from the wrong member's keyframe"
        );
        let gen = agent.exec(&["cat", "/tmp/gen"]).expect("read gen");
        assert_eq!(gen.stdout.trim(), "child");
    }

    tree.prune(&root_id).expect("prune");
}
