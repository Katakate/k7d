//! Integration tests for the **named persistent data disk** primitive
//! : a disk whose lifetime is not the VM's, so an inner
//! node's `/var/lib/longhorn` is still there for the next VM that claims
//! the same id, and a warm fork gives the child its own reflinked clone.
//!
//! Everything here is the generic read-write virtio-blk path
//! `test_ubuntu_guest.rs` already drives — what is new is the *lifetime*:
//! `Vm::drop` must leave the image alone, a second VM must see the first
//! one's bytes, and `delete_data_disk` must be the only thing that
//! removes them.
//!
//! Requires KVM, /dev/vhost-vsock, /dev/net/tun, root, and
//! `/var/lib/k7d/disks` on the reflink XFS.

mod common;

use std::process::Command;
use std::time::{Duration, Instant};

use k7d::disks::{data_disk_path, DataDisk};
use k7d::fork::fork_cluster_warm;
use k7d::latency::FORK_UBUNTU_NODE_1VM;
use k7d::network::ClusterNetwork;
use k7d::vm::Vm;

use common::ubuntu::{
    build_node_vm_with_data, connect_or_dump, image_contains, node_image, physical_extents, sh_ok,
    NodeCmdlineExtra, TestDataDisk, VmDisk,
};

/// 1 GiB is well above the ext4 floor and still sparse, so the image
/// costs its metadata and nothing else until the guest writes.
const DISK_SIZE: u64 = 1024 * 1024 * 1024;

/// Where the guest mounts it. `/mnt/data` and not `/var/lib/longhorn`,
/// so this test proves the primitive and not the Longhorn layout.
const GUEST_MOUNT: &str = "/mnt/data";

/// Run a host command and return its stdout, for the mount/loop-device
/// checks that `Path::exists()` cannot answer.
fn host_text(program: &str, args: &[&str]) -> String {
    let out = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("run {program}: {e}"));
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The disk survives the VM: write on one VM, drop it, boot a second VM
/// with the same id, read the bytes back. Then delete it explicitly and
/// watch the image go away — the only thing that removes it.
#[test]
fn test_data_disk_outlives_the_vm_and_is_deleted_explicitly() {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = k7d::network::cleanup_stale_k7_bridges();

    let image = node_image();
    let id = TestDataDisk::unique_id("persist");
    let data = TestDataDisk::attach(&id, DISK_SIZE, GUEST_MOUNT);
    let image_path = data_disk_path(&id);
    assert!(
        image_path.exists(),
        "attach must create {}",
        image_path.display()
    );

    const MARKER: &str = "k7d-data-disk-survives-the-vm-1a2b";

    // ── first VM: write and sync ──
    {
        let disk = VmDisk::clone_of(&image.base_image(), "dd-first");
        let mut net = ClusterNetwork::create("dd1").expect("cluster bridge");
        let tap = net.add_tap().expect("tap");
        let mut vm = build_node_vm_with_data(
            &image,
            &disk,
            tap,
            NodeCmdlineExtra {
                k3s: None,
                cni: None,
            },
            std::slice::from_ref(&data.disk),
        );
        vm.start().expect("first VM should start");
        let mut agent = connect_or_dump(&mut vm, "first");
        // The agent mounts it from `k7d.blk=` before containers start,
        // so the mount is a fact about boot, not something the test does.
        let mount = sh_ok(&mut agent, &format!("findmnt -no FSTYPE {GUEST_MOUNT}"));
        assert_eq!(
            mount.trim(),
            "ext4",
            "the agent must have mounted the data disk at {GUEST_MOUNT}"
        );
        sh_ok(
            &mut agent,
            &format!("echo {MARKER} > {GUEST_MOUNT}/marker && sync"),
        );
        // A data disk is a virtio-blk image, never a virtiofs share: a
        // fork does not inherit its source's virtiofsd connection, and
        // `--cache never` rejects the shared mmap (CHALLENGES #34).
        assert!(
            vm.virtiofs_shares().is_empty(),
            "a VM with a data disk must have zero virtiofs shares"
        );
        vm.shutdown();
        drop(vm);
        drop(net);
    }

    // ── teardown left the image and nothing else ──
    // `Path::exists()` cannot tell a mount from a mountpoint
    // (CHALLENGES #63), so the check is against the host's real mount
    // and loop-device tables, not the path.
    assert!(
        !host_text("losetup", &["-j", &image_path.to_string_lossy()]).contains("data"),
        "teardown left a loop device on {}",
        image_path.display()
    );
    assert!(
        !host_text("findmnt", &["-rno", "SOURCE,TARGET"])
            .contains(&format!("{}", image_path.display())),
        "teardown left a host mount of {}",
        image_path.display()
    );

    // ── the image is still there, with the bytes in it ──
    assert!(
        image_path.exists(),
        "dropping the VM removed {} — a data disk must outlive its VM",
        image_path.display()
    );
    assert!(
        image_contains(&image_path, MARKER),
        "the guest's write is not in {}",
        image_path.display()
    );

    // ── second VM, same id: reads the first one's bytes ──
    {
        let same = DataDisk::attach(&id, DISK_SIZE, GUEST_MOUNT).expect("re-attach the same id");
        assert_eq!(
            same.path(),
            image_path,
            "re-attach must reuse the same image, not mint a new one"
        );
        let disk = VmDisk::clone_of(&image.base_image(), "dd-second");
        let mut net = ClusterNetwork::create("dd2").expect("cluster bridge");
        let tap = net.add_tap().expect("tap");
        let mut vm = build_node_vm_with_data(
            &image,
            &disk,
            tap,
            NodeCmdlineExtra {
                k3s: None,
                cni: None,
            },
            std::slice::from_ref(&same),
        );
        vm.start().expect("second VM should start");
        let mut agent = connect_or_dump(&mut vm, "second");
        assert_eq!(
            sh_ok(&mut agent, &format!("cat {GUEST_MOUNT}/marker")).trim(),
            MARKER,
            "the second VM did not see the first VM's write — the disk was reformatted"
        );
        vm.shutdown();
        drop(vm);
        drop(net);
    }

    // ── a size that disagrees with the image is an error, not a resize ──
    let err = DataDisk::attach(&id, DISK_SIZE * 2, GUEST_MOUNT)
        .expect_err("a different size must not silently resize or reformat");
    assert!(
        err.to_string().contains("resizing"),
        "unexpected error: {err}"
    );

    // ── explicit delete is the only thing that removes it ──
    drop(data);
    assert!(
        !image_path.exists(),
        "delete left {} behind",
        image_path.display()
    );
    let err = DataDisk::delete(&id).expect_err("deleting a disk twice must be loud");
    assert!(
        err.to_string().contains("No such file"),
        "unexpected error: {err}"
    );
}

/// A warm fork gives the child its **own reflinked clone** of the data
/// disk: it inherits the pre-fork bytes, shares physical extents with the
/// source's copy, and the two diverge in both directions afterwards.
#[test]
fn test_data_disk_forks_copy_on_write() {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = k7d::network::cleanup_stale_k7_bridges();

    let image = node_image();
    let id = TestDataDisk::unique_id("fork");
    let data = TestDataDisk::attach(&id, DISK_SIZE, GUEST_MOUNT);

    let disk = VmDisk::clone_of(&image.base_image(), "dd-fork-src");
    let mut src_net = ClusterNetwork::create("dd3").expect("source bridge");
    let tap = src_net.add_tap().expect("tap");
    let mut source = build_node_vm_with_data(
        &image,
        &disk,
        tap,
        NodeCmdlineExtra {
            k3s: None,
            cni: None,
        },
        std::slice::from_ref(&data.disk),
    );
    source.start().expect("source VM should start");
    let mut agent = connect_or_dump(&mut source, "source");

    const SHARED: &str = "k7d-data-disk-before-the-fork-7e31";
    const SRC_ONLY: &str = "k7d-data-disk-source-only-5c04";
    const CHILD_ONLY: &str = "k7d-data-disk-child-only-8fa9";
    sh_ok(
        &mut agent,
        &format!("echo {SHARED} > {GUEST_MOUNT}/shared && sync"),
    );

    // The data disk is the second block device (root is the first), and
    // it stays that way across the fork — the child's `k7d.blk=` mounts
    // are positional.
    const DATA_INDEX: usize = 1;
    assert_eq!(
        source.data_disks().len(),
        1,
        "the source must report its data disk"
    );

    source
        .prepare_fork_source()
        .expect("prepare_fork_source with a data disk attached");
    let mut agent = source
        .connect_agent(Duration::from_secs(60))
        .expect("reconnect after prepare_fork_source");
    // The prepare swap restores the source from its own snapshot, but it
    // reopens the *same* image paths — so the live source goes on writing
    // the retained image, which is what makes a persistent disk
    // persistent across a fork rather than only up to one.
    let source_data = source.block_devices()[DATA_INDEX].host_path.clone();
    assert_eq!(
        source_data,
        data.disk.path(),
        "the source must keep writing its retained data-disk image across the prepare swap"
    );

    let mut sources: Vec<(&mut Vm, u32)> = vec![(&mut source, 0)];
    let fork_start = Instant::now();
    let (fork_net, mut forks) = fork_cluster_warm(
        &src_net,
        &mut sources,
        "dd3f",
        &[None],
        &[None],
        &["data-disk-fork"],
    )
    .expect("warm fork of a VM with a data disk");
    let fork_latency = fork_start.elapsed();
    eprintln!("MEASUREMENT ubuntu warm fork (1 VM, 1 data disk): {fork_latency:?}");
    // A data disk is one more image to `FICLONE`, which is O(1) — if it
    // ever became a byte copy, a 1 GiB image would blow this budget long
    // before a functional assertion noticed.
    assert!(
        fork_latency < FORK_UBUNTU_NODE_1VM,
        "warm fork of an Ubuntu node with one data disk took {fork_latency:?}, over the \
         {FORK_UBUNTU_NODE_1VM:?} budget"
    );
    let mut child = forks.pop().expect("one fork");
    child.start().expect("fork should start");
    let mut child_agent = child
        .connect_agent(Duration::from_secs(90))
        .expect("forked VM should answer on vsock");

    let child_data = child.block_devices()[DATA_INDEX].host_path.clone();
    assert_ne!(
        child_data, source_data,
        "the child must have its own data-disk image"
    );
    let shared: Vec<u64> = physical_extents(&source_data)
        .intersection(&physical_extents(&child_data))
        .copied()
        .collect();
    assert!(
        !shared.is_empty(),
        "source {} and child {} share no physical extents — the data disk was copied, \
         not reflinked",
        source_data.display(),
        child_data.display()
    );

    assert_eq!(
        sh_ok(&mut child_agent, &format!("cat {GUEST_MOUNT}/shared")).trim(),
        SHARED,
        "the child did not inherit the data disk's pre-fork content"
    );

    // ── two-way divergence, proven in the host's bytes ──
    sh_ok(
        &mut agent,
        &format!("echo {SRC_ONLY} > {GUEST_MOUNT}/side && sync"),
    );
    sh_ok(
        &mut child_agent,
        &format!("echo {CHILD_ONLY} > {GUEST_MOUNT}/side && sync"),
    );
    assert_eq!(
        sh_ok(&mut agent, &format!("cat {GUEST_MOUNT}/side")).trim(),
        SRC_ONLY,
        "the child's data-disk write reached the source"
    );
    assert_eq!(
        sh_ok(&mut child_agent, &format!("cat {GUEST_MOUNT}/side")).trim(),
        CHILD_ONLY,
        "the source's data-disk write reached the child"
    );
    assert!(
        !image_contains(&source_data, CHILD_ONLY),
        "the child's write landed in the source's data disk — the reflink is not CoW"
    );
    assert!(
        !image_contains(&child_data, SRC_ONLY),
        "the source's write landed in the child's data disk — the reflink is not CoW"
    );
    // The retained image *is* the source's, so it keeps the pre-fork
    // bytes and the source's later writes — and never the child's.
    assert!(
        image_contains(data.disk.path(), SHARED) && image_contains(data.disk.path(), SRC_ONLY),
        "the retained image {} lost the source's content",
        data.disk.path().display()
    );
    assert!(
        !image_contains(data.disk.path(), CHILD_ONLY),
        "the child's write reached the retained image {}",
        data.disk.path().display()
    );

    child.shutdown();
    drop(fork_net);
    source.shutdown();
    drop(src_net);
}
