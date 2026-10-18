//! Integration tests for the **named persistent data disk** primitive:
//! a disk whose lifetime is not the VM's, so an inner
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

use k7d::control::{Client, Request, Response, VmConfig};
use k7d::disks::{data_disk_path, DataDisk};
use k7d::fork::fork_cluster_warm;
use k7d::guest::Backend;
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

/// Daemon `create_vm` refuses a data-disk id held by a live VM.
/// After `stop_vm` the same id attaches; a warm fork still
/// gets its own reflink.
#[test]
fn test_data_disk_exclusive_while_live() {
    let _ = env_logger::builder().is_test(true).try_init();
    let pid = std::process::id();
    let socket_dir = std::env::temp_dir().join(format!("k7d-test-ddexcl-{pid}"));
    let _ = std::fs::remove_dir_all(&socket_dir);
    std::fs::create_dir_all(&socket_dir).expect("socket parent");
    let socket = socket_dir.join("k7d.sock");
    let tree_root = std::env::temp_dir().join(format!("k7d-test-trees-ddexcl-{pid}"));
    let sandbox_root = std::env::temp_dir().join(format!("k7d-test-sandboxes-ddexcl-{pid}"));
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_k7d"))
        .arg("--socket")
        .arg(&socket)
        .env("RUST_LOG", "info")
        .env("K7D_TREE_ROOT", &tree_root)
        .env("K7D_SANDBOX_ROOT", &sandbox_root)
        .spawn()
        .expect("spawn k7d");
    struct Guard {
        child: std::process::Child,
        socket_dir: std::path::PathBuf,
        tree_root: std::path::PathBuf,
        sandbox_root: std::path::PathBuf,
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = std::fs::remove_dir_all(&self.socket_dir);
            let _ = std::fs::remove_dir_all(&self.tree_root);
            let _ = std::fs::remove_dir_all(&self.sandbox_root);
        }
    }
    let _guard = Guard {
        child,
        socket_dir: socket_dir.clone(),
        tree_root,
        sandbox_root,
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon socket never appeared");
        std::thread::sleep(Duration::from_millis(50));
    }

    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace")
        .to_path_buf();
    let id = format!("test-excl-{pid}");
    let _ = std::fs::remove_file(data_disk_path(&id));
    let config = VmConfig {
        kernel: Some(
            root.join("guest/kernel/vmlinux")
                .to_string_lossy()
                .into_owned(),
        ),
        initrd: Some(
            root.join("guest/rootfs/initramfs.cpio.gz")
                .to_string_lossy()
                .into_owned(),
        ),
        data_disks: vec![k7d::control::DataDiskConfig {
            id: id.clone(),
            size_bytes: 64 * 1024 * 1024,
            guest_mount: "/run/k7d/data".to_string(),
        }],
        ..VmConfig::default()
    };

    let call = |req: &Request| -> Response {
        let mut c = Client::connect(socket.to_str().expect("utf8")).expect("connect");
        c.call(req).expect("call")
    };

    let vm_id = match call(&Request::CreateVm {
        config: config.clone(),
    }) {
        Response::VmCreated { vm_id, .. } => vm_id,
        other => panic!("first create_vm: {other:?}"),
    };

    match call(&Request::CreateVm {
        config: config.clone(),
    }) {
        Response::Error { message } => {
            assert!(
                message.contains("attached to live VM") && message.contains(&vm_id),
                "refusal must name the holder, got: {message}"
            );
        }
        other => panic!("second create_vm while live must fail, got {other:?}"),
    }

    assert!(matches!(call(&Request::StopVm { vm_id }), Response::Ok));

    let (vm_id2, cid2) = match call(&Request::CreateVm {
        config: config.clone(),
    }) {
        Response::VmCreated {
            vm_id, guest_cid, ..
        } => (vm_id, guest_cid),
        other => panic!("create_vm after stop must succeed, got {other:?}"),
    };

    let mut agent =
        k7d::api::AgentClient::connect_vsock(cid2, Duration::from_secs(90)).expect("agent");
    let ready = agent.exec(&["echo", "ready"]).expect("exec");
    assert_eq!(ready.exit_code, 0, "{}", ready.stderr);

    match call(&Request::ForkVm {
        vm_id: vm_id2.clone(),
        sandbox_id: None,
        pod_netns: None,
        dilation: None,
    }) {
        Response::VmForked { vm_id: fork_id, .. } => {
            assert!(matches!(
                call(&Request::StopVm { vm_id: fork_id }),
                Response::Ok
            ));
        }
        other => panic!("warm fork of a VM with a data disk must succeed, got {other:?}"),
    }

    assert!(matches!(
        call(&Request::StopVm { vm_id: vm_id2 }),
        Response::Ok
    ));
    assert!(matches!(
        call(&Request::DeleteDataDisk { id }),
        Response::Ok
    ));
}

/// Firecracker is a holder of its data disks: a second
/// FC `create_vm` with the same id fails naming the first, native-vs-FC
/// and FC-vs-native both refuse, and `delete_data_disk` while the FC VM
/// is live fails — after `stop_vm` it succeeds.
#[test]
fn test_fc_data_disk_exclusive_while_live() {
    let _ = env_logger::builder().is_test(true).try_init();
    common::ensure_firecracker_installed();
    let pid = std::process::id();
    let socket_dir = std::env::temp_dir().join(format!("k7d-test-fcddexcl-{pid}"));
    let _ = std::fs::remove_dir_all(&socket_dir);
    std::fs::create_dir_all(&socket_dir).expect("socket parent");
    let socket = socket_dir.join("k7d.sock");
    let tree_root = std::env::temp_dir().join(format!("k7d-test-trees-fcddexcl-{pid}"));
    let sandbox_root = std::env::temp_dir().join(format!("k7d-test-sandboxes-fcddexcl-{pid}"));
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace")
        .to_path_buf();
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_k7d"))
        .arg("--socket")
        .arg(&socket)
        .env("RUST_LOG", "info")
        .env("K7D_KERNEL", root.join("guest/kernel/vmlinux"))
        .env("K7D_INITRD", root.join("guest/rootfs/initramfs.cpio.gz"))
        .env("K7D_TREE_ROOT", &tree_root)
        .env("K7D_SANDBOX_ROOT", &sandbox_root)
        .spawn()
        .expect("spawn k7d");
    struct Guard {
        child: std::process::Child,
        socket_dir: std::path::PathBuf,
        tree_root: std::path::PathBuf,
        sandbox_root: std::path::PathBuf,
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = std::fs::remove_dir_all(&self.socket_dir);
            let _ = std::fs::remove_dir_all(&self.tree_root);
            let _ = std::fs::remove_dir_all(&self.sandbox_root);
        }
    }
    let _guard = Guard {
        child,
        socket_dir: socket_dir.clone(),
        tree_root,
        sandbox_root,
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon socket never appeared");
        std::thread::sleep(Duration::from_millis(50));
    }

    let id = format!("test-fc-excl-{pid}");
    let _ = std::fs::remove_file(data_disk_path(&id));
    let disks = vec![k7d::control::DataDiskConfig {
        id: id.clone(),
        size_bytes: 64 * 1024 * 1024,
        guest_mount: "/run/k7d/data".to_string(),
    }];
    let native = VmConfig {
        kernel: Some(
            root.join("guest/kernel/vmlinux")
                .to_string_lossy()
                .into_owned(),
        ),
        initrd: Some(
            root.join("guest/rootfs/initramfs.cpio.gz")
                .to_string_lossy()
                .into_owned(),
        ),
        data_disks: disks.clone(),
        ..VmConfig::default()
    };
    let fc = VmConfig {
        memory_mb: 512,
        vcpus: 1,
        backend: Backend::Firecracker,
        data_disks: disks,
        ..VmConfig::default()
    };

    let call = |req: &Request| -> Response {
        let mut c = Client::connect(socket.to_str().expect("utf8")).expect("connect");
        c.call(req).expect("call")
    };
    let refuse = |holder: &str, got: Response, what: &str| match got {
        Response::Error { message } => {
            assert!(
                message.contains("attached to live VM") && message.contains(holder),
                "{what}: refusal must name the holder {holder}, got: {message}"
            );
        }
        other => panic!("{what}: must fail, got {other:?}"),
    };

    let native_id = match call(&Request::CreateVm {
        config: native.clone(),
    }) {
        Response::VmCreated { vm_id, .. } => vm_id,
        other => panic!("native create_vm: {other:?}"),
    };
    refuse(
        &native_id,
        call(&Request::CreateVm { config: fc.clone() }),
        "FC-steals-from-native",
    );
    assert!(matches!(
        call(&Request::StopVm { vm_id: native_id }),
        Response::Ok
    ));

    let fc_id = match call(&Request::CreateVm { config: fc.clone() }) {
        Response::VmCreated { vm_id, .. } => vm_id,
        other => panic!("FC create_vm: {other:?}"),
    };
    refuse(
        &fc_id,
        call(&Request::CreateVm { config: fc.clone() }),
        "second FC create_vm",
    );
    refuse(
        &fc_id,
        call(&Request::CreateVm {
            config: native.clone(),
        }),
        "native-steals-from-FC",
    );
    match call(&Request::DeleteDataDisk { id: id.clone() }) {
        Response::Error { message } => {
            assert!(
                message.contains("attached to live VM") && message.contains(&fc_id),
                "delete while FC live must name the holder, got: {message}"
            );
        }
        other => panic!("delete_data_disk while FC live must fail, got {other:?}"),
    }
    assert!(matches!(
        call(&Request::StopVm { vm_id: fc_id }),
        Response::Ok
    ));
    assert!(matches!(
        call(&Request::DeleteDataDisk { id }),
        Response::Ok
    ));
}
