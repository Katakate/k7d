//! Integration tests for: userspace virtio-blk device.
//! Requires KVM, /dev/vhost-vsock, built guest kernel (CONFIG_VIRTIO_BLK,
//! CONFIG_EXT4_FS), built initramfs, and mkfs.ext4 on the host.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use k7d::vm::Vm;

/// Create a raw ext4 image of `mb` MiB at `dir/name`.
fn make_ext4_image(dir: &Path, name: &str, mb: u64) -> PathBuf {
    let img = dir.join(name);
    let f = std::fs::File::create(&img).unwrap();
    f.set_len(mb * 1024 * 1024).unwrap();
    drop(f);
    let out = Command::new("mkfs.ext4")
        .args(["-F", "-q"])
        .arg(&img)
        .output()
        .expect("mkfs.ext4 should be installed on the node");
    assert!(
        out.status.success(),
        "mkfs.ext4 failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    img
}

/// Loop-mount `img` at a fresh tempdir, run `f`, always unmount.
fn with_host_mount<R>(img: &Path, writable: bool, f: impl FnOnce(&Path) -> R) -> R {
    let mnt = tempfile::tempdir().unwrap();
    let mut opts = String::from("loop");
    if !writable {
        opts.push_str(",ro");
    }
    let out = Command::new("mount")
        .args(["-o", &opts])
        .arg(img)
        .arg(mnt.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "host loop mount of {} failed: {}",
        img.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(mnt.path())));
    let um = Command::new("umount").arg(mnt.path()).output().unwrap();
    assert!(
        um.status.success(),
        "host umount failed: {}",
        String::from_utf8_lossy(&um.stderr)
    );
    match result {
        Ok(r) => r,
        Err(p) => std::panic::resume_unwind(p),
    }
}

fn build_vm_with_block(img: &Path, readonly: bool) -> Vm {
    Vm::builder()
        .kernel_and_initrd()
        .memory_mb(256)
        .vsock(true)
        .block_device(img, readonly)
        .build()
        .expect("VM with block device should build")
}

/// Run a shell command in the guest, asserting success.
fn guest_sh(agent: &mut k7d::api::AgentClient, cmd: &str) -> String {
    let out = agent.exec(&["sh", "-c", cmd]).unwrap();
    assert_eq!(
        out.exit_code, 0,
        "guest command `{cmd}` failed: stdout={} stderr={}",
        out.stdout, out.stderr
    );
    out.stdout
}

#[test]
fn test_block_device_read_write() {
    let _ = env_logger::builder().is_test(true).try_init();

    let dir = tempfile::tempdir().unwrap();
    let img = make_ext4_image(dir.path(), "rw.img", 64);

    let mut vm = build_vm_with_block(&img, false);
    vm.start().unwrap();
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect to agent");

    guest_sh(&mut agent, "test -b /dev/vda");
    guest_sh(
        &mut agent,
        "mkdir -p /mnt/blk && mount -t ext4 /dev/vda /mnt/blk \
         && echo hello-from-guest > /mnt/blk/guest.txt && sync && umount /mnt/blk",
    );
    vm.shutdown();

    // Host sees the guest's write through a loop mount.
    let content = with_host_mount(&img, false, |mnt| {
        std::fs::read_to_string(mnt.join("guest.txt")).unwrap()
    });
    assert_eq!(content.trim(), "hello-from-guest");
}

#[test]
fn test_block_device_readonly_enforced() {
    let _ = env_logger::builder().is_test(true).try_init();

    let dir = tempfile::tempdir().unwrap();
    let img = make_ext4_image(dir.path(), "ro.img", 16);
    with_host_mount(&img, true, |mnt| {
        std::fs::write(mnt.join("host.txt"), "from-host\n").unwrap();
    });
    let bytes_before = std::fs::read(&img).unwrap();

    let mut vm = build_vm_with_block(&img, true);
    vm.start().unwrap();
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect to agent");

    // RO mount works and sees the host's file.
    let content = guest_sh(
        &mut agent,
        "mkdir -p /mnt/blk && mount -t ext4 -o ro /dev/vda /mnt/blk && cat /mnt/blk/host.txt",
    );
    assert_eq!(content.trim(), "from-host");

    // In-guest write attempts fail: on the ro mount and on the raw device
    // (the kernel marks the disk read-only from VIRTIO_BLK_F_RO).
    let w1 = agent
        .exec(&["sh", "-c", "echo x > /mnt/blk/new.txt"])
        .unwrap();
    assert_ne!(w1.exit_code, 0, "write on ro mount must fail");
    let w2 = agent
        .exec(&[
            "sh",
            "-c",
            "dd if=/dev/zero of=/dev/vda bs=512 count=1 conv=notrunc",
        ])
        .unwrap();
    assert_ne!(w2.exit_code, 0, "raw write to read-only /dev/vda must fail");

    guest_sh(&mut agent, "umount /mnt/blk");
    vm.shutdown();

    // Backing file must be bit-for-bit unchanged.
    let bytes_after = std::fs::read(&img).unwrap();
    assert!(
        bytes_before == bytes_after,
        "read-only backing file was modified"
    );
}

#[test]
fn test_block_device_snapshot_restore() {
    let _ = env_logger::builder().is_test(true).try_init();

    let dir = tempfile::tempdir().unwrap();
    let img = make_ext4_image(dir.path(), "snap.img", 64);

    let mut vm = build_vm_with_block(&img, false);
    vm.start().unwrap();
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect to agent");

    // Write while the device stays mounted, then snapshot: page cache and
    // device ring state must survive the restore coherently.
    guest_sh(
        &mut agent,
        "mkdir -p /mnt/blk && mount -t ext4 /dev/vda /mnt/blk \
         && echo pre-snapshot > /mnt/blk/data.txt && sync",
    );

    let snapshot_dir = tempfile::tempdir().unwrap();
    vm.snapshot(snapshot_dir.path()).unwrap();
    vm.shutdown();

    let mut restored = Vm::restore(snapshot_dir.path()).expect("restore with block device");
    restored.start().unwrap();
    let mut agent = restored
        .connect_agent(Duration::from_secs(30))
        .expect("should connect to restored agent");

    let content = guest_sh(&mut agent, "cat /mnt/blk/data.txt");
    assert_eq!(content.trim(), "pre-snapshot");

    // Device still services fresh I/O after restore.
    guest_sh(
        &mut agent,
        "echo post-restore > /mnt/blk/data2.txt && sync && cat /mnt/blk/data2.txt",
    );

    restored.shutdown();
}

#[test]
fn test_block_device_warm_fork_ro() {
    let _ = env_logger::builder().is_test(true).try_init();

    let dir = tempfile::tempdir().unwrap();
    let img = make_ext4_image(dir.path(), "fork-ro.img", 16);
    with_host_mount(&img, true, |mnt| {
        std::fs::write(mnt.join("marker.txt"), "ro-fork-marker\n").unwrap();
    });

    let mut source = build_vm_with_block(&img, true);
    source.start().unwrap();
    let _ = source
        .connect_agent(Duration::from_secs(90))
        .expect("initial agent connect");

    source
        .prepare_fork_source()
        .expect("prepare_fork_source with RO block device");
    let mut agent = source
        .connect_agent(Duration::from_secs(30))
        .expect("reconnect after prepare_fork_source");

    // Mount before forking so the fork inherits the live mount.
    let content = guest_sh(
        &mut agent,
        "mkdir -p /mnt/blk && mount -t ext4 -o ro /dev/vda /mnt/blk && cat /mnt/blk/marker.txt",
    );
    assert_eq!(content.trim(), "ro-fork-marker");

    let mut forked = source.fork_warm("blk-ro-fork").expect("warm fork");

    // Invariant: a VM whose only extra device is virtio-blk must
    // stay on the CoW (MAP_PRIVATE base.mem) fork path, not full-memfd.
    assert!(
        !forked.fork_memory_is_full_copy(),
        "block-only VM took the full-memfd fork path"
    );

    forked.start().unwrap();
    let mut fork_agent = forked
        .connect_agent(Duration::from_secs(30))
        .expect("forked VM should be reachable");
    let fork_content = guest_sh(&mut fork_agent, "cat /mnt/blk/marker.txt");
    assert_eq!(fork_content.trim(), "ro-fork-marker");

    // Source keeps reading the shared backing file, undisturbed.
    let src_content = guest_sh(&mut agent, "cat /mnt/blk/marker.txt");
    assert_eq!(src_content.trim(), "ro-fork-marker");

    forked.shutdown();
    source.shutdown();
}

#[test]
fn test_block_device_warm_fork_rw_requires_reflink() {
    let _ = env_logger::builder().is_test(true).try_init();

    let dir = tempfile::tempdir().unwrap();
    let img = make_ext4_image(dir.path(), "fork-rw.img", 16);

    let mut source = build_vm_with_block(&img, false);
    source.start().unwrap();
    let _ = source
        .connect_agent(Duration::from_secs(90))
        .expect("initial agent connect");

    source
        .prepare_fork_source()
        .expect("prepare_fork_source with RW block device");
    let _ = source
        .connect_agent(Duration::from_secs(30))
        .expect("reconnect after prepare_fork_source");

    // The node's /tmp is not reflink-capable (ext4/tmpfs): forking a VM
    // with an RW block image must fail loudly, naming the requirement.
    let msg = match source.fork_warm("blk-rw-fork") {
        Ok(_) => panic!("warm fork of RW block device must fail without reflink"),
        Err(e) => format!("{e}"),
    };
    assert!(
        msg.contains("reflink"),
        "error should name the reflink requirement, got: {msg}"
    );

    // The source must remain usable after the failed fork.
    let mut agent = source
        .connect_agent(Duration::from_secs(30))
        .expect("source agent after failed fork");
    let alive = agent.exec(&["echo", "still-alive"]).unwrap();
    assert_eq!(alive.stdout.trim(), "still-alive");

    source.shutdown();
}

#[test]
fn test_fork_full_dump_when_nonquiescent_virtio_blk() {
    let _ = env_logger::builder().is_test(true).try_init();

    let dir = tempfile::tempdir().unwrap();
    let img = make_ext4_image(dir.path(), "wedge.img", 16);
    let mut source = build_vm_with_block(&img, true);
    source.start().unwrap();
    let _ = source
        .connect_agent(Duration::from_secs(90))
        .expect("initial agent connect");

    source
        .prepare_fork_source()
        .expect("prepare while workers can park");
    let _ = source
        .connect_agent(Duration::from_secs(30))
        .expect("reconnect after prepare_fork_source");

    let before = k7d::virtio_mmio::fork_nonquiescent_counts();
    source.hold_virtio_workers_for_test(true);
    let mut dumped = source
        .fork_warm("wedged-blk")
        .expect("missed park must fall back to a full dump, not refuse");
    source.hold_virtio_workers_for_test(false);

    assert!(
        dumped.fork_memory_is_full_copy(),
        "non-quiescent fork must take the memfd full-dump path"
    );
    let after = k7d::virtio_mmio::fork_nonquiescent_counts();
    assert!(
        after.virtio_blk > before.virtio_blk,
        "counter must increment: before={before:?} after={after:?}"
    );

    dumped.start().unwrap();
    let mut dump_agent = dumped
        .connect_agent(Duration::from_secs(30))
        .expect("full-dump child reachable");
    dump_agent.ping().unwrap();
    dumped.shutdown();

    // Source stays up; a later fork with the wedge off is CoW again.
    let mut agent = source
        .connect_agent(Duration::from_secs(30))
        .expect("source agent after full-dump fork");
    let alive = agent.exec(&["echo", "still-alive"]).unwrap();
    assert_eq!(alive.stdout.trim(), "still-alive");

    let mut forked = source
        .fork_warm("after-wedge")
        .expect("healthy fork after the wedge is lifted");
    assert!(!forked.fork_memory_is_full_copy());
    forked.start().unwrap();
    let mut fork_agent = forked
        .connect_agent(Duration::from_secs(30))
        .expect("fork after wedge");
    fork_agent.ping().unwrap();
    forked.shutdown();
    source.shutdown();
}
