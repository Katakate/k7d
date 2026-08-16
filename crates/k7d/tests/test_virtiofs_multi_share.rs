//! Chunk 1: multi-share virtiofs.
//!
//! Boots a single VM with **three** virtiofs shares — primary
//! (`k7fs` at `/mnt/state`, rw), a second rw share (`k7fs1` at
//! `/mnt/rw-extra`), and a read-only share (`k7fs2` at `/mnt/ro`) —
//! then verifies that:
//!
//! 1. All three shares are mounted inside the guest at the right
//!    paths with the right rw/ro flags.
//! 2. Host content shows up in each share inside the guest.
//! 3. Guest writes propagate back to the host on the two rw shares.
//! 4. Guest writes are refused (`EROFS`) on the ro share.
//!
//! This is the chunk-1 acceptance test for — the
//! plumbing must support arbitrary `(host_dir, guest_mount, ro)`
//! triples before the `volumes.rs` /
//! `PodVolumes::prepare_from_spec` can stand on top of it.

use std::path::PathBuf;
use std::time::Duration;

use k7d::vm::Vm;

fn workspace_path(relative: &str) -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join(relative)
}

#[test]
fn test_virtiofs_three_shares_mixed_ro_rw() {
    let _ = env_logger::builder().is_test(true).try_init();

    let kernel = workspace_path("guest/kernel/vmlinux");
    let initrd = workspace_path("guest/rootfs/initramfs.cpio.gz");

    // Three independent host directories — one per share. Each
    // pre-populated with a distinct file so we can prove the
    // guest sees the right host content for the right tag.
    let primary = tempfile::tempdir().expect("primary tmpdir");
    let rw_extra = tempfile::tempdir().expect("rw-extra tmpdir");
    let ro = tempfile::tempdir().expect("ro tmpdir");
    std::fs::write(primary.path().join("primary.txt"), "hello primary").unwrap();
    std::fs::write(rw_extra.path().join("extra.txt"), "hello extra").unwrap();
    std::fs::write(ro.path().join("readonly.txt"), "hello ro").unwrap();

    // Build the VM with one primary (.virtiofs) + two .virtiofs_share
    // calls. Tag assignment is implementation-internal: k7fs / k7fs1
    // / k7fs2 in declaration order — the test does NOT rely on those
    // names, only on the guest mounts being populated correctly.
    let mut vm = Vm::builder()
        .kernel(&kernel)
        .initrd(&initrd)
        .memory_mb(256)
        .vsock(true)
        .virtiofs(primary.path(), "/mnt/state")
        .virtiofs_share(rw_extra.path(), "/mnt/rw-extra", false)
        .virtiofs_share(ro.path(), "/mnt/ro", true)
        .build()
        .expect("VM should create");

    vm.start().expect("VM should start");
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect to agent");

    // Give the guest agent a beat to finish mounting all three
    // shares. Multi-share adds ~30 ms per extra virtiofsd handshake
    // on top of the cold-boot path; 3 s is more than enough.
    std::thread::sleep(Duration::from_secs(3));

    // 1. All three shares are mounted at the expected paths. Check
    //    via /proc/mounts so a failed mount surfaces here with the
    //    full listing instead of as a confusing read failure below.
    let mounts = agent
        .exec(&["cat", "/proc/mounts"])
        .expect("read /proc/mounts");
    for expected in &["/mnt/state", "/mnt/rw-extra", "/mnt/ro"] {
        assert!(
            mounts.stdout.contains(expected),
            "{expected} not mounted in guest. /proc/mounts:\n{}",
            mounts.stdout
        );
    }
    // Read-only share should have `ro` in its mount options.
    let ro_line = mounts
        .stdout
        .lines()
        .find(|l| l.contains("/mnt/ro "))
        .expect("ro mount line");
    assert!(
        ro_line.contains(" ro,") || ro_line.contains(",ro,") || ro_line.contains(",ro "),
        "ro share missing ro flag: {ro_line}"
    );

    // 2. Host → guest visibility for each share.
    let primary_in_guest = agent
        .exec(&["cat", "/mnt/state/primary.txt"])
        .expect("read primary");
    assert_eq!(primary_in_guest.stdout.trim(), "hello primary");
    let extra_in_guest = agent
        .exec(&["cat", "/mnt/rw-extra/extra.txt"])
        .expect("read extra");
    assert_eq!(extra_in_guest.stdout.trim(), "hello extra");
    let ro_in_guest = agent
        .exec(&["cat", "/mnt/ro/readonly.txt"])
        .expect("read ro");
    assert_eq!(ro_in_guest.stdout.trim(), "hello ro");

    // 3. Guest → host for both rw shares. Read back on the host
    //    filesystem to prove the writes traversed virtiofs.
    agent
        .exec(&["sh", "-c", "echo 'from guest primary' > /mnt/state/g1.txt"])
        .expect("write primary");
    agent
        .exec(&["sh", "-c", "echo 'from guest extra' > /mnt/rw-extra/g2.txt"])
        .expect("write extra");
    let primary_back = std::fs::read_to_string(primary.path().join("g1.txt"))
        .expect("primary write visible on host");
    assert_eq!(primary_back.trim(), "from guest primary");
    let extra_back = std::fs::read_to_string(rw_extra.path().join("g2.txt"))
        .expect("extra write visible on host");
    assert_eq!(extra_back.trim(), "from guest extra");

    // 4. RO share must refuse writes. virtiofsd was launched with
    //    `--readonly`, and the in-guest mount has `ro` — either one
    //    is sufficient to bounce the write back to userspace with
    //    EROFS, which busybox `sh` surfaces as a non-zero exit and
    //    "Read-only file system" on stderr.
    let ro_write = agent
        .exec(&["sh", "-c", "echo nope > /mnt/ro/should-fail.txt"])
        .expect("write attempt should at least invoke");
    assert_ne!(
        ro_write.exit_code, 0,
        "write to ro share should have failed; stdout={} stderr={}",
        ro_write.stdout, ro_write.stderr
    );
    // No file should appear on the host either.
    assert!(
        !ro.path().join("should-fail.txt").exists(),
        "ro share allowed a write through to the host filesystem"
    );

    vm.shutdown();
}
