//! Integration test for Milestone 3: host-guest directory sharing via virtiofs.
//! Requires KVM (/dev/kvm), virtiofsd, built guest kernel, and built initramfs.

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
fn test_virtiofs_host_guest_shared() {
    let _ = env_logger::builder().is_test(true).try_init();

    let kernel = workspace_path("guest/kernel/vmlinux");
    let initrd = workspace_path("guest/rootfs/initramfs.cpio.gz");

    // Create a temporary host directory with a file
    let state_dir = tempfile::tempdir().unwrap();
    std::fs::write(state_dir.path().join("host-file.txt"), "from host").unwrap();

    let mut vm = Vm::builder()
        .kernel(&kernel)
        .initrd(&initrd)
        .memory_mb(256)
        .vsock(true)
        .virtiofs(state_dir.path(), "/mnt/state")
        .build()
        .expect("VM should create");

    vm.start().expect("VM should start");
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect to agent");

    // Wait for virtiofs mount to complete
    std::thread::sleep(Duration::from_secs(3));

    // Read host file from guest via exec (true virtiofs — kernel mount, not agent file transfer)
    let read = agent
        .exec(&["cat", "/mnt/state/host-file.txt"])
        .expect("cat should work");
    assert_eq!(read.stdout.trim(), "from host");

    // Write from guest, read from host (bidirectional via virtiofs)
    agent
        .exec(&["sh", "-c", "echo 'from guest' > /mnt/state/guest-file.txt"])
        .expect("write should work");

    // Read the guest-written file directly from the host filesystem
    let content = std::fs::read_to_string(state_dir.path().join("guest-file.txt"))
        .expect("should read guest file on host");
    assert_eq!(content.trim(), "from guest");

    vm.shutdown();
}
