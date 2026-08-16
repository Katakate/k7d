//! Integration test: guest agent + vsock communication.
//! Requires KVM, /dev/vhost-vsock, built guest kernel, and built initramfs.

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
fn test_vsock_ping_pong() {
    let _ = env_logger::builder().is_test(true).try_init();

    let kernel = workspace_path("guest/kernel/vmlinux");
    let initrd = workspace_path("guest/rootfs/initramfs.cpio.gz");

    assert!(kernel.exists(), "guest kernel not found at {kernel:?}");
    assert!(initrd.exists(), "initramfs not found at {initrd:?}");

    let mut vm = Vm::builder()
        .kernel(&kernel)
        .initrd(&initrd)
        .memory_mb(256)
        .vsock(true)
        .build()
        .expect("VM should create");

    vm.start().expect("VM should start");

    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect to agent via vsock");

    let resp = agent.ping().expect("ping should succeed");
    assert_eq!(resp.version, "0.1.0");

    let exec = agent.exec(&["echo", "hello"]).expect("exec should succeed");
    assert_eq!(exec.exit_code, 0);
    assert_eq!(exec.stdout.trim(), "hello");

    vm.shutdown();
}
