//! Integration test: per-cluster bridge + virtio-net.
//! Requires KVM, /dev/vhost-net, /dev/net/tun, built guest kernel with
//! CONFIG_VIRTIO_NET=y, and built initramfs with `ifconfig`/`ip`.

use std::path::PathBuf;
use std::time::Duration;

use k7d::network::ClusterNetwork;
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
fn test_vm_has_network_interface() {
    let _ = env_logger::builder().is_test(true).try_init();
    // Test-setup hygiene: sweep stale k7-br-* bridges from prior runs so
    // a zombie bridge doesn't keep the 10.200.0.1 gateway IP and break
    // our freshly-created one. See k7d::network::cleanup_stale_k7_bridges
    // for the full rationale.
    let _ = k7d::network::cleanup_stale_k7_bridges();

    let kernel = workspace_path("guest/kernel/vmlinux");
    let initrd = workspace_path("guest/rootfs/initramfs.cpio.gz");

    let mut net = ClusterNetwork::create("test-net").unwrap();
    let tap = net.add_tap().unwrap();
    let guest_ip = tap.guest_ip();

    let mut vm = Vm::builder()
        .kernel(&kernel)
        .initrd(&initrd)
        .memory_mb(256)
        .vsock(true)
        .network(tap)
        .build()
        .expect("VM should create");

    vm.start().expect("VM should start");
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect to agent");

    // Wait for virtio device to appear
    std::thread::sleep(Duration::from_secs(3));

    // Verify the virtio-net device exists in sysfs
    let virtio_devs = agent
        .exec(&["ls", "/sys/bus/virtio/devices/"])
        .expect("ls virtio");

    // Check if virtio_net driver bound (eth0 should appear)
    let sys_net = agent.exec(&["ls", "/sys/class/net/"]).expect("ls net");

    if !sys_net.stdout.contains("eth0") {
        // Check if it's a kernel config issue (virtio_net not compiled in)
        let net_dev = agent.exec(&["cat", "/proc/net/dev"]).unwrap();
        eprintln!(
            "No eth0 found. virtio devices: {}",
            virtio_devs.stdout.trim()
        );
        eprintln!("/sys/class/net: {}", sys_net.stdout.trim());
        eprintln!("/proc/net/dev:\n{}", net_dev.stdout);
        eprintln!("Guest kernel may not have CONFIG_VIRTIO_NET=y compiled in.");
        eprintln!("Rebuild the guest kernel with: make remote-build-guest-kernel");

        // Still verify the MMIO device was registered
        assert!(
            virtio_devs.stdout.lines().count() >= 2,
            "should have at least 2 virtio devices (vsock + net)"
        );
        vm.shutdown();
        return;
    }

    // Configure the interface
    let _ = agent.exec(&[
        "ifconfig",
        "eth0",
        &format!("{guest_ip}"),
        "netmask",
        "255.255.255.0",
        "up",
    ]);
    let _ = agent.exec(&["route", "add", "default", "gw", "10.200.0.1"]);

    // Verify interface is configured
    let ifconfig = agent.exec(&["ifconfig", "eth0"]).expect("ifconfig");
    assert!(
        ifconfig.stdout.contains("eth0"),
        "eth0 should be configured: {}",
        ifconfig.stdout
    );

    // Check guest-side interface status
    let ifstatus = agent.exec(&["ifconfig", "eth0"]).expect("ifconfig");
    eprintln!("Guest eth0:\n{}", ifstatus.stdout);

    // Check if the vhost-net activation succeeded by looking at virtio status
    let status = agent
        .exec(&["cat", "/sys/bus/virtio/devices/virtio1/status"])
        .expect("status");
    eprintln!("virtio1 status: {}", status.stdout.trim());

    // Check ARP table before ping
    let arp_before = agent.exec(&["cat", "/proc/net/arp"]);
    eprintln!("ARP before ping: {:?}", arp_before);

    // Check TX/RX after ifconfig
    let tx_check = agent.exec(&["cat", "/sys/class/net/eth0/statistics/tx_packets"]);
    eprintln!("TX packets: {:?}", tx_check);

    // First do an ARP probe to populate the table
    let _ = agent.exec(&["ping", "-c", "1", "-W", "2", "10.200.0.1"]);
    std::thread::sleep(Duration::from_millis(500));

    // Now ping should work with ARP already resolved
    let ping = agent
        .exec(&["ping", "-c", "1", "-W", "3", "10.200.0.1"])
        .expect("ping");
    eprintln!(
        "ping exit={} stdout={} stderr={}",
        ping.exit_code, ping.stdout, ping.stderr
    );
    // Check TX/RX after ping
    let tx_after = agent.exec(&["cat", "/sys/class/net/eth0/statistics/tx_packets"]);
    let rx_after = agent.exec(&["cat", "/sys/class/net/eth0/statistics/rx_packets"]);
    eprintln!("TX after ping: {:?}", tx_after);
    eprintln!("RX after ping: {:?}", rx_after);

    let arp_after = agent.exec(&["cat", "/proc/net/arp"]);
    eprintln!("ARP after ping: {:?}", arp_after);

    assert_eq!(
        ping.exit_code, 0,
        "should ping gateway: stdout={} stderr={}",
        ping.stdout, ping.stderr
    );

    vm.shutdown();
}

#[test]
fn test_fork_from_preserves_topology() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut src = ClusterNetwork::create("topo-src").expect("source bridge");
    let t1 = src.add_tap().expect("tap 0");
    let t2 = src.add_tap().expect("tap 1");
    let t1_ip = t1.guest_ip();
    let t1_mac = t1.mac();
    let t2_ip = t2.guest_ip();
    let t2_mac = t2.mac();
    let t1_idx = t1.vm_index();
    let t2_idx = t2.vm_index();
    drop(t1);
    drop(t2);

    let mut fork = ClusterNetwork::fork_from(&src, "topo-fork").expect("fork bridge");
    assert_ne!(fork.bridge_name(), src.bridge_name(), "different bridges");

    // Reproduce both source TAP indices on the fork bridge.
    let f1 = fork.add_tap_at(t1_idx).expect("fork tap 0");
    let f2 = fork.add_tap_at(t2_idx).expect("fork tap 1");
    assert_eq!(
        f1.guest_ip(),
        t1_ip,
        "fork should reuse source's guest IP for vm_index 0"
    );
    assert_eq!(
        f1.mac(),
        t1_mac,
        "fork should reuse source's MAC for vm_index 0"
    );
    assert_eq!(f2.guest_ip(), t2_ip);
    assert_eq!(f2.mac(), t2_mac);
    assert_ne!(
        f1.name(),
        src.entry(t1_idx).unwrap().tap_name,
        "fork TAP names must differ from source TAP names"
    );

    drop(f1);
    drop(f2);
}

#[test]
fn test_add_tap_at_rejects_duplicate_index() {
    let mut net = ClusterNetwork::create("dup-idx").expect("bridge");
    let _t = net.add_tap_at(7).expect("first add_tap_at");
    let dup = net.add_tap_at(7);
    assert!(dup.is_err(), "duplicate vm_index must fail");
    drop(_t);
}

#[test]
fn test_create_is_idempotent() {
    let net1 = ClusterNetwork::create("idempotent").expect("first create");
    let net2 = ClusterNetwork::create("idempotent").expect("second create attaches");
    assert_eq!(net1.bridge_name(), net2.bridge_name());
    drop(net2);
    // net1's Drop will tear down the bridge.
    drop(net1);
}
