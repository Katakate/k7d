//! virtio-pci transport, end to end on a real guest.
//!
//! The Ubuntu node kernel (`linux-image-virtual`) has `virtio_pci`
//! built in, so it is the proof that k7d's own PCI bus — type-1
//! config access at `0xCF8/0xCFC`, a host bridge at `00:00.0`, one
//! modern virtio-pci function per device — is something a stock
//! distro kernel enumerates, binds, and drives. The same node boots
//! on virtio-mmio in every other `test_ubuntu_*` suite; the only
//! differences here are `transport(Pci)` and a cmdline without
//! `pci=off`.
//!
//! Three rebuild paths carry the PCI function state, and all three run
//! here: `prepare_fork_source` is a cold snapshot + restore of the
//! source, `fork_cluster_warm` builds the child from in-memory device
//! state, and `pause`/`resume` stops and restarts the child's vCPUs
//! with the bus untouched.

mod common;

use std::time::Duration;

use k7d::api::AgentClient;
use k7d::fork::fork_cluster_warm;
use k7d::network::ClusterNetwork;
use k7d::virtio_mmio::Transport;
use k7d::vm::Vm;

use common::ubuntu::{
    connect_or_dump, node_cmdline, node_image, sh, sh_ok, TestDataDisk, VmDisk, NODE_MEMORY_MB,
    NODE_VCPUS,
};

/// virtio-pci modern device ids: `0x1040 + virtio device type`.
const PCI_ID_NET: &str = "0x1041";
const PCI_ID_BLK: &str = "0x1042";
const PCI_ID_VSOCK: &str = "0x1053";

/// Where the data disk is mounted in the guest.
const DATA_MOUNT: &str = "/mnt/k7d-pci-data";

/// Ubuntu cmdline for a PCI guest: the same line minus `pci=off`.
fn pci_cmdline(guest_ip: std::net::Ipv4Addr) -> String {
    let mmio = node_cmdline(guest_ip);
    assert!(
        mmio.split_whitespace().any(|t| t == "pci=off"),
        "the mmio node cmdline no longer carries pci=off: {mmio}"
    );
    mmio.split_whitespace()
        .filter(|t| *t != "pci=off")
        .collect::<Vec<_>>()
        .join(" ")
}

/// `(slot, vendor, device)` for every PCI function the guest sees,
/// in slot order, from sysfs (no `pciutils` dependency).
fn pci_functions(agent: &mut AgentClient) -> Vec<(String, String, String)> {
    let out = sh_ok(
        agent,
        "for d in /sys/bus/pci/devices/*; do \
            printf '%s %s %s\\n' \"$(basename $d)\" \"$(cat $d/vendor)\" \"$(cat $d/device)\"; \
         done | sort",
    );
    out.lines()
        .map(|l| {
            let mut f = l.split_whitespace();
            (
                f.next().unwrap_or_default().to_string(),
                f.next().unwrap_or_default().to_string(),
                f.next().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

/// What a PCI guest built by [`build_pci_node`] must look like from
/// the inside: bus, functions, virtio binding, and the devices doing
/// their job (root on vda, data disk mounted, eth0 reaching the bridge).
fn assert_pci_guest(agent: &mut AgentClient, whose: &str) {
    let funcs = pci_functions(agent);
    eprintln!("{whose}: PCI functions: {funcs:?}");
    let want = [
        ("0000:00:00.0", "0x8086", "0x1237"),
        ("0000:00:01.0", "0x1af4", PCI_ID_VSOCK),
        ("0000:00:02.0", "0x1af4", PCI_ID_BLK),
        ("0000:00:03.0", "0x1af4", PCI_ID_BLK),
        ("0000:00:04.0", "0x1af4", PCI_ID_NET),
    ];
    let got: Vec<(&str, &str, &str)> = funcs
        .iter()
        .map(|(s, v, d)| (s.as_str(), v.as_str(), d.as_str()))
        .collect();
    assert_eq!(
        got, want,
        "{whose}: the bus does not show the host bridge plus vsock, root, data, net"
    );

    // `lspci` is the doc's check; the image may or may not ship pciutils.
    let (code, lspci, _) = sh(agent, "command -v lspci >/dev/null && lspci -n");
    if code == 0 {
        eprintln!("{whose}: lspci -n:\n{lspci}");
        assert!(
            lspci.contains("1af4:1042") && lspci.contains("1af4:1041"),
            "{whose}: lspci -n does not list the blk and net functions:\n{lspci}"
        );
    }

    // virtio-pci bound every function: virtio0 is the first device on
    // the bus (vsock at slot 1), and the count matches.
    let virtio0 = sh_ok(agent, "readlink -f /sys/bus/virtio/devices/virtio0");
    assert!(
        virtio0.trim().contains("0000:00:01.0"),
        "{whose}: virtio0 is not the function at 00:01.0: {virtio0}"
    );
    let bound = sh_ok(agent, "ls /sys/bus/virtio/devices | wc -l");
    assert_eq!(
        bound.trim(),
        "4",
        "{whose}: virtio-pci did not bind all four functions"
    );
    let drivers = sh_ok(
        agent,
        "for d in /sys/bus/pci/devices/0000:00:0[1-4].0; do basename $(readlink -f $d/driver); done",
    );
    assert!(
        drivers.lines().all(|l| l.trim() == "virtio-pci"),
        "{whose}: not every function is driven by virtio-pci: {drivers}"
    );

    // Interrupts are the INTx lines this VMM pulses: each function's
    // irq is `5 + idx`, and the kernel kept them (no IOAPIC rerouting).
    let irqs = sh_ok(
        agent,
        "for d in /sys/bus/pci/devices/0000:00:0[1-4].0; do cat $d/irq; done",
    );
    let irqs: Vec<&str> = irqs.split_whitespace().collect();
    assert_eq!(
        irqs,
        ["5", "6", "7", "8"],
        "{whose}: PCI INTx lines were rerouted away from the 8259 lines k7d drives"
    );

    // The devices work: root on the first blk, data disk mounted by
    // the agent, eth0 up with the bridge gateway answering.
    assert_eq!(
        sh_ok(agent, "findmnt -no SOURCE /").trim(),
        "/dev/vda",
        "{whose}: root is not on the first virtio-blk function"
    );
    let data = sh_ok(
        agent,
        &format!("findmnt -no SOURCE,FSTYPE {DATA_MOUNT} && touch {DATA_MOUNT}/probe-{whose}"),
    );
    assert!(
        data.starts_with("/dev/vdb ext4"),
        "{whose}: data disk is not mounted from vdb: {data}"
    );
    sh_ok(agent, "ip link show eth0 | grep -q 'state UP'");
    sh_ok(agent, "ping -c 1 -W 3 10.200.0.1");
    // A real TCP round trip over virtio-net, not just ICMP.
    let echo = sh_ok(
        agent,
        "(printf 'k7d-pci-echo' | timeout 5 nc -l 4747 >/tmp/echo-in &) ; sleep 0.3; \
         printf 'k7d-pci-echo' | timeout 5 nc -q1 127.0.0.1 4747; sleep 0.3; cat /tmp/echo-in",
    );
    assert!(
        echo.contains("k7d-pci-echo"),
        "{whose}: TCP echo over the stack failed: {echo}"
    );
}

/// The Ubuntu node, but on the PCI bus and with a data disk.
fn build_pci_node(
    image: &common::ubuntu::NodeImage,
    disk: &VmDisk,
    data: &TestDataDisk,
    tap: k7d::network::TapDevice,
) -> Vm {
    let cmdline = pci_cmdline(tap.guest_ip());
    Vm::builder()
        .kernel(image.kernel())
        .cmdline(&cmdline)
        .memory_mb(NODE_MEMORY_MB)
        .vcpus(NODE_VCPUS)
        .vsock(true)
        .transport(Transport::Pci)
        .network(tap)
        .block_device(&disk.path, false)
        .data_disk(data.disk.clone())
        .build()
        .expect("Ubuntu node VM on virtio-pci should build")
}

/// Boot on PCI; cold snapshot + restore (`prepare_fork_source`); warm
/// fork; pause/resume the child. The bus must look and work the same
/// at every step.
#[test]
fn test_pci_boot_fork_resume() {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = k7d::network::cleanup_stale_k7_bridges();

    let image = node_image();
    let disk = VmDisk::clone_of(&image.base_image(), "pci-src");
    let data = TestDataDisk::attach(
        &TestDataDisk::unique_id("pci"),
        256 * 1024 * 1024,
        DATA_MOUNT,
    );
    let mut src_net = ClusterNetwork::create("pci").expect("source bridge");
    let tap = src_net.add_tap().expect("tap");
    let guest_ip = tap.guest_ip();

    let mut source = build_pci_node(&image, &disk, &data, tap);
    assert_eq!(source.transport(), Transport::Pci);
    source.start().expect("PCI Ubuntu node should start");
    let mut agent = connect_or_dump(&mut source, "pci boot");
    eprintln!(
        "--- pci boot serial (tail) ---\n{}",
        source
            .serial_output(Duration::from_millis(200))
            .lines()
            .filter(|l| l.contains("PCI") || l.contains("pci") || l.contains("virtio"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert_pci_guest(&mut agent, "boot");
    drop(agent);

    // Cold path: snapshot, tear down, rebuild from `MmioDeviceState`
    // (now carrying `PciFunctionState`), resume.
    source
        .prepare_fork_source()
        .expect("prepare_fork_source on a PCI guest");
    assert_eq!(source.transport(), Transport::Pci);
    let mut agent = source
        .connect_agent(Duration::from_secs(60))
        .expect("reconnect after prepare_fork_source");
    assert_pci_guest(&mut agent, "cold-restored");

    // Warm path: child built from the in-memory device state.
    let mut sources: Vec<(&mut Vm, u32)> = vec![(&mut source, 0)];
    let (_fork_net, mut forks) = fork_cluster_warm(
        &src_net,
        &mut sources,
        "pcif",
        &[None],
        &[None],
        &["pci-fork"],
    )
    .expect("warm fork of a PCI guest");
    let mut child = forks.pop().expect("one fork");
    assert_eq!(child.transport(), Transport::Pci);
    assert_eq!(child.guest_ip(), Some(guest_ip));
    child.start().expect("fork should start");
    let mut child_agent = child
        .connect_agent(Duration::from_secs(90))
        .expect("forked PCI guest should answer on vsock");
    assert_pci_guest(&mut child_agent, "warm-fork");
    // The source is still fine after the fork.
    assert_pci_guest(&mut agent, "source-after-fork");

    // Suspend / resume the child.
    drop(child_agent);
    child.pause().expect("pause fork");
    std::thread::sleep(Duration::from_millis(300));
    child.resume().expect("resume fork");
    let mut child_agent = child
        .connect_agent(Duration::from_secs(60))
        .expect("resumed PCI guest should answer on vsock");
    assert_pci_guest(&mut child_agent, "resumed");

    // Everything the test touched on the data disk is really there.
    let probes = sh_ok(&mut child_agent, &format!("ls {DATA_MOUNT}"));
    assert!(
        probes.contains("probe-boot") && probes.contains("probe-warm-fork"),
        "data disk lost writes across the rebuilds: {probes}"
    );
}

/// The builder refuses a PCI guest whose cmdline would never see the
/// bus, and one that would route INTx through an IOAPIC k7d gives no
/// PCI routing for.
#[test]
fn test_pci_rejects_pci_off_and_requires_noapic() {
    let image = node_image();
    let disk = VmDisk::clone_of(&image.base_image(), "pci-neg");
    for (cmdline, needle) in [
        (
            node_cmdline(std::net::Ipv4Addr::new(10, 200, 0, 2)),
            "pci=off",
        ),
        (
            pci_cmdline(std::net::Ipv4Addr::new(10, 200, 0, 2)).replace("noapic ", ""),
            "noapic",
        ),
    ] {
        let err = Vm::builder()
            .kernel(image.kernel())
            .cmdline(&cmdline)
            .memory_mb(512)
            .transport(Transport::Pci)
            .block_device(&disk.path, false)
            .build()
            .err()
            .map(|e| e.to_string())
            .expect("transport=pci with that cmdline must not build");
        assert!(err.contains(needle), "error does not name {needle}: {err}");
    }
}
