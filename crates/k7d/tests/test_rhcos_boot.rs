//! RHCOS 4.22 on k7d's virtio-pci bus.
//!
//! The RHCOS kernel (`5.14.0-*.el9_8`) is built without
//! `CONFIG_VIRTIO_MMIO`, which is what "OpenShift 4.22 needs a PCI"
//! means. This boots the published 4.22 **live** kernel + initramfs
//! with the live rootfs appended (no disk image, no ostree, no
//! bootloader) with `transport: pci`, and reads the result off the
//! serial console: systemd reaching `multi-user.target`, and an
//! Ignition-injected unit printing `lspci`, the virtio bus, and a ping
//! to the bridge gateway. The Ignition config travels inline as a
//! `data:` URL, so nothing is fetched at boot.
//!
//! Then the same guest goes through `prepare_fork_source` (cold
//! snapshot + restore), a warm fork, and `pause`/`resume` of the child,
//! each proven live by a heartbeat unit that keeps writing to ttyS0.
//!
//! Download-gated: the three artifacts (~1.3 GiB) are fetched once
//! into `/var/cache/k7d-rhcos` and sha256-pinned to the 4.22.20
//! release (`rhcos-id` 9.8.20260715-1).
//!
//! The second test takes the wall the design note names after the
//! transport: from that live system, `coreos-installer install
//! --offline` writes the 4.22.20 metal image to a virtio-blk disk, and
//! the guest then boots **from the disk** — k7d reads the installed
//! GRUB/BLS state (`crates/k7d/src/bls.rs`), the disk's own kernel and
//! initramfs run, the initramfs pivots into the ostree deployment on
//! `/dev/vda4`, Ignition applies the installer-supplied config on first
//! boot, and the guest reboots itself. The reboot ends that VM (no
//! firmware, so a triple fault is how the kernel resets); the next VM
//! built from the same disk comes up with the firstboot stamp gone and
//! its state intact.
//!
//! Not in scope: Ignition from a cluster, installing or joining a
//! cluster (OKD from public registries when that happens — no Red Hat
//! pull secret here), running workloads.

mod common;

use std::fs;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use common::coreos::{
    assert_alive, assert_pci_probe, base64, heartbeat_unit, heartbeats, ignition, live_artifacts,
    probe_script, probe_section, tail, unit, wait_guest_exit, wait_serial, PROBE_BEGIN, PROBE_END,
};

use k7d::bls::DiskBoot;
use k7d::fork::fork_cluster_warm;
use k7d::network::ClusterNetwork;
use k7d::virtio_mmio::Transport;
use k7d::vm::Vm;

const MIRROR: &str =
    "https://mirror.openshift.com/pub/openshift-v4/x86_64/dependencies/rhcos/4.22/4.22.20";
const CACHE_DIR: &str = "/var/cache/k7d-rhcos";

/// `(file, sha256)` from the release's `sha256sum.txt`.
const KERNEL: (&str, &str) = (
    "rhcos-4.22.20-x86_64-live-kernel.x86_64",
    "98d6814ad88e646c595cd5d0705d1d26d315c527f35e4385771b4ae2254ac336",
);
const INITRAMFS: (&str, &str) = (
    "rhcos-4.22.20-x86_64-live-initramfs.x86_64.img",
    "06b0b09f2e880ff1235a188b887202e2e35aef39ac5c711ccfec41f721aca70a",
);
const ROOTFS: (&str, &str) = (
    "rhcos-4.22.20-x86_64-live-rootfs.x86_64.img",
    "7e56af38b7ee422e7ccc33007f0c28872b00b06da5bf4793ba60bd61c828a9c0",
);

/// The live rootfs is unpacked into RAM. Red Hat's floor for the live
/// environment is 4 GiB, and 4 GiB is not enough here: the kernel sizes
/// the rootfs tmpfs at 50% of the RAM *not* reserved at that moment,
/// and the 1.3 GiB appended initrd is still reserved while it unpacks,
/// so a 4 GiB guest gets a ~1.3 GiB tmpfs for a 1.1 GiB squashfs plus
/// the initramfs itself (`Initramfs unpacking failed: write error`).
const MEMORY_MB: u64 = 6144;
/// Booted from disk the rootfs is on `/dev/vda4`, not in RAM; 4 GiB,
/// Red Hat's floor, is enough there.
const DISK_BOOT_MEMORY_MB: u64 = 4096;
const VCPUS: u32 = 2;
/// Sparse; the metal image writes ~3.5 GiB of it.
const INSTALL_DISK_BYTES: u64 = 12 << 30;
/// Size of the raw "config disk" that carries the target Ignition
/// config into the live system (the kernel command line is full).
const CONFIG_DISK_BYTES: u64 = 1 << 20;
/// `coreos-installer` unpacking the osmet image onto virtio-blk.
const INSTALL_CEILING: Duration = Duration::from_secs(1200);

/// RHCOS userspace takes longer than Ubuntu's: the live initramfs
/// unpacks a 1 GiB squashfs before switching root.
const BOOT_CEILING: Duration = Duration::from_secs(300);

const INSTALL_OK: &str = "K7D-INSTALL-OK";
const INSTALL_FAIL: &str = "K7D-INSTALL-FAIL";
const BOOTS: &str = "K7D-BOOTS";

/// The live test's config: one service that prints the bus (after
/// waiting for the gateway to answer), one loop that keeps proving the
/// guest is scheduled.
fn ignition_config(gateway: Ipv4Addr) -> String {
    ignition(&[
        unit("k7d-probe.service", &probe_script(gateway, "")),
        heartbeat_unit(),
    ])
}

/// The live system's config for the install test: no probe, just
/// `coreos-installer` onto `/dev/vda` from the osmet image the live
/// rootfs carries, with the target Ignition read off the raw config
/// disk `/dev/vdb`. The kargs are the ones GRUB would have to pass for
/// this VMM (serial console, `noapic` for INTx on the PIC, a reboot
/// path that does not need ACPI) plus the static address; they land in
/// the installed BLS entry, where [`DiskBoot`] reads them back.
fn install_ignition(guest_ip: Ipv4Addr, gateway: Ipv4Addr, target_len: usize) -> String {
    let install = format!(
        "head -c {target_len} /dev/vdb > /run/target.ign; \
         coreos-installer install /dev/vda --offline --ignition-file /run/target.ign \
         --append-karg console=ttyS0,115200 --append-karg noapic --append-karg reboot=k \
         --append-karg panic=1 --append-karg net.ifnames=0 \
         --append-karg ip={guest_ip}::{gateway}:255.255.255.0:rhcos:eth0:none \
         && sync && echo {INSTALL_OK} || echo {INSTALL_FAIL} rc=$?"
    );
    ignition(&[unit("k7d-install.service", &install)])
}

/// What the installed system runs: the probe plus where it booted from
/// (`/proc/cmdline`, the ostree sysroot, a boot counter in `/var`), and
/// on the first boot a reboot of itself once the probe is out.
fn target_ignition(gateway: Ipv4Addr) -> String {
    let extra = format!(
        "echo K7D-CMDLINE $(cat /proc/cmdline); \
         echo K7D-ROOT $(findmnt -no SOURCE,FSTYPE /); \
         echo K7D-SYSROOT $(findmnt -no SOURCE,FSTYPE /sysroot); \
         ostree admin status 2>&1 | head -2; \
         b=$(cat /var/lib/k7d-boots 2>/dev/null || echo 0); b=$((b+1)); echo $b > /var/lib/k7d-boots; \
         echo {BOOTS} $b; \
         test -e /boot/ignition.firstboot && echo K7D-STAMP present || echo K7D-STAMP absent; "
    );
    let probe = format!(
        "{}; if [ $b = 1 ]; then sleep 3; echo K7D-REBOOTING; systemctl reboot; fi",
        probe_script(gateway, &extra)
    );
    ignition(&[unit("k7d-probe.service", &probe), heartbeat_unit()])
}

fn cmdline(guest_ip: Ipv4Addr, gateway: Ipv4Addr, ignition: &str) -> String {
    let ign = base64(ignition.as_bytes());
    let line = format!(
        "console=ttyS0,115200 noapic reboot=k panic=1 net.ifnames=0 \
         ignition.firstboot ignition.platform.id=metal rd.neednet=1 \
         ignition.config.url=data:;base64,{ign} \
         ip={guest_ip}::{gateway}:255.255.255.0:rhcos:eth0:none"
    );
    // x86 COMMAND_LINE_SIZE; the kernel silently truncates past it.
    assert!(line.len() < 2048, "cmdline is {} bytes", line.len());
    line
}

/// What the probe unit must have printed.
fn assert_probe(out: &str, whose: &str) {
    let probe = probe_section(out);
    eprintln!("{whose}: probe output:\n{probe}");
    for (what, needle) in [
        ("RHCOS kernel", "el9_8"),
        ("RHCOS userspace", "Red Hat Enterprise Linux CoreOS"),
    ] {
        assert!(
            probe.contains(needle),
            "{whose}: {what} missing ({needle:?})"
        );
    }
    assert_pci_probe(probe, whose);
}

#[test]
fn test_rhcos_4_22_live_boots_on_virtio_pci_and_forks() {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = k7d::network::cleanup_stale_k7_bridges();

    let (kernel, initrd) = live_artifacts(CACHE_DIR, MIRROR, KERNEL, INITRAMFS, ROOTFS);
    // A disk so the bus carries a virtio-blk function the way a node
    // would; the live system does not use it. Read-only, so the fork
    // shares it instead of needing a reflink on the disks XFS.
    let scratch = tempfile::NamedTempFile::new().expect("scratch image");
    scratch.as_file().set_len(64 << 20).expect("size scratch");

    let mut net = ClusterNetwork::create("rhcos").expect("bridge");
    let tap = net.add_tap().expect("tap");
    let guest_ip = tap.guest_ip();
    let gateway = Ipv4Addr::new(10, 200, 0, 1);

    let mut source = Vm::builder()
        .kernel(&kernel)
        .initrd(&initrd)
        .cmdline(&cmdline(guest_ip, gateway, &ignition_config(gateway)))
        .memory_mb(MEMORY_MB)
        .vcpus(VCPUS)
        .vsock(false)
        .transport(Transport::Pci)
        .block_device(scratch.path(), true)
        .network(tap)
        .build()
        .expect("RHCOS live VM should build");
    assert_eq!(source.transport(), Transport::Pci);

    let boot = Instant::now();
    source.start().expect("RHCOS live VM should start");
    wait_serial(&source, "boot", "Multi-User System", BOOT_CEILING);
    eprintln!(
        "MEASUREMENT rhcos 4.22 live boot to multi-user.target: {:?}",
        boot.elapsed()
    );
    // The probe waits for the gateway itself (NetworkManager brings
    // eth0 up from the `ip=` karg after multi-user is reached).
    let out = wait_serial(&source, "boot", PROBE_END, BOOT_CEILING);
    assert_probe(&out, "boot");
    assert_alive(&source, "boot");

    // Cold snapshot + restore through MmioDeviceState / PciFunctionState.
    source
        .prepare_fork_source()
        .expect("prepare_fork_source on RHCOS");
    assert_eq!(source.transport(), Transport::Pci);
    assert_alive(&source, "cold-restored");

    // Warm fork from in-memory state.
    let mut sources: Vec<(&mut Vm, u32)> = vec![(&mut source, 0)];
    let (_fork_net, mut forks) = fork_cluster_warm(
        &net,
        &mut sources,
        "rhcosf",
        &[None],
        &[None],
        &["rhcos-fork"],
    )
    .expect("warm fork of RHCOS");
    let mut child = forks.pop().expect("one fork");
    assert_eq!(child.transport(), Transport::Pci);
    child.start().expect("fork should start");
    assert_alive(&child, "warm-fork");
    assert_alive(&source, "source-after-fork");

    // Suspend / resume the child.
    child.pause().expect("pause fork");
    let paused_at = heartbeats(&child);
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(
        heartbeats(&child),
        paused_at,
        "a paused guest kept writing to its console"
    );
    child.resume().expect("resume fork");
    assert_alive(&child, "resumed");
}

/// What a boot *from the installed disk* must show beyond the live
/// probe: the disk's kernel ran with the BLS options, the initramfs
/// pivoted into the ostree deployment on `/dev/vda4`, and this is boot
/// number `boots` of that deployment.
fn assert_disk_probe(out: &str, whose: &str, boots: u32, firstboot: bool) {
    assert_probe(out, whose);
    let start = out.find(PROBE_BEGIN).unwrap_or(0);
    let probe = &out[start..];
    let cmdline = probe
        .lines()
        .find_map(|l| l.strip_prefix("K7D-CMDLINE "))
        .unwrap_or_else(|| panic!("{whose}: no K7D-CMDLINE line\n{probe}"));
    for (what, needle) in [
        // No `root=`: RHCOS's initramfs finds the root partition by its
        // `root` label and `ostree=` names the deployment inside it.
        ("ostree deployment karg", "ostree=/ostree/boot."),
        ("console karg from the BLS entry", "console=ttyS0,115200"),
        ("noapic from the BLS entry", "noapic"),
        ("metal platform", "ignition.platform.id=metal"),
    ] {
        assert!(
            cmdline.contains(needle),
            "{whose}: {what} missing from the guest cmdline ({needle:?}): {cmdline}"
        );
    }
    assert_eq!(
        cmdline.contains("ignition.firstboot"),
        firstboot,
        "{whose}: ignition.firstboot on the cmdline: {cmdline}"
    );
    // `/` itself is `/dev/vda4[/ostree/deploy/...]` or, with composefs,
    // an overlay over it; the physical sysroot is the unambiguous one.
    for (what, needle) in [
        (
            "sysroot is the xfs root partition",
            "K7D-SYSROOT /dev/vda4 xfs",
        ),
        ("ostree knows the deployment", "* rhcos "),
    ] {
        assert!(
            probe.contains(needle),
            "{whose}: {what} missing ({needle:?})"
        );
    }
    assert!(
        probe.contains(&format!("{BOOTS} {boots}\n"))
            || probe.contains(&format!("{BOOTS} {boots}\r")),
        "{whose}: expected boot counter {boots}"
    );
}

#[test]
fn test_rhcos_4_22_installs_to_disk_and_boots_from_it_on_virtio_pci() {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = k7d::network::cleanup_stale_k7_bridges();

    let (kernel, initrd) = live_artifacts(CACHE_DIR, MIRROR, KERNEL, INITRAMFS, ROOTFS);
    let work = tempfile::tempdir().expect("workdir");
    let disk = work.path().join("rhcos.img");
    fs::File::create(&disk)
        .expect("create disk")
        .set_len(INSTALL_DISK_BYTES)
        .expect("size disk");

    let mut net = ClusterNetwork::create("rhcosd").expect("bridge");
    let gateway = Ipv4Addr::new(10, 200, 0, 1);

    // --- 1. Live system installs to /dev/vda. ---
    let tap = net.add_tap().expect("tap");
    let guest_ip = tap.guest_ip();
    // The installed system keeps this address (it is in its BLS
    // options), so every later boot must own the same per-TAP identity:
    // the bridge's anti-spoof chain drops a guest that claims another
    // TAP's IP.
    let vm_index = tap.vm_index();
    let target = target_ignition(gateway);
    let config_disk = work.path().join("config.img");
    let mut config = target.clone().into_bytes();
    config.resize(CONFIG_DISK_BYTES as usize, 0);
    fs::write(&config_disk, &config).expect("write config disk");

    let mut live = Vm::builder()
        .kernel(&kernel)
        .initrd(&initrd)
        .cmdline(&cmdline(
            guest_ip,
            gateway,
            &install_ignition(guest_ip, gateway, target.len()),
        ))
        .memory_mb(MEMORY_MB)
        .vcpus(VCPUS)
        .vsock(false)
        .transport(Transport::Pci)
        .block_device(&disk, false)
        .block_device(&config_disk, true)
        .network(tap)
        .build()
        .expect("RHCOS live VM should build");
    let t0 = Instant::now();
    live.start().expect("RHCOS live VM should start");
    wait_serial(&live, "installer", "Multi-User System", BOOT_CEILING);
    let out = wait_serial(&live, "installer", "K7D-INSTALL-", INSTALL_CEILING);
    assert!(
        out.contains(INSTALL_OK) && !out.contains(INSTALL_FAIL),
        "installer: coreos-installer failed\n--- serial (tail) ---\n{}",
        tail(&out, 60)
    );
    eprintln!(
        "MEASUREMENT rhcos 4.22 coreos-installer --offline onto virtio-blk: {:?}",
        t0.elapsed()
    );
    drop(live);

    // --- 2. What the bootloader would do with that disk. ---
    let boot = DiskBoot::load(&disk, &work.path().join("boot1")).expect("read the installed disk");
    eprintln!(
        "installed BLS entry {} ({}): linux={} initrd={}\n  options: {}",
        boot.entry.name, boot.entry.title, boot.entry.linux, boot.entry.initrd, boot.cmdline
    );
    assert!(
        boot.firstboot,
        "coreos-installer leaves /boot/ignition.firstboot"
    );
    assert!(
        boot.entry.name.starts_with("ostree-"),
        "{}",
        boot.entry.name
    );
    assert!(boot.entry.linux.contains("el9_8"), "{}", boot.entry.linux);
    assert!(
        boot.cmdline.contains("ostree=/ostree/boot."),
        "{}",
        boot.cmdline
    );
    assert!(
        boot.cmdline.contains("ignition.firstboot "),
        "{}",
        boot.cmdline
    );
    assert!(boot.cmdline.contains(" noapic"), "{}", boot.cmdline);
    let kernel_len = fs::metadata(&boot.kernel).expect("kernel").len();
    let initrd_len = fs::metadata(&boot.initrd).expect("initrd").len();
    assert!(kernel_len > 8 << 20, "kernel is {kernel_len} bytes");
    assert!(initrd_len > 32 << 20, "initrd is {initrd_len} bytes");

    // --- 3. First boot from the disk: ostree pivot, Ignition, reboot. ---
    net.remove_entry(vm_index);
    let tap = net.add_tap_at(vm_index).expect("tap");
    let mut first = Vm::builder()
        .boot_from(&boot)
        .memory_mb(DISK_BOOT_MEMORY_MB)
        .vcpus(VCPUS)
        .vsock(false)
        .transport(Transport::Pci)
        .block_device(&disk, false)
        .network(tap)
        .build()
        .expect("installed RHCOS VM should build");
    let t1 = Instant::now();
    first.start().expect("installed RHCOS VM should start");
    wait_serial(&first, "disk-boot-1", "Multi-User System", BOOT_CEILING);
    eprintln!(
        "MEASUREMENT rhcos 4.22 first boot from disk to multi-user.target: {:?}",
        t1.elapsed()
    );
    let out = wait_serial(&first, "disk-boot-1", PROBE_END, BOOT_CEILING);
    assert_disk_probe(&out, "disk-boot-1", 1, true);
    wait_serial(
        &first,
        "disk-boot-1",
        "K7D-REBOOTING",
        Duration::from_secs(60),
    );
    wait_guest_exit(&first, "disk-boot-1", Duration::from_secs(120));
    let out = first.serial_output(Duration::from_millis(100));
    assert!(
        out.contains("reboot: Restarting system"),
        "disk-boot-1: the guest left without the kernel's reboot line\n--- serial (tail) ---\n{}",
        tail(&out, 40)
    );
    drop(first);

    // --- 4. Second boot: the stamp is gone, the state is there. ---
    let boot = DiskBoot::load(&disk, &work.path().join("boot2")).expect("re-read the disk");
    assert!(
        !boot.firstboot,
        "the OS removes /boot/ignition.firstboot after Ignition ran"
    );
    assert!(
        !boot.cmdline.contains("ignition.firstboot"),
        "{}",
        boot.cmdline
    );
    net.remove_entry(vm_index);
    let tap = net.add_tap_at(vm_index).expect("tap");
    let mut second = Vm::builder()
        .boot_from(&boot)
        .memory_mb(DISK_BOOT_MEMORY_MB)
        .vcpus(VCPUS)
        .vsock(false)
        .transport(Transport::Pci)
        .block_device(&disk, false)
        .network(tap)
        .build()
        .expect("rebooted RHCOS VM should build");
    assert_eq!(second.transport(), Transport::Pci);
    let t2 = Instant::now();
    second.start().expect("rebooted RHCOS VM should start");
    wait_serial(&second, "disk-boot-2", "Multi-User System", BOOT_CEILING);
    eprintln!(
        "MEASUREMENT rhcos 4.22 second boot from disk to multi-user.target: {:?}",
        t2.elapsed()
    );
    let out = wait_serial(&second, "disk-boot-2", PROBE_END, BOOT_CEILING);
    assert_disk_probe(&out, "disk-boot-2", 2, false);
    assert_alive(&second, "disk-boot-2");
    assert!(
        !second.guest_exited(),
        "disk-boot-2: the second boot rebooted itself too"
    );
}
