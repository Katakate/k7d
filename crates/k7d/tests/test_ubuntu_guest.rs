//! Integration tests: a stock Ubuntu 24.04 userspace on a stock Ubuntu
//! kernel, booted as a bare k7d `create_vm` VM.
//!
//! The bet this file exists to check is that the VMM is
//! workload-agnostic — that only the guest *contents* change between the
//! 250 ms minimal guest and a distro node. So nothing here is a new VMM
//! feature except bzImage loading: direct kernel boot, ext4 root on
//! virtio-blk, vsock, a TAP on a bridge, and a warm fork are the same
//! code paths `test_erofs.rs` and `test_cluster_fork.rs` already drive.
//!
//! Requires KVM, /dev/vhost-vsock, /dev/net/tun, root, network egress
//! (apt + one HTTPS fetch from the guest), and `/var/lib/k7d/disks` on
//! the reflink XFS. The Ubuntu image is built on first use by
//! `guest/ubuntu/build-node-image.sh` and content-cached after that.

mod common;

use std::collections::BTreeSet;
use std::process::Command;
use std::time::{Duration, Instant};

use k7d::api::AgentClient;
use k7d::fork::fork_cluster_warm;
use k7d::latency::FORK_UBUNTU_NODE_1VM;
use k7d::network::ClusterNetwork;

use common::ubuntu::{
    assert_clock_and_idle, assert_systemd_healthy, build_node_vm, failed_units, image_contains,
    node_image, physical_extents, sh, sh_ok, systemd_state, VmDisk, BOOT_TO_AGENT_CEILING,
    NODE_MEMORY_MB, UBUNTU_LSM_LIST,
};
use k7d::vm::Vm;

/// The Cilium/Longhorn set from `test_kernel_features.rs::REQUIRED_CONFIGS`
/// plus the Tetragon set, checked against the *distro* kernel's config so
/// the CNI and Tetragon suites do not discover a flavour gap late.
///
/// The minimal guest's copy of this list demands `=y` because it has no
/// modules at all. A distro kernel ships most of it as modules, so `=m`
/// counts here only when the `.ko` is actually present in the image —
/// `linux-image-virtual` installs the base module set and *not*
/// `linux-modules-extra`, which is exactly the gap this check is for.
const REQUIRED_CONFIGS: &[&str] = &[
    // Cilium eBPF datapath
    "CONFIG_BPF_JIT",
    "CONFIG_BPF_JIT_ALWAYS_ON",
    "CONFIG_NET_SCHED",
    "CONFIG_NET_CLS_ACT",
    "CONFIG_NET_SCH_INGRESS",
    "CONFIG_NET_CLS_BPF",
    "CONFIG_PERF_EVENTS",
    "CONFIG_IP_ADVANCED_ROUTER",
    "CONFIG_IP_MULTIPLE_TABLES",
    "CONFIG_IPV6_MULTIPLE_TABLES",
    "CONFIG_VXLAN",
    "CONFIG_MODULES",
    "CONFIG_XFRM",
    "CONFIG_XFRM_USER",
    "CONFIG_CRYPTO",
    "CONFIG_CRYPTO_SHA1",
    "CONFIG_CRYPTO_USER_API_HASH",
    // BTF (CO-RE)
    "CONFIG_DEBUG_KERNEL",
    "CONFIG_DEBUG_INFO_BTF",
    // Longhorn v1 / generic CSI storage
    "CONFIG_SCSI",
    "CONFIG_BLK_DEV_SD",
    "CONFIG_SCSI_ISCSI_ATTRS",
    "CONFIG_ISCSI_TCP",
    "CONFIG_NFS_FS",
    "CONFIG_NFS_V4",
    "CONFIG_NFS_V4_1",
    "CONFIG_NFS_V4_2",
    // Tetragon: kprobes, syscall tracepoints, BPF LSM
    "CONFIG_KPROBES",
    "CONFIG_KPROBES_ON_FTRACE",
    "CONFIG_FTRACE_SYSCALLS",
    "CONFIG_SECURITY",
    "CONFIG_BPF_LSM",
];

/// One booted Ubuntu node: bzImage boot, systemd, the static IP the
/// daemon assigned, NAT egress through the bridge, the flavour's config
/// as it will matter to the CNI and Tetragon suites, and the clock/idle probes.
#[test]
fn test_ubuntu_guest_boots_to_agent_with_systemd_network_and_clock() {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = k7d::network::cleanup_stale_k7_bridges();

    let image = node_image();
    let disk = VmDisk::clone_of(&image.base_image(), "boot");
    let mut net = ClusterNetwork::create("ubu1").expect("cluster bridge");
    let tap = net.add_tap().expect("tap");
    let guest_ip = tap.guest_ip();

    let mut vm = build_node_vm(&image, &disk, tap);
    let boot_start = Instant::now();
    vm.start().expect("Ubuntu node VM should start");
    let mut agent = match vm.connect_agent(BOOT_TO_AGENT_CEILING) {
        Ok(a) => a,
        Err(e) => panic!(
            "no agent within {BOOT_TO_AGENT_CEILING:?}: {e}\n--- serial ---\n{}",
            vm.serial_output(Duration::from_secs(1))
        ),
    };
    let boot_to_agent = boot_start.elapsed();
    eprintln!("MEASUREMENT ubuntu boot-to-agent: {boot_to_agent:?}");

    // ── systemd ──
    let (state, _) = systemd_state(&mut agent, "boot");
    eprintln!(
        "MEASUREMENT ubuntu boot-to-systemd-{state}: {:?}",
        boot_start.elapsed()
    );
    let failed = failed_units(&mut agent, "boot");
    assert!(
        state == "running" || state == "degraded",
        "systemd is {state}, expected running or degraded"
    );
    assert!(
        failed.is_empty(),
        "systemd is {state} with failed units: {failed:?}"
    );
    assert_eq!(sh_ok(&mut agent, "cat /proc/1/comm").trim(), "systemd");

    // The whole point of the ext4-root path: no initramfs was loaded and
    // the kernel still found its root, because virtio-mmio/virtio-blk/ext4
    // are built into this flavour (recorded in the manifest as
    // `boots_without_initrd`).
    assert_eq!(image.field("boots_without_initrd"), "true");
    assert!(
        vm.initrd_path().is_none(),
        "this VM must boot with no initrd at all"
    );
    let root_mount = sh_ok(&mut agent, "findmnt -no SOURCE,FSTYPE /");
    assert!(
        root_mount.contains("/dev/vda") && root_mount.contains("ext4"),
        "root is not ext4 on /dev/vda: {root_mount}"
    );

    // ── static IP from the command line ──
    let addr = sh_ok(&mut agent, "ip -4 -o addr show dev eth0");
    assert!(
        addr.contains(&format!("{guest_ip}/24")),
        "eth0 does not carry the cmdline address {guest_ip}/24: {addr}"
    );
    let route = sh_ok(&mut agent, "ip -4 route show default");
    assert!(
        route.contains("10.200.0.1"),
        "no default route via the bridge: {route}"
    );

    // ── NAT egress through the bridge ──
    // One HTTPS fetch, name resolution included: this is the capability
    // the sidecar substrate never had (no pull path, airgap tars) and the
    // reason `apt`/`ctr pull` will just work on a cluster node.
    let (code, status, stderr) = sh(
        &mut agent,
        "curl -4 -sS --max-time 45 -o /dev/null -w '%{http_code}' \
         https://cloud-images.ubuntu.com/",
    );
    assert_eq!(
        code, 0,
        "HTTPS fetch through the bridge failed: {status} {stderr}"
    );
    assert_eq!(status.trim(), "200", "unexpected HTTP status: {status}");
    eprintln!("boot: NAT egress OK (HTTP 200 over TLS, DNS resolved)");

    // ── flavour config check ──
    assert_kernel_flavour_covers_cilium_and_tetragon(&mut agent);

    // ── clock + idle ──
    assert_clock_and_idle(&mut agent, "boot");

    vm.shutdown();
    drop(net);
}

/// The flavour check: every config the later rungs need is either built
/// in or present as a module in *this* image, and BPF LSM is actually
/// active rather than merely compiled.
fn assert_kernel_flavour_covers_cilium_and_tetragon(agent: &mut AgentClient) {
    let kver = sh_ok(agent, "uname -r").trim().to_string();
    let config = sh_ok(agent, &format!("cat /boot/config-{kver}"));
    let modules = sh_ok(
        agent,
        &format!("find /lib/modules/{kver} -name '*.ko*' -printf '%f\\n'"),
    );
    let module_names: BTreeSet<String> = modules
        .lines()
        .map(|m| {
            m.trim()
                .trim_end_matches(".zst")
                .trim_end_matches(".ko")
                .replace('-', "_")
        })
        .collect();

    let mut findings = Vec::new();
    for want in REQUIRED_CONFIGS {
        let y = config.lines().any(|l| l.trim() == format!("{want}=y"));
        let m = config.lines().any(|l| l.trim() == format!("{want}=m"));
        assert!(
            y || m,
            "{want} is neither =y nor =m in {kver} — linux-image-virtual cannot carry \
             the Ubuntu ladder; the remedy is a different flavour, not a workaround"
        );
        if m {
            findings.push(format!("{want}=m"));
        }
    }
    eprintln!(
        "FINDING flavour {kver}: {} of {} required options are modules (the image ships \
         {} modules): {}",
        findings.len(),
        REQUIRED_CONFIGS.len(),
        module_names.len(),
        findings.join(" ")
    );

    // The modules the later rungs load by name must be *in this image*:
    // `linux-image-virtual` omits `linux-modules-extra`, so "=m in the
    // config" is not the same as "shipped". Finding this now is the whole
    // point of the check.
    // `cpuidle_haltpoll` is the one that actually bit: it ships in
    // linux-modules-*-extra, so a plain `linux-image-virtual` image has no
    // haltpoll driver at all and the guest idles on `menu` — which is why
    // the image installs linux-image-extra-virtual (CHALLENGES #103).
    for module in [
        "vxlan",
        "cls_bpf",
        "sch_ingress",
        "iscsi_tcp",
        "nfsv4",
        "xfrm_user",
        "cpuidle_haltpoll",
        "rdma_rxe",
    ] {
        assert!(
            module_names.contains(module),
            "module {module} is missing from the image's module set in {kver} — \
             the CNI, Tetragon and CSI suites would fail to load it; the remedy is the \
             linux-image-extra-virtual package in build-node-image.sh"
        );
    }

    // BTF, end to end: Cilium and Tetragon are CO-RE consumers.
    let btf = sh_ok(agent, "stat -c %s /sys/kernel/btf/vmlinux")
        .trim()
        .parse::<u64>()
        .expect("BTF size is a number");
    assert!(
        btf > 1024 * 1024,
        "/sys/kernel/btf/vmlinux is only {btf} bytes"
    );
    eprintln!("flavour: /sys/kernel/btf/vmlinux = {btf} bytes");

    // BPF LSM activation — the recorded gap and its fix. Ubuntu's
    // CONFIG_LSM= omits `bpf`, so the cmdline appends it; without that
    // Tetragon's BPF-LSM sensors have nowhere to attach even though
    // CONFIG_BPF_LSM=y.
    assert!(
        !config
            .lines()
            .any(|l| l.starts_with("CONFIG_LSM=") && l.contains("bpf")),
        "CONFIG_LSM= now ships bpf; the lsm= cmdline override is redundant and this \
         finding needs re-recording"
    );
    let active = sh_ok(agent, "cat /sys/kernel/security/lsm");
    assert!(
        active.trim().split(',').any(|l| l == "bpf"),
        "bpf is not in the active LSM list ({active}) despite lsm={UBUNTU_LSM_LIST} — \
         Tetragon's BPF-LSM sensors would have nothing to attach to"
    );
    eprintln!("FINDING flavour {kver}: active LSMs {}", active.trim());

    // Cgroup v2 unified, which k3s and Tetragon both assume.
    let cgroup = sh_ok(agent, "stat -fc %T /sys/fs/cgroup");
    assert_eq!(
        cgroup.trim(),
        "cgroup2fs",
        "/sys/fs/cgroup is not the unified hierarchy"
    );
}

/// Warm-fork a booted Ubuntu node: the child answers on vsock, its root
/// disk is a reflink of the source's (shared extents, different paths),
/// the two diverge on disk in both directions, and systemd on the child
/// has no newly-failed unit.
#[test]
fn test_ubuntu_guest_warm_fork() {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = k7d::network::cleanup_stale_k7_bridges();

    let image = node_image();
    let disk = VmDisk::clone_of(&image.base_image(), "fork-src");
    let mut src_net = ClusterNetwork::create("ubu2").expect("source bridge");
    let tap = src_net.add_tap().expect("tap");
    let guest_ip = tap.guest_ip();
    let source_disk = disk.path.clone();

    let mut source = build_node_vm(&image, &disk, tap);
    source.start().expect("source VM should start");
    let mut agent = match source.connect_agent(BOOT_TO_AGENT_CEILING) {
        Ok(a) => a,
        Err(e) => panic!(
            "no agent within {BOOT_TO_AGENT_CEILING:?}: {e}\n--- serial ---\n{}",
            source.serial_output(Duration::from_secs(1))
        ),
    };
    let source_failed = assert_systemd_healthy(&mut agent, "source");

    // Pre-fork state, on disk and synced: the child must inherit it.
    sh_ok(
        &mut agent,
        "echo k7d-ubuntu-shared-before-fork > /root/shared && sync",
    );

    source
        .prepare_fork_source()
        .expect("prepare_fork_source on an Ubuntu guest");
    let mut agent = source
        .connect_agent(Duration::from_secs(60))
        .expect("reconnect after prepare_fork_source");

    let mut sources: Vec<(&mut Vm, u32)> = vec![(&mut source, 0)];
    let fork_start = Instant::now();
    let (fork_net, mut forks) = fork_cluster_warm(
        &src_net,
        &mut sources,
        "ubu2f",
        &[None],
        &[None],
        &["ubuntu-fork"],
    )
    .expect("warm fork of an Ubuntu node");
    let fork_latency = fork_start.elapsed();
    eprintln!("MEASUREMENT ubuntu warm fork (1 VM, {NODE_MEMORY_MB} MB): {fork_latency:?}");
    assert!(
        fork_latency < FORK_UBUNTU_NODE_1VM,
        "warm fork of a {NODE_MEMORY_MB} MB Ubuntu node took {fork_latency:?}, over the \
         {FORK_UBUNTU_NODE_1VM:?} budget"
    );

    let mut child = forks.pop().expect("one fork");
    assert_eq!(
        child.guest_ip(),
        Some(guest_ip),
        "the fork must keep the source's guest IP on its own bridge"
    );

    // ── the child answers on vsock ──
    child.start().expect("fork should start");
    let mut child_agent = child
        .connect_agent(Duration::from_secs(90))
        .expect("forked Ubuntu node should answer on vsock");
    assert_eq!(
        sh_ok(&mut child_agent, "cat /root/shared").trim(),
        "k7d-ubuntu-shared-before-fork",
        "the child did not inherit the source's pre-fork disk state"
    );

    // ── the child's root disk is a reflink, not a copy ──
    let child_disk = child
        .block_devices()
        .first()
        .map(|cfg| cfg.host_path.clone())
        .expect("fork has a root disk");
    assert_ne!(
        child_disk, source_disk,
        "the fork must have its own image path"
    );
    let shared: Vec<u64> = physical_extents(&source_disk)
        .intersection(&physical_extents(&child_disk))
        .copied()
        .collect();
    assert!(
        !shared.is_empty(),
        "source {} and fork {} share no physical extents — the disk was copied, not \
         reflinked",
        source_disk.display(),
        child_disk.display()
    );
    eprintln!(
        "fork: root disk {} shares {} extents with the source's {}",
        child_disk.display(),
        shared.len(),
        source_disk.display()
    );

    // ── two-way divergence, on disk ──
    // `sync` then read the raw images from the host: two guests' page
    // caches would diverge even if both wrote the same file, so the
    // proof has to be in the bytes.
    const SRC_MARKER: &str = "k7d-ubuntu-only-on-the-source-9f2a";
    const CHILD_MARKER: &str = "k7d-ubuntu-only-on-the-child-4b7c";
    sh_ok(
        &mut agent,
        &format!("echo {SRC_MARKER} > /root/side && sync"),
    );
    sh_ok(
        &mut child_agent,
        &format!("echo {CHILD_MARKER} > /root/side && sync"),
    );
    assert_eq!(
        sh_ok(&mut agent, "cat /root/side").trim(),
        SRC_MARKER,
        "the child's write reached the source"
    );
    assert_eq!(
        sh_ok(&mut child_agent, "cat /root/side").trim(),
        CHILD_MARKER,
        "the source's write reached the child"
    );
    assert!(
        image_contains(&source_disk, SRC_MARKER),
        "the source's own write is not in its image"
    );
    assert!(
        image_contains(&child_disk, CHILD_MARKER),
        "the child's own write is not in its image"
    );
    assert!(
        !image_contains(&source_disk, CHILD_MARKER),
        "the child's write landed in the source's image — the reflink is not CoW"
    );
    assert!(
        !image_contains(&child_disk, SRC_MARKER),
        "the source's write landed in the child's image — the reflink is not CoW"
    );

    // ── the child's systemd is no worse than the source's ──
    let child_failed = failed_units(&mut child_agent, "fork");
    let newly_failed: Vec<&String> = child_failed.difference(&source_failed).collect();
    assert!(
        newly_failed.is_empty(),
        "units failed on the child that were fine on the source: {newly_failed:?} — \
         something time-triggered fired on resume"
    );
    let (state, _) = systemd_state(&mut child_agent, "fork");
    assert!(
        state == "running" || state == "degraded",
        "the child's systemd is {state}"
    );

    // ── clock and idle on the child, not just the boot ──
    assert_clock_and_idle(&mut child_agent, "fork");

    // The source is undisturbed by its own fork.
    assert_eq!(
        sh_ok(&mut agent, "echo source-alive").trim(),
        "source-alive"
    );

    child.shutdown();
    drop(fork_net);
    source.shutdown();
    drop(src_net);
}

/// Fork-of-fork on a real Ubuntu guest (CHALLENGES.md #130).
///
/// The child of a warm fork runs on a reflinked root disk owned by its
/// `Vm`. Preparing that child as a fork source used to drop the husk
/// that owned the disk, deleting it under the live guest — the
/// grandchild's FICLONE then failed with `IO error: No such file or
/// directory`, capping every Ubuntu tree at depth 1 (the MCP agent
/// runs hit exactly this). Asserts the grandchild boots, answers on
/// vsock, inherits child-only disk state, and that the child's image
/// still exists on the host.
#[test]
fn test_ubuntu_guest_fork_of_fork() {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = k7d::network::cleanup_stale_k7_bridges();

    let image = node_image();
    let disk = VmDisk::clone_of(&image.base_image(), "fof-src");
    let mut src_net = ClusterNetwork::create("ubff").expect("source bridge");
    let tap = src_net.add_tap().expect("tap");

    let mut source = build_node_vm(&image, &disk, tap);
    source.start().expect("source VM should start");
    let mut agent = match source.connect_agent(BOOT_TO_AGENT_CEILING) {
        Ok(a) => a,
        Err(e) => panic!(
            "no agent within {BOOT_TO_AGENT_CEILING:?}: {e}\n--- serial ---\n{}",
            source.serial_output(Duration::from_secs(1))
        ),
    };
    sh_ok(&mut agent, "echo from-root > /root/lineage && sync");

    source.prepare_fork_source().expect("prepare source");
    let _agent = source
        .connect_agent(Duration::from_secs(60))
        .expect("reconnect source after prepare");

    let mut sources: Vec<(&mut Vm, u32)> = vec![(&mut source, 0)];
    let (child_net, mut forks) = fork_cluster_warm(
        &src_net,
        &mut sources,
        "ubffc",
        &[None],
        &[None],
        &["ubuntu-fof-child"],
    )
    .expect("warm fork of the Ubuntu source");
    let mut child = forks.pop().expect("one child");
    child.start().expect("child should start");
    let mut child_agent = child
        .connect_agent(Duration::from_secs(90))
        .expect("child answers on vsock");
    sh_ok(&mut child_agent, "echo from-child >> /root/lineage && sync");
    let child_disk = child
        .block_devices()
        .first()
        .map(|cfg| cfg.host_path.clone())
        .expect("child has a root disk");

    // The heart of the regression: prepare the CHILD as a fork source
    // (husk swap) and fork from it. Pre-fix, the swap deleted
    // `child_disk` and this fork failed ENOENT.
    child
        .prepare_fork_source()
        .expect("prepare a fork child as fork source");
    assert!(
        child_disk.exists(),
        "preparing the child deleted its root disk {} out from under it",
        child_disk.display()
    );
    let _child_agent = child
        .connect_agent(Duration::from_secs(60))
        .expect("reconnect child after prepare");

    let mut child_sources: Vec<(&mut Vm, u32)> = vec![(&mut child, 0)];
    let (grand_net, mut grand_forks) = fork_cluster_warm(
        &child_net,
        &mut child_sources,
        "ubffg",
        &[None],
        &[None],
        &["ubuntu-fof-grand"],
    )
    .expect("fork-of-fork of an Ubuntu guest (CHALLENGES #130)");
    let mut grand = grand_forks.pop().expect("one grandchild");
    grand.start().expect("grandchild should start");
    let mut grand_agent = grand
        .connect_agent(Duration::from_secs(90))
        .expect("grandchild answers on vsock");
    assert_eq!(
        sh_ok(&mut grand_agent, "cat /root/lineage")
            .split_whitespace()
            .collect::<Vec<_>>(),
        vec!["from-root", "from-child"],
        "the grandchild must inherit the child's disk state, not root's"
    );

    grand.shutdown();
    drop(grand_net);
    child.shutdown();
    drop(child_net);
    source.shutdown();
    drop(src_net);
}

/// ~11 MiB public object; no registry auth.
const EGRESS_GITHUB: &str =
    "https://github.com/opencontainers/runc/releases/download/v1.2.5/runc.amd64";
/// Cilium operator layer (~26 MiB) — the same registry the Cilium pull starves on.
const EGRESS_QUAY_BLOB: &str = "https://quay.io/v2/cilium/operator-generic/blobs/sha256:1eb39da6a769c638269f4448e1fe6bad052bf21386de43288c42f0cbc950d7f0";
const EGRESS_QUAY_AUTH: &str =
    "https://quay.io/v2/auth?service=quay.io&scope=repository:cilium/operator-generic:pull";
/// Floor well above the #117 collapse (~50 KB/s) and well below host line rate.
const EGRESS_MIN_BPS: f64 = 1_000_000.0;

/// Guest NAT egress through the k7 bridge must be megabytes/s, not the
/// ~50 KB/s collapse in CHALLENGES.md #117. Measures one Ubuntu guest
/// against the host on a quay blob and a non-quay object.
#[test]
fn test_ubuntu_guest_egress_throughput() {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = k7d::network::cleanup_stale_k7_bridges();

    let host_github = host_curl_speed(EGRESS_GITHUB, &[]);
    let token = host_quay_token();
    let auth = format!("Authorization: Bearer {token}");
    let host_quay = host_curl_speed(EGRESS_QUAY_BLOB, &[&auth]);
    eprintln!(
        "MEASUREMENT host egress github={:.0} B/s ({} bytes) quay={:.0} B/s ({} bytes)",
        host_github.1, host_github.2, host_quay.1, host_quay.2
    );

    let image = node_image();
    let disk = VmDisk::clone_of(&image.base_image(), "egress");
    let mut net = ClusterNetwork::create("ubeg").expect("cluster bridge");
    let tap = net.add_tap().expect("tap");

    let mut vm = build_node_vm(&image, &disk, tap);
    vm.start().expect("Ubuntu node VM should start");
    let mut agent = match vm.connect_agent(BOOT_TO_AGENT_CEILING) {
        Ok(a) => a,
        Err(e) => panic!(
            "no agent within {BOOT_TO_AGENT_CEILING:?}: {e}\n--- serial ---\n{}",
            vm.serial_output(Duration::from_secs(1))
        ),
    };
    assert_systemd_healthy(&mut agent, "egress");

    let link = sh_ok(&mut agent, "ip -o link show dev eth0");
    eprintln!("egress guest eth0: {}", link.trim());
    let mtu = sh_ok(&mut agent, "cat /sys/class/net/eth0/mtu");
    assert_eq!(mtu.trim(), "1500", "guest eth0 MTU: {mtu}");

    let ping_gw = sh(
        &mut agent,
        "ping -4 -c 1 -M do -s 1472 -W 2 10.200.0.1 >/dev/null && echo ok || echo fail",
    );
    assert_eq!(
        ping_gw.1.trim(),
        "ok",
        "1472-byte DF ping to the bridge failed: stdout={} stderr={}",
        ping_gw.1,
        ping_gw.2
    );

    let guest_github = guest_curl_speed(&mut agent, EGRESS_GITHUB, None);
    let guest_quay = guest_curl_speed(&mut agent, EGRESS_QUAY_BLOB, Some(token.as_str()));
    eprintln!(
        "MEASUREMENT guest egress github={:.0} B/s ({} bytes) quay={:.0} B/s ({} bytes)",
        guest_github.1, guest_github.2, guest_quay.1, guest_quay.2
    );

    assert!(
        guest_github.1 >= EGRESS_MIN_BPS,
        "guest github download {:.0} B/s is below {EGRESS_MIN_BPS} B/s \
         (host was {:.0} B/s) — NAT path is still the #117 collapse",
        guest_github.1,
        host_github.1
    );
    assert!(
        guest_quay.1 >= EGRESS_MIN_BPS,
        "guest quay download {:.0} B/s is below {EGRESS_MIN_BPS} B/s \
         (host was {:.0} B/s) — NAT path is still the #117 collapse",
        guest_quay.1,
        host_quay.1
    );

    vm.shutdown();
    drop(net);
}

/// Guest-to-guest TCP on the k7 bridge (no NAT, no Cilium). Isolates
/// virtio-net L2 from the #117 NAT path and from in-guest BPF.
#[test]
fn test_ubuntu_guest_bridge_tcp() {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = k7d::network::cleanup_stale_k7_bridges();

    let image = node_image();
    let disk_a = VmDisk::clone_of(&image.base_image(), "brtcp-a");
    let disk_b = VmDisk::clone_of(&image.base_image(), "brtcp-b");
    let mut net = ClusterNetwork::create("ubtcp").expect("cluster bridge");
    let tap_a = net.add_tap().expect("tap a");
    let tap_b = net.add_tap().expect("tap b");
    let ip_a = tap_a.guest_ip();
    let ip_b = tap_b.guest_ip();

    let mut vm_a = build_node_vm(&image, &disk_a, tap_a);
    let mut vm_b = build_node_vm(&image, &disk_b, tap_b);
    vm_a.start().expect("guest A");
    vm_b.start().expect("guest B");
    let mut a = match vm_a.connect_agent(BOOT_TO_AGENT_CEILING) {
        Ok(ag) => ag,
        Err(e) => panic!("guest A agent: {e}"),
    };
    let mut b = match vm_b.connect_agent(BOOT_TO_AGENT_CEILING) {
        Ok(ag) => ag,
        Err(e) => panic!("guest B agent: {e}"),
    };
    assert_systemd_healthy(&mut a, "brtcp-a");
    assert_systemd_healthy(&mut b, "brtcp-b");

    let ping = sh(
        &mut a,
        &format!("ping -4 -c 2 -W 2 {ip_b} >/dev/null && echo PING_OK || echo PING_FAIL"),
    );
    assert_eq!(
        ping.1.trim(),
        "PING_OK",
        "guest A ({ip_a}) cannot ping guest B ({ip_b}): stdout={} stderr={}",
        ping.1,
        ping.2
    );

    sh_ok(
        &mut b,
        "mkdir -p /tmp/www && echo BRIDGE_TCP_OK > /tmp/www/index.html && \
         nohup python3 -m http.server 8080 --bind 0.0.0.0 --directory /tmp/www \
         >/tmp/http.log 2>&1 & sleep 0.3",
    );
    let curl = sh(
        &mut a,
        &format!("curl -4 -sS --max-time 5 http://{ip_b}:8080/ || echo CURL_FAIL"),
    );
    assert!(
        curl.1.contains("BRIDGE_TCP_OK"),
        "guest A ({ip_a}) TCP to guest B ({ip_b}:8080) failed: stdout={} stderr={}",
        curl.1,
        curl.2
    );
    eprintln!("MEASUREMENT guest-to-guest bridge TCP {ip_a} → {ip_b}:8080 ok");

    vm_a.shutdown();
    vm_b.shutdown();
    drop(net);
}

/// A non-agent uid cannot create `AF_VSOCK`, while the agent still
/// serves a round trip.
///
/// Enforcement is AppArmor: `k7-deny-vsock` on `/usr/bin/python3*`
/// (`allow all` + `deny network vsock`); `k7-agent` on the agent
/// binary allows vsock. k3s units attach the named deny profile;
/// CRI AppArmor is off so pods inherit it (CHALLENGES #166).
/// Boundary is a non-agent uid running a profiled workload
/// interpreter. `SystemCallFilter` cannot match `socket()` by family;
/// `RestrictAddressFamilies` returns EAFNOSUPPORT.
#[test]
fn test_ubuntu_vsock_denied_to_non_agent() {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = k7d::network::cleanup_stale_k7_bridges();

    let image = node_image();
    let disk = VmDisk::clone_of(&image.base_image(), "vsockdeny");
    let mut net = ClusterNetwork::create("ubvsd").expect("cluster bridge");
    let tap = net.add_tap().expect("tap");

    let mut vm = build_node_vm(&image, &disk, tap);
    vm.start().expect("Ubuntu node VM should start");
    let mut agent = match vm.connect_agent(BOOT_TO_AGENT_CEILING) {
        Ok(a) => a,
        Err(e) => panic!(
            "no agent within {BOOT_TO_AGENT_CEILING:?}: {e}\n--- serial ---\n{}",
            vm.serial_output(Duration::from_secs(1))
        ),
    };
    assert_systemd_healthy(&mut agent, "vsockdeny");

    let pong = agent.ping().expect("agent ping before deny probe");
    assert_eq!(pong.version, "0.1.0");
    assert_eq!(sh_ok(&mut agent, "echo AGENT_OK").trim(), "AGENT_OK");

    let profiles = sh_ok(&mut agent, "cat /sys/kernel/security/apparmor/profiles");
    assert!(
        profiles.contains("k7-agent (enforce)"),
        "k7-agent AppArmor profile not enforcing:\n{profiles}"
    );
    assert!(
        profiles.contains("k7-deny-vsock (enforce)"),
        "k7-deny-vsock AppArmor profile not enforcing:\n{profiles}"
    );

    // Fail loud if this image lost python3 — the probe is not a new
    // package, it is the same interpreter test_ubuntu_guest_bridge_tcp
    // already uses.
    let af = sh_ok(
        &mut agent,
        "python3 -c 'import socket; print(int(socket.AF_VSOCK))'",
    );
    assert_eq!(af.trim(), "40", "python3 AF_VSOCK is not 40: {af}");

    const PROBE: &str = "\
#!/usr/bin/python3
import socket, os, sys
aa = open('/proc/self/attr/current').read().strip()
print('aa=%s uid=%d' % (aa, os.getuid()))
try:
    socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    print('opened')
    sys.exit(0)
except OSError as e:
    print('errno=%d' % e.errno)
    sys.exit(1)
";
    agent
        .write_file("/usr/local/share/k7-vsock-probe.py", PROBE.as_bytes())
        .expect("write vsock probe");
    sh_ok(&mut agent, "chmod 0755 /usr/local/share/k7-vsock-probe.py");

    // `allow all` inherit-execs, so a bare agent.exec of python3 stays
    // in k7-agent and can open vsock. aa-exec change_profiles into
    // k7-deny-vsock (the same named profile k3s units attach).
    // setpriv then drops to nobody without dbus.
    let (code, stdout, stderr) = sh(
        &mut agent,
        "aa-exec -p k7-deny-vsock -- \
         setpriv --reuid=nobody --regid=nogroup --clear-groups \
         /usr/bin/python3 /usr/local/share/k7-vsock-probe.py",
    );
    if code == 0 {
        let diag = sh_ok(
            &mut agent,
            "cat /sys/kernel/security/apparmor/profiles; \
             aa-status 2>/dev/null | head -40 || true; \
             dmesg | grep -i apparmor | tail -20 || true",
        );
        panic!(
            "nobody opened AF_VSOCK (wanted EPERM/EACCES): \
             stdout={stdout} stderr={stderr}\n{diag}"
        );
    }
    let errno_ok = stdout.contains("errno=1") || stdout.contains("errno=13");
    assert!(
        errno_ok,
        "expected EPERM (1) or EACCES (13) for nobody AF_VSOCK, got \
         exit={code} stdout={stdout} stderr={stderr}"
    );
    assert!(
        stdout.contains("uid=65534"),
        "probe did not run as nobody (65534): stdout={stdout} stderr={stderr}"
    );
    assert!(
        stdout.contains("k7-deny-vsock"),
        "probe was not in k7-deny-vsock (agent ix inherit?): \
         stdout={stdout} stderr={stderr}"
    );

    let pong2 = agent.ping().expect("agent ping after deny probe");
    assert_eq!(pong2.version, "0.1.0");
    assert_eq!(
        sh_ok(&mut agent, "echo AGENT_STILL_OK").trim(),
        "AGENT_STILL_OK"
    );

    vm.shutdown();
    drop(net);
}

fn host_quay_token() -> String {
    let out = Command::new("curl")
        .args(["-4", "-sS", "--max-time", "20", EGRESS_QUAY_AUTH])
        .output()
        .expect("curl quay auth");
    assert!(
        out.status.success(),
        "quay auth failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("quay auth JSON");
    v["token"].as_str().expect("quay auth token").to_string()
}

/// `(http_code, speed_download B/s, size_download)`.
fn host_curl_speed(url: &str, headers: &[&str]) -> (u16, f64, u64) {
    let mut cmd = Command::new("curl");
    cmd.args([
        "-4",
        "-sS",
        "--max-time",
        "60",
        "-L",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code} %{speed_download} %{size_download}",
        url,
    ]);
    for h in headers {
        cmd.args(["-H", h]);
    }
    let out = cmd.output().expect("host curl");
    assert!(
        out.status.success(),
        "host curl {url} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    parse_curl_speed(url, &String::from_utf8_lossy(&out.stdout))
}

fn guest_curl_speed(agent: &mut AgentClient, url: &str, bearer: Option<&str>) -> (u16, f64, u64) {
    let hdr = bearer
        .map(|t| format!("-H 'Authorization: Bearer {t}'"))
        .unwrap_or_default();
    let cmd = format!(
        "curl -4 -sS --max-time 60 -L -o /dev/null {hdr} \
         -w '%{{http_code}} %{{speed_download}} %{{size_download}}' '{url}'"
    );
    let (code, stdout, stderr) = sh(agent, &cmd);
    assert_eq!(code, 0, "guest curl {url} exited {code}: {stdout} {stderr}");
    parse_curl_speed(url, &stdout)
}

fn parse_curl_speed(url: &str, stdout: &str) -> (u16, f64, u64) {
    let parts: Vec<&str> = stdout.split_whitespace().collect();
    assert_eq!(parts.len(), 3, "curl -w for {url} printed {stdout:?}");
    let http: u16 = parts[0].parse().expect("http_code");
    let speed: f64 = parts[1].parse().expect("speed_download");
    let size: u64 = parts[2].parse().expect("size_download");
    assert_eq!(http, 200, "{url} HTTP {http}");
    assert!(size > 1_000_000, "{url} only downloaded {size} bytes");
    (http, speed, size)
}
