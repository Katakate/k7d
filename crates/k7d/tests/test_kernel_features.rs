//! Integration test: the guest kernel features Cilium and Longhorn need
//! are not merely configured, they are alive inside a booted VM.
//!
//! Two separate traps are covered here, and they are not the same trap:
//!
//! 1. `make olddefconfig` drops an option whose dependency is unmet
//!    without a word, so `config-minimal` asking for it proves nothing.
//!    `guest/kernel/build.sh` catches that at build time; the
//!    `/proc/config.gz` assertion below catches a guest built somewhere
//!    else, or a stale image the daemon is still booting.
//! 2. A configured feature is not a usable feature. `CONFIG_VXLAN=y`
//!    with no `NET_UDP_TUNNEL`, a bpffs that was never mounted, or a
//!    `.BTF` section that `strip` ate all read as "on" in config.gz and
//!    fail only where the feature is actually used. So every fiddly
//!    part gets a functional probe.
//!
//! Everything that can share a VM shares one (booting is the expensive
//! part); the fork test needs its own source.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use k7d::api::AgentClient;
use k7d::network::ClusterNetwork;
use k7d::vm::Vm;

/// Every `CONFIG_*` the referenced work adds, asserted as one list rather
/// than a hand-picked subset: picking a subset is how
/// `CONFIG_NF_TABLES_INET` stayed missing for weeks.
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
    // Cilium's agent startup, not Cilium's IPsec: the module list it
    // reads before any datapath work, and the XFRM netlink socket its
    // datapath init opens to clear policies (the referenced work,
    // CHALLENGES #100).
    "CONFIG_MODULES",
    "CONFIG_XFRM",
    "CONFIG_XFRM_USER",
    "CONFIG_CRYPTO",
    "CONFIG_CRYPTO_SHA1",
    "CONFIG_CRYPTO_USER_API_HASH",
    // BTF (CO-RE)
    "CONFIG_DEBUG_KERNEL",
    "CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT",
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
];

/// Options that must stay *off*: `DEBUG_INFO_BTF` depends on both being
/// unset, and either one silently yields a kernel with DWARF and no BTF.
const FORBIDDEN_CONFIGS: &[&str] = &["CONFIG_DEBUG_INFO_REDUCED", "CONFIG_DEBUG_INFO_SPLIT"];

/// Minimum size of `/sys/kernel/btf/vmlinux`. A kernel that generated
/// BTF for a config this size lands well above 3 MiB; 1 MiB is a floor
/// that only a truncated or synthetic blob could sneak under.
const BTF_MIN_BYTES: u64 = 1024 * 1024;

/// Where the guest sees the virtiofs share carrying `ip` and `tc`.
const TOOLS: &str = "/mnt/state";

/// `ip` and `tc` reach the guest over virtiofs, not in the initramfs:
/// alpine's iproute2 plus the musl loader and libelf/libzstd it links
/// against is 2.4 MB, which took the gzipped initramfs from 1.6 MB to
/// 3.0 MB and boot-to-agent from ~205 ms to ~221 ms against a 250 ms
/// budget. runc rides the same side-channel for the same reason.
///
/// Invoked through the loader with an explicit `--library-path` because
/// nothing in the guest's own `/lib` can resolve a musl-linked binary.
fn tool_at(root: &str, name: &str) -> String {
    format!(
        "{root}/lib/ld-musl-x86_64.so.1 \
         --library-path {root}/lib:{root}/usr/lib {root}/sbin/{name}"
    )
}

fn tool(name: &str) -> String {
    tool_at(TOOLS, name)
}

/// Build the tools image from `guest/rootfs/Dockerfile` and unpack
/// `ip`, `tc` and the libraries they resolve against into `dir`, which
/// the caller shares with the guest. `tar -ch` dereferences the `.so`
/// version symlinks so the guest gets real files under the soname the
/// loader asks for.
fn stage_guest_tools(dir: &Path) {
    let context = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("guest/rootfs");
    let build = Command::new("docker")
        .args(["build", "-q", "--", context.to_str().unwrap()])
        .output()
        .expect("docker build should run");
    assert!(
        build.status.success(),
        "docker build of {} failed: {}",
        context.display(),
        String::from_utf8_lossy(&build.stderr)
    );
    let image = String::from_utf8_lossy(&build.stdout).trim().to_string();

    let extract = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "docker run --rm --entrypoint sh {image} -c '\
             set -eu; bins=\"/sbin/ip /sbin/tc\"; \
             libs=$(for b in $bins; do \
               ldd \"$b\" | sed -n \"s|.*=> \\(/[^ ]*\\).*|\\1|p\"; \
               ldd \"$b\" | sed -n \"s|^[[:space:]]*\\(/lib/ld-musl[^ ]*\\).*|\\1|p\"; \
             done | sort -u); \
             tar -ch $bins $libs /usr/lib/tc /usr/share/iproute2' \
             | tar -x -C {}",
            dir.display()
        ))
        .stderr(Stdio::piped())
        .output()
        .expect("docker run should extract the tools image");
    assert!(
        extract.status.success(),
        "extracting iproute2 from {image} failed: {}",
        String::from_utf8_lossy(&extract.stderr)
    );
    for bin in ["sbin/ip", "sbin/tc"] {
        assert!(
            dir.join(bin).is_file(),
            "tools image produced no {bin} — did the alpine package split change? \
             (iproute2-minimal ships ip, iproute2-tc ships tc)"
        );
    }
}

fn run(agent: &mut AgentClient, cmd: &str) -> (i32, String, String) {
    let out = agent
        .exec(&["sh", "-c", cmd])
        .unwrap_or_else(|e| panic!("guest exec `{cmd}` failed to run: {e:?}"));
    (out.exit_code, out.stdout, out.stderr)
}

/// Run `cmd` in the guest and fail with its output unless it succeeds.
fn run_ok(agent: &mut AgentClient, cmd: &str) -> String {
    let (code, stdout, stderr) = run(agent, cmd);
    assert_eq!(
        code, 0,
        "guest command `{cmd}` exited {code}\nstdout: {stdout}\nstderr: {stderr}"
    );
    stdout
}

/// `/sys/kernel/btf/vmlinux` exists and is big enough to be real BTF.
/// This single assertion is the end-to-end proof of the whole
/// DWARF -> pahole -> strip pipeline: it fails if `DEBUG_INFO_BTF` was
/// dropped, if pahole was missing on the build host, or if
/// `strip --strip-all` removed the `.BTF` section from the shipped
/// vmlinux.
fn assert_btf_present(agent: &mut AgentClient, whose: &str) {
    let size = run_ok(agent, "stat -c %s /sys/kernel/btf/vmlinux");
    let size: u64 = size
        .trim()
        .parse()
        .unwrap_or_else(|e| panic!("{whose}: BTF size {size:?} is not a number: {e}"));
    assert!(
        size > BTF_MIN_BYTES,
        "{whose}: /sys/kernel/btf/vmlinux is {size} bytes, expected > {BTF_MIN_BYTES} — \
         CO-RE consumers (Cilium) would load a truncated vmlinux BTF"
    );
    eprintln!("{whose}: /sys/kernel/btf/vmlinux = {size} bytes");
}

/// One booted VM, every non-fork assertion. The VM gets a TAP so the
/// tc and VXLAN probes run against `eth0` — the interface Cilium would
/// actually attach to on a k7d node — rather than loopback.
#[test]
fn test_guest_kernel_features_alive() {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = k7d::network::cleanup_stale_k7_bridges();

    let tools = tempfile::tempdir().expect("tools dir");
    stage_guest_tools(tools.path());

    let mut net = ClusterNetwork::create("kfeat").expect("cluster bridge");
    let tap = net.add_tap().expect("tap");
    let guest_ip = tap.guest_ip();

    let mut vm = Vm::builder()
        .kernel_and_initrd()
        .memory_mb(512)
        .vsock(true)
        .network(tap)
        .virtiofs(tools.path(), TOOLS)
        .build()
        .expect("VM should build");
    vm.start().expect("VM should start");
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("agent should connect");

    // ── Config honesty ──
    let cfg = run_ok(&mut agent, "zcat /proc/config.gz");
    for want in REQUIRED_CONFIGS {
        assert!(
            cfg.lines().any(|l| l.trim() == format!("{want}=y")),
            "booted guest kernel is missing {want}=y — config-minimal asks for it, \
             so either olddefconfig dropped it or this VM is booting a stale vmlinux \
             (rebuild with `make build-guest-kernel`)"
        );
    }
    for forbidden in FORBIDDEN_CONFIGS {
        assert!(
            !cfg.lines().any(|l| l.trim() == format!("{forbidden}=y")),
            "{forbidden}=y in the booted guest — DEBUG_INFO_BTF depends on it being \
             unset, so BTF generation would have been skipped"
        );
    }

    // ── BTF ──
    assert_btf_present(&mut agent, "boot");

    // ── BPF JIT ──
    // BPF_JIT_ALWAYS_ON pins this sysctl read-only at 1. A plain
    // BPF_JIT=y guest would report the distro/kernel default here and
    // the assertion would be meaningless — that is why ALWAYS_ON is in
    // the config.
    let jit = run_ok(&mut agent, "cat /proc/sys/net/core/bpf_jit_enable");
    assert_eq!(
        jit.trim(),
        "1",
        "net.core.bpf_jit_enable is {:?}, not 1 — CONFIG_BPF_JIT_ALWAYS_ON did not take",
        jit.trim()
    );

    // ── bpffs ──
    // Read /proc/mounts rather than trusting init.sh: the mount is
    // where Cilium pins its maps, and a missing bpffs surfaces as an
    // agent that cannot survive its own restart.
    let mounts = run_ok(&mut agent, "cat /proc/mounts");
    assert!(
        mounts
            .lines()
            .any(|l| { l.split_whitespace().nth(1) == Some("/sys/fs/bpf") && l.contains(" bpf ") }),
        "no bpf filesystem mounted on /sys/fs/bpf:\n{mounts}"
    );

    // eth0 must be up before qdiscs and tunnels attach to it.
    run_ok(
        &mut agent,
        &format!("ifconfig eth0 {guest_ip} netmask 255.255.255.0 up"),
    );

    // ── tc hooks (clsact) ──
    // This is the qdisc Cilium hangs its ingress/egress programs off.
    // NET_SCH_INGRESS is what provides it, and a kernel missing it
    // fails right here with "Unknown qdisc".
    let tc = tool("tc");
    run_ok(&mut agent, &format!("{tc} qdisc add dev eth0 clsact"));
    let qdisc = run_ok(&mut agent, &format!("{tc} qdisc show dev eth0"));
    assert!(
        qdisc.contains("clsact"),
        "clsact qdisc added but not listed on eth0:\n{qdisc}"
    );
    run_ok(&mut agent, &format!("{tc} qdisc del dev eth0 clsact"));

    // ── VXLAN ──
    // Creation is the assertion: a kernel without CONFIG_VXLAN fails
    // exactly here and nowhere louder.
    let ip = tool("ip");
    run_ok(
        &mut agent,
        &format!("{ip} link add k7vx0 type vxlan id 1 dstport 4789 dev eth0"),
    );
    let vx = run_ok(&mut agent, &format!("{ip} -d link show k7vx0"));
    assert!(
        vx.contains("vxlan"),
        "k7vx0 exists but is not a vxlan device:\n{vx}"
    );
    run_ok(&mut agent, &format!("{ip} link del k7vx0"));

    // ── Policy routing ──
    // IP_MULTIPLE_TABLES at runtime, not just in config.gz: Cilium
    // puts per-endpoint rules in their own tables.
    run_ok(&mut agent, &format!("{ip} rule add pref 100 lookup 100"));
    let rules = run_ok(&mut agent, &format!("{ip} rule"));
    assert!(
        rules.lines().any(|l| l.trim_start().starts_with("100:")),
        "ip rule pref 100 added but not listed:\n{rules}"
    );
    run_ok(&mut agent, &format!("{ip} rule del pref 100 lookup 100"));

    // ── /proc/modules ──
    // CONFIG_MODULES=y is in the config for this file and nothing else:
    // the guest ships no modules, but Cilium's agent opens
    // /proc/modules before it does any datapath work and its start hook
    // is fatal if that open fails. Empty is the correct content here
    // (everything is built in); existing is the assertion.
    run_ok(&mut agent, "test -f /proc/modules");
    let loaded = run_ok(&mut agent, "cat /proc/modules");
    assert!(
        loaded.trim().is_empty(),
        "the guest loaded a kernel module, which it has no business doing:\n{loaded}"
    );

    // ── XFRM netlink ──
    // Not IPsec: an openable NETLINK_XFRM socket, which is what Cilium's
    // datapath init needs to clear xfrm policies. `ip xfrm policy` opens
    // exactly that socket, so it fails here and nowhere louder.
    let xfrm = run_ok(&mut agent, &format!("{ip} xfrm policy show"));
    assert!(
        xfrm.trim().is_empty(),
        "unexpected xfrm policies in a fresh guest:\n{xfrm}"
    );

    // ── iSCSI initiator ──
    // ISCSI_TCP registers its transport at boot with no userspace at
    // all, so this is assertable today even though iscsiadm/iscsid only
    // arrive in 24a-inc2.
    run_ok(&mut agent, "test -d /sys/class/iscsi_transport/tcp");

    // ── SCSI disk layer ──
    run_ok(&mut agent, "test -d /sys/bus/scsi");

    // ── NFS client ──
    let filesystems = run_ok(&mut agent, "cat /proc/filesystems");
    for want in ["nfs", "nfs4"] {
        assert!(
            filesystems
                .lines()
                .any(|l| l.split_whitespace().last() == Some(want)),
            "{want} missing from /proc/filesystems — Longhorn RWX volumes mount \
             the share-manager's NFSv4 export:\n{filesystems}"
        );
    }

    vm.shutdown();
    drop(net);
}

/// eBPF-relevant guest state is guest RAM, and a fork carries guest
/// RAM. Pinned as a tested fact rather than folklore: BTF still reads
/// back on the fork (the `.BTF` blob lives in the kernel image the fork
/// inherited), and a clsact qdisc attached on the source *before* the
/// fork is present on the child.
///
/// The qdisc goes on `lo`, not `eth0`: reproducing a TAP on the fork's
/// own bridge is `ClusterNetwork::fork_from`'s job and is tested there,
/// and it would only add topology to a test about memory.
#[test]
fn test_fork_carries_ebpf_state() {
    let _ = env_logger::builder().is_test(true).try_init();

    let tools = tempfile::tempdir().expect("tools dir");
    stage_guest_tools(tools.path());

    let mut source = Vm::builder()
        .kernel_and_initrd()
        .memory_mb(512)
        .vsock(true)
        .virtiofs(tools.path(), TOOLS)
        .build()
        .expect("source VM should build");
    source.start().expect("source VM should start");
    let mut agent = source
        .connect_agent(Duration::from_secs(90))
        .expect("source agent should connect");

    assert_btf_present(&mut agent, "source");
    // Copy the tools out of virtiofs into the guest's own tmpfs before
    // forking. A fork does not inherit the source's vhost-user
    // connection to virtiofsd, so any read under /mnt/state on the
    // child blocks forever — which is the whole reason the copy is
    // here and not a convenience. In tmpfs they are guest RAM, so the
    // fork gets them for the same reason it gets the qdisc.
    let ram_tools = "/tmp/k7tools";
    run_ok(
        &mut agent,
        &format!("mkdir -p {ram_tools} && cp -a {TOOLS}/lib {TOOLS}/sbin {TOOLS}/usr {ram_tools}/"),
    );

    // The agent brings `lo` up itself before it accepts a connection.
    let tc = tool_at(ram_tools, "tc");
    run_ok(&mut agent, &format!("{tc} qdisc add dev lo clsact"));

    let mut forked = source.fork("kfeat-fork").expect("fork should succeed");
    forked.start().expect("fork should start");
    let mut fork_agent = forked
        .connect_agent(Duration::from_secs(60))
        .expect("fork agent should connect");

    assert_btf_present(&mut fork_agent, "fork");
    let qdisc = run_ok(&mut fork_agent, &format!("{tc} qdisc show dev lo"));
    assert!(
        qdisc.contains("clsact"),
        "clsact qdisc attached before the fork is absent on the child — \
         eBPF-relevant guest state did not survive the fork:\n{qdisc}"
    );

    forked.shutdown();
    source.shutdown();
}
