//! Shared Ubuntu bare-VM node helpers.
//!
//! Lifted out of `test_ubuntu_guest.rs` so the k3s cluster fixture does
//! not copy the image builder, per-VM reflink, cmdline, or systemd
//! assertions a second time.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use k7d::api::AgentClient;
use k7d::disks::{ensure_loopback_xfs, DataDisk, DISKS_DIR, DISKS_IMAGE, DISKS_IMAGE_SIZE};
use k7d::network::TapDevice;
use k7d::vm::Vm;

/// Guest RAM and vCPUs for a node VM, per the spec's "boot one VM
/// (2 GB, 2 vCPU)".
pub const NODE_MEMORY_MB: u64 = 2048;
pub const NODE_VCPUS: u32 = 2;

/// How long a cold Ubuntu boot may take to reach the agent. Hang
/// detection, not a budget — see `LATENCY_BUDGETS.md`.
pub const BOOT_TO_AGENT_CEILING: Duration = Duration::from_secs(120);

/// How long systemd may take to leave the `starting` state.
pub const SYSTEMD_READY_CEILING: Duration = Duration::from_secs(180);

/// Tolerated guest/host wall-clock skew (same figure as `test_clock.rs`).
pub const MAX_SKEW_SECS: i64 = 2;

/// `CONFIG_BPF_LSM=y` is not the same as BPF LSM being *active*: Ubuntu's
/// `CONFIG_LSM=` list omits `bpf`, so it must be appended on the kernel
/// command line.
pub const UBUNTU_LSM_LIST: &str = "landlock,lockdown,yama,integrity,apparmor,bpf";

pub fn workspace_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join(relative)
}

/// The image manifest `build-node-image.sh` writes, read back as the
/// single source of truth for what a test booted.
pub struct NodeImage {
    pub manifest: serde_json::Value,
}

impl NodeImage {
    pub fn field(&self, key: &str) -> String {
        self.manifest
            .get(key)
            .map(|v| match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .unwrap_or_else(|| panic!("image manifest has no {key}: {}", self.manifest))
    }

    pub fn base_image(&self) -> PathBuf {
        PathBuf::from(self.field("image"))
    }

    pub fn kernel(&self) -> PathBuf {
        PathBuf::from(self.field("kernel"))
    }
}

/// Build (or hit the cache for) the Ubuntu node image and return its
/// manifest. The builder is idempotent and content-keyed, so this is a
/// no-op after the first run on a node.
pub fn node_image() -> NodeImage {
    ensure_loopback_xfs(
        Path::new(DISKS_IMAGE),
        Path::new(DISKS_DIR),
        DISKS_IMAGE_SIZE,
    )
    .expect("reflink XFS at /var/lib/k7d/disks");

    let agent = workspace_path("target/x86_64-unknown-linux-musl/release/k7-agent");
    assert!(
        agent.is_file(),
        "static k7-agent not found at {} — run `make build-agent`",
        agent.display()
    );

    let script = workspace_path("guest/ubuntu/build-node-image.sh");
    let out = Command::new("bash")
        .arg(&script)
        .output()
        .expect("run the Ubuntu image builder");
    assert!(
        out.status.success(),
        "{} failed: {}\n{}",
        script.display(),
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let json_start = stdout
        .find('{')
        .unwrap_or_else(|| panic!("image builder printed no manifest:\n{stdout}"));
    let manifest: serde_json::Value =
        serde_json::from_str(&stdout[json_start..]).unwrap_or_else(|e| {
            panic!(
                "image manifest is not JSON ({e}):\n{}",
                &stdout[json_start..]
            )
        });
    eprintln!(
        "ubuntu image: kernel {} ({}), cloud image {} sha256 {}, k3s {}, {} masked units",
        manifest["kernel_version"],
        manifest["kernel_package_version"],
        manifest["cloud_image_build"],
        manifest["cloud_image_sha256"],
        manifest["k3s_version"],
        manifest["masked_units"].as_array().map_or(0, Vec::len)
    );
    NodeImage { manifest }
}

/// A per-VM reflink copy of the pristine base image, removed on drop.
///
/// Never boot the base image itself: a VM mounts its root read-write, so
/// booting the cached artifact would mutate the thing every later test
/// clones from.
pub struct VmDisk {
    pub path: PathBuf,
}

impl VmDisk {
    pub fn clone_of(base: &Path, tag: &str) -> Self {
        let path = Path::new(DISKS_DIR).join(format!(
            "ubuntu-vm-{tag}-{}-{}.img",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos())
        ));
        let out = Command::new("cp")
            .args(["--reflink=always", "-f"])
            .arg(base)
            .arg(&path)
            .output()
            .expect("cp --reflink=always runs");
        assert!(
            out.status.success(),
            "reflink copy of {} to {} failed: {}",
            base.display(),
            path.display(),
            String::from_utf8_lossy(&out.stderr)
        );
        Self { path }
    }
}

impl Drop for VmDisk {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The kernel command line for an Ubuntu node VM.
///
/// Deliberately a *replacement* of the minimal guest's line, not an
/// addition to it: there is no `rdinit=/init` (systemd is PID 1 off the
/// ext4 root) and no initramfs at all.
pub fn node_cmdline(guest_ip: Ipv4Addr) -> String {
    node_cmdline_ex(guest_ip, None)
}

/// Extra kernel cmdline tokens for an Ubuntu node.
///
/// `cni` is the `k7d.cni=flannel|none`. `None` on the
/// Option leaves the token off the line (absent == flannel), so the
/// path stays byte-identical.
pub struct NodeCmdlineExtra<'a> {
    pub k3s: Option<&'a str>,
    pub cni: Option<&'a str>,
}

/// Like [`node_cmdline`], with an optional `k7d.k3s=` spec
/// (`server|agent,<server-ip>,<token>`).
pub fn node_cmdline_ex(guest_ip: Ipv4Addr, k3s: Option<&str>) -> String {
    node_cmdline_with(guest_ip, NodeCmdlineExtra { k3s, cni: None })
}

/// Like [`node_cmdline_ex`], with an optional `k7d.cni=` token.
pub fn node_cmdline_with(guest_ip: Ipv4Addr, extra: NodeCmdlineExtra<'_>) -> String {
    let mut cmd = format!(
        "console=ttyS0 earlyprintk=serial,ttyS0,115200 noapic reboot=k panic=1 pci=off \
         net.ifnames=0 root=/dev/vda rootfstype=ext4 rw mitigations=off \
         clocksource=kvm-clock cpuidle_haltpoll.force=1 \
         haltpoll.guest_halt_poll_ns=200000 haltpoll.guest_halt_poll_grow_start=200000 \
         haltpoll.guest_halt_poll_allow_shrink=0 lsm={UBUNTU_LSM_LIST} \
         k7d.ip={guest_ip}/24,10.200.0.1,eth0"
    );
    if let Some(spec) = extra.k3s {
        cmd.push_str(&format!(" k7d.k3s={spec}"));
    }
    if let Some(cni) = extra.cni {
        match cni {
            "flannel" | "none" => cmd.push_str(&format!(" k7d.cni={cni}")),
            other => panic!("k7d.cni must be flannel or none, got {other:?}"),
        }
    }
    cmd
}

pub fn build_node_vm(image: &NodeImage, disk: &VmDisk, tap: TapDevice) -> Vm {
    build_node_vm_ex(image, disk, tap, None)
}

pub fn build_node_vm_ex(image: &NodeImage, disk: &VmDisk, tap: TapDevice, k3s: Option<&str>) -> Vm {
    build_node_vm_with(image, disk, tap, NodeCmdlineExtra { k3s, cni: None })
}

pub fn build_node_vm_with(
    image: &NodeImage,
    disk: &VmDisk,
    tap: TapDevice,
    extra: NodeCmdlineExtra<'_>,
) -> Vm {
    build_node_vm_with_data(image, disk, tap, extra, &[])
}

/// Like [`build_node_vm_with`], plus named persistent data disks
/// the agent mounts before k3s starts.
///
/// Declared after the root disk, so `/dev/vda` stays the root and the
/// `k7d.blk=` mounts the agent performs are the data disks.
pub fn build_node_vm_with_data(
    image: &NodeImage,
    disk: &VmDisk,
    tap: TapDevice,
    extra: NodeCmdlineExtra<'_>,
    data_disks: &[DataDisk],
) -> Vm {
    build_node_vm_sized(image, disk, tap, extra, data_disks, NodeSize::DEFAULT)
}

/// What one node VM is given.
///
/// [`NodeSize::DEFAULT`] is what the cluster fixtures measured their budgets
/// against, so it stays the default and no existing test moves. A
/// workload with its own documented floor — Longhorn asks for 4 vCPU and
/// 4 GB per storage node, where we sized for k3s alone (CHALLENGES
/// #120) — asks for what it needs instead of making every other Ubuntu
/// test pay for it.
#[derive(Clone, Copy)]
pub struct NodeSize {
    pub memory_mb: u64,
    pub vcpus: u32,
    /// Continuous time dilation factor: the node's
    /// clocks run this many times faster than wall time. 1 is stock and
    /// needs no kernel patch; anything else needs `utils/kvm-dilation`
    /// installed and fails the boot loudly if it is not.
    pub dilation: u32,
}

impl NodeSize {
    pub const DEFAULT: Self = Self {
        memory_mb: NODE_MEMORY_MB,
        vcpus: NODE_VCPUS,
        dilation: 1,
    };

    /// The same node, with its clocks dilated `n` times.
    #[must_use]
    pub const fn dilated(self, n: u32) -> Self {
        Self {
            dilation: n,
            ..self
        }
    }
}

/// [`build_node_vm_with_data`] with an explicit node size.
pub fn build_node_vm_sized(
    image: &NodeImage,
    disk: &VmDisk,
    tap: TapDevice,
    extra: NodeCmdlineExtra<'_>,
    data_disks: &[DataDisk],
    size: NodeSize,
) -> Vm {
    build_node_vm_tuned(image, disk, tap, extra, data_disks, size, |b| b)
}

/// [`build_node_vm_sized`], with `tune` applied to the builder last.
pub fn build_node_vm_tuned(
    image: &NodeImage,
    disk: &VmDisk,
    tap: TapDevice,
    extra: NodeCmdlineExtra<'_>,
    data_disks: &[DataDisk],
    size: NodeSize,
    tune: impl FnOnce(k7d::vm::VmBuilder) -> k7d::vm::VmBuilder,
) -> Vm {
    let cmdline = node_cmdline_with(tap.guest_ip(), extra);
    let mut builder = Vm::builder()
        .kernel(image.kernel())
        .cmdline(&cmdline)
        .memory_mb(size.memory_mb)
        .vcpus(size.vcpus)
        .vsock(true)
        .dilation(size.dilation)
        .network(tap)
        .block_device(&disk.path, false);
    for dd in data_disks {
        builder = builder.data_disk(dd.clone());
    }
    tune(builder).build().expect("Ubuntu node VM should build")
}

/// A named persistent data disk owned by a test: same
/// [`DataDisk`] the daemon attaches, plus the cleanup a test needs.
///
/// Retention is the primitive's contract, so nothing in the daemon
/// deletes the image — a test that made one has to, or the node
/// accumulates a `/var/lib/longhorn` per run until the age-gated sweep
/// notices.
pub struct TestDataDisk {
    pub disk: DataDisk,
}

impl TestDataDisk {
    /// Attach (creating on first use) the disk `id`, mounted in the
    /// guest at `guest_mount`.
    pub fn attach(id: &str, size_bytes: u64, guest_mount: &str) -> Self {
        let disk = DataDisk::attach(id, size_bytes, guest_mount)
            .unwrap_or_else(|e| panic!("attach data disk {id}: {e}"));
        Self { disk }
    }

    /// A run-unique id, so two concurrent runs (or a leftover image from
    /// a killed one) never share a disk by accident.
    pub fn unique_id(tag: &str) -> String {
        format!(
            "test-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos())
        )
    }
}

impl Drop for TestDataDisk {
    fn drop(&mut self) {
        if let Err(e) = DataDisk::delete(self.disk.id()) {
            eprintln!("test data disk {}: {e}", self.disk.id());
        }
    }
}

pub fn connect_or_dump(vm: &mut Vm, whose: &str) -> AgentClient {
    match vm.connect_agent(BOOT_TO_AGENT_CEILING) {
        Ok(a) => a,
        Err(e) => panic!(
            "{whose}: no agent within {BOOT_TO_AGENT_CEILING:?}: {e}\n--- serial ---\n{}",
            vm.serial_output(Duration::from_secs(1))
        ),
    }
}

pub fn host_epoch() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("host clock past the epoch")
            .as_secs(),
    )
    .expect("host epoch fits i64")
}

pub fn sh(agent: &mut AgentClient, cmd: &str) -> (i32, String, String) {
    let out = agent
        .exec(&["sh", "-c", cmd])
        .unwrap_or_else(|e| panic!("guest exec `{cmd}` failed to run: {e:?}"));
    (out.exit_code, out.stdout, out.stderr)
}

/// Strict `rp_filter` on guest eth0 drops cross-node pod sources
/// (`10.244.x` arriving on `10.200.0.0/24`). Host-ns curls use an
/// on-subnet source and pass; pod-to-pod does not (CHALLENGES.md #117).
///
/// `ip_forward` must be on for the same matrix: Cilium 1.16 reports
/// `enable-host-legacy-routing=true` on this virtio NIC, so pod-to-pod
/// is `FORWARD` not `bpf_redirect`. Host-ns is OUTPUT; same-node is
/// local. The image never sets this (CHALLENGES.md #117).
pub fn relax_guest_rp_filter(agent: &mut AgentClient, whose: &str) {
    let out = sh_ok(
        agent,
        "sysctl -w net.ipv4.ip_forward=1 \
         net.ipv4.conf.all.rp_filter=0 \
         net.ipv4.conf.default.rp_filter=0 \
         net.ipv4.conf.eth0.rp_filter=0 && \
         ip link set eth0 promisc on && \
         ip -o link show eth0",
    );
    assert!(
        out.contains("net.ipv4.ip_forward = 1"),
        "{whose}: ip_forward did not stick:\n{out}"
    );
    assert!(
        out.contains("PROMISC"),
        "{whose}: eth0 PROMISC did not stick:\n{out}"
    );
    eprintln!("{whose}: {out}");
}

pub fn sh_ok(agent: &mut AgentClient, cmd: &str) -> String {
    let (code, stdout, stderr) = sh(agent, cmd);
    assert_eq!(
        code, 0,
        "guest command `{cmd}` exited {code}\nstdout: {stdout}\nstderr: {stderr}"
    );
    stdout
}

/// Wait until systemd has finished starting, then return its state.
pub fn systemd_state(agent: &mut AgentClient, whose: &str) -> (String, Duration) {
    let start = Instant::now();
    loop {
        let (_, out, _) = sh(agent, "systemctl is-system-running 2>/dev/null || true");
        let state = out.trim().to_string();
        if !state.is_empty() && state != "starting" && state != "initializing" {
            eprintln!("{whose}: systemd is {state} after {:?}", start.elapsed());
            return (state, start.elapsed());
        }
        assert!(
            start.elapsed() < SYSTEMD_READY_CEILING,
            "{whose}: systemd still {state:?} after {SYSTEMD_READY_CEILING:?}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// The set of failed units, printed in full.
pub fn failed_units(agent: &mut AgentClient, whose: &str) -> BTreeSet<String> {
    let out = sh_ok(
        agent,
        "systemctl list-units --state=failed --no-legend --plain --no-pager || true",
    );
    let units: BTreeSet<String> = out
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|u| !u.is_empty())
        .map(ToString::to_string)
        .collect();
    if units.is_empty() {
        eprintln!("{whose}: no failed units");
    } else {
        for unit in &units {
            eprintln!("{whose}: FAILED unit {unit}");
            let (_, status, _) = sh(agent, &format!("systemctl status --no-pager -l {unit}"));
            eprintln!("{status}");
        }
    }
    units
}

/// Assert systemd came up and nothing failed. `running` or `degraded`
/// only, and `degraded` needs an empty failed set.
pub fn assert_systemd_healthy(agent: &mut AgentClient, whose: &str) -> BTreeSet<String> {
    let (state, _) = systemd_state(agent, whose);
    let failed = failed_units(agent, whose);
    assert!(
        state == "running" || state == "degraded",
        "{whose}: systemd is {state}, expected running or degraded"
    );
    assert!(
        failed.is_empty(),
        "{whose}: systemd is {state} with failed units: {failed:?}"
    );
    failed
}

/// The clock and idle probes, run on whatever VM is handed in.
pub fn assert_clock_and_idle(agent: &mut AgentClient, whose: &str) {
    let clocksource = sh_ok(
        agent,
        "cat /sys/devices/system/clocksource/clocksource0/current_clocksource",
    );
    assert_eq!(
        clocksource.trim(),
        "kvm-clock",
        "{whose}: guest is not reading the clock k7d owns"
    );

    let guest = sh_ok(agent, "date +%s")
        .trim()
        .parse::<i64>()
        .expect("guest `date +%s` prints a number");
    let skew = guest - host_epoch();
    eprintln!("{whose}: wall-clock skew {skew}s");
    assert!(
        skew.abs() <= MAX_SKEW_SECS,
        "{whose}: guest wall clock is {skew}s off the host's"
    );

    let driver = sh_ok(agent, "cat /sys/devices/system/cpu/cpuidle/current_driver");
    if driver.trim() != "haltpoll" {
        let diag = sh_ok(
            agent,
            "set -x; cat /proc/cmdline; lsmod | grep -i haltpoll; \
             modprobe -v cpuidle_haltpoll; \
             cat /sys/module/cpuidle_haltpoll/parameters/force 2>&1; \
             cat /sys/devices/system/cpu/cpuidle/current_driver \
                 /sys/devices/system/cpu/cpuidle/current_governor 2>&1; \
             dmesg | grep -i 'haltpoll\\|cpuidle\\|kvm' | tail -20; \
             systemctl status --no-pager -l systemd-modules-load.service; true",
        );
        panic!(
            "{whose}: cpuidle driver is {:?}, not haltpoll\n{diag}",
            driver.trim()
        );
    }

    let splats = sh_ok(
        agent,
        "dmesg | grep -ci 'soft lockup\\|clocksource.*unstable\\|rcu_sched detected\\|\
         BUG: soft' || true",
    );
    assert_eq!(
        splats.trim(),
        "0",
        "{whose}: the kernel complained about the clock or a stall:\n{}",
        sh_ok(agent, "dmesg | tail -40")
    );
}

/// Physical extent start blocks of `path`, from `filefrag -v`.
pub fn physical_extents(path: &Path) -> BTreeSet<u64> {
    let out = Command::new("filefrag")
        .arg("-v")
        .arg(path)
        .output()
        .expect("filefrag runs");
    assert!(
        out.status.success(),
        "filefrag -v {} failed: {}",
        path.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    let mut extents = BTreeSet::new();
    for line in text.lines() {
        let cols: Vec<&str> = line.split(':').collect();
        if cols.len() < 4 || cols[0].trim().parse::<u64>().is_err() {
            continue;
        }
        if let Some(start) = cols[2].split("..").next() {
            if let Ok(block) = start.trim().parse::<u64>() {
                extents.insert(block);
            }
        }
    }
    assert!(
        !extents.is_empty(),
        "filefrag reported no extents for {}:\n{text}",
        path.display()
    );
    extents
}

/// Does the raw image file contain `needle`?
pub fn image_contains(path: &Path, needle: &str) -> bool {
    let out = Command::new("grep")
        .args(["-c", "-a", "-F", "-m", "1", needle])
        .arg(path)
        .output()
        .expect("grep runs");
    out.status.success() && String::from_utf8_lossy(&out.stdout).trim() != "0"
}

/// Host `MemAvailable` in KiB — used to record RAM per Ubuntu node.
pub fn host_mem_available_kb() -> u64 {
    let text = std::fs::read_to_string("/proc/meminfo").expect("/proc/meminfo");
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemAvailable:") {
            return rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .expect("MemAvailable is a number");
        }
    }
    panic!("/proc/meminfo has no MemAvailable");
}
