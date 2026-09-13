//! Integration test: the guest's iSCSI and NFSv4 *userspace*, proven
//! against real host-side services.
//!
//! A cheaper test could assert `test -d /sys/class/iscsi_transport/tcp`
//! and stop there: `ISCSI_TCP=y` registers a transport at boot with no
//! userspace at all. That proves the module initialised — not that a
//! session can be established, not that a LUN becomes a block device,
//! and not that a filesystem survives on it. Longhorn v1 attaches every
//! volume to the node as an iSCSI target and serves RWX volumes over
//! NFSv4 from its share-manager, so those two round trips are the
//! actual contract, and they are what this file drives end to end.
//!
//! Host side, created and destroyed per test: a `tgt` (`tgtd`/`tgtadm`)
//! file-backed LUN and an `exportfs -o` NFSv4 export, both scoped to
//! the bridge gateway `10.200.0.1` and the `10.200.0.0/24` subnet. `tgt`
//! is a *userspace* target, so unlike LIO/configfs it needs nothing
//! from the host kernel. Both are torn down by a `Drop` guard: a leaked
//! target, export, or logged-in session outlives a panicking test and
//! leaves a `/dev/sd*` plus a kernel thread behind on a node other
//! suites share.
//!
//! Guest side: the whole alpine root from
//! `guest/rootfs/Dockerfile.nodeusr`, packed with `build_erofs_image`
//! and attached read-only on virtio-blk, entered with `chroot`. Not the
//! initramfs (every VM pays its decompression, and we measured
//! 2.4 MB of iproute2 costing ~16 ms against a 250 ms budget) and not
//! virtiofs (a warm fork does not inherit its source's virtiofsd
//! connection, so reads on the fork hang).
//!
//! Requires KVM, `/dev/vhost-vsock`, TUN, docker, `mkfs.erofs`, and
//! `tgtd`/`exportfs`+`nfsd` on the host. Missing host services fail
//! loudly — `your node provisioning` installs them.

use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use k7d::api::AgentClient;
use k7d::erofs::{build_erofs_image, DEFAULT_CACHE_DIR};
use k7d::latency::VM_BOOT_TO_AGENT;
use k7d::network::ClusterNetwork;
use k7d::vm::Vm;

/// Where the erofs userspace is mounted inside the guest, and the root
/// every `chroot` below enters.
const NODEUSR: &str = "/run/k7d/nodeusr";

/// The host end of the k7 bridge — `network.rs`'s `GUEST_GATEWAY`, and
/// the only address a guest can reach a host-side service on.
const GATEWAY: &str = "10.200.0.1";

/// The bridge subnet, used to scope both the iSCSI initiator ACL and
/// the NFS export. Never `0.0.0.0`: the node is shared.
const SUBNET: &str = "10.200.0.0/24";

/// Standard iSCSI port. Free on the node because the packaged `tgt`
/// service is disabled by `your node provisioning` — it binds
/// `0.0.0.0:3260`, which is exactly the exposure this test avoids.
const ISCSI_PORT: u16 = 3260;

/// Marker written through the iSCSI LUN and through the NFS export.
const MARKER: &str = "k7d-storage-round-trip";

/// How long the slowest asynchronous step (`sd` binding a LUN) is given.
const SETTLE: Duration = Duration::from_secs(30);

/// Boots per configuration in the boot-cost test. Enough that one
/// unlucky sample cannot decide the result, few enough to stay cheap
/// (the whole comparison runs in under 10 s).
const BOOT_SAMPLES: usize = 9;

/// What attaching the nodeusr erofs image is allowed to add to
/// boot-to-agent: one more virtio-mmio device to probe and one more
/// `mount` before the agent listens.
///
/// Two of the instrument's steps, and that is the honest floor for this
/// allowance. `Vm::connect_agent` polls the serial buffer for the
/// agent's listen marker every 10 ms, so boot-to-agent is *quantized*
/// to 10 ms — measured samples land on ~236/246/256 ms and nowhere in
/// between, and a sub-tick cost reads as either 0 or 10 ms depending on
/// where in the poll interval it happens to fall. Observed minimum
/// deltas across runs were 0.3, 10 and 10.5 ms, so the real cost is
/// under one step; 20 ms is two steps of headroom over that, and still
/// catches anything that adds a genuine third.
const NODEUSR_BOOT_OVERHEAD: Duration = Duration::from_millis(20);

// ─────────────────────────── host helpers ───────────────────────────

/// Run a host command, returning `(exit_code, stdout, stderr)`.
fn host(program: &str, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "host command `{program} {}` failed to spawn: {e}",
                args.join(" ")
            )
        });
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// Run a host command and fail with its output unless it succeeds.
fn host_ok(program: &str, args: &[&str]) -> String {
    let (code, stdout, stderr) = host(program, args);
    assert_eq!(
        code,
        0,
        "host command `{program} {}` exited {code}\nstdout: {stdout}\nstderr: {stderr}",
        args.join(" ")
    );
    stdout
}

/// Assert a host-side precondition binary exists, naming the fix. The
/// spec is explicit that a missing service fails rather than skips: a
/// skipped storage test is indistinguishable from a passing one.
fn require_host_tool(name: &str) {
    let found = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {name}"))
        .stdout(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    assert!(
        found,
        "{name} is missing on this node — install it with \
         `bash your node provisioning` (or \
         `apt-get install -y tgt nfs-kernel-server`). This test must not skip."
    );
}

/// Poll a host-side condition until it holds, or fail naming it.
fn wait_for_host(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + SETTLE;
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(200));
    }
}

// ───────────────────────── host iSCSI target ────────────────────────

/// A `tgtd` instance plus one file-backed target, both owned by the
/// test and both removed by [`Drop`].
///
/// Its own daemon rather than the node's: the packaged `tgt.service`
/// binds `0.0.0.0:3260`, and this one binds the bridge gateway only.
/// The mgmt channel needs a control-port index distinct from the
/// default `0`, otherwise `tgtadm` talks to whichever `tgtd` got there
/// first.
struct IscsiTarget {
    daemon: Child,
    control_port: u16,
    iqn: String,
    backing_file: PathBuf,
    /// Owns the temp dir holding the backing file and the daemon log.
    dir: tempfile::TempDir,
}

impl IscsiTarget {
    /// Start `tgtd` on `GATEWAY:ISCSI_PORT` and give it one LUN backed
    /// by a fresh sparse file, ACL'd to the bridge subnet.
    fn create(name: &str) -> Self {
        require_host_tool("tgtd");
        require_host_tool("tgtadm");

        let dir = tempfile::tempdir().expect("temp dir for the LUN backing file");
        let backing_file = dir.path().join("lun.img");
        let f = std::fs::File::create(&backing_file).expect("create LUN backing file");
        f.set_len(64 * 1024 * 1024)
            .expect("size the LUN backing file");
        drop(f);

        // tgtadm rejects a control port above ~1023; derive one from the
        // pid so two suites on one node never share a mgmt channel.
        let control_port = 100 + u16::try_from(std::process::id() % 900).expect("pid mod fits u16");
        let iqn = format!("iqn.2026-08.org.katakate:{name}");

        let log = std::fs::File::create(dir.path().join("tgtd.log")).expect("tgtd log");
        let daemon = Command::new("tgtd")
            .args([
                "-f",
                "--iscsi",
                &format!("portal={GATEWAY}:{ISCSI_PORT}"),
                "-C",
                &control_port.to_string(),
            ])
            .stdout(Stdio::from(log.try_clone().expect("clone tgtd log fd")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("spawn tgtd");

        let target = Self {
            daemon,
            control_port,
            iqn,
            backing_file,
            dir,
        };

        // The mgmt socket appears a beat after the fork, and everything
        // below goes through it, so wait for it rather than racing.
        let deadline = Instant::now() + SETTLE;
        while target.tgtadm(&["--op", "show", "--mode", "target"]).0 != 0 {
            assert!(
                Instant::now() < deadline,
                "tgtd never answered on control port {control_port} — log:\n{}",
                target.daemon_log()
            );
            std::thread::sleep(Duration::from_millis(100));
        }

        target.tgtadm_ok(&[
            "--op",
            "new",
            "--mode",
            "target",
            "--tid",
            "1",
            "-T",
            &target.iqn,
        ]);
        target.tgtadm_ok(&[
            "--op",
            "new",
            "--mode",
            "logicalunit",
            "--tid",
            "1",
            "--lun",
            "1",
            "-b",
            target.backing_file.to_str().expect("utf-8 backing path"),
        ]);
        // Scope the initiator ACL to the bridge subnet, not ALL.
        target.tgtadm_ok(&[
            "--op", "bind", "--mode", "target", "--tid", "1", "-I", SUBNET,
        ]);
        target
    }

    fn tgtadm(&self, args: &[&str]) -> (i32, String, String) {
        let port = self.control_port.to_string();
        let mut full = vec!["--control-port", port.as_str(), "--lld", "iscsi"];
        full.extend_from_slice(args);
        host("tgtadm", &full)
    }

    fn tgtadm_ok(&self, args: &[&str]) -> String {
        let (code, stdout, stderr) = self.tgtadm(args);
        assert_eq!(
            code,
            0,
            "tgtadm {} exited {code}\nstdout: {stdout}\nstderr: {stderr}\ntgtd log:\n{}",
            args.join(" "),
            self.daemon_log()
        );
        stdout
    }

    fn daemon_log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("tgtd.log")).unwrap_or_default()
    }

    /// Connections `tgtd` currently has, as reported by the target
    /// itself: the host's view of the session, independent of the
    /// guest's `iscsiadm -m session`.
    fn connection_count(&self) -> usize {
        self.tgtadm_ok(&["--op", "show", "--mode", "target"])
            .lines()
            .filter(|l| l.trim_start().starts_with("Connection:"))
            .count()
    }
}

impl Drop for IscsiTarget {
    fn drop(&mut self) {
        // --force detaches any still-logged-in initiator; without it a
        // guest that panicked mid-session pins the target forever.
        let _ = self.tgtadm(&[
            "--op", "delete", "--mode", "target", "--tid", "1", "--force",
        ]);
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
    }
}

// ───────────────────────── host NFSv4 export ────────────────────────

/// One NFSv4 export made with `exportfs -o`, removed by [`Drop`].
///
/// Deliberately not `/etc/exports`: the node is shared and that file is
/// not ours. NFSv4 is single-port on 2049, which is also why this needs
/// no `rpcbind`/`statd`.
struct NfsExport {
    dir: tempfile::TempDir,
    spec: String,
}

impl NfsExport {
    fn create() -> Self {
        require_host_tool("exportfs");
        assert!(
            Path::new("/proc/fs/nfsd/versions").exists(),
            "nfsd is not running on this node (no /proc/fs/nfsd/versions) — \
             install and start it with `bash your node provisioning` \
             (or `apt-get install -y nfs-kernel-server`). This test must not skip."
        );

        let dir = tempfile::tempdir().expect("temp dir for the NFS export");
        // The server traverses the export as the mapped user; 0o777
        // keeps that from tripping over the temp dir's 0o700.
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777))
                .expect("widen export dir permissions");
        }

        // fsid is explicit: an auto-derived one comes from the backing
        // device UUID, so two exports off the same filesystem collide.
        let opts = format!(
            "rw,sync,no_subtree_check,no_root_squash,fsid={}",
            7000 + std::process::id() % 1000
        );
        let spec = format!("{SUBNET}:{}", dir.path().display());
        host_ok("exportfs", &["-o", &opts, &spec]);
        Self { dir, spec }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }
}

impl Drop for NfsExport {
    fn drop(&mut self) {
        let _ = host("exportfs", &["-u", &self.spec]);
    }
}

// ──────────────────────── guest-side helpers ────────────────────────

/// Run a shell command in the guest, returning `(code, stdout, stderr)`.
fn guest(agent: &mut AgentClient, cmd: &str) -> (i32, String, String) {
    let out = agent
        .exec(&["sh", "-c", cmd])
        .unwrap_or_else(|e| panic!("guest exec `{cmd}` failed to run: {e:?}"));
    (out.exit_code, out.stdout, out.stderr)
}

/// Run a shell command in the guest and fail with its output unless it
/// succeeds.
fn guest_ok(agent: &mut AgentClient, cmd: &str) -> String {
    let (code, stdout, stderr) = guest(agent, cmd);
    assert_eq!(
        code, 0,
        "guest command `{cmd}` exited {code}\nstdout: {stdout}\nstderr: {stderr}"
    );
    stdout
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Wrap `cmd` so it runs inside the erofs userspace chroot. The
/// initramfs busybox has no `chroot` symlink, only the applet, and PATH
/// is set explicitly rather than inherited so the alpine `sbin`
/// directories are always searched.
fn chroot_cmd(cmd: &str) -> String {
    format!(
        "busybox chroot {NODEUSR} /bin/sh -c {}",
        shell_quote(&format!("export PATH=/usr/sbin:/usr/bin:/sbin:/bin; {cmd}"))
    )
}

fn in_chroot(agent: &mut AgentClient, cmd: &str) -> (i32, String, String) {
    guest(agent, &chroot_cmd(cmd))
}

fn in_chroot_ok(agent: &mut AgentClient, cmd: &str) -> String {
    guest_ok(agent, &chroot_cmd(cmd))
}

/// Poll a guest predicate until it matches `want`, or fail naming what
/// it was waiting for. Used for the two events that lag the command
/// that triggers them: `sd` binding a LUN, and the device going away.
fn wait_for_guest(agent: &mut AgentClient, cmd: &str, want: bool, what: &str) {
    let deadline = Instant::now() + SETTLE;
    loop {
        if (guest(agent, cmd).0 == 0) == want {
            return;
        }
        if Instant::now() >= deadline {
            let state = guest(agent, "ls -l /dev/sd* /sys/class/scsi_disk/ 2>&1").1;
            panic!(
                "timed out after {SETTLE:?} waiting for {what} (`{cmd}` to {}) — \
                 SCSI state:\n{state}",
                if want { "succeed" } else { "fail" }
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

// ───────────────────── the erofs userspace image ────────────────────

fn workspace_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join(relative)
}

/// Build `guest/rootfs/Dockerfile.nodeusr`, export the whole container
/// filesystem, and pack it into a read-only erofs image.
///
/// Keyed by the built image ID, so the ~65 MB export and `mkfs.erofs`
/// happen once per Dockerfile change rather than once per run.
fn nodeusr_erofs_image() -> PathBuf {
    let context = workspace_path("guest/rootfs");
    let dockerfile = context.join("Dockerfile.nodeusr");
    let build = Command::new("docker")
        .args([
            "build",
            "-q",
            "-f",
            dockerfile.to_str().expect("utf-8 path"),
            "--",
            context.to_str().expect("utf-8 path"),
        ])
        .output()
        .expect("docker build should run");
    assert!(
        build.status.success(),
        "docker build of Dockerfile.nodeusr failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );
    let image = String::from_utf8_lossy(&build.stdout).trim().to_string();
    assert!(!image.is_empty(), "docker build -q printed no image ID");

    let key: String = image
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let img = PathBuf::from(DEFAULT_CACHE_DIR).join(format!("nodeusr-{key}.erofs"));
    if img.exists() {
        return img;
    }

    let staging = tempfile::tempdir().expect("staging dir for the exported root");
    let export = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "set -eu; cid=$(docker create {image}); \
             trap 'docker rm -f \"$cid\" >/dev/null 2>&1' EXIT; \
             docker export \"$cid\" | tar -x -C {}",
            staging.path().display()
        ))
        .output()
        .expect("docker export should run");
    assert!(
        export.status.success(),
        "exporting {image} failed: {}",
        String::from_utf8_lossy(&export.stderr)
    );
    for bin in [
        "usr/sbin/iscsid",
        "usr/sbin/iscsiadm",
        "sbin/mount.nfs4",
        "sbin/mkfs.ext4",
    ] {
        assert!(
            staging.path().join(bin).exists(),
            "the exported nodeusr root has no {bin} — did the alpine package \
             split change?"
        );
    }

    build_erofs_image(staging.path(), &img).expect("pack the nodeusr root into erofs");
    img
}

/// Bring the erofs root up as a usable chroot and start `iscsid` in it.
///
/// erofs is read-only and `iscsid` writes: it reads `/etc/iscsi`, keeps
/// its node database under `/var/lib/iscsi`, and locks in `/run`. Its
/// failure mode when any of those is unwritable is an unhelpful early
/// exit, not "read-only filesystem", so every writable path is
/// tmpfs-mounted over the image before the daemon ever runs.
/// `/etc/iscsi` is seeded from the copy the image keeps outside the
/// mount point, which would otherwise be hidden by the tmpfs.
///
/// The initiator IQN is generated per VM: `iscsid` refuses to start
/// without one, and two guests sharing an IQN against one target
/// produces confusing session behaviour rather than a clean error.
fn enter_nodeusr(agent: &mut AgentClient, iqn: &str) {
    guest_ok(
        agent,
        &format!(
            "set -e
             mount -t tmpfs tmpfs {NODEUSR}/run
             mkdir -p {NODEUSR}/run/lock
             mount -t tmpfs tmpfs {NODEUSR}/tmp
             mount -t tmpfs tmpfs {NODEUSR}/var/lib/iscsi
             mount -t tmpfs tmpfs {NODEUSR}/etc/iscsi
             cp -a {NODEUSR}/usr/share/k7-iscsi/. {NODEUSR}/etc/iscsi/
             mount -t tmpfs tmpfs {NODEUSR}/mnt
             mkdir -p {NODEUSR}/mnt/iscsi {NODEUSR}/mnt/nfs
             mount -o bind /proc {NODEUSR}/proc
             mount -o bind /sys {NODEUSR}/sys
             mount -o bind /dev {NODEUSR}/dev
             echo 'InitiatorName={iqn}' > {NODEUSR}/etc/iscsi/initiatorname.iscsi"
        ),
    );

    in_chroot_ok(agent, "iscsid");
    // Started is not the same as still running: iscsid daemonises and
    // then exits silently on a config or permission problem, so
    // re-check after it has had a moment to do that.
    std::thread::sleep(Duration::from_millis(500));
    let pid = in_chroot_ok(agent, "pidof iscsid");
    assert!(
        !pid.trim().is_empty(),
        "iscsid started but did not stay up — its exit is silent, so check \
         that /etc/iscsi, /var/lib/iscsi and /run are writable in the chroot"
    );
}

/// Boot a VM with a TAP on the cluster bridge and, when `img` is set,
/// the erofs userspace on virtio-blk. Gives `eth0` its address and
/// returns the VM, its agent, the guest IP, and boot-to-agent.
fn boot_storage_vm(
    net: &mut ClusterNetwork,
    img: Option<&Path>,
) -> (Vm, AgentClient, Ipv4Addr, Duration) {
    let tap = net.add_tap().expect("tap on the cluster bridge");
    let guest_ip = tap.guest_ip();
    let builder = Vm::builder()
        .kernel_and_initrd()
        .memory_mb(512)
        .vsock(true)
        .network(tap);
    let builder = match img {
        Some(img) => builder.block_device_mounted(img, true, NODEUSR, "erofs"),
        None => builder,
    };
    let mut vm = builder
        .build()
        .expect("VM with the nodeusr erofs image should build");

    let started = Instant::now();
    vm.start().expect("VM should start");
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("agent should connect");
    let boot = started.elapsed();

    guest_ok(
        &mut agent,
        &format!("ifconfig eth0 {guest_ip} netmask 255.255.255.0 up"),
    );
    (vm, agent, guest_ip, boot)
}

// ──────────────────────────── the tests ─────────────────────────────

/// The full iSCSI round trip and the NFSv4 one, on a single VM —
/// booting is the expensive part.
///
/// Each step is a distinct failure class and each gets its own
/// assertion: a session that establishes but never binds `sd`, an `sd`
/// device that appears but takes no filesystem, and a filesystem whose
/// writes never leave the guest all look identical from `--login`'s
/// exit code.
#[test]
#[allow(clippy::too_many_lines)]
fn test_iscsi_and_nfs_round_trips() {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = k7d::network::cleanup_stale_k7_bridges();

    let img = nodeusr_erofs_image();

    // The bridge must exist before tgtd binds the gateway address, and
    // its INPUT ACCEPT rule is what lets guest→host traffic reach these
    // services at all: `network.rs`'s FORWARD/MASQUERADE rules are
    // about guest *egress* and do nothing for a connection terminating
    // on the host itself.
    let mut net = ClusterNetwork::create("k7stor").expect("cluster bridge");
    let target = IscsiTarget::create("lun0");
    let export = NfsExport::create();
    let export_path = export.path().to_path_buf();

    let (mut vm, mut agent, guest_ip, boot) = boot_storage_vm(&mut net, Some(&img));
    eprintln!("boot-to-agent with the nodeusr erofs attached: {boot:?}");

    let iqn = format!("iqn.2026-08.org.katakate:guest-{guest_ip}");
    enter_nodeusr(&mut agent, &iqn);

    // ── iSCSI: discovery ──
    let portal = format!("{GATEWAY}:{ISCSI_PORT}");
    let discovered = in_chroot_ok(
        &mut agent,
        &format!("iscsiadm -m discovery -t sendtargets -p {portal}"),
    );
    assert!(
        discovered.contains(&target.iqn),
        "sendtargets discovery did not list {} — if this timed out rather than \
         being refused, suspect the host INPUT chain before suspecting tgtd:\n{discovered}",
        target.iqn
    );

    // ── iSCSI: login ──
    in_chroot_ok(
        &mut agent,
        &format!("iscsiadm -m node -T {} -p {portal} --login", target.iqn),
    );
    let session = in_chroot_ok(&mut agent, "iscsiadm -m session");
    assert!(
        session.contains(&target.iqn),
        "logged in but `iscsiadm -m session` does not show the target:\n{session}"
    );
    wait_for_host("the host-side target to see the connection", || {
        target.connection_count() == 1
    });

    // ── iSCSI: a LUN is not a disk until `sd` binds it ──
    // devtmpfs is mounted on /dev by init.sh, so the node appears by
    // itself with no udev — but not the instant --login returns.
    wait_for_guest(
        &mut agent,
        "ls /dev/sd? >/dev/null 2>&1",
        true,
        "the LUN to be bound by sd and appear under /dev",
    );
    let dev = guest_ok(&mut agent, "ls /dev/sd?").trim().to_string();
    assert!(
        dev.starts_with("/dev/sd"),
        "unexpected device list: {dev:?}"
    );
    let disks = guest_ok(&mut agent, "ls /sys/class/scsi_disk/");
    assert!(
        !disks.trim().is_empty(),
        "{dev} exists but /sys/class/scsi_disk is empty"
    );

    // ── iSCSI: a filesystem survives the round trip ──
    in_chroot_ok(&mut agent, &format!("mkfs.ext4 -F -q {dev}"));
    guest_ok(&mut agent, &format!("mount -t ext4 {dev} /mnt"));
    guest_ok(&mut agent, &format!("echo {MARKER} > /mnt/marker"));
    guest_ok(&mut agent, "umount /mnt");
    guest_ok(&mut agent, &format!("mount -t ext4 {dev} /mnt"));
    let read_back = guest_ok(&mut agent, "cat /mnt/marker");
    assert_eq!(
        read_back.trim(),
        MARKER,
        "the marker did not survive unmount + remount of the iSCSI LUN"
    );
    guest_ok(&mut agent, "umount /mnt");

    // ── iSCSI: logout releases the device ──
    in_chroot_ok(
        &mut agent,
        &format!("iscsiadm -m node -T {} -p {portal} --logout", target.iqn),
    );
    wait_for_guest(
        &mut agent,
        "ls /dev/sd? >/dev/null 2>&1",
        false,
        "the block device to disappear after logout",
    );
    wait_for_host("the host-side connection to close after logout", || {
        target.connection_count() == 0
    });

    // ── iSCSI: the writes actually left the guest ──
    // Guest page cache would satisfy every assertion above. The host's
    // backing file carrying an ext4 signature cannot be faked from
    // inside the VM.
    let blkid = host_ok(
        "blkid",
        &[
            "-o",
            "value",
            "-s",
            "TYPE",
            target.backing_file.to_str().expect("utf-8 backing path"),
        ],
    );
    assert_eq!(
        blkid.trim(),
        "ext4",
        "the LUN's host-side backing file is not ext4 — the guest's writes \
         never left it"
    );

    // ── NFSv4 ──
    // mount.nfs4 is invoked directly rather than through mount(8): it is
    // the helper mount(8) would exec anyway, and calling it removes any
    // question of which mount binary the chroot resolved.
    let mount_src = format!("{GATEWAY}:{}", export_path.display());
    in_chroot_ok(
        &mut agent,
        &format!("mount.nfs4 {mount_src} /mnt/nfs -o vers=4"),
    );
    let mounts = guest_ok(&mut agent, &format!("grep {NODEUSR}/mnt/nfs /proc/mounts"));
    assert!(
        mounts.contains("nfs4"),
        "mounted, but not as nfs4:\n{mounts}"
    );

    // Guest writes, host reads.
    in_chroot_ok(
        &mut agent,
        &format!("echo {MARKER}-from-guest > /mnt/nfs/from-guest"),
    );
    let on_host = std::fs::read_to_string(export_path.join("from-guest"))
        .expect("the guest's NFS write should be a real file on the host");
    assert_eq!(on_host.trim(), format!("{MARKER}-from-guest"));

    // Host writes, guest reads.
    let mut f = std::fs::File::create(export_path.join("from-host"))
        .expect("write into the export on the host");
    writeln!(f, "{MARKER}-from-host").expect("write the host marker");
    drop(f);
    let in_guest = in_chroot_ok(&mut agent, "cat /mnt/nfs/from-host");
    assert_eq!(in_guest.trim(), format!("{MARKER}-from-host"));

    in_chroot_ok(&mut agent, "umount /mnt/nfs");
    assert_ne!(
        in_chroot(&mut agent, "grep /mnt/nfs /proc/mounts").0,
        0,
        "the NFS mount is still present after umount"
    );

    vm.shutdown();
    drop(export);
    drop(target);
    drop(net);

    // ── Leak check ──
    // The guards above ran; this asserts they were enough. A leaked
    // export or target outlives the suite on a node others share.
    let exports = host_ok("exportfs", &["-s"]);
    assert!(
        !exports.contains(&export_path.display().to_string()),
        "an export from this test survived its guard:\n{exports}"
    );
    wait_for_host("the test's tgtd to release the iSCSI port", || {
        host(
            "sh",
            &["-c", &format!("ss -ltn | grep -q ':{ISCSI_PORT} '")],
        )
        .0 != 0
    });
}

/// Boot once and throw the VM away, returning boot-to-agent.
fn sample_boot(net: &mut ClusterNetwork, img: Option<&Path>) -> Duration {
    let (mut vm, agent, _ip, boot) = boot_storage_vm(net, img);
    drop(agent);
    vm.shutdown();
    boot
}

/// Boot both arms `BOOT_SAMPLES` times each, **interleaved**, and
/// return `(median pair delta, min without, min with)`.
///
/// Interleaved because the arms are compared to each other: a node that
/// gets busy halfway through would otherwise land entirely on whichever
/// arm ran second and read as that arm's cost. Pair-delta median, not
/// `min(with) - min(without)`: a single lucky baseline sample (225 ms
/// vs a 235 ms cluster) made a 10 ms real overhead look like 20.3 ms
/// after `test_inner_k3s` on a hot node.
fn compare_boot(net: &mut ClusterNetwork, img: &Path) -> (Duration, Duration, Duration) {
    let mut without = Vec::with_capacity(BOOT_SAMPLES);
    let mut with = Vec::with_capacity(BOOT_SAMPLES);
    for _ in 0..BOOT_SAMPLES {
        without.push(sample_boot(net, None));
        with.push(sample_boot(net, Some(img)));
    }
    eprintln!("boot-to-agent samples without the image: {without:?}");
    eprintln!("boot-to-agent samples with the image:    {with:?}");
    let mut deltas: Vec<Duration> = without
        .iter()
        .zip(with.iter())
        .map(|(wo, w)| w.saturating_sub(*wo))
        .collect();
    deltas.sort();
    let median_delta = deltas[deltas.len() / 2];
    (
        median_delta,
        without.into_iter().min().expect("a sample"),
        with.into_iter().min().expect("a sample"),
    )
}

/// Attaching the ~60 MB userspace as a second read-only virtio-blk
/// device must not move boot-to-agent measurably — the whole reason
/// this is an erofs image and not initramfs content, where we
/// measured 2.4 MB of iproute2 costing ~16 ms.
///
/// The assertion is on the *delta* against the same VM with no block
/// device, because the absolute number is not this change's to own: a
/// VM with a TAP already boots slower than the bare
/// [`VM_BOOT_TO_AGENT`] shape `test_latency` measures, and folding that
/// in would make this test fail for someone else's reasons. Both
/// numbers are printed; a regression in either is a finding to report,
/// not a budget to edit.
#[test]
fn test_nodeusr_image_does_not_regress_boot() {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = k7d::network::cleanup_stale_k7_bridges();

    let img = nodeusr_erofs_image();
    let size = std::fs::metadata(&img).expect("erofs image metadata").len();

    let mut net = ClusterNetwork::create("k7storb").expect("cluster bridge");
    let (delta, without, with) = compare_boot(&mut net, &img);
    eprintln!(
        "nodeusr erofs image = {size} bytes; boot-to-agent (best of {BOOT_SAMPLES}): \
         {without:?} without it, {with:?} with it; median pair-delta {delta:?} \
         (bare-VM budget {VM_BOOT_TO_AGENT:?})"
    );

    // The image really is the one attached, and really is read-only.
    let (mut vm, mut agent, _ip, _boot) = boot_storage_vm(&mut net, Some(&img));
    let mounts = guest_ok(&mut agent, &format!("grep {NODEUSR} /proc/mounts"));
    assert!(
        mounts.contains("erofs") && mounts.contains("ro"),
        "expected a read-only erofs mount at {NODEUSR}, got: {mounts}"
    );
    guest_ok(&mut agent, &format!("test -x {NODEUSR}/usr/sbin/iscsid"));
    guest_ok(&mut agent, &format!("test -e {NODEUSR}/sbin/mount.nfs4"));
    vm.shutdown();

    // connect_agent polls every 10 ms, so the common two-tick pair
    // (236→256) reads 20.0–20.5 ms of sub-ms clock noise. Compare at
    // millisecond resolution so that pair is still two ticks, not a
    // raised 21 ms allowance (CHALLENGES #127). A third tick (30 ms)
    // still fails.
    assert!(
        delta.as_millis() <= NODEUSR_BOOT_OVERHEAD.as_millis(),
        "attaching the nodeusr erofs image moved boot-to-agent by median \
         pair-delta {delta:?} (floors {without:?} → {with:?}), more than the \
         {NODEUSR_BOOT_OVERHEAD:?} a second read-only virtio-blk device and \
         its mount should cost — report this as a finding rather than \
         raising the allowance"
    );

    drop(net);
}
