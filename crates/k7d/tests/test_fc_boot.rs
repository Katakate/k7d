//! Integration test: booting the k7d guest on stock Firecracker under
//! the stock jailer.
//!
//! Proves the four things that make this a *second engine* rather than
//! a second code path:
//!
//! 1. the binaries are the pinned upstream ones, verified by digest;
//! 2. `CreateVm { backend: firecracker }` boots the same
//!    `config-minimal` kernel + busybox initramfs the native backend
//!    boots, and the same guest agent answers `ping`/`exec` — over
//!    Firecracker's vsock UDS instead of `AF_VSOCK`;
//! 3. the process it boots is genuinely jailed, asserted from the host
//!    through `/proc` rather than taken on the jailer's word;
//! 4. `stop_vm` leaves nothing behind — twenty times in a row.
//!
//! Plus the negative half: everything Firecracker cannot
//! do returns `Unsupported` with the backend named, instead of being
//! silently ignored.

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use k7d::api::AgentClient;
use k7d::control::{Client, NetConfig, Request, Response, ShareConfig, VmConfig};
use k7d::fc::{FcConfig, FcVm};
use k7d::guest::{AgentEndpoint, Backend, Guest};

/// Boot budget for a Firecracker VM: `CreateVm` accepted to the guest
/// agent answering `ping`. The success criterion.
const FC_BOOT_BUDGET: Duration = Duration::from_secs(2);

/// Create/stop cycles the leak assertions run.
const CYCLES: usize = 20;

fn workspace_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join(relative)
}

fn kernel_path() -> PathBuf {
    let p = workspace_path("guest/kernel/vmlinux");
    assert!(p.exists(), "guest kernel not found at {p:?}");
    p
}

fn initrd_path() -> PathBuf {
    let p = workspace_path("guest/rootfs/initramfs.cpio.gz");
    assert!(p.exists(), "initramfs not found at {p:?}");
    p
}

/// Kills the daemon child on drop so a panicking assertion cannot leak
/// the process (and its jailed Firecracker children).
struct DaemonGuard {
    child: Child,
    socket: PathBuf,
    sandbox_root: PathBuf,
    tree_root: PathBuf,
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_dir_all(&self.sandbox_root);
        let _ = std::fs::remove_dir_all(&self.tree_root);
    }
}

fn spawn_daemon(tag: &str) -> DaemonGuard {
    let pid = std::process::id();
    let socket = std::env::temp_dir().join(format!("k7d-fc-{tag}-{pid}.sock"));
    let sandbox_root = std::env::temp_dir().join(format!("k7d-fc-sandboxes-{tag}-{pid}"));
    let tree_root = std::env::temp_dir().join(format!("k7d-fc-trees-{tag}-{pid}"));
    let _ = std::fs::remove_file(&socket);

    let child = Command::new(env!("CARGO_BIN_EXE_k7d"))
        .arg("--socket")
        .arg(&socket)
        .env("RUST_LOG", "info")
        .env("K7D_KERNEL", kernel_path())
        .env("K7D_INITRD", initrd_path())
        .env("K7D_SANDBOX_ROOT", &sandbox_root)
        .env("K7D_TREE_ROOT", &tree_root)
        .spawn()
        .expect("spawn k7d daemon");
    let guard = DaemonGuard {
        child,
        socket,
        sandbox_root,
        tree_root,
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while !guard.socket.exists() {
        assert!(Instant::now() < deadline, "daemon socket never appeared");
        std::thread::sleep(Duration::from_millis(50));
    }
    guard
}

fn call(guard: &DaemonGuard, req: &Request) -> Response {
    let mut client = Client::connect(guard.socket.to_str().expect("utf8 socket path"))
        .expect("connect control socket");
    client.call(req).expect("control-plane call")
}

fn fc_config() -> VmConfig {
    VmConfig {
        memory_mb: 512,
        vcpus: 1,
        backend: Backend::Firecracker,
        ..VmConfig::default()
    }
}

/// `create_vm` on the Firecracker backend, returning
/// `(vm_id, agent uds path)`.
fn create_fc_vm(guard: &DaemonGuard, config: VmConfig) -> (String, PathBuf) {
    match call(guard, &Request::CreateVm { config }) {
        Response::VmCreated {
            vm_id,
            guest_cid,
            agent_endpoint,
            ..
        } => {
            assert_eq!(
                guest_cid, 0,
                "a Firecracker guest is not reachable over AF_VSOCK; \
                 guest_cid must be the never-a-guest 0 and callers must use agent_endpoint"
            );
            match agent_endpoint {
                Some(AgentEndpoint::FcUds { path }) => (vm_id, PathBuf::from(path)),
                other => panic!("create_vm must answer with an FcUds endpoint, got {other:?}"),
            }
        }
        other => panic!("unexpected create_vm response: {other:?}"),
    }
}

fn stop_vm(guard: &DaemonGuard, vm_id: &str) {
    assert!(
        matches!(
            call(
                guard,
                &Request::StopVm {
                    vm_id: vm_id.to_string()
                }
            ),
            Response::Ok
        ),
        "stop_vm({vm_id}) must succeed"
    );
}

fn connect_agent(uds: &Path, timeout: Duration) -> AgentClient {
    AgentClient::connect_fc_uds(uds, 1024, timeout)
        .unwrap_or_else(|e| panic!("connect agent over {}: {e}", uds.display()))
}

/// The chroot a VM's `run/v.sock` lives in: `<…>/<vm_id>/root`.
fn chroot_of(uds: &Path) -> PathBuf {
    uds.parent()
        .and_then(Path::parent)
        .expect("v.sock lives at <chroot>/run/v.sock")
        .to_path_buf()
}

/// The pid of the Firecracker process jailed in `chroot`.
///
/// k7d is not that process's parent (the jailer `clone`s and exits), so
/// the host finds it the same way an operator would: through the pid
/// file the jailer leaves in the chroot.
fn firecracker_pid(chroot: &Path) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let found = std::fs::read_dir(chroot).ok().and_then(|entries| {
            entries
                .flatten()
                .map(|e| e.path())
                .find(|p| p.extension().is_some_and(|x| x == "pid"))
        });
        if let Some(pid_file) = found {
            if let Ok(pid) = std::fs::read_to_string(&pid_file) {
                if let Ok(pid) = pid.trim().parse::<u32>() {
                    return pid;
                }
            }
        }
        assert!(
            Instant::now() < deadline,
            "no jailer pid file in {}",
            chroot.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Whether `pid`'s `/` is `chroot`, compared by inode.
///
/// Not by string: the jailer `pivot_root`s, so the jail is visible only
/// as the *root field* of the mount the process has at `/`, and that
/// field is a path **within the mount's filesystem**. Since staging puts
/// the chroot base on the reflink XFS loopback (mounted at
/// `/var/lib/k7d/disks`), that reads `/fc/<exec>/<id>/root` rather than
/// the host path — the same directory, spelled from a different root.
fn jailed_root_is(pid: u32, chroot: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (
        std::fs::metadata(format!("/proc/{pid}/root")),
        std::fs::metadata(chroot),
    ) {
        (Ok(jail), Ok(staged)) => jail.dev() == staged.dev() && jail.ino() == staged.ino(),
        _ => false,
    }
}

/// The mount-relative path the host sees as `pid`'s `/`. Failure
/// message only — see [`jailed_root_is`] for the assertion.
fn jailed_root(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/mountinfo"))
        .unwrap_or_else(|e| panic!("read /proc/{pid}/mountinfo: {e}"))
        .lines()
        .find_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.get(4) == Some(&"/"))
                .then(|| f.get(3).map(|root| (*root).to_string()))
                .flatten()
        })
        .unwrap_or_else(|| panic!("no mount at / in /proc/{pid}/mountinfo"))
}

/// `/proc/<pid>/status` as a map.
fn proc_status(pid: u32) -> BTreeMap<String, String> {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap_or_else(|e| panic!("read /proc/{pid}/status: {e}"))
        .lines()
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.to_string(), v.trim().to_string()))
        .collect()
}

fn process_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

fn bridge_exists(name: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", name])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn tun_names() -> Vec<String> {
    let out = Command::new("ip")
        .args(["-o", "link", "show", "type", "tun"])
        .output()
        .expect("ip link show type tun");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            line.split_whitespace()
                .nth(1)
                .map(|n| n.trim_end_matches(':').to_string())
        })
        .collect()
}

#[test]
fn test_fc_install_is_pinned() {
    let version = common::ensure_firecracker_installed();
    assert!(version.starts_with('v'), "unexpected pin {version:?}");

    // The digests on the node must be the digests in guest/fc/pins.env
    // — the whole argument for this backend is that the VMM is the
    // audited upstream binary, and "we downloaded something" is not
    // that. Re-running the installer is the fast path (it verifies and
    // no-ops), so this also covers idempotence.
    for (link, pinned_key) in [
        ("/usr/local/bin/firecracker", "FIRECRACKER_SHA256"),
        ("/usr/local/bin/jailer", "JAILER_SHA256"),
    ] {
        let out = Command::new("sha256sum")
            .arg(link)
            .output()
            .expect("sha256sum");
        assert!(out.status.success(), "sha256sum {link} failed");
        let got = String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .next()
            .expect("digest")
            .to_string();
        assert_eq!(
            got,
            common::firecracker_pin(pinned_key),
            "{link} is not the pinned binary"
        );
    }
    common::ensure_firecracker_installed();
}

/// Firecracker defers CNI attach until after `TUNSETIFF` (TAP-by-name).
/// A requested attach that then fails must still drop the spawned
/// `FcVm` and the bridge slot — not register a VM on the host bridge
/// (bug-candidates #38).
#[test]
fn test_fc_bogus_pod_netns_fails_create_loud() {
    common::ensure_firecracker_installed();
    let cluster_id = format!("f{}", std::process::id() % 99_999_999);
    let bridge = format!("k7-br-{cluster_id}");
    if bridge_exists(&bridge) {
        let _ = Command::new("ip")
            .args(["link", "delete", &bridge])
            .status();
    }
    assert!(
        !bridge_exists(&bridge),
        "stale {bridge} present before test"
    );

    let d = spawn_daemon("cnifl");
    let taps_before = tun_names();
    let mut config = fc_config();
    config.network = Some(NetConfig {
        cluster_id,
        vm_index: None,
        pod_netns: Some("/var/run/netns/does-not-exist".to_string()),
    });

    match call(&d, &Request::CreateVm { config }) {
        Response::Error { message } => {
            assert!(
                message.contains("CNI attach"),
                "error must name the CNI attach, not a missing kernel: {message}"
            );
            assert!(
                message.contains("does-not-exist"),
                "error must name the bogus netns path: {message}"
            );
            assert!(
                !message.to_lowercase().contains("kernel"),
                "must not look like a kernel-path error: {message}"
            );
        }
        other => panic!("bogus pod_netns must not create a Firecracker VM: {other:?}"),
    }

    match call(&d, &Request::ListVms) {
        Response::VmList { vms } => {
            assert!(vms.is_empty(), "failed CNI attach left a VM: {vms:?}");
        }
        other => panic!("unexpected list_vms response: {other:?}"),
    }
    assert!(
        !bridge_exists(&bridge),
        "{bridge} must not survive a failed CNI attach"
    );
    let leftover: Vec<_> = tun_names()
        .into_iter()
        .filter(|n| !taps_before.contains(n))
        .collect();
    assert!(
        leftover.is_empty(),
        "leftover TAP after failed FC CNI attach: {leftover:?}"
    );
    drop(d);
}

#[test]
fn test_fc_boot_ping_and_exec_match_a_native_vm() {
    common::ensure_firecracker_installed();
    let d = spawn_daemon("boot");

    // Native VM first, as the reference: the point of this backend is
    // that the *same* guest runs under a different VMM, so the agent
    // version and kernel release must be identical, not merely present.
    let (native_id, native_cid) = match call(
        &d,
        &Request::CreateVm {
            config: VmConfig {
                memory_mb: 512,
                ..VmConfig::default()
            },
        },
    ) {
        Response::VmCreated {
            vm_id, guest_cid, ..
        } => (vm_id, guest_cid),
        other => panic!("native create_vm: {other:?}"),
    };
    let mut native_agent = AgentClient::connect_vsock(native_cid, Duration::from_secs(30))
        .expect("connect native agent");
    let native_version = native_agent.ping().expect("native ping").version;
    let native_release = native_agent
        .exec(&["uname", "-r"])
        .expect("native uname")
        .stdout
        .trim()
        .to_string();
    assert!(!native_release.is_empty(), "native uname -r said nothing");

    let started = Instant::now();
    let (fc_id, uds) = create_fc_vm(&d, fc_config());
    let mut agent = connect_agent(&uds, FC_BOOT_BUDGET);
    let pong = agent.ping().expect("firecracker guest ping");
    let boot = started.elapsed();
    assert!(
        boot < FC_BOOT_BUDGET,
        "firecracker boot-to-agent took {boot:?}, budget {FC_BOOT_BUDGET:?}"
    );
    assert_eq!(
        pong.version, native_version,
        "the Firecracker guest must run the same agent as the native one"
    );

    let uname = agent.exec(&["uname", "-r"]).expect("firecracker uname");
    assert_eq!(uname.exit_code, 0, "uname -r: {}", uname.stderr);
    assert_eq!(
        uname.stdout.trim(),
        native_release,
        "the Firecracker guest must boot the same config-minimal kernel"
    );

    stop_vm(&d, &fc_id);
    stop_vm(&d, &native_id);
}

#[test]
fn test_fc_process_is_jailed() {
    common::ensure_firecracker_installed();
    let d = spawn_daemon("jail");
    let (vm_id, uds) = create_fc_vm(&d, fc_config());
    let chroot = chroot_of(&uds);
    // Boot it fully before inspecting: a Firecracker that has not
    // reached its run loop has not opened the fds this asserts about.
    connect_agent(&uds, FC_BOOT_BUDGET).ping().expect("ping");

    let pid = firecracker_pid(&chroot);
    let status = proc_status(pid);

    // Unprivileged, and *entirely* so: real, effective, saved and
    // filesystem uid all the allocated one. A saved-set uid of 0 would
    // be a process one setuid() away from root.
    let uids: Vec<u32> = status["Uid"]
        .split_whitespace()
        .map(|v| v.parse().expect("numeric uid"))
        .collect();
    assert_eq!(uids.len(), 4, "Uid: {:?}", status["Uid"]);
    assert!(
        uids[0] >= 60_000 && uids.iter().all(|u| *u == uids[0]),
        "firecracker must run as one unprivileged uid, got {:?}",
        status["Uid"]
    );
    assert_eq!(status["Gid"].split_whitespace().count(), 4);
    assert!(
        status["Gid"]
            .split_whitespace()
            .all(|g| g.parse::<u32>().expect("numeric gid") == uids[0]),
        "Gid: {:?}",
        status["Gid"]
    );

    // Jailed, seccomp'd (2 == SECCOMP_MODE_FILTER — Firecracker's own
    // default filters, on top of the daemon's), and init(1) of a
    // private pid namespace.
    assert!(
        jailed_root_is(pid, &chroot),
        "firecracker's / must be the staged chroot {} (its mount reports {})",
        chroot.display(),
        jailed_root(pid)
    );
    assert_eq!(
        status["Seccomp"], "2",
        "firecracker must be seccomp-filtered"
    );
    let nspid: Vec<&str> = status["NSpid"].split_whitespace().collect();
    assert_eq!(
        nspid,
        vec![pid.to_string().as_str(), "1"],
        "firecracker must be pid 1 of its own pid namespace"
    );

    // The jailer's cgroup, with the memory ceiling actually written.
    let cgroup_line = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).expect("read cgroup");
    let want_cgroup = format!("k7d/{vm_id}/{vm_id}");
    assert!(
        cgroup_line.contains(&want_cgroup),
        "cgroup {cgroup_line:?} is not under {want_cgroup}"
    );
    let memory_max = std::fs::read_to_string(format!("/sys/fs/cgroup/{want_cgroup}/memory.max"))
        .expect("read memory.max");
    let want_memory = k7d::fc::spawn::memory_max_bytes(512);
    assert_eq!(
        memory_max
            .trim()
            .parse::<u64>()
            .expect("numeric memory.max"),
        want_memory
    );

    // No file descriptor reaches outside the jail. Firecracker's
    // targets render either as host paths under the chroot or as the
    // chroot-relative paths it opened them by, so both are accepted;
    // anything else (a host /usr, /var, /etc path) is an escape.
    // Canonicalized: the chroot base is a symlink onto the
    // reflink XFS, and the jailer's own `stderr.log` — opened before
    // the chroot — reads back through the target, not the link.
    let real_chroot = std::fs::canonicalize(&chroot).expect("canonicalize the jail chroot");
    let mut outside = Vec::new();
    for entry in std::fs::read_dir(format!("/proc/{pid}/fd"))
        .expect("read fd dir")
        .flatten()
    {
        let Ok(target) = std::fs::read_link(entry.path()) else {
            continue;
        };
        let t = target.to_string_lossy().into_owned();
        let pseudo = ["socket:", "pipe:", "anon_inode:", "memfd:", "/dev/"]
            .iter()
            .any(|p| t.starts_with(p));
        let inside = target.starts_with(&real_chroot)
            || real_chroot.join(t.trim_start_matches('/')).exists();
        if !pseudo && !inside {
            outside.push(t);
        }
    }
    assert!(
        outside.is_empty(),
        "firecracker holds fds outside its chroot: {outside:?}"
    );

    stop_vm(&d, &vm_id);
}

#[test]
fn test_fc_stop_leaks_nothing_over_twenty_cycles() {
    common::ensure_firecracker_installed();
    let d = spawn_daemon("cycles");

    let mut first_uid = None;
    for cycle in 0..CYCLES {
        let (vm_id, uds) = create_fc_vm(&d, fc_config());
        let chroot = chroot_of(&uds);
        let pid = firecracker_pid(&chroot);

        // The uid must be the *same* every cycle: that is what proves
        // the allocator recycles rather than walking its range until it
        // runs out somewhere in production a week later.
        let uid = proc_status(pid)["Uid"]
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<u32>().ok())
            .expect("numeric uid");
        match first_uid {
            None => first_uid = Some(uid),
            Some(want) => assert_eq!(
                uid, want,
                "cycle {cycle} used uid {uid}, not the freed {want}"
            ),
        }

        stop_vm(&d, &vm_id);

        let deadline = Instant::now() + Duration::from_secs(3);
        while process_alive(pid) || chroot.exists() {
            assert!(
                Instant::now() < deadline,
                "cycle {cycle}: after stop_vm, process alive={} chroot {} still present",
                process_alive(pid),
                chroot.display()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let vm_dir = chroot.parent().expect("chroot has a parent");
        assert!(
            !vm_dir.exists(),
            "cycle {cycle}: {} left behind",
            vm_dir.display()
        );
        assert!(
            !Path::new(&format!("/sys/fs/cgroup/k7d/{vm_id}")).exists(),
            "cycle {cycle}: cgroup k7d/{vm_id} left behind"
        );
    }
}

fn in_process_fc_config(vm_id: &str) -> FcConfig {
    FcConfig {
        vm_id: vm_id.to_string(),
        memory_mb: 256,
        vcpus: 1,
        kernel: kernel_path(),
        initrd: Some(initrd_path()),
        cmdline: k7d::vm::DEFAULT_GUEST_CMDLINE.to_string(),
        cpu_quota_us: None,
        cpu_period_us: None,
        drives: Vec::new(),
        net: None,
        track_dirty_pages: false,
    }
}

/// A spawn that fails *after* the jailer has cloned Firecracker must
/// kill that process before the uid, chroot and cgroup are released —
/// otherwise the next VM is handed the uid of a live one
/// (bug-candidates #51 / #32; #12's cgroup leak closes with it).
///
/// In-process, because the assertions are about this allocator's
/// `live_uid_count` and the reaper's ordering against the lease. The
/// uid base is moved off the default so the `/proc` scan cannot see the
/// node daemon's own Firecracker VMs.
#[test]
fn test_fc_spawn_failure_after_jailer_reaps_the_orphan() {
    common::ensure_firecracker_installed();
    const UID_BASE: u32 = 61_500;
    std::env::set_var("K7D_FC_UID_BASE", UID_BASE.to_string());
    std::env::set_var(k7d::fc::spawn::TEST_HOOK_FAIL_PIDFILE, "1");
    let vm_id = format!("vm-fcreap-{}", std::process::id());
    let vm_dir = k7d::fc::stage::chroot_base()
        .join("firecracker")
        .join(&vm_id);
    let cgroup = PathBuf::from(format!("/sys/fs/cgroup/k7d/{vm_id}"));
    let baseline = k7d::fc::stage::live_uid_count();

    let err = match FcVm::create(&in_process_fc_config(&vm_id), None) {
        Ok(_) => panic!(
            "{} must fail the spawn",
            k7d::fc::spawn::TEST_HOOK_FAIL_PIDFILE
        ),
        Err(e) => e.to_string(),
    };
    std::env::remove_var(k7d::fc::spawn::TEST_HOOK_FAIL_PIDFILE);
    assert!(
        err.contains("read jailer pid file"),
        "the forced failure must be the pid-file read, got: {err}"
    );

    // (a) the allocator is back at baseline — and, unlike before, that
    // now means something: (b) no process on the node runs as the uid
    // the failed VM was leased, and (c) its chroot and cgroup are gone.
    assert_eq!(
        k7d::fc::stage::live_uid_count(),
        baseline,
        "uid lease leaked"
    );
    let orphans = k7d::fc::spawn::pids_owned_by(UID_BASE);
    assert!(
        orphans.is_empty(),
        "firecracker still runs as uid {UID_BASE} after the failed spawn: {orphans:?}"
    );
    assert!(!vm_dir.exists(), "chroot {} left behind", vm_dir.display());
    assert!(!cgroup.exists(), "cgroup {} left behind", cgroup.display());

    // The uid may now be reused safely: the next VM gets it and is the
    // only process running as it.
    let vm =
        FcVm::create(&in_process_fc_config(&vm_id), None).expect("create after a reaped failure");
    let uids = proc_status(vm.pid())["Uid"].clone();
    assert!(
        uids.starts_with(&UID_BASE.to_string()),
        "the recycled uid must be {UID_BASE}, got Uid: {uids}"
    );
    assert_eq!(
        k7d::fc::spawn::pids_owned_by(UID_BASE),
        vec![vm.pid()],
        "exactly one process may run as the reused uid"
    );
    drop(vm);
    std::env::remove_var("K7D_FC_UID_BASE");
    assert!(k7d::fc::spawn::pids_owned_by(UID_BASE).is_empty());
}

/// The jailed Firecracker holds no descriptor of the daemon's: nothing
/// under `/run/k7d`, and no pipe whose other end k7d has open. Every
/// pipe/eventfd k7d makes is `CLOEXEC` (`fdutil.rs`), so the only fds
/// that cross into a helper are the ones `Command` hands it on purpose.
#[test]
fn test_fc_process_holds_no_daemon_fd() {
    common::ensure_firecracker_installed();
    let d = spawn_daemon("nofd");
    let (vm_id, uds) = create_fc_vm(&d, fc_config());
    connect_agent(&uds, FC_BOOT_BUDGET).ping().expect("ping");
    let fc_pid = firecracker_pid(&chroot_of(&uds));
    let daemon_pid = d.child.id();

    let links = |pid: u32| -> Vec<String> {
        std::fs::read_dir(format!("/proc/{pid}/fd"))
            .unwrap_or_else(|e| panic!("read /proc/{pid}/fd: {e}"))
            .flatten()
            .filter_map(|e| std::fs::read_link(e.path()).ok())
            .map(|t| t.to_string_lossy().into_owned())
            .collect()
    };
    let daemon_pipes: Vec<String> = links(daemon_pid)
        .into_iter()
        .filter(|t| t.starts_with("pipe:") || t.starts_with("anon_inode:[eventfd]"))
        .collect();
    let fc_fds = links(fc_pid);

    let under_run_k7d: Vec<&String> = fc_fds
        .iter()
        .filter(|t| t.starts_with("/run/k7d"))
        .collect();
    assert!(
        under_run_k7d.is_empty(),
        "jailed firecracker holds daemon paths: {under_run_k7d:?}"
    );
    // A pipe's inode is the same on both ends, so a `pipe:[N]` shared
    // between the two fd tables is a daemon pipe inside the jail.
    let shared: Vec<&String> = fc_fds
        .iter()
        .filter(|t| t.starts_with("pipe:") && daemon_pipes.contains(t))
        .collect();
    assert!(
        shared.is_empty(),
        "jailed firecracker shares pipes with the daemon: {shared:?} (daemon pipes: {daemon_pipes:?})"
    );
    stop_vm(&d, &vm_id);
}

#[test]
fn test_fc_unsupported_operations_name_the_backend() {
    common::ensure_firecracker_installed();

    // Device fields `create_vm` cannot honour are refused, not ignored.
    let d = spawn_daemon("unsupported");
    let resp = call(
        &d,
        &Request::CreateVm {
            config: VmConfig {
                virtiofs: vec![ShareConfig {
                    host_dir: "/tmp".to_string(),
                    guest_mount: "/mnt/share".to_string(),
                    readonly: true,
                }],
                ..fc_config()
            },
        },
    );
    match resp {
        Response::Error { message } => assert_eq!(
            message, "virtiofs is not supported on backend Firecracker",
            "a virtiofs share on Firecracker must be refused by name"
        ),
        other => panic!("virtiofs on Firecracker must not be accepted: {other:?}"),
    }
    drop(d);

    // And the operations themselves, on a live guest. Built in-process
    // rather than through the daemon because `warp_clock` /
    // `set_dilation` are cluster-scoped verbs and a bare Firecracker
    // VM has no network to put it on a cluster with.
    let vm_id = format!("vm-fcunsup-{}", std::process::id());
    let fc = FcVm::create(
        &FcConfig {
            vm_id: vm_id.clone(),
            memory_mb: 256,
            vcpus: 1,
            kernel: kernel_path(),
            initrd: Some(initrd_path()),
            cmdline: k7d::vm::DEFAULT_GUEST_CMDLINE.to_string(),
            cpu_quota_us: None,
            cpu_period_us: None,
            drives: Vec::new(),
            net: None,
            track_dirty_pages: false,
        },
        None,
    )
    .expect("create firecracker vm");
    let mut guest = Guest::from(fc);
    guest.start().expect("start firecracker vm");
    assert_eq!(guest.backend(), Backend::Firecracker);

    // `.err()` rather than `.unwrap_err()`: several of these return a
    // `Vm` or a `Vec<Guest>` on the success side, and neither is
    // `Debug`. `snapshot`, `prepare_fork_source` and an undilated
    // `fork_batch` are supported (`test_fc_tree.rs`);
    // a *dilated* fork is the refusal that remains on that path.
    for (label, err) in [
        ("warp_clock", guest.warp_clock(Duration::from_secs(1)).err()),
        ("set_dilation", guest.set_dilation(4).err()),
        (
            "fork_batch(dilation)",
            guest.fork_batch(&["a"], Some(4)).err(),
        ),
        ("as_native", guest.as_native().err()),
    ] {
        let text = err
            .unwrap_or_else(|| panic!("{label} must fail on Firecracker, it succeeded"))
            .to_string();
        assert!(
            text.contains("Firecracker") && text.contains("not supported"),
            "{label} must return Unsupported naming the backend, got {text:?}"
        );
    }
    assert!(
        guest.virtiofs_shares().is_empty(),
        "Firecracker has no vhost-user-fs device"
    );
    assert_eq!(guest.guest_cid(), None);
    guest
        .serial_output(Duration::ZERO)
        .expect("Firecracker serial dump must not be Unsupported");
    assert_eq!(guest.memory_mb(), 256);
    assert!(matches!(
        guest.agent_endpoint(),
        AgentEndpoint::FcUds { .. }
    ));

    // Pause/resume are supported, and are the two verbs the fork
    // builds on — assert them here rather than adding a fourth VM boot.
    guest.pause().expect("pause");
    assert!(guest.paused());
    guest.resume().expect("resume");
    assert!(!guest.paused());
    assert!(guest.is_running());
    guest.stop().expect("stop");
}

fn pause_vm(guard: &DaemonGuard, vm_id: &str) {
    let req = Request::PauseVm {
        vm_id: vm_id.to_string(),
    };
    assert!(
        matches!(call(guard, &req), Response::Ok),
        "pause_vm({vm_id}) must succeed"
    );
}

fn resume_vm(guard: &DaemonGuard, vm_id: &str) {
    let req = Request::ResumeVm {
        vm_id: vm_id.to_string(),
    };
    assert!(
        matches!(call(guard, &req), Response::Ok),
        "resume_vm({vm_id}) must succeed"
    );
}

/// After resume, a guest that was dialled *while paused* must answer,
/// and a fresh exec must answer, each within this budget. Native does
/// it in ~0.3 s (`PERFORMANCE.md`); Firecracker may be slower but not
/// unbounded — the k7 symptom (k7-forked CHALLENGES #17) was a hang.
const RESUME_ANSWER_BUDGET: Duration = Duration::from_secs(5);

/// How long the guest stays paused before the concurrent dial: long
/// enough for the host `CONNECT` to land on a muxer whose guest cannot
/// answer (the k7 symptom showed with a ~3 s pause).
const PAUSE_HOLD: Duration = Duration::from_secs(3);

/// Daemon-level repro of k7-forked CHALLENGES #17: `k7d-fc` pause →
/// resume → exec hung. Each round pauses the VM, dials the agent from
/// a second thread **while paused** (a readiness probe or `kubectl exec`
/// landing in the window — it must block, not fail), resumes, and
/// asserts that the blocked dial's ping returns and a fresh
/// `exec echo hello` answers, both within [`RESUME_ANSWER_BUDGET`]. The
/// client that was connected *before* the pause must survive too. Twenty
/// rounds, because the k7 symptom was not deterministic.
#[test]
fn test_fc_pause_resume_exec_answers_twenty_times() {
    common::ensure_firecracker_installed();
    let d = spawn_daemon("pauseexec");
    let (vm_id, uds) = create_fc_vm(&d, fc_config());
    let mut before = connect_agent(&uds, FC_BOOT_BUDGET);
    before.ping().expect("ping before any pause");

    let mut worst = Duration::ZERO;
    for round in 0..CYCLES {
        pause_vm(&d, &vm_id);
        std::thread::sleep(PAUSE_HOLD);

        let dial_uds = uds.clone();
        let dialled_while_paused = std::thread::spawn(move || {
            let started = Instant::now();
            let mut agent =
                AgentClient::connect_fc_uds(&dial_uds, 1024, PAUSE_HOLD + RESUME_ANSWER_BUDGET)
                    .map_err(|e| format!("round {round}: connect while paused: {e}"))?;
            agent
                .ping()
                .map_err(|e| format!("round {round}: ping after resume: {e}"))?;
            Ok::<Duration, String>(started.elapsed())
        });
        // Let the CONNECT land while the guest is still frozen.
        std::thread::sleep(Duration::from_secs(1));
        let dialled_for = Duration::from_secs(1);

        let resumed_at = Instant::now();
        resume_vm(&d, &vm_id);

        let dial_total = dialled_while_paused
            .join()
            .expect("dial thread panicked")
            .unwrap_or_else(|e| panic!("{e}"));
        let dial_after_resume = dial_total.saturating_sub(dialled_for);
        assert!(
            dial_after_resume < RESUME_ANSWER_BUDGET,
            "round {round}: a dial made while paused took {dial_after_resume:?} after resume \
             to answer ping (budget {RESUME_ANSWER_BUDGET:?})"
        );

        let mut fresh = connect_agent(&uds, RESUME_ANSWER_BUDGET);
        let hello = fresh
            .exec(&["echo", "hello"])
            .unwrap_or_else(|e| panic!("round {round}: exec after resume: {e}"));
        assert_eq!(hello.stdout.trim(), "hello", "round {round}: {hello:?}");
        let exec_answered = resumed_at.elapsed();
        assert!(
            exec_answered < RESUME_ANSWER_BUDGET,
            "round {round}: resume → fresh exec answered took {exec_answered:?} \
             (budget {RESUME_ANSWER_BUDGET:?})"
        );
        worst = worst.max(exec_answered);

        before
            .ping()
            .unwrap_or_else(|e| panic!("round {round}: pre-pause client ping after resume: {e}"));
    }
    eprintln!("fc pause→resume→exec: worst of {CYCLES} rounds {worst:?}");
    stop_vm(&d, &vm_id);
}

#[test]
fn test_fc_fork_vm_child_answers_on_uds() {
    common::ensure_firecracker_installed();
    let d = spawn_daemon("forkvm");
    let (src_id, src_uds) = create_fc_vm(&d, fc_config());
    let mut src = connect_agent(&src_uds, FC_BOOT_BUDGET);
    src.ping().expect("source ping");
    let wrote = src
        .exec(&["sh", "-c", "echo from-source > /tmp/fork-marker"])
        .expect("write marker");
    assert_eq!(wrote.exit_code, 0, "{}", wrote.stderr);

    let (fork_id, fork_uds) = match call(
        &d,
        &Request::ForkVm {
            vm_id: src_id.clone(),
            sandbox_id: None,
            dilation: None,
        },
    ) {
        Response::VmForked {
            vm_id,
            guest_cid,
            agent_endpoint,
            ..
        } => {
            assert_eq!(guest_cid, 0, "Firecracker fork is not AF_VSOCK");
            match agent_endpoint {
                Some(AgentEndpoint::FcUds { path }) => (vm_id, PathBuf::from(path)),
                other => panic!("fork_vm must answer FcUds, got {other:?}"),
            }
        }
        other => panic!("fork_vm: {other:?}"),
    };
    assert_ne!(fork_id, src_id);

    let mut child = connect_agent(&fork_uds, Duration::from_secs(5));
    child.ping().expect("child ping");
    let got = child
        .exec(&["cat", "/tmp/fork-marker"])
        .expect("read marker");
    assert_eq!(got.exit_code, 0, "{}", got.stderr);
    assert!(
        got.stdout.contains("from-source"),
        "fork did not inherit source memory: {got:?}"
    );

    let mut src = connect_agent(&src_uds, Duration::from_secs(5));
    src.ping().expect("source ping after fork");

    stop_vm(&d, &fork_id);
    stop_vm(&d, &src_id);
}

/// `DumpSerial` by `vm_id` works on a live Firecracker VM. CID 0 — the
/// registry value of every FC VM — must not match that VM.
#[test]
fn test_fc_dump_serial_by_vm_id_cid_zero_is_not_a_match() {
    common::ensure_firecracker_installed();
    let d = spawn_daemon("dumpser");
    let (vm_id, _uds) = create_fc_vm(&d, fc_config());
    match call(
        &d,
        &Request::DumpSerial {
            vm_id: Some(vm_id.clone()),
            guest_cid: None,
        },
    ) {
        Response::SerialDump {
            vm_id: dumped,
            guest_cid,
            console: _,
        } => {
            assert_eq!(dumped, vm_id);
            assert_eq!(guest_cid, 0, "Firecracker has no host vsock CID");
        }
        other => panic!("dump_serial by FC vm_id must return SerialDump, got {other:?}"),
    }
    match call(
        &d,
        &Request::DumpSerial {
            vm_id: None,
            guest_cid: Some(0),
        },
    ) {
        Response::Error { message } => {
            assert!(
                message.contains("no such VM"),
                "DumpSerial cid 0 must not match an FC registry entry, got {message}"
            );
        }
        other => panic!("DumpSerial cid 0 must not dump the FC VM, got {other:?}"),
    }
    stop_vm(&d, &vm_id);
}
