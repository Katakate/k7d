//! Capability bounding: the running systemd k7d has the measured CapBnd,
//! and `k7d doctor` (the control verb, inside the daemon) reports
//! `hardening:` with every item `ok`.
//!
//! Pre-seccomp helper spawner: the helper spawner is a second,
//! separately filtered process, it holds nothing but its control socket,
//! and the daemon does not outlive it.
//!
//! The suite installs the unit via [`common::ensure_k7d_daemon_running`];
//! a node still on the old unit fails this test on purpose.

mod common;

use std::process::Command;
use std::time::{Duration, Instant};

use k7d::control::{Client, Request, Response, DEFAULT_SOCKET};
use k7d::doctor::{capbnd_of, EXPECTED_CAPBND, EXPECTED_CAPBND_NAMES};

#[test]
fn test_systemd_daemon_capbnd_matches_measured_mask() {
    common::ensure_k7d_daemon_running();
    let pid = k7d_main_pid();
    let got = capbnd_of(pid).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        got, EXPECTED_CAPBND,
        "CapBnd of k7d.service MainPID {pid} is {got:016x}, want {EXPECTED_CAPBND:016x}"
    );

    let shown = Command::new("systemctl")
        .args(["show", "k7d", "-p", "CapabilityBoundingSet", "--value"])
        .output()
        .expect("systemctl show");
    let bounding = String::from_utf8_lossy(&shown.stdout);
    let bounding_lc = bounding.to_ascii_lowercase();
    for name in EXPECTED_CAPBND_NAMES {
        let sysd = format!(
            "cap_{}",
            name.strip_prefix("CAP_")
                .unwrap_or(name)
                .to_ascii_lowercase()
        );
        assert!(
            bounding_lc.split_whitespace().any(|t| t == sysd),
            "systemctl CapabilityBoundingSet missing {name} (systemd prints {sysd}): {bounding}"
        );
    }

    let mut client = Client::connect(DEFAULT_SOCKET).expect("connect k7d.sock");
    match client.call(&Request::Doctor).expect("doctor verb") {
        Response::Doctor { details, ok, .. } => {
            assert!(ok, "doctor ok: {details:?}");
            assert!(
                details.iter().any(|d| d == "hardening:"),
                "missing hardening: section: {details:?}"
            );
            let start = details.iter().position(|d| d == "hardening:").unwrap();
            // Bounded at the next section header: privilege separation
            // appends `privsep:`, whose items are deliberately not all `ok` (the
            // split ships off), and an unbounded slice would read them as
            // hardening regressions.
            let end = details[start + 1..]
                .iter()
                .position(|d| d.ends_with(':') && !d.starts_with(' '))
                .map_or(details.len(), |offset| start + 1 + offset);
            let hard = &details[start + 1..end];
            for line in hard {
                assert!(
                    line.starts_with("ok"),
                    "hardening item not ok on the suite node: {line}"
                );
            }
            for name in [
                "capbnd",
                "nonewprivs",
                "usr_ro",
                "seccomp",
                "spawner",
                "socket",
            ] {
                assert!(
                    hard.iter().any(|l| l.contains(name)),
                    "missing {name} in {hard:?}"
                );
            }
        }
        other => panic!("unexpected doctor response: {other:?}"),
    }

    let touch = Command::new("nsenter")
        .args(["-t", &pid.to_string(), "-m", "touch", "/usr/x"])
        .output()
        .expect("nsenter");
    assert!(
        !touch.status.success(),
        "touch /usr/x in the k7d mount ns must fail (ProtectSystem=strict), got {:?}\nstdout={}\nstderr={}",
        touch.status,
        String::from_utf8_lossy(&touch.stdout),
        String::from_utf8_lossy(&touch.stderr)
    );
}

/// Pre-seccomp helper spawner: two processes, two filters, and the
/// spawner holds nothing but the socket it serves.
///
/// `Seccomp: 2` on the daemon alone proved nothing once the helper
/// allowlist moved: the interesting claim is that the *spawner* is
/// filtered too (its filter is what every helper inherits) and that the
/// daemon's own filter no longer carries the helpers' syscalls — which
/// `seccomp.rs`'s `daemon_filter_has_no_privilege_syscalls` asserts on
/// the list and this test corroborates from `/proc`.
#[test]
fn test_spawner_is_a_second_filtered_process_holding_only_its_socket() {
    common::ensure_k7d_daemon_running();
    let daemon = k7d_main_pid();
    let spawner = spawner_pid_from_doctor();

    let control = control_pid(daemon, spawner);
    assert_eq!(
        proc_field(spawner, "PPid"),
        control.to_string(),
        "the spawner must be a direct child of the process that serves the socket (pid {control})"
    );
    for (who, pid) in [
        ("daemon", daemon),
        ("control", control),
        ("spawner", spawner),
    ] {
        assert_eq!(
            proc_field(pid, "Seccomp"),
            "2",
            "{who} (pid {pid}) is not running a seccomp filter"
        );
    }

    // Everything the spawner inherited at fork is closed except the
    // standard three (`StdioSpec::Inherit` means the daemon's journald
    // stdio) and the SEQPACKET socketpair it serves. A fourth
    // descriptor here is a daemon fd one `execve` away from a helper.
    let mut fds: Vec<u32> = std::fs::read_dir(format!("/proc/{spawner}/fd"))
        .unwrap_or_else(|e| panic!("read /proc/{spawner}/fd: {e}"))
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse().ok())
        .collect();
    fds.sort_unstable();
    assert_eq!(
        fds,
        vec![0, 1, 2, 3],
        "spawner (pid {spawner}) holds descriptors beyond its stdio and its control socket"
    );

    let seqpacket = seqpacket_inodes();
    let sockets: Vec<u32> = fds
        .iter()
        .filter_map(|fd| {
            let target = std::fs::read_link(format!("/proc/{spawner}/fd/{fd}")).ok()?;
            let target = target.to_string_lossy();
            let inode: u32 = target
                .strip_prefix("socket:[")?
                .strip_suffix(']')?
                .parse()
                .ok()?;
            seqpacket.contains(&inode).then_some(*fd)
        })
        .collect();
    assert_eq!(
        sockets,
        vec![3],
        "the spawner must hold exactly one SEQPACKET socket (its control socket on fd 3); \
         /proc/net/unix seqpacket inodes: {seqpacket:?}"
    );
}

/// Helper-spawner crash coupling: a daemon whose spawner died cannot exec a
/// helper and cannot fork a replacement behind its own filter, so it
/// must exit loudly rather than fail every network and volume operation
/// from then on. `Restart=on-failure` brings the pair back.
#[test]
fn test_daemon_exits_when_the_spawner_is_killed() {
    common::ensure_k7d_daemon_running();
    let daemon = k7d_main_pid();
    let spawner = spawner_pid_from_doctor();
    let since = journal_cursor_now();

    let killed = Command::new("kill")
        .args(["-9", &spawner.to_string()])
        .status()
        .expect("kill -9 the spawner");
    assert!(killed.success(), "kill -9 {spawner}: {killed}");

    let deadline = Instant::now() + Duration::from_secs(5);
    while std::path::Path::new(&format!("/proc/{daemon}")).exists() {
        assert!(
            Instant::now() < deadline,
            "daemon pid {daemon} still alive 5s after its spawner (pid {spawner}) was killed"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    let log = journal_since(&since);
    assert!(
        log.contains(&format!("spawner (pid {spawner}) is gone"))
            || log.contains(&format!("spawner pid {spawner}")),
        "the daemon must name the spawner on its way out:\n{log}"
    );
    assert!(
        log.contains("status=1/FAILURE"),
        "the daemon must exit non-zero so systemd restarts it:\n{log}"
    );

    // Leave the node as the rest of the suite expects to find it: a
    // live daemon with a live spawner of its own.
    common::ensure_k7d_daemon_running();
    let restarted = k7d_main_pid();
    assert_ne!(restarted, daemon, "systemd did not restart k7d");
    assert_eq!(proc_field(spawner_pid_from_doctor(), "Seccomp"), "2");
}

/// The other half of the crash coupling, and the half that actually
/// broke: `systemctl restart k7d` must be an ordinary restart.
///
/// systemd stops a unit by signalling its whole cgroup, so the spawner
/// gets the same `SIGTERM` as the daemon. With the default disposition
/// it died first, the watchdog read that as a crash, and the daemon
/// exited 1 — which `Restart=on-failure` turned into a second restart
/// on top of the one that was asked for. Every test that restarts the
/// daemon was racing a daemon that might be on its way out
/// (`test_docker_warm_fork_nginx_survives` timing out on a pod that
/// never came ready). The spawner now catches `SIGTERM` and leaves on
/// the EOF that follows the daemon's own exit.
#[test]
fn test_restarting_the_unit_is_not_a_spawner_crash() {
    common::ensure_k7d_daemon_running();
    let before = k7d_main_pid();
    let old_spawner = spawner_pid_from_doctor();
    let since = journal_cursor_now();

    let restart = Command::new("systemctl")
        .args(["restart", "k7d"])
        .status()
        .expect("systemctl restart k7d");
    assert!(restart.success(), "systemctl restart k7d: {restart}");
    wait_for_socket();

    let log = journal_since(&since);
    assert!(
        !log.contains("is gone ("),
        "a plain restart was reported as a spawner crash:\n{log}"
    );
    assert!(
        !log.contains("status=1/FAILURE"),
        "a plain restart exited non-zero, so Restart=on-failure will loop it:\n{log}"
    );

    // Exactly one new daemon, with a spawner of its own, and it stays up
    // rather than being restarted again by the failure path.
    let after = k7d_main_pid();
    assert_ne!(
        after, before,
        "systemctl restart did not replace the daemon"
    );
    let new_spawner = spawner_pid_from_doctor();
    assert_ne!(new_spawner, old_spawner);
    assert_eq!(
        proc_field(new_spawner, "PPid"),
        control_pid(after, new_spawner).to_string()
    );
    assert_eq!(proc_field(new_spawner, "Seccomp"), "2");
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(
        k7d_main_pid(),
        after,
        "the daemon was restarted again after the restart completed:\n{}",
        journal_since(&since)
    );
}

/// Privilege separation: `k7d doctor` publishes a `privsep:` section, and the
/// packaging half of it is `ok` on this node whether or not the split is
/// switched on.
///
/// The split itself is `K7D_PRIVSEP`, which the unit ships `off` while
/// the network and Firecracker verb families are still `ENOSYS`. So the
/// two claims are separated: the *account*, the *device group* and the
/// *unit's mode* are asserted unconditionally, because they are what
/// `packaging/install.sh` did and a node that lost them would fail the
/// split silently later; the *delegated cgroup* is asserted only when
/// the mode says the pair is actually running, because with the split
/// off there is no `vm/` subtree to own.
///
/// A `privsep:` section that vanished would otherwise be caught by
/// nothing — the `ok` flag on the doctor response covers only the four
/// required host checks.
#[test]
fn test_doctor_reports_privilege_separation() {
    common::ensure_k7d_daemon_running();
    let mut client = Client::connect(DEFAULT_SOCKET).expect("connect k7d.sock");
    let Response::Doctor { details, .. } = client.call(&Request::Doctor).expect("doctor verb")
    else {
        panic!("unexpected doctor response");
    };
    let start = details
        .iter()
        .position(|d| d == "privsep:")
        .unwrap_or_else(|| panic!("missing privsep: section: {details:?}"));
    let privsep = &details[start + 1..];
    for name in [
        "mode",
        "account",
        "vhost_vsock_perms",
        "delegated_cgroup",
        "channels",
    ] {
        assert!(
            privsep.iter().any(|l| l.contains(&format!("  {name}  "))),
            "missing {name} in privsep: {privsep:?}"
        );
    }
    let item = |name: &str| -> String {
        privsep
            .iter()
            .find(|l| l.contains(&format!("  {name}  ")))
            .unwrap_or_else(|| panic!("no {name} line"))
            .clone()
    };

    // Packaging, regardless of the mode: the account exists and is in
    // `kvm`, and 60-k7d.rules put /dev/vhost-vsock in that group.
    for name in ["account", "vhost_vsock_perms"] {
        let line = item(name);
        assert!(
            line.starts_with("ok"),
            "privsep {name} is not ok on the suite node — packaging/k7d-account.sh has not run \
             (or has regressed): {line}"
        );
    }
    // Channel pressure is reported and under the cap even with the split
    // off, where the daemon opens none.
    assert!(item("channels").starts_with("ok"), "{}", item("channels"));

    let mode = item("mode");
    let split_on = mode.starts_with("ok");
    assert!(
        mode.contains("K7D_PRIVSEP"),
        "the mode line must name the variable that decides it: {mode}"
    );
    if split_on {
        let line = item("delegated_cgroup");
        assert!(
            line.starts_with("ok"),
            "the split is on but the delegated cgroup subtree is not owned by the VM broker with \
             every controller — the unit's Delegate= is the usual cause: {line}"
        );
    }
}

/// `systemctl restart` returns when the unit is active, which is before
/// the daemon has bound its socket.
fn wait_for_socket() {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Client::connect(DEFAULT_SOCKET).is_err() {
        assert!(
            Instant::now() < deadline,
            "k7d did not accept on {DEFAULT_SOCKET} within 30s of a restart:\n{}",
            journal_since("-1min")
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn journal_cursor_now() -> String {
    let out = Command::new("date")
        .args(["+%Y-%m-%d %H:%M:%S"])
        .output()
        .expect("date");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn journal_since(since: &str) -> String {
    let out = Command::new("journalctl")
        .args(["-u", "k7d", "--since", since, "--no-pager"])
        .output()
        .expect("journalctl -u k7d");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Ask the running daemon for its spawner's pid — `k7d doctor`'s
/// `hardening:` section is where it is published.
fn spawner_pid_from_doctor() -> u32 {
    let mut client = Client::connect(DEFAULT_SOCKET).expect("connect k7d.sock");
    let Response::Doctor { details, .. } = client.call(&Request::Doctor).expect("doctor verb")
    else {
        panic!("unexpected doctor response");
    };
    let line = details
        .iter()
        .find(|l| l.contains("  spawner  "))
        .unwrap_or_else(|| panic!("doctor has no spawner hardening line: {details:?}"));
    assert!(
        line.starts_with("ok"),
        "the daemon reports no filtered spawner: {line}"
    );
    line.split_whitespace()
        .skip_while(|w| *w != "pid")
        .nth(1)
        .and_then(|p| p.trim_end_matches(',').parse().ok())
        .unwrap_or_else(|| panic!("no pid in the spawner line: {line}"))
}

/// The pid that serves the control socket and owns the spawner.
///
/// Un-split that is the unit's `MainPID`. With privilege separation on it is the VM
/// broker, one fork below: `MainPID` is the node broker, which keeps the
/// capabilities, and everything that spawns a helper lives in its
/// unprivileged child. Derived from the spawner's own `PPid` rather than
/// by scanning for uid `k7d`, so the chain
/// `spawner → control → MainPID` is asserted rather than assumed.
fn control_pid(main: u32, spawner: u32) -> u32 {
    let parent: u32 = proc_field(spawner, "PPid").parse().expect("numeric PPid");
    if parent == main {
        return main;
    }
    assert_eq!(
        proc_field(parent, "PPid"),
        main.to_string(),
        "the spawner's parent (pid {parent}) is neither the unit's MainPID {main} nor a child \
         of it — it belongs to some other k7d"
    );
    assert_ne!(
        proc_field(parent, "Uid").split('\t').next().unwrap_or("0"),
        "0",
        "pid {parent} sits between the spawner and MainPID but runs as root — the VM broker is \
         the only process that belongs there"
    );
    parent
}

/// One `/proc/<pid>/status` field, verbatim.
fn proc_field(pid: u32, field: &str) -> String {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap_or_else(|e| panic!("read /proc/{pid}/status: {e}"));
    status
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{field}:")))
        .unwrap_or_else(|| panic!("no {field} in /proc/{pid}/status"))
        .trim()
        .to_string()
}

/// Inodes of every `SOCK_SEQPACKET` unix socket on the host
/// (`/proc/net/unix` type `0005`). The socketpair the daemon and the
/// spawner share is the only one k7d makes.
fn seqpacket_inodes() -> Vec<u32> {
    let text = std::fs::read_to_string("/proc/net/unix").expect("read /proc/net/unix");
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let mut cols = line.split_whitespace();
            // Num RefCount Protocol Flags Type St Inode Path
            let ty = cols.nth(4)?;
            let inode = cols.nth(1)?;
            (ty == "0005").then(|| inode.parse().ok())?
        })
        .collect()
}

fn k7d_main_pid() -> u32 {
    let out = Command::new("systemctl")
        .args(["show", "-p", "MainPID", "--value", "k7d"])
        .output()
        .expect("systemctl show k7d");
    let pid: u32 = String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("k7d MainPID");
    assert!(pid > 0, "k7d.service has no main PID — is it running?");
    pid
}
