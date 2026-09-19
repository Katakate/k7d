//! Privilege separation: k7d is two processes, and the one a guest or a
//! shim can reach has no privileges.
//!
//! Every claim here is read back out of `/proc`, `/sys/fs/cgroup` or the
//! kernel's own capability check rather than out of a log line the daemon
//! printed about itself. That distinction is the point of the increment:
//! a `setresuid` that ran before `PR_CAPBSET_DROP` succeeds, logs
//! nothing, and leaves a process whose name and output are identical to a
//! jailed one (`CHALLENGES.md` #246).
//!
//! ## Why a transient unit
//!
//! The shipped `k7d.service` sets `K7D_PRIVSEP=off` while the network,
//! cgroup-helper and Firecracker verb families still answer `ENOSYS`, so
//! the rest of the suite keeps running one root process. These tests
//! therefore start their *own* pair with the split on, under
//! `systemd-run -p Delegate=yes`, on a private socket, tree root and
//! sandbox root.
//!
//! It has to be a unit rather than a plain child: the delegation in §4.3
//! enables `memory` in the service cgroup's `cgroup.subtree_control`, and
//! cgroup v2 refuses that in a cgroup that has member processes of its
//! own. A test process's cgroup is an ssh session scope full of them; a
//! transient unit's is empty. That is also how it runs in production, so
//! testing anything else would be testing an arrangement no node has.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use k7d::control::{Client, Request, Response, ShareConfig, VmConfig};
use k7d::doctor::{capbnd_of, EXPECTED_CAPBND};

/// Transient unit name. One at a time: the suite runs with
/// `--test-threads=1`, and a second pair would fight over the unit.
const UNIT: &str = "k7d-privsep-test";

/// Directories the pair needs to own, all outside the running daemon's.
const RUN_DIR: &str = "/run/k7d-privsep-test";

/// A running node-broker/VM-broker pair on a private socket.
struct SplitPair {
    socket: PathBuf,
    node_pid: u32,
    vm_pid: u32,
    tree_root: PathBuf,
    sandbox_root: PathBuf,
}

impl Drop for SplitPair {
    fn drop(&mut self) {
        stop_unit();
        let _ = std::fs::remove_dir_all(&self.tree_root);
        let _ = std::fs::remove_dir_all(&self.sandbox_root);
        let _ = std::fs::remove_dir_all(RUN_DIR);
    }
}

fn stop_unit() {
    let _ = Command::new("systemctl")
        .args(["stop", &format!("{UNIT}.service")])
        .status();
    let _ = Command::new("systemctl")
        .args(["reset-failed", &format!("{UNIT}.service")])
        .status();
    // The unit is `--collect`ed, but a SIGKILLed pair can outlive the
    // stop by the time the next test starts one.
    let deadline = Instant::now() + Duration::from_secs(15);
    while unit_property("MainPID") != "0" && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn unit_property(name: &str) -> String {
    let out = Command::new("systemctl")
        .args(["show", "-p", name, "--value", &format!("{UNIT}.service")])
        .output()
        .expect("systemctl show");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Start the pair, with the split on.
///
/// Reuses `common::ensure_k7d_daemon_running` for the parts that are the
/// same as the single-process suite — the binary is built and installed,
/// the guest is in place, the disks are mounted and, since this
/// increment, the `k7d` account and `60-k7d.rules` exist.
fn start_pair() -> SplitPair {
    start_pair_with(&[])
}

/// The pair with `K7D_VM_BROKER_RESTART=on`. Only the tests turn it
/// on: the shipped unit does not set it.
fn start_pair_with_restart() -> SplitPair {
    start_pair_with(&[("K7D_VM_BROKER_RESTART", "on")])
}

fn start_pair_with(extra_env: &[(&str, &str)]) -> SplitPair {
    common::ensure_k7d_daemon_running();
    stop_unit();

    let uid = passwd_uid("k7d");
    let tree_root = PathBuf::from("/var/lib/k7d/trees/privsep-test");
    let sandbox_root = PathBuf::from("/var/lib/k7d/sandboxes/privsep-test");
    for dir in [Path::new(RUN_DIR), &tree_root, &sandbox_root] {
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).unwrap_or_else(|e| panic!("mkdir {}: {e}", dir.display()));
        chown_to(dir, uid);
    }
    let socket = Path::new(RUN_DIR).join("k7d.sock");

    let (kernel, initrd) = installed_guest();
    let mut cmd = Command::new("systemd-run");
    // No `--collect`: a unit that systemd garbage-collects reports
    // `Result=success` because `systemctl show` on an unloaded unit
    // answers with the property's default, which is indistinguishable
    // from a clean exit. `stop_unit` does the `reset-failed` instead.
    cmd.args(["--unit", UNIT, "-p", "Delegate=yes", "-p", "Restart=no"]);
    // The properties the shipped unit sets that these tests assert. Taken
    // from the template rather than repeated, so a mask edited in
    // `k7d.service.in` is what gets measured here (`doctor.rs`'s
    // `expected_capbnd_matches_the_unit_template` is the other half).
    for property in ["CapabilityBoundingSet", "NoNewPrivileges"] {
        cmd.args(["-p", &unit_template_property(property)]);
    }
    for (k, v) in [
        ("K7D_PRIVSEP", "on".to_string()),
        ("RUST_LOG", "info".to_string()),
        ("K7D_SOCKET", socket.display().to_string()),
        ("K7D_TREE_ROOT", tree_root.display().to_string()),
        ("K7D_SANDBOX_ROOT", sandbox_root.display().to_string()),
        ("K7D_KERNEL", kernel),
        ("K7D_INITRD", initrd),
    ] {
        cmd.args(["-p", &format!("Environment={k}={v}")]);
    }
    for (k, v) in extra_env {
        cmd.args(["-p", &format!("Environment={k}={v}")]);
    }
    cmd.arg("/usr/local/bin/k7d");
    let status = cmd.status().expect("systemd-run");
    assert!(status.success(), "systemd-run {UNIT}: {status}");

    let deadline = Instant::now() + Duration::from_secs(30);
    while !socket.exists() {
        assert!(
            Instant::now() < deadline,
            "the split pair never bound {}:\n{}",
            socket.display(),
            journal()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let node_pid: u32 = unit_property("MainPID")
        .parse()
        .unwrap_or_else(|e| panic!("MainPID: {e}\n{}", journal()));
    let vm_pid = only_child_of(node_pid);
    SplitPair {
        socket,
        node_pid,
        vm_pid,
        tree_root,
        sandbox_root,
    }
}

/// One `Key=value` line, verbatim, from `packaging/k7d.service.in`.
fn unit_template_property(key: &str) -> String {
    let template = include_str!("../../../packaging/k7d.service.in");
    template
        .lines()
        .find(|l| l.starts_with(&format!("{key}=")))
        .unwrap_or_else(|| panic!("packaging/k7d.service.in has no {key}="))
        .to_string()
}

fn journal() -> String {
    journal_since("-2min")
}

/// The unit's journal from `since`. Scoped, because these tests reuse one
/// unit name: an unscoped read picks up the `is gone (...)` line that the
/// *previous* test deliberately provoked, and the restart test would fail
/// on evidence of a kill it did not perform.
fn journal_since(since: &str) -> String {
    let out = Command::new("journalctl")
        .args(["-u", UNIT, "--since", since, "--no-pager"])
        .output()
        .expect("journalctl");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// An opaque journal position, for a window that means "strictly after
/// the lines that exist now".
///
/// A `--since` timestamp cannot mean that: `date` has one-second
/// resolution and `journalctl --since` is inclusive of that second. So a
/// test that begins in the same second as the previous one's *deliberate*
/// `killed by signal 9` reads that kill as its own — which is what the
/// restart test failed on, intermittently, and only when the node was
/// loaded enough for the two to land together. Scoping by cursor removes
/// the whole class rather than widening a sleep.
fn journal_cursor() -> String {
    let out = Command::new("journalctl")
        .args(["-u", UNIT, "-n", "0", "--show-cursor", "--no-pager"])
        .output()
        .expect("journalctl --show-cursor");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.trim().strip_prefix("-- cursor: ").map(str::to_string))
        .unwrap_or_default()
}

/// The unit's journal strictly after `cursor`. An empty cursor is a unit
/// that has never logged, where everything is after it.
fn journal_after(cursor: &str) -> String {
    if cursor.is_empty() {
        return journal();
    }
    let out = Command::new("journalctl")
        .args(["-u", UNIT, "--after-cursor", cursor, "--no-pager"])
        .output()
        .expect("journalctl --after-cursor");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The children of `pid`, from `/proc/<pid>/task/*/children`.
fn children_of(pid: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return out;
    };
    for task in tasks.flatten() {
        if let Ok(list) = std::fs::read_to_string(task.path().join("children")) {
            out.extend(
                list.split_whitespace()
                    .filter_map(|c| c.parse::<u32>().ok()),
            );
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn only_child_of(pid: u32) -> u32 {
    let kids = children_of(pid);
    assert_eq!(
        kids.len(),
        1,
        "pid {pid} has children {kids:?}, want exactly one\n{}",
        journal()
    );
    kids[0]
}

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

fn passwd_uid(name: &str) -> u32 {
    std::fs::read_to_string("/etc/passwd")
        .expect("read /etc/passwd")
        .lines()
        .find(|l| l.starts_with(&format!("{name}:")))
        .and_then(|l| l.split(':').nth(2))
        .and_then(|f| f.parse().ok())
        .unwrap_or_else(|| panic!("no {name} account"))
}

fn group_gid(name: &str) -> u32 {
    std::fs::read_to_string("/etc/group")
        .expect("read /etc/group")
        .lines()
        .find(|l| l.starts_with(&format!("{name}:")))
        .and_then(|l| l.split(':').nth(2))
        .and_then(|f| f.parse().ok())
        .unwrap_or_else(|| panic!("no {name} group"))
}

fn chown_to(path: &Path, uid: u32) {
    let status = Command::new("chown")
        .arg("-R")
        .arg(format!("{uid}:{uid}"))
        .arg(path)
        .status()
        .expect("chown");
    assert!(status.success(), "chown {}: {status}", path.display());
}

fn installed_guest() -> (String, String) {
    let kernel = "/usr/local/share/k7d/vmlinux";
    let initrd = "/usr/local/share/k7d/initramfs.cpio.gz";
    for p in [kernel, initrd] {
        assert!(
            Path::new(p).exists(),
            "{p} is missing — ensure_k7d_daemon_running installs the workspace guest"
        );
    }
    (kernel.to_string(), initrd.to_string())
}

fn call(pair: &SplitPair, req: &Request) -> Response {
    let mut client =
        Client::connect(pair.socket.to_str().expect("utf8 socket")).expect("connect split socket");
    client.call(req).expect("control call")
}

/// Run one command as uid `k7d` with no capabilities, the way §10.4
/// describes the fuzz sandbox.
fn as_vm_broker(args: &[&str]) -> std::process::Output {
    Command::new("setpriv")
        .args([
            "--reuid",
            "k7d",
            "--regid",
            "k7d",
            "--clear-groups",
            "--no-new-privs",
            "--inh-caps=-all",
            "--bounding-set=-all",
            "--",
        ])
        .args(args)
        .output()
        .expect("setpriv")
}

// --- §10.1(a) identity ----------------------------------------------

/// Three processes, three identities, and the child's capability sets are
/// empty in `/proc` — not "were dropped" according to the process that
/// dropped them.
///
/// The bounding set is the one that matters and the one that is easiest
/// to get wrong: `PR_CAPBSET_DROP` needs `CAP_SETPCAP` *effective*, and
/// `setresuid` away from 0 clears the effective set. Run in the wrong
/// order every `prctl` returns `EPERM`, the daemon carries on, and the VM
/// broker is a uid-`k7d` process that can still regain `CAP_NET_ADMIN`
/// through any setuid-root binary — which `NoNewPrivs` is the second half
/// of. Both are read here.
#[test]
fn test_the_split_pair_has_the_identities_the_spec_names() {
    let pair = start_pair();
    let broker_uid = passwd_uid("k7d");
    let kvm_gid = group_gid("kvm");

    // Node broker: root, the capability-bounding measured set, its own filter.
    assert_eq!(
        proc_field(pair.node_pid, "Uid")
            .split_whitespace()
            .next()
            .unwrap(),
        "0",
        "the node broker must stay root"
    );
    assert_eq!(
        capbnd_of(pair.node_pid).unwrap_or_else(|e| panic!("{e}")),
        EXPECTED_CAPBND,
        "the node broker's bounding set is not the capability-bounding measured mask"
    );
    assert_eq!(proc_field(pair.node_pid, "Seccomp"), "2");

    // VM broker: uid k7d everywhere, gid k7d, kvm as its only
    // supplementary group, no capabilities of any kind.
    for (field, want) in [("Uid", broker_uid), ("Gid", group_gid("k7d"))] {
        let got = proc_field(pair.vm_pid, field);
        assert!(
            got.split_whitespace().all(|f| f == want.to_string()),
            "VM broker {field} is {got}, want all four to be {want} — a saved uid left at 0 is a \
             process that can go back"
        );
    }
    let groups = proc_field(pair.vm_pid, "Groups");
    assert_eq!(
        groups.split_whitespace().collect::<Vec<_>>(),
        vec![kvm_gid.to_string()],
        "VM broker Groups is {groups:?}, want exactly [{kvm_gid}] (kvm) — that membership is what \
         carries /dev/kvm and /dev/vhost-vsock to a process with no capabilities"
    );
    for field in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        let got = proc_field(pair.vm_pid, field);
        assert_eq!(
            got.trim_start_matches('0'),
            "",
            "VM broker {field} is {got}, want all zeroes (privilege-separation drop order)"
        );
    }
    assert_eq!(proc_field(pair.vm_pid, "NoNewPrivs"), "1");
    assert_eq!(proc_field(pair.vm_pid, "Seccomp"), "2");
    // DUMPABLE=0 keeps /proc/<vm broker>/{fd,mem} root-owned, so a second
    // uid-k7d process cannot walk the VM broker's guest memory.
    let fd_owner = std::fs::metadata(format!("/proc/{}/fd", pair.vm_pid))
        .map(|m| std::os::unix::fs::MetadataExt::uid(&m))
        .expect("stat the VM broker's fd dir");
    assert_eq!(
        fd_owner, 0,
        "/proc/{}/fd is owned by uid {fd_owner}, want root (PR_SET_DUMPABLE=0)",
        pair.vm_pid
    );
    // The unprivileged uid confirms it from where an attacker would be.
    let peek = as_vm_broker(&["ls", &format!("/proc/{}/fd", pair.vm_pid)]);
    assert!(
        !peek.status.success(),
        "uid k7d could list the VM broker's descriptors — PR_SET_DUMPABLE=0 did not take"
    );

    // Helper spawner: the pre-seccomp helper spawner's third process, now inheriting uid k7d.
    let spawner = only_child_of(pair.vm_pid);
    assert_eq!(
        proc_field(spawner, "Uid")
            .split_whitespace()
            .next()
            .unwrap(),
        broker_uid.to_string(),
        "the helper spawner must inherit the VM broker's uid"
    );
    assert_eq!(proc_field(spawner, "Seccomp"), "2");
}

// --- §10.1(b) the descriptor table ----------------------------------

/// What the VM broker holds, and more importantly what it does not.
///
/// The split is only worth its complexity if the descriptors stay on the
/// right side of it. A VM broker holding an open fd under
/// `/sys/fs/cgroup/k7d` or `/var/lib/k7d/fc` has the node broker's
/// authority whatever its capability sets say, and an open `/proc/sys/net`
/// is `CAP_NET_ADMIN` by another name.
#[test]
fn test_the_vm_broker_holds_no_node_broker_descriptor() {
    let pair = start_pair();
    let targets = fd_targets(pair.vm_pid);
    assert!(
        !targets.is_empty(),
        "read no descriptors for the VM broker at all"
    );
    for forbidden in [
        "/sys/fs/cgroup/k7d/",
        "/var/lib/k7d/fc",
        "/proc/sys/net",
        "/etc/",
    ] {
        assert!(
            !targets.iter().any(|t| t.starts_with(forbidden)),
            "the VM broker holds a descriptor under {forbidden}: {targets:?}"
        );
    }
    // And the node broker has no listening socket of its own: its only
    // peer is the pre-fork socketpair, which has no path to connect to.
    let listening = Command::new("ss").args(["-lxp"]).output().expect("ss -lxp");
    let listening = String::from_utf8_lossy(&listening.stdout);
    let node_marker = format!("pid={}", pair.node_pid);
    assert!(
        !listening.contains(&node_marker),
        "the node broker is listening on a unix socket:\n{listening}"
    );
}

fn fd_targets(pid: u32) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        panic!("read /proc/{pid}/fd");
    };
    for entry in entries.flatten() {
        if let Ok(target) = std::fs::read_link(entry.path()) {
            out.push(target.to_string_lossy().into_owned());
        }
    }
    out
}

// --- §10.1(c) the kernel's own capability check ----------------------

/// The kernel is asked whether the VM broker ever *gets* a capability,
/// and the answer must be no.
///
/// This is the capability-bounding instrument — `kprobe:cap_capable`, whose union produced
/// the bounding set (`CHALLENGES.md` #244) — pointed at the other half of
/// the split. Two things about how it is read here matter:
///
/// * The **return value** is asserted on first: `cap_capable` returns 0
///   when the capability is granted, so `@granted[0]` is the key that
///   must not exist.
/// * Since the `net.*` / `virtiofsd.spawn` / pinned-descriptor verbs landed the **entry** tally is asserted too, and that is
///   the stronger half. A granted capability is impossible with an empty
///   `CapEff`; an *asked-for* one is a call site that still belongs on
///   the node broker's side, and while the network, cgroup-helper and
///   Firecracker families answered `ENOSYS` there were many. Now the
///   only ones left are the two the doctor provokes on purpose — it
///   stats the Firecracker chroot base, which is root `0700` exactly so
///   the VM broker cannot enter it, and the kernel checks
///   `DAC_OVERRIDE`/`DAC_READ_SEARCH` before refusing. Anything else in
///   `@asked[]` is a migration that was missed, which is what "the
///   family is done" is supposed to mean.
/// * The pair is kept busy while the probe is attached, and the entry
///   tally is asserted non-empty, so a clean result means "asked and never
///   granted" rather than "the probe never attached".
/// * Only **audited** asks count as asks (`opts & CAP_OPT_NOAUDIT == 0`,
///   `arg3` of `cap_capable`). The kernel also probes `CAP_SYS_ADMIN`
///   with `CAP_OPT_NOAUDIT` on the process's behalf, not at its request:
///   `cap_vm_enough_memory` asks it on every accountable `mmap`,
///   `mprotect` and `clone` to decide whether the overcommit reserve
///   applies, and the seccomp BPF JIT asks it for hardening. Those are
///   not privileged call sites in k7d — every unprivileged process on
///   the host makes them — and whether the kprobe *sees* them is a
///   compiler decision: on the AMD nodes' 6.8 kernel `cap_capable` is
///   inlined into `cap_vm_enough_memory` and the tally is silent; on the
///   Intel node's 7.0 kernel it is a real call and the same VM broker
///   showed `@asked[21]: 65` serving ping/doctor/list. The doctor's DAC
///   checks come through `ns_capable`, which audits, so they still show.
///
/// Stronger than reading `CapEff` once: it covers a window rather than an
/// instant, and it covers `ns_capable` in a namespace this process might
/// have entered, where an empty `CapEff` would still read as root.
#[test]
fn test_the_vm_broker_is_never_granted_a_capability() {
    ensure_bpftrace();
    let pair = start_pair();
    // `CAP_OPT_NOAUDIT` is bit 1 of `opts` (`include/linux/security.h`).
    let probe = Command::new("bpftrace")
        .args([
            "-e",
            &format!(
                "kprobe:cap_capable /pid == {pid} && !(arg3 & 2)/ {{ @asked[arg2] = count(); }} \
                 kretprobe:cap_capable /pid == {pid}/ {{ @granted[retval] = count(); }} \
                 interval:s:8 {{ exit(); }}",
                pid = pair.vm_pid
            ),
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn bpftrace");
    std::thread::sleep(Duration::from_secs(1));
    for _ in 0..20 {
        assert!(matches!(call(&pair, &Request::Ping), Response::Pong { .. }));
        let _ = call(&pair, &Request::Doctor);
        let _ = call(&pair, &Request::ListVms);
    }
    let out = probe.wait_with_output().expect("bpftrace output");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("@asked["),
        "bpftrace saw no cap_capable call for pid {} at all — the probe did not attach, so this \
         test asserted nothing\nstdout={text}\nstderr={}",
        pair.vm_pid,
        String::from_utf8_lossy(&out.stderr)
    );
    let granted: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("@granted[0]"))
        .collect();
    assert!(
        granted.is_empty(),
        "the kernel granted the VM broker a capability {granted:?} while it served \
         ping/doctor/list — with CapEff empty that should be impossible, so either the drop did \
         not run or the process is root in a user namespace\n{text}"
    );
    let unexpected: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("@asked["))
        .filter(|l| !DELIBERATE_DAC_CHECKS.iter().any(|k| l.starts_with(k)))
        .collect();
    assert!(
        unexpected.is_empty(),
        "the VM broker asked the kernel for {unexpected:?} — every capability it *checks* is a \
         privileged call site that should have become a `net.*` / `virtiofsd.spawn` / pinned-descriptor verb; only the doctor's \
         deliberate DAC checks on the root-0700 Firecracker chroot base belong here\n{text}"
    );
}

/// `CAP_DAC_OVERRIDE` (1) and `CAP_DAC_READ_SEARCH` (2), the two
/// `capability.h` numbers `k7d doctor` provokes on purpose by stating
/// `/var/lib/k7d/fc` — a refusal it reports rather than a failure.
const DELIBERATE_DAC_CHECKS: [&str; 2] = ["@asked[1]", "@asked[2]"];

/// `bpftrace` is how capability bounding measured the capability table, so a node
/// without it cannot run the measurement this increment's claim rests on.
/// Installed rather than skipped: a test that quietly passes on a node
/// missing its instrument asserts nothing.
fn ensure_bpftrace() {
    if Command::new("bpftrace")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
    {
        return;
    }
    let status = Command::new("apt-get")
        .args(["install", "-y", "bpftrace"])
        .env("DEBIAN_FRONTEND", "noninteractive")
        .status()
        .expect("apt-get install bpftrace");
    assert!(status.success(), "install bpftrace: {status}");
}

// --- crash coupling --------------------------------------------------

/// Node broker killed: the VM broker must not survive it.
///
/// `PR_SET_PDEATHSIG` is the mechanism, and it has a trap the assertion
/// is aimed at — the signal is delivered when the *thread* that forked
/// exits, not when the process does. The VM broker is forked from
/// `main`'s first statement, before any thread exists, which is what
/// makes the two the same event. Something that later moved the fork
/// behind a thread would leave a uid-`k7d` process holding every VM with
/// nothing able to tear them down, and only this test would notice.
#[test]
fn test_killing_the_node_broker_takes_the_vm_broker_with_it() {
    let pair = start_pair();
    kill9(pair.node_pid);
    await_gone(
        pair.vm_pid,
        "the VM broker outlived its node broker (PDEATHSIG)",
    );
}

/// VM broker killed: the node broker releases every id and exits
/// non-zero, so systemd starts a clean pair instead of leaving half a
/// unit live (§9.2).
///
/// This is the pair with `K7D_VM_BROKER_RESTART` **off** — the shipped
/// default — and VM-broker restart must not have changed a byte of it. The
/// survival path is the next section.
#[test]
fn test_killing_the_vm_broker_makes_the_node_broker_exit_non_zero() {
    let pair = start_pair();
    kill9(pair.vm_pid);
    await_gone(pair.node_pid, "the node broker outlived its VM broker");
    // `Result` alone is not enough: `systemctl show` on a unit systemd has
    // already garbage-collected answers with the property's *default*,
    // which is `success` — indistinguishable from a clean exit. That is why
    // the unit is started without `--collect`, and why the exit code is
    // read as well.
    let result = unit_property("Result");
    let code = unit_property("ExecMainStatus");
    assert!(
        result != "success" || code != "0",
        "the unit reports Result={result:?} ExecMainStatus={code:?} after the VM broker was \
         killed — a node broker that exits 0 gives Restart=on-failure nothing to do, so half a \
         unit stays live holding TAPs, mounts and jailed pids nothing else knows about (§9.2)\n{}",
        journal()
    );
}

/// An orderly stop is not a crash: the node broker forwards `SIGTERM`,
/// keeps serving verbs while the VM broker runs `shutdown_all`, and exits
/// 0 (§9.4). Three times, because the failure this guards against was a
/// restart that looked clean once and looped on the second (`CHALLENGES`
/// #245 for the spawner's version of it).
#[test]
fn test_restarting_the_split_pair_is_not_a_crash() {
    let pair = start_pair();
    let cursor = journal_cursor();
    let mut previous = pair.node_pid;
    for round in 1..=3 {
        let status = Command::new("systemctl")
            .args(["restart", &format!("{UNIT}.service")])
            .status()
            .expect("systemctl restart");
        assert!(
            status.success(),
            "restart {round}: {status}\n{}",
            journal_after(&cursor)
        );
        // `systemctl restart` returns when the unit is active, which is
        // before the VM broker has bound anything — and the socket from
        // the previous round is still on disk, so its existence proves
        // nothing. Wait for a new main pid that answers.
        let node = wait_for_new_pair(&pair, previous, round, &cursor);
        assert_ne!(node, previous);
        previous = node;
        assert_eq!(
            unit_property("Result"),
            "success",
            "round {round}:\n{}",
            journal_after(&cursor)
        );
    }
    let log = journal_after(&cursor);
    assert!(
        !log.contains("is gone ("),
        "a plain restart was reported as a broker crash — the VM-broker watchdog fired on the \
         orderly path, which is the failure #245 had for the spawner:\n{log}"
    );
}

/// Wait until the unit has a main pid other than `previous`, that pid has
/// exactly one child, and the control socket answers.
fn wait_for_new_pair(pair: &SplitPair, previous: u32, round: u32, cursor: &str) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let node: u32 = unit_property("MainPID").parse().unwrap_or(0);
        if node != 0 && node != previous && children_of(node).len() == 1 {
            if let Ok(mut client) = Client::connect(pair.socket.to_str().expect("utf8 socket")) {
                if client.call(&Request::Ping).is_ok() {
                    return node;
                }
            }
        }
        assert!(
            Instant::now() < deadline,
            "round {round}: no new pair answering on {} within 30s\n{}",
            pair.socket.display(),
            journal_after(cursor)
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn kill9(pid: u32) {
    let status = Command::new("kill")
        .args(["-9", &pid.to_string()])
        .status()
        .expect("kill -9");
    assert!(status.success(), "kill -9 {pid}: {status}");
}

fn await_gone(pid: u32, why: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Path::new(&format!("/proc/{pid}")).exists() {
        assert!(
            Instant::now() < deadline,
            "{why}: pid {pid} is still there after 20s\n{}",
            journal()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

// --- VM-broker restart: standalone Firecracker sandboxes survive a
// VM-broker crash when `K7D_VM_BROKER_RESTART` is on ------------------

/// Three VMs, one `kill -9`, one survivor — and the survivor is the
/// **same** VM afterwards, not a lookalike.
///
/// * A Firecracker pod the way the shim makes one: `sandbox_id` set and
///   a bridge named after it. Its jail, TAP, uid lease and pinned
///   descriptors are the node broker's and stay put; the successor VM
///   broker re-adopts it out of `fc.list`.
/// * A native VM: its KVM state was the dead process's address space.
///   Released, along with its bridge.
/// * A Firecracker VM whose bridge names a cluster that is not its pod:
///   a tree member, and trees are not survived. Released, bridge and
///   all.
///
/// What proves the survivor is the same VM: the jailed pid, the chroot
/// and the published agent socket are read from `list_vms` before and
/// after and must match; the guest's `boot_id` is read *through* that
/// socket on both sides of the kill, which is the `kubectl exec`
/// survival criterion. And `reattach_sandbox` — the shim's own
/// reconnection — resolves the sandbox to that same `vm_id`.
///
/// Then the survivor is stopped through the successor, and nothing it
/// held is left behind: the jailer's cgroup, the bridge, the registry
/// entry. A re-adoption that lost a handle would leak exactly here.
#[test]
fn test_a_standalone_firecracker_sandbox_survives_a_vm_broker_kill() {
    let pair = start_pair_with_restart();
    let cursor = journal_cursor();
    let uds_timeout = Duration::from_secs(90);

    // The pod. `cluster_id == sandbox_id` is what the shim registers
    // for a networked single-VM pod, and the predicate in
    // `broker::node::survives` admits exactly that.
    let sandbox_id = "psfc".to_string();
    let (survivor, created_endpoint) = create(
        &pair,
        VmConfig {
            memory_mb: 512,
            vcpus: 1,
            backend: k7d::guest::Backend::Firecracker,
            sandbox_id: Some(sandbox_id.clone()),
            network: Some(k7d::control::NetConfig {
                cluster_id: sandbox_id.clone(),
                vm_index: None,
                pod_netns: None,
            }),
            ..VmConfig::default()
        },
        "the pod",
    );
    // The two that must not survive.
    let (native, _) = create(
        &pair,
        VmConfig {
            sandbox_id: Some("privsep-native".to_string()),
            ..VmConfig::default()
        },
        "the native VM",
    );
    let (member, _) = create(
        &pair,
        VmConfig {
            memory_mb: 512,
            vcpus: 1,
            backend: k7d::guest::Backend::Firecracker,
            sandbox_id: Some("privsep-member".to_string()),
            network: Some(k7d::control::NetConfig {
                cluster_id: "psclust".to_string(),
                vm_index: None,
                pod_netns: None,
            }),
            ..VmConfig::default()
        },
        "the tree member",
    );

    let before = vm_info(&pair, &survivor);
    let jail = before
        .jail
        .clone()
        .unwrap_or_else(|| panic!("a Firecracker VM lists no jail: {before:?}"));
    // The guest first, with a boot-length timeout: `reattach_sandbox`
    // pings the agent with a *reattach*-length one and tears down a VM
    // that does not answer, which a guest still booting does not.
    let uds_before = match created_endpoint {
        Some(k7d::guest::AgentEndpoint::FcUds { path }) => PathBuf::from(path),
        other => panic!("a Firecracker VM must publish an FcUds endpoint, got {other:?}"),
    };
    let boot_id_before = guest_boot_id(&uds_before, uds_timeout);
    let found_before = reattach(&pair, &sandbox_id);
    assert_eq!(fc_uds(&found_before), uds_before);
    let Response::SandboxFound {
        vm_index: index_before,
        ..
    } = &found_before
    else {
        unreachable!("reattach checked the variant");
    };
    let links_before = links();
    assert!(
        links_before.contains("k7-br-psfc") && links_before.contains("k7-br-psclust"),
        "both bridges must be up before the kill:\n{links_before}"
    );

    // The crash.
    let first_generation = pair.vm_pid;
    kill9(first_generation);
    let successor = wait_for_successor(&pair, first_generation, &cursor);
    assert_eq!(
        unit_property("MainPID"),
        pair.node_pid.to_string(),
        "the node broker changed pid — systemd restarted the unit instead of the node broker \
         re-forking its other half"
    );

    // Who survived, according to the successor.
    let vms = list(&pair);
    let ids: Vec<&str> = vms.iter().map(|v| v.vm_id.as_str()).collect();
    assert_eq!(
        ids,
        vec![survivor.as_str()],
        "the successor lists {ids:?}, want only the pod\n{}",
        journal_after(&cursor)
    );
    let after = &vms[0];
    assert_eq!(
        after.jail.as_ref(),
        Some(&jail),
        "the re-adopted pod is not the jail it was: before {jail:?}, after {:?}",
        after.jail
    );
    assert_eq!(after.sandbox_id.as_deref(), Some(sandbox_id.as_str()));
    assert!(
        Path::new(&format!("/proc/{}", jail.pid)).exists(),
        "the jailed Firecracker (pid {}) died with the VM broker",
        jail.pid
    );

    // Same guest, through the same socket, found the way the shim finds
    // it.
    let found = reattach(&pair, &sandbox_id);
    let Response::SandboxFound {
        vm_id: found_id,
        cluster_id: found_cluster,
        vm_index: found_index,
        ..
    } = &found
    else {
        unreachable!("fc_uds checked the variant");
    };
    assert_eq!(found_id, &survivor);
    assert_eq!(found_cluster.as_deref(), Some(sandbox_id.as_str()));
    assert_eq!(found_index, index_before, "the pod's bridge slot moved");
    let uds_after = fc_uds(&found);
    assert_eq!(
        uds_after, uds_before,
        "the agent endpoint moved across the restart"
    );
    assert_eq!(
        guest_boot_id(&uds_after, uds_timeout),
        boot_id_before,
        "the guest behind the re-adopted socket is not the guest that was there before the kill"
    );

    // The node broker said which was which, and released the rest.
    let log = journal_after(&cursor);
    for want in [
        format!("keeping vm {survivor}"),
        format!("releasing vm {native}"),
        format!("releasing vm {member}"),
        "trees are not survived".to_string(),
        "re-forking as generation 1".to_string(),
        format!("survived: {survivor}"),
    ] {
        assert!(log.contains(&want), "journal lacks {want:?}:\n{log}");
    }
    let links_after = links();
    assert!(
        links_after.contains("k7-br-psfc"),
        "the survivor's bridge went with the VM broker:\n{links_after}"
    );
    assert!(
        !links_after.contains("k7-br-psclust"),
        "the tree member's bridge outlived its tree:\n{links_after}"
    );
    for id in [&native, &member] {
        assert!(
            !Path::new("/sys/fs/cgroup/k7d").join(id).exists(),
            "released VM {id} still has a jailer cgroup"
        );
    }

    // The successor owns it: stopping it through the new VM broker
    // releases everything the old one acquired.
    match call(
        &pair,
        &Request::StopVm {
            vm_id: survivor.clone(),
        },
    ) {
        Response::Ok => {}
        other => panic!(
            "stop the re-adopted pod: {other:?}\n{}",
            journal_after(&cursor)
        ),
    }
    assert!(list(&pair).is_empty(), "stop left a VM registered");
    await_gone(jail.pid, "the jailed Firecracker outlived its StopVm");
    assert!(
        !Path::new("/sys/fs/cgroup/k7d").join(&survivor).exists(),
        "the jailer cgroup of the re-adopted pod leaked across the restart"
    );
    assert!(
        !links().contains("k7-br-psfc"),
        "the re-adopted pod's bridge leaked across the restart:\n{}",
        links()
    );
    assert!(
        Path::new(&format!("/proc/{successor}")).exists(),
        "the successor VM broker died on StopVm\n{}",
        journal_after(&cursor)
    );
}

/// A crash-looping VM broker is a failed unit, not a unit that respawns
/// forever: `RESPAWN_MAX` re-forks in `RESPAWN_WINDOW`, and the next
/// death releases everything and exits non-zero.
///
/// Each kill waits out `RESPAWN_FAST_FAIL` first, so what trips here is
/// the count and not the "died right after exec" rule — a successor
/// that is answering `ping` did start.
#[test]
fn test_four_vm_broker_kills_in_a_minute_fail_the_unit() {
    use k7d::broker::node::{RESPAWN_FAST_FAIL, RESPAWN_MAX};
    let pair = start_pair_with_restart();
    let cursor = journal_cursor();
    let started = Instant::now();
    let mut vm_pid = pair.vm_pid;
    for generation in 1..=RESPAWN_MAX {
        kill9(vm_pid);
        vm_pid = wait_for_successor(&pair, vm_pid, &cursor);
        let log = journal_after(&cursor);
        assert!(
            log.contains(&format!("re-forking as generation {generation}")),
            "no generation {generation} in the journal:\n{log}"
        );
        std::thread::sleep(RESPAWN_FAST_FAIL + Duration::from_secs(1));
    }
    assert!(
        started.elapsed() < Duration::from_secs(50),
        "the three respawns took {:?}; the fourth kill would fall outside the window and \
         test nothing",
        started.elapsed()
    );
    kill9(vm_pid);
    await_gone(
        pair.node_pid,
        "the node broker re-forked a fourth time instead of failing",
    );
    let result = unit_property("Result");
    let code = unit_property("ExecMainStatus");
    let log = journal_after(&cursor);
    assert!(
        result != "success" || code != "0",
        "Result={result:?} ExecMainStatus={code:?} after four kills — the loop must be a \
         systemd-visible failure\n{log}"
    );
    assert!(
        log.contains(&format!("already re-forked it {RESPAWN_MAX} times")),
        "the refusal must say why:\n{log}"
    );
}

/// With the flag on, `systemctl restart` and `systemctl stop` are still
/// §9.4's orderly path: `DRAINING` wins, nothing is re-forked, and the
/// exit is 0.
#[test]
fn test_an_orderly_stop_with_restart_on_does_not_respawn() {
    let pair = start_pair_with_restart();
    let cursor = journal_cursor();
    let status = Command::new("systemctl")
        .args(["restart", &format!("{UNIT}.service")])
        .status()
        .expect("systemctl restart");
    assert!(
        status.success(),
        "restart: {status}\n{}",
        journal_after(&cursor)
    );
    let node = wait_for_new_pair(&pair, pair.node_pid, 1, &cursor);
    assert_ne!(node, pair.node_pid);
    assert_eq!(unit_property("Result"), "success");

    let status = Command::new("systemctl")
        .args(["stop", &format!("{UNIT}.service")])
        .status()
        .expect("systemctl stop");
    assert!(
        status.success(),
        "stop: {status}\n{}",
        journal_after(&cursor)
    );
    await_gone(node, "the node broker did not exit on systemctl stop");
    assert_eq!(unit_property("Result"), "success");
    assert_eq!(unit_property("ExecMainStatus"), "0");
    let log = journal_after(&cursor);
    for forbidden in ["re-forking as generation", "is gone ("] {
        assert!(
            !log.contains(forbidden),
            "an orderly stop with K7D_VM_BROKER_RESTART=on {forbidden:?}:\n{log}"
        );
    }
}

fn create(
    pair: &SplitPair,
    config: VmConfig,
    what: &str,
) -> (String, Option<k7d::guest::AgentEndpoint>) {
    match call(pair, &Request::CreateVm { config }) {
        Response::VmCreated {
            vm_id,
            agent_endpoint,
            ..
        } => (vm_id, agent_endpoint),
        other => panic!("create {what} under the split: {other:?}\n{}", journal()),
    }
}

fn list(pair: &SplitPair) -> Vec<k7d::control::VmInfo> {
    match call(pair, &Request::ListVms) {
        Response::VmList { mut vms } => {
            vms.sort_by(|a, b| a.vm_id.cmp(&b.vm_id));
            vms
        }
        other => panic!("list_vms: {other:?}"),
    }
}

fn vm_info(pair: &SplitPair, vm_id: &str) -> k7d::control::VmInfo {
    list(pair)
        .into_iter()
        .find(|v| v.vm_id == vm_id)
        .unwrap_or_else(|| panic!("{vm_id} is not listed"))
}

fn reattach(pair: &SplitPair, sandbox_id: &str) -> Response {
    match call(
        pair,
        &Request::ReattachSandbox {
            sandbox_id: sandbox_id.to_string(),
        },
    ) {
        found @ Response::SandboxFound { .. } => found,
        other => panic!("reattach_sandbox({sandbox_id}): {other:?}\n{}", journal()),
    }
}

fn fc_uds(found: &Response) -> PathBuf {
    match found {
        Response::SandboxFound {
            agent_endpoint: Some(k7d::guest::AgentEndpoint::FcUds { path }),
            ..
        } => PathBuf::from(path),
        other => panic!("a Firecracker sandbox must publish an FcUds endpoint, got {other:?}"),
    }
}

fn guest_boot_id(uds: &Path, timeout: Duration) -> String {
    let mut agent = k7d::api::AgentClient::connect_fc_uds(uds, 1024, timeout)
        .unwrap_or_else(|e| panic!("dial the FC guest at {}: {e}\n{}", uds.display(), journal()));
    let out = agent
        .exec(&["cat", "/proc/sys/kernel/random/boot_id"])
        .expect("boot_id in the guest");
    let id = out.stdout.trim().to_string();
    assert!(!id.is_empty(), "empty boot_id: {out:?}");
    id
}

fn links() -> String {
    let out = Command::new("ip")
        .args(["link", "show"])
        .output()
        .expect("ip link show");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The VM broker among the node broker's children. Not `only_child_of`:
/// every jailed Firecracker is the node broker's child too, so the one
/// wanted is the one whose `comm` is `k7d`.
fn vm_broker_child_of(node_pid: u32) -> Option<u32> {
    children_of(node_pid).into_iter().find(|pid| {
        std::fs::read_to_string(format!("/proc/{pid}/comm")).is_ok_and(|comm| comm.trim() == "k7d")
    })
}

/// Wait for a VM broker other than `previous` under the **same** node
/// broker, answering on the socket — which it only does after
/// `readopt_fc_sandboxes` has run. A node broker that exits instead is
/// the failure this reports.
fn wait_for_successor(pair: &SplitPair, previous: u32, cursor: &str) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        assert!(
            Path::new(&format!("/proc/{}", pair.node_pid)).exists(),
            "the node broker exited instead of re-forking the VM broker\n{}",
            journal_after(cursor)
        );
        if let Some(pid) = vm_broker_child_of(pair.node_pid) {
            if pid != previous {
                if let Ok(mut client) = Client::connect(pair.socket.to_str().expect("utf8 socket"))
                {
                    if client.call(&Request::Ping).is_ok() {
                        return pid;
                    }
                }
            }
        }
        assert!(
            Instant::now() < deadline,
            "no successor VM broker answering on {} within 60s\n{}",
            pair.socket.display(),
            journal_after(cursor)
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

// --- §10.1(e) path validation, end to end ---------------------------

/// A share the allowlist does not cover is refused at `CreateVm`, by the
/// node broker, with the field and the index in the message.
///
/// End to end matters here because the validator is only as good as where
/// it sits. `vm.register` runs before any disk is provisioned and before
/// any network is acquired, so a refusal is a `CreateVm` error and not a
/// half-built VM that has to be torn back down — and the message is what
/// an operator gets, so it names `virtiofs[0]` rather than "permission
/// denied".
#[test]
fn test_a_share_outside_the_allowlist_is_refused_at_create() {
    let pair = start_pair();
    let response = call(
        &pair,
        &Request::CreateVm {
            config: VmConfig {
                virtiofs: vec![ShareConfig {
                    // Root-owned, outside every §5 root, and the classic
                    // target: a share of /etc is the guest reading the
                    // host's shadow file.
                    host_dir: "/etc".to_string(),
                    guest_mount: "/mnt/etc".to_string(),
                    readonly: true,
                }],
                ..VmConfig::default()
            },
        },
    );
    let Response::Error { message } = response else {
        panic!("a share of /etc must be refused, got {response:?}");
    };
    assert!(
        message.contains("virtiofs[0]"),
        "the refusal must name the field and index an operator can act on: {message}"
    );
    // Nothing was built: no VM, and the id was never registered.
    match call(&pair, &Request::ListVms) {
        Response::VmList { vms } => assert!(
            vms.is_empty(),
            "a refused CreateVm left a VM behind: {vms:?}"
        ),
        other => panic!("unexpected list response: {other:?}"),
    }
}

// --- §10.1(f) the three migrated families, end to end ----------------

/// A native VM boots under the split with a virtiofs share, a
/// virtio-blk disk and a bridge — which is the whole of the `net.*` /
/// `virtiofsd.spawn` / pinned-descriptor verb family in one assertion.
///
/// Each of the three is a different direction across the boundary and
/// none of them would work by accident:
///
/// * The **disk** is root-owned under an allowlisted root, so uid `k7d`
///   cannot open it at all. It arrives as a descriptor from `disk.open`,
///   re-opened through the `O_PATH` pin `vm.register` made.
/// * The **share** goes the other way: the VM broker binds the
///   vhost-user listener in a directory it owns and sends the *listening
///   socket* to the node broker, which execs `virtiofsd --fd 3`.
/// * The **bridge and TAP** are `CAP_NET_ADMIN` from end to end; the TAP
///   descriptor comes back over `SCM_RIGHTS` and the VM broker never
///   names a link.
///
/// The guest reaching its agent is the assertion rather than a log line:
/// a virtiofsd that never got its listener, or a `BlockBackend` opened
/// on the wrong inode, both boot far enough to print hopeful messages.
#[test]
fn test_a_native_vm_boots_under_the_split_with_a_share_a_disk_and_a_bridge() {
    let pair = start_pair();
    let uid = passwd_uid("k7d");

    // A share under an allowlisted root, owned by the VM broker because
    // the guest writes to it.
    //
    // Directly under `/var/lib/k7d` and not under the pair's tree root:
    // `/var/lib/k7d/trees` is a *symlink* onto the loop-mounted XFS
    // (`packaging/k7d-account.sh`), and §5 resolves a registered path
    // with `RESOLVE_NO_SYMLINKS`, so a share there is refused at
    // `vm.register` — correctly, and with nothing to do with this test.
    let share = PathBuf::from("/var/lib/k7d/privsep-share");
    std::fs::create_dir_all(&share).expect("mkdir share");
    chown_to(&share, uid);

    // And a disk that is deliberately **not**: root-owned 0600 under
    // /var/lib/k7d/images is exactly the shim's overlay slot, and the
    // negative below proves uid k7d cannot open it directly.
    std::fs::create_dir_all("/var/lib/k7d/images").expect("mkdir images");
    let disk = PathBuf::from("/var/lib/k7d/images/privsep-test.img");
    let _ = std::fs::remove_file(&disk);
    std::fs::write(&disk, vec![0u8; 4 * 1024 * 1024]).expect("write disk image");
    std::fs::set_permissions(&disk, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .expect("chmod 0600 the disk");
    let denied = as_vm_broker(&["dd", "if=/dev/null", &format!("of={}", disk.display())]);
    assert!(
        !denied.status.success(),
        "uid k7d could open {} directly — the disk this test relies on disk.open for is not \
         actually root-only",
        disk.display()
    );

    let response = call(
        &pair,
        &Request::CreateVm {
            config: VmConfig {
                virtiofs: vec![ShareConfig {
                    host_dir: share.display().to_string(),
                    guest_mount: "/mnt/state".to_string(),
                    readonly: false,
                }],
                block_devices: vec![k7d::control::BlockDeviceConfig {
                    host_path: disk.display().to_string(),
                    readonly: false,
                    guest_mount: None,
                    fstype: None,
                }],
                network: Some(k7d::control::NetConfig {
                    cluster_id: "privsep".to_string(),
                    vm_index: None,
                    pod_netns: None,
                }),
                ..VmConfig::default()
            },
        },
    );
    let (vm_id, guest_cid) = match response {
        Response::VmCreated {
            vm_id, guest_cid, ..
        } => (vm_id, guest_cid),
        other => panic!("create under the split failed: {other:?}\n{}", journal()),
    };

    // The guest agent answering is what proves the three families
    // actually delivered: the share's virtiofsd, the disk's descriptor
    // and the TAP are all on the path to a booted guest, and each of
    // them fails the boot rather than the answer.
    let mut agent = k7d::api::AgentClient::connect_vsock(guest_cid, Duration::from_secs(90))
        .unwrap_or_else(|e| panic!("connect to the split VM's agent: {e}\n{}", journal()));
    let mounts = agent
        .exec(&["cat", "/proc/mounts"])
        .expect("read the guest's mount table");
    assert!(
        mounts.stdout.contains("virtiofs"),
        "the guest has no virtiofs mount — the listener never reached virtiofsd:\n{}",
        mounts.stdout
    );
    let disks = agent
        .exec(&["cat", "/proc/partitions"])
        .expect("partitions");
    assert!(
        disks.stdout.contains("vda"),
        "the guest has no virtio-blk device — disk.open did not deliver:\n{}",
        disks.stdout
    );

    // The bridge is the node broker's, and the VM broker holds only the
    // TAP descriptor it was sent.
    let links = Command::new("ip")
        .args(["link", "show"])
        .output()
        .expect("ip link show");
    let links = String::from_utf8_lossy(&links.stdout);
    assert!(
        links.contains("k7-br-privsep"),
        "no bridge for the tree the VM joined:\n{links}"
    );

    match call(
        &pair,
        &Request::StopVm {
            vm_id: vm_id.clone(),
        },
    ) {
        Response::Ok => {}
        other => panic!("stop {vm_id}: {other:?}"),
    }
    let _ = std::fs::remove_file(&disk);
    let _ = std::fs::remove_dir_all(&share);
}

/// The delegated subtree is the VM broker's and the jailer's is not.
///
/// Both halves are load-bearing. `<service>/vm` has to be writable or the
/// fork hot path would need a round trip it cannot afford (§4.3);
/// `/sys/fs/cgroup/k7d` has to stay root-only or the delegation gave away
/// the thing it was carefully scoped around, and it is the precondition
/// §10.4 asserts before every fuzz run.
#[test]
fn test_the_delegated_cgroup_is_the_vm_brokers_and_the_jailers_is_not() {
    let pair = start_pair();
    let vm_cgroup = cgroup_of(pair.vm_pid);
    assert!(
        vm_cgroup.ends_with(&format!("/{}", k7d::broker::DELEGATED_SUBDIR)),
        "the VM broker is in {vm_cgroup}, want a path ending in /{}",
        k7d::broker::DELEGATED_SUBDIR
    );
    let node_cgroup = cgroup_of(pair.node_pid);
    assert_ne!(
        node_cgroup, vm_cgroup,
        "both brokers are in one cgroup — the service cgroup cannot enable a domain controller \
         with a member process of its own"
    );

    let dir = Path::new("/sys/fs/cgroup").join(vm_cgroup.trim_start_matches('/'));
    let owner = std::fs::metadata(&dir)
        .map(|m| std::os::unix::fs::MetadataExt::uid(&m))
        .unwrap_or_else(|e| panic!("stat {}: {e}", dir.display()));
    assert_eq!(
        owner,
        passwd_uid("k7d"),
        "{} is owned by uid {owner}, want the VM broker's",
        dir.display()
    );
    let controllers =
        std::fs::read_to_string(dir.join("cgroup.controllers")).expect("cgroup.controllers");
    for want in k7d::broker::DELEGATED_CONTROLLERS {
        assert!(
            controllers.split_whitespace().any(|c| c == *want),
            "{} has controllers [{}], missing {want} — the unit needs Delegate=",
            dir.display(),
            controllers.trim()
        );
    }
    // Writable by the delegatee, which is the whole claim.
    let probe = as_vm_broker(&["mkdir", dir.join("privsep-probe").to_str().expect("utf8")]);
    assert!(
        probe.status.success(),
        "uid k7d cannot mkdir in its own delegated subtree: {}",
        String::from_utf8_lossy(&probe.stderr)
    );
    let _ = std::fs::remove_dir(dir.join("privsep-probe"));

    // The jailer's parent cgroup is the negative.
    std::fs::create_dir_all("/sys/fs/cgroup/k7d").expect("mkdir /sys/fs/cgroup/k7d");
    let denied = as_vm_broker(&["mkdir", "/sys/fs/cgroup/k7d/privsep-probe"]);
    assert!(
        !denied.status.success(),
        "uid k7d could create under /sys/fs/cgroup/k7d — the jailer's cgroup tree was delegated \
         by accident"
    );
    // And the two operations the node broker owns outright.
    for argv in [
        vec!["mount", "--bind", "/tmp", "/tmp"],
        vec!["ip", "tuntap", "add", "dev", "k7privsep0", "mode", "tap"],
    ] {
        let out = as_vm_broker(&argv);
        assert!(
            !out.status.success(),
            "uid k7d could run {argv:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

// --- §4.4 the Firecracker family, end to end -------------------------

/// A Firecracker VM boots under the split, forks, and every privileged
/// half of it happened in the other process — which is the whole of
/// `fc.*` verbs and `K7D_PRIVSEP` on in one assertion.
///
/// The jail is the hardest of the families to get right because the VM
/// broker has no usable *name* for any of it: `/var/lib/k7d/fc` is
/// `0700` root, so every ancestor is closed to uid `k7d` and every path
/// it uses is `/proc/self/fd/<n>/…` off the `O_PATH` descriptor
/// `fc.spawn` sent back. Four things have to line up for the agent to
/// answer, and none of them would by accident:
///
/// * `<root>` and `<root>/run` re-opened to group `k7d` *after* the
///   jailer's own `chmod 0700; chown jail:jail` (`broker::jail`).
/// * The jailer spawned with a `0007` umask, plus the setgid bit on
///   `run/`, so `v.sock` — bound minutes later by the VM broker's `PUT
///   /vsock`, when no verb is in flight — comes out `srwxrwx---
///   jail:k7d` and can be *connected to* (which needs **write**).
/// * The fork child's jail staged from the parent's point by the node
///   broker, in the one `fc.spawn` round trip the hot path allows.
/// * The UDS path published to a third process being the real one and
///   not this process's magic link (CHALLENGES #248) — which is what
///   the agent connection below actually exercises, since the test
///   dials it from outside the pair.
#[test]
fn test_a_firecracker_vm_boots_and_forks_under_the_split() {
    let pair = start_pair();
    let response = call(
        &pair,
        &Request::CreateVm {
            config: VmConfig {
                memory_mb: 512,
                vcpus: 1,
                backend: k7d::guest::Backend::Firecracker,
                ..VmConfig::default()
            },
        },
    );
    let (vm_id, endpoint) = match response {
        Response::VmCreated {
            vm_id,
            agent_endpoint,
            ..
        } => (vm_id, agent_endpoint),
        other => panic!(
            "create a Firecracker VM under the split: {other:?}\n{}",
            journal()
        ),
    };
    let uds = match endpoint {
        Some(k7d::guest::AgentEndpoint::FcUds { path }) => PathBuf::from(path),
        other => panic!("a Firecracker VM must publish an FcUds endpoint, got {other:?}"),
    };

    // Everything privileged about the jail is the node broker's. The
    // uid the jailer dropped to is neither root's nor `k7d`'s, the
    // sockets are group `k7d` and mode `0660`, and the cgroup the
    // jailer made is under the root-only tree.
    let jail_uid = owner_uid(&uds);
    let broker_uid = passwd_uid("k7d");
    assert!(
        jail_uid != 0 && jail_uid != broker_uid,
        "{} is owned by uid {jail_uid} — the jailer did not drop to a lease uid",
        uds.display()
    );
    for socket in [uds.clone(), uds.with_file_name("firecracker.socket")] {
        let meta =
            std::fs::metadata(&socket).unwrap_or_else(|e| panic!("stat {}: {e}", socket.display()));
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            meta.gid(),
            group_gid("k7d"),
            "{} is group {} — the VM broker cannot connect to a socket it is not in the group \
             of, and `chown` is root's",
            socket.display(),
            meta.gid()
        );
        // Group **write** specifically: `connect(2)` on a Unix socket
        // is a write access check, which is why the default `0022`
        // umask (`srwxr-xr-x`) is not enough and `0007` is.
        assert!(
            meta.mode() & 0o020 != 0,
            "{} is mode {:o} — connecting to a Unix socket needs write on it, so the jailer's \
             umask (fc::spawn::JAIL_UMASK) or the setgid bit on run/ is wrong",
            socket.display(),
            meta.mode() & 0o777
        );
    }

    // The agent answering is the assertion: it is dialled from *this*
    // process, over the path the daemon published, through a socket
    // Firecracker bound inside a chroot neither of us can name.
    let mut agent = k7d::api::AgentClient::connect_fc_uds(&uds, 1024, Duration::from_secs(90))
        .unwrap_or_else(|e| {
            panic!(
                "dial the split FC guest at {}: {e}\n{}",
                uds.display(),
                journal()
            )
        });
    let uname = agent.exec(&["uname", "-r"]).expect("uname in the guest");
    assert!(!uname.stdout.trim().is_empty(), "empty uname: {uname:?}");

    // And the jailer's cgroup is in the tree uid `k7d` was deliberately
    // not delegated, which is why `--parent-cgroup` stayed the node
    // broker's.
    let cgroup = Path::new("/sys/fs/cgroup/k7d").join(&vm_id);
    assert!(
        cgroup.is_dir(),
        "no jailer cgroup at {} — the node broker did not make it",
        cgroup.display()
    );

    // A fork: one `fc.spawn` with `restore_from: Point`, staged by the
    // node broker out of the parent's jail. The child inherits the
    // parent's read-only images without naming a single path.
    let (child_id, child_uds) = match call(
        &pair,
        &Request::ForkVm {
            vm_id: vm_id.clone(),
            sandbox_id: None,
            dilation: None,
        },
    ) {
        Response::VmForked {
            vm_id,
            agent_endpoint: Some(k7d::guest::AgentEndpoint::FcUds { path }),
            ..
        } => (vm_id, PathBuf::from(path)),
        other => panic!("fork under the split: {other:?}\n{}", journal()),
    };
    let mut child_agent =
        k7d::api::AgentClient::connect_fc_uds(&child_uds, 1024, Duration::from_secs(90))
            .unwrap_or_else(|e| {
                panic!(
                    "dial the forked guest at {}: {e}\n{}",
                    child_uds.display(),
                    journal()
                )
            });
    let child_uname = child_agent
        .exec(&["uname", "-r"])
        .expect("uname in the forked guest");
    assert_eq!(
        child_uname.stdout, uname.stdout,
        "the fork child is not running the kernel it was forked from: {child_uname:?}"
    );

    for id in [child_id, vm_id] {
        match call(&pair, &Request::StopVm { vm_id: id.clone() }) {
            Response::Ok => {}
            other => panic!("stop {id}: {other:?}"),
        }
    }
}

fn owner_uid(path: &Path) -> u32 {
    std::fs::metadata(path)
        .map(|m| std::os::unix::fs::MetadataExt::uid(&m))
        .unwrap_or_else(|e| panic!("stat {}: {e}", path.display()))
}

fn cgroup_of(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .unwrap_or_else(|e| panic!("read /proc/{pid}/cgroup: {e}"))
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .expect("a cgroup v2 line")
        .trim()
        .to_string()
}
