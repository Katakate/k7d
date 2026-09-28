//! Host readiness checks for k7d (`doctor`).
//!
//! Four checks, all loud: `/dev/kvm`, `/dev/vhost-vsock`, `/dev/net/tun`,
//! and cgroup v2. Used by the `k7d doctor` CLI, the `doctor` control
//! verb, and `k7d quickstart`. The primitive freeze is lifted for
//! this verb only — it reports host state; it does not create VMs.
//!
//! A fifth group reports the Firecracker backend: which
//! binaries are installed, their digests, and whether the jailer chroot
//! base can hold hard links of the guest and reflinks of a disk. Those
//! are reported separately and do **not** decide [`Report::ok`]: a node
//! that only ever runs `backend: native` VMs is a healthy node, and a
//! `doctor` that failed on a backend nobody enabled would be noise.
//!
//! A sixth group reports **hardening** (capability bounding): `CapBnd`,
//! `NoNewPrivs`, whether `/usr` is writable, seccomp mode, the helper
//! spawner's pid and its own seccomp mode (pre-seccomp helper
//! spawner — the daemon's filter is only half the claim now), and the
//! control socket. `weak` is
//! not an error — an operator running the
//! unhardened unit (or `k7d doctor` from a shell, not the daemon)
//! must still get `doctor: ok`.

use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::Path;

use sha2::{Digest, Sha256};

/// Linux capability bits named in `packaging/k7d.service.in`
/// `CapabilityBoundingSet=` (capability bounding). Order matches the unit.
pub const EXPECTED_CAPBND_NAMES: &[&str] = &[
    "CAP_SYS_ADMIN",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_SETUID",
    "CAP_SETGID",
    "CAP_SETPCAP",
    "CAP_SYS_CHROOT",
    "CAP_SYS_RESOURCE",
    "CAP_MKNOD",
    "CAP_SETFCAP",
    "CAP_CHOWN",
    "CAP_KILL",
    "CAP_SYS_PTRACE",
    "CAP_FSETID",
    "CAP_FOWNER",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
];

/// `CapBnd` mask matching [`EXPECTED_CAPBND_NAMES`]. Shared with the
/// integration test that reads the running daemon's `/proc/<pid>/status`.
pub const EXPECTED_CAPBND: u64 = capbnd_mask(EXPECTED_CAPBND_NAMES);

/// One named host check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// Stable name (`kvm`, `vhost_vsock`, `tun`, `cgroup_v2`).
    pub name: &'static str,
    /// Whether the check passed.
    pub ok: bool,
    /// Path or reason — always populated so a failure is readable.
    pub detail: String,
}

/// Full doctor report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Checks in display order. These decide [`Report::ok`].
    pub checks: Vec<Check>,
    /// Firecracker backend checks — advisory (see the module docs).
    pub fc: Vec<Check>,
    /// systemd hardening (capability bounding). Advisory: `ok`/`weak`, never `FAIL`.
    pub hardening: Vec<Check>,
    /// Privilege separation (node broker / VM broker). Advisory, same as `hardening`:
    /// the split is opt-in while the network and Firecracker verb
    /// families are still node-broker `ENOSYS`, so a node running one
    /// root process is a supported configuration and must not read as a
    /// failure — it reads as `weak`, which is exactly what it is.
    pub privsep: Vec<Check>,
    /// `/sys/kernel/mm/ksm/run`, read only. `None` when the kernel has
    /// no KSM. Does not decide [`Report::ok`].
    pub ksm_run: Option<u32>,
}

impl Report {
    /// True when every check passed.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.checks.iter().all(|c| c.ok)
    }

    /// `/dev/kvm` result.
    #[must_use]
    pub fn kvm(&self) -> bool {
        self.named("kvm")
    }

    /// `/dev/vhost-vsock` result.
    #[must_use]
    pub fn vhost_vsock(&self) -> bool {
        self.named("vhost_vsock")
    }

    /// `/dev/net/tun` result.
    #[must_use]
    pub fn tun(&self) -> bool {
        self.named("tun")
    }

    /// cgroup v2 result.
    #[must_use]
    pub fn cgroup_v2(&self) -> bool {
        self.named("cgroup_v2")
    }

    /// Host `ksmd` state from `/sys/kernel/mm/ksm/run`.
    ///
    /// `Some(1)` means ksmd is scanning. k7d never writes that file.
    #[must_use]
    pub fn ksm_run(&self) -> Option<u32> {
        self.ksm_run
    }

    fn named(&self, name: &str) -> bool {
        self.checks
            .iter()
            .find(|c| c.name == name)
            .is_some_and(|c| c.ok)
    }

    /// One line per check, plus a summary. For the CLI and the socket
    /// `details` field. Firecracker lines are marked `warn` rather than
    /// `FAIL` because they do not decide [`Report::ok`]. Hardening lines
    /// are `ok`/`weak` and follow a `hardening:` header.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        let required = self.checks.iter().map(|c| {
            let mark = if c.ok { "ok" } else { "FAIL" };
            format!("{mark:4}  {}  {}", c.name, c.detail)
        });
        let firecracker = self.fc.iter().map(|c| {
            let mark = if c.ok { "ok" } else { "warn" };
            format!("{mark:4}  {}  {}", c.name, c.detail)
        });
        let mut out: Vec<String> = required.chain(firecracker).collect();
        if !self.hardening.is_empty() {
            out.push("hardening:".to_string());
            out.extend(self.hardening.iter().map(|c| {
                let mark = if c.ok { "ok" } else { "weak" };
                format!("{mark:4}  {}  {}", c.name, c.detail)
            }));
        }
        if !self.privsep.is_empty() {
            out.push("privsep:".to_string());
            out.extend(self.privsep.iter().map(|c| {
                let mark = if c.ok { "ok" } else { "weak" };
                format!("{mark:4}  {}  {}", c.name, c.detail)
            }));
        }
        out.push(ksmd_line(self.ksm_run));
        out
    }
}

/// One advisory line: whether host `ksmd` is scanning. Not a `checks`
/// entry, so a stopped ksmd does not fail `doctor`.
fn ksmd_line(run: Option<u32>) -> String {
    let (mark, detail) = match run {
        Some(1) => (
            "ok",
            "running (run=1); same-tenant only — k7d does not start ksmd",
        ),
        Some(0) => (
            "warn",
            "stopped (run=0); opt-in guest KSM stays idle until an operator starts ksmd",
        ),
        Some(2) => (
            "warn",
            "unmerging (run=2); k7d does not write /sys/kernel/mm/ksm",
        ),
        Some(v) => return format!("warn  ksmd  /sys/kernel/mm/ksm/run={v}"),
        None => (
            "warn",
            "no /sys/kernel/mm/ksm/run (kernel built without KSM)",
        ),
    };
    format!("{mark:4}  ksmd  {detail}")
}

/// Run the four host checks.
#[must_use]
pub fn run() -> Report {
    Report {
        checks: vec![
            check_char_device("kvm", "/dev/kvm"),
            check_char_device("vhost_vsock", "/dev/vhost-vsock"),
            check_char_device("tun", "/dev/net/tun"),
            check_cgroup_v2(),
        ],
        fc: fc_checks(),
        hardening: hardening_checks(),
        privsep: privsep_checks(),
        ksm_run: crate::ksm::host_ksmd_run(),
    }
}

/// Privilege separation (node broker / VM broker).
///
/// Read from the host rather than from this process: `k7d doctor` is a
/// separate root invocation, so everything here is a `/proc`, `stat` or
/// `/sys/fs/cgroup` read about the *running* pair. That is the point —
/// the daemon claiming it dropped privileges is the claim being checked.
#[must_use]
pub fn privsep_checks() -> Vec<Check> {
    vec![
        check_privsep_mode(),
        check_vm_broker_account(),
        check_vhost_vsock_group(),
        check_delegated_cgroup(),
        check_channels(),
    ]
}

fn check_privsep_mode() -> Check {
    match crate::broker::enabled() {
        Ok(true) => Check {
            name: "mode",
            ok: true,
            detail: "K7D_PRIVSEP=on — node broker (root) + VM broker (uid k7d)".to_string(),
        },
        Ok(false) => Check {
            name: "mode",
            ok: false,
            detail: "K7D_PRIVSEP off — one root process, as before privilege separation"
                .to_string(),
        },
        Err(e) => Check {
            name: "mode",
            ok: false,
            detail: e,
        },
    }
}

/// The account and its `kvm` membership, which is what carries `/dev/kvm`
/// and `/dev/vhost-vsock` to a process with no capabilities at all.
fn check_vm_broker_account() -> Check {
    let user = crate::broker::VM_BROKER_USER;
    let Some(passwd) = fs::read_to_string("/etc/passwd").ok().and_then(|t| {
        t.lines()
            .find(|l| l.starts_with(&format!("{user}:")))
            .map(str::to_string)
    }) else {
        return Check {
            name: "account",
            ok: false,
            detail: format!(
                "no {user} account — packaging/k7d-account.sh (install.sh, \
                 your node provisioning) creates it"
            ),
        };
    };
    let uid = passwd.split(':').nth(2).unwrap_or("?");
    let in_kvm = fs::read_to_string("/etc/group").is_ok_and(|t| {
        t.lines()
            .filter(|l| l.starts_with(&format!("{}:", crate::broker::KVM_GROUP)))
            .any(|l| {
                l.rsplit(':')
                    .next()
                    .is_some_and(|members| members.split(',').any(|m| m.trim() == user))
            })
    });
    Check {
        name: "account",
        ok: in_kvm,
        detail: if in_kvm {
            format!("{user} uid={uid}, member of {}", crate::broker::KVM_GROUP)
        } else {
            format!(
                "{user} uid={uid} is NOT in group {} — the VM broker cannot open /dev/kvm",
                crate::broker::KVM_GROUP
            )
        },
    }
}

fn check_vhost_vsock_group() -> Check {
    let path = "/dev/vhost-vsock";
    let Ok(meta) = fs::metadata(path) else {
        return Check {
            name: "vhost_vsock_perms",
            ok: false,
            detail: format!("{path} is missing (modprobe vhost_vsock)"),
        };
    };
    let mode = meta.permissions().mode() & 0o777;
    let gid = meta.gid();
    let want_gid = group_gid(crate::broker::KVM_GROUP);
    let ok = mode & 0o060 == 0o060 && Some(gid) == want_gid;
    Check {
        name: "vhost_vsock_perms",
        ok,
        detail: if ok {
            format!("{path} gid={gid} mode={mode:04o} (60-k7d.rules applied)")
        } else {
            format!(
                "{path} gid={gid} mode={mode:04o} — want group {} with g+rw; install \
                 packaging/60-k7d.rules",
                crate::broker::KVM_GROUP
            )
        },
    }
}

/// `<service cgroup>/vm`, owned by `k7d`, with the controllers the fork
/// hot path writes. This is the check that would catch systemd taking
/// the subtree back because `Delegate=` went missing from the unit.
fn check_delegated_cgroup() -> Check {
    let Ok(service) = crate::cgroup::self_cgroup_dir() else {
        return Check {
            name: "delegated_cgroup",
            ok: false,
            detail: "no cgroup v2 path for this process".to_string(),
        };
    };
    // `k7d doctor` runs outside the unit, so the subtree is looked for
    // under the service cgroup rather than under this process's.
    let candidates = [
        service.join(crate::broker::DELEGATED_SUBDIR),
        Path::new("/sys/fs/cgroup/system.slice/k7d.service").join(crate::broker::DELEGATED_SUBDIR),
    ];
    let Some(dir) = candidates.iter().find(|p| p.is_dir()) else {
        return Check {
            name: "delegated_cgroup",
            ok: false,
            detail: format!(
                "no {} subtree under {} — the node broker creates it at startup",
                crate::broker::DELEGATED_SUBDIR,
                service.display()
            ),
        };
    };
    let owner = fs::metadata(dir).ok().map(|m| m.uid());
    let want = passwd_uid(crate::broker::VM_BROKER_USER);
    let controllers = fs::read_to_string(dir.join("cgroup.controllers"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let missing: Vec<&str> = crate::broker::DELEGATED_CONTROLLERS
        .iter()
        .copied()
        .filter(|c| !controllers.split_whitespace().any(|got| got == *c))
        .collect();
    let ok = owner.is_some() && owner == want && missing.is_empty();
    Check {
        name: "delegated_cgroup",
        ok,
        detail: format!(
            "{} owner={} controllers=[{controllers}]{}",
            dir.display(),
            owner.map_or_else(|| "?".to_string(), |u| u.to_string()),
            if missing.is_empty() {
                String::new()
            } else {
                format!(" MISSING {missing:?} — unit needs Delegate=")
            }
        ),
    }
}

/// Channel-pool pressure (§3.3). Zero in a `k7d doctor` process, which
/// has no channels of its own; the number that matters is the daemon's,
/// over the socket's `details`.
fn check_channels() -> Check {
    let (in_use, high_water, max) = crate::broker::client::channel_stats();
    Check {
        name: "channels",
        ok: high_water < max,
        detail: format!("in-use={in_use} high-water={high_water} max={max}"),
    }
}

/// Numeric id of `name` in a colon-separated account database. Parsed
/// rather than looked up through NSS: `doctor` must answer the same on a
/// node whose name service is down as on one whose is up.
fn database_id(file: &str, name: &str) -> Option<u32> {
    fs::read_to_string(file)
        .ok()?
        .lines()
        .find(|l| l.starts_with(&format!("{name}:")))
        .and_then(|l| l.split(':').nth(2))
        .and_then(|f| f.parse().ok())
}

fn group_gid(name: &str) -> Option<u32> {
    database_id("/etc/group", name)
}

fn passwd_uid(name: &str) -> Option<u32> {
    database_id("/etc/passwd", name)
}

/// Firecracker backend checks: the two pinned binaries with
/// the version and sha256 actually on disk, and the jailer chroot base.
///
/// `/dev/kvm` is not repeated here — it is a required check above and
/// Firecracker needs exactly the same device.
#[must_use]
pub fn fc_checks() -> Vec<Check> {
    vec![
        check_fc_binary("fc_firecracker", "/usr/local/bin/firecracker"),
        check_fc_binary("fc_jailer", "/usr/local/bin/jailer"),
        check_fc_chroot_base(),
        check_fc_fork_mode(),
        check_fc_clock_realtime(),
    ]
}

/// Which `snapshot_type` FC fork points are taken with
/// (`K7D_FC_FORK_SNAPSHOT`). Reported so a node pinned
/// to `full` around an upstream Diff regression says so on inspection
/// instead of only in a startup log line nobody kept.
fn check_fc_fork_mode() -> Check {
    match crate::fc::snapshot::fork_mode() {
        Ok(mode) => Check {
            name: "fc_fork_mode",
            ok: true,
            detail: format!("{} (K7D_FC_FORK_SNAPSHOT)", mode.env_name()),
        },
        Err(e) => Check {
            name: "fc_fork_mode",
            ok: false,
            detail: e.to_string(),
        },
    }
}

/// `LoadSnapshot { clock_realtime: true }` needs `KVM_CLOCK_REALTIME`
/// (host kernel ≥ 5.16); without it a child of an old restore point
/// wakes up with its clock where the point left it.
fn check_fc_clock_realtime() -> Check {
    let release = kernel_release();
    let (ok, detail) = match parse_kernel_version(&release) {
        Some((major, minor)) if (major, minor) >= (5, 16) => {
            (true, format!("kernel {release} ≥ 5.16 (KVM_CLOCK_REALTIME)"))
        }
        Some(_) => (
            false,
            format!("kernel {release} < 5.16 — no KVM_CLOCK_REALTIME; FC fork children keep the snapshot's clock"),
        ),
        None => (false, format!("cannot parse kernel release {release:?}")),
    };
    Check {
        name: "fc_clock_realtime",
        ok,
        detail,
    }
}

fn kernel_release() -> String {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// `(major, minor)` of a `uname -r` string such as `6.8.0-45-generic`.
fn parse_kernel_version(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.split(|c: char| !c.is_ascii_digit());
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// One pinned binary: present, executable, its sha256, and — for
/// Firecracker itself — the version it reports.
fn check_fc_binary(name: &'static str, path: &str) -> Check {
    let p = Path::new(path);
    let Ok(meta) = fs::metadata(p) else {
        return Check {
            name,
            ok: false,
            detail: format!("{path} missing — run utils/install-firecracker.sh"),
        };
    };
    if meta.permissions().mode() & 0o111 == 0 {
        return Check {
            name,
            ok: false,
            detail: format!("{path} is not executable"),
        };
    }
    let resolved = fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let digest = match fs::read(&resolved) {
        Ok(bytes) => sha256_hex(&bytes),
        Err(e) => {
            return Check {
                name,
                ok: false,
                detail: format!("{}: {e}", resolved.display()),
            }
        }
    };
    Check {
        name,
        ok: true,
        detail: format!("{} sha256={digest}", resolved.display()),
    }
}

/// The jailer chroot base: where it is, what filesystem it is on, and
/// whether that filesystem can reflink (staged disks need it; a
/// hard-linked kernel does not).
fn check_fc_chroot_base() -> Check {
    let base = crate::fc::stage::chroot_base();
    if !base.is_dir() {
        return Check {
            name: "fc_chroot_base",
            ok: false,
            detail: format!(
                "{} missing — created by your node provisioning or the daemon",
                base.display()
            ),
        };
    }
    let reflink = match crate::disks::assert_reflink_capable(&base) {
        Ok(()) => "reflink=yes".to_string(),
        Err(e) => format!("reflink=no ({e})"),
    };
    Check {
        name: "fc_chroot_base",
        ok: true,
        detail: format!("{} {reflink}", base.display()),
    }
}

/// Print the report to stdout. Returns the process exit code (0 = all ok).
#[must_use]
pub fn print_and_exit_code(report: &Report) -> i32 {
    for line in report.lines() {
        println!("{line}");
    }
    if report.ok() {
        println!("doctor: ok — host can run k7d");
        0
    } else {
        println!("doctor: FAIL — fix the checks above before starting k7d");
        1
    }
}

const fn cap_bit(name: &[u8]) -> u64 {
    match name {
        b"CAP_CHOWN" => 1 << 0,
        b"CAP_DAC_OVERRIDE" => 1 << 1,
        b"CAP_DAC_READ_SEARCH" => 1 << 2,
        b"CAP_FOWNER" => 1 << 3,
        b"CAP_FSETID" => 1 << 4,
        b"CAP_KILL" => 1 << 5,
        b"CAP_SETGID" => 1 << 6,
        b"CAP_SETUID" => 1 << 7,
        b"CAP_SETPCAP" => 1 << 8,
        b"CAP_NET_ADMIN" => 1 << 12,
        b"CAP_NET_RAW" => 1 << 13,
        b"CAP_SYS_CHROOT" => 1 << 18,
        b"CAP_SYS_PTRACE" => 1 << 19,
        b"CAP_SYS_ADMIN" => 1 << 21,
        b"CAP_SYS_NICE" => 1 << 23,
        b"CAP_SYS_RESOURCE" => 1 << 24,
        b"CAP_MKNOD" => 1 << 27,
        b"CAP_SETFCAP" => 1 << 31,
        _ => panic!("unknown capability name in EXPECTED_CAPBND_NAMES"),
    }
}

const fn capbnd_mask(names: &[&str]) -> u64 {
    let mut mask = 0u64;
    let mut i = 0;
    while i < names.len() {
        mask |= cap_bit(names[i].as_bytes());
        i += 1;
    }
    mask
}

/// `CapBnd` of `/proc/<pid>/status`. Used by the capability-bounding integration test.
pub fn capbnd_of(pid: u32) -> Result<u64, String> {
    let text = fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|e| format!("read /proc/{pid}/status: {e}"))?;
    parse_hex_field(&text, "CapBnd").ok_or_else(|| format!("no CapBnd in /proc/{pid}/status"))
}

fn hardening_checks() -> Vec<Check> {
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    vec![
        check_capbnd(&status),
        check_nonewprivs(&status),
        check_usr_ro(),
        check_seccomp(&status),
        check_spawner(),
        check_socket(),
    ]
}

fn check_capbnd(status: &str) -> Check {
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        return check_capbnd_as_vm_broker(status);
    }
    match parse_hex_field(status, "CapBnd") {
        Some(got) if got == EXPECTED_CAPBND => Check {
            name: "capbnd",
            ok: true,
            detail: format!("{got:016x} (matches EXPECTED_CAPBND)"),
        },
        Some(got) => Check {
            name: "capbnd",
            ok: false,
            detail: format!("{got:016x} want {EXPECTED_CAPBND:016x} (unhardened or extra cap)"),
        },
        None => Check {
            name: "capbnd",
            ok: false,
            detail: "CapBnd missing from /proc/self/status".to_string(),
        },
    }
}

/// The same claim seen from the unprivileged half.
///
/// Asked over the control socket with the split on, `hardening_checks`
/// runs in the VM broker, whose bounding set is empty *by construction*
/// — dropping it is the point of privilege separation, so reporting the capability-bounding mask
/// as missing was the check reading its own success as a regression.
/// The mask still has to exist somewhere, so this asserts both halves:
/// ∅ here, and `EXPECTED_CAPBND` on the parent, which is the node
/// broker (`PPid` of the VM broker is the only process that could have
/// forked it).
fn check_capbnd_as_vm_broker(status: &str) -> Check {
    let mine = parse_hex_field(status, "CapBnd");
    let ppid = parse_dec_field(status, "PPid");
    let theirs = ppid.and_then(|p| capbnd_of(u32::try_from(p).unwrap_or(0)).ok());
    let ok = mine == Some(0) && theirs == Some(EXPECTED_CAPBND);
    Check {
        name: "capbnd",
        ok,
        detail: format!(
            "{} as uid {} (VM broker — ∅ is the point); node broker pid {} has {}, want \
             {EXPECTED_CAPBND:016x}",
            mine.map_or_else(|| "missing".to_string(), |m| format!("{m:016x}")),
            // SAFETY: `geteuid` takes no arguments and cannot fail.
            unsafe { libc::geteuid() },
            ppid.map_or_else(|| "?".to_string(), |p| p.to_string()),
            theirs.map_or_else(|| "?".to_string(), |m| format!("{m:016x}")),
        ),
    }
}

fn check_nonewprivs(status: &str) -> Check {
    match parse_dec_field(status, "NoNewPrivs") {
        Some(1) => Check {
            name: "nonewprivs",
            ok: true,
            detail: "1".to_string(),
        },
        Some(v) => Check {
            name: "nonewprivs",
            ok: false,
            detail: format!("{v} (want 1 — NoNewPrivileges=yes / ProtectSystem)"),
        },
        None => Check {
            name: "nonewprivs",
            ok: false,
            detail: "NoNewPrivs missing from /proc/self/status".to_string(),
        },
    }
}

fn check_usr_ro() -> Check {
    let access_w = path_access_w_ok("/usr");
    match path_is_readonly("/usr") {
        Ok(true) => Check {
            name: "usr_ro",
            ok: true,
            detail: "/usr ST_RDONLY (ProtectSystem=strict)".to_string(),
        },
        Ok(false) if !access_w => Check {
            name: "usr_ro",
            ok: true,
            detail: "/usr access(W_OK) denied".to_string(),
        },
        Ok(false) => Check {
            name: "usr_ro",
            ok: false,
            detail: "/usr is writable (unhardened unit or doctor not in the service ns)"
                .to_string(),
        },
        Err(e) => Check {
            name: "usr_ro",
            ok: false,
            detail: format!("statvfs /usr: {e}"),
        },
    }
}

/// The second filter (pre-seccomp helper spawner): the helper allowlist lives on the
/// spawner, so a daemon reporting `Seccomp: 2` proves only half of the
/// claim. Reports the spawner's pid and its own seccomp mode, which is
/// what the hardening test asserts from outside.
fn check_spawner() -> Check {
    let Some(pid) = crate::spawner::pid() else {
        return Check {
            name: "spawner",
            ok: false,
            detail: "no spawner in this process (k7d doctor from a shell, not the daemon)"
                .to_string(),
        };
    };
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    match parse_dec_field(&status, "Seccomp") {
        Some(2) => Check {
            name: "spawner",
            ok: true,
            detail: format!("pid {pid}, Seccomp 2 (helper allowlist; the daemon has none of it)"),
        },
        Some(v) => Check {
            name: "spawner",
            ok: false,
            detail: format!("pid {pid}, Seccomp {v} (want 2 = filter)"),
        },
        None => Check {
            name: "spawner",
            ok: false,
            detail: format!("pid {pid} has no Seccomp in /proc/{pid}/status — is it alive?"),
        },
    }
}

fn check_seccomp(status: &str) -> Check {
    match parse_dec_field(status, "Seccomp") {
        Some(2) => Check {
            name: "seccomp",
            ok: true,
            detail: "2 (filter; daemon-only allowlist, helpers exec behind the spawner's)"
                .to_string(),
        },
        Some(0) => Check {
            name: "seccomp",
            ok: false,
            detail: "0 (disabled — K7D_SECCOMP=off or not the daemon)".to_string(),
        },
        Some(v) => Check {
            name: "seccomp",
            ok: false,
            detail: format!("{v} (want 2 = filter)"),
        },
        None => Check {
            name: "seccomp",
            ok: false,
            detail: "Seccomp missing from /proc/self/status".to_string(),
        },
    }
}

fn check_socket() -> Check {
    let path = crate::control::DEFAULT_SOCKET;
    let mode = match fs::metadata(path) {
        Ok(meta) => meta.permissions().mode() & 0o777,
        Err(e) => {
            return Check {
                name: "socket",
                ok: false,
                detail: format!("{path}: {e}"),
            };
        }
    };
    let parent_mode = Path::new(path)
        .parent()
        .and_then(|p| fs::metadata(p).ok().map(|m| m.permissions().mode() & 0o777));
    let uids = std::env::var("K7D_ALLOWED_UIDS")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map_or_else(
            || "K7D_ALLOWED_UIDS=unset (any connecting uid)".to_string(),
            |s| format!("K7D_ALLOWED_UIDS={s}"),
        );
    let mode_ok = mode == 0o660;
    let parent_ok = parent_mode == Some(0o750);
    let ok = mode_ok && parent_ok;
    let parent_s = parent_mode.map_or_else(|| "missing".to_string(), |m| format!("{m:04o}"));
    Check {
        name: "socket",
        ok,
        detail: format!("{path} mode={mode:04o} parent={parent_s} {uids}"),
    }
}

fn parse_hex_field(status: &str, key: &str) -> Option<u64> {
    status.lines().find_map(|line| {
        let rest = line.strip_prefix(key)?;
        let rest = rest.strip_prefix(':')?;
        u64::from_str_radix(rest.trim(), 16).ok()
    })
}

fn parse_dec_field(status: &str, key: &str) -> Option<u64> {
    status.lines().find_map(|line| {
        let rest = line.strip_prefix(key)?;
        let rest = rest.strip_prefix(':')?;
        rest.trim().parse().ok()
    })
}

fn path_access_w_ok(path: &str) -> bool {
    let Ok(c) = std::ffi::CString::new(path) else {
        return false;
    };
    // SAFETY: `c` is a valid C string for the duration of the call.
    unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 }
}

fn path_is_readonly(path: &str) -> Result<bool, String> {
    let c = std::ffi::CString::new(path).map_err(|e| e.to_string())?;
    let mut buf = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `c` is a valid path; `buf` is a valid out-param.
    let rc = unsafe { libc::statvfs(c.as_ptr(), buf.as_mut_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: `statvfs` filled `buf` on rc==0.
    let buf = unsafe { buf.assume_init() };
    Ok(buf.f_flag & libc::ST_RDONLY != 0)
}

fn check_char_device(name: &'static str, path: &str) -> Check {
    let p = Path::new(path);
    match fs::metadata(p) {
        Ok(meta) if meta.file_type().is_char_device() => Check {
            name,
            ok: true,
            detail: path.to_string(),
        },
        Ok(_) => Check {
            name,
            ok: false,
            detail: format!("{path} exists but is not a character device"),
        },
        Err(e) => Check {
            name,
            ok: false,
            detail: format!("{path}: {e}"),
        },
    }
}

fn check_cgroup_v2() -> Check {
    match cgroup_v2_status() {
        Ok(detail) => Check {
            name: "cgroup_v2",
            ok: true,
            detail,
        },
        Err(detail) => Check {
            name: "cgroup_v2",
            ok: false,
            detail,
        },
    }
}

/// Unified hierarchy: `/sys/fs/cgroup/cgroup.controllers` exists and
/// `/proc/self/cgroup` has a `0::` line. Hybrid/v1 hosts fail loud.
fn cgroup_v2_status() -> Result<String, String> {
    let controllers = Path::new("/sys/fs/cgroup/cgroup.controllers");
    if !controllers.is_file() {
        return Err(
            "/sys/fs/cgroup/cgroup.controllers missing — host is not cgroup v2".to_string(),
        );
    }
    let content = fs::read_to_string("/proc/self/cgroup")
        .map_err(|e| format!("read /proc/self/cgroup: {e}"))?;
    parse_cgroup_v2(&content)?;
    Ok("/sys/fs/cgroup (unified) + /proc/self/cgroup 0::".to_string())
}

fn parse_cgroup_v2(content: &str) -> Result<(), String> {
    if content.lines().any(|line| line.starts_with("0::")) {
        Ok(())
    } else {
        Err(format!(
            "no cgroup v2 (`0::`) entry in /proc/self/cgroup: {content:?}"
        ))
    }
}

/// Lowercase hex sha256 of `data`.
fn sha256_hex(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cgroup_v2_accepts_unified() {
        parse_cgroup_v2("0::/system.slice/k7d.service\n").expect("unified");
    }

    #[test]
    fn parse_cgroup_v2_rejects_v1_only() {
        let err = parse_cgroup_v2("1:name=systemd:/\n12:memory:/\n").unwrap_err();
        assert!(err.contains("0::"), "{err}");
    }

    #[test]
    fn run_on_this_host_is_structured() {
        let report = run();
        assert_eq!(report.checks.len(), 4);
        let names: Vec<_> = report.checks.iter().map(|c| c.name).collect();
        assert_eq!(names, ["kvm", "vhost_vsock", "tun", "cgroup_v2"]);
        let fc_names: Vec<_> = report.fc.iter().map(|c| c.name).collect();
        assert_eq!(
            fc_names,
            [
                "fc_firecracker",
                "fc_jailer",
                "fc_chroot_base",
                "fc_fork_mode",
                "fc_clock_realtime"
            ]
        );
        for c in report.checks.iter().chain(&report.fc) {
            assert!(!c.detail.is_empty(), "{} has empty detail", c.name);
        }
        assert!(
            report.lines().iter().any(|l| l == "hardening:"),
            "doctor must print a hardening: section: {:?}",
            report.lines()
        );
        assert_eq!(report.hardening.len(), 6, "{:?}", report.hardening);
        let hnames: Vec<_> = report.hardening.iter().map(|c| c.name).collect();
        assert_eq!(
            hnames,
            [
                "capbnd",
                "nonewprivs",
                "usr_ro",
                "seccomp",
                "spawner",
                "socket"
            ]
        );
        assert!(
            report.lines().iter().any(|l| l == "privsep:"),
            "doctor must print a privsep: section (privilege separation): {:?}",
            report.lines()
        );
        let pnames: Vec<_> = report.privsep.iter().map(|c| c.name).collect();
        assert_eq!(
            pnames,
            [
                "mode",
                "account",
                "vhost_vsock_perms",
                "delegated_cgroup",
                "channels"
            ]
        );
        // 4 required host checks, 5 Firecracker, 2 section headers, 6
        // hardening items, 5 privsep items. Counted rather than
        // approximated so a section that stops being printed at all fails
        // here as well as in its own assertion above.
        // +1 is the trailing ksmd line (advisory, not a section).
        assert_eq!(report.lines().len(), 4 + 5 + 2 + 6 + 5 + 1);
        assert!(
            report.lines().last().is_some_and(|l| l.contains("ksmd")),
            "doctor must say whether ksmd is running: {:?}",
            report.lines()
        );
    }

    #[test]
    fn kernel_versions_parse_and_compare() {
        assert_eq!(parse_kernel_version("6.8.0-45-generic"), Some((6, 8)));
        assert_eq!(parse_kernel_version("5.15.0"), Some((5, 15)));
        assert_eq!(parse_kernel_version("garbage"), None);
    }

    #[test]
    fn firecracker_checks_do_not_decide_host_readiness() {
        // A node that never runs `backend: firecracker` must still be
        // "doctor: ok" — the FC group is advisory.
        let report = Report {
            checks: vec![Check {
                name: "kvm",
                ok: true,
                detail: "/dev/kvm".to_string(),
            }],
            fc: vec![Check {
                name: "fc_firecracker",
                ok: false,
                detail: "missing".to_string(),
            }],
            hardening: vec![],
            privsep: vec![],
            ksm_run: None,
        };
        assert!(report.ok());
        assert!(
            report.lines()[1].starts_with("warn"),
            "{:?}",
            report.lines()
        );
    }

    #[test]
    fn sha256_matches_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // Longer than one 64-byte block, to exercise the message schedule.
        assert_eq!(
            sha256_hex(&[b'a'; 200]),
            "c2a908d98f5df987ade41b5fce213067efbcc21ef2240212a41e54b5e7c28ae5"
        );
    }

    #[test]
    fn expected_capbnd_matches_the_unit_template() {
        let template = include_str!("../../../packaging/k7d.service.in");
        let line = template
            .lines()
            .find(|l| l.starts_with("CapabilityBoundingSet="))
            .expect("CapabilityBoundingSet in packaging/k7d.service.in");
        let rest = line
            .strip_prefix("CapabilityBoundingSet=")
            .expect("CapabilityBoundingSet prefix");
        let mut mask = 0u64;
        for name in rest.split_whitespace() {
            mask |= cap_bit(name.as_bytes());
        }
        assert_eq!(mask, EXPECTED_CAPBND, "{line}");
    }

    #[test]
    fn unit_consumers_cannot_diverge_from_the_template() {
        let install = include_str!("../../../packaging/install.sh");
        assert!(
            install.contains("k7d.service.in"),
            "install.sh must consume packaging/k7d.service.in"
        );
        assert!(
            install.contains("k7d-mount-disks"),
            "install.sh must install the ExecStartPre mount helper"
        );
        let setup = include_str!("../../../your node provisioning");
        assert!(
            setup.contains("k7d-mount-disks"),
            "setup-node-after-reset.sh must consume packaging/k7d-mount-disks.sh"
        );
        assert!(
            setup.contains("k7d.service.in"),
            "setup-node-after-reset.sh must name the unit template"
        );
    }

    #[test]
    fn parse_status_fields() {
        let status = format!("CapBnd:\t{EXPECTED_CAPBND:016x}\nNoNewPrivs:\t1\nSeccomp:\t2\n");
        assert_eq!(parse_hex_field(&status, "CapBnd"), Some(EXPECTED_CAPBND));
        assert_eq!(parse_dec_field(&status, "NoNewPrivs"), Some(1));
        assert_eq!(parse_dec_field(&status, "Seccomp"), Some(2));
    }
}
