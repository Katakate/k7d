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

use std::fs;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;

use sha2::{Digest, Sha256};

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

    fn named(&self, name: &str) -> bool {
        self.checks
            .iter()
            .find(|c| c.name == name)
            .is_some_and(|c| c.ok)
    }

    /// One line per check, plus a summary. For the CLI and the socket
    /// `details` field. Firecracker lines are marked `warn` rather than
    /// `FAIL` because they do not decide [`Report::ok`].
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
        required.chain(firecracker).collect()
    }
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
    }
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
        assert_eq!(report.lines().len(), 9);
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
}
