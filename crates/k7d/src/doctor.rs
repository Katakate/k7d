//! Host readiness checks for k7d (`doctor`).
//!
//! Four checks, all loud: `/dev/kvm`, `/dev/vhost-vsock`, `/dev/net/tun`,
//! and cgroup v2. Used by the `k7d doctor` CLI, the `doctor` control
//! verb, and `k7d quickstart`. The 27a primitive freeze is lifted for
//! this verb only — it reports host state; it does not create VMs.

use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;

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
    /// Checks in display order.
    pub checks: Vec<Check>,
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
    /// `details` field.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        self.checks
            .iter()
            .map(|c| {
                let mark = if c.ok { "ok" } else { "FAIL" };
                format!("{mark:4}  {}  {}", c.name, c.detail)
            })
            .collect()
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
        for c in &report.checks {
            assert!(!c.detail.is_empty(), "{} has empty detail", c.name);
        }
    }
}
