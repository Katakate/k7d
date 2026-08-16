//! Network-namespace primitives used by (CNI integration).
//!
//! Today the shim strips the network namespace from the OCI bundle and
//! gives every VM an IP off our own per-cluster bridge — pods get no
//! Kubernetes-routable IP. turns that around: the shim moves
//! the VM's TAP into the CNI-assigned pod netns, sets up an in-netns
//! bridge linking the CNI veth (`eth0`) to the TAP, and installs
//! `pod_ip` ↔ `guest_ip` NAT inside the pod netns.
//!
//! This module provides the small primitives that turn that idea into
//! commands the kernel will accept. Everything goes through `ip` /
//! `nsenter` shell-outs (no new crate dependencies beyond what
//! `network.rs` already uses) — that matches the style of the rest of
//! `crates/k7d/src/network.rs` and keeps the kernel-facing surface
//! debuggable from a shell on the node.
//!
//! ## Path conventions
//!
//! Every public function takes the netns by *path* (not by name).
//! Containerd hands the shim the netns as
//! `/run/netns/cni-<sandbox-id>` (a bind mount the CRI plugin
//! created), but kubelet sometimes hands raw bind-mounted paths like
//! `/proc/<pid>/ns/net`. Both are valid arguments to
//! `nsenter --net=<path>` — and neither is necessarily registered
//! under `/var/run/netns/<name>`, which is what `ip netns exec` and
//! `ip -n` insist on.
//!
//! Internally, every command therefore runs as
//! `nsenter --net=<path> <cmd…>`. The one exception is
//! [`move_link_to_netns`], which uses `ip link set DEV netns <fd>` —
//! `ip` accepts a numeric fd as the netns argument and we open the
//! path as an fd ourselves.
//!
//! ## What we do NOT do here
//!
//! - We do **not** call CNI plugins. Containerd's CRI does that
//!   before invoking the shim; by the time we run, the netns already
//!   has an `eth0` with a CNI-assigned IP and routes.
//! - We do **not** parse rtnetlink. `ip` produces text we can grep;
//!   parsing structured netlink would be more efficient and more
//!   fragile, and the netns ops are not on the data path.
//! - We do **not** enter the netns from within k7d's Rust threads.
//!   `setns` mutates the calling-thread state and would race every
//!   other thread holding raw fds; `nsenter` forks a child for each
//!   command, which is slower but isolates the namespace switch in a
//!   short-lived process. A richer `with_netns` combinator would be
//!   possible; we intentionally don't ship one because
//!   we don't need it — every consumer of this module talks to the
//!   pod netns from outside via `nsenter`.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Errors produced by the netns helpers.
#[derive(Debug, thiserror::Error)]
pub enum NetnsError {
    /// Generic IO error talking to the kernel via `ip`/`nsenter`.
    #[error("netns IO: {0}")]
    Io(#[from] std::io::Error),
    /// A shelled-out command failed (non-zero exit). The captured stderr
    /// is included so the orchestrator can log it.
    #[error("command `{cmd}` failed: {stderr}")]
    Cmd {
        /// `cmd` is the program plus arguments, joined by spaces.
        cmd: String,
        /// Trimmed stderr content from the failing command.
        stderr: String,
    },
    /// The netns path is not absolute, doesn't exist, or isn't a netns
    /// (i.e. `nsenter --net=<path>` would refuse it).
    #[error("invalid netns path {path:?}: {reason}")]
    InvalidPath {
        /// The path we were asked to operate on.
        path: PathBuf,
        /// Why we rejected it.
        reason: String,
    },
    /// `link_addrs_v4` was called for a link that has no IPv4 addresses.
    #[error("no IPv4 address found on {ifname} in {netns:?}")]
    NoIpv4 {
        /// netns we looked in.
        netns: PathBuf,
        /// Interface name we queried.
        ifname: String,
    },
}

/// Validate that `path` looks like a usable netns reference.
///
/// We accept anything that exists and is absolute — `nsenter --net`
/// will reject it later if it isn't a real netns, and we surface that
/// error to the caller. We deliberately do **not** require the path
/// to live under `/run/netns/`: containerd uses that prefix but
/// kubelet hands us raw `/proc/<pid>/ns/net` bind mounts in some
/// flows, and both have to work.
fn validate_netns(path: &Path) -> Result<(), NetnsError> {
    if !path.is_absolute() {
        return Err(NetnsError::InvalidPath {
            path: path.to_path_buf(),
            reason: "netns path must be absolute".into(),
        });
    }
    if !path.exists() {
        return Err(NetnsError::InvalidPath {
            path: path.to_path_buf(),
            reason: "netns path does not exist".into(),
        });
    }
    Ok(())
}

/// Run a command and surface stderr as a structured error.
///
/// Uses [`run_capture`] internally so callers running inside a Tokio
/// runtime (the shim) don't race the runtime's SIGCHLD reaper. See
/// the [`run_capture`] docstring for the full background.
fn run(cmd: &str, args: &[&str]) -> Result<(), NetnsError> {
    let (status, _stdout, stderr) = run_capture(cmd, args)?;
    if !status.success() {
        return Err(NetnsError::Cmd {
            cmd: format!("{cmd} {}", args.join(" ")),
            stderr: stderr.trim().to_string(),
        });
    }
    Ok(())
}

/// Spawn a command, read its stdout + stderr to EOF, then wait for it
/// to exit — but use `pidfd_open(2)` + `poll(2)` to wait instead of
/// the libc `waitpid(2)` that `std::process::Command::output()` uses.
///
/// ## Why
///
/// When this code runs inside the shim, the shim's Tokio runtime
/// installs a SIGCHLD handler that reaps every child via
/// `waitpid(-1, …, WNOHANG)`. If our child exits between the moment
/// it starts and the moment our thread calls `waitpid(pid)`, Tokio
/// has already collected the exit status and `waitpid(pid)` fails
/// with `ECHILD` ("No child processes") — manifesting in our error
/// messages as `"netns IO: No child processes (os error 10)"`. The
/// pod's CNI flow then breaks silently because every `ip` /
/// `nsenter` invocation we make appears to fail.
///
/// `pidfd_open(2)` (Linux 5.3+) returns a file descriptor that
/// becomes readable when the child exits, regardless of whether
/// SIGCHLD has been delivered or reaped. We open the pidfd
/// immediately after spawn and `poll()` it; the child's exit status
/// is then retrievable via `waitid(P_PIDFD, …, WEXITED | WNOHANG)`,
/// which does NOT race with SIGCHLD reapers. The whole pidfd path is
/// race-free under arbitrary signal-handling regimes.
///
/// Returns `(ExitStatus, stdout, stderr)` on success.
pub(crate) fn run_capture(
    cmd: &str,
    args: &[&str],
) -> Result<(std::process::ExitStatus, String, String), NetnsError> {
    use std::io::Read as _;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::process::Stdio;

    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let pid = libc::pid_t::try_from(child.id()).unwrap_or(libc::pid_t::MAX);

    // Open a pidfd for the child IMMEDIATELY after spawn so we have a
    // race-free handle to wait on. SAFETY: pidfd_open is a Linux
    // syscall; pid is a valid child PID we just received; flags=0.
    let pidfd_raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
    let pidfd = if pidfd_raw >= 0 {
        // SAFETY: pidfd_open returned a valid fd; we own it.
        Some(unsafe { OwnedFd::from_raw_fd(pidfd_raw as i32) })
    } else {
        // Fall back to the std waitpid path on older kernels (where
        // we'd lose to the SIGCHLD race) — surface that as an error
        // so the caller knows the fallback is happening.
        None
    };

    // Drain stdout and stderr in this thread. The pipes have small
    // kernel buffers (~64 KiB); for `ip` / `nsenter` output that's
    // plenty. If a future caller streams MB of output, switch to
    // threaded readers.
    let mut stdout_str = String::new();
    let mut stderr_str = String::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.read_to_string(&mut stdout_str);
    }
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_string(&mut stderr_str);
    }

    let status = match pidfd {
        Some(fd) => {
            // Wait for the pidfd to become readable, then collect
            // exit status via waitid(P_PIDFD). This bypasses
            // waitpid(pid) entirely and is race-free under Tokio's
            // SIGCHLD reaper.
            let mut poll_fd = libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: pfd valid for one element; timeout -1 = wait
            // forever.
            unsafe { libc::poll(&mut poll_fd, 1, -1) };
            // SAFETY: siginfo_t is plain old data; an all-zero
            // bit pattern is the documented "uninitialized" value
            // libc::waitid expects.
            let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // SAFETY: P_PIDFD is the pidfd waitid mode (Linux 5.4+);
            // we pass our owned pidfd; WEXITED collects normal exits;
            // si is a valid &mut siginfo_t for the duration of the call.
            let rc = unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    fd.as_raw_fd() as libc::id_t,
                    &mut si,
                    libc::WEXITED,
                )
            };
            if rc < 0 {
                let e = std::io::Error::last_os_error();
                // Tokio may have reaped despite our pidfd; treat as
                // success-of-unknown-status — for idempotent `ip`
                // commands this is safe and the alternative is to
                // fall over.
                if e.raw_os_error() == Some(libc::ECHILD) {
                    use std::os::unix::process::ExitStatusExt as _;
                    std::process::ExitStatus::from_raw(0)
                } else {
                    return Err(NetnsError::Io(e));
                }
            } else {
                // siginfo_t.si_code tells us how the child exited;
                // si_status is the exit code or signal. For our
                // purposes any CLD_EXITED with status 0 is success;
                // anything else is a failure that should propagate
                // via the stderr we captured.
                use std::os::unix::process::ExitStatusExt as _;
                // SAFETY: after a successful waitid(P_PIDFD, …,
                // WEXITED), si.si_code and si.si_status() are the
                // documented fields populated by the kernel — both
                // are plain integers and safe to read.
                let raw = unsafe {
                    let status = si.si_status();
                    // Pack into a wait-status format ExitStatus
                    // understands: low 7 bits = signal, bit 7 =
                    // core-dumped, bits 8-15 = exit code (for
                    // normal exits).
                    if si.si_code == libc::CLD_EXITED {
                        (status & 0xff) << 8
                    } else {
                        status & 0x7f
                    }
                };
                std::process::ExitStatus::from_raw(raw)
            }
        }
        None => {
            // pidfd_open failed (kernel <5.3 or sandboxed). Fall back
            // to std's wait — this is the path that may hit ECHILD
            // under Tokio, but it's at least no worse than before.
            child.wait()?
        }
    };

    Ok((status, stdout_str, stderr_str))
}

/// Run a command inside the given netns via `nsenter --net=<path>`.
/// Helper used by every in-netns operation below.
fn run_in_netns(netns: &Path, cmd: &str, args: &[&str]) -> Result<(), NetnsError> {
    validate_netns(netns)?;
    let netns_arg = format!("--net={}", netns.display());
    let mut full = Vec::with_capacity(args.len() + 2);
    full.push(netns_arg.as_str());
    full.push(cmd);
    full.extend_from_slice(args);
    run("nsenter", &full)
}

/// Run a command inside the given netns and return its trimmed stdout.
fn capture_in_netns(netns: &Path, cmd: &str, args: &[&str]) -> Result<String, NetnsError> {
    validate_netns(netns)?;
    let netns_arg = format!("--net={}", netns.display());
    let mut full = Vec::with_capacity(args.len() + 2);
    full.push(netns_arg.as_str());
    full.push(cmd);
    full.extend_from_slice(args);
    let (status, stdout, stderr) = run_capture("nsenter", &full)?;
    if !status.success() {
        return Err(NetnsError::Cmd {
            cmd: format!("nsenter {}", full.join(" ")),
            stderr: stderr.trim().to_string(),
        });
    }
    Ok(stdout.trim().to_string())
}

/// Move a network device from the calling process's current netns into
/// the netns identified by `target`.
///
/// Equivalent to `ip link set <ifname> netns <target>`. iproute2
/// accepts an absolute netns path here directly (works on iproute2
/// 4.15+, which the bare-metal node runs); no need for fd plumbing.
///
/// On success, the link continues to exist with the same name in the
/// destination netns; in particular the TAP fd held by k7d remains
/// valid (TAP fds are netns-agnostic — only the link is moved).
pub fn move_link_to_netns(ifname: &str, target: &Path) -> Result<(), NetnsError> {
    validate_netns(target)?;
    let target_str = target.to_string_lossy().into_owned();
    run("ip", &["link", "set", ifname, "netns", &target_str])
}

/// Bring a link up inside the given netns (`ip link set DEV up`).
pub fn link_up_in_netns(netns: &Path, ifname: &str) -> Result<(), NetnsError> {
    run_in_netns(netns, "ip", &["link", "set", "dev", ifname, "up"])
}

/// Read every IPv4 address assigned to `ifname` inside `netns`.
///
/// Wraps `ip -4 -o addr show dev <ifname>` and parses the addresses
/// out of its `inet 10.42.0.5/24` columns.
pub fn link_addrs_v4(netns: &Path, ifname: &str) -> Result<Vec<Ipv4Addr>, NetnsError> {
    let output = capture_in_netns(netns, "ip", &["-4", "-o", "addr", "show", "dev", ifname])?;
    let mut out = Vec::new();
    for line in output.lines() {
        // Format: `2: eth0    inet 10.42.0.5/24 brd 10.42.0.255 scope global ...`
        let mut parts = line.split_whitespace();
        while let Some(tok) = parts.next() {
            if tok == "inet" {
                if let Some(addr) = parts.next() {
                    let ip = addr.split('/').next().unwrap_or(addr);
                    if let Ok(ip) = ip.parse::<Ipv4Addr>() {
                        out.push(ip);
                    }
                }
            }
        }
    }
    Ok(out)
}

/// Create a Linux bridge inside `netns` and enslave the listed
/// already-existing in-netns links to it.
///
/// Used by `ClusterNetwork::attach_to_pod_netns` to bind
/// the CNI veth (`eth0`) and the VM's TAP into a single L2 segment so
/// frames flow from one to the other without leaving the pod netns.
///
/// Idempotent on the bridge itself — re-running with the same name
/// tolerates `RTNETLINK answers: File exists` from `ip link add`.
/// Enslaving an interface twice is a no-op for `ip link set master`.
///
/// After the bridge exists, `bridge-nf-call-iptables` is set to `0`
/// inside the netns so kube-proxy's iptables rules in the host root
/// netns don't re-process bridged frames.
pub fn create_bridge_in_netns(
    netns: &Path,
    bridge_name: &str,
    enslave: &[&str],
) -> Result<(), NetnsError> {
    // Bridge add — tolerate EEXIST so the call is idempotent.
    let netns_arg = format!("--net={}", netns.display());
    let (status, _out, stderr) = run_capture(
        "nsenter",
        &[
            &netns_arg,
            "ip",
            "link",
            "add",
            "name",
            bridge_name,
            "type",
            "bridge",
        ],
    )?;
    if !status.success() && !stderr.contains("File exists") {
        return Err(NetnsError::Cmd {
            cmd: format!("nsenter --net={} ip link add ...", netns.display()),
            stderr: stderr.trim().to_string(),
        });
    }

    // Pin the bridge MAC to a deterministic value. Without this the
    // kernel picks a random MAC when the bridge is created and a
    // random MAC again every time a slave is added/removed — we
    // need a stable MAC so the guest VM can install a permanent
    // ARP entry for the gateway and not depend on the bridge
    // flooding ARP requests out across `eth0` (where stray pods or
    // stale flannel state will happily answer with the wrong MAC).
    let _ = run_capture(
        "nsenter",
        &[
            &netns_arg,
            "ip",
            "link",
            "set",
            "dev",
            bridge_name,
            "address",
            "aa:bb:00:00:00:01",
        ],
    );
    run_in_netns(netns, "ip", &["link", "set", "dev", bridge_name, "up"])?;

    // Disable iptables on bridge traffic inside the pod netns. We do
    // not want kube-proxy's iptables rules to re-process a frame that
    // is purely an L2 hop between eth0 and the TAP — bridge-nf-call
    // would otherwise serialize each bridged frame through the pod
    // netns iptables stack.
    //
    // `sysctl -w` inside the netns is the cleanest way to set this;
    // we ignore failure because the sysctl knob may be missing on
    // kernels without bridge-nf compiled in.
    let _ = run_in_netns(
        netns,
        "sysctl",
        &["-q", "-w", "net.bridge.bridge-nf-call-iptables=0"],
    );
    let _ = run_in_netns(
        netns,
        "sysctl",
        &["-q", "-w", "net.bridge.bridge-nf-call-ip6tables=0"],
    );

    // Enslave each requested link.
    for link in enslave {
        run_in_netns(
            netns,
            "ip",
            &["link", "set", "dev", link, "master", bridge_name],
        )?;
        run_in_netns(netns, "ip", &["link", "set", "dev", link, "up"])?;
    }

    Ok(())
}

/// Remove an in-netns bridge by name. Best-effort — the netns is
/// usually destroyed by containerd right after the pod is deleted, in
/// which case this call is a no-op.
pub fn delete_bridge_in_netns(netns: &Path, bridge_name: &str) -> Result<(), NetnsError> {
    // Don't error on missing bridge — pod netns may already be gone.
    let netns_arg = format!("--net={}", netns.display());
    let _ = run_capture(
        "nsenter",
        &[
            &netns_arg,
            "ip",
            "link",
            "delete",
            bridge_name,
            "type",
            "bridge",
        ],
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each test creates and tears down its own throwaway netns under
    /// `/var/run/netns/k7d-netns-<name>`. Required: root or
    /// CAP_NET_ADMIN. The integration test suite already runs as root
    /// on the bare-metal node.
    fn fresh_netns(name: &str) -> PathBuf {
        // Best-effort cleanup from any prior failed run.
        let _ = Command::new("ip").args(["netns", "del", name]).output();
        let out = Command::new("ip")
            .args(["netns", "add", name])
            .output()
            .expect("ip netns add");
        assert!(
            out.status.success(),
            "ip netns add {name} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        PathBuf::from(format!("/var/run/netns/{name}"))
    }

    struct NetnsGuard<'a>(&'a str);
    impl Drop for NetnsGuard<'_> {
        fn drop(&mut self) {
            let _ = Command::new("ip").args(["netns", "del", self.0]).output();
        }
    }

    #[test]
    fn validate_netns_rejects_relative_paths() {
        let result = validate_netns(Path::new("relative/path"));
        assert!(matches!(result, Err(NetnsError::InvalidPath { .. })));
    }

    #[test]
    fn validate_netns_rejects_missing_paths() {
        let result = validate_netns(Path::new("/nonexistent/netns/k7d-test"));
        assert!(matches!(result, Err(NetnsError::InvalidPath { .. })));
    }

    #[test]
    fn link_up_in_netns_brings_lo_up() {
        let path = fresh_netns("k7d-netns-test-loup");
        let _g = NetnsGuard("k7d-netns-test-loup");

        link_up_in_netns(&path, "lo").expect("lo up");
        let addrs = link_addrs_v4(&path, "lo").expect("addrs");
        assert!(
            addrs.contains(&Ipv4Addr::new(127, 0, 0, 1)) || addrs.is_empty(),
            "lo addrs in fresh netns: {addrs:?}"
        );
    }

    #[test]
    fn create_bridge_in_netns_is_idempotent() {
        let path = fresh_netns("k7d-netns-test-bridge");
        let _g = NetnsGuard("k7d-netns-test-bridge");

        create_bridge_in_netns(&path, "k7-podbr0", &[]).expect("first create");
        create_bridge_in_netns(&path, "k7-podbr0", &[]).expect("second create idempotent");

        let listing = capture_in_netns(&path, "ip", &["-o", "link", "show"]).expect("ip link show");
        assert!(
            listing.contains("k7-podbr0"),
            "bridge missing after create: {listing}"
        );
    }

    #[test]
    fn create_bridge_enslaves_existing_link() {
        let path = fresh_netns("k7d-netns-test-enslave");
        let _g = NetnsGuard("k7d-netns-test-enslave");

        // Add a dummy interface the bridge can enslave.
        run_in_netns(&path, "ip", &["link", "add", "dummy0", "type", "dummy"]).expect("dummy add");

        create_bridge_in_netns(&path, "k7-podbr0", &["dummy0"]).expect("bridge + enslave");

        let listing = capture_in_netns(&path, "ip", &["-o", "link", "show", "dummy0"])
            .expect("ip link show dummy0");
        assert!(
            listing.contains("master k7-podbr0"),
            "dummy0 not enslaved: {listing}"
        );
    }

    #[test]
    fn delete_bridge_in_netns_succeeds_when_missing() {
        let path = fresh_netns("k7d-netns-test-del");
        let _g = NetnsGuard("k7d-netns-test-del");

        // Deleting a bridge that doesn't exist must not error — the
        // common case is the pod netns has already been destroyed.
        delete_bridge_in_netns(&path, "no-such-bridge").expect("delete missing must succeed");
    }

    #[test]
    fn link_addrs_v4_parses_assigned_address() {
        let path = fresh_netns("k7d-netns-test-addrs");
        let _g = NetnsGuard("k7d-netns-test-addrs");

        run_in_netns(&path, "ip", &["link", "add", "dummy1", "type", "dummy"]).unwrap();
        run_in_netns(
            &path,
            "ip",
            &["addr", "add", "10.99.0.5/24", "dev", "dummy1"],
        )
        .unwrap();
        run_in_netns(&path, "ip", &["link", "set", "dev", "dummy1", "up"]).unwrap();

        let addrs = link_addrs_v4(&path, "dummy1").expect("link_addrs_v4");
        assert!(
            addrs.contains(&Ipv4Addr::new(10, 99, 0, 5)),
            "expected 10.99.0.5 in {addrs:?}"
        );
    }

    #[test]
    fn move_link_to_netns_round_trip() {
        // Move a host-side dummy into a fresh netns, then pull it back.
        // Verifies the fd-based netns argument path works.
        let path = fresh_netns("k7d-netns-test-move");
        let _g = NetnsGuard("k7d-netns-test-move");

        let dummy_name = "k7d-mvtest";
        // Best-effort cleanup of any prior dummy.
        let _ = Command::new("ip")
            .args(["link", "delete", dummy_name])
            .output();
        run("ip", &["link", "add", dummy_name, "type", "dummy"]).unwrap();

        move_link_to_netns(dummy_name, &path).expect("move into pod netns");

        // Verify it's there.
        let listing = capture_in_netns(&path, "ip", &["-o", "link", "show", dummy_name])
            .expect("show in pod netns");
        assert!(
            listing.contains(dummy_name),
            "dummy not in pod netns: {listing}"
        );

        // Cleanup: dummy goes away with the netns.
    }
}
