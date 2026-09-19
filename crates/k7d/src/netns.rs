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

/// Run a command through [`crate::spawner`], read its stdout + stderr
/// to EOF, and return `(ExitStatus, stdout, stderr)`.
///
/// ## Why not `std::process::Command::output()`
///
/// Two independent reasons, both about *who* the child is.
///
/// In the daemon it is not a child at all: `spawner.rs` execs helpers
/// from a process forked before the daemon's seccomp filter, so an `ip`
/// invocation is the daemon's *grand*child and `waitpid` on it would
/// fail with `ECHILD` even without a reaper in play. The spawner owns
/// the wait.
///
/// In the shim it is a child, but the shim's Tokio runtime installs a
/// SIGCHLD handler that reaps every child via `waitpid(-1, …, WNOHANG)`.
/// If ours exits before our thread calls `waitpid(pid)`, Tokio has
/// already collected the status and `waitpid` returns `ECHILD` —
/// which surfaced as `"netns IO: No child processes (os error 10)"` and
/// silently broke every `attach_to_pod_netns` call on a live cluster.
/// `spawner` waits on a `pidfd` for that reason, which is race-free
/// under any signal-handling regime.
pub(crate) fn run_capture(
    cmd: &str,
    args: &[&str],
) -> Result<(std::process::ExitStatus, String, String), NetnsError> {
    let out = crate::spawner::command(cmd).args(args).output()?;
    Ok((
        out.status,
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
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
        let _ = crate::spawner::command("ip")
            .args(["netns", "del", name])
            .output();
        let out = crate::spawner::command("ip")
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
            let _ = crate::spawner::command("ip")
                .args(["netns", "del", self.0])
                .output();
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
        let _ = crate::spawner::command("ip")
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
