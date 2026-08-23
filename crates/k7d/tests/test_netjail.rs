//! the referenced work layer 2: the per-tree network jail.
//!
//! The property under test is "two trees on one node cannot reach each
//! other", and it is tested where it lives — the host's `forward` hook
//! — rather than through two booted guests. Two `k7-br-*` bridges each
//! get a veth into their own network namespace, which is exactly the
//! topology a pair of tree bridges present to the kernel, and the test
//! drives real packets across them.
//!
//! Deliberately *with* the `FORWARD -i <bridge> -j ACCEPT` iptables
//! rules `ClusterNetwork::create` installs: the jail is only worth
//! anything if it beats them, so the test proves the baseline is
//! reachable first and then that the jail closes it.

use std::process::Command;

use k7d::netjail::{clean_stale_jails, jail_installed, table_name, TreeNetJail};

/// One side of the topology: bridge + netns + veth pair.
struct Side {
    bridge: String,
    netns: String,
    veth_host: String,
    veth_ns: String,
    subnet: u8,
}

impl Side {
    fn new(tag: &str, subnet: u8) -> Self {
        Self {
            bridge: format!("k7-br-nj{tag}"),
            netns: format!("k7jail-test-{tag}"),
            veth_host: format!("njh{tag}"),
            veth_ns: format!("njg{tag}"),
            subnet,
        }
    }

    fn guest_ip(&self) -> String {
        format!("10.{}.0.2", self.subnet)
    }

    fn gateway_ip(&self) -> String {
        format!("10.{}.0.1", self.subnet)
    }

    fn up(&self) {
        let veth_ns = self.veth_ns.as_str();
        run(&["ip", "netns", "add", &self.netns]);
        run(&["ip", "link", "add", "name", &self.bridge, "type", "bridge"]);
        run(&[
            "ip",
            "addr",
            "add",
            &format!("{}/24", self.gateway_ip()),
            "dev",
            &self.bridge,
        ]);
        run(&["ip", "link", "set", "dev", &self.bridge, "up"]);
        run(&[
            "ip",
            "link",
            "add",
            &self.veth_host,
            "type",
            "veth",
            "peer",
            "name",
            veth_ns,
        ]);
        run(&["ip", "link", "set", veth_ns, "netns", &self.netns]);
        run(&["ip", "link", "set", &self.veth_host, "master", &self.bridge]);
        run(&["ip", "link", "set", &self.veth_host, "up"]);
        run(&[
            "ip",
            "netns",
            "exec",
            &self.netns,
            "ip",
            "link",
            "set",
            "lo",
            "up",
        ]);
        run(&[
            "ip",
            "netns",
            "exec",
            &self.netns,
            "ip",
            "addr",
            "add",
            &format!("{}/24", self.guest_ip()),
            "dev",
            veth_ns,
        ]);
        run(&[
            "ip",
            "netns",
            "exec",
            &self.netns,
            "ip",
            "link",
            "set",
            veth_ns,
            "up",
        ]);
        run(&[
            "ip",
            "netns",
            "exec",
            &self.netns,
            "ip",
            "route",
            "add",
            "default",
            "via",
            &self.gateway_ip(),
        ]);
        // The same FORWARD ACCEPTs `ClusterNetwork::create` installs —
        // the jail has to beat them, so they must be present.
        for spec in [["-i", self.bridge.as_str()], ["-o", self.bridge.as_str()]] {
            let _ = Command::new("iptables")
                .args(["-I", "FORWARD", spec[0], spec[1], "-j", "ACCEPT"])
                .status();
        }
    }

    /// Can this side reach `target` in one second?
    fn can_reach(&self, target: &str) -> bool {
        Command::new("ip")
            .args([
                "netns",
                "exec",
                &self.netns,
                "ping",
                "-c",
                "1",
                "-W",
                "1",
                target,
            ])
            .output()
            .expect("run ping")
            .status
            .success()
    }

    fn down(&self) {
        for spec in [["-i", self.bridge.as_str()], ["-o", self.bridge.as_str()]] {
            let _ = Command::new("iptables")
                .args(["-D", "FORWARD", spec[0], spec[1], "-j", "ACCEPT"])
                .status();
        }
        let _ = Command::new("ip")
            .args(["netns", "delete", &self.netns])
            .status();
        let _ = Command::new("ip")
            .args(["link", "delete", &self.bridge, "type", "bridge"])
            .status();
    }
}

/// Both sides, torn down whatever the test does — a leaked netns or
/// bridge poisons every later run on the node.
struct Topology {
    a: Side,
    b: Side,
    prev_forward: String,
}

impl Topology {
    fn up() -> Self {
        let a = Side::new("aa", 201);
        let b = Side::new("bb", 202);
        // A previous crashed run's leftovers would make `ip netns add`
        // fail and the test read as a jail bug.
        a.down();
        b.down();
        let prev_forward =
            std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward").unwrap_or_default();
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").expect("enable ip_forward");
        a.up();
        b.up();
        Self { a, b, prev_forward }
    }
}

impl Drop for Topology {
    fn drop(&mut self) {
        self.a.down();
        self.b.down();
        if !self.prev_forward.trim().is_empty() {
            let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", self.prev_forward.trim());
        }
        let _ = clean_stale_jails();
    }
}

fn run(args: &[&str]) {
    let out = Command::new(args[0])
        .args(&args[1..])
        .output()
        .unwrap_or_else(|e| panic!("spawn {args:?}: {e}"));
    assert!(
        out.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );
}

/// The jail denies bridge-to-bridge forwarding that the iptables
/// FORWARD ACCEPT rules allow, and leaves the guest's own gateway
/// (host services, INPUT hook) alone.
#[test]
fn test_inter_tree_traffic_denied() {
    let topo = Topology::up();

    assert!(
        topo.a.can_reach(&topo.b.guest_ip()),
        "baseline: without a jail, tree A must be able to reach tree B \
         (otherwise this test proves nothing)"
    );

    let jail_a = TreeNetJail::install(&topo.a.bridge, &["lo".to_string()])
        .expect("install jail A")
        .expect("jail enforced by default");
    let jail_b = TreeNetJail::install(&topo.b.bridge, &["lo".to_string()])
        .expect("install jail B")
        .expect("jail enforced by default");

    assert!(
        !topo.a.can_reach(&topo.b.guest_ip()),
        "jailed tree A reached tree B's guest — inter-tree traffic must be dropped"
    );
    assert!(
        !topo.b.can_reach(&topo.a.guest_ip()),
        "jailed tree B reached tree A's guest — the drop must be symmetric"
    );
    assert!(
        topo.a.can_reach(&topo.a.gateway_ip()),
        "the jail must not cut a guest off from its own gateway"
    );

    drop(jail_a);
    drop(jail_b);
    assert!(
        topo.a.can_reach(&topo.b.guest_ip()),
        "dropping the jails must restore the pre-jail behaviour"
    );
}

/// The table exists exactly as long as the guard does.
#[test]
fn test_jail_table_removed_on_drop() {
    let bridge = "k7-br-njdrop";
    let _ = Command::new("ip")
        .args(["link", "add", "name", bridge, "type", "bridge"])
        .status();
    let jail = TreeNetJail::install(bridge, &["lo".to_string()])
        .expect("install")
        .expect("enforced");
    assert_eq!(jail.table(), table_name(bridge));
    assert!(jail_installed(bridge));
    drop(jail);
    assert!(!jail_installed(bridge), "Drop must remove the table");
    let _ = Command::new("ip")
        .args(["link", "delete", bridge, "type", "bridge"])
        .status();
}

/// A table whose bridge died with the daemon is reaped at startup.
#[test]
fn test_stale_jail_reaped() {
    let bridge = "k7-br-njgone";
    let _ = Command::new("ip")
        .args(["link", "add", "name", bridge, "type", "bridge"])
        .status();
    let jail = TreeNetJail::install(bridge, &["lo".to_string()])
        .expect("install")
        .expect("enforced");
    std::mem::forget(jail); // simulate a daemon that died without its Drops
    let _ = Command::new("ip")
        .args(["link", "delete", bridge, "type", "bridge"])
        .status();

    let removed = clean_stale_jails();
    assert!(
        removed.contains(&table_name(bridge)),
        "stale table not reaped: {removed:?}"
    );
    assert!(!jail_installed(bridge));
}
