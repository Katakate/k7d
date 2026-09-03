//! the referenced work layer 2 + the referenced work: the per-tree network jail.
//!
//! The properties under test are "two trees on one node cannot reach
//! each other" (29a), and 29b's extensions: the egress policy
//! (Open/Deny/Whitelist), host lockdown on the `input` hook, per-TAP
//! anti-spoof, the per-tree conntrack/rate caps, and the always-on
//! metadata (`169.254.0.0/16`) deny. They are tested where they live —
//! the host's nftables hooks — rather than through booted guests. Each
//! `k7-br-*` bridge gets a veth into its own network namespace, which
//! is exactly the topology a tree bridge presents to the kernel, and a
//! separate "wan" namespace behind a plain veth stands in for the
//! outside world (its host-side interface is the jail's WAN iface).
//!
//! Deliberately *with* the `FORWARD -i <bridge> -j ACCEPT` iptables
//! rules `ClusterNetwork::create` installs: the jail is only worth
//! anything if it beats them, so the tests prove the baseline is
//! reachable first and then that the jail closes it.
//!
//! RoCEv2/Soft-RoCE  rides the guest TAP as **UDP/4791**
//! — `test_egress_policy_modes` proves the jail treats it like any
//! other UDP (egress 4791 drops under Deny, passes when whitelisted)
//! and that *intra-tree* 4791 keeps flowing under Deny, which is what
//! the multi-node ML labs need.

use std::net::Ipv4Addr;
use std::process::Command;

use k7d::netjail::{
    clean_stale_jails, clean_stale_tap_jails, jail_installed, table_name, tap_jail_installed,
    tap_table_name, CidrPort, EgressMode, EgressPolicy, JailIfaces, TapAntiSpoof, TreeNetJail,
};

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
        self.in_ns(&["ip", "link", "set", "lo", "up"]);
        self.in_ns(&[
            "ip",
            "addr",
            "add",
            &format!("{}/24", self.guest_ip()),
            "dev",
            veth_ns,
        ]);
        self.in_ns(&["ip", "link", "set", veth_ns, "up"]);
        self.in_ns(&["ip", "route", "add", "default", "via", &self.gateway_ip()]);
        // The same FORWARD ACCEPTs `ClusterNetwork::create` installs —
        // the jail has to beat them, so they must be present.
        for spec in [["-i", self.bridge.as_str()], ["-o", self.bridge.as_str()]] {
            let _ = Command::new("iptables")
                .args(["-I", "FORWARD", spec[0], spec[1], "-j", "ACCEPT"])
                .status();
        }
    }

    fn in_ns(&self, args: &[&str]) {
        let mut full = vec!["ip", "netns", "exec", &self.netns];
        full.extend_from_slice(args);
        run(&full);
    }

    /// Can this side reach `target` in one second?
    fn can_reach(&self, target: &str) -> bool {
        ping_from(&self.netns, target)
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
        // Deleting the bridge unenslaves the host veth; it does not
        // delete it. A leftover `njhaa` makes the next `ip link add`
        // fail with EEXIST (CHALLENGES #167).
        let _ = Command::new("ip")
            .args(["link", "delete", &self.veth_host])
            .status();
        let _ = Command::new("ip")
            .args(["link", "delete", &self.bridge, "type", "bridge"])
            .status();
    }
}

/// A second guest namespace attached to an existing [`Side`]'s bridge —
/// the "sibling in the same tree" for intra-tree assertions.
struct Sibling {
    netns: String,
    veth_host: String,
    ip: String,
}

impl Sibling {
    fn up(side: &Side, tag: &str, host_octet: u8) -> Self {
        let netns = format!("k7jail-test-{tag}");
        let veth_host = format!("njh{tag}");
        let veth_ns = format!("njg{tag}");
        let ip = format!("10.{}.0.{host_octet}", side.subnet);
        let _ = Command::new("ip")
            .args(["netns", "delete", &netns])
            .status();
        run(&["ip", "netns", "add", &netns]);
        run(&[
            "ip", "link", "add", &veth_host, "type", "veth", "peer", "name", &veth_ns,
        ]);
        run(&["ip", "link", "set", &veth_ns, "netns", &netns]);
        run(&["ip", "link", "set", &veth_host, "master", &side.bridge]);
        run(&["ip", "link", "set", &veth_host, "up"]);
        run(&[
            "ip", "netns", "exec", &netns, "ip", "link", "set", "lo", "up",
        ]);
        run(&[
            "ip",
            "netns",
            "exec",
            &netns,
            "ip",
            "addr",
            "add",
            &format!("{ip}/24"),
            "dev",
            &veth_ns,
        ]);
        run(&[
            "ip", "netns", "exec", &netns, "ip", "link", "set", &veth_ns, "up",
        ]);
        Self {
            netns,
            veth_host,
            ip,
        }
    }
}

impl Drop for Sibling {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["netns", "delete", &self.netns])
            .status();
        let _ = Command::new("ip")
            .args(["link", "delete", &self.veth_host])
            .status();
    }
}

/// The "outside world": a namespace behind a plain (non-bridge) veth.
/// Its host-side interface plays the WAN / default-route iface, so the
/// jail's egress verdicts are observable without touching the node's
/// real uplink. It also owns `169.254.169.254` (the metadata address),
/// routed to it from the host.
struct WanSide {
    netns: String,
    veth_host: String,
}

const WAN_HOST_IP: &str = "203.0.113.1";
const WAN_NS_IP: &str = "203.0.113.2";
const METADATA_IP: &str = "169.254.169.254";

impl WanSide {
    fn up(guest_subnets: &[u8]) -> Self {
        let netns = "k7jail-test-wan".to_string();
        let veth_host = "njhwan".to_string();
        let veth_ns = "njgwan";
        let _ = Command::new("ip")
            .args(["netns", "delete", &netns])
            .status();
        let _ = Command::new("ip")
            .args(["link", "delete", &veth_host])
            .status();
        run(&["ip", "netns", "add", &netns]);
        run(&[
            "ip", "link", "add", &veth_host, "type", "veth", "peer", "name", veth_ns,
        ]);
        run(&["ip", "link", "set", veth_ns, "netns", &netns]);
        run(&[
            "ip",
            "addr",
            "add",
            &format!("{WAN_HOST_IP}/24"),
            "dev",
            &veth_host,
        ]);
        run(&["ip", "link", "set", &veth_host, "up"]);
        // Same as `ClusterNetwork::create`: strict reverse-path
        // filtering would drop the wan side's replies toward the
        // 10.x guest subnets before the jail is even consulted.
        let _ = std::fs::write(
            format!("/proc/sys/net/ipv4/conf/{veth_host}/rp_filter"),
            "0",
        );
        let _ = std::fs::write("/proc/sys/net/ipv4/conf/all/rp_filter", "0");
        let ns_exec = |args: &[&str]| {
            let mut full = vec!["ip", "netns", "exec", &netns];
            full.extend_from_slice(args);
            run(&full);
        };
        ns_exec(&["ip", "link", "set", "lo", "up"]);
        ns_exec(&[
            "ip",
            "addr",
            "add",
            &format!("{WAN_NS_IP}/24"),
            "dev",
            veth_ns,
        ]);
        // The wan namespace also owns the metadata address, so a guest
        // reaching 169.254.169.254 would actually get an answer if the
        // jail let the packet through.
        ns_exec(&[
            "ip",
            "addr",
            "add",
            &format!("{METADATA_IP}/32"),
            "dev",
            veth_ns,
        ]);
        ns_exec(&["ip", "link", "set", veth_ns, "up"]);
        // Return routes to the guest subnets.
        for subnet in guest_subnets {
            ns_exec(&[
                "ip",
                "route",
                "add",
                &format!("10.{subnet}.0.0/24"),
                "via",
                WAN_HOST_IP,
            ]);
        }
        // Host route: metadata lives behind the wan veth.
        run(&[
            "ip",
            "route",
            "add",
            &format!("{METADATA_IP}/32"),
            "via",
            WAN_NS_IP,
            "dev",
            &veth_host,
        ]);
        Self { netns, veth_host }
    }

    fn ifaces(&self) -> JailIfaces {
        JailIfaces {
            wan: self.veth_host.clone(),
            restricted: Vec::new(),
        }
    }
}

impl Drop for WanSide {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["route", "del", &format!("{METADATA_IP}/32")])
            .status();
        let _ = Command::new("ip")
            .args(["netns", "delete", &self.netns])
            .status();
        let _ = Command::new("ip")
            .args(["link", "delete", &self.veth_host])
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
        let _ = clean_stale_tap_jails();
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

fn ping_from(netns: &str, target: &str) -> bool {
    Command::new("ip")
        .args(["netns", "exec", netns, "ping", "-c", "1", "-W", "1", target])
        .output()
        .expect("run ping")
        .status
        .success()
}

/// One ARP request/reply from `netns` on `iface` for `target`.
///
/// Used when two bridges share a guest /24: the host FIB has one
/// unicast route back to that guest IP, so ICMP replies leave via the
/// first bridge and never prove the second TAP still forwards.
/// ARP is L2 — the reply is addressed to this iface's MAC.
fn arp_reach(netns: &str, iface: &str, src_ip: &str, src_mac: &str, target: &str) -> bool {
    let script = format!(
        "import socket, struct, sys, time\n\
         iface, src_ip, dst_ip = {iface:?}, {src_ip:?}, {target:?}\n\
         src_mac = bytes.fromhex({src_mac:?}.replace(':', ''))\n\
         ETH_P_ARP = 0x0806\n\
         s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))\n\
         s.bind((iface, ETH_P_ARP))\n\
         s.settimeout(1.0)\n\
         pkt = (b'\\xff'*6 + src_mac + struct.pack('!H', ETH_P_ARP)\n\
                + struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1)\n\
                + src_mac + socket.inet_aton(src_ip)\n\
                + b'\\x00'*6 + socket.inet_aton(dst_ip))\n\
         s.send(pkt)\n\
         deadline = time.time() + 1.0\n\
         while time.time() < deadline:\n\
         \x20   try:\n\
         \x20       rec = s.recv(65535)\n\
         \x20   except socket.timeout:\n\
         \x20       sys.exit(1)\n\
         \x20   if len(rec) < 42 or rec[12:14] != b'\\x08\\x06':\n\
         \x20       continue\n\
         \x20   if struct.unpack('!H', rec[20:22])[0] != 2:\n\
         \x20       continue\n\
         \x20   if rec[28:32] == socket.inet_aton(dst_ip) and rec[38:42] == socket.inet_aton(src_ip):\n\
         \x20       sys.exit(0)\n\
         sys.exit(1)\n"
    );
    Command::new("ip")
        .args(["netns", "exec", netns, "python3", "-c", &script])
        .output()
        .expect("arp reach")
        .status
        .success()
}

/// Emit one IPv6 EtherType frame from `netns` on `iface`.
///
/// `ping6` is not a reliable probe here: if DAD never finishes (the
/// pin drops the NS) the stack has no source address and sends nothing,
/// so the EtherType drop counter stays put.
fn emit_ipv6_frame(netns: &str, iface: &str, src_mac: &str) {
    let script = format!(
        "import socket, struct\n\
         iface = {iface:?}\n\
         src = bytes.fromhex({src_mac:?}.replace(':', ''))\n\
         s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x86DD))\n\
         s.bind((iface, 0x86DD))\n\
         s.send(b'\\xff'*6 + src + struct.pack('!H', 0x86DD) + b'\\x00'*40)\n"
    );
    let out = Command::new("ip")
        .args(["netns", "exec", netns, "python3", "-c", &script])
        .output()
        .expect("emit ipv6 frame");
    assert!(
        out.status.success(),
        "emit ipv6 frame: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Loopback stands in for "some host iface" in tests that don't care
/// about egress.
fn lo_ifaces() -> JailIfaces {
    JailIfaces {
        wan: "lo".to_string(),
        restricted: Vec::new(),
    }
}

fn open_policy() -> EgressPolicy {
    EgressPolicy::default()
}

fn deny_policy() -> EgressPolicy {
    EgressPolicy {
        mode: EgressMode::Deny,
        allow: Vec::new(),
        allow_dns: None,
    }
}

fn whitelist(allow: Vec<CidrPort>) -> EgressPolicy {
    EgressPolicy {
        mode: EgressMode::Whitelist,
        allow,
        allow_dns: None,
    }
}

/// Start a UDP echo server on `port` inside `netns`, bound to `bind`.
/// Returns the child; kill it by dropping the guard.
struct NsUdpEcho(std::process::Child);

impl NsUdpEcho {
    fn spawn(netns: &str, bind: &str, port: u16) -> Self {
        let script = format!(
            "import socket\n\
             s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n\
             s.bind((\"{bind}\", {port}))\n\
             while True:\n\
             \x20   data, addr = s.recvfrom(2048)\n\
             \x20   s.sendto(data, addr)\n"
        );
        let child = Command::new("ip")
            .args(["netns", "exec", netns, "python3", "-c", &script])
            .spawn()
            .expect("spawn udp echo");
        // Give the socket a beat to bind.
        std::thread::sleep(std::time::Duration::from_millis(300));
        Self(child)
    }
}

impl Drop for NsUdpEcho {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// One UDP round trip from `netns` to `target:port` with a 1s
/// deadline. `true` means the echo came back.
fn udp_round_trip(netns: &str, target: &str, port: u16) -> bool {
    let script = format!(
        "import socket, sys\n\
         s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n\
         s.settimeout(1.0)\n\
         s.sendto(b\"roce?\", (\"{target}\", {port}))\n\
         try:\n\
         \x20   data, _ = s.recvfrom(2048)\n\
         \x20   sys.exit(0 if data == b\"roce?\" else 1)\n\
         except socket.timeout:\n\
         \x20   sys.exit(1)\n"
    );
    Command::new("ip")
        .args(["netns", "exec", netns, "python3", "-c", &script])
        .output()
        .expect("udp round trip")
        .status
        .success()
}

/// One TCP connect from `netns` to `target:port` with a 1s deadline.
fn tcp_connect(netns: &str, target: &str, port: u16) -> bool {
    let script = format!(
        "import socket, sys\n\
         s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n\
         s.settimeout(1.0)\n\
         try:\n\
         \x20   s.connect((\"{target}\", {port}))\n\
         \x20   sys.exit(0)\n\
         except OSError:\n\
         \x20   sys.exit(1)\n"
    );
    Command::new("ip")
        .args(["netns", "exec", netns, "python3", "-c", &script])
        .output()
        .expect("tcp connect")
        .status
        .success()
}

/// A TCP listener inside a namespace (or the host when `netns` is
/// `None`).
struct TcpListener(std::process::Child);

impl TcpListener {
    fn spawn(netns: Option<&str>, bind: &str, port: u16) -> Self {
        let script = format!(
            "import socket\n\
             s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n\
             s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n\
             s.bind((\"{bind}\", {port}))\n\
             s.listen(16)\n\
             while True:\n\
             \x20   c, _ = s.accept()\n\
             \x20   c.close()\n"
        );
        let child = match netns {
            Some(ns) => Command::new("ip")
                .args(["netns", "exec", ns, "python3", "-c", &script])
                .spawn()
                .expect("spawn tcp listener"),
            None => Command::new("python3")
                .args(["-c", &script])
                .spawn()
                .expect("spawn tcp listener"),
        };
        std::thread::sleep(std::time::Duration::from_millis(300));
        Self(child)
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Sum of `counter packets` on rules matching `needle` in `table`.
fn counter_packets(family: &str, table: &str, needle: &str) -> u64 {
    let out = Command::new("nft")
        .args(["list", "table", family, table])
        .output()
        .expect("nft list table");
    assert!(
        out.status.success(),
        "nft list table {family} {table}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut total = 0u64;
    for line in text.lines().filter(|l| l.contains(needle)) {
        if let Some(rest) = line.split("counter packets ").nth(1) {
            if let Some(n) = rest.split_whitespace().next() {
                total += n.parse::<u64>().unwrap_or(0);
            }
        }
    }
    total
}

fn with_env<T>(key: &str, val: &str, f: impl FnOnce() -> T) -> T {
    let prev = std::env::var(key).ok();
    std::env::set_var(key, val);
    let out = f();
    match prev {
        Some(v) => std::env::set_var(key, v),
        None => std::env::remove_var(key),
    }
    out
}

/// The jail denies bridge-to-bridge forwarding that the iptables
/// FORWARD ACCEPT rules allow, and (in Open mode) leaves the guest's
/// own gateway (host services, INPUT hook) alone.
#[test]
fn test_inter_tree_traffic_denied() {
    let topo = Topology::up();

    assert!(
        topo.a.can_reach(&topo.b.guest_ip()),
        "baseline: without a jail, tree A must be able to reach tree B \
         (otherwise this test proves nothing)"
    );

    let jail_a = TreeNetJail::install(&topo.a.bridge, &lo_ifaces(), &open_policy())
        .expect("install jail A")
        .expect("jail enforced by default");
    let jail_b = TreeNetJail::install(&topo.b.bridge, &lo_ifaces(), &open_policy())
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
        "the Open jail must not cut a guest off from its own gateway"
    );

    drop(jail_a);
    drop(jail_b);
    assert!(
        topo.a.can_reach(&topo.b.guest_ip()),
        "dropping the jails must restore the pre-jail behaviour"
    );
}

/// the referenced work §1: the egress knob. Open forwards to the WAN iface,
/// Deny does not, Whitelist forwards only the named CIDR:port pairs —
/// including UDP/4791 (RoCEv2), which must drop under Deny, pass when
/// whitelisted, and keep flowing *intra-tree* regardless of mode.
/// `169.254.0.0/16` drops in every mode unless whitelisted explicitly.
#[test]
#[allow(clippy::too_many_lines)]
fn test_egress_policy_modes() {
    let topo = Topology::up();
    let wan = WanSide::up(&[topo.a.subnet]);
    let sibling = Sibling::up(&topo.a, "as", 3);
    let _wan_udp = NsUdpEcho::spawn(&wan.netns, "0.0.0.0", 4791);
    let _wan_tcp = TcpListener::spawn(Some(&wan.netns), "0.0.0.0", 8080);
    let _meta_tcp = TcpListener::spawn(Some(&wan.netns), METADATA_IP, 80);

    // ── Open ──
    let jail = TreeNetJail::install(&topo.a.bridge, &wan.ifaces(), &open_policy())
        .expect("install open")
        .expect("enforced");
    assert!(
        topo.a.can_reach(WAN_NS_IP),
        "Open: guest must reach the WAN"
    );
    assert!(
        udp_round_trip(&topo.a.netns, WAN_NS_IP, 4791),
        "Open: UDP/4791 (RoCEv2) egress must work"
    );
    assert!(
        !tcp_connect(&topo.a.netns, METADATA_IP, 80),
        "Open: 169.254.169.254 (metadata) must be denied even under Open"
    );
    assert!(
        counter_packets("inet", jail.table(), "169.254.0.0/16") > 0,
        "the metadata drop rule should have counted the attempt"
    );
    drop(jail);

    // ── Deny ──
    let jail = TreeNetJail::install(&topo.a.bridge, &wan.ifaces(), &deny_policy())
        .expect("install deny")
        .expect("enforced");
    assert!(
        !topo.a.can_reach(WAN_NS_IP),
        "Deny: guest must not reach the WAN"
    );
    assert!(
        !udp_round_trip(&topo.a.netns, WAN_NS_IP, 4791),
        "Deny: UDP/4791 (RoCEv2) egress must be dropped — RDMA is not \
         a jail bypass"
    );
    // Intra-tree stays alive: the ML labs are multi-node RDMA inside
    // ONE tree, and that path must survive every posture.
    let _sib_udp = NsUdpEcho::spawn(&sibling.netns, "0.0.0.0", 4791);
    assert!(
        udp_round_trip(&topo.a.netns, &sibling.ip, 4791),
        "Deny: intra-tree UDP/4791 (RoCEv2 between members of one tree) \
         must keep working"
    );
    assert!(
        ping_from(&sibling.netns, &topo.a.guest_ip()),
        "Deny: intra-tree ICMP must keep working"
    );
    drop(jail);

    // ── Whitelist: 4791 to the WAN subnet, nothing else ──
    let jail = TreeNetJail::install(
        &topo.a.bridge,
        &wan.ifaces(),
        &whitelist(vec![CidrPort {
            cidr: "203.0.113.0/24".into(),
            port: 4791,
        }]),
    )
    .expect("install whitelist")
    .expect("enforced");
    assert!(
        udp_round_trip(&topo.a.netns, WAN_NS_IP, 4791),
        "Whitelist: the named CIDR:port (UDP/4791) must pass"
    );
    assert!(
        !tcp_connect(&topo.a.netns, WAN_NS_IP, 8080),
        "Whitelist: a port outside the allow set must drop"
    );
    assert!(
        !topo.a.can_reach(WAN_NS_IP),
        "Whitelist: ICMP to the WAN is not whitelisted and must drop"
    );
    assert!(
        !tcp_connect(&topo.a.netns, METADATA_IP, 80),
        "Whitelist: metadata not in the allow set must drop"
    );
    drop(jail);

    // ── Whitelist naming the metadata address explicitly wins ──
    let jail = TreeNetJail::install(
        &topo.a.bridge,
        &wan.ifaces(),
        &whitelist(vec![CidrPort {
            cidr: format!("{METADATA_IP}/32"),
            port: 80,
        }]),
    )
    .expect("install metadata whitelist")
    .expect("enforced");
    assert!(
        tcp_connect(&topo.a.netns, METADATA_IP, 80),
        "an explicit 169.254.169.254/32:80 whitelist entry must override \
         the metadata deny"
    );
    drop(jail);
}

/// the referenced work §2: host lockdown. Under Deny/Whitelist a guest cannot
/// reach a service bound on the gateway (the host), and a whitelist
/// entry naming the gateway explicitly re-opens exactly that port.
/// Open keeps today's behaviour (guest→host allowed).
#[test]
fn test_host_lockdown() {
    let topo = Topology::up();
    let gw = topo.a.gateway_ip();
    // A deliberately 0.0.0.0-bound "mis-bound host service" — reachable
    // via the gateway address from inside the tree.
    let _svc = TcpListener::spawn(None, "0.0.0.0", 18099);

    let jail = TreeNetJail::install(&topo.a.bridge, &lo_ifaces(), &open_policy())
        .expect("install open")
        .expect("enforced");
    assert!(
        tcp_connect(&topo.a.netns, &gw, 18099),
        "Open: guest→host service must keep working (iSCSI/NFS parity \
         after the iptables INPUT ACCEPT was drained)"
    );
    drop(jail);

    let jail = TreeNetJail::install(&topo.a.bridge, &lo_ifaces(), &deny_policy())
        .expect("install deny")
        .expect("enforced");
    assert!(
        !tcp_connect(&topo.a.netns, &gw, 18099),
        "Deny: the host service must be unreachable from the guest"
    );
    assert!(
        !topo.a.can_reach(&gw),
        "Deny: even ICMP to the gateway must drop (host lockdown)"
    );
    drop(jail);

    let jail = TreeNetJail::install(
        &topo.a.bridge,
        &lo_ifaces(),
        &whitelist(vec![CidrPort {
            cidr: format!("{gw}/32"),
            port: 18099,
        }]),
    )
    .expect("install whitelist")
    .expect("enforced");
    assert!(
        tcp_connect(&topo.a.netns, &gw, 18099),
        "Whitelist naming the gateway:port must re-open exactly that \
         service (the input chain honours the allow set)"
    );
    assert!(
        !topo.a.can_reach(&gw),
        "Whitelist: ICMP to the gateway stays dropped"
    );
    drop(jail);
}

/// the referenced work §3: per-TAP anti-spoof, verified with duplicate IPs across
/// two live trees (the load-bearing constraint: forks REUSE guest IPs,
/// so the pin is per-TAP, never a global source-IP set). Also proves
/// the v6/EtherType lockdown (§5): the guest cannot emit IPv6.
#[test]
#[allow(clippy::too_many_lines)]
fn test_tap_anti_spoof() {
    let topo = Topology::up();

    // Give tree B's guest the SAME IP as tree A's guest — both pins
    // must hold simultaneously because they are per-TAP.
    let dup_ip = topo.a.guest_ip(); // 10.201.0.2
    topo.b
        .in_ns(&["ip", "addr", "flush", "dev", &topo.b.veth_ns]);
    topo.b.in_ns(&[
        "ip",
        "addr",
        "add",
        &format!("{dup_ip}/24"),
        "dev",
        &topo.b.veth_ns,
    ]);
    // B's bridge needs a matching gateway for the duplicate subnet.
    run(&[
        "ip",
        "addr",
        "add",
        &format!("10.{}.0.1/24", topo.a.subnet),
        "dev",
        &topo.b.bridge,
    ]);
    // A unique /32 on B is the ARP target. Do not ICMP-ping it from
    // the duplicate guest IP: the host's one FIB entry for
    // 10.{A}.0.2 prefers A's connected /24, so the echo reply never
    // reaches B (CHALLENGES #167). ARP is L2 and stays on B's TAP.
    let b_unique = format!("10.{}.0.254", topo.a.subnet);
    run(&[
        "ip",
        "addr",
        "add",
        &format!("{b_unique}/32"),
        "dev",
        &topo.b.bridge,
    ]);

    let mac_of = |netns: &str, dev: &str| -> String {
        let out = Command::new("ip")
            .args([
                "netns",
                "exec",
                netns,
                "cat",
                &format!("/sys/class/net/{dev}/address"),
            ])
            .output()
            .expect("read mac");
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    let parse_mac = |s: &str| -> [u8; 6] {
        let mut out = [0u8; 6];
        for (i, part) in s.split(':').enumerate() {
            out[i] = u8::from_str_radix(part, 16).expect("mac octet");
        }
        out
    };

    let mac_a_s = mac_of(&topo.a.netns, &topo.a.veth_ns);
    let mac_b_s = mac_of(&topo.b.netns, &topo.b.veth_ns);
    let mac_a = parse_mac(&mac_a_s);
    let mac_b = parse_mac(&mac_b_s);
    let ip: Ipv4Addr = dup_ip.parse().unwrap();

    let jail_a = TapAntiSpoof::install(&topo.a.veth_host, mac_a, ip)
        .expect("install anti-spoof A")
        .expect("enforced");
    let _jail_b = TapAntiSpoof::install(&topo.b.veth_host, mac_b, ip)
        .expect("install anti-spoof B")
        .expect("enforced");
    assert!(tap_jail_installed(&topo.a.veth_host));

    // Both guests, same IP, different trees: both pins hold.
    assert!(
        topo.a.can_reach(&topo.a.gateway_ip()),
        "A with its assigned (mac, ip) must reach its gateway"
    );
    assert!(
        arp_reach(&topo.b.netns, &topo.b.veth_ns, &dup_ip, &mac_b_s, &b_unique),
        "B with the DUPLICATE ip must ARP a host address unique to its \
         own bridge (per-TAP pins must not collide across trees)"
    );

    // Spoofed source IP: dropped (and so is the ARP sender ip).
    topo.a
        .in_ns(&["ip", "addr", "flush", "dev", &topo.a.veth_ns]);
    topo.a.in_ns(&[
        "ip",
        "addr",
        "add",
        &format!("10.{}.0.9/24", topo.a.subnet),
        "dev",
        &topo.a.veth_ns,
    ]);
    assert!(
        !topo.a.can_reach(&topo.a.gateway_ip()),
        "a spoofed ip saddr must be dropped at the TAP"
    );
    assert!(
        counter_packets("netdev", &tap_table_name(&topo.a.veth_host), "saddr") > 0,
        "the anti-spoof drop rules should have counted"
    );

    // Restore the IP, spoof the MAC: dropped.
    topo.a
        .in_ns(&["ip", "addr", "flush", "dev", &topo.a.veth_ns]);
    topo.a.in_ns(&[
        "ip",
        "addr",
        "add",
        &format!("{dup_ip}/24"),
        "dev",
        &topo.a.veth_ns,
    ]);
    assert!(
        topo.a.can_reach(&topo.a.gateway_ip()),
        "restored identity must work again"
    );

    // Host-gw CNI parity: a source OUTSIDE the guest /24 (a pod-CIDR
    // address the guest legitimately routes, flannel host-gw style)
    // must pass the pin — only another guest's 10.x.0.x is spoofing.
    topo.a
        .in_ns(&["ip", "addr", "add", "10.60.0.5/24", "dev", &topo.a.veth_ns]);
    // Route the "pod subnet" back to the guest so replies return; the
    // route dies with the bridge at teardown.
    run(&[
        "ip",
        "route",
        "add",
        "10.60.0.0/24",
        "via",
        &topo.a.guest_ip(),
        "dev",
        &topo.a.bridge,
    ]);
    let out = Command::new("ip")
        .args([
            "netns",
            "exec",
            &topo.a.netns,
            "ping",
            "-c",
            "1",
            "-W",
            "1",
            "-I",
            "10.60.0.5",
            &topo.a.gateway_ip(),
        ])
        .output()
        .expect("ping with pod-cidr source");
    assert!(
        out.status.success(),
        "a pod-CIDR source (10.60.0.5, outside the guest /24) must pass \
         the anti-spoof pin — flannel host-gw traffic is legitimate: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    topo.a
        .in_ns(&["ip", "addr", "del", "10.60.0.5/24", "dev", &topo.a.veth_ns]);

    topo.a
        .in_ns(&["ip", "link", "set", &topo.a.veth_ns, "down"]);
    topo.a.in_ns(&[
        "ip",
        "link",
        "set",
        &topo.a.veth_ns,
        "address",
        "02:11:22:33:44:55",
    ]);
    topo.a.in_ns(&["ip", "link", "set", &topo.a.veth_ns, "up"]);
    // Link flap flushed the address; re-add with the spoofed MAC.
    topo.a.in_ns(&[
        "ip",
        "addr",
        "replace",
        &format!("{dup_ip}/24"),
        "dev",
        &topo.a.veth_ns,
    ]);
    assert!(
        !topo.a.can_reach(&topo.a.gateway_ip()),
        "a spoofed ether saddr must be dropped at the TAP"
    );

    // §5: guest IPv6 (and any non-IP/ARP EtherType) is dropped at the
    // TAP — the jail cannot be routed around over v6.
    let before = counter_packets("netdev", &tap_table_name(&topo.b.veth_host), "counter");
    // Raw EtherType 0x86dd — do not depend on ping6 having a
    // non-tentative link-local (the pin drops DAD NS).
    emit_ipv6_frame(&topo.b.netns, &topo.b.veth_ns, &mac_b_s);
    let after = counter_packets("netdev", &tap_table_name(&topo.b.veth_host), "counter");
    assert!(
        after > before,
        "the EtherType drop should have counted the v6 frames ({before} -> {after})"
    );

    drop(jail_a);
    assert!(
        !tap_jail_installed(&topo.a.veth_host),
        "Drop must remove the TAP table"
    );
}

/// the referenced work §4: the per-tree conntrack and new-connection rate caps
/// engage under a flood from one tree.
#[test]
fn test_ct_and_rate_caps() {
    let topo = Topology::up();
    let wan = WanSide::up(&[topo.a.subnet]);
    let _wan_udp = NsUdpEcho::spawn(&wan.netns, "0.0.0.0", 4791);

    // Tiny caps so a small flood trips them.
    let (ct_trips, rate_trips) = with_env("K7D_NET_JAIL_CT_MAX", "8", || {
        with_env("K7D_NET_JAIL_NEW_RATE", "16", || {
            let jail = TreeNetJail::install(&topo.a.bridge, &wan.ifaces(), &open_policy())
                .expect("install capped jail")
                .expect("enforced");
            // 200 datagrams from 200 distinct source ports = 200
            // would-be conntrack entries, sent as fast as python can.
            let script = format!(
                "import socket\n\
                 for i in range(200):\n\
                 \x20   s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n\
                 \x20   s.sendto(b\"x\", (\"{WAN_NS_IP}\", 4791))\n\
                 \x20   s.close()\n"
            );
            run(&[
                "ip",
                "netns",
                "exec",
                &topo.a.netns,
                "python3",
                "-c",
                &script,
            ]);
            let ct = counter_packets("inet", jail.table(), "ct count over");
            let rate = counter_packets("inet", jail.table(), "limit rate over");
            drop(jail);
            (ct, rate)
        })
    });
    assert!(
        ct_trips > 0 || rate_trips > 0,
        "a 200-flow burst against ct_max=8/rate=16 must trip at least one \
         cap (ct={ct_trips}, rate={rate_trips})"
    );
}

/// The table exists exactly as long as the guard does.
#[test]
fn test_jail_table_removed_on_drop() {
    let bridge = "k7-br-njdrop";
    let _ = Command::new("ip")
        .args(["link", "add", "name", bridge, "type", "bridge"])
        .status();
    let jail = TreeNetJail::install(bridge, &lo_ifaces(), &open_policy())
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
    let jail = TreeNetJail::install(bridge, &lo_ifaces(), &open_policy())
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
