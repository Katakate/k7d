//! Per-tree network jail: an nftables table scoped to one `k7-br-{id}`
//! bridge.
//!
//! Every live cluster payload — a tree root, a forked node, an adopted
//! cluster — owns one bridge, and every guest on every bridge sits in
//! the same `10.200.0.0/24`. The iptables rules k7d installs for a
//! bridge are `FORWARD -i k7-br-A -j ACCEPT` / `FORWARD -o k7-br-A -j
//! ACCEPT`, so before this module two trees on one node could route to
//! each other's guests: the host forwarded between the bridges and both
//! ends were explicitly accepted.
//!
//! The jail is a table per bridge, `k7jail-{bridge}`, with a `forward`
//! chain and an `input` chain, both at priority
//! `filter - 1` so they are evaluated *before* the iptables rules:
//!
//! ```text
//! chain forward:
//!   iifname != B oifname != B    return   # not this bridge's traffic
//!   iifname B    oifname B       accept   # intra-tree, guest to guest
//!   ct state established,related accept   # replies to allowed flows
//!   iifname "k7-br-*" oifname "k7-br-*" counter drop   # INTER-TREE
//!   iifname B ct state new ct count over N counter drop      # ct cap
//!   iifname B ct state new limit rate over R/second ... drop # rate cap
//!   [Whitelist: iifname B ip daddr . th dport @egress_allow accept]
//!   [Whitelist: iifname B ip daddr <dns> {udp,tcp} dport 53 accept]
//!   iifname B ip daddr 169.254.0.0/16 counter drop  # metadata, always
//!   iifname B oifname { egress ifaces } accept      # mode-dependent
//!   oifname B iifname { inbound ifaces } accept
//!   counter drop                                    # default deny
//!
//! chain input:                          # host lockdown
//!   iifname != B return
//!   [Open: counter accept]              # parity with the drained
//!                                       # iptables INPUT ACCEPT
//!   [Deny/Whitelist:
//!     ct state established,related accept
//!     [Whitelist set + allow_dns accepts]
//!     counter drop]
//! ```
//!
//! ## Egress policy
//!
//! [`EgressPolicy`] decides what a guest may reach *outside its own
//! bridge*, carried per tree (fork inherits the source's policy):
//!
//! * **Open** (default) — today's behaviour: egress via the host's
//!   default-route interface and the CNI path. The `RuntimeClass` product
//!   and every existing test run in this mode.
//! * **Deny** — no WAN egress at all. The CNI/pod-net interfaces stay
//!   forwardable (intra-node, not "the outside world").
//! * **Whitelist** — only `allow` CIDR:port pairs (tcp+udp) and, if
//!   set, `allow_dns` on port 53. Everything else drops. Whitelist
//!   entries are also honoured by the `input` chain, so a policy can
//!   name a host/gateway service explicitly.
//!
//! `169.254.0.0/16` (cloud metadata / link-local) is dropped in **all**
//! modes unless a whitelist entry names it explicitly — the whitelist
//! accepts run before the metadata drop.
//!
//! **RDMA / `Soft-RoCE` note:** `RoCEv2` encapsulates in **UDP/4791**. The
//! jail sees it like any other UDP (verified by test): intra-tree RDMA
//! (multi-node ML labs inside one tree) rides the bridge at L2 and is
//! never dropped, but *egress* `RoCE` is subject to the policy — an
//! operator enabling an ML lab that needs RDMA to leave the tree must
//! whitelist `<cidr>:4791` explicitly.
//!
//! ## Per-TAP anti-spoof
//!
//! All bridges share `10.200.0.0/24` and forks reuse guest IPs, so
//! anti-spoof cannot be a global source-IP set — the same IP is valid
//! in multiple trees. [`TapAntiSpoof`] is a `netdev`-family ingress
//! chain per TAP that drops any frame whose `ether saddr` or ARP
//! sender fields differ from the TAP's *assigned* `(mac, ip)`, or
//! whose `ip saddr` claims *another guest's* address in the shared
//! guest /24 (sources outside that subnet are legitimate routed
//! workload traffic — flannel host-gw pod CIDRs — see [`tap_ruleset`]),
//! and drops every `EtherType` except IPv4 and ARP (which also disables
//! guest IPv6 and VLAN-tag evasion — we pick "disable v6 on
//! the TAP" over a parallel v6 ruleset; the `inet`-family bridge chains
//! additionally fail closed for any v6 that could appear).
//!
//! Teardown is RAII: [`ClusterNetwork::destroy`](crate::network::ClusterNetwork)
//! drops the bridge table when it deletes the bridge, and the TAP jail
//! drops with its [`TapDevice`](crate::network::TapDevice). A daemon
//! that dies without running its `Drop`s leaves tables behind, so
//! [`clean_stale_jails`] / [`clean_stale_tap_jails`] reap every table
//! whose bridge/TAP no longer exists at startup — a stale table would
//! otherwise silently filter a later link that happened to reuse the
//! name.
//!
//! The agent **vsock** channel is deliberately not jailed here: it is
//! the harness's control plane, point-to-point to the host CID (no
//! inter-tree vsock path exists). Keeping the rogue *workload* away
//! from `AF_VSOCK` is guest-image hardening, tracked separately.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::netns::run_capture;

/// Prefix of every bridge table this module owns. The bridge name is
/// appended verbatim, which is what makes [`clean_stale_jails`] able to
/// decide whether a table is stale by looking at the host's links.
const TABLE_PREFIX: &str = "k7jail-";

/// Prefix of every per-TAP anti-spoof table (family `netdev`). The TAP
/// device name is appended verbatim (same reaping contract).
const TAP_TABLE_PREFIX: &str = "k7tapjail-";

/// Host interfaces a jailed guest may always be forwarded to/from, on
/// top of the host's default-route interface: reaching the node's pod
/// network is existing, tested behaviour and is intra-node — it stays
/// permitted even under `Deny`/`Whitelist`.
const CNI_IFACES: [&str; 2] = ["cni0", "flannel.1"];

/// Default per-tree concurrent-connection cap. Generous:
/// an inner-k3s cluster's egress (image pulls, DNS) is far below this;
/// a rogue flood is far above. Override with `K7D_NET_JAIL_CT_MAX`.
const DEFAULT_CT_MAX: u32 = 16384;

/// Default per-tree new-connection rate cap in packets/second.
/// Override with `K7D_NET_JAIL_NEW_RATE`.
const DEFAULT_NEW_RATE: u32 = 2000;

/// Whether the jail is enforced. `K7D_NET_JAIL=off` skips installation
/// entirely (the escape hatch for debugging a suspected jail bug on a
/// live node); any other value than `enforce`/`off` is a loud error.
fn enforced() -> Result<bool, String> {
    match std::env::var("K7D_NET_JAIL") {
        Err(_) => Ok(true),
        Ok(v) => match v.trim() {
            "" | "enforce" => Ok(true),
            "off" => Ok(false),
            other => Err(format!("K7D_NET_JAIL={other:?} is not one of enforce|off")),
        },
    }
}

/// Parse a `u32` cap from `key`, defaulting to `default` when unset.
/// Garbage or zero is a loud error, never a silent fallback.
fn env_cap(key: &str, default: u32) -> Result<u32, String> {
    match std::env::var(key) {
        Err(_) => Ok(default),
        Ok(v) => match v.trim().parse::<u32>() {
            Ok(0) => Err(format!("{key}=0 would drop all new connections")),
            Ok(n) => Ok(n),
            Err(e) => Err(format!("{key}={v:?} is not a u32: {e}")),
        },
    }
}

/// Egress posture of one tree. `Open` is the default:
/// the `RuntimeClass` product and every legacy test run unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressMode {
    /// Today's behaviour — WAN + CNI egress allowed.
    #[default]
    Open,
    /// No WAN egress; CNI/pod-net (intra-node) still forwarded.
    Deny,
    /// Only [`EgressPolicy::allow`] CIDR:port pairs (and
    /// [`EgressPolicy::allow_dns`]) leave the tree.
    Whitelist,
}

/// One whitelist entry: an IPv4 CIDR and a destination port, matched
/// for both TCP and UDP (`RoCEv2` is UDP/4791 — name it explicitly if an
/// ML lab needs RDMA to leave the tree).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CidrPort {
    /// Destination IPv4 CIDR, e.g. `"140.82.112.0/20"` or a single
    /// address `"10.200.0.1/32"`.
    pub cidr: String,
    /// Destination port (tcp and udp).
    pub port: u16,
}

impl CidrPort {
    /// Validate `cidr` parses as `<ipv4>/<prefix ≤ 32>`.
    fn validate(&self) -> Result<(), String> {
        let (addr, prefix) = self
            .cidr
            .split_once('/')
            .ok_or_else(|| format!("egress allow cidr {:?} must be <addr>/<prefix>", self.cidr))?;
        addr.parse::<Ipv4Addr>()
            .map_err(|e| format!("egress allow cidr {:?}: bad address: {e}", self.cidr))?;
        let p: u8 = prefix
            .parse()
            .map_err(|e| format!("egress allow cidr {:?}: bad prefix: {e}", self.cidr))?;
        if p > 32 {
            return Err(format!("egress allow cidr {:?}: prefix > 32", self.cidr));
        }
        Ok(())
    }
}

/// Per-tree egress policy, threaded from the tree control op
/// (`tree_create_cluster` / `tree_adopt_cluster`; forks inherit their
/// source's policy) into [`TreeNetJail::install`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EgressPolicy {
    /// The posture. Default [`EgressMode::Open`].
    #[serde(default)]
    pub mode: EgressMode,
    /// Whitelist-only: destination CIDR:port pairs allowed out.
    #[serde(default)]
    pub allow: Vec<CidrPort>,
    /// Whitelist-only: resolver allowed on udp/tcp 53.
    #[serde(default)]
    pub allow_dns: Option<Ipv4Addr>,
}

impl EgressPolicy {
    /// Validate the policy. Loud on nonsense: `allow`/`allow_dns` on a
    /// non-whitelist mode is a config error, not something to ignore.
    pub fn validate(&self) -> Result<(), String> {
        if self.mode != EgressMode::Whitelist
            && (!self.allow.is_empty() || self.allow_dns.is_some())
        {
            return Err(format!(
                "egress policy: allow/allow_dns are only meaningful with mode=whitelist \
                 (mode is {:?})",
                self.mode
            ));
        }
        for entry in &self.allow {
            entry.validate()?;
        }
        Ok(())
    }
}

/// The host interfaces the jail distinguishes: the WAN (default-route)
/// interface — "the outside world", subject to [`EgressMode`] — and
/// the restricted set (CNI/pod-net + operator extras) that stays
/// forwardable in every mode.
#[derive(Debug, Clone)]
pub struct JailIfaces {
    /// The host's default-route interface (guest egress via the
    /// existing MASQUERADE).
    pub wan: String,
    /// CNI interfaces that exist plus `K7D_NET_JAIL_ALLOW_IFACES`
    /// (comma-separated) — intra-node, allowed in every mode.
    pub restricted: Vec<String>,
}

impl JailIfaces {
    /// Detect the interface sets for `default_iface`.
    #[must_use]
    pub fn detect(default_iface: &str) -> Self {
        let mut restricted = Vec::new();
        for iface in CNI_IFACES {
            if Path::new("/sys/class/net").join(iface).exists() {
                restricted.push(iface.to_string());
            }
        }
        if let Ok(extra) = std::env::var("K7D_NET_JAIL_ALLOW_IFACES") {
            for iface in extra.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                restricted.push(iface.to_string());
            }
        }
        // nft rejects a duplicate element inside an anonymous set, so a
        // default route that is also named in the env var must collapse.
        restricted.sort();
        restricted.dedup();
        restricted.retain(|i| i != default_iface);
        Self {
            wan: default_iface.to_string(),
            restricted,
        }
    }

    /// All interfaces (WAN + restricted), for Open-mode egress and the
    /// inbound rule.
    fn all(&self) -> Vec<String> {
        let mut out = vec![self.wan.clone()];
        out.extend(self.restricted.iter().cloned());
        out.sort();
        out.dedup();
        out
    }
}

/// Table name for `bridge`.
#[must_use]
pub fn table_name(bridge: &str) -> String {
    format!("{TABLE_PREFIX}{bridge}")
}

/// Anti-spoof table name for `tap`.
#[must_use]
pub fn tap_table_name(tap: &str) -> String {
    format!("{TAP_TABLE_PREFIX}{tap}")
}

/// One bridge's nftables jail. Dropping it deletes the table.
#[derive(Debug)]
pub struct TreeNetJail {
    bridge: String,
    table: String,
}

impl TreeNetJail {
    /// Install the jail for `bridge` under `policy`, forwarding to and
    /// from the interfaces in `ifaces` as the mode allows. Returns
    /// `Ok(None)` when `K7D_NET_JAIL=off`.
    ///
    /// Re-installing over an existing table is an atomic replace, not
    /// an append: `ClusterNetwork::create` is idempotent across
    /// cooperating pods on a shared bridge, and appending would stack
    /// duplicate rule sets until the counters were meaningless.
    pub fn install(
        bridge: &str,
        ifaces: &JailIfaces,
        policy: &EgressPolicy,
    ) -> Result<Option<Self>, String> {
        policy.validate()?;
        if !enforced()? {
            log::warn!("K7D_NET_JAIL=off: bridge {bridge} runs unjailed");
            return Ok(None);
        }
        let table = table_name(bridge);
        let ct_max = env_cap("K7D_NET_JAIL_CT_MAX", DEFAULT_CT_MAX)?;
        let new_rate = env_cap("K7D_NET_JAIL_NEW_RATE", DEFAULT_NEW_RATE)?;
        let ruleset = ruleset(bridge, &table, ifaces, policy, ct_max, new_rate);
        // The elapsed time is part of the message on purpose: this is one
        // `nft` process on the fork path, and it is the jail's whole
        // measured cost (`LATENCY_BUDGETS.md`). A regression
        // here shows up in the daemon log before it shows up as a blown
        // fork budget.
        let t0 = std::time::Instant::now();
        apply_ruleset(&table, &ruleset)?;
        log::info!(
            "net jail {table} installed in {:?} (mode {:?}, wan {}, restricted {:?})",
            t0.elapsed(),
            policy.mode,
            ifaces.wan,
            ifaces.restricted,
        );
        Ok(Some(Self {
            bridge: bridge.to_string(),
            table,
        }))
    }

    /// Delete this bridge's table. Idempotent — a table someone else
    /// already removed is success, not an error.
    pub fn remove(&self) -> Result<(), String> {
        delete_table("inet", &self.table)
    }

    /// The bridge this jail is scoped to.
    #[must_use]
    pub fn bridge(&self) -> &str {
        &self.bridge
    }

    /// This jail's nftables table name.
    #[must_use]
    pub fn table(&self) -> &str {
        &self.table
    }
}

impl Drop for TreeNetJail {
    fn drop(&mut self) {
        if let Err(e) = self.remove() {
            log::error!("remove net jail {}: {e}", self.table);
        }
    }
}

/// Render the ruleset for `bridge` under `policy`.
#[allow(clippy::too_many_lines)]
fn ruleset(
    bridge: &str,
    table: &str,
    ifaces: &JailIfaces,
    policy: &EgressPolicy,
    ct_max: u32,
    new_rate: u32,
) -> String {
    let iface_set = |ifaces: &[String]| {
        ifaces
            .iter()
            .map(|i| format!("\"{i}\""))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let all = ifaces.all();
    // Which interfaces guest-originated traffic may be forwarded OUT
    // to. Open: everything. Deny/Whitelist: never the WAN — under
    // Whitelist the daddr:port set (rendered separately) is the only
    // WAN path.
    let egress_ifaces = match policy.mode {
        EgressMode::Open => all.clone(),
        EgressMode::Deny | EgressMode::Whitelist => ifaces.restricted.clone(),
    };
    // Which interfaces may originate NEW inbound connections to the
    // guest. Open: everything (today's behaviour). Deny/Whitelist:
    // intra-node only — an outside accomplice must not be able to open
    // a channel into a contained tree (replies ride established,related).
    let inbound_ifaces = match policy.mode {
        EgressMode::Open => all,
        EgressMode::Deny | EgressMode::Whitelist => ifaces.restricted.clone(),
    };

    // `table` then `delete table` then the definition is nft's atomic
    // replace idiom: the bare `table` line creates it when missing so
    // the `delete` cannot fail on a first install.
    let mut out = format!(
        "table inet {table}\n\
         delete table inet {table}\n\
         table inet {table} {{\n"
    );

    // Whitelist destination set. Declared even when empty so the rule
    // referencing it is always valid; `flags interval` admits CIDRs.
    if policy.mode == EgressMode::Whitelist {
        out.push_str(
            "    set egress_allow {\n\
             \x20       type ipv4_addr . inet_service\n\
             \x20       flags interval\n",
        );
        if !policy.allow.is_empty() {
            let elements = policy
                .allow
                .iter()
                .map(|e| format!("{} . {}", e.cidr, e.port))
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!("        elements = {{ {elements} }}\n"));
        }
        out.push_str("    }\n");
    }

    // ── forward chain ──
    out.push_str(&format!(
        "    chain forward {{\n\
         \x20       type filter hook forward priority filter - 1; policy accept;\n\
         \x20       iifname != \"{bridge}\" oifname != \"{bridge}\" return\n\
         \x20       iifname \"{bridge}\" oifname \"{bridge}\" accept\n\
         \x20       ct state established,related accept\n\
         \x20       iifname \"k7-br-*\" oifname \"k7-br-*\" counter drop\n\
         \x20       iifname \"{bridge}\" ct state new ct count over {ct_max} counter drop\n\
         \x20       iifname \"{bridge}\" ct state new limit rate over {new_rate}/second \
         burst {new_rate} packets counter drop\n"
    ));
    // Whitelist accepts come BEFORE the metadata drop so an explicit
    // 169.254/16 entry wins.
    if policy.mode == EgressMode::Whitelist {
        out.push_str(&format!(
            " \x20      iifname \"{bridge}\" meta l4proto {{ tcp, udp }} \
             ip daddr . th dport @egress_allow counter accept\n"
        ));
        if let Some(dns) = policy.allow_dns {
            out.push_str(&format!(
                " \x20      iifname \"{bridge}\" ip daddr {dns} udp dport 53 accept\n\
                 \x20       iifname \"{bridge}\" ip daddr {dns} tcp dport 53 accept\n"
            ));
        }
    }
    // Cloud metadata / link-local: denied in EVERY mode unless
    // whitelisted above (credential-theft path in the threat model).
    out.push_str(&format!(
        " \x20      iifname \"{bridge}\" ip daddr 169.254.0.0/16 counter drop\n"
    ));
    if !egress_ifaces.is_empty() {
        out.push_str(&format!(
            " \x20      iifname \"{bridge}\" oifname {{ {} }} accept\n",
            iface_set(&egress_ifaces)
        ));
    }
    if !inbound_ifaces.is_empty() {
        out.push_str(&format!(
            " \x20      oifname \"{bridge}\" iifname {{ {} }} accept\n",
            iface_set(&inbound_ifaces)
        ));
    }
    out.push_str(" \x20      counter drop\n \x20  }\n");

    // ── input chain: host lockdown ──
    // Runs at filter - 1, before every iptables INPUT rule. The
    // formerly load-bearing `INPUT -i <bridge> -j ACCEPT` iptables rule
    // is drained by `network.rs` — this chain owns the decision now.
    out.push_str(&format!(
        "    chain input {{\n\
         \x20       type filter hook input priority filter - 1; policy accept;\n\
         \x20       iifname != \"{bridge}\" return\n"
    ));
    match policy.mode {
        EgressMode::Open => {
            // Parity with the drained iptables ACCEPT: guests may reach
            // host services (gateway-bound iSCSI/NFS targets et al).
            out.push_str(" \x20      counter accept\n");
        }
        EgressMode::Deny | EgressMode::Whitelist => {
            out.push_str(" \x20      ct state established,related accept\n");
            if policy.mode == EgressMode::Whitelist {
                // A whitelist entry may name the gateway/host itself —
                // guest→host terminates in `input`, not `forward`.
                out.push_str(
                    " \x20      meta l4proto { tcp, udp } \
                     ip daddr . th dport @egress_allow counter accept\n",
                );
                if let Some(dns) = policy.allow_dns {
                    out.push_str(&format!(
                        " \x20      ip daddr {dns} udp dport 53 accept\n\
                         \x20       ip daddr {dns} tcp dport 53 accept\n"
                    ));
                }
            }
            out.push_str(" \x20      counter drop\n");
        }
    }
    out.push_str(" \x20  }\n}\n");
    out
}

/// Per-TAP L2 anti-spoof: a `netdev`-family ingress
/// chain on one TAP that pins every frame the guest emits to the TAP's
/// assigned `(mac, guest_ip)` — `ether saddr` and the ARP sender fields
/// must match exactly, `ip saddr` may not claim another guest's address
/// in the shared /24 (see [`tap_ruleset`] for why routed pod-CIDR
/// sources pass), and every `EtherType` except IPv4 and ARP drops (no
/// guest IPv6, no VLAN-tag evasion of the IP match).
///
/// Per-TAP by necessity: all bridges share `10.200.0.0/24` and forks
/// reuse guest IPs, so a global source-IP set cannot distinguish the
/// legitimate owner of an address from a spoofer in another tree.
#[derive(Debug)]
pub struct TapAntiSpoof {
    table: String,
}

impl TapAntiSpoof {
    /// Install the anti-spoof chain on `tap` (which must exist),
    /// pinning it to `mac`/`ip`. Returns `Ok(None)` when
    /// `K7D_NET_JAIL=off`.
    pub fn install(tap: &str, mac: [u8; 6], ip: Ipv4Addr) -> Result<Option<Self>, String> {
        if !enforced()? {
            return Ok(None);
        }
        let table = tap_table_name(tap);
        let ruleset = tap_ruleset(tap, &table, mac, ip);
        apply_ruleset(&table, &ruleset)?;
        Ok(Some(Self { table }))
    }

    /// Install anti-spoof chains for a whole set of TAPs in **one**
    /// `nft` invocation. One process per TAP is the difference between
    /// ~75 ms and ~250 ms per forked 3-VM cluster in the 50-cluster
    /// batch (each `nft` run costs tens of ms once the node carries a
    /// few hundred jail tables), so the fork path batches. Semantics
    /// are identical to N separate [`install`](Self::install) calls —
    /// the file is just the N table definitions concatenated, and nft
    /// applies it as one transaction (all-or-nothing). Returns
    /// `Ok(None)` when `K7D_NET_JAIL=off`.
    pub fn install_batch(
        specs: &[(String, [u8; 6], Ipv4Addr)],
    ) -> Result<Option<Vec<Self>>, String> {
        if !enforced()? {
            return Ok(None);
        }
        if specs.is_empty() {
            return Ok(Some(Vec::new()));
        }
        let mut ruleset = String::new();
        let mut guards = Vec::with_capacity(specs.len());
        for (tap, mac, ip) in specs {
            let table = tap_table_name(tap);
            ruleset.push_str(&tap_ruleset(tap, &table, *mac, *ip));
            guards.push(Self { table });
        }
        // If nft rejects the transaction nothing was installed; drop
        // the guards without their Drop deleting tables that never
        // existed (delete tolerates that anyway, but don't spam).
        match apply_ruleset(&tap_table_name(&specs[0].0), &ruleset) {
            Ok(()) => Ok(Some(guards)),
            Err(e) => {
                guards.into_iter().for_each(std::mem::forget);
                Err(e)
            }
        }
    }

    /// Delete this TAP's table. Idempotent.
    pub fn remove(&self) -> Result<(), String> {
        delete_table("netdev", &self.table)
    }

    /// This jail's nftables table name.
    #[must_use]
    pub fn table(&self) -> &str {
        &self.table
    }
}

impl Drop for TapAntiSpoof {
    fn drop(&mut self) {
        if let Err(e) = self.remove() {
            log::error!("remove tap anti-spoof {}: {e}", self.table);
        }
    }
}

/// Render the anti-spoof ruleset for one TAP.
///
/// The IP pin is scoped to the guest /24 on purpose: an inner-k3s
/// guest running flannel **host-gw** legitimately emits frames whose
/// source is a pod-CIDR address (e.g. `10.60.x.x`) — the peer node
/// routes the pod subnet via the guest's `10.200.0.x` next hop, no
/// encapsulation, no SNAT. A strict `ip saddr != <guest_ip>` pin kills
/// that CNI outright (learned the hard way; every inner-k3s suite
/// failed with "inner pause pod unreachable"). The identity the spec's
/// fork invariant actually needs to protect is the shared guest
/// subnet: no TAP may claim *another guest's* `10.200.0.0/24` address.
/// Sources outside that subnet are routed workload traffic and pass
/// (the tree jail's forward chain still governs where they may go).
fn tap_ruleset(tap: &str, table: &str, mac: [u8; 6], ip: Ipv4Addr) -> String {
    let mac = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
    let net = Ipv4Addr::from(u32::from(ip) & 0xffff_ff00);
    format!(
        "table netdev {table}\n\
         delete table netdev {table}\n\
         table netdev {table} {{\n\
         \x20   chain ingress {{\n\
         \x20       type filter hook ingress device \"{tap}\" priority filter; policy accept;\n\
         \x20       ether saddr != {mac} counter drop\n\
         \x20       arp saddr ether != {mac} counter drop\n\
         \x20       arp saddr ip != {ip} counter drop\n\
         \x20       ip saddr {net}/24 ip saddr != {ip} counter drop\n\
         \x20       ether type {{ ip, arp }} accept\n\
         \x20       counter drop\n\
         \x20   }}\n\
         }}\n"
    )
}

/// Feed `ruleset` to `nft -f`. The ruleset goes through a file rather
/// than stdin so the child needs no pipe plumbing on the daemon's hot
/// paths; the file lives in `/run` and is removed either way.
fn apply_ruleset(table: &str, ruleset: &str) -> Result<(), String> {
    let path = ruleset_path(table);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    }
    std::fs::write(&path, ruleset).map_err(|e| format!("write {}: {e}", path.display()))?;
    let result = run_capture("nft", &["-f", &path.to_string_lossy()]);
    let _ = std::fs::remove_file(&path);
    let (status, _out, stderr) = result.map_err(|e| format!("nft -f: {e}"))?;
    if !status.success() {
        return Err(format!(
            "nft -f failed for {table}: {}\nruleset:\n{ruleset}",
            stderr.trim()
        ));
    }
    Ok(())
}

fn ruleset_path(table: &str) -> PathBuf {
    PathBuf::from("/run/k7d").join(format!("{table}.nft"))
}

/// Delete one table in `family`, tolerating "does not exist".
fn delete_table(family: &str, table: &str) -> Result<(), String> {
    let (status, _out, stderr) =
        run_capture("nft", &["delete", "table", family, table]).map_err(|e| format!("nft: {e}"))?;
    if status.success() || stderr.contains("No such file or directory") {
        return Ok(());
    }
    Err(format!(
        "nft delete table {family} {table}: {}",
        stderr.trim()
    ))
}

/// List the tables in `family` whose name starts with `prefix`.
fn list_tables(family: &str, prefix: &str) -> Result<Vec<String>, String> {
    let (status, stdout, stderr) =
        run_capture("nft", &["list", "tables", family]).map_err(|e| format!("nft: {e}"))?;
    if !status.success() {
        return Err(format!("nft list tables {family}: {}", stderr.trim()));
    }
    Ok(stdout
        .lines()
        .filter_map(|l| l.split_whitespace().nth(2))
        .filter(|t| t.starts_with(prefix))
        .map(str::to_string)
        .collect())
}

/// Delete every `k7jail-*` table whose bridge no longer exists.
///
/// Called once at daemon startup, next to
/// [`crate::cgroup::clean_stale_vm_cgroups`]. Failures are logged
/// loudly and never stop the daemon: a leftover table is a bug worth
/// shouting about, a daemon that refuses to start is worse. Returns
/// the tables it removed (tests assert on this).
#[must_use]
pub fn clean_stale_jails() -> Vec<String> {
    reap_stale("inet", TABLE_PREFIX)
}

/// Delete every `k7tapjail-*` netdev table whose TAP no longer exists.
/// Same contract as [`clean_stale_jails`].
#[must_use]
pub fn clean_stale_tap_jails() -> Vec<String> {
    reap_stale("netdev", TAP_TABLE_PREFIX)
}

fn reap_stale(family: &str, prefix: &str) -> Vec<String> {
    let tables = match list_tables(family, prefix) {
        Ok(t) => t,
        Err(e) => {
            log::error!("clean stale {family} jails: {e}");
            return Vec::new();
        }
    };
    let mut removed = Vec::new();
    for table in tables {
        let link = &table[prefix.len()..];
        if Path::new("/sys/class/net").join(link).exists() {
            continue;
        }
        match delete_table(family, &table) {
            Ok(()) => {
                log::warn!("removed stale net jail {table} (link {link} is gone)");
                removed.push(table);
            }
            Err(e) => log::error!("remove stale net jail {table}: {e}"),
        }
    }
    removed
}

/// Whether a jail table for `bridge` is currently installed.
#[must_use]
pub fn jail_installed(bridge: &str) -> bool {
    list_tables("inet", TABLE_PREFIX).is_ok_and(|tables| tables.contains(&table_name(bridge)))
}

/// Whether an anti-spoof table for `tap` is currently installed.
#[must_use]
pub fn tap_jail_installed(tap: &str) -> bool {
    list_tables("netdev", TAP_TABLE_PREFIX)
        .is_ok_and(|tables| tables.contains(&tap_table_name(tap)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_env<T>(key: &str, val: Option<&str>, f: impl FnOnce() -> T) -> T {
        let prev = std::env::var(key).ok();
        match val {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        let out = f();
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        out
    }

    fn lo_ifaces() -> JailIfaces {
        JailIfaces {
            wan: "lo".to_string(),
            restricted: Vec::new(),
        }
    }

    fn render(policy: &EgressPolicy) -> String {
        ruleset(
            "k7-br-a",
            "k7jail-k7-br-a",
            &JailIfaces {
                wan: "eth0".to_string(),
                restricted: vec!["cni0".to_string()],
            },
            policy,
            DEFAULT_CT_MAX,
            DEFAULT_NEW_RATE,
        )
    }

    #[test]
    fn mode_defaults_to_enforce_and_rejects_garbage() {
        with_env("K7D_NET_JAIL", None, || assert!(enforced().unwrap()));
        with_env(
            "K7D_NET_JAIL",
            Some("off"),
            || assert!(!enforced().unwrap()),
        );
        with_env("K7D_NET_JAIL", Some("maybe"), || {
            assert!(enforced().is_err(), "unknown mode must fail loudly");
        });
    }

    #[test]
    fn caps_reject_zero_and_garbage() {
        with_env("K7D_NET_JAIL_CT_MAX", None, || {
            assert_eq!(
                env_cap("K7D_NET_JAIL_CT_MAX", DEFAULT_CT_MAX).unwrap(),
                DEFAULT_CT_MAX
            );
        });
        with_env("K7D_NET_JAIL_CT_MAX", Some("64"), || {
            assert_eq!(env_cap("K7D_NET_JAIL_CT_MAX", DEFAULT_CT_MAX).unwrap(), 64);
        });
        with_env("K7D_NET_JAIL_CT_MAX", Some("0"), || {
            assert!(env_cap("K7D_NET_JAIL_CT_MAX", DEFAULT_CT_MAX).is_err());
        });
        with_env("K7D_NET_JAIL_CT_MAX", Some("lots"), || {
            assert!(env_cap("K7D_NET_JAIL_CT_MAX", DEFAULT_CT_MAX).is_err());
        });
    }

    #[test]
    fn policy_validation_is_loud() {
        assert!(EgressPolicy::default().validate().is_ok());
        // allow entries on a non-whitelist mode are a config error.
        let p = EgressPolicy {
            mode: EgressMode::Deny,
            allow: vec![CidrPort {
                cidr: "10.0.0.0/8".into(),
                port: 443,
            }],
            allow_dns: None,
        };
        assert!(p.validate().is_err());
        // malformed CIDRs are loud.
        for bad in ["10.0.0.0", "10.0.0.0/33", "banana/8"] {
            let p = EgressPolicy {
                mode: EgressMode::Whitelist,
                allow: vec![CidrPort {
                    cidr: bad.into(),
                    port: 443,
                }],
                allow_dns: None,
            };
            assert!(p.validate().is_err(), "cidr {bad:?} must be rejected");
        }
        let ok = EgressPolicy {
            mode: EgressMode::Whitelist,
            allow: vec![CidrPort {
                cidr: "203.0.113.0/24".into(),
                port: 4791,
            }],
            allow_dns: Some(Ipv4Addr::new(10, 200, 0, 1)),
        };
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn egress_policy_default_serde_is_open() {
        // The control op omits `egress` entirely today — that must
        // deserialize to Open with no allowances.
        let p: EgressPolicy = serde_json::from_str("{}").unwrap();
        assert_eq!(p, EgressPolicy::default());
        assert_eq!(p.mode, EgressMode::Open);
        let p: EgressPolicy = serde_json::from_str(
            r#"{"mode":"whitelist","allow":[{"cidr":"1.2.3.0/24","port":4791}],"allow_dns":"10.200.0.1"}"#,
        )
        .unwrap();
        assert_eq!(p.mode, EgressMode::Whitelist);
        assert_eq!(p.allow[0].port, 4791);
    }

    #[test]
    fn ruleset_denies_inter_tree_and_defaults_to_drop() {
        let rules = ruleset(
            "k7-br-a",
            "k7jail-k7-br-a",
            &JailIfaces {
                wan: "eth0".to_string(),
                restricted: Vec::new(),
            },
            &EgressPolicy::default(),
            DEFAULT_CT_MAX,
            DEFAULT_NEW_RATE,
        );
        assert!(rules.contains("iifname \"k7-br-*\" oifname \"k7-br-*\" counter drop"));
        assert!(rules.contains("iifname \"k7-br-a\" oifname \"k7-br-a\" accept"));
        assert!(rules.contains("oifname { \"eth0\" } accept"));
        assert!(rules.trim_end().ends_with('}'));
        // Atomic replace, not append: a second create on a shared
        // bridge must not stack a duplicate rule set.
        assert!(rules.starts_with("table inet k7jail-k7-br-a\ndelete table inet k7jail-k7-br-a\n"));
        // Metadata denied even under Open.
        assert!(rules.contains("ip daddr 169.254.0.0/16 counter drop"));
        // Per-tree caps present in every mode.
        assert!(rules.contains(&format!("ct count over {DEFAULT_CT_MAX} counter drop")));
        assert!(rules.contains(&format!("limit rate over {DEFAULT_NEW_RATE}/second")));
        // Open input chain accepts (parity with the drained iptables
        // INPUT ACCEPT).
        assert!(rules.contains("chain input"));
    }

    #[test]
    fn ruleset_deny_removes_wan_and_locks_down_input() {
        let rules = render(&EgressPolicy {
            mode: EgressMode::Deny,
            allow: Vec::new(),
            allow_dns: None,
        });
        // WAN iface must not appear in any accept set; CNI path stays.
        assert!(
            !rules.contains("\"eth0\""),
            "Deny must not forward to the WAN iface:\n{rules}"
        );
        assert!(rules.contains("oifname { \"cni0\" } accept"));
        // Input chain fails closed.
        assert!(rules.contains("chain input"));
        let input = rules.split("chain input").nth(1).unwrap();
        assert!(input.contains("counter drop"));
        assert!(input.contains("ct state established,related accept"));
    }

    #[test]
    fn ruleset_whitelist_renders_set_dns_and_metadata_order() {
        let rules = render(&EgressPolicy {
            mode: EgressMode::Whitelist,
            allow: vec![
                CidrPort {
                    cidr: "203.0.113.0/24".into(),
                    port: 4791,
                },
                CidrPort {
                    cidr: "169.254.169.254/32".into(),
                    port: 80,
                },
            ],
            allow_dns: Some(Ipv4Addr::new(10, 200, 0, 1)),
        });
        assert!(rules.contains("set egress_allow"));
        assert!(rules.contains("203.0.113.0/24 . 4791"));
        assert!(rules.contains("ip daddr 10.200.0.1 udp dport 53 accept"));
        assert!(rules.contains("ip daddr 10.200.0.1 tcp dport 53 accept"));
        assert!(
            !rules.contains("\"eth0\""),
            "Whitelist must not blanket-forward to the WAN iface:\n{rules}"
        );
        // The whitelist accept must come BEFORE the metadata drop, so
        // an explicit 169.254 entry wins.
        let fwd = rules.split("chain forward").nth(1).unwrap();
        let accept_at = fwd.find("@egress_allow counter accept").unwrap();
        let meta_at = fwd.find("169.254.0.0/16 counter drop").unwrap();
        assert!(
            accept_at < meta_at,
            "whitelist accept must precede metadata drop"
        );
        // Input chain honours the whitelist set too.
        let input = rules.split("chain input").nth(1).unwrap();
        assert!(input.contains("@egress_allow counter accept"));
        assert!(input.contains("counter drop"));
    }

    #[test]
    fn tap_ruleset_pins_mac_ip_and_drops_other_ethertypes() {
        let rules = tap_ruleset(
            "t1234t0",
            "k7tapjail-t1234t0",
            [0xaa, 0xbb, 0, 0, 0, 2],
            Ipv4Addr::new(10, 200, 0, 2),
        );
        assert!(rules.contains("ether saddr != aa:bb:00:00:00:02 counter drop"));
        assert!(rules.contains("arp saddr ether != aa:bb:00:00:00:02 counter drop"));
        assert!(rules.contains("arp saddr ip != 10.200.0.2 counter drop"));
        // Scoped to the guest /24: pod-CIDR sources (flannel host-gw)
        // pass, another guest's 10.200.0.x is dropped.
        assert!(rules.contains("ip saddr 10.200.0.0/24 ip saddr != 10.200.0.2 counter drop"));
        // v6 (and every non-IP/ARP EtherType, incl. VLAN evasion) drops.
        assert!(rules.contains("ether type { ip, arp } accept"));
        assert!(rules.trim_end().ends_with('}'));
        assert!(rules.starts_with(
            "table netdev k7tapjail-t1234t0\ndelete table netdev k7tapjail-t1234t0\n"
        ));
    }

    /// The jail is installed on a throwaway bridge, seen by `nft`, and
    /// gone once the guard drops.
    #[test]
    fn install_and_drop_round_trip() {
        let bridge = "k7-br-njt";
        let _ = run_capture("ip", &["link", "add", "name", bridge, "type", "bridge"]);
        let jail = TreeNetJail::install(bridge, &lo_ifaces(), &EgressPolicy::default())
            .expect("install jail")
            .expect("jail enforced by default");
        assert!(
            jail_installed(bridge),
            "table should exist while jail lives"
        );
        drop(jail);
        assert!(!jail_installed(bridge), "Drop must delete the table");
        let _ = run_capture("ip", &["link", "delete", bridge, "type", "bridge"]);
    }

    /// Every mode's rendered ruleset is accepted by the kernel, not
    /// just by our string asserts.
    #[test]
    fn install_all_modes_round_trip() {
        let bridge = "k7-br-njm";
        let _ = run_capture("ip", &["link", "add", "name", bridge, "type", "bridge"]);
        for policy in [
            EgressPolicy {
                mode: EgressMode::Deny,
                allow: Vec::new(),
                allow_dns: None,
            },
            EgressPolicy {
                mode: EgressMode::Whitelist,
                allow: Vec::new(),
                allow_dns: None,
            },
            EgressPolicy {
                mode: EgressMode::Whitelist,
                allow: vec![CidrPort {
                    cidr: "203.0.113.0/24".into(),
                    port: 4791,
                }],
                allow_dns: Some(Ipv4Addr::new(10, 200, 0, 1)),
            },
        ] {
            let jail = TreeNetJail::install(bridge, &lo_ifaces(), &policy)
                .unwrap_or_else(|e| panic!("install {policy:?}: {e}"))
                .expect("enforced");
            assert!(jail_installed(bridge), "{policy:?} table missing");
            drop(jail);
        }
        let _ = run_capture("ip", &["link", "delete", bridge, "type", "bridge"]);
    }

    /// A table whose bridge is gone is reaped; one whose bridge exists
    /// is left alone.
    #[test]
    fn stale_jails_are_reaped_live_ones_are_not() {
        let live = "k7-br-njl";
        let _ = run_capture("ip", &["link", "add", "name", live, "type", "bridge"]);
        let live_jail = TreeNetJail::install(live, &lo_ifaces(), &EgressPolicy::default())
            .expect("install live jail")
            .expect("enforced");

        let gone = "k7-br-njg";
        let stale = table_name(gone);
        apply_ruleset(
            &stale,
            &ruleset(
                gone,
                &stale,
                &lo_ifaces(),
                &EgressPolicy::default(),
                DEFAULT_CT_MAX,
                DEFAULT_NEW_RATE,
            ),
        )
        .expect("install stale");

        let removed = clean_stale_jails();
        assert!(
            removed.contains(&stale),
            "stale table not reaped: {removed:?}"
        );
        assert!(jail_installed(live), "live bridge's jail must survive");

        drop(live_jail);
        let _ = run_capture("ip", &["link", "delete", live, "type", "bridge"]);
    }

    /// The per-TAP anti-spoof round trip on a dummy link, and the
    /// stale reaper for `netdev` tables.
    #[test]
    fn tap_anti_spoof_round_trip_and_reap() {
        let dev = "k7njtap0";
        let _ = run_capture("ip", &["link", "delete", dev]);
        let (st, _, err) =
            run_capture("ip", &["link", "add", dev, "type", "dummy"]).expect("ip link add");
        assert!(st.success(), "add dummy: {err}");
        let jail =
            TapAntiSpoof::install(dev, [0xaa, 0xbb, 0, 0, 0, 2], Ipv4Addr::new(10, 200, 0, 2))
                .expect("install tap anti-spoof")
                .expect("enforced");
        assert!(tap_jail_installed(dev));
        drop(jail);
        assert!(!tap_jail_installed(dev), "Drop must delete the table");

        // Stale reap: table outlives its device.
        let jail =
            TapAntiSpoof::install(dev, [0xaa, 0xbb, 0, 0, 0, 2], Ipv4Addr::new(10, 200, 0, 2))
                .expect("install")
                .expect("enforced");
        std::mem::forget(jail); // simulate a daemon that died without Drops
        let _ = run_capture("ip", &["link", "delete", dev]);
        let removed = clean_stale_tap_jails();
        assert!(
            removed.contains(&tap_table_name(dev)),
            "stale tap table not reaped: {removed:?}"
        );
    }
}
