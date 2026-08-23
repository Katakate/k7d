//! Per-tree network jail: an nftables table scoped to one `k7-br-{id}`
//! bridge .
//!
//! Every live cluster payload — a tree root, a forked node, an adopted
//! cluster — owns one bridge, and every guest on every bridge sits in
//! the same `10.200.0.0/24`. The iptables rules k7d installs for a
//! bridge are `FORWARD -i k7-br-A -j ACCEPT` / `FORWARD -o k7-br-A -j
//! ACCEPT`, so before this module two trees on one node could route to
//! each other's guests: the host forwarded between the bridges and both
//! ends were explicitly accepted.
//!
//! The jail is a table per bridge, `k7jail-{bridge}`, with one chain in
//! the `forward` hook at priority `filter - 1` so it is evaluated
//! *before* those iptables rules:
//!
//! ```text
//! iifname != B oifname != B    return   # not this bridge's traffic
//! iifname B    oifname B       accept   # intra-tree, guest to guest
//! ct state established,related accept   # replies to allowed flows
//! iifname "k7-br-*" oifname "k7-br-*" counter drop   # INTER-TREE
//! iifname B oifname { allowed } accept  # whitelist (egress, CNI)
//! oifname B iifname { allowed } accept
//! counter drop                          # default deny
//! ```
//!
//! Teardown is RAII: [`ClusterNetwork::destroy`](crate::network::ClusterNetwork::destroy)
//! drops the table when it deletes the bridge. A daemon that dies
//! without running its `Drop`s leaves tables behind, so
//! [`clean_stale_jails`] reaps every `k7jail-*` table whose bridge no
//! longer exists at startup — a stale table would otherwise silently
//! filter a later bridge that happened to reuse the name.

use std::path::{Path, PathBuf};

use crate::netns::run_capture;

/// Prefix of every table this module owns. The bridge name is appended
/// verbatim, which is what makes [`clean_stale_jails`] able to decide
/// whether a table is stale by looking at the host's links.
const TABLE_PREFIX: &str = "k7jail-";

/// Host interfaces a jailed guest may always be forwarded to/from, on
/// top of the host's default-route interface: reaching the node's pod
/// network is existing, tested behaviour and is not what this jail is
/// for (it exists to stop tree-to-tree traffic).
const CNI_IFACES: [&str; 2] = ["cni0", "flannel.1"];

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

/// Table name for `bridge`.
#[must_use]
pub fn table_name(bridge: &str) -> String {
    format!("{TABLE_PREFIX}{bridge}")
}

/// Interfaces the jail whitelists for `default_iface`: the host's
/// default route (guest egress via the existing MASQUERADE), the host
/// CNI interfaces that exist, and anything the operator adds through
/// `K7D_NET_JAIL_ALLOW_IFACES` (comma-separated).
#[must_use]
pub fn allowed_ifaces(default_iface: &str) -> Vec<String> {
    let mut out = vec![default_iface.to_string()];
    for iface in CNI_IFACES {
        if Path::new("/sys/class/net").join(iface).exists() {
            out.push(iface.to_string());
        }
    }
    if let Ok(extra) = std::env::var("K7D_NET_JAIL_ALLOW_IFACES") {
        for iface in extra.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            out.push(iface.to_string());
        }
    }
    // nft rejects a duplicate element inside an anonymous set, so a
    // default route that is also named in the env var must collapse.
    out.sort();
    out.dedup();
    out
}

/// One bridge's nftables jail. Dropping it deletes the table.
#[derive(Debug)]
pub struct TreeNetJail {
    bridge: String,
    table: String,
}

impl TreeNetJail {
    /// Install the jail for `bridge`, whitelisting forwarding to and
    /// from `allowed`. Returns `Ok(None)` when `K7D_NET_JAIL=off`.
    ///
    /// Re-installing over an existing table is an atomic replace, not
    /// an append: `ClusterNetwork::create` is idempotent across
    /// cooperating pods on a shared bridge, and appending would stack
    /// duplicate rule sets until the counters were meaningless.
    pub fn install(bridge: &str, allowed: &[String]) -> Result<Option<Self>, String> {
        if !enforced()? {
            log::warn!("K7D_NET_JAIL=off: bridge {bridge} runs unjailed");
            return Ok(None);
        }
        let table = table_name(bridge);
        let ruleset = ruleset(bridge, &table, allowed);
        // The elapsed time is part of the message on purpose: this is one
        // `nft` process on the fork path, and it is the jail's whole
        // measured cost . A regression
        // here shows up in the daemon log before it shows up as a blown
        // fork budget.
        let t0 = std::time::Instant::now();
        apply_ruleset(&table, &ruleset)?;
        log::info!(
            "net jail {table} installed in {:?} (allowed ifaces: {allowed:?})",
            t0.elapsed()
        );
        Ok(Some(Self {
            bridge: bridge.to_string(),
            table,
        }))
    }

    /// Delete this bridge's table. Idempotent — a table someone else
    /// already removed is success, not an error.
    pub fn remove(&self) -> Result<(), String> {
        delete_table(&self.table)
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

/// Render the ruleset for `bridge`.
fn ruleset(bridge: &str, table: &str, allowed: &[String]) -> String {
    let allow_set = allowed
        .iter()
        .map(|i| format!("\"{i}\""))
        .collect::<Vec<_>>()
        .join(", ");
    // `table` then `delete table` then the definition is nft's atomic
    // replace idiom: the bare `table` line creates it when missing so
    // the `delete` cannot fail on a first install.
    let mut out = format!(
        "table inet {table}\n\
         delete table inet {table}\n\
         table inet {table} {{\n\
         \x20   chain forward {{\n\
         \x20       type filter hook forward priority filter - 1; policy accept;\n\
         \x20       iifname != \"{bridge}\" oifname != \"{bridge}\" return\n\
         \x20       iifname \"{bridge}\" oifname \"{bridge}\" accept\n\
         \x20       ct state established,related accept\n\
         \x20       iifname \"k7-br-*\" oifname \"k7-br-*\" counter drop\n"
    );
    if !allow_set.is_empty() {
        out.push_str(&format!(
            " \x20      iifname \"{bridge}\" oifname {{ {allow_set} }} accept\n\
             \x20       oifname \"{bridge}\" iifname {{ {allow_set} }} accept\n"
        ));
    }
    out.push_str(" \x20      counter drop\n \x20  }\n}\n");
    out
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

/// Delete one table, tolerating "does not exist".
fn delete_table(table: &str) -> Result<(), String> {
    let (status, _out, stderr) =
        run_capture("nft", &["delete", "table", "inet", table]).map_err(|e| format!("nft: {e}"))?;
    if status.success() || stderr.contains("No such file or directory") {
        return Ok(());
    }
    Err(format!("nft delete table inet {table}: {}", stderr.trim()))
}

/// List the `k7jail-*` tables currently in the `inet` family.
fn list_jail_tables() -> Result<Vec<String>, String> {
    let (status, stdout, stderr) =
        run_capture("nft", &["list", "tables", "inet"]).map_err(|e| format!("nft: {e}"))?;
    if !status.success() {
        return Err(format!("nft list tables inet: {}", stderr.trim()));
    }
    Ok(stdout
        .lines()
        .filter_map(|l| l.split_whitespace().nth(2))
        .filter(|t| t.starts_with(TABLE_PREFIX))
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
    let tables = match list_jail_tables() {
        Ok(t) => t,
        Err(e) => {
            log::error!("clean_stale_jails: {e}");
            return Vec::new();
        }
    };
    let mut removed = Vec::new();
    for table in tables {
        let bridge = &table[TABLE_PREFIX.len()..];
        if Path::new("/sys/class/net").join(bridge).exists() {
            continue;
        }
        match delete_table(&table) {
            Ok(()) => {
                log::warn!("removed stale net jail {table} (bridge {bridge} is gone)");
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
    list_jail_tables().is_ok_and(|tables| tables.contains(&table_name(bridge)))
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
    fn ruleset_denies_inter_tree_and_defaults_to_drop() {
        let rules = ruleset("k7-br-a", "k7jail-k7-br-a", &["eth0".to_string()]);
        assert!(rules.contains("iifname \"k7-br-*\" oifname \"k7-br-*\" counter drop"));
        assert!(rules.contains("iifname \"k7-br-a\" oifname \"k7-br-a\" accept"));
        assert!(rules.contains("oifname { \"eth0\" } accept"));
        assert!(rules.trim_end().ends_with('}'));
        // Atomic replace, not append: a second create on a shared
        // bridge must not stack a duplicate rule set.
        assert!(rules.starts_with("table inet k7jail-k7-br-a\ndelete table inet k7jail-k7-br-a\n"));
    }

    /// The jail is installed on a throwaway bridge, seen by `nft`, and
    /// gone once the guard drops.
    #[test]
    fn install_and_drop_round_trip() {
        let bridge = "k7-br-njt";
        let _ = run_capture("ip", &["link", "add", "name", bridge, "type", "bridge"]);
        let jail = TreeNetJail::install(bridge, &["lo".to_string()])
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

    /// A table whose bridge is gone is reaped; one whose bridge exists
    /// is left alone.
    #[test]
    fn stale_jails_are_reaped_live_ones_are_not() {
        let live = "k7-br-njl";
        let _ = run_capture("ip", &["link", "add", "name", live, "type", "bridge"]);
        let live_jail = TreeNetJail::install(live, &["lo".to_string()])
            .expect("install live jail")
            .expect("enforced");

        let gone = "k7-br-njg";
        let stale = table_name(gone);
        apply_ruleset(&stale, &ruleset(gone, &stale, &["lo".to_string()])).expect("install stale");

        let removed = clean_stale_jails();
        assert!(
            removed.contains(&stale),
            "stale table not reaped: {removed:?}"
        );
        assert!(jail_installed(live), "live bridge's jail must survive");

        drop(live_jail);
        let _ = run_capture("ip", &["link", "delete", live, "type", "bridge"]);
    }
}
