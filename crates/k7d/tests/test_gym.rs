//! the referenced work: gym HTTP lease / act / score / reap.
//!
//! Spawns `gym/server.py` against the node daemon (create mode), drives
//! the frozen contract, and asserts zero residue vs a pre-lease snapshot.
//! Never `#[ignore]` — the remote node has KVM and k7d.

mod common;

use std::collections::HashSet;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use k7d::control::{Client, Request, Response};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn k7d_sock() -> &'static str {
    "/run/k7d/k7d.sock"
}

fn list_k7_bridges() -> HashSet<String> {
    list_net_prefixed("k7-br-")
}

fn list_net_prefixed(prefix: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let net = Path::new("/sys/class/net");
    let Ok(entries) = std::fs::read_dir(net) else {
        return out;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with(prefix) {
            out.insert(name);
        }
    }
    out
}

fn list_taps() -> HashSet<String> {
    let mut out = HashSet::new();
    let net = Path::new("/sys/class/net");
    let Ok(entries) = std::fs::read_dir(net) else {
        return out;
    };
    for e in entries.flatten() {
        if e.path().join("tun_flags").is_file() {
            out.insert(e.file_name().to_string_lossy().into_owned());
        }
    }
    out
}

fn mem_available_bytes() -> u64 {
    let text = std::fs::read_to_string("/proc/meminfo").expect("meminfo");
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemAvailable:") {
            let kb: u64 = rest.split_whitespace().next().unwrap().parse().unwrap();
            return kb * 1024;
        }
    }
    panic!("MemAvailable missing");
}

fn k7d_vmrss_bytes() -> Option<u64> {
    let listing = Command::new("pidof").arg("k7d").output().ok()?;
    let pid = String::from_utf8_lossy(&listing.stdout)
        .split_whitespace()
        .next()?
        .to_string();
    let text = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

fn tree_node_ids(tree_id: &str) -> Vec<String> {
    let mut c = Client::connect(k7d_sock()).expect("connect k7d");
    match c.call(&Request::TreeNodes {
        tree_id: tree_id.to_string(),
    }) {
        Ok(Response::TreeNodeList { nodes, .. }) => nodes.into_iter().map(|n| n.id).collect(),
        Ok(Response::Error { message }) if message.contains("no such tree") => vec![],
        other => panic!("tree_nodes {tree_id}: {other:?}"),
    }
}

fn wipe_tree(tree_id: &str) {
    let mut c = match Client::connect(k7d_sock()) {
        Ok(c) => c,
        Err(_) => return,
    };
    let _ = c.call(&Request::TreePrune {
        tree_id: tree_id.to_string(),
        node_id: "root".to_string(),
    });
    let _ = c.call(&Request::TreeDrop {
        tree_id: tree_id.to_string(),
    });
}

fn wipe_stale_gym_test_trees() {
    let mut c = match Client::connect(k7d_sock()) {
        Ok(c) => c,
        Err(_) => return,
    };
    let trees = match c.call(&Request::TreeList) {
        Ok(Response::TreeList { trees }) => trees,
        _ => return,
    };
    for t in trees {
        if t.tree_id.starts_with("gym-src-test-") {
            wipe_tree(&t.tree_id);
        }
    }
}

/// Residue that belongs to one gym lease — not every `k7-br-*` on a
/// shared node (other suites can mint `k7-br-3vm-*` while we run).
struct LeaseResidue {
    bridges: HashSet<String>,
    nodes: HashSet<String>,
}

impl LeaseResidue {
    fn from_envs(envs: &[serde_json::Value]) -> Self {
        let mut bridges = HashSet::new();
        let mut nodes = HashSet::new();
        for e in envs {
            if let Some(b) = e["bridge"].as_str() {
                bridges.insert(b.to_string());
            }
            if let Some(n) = e["branch_node_id"].as_str() {
                nodes.insert(n.to_string());
            }
        }
        Self { bridges, nodes }
    }

    fn leftover(&self, tree_id: &str) -> (HashSet<String>, HashSet<String>, HashSet<String>) {
        let live_br = list_k7_bridges();
        let live_nodes: HashSet<String> = tree_node_ids(tree_id).into_iter().collect();
        let extra_br: HashSet<_> = self.bridges.intersection(&live_br).cloned().collect();
        let extra_nodes: HashSet<_> = self.nodes.intersection(&live_nodes).cloned().collect();
        let taps = list_taps();
        let mut extra_tap = HashSet::new();
        for br in &extra_br {
            let brif = Path::new("/sys/class/net").join(br).join("brif");
            if let Ok(entries) = std::fs::read_dir(&brif) {
                for e in entries.flatten() {
                    let name = e.file_name().to_string_lossy().into_owned();
                    if taps.contains(&name) {
                        extra_tap.insert(name);
                    }
                }
            }
        }
        (extra_br, extra_tap, extra_nodes)
    }

    fn assert_gone(&self, tree_id: &str, when: &str) {
        let (br, tap, nodes) = self.leftover(tree_id);
        assert!(
            br.is_empty() && tap.is_empty() && nodes.is_empty(),
            "{when}: lease residue leftover bridges={br:?} taps={tap:?} nodes={nodes:?}"
        );
    }
}

fn assert_http_residue_empty(rel: &serde_json::Value, when: &str) {
    let residue = &rel["residue"];
    assert_eq!(
        residue["bridges"].as_array().map(Vec::len),
        Some(0),
        "{when}: {rel}"
    );
    assert_eq!(
        residue["taps"].as_array().map(Vec::len),
        Some(0),
        "{when}: {rel}"
    );
    assert_eq!(
        residue["tree_node_ids"].as_array().map(Vec::len),
        Some(0),
        "{when}: {rel}"
    );
}

struct GymGuard {
    child: Child,
    log_path: PathBuf,
    tree_id: String,
    base: String,
}

impl Drop for GymGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        wipe_tree(&self.tree_id);
        if let Ok(log) = std::fs::read_to_string(&self.log_path) {
            eprintln!(
                "---- gym log {} ----\n{log}\n---- end gym log ----",
                self.log_path.display()
            );
        }
    }
}

fn spawn_gym(tree_id: &str, max_live_vms: u32) -> GymGuard {
    let root = workspace_root();
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral bind");
        l.local_addr().expect("local_addr").port()
    };
    let log_path =
        std::env::temp_dir().join(format!("k7-gym-test-{}-{port}.log", std::process::id()));
    let log = File::create(&log_path).expect("gym log");
    let child = Command::new("python3")
        .arg(root.join("gym/server.py"))
        .env("GYM_SOURCE_MODE", "create")
        .env("GYM_BIND", "127.0.0.1")
        .env("GYM_PORT", port.to_string())
        .env("GYM_SOURCE_TREE_ID", tree_id)
        .env("GYM_MAX_LIVE_VMS", max_live_vms.to_string())
        .env("GYM_MAX_LEASES", "4")
        .env("GYM_REAPER_INTERVAL_S", "1")
        .env("GYM_K7D_TIMEOUT_S", "180")
        .env("GYM_MEMORY_MB", "256")
        .env("GYM_VM_COUNT", "3")
        .stdout(Stdio::from(log.try_clone().expect("clone log")))
        .stderr(Stdio::from(log))
        .spawn()
        .expect("spawn gym/server.py");
    let guard = GymGuard {
        child,
        log_path,
        tree_id: tree_id.to_string(),
        base: format!("http://127.0.0.1:{port}"),
    };
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        if let Ok((code, _, v)) = try_http("GET", &format!("{}/healthz", guard.base), None, 5) {
            if code == 200 && v.get("ok").and_then(|x| x.as_bool()) == Some(true) {
                break;
            }
        }
        // If the child already exited, fail now with the log.
        // Safety: we only peek; Drop still owns the Child.
        let dead = kill_zero(&guard);
        assert!(
            Instant::now() < deadline && !dead,
            "gym never became healthy (dead={dead}); see {}",
            guard.log_path.display()
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    guard
}

fn kill_zero(g: &GymGuard) -> bool {
    // Peek via /proc; do not take ownership of Child.
    !Path::new(&format!("/proc/{}/status", g.child.id())).exists()
}

fn try_http(
    method: &str,
    url: &str,
    body: Option<&str>,
    timeout_s: u64,
) -> Result<(u16, String, serde_json::Value), String> {
    let mut cmd = Command::new("curl");
    cmd.args([
        "-sS",
        "-w",
        "\n%{http_code}",
        "--max-time",
        &timeout_s.to_string(),
        "-X",
        method,
    ]);
    if let Some(b) = body {
        cmd.args(["-H", "Content-Type: application/json", "--data-binary", b]);
    }
    cmd.arg(url);
    let out = cmd.output().map_err(|e| format!("curl: {e}"))?;
    if !out.status.success() && out.stdout.is_empty() {
        return Err(format!(
            "curl failed: status={} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let (payload, code_s) = stdout
        .rsplit_once('\n')
        .ok_or_else(|| format!("curl missing status line: {stdout}"))?;
    let code: u16 = code_s
        .trim()
        .parse()
        .map_err(|_| format!("bad status {code_s:?} body={payload}"))?;
    let json: serde_json::Value =
        serde_json::from_str(payload).unwrap_or_else(|_| serde_json::json!({ "raw": payload }));
    Ok((code, payload.to_string(), json))
}

fn http(method: &str, url: &str, body: Option<&str>, timeout_s: u64) -> (u16, serde_json::Value) {
    let (code, _, json) =
        try_http(method, url, body, timeout_s).unwrap_or_else(|e| panic!("{method} {url}: {e}"));
    (code, json)
}

fn measure(label: &str) {
    eprintln!(
        "GYM_MEASURE {label} mem_available_bytes={} k7d_vmrss_bytes={:?}",
        mem_available_bytes(),
        k7d_vmrss_bytes()
    );
}

#[test]
fn test_gym_lease_act_score_release_reaper_budget() {
    let _ = env_logger::builder().is_test(true).try_init();
    common::ensure_k7d_daemon_running();

    let tree_id = format!("gym-src-test-{}", std::process::id());
    wipe_stale_gym_test_trees();
    wipe_tree(&tree_id);

    measure("before_source");
    let gym = spawn_gym(&tree_id, 64);
    measure("after_source");

    let (code, hz) = http("GET", &format!("{}/healthz", gym.base), None, 5);
    assert_eq!(code, 200, "healthz: {hz}");
    assert_eq!(hz["ok"], true);
    assert_eq!(hz["k7d"], "ready");
    assert!(hz["node_id"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(hz["free_ram_bytes"].as_u64().unwrap_or(0) > 0);
    assert_eq!(hz["leases_in_flight"], 0);

    let source_nodes: HashSet<String> = tree_node_ids(&tree_id).into_iter().collect();
    assert!(
        source_nodes.contains("root"),
        "source root must exist after gym start: {source_nodes:?}"
    );

    // 7. Over-budget lease is rejected early and forks nothing.
    let (code, rej) = http(
        "POST",
        &format!("{}/lease", gym.base),
        Some(r#"{"fault_id":"none","n":32,"group_id":"too-big","ttl_s":30}"#),
        10,
    );
    assert_eq!(code, 400, "budget reject: {rej}");
    let err = rej["error"].as_str().unwrap_or("");
    assert!(
        err.contains("need ") && err.contains("max_live_vms=64") && err.contains("n=32"),
        "arithmetic missing from reject: {err}"
    );
    assert!(err.contains("vms_per_branch=3"), "reject: {err}");
    let after_reject: HashSet<String> = tree_node_ids(&tree_id).into_iter().collect();
    assert_eq!(
        after_reject, source_nodes,
        "over-budget lease must not fork"
    );

    // 2–5. n=4 full cycle.
    let t_lease = Instant::now();
    let (code, lease4) = http(
        "POST",
        &format!("{}/lease", gym.base),
        Some(r#"{"fault_id":"none","n":4,"group_id":"g4","ttl_s":180}"#),
        180,
    );
    let lease4_ms = t_lease.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(code, 200, "lease n=4: {lease4}");
    measure("after_lease_n4");
    eprintln!("GYM_MEASURE lease_n4_ms={lease4_ms:.1}");
    let envs = lease4["envs"].as_array().expect("envs");
    assert_eq!(envs.len(), 4);
    let mut branches = HashSet::new();
    for (i, e) in envs.iter().enumerate() {
        assert_eq!(e["index"], i);
        let bid = e["branch_node_id"].as_str().expect("branch_node_id");
        assert!(branches.insert(bid.to_string()), "duplicate branch {bid}");
        assert!(
            e["bridge"].as_str().unwrap_or("").starts_with("k7-br-"),
            "bridge: {e}"
        );
        let ips = e["guest_ips"].as_array().expect("guest_ips");
        assert_eq!(ips.len(), 3);
    }
    let owned4 = LeaseResidue::from_envs(envs);
    let listed = tree_node_ids(&tree_id);
    for b in &branches {
        assert!(listed.contains(b), "{b} missing from tree_nodes {listed:?}");
    }
    // All branches share one parent (one tree_fork_batch from the source).
    let mut c = Client::connect(k7d_sock()).expect("k7d");
    match c
        .call(&Request::TreeNodes {
            tree_id: tree_id.clone(),
        })
        .expect("tree_nodes")
    {
        Response::TreeNodeList { nodes, .. } => {
            for b in &branches {
                let n = nodes.iter().find(|n| n.id == *b).expect("node");
                assert_eq!(
                    n.parent.as_deref(),
                    Some("root"),
                    "{b} parent {:?}",
                    n.parent
                );
            }
        }
        other => panic!("{other:?}"),
    }

    let lease_id = lease4["lease_id"].as_str().expect("lease_id").to_string();
    let mut act_ms = Vec::new();
    for e in envs {
        let env_id = e["env_id"].as_str().unwrap();
        let t0 = Instant::now();
        let (code, act) = http(
            "POST",
            &format!("{}/env/{env_id}/act", gym.base),
            Some(r#"{"action":"exec","args":["echo","gym-ok"],"timeout_s":15}"#),
            30,
        );
        act_ms.push(t0.elapsed().as_secs_f64() * 1000.0);
        assert_eq!(code, 200, "act: {act}");
        assert_eq!(act["ok"], true, "act: {act}");
        assert!(
            act["stdout"].as_str().unwrap_or("").contains("gym-ok"),
            "act stdout: {act}"
        );
        let (code, obs) = http(
            "POST",
            &format!("{}/env/{env_id}/obs", gym.base),
            Some("{}"),
            30,
        );
        assert_eq!(code, 200, "obs: {obs}");
        assert!(obs.get("observation").is_some(), "obs: {obs}");
        assert_eq!(obs["truncated_bytes"], 0);
    }
    let t_score = Instant::now();
    let (code, score) = http(
        "POST",
        &format!("{}/lease/{lease_id}/score", gym.base),
        Some("{}"),
        60,
    );
    let score_ms = t_score.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(code, 200, "score: {score}");
    let scores = score["scores"].as_array().expect("scores");
    assert_eq!(scores.len(), 4);
    for (i, s) in scores.iter().enumerate() {
        assert_eq!(s["env_id"], envs[i]["env_id"]);
        let terms = s["terms"].as_object().expect("terms");
        for k in [
            "liveness",
            "workload_ready",
            "source_intact",
            "contained",
            "restored",
        ] {
            assert!(terms.contains_key(k), "missing term {k} in {s}");
        }
        assert!(s["reward"].as_f64().is_some());
    }
    eprintln!("GYM_MEASURE act_ms={:?} score_n4_ms={score_ms:.1}", act_ms);

    let (code, rel) = http(
        "POST",
        &format!("{}/lease/{lease_id}/release", gym.base),
        Some("{}"),
        60,
    );
    assert_eq!(code, 200, "release: {rel}");
    assert_eq!(rel["released"], true);
    assert_http_residue_empty(&rel, "n=4");
    owned4.assert_gone(&tree_id, "after n=4 release");
    measure("after_release_n4");

    let episode_ms = lease4_ms
        + act_ms.iter().sum::<f64>()
        + score_ms
        + /* release already done; fold a conservative 0 */ 0.0;
    if episode_ms > 0.0 {
        eprintln!(
            "GYM_MEASURE episodes_per_min_n4={:.2} episode_ms={episode_ms:.1}",
            60_000.0 / episode_ms
        );
    }

    // Success criterion: n=8 from one tree_fork_batch.
    let t8 = Instant::now();
    let (code, lease8) = http(
        "POST",
        &format!("{}/lease", gym.base),
        Some(r#"{"fault_id":"none","n":8,"group_id":"g8","ttl_s":180}"#),
        180,
    );
    let lease8_ms = t8.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(code, 200, "lease n=8: {lease8}");
    measure("after_lease_n8");
    eprintln!("GYM_MEASURE lease_n8_ms={lease8_ms:.1}");
    let envs8 = lease8["envs"].as_array().expect("envs8");
    assert_eq!(envs8.len(), 8);
    let owned8 = LeaseResidue::from_envs(envs8);
    let mut b8 = HashSet::new();
    for e in envs8 {
        assert!(b8.insert(e["branch_node_id"].as_str().unwrap().to_string()));
    }
    let listed = tree_node_ids(&tree_id);
    for b in &b8 {
        assert!(listed.contains(b), "{b} not in {listed:?}");
    }
    let lid8 = lease8["lease_id"].as_str().unwrap();
    let (code, rel8) = http(
        "POST",
        &format!("{}/lease/{lid8}/release", gym.base),
        Some("{}"),
        90,
    );
    assert_eq!(code, 200, "release n=8: {rel8}");
    assert_http_residue_empty(&rel8, "n=8");
    owned8.assert_gone(&tree_id, "after n=8 release");
    measure("after_release_n8");

    // 6. Kill the client mid-lease (no /release); reaper cleans up.
    let (code, short) = http(
        "POST",
        &format!("{}/lease", gym.base),
        Some(r#"{"fault_id":"none","n":2,"group_id":"ttl","ttl_s":3}"#),
        180,
    );
    assert_eq!(code, 200, "short ttl lease: {short}");
    let short_id = short["lease_id"].as_str().unwrap().to_string();
    let owned_ttl = LeaseResidue::from_envs(short["envs"].as_array().expect("ttl envs"));
    // Client walks away. GET stays 200 until prune finishes.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let (code, rec) = http("GET", &format!("{}/lease/{short_id}", gym.base), None, 5);
        if code == 404 {
            let (br, tap, nodes) = owned_ttl.leftover(&tree_id);
            if br.is_empty() && tap.is_empty() && nodes.is_empty() {
                break;
            }
        }
        assert!(
            Instant::now() < deadline,
            "reaper did not drop lease {short_id} with zero residue: last {rec}"
        );
        std::thread::sleep(Duration::from_millis(400));
    }
    owned_ttl.assert_gone(&tree_id, "after TTL reap");
    measure("after_ttl_reap");
}

fn term_f64(score: &serde_json::Value, key: &str) -> f64 {
    score["terms"][key]
        .as_f64()
        .unwrap_or_else(|| panic!("missing term {key} in {score}"))
}

fn assert_terms_present(score: &serde_json::Value) {
    let terms = score["terms"].as_object().expect("terms");
    for k in [
        "liveness",
        "workload_ready",
        "source_intact",
        "contained",
        "restored",
    ] {
        assert!(terms.contains_key(k), "missing term {k} in {score}");
    }
}

/// the referenced work: named injectors, contain/restore terms, zero residue.
#[test]
fn test_gym_fault_catalog_contain_restore() {
    let _ = env_logger::builder().is_test(true).try_init();
    common::ensure_k7d_daemon_running();

    let tree_id = format!("gym-src-test-fault-{}", std::process::id());
    wipe_stale_gym_test_trees();
    wipe_tree(&tree_id);

    measure("faults_before_source");
    let gym = spawn_gym(&tree_id, 64);
    measure("faults_after_source");

    // Unknown id is 400 with the allowlist — nothing is forked.
    let source_nodes: HashSet<String> = tree_node_ids(&tree_id).into_iter().collect();
    let (code, bad) = http(
        "POST",
        &format!("{}/lease", gym.base),
        Some(r#"{"fault_id":"not-a-fault","n":2,"group_id":"nope","ttl_s":30}"#),
        10,
    );
    assert_eq!(code, 400, "unknown fault: {bad}");
    let err = bad["error"].as_str().unwrap_or("");
    assert!(
        err.contains("unknown fault_id") && err.contains("allowlist:"),
        "allowlist missing: {err}"
    );
    for id in ["none", "kill-member-0", "partition-member-0"] {
        assert!(err.contains(id), "allowlist missing {id}: {err}");
    }
    let after_unknown: HashSet<String> = tree_node_ids(&tree_id).into_iter().collect();
    assert_eq!(
        after_unknown, source_nodes,
        "unknown fault_id must not fork"
    );

    for fault_id in ["kill-member-0", "partition-member-0"] {
        let body =
            format!(r#"{{"fault_id":"{fault_id}","n":2,"group_id":"g-{fault_id}","ttl_s":180}}"#);
        let t_lease = Instant::now();
        let (code, lease) = http("POST", &format!("{}/lease", gym.base), Some(&body), 180);
        let lease_ms = t_lease.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(code, 200, "lease {fault_id}: {lease}");
        let inject_ms = lease["inject_ms"].as_f64().unwrap_or(-1.0);
        eprintln!(
            "GYM_MEASURE lease_{fault_id}_ms={lease_ms:.1} inject_{fault_id}_ms={inject_ms:.1}"
        );
        assert_eq!(lease["fault_id"], fault_id);
        let hint = lease["good_fix_hint"].as_object().expect("good_fix_hint");
        assert_eq!(hint["action"], "exec");
        assert!(
            hint["args"].as_array().is_some_and(|a| !a.is_empty()),
            "good_fix_hint.args: {hint:?}"
        );

        let envs = lease["envs"].as_array().expect("envs");
        assert_eq!(envs.len(), 2);
        let owned = LeaseResidue::from_envs(envs);
        let lease_id = lease["lease_id"].as_str().expect("lease_id").to_string();

        let t_score = Instant::now();
        let (code, score) = http(
            "POST",
            &format!("{}/lease/{lease_id}/score", gym.base),
            Some("{}"),
            60,
        );
        let score_ms = t_score.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(code, 200, "score before fix {fault_id}: {score}");
        eprintln!("GYM_MEASURE score_{fault_id}_ms={score_ms:.1}");
        let scores = score["scores"].as_array().expect("scores");
        assert_eq!(scores.len(), 2);
        for s in scores {
            assert_terms_present(s);
            assert_eq!(term_f64(s, "source_intact"), 1.0, "source leaked: {s}");
            assert_eq!(term_f64(s, "contained"), 1.0, "not contained: {s}");
            assert_eq!(term_f64(s, "restored"), 0.0, "already restored: {s}");
        }
        assert_eq!(
            term_f64(&scores[1], "liveness"),
            1.0,
            "sibling liveness: {}",
            scores[1]
        );

        let hint_args = hint["args"].as_array().unwrap();
        let act_body = serde_json::json!({
            "action": "exec",
            "args": hint_args,
            "timeout_s": 15,
        });
        let target = envs[0]["env_id"].as_str().unwrap();
        let (code, act) = http(
            "POST",
            &format!("{}/env/{target}/act", gym.base),
            Some(&act_body.to_string()),
            30,
        );
        assert_eq!(code, 200, "good fix {fault_id}: {act}");
        assert_eq!(act["ok"], true, "good fix {fault_id}: {act}");

        let t_score2 = Instant::now();
        let (code, score2) = http(
            "POST",
            &format!("{}/lease/{lease_id}/score", gym.base),
            Some("{}"),
            60,
        );
        let score2_ms = t_score2.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(code, 200, "score after fix {fault_id}: {score2}");
        eprintln!("GYM_MEASURE score_restored_{fault_id}_ms={score2_ms:.1}");
        let scores2 = score2["scores"].as_array().expect("scores2");
        for s in scores2 {
            assert_terms_present(s);
            assert_eq!(term_f64(s, "source_intact"), 1.0, "source after fix: {s}");
            assert_eq!(term_f64(s, "restored"), 1.0, "not restored: {s}");
            assert_eq!(term_f64(s, "contained"), 1.0, "contain lost after fix: {s}");
        }

        let (code, rel) = http(
            "POST",
            &format!("{}/lease/{lease_id}/release", gym.base),
            Some("{}"),
            60,
        );
        assert_eq!(code, 200, "release {fault_id}: {rel}");
        assert_eq!(rel["released"], true);
        assert_http_residue_empty(&rel, fault_id);
        owned.assert_gone(&tree_id, &format!("after {fault_id} release"));

        let episode_ms = lease_ms + score_ms + score2_ms;
        eprintln!(
            "GYM_MEASURE episode_{fault_id}_ms={episode_ms:.1} episodes_per_min_{fault_id}={:.2}",
            60_000.0 / episode_ms.max(1.0)
        );
        measure(&format!("after_{fault_id}"));
    }
}

/// POST /lease `autowarp_mode` starts the daemon policy; `/act` exec
/// holds it; `/release` stops it and returns the counters.
#[test]
fn test_gym_autowarp_mode_jump() {
    let _ = env_logger::builder().is_test(true).try_init();
    common::ensure_k7d_daemon_running();

    let tree_id = format!("gym-src-warp-{}", std::process::id());
    wipe_stale_gym_test_trees();
    wipe_tree(&tree_id);
    let gym = spawn_gym(&tree_id, 64);

    let (code, bad) = http(
        "POST",
        &format!("{}/lease", gym.base),
        Some(
            r#"{"fault_id":"none","n":1,"group_id":"warp-bad","ttl_s":60,"autowarp_mode":"fast"}"#,
        ),
        10,
    );
    assert_eq!(code, 400, "unknown mode must be 400: {bad}");
    let err = bad["error"].as_str().unwrap_or("");
    assert!(
        err.contains("off|jump|micro|dilate"),
        "loud mode error missing: {err}"
    );

    let (code, dilate) = http(
        "POST",
        &format!("{}/lease", gym.base),
        Some(
            r#"{"fault_id":"none","n":1,"group_id":"warp-dilate","ttl_s":60,"autowarp_mode":"dilate"}"#,
        ),
        10,
    );
    assert_eq!(code, 400, "dilate on create-mode gym must be 400: {dilate}");
    let dilate_err = dilate["error"].as_str().unwrap_or("");
    assert!(
        dilate_err.contains("GYM_SOURCE_MODE=ubuntu"),
        "dilate must require the ubuntu source : {dilate_err}"
    );

    let (code, lease) = http(
        "POST",
        &format!("{}/lease", gym.base),
        Some(
            r#"{"fault_id":"none","n":1,"group_id":"warp-jump","ttl_s":90,"autowarp_mode":"jump"}"#,
        ),
        180,
    );
    assert_eq!(code, 200, "lease jump: {lease}");
    assert_eq!(lease["autowarp_mode"], "jump");
    let env = &lease["envs"][0];
    assert_eq!(env["autowarp_mode"], "jump");
    let cluster_id = env["cluster_id"]
        .as_str()
        .expect("cluster_id on env")
        .to_string();
    assert!(
        cluster_id.starts_with(&format!("{tree_id}-")),
        "cluster_id={cluster_id} tree={tree_id}"
    );

    let mut client = Client::connect(k7d_sock()).expect("k7d client");
    match client
        .call(&Request::AutoWarpStatus {
            cluster_id: cluster_id.clone(),
        })
        .expect("status")
    {
        Response::AutoWarp { mode, .. } => {
            assert_eq!(mode, k7d::autowarp::AutoWarpMode::Jump);
        }
        other => panic!("status: {other:?}"),
    }

    let env_id = env["env_id"].as_str().expect("env_id");
    let (code, act) = http(
        "POST",
        &format!("{}/env/{env_id}/act", gym.base),
        Some(r#"{"action":"exec","args":["echo","gym-ok"]}"#),
        30,
    );
    assert_eq!(code, 200, "exec under hold: {act}");
    assert_eq!(act["ok"], true, "exec: {act}");
    assert!(
        act["stdout"].as_str().unwrap_or("").contains("gym-ok"),
        "exec: {act}"
    );

    let lease_id = lease["lease_id"].as_str().expect("lease_id");
    let (code, rel) = http(
        "POST",
        &format!("{}/lease/{lease_id}/release", gym.base),
        Some("{}"),
        60,
    );
    assert_eq!(code, 200, "release: {rel}");
    assert_eq!(rel["released"], true);
    let stats = rel["autowarp"]
        .as_array()
        .expect("release returns autowarp stats");
    assert_eq!(stats.len(), 1, "{stats:?}");
    assert_eq!(stats[0]["mode"], "off");
    assert_eq!(stats[0]["cluster_id"], cluster_id);

    match client
        .call(&Request::AutoWarpStatus {
            cluster_id: cluster_id.clone(),
        })
        .expect("status after release")
    {
        Response::AutoWarp { mode, .. } => {
            assert_eq!(mode, k7d::autowarp::AutoWarpMode::Off);
        }
        other => panic!("status after release: {other:?}"),
    }
}

/// `dilate` is CreateVm N=8, not `Request::AutoWarp`. Create-mode
/// (busybox) is out of scope for inc4 — refuse loud on stock KVM.
#[test]
fn test_gym_autowarp_mode_dilate_refuses_create() {
    let _ = env_logger::builder().is_test(true).try_init();
    common::ensure_k7d_daemon_running();

    let tree_id = format!("gym-src-dilate-{}", std::process::id());
    wipe_stale_gym_test_trees();
    wipe_tree(&tree_id);
    let gym = spawn_gym(&tree_id, 64);

    let (code, rec) = http(
        "POST",
        &format!("{}/lease", gym.base),
        Some(
            r#"{"fault_id":"none","n":1,"group_id":"warp-dilate","ttl_s":60,"autowarp_mode":"dilate"}"#,
        ),
        10,
    );
    assert_eq!(code, 400, "dilate on create-mode gym must be 400: {rec}");
    let err = rec["error"].as_str().unwrap_or("");
    assert!(
        err.contains("GYM_SOURCE_MODE=ubuntu"),
        "dilate must require the ubuntu source : {err}"
    );
}
