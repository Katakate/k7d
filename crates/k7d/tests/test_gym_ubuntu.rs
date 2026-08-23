//! the referenced work: gym `GYM_SOURCE_MODE=ubuntu` over a 25a-inc2 cluster.
//!
//! Talks only to `/run/k7d/k7d.sock`. Never `#[ignore]`. Does not edit
//! minimal-guest budgets or fall back to busybox / INNER3.

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

fn wipe_stale_ubuntu_gym_trees() {
    let mut c = match Client::connect(k7d_sock()) {
        Ok(c) => c,
        Err(_) => return,
    };
    let trees = match c.call(&Request::TreeList) {
        Ok(Response::TreeList { trees }) => trees,
        _ => return,
    };
    for t in trees {
        if t.tree_id.starts_with("gym-src-test-ubuntu-") {
            wipe_tree(&t.tree_id);
        }
    }
}

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
                "---- gym ubuntu log {} ----\n{log}\n---- end gym ubuntu log ----",
                self.log_path.display()
            );
        }
    }
}

fn ensure_musl_agent() {
    let agent = workspace_root().join("target/x86_64-unknown-linux-musl/release/k7-agent");
    if agent.is_file() {
        return;
    }
    let status = Command::new("make")
        .arg("build-agent")
        .current_dir(workspace_root())
        .status()
        .expect("make build-agent");
    assert!(status.success(), "make build-agent failed");
    assert!(
        agent.is_file(),
        "k7-agent still missing at {}",
        agent.display()
    );
}

fn spawn_ubuntu_gym(tree_id: &str) -> GymGuard {
    let root = workspace_root();
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral bind");
        l.local_addr().expect("local_addr").port()
    };
    let log_path =
        std::env::temp_dir().join(format!("k7-gym-ubuntu-{}-{port}.log", std::process::id()));
    let log = File::create(&log_path).expect("gym log");
    let child = Command::new("python3")
        .arg(root.join("gym/server.py"))
        .env("GYM_SOURCE_MODE", "ubuntu")
        .env("GYM_BIND", "127.0.0.1")
        .env("GYM_PORT", port.to_string())
        .env("GYM_SOURCE_TREE_ID", tree_id)
        .env("GYM_MAX_LIVE_VMS", "64")
        .env("GYM_MAX_LEASES", "4")
        .env("GYM_REAPER_INTERVAL_S", "1")
        .env("GYM_K7D_TIMEOUT_S", "180")
        .env("GYM_MEMORY_MB", "2048")
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
    // Hang-detection window, not a 250 ms budget (25a-inc2).
    let deadline = Instant::now() + Duration::from_secs(600);
    loop {
        if let Ok((code, _, v)) = try_http("GET", &format!("{}/healthz", guard.base), None, 5) {
            if code == 200 && v.get("ok").and_then(|x| x.as_bool()) == Some(true) {
                break;
            }
        }
        let dead = !Path::new(&format!("/proc/{}/status", guard.child.id())).exists();
        assert!(
            Instant::now() < deadline && !dead,
            "ubuntu gym never became healthy (dead={dead}); see {}",
            guard.log_path.display()
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    if let Ok(log) = std::fs::read_to_string(&guard.log_path) {
        assert!(
            !log.contains("tree_create_cluster"),
            "ubuntu gym must not call tree_create_cluster:\n{log}"
        );
        assert!(
            !log.contains("k7-br-inner3"),
            "ubuntu gym must not adopt INNER3:\n{log}"
        );
    }
    guard
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
        "GYM_UBUNTU_MEASURE {label} mem_available_bytes={} k7d_vmrss_bytes={:?}",
        mem_available_bytes(),
        k7d_vmrss_bytes()
    );
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

#[test]
fn test_gym_ubuntu_source_kill_partition_release() {
    let _ = env_logger::builder().is_test(true).try_init();
    common::ensure_k7d_daemon_running();
    ensure_musl_agent();

    let tree_id = format!("gym-src-test-ubuntu-{}", std::process::id());
    wipe_stale_ubuntu_gym_trees();
    wipe_tree(&tree_id);

    measure("before_source");
    let t_src = Instant::now();
    let gym = spawn_ubuntu_gym(&tree_id);
    let bring_ms = t_src.elapsed().as_secs_f64() * 1000.0;
    measure("after_source");
    eprintln!("GYM_UBUNTU_MEASURE source_bring_up_ms={bring_ms:.1}");

    let (code, hz) = http("GET", &format!("{}/healthz", gym.base), None, 5);
    assert_eq!(code, 200, "healthz: {hz}");
    assert_eq!(hz["ok"], true);
    assert_eq!(hz["k7d"], "ready");

    let source_nodes: HashSet<String> = tree_node_ids(&tree_id).into_iter().collect();
    assert!(
        source_nodes.contains("root"),
        "ubuntu source root missing: {source_nodes:?}"
    );

    let (code, rej) = http(
        "POST",
        &format!("{}/lease", gym.base),
        Some(r#"{"fault_id":"none","n":32,"group_id":"too-big","ttl_s":30}"#),
        10,
    );
    assert_eq!(code, 400, "budget reject: {rej}");
    let err = rej["error"].as_str().unwrap_or("");
    assert!(
        err.contains("need ") && err.contains("n=32") && err.contains("vms_per_branch=3"),
        "arithmetic missing from reject: {err}"
    );
    assert_eq!(
        tree_node_ids(&tree_id).into_iter().collect::<HashSet<_>>(),
        source_nodes,
        "over-budget lease must not fork"
    );

    // n=1 then n=2 — measure tree_fork_batch on the gym path.
    for n in [1_u32, 2] {
        let body = format!(r#"{{"fault_id":"none","n":{n},"group_id":"g{n}","ttl_s":180}}"#);
        let t_lease = Instant::now();
        let (code, lease) = http("POST", &format!("{}/lease", gym.base), Some(&body), 180);
        let lease_ms = t_lease.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(code, 200, "lease n={n}: {lease}");
        measure(&format!("after_lease_n{n}"));
        eprintln!(
            "GYM_UBUNTU_MEASURE lease_n{n}_ms={lease_ms:.1} inject_ms={:.1}",
            lease["inject_ms"].as_f64().unwrap_or(-1.0)
        );
        let envs = lease["envs"].as_array().expect("envs");
        assert_eq!(envs.len(), n as usize);
        let owned = LeaseResidue::from_envs(envs);
        let env0 = envs[0]["env_id"].as_str().unwrap();
        let (code, obs) = http(
            "POST",
            &format!("{}/env/{env0}/obs", gym.base),
            Some("{}"),
            30,
        );
        assert_eq!(code, 200, "obs: {obs}");
        assert!(
            obs["observation"].get("readyz").is_some(),
            "obs must be API, not uname: {obs}"
        );
        assert!(
            obs["observation"].get("nodes").is_some(),
            "obs nodes: {obs}"
        );
        let (code, act) = http(
            "POST",
            &format!("{}/env/{env0}/act", gym.base),
            Some(r#"{"action":"kubectl","args":["get","nodes"],"timeout_s":20}"#),
            30,
        );
        assert_eq!(code, 200, "kubectl get nodes: {act}");
        assert_eq!(act["ok"], true, "kubectl get nodes: {act}");
        let lid = lease["lease_id"].as_str().unwrap();
        let t_score = Instant::now();
        let (code, score) = http(
            "POST",
            &format!("{}/lease/{lid}/score", gym.base),
            Some("{}"),
            60,
        );
        let score_ms = t_score.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(code, 200, "score n={n}: {score}");
        eprintln!("GYM_UBUNTU_MEASURE score_n{n}_ms={score_ms:.1}");
        let (code, rel) = http(
            "POST",
            &format!("{}/lease/{lid}/release", gym.base),
            Some("{}"),
            90,
        );
        assert_eq!(code, 200, "release n={n}: {rel}");
        assert_http_residue_empty(&rel, &format!("n={n}"));
        owned.assert_gone(&tree_id, &format!("after n={n} release"));
        if n == 2 {
            let episode_ms = lease_ms + score_ms;
            eprintln!(
                "GYM_UBUNTU_MEASURE episodes_per_min_n2={:.2} episode_ms={episode_ms:.1}",
                60_000.0 / episode_ms.max(1.0)
            );
        }
    }

    for fault_id in ["kill-member-0", "partition-member-0"] {
        let body =
            format!(r#"{{"fault_id":"{fault_id}","n":2,"group_id":"g-{fault_id}","ttl_s":180}}"#);
        let t_lease = Instant::now();
        let (code, lease) = http("POST", &format!("{}/lease", gym.base), Some(&body), 180);
        let lease_ms = t_lease.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(code, 200, "lease {fault_id}: {lease}");
        eprintln!(
            "GYM_UBUNTU_MEASURE lease_{fault_id}_ms={lease_ms:.1} inject_ms={:.1}",
            lease["inject_ms"].as_f64().unwrap_or(-1.0)
        );
        let hint = lease["good_fix_hint"].as_object().expect("good_fix_hint");
        assert_eq!(hint["action"], "exec");
        if fault_id == "kill-member-0" {
            let args = hint["args"].as_array().expect("args");
            let joined = args
                .iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            assert!(
                joined.contains("systemctl") && joined.contains("k3s"),
                "ubuntu kill fix must be systemctl, not kill -9 1: {hint:?}"
            );
            assert!(!joined.contains("kill -9"), "must not kill PID 1: {hint:?}");
        }
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
        eprintln!("GYM_UBUNTU_MEASURE score_{fault_id}_ms={score_ms:.1}");
        let scores = score["scores"].as_array().expect("scores");
        assert_eq!(scores.len(), 2);
        for s in scores {
            assert_terms_present(s);
            assert_eq!(term_f64(s, "source_intact"), 1.0, "source leaked: {s}");
            assert_eq!(term_f64(s, "contained"), 1.0, "not contained: {s}");
            assert_eq!(term_f64(s, "restored"), 0.0, "already restored: {s}");
        }

        let hint_args = hint["args"].as_array().unwrap();
        let act_body = serde_json::json!({
            "action": "exec",
            "args": hint_args,
            "timeout_s": 45,
        });
        let target = envs[0]["env_id"].as_str().unwrap();
        let (code, act) = http(
            "POST",
            &format!("{}/env/{target}/act", gym.base),
            Some(&act_body.to_string()),
            60,
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
        eprintln!("GYM_UBUNTU_MEASURE score_restored_{fault_id}_ms={score2_ms:.1}");
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
            90,
        );
        assert_eq!(code, 200, "release {fault_id}: {rel}");
        assert_http_residue_empty(&rel, fault_id);
        owned.assert_gone(&tree_id, &format!("after {fault_id} release"));
        measure(&format!("after_{fault_id}"));
    }
}
