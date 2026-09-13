//! Gym-router sticky groups, Ubuntu admission, drain.
//!
//! Two stub gym processes + `gym/router.py`. The router never talks to
//! `/run/k7d/k7d.sock` and never forks — stubs implement the frozen
//! HTTP contract. No `#[ignore]`.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn ephemeral_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral bind");
    l.local_addr().expect("local_addr").port()
}

struct Proc {
    child: Child,
    log_path: PathBuf,
    base: String,
    node_id: String,
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Ok(log) = std::fs::read_to_string(&self.log_path) {
            eprintln!(
                "---- {} log {} ----\n{log}\n---- end ----",
                self.node_id,
                self.log_path.display()
            );
        }
    }
}

fn child_dead(child: &Child) -> bool {
    !Path::new(&format!("/proc/{}/status", child.id())).exists()
}

fn try_http(
    method: &str,
    url: &str,
    body: Option<&str>,
    timeout_s: u64,
) -> Result<(u16, serde_json::Value), String> {
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
    Ok((code, json))
}

fn http(method: &str, url: &str, body: Option<&str>, timeout_s: u64) -> (u16, serde_json::Value) {
    try_http(method, url, body, timeout_s).unwrap_or_else(|e| panic!("{method} {url}: {e}"))
}

fn wait_healthz(base: &str, child: &Child, log_path: &Path, want_ok: bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok((code, v)) = try_http("GET", &format!("{base}/healthz"), None, 2) {
            let ok = v.get("ok").and_then(|x| x.as_bool()) == Some(true);
            if want_ok && code == 200 && ok {
                return;
            }
            if !want_ok && (code == 503 || !ok) {
                return;
            }
        }
        assert!(
            Instant::now() < deadline && !child_dead(child),
            "never healthy want_ok={want_ok} at {base}; see {}",
            log_path.display()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn spawn_stub(node_id: &str) -> Proc {
    let root = workspace_root();
    let port = ephemeral_port();
    let log_path = std::env::temp_dir().join(format!(
        "k7-gym-stub-{}-{}-{port}.log",
        node_id,
        std::process::id()
    ));
    let log = File::create(&log_path).expect("stub log");
    let child = Command::new("python3")
        .arg(root.join("gym/stub.py"))
        .env("GYM_BIND", "127.0.0.1")
        .env("GYM_PORT", port.to_string())
        .env("GYM_NODE_ID", node_id)
        .stdout(Stdio::from(log.try_clone().expect("clone log")))
        .stderr(Stdio::from(log))
        .spawn()
        .expect("spawn gym/stub.py");
    let base = format!("http://127.0.0.1:{port}");
    wait_healthz(&base, &child, &log_path, true);
    Proc {
        child,
        log_path,
        base,
        node_id: node_id.to_string(),
    }
}

fn spawn_router(upstreams: &[String]) -> Proc {
    let root = workspace_root();
    let port = ephemeral_port();
    let log_path =
        std::env::temp_dir().join(format!("k7-gym-router-{}-{port}.log", std::process::id()));
    let log = File::create(&log_path).expect("router log");
    let child = Command::new("python3")
        .arg(root.join("gym/router.py"))
        .env("GYM_BIND", "127.0.0.1")
        .env("GYM_PORT", port.to_string())
        .env("GYM_NODE_ID", "router-test")
        .env("GYM_MEMORY_MB", "2048")
        .env("GYM_VM_COUNT", "3")
        .env("GYM_UPSTREAMS", upstreams.join(","))
        .env("GYM_HEALTH_TIMEOUT_S", "1")
        .stdout(Stdio::from(log.try_clone().expect("clone log")))
        .stderr(Stdio::from(log))
        .spawn()
        .expect("spawn gym/router.py");
    let base = format!("http://127.0.0.1:{port}");
    wait_healthz(&base, &child, &log_path, true);
    Proc {
        child,
        log_path,
        base,
        node_id: "router-test".to_string(),
    }
}

fn lease_body(group_id: &str, n: u32) -> String {
    format!(r#"{{"fault_id":"none","n":{n},"group_id":"{group_id}","ttl_s":60}}"#)
}

#[test]
fn test_router_never_mentions_k7d_client() {
    let src = std::fs::read_to_string(workspace_root().join("gym/router.py")).expect("router.py");
    assert!(
        !src.contains("k7d_client") && !src.contains("AF_UNIX") && !src.contains("tree_fork"),
        "router must not talk to k7d or fork"
    );
    assert!(
        src.contains("Never talks to"),
        "forbid-socket docstring missing"
    );
}

#[test]
fn test_gym_router_sticky_drain_admission() {
    let a = spawn_stub("node-a");
    let b = spawn_stub("node-b");
    let router = spawn_router(&[a.base.clone(), b.base.clone()]);

    // Admission reject spells Ubuntu arithmetic; nothing is placed.
    let t_rej = Instant::now();
    let (code, rej) = http(
        "POST",
        &format!("{}/lease", router.base),
        Some(&lease_body("too-big", 32)),
        5,
    );
    let reject_ms = t_rej.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(code, 400, "budget reject: {rej}");
    let err = rej["error"].as_str().unwrap_or("");
    assert!(
        err.contains("need 99 live VMs")
            && err.contains("vms_per_branch=3")
            && err.contains("2048 MiB × 3 × (1+n)")
            && err.contains("GYM_MEMORY_MB=2048"),
        "ubuntu arithmetic missing: {err}"
    );
    eprintln!("ROUTER_MEASURE reject_ms={reject_ms:.2}");

    let mut proxy_ms = Vec::new();
    let t0 = Instant::now();
    let (code, first) = http(
        "POST",
        &format!("{}/lease", router.base),
        Some(&lease_body("g1", 1)),
        5,
    );
    proxy_ms.push(t0.elapsed().as_secs_f64() * 1000.0);
    assert_eq!(code, 200, "first lease: {first}");
    let owner = first["node_id"].as_str().expect("node_id").to_string();
    assert!(owner == "node-a" || owner == "node-b", "{owner}");
    let env_id = first["envs"][0]["env_id"]
        .as_str()
        .expect("env_id")
        .to_string();
    let lease_id = first["lease_id"].as_str().expect("lease_id").to_string();

    let t1 = Instant::now();
    let (code, second) = http(
        "POST",
        &format!("{}/lease", router.base),
        Some(&lease_body("g1", 1)),
        5,
    );
    proxy_ms.push(t1.elapsed().as_secs_f64() * 1000.0);
    assert_eq!(code, 200, "sticky lease: {second}");
    assert_eq!(
        second["node_id"].as_str(),
        Some(owner.as_str()),
        "same group_id must stick"
    );
    assert_ne!(second["lease_id"].as_str(), Some(lease_id.as_str()));

    proxy_ms.sort_by(|x, y| x.partial_cmp(y).unwrap());
    let p50 = proxy_ms[proxy_ms.len() / 2];
    eprintln!("ROUTER_MEASURE proxy_overhead_p50_ms={p50:.2} samples={proxy_ms:?}");

    let (code, unknown) = http(
        "GET",
        &format!("{}/lease/does-not-exist", router.base),
        None,
        5,
    );
    assert_eq!(code, 404, "unknown lease must not broadcast: {unknown}");
    assert!(
        unknown["error"]
            .as_str()
            .unwrap_or("")
            .contains("no such lease"),
        "{unknown}"
    );

    let (code, act_ok) = http(
        "POST",
        &format!("{}/env/{env_id}/act", router.base),
        Some(r#"{"action":"exec","args":["true"],"timeout_s":1}"#),
        5,
    );
    assert_eq!(code, 200, "act while up: {act_ok}");
    assert_eq!(act_ok["node_id"].as_str(), Some(owner.as_str()));

    // Kill the owner gym. In-flight act is loud; a new group goes elsewhere.
    // /proc stays around for a zombie, so drain-detect is "healthz fails".
    let victim = if owner == "node-a" { &a } else { &b };
    let _ = Command::new("kill")
        .args(["-9", &victim.child.id().to_string()])
        .status();
    let dead_at = Instant::now();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match try_http("GET", &format!("{}/healthz", victim.base), None, 1) {
            Ok((200, _)) => {}
            _ => break,
        }
        assert!(
            Instant::now() < deadline,
            "victim {owner} still serving healthz after kill"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    let (code, act_dead) = http(
        "POST",
        &format!("{}/env/{env_id}/act", router.base),
        Some(r#"{"action":"exec","args":["true"],"timeout_s":1}"#),
        5,
    );
    assert_eq!(
        code, 502,
        "in-flight act on dead gym must be loud: {act_dead}"
    );
    let act_err = act_dead["error"].as_str().unwrap_or("");
    assert!(
        act_err.contains("unreachable") || act_err.contains("upstream"),
        "loud error missing: {act_err}"
    );

    let t_drain = Instant::now();
    let (code, nxt) = http(
        "POST",
        &format!("{}/lease", router.base),
        Some(&lease_body("g-new", 1)),
        5,
    );
    let drain_ms = t_drain.elapsed().as_secs_f64() * 1000.0;
    let detect_ms = dead_at.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(code, 200, "new group after drain: {nxt}");
    let other = nxt["node_id"].as_str().expect("node_id");
    assert_ne!(other, owner, "new group must not land on the dead gym");
    eprintln!("ROUTER_MEASURE drain_detect_ms={detect_ms:.2} new_group_ms={drain_ms:.2}");

    let (code, stuck) = http(
        "POST",
        &format!("{}/lease", router.base),
        Some(&lease_body("g1", 1)),
        5,
    );
    assert_eq!(code, 503, "do not migrate sticky group: {stuck}");
    assert!(
        stuck["error"]
            .as_str()
            .unwrap_or("")
            .contains("not migrating"),
        "{stuck}"
    );
}
