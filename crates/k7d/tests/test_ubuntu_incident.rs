//! Inspect-battery proof for the `relay` incident.
//!
//! The point of this test is the *information structure*, not a fork.
//! A competent agent inspects the whole guest before it forks, so an
//! incident whose deeper persistences are named by that inspection gets
//! a full-cleanup fan-out at depth 1 (CHALLENGES #131 — `hydra` and
//! `sleeper` both did). `relay` is designed so a pre-fork inspect
//! battery **cannot name** layers 2 and 3, and they only become
//! observable once the agent deletes the layer above them.
//!
//! This test plants the *real* catalog incident (it fetches
//! `incidents.Relay.plant_script()` from `examples/k7d-mcp/incidents.py`
//! and execs it verbatim — no reimplementation that could drift), runs
//! the exact battery from the spec, and asserts:
//!   1. the pre-delete dump names layer 1 (`node-agent`) but **not**
//!      the layer-2/3 tokens (`kubelet-sync`, `systemd-unit-check`) —
//!      not even under a `find -name '*node-agent*'`;
//!   2. after deleting only layer 1 and soaking, the miner Deployment
//!      comes back — the natural, causal proof that layer 2 exists;
//!   3. removing layer 2's unit files (but not layer 3) and soaking
//!      brings layer 2 back — the causal proof that the deeper guard
//!      only becomes observable once layer 2 is destroyed;
//!   4. the scripted full remediation peels every layer and the miner
//!      stays gone.
//!
//! Ubuntu bare-VM only — never the busybox `K7D_KERNEL`/`K7D_INITRD`
//! guest (`bring_up_cluster` boots the adopted Ubuntu node image).

mod common;

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use common::ubuntu::{connect_or_dump, sh, sh_ok, workspace_path};
use common::ubuntu_k3s::{bring_up_cluster, kubectl};

use k7d::api::AgentClient;

/// What `examples/k7d-mcp/incidents.py` says the incident is — fetched
/// from the catalog so the test cannot drift from the shipped incident.
struct RelaySpec {
    yaml: String,
    plant: String,
    remediate: String,
    tokens: Vec<String>,
    deploy: String,
}

fn load_relay_spec() -> RelaySpec {
    let mcp_dir = workspace_path("examples/k7d-mcp");
    let py = r#"
import json, incidents
r = incidents.get("relay")
print(json.dumps({
    "yaml": r.yaml,
    "plant": r.plant_script(),
    "remediate": r.remediate_cmd(),
    "tokens": list(r.next_layer_tokens),
    "deploy": incidents.RELAY_MINER,
}))
"#;
    let out = Command::new("python3")
        .arg("-c")
        .arg(py)
        .current_dir(&mcp_dir)
        .output()
        .expect("run python3 to read the relay catalog entry");
    assert!(
        out.status.success(),
        "python3 -c import incidents failed: {}\n{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "relay catalog json: {e}: {:?}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    let s = |k: &str| {
        v[k].as_str()
            .unwrap_or_else(|| panic!("relay json missing {k}"))
            .to_string()
    };
    let tokens = v["tokens"]
        .as_array()
        .expect("tokens array")
        .iter()
        .map(|t| t.as_str().expect("token string").to_string())
        .collect::<Vec<_>>();
    assert!(!tokens.is_empty(), "relay declared no next-layer tokens");
    RelaySpec {
        yaml: s("yaml"),
        plant: s("plant"),
        remediate: s("remediate"),
        tokens,
        deploy: s("deploy"),
    }
}

/// Run the whole spec inspect battery and return one concatenated dump.
/// `kube` covers the two `kubectl get` arms; `server` covers the host
/// arms (systemd units + timers + cron + ps) on the control-plane node.
fn inspect_battery(kube: &std::path::Path, server: &mut AgentClient) -> String {
    let mut dump = String::new();
    for args in [
        vec![
            "get",
            "deploy,ds,sts,cj,job,po,sa,role,rolebinding,cm,secret",
            "-A",
        ],
        vec!["get", "deploy,cj", "-A", "-o", "yaml"],
    ] {
        let out = kubectl(kube, &args).unwrap_or_else(|e| panic!("battery `{args:?}`: {e}"));
        dump.push_str(&out);
        dump.push('\n');
    }
    for cmd in [
        "systemctl list-units --type=service --state=running --no-pager --plain --no-legend",
        "systemctl list-timers --all --no-pager --no-legend",
        "ls -la /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly \
         /etc/cron.monthly /etc/crontab /var/spool/cron 2>&1 || true",
        "crontab -l 2>&1 || true",
        "ps aux",
        // The agent's own extra probe from the recorded run — a name
        // walk from the visible symptom. Neutral host names must keep it
        // from reaching either deeper layer.
        "find / -xdev \\( -name '*node-agent*' -o -name '*nodecheck*' \\) 2>/dev/null || true",
    ] {
        let (_, out, err) = sh(server, cmd);
        dump.push_str(&out);
        dump.push_str(&err);
        dump.push('\n');
    }
    dump
}

fn deploy_present(kube: &std::path::Path, name: &str) -> bool {
    kubectl(
        kube,
        &["-n", "default", "get", "deploy", name, "--no-headers"],
    )
    .map(|s| s.contains(name))
    .unwrap_or(false)
}

fn wait_deploy(kube: &std::path::Path, name: &str, present: bool, ceiling: Duration) -> Duration {
    let start = Instant::now();
    loop {
        if deploy_present(kube, name) == present {
            return start.elapsed();
        }
        assert!(
            start.elapsed() < ceiling,
            "Deployment {name} never became present={present} within {ceiling:?}"
        );
        std::thread::sleep(Duration::from_secs(2));
    }
}

/// Assert the miner Deployment does NOT reappear for `hold` — the
/// remediated end state, where no reseeder is left to resurrect it.
fn assert_stays_gone(kube: &std::path::Path, name: &str, hold: Duration) {
    let start = Instant::now();
    while start.elapsed() < hold {
        assert!(
            !deploy_present(kube, name),
            "Deployment {name} came back after full remediation — a layer was missed"
        );
        std::thread::sleep(Duration::from_secs(3));
    }
}

/// Let the dormant oneshot services settle to `inactive` before the
/// battery snapshot: a `.path` unit's paired `.service` is `active
/// (running)` for the <1s it takes to fire, and pod churn or the
/// plant's own `daemon-reload` can have just fired one.
fn wait_units_dormant(server: &mut AgentClient, units: &[&str]) {
    let start = Instant::now();
    loop {
        let busy: Vec<&str> = units
            .iter()
            .copied()
            .filter(|u| {
                let (_, out, _) = sh(
                    server,
                    &format!("systemctl is-active {u} 2>/dev/null || true"),
                );
                let s = out.trim();
                s == "active" || s == "activating" || s == "reloading"
            })
            .collect();
        if busy.is_empty() {
            return;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "reseed oneshots never went dormant: {busy:?}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Success criterion: the pre-delete inspect dump must
/// not name layers 2+, and a delete of layer 1 alone must bring the
/// miner back on the soak.
#[test]
fn test_ubuntu_relay_inspect_battery_is_blind_to_deeper_layers() {
    let _ = env_logger::builder().is_test(true).try_init();
    let relay = load_relay_spec();
    let reseed_units = ["kubelet-sync.service", "systemd-unit-check.service"];

    let mut cluster = bring_up_cluster();
    let kube = cluster.kubeconfig.clone();

    // Layer 1: apply the miner Deployment (control-plane pinned) and
    // wait for its pod to run — that also creates the kubelet pod dir
    // the reconcile watcher keys off.
    let manifest = PathBuf::from(format!("/tmp/k7d-relay-{}.yaml", std::process::id()));
    std::fs::write(&manifest, &relay.yaml).expect("write relay manifest");
    kubectl(&kube, &["apply", "-f", &manifest.to_string_lossy()]).expect("apply relay layer 1");
    kubectl(
        &kube,
        &[
            "-n",
            "default",
            "rollout",
            "status",
            &format!("deploy/{}", relay.deploy),
            "--timeout=240s",
        ],
    )
    .unwrap_or_else(|e| panic!("relay miner never rolled out (image pull through bridge?): {e}"));

    // Layers 2/3: plant the dormant path units on the control-plane node.
    let mut server = connect_or_dump(&mut cluster.server, "server");
    sh_ok(&mut server, &relay.plant);
    let path_units = sh_ok(
        &mut server,
        "systemctl list-units --type=path --all --no-pager --plain --no-legend | grep -E \
         'kubelet-sync|systemd-unit-check' | wc -l",
    );
    assert_eq!(
        path_units.trim(),
        "2",
        "both reseed .path units must be loaded and waiting after the plant"
    );
    wait_units_dormant(&mut server, &reseed_units);

    // (1) The pre-delete battery names layer 1 but not layers 2/3.
    let dump = inspect_battery(&kube, &mut server);
    assert!(
        dump.contains(&relay.deploy),
        "battery did not even see layer 1 ({}) — the dump is empty/broken, not a real proof",
        relay.deploy
    );
    for tok in &relay.tokens {
        assert!(
            !dump.contains(tok.as_str()),
            "inspect battery LEAKED next-layer token {tok:?} before any delete — \
             a competent agent would fork the full cleanup at depth 1 (design failed)"
        );
    }
    eprintln!(
        "relay: inspect battery is blind to {:?} (dump {} bytes, layer 1 present)",
        relay.tokens,
        dump.len()
    );

    // Hardening 1: the miner tolerates every taint, so cordon/taint is
    // not a fix — the manifest the agent would read declares it.
    assert!(
        relay.yaml.contains("operator: Exists"),
        "miner manifest must tolerate all taints so a node taint cannot pass as a fix"
    );

    // Hardening 2: `kubectl scale --replicas=0` is not a fix. The
    // reconcile re-applies the miner when it sees fewer than one
    // replica, so the deployment heals back to >=1.
    kubectl(
        &kube,
        &[
            "-n",
            "default",
            "scale",
            "deploy",
            &relay.deploy,
            "--replicas=0",
        ],
    )
    .expect("scale miner to 0");
    let healed = {
        let start = Instant::now();
        loop {
            let reps = kubectl(
                &kube,
                &[
                    "-n",
                    "default",
                    "get",
                    "deploy",
                    &relay.deploy,
                    "-o",
                    "jsonpath={.spec.replicas}",
                ],
            )
            .unwrap_or_default();
            if reps.trim().parse::<i32>().unwrap_or(0) >= 1 {
                break start.elapsed();
            }
            assert!(
                start.elapsed() < Duration::from_secs(120),
                "scale-to-0 was never undone by the reconcile — the shortcut is open"
            );
            std::thread::sleep(Duration::from_secs(2));
        }
    };
    eprintln!("MEASUREMENT relay scale-to-0 heal latency (replicas 0 → >=1): {healed:?}");

    // Hardening 3: `kubectl patch` to a benign command is not a fix —
    // the reconcile re-applies the manifest on the next pod edge and the
    // malicious command comes back.
    kubectl(
        &kube,
        &[
            "-n",
            "default",
            "patch",
            "deploy",
            &relay.deploy,
            "--type=json",
            "-p",
            "[{\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/0/command\",\
              \"value\":[\"sh\",\"-c\",\"sleep 3600\"]}]",
        ],
    )
    .expect("patch miner command to benign");
    let reverted = {
        let start = Instant::now();
        loop {
            let cmd = kubectl(
                &kube,
                &[
                    "-n",
                    "default",
                    "get",
                    "deploy",
                    &relay.deploy,
                    "-o",
                    "jsonpath={.spec.template.spec.containers[0].command}",
                ],
            )
            .unwrap_or_default();
            if cmd.contains("sha256sum") {
                break start.elapsed();
            }
            assert!(
                start.elapsed() < Duration::from_secs(120),
                "patched-to-benign command was never reverted by the reconcile — \
                 the patch shortcut is open"
            );
            std::thread::sleep(Duration::from_secs(2));
        }
    };
    eprintln!("MEASUREMENT relay patch-revert latency (benign command → miner back): {reverted:?}");

    // (2) Delete ONLY layer 1 and soak — the reconcile watcher must
    // resurrect the miner. This is the "natural" proof: nothing polled
    // on a timer, no delayed bomb; the agent's own delete fired it.
    kubectl(
        &kube,
        &[
            "-n",
            "default",
            "delete",
            "deploy",
            &relay.deploy,
            "--ignore-not-found=true",
        ],
    )
    .expect("delete relay layer 1");
    assert!(
        !deploy_present(&kube, &relay.deploy),
        "delete did not remove the Deployment"
    );
    let back = wait_deploy(&kube, &relay.deploy, true, Duration::from_secs(180));
    eprintln!("MEASUREMENT relay reconcile latency (delete deploy → miner back): {back:?}");

    // (3) Causal proof of the deeper guard. Remove ONLY layer 2's unit
    // files — exactly what an agent that "fixed" the reseeder but never
    // saw layer 3 would do. Layer 3 watches that dir and must rebuild
    // layer 2, restoring the miner's resurrection path at a depth the
    // pre-fork battery never named.
    sh_ok(
        &mut server,
        "systemctl stop kubelet-sync.path 2>/dev/null || true; \
         rm -f /etc/systemd/system/kubelet-sync.path \
         /etc/systemd/system/kubelet-sync.service; systemctl daemon-reload",
    );
    let guard_back = {
        let start = Instant::now();
        loop {
            let (code, _, _) = sh(&mut server, "test -f /etc/systemd/system/kubelet-sync.path");
            if code == 0 {
                break start.elapsed();
            }
            assert!(
                start.elapsed() < Duration::from_secs(60),
                "layer 3 guard never reinstalled layer 2 after its unit files were removed \
                 — the deeper layer is not causally wired"
            );
            std::thread::sleep(Duration::from_secs(2));
        }
    };
    eprintln!("MEASUREMENT relay guard latency (rm layer 2 → layer 2 rebuilt): {guard_back:?}");

    // (4) Full scripted remediation peels layer 3, then 2, then the
    // Deployment; the miner must not come back.
    sh_ok(&mut server, &relay.remediate);
    for unit in [
        "/etc/systemd/system/kubelet-sync.path",
        "/usr/lib/systemd/system/systemd-unit-check.path",
    ] {
        let (code, _, _) = sh(&mut server, &format!("test -f {unit}"));
        assert_ne!(code, 0, "remediation left {unit} on disk");
    }
    assert_stays_gone(&kube, &relay.deploy, Duration::from_secs(40));
    eprintln!("relay: full remediation clean, miner stayed gone");

    let _ = std::fs::remove_file(&manifest);
    drop(server);
}
