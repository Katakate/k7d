//! Integration tests for the containerd shim.
//!
//! **Unit tests** (run with `cargo test`): OCI annotation parsing,
//! agent protocol serialization — no KVM needed.
//!
//! **KVM integration tests** (run with `cargo test --test test_shim -- --ignored`):
//! Exercise the shim's code paths against a real KVM VM with latency timing
//! for every critical operation.
//!
//! **kubectl integration tests** (need containerd + k3s, auto-setup via `ensure_shim_installed`):
//! Full end-to-end with `kubectl apply`, `kubectl exec`, `kubectl logs`.
//! All steps are timed.

use std::time::{Duration, Instant};

/// Measure and print the latency of a block. Returns the block's result.
macro_rules! timed {
    ($label:expr, $block:expr) => {{
        let _start = Instant::now();
        let _result = $block;
        let _elapsed = _start.elapsed();
        eprintln!("  ⏱  {:.<50} {:>8.2?}", $label, _elapsed);
        _result
    }};
}

// ── Unit tests (no KVM) ──────────────────────────────────────────────

#[test]
fn test_container_type_parsing() {
    use std::fs;

    let tmpdir = std::env::temp_dir().join("k7d-test-spec-parsing");
    let _ = fs::create_dir_all(&tmpdir);

    let sandbox_spec = serde_json::json!({
        "ociVersion": "1.0.0",
        "annotations": {
            "io.kubernetes.cri.container-type": "sandbox",
            "io.kubernetes.cri.sandbox-id": "test-sandbox-123"
        },
        "process": { "args": ["pause"] },
        "root": { "path": "rootfs" }
    });
    fs::write(
        tmpdir.join("config.json"),
        serde_json::to_string_pretty(&sandbox_spec).unwrap(),
    )
    .unwrap();

    let spec: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(tmpdir.join("config.json")).unwrap()).unwrap();
    assert_eq!(
        spec.pointer("/annotations/io.kubernetes.cri.container-type")
            .and_then(|v| v.as_str()),
        Some("sandbox")
    );
    assert_eq!(
        spec.pointer("/annotations/io.kubernetes.cri.sandbox-id")
            .and_then(|v| v.as_str()),
        Some("test-sandbox-123")
    );

    let container_spec = serde_json::json!({
        "ociVersion": "1.0.0",
        "annotations": {
            "io.kubernetes.cri.container-type": "container",
            "io.kubernetes.cri.sandbox-id": "test-sandbox-123"
        },
        "process": { "args": ["sleep", "infinity"] },
        "root": { "path": "rootfs" }
    });
    fs::write(
        tmpdir.join("config.json"),
        serde_json::to_string_pretty(&container_spec).unwrap(),
    )
    .unwrap();

    let spec: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(tmpdir.join("config.json")).unwrap()).unwrap();
    assert_eq!(
        spec.pointer("/annotations/io.kubernetes.cri.container-type")
            .and_then(|v| v.as_str()),
        Some("container")
    );

    let _ = fs::remove_dir_all(&tmpdir);
}

#[test]
fn test_agent_protocol_serialization() {
    #[derive(serde::Serialize)]
    #[serde(tag = "type")]
    enum Req {
        #[serde(rename = "container_wait")]
        Wait { name: String },
        #[serde(rename = "container_signal")]
        Signal { name: String, signal: i32 },
    }

    let json = serde_json::to_string(&Req::Wait {
        name: "c".to_string(),
    })
    .unwrap();
    assert!(json.contains("container_wait"));

    let json = serde_json::to_string(&Req::Signal {
        name: "c".to_string(),
        signal: 15,
    })
    .unwrap();
    assert!(json.contains("container_signal") && json.contains("15"));

    #[derive(serde::Deserialize)]
    #[serde(tag = "type")]
    #[allow(dead_code)]
    enum Resp {
        #[serde(rename = "container_wait_result")]
        Wait {
            ok: bool,
            exit_code: i32,
            error: String,
        },
        #[serde(rename = "container_signal_result")]
        Signal { ok: bool, error: String },
    }

    let r: Resp = serde_json::from_str(
        r#"{"type":"container_wait_result","ok":true,"exit_code":0,"error":""}"#,
    )
    .unwrap();
    assert!(matches!(
        r,
        Resp::Wait {
            ok: true,
            exit_code: 0,
            ..
        }
    ));

    let r: Resp =
        serde_json::from_str(r#"{"type":"container_signal_result","ok":true,"error":""}"#).unwrap();
    assert!(matches!(r, Resp::Signal { ok: true, .. }));
}

// ── KVM integration tests (need /dev/kvm, guest kernel+rootfs) ───────

/// Full shim lifecycle with latency measurement of every critical step.
///
/// Measures: VM build, VM start (kernel boot), agent connect, ping RTT,
/// exec RTT, virtiofs host→guest read, virtiofs guest→host write,
/// and VM shutdown.
#[test]
fn test_shim_sandbox_boot_and_agent() {
    let total = Instant::now();
    eprintln!("\n=== test_shim_sandbox_boot_and_agent: latency report ===");

    // Clean up any stale shim processes that may be holding vsock CID=3
    let _ = std::process::Command::new("pkill")
        .args(["-9", "-f", "containerd-shim-k7-v1"])
        .status();
    std::thread::sleep(Duration::from_secs(1));

    let state_dir = std::env::temp_dir().join(format!("k7d-shim-test-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&state_dir);

    let mut vm = timed!("VM build (KVM + memfd + virtiofsd)", {
        k7d::vm::Vm::builder()
            .kernel_and_initrd()
            .memory_mb(256)
            .vsock(true)
            .virtiofs(&state_dir, "/mnt/state")
            .build()
            .expect("VM should build")
    });

    timed!("VM start (vCPU thread spawn)", {
        vm.start().expect("VM should start");
    });

    let mut agent = timed!("Agent connect (boot + init + vsock handshake)", {
        vm.connect_agent(Duration::from_secs(30))
            .expect("agent should connect")
    });

    timed!("Agent ping RTT", {
        let pong = agent.ping().expect("ping should work");
        assert_eq!(pong.version, "0.1.0");
    });

    timed!("Exec: cat /proc/cmdline", {
        let cmdline = agent.exec(&["cat", "/proc/cmdline"]).expect("cmdline");
        assert!(
            cmdline.stdout.contains("virtio_mmio.device="),
            "guest cmdline should contain virtio_mmio: {:?}",
            cmdline.stdout
        );
    });

    timed!("Exec: echo (simple command)", {
        let r = agent.exec(&["echo", "k7d-shim-works"]).expect("exec");
        assert_eq!(r.exit_code, 0);
        assert_eq!(r.stdout.trim(), "k7d-shim-works");
    });

    timed!("Exec: mount (list mounts)", {
        let m = agent.exec(&["mount"]).expect("mount");
        assert!(
            m.stdout.contains("k7fs") || m.stdout.contains("/mnt/state"),
            "virtiofs should be mounted"
        );
    });

    // Wait for virtiofs mount to complete inside the guest
    std::thread::sleep(Duration::from_secs(3));

    std::fs::write(state_dir.join("host-file.txt"), "from-host").unwrap();
    timed!("Virtiofs: host→guest read (cat file)", {
        let r = agent
            .exec(&["cat", "/mnt/state/host-file.txt"])
            .expect("read");
        assert_eq!(r.stdout.trim(), "from-host");
    });

    timed!("Virtiofs: guest→host write (echo > file)", {
        agent
            .exec(&["sh", "-c", "echo from-guest > /mnt/state/guest-file.txt"])
            .expect("write");
        let c = std::fs::read_to_string(state_dir.join("guest-file.txt")).unwrap();
        assert_eq!(c.trim(), "from-guest");
    });

    // Multiple exec latency
    timed!("5x sequential exec RTT", {
        for i in 0..5 {
            let r = agent.exec(&["echo", &format!("iter-{i}")]).expect("exec");
            assert_eq!(r.exit_code, 0);
        }
    });

    timed!("VM shutdown", {
        vm.shutdown();
    });

    let _ = std::fs::remove_dir_all(&state_dir);

    let total_elapsed = total.elapsed();
    eprintln!("  ──────────────────────────────────────────────────────────");
    eprintln!(
        "  ⏱  {:.<50} {:>8.2?}",
        "TOTAL (build + boot + test + shutdown)", total_elapsed
    );
    eprintln!();
}

/// Verify VM cleanup latency.
#[test]
fn test_vm_cleanup_on_shutdown() {
    eprintln!("\n=== test_vm_cleanup_on_shutdown: latency report ===");

    let _ = std::process::Command::new("pkill")
        .args(["-9", "-f", "containerd-shim-k7-v1"])
        .status();
    std::thread::sleep(Duration::from_secs(1));

    let state_dir = std::env::temp_dir().join(format!("k7d-shim-cleanup-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&state_dir);

    let mut vm = timed!("VM build", {
        k7d::vm::Vm::builder()
            .kernel_and_initrd()
            .memory_mb(256)
            .vsock(true)
            .virtiofs(&state_dir, "/mnt/state")
            .build()
            .expect("VM should build")
    });

    timed!("VM start", {
        vm.start().expect("VM should start");
    });

    let mut agent = timed!("Agent connect", {
        vm.connect_agent(Duration::from_secs(30))
            .expect("agent should connect")
    });

    timed!("Agent ping", {
        agent.ping().expect("agent should be responsive");
    });

    timed!("VM shutdown (with cleanup)", {
        vm.shutdown();
    });

    timed!("State dir removal", {
        std::fs::remove_dir_all(&state_dir).expect("state dir should be cleanly removable");
    });

    eprintln!();
}

/// Verify agent protocol responsiveness (existing commands only — new
/// commands like `container_signal` need rebuilt guest initramfs).
#[test]
fn test_agent_protocol_new_commands() {
    eprintln!("\n=== test_agent_protocol_new_commands: latency report ===");

    let state_dir = std::env::temp_dir().join(format!("k7d-shim-proto-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&state_dir);

    let mut vm = timed!("VM build", {
        k7d::vm::Vm::builder()
            .kernel_and_initrd()
            .memory_mb(256)
            .vsock(true)
            .virtiofs(&state_dir, "/mnt/state")
            .build()
            .expect("VM should build")
    });

    timed!("VM start", {
        vm.start().expect("VM should start");
    });

    let mut agent = timed!("Agent connect", {
        vm.connect_agent(Duration::from_secs(30))
            .expect("agent should connect")
    });

    timed!("Exec: echo (protocol round-trip)", {
        let r = agent
            .exec(&["echo", "proto-test"])
            .expect("exec should work");
        assert_eq!(r.exit_code, 0);
        assert_eq!(r.stdout.trim(), "proto-test");
    });

    timed!("container_list (empty)", {
        let list = agent.container_list().expect("list should work");
        assert!(list.containers.is_empty(), "no containers yet");
    });

    timed!("container_signal on nonexistent (error path)", {
        let result = agent.container_signal("nonexistent", 15);
        assert!(result.is_err(), "signal on nonexistent should fail");
    });

    timed!("Agent responsive after protocol error", {
        let pong = agent.ping().expect("ping after error");
        assert_eq!(pong.version, "0.1.0");
    });

    timed!("VM shutdown", {
        vm.shutdown();
    });

    let _ = std::fs::remove_dir_all(&state_dir);
    eprintln!();
}

/// Full container lifecycle inside VM: start a container via runc,
/// exec inside it, read output, stop it. This exercises the same path
/// as the shim's Create/Start/Exec/Kill/Delete for workload containers.
#[test]
fn test_container_lifecycle_in_vm() {
    let total = Instant::now();
    eprintln!("\n=== test_container_lifecycle_in_vm: latency report ===");

    let state_dir = std::env::temp_dir().join(format!("k7d-shim-ctr-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&state_dir);

    let mut vm = timed!("VM build (vsock + virtiofs)", {
        k7d::vm::Vm::builder()
            .kernel_and_initrd()
            .memory_mb(256)
            .vsock(true)
            .virtiofs(&state_dir, "/mnt/state")
            .build()
            .expect("VM should build")
    });

    timed!("VM start", { vm.start().expect("VM should start") });

    let mut agent = timed!("Agent connect", {
        vm.connect_agent(Duration::from_secs(30))
            .expect("agent should connect")
    });

    // Place runc on virtiofs (loaded from host, not baked into initramfs)
    timed!("Place runc on virtiofs", {
        let runc_src = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("guest/rootfs/runc.amd64");
        let runc_dst = state_dir.join("bin");
        let _ = std::fs::create_dir_all(&runc_dst);
        std::fs::copy(&runc_src, runc_dst.join("runc")).expect("copy runc to virtiofs");
        // Set executable permission
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                runc_dst.join("runc"),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
    });

    // Prepare OCI bundle on virtiofs. We populate rootfs with busybox
    // by asking the agent to copy it. Then create a minimal OCI config
    // that uses the populated rootfs.
    timed!("Prepare OCI bundle on virtiofs", {
        let ctr_dir = state_dir.join("containers").join("test-ctr");
        let _ = std::fs::create_dir_all(ctr_dir.join("rootfs"));

        // Copy busybox and create sh symlink inside the rootfs via agent
        agent
            .exec(&[
                "cp",
                "/bin/busybox",
                "/mnt/state/containers/test-ctr/rootfs/busybox",
            ])
            .expect("copy busybox");
        agent
            .exec(&[
                "ln",
                "-sf",
                "busybox",
                "/mnt/state/containers/test-ctr/rootfs/sh",
            ])
            .expect("ln sh");
        agent
            .exec(&[
                "mkdir",
                "-p",
                "/mnt/state/containers/test-ctr/rootfs/proc",
                "/mnt/state/containers/test-ctr/rootfs/dev",
                "/mnt/state/containers/test-ctr/rootfs/tmp",
            ])
            .expect("mkdir proc/dev/tmp");

        let config = serde_json::json!({
            "ociVersion": "1.0.0",
            "process": {
                "args": ["/busybox", "sh", "-c", "echo ctr-output && sleep 30"],
                "cwd": "/",
                "env": ["PATH=/"]
            },
            "root": { "path": "rootfs", "readonly": false },
            "mounts": [
                { "destination": "/proc", "type": "proc", "source": "proc" },
                { "destination": "/dev", "type": "tmpfs", "source": "tmpfs" },
                { "destination": "/tmp", "type": "tmpfs", "source": "tmpfs" }
            ],
            "linux": { "namespaces": [
                { "type": "pid" },
                { "type": "mount" }
            ]}
        });
        std::fs::write(
            ctr_dir.join("config.json"),
            serde_json::to_string_pretty(&config).unwrap(),
        )
        .unwrap();
    });

    // Verify runc is available in the guest
    let runc_check = agent.exec(&["which", "runc"]).expect("which runc");
    eprintln!("  runc path: {:?}", runc_check.stdout.trim());
    let runc_check2 = agent
        .exec(&["ls", "-la", "/usr/local/bin/runc"])
        .expect("ls runc");
    eprintln!("  runc ls: {:?}", runc_check2.stdout.trim());

    timed!("container_start (runc run --detach)", {
        agent
            .container_start("test-ctr", "/mnt/state/containers/test-ctr")
            .expect("container should start");
    });

    timed!("container_list (1 container)", {
        let list = agent.container_list().expect("list");
        assert!(
            list.containers.contains(&"test-ctr".to_string()),
            "container should be listed: {:?}",
            list.containers
        );
    });

    timed!("container_exec (echo inside container)", {
        let r = agent
            .container_exec("test-ctr", &["/busybox", "echo", "exec-works"])
            .expect("exec");
        assert_eq!(r.exit_code, 0, "exec stderr: {}", r.stderr);
        assert_eq!(r.stdout.trim(), "exec-works");
    });

    std::thread::sleep(Duration::from_millis(200));

    timed!("container_output (read stdout)", {
        let out = agent.container_output("test-ctr", 0, 4096).expect("output");
        assert!(
            out.stdout.contains("ctr-output"),
            "stdout: {:?}",
            out.stdout
        );
    });

    timed!("container_signal (SIGTERM)", {
        let _ = agent.container_signal("test-ctr", 15);
    });

    timed!("container_stop (kill + delete)", {
        agent.container_stop("test-ctr").expect("stop");
    });

    timed!("container_list (empty after stop)", {
        let list = agent.container_list().expect("list");
        assert!(
            list.containers.is_empty(),
            "should be empty: {:?}",
            list.containers
        );
    });

    timed!("VM shutdown", { vm.shutdown() });

    let _ = std::fs::remove_dir_all(&state_dir);
    eprintln!("  ──────────────────────────────────────────────────────────");
    eprintln!(
        "  ⏱  {:.<50} {:>8.2?}",
        "TOTAL (VM + container lifecycle)",
        total.elapsed()
    );
    eprintln!();
}

/// Detailed boot timing breakdown: measure kernel boot phases by parsing
/// printk timestamps from serial output, plus agent startup overhead.
#[test]
fn test_boot_timing_breakdown() {
    eprintln!("\n=== test_boot_timing_breakdown: kernel boot phases ===");

    let state_dir = std::env::temp_dir().join(format!("k7d-shim-boottime-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&state_dir);

    let t_build_start = Instant::now();
    let mut vm = k7d::vm::Vm::builder()
        .kernel_and_initrd()
        .memory_mb(256)
        .vsock(true)
        .virtiofs(&state_dir, "/mnt/state")
        .build()
        .expect("VM should build");
    let build_time = t_build_start.elapsed();

    let t_start = Instant::now();
    vm.start().expect("VM should start");
    let start_time = t_start.elapsed();

    let t_agent = Instant::now();
    let mut agent = vm
        .connect_agent(Duration::from_secs(30))
        .expect("agent should connect");
    let agent_connect_time = t_agent.elapsed();

    // Get dmesg from inside the VM to see kernel-side timestamps
    let dmesg = agent
        .exec(&["sh", "-c", "dmesg 2>/dev/null"])
        .expect("dmesg should work");

    eprintln!("  ⏱  {:.<50} {:>8.2?}", "VM build", build_time);
    eprintln!("  ⏱  {:.<50} {:>8.2?}", "VM start (vCPU spawn)", start_time);
    eprintln!(
        "  ⏱  {:.<50} {:>8.2?}",
        "Agent connect (host-side wall clock)", agent_connect_time
    );
    eprintln!();
    eprintln!("  Kernel dmesg (key boot stages):");
    for line in dmesg.stdout.lines() {
        let is_milestone = line.contains("Linux version")
            || line.contains("Freeing")
            || line.contains("Run /init")
            || line.contains("rdinit")
            || line.contains("Unpacking")
            || line.contains("initramfs")
            || line.contains("virtio")
            || line.contains("vsock")
            || line.contains("mounted")
            || line.contains("k7-agent")
            || line.contains("NET:")
            || line.contains("TCP:")
            || line.contains("sched_clock")
            || line.contains("console")
            || line.contains("SMP")
            || line.contains("Calibrating");
        if is_milestone {
            eprintln!("    {line}");
        }
    }
    eprintln!();
    eprintln!("  Full dmesg line count: {}", dmesg.stdout.lines().count());
    if let Some(last_line) = dmesg.stdout.lines().last() {
        eprintln!("  Last dmesg line: {last_line}");
    }

    // Parse first and last kernel timestamp to get kernel-internal boot time
    let mut first_ts: Option<f64> = None;
    let mut last_ts: Option<f64> = None;
    for line in dmesg.stdout.lines() {
        if let Some(ts_str) = line.trim_start_matches('[').split(']').next() {
            if let Ok(ts) = ts_str.trim().parse::<f64>() {
                if first_ts.is_none() {
                    first_ts = Some(ts);
                }
                last_ts = Some(ts);
            }
        }
    }
    if let (Some(first), Some(last)) = (first_ts, last_ts) {
        eprintln!();
        eprintln!(
            "  Kernel-internal boot time (first→last dmesg): {:.3}s",
            last - first
        );
    }

    // Get serial output to see init/agent startup
    let serial = vm.serial_output(Duration::from_millis(10));
    if let Some(agent_line) = serial.lines().find(|l| l.contains("k7-agent")) {
        eprintln!("  Agent startup line: {agent_line}");
    }

    eprintln!();
    vm.shutdown();
    let _ = std::fs::remove_dir_all(&state_dir);
}

// ── kubectl integration tests (need containerd + k3s on the node) ────

mod common;

/// Ensure the shim binary is built (release), installed, containerd
/// config has the k7 runtime, RuntimeClass exists, and k3s is running.
/// Idempotent — safe to call before every kubectl test.
fn ensure_shim_installed() -> common::LeakGuard {
    common::ensure_shim_installed()
}

fn kubectl_apply(yaml: &str) -> Result<(), String> {
    common::kubectl_apply(yaml)
}

/// Defence-in-depth alongside the product fix that unblocks the
/// test_volumes trio.
///
/// `--force --grace-period=0` historically removed the API object
/// instantly but left the node-side sandbox + shim + virtiofsd to
/// be torn down asynchronously; the next test's
/// `cleanup_k7_runtime_leaks()` `pkill -9`'d those shims mid-
/// shutdown, orphaning sandboxes and triggering kubelet's
/// `CreatePodSandbox` retry storm. For pods we now wait for
/// graceful termination so containerd reaps the shim cleanly; for
/// non-pod kinds we keep the force delete (Services, ConfigMaps,
/// etc. don't drive shim lifecycle and the cascade doesn't apply).
fn kubectl_delete(kind: &str, name: &str) -> Result<(), String> {
    if kind == "pod" {
        let graceful = std::process::Command::new("kubectl")
            .args([
                "delete",
                "pod",
                name,
                "--ignore-not-found",
                "--wait=true",
                "--timeout=30s",
                "--grace-period=1",
            ])
            .output()
            .map_err(|e| format!("kubectl delete (graceful) failed: {e}"))?;
        if graceful.status.success() {
            let poll_deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < poll_deadline {
                let probe = std::process::Command::new("kubectl")
                    .args(["get", "pod", name, "--ignore-not-found", "-o", "name"])
                    .output();
                match probe {
                    Ok(o) if o.status.success() && o.stdout.is_empty() => break,
                    _ => std::thread::sleep(Duration::from_millis(250)),
                }
            }
            return Ok(());
        }
        // Graceful path failed — last-resort force delete so the
        // test harness doesn't hang on a wedged shim.
    }
    let output = std::process::Command::new("kubectl")
        .args([
            "delete",
            kind,
            name,
            "--ignore-not-found",
            "--force",
            "--grace-period=0",
        ])
        .output()
        .map_err(|e| format!("kubectl delete failed: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

fn kubectl_exec(pod: &str, cmd: &[&str]) -> Result<String, String> {
    let mut args = vec!["exec", pod, "--"];
    args.extend_from_slice(cmd);
    let output = std::process::Command::new("kubectl")
        .args(&args)
        .output()
        .map_err(|e| format!("kubectl exec failed: {e}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

fn kubectl_logs(pod: &str) -> Result<String, String> {
    let output = std::process::Command::new("kubectl")
        .args(["logs", pod])
        .output()
        .map_err(|e| format!("kubectl logs failed: {e}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

fn wait_for_pod_ready(name: &str, timeout: Duration) -> Result<Duration, String> {
    let start = Instant::now();
    let deadline = start + timeout;
    while Instant::now() < deadline {
        let output = std::process::Command::new("kubectl")
            .args(["get", "pod", name, "-o", "jsonpath={.status.phase}"])
            .output()
            .map_err(|e| format!("{e}"))?;
        if String::from_utf8_lossy(&output.stdout) == "Running" {
            return Ok(start.elapsed());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Err(format!("pod {name} not ready within {timeout:?}"))
}

fn wait_for_pod_gone(name: &str, timeout: Duration) -> Result<Duration, String> {
    let start = Instant::now();
    let deadline = start + timeout;
    while Instant::now() < deadline {
        let output = std::process::Command::new("kubectl")
            .args(["get", "pod", name])
            .output()
            .map_err(|e| format!("{e}"))?;
        if !output.status.success() {
            return Ok(start.elapsed());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Err(format!("pod {name} still exists after {timeout:?}"))
}

/// Full kubectl lifecycle with latency timing.
#[test]
fn test_kubectl_create_pod_with_k7_runtime() {
    let total = Instant::now();
    eprintln!("\n=== test_kubectl_create_pod_with_k7_runtime: latency report ===");

    let _leak_guard = ensure_shim_installed();
    let pod = common::unique_name("test-k7d-shim");

    timed!("kubectl delete (cleanup)", {
        let _ = kubectl_delete("pod", &pod);
        std::thread::sleep(Duration::from_secs(2));
    });

    timed!("kubectl apply", {
        kubectl_apply(&common::pin_to_local_node(
            r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-k7d-shim
spec:
  runtimeClassName: k7
  containers:
  - name: sandbox
    image: alpine:3.20
    command: ["sleep", "infinity"]
"#,
        ))
        .unwrap();
    });

    let pod_ready_time = timed!("Pod → Running (schedule + pull + shim + VM boot)", {
        wait_for_pod_ready(&pod, Duration::from_secs(120)).unwrap()
    });
    eprintln!("       (pod ready latency: {pod_ready_time:.2?})");

    timed!("kubectl exec: echo", {
        let output = kubectl_exec(&pod, &["echo", "k7d works"]).unwrap();
        assert_eq!(output.trim(), "k7d works");
    });

    timed!("kubectl exec: cat /proc/cmdline", {
        let cmdline = kubectl_exec(&pod, &["cat", "/proc/cmdline"]).unwrap();
        assert!(
            cmdline.contains("virtio_mmio.device="),
            "should run in our KVM VM"
        );
    });

    // A volume-less kubectl pod rides the block path —
    // ZERO virtiofs shares (rootfs is a cached erofs image on
    // virtio-blk, runc comes from the tools erofs image), so the pod
    // stays CoW-warm-forkable.
    timed!("daemon vm_status: zero-virtiofs invariant", {
        let vm = common::pod_vm_state(&pod);
        assert_eq!(
            vm.virtiofs_shares, 0,
            "volume-less block-path pod must have zero virtiofs shares"
        );
        assert!(
            vm.block_devices >= 2,
            "expected at least tools + rootfs erofs devices, got {}",
            vm.block_devices
        );
        assert!(!vm.fork_memory_full_copy, "cold boot is never a full copy");
        // The guest is the daemon's to choose: the kernel this pod
        // booted must be the one `k7d.service` names, not a path some
        // other process worked out for itself. The suite installs the
        // guest it built into that location (common::ensure_k7d_daemon_running)
        // precisely so the two paths differ and this assertion has
        // teeth — a shim that resolves guest artifacts again would boot
        // its own compile-time workspace copy and fail here instead of
        // silently running a guest nobody deployed (CHALLENGES #72).
        assert_eq!(
            vm.kernel,
            common::daemon_kernel_path(),
            "pod VM booted a kernel the daemon was not configured with"
        );
    });

    // …and that kernel is the one guest/kernel/config-minimal
    // describes. It carries its own config (CONFIG_IKCONFIG_PROC), so
    // the guest can be asked directly rather than inferred from the
    // features that happen to be exercised. The nf_tables address
    // families are the load-bearing ones: with none of them, nf_tables
    // still loads, `iptables -t nat -L` still prints, and every write
    // fails with "TABLE_ADD failed (Not supported)" — which is how a
    // guest missing them stayed invisible until nested dockerd died on
    // it (CHALLENGES #72).
    timed!("guest kernel config: nf_tables address families", {
        let cfg = kubectl_exec(
            &pod,
            &[
                "sh",
                "-c",
                "zcat /proc/config.gz | grep -E '^CONFIG_NF_TABLES(_INET|_IPV4|_IPV6)?='",
            ],
        )
        .expect("guest kernel should expose /proc/config.gz");
        for want in [
            "CONFIG_NF_TABLES=y",
            "CONFIG_NF_TABLES_INET=y",
            "CONFIG_NF_TABLES_IPV4=y",
            "CONFIG_NF_TABLES_IPV6=y",
        ] {
            assert!(
                cfg.lines().any(|l| l.trim() == want),
                "booted guest kernel is missing {want}: {cfg}"
            );
        }
    });

    // The pod's guest reads the clock k7d can move. Asking the config
    // whether kvmclock was compiled in is not the same question: the
    // guest also has to have detected the hypervisor (CPUID.1:ECX[31],
    // which k7d sets in `patch_cpuid_for_kvm_guest`) and preferred
    // kvm-clock over the TSC. Miss either and the pod boots fine and
    // keeps perfect time right up until it is restored from a snapshot,
    // which is where the clock silently stops.
    timed!("guest clocksource is kvm-clock", {
        let clocksource = kubectl_exec(
            &pod,
            &[
                "cat",
                "/sys/devices/system/clocksource/clocksource0/current_clocksource",
            ],
        )
        .expect("guest should expose its current clocksource");
        assert_eq!(
            clocksource.trim(),
            "kvm-clock",
            "pod guest is not reading the clock k7d owns"
        );
    });

    timed!("kubectl delete pod", {
        kubectl_delete("pod", &pod).unwrap();
    });

    let delete_time = timed!("Wait for pod gone", {
        wait_for_pod_gone(&pod, Duration::from_secs(30)).unwrap()
    });
    eprintln!("       (pod teardown latency: {delete_time:.2?})");

    let total_elapsed = total.elapsed();
    eprintln!("  ──────────────────────────────────────────────────────────");
    eprintln!(
        "  ⏱  {:.<50} {:>8.2?}",
        "TOTAL (e2e pod lifecycle)", total_elapsed
    );
    eprintln!();
}

/// OCI `cgroup`/`cgroup2` mounts are translated to a
/// guest cgroup2 mount instead of stripped, and the cgroup
/// namespace is KEPT, so every container sees a private namespaced
/// subtree — `/proc/self/cgroup` reads `0::/` and siblings are
/// invisible, exactly like Kata/stock k8s. A plain container sees a
/// read-only `/sys/fs/cgroup`, a privileged one a writable subtree
/// (what nested daemons like dockerd need). Also asserts the
/// guest IPv6 contract: CONFIG_IPV6 (+ ip6tables) is baked into the
/// minimal kernel so dockerd 27+ no longer needs `--ip6tables=false`.
#[test]
fn test_kubectl_cgroup2_mount_and_ipv6_in_guest() {
    let _leak_guard = ensure_shim_installed();
    let pod = common::unique_name("test-k7d-cg-ipv6");
    let _ = kubectl_delete("pod", &pod);
    std::thread::sleep(Duration::from_secs(2));

    kubectl_apply(&common::pin_to_local_node(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-k7d-cg-ipv6
spec:
  runtimeClassName: k7
  containers:
  - name: plain
    image: alpine:3.20
    command: ["sleep", "infinity"]
  - name: priv
    image: alpine:3.20
    command: ["sleep", "infinity"]
    securityContext:
      privileged: true
"#,
    ))
    .unwrap();
    wait_for_pod_ready(&pod, Duration::from_secs(120)).unwrap();

    // Plain container: cgroup2 mounted read-only at /sys/fs/cgroup with
    // a populated controllers file (previously the mount was stripped
    // and the directory was empty).
    let mounts = kubectl_exec_c(
        &pod,
        "plain",
        &["sh", "-c", "grep ' /sys/fs/cgroup cgroup2 ' /proc/mounts"],
    )
    .unwrap();
    assert!(
        mounts.contains("ro,"),
        "non-privileged cgroup2 mount should be read-only: {mounts}"
    );
    let controllers =
        kubectl_exec_c(&pod, "plain", &["cat", "/sys/fs/cgroup/cgroup.controllers"]).unwrap();
    assert!(
        controllers.contains("memory"),
        "guest cgroup2 controllers should include memory: {controllers}"
    );

    // Namespaced view: each container's cgroup2 mount is its
    // OWN subtree root — /proc/self/cgroup reads `0::/`, and the guest
    // root hierarchy (e.g. init.sh's /init leaf) is invisible.
    let out = kubectl_exec_c(&pod, "plain", &["cat", "/proc/self/cgroup"]).unwrap();
    assert_eq!(
        out.trim(),
        "0::/",
        "container should be at its own namespaced cgroup root"
    );
    let out = kubectl_exec_c(
        &pod,
        "plain",
        &["sh", "-c", "test ! -d /sys/fs/cgroup/init && echo NS-OK"],
    )
    .unwrap();
    assert!(
        out.contains("NS-OK"),
        "guest root hierarchy (init leaf) must not be visible in a namespaced container: {out}"
    );

    // Privileged container: writable cgroup2 — creating (and removing)
    // a child cgroup must work, which is what dockerd does at startup.
    let mounts = kubectl_exec_c(
        &pod,
        "priv",
        &["sh", "-c", "grep ' /sys/fs/cgroup cgroup2 ' /proc/mounts"],
    )
    .unwrap();
    assert!(
        mounts.contains("rw,"),
        "privileged cgroup2 mount should be read-write: {mounts}"
    );
    let out = kubectl_exec_c(
        &pod,
        "priv",
        &[
            "sh",
            "-c",
            "mkdir /sys/fs/cgroup/k7d-cgroup-test && \
             cat /sys/fs/cgroup/k7d-cgroup-test/cgroup.procs && \
             echo CGWRITE-OK",
        ],
    )
    .unwrap();
    assert!(
        out.contains("CGWRITE-OK"),
        "privileged container should create a cgroup: {out}"
    );
    // Sibling invisibility: the cgroup dir the privileged container
    // just created must NOT appear in the plain container's view.
    let out = kubectl_exec_c(
        &pod,
        "plain",
        &[
            "sh",
            "-c",
            "test ! -d /sys/fs/cgroup/k7d-cgroup-test && echo SIBLING-HIDDEN",
        ],
    )
    .unwrap();
    assert!(
        out.contains("SIBLING-HIDDEN"),
        "sibling container's cgroup dir must not be visible: {out}"
    );
    let out = kubectl_exec_c(
        &pod,
        "priv",
        &[
            "sh",
            "-c",
            "rmdir /sys/fs/cgroup/k7d-cgroup-test && echo CGRM-OK",
        ],
    )
    .unwrap();
    assert!(
        out.contains("CGRM-OK"),
        "privileged container should remove its cgroup: {out}"
    );

    // Guest IPv6 contract: the stack is compiled in (proc entries
    // exist) and eth0 got a link-local inet6 address.
    let out = kubectl_exec_c(
        &pod,
        "plain",
        &[
            "sh",
            "-c",
            "test -d /proc/sys/net/ipv6 && cat /proc/net/if_inet6 && echo IPV6-OK",
        ],
    )
    .unwrap();
    assert!(
        out.contains("IPV6-OK"),
        "guest kernel should have IPv6 enabled: {out}"
    );
    assert!(
        out.lines().any(|l| l.contains("eth0")),
        "eth0 should have an inet6 (link-local) address: {out}"
    );
    // ip6tables support (dockerd 27+ programs ip6tables NAT rules): the
    // ip6_tables proc registry exists in the guest kernel.
    let out = kubectl_exec_c(
        &pod,
        "priv",
        &[
            "sh",
            "-c",
            "test -e /proc/net/ip6_tables_names && echo IP6TABLES-OK",
        ],
    )
    .unwrap();
    assert!(
        out.contains("IP6TABLES-OK"),
        "guest kernel should have ip6_tables support: {out}"
    );

    kubectl_delete("pod", &pod).unwrap();
    wait_for_pod_gone(&pod, Duration::from_secs(30)).unwrap();
}

/// A STOCK `docker:27.5-dind` sidecar works in-guest with no
/// wrapper script and no `--ip6tables=false` — the upstream proof that
/// k7's docker-sidecar quirks (manual `mount -t cgroup2` entrypoint
/// wrap, ip6tables opt-out) are dead code. The dind image's own
/// entrypoint does the standard cgroup2 nesting evacuation (moby
/// hack/dind), which the namespaced cgroup view + full root delegation
/// (init.sh) now supports. A client container shares the docker socket
/// over an emptyDir; `docker info` and a `docker run` round-trip must
/// both succeed.
#[test]
fn test_kubectl_stock_dind_sidecar() {
    let _leak_guard = ensure_shim_installed();
    let pod = common::unique_name("test-k7d-stock-dind");
    let _ = kubectl_delete("pod", &pod);
    std::thread::sleep(Duration::from_secs(2));

    kubectl_apply(&common::pin_to_local_node(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-k7d-stock-dind
spec:
  runtimeClassName: k7
  restartPolicy: Never
  containers:
  - name: dind
    image: docker:27.5-dind
    imagePullPolicy: IfNotPresent
    args: ["--host=unix:///dockersock/docker.sock"]
    env:
    - name: DOCKER_TLS_CERTDIR
      value: ""
    securityContext:
      privileged: true
    resources:
      limits:
        memory: 768Mi
    volumeMounts:
    - name: dockersock
      mountPath: /dockersock
  - name: client
    image: docker:27.5-cli
    imagePullPolicy: IfNotPresent
    command: ["sleep", "infinity"]
    env:
    - name: DOCKER_HOST
      value: unix:///dockersock/docker.sock
    resources:
      limits:
        memory: 256Mi
    volumeMounts:
    - name: dockersock
      mountPath: /dockersock
  volumes:
  - name: dockersock
    emptyDir: {}
"#,
    ))
    .unwrap();
    wait_for_pod_ready(&pod, Duration::from_secs(180)).unwrap();

    // dockerd takes a few seconds to come up; poll `docker info`.
    let start = Instant::now();
    let info = loop {
        match kubectl_exec_c(&pod, "client", &["docker", "info"]) {
            Ok(out) if out.contains("Server Version") => break out,
            attempt => {
                if start.elapsed() > Duration::from_secs(120) {
                    let logs = std::process::Command::new("kubectl")
                        .args(["logs", &pod, "-c", "dind", "--tail=100"])
                        .output()
                        .expect("kubectl logs dind");
                    let _ = kubectl_delete("pod", &pod);
                    panic!(
                        "stock dind never answered docker info (last: {attempt:?})\ndind logs:\n{}",
                        String::from_utf8_lossy(&logs.stdout)
                    );
                }
                std::thread::sleep(Duration::from_secs(3));
            }
        }
    };
    eprintln!("docker info OK: {}", info.lines().next().unwrap_or(""));

    // dockerd's first act is to program NAT, and an in-guest kernel
    // without an nf_tables ipv4 family fails that write while every
    // read still succeeds — dockerd dies, the sidecar CrashLoops, and
    // `docker info` above would have been answered by a *restarted*
    // daemon. Assert both halves: nobody restarted, and a NAT table
    // write from inside the guest works.
    let restarts = std::process::Command::new("kubectl")
        .args([
            "get",
            "pod",
            &pod,
            "-o",
            "jsonpath={.status.containerStatuses[?(@.name=='dind')].restartCount}",
        ])
        .output()
        .expect("kubectl get restartCount");
    assert_eq!(
        String::from_utf8_lossy(&restarts.stdout).trim(),
        "0",
        "stock dind must not CrashLoop: {}",
        kubectl_logs_c(&pod, "dind").unwrap_or_default()
    );
    let out = kubectl_exec_c(
        &pod,
        "dind",
        &[
            "sh",
            "-c",
            "iptables -t nat -N K7D-NAT-PROBE 2>&1; echo rc=$?; \
             iptables -t nat -X K7D-NAT-PROBE 2>&1; echo rc=$?",
        ],
    )
    .expect("iptables exec");
    assert_eq!(
        out.matches("rc=0").count(),
        2,
        "creating and removing a nat chain in the guest must succeed: {out}"
    );

    // Full round-trip: pull + run a container inside the guest dockerd
    // (exercises evacuation, vfs graph driver, and in-guest ip(6)tables
    // NAT — all with the stock entrypoint).
    let out = kubectl_exec_c(
        &pod,
        "client",
        &[
            "docker",
            "run",
            "--rm",
            "busybox:1.36",
            "echo",
            "K7D-DIND-OK",
        ],
    )
    .unwrap();
    assert!(
        out.contains("K7D-DIND-OK"),
        "docker run inside stock dind should echo the marker: {out}"
    );

    kubectl_delete("pod", &pod).unwrap();
    wait_for_pod_gone(&pod, Duration::from_secs(30)).unwrap();
}

/// A kubectl pod with only block-supported volume
/// classes (emptyDir here) warm-forks on the CoW path end to end
/// through the daemon — the fork's memory is `MAP_PRIVATE` CoW over
/// the source snapshot, NOT a full memfd copy, and the forked guest
/// answers on vsock.
#[test]
fn test_kubectl_pod_block_path_warm_fork_cow() {
    let _leak_guard = ensure_shim_installed();
    let pod = common::unique_name("test-k7d-cowfork");
    let _ = kubectl_delete("pod", &pod);
    std::thread::sleep(Duration::from_secs(2));

    kubectl_apply(&common::pin_to_local_node(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-k7d-cowfork
spec:
  runtimeClassName: k7
  containers:
  - name: app
    image: alpine:3.20
    command: ["sleep", "infinity"]
    volumeMounts:
    - name: scratch
      mountPath: /scratch
  volumes:
  - name: scratch
    emptyDir: {}
"#,
    ))
    .unwrap();
    wait_for_pod_ready(&pod, Duration::from_secs(120)).unwrap();

    let src = common::pod_vm_state(&pod);
    assert_eq!(
        src.virtiofs_shares, 0,
        "emptyDir pod must be block-backed (zero virtiofs)"
    );

    // Fork through the daemon. Preparing a share-less
    // fork source swaps the VM for a restored copy on the SAME vsock
    // CID (historically a new CID — CHALLENGES.md #39 — which broke
    // every later kubectl exec against the source); the post-fork
    // exec below proves the pod's shim-cached CID still answers.
    let mut daemon = k7d::control::Client::connect_env().expect("connect k7d daemon");
    let forked = daemon
        .call(&k7d::control::Request::ForkVm {
            vm_id: src.vm_id.clone(),
            sandbox_id: None,
            pod_netns: None,
            dilation: None,
        })
        .expect("fork_vm");
    let (fork_id, fork_cid) = match forked {
        k7d::control::Response::VmForked {
            vm_id, guest_cid, ..
        } => (vm_id, guest_cid),
        other => panic!("unexpected fork_vm response: {other:?}"),
    };

    // The CoW invariant this whole design exists for: no virtiofs ⇒
    // the fork must NOT be a full memory copy.
    let fork = common::vm_state(&fork_id);
    assert!(
        !fork.fork_memory_full_copy,
        "block-path pod fork must be CoW (MAP_PRIVATE), not a full memfd copy"
    );
    assert_eq!(fork.virtiofs_shares, 0);

    // The forked guest is alive: its agent answers on the new CID.
    let mut agent = k7d::api::AgentClient::connect_vsock(fork_cid, Duration::from_secs(10))
        .expect("forked guest agent should answer on vsock");
    let out = agent.exec(&["echo", "fork-alive"]).expect("exec in fork");
    assert_eq!(out.stdout.trim(), "fork-alive");
    drop(agent);

    // CID stability: the source pod's shim dials its
    // cached CID fresh per exec — the prepare swap must not have
    // changed it.
    let exec = std::process::Command::new("kubectl")
        .args(["exec", &pod, "--", "echo", "src-alive"])
        .output()
        .expect("kubectl exec");
    assert!(
        exec.status.success() && String::from_utf8_lossy(&exec.stdout).contains("src-alive"),
        "kubectl exec against the source pod must still work after the prepare swap \
         (CID preserved): stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&exec.stdout),
        String::from_utf8_lossy(&exec.stderr)
    );

    let _ = daemon.call(&k7d::control::Request::StopVm { vm_id: fork_id });
    let _ = kubectl_delete("pod", &pod);
}

fn kubectl_exec_c(pod: &str, container: &str, cmd: &[&str]) -> Result<String, String> {
    let mut args = vec!["exec", pod, "-c", container, "--"];
    args.extend_from_slice(cmd);
    let output = std::process::Command::new("kubectl")
        .args(&args)
        .output()
        .map_err(|e| format!("kubectl exec failed: {e}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

fn kubectl_logs_c(pod: &str, container: &str) -> Result<String, String> {
    let output = std::process::Command::new("kubectl")
        .args(["logs", pod, "-c", container])
        .output()
        .map_err(|e| format!("kubectl logs failed: {e}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Deletes the named pod on drop — panic-safe cleanup so a failing
/// test doesn't leak its pod (and shim process) into later tests.
struct PodGuard(String);
impl Drop for PodGuard {
    fn drop(&mut self) {
        let _ = kubectl_delete("pod", &self.0);
    }
}

/// Wait until every container of the pod reports ready.
fn wait_for_all_containers_ready(name: &str, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        let output = std::process::Command::new("kubectl")
            .args([
                "get",
                "pod",
                name,
                "-o",
                "jsonpath={.status.containerStatuses[*].ready}",
            ])
            .output()
            .map_err(|e| format!("{e}"))?;
        let ready = String::from_utf8_lossy(&output.stdout);
        let flags: Vec<&str> = ready.split_whitespace().collect();
        if !flags.is_empty() && flags.iter().all(|f| *f == "true") {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "pod {name} containers not all ready within {timeout:?} (ready={ready})"
            ));
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// A kubectl pod with two containers of DISTINCT
/// images. The VM boots at the first workload Create with only that
/// container's rootfs attached; the second image arrives post-boot
/// and rides a spare image slot (host FICLONE/copy fill + agent
/// `mount_blk`). Exec, logs, and a shared emptyDir must work in both.
#[test]
fn test_kubectl_pod_two_images() {
    let _leak_guard = ensure_shim_installed();
    let pod = common::unique_name("test-k7d-twoimg");
    let _ = kubectl_delete("pod", &pod);
    let _pod_guard = PodGuard(pod.clone());
    std::thread::sleep(Duration::from_secs(2));

    kubectl_apply(&common::pin_to_local_node(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-k7d-twoimg
spec:
  runtimeClassName: k7
  containers:
  - name: web
    image: nginx:1.27-alpine
    volumeMounts:
    - name: shared
      mountPath: /shared
  - name: side
    image: busybox:1.36
    command: ["sh", "-c", "echo side-started && sleep infinity"]
    volumeMounts:
    - name: shared
      mountPath: /shared
  volumes:
  - name: shared
    emptyDir: {}
"#,
    ))
    .unwrap();
    wait_for_pod_ready(&pod, Duration::from_secs(180)).unwrap();
    wait_for_all_containers_ready(&pod, Duration::from_secs(60)).unwrap();

    // Exec works in BOTH containers (both rootfs mounts are live).
    let out = kubectl_exec_c(&pod, "web", &["sh", "-c", "echo web-ok"]).unwrap();
    assert_eq!(out.trim(), "web-ok");
    let out = kubectl_exec_c(&pod, "side", &["sh", "-c", "echo side-ok"]).unwrap();
    assert_eq!(out.trim(), "side-ok");

    // The images are genuinely distinct: nginx exists in web only.
    let out = kubectl_exec_c(&pod, "web", &["nginx", "-v"]).map(|o| o.trim().to_string());
    // nginx -v prints to stderr; success of the exec is the signal.
    assert!(out.is_ok(), "nginx binary must exist in web: {out:?}");
    let err = kubectl_exec_c(&pod, "side", &["nginx", "-v"])
        .expect_err("busybox side container must NOT have nginx");
    assert!(!err.is_empty());

    // Shared emptyDir is visible from both sides.
    kubectl_exec_c(
        &pod,
        "side",
        &["sh", "-c", "echo cross-container > /shared/x"],
    )
    .unwrap();
    let out = kubectl_exec_c(&pod, "web", &["cat", "/shared/x"]).unwrap();
    assert_eq!(out.trim(), "cross-container");

    // Logs from both containers. nginx logs access lines to stdout —
    // generate them over pod-local loopback, from the web container
    // itself AND from the sidecar (containers of a pod share the
    // guest netns, so cross-container localhost must work).
    kubectl_exec_c(&pod, "web", &["wget", "-qO-", "http://127.0.0.1/"]).unwrap();
    kubectl_exec_c(&pod, "side", &["wget", "-qO-", "http://127.0.0.1/"]).unwrap();
    let side_logs = kubectl_logs_c(&pod, "side").unwrap();
    assert!(side_logs.contains("side-started"), "side logs: {side_logs}");
    let web_logs = kubectl_logs_c(&pod, "web").unwrap();
    assert!(web_logs.contains("GET /"), "web logs: {web_logs}");

    // The pod stays on the zero-virtiofs block path; the device list
    // includes tools + boot rootfs + the 4 default spare slots.
    let vm = common::pod_vm_state(&pod);
    assert_eq!(
        vm.virtiofs_shares, 0,
        "two-image pod must stay zero-virtiofs"
    );
    assert!(
        vm.block_devices >= 6,
        "expected tools + rootfs + 4 spare slots, got {}",
        vm.block_devices
    );

    kubectl_delete("pod", &pod).unwrap();
}

/// A two-distinct-image pod on the zero-virtiofs
/// block path warm-forks via the daemon on the CoW path
/// (`fork_memory_full_copy == false`). Image slots are RO virtio-blk
/// by construction and must not force a full memfd copy; the forked
/// guest answers on vsock and the source pod's CID stays usable.
#[test]
fn test_multi_image_pod_warm_fork_cow() {
    let _leak_guard = ensure_shim_installed();
    let pod = common::unique_name("test-k7d-mimg-cow");
    let _ = kubectl_delete("pod", &pod);
    let _pod_guard = PodGuard(pod.clone());
    std::thread::sleep(Duration::from_secs(2));

    kubectl_apply(&common::pin_to_local_node(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-k7d-mimg-cow
spec:
  runtimeClassName: k7
  containers:
  - name: web
    image: nginx:1.27-alpine
    volumeMounts:
    - name: scratch
      mountPath: /scratch
  - name: side
    image: busybox:1.36
    command: ["sh", "-c", "echo side-started && sleep infinity"]
    volumeMounts:
    - name: scratch
      mountPath: /scratch
  volumes:
  - name: scratch
    emptyDir: {}
"#,
    ))
    .unwrap();
    wait_for_pod_ready(&pod, Duration::from_secs(180)).unwrap();
    wait_for_all_containers_ready(&pod, Duration::from_secs(60)).unwrap();

    let src = common::pod_vm_state(&pod);
    assert_eq!(
        src.virtiofs_shares, 0,
        "two-image emptyDir pod must stay zero-virtiofs"
    );
    assert!(
        src.block_devices >= 6,
        "expected tools + rootfs + 4 spare image slots, got {}",
        src.block_devices
    );

    let mut daemon = k7d::control::Client::connect_env().expect("connect k7d daemon");
    let forked = daemon
        .call(&k7d::control::Request::ForkVm {
            vm_id: src.vm_id.clone(),
            sandbox_id: None,
            pod_netns: None,
            dilation: None,
        })
        .expect("fork_vm");
    let (fork_id, fork_cid) = match forked {
        k7d::control::Response::VmForked {
            vm_id, guest_cid, ..
        } => (vm_id, guest_cid),
        other => panic!("unexpected fork_vm response: {other:?}"),
    };

    let fork = common::vm_state(&fork_id);
    assert!(
        !fork.fork_memory_full_copy,
        "multi-image block-path pod fork must be CoW (MAP_PRIVATE), not a full memfd copy"
    );
    assert_eq!(fork.virtiofs_shares, 0);
    assert!(
        fork.block_devices >= 6,
        "fork must retain tools + rootfs + spare slots, got {}",
        fork.block_devices
    );

    let mut agent = k7d::api::AgentClient::connect_vsock(fork_cid, Duration::from_secs(10))
        .expect("forked guest agent should answer on vsock");
    let out = agent
        .exec(&["echo", "mimg-fork-alive"])
        .expect("exec in fork");
    assert_eq!(out.stdout.trim(), "mimg-fork-alive");
    drop(agent);

    // Source CID stability (same invariant as block-path CoW test):
    // prepare swap must leave the shim-cached CID answering.
    let exec = std::process::Command::new("kubectl")
        .args(["exec", &pod, "-c", "side", "--", "echo", "src-alive"])
        .output()
        .expect("kubectl exec");
    assert!(
        exec.status.success() && String::from_utf8_lossy(&exec.stdout).contains("src-alive"),
        "kubectl exec against the source pod must still work after the prepare swap \
         (CID preserved): stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&exec.stdout),
        String::from_utf8_lossy(&exec.stderr)
    );

    let _ = daemon.call(&k7d::control::Request::StopVm { vm_id: fork_id });
    let _ = kubectl_delete("pod", &pod);
}

/// More distinct images than spare slots must fail
/// LOUD, with the workload Create error naming the
/// `k7d.katakate.org/image-slots` annotation (visible in pod events).
#[test]
fn test_image_slot_exhaustion_fails_loud() {
    let _leak_guard = ensure_shim_installed();
    let pod = common::unique_name("test-k7d-slotfull");
    // The image-slots annotation only reaches the shim when containerd
    // forwards k7d.katakate.org/* pod annotations into the OCI spec.
    common::ensure_pod_annotations_forwarded();
    let _ = kubectl_delete("pod", &pod);
    let _pod_guard = PodGuard(pod.clone());
    std::thread::sleep(Duration::from_secs(2));

    // 1 spare slot, 3 distinct images: the first image boots the VM
    // (boot-time rootfs device), the second fills the only slot, the
    // third must fail loudly.
    kubectl_apply(&common::pin_to_local_node(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-k7d-slotfull
  annotations:
    k7d.katakate.org/image-slots: "1"
spec:
  runtimeClassName: k7
  containers:
  - name: c1
    image: alpine:3.20
    command: ["sleep", "infinity"]
  - name: c2
    image: busybox:1.36
    command: ["sleep", "infinity"]
  - name: c3
    image: nginx:1.27-alpine
"#,
    ))
    .unwrap();

    // Whichever two containers land first attach fine (boot + slot);
    // the third's Create fails and kubelet surfaces the shim error in
    // the pod's events. Poll describe for the annotation name the
    // error must carry.
    let deadline = Instant::now() + Duration::from_secs(240);
    let describe = loop {
        let output = std::process::Command::new("kubectl")
            .args(["describe", "pod", &pod])
            .output()
            .expect("kubectl describe");
        let describe = String::from_utf8_lossy(&output.stdout).to_string();
        if describe.contains("no free image slot") {
            break describe;
        }
        assert!(
            Instant::now() < deadline,
            "slot-exhaustion error never surfaced in pod events; describe:\n{describe}"
        );
        std::thread::sleep(Duration::from_secs(2));
    };
    // The error must name the annotation knob (success criterion).
    let event_tail = describe
        .split("no free image slot")
        .nth(1)
        .expect("split on matched needle");
    assert!(
        event_tail.contains("k7d.katakate.org/image-slots"),
        "exhaustion error must name the image-slots annotation; describe:\n{describe}"
    );

    let _ = kubectl_delete("pod", &pod);
}

fn pod_jsonpath(name: &str, path: &str) -> String {
    let output = std::process::Command::new("kubectl")
        .args(["get", "pod", name, "-o", &format!("jsonpath={{{path}}}")])
        .output()
        .expect("kubectl get");
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// A container that exits ON ITS OWN (no Kill) must be
/// reported Terminated with its REAL exit code, and
/// `restartPolicy: Always` must then restart it (new containerd id;
/// the same image dedupes onto the existing erofs mount).
#[test]
fn test_container_natural_exit() {
    let _leak_guard = ensure_shim_installed();
    let pod = common::unique_name("test-k7d-natexit");
    let _ = kubectl_delete("pod", &pod);
    let _pod_guard = PodGuard(pod.clone());
    std::thread::sleep(Duration::from_secs(2));

    kubectl_apply(&common::pin_to_local_node(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-k7d-natexit
spec:
  runtimeClassName: k7
  restartPolicy: Always
  containers:
  - name: worker
    image: busybox:1.36
    command: ["sh", "-c", "sleep 2; exit 7"]
"#,
    ))
    .unwrap();

    // Capture the first run's containerd id (and the restart count at
    // capture time — if the kubelet already restarted before we got
    // here, the id comparison below is skipped; restartCount is proof
    // enough of the restart in that case).
    let deadline = Instant::now() + Duration::from_secs(180);
    let (first_id, first_restart_count) = loop {
        let id = pod_jsonpath(&pod, ".status.containerStatuses[0].containerID");
        if !id.is_empty() {
            let rc = pod_jsonpath(&pod, ".status.containerStatuses[0].restartCount");
            break (id, rc);
        }
        assert!(
            Instant::now() < deadline,
            "containerStatuses never populated"
        );
        std::thread::sleep(Duration::from_millis(500));
    };

    // The natural exit must surface as Terminated with exit code 7 —
    // in lastState once the kubelet restarts the container (or in
    // state.terminated during the restart window).
    loop {
        let last = pod_jsonpath(
            &pod,
            ".status.containerStatuses[0].lastState.terminated.exitCode",
        );
        let current = pod_jsonpath(
            &pod,
            ".status.containerStatuses[0].state.terminated.exitCode",
        );
        if last == "7" || current == "7" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "exit code 7 never surfaced (lastState={last:?} state={current:?})"
        );
        std::thread::sleep(Duration::from_secs(1));
    }

    // restartPolicy: Always — the kubelet restarts it: restartCount
    // rises and the container runs again under a NEW containerd id.
    loop {
        let restart_count = pod_jsonpath(&pod, ".status.containerStatuses[0].restartCount");
        let running = pod_jsonpath(&pod, ".status.containerStatuses[0].state.running.startedAt");
        let id = pod_jsonpath(&pod, ".status.containerStatuses[0].containerID");
        let restarted = restart_count.parse::<u32>().unwrap_or(0) >= 1;
        let new_id = first_restart_count != "0" || (!id.is_empty() && id != first_id);
        if restarted && !running.is_empty() && new_id {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "container never restarted (restartCount={restart_count} running={running:?} \
             id={id} first_id={first_id})"
        );
        std::thread::sleep(Duration::from_secs(1));
    }

    kubectl_delete("pod", &pod).unwrap();
}

/// CRI container id of a named container in a pod (running or not).
fn cri_container_id(pod: &str, container: &str) -> String {
    let sandbox_id = common::pod_sandbox_id(pod);
    let ps = std::process::Command::new("k3s")
        .args([
            "crictl",
            "ps",
            "-a",
            "-p",
            &sandbox_id,
            "--name",
            container,
            "-q",
        ])
        .output()
        .expect("k3s crictl ps");
    let id = String::from_utf8_lossy(&ps.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    assert!(
        !id.is_empty(),
        "no CRI container found for {container}: {}",
        String::from_utf8_lossy(&ps.stderr)
    );
    id
}

/// Exit code kubelet recorded for a named container — in `lastState`
/// once it was restarted, or in `state.terminated` during the restart
/// window. Empty until one of them is populated.
fn recorded_exit_code(pod: &str, container: &str) -> String {
    let sel = format!(".status.containerStatuses[?(@.name==\"{container}\")]");
    let last = pod_jsonpath(pod, &format!("{sel}.lastState.terminated.exitCode"));
    if last.is_empty() {
        pod_jsonpath(pod, &format!("{sel}.state.terminated.exitCode"))
    } else {
        last
    }
}

/// A container stopped through the CRI (SIGTERM, then SIGKILL after
/// the grace timeout — every `kubectl delete`, rolling update and
/// eviction) must be reported with the exit status the process
/// ACTUALLY died with, observed by the exit watcher — not stamped by
/// the shim's `Kill` handler (docs/bug-candidates.md #46, which
/// reported `0`/Completed for every SIGTERM regardless of what the
/// process did, and unblocked `Wait` while it was still running).
///
///   - `graceful` traps SIGTERM and exits 3 → kubelet must see 3;
///   - `stubborn` is a PID-1 `sleep` that ignores SIGTERM → containerd
///     SIGKILLs it at the timeout → kubelet must see 137.
#[test]
fn test_cri_stop_reports_real_exit_code() {
    let _leak_guard = ensure_shim_installed();
    let pod = common::unique_name("test-k7d-sigterm");
    let _ = kubectl_delete("pod", &pod);
    let _pod_guard = PodGuard(pod.clone());
    std::thread::sleep(Duration::from_secs(2));

    kubectl_apply(&common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {pod}
spec:
  runtimeClassName: k7
  restartPolicy: Always
  containers:
  - name: graceful
    image: busybox:1.36
    command: ["sh", "-c", "trap 'exit 3' TERM; while true; do sleep 1; done"]
  - name: stubborn
    image: busybox:1.36
    command: ["sleep", "infinity"]
"#
    )))
    .unwrap();
    wait_for_all_containers_ready(&pod, Duration::from_secs(180)).unwrap();

    for (container, timeout, want) in [("graceful", "10", "3"), ("stubborn", "3", "137")] {
        let cid = cri_container_id(&pod, container);
        let started = Instant::now();
        let stop = std::process::Command::new("k3s")
            .args(["crictl", "stop", "-t", timeout, &cid])
            .output()
            .expect("k3s crictl stop");
        assert!(
            stop.status.success(),
            "crictl stop {container}: {}",
            String::from_utf8_lossy(&stop.stderr)
        );
        eprintln!(
            "crictl stop -t {timeout} {container}: {:?}",
            started.elapsed()
        );

        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let got = recorded_exit_code(&pod, container);
            if !got.is_empty() {
                assert_eq!(
                    got, want,
                    "{container}: kubelet recorded exit code {got}, expected {want}"
                );
                break;
            }
            assert!(
                Instant::now() < deadline,
                "{container}: no terminated exit code ever recorded"
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    kubectl_delete("pod", &pod).unwrap();
}

/// Init containers sequence end-to-end with NO shim
/// special-casing — kubelet drives plain CRI Create/Start/Wait off
/// the natural-exit observation and the distinct init image
/// rides a spare slot. Two init containers run IN ORDER
/// before the main container:
///
///   1. `init-marker` (busybox — the FIRST workload, boots the VM)
///      writes a marker into a shared emptyDir and exits 0;
///   2. `init-same` (alpine — SAME image as main, post-boot slot
///      attach shared with main) exits 0;
///   3. `main` (alpine) starts only after both and must see the
///      marker at ITS startup.
///
/// Then the exited same-image init is removed through the CRI
/// (`crictl rm` — the kubelet container-GC path): the shim's Delete
/// must release the init's refcount on the shared erofs key WITHOUT
/// unmounting the rootfs the main container still runs from.
#[test]
fn test_init_container_sequencing() {
    let _leak_guard = ensure_shim_installed();
    let pod = common::unique_name("test-k7d-initseq");
    let _ = kubectl_delete("pod", &pod);
    let _pod_guard = PodGuard(pod.clone());
    std::thread::sleep(Duration::from_secs(2));

    kubectl_apply(&common::pin_to_local_node(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-k7d-initseq
spec:
  runtimeClassName: k7
  initContainers:
  - name: init-marker
    image: busybox:1.36
    command: ["sh", "-c", "echo from-init > /shared/init-done && echo init-marker-done"]
    volumeMounts:
    - name: shared
      mountPath: /shared
  - name: init-same
    image: alpine:3.20
    command: ["sh", "-c", "echo init-same-done"]
  containers:
  - name: main
    image: alpine:3.20
    command: ["sh", "-c", "if [ -f /shared/init-done ]; then echo main-saw-marker; else echo main-missed-marker; fi; sleep infinity"]
    volumeMounts:
    - name: shared
      mountPath: /shared
  volumes:
  - name: shared
    emptyDir: {}
"#,
    ))
    .unwrap();
    wait_for_pod_ready(&pod, Duration::from_secs(240)).unwrap();
    wait_for_all_containers_ready(&pod, Duration::from_secs(60)).unwrap();

    // Both init containers report Terminated/Completed with the REAL
    // exit code 0 (natural-exit observation).
    for (idx, name) in [(0, "init-marker"), (1, "init-same")] {
        let got_name = pod_jsonpath(&pod, &format!(".status.initContainerStatuses[{idx}].name"));
        assert_eq!(got_name, name, "init container order in pod status");
        let exit_code = pod_jsonpath(
            &pod,
            &format!(".status.initContainerStatuses[{idx}].state.terminated.exitCode"),
        );
        assert_eq!(exit_code, "0", "{name} must terminate with exit 0");
        let reason = pod_jsonpath(
            &pod,
            &format!(".status.initContainerStatuses[{idx}].state.terminated.reason"),
        );
        assert_eq!(reason, "Completed", "{name} termination reason");
    }

    // Ordering straight from pod status: each stage may only start
    // after the previous one finished. Kubelet timestamps are RFC3339
    // UTC of equal length, so lexicographic comparison is
    // chronological.
    let init1_finished = pod_jsonpath(
        &pod,
        ".status.initContainerStatuses[0].state.terminated.finishedAt",
    );
    let init2_started = pod_jsonpath(
        &pod,
        ".status.initContainerStatuses[1].state.terminated.startedAt",
    );
    let init2_finished = pod_jsonpath(
        &pod,
        ".status.initContainerStatuses[1].state.terminated.finishedAt",
    );
    let main_started = pod_jsonpath(&pod, ".status.containerStatuses[0].state.running.startedAt");
    assert!(
        !init1_finished.is_empty() && !init2_started.is_empty() && !main_started.is_empty(),
        "pod status timestamps must be populated \
         (init1_finished={init1_finished:?} init2_started={init2_started:?} \
         main_started={main_started:?})"
    );
    assert!(
        init1_finished <= init2_started,
        "init-same may only start after init-marker finished \
         ({init1_finished} vs {init2_started})"
    );
    assert!(
        init2_finished <= main_started,
        "main may only start after init-same finished ({init2_finished} vs {main_started})"
    );

    // Marker-based ordering proof: main checked for the marker at ITS
    // startup, so the log line is only right if init ran first.
    let main_logs = kubectl_logs_c(&pod, "main").unwrap();
    assert!(
        main_logs.contains("main-saw-marker"),
        "main must see the init marker at startup; logs: {main_logs}"
    );
    let out = kubectl_exec_c(&pod, "main", &["cat", "/shared/init-done"]).unwrap();
    assert_eq!(out.trim(), "from-init");

    // ── Same-image share survives init Delete ──
    // Remove the exited alpine init through the CRI, exactly like
    // kubelet's container GC would. The shim's Delete releases the
    // init's claim on the shared erofs key and must NOT unmount the
    // rootfs the main container still runs from (it fails loud if
    // the refcount invariant is violated — which would fail the rm).
    let main_id_before = pod_jsonpath(&pod, ".status.containerStatuses[0].containerID");
    let sandbox_id = common::pod_sandbox_id(&pod);
    let ps = std::process::Command::new("k3s")
        .args([
            "crictl",
            "ps",
            "-a",
            "-p",
            &sandbox_id,
            "--name",
            "init-same",
            "-q",
        ])
        .output()
        .expect("k3s crictl ps");
    let init_cid = String::from_utf8_lossy(&ps.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    assert!(
        !init_cid.is_empty(),
        "no CRI container found for init-same: {}",
        String::from_utf8_lossy(&ps.stderr)
    );
    let rm = std::process::Command::new("k3s")
        .args(["crictl", "rm", &init_cid])
        .output()
        .expect("k3s crictl rm");
    assert!(
        rm.status.success(),
        "crictl rm of the exited init must succeed (a loud shim Delete failure \
         means the refcount invariant fired): {}",
        String::from_utf8_lossy(&rm.stderr)
    );

    // Main still runs from the shared erofs mount: a rootfs read
    // (uncached file off the erofs device) and an exec both work.
    let out = kubectl_exec_c(&pod, "main", &["cat", "/etc/os-release"]).unwrap();
    assert!(out.contains("Alpine"), "rootfs read after init rm: {out}");
    let out = kubectl_exec_c(&pod, "main", &["sh", "-c", "echo still-alive"]).unwrap();
    assert_eq!(out.trim(), "still-alive");

    // And the removal did not disturb the main container.
    std::thread::sleep(Duration::from_secs(3));
    let main_id_after = pod_jsonpath(&pod, ".status.containerStatuses[0].containerID");
    assert_eq!(
        main_id_before, main_id_after,
        "main must not be restarted when the exited init is removed"
    );

    kubectl_delete("pod", &pod).unwrap();
}

/// Two containers with different memory limits.
/// Guest runc enforces each cgroup independently — a 40 Mi
/// *anonymous* allocation OOMs inside the 32Mi container but succeeds
/// in the 256Mi sibling. (Assert via kubectl exec rather than kubelet
/// OOMKilled: exit observation is not required for limit
/// enforcement.)
///
/// The allocation is `dd`'s own 40 MiB I/O buffer, written to
/// `/dev/null`. It used to be a 40 MiB *file* under `/tmp`, which
/// worked only because the container's writable layer was a guest
/// tmpfs whose pages are charged to the memory cgroup and cannot be
/// reclaimed. moved that layer onto a host-backed virtio-blk
/// scratch disk, so file writes are now reclaimable page cache and a
/// 40 MiB write no longer says anything about a 32 MiB memory limit.
#[test]
fn test_kubectl_pod_per_container_memory_limits() {
    let _leak_guard = ensure_shim_installed();
    let pod = common::unique_name("test-k7d-ctrmem");
    let _ = kubectl_delete("pod", &pod);
    let _pod_guard = PodGuard(pod.clone());
    std::thread::sleep(Duration::from_secs(2));

    kubectl_apply(&common::pin_to_local_node(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-k7d-ctrmem
spec:
  runtimeClassName: k7
  containers:
  - name: small
    image: alpine:3.20
    command: ["sleep", "infinity"]
    resources:
      limits:
        memory: 32Mi
  - name: big
    image: alpine:3.20
    command: ["sleep", "infinity"]
    resources:
      limits:
        memory: 256Mi
"#,
    ))
    .unwrap();
    wait_for_pod_ready(&pod, Duration::from_secs(180)).unwrap();
    wait_for_all_containers_ready(&pod, Duration::from_secs(60)).unwrap();

    // A single 40 MiB dd buffer, faulted in by the read: over small's
    // 32Mi cgroup limit, under big's 256Mi. Guest OOM kills the small
    // exec (exit 137).
    let hog = ["dd", "if=/dev/zero", "of=/dev/null", "bs=40M", "count=1"];
    let small_hog = kubectl_exec_c(&pod, "small", &hog);
    assert!(
        small_hog.is_err(),
        "40Mi anonymous allocation in a 32Mi cgroup must fail, got: {small_hog:?}"
    );
    let err = small_hog.unwrap_err();
    assert!(
        err.contains("137") || err.contains("Killed") || err.contains("oom"),
        "small hog should look like OOM/SIGKILL, got: {err}"
    );

    // The same allocation in the sibling must succeed — proves the
    // limits are per-container, not a shared VM-wide cap alone.
    kubectl_exec_c(&pod, "big", &hog)
        .expect("40Mi anonymous allocation in a 256Mi cgroup must succeed");
    let out = kubectl_exec_c(&pod, "big", &["echo", "still-alive"]).unwrap();
    assert!(out.contains("still-alive"));

    // Small's main process survived the exec OOM (process-level).
    let out = kubectl_exec_c(&pod, "small", &["echo", "small-alive"]).unwrap();
    assert!(out.contains("small-alive"));

    let _ = kubectl_delete("pod", &pod);
}

/// kubectl logs latency.
#[test]
fn test_kubectl_logs_works() {
    let total = Instant::now();
    eprintln!("\n=== test_kubectl_logs_works: latency report ===");

    let _leak_guard = ensure_shim_installed();
    let pod = common::unique_name("test-k7d-logs");

    let _ = kubectl_delete("pod", &pod);
    std::thread::sleep(Duration::from_secs(2));

    timed!("kubectl apply", {
        kubectl_apply(&common::pin_to_local_node(
            r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-k7d-logs
spec:
  runtimeClassName: k7
  containers:
  - name: echo
    image: alpine:3.20
    command: ["sh", "-c", "echo hello-from-k7d && sleep infinity"]
"#,
        ))
        .unwrap();
    });

    timed!("Pod → Running", {
        wait_for_pod_ready(&pod, Duration::from_secs(120)).unwrap();
    });

    std::thread::sleep(Duration::from_secs(3));

    timed!("kubectl logs", {
        let logs = kubectl_logs(&pod).unwrap();
        assert!(logs.contains("hello-from-k7d"), "kubectl logs: {:?}", logs);
    });

    timed!("kubectl delete + cleanup", {
        kubectl_delete("pod", &pod).unwrap();
    });

    eprintln!("  ⏱  {:.<50} {:>8.2?}", "TOTAL", total.elapsed());
    eprintln!();
}

/// kubectl exec latency.
#[test]
fn test_kubectl_exec_non_interactive() {
    let total = Instant::now();
    eprintln!("\n=== test_kubectl_exec_non_interactive: latency report ===");

    let _leak_guard = ensure_shim_installed();
    let pod = common::unique_name("test-k7d-exec");

    let _ = kubectl_delete("pod", &pod);
    std::thread::sleep(Duration::from_secs(2));

    timed!("kubectl apply", {
        kubectl_apply(&common::pin_to_local_node(
            r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-k7d-exec
spec:
  runtimeClassName: k7
  containers:
  - name: sandbox
    image: alpine:3.20
    command: ["sleep", "infinity"]
"#,
        ))
        .unwrap();
    });

    timed!("Pod → Running", {
        wait_for_pod_ready(&pod, Duration::from_secs(120)).unwrap();
    });

    timed!("kubectl exec: echo (1st)", {
        let output = kubectl_exec(&pod, &["echo", "k7d-exec"]).unwrap();
        assert_eq!(output.trim(), "k7d-exec");
    });

    timed!("kubectl exec: write file", {
        kubectl_exec(&pod, &["sh", "-c", "echo persist > /tmp/test"]).unwrap();
    });

    timed!("kubectl exec: read file", {
        let read = kubectl_exec(&pod, &["cat", "/tmp/test"]).unwrap();
        assert_eq!(read.trim(), "persist");
    });

    timed!("5x sequential kubectl exec", {
        for i in 0..5 {
            let r = kubectl_exec(&pod, &["echo", &format!("iter-{i}")]).unwrap();
            assert_eq!(r.trim(), format!("iter-{i}"));
        }
    });

    timed!("kubectl delete", {
        kubectl_delete("pod", &pod).unwrap();
    });

    eprintln!("  ⏱  {:.<50} {:>8.2?}", "TOTAL", total.elapsed());
    eprintln!();
}

/// Return `(-id <sandbox_id>)` of every running k7 shim process.
fn running_k7_shim_sandbox_ids() -> Vec<String> {
    let out = std::process::Command::new("pgrep")
        .args(["-af", "^/usr/local/bin/containerd-shim-k7-v1"])
        .output()
        .expect("pgrep should run");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let mut toks = line.split_whitespace();
            while let Some(t) = toks.next() {
                if t == "-id" {
                    return toks.next().map(str::to_string);
                }
            }
            None
        })
        .collect()
}

/// Ask the node's k7d daemon (default socket) to resolve a sandbox.
fn daemon_lookup_sandbox(sandbox_id: &str) -> k7d::control::Response {
    let mut client = k7d::control::Client::connect_env().expect("connect k7d daemon");
    client
        .call(&k7d::control::Request::LookupSandbox {
            sandbox_id: sandbox_id.to_string(),
        })
        .expect("lookup_sandbox call")
}

/// Crash recovery: killing a pod's shim must
/// not wedge the pod or leak its VM.
///
/// Empirically (k3s 1.36 / containerd 2.3), containerd does NOT
/// respawn a killed shim: kubelet stops the dead sandbox (containerd
/// runs the shim binary's `delete` subcommand — cleanup-after-dead-
/// shim) and recreates it under a NEW sandbox id. This test therefore
/// asserts the two things a crashed shim must guarantee:
///
/// 1. the orphaned VM is stopped in the k7d daemon and its reattach
///    record removed (it used to leak forever, and its
///    virtiofsd blocked every successor VM's socket — the pod
///    retry-stormed and never recovered);
/// 2. the pod returns to Running with a working exec path on the
///    recreated sandbox.
///
/// Container-filesystem state intentionally does NOT survive — the
/// workload container is recreated from its image, exactly as with a
/// killed runc shim. VM-identity reattach (`reattach_sandbox`,
/// shim `Connect`) is exercised by the daemon-level tests above the
/// kubelet layer, because kubelet never re-uses a dead sandbox id.
#[test]
fn test_shim_survives_shim_kill() {
    let total = Instant::now();
    eprintln!("\n=== test_shim_survives_shim_kill: latency report ===");

    let _leak_guard = ensure_shim_installed();
    let pod = common::unique_name("test-k7d-crash");

    let _ = kubectl_delete("pod", &pod);
    std::thread::sleep(Duration::from_secs(2));

    timed!("kubectl apply", {
        kubectl_apply(&common::pin_to_local_node(
            r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-k7d-crash
spec:
  runtimeClassName: k7
  containers:
  - name: sandbox
    image: alpine:3.20
    command: ["sleep", "infinity"]
"#,
        ))
        .unwrap();
    });

    timed!("Pod → Running", {
        wait_for_pod_ready(&pod, Duration::from_secs(120)).unwrap();
    });

    timed!("kubectl exec: write marker", {
        kubectl_exec(&pod, &["sh", "-c", "echo persist > /tmp/m"]).unwrap();
        let read = kubectl_exec(&pod, &["cat", "/tmp/m"]).unwrap();
        assert_eq!(read.trim(), "persist");
    });

    // The daemon must know the sandbox while its shim is alive.
    let old_ids = running_k7_shim_sandbox_ids();
    assert_eq!(old_ids.len(), 1, "one k7 shim expected: {old_ids:?}");
    let old_sandbox = old_ids[0].clone();
    let old_record = k7d::control::sandbox_root_dir().join(format!("{old_sandbox}.json"));
    assert!(
        matches!(
            daemon_lookup_sandbox(&old_sandbox),
            k7d::control::Response::SandboxFound { .. }
        ),
        "daemon should hold the sandbox VM pre-kill"
    );
    assert!(
        old_record.exists(),
        "reattach record should exist pre-kill: {old_record:?}"
    );

    timed!("pkill -9 shim", {
        let status = std::process::Command::new("pkill")
            .args(["-9", "-f", "^/usr/local/bin/containerd-shim-k7-v1"])
            .status()
            .expect("pkill should run");
        assert!(status.success(), "no shim process matched");
    });

    // Recovery: kubelet stops the dead sandbox and recreates it. Poll
    // until the pod is Running again AND exec works end-to-end.
    let recovery = timed!("Pod recovery (kubelet recreate + fresh VM boot)", {
        let start = Instant::now();
        let deadline = start + Duration::from_secs(180);
        loop {
            std::thread::sleep(Duration::from_secs(2));
            let phase = std::process::Command::new("kubectl")
                .args(["get", "pod", &pod, "-o", "jsonpath={.status.phase}"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default();
            if phase == "Running" {
                if let Ok(out) = kubectl_exec(&pod, &["echo", "recovered"]) {
                    if out.trim() == "recovered" {
                        break start.elapsed();
                    }
                }
            }
            assert!(
                Instant::now() < deadline,
                "pod did not recover within 180s (phase={phase})"
            );
        }
    });
    eprintln!("       (recovery latency: {recovery:.2?})");

    // The dead shim's VM must be reaped from the daemon (no orphan)
    // and its reattach record removed. Give the async teardown a beat.
    let gc_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let gone = matches!(
            daemon_lookup_sandbox(&old_sandbox),
            k7d::control::Response::Error { .. }
        ) && !old_record.exists();
        if gone {
            break;
        }
        assert!(
            Instant::now() < gc_deadline,
            "orphaned VM/record of dead sandbox {old_sandbox} never reaped"
        );
        std::thread::sleep(Duration::from_secs(1));
    }

    // The recovered pod runs under a NEW sandbox id with its own
    // record — exactly one k7 sandbox VM total (no leak).
    let new_ids = running_k7_shim_sandbox_ids();
    assert_eq!(new_ids.len(), 1, "one recovered shim expected: {new_ids:?}");
    assert_ne!(
        new_ids[0], old_sandbox,
        "kubelet recreates the sandbox under a new id"
    );
    assert!(
        matches!(
            daemon_lookup_sandbox(&new_ids[0]),
            k7d::control::Response::SandboxFound { .. }
        ),
        "daemon should hold the recovered sandbox VM"
    );

    timed!("kubectl delete + cleanup", {
        kubectl_delete("pod", &pod).unwrap();
        wait_for_pod_gone(&pod, Duration::from_secs(30)).unwrap();
    });

    eprintln!("  ⏱  {:.<50} {:>8.2?}", "TOTAL", total.elapsed());
    eprintln!();
}

/// Pod deletion + cleanup latency.
#[test]
fn test_pod_delete_cleans_up() {
    let total = Instant::now();
    eprintln!("\n=== test_pod_delete_cleans_up: latency report ===");

    let _leak_guard = ensure_shim_installed();
    let pod = common::unique_name("test-k7d-cleanup");

    let _ = kubectl_delete("pod", &pod);
    std::thread::sleep(Duration::from_secs(2));

    timed!("kubectl apply", {
        kubectl_apply(&common::pin_to_local_node(
            r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-k7d-cleanup
spec:
  runtimeClassName: k7
  containers:
  - name: sandbox
    image: alpine:3.20
    command: ["sleep", "infinity"]
"#,
        ))
        .unwrap();
    });

    timed!("Pod → Running", {
        wait_for_pod_ready(&pod, Duration::from_secs(120)).unwrap();
    });

    timed!("kubectl delete pod", {
        kubectl_delete("pod", &pod).unwrap();
    });

    let teardown = timed!("Wait for pod gone (VM shutdown + cleanup)", {
        wait_for_pod_gone(&pod, Duration::from_secs(30)).unwrap()
    });
    eprintln!("       (teardown latency: {teardown:.2?})");

    eprintln!("  ⏱  {:.<50} {:>8.2?}", "TOTAL", total.elapsed());
    eprintln!();
}

// ──: multi-vCPU kubectl / annotation path ───────────────────

/// The directory per-VM CPU cgroups live in — the service cgroup, or
/// the delegated `vm/` subtree under it once the split is on.
fn k7d_service_cgroup() -> std::path::PathBuf {
    common::vm_cgroup_root()
}

/// vCPU thread comm names (`vcpu0`, `vcpu1`, …) currently in `cg`'s
/// `cgroup.threads`.
fn vcpu_comms_in_cgroup(cg: &std::path::Path) -> Vec<String> {
    let threads_raw =
        std::fs::read_to_string(cg.join("cgroup.threads")).expect("read cgroup.threads");
    let mut names: Vec<String> = threads_raw
        .split_whitespace()
        .filter_map(|tid| std::fs::read_to_string(format!("/proc/{tid}/comm")).ok())
        .map(|comm| comm.trim().to_string())
        .filter(|comm| comm.starts_with("vcpu"))
        .collect();
    names.sort();
    names
}

/// A kubectl pod with `cpu: "2"` warm-forks via the daemon;
/// the child sees 2 CPUs and both vCPU TIDs land in a CFS-capped
/// cgroup (`vcpu0`/`vcpu1`). Also asserts the sandbox reattach record
/// persisted `vcpus: 2`.
#[test]
fn test_kubectl_pod_multi_vcpu_fork() {
    let _leak_guard = ensure_shim_installed();
    let pod = common::unique_name("test-k7d-mvcpu-fork");
    let _ = kubectl_delete("pod", &pod);
    std::thread::sleep(Duration::from_secs(2));

    kubectl_apply(&common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {pod}
spec:
  runtimeClassName: k7
  containers:
  - name: app
    image: alpine:3.20
    command: ["sleep", "infinity"]
    resources:
      limits:
        cpu: "2"
"#
    )))
    .expect("kubectl apply");
    wait_for_pod_ready(&pod, Duration::from_secs(120)).expect("pod ready");

    let nproc = kubectl_exec(&pod, &["nproc"]).expect("nproc");
    assert_eq!(nproc.trim(), "2", "cpu: \"2\" pod must see 2 vCPUs");

    let src = common::pod_vm_state(&pod);
    let sandbox_id = common::pod_sandbox_id(&pod);
    let record_path = std::path::PathBuf::from(k7d::control::DEFAULT_SANDBOX_ROOT)
        .join(format!("{sandbox_id}.json"));
    let record: k7d::control::SandboxRecord =
        serde_json::from_str(&std::fs::read_to_string(&record_path).expect("read sandbox record"))
            .expect("parse sandbox record");
    assert_eq!(
        record.vcpus, 2,
        "sandbox record must carry create-time vCPU count"
    );
    assert_eq!(record.cpu_quota, Some(200_000));
    assert_eq!(record.cpu_period, Some(100_000));

    let src_cg = k7d_service_cgroup().join(format!("vm-{}", src.vm_id));
    assert!(
        src_cg.exists(),
        "source VM CPU cgroup missing: {}",
        src_cg.display()
    );
    assert_eq!(
        std::fs::read_to_string(src_cg.join("cpu.max"))
            .expect("read cpu.max")
            .trim(),
        "200000 100000"
    );
    assert_eq!(vcpu_comms_in_cgroup(&src_cg), ["vcpu0", "vcpu1"]);

    let mut daemon = k7d::control::Client::connect_env().expect("connect k7d daemon");
    let forked = daemon
        .call(&k7d::control::Request::ForkVm {
            vm_id: src.vm_id.clone(),
            sandbox_id: None,
            pod_netns: None,
            dilation: None,
        })
        .expect("fork_vm");
    let (fork_id, fork_cid) = match forked {
        k7d::control::Response::VmForked {
            vm_id, guest_cid, ..
        } => (vm_id, guest_cid),
        other => panic!("unexpected fork_vm response: {other:?}"),
    };

    let mut agent = k7d::api::AgentClient::connect_vsock(fork_cid, Duration::from_secs(10))
        .expect("forked guest agent");
    let fork_nproc = agent
        .exec(&["sh", "-c", "grep -c ^processor /proc/cpuinfo"])
        .expect("nproc in fork");
    assert_eq!(
        fork_nproc.stdout.trim(),
        "2",
        "forked guest must see 2 CPUs"
    );
    drop(agent);

    let fork_cg = k7d_service_cgroup().join(format!("vm-{fork_id}"));
    assert!(
        fork_cg.exists(),
        "fork VM CPU cgroup missing: {}",
        fork_cg.display()
    );
    assert_eq!(
        std::fs::read_to_string(fork_cg.join("cpu.max"))
            .expect("read fork cpu.max")
            .trim(),
        "200000 100000",
        "fork must inherit the source's CFS cap"
    );
    assert_eq!(
        vcpu_comms_in_cgroup(&fork_cg),
        ["vcpu0", "vcpu1"],
        "both fork vCPU TIDs must be in the CFS cgroup"
    );

    // CID stability: source pod still answers after prepare swap.
    let src_alive = kubectl_exec(&pod, &["echo", "src-alive"]).expect("kubectl exec source");
    assert!(src_alive.contains("src-alive"));

    let _ = daemon.call(&k7d::control::Request::StopVm { vm_id: fork_id });
    let _ = kubectl_delete("pod", &pod);
}

/// Annotation-driven cluster fork with mixed per-member vCPU
/// counts — kubectl pods sized `[1, 2, 1]` on one `cluster-id`, then a
/// trigger pod's `tree-*` annotations adopt + fork. Per-member counts
/// must survive on the fork.
#[test]
fn test_cluster_annotation_mixed_vcpus() {
    let _leak_guard = ensure_shim_installed();
    common::ensure_pod_annotations_forwarded();

    let cluster_id = format!("mvcpu{}", std::process::id() % 10_000);
    // Bridge names are `k7-br-{cluster_id}`; keep cluster_id short.
    assert!(
        cluster_id.len() <= 9,
        "cluster_id {cluster_id:?} too long for bridge name"
    );
    let pods = [
        common::unique_name("test-k7d-mixvcpu-0"),
        common::unique_name("test-k7d-mixvcpu-1"),
        common::unique_name("test-k7d-mixvcpu-2"),
    ];
    let vcpu_counts: [u32; 3] = [1, 2, 1];
    let trigger = common::unique_name("test-k7d-mixvcpu-trig");
    let tree_id = format!("mixvcpu-{}", std::process::id());

    let teardown = |daemon: &mut k7d::control::Client| {
        let _ = daemon.call(&k7d::control::Request::TreeDrop {
            tree_id: tree_id.clone(),
        });
        let _ = kubectl_delete("pod", &trigger);
        for p in &pods {
            let _ = kubectl_delete("pod", p);
        }
        let _ = std::fs::remove_dir_all(format!("/var/lib/k7d/trees/{tree_id}"));
    };

    for p in &pods {
        let _ = kubectl_delete("pod", p);
    }
    let _ = kubectl_delete("pod", &trigger);
    std::thread::sleep(Duration::from_secs(2));

    for (idx, (pod, &ncpu)) in pods.iter().zip(&vcpu_counts).enumerate() {
        let cpu_yaml = if ncpu > 1 {
            format!(
                r#"
    resources:
      limits:
        cpu: "{ncpu}""#
            )
        } else {
            String::new()
        };
        kubectl_apply(&common::pin_to_local_node(&format!(
            r#"
apiVersion: v1
kind: Pod
metadata:
  name: {pod}
  annotations:
    k7d.katakate.org/cluster-id: {cluster_id}
    k7d.katakate.org/fork-vm-index: "{idx}"
spec:
  runtimeClassName: k7
  restartPolicy: Never
  containers:
  - name: app
    image: alpine:3.20
    command: ["sleep", "infinity"]{cpu_yaml}
"#
        )))
        .unwrap_or_else(|e| panic!("apply {pod}: {e}"));
    }
    for pod in &pods {
        wait_for_pod_ready(&pod, Duration::from_secs(180))
            .unwrap_or_else(|e| panic!("pod {pod} ready: {e}"));
    }
    for (pod, &want) in pods.iter().zip(&vcpu_counts) {
        let nproc = kubectl_exec(&pod, &["nproc"]).expect("nproc");
        assert_eq!(
            nproc.trim(),
            want.to_string(),
            "pre-adopt {pod} must see {want} CPU(s)"
        );
    }

    let budget = serde_json::to_string(&k7d::tree::TreeBudget {
        max_live_vms: 16,
        max_live_ram_bytes: 16 * 1024 * 1024 * 1024,
        max_disk_bytes: 32 * 1024 * 1024 * 1024,
        max_chain_depth: 8,
    })
    .expect("serialize TreeBudget");
    kubectl_apply(&common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {trigger}
  annotations:
    k7d.katakate.org/tree-id: "{tree_id}"
    k7d.katakate.org/tree-adopt-cluster: "{cluster_id}"
    k7d.katakate.org/tree-fork-from: "root"
    k7d.katakate.org/tree-fork-label: "warm"
    k7d.katakate.org/tree-budget: '{budget}'
spec:
  runtimeClassName: k7
  restartPolicy: Never
  containers:
  - name: trigger
    image: alpine:3.20
    command: ["sleep", "infinity"]
"#
    )))
    .expect("apply trigger");
    wait_for_pod_ready(&trigger, Duration::from_secs(300))
        .expect("trigger Running (= adopt+fork succeeded)");
    common::mark_test_tree(&tree_id);

    let mut daemon = k7d::control::Client::connect_env().expect("connect k7d daemon");
    match daemon.call(&k7d::control::Request::TreeNodes {
        tree_id: tree_id.clone(),
    }) {
        Ok(k7d::control::Response::TreeNodeList { nodes, .. }) => {
            assert!(
                nodes.iter().any(|n| n.label == "warm"),
                "annotation fork node labeled 'warm' must exist: {nodes:?}"
            );
        }
        other => {
            teardown(&mut daemon);
            panic!("unexpected TreeNodes response: {other:?}");
        }
    }

    // Second fork from the adopted root (the annotation fork's source)
    // to obtain guest CIDs. Fork children are not themselves prepared
    // as fork sources, so probing from `warm` would fail loud — the
    // root is the prepared lineage and still carries the mixed vCPU
    // counts from the kubectl members.
    let probe_cids = match daemon.call(&k7d::control::Request::TreeFork {
        tree_id: tree_id.clone(),
        source_id: "root".to_string(),
        label: "probe".to_string(),
        dilation: None,
        dilation_policy: None,
        dilation_config: None,
    }) {
        Ok(k7d::control::Response::TreeForked { guest_cids, .. }) => guest_cids,
        other => {
            teardown(&mut daemon);
            panic!("unexpected TreeFork(probe) response: {other:?}");
        }
    };
    if probe_cids.len() != 3 {
        teardown(&mut daemon);
        panic!("probe fork must clone all 3 members, got {probe_cids:?}");
    }
    for (i, (&cid, &want)) in probe_cids.iter().zip(&vcpu_counts).enumerate() {
        let mut agent = match k7d::api::AgentClient::connect_vsock(cid, Duration::from_secs(30)) {
            Ok(a) => a,
            Err(e) => {
                teardown(&mut daemon);
                panic!("connect probe member {i} (cid {cid}): {e}");
            }
        };
        let nproc = match agent.exec(&["sh", "-c", "grep -c ^processor /proc/cpuinfo"]) {
            Ok(o) => o.stdout.trim().to_string(),
            Err(e) => {
                teardown(&mut daemon);
                panic!("nproc probe member {i}: {e}");
            }
        };
        if nproc != want.to_string() {
            teardown(&mut daemon);
            panic!("probe member {i} saw {nproc} CPUs, want {want}");
        }
    }

    // Source members still answer kubectl exec after adopt (CID preserved).
    let echo = kubectl_exec(&pods[1], &["echo", "post-adopt-2vcpu"]);
    if !matches!(echo, Ok(ref s) if s.contains("post-adopt-2vcpu")) {
        teardown(&mut daemon);
        panic!("post-adopt exec into 2-vCPU member failed: {echo:?}");
    }

    teardown(&mut daemon);
}

/// A kubectl pod B with `fork-source-{cluster,vm}` pointing at Running
/// pod A boots as a warm fork of A's VM (annotation-only
/// drive path — no test-side `ForkVm`). Share-less emptyDir → CoW;
/// source still execs (CID preserved across prepare swap).
#[test]
fn test_kubectl_fork_source_annotation() {
    let _leak_guard = ensure_shim_installed();
    common::ensure_pod_annotations_forwarded();

    let src = common::unique_name("test-k7d-fsrc-a");
    let fork = common::unique_name("test-k7d-fsrc-b");
    let cluster_id = format!("fsrc{}", std::process::id() % 10_000);
    assert!(
        cluster_id.len() <= 9,
        "cluster_id {cluster_id:?} too long for bridge name"
    );

    let _ = kubectl_delete("pod", &src);
    let _ = kubectl_delete("pod", &fork);
    std::thread::sleep(Duration::from_secs(2));

    kubectl_apply(&common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {src}
  annotations:
    k7d.katakate.org/cluster-id: {cluster_id}
spec:
  runtimeClassName: k7
  containers:
  - name: app
    image: alpine:3.20
    command: ["sleep", "infinity"]
    volumeMounts:
    - name: scratch
      mountPath: /scratch
  volumes:
  - name: scratch
    emptyDir: {{}}
"#
    )))
    .expect("apply source");
    wait_for_pod_ready(&src, Duration::from_secs(120)).expect("source ready");

    let src_state = common::pod_vm_state(&src);
    assert_eq!(
        src_state.virtiofs_shares, 0,
        "emptyDir source must be block-backed (zero virtiofs)"
    );
    let src_sandbox = common::pod_sandbox_id(&src);

    // Annotation-only drive path: the fork pod's Create performs
    // LookupSandbox + ForkVm. `fork-source-vm` is the CRI sandbox id
    // (LookupSandbox key); both annotations required together.
    kubectl_apply(&common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {fork}
  annotations:
    k7d.katakate.org/fork-source-cluster: {cluster_id}
    k7d.katakate.org/fork-source-vm: {src_sandbox}
spec:
  runtimeClassName: k7
  restartPolicy: Never
  containers:
  - name: app
    image: alpine:3.20
    command: ["sleep", "infinity"]
"#
    )))
    .expect("apply fork");
    wait_for_pod_ready(&fork, Duration::from_secs(180)).expect("fork pod Running");

    let fork_state = common::pod_vm_state(&fork);
    assert!(
        !fork_state.fork_memory_full_copy,
        "annotation fork of share-less source must be CoW, not full memfd copy"
    );
    assert_eq!(fork_state.virtiofs_shares, 0);
    assert_ne!(
        fork_state.vm_id, src_state.vm_id,
        "fork must be a distinct VM id from the source"
    );

    let alive = kubectl_exec(&fork, &["echo", "fork-alive"]).expect("exec in fork");
    assert!(
        alive.contains("fork-alive"),
        "fork workload must answer kubectl exec: {alive:?}"
    );

    // CID stability (/ CHALLENGES #39): source still
    // answers after the prepare swap triggered by the annotation fork.
    let src_alive = kubectl_exec(&src, &["echo", "src-alive"]).expect("exec in source");
    assert!(
        src_alive.contains("src-alive"),
        "source must still exec after annotation ForkVm: {src_alive:?}"
    );

    let _ = kubectl_delete("pod", &fork);
    let _ = kubectl_delete("pod", &src);
}

/// A CNI (non-cluster-mode) pod's annotation fork keeps internet
/// egress, through its own pod netns: own bridge at the source's
/// `vm_index`, TAP attached into the fork pod's netns (CHALLENGES
/// #283 — the fork used to come up with no virtio-net at all).
#[test]
fn test_kubectl_fork_keeps_pod_egress() {
    let _leak_guard = ensure_shim_installed();
    common::ensure_pod_annotations_forwarded();

    let src = common::unique_name("test-k7d-fnet-a");
    let fork = common::unique_name("test-k7d-fnet-b");
    let _ = kubectl_delete("pod", &src);
    let _ = kubectl_delete("pod", &fork);
    std::thread::sleep(Duration::from_secs(2));

    kubectl_apply(&common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {src}
spec:
  runtimeClassName: k7
  containers:
  - name: app
    image: alpine:3.20
    command: ["sleep", "infinity"]
"#
    )))
    .expect("apply source");
    wait_for_pod_ready(&src, Duration::from_secs(120)).expect("source ready");
    let (src_cluster, src_index, src_in_pod) = common::pod_vm_network(&src);
    assert!(src_in_pod, "CNI source must be attached to its pod netns");
    common::assert_pod_egress(&src, "source before fork");
    let src_sandbox = common::pod_sandbox_id(&src);
    let src_cluster = src_cluster.expect("networked source has a cluster id");

    kubectl_apply(&common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {fork}
  annotations:
    k7d.katakate.org/fork-source-cluster: {src_cluster}
    k7d.katakate.org/fork-source-vm: {src_sandbox}
spec:
  runtimeClassName: k7
  restartPolicy: Never
  containers:
  - name: app
    image: alpine:3.20
    command: ["sleep", "infinity"]
"#
    )))
    .expect("apply fork");
    wait_for_pod_ready(&fork, Duration::from_secs(180)).expect("fork pod Running");

    let (fork_cluster, fork_index, fork_in_pod) = common::pod_vm_network(&fork);
    assert_eq!(
        fork_cluster.as_deref(),
        Some(common::pod_sandbox_id(&fork).as_str()),
        "fork must get its own bridge keyed by its sandbox id"
    );
    assert_eq!(
        fork_index, src_index,
        "fork TAP must carry the source's vm_index (inherited guest IP/MAC)"
    );
    assert!(
        fork_in_pod,
        "fork TAP must be attached into the fork pod netns"
    );
    common::assert_pod_egress(&fork, "fork");
    common::assert_pod_egress(&src, "source after fork");

    let _ = kubectl_delete("pod", &fork);
    let _ = kubectl_delete("pod", &src);
}

/// Half-specified `fork-source-*` annotations fail
/// sandbox Create loudly (events name the annotation keys).
#[test]
fn test_kubectl_fork_source_half_specified_fails_loud() {
    let _leak_guard = ensure_shim_installed();
    common::ensure_pod_annotations_forwarded();

    for (name, annotations) in [
        (
            common::unique_name("test-k7d-fsrc-half-vm"),
            r#"    k7d.katakate.org/fork-source-vm: "deadbeef""#,
        ),
        (
            common::unique_name("test-k7d-fsrc-half-cl"),
            r#"    k7d.katakate.org/fork-source-cluster: "orphan""#,
        ),
    ] {
        let _ = kubectl_delete("pod", &name);
        std::thread::sleep(Duration::from_secs(1));
        kubectl_apply(&common::pin_to_local_node(&format!(
            r#"
apiVersion: v1
kind: Pod
metadata:
  name: {name}
  annotations:
{annotations}
spec:
  runtimeClassName: k7
  restartPolicy: Never
  containers:
  - name: app
    image: alpine:3.20
    command: ["sleep", "infinity"]
"#
        )))
        .unwrap_or_else(|e| panic!("apply {name}: {e}"));

        let deadline = Instant::now() + Duration::from_secs(120);
        let describe = loop {
            let output = std::process::Command::new("kubectl")
                .args(["describe", "pod", &name])
                .output()
                .expect("kubectl describe");
            let describe = String::from_utf8_lossy(&output.stdout).to_string();
            // Exact fail-loud message from sandbox_create_fork_adopt.
            if describe.contains("must be set together") {
                break describe;
            }
            assert!(
                Instant::now() < deadline,
                "half-specified fork-source error never surfaced for {name}; describe:\n{describe}"
            );
            std::thread::sleep(Duration::from_secs(2));
        };
        assert!(
            describe.contains("fork-source-vm") && describe.contains("fork-source-cluster"),
            "error must name both annotation keys; describe:\n{describe}"
        );
        // Must never reach Running — Create failed.
        let phase = pod_jsonpath(&name, ".status.phase");
        assert_ne!(
            phase, "Running",
            "half-specified fork-source pod must not become Running"
        );
        let _ = kubectl_delete("pod", &name);
    }
}

/// Pause/resume a kubectl sandbox VM over `/run/k7d/k7d.sock`
/// (`PauseVm` / `ResumeVm`). While paused the guest agent must not
/// answer; after resume kubectl exec works again and a CFS-capped VM
/// keeps its vCPU TIDs in the cgroup.
#[test]
fn test_kubectl_pause_resume_over_socket() {
    let _leak_guard = ensure_shim_installed();
    let pod = common::unique_name("test-k7d-pause-sock");
    let _ = kubectl_delete("pod", &pod);
    std::thread::sleep(Duration::from_secs(2));

    kubectl_apply(&common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {pod}
spec:
  runtimeClassName: k7
  containers:
  - name: app
    image: alpine:3.20
    command: ["sleep", "infinity"]
    resources:
      limits:
        cpu: "2"
"#
    )))
    .expect("kubectl apply");
    wait_for_pod_ready(&pod, Duration::from_secs(120)).expect("pod ready");

    let pre = kubectl_exec(&pod, &["echo", "pre-pause"]).expect("exec before pause");
    assert!(pre.contains("pre-pause"));

    let sandbox_id = common::pod_sandbox_id(&pod);
    let mut daemon = k7d::control::Client::connect_env().expect("connect k7d daemon");
    let (vm_id, guest_cid) = match daemon
        .call(&k7d::control::Request::LookupSandbox {
            sandbox_id: sandbox_id.clone(),
        })
        .expect("lookup_sandbox")
    {
        k7d::control::Response::SandboxFound {
            vm_id, guest_cid, ..
        } => (vm_id, guest_cid),
        other => panic!("unexpected LookupSandbox: {other:?}"),
    };

    match daemon
        .call(&k7d::control::Request::PauseVm {
            vm_id: vm_id.clone(),
        })
        .expect("pause_vm")
    {
        k7d::control::Response::Ok => {}
        other => panic!("unexpected PauseVm: {other:?}"),
    }

    // Frozen vCPUs: a fresh vsock dial must time out (guest agent dead).
    if let Ok(_agent) = k7d::api::AgentClient::connect_vsock(guest_cid, Duration::from_secs(2)) {
        panic!("guest agent must not answer while VM is paused (cid {guest_cid})");
    }

    match daemon
        .call(&k7d::control::Request::ResumeVm {
            vm_id: vm_id.clone(),
        })
        .expect("resume_vm")
    {
        k7d::control::Response::Ok => {}
        other => panic!("unexpected ResumeVm: {other:?}"),
    }

    let mut agent = k7d::api::AgentClient::connect_vsock(guest_cid, Duration::from_secs(10))
        .expect("guest agent after resume");
    let pong = agent.ping().expect("ping after resume");
    assert!(!pong.version.is_empty());
    drop(agent);

    let post = kubectl_exec(&pod, &["echo", "post-resume"]).expect("exec after resume");
    assert!(post.contains("post-resume"));

    // Invariant: resume re-attaches fresh vCPU TIDs to the CFS cgroup.
    let cg = k7d_service_cgroup().join(format!("vm-{vm_id}"));
    assert!(
        cg.exists(),
        "CPU cgroup missing after resume: {}",
        cg.display()
    );
    assert_eq!(
        std::fs::read_to_string(cg.join("cpu.max"))
            .expect("read cpu.max")
            .trim(),
        "200000 100000"
    );
    assert_eq!(
        vcpu_comms_in_cgroup(&cg),
        ["vcpu0", "vcpu1"],
        "both vCPU TIDs must be in the CFS cgroup after resume"
    );

    let _ = kubectl_delete("pod", &pod);
}

/// / CHALLENGES #60 and #279: after an annotation-driven fork, deleting
/// both pods must clear the *source* within seconds. #60 was `Kill`
/// blocking on the dead pre-swap agent connection. #279 is the log
/// bridge holding that same connection's stdio FIFOs, so containerd
/// never gets from the container exit to sandbox `Delete` / `stop_vm`.
#[test]
fn test_kubectl_fork_source_teardown() {
    let _leak_guard = ensure_shim_installed();
    common::ensure_pod_annotations_forwarded();

    let src = common::unique_name("test-k7d-fsrc-td-a");
    let fork = common::unique_name("test-k7d-fsrc-td-b");
    let cluster_id = format!("fstd{}", std::process::id() % 10_000);
    assert!(cluster_id.len() <= 9);

    let _ = kubectl_delete("pod", &src);
    let _ = kubectl_delete("pod", &fork);
    std::thread::sleep(Duration::from_secs(2));

    kubectl_apply(&common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {src}
  annotations:
    k7d.katakate.org/cluster-id: {cluster_id}
spec:
  runtimeClassName: k7
  containers:
  - name: app
    image: alpine:3.20
    command: ["sleep", "infinity"]
    volumeMounts:
    - name: scratch
      mountPath: /scratch
  volumes:
  - name: scratch
    emptyDir: {{}}
"#
    )))
    .expect("apply source");
    wait_for_pod_ready(&src, Duration::from_secs(120)).expect("source ready");
    let src_sandbox = common::pod_sandbox_id(&src);

    kubectl_apply(&common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {fork}
  annotations:
    k7d.katakate.org/fork-source-cluster: {cluster_id}
    k7d.katakate.org/fork-source-vm: {src_sandbox}
spec:
  runtimeClassName: k7
  restartPolicy: Never
  containers:
  - name: app
    image: alpine:3.20
    command: ["sleep", "infinity"]
"#
    )))
    .expect("apply fork");
    wait_for_pod_ready(&fork, Duration::from_secs(180)).expect("fork ready");

    // Fire-and-forget delete of both; the regression is the source
    // wedging in Terminating after prepare_fork_source swapped its
    // vsock backend under the shim's cached agent connection.
    let del = std::process::Command::new("kubectl")
        .args([
            "delete",
            "pod",
            &src,
            &fork,
            "--ignore-not-found",
            "--wait=false",
            "--grace-period=1",
        ])
        .output()
        .expect("kubectl delete");
    assert!(
        del.status.success(),
        "kubectl delete --wait=false failed: {}",
        String::from_utf8_lossy(&del.stderr)
    );

    let start = Instant::now();
    let deadline = start + Duration::from_secs(30);
    loop {
        let gone = |name: &str| {
            let o = std::process::Command::new("kubectl")
                .args(["get", "pod", name, "--ignore-not-found", "-o", "name"])
                .output()
                .expect("kubectl get");
            o.status.success() && o.stdout.is_empty()
        };
        if gone(&src) && gone(&fork) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "fork-source teardown: pods still present after {:?}\n\
             source={:?} fork={:?}\n\
             (CHALLENGES #60/#279: source still up = teardown stuck on the \
              pre-swap agent connection)",
            start.elapsed(),
            pod_jsonpath(&src, ".status.phase"),
            pod_jsonpath(&fork, ".status.phase"),
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    let elapsed = start.elapsed();
    eprintln!("  ⏱  fork-source teardown (both pods gone) ........ {elapsed:?}");
    assert!(
        elapsed < Duration::from_secs(15),
        "source+fork must leave Terminating within 15s after delete, took {elapsed:?}"
    );
}

/// Bytes actually allocated on the host for `path` — a sparse scratch
/// image reports far less than its apparent length.
fn allocated_bytes(path: &std::path::Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).map_or(0, |m| m.blocks() * 512)
}

/// `k3s crictl stats -o json`, as (whole-call success, container ids
/// reported). The whole-call success is the CHALLENGES #61 canary: one
/// shim answering `Stats` with a payload containerd cannot decode fails
/// the AGGREGATE ListContainerStats, so every pod on the node loses
/// stats at once.
fn crictl_stats() -> (bool, Vec<String>) {
    let out = std::process::Command::new("k3s")
        .args(["crictl", "stats", "-o", "json"])
        .output()
        .expect("k3s crictl stats should run");
    if !out.status.success() {
        eprintln!(
            "  crictl stats failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return (false, Vec::new());
    }
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).unwrap_or(serde_json::Value::Null);
    let ids = parsed
        .get("stats")
        .and_then(|s| s.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| {
                    s.pointer("/attributes/id")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default();
    (true, ids)
}

/// Container ids of a pod, per crictl.
fn pod_container_ids(pod: &str) -> Vec<String> {
    let out = std::process::Command::new("k3s")
        .args(["crictl", "ps", "-q", "--pod", &common::pod_sandbox_id(&pod)])
        .output()
        .expect("k3s crictl ps should run");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// End to end through kubectl: `k7d.katakate.org/
/// container-scratch-size` gives the named container its own writable
/// image, so filling it is that container's `ENOSPC` while its sibling
/// keeps writing on the pod-wide disk that
/// `k7d.katakate.org/scratch-size` sized. Polling `Stats` then makes the
/// usage visible in the shim log — and never breaks the payload other
/// pods on this node depend on.
#[test]
fn test_kubectl_pod_per_container_scratch_limits() {
    let _leak_guard = ensure_shim_installed();
    // Both annotations only reach the shim when containerd forwards
    // k7d.katakate.org/* pod annotations into the OCI spec.
    common::ensure_pod_annotations_forwarded();

    // The node is shared and part of a live cluster: sample the
    // non-k7 stats surface BEFORE our pod exists, so the assertion
    // below is about our change and not about whatever else is running.
    let (baseline_ok, baseline_ids) = crictl_stats();
    assert!(
        baseline_ok,
        "crictl stats must work on this node before the test starts"
    );

    let pod = common::unique_name("test-k7d-cscratch");
    let _ = kubectl_delete("pod", &pod);
    let _pod_guard = PodGuard(pod.clone());
    std::thread::sleep(Duration::from_secs(2));

    // 64Mi for `builder`, 1Gi shared for everyone else. Both numbers
    // are storage, never memory: the pod's memory limit is deliberately
    // smaller than the write below (CHALLENGES #65).
    kubectl_apply(&common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {pod}
  annotations:
    k7d.katakate.org/scratch-size: "1Gi"
    k7d.katakate.org/container-scratch-size: "builder=64Mi"
spec:
  runtimeClassName: k7
  containers:
  - name: builder
    image: busybox:1.36
    command: ["sleep", "infinity"]
    resources:
      limits:
        memory: 256Mi
  - name: sidecar
    image: busybox:1.36
    command: ["sleep", "infinity"]
"#
    )))
    .expect("apply per-container scratch pod");
    wait_for_pod_ready(&pod, Duration::from_secs(240)).expect("pod ready");
    wait_for_all_containers_ready(&pod, Duration::from_secs(120)).expect("both containers ready");

    // Two images on the host: the pod's shared scratch and builder's own.
    let vm_id = common::pod_vm_id(&pod);
    let shared =
        std::path::PathBuf::from(k7d::disks::DISKS_DIR).join(format!("scratch-{vm_id}.img"));
    let builder = std::path::PathBuf::from(k7d::disks::DISKS_DIR)
        .join(format!("scratch-{vm_id}-c-builder.img"));
    for image in [&shared, &builder] {
        assert!(
            image.exists(),
            "no host image at {} for pod {pod}",
            image.display()
        );
    }

    // builder's writable layer is its own device: from inside the
    // container the guest's `ext4` mount is out of namespace, but its
    // rootfs overlay names the upper dir, and that is the mount point
    // the daemon attached the image at.
    let mount = k7d::disks::container_scratch_mount("builder");
    let mounts =
        kubectl_exec_c(&pod, "builder", &["cat", "/proc/mounts"]).expect("read /proc/mounts");
    assert!(
        mounts
            .lines()
            .any(|l| l.contains("overlay") && l.contains(&format!("upperdir={mount}/"))),
        "expected builder's rootfs overlay to write into its own image at {mount}, got:\n{mounts}"
    );

    // 256 MiB is 4x builder's limit and a quarter of the pod's shared
    // disk: it must fail for builder and succeed for the sidecar.
    // `; echo rc=` so the exec itself succeeds and dd's own complaint
    // comes back on stdout — only the write is expected to fail.
    let attempt = kubectl_exec_c(
        &pod,
        "builder",
        &[
            "sh",
            "-c",
            "dd if=/dev/zero of=/fill bs=1M count=256 conv=fsync 2>&1; echo rc=$?",
        ],
    )
    .expect("the exec must succeed")
    .to_ascii_lowercase();
    assert!(
        !attempt.contains("rc=0"),
        "writing 4x builder's own limit must fail, got: {attempt}"
    );
    assert!(
        attempt.contains("no space left"),
        "builder must hit a clean ENOSPC on its own device, got: {attempt}"
    );
    kubectl_exec_c(
        &pod,
        "sidecar",
        &[
            "sh",
            "-c",
            "dd if=/dev/zero of=/big bs=1M count=256 conv=fsync",
        ],
    )
    .expect("the sidecar must keep writing past the limit that stopped builder");

    // Stats: the numbers reach the shim log (builder is over the
    // high-water mark, having just filled its image), and the aggregate
    // call still works for every container on the node — including the
    // ones that were there before this pod.
    let log = std::path::Path::new("/tmp/k7-shim.log");
    let before = std::fs::metadata(log).map_or(0, |m| m.len());
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut saw_usage = false;
    while Instant::now() < deadline && !saw_usage {
        let (ok, ids) = crictl_stats();
        assert!(ok, "crictl stats must keep working while k7 pods report");
        for id in pod_container_ids(&pod) {
            assert!(
                ids.contains(&id),
                "container {id} of {pod} is missing from crictl stats"
            );
        }
        std::thread::sleep(Duration::from_secs(3));
        let tail = std::fs::read_to_string(log).unwrap_or_default();
        saw_usage = tail
            .get(before as usize..)
            .unwrap_or(&tail)
            .lines()
            .any(|l| l.contains("ephemeral storage") && l.contains("%"));
    }
    assert!(
        saw_usage,
        "no per-container ephemeral-storage line in {} after polling Stats — \
         a full writable layer would be invisible",
        log.display()
    );

    // CHALLENGES #61 from the other direction: a pod that has nothing
    // to do with k7 still reports stats.
    let (ok, ids) = crictl_stats();
    assert!(ok, "crictl stats must still succeed node-wide");
    let surviving = baseline_ids.iter().filter(|id| ids.contains(id)).count();
    assert!(
        surviving > 0,
        "no non-k7 container from the pre-test baseline ({} sampled) still reports stats — \
         the shim's Stats payload is poisoning ListContainerStats node-wide",
        baseline_ids.len()
    );

    // Both images are scratch: deleting the pod takes them with it.
    kubectl_delete("pod", &pod).expect("delete pod");
    let deadline = Instant::now() + Duration::from_secs(60);
    while shared.exists() || builder.exists() {
        assert!(
            Instant::now() < deadline,
            "host images survived pod deletion (leak): shared={} builder={}",
            shared.exists(),
            builder.exists()
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// A pod on the **stock** runtime keeps reporting container
/// stats while a k7 pod on the same node is answering `Stats`. This is
/// CHALLENGES #61's blast radius — the shim's payload is decoded inside
/// containerd's node-wide `ListContainerStats`, so getting it wrong
/// takes out pods that never went near k7. Both pods have to be running
/// at once for the test to mean anything.
#[test]
fn test_non_k7_pod_still_reports_stats_beside_a_k7_pod() {
    let _leak_guard = ensure_shim_installed();

    let stock = common::unique_name("test-k7d-stock-stats");
    let k7 = common::unique_name("test-k7d-stats-neighbour");
    let _ = kubectl_delete("pod", &stock);
    let _ = kubectl_delete("pod", &k7);
    let _stock_guard = PodGuard(stock.clone());
    let _k7_guard = PodGuard(k7.clone());
    std::thread::sleep(Duration::from_secs(2));

    // No runtimeClassName: stock containerd + runc, pinned to this node.
    kubectl_apply(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {stock}
spec:
  nodeSelector:
    kubernetes.io/hostname: "{host}"
  containers:
  - name: app
    image: busybox:1.36
    command: ["sleep", "infinity"]
"#,
        host = common::current_hostname()
    ))
    .expect("apply stock-runtime pod");
    kubectl_apply(&common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {k7}
spec:
  runtimeClassName: k7
  containers:
  - name: app
    image: busybox:1.36
    command: ["sleep", "infinity"]
"#
    )))
    .expect("apply k7 pod");
    wait_for_pod_ready(&stock, Duration::from_secs(180)).expect("stock pod ready");
    wait_for_pod_ready(&k7, Duration::from_secs(240)).expect("k7 pod ready");

    let want = pod_container_ids(&stock);
    assert!(!want.is_empty(), "no CRI containers for {stock}");
    let k7_containers = pod_container_ids(&k7);
    assert!(!k7_containers.is_empty(), "no CRI containers for {k7}");

    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let (ok, ids) = crictl_stats();
        assert!(
            ok,
            "node-wide crictl stats must succeed while a k7 pod answers Stats — \
             a malformed shim payload fails the whole aggregate call"
        );
        if want.iter().all(|id| ids.contains(id)) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "stock-runtime container(s) {want:?} never appeared in crictl stats \
             ({} reported) while {k7} was running",
            ids.len()
        );
        std::thread::sleep(Duration::from_secs(3));
    }

    kubectl_delete("pod", &k7).expect("delete k7 pod");
    kubectl_delete("pod", &stock).expect("delete stock pod");
}

/// End to end through kubectl: a pod annotated with
/// `k7d.katakate.org/scratch-size` writes more than its guest RAM to
/// its container filesystem, reads it back intact, and the bytes land
/// on a host image that is removed when the pod goes away — none of
/// which the old RAM-backed `tmpfs` upper could do.
#[test]
fn test_kubectl_pod_scratch_disk_off_guest_ram() {
    let _leak_guard = ensure_shim_installed();
    // The scratch-size annotation only reaches the shim when containerd
    // forwards k7d.katakate.org/* pod annotations into the OCI spec.
    common::ensure_pod_annotations_forwarded();

    let pod = common::unique_name("test-k7d-scratch");
    let _ = kubectl_delete("pod", &pod);
    let _pod_guard = PodGuard(pod.clone());
    std::thread::sleep(Duration::from_secs(2));

    // 512Mi limit ⇒ a ~576 MB guest (adds 64 MB overhead), so
    // the 1 GiB write below is comfortably more than guest RAM and more
    // than double what a 50%-of-RAM tmpfs upper would have allowed.
    kubectl_apply(&common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {pod}
  annotations:
    k7d.katakate.org/scratch-size: "4Gi"
spec:
  runtimeClassName: k7
  containers:
  - name: app
    image: busybox:1.36
    command: ["sleep", "infinity"]
    resources:
      limits:
        memory: 512Mi
"#
    )))
    .expect("apply scratch pod");
    wait_for_pod_ready(&pod, Duration::from_secs(180)).expect("scratch pod ready");

    // The daemon named the image after the VM it belongs to.
    let vm_id = common::pod_vm_id(&pod);
    let image =
        std::path::PathBuf::from(k7d::disks::DISKS_DIR).join(format!("scratch-{vm_id}.img"));
    assert!(
        image.exists(),
        "no host scratch image at {} for pod {pod}",
        image.display()
    );

    let mem_before = kubectl_exec(&pod, &["grep", "MemAvailable", "/proc/meminfo"])
        .expect("read guest MemAvailable");
    let mem_before: u64 = mem_before
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| panic!("cannot parse MemAvailable out of {mem_before:?}"));
    let allocated_before = allocated_bytes(&image);

    let write_mib = 1024u32;
    let digest_hot = kubectl_exec(
        &pod,
        &[
            "sh",
            "-c",
            &format!(
                "dd if=/dev/urandom of=/big bs=1M count={write_mib} conv=fsync 2>/dev/null && \
                 md5sum /big | cut -d' ' -f1"
            ),
        ],
    )
    .unwrap_or_else(|e| {
        panic!("writing {write_mib} MiB into the container filesystem failed: {e}")
    });
    let digest_hot = digest_hot.trim().to_string();
    assert!(!digest_hot.is_empty(), "md5sum produced no digest");

    // Re-read it. The file is larger than the whole guest, so most of
    // it necessarily comes back off the virtio-blk device rather than
    // out of the page cache — a matching digest is proof the bytes are
    // on the host image and intact.
    let digest_cold = kubectl_exec(&pod, &["sh", "-c", "md5sum /big | cut -d' ' -f1"])
        .expect("re-read the file")
        .trim()
        .to_string();
    assert_eq!(
        digest_hot, digest_cold,
        "{write_mib} MiB read back off the scratch disk does not match what was written"
    );

    let grew_mib = allocated_bytes(&image).saturating_sub(allocated_before) / (1024 * 1024);
    assert!(
        grew_mib >= u64::from(write_mib) * 9 / 10,
        "host scratch image {} grew by only {grew_mib} MiB for a {write_mib} MiB write",
        image.display()
    );

    let mem_after = kubectl_exec(&pod, &["grep", "MemAvailable", "/proc/meminfo"])
        .expect("read guest MemAvailable again");
    let mem_after: u64 = mem_after
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| panic!("cannot parse MemAvailable out of {mem_after:?}"));
    let dropped_mib = mem_before.saturating_sub(mem_after) / 1024;
    assert!(
        dropped_mib < 128,
        "guest MemAvailable fell {dropped_mib} MiB while writing {write_mib} MiB \
         (before={mem_before} kB after={mem_after} kB) — the writes are landing in RAM"
    );

    // Scratch is scratch: deleting the pod takes the host image with it.
    kubectl_delete("pod", &pod).expect("delete scratch pod");
    let deadline = Instant::now() + Duration::from_secs(60);
    while image.exists() {
        assert!(
            Instant::now() < deadline,
            "host scratch image {} survived pod deletion (leak)",
            image.display()
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}
