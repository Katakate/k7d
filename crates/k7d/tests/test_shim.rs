//! Integration tests for milestone 6: containerd shim.
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
    eprintln!("  Kernel dmesg (key boot milestones):");
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

/// Ensure the shim binary is built (release), installed, containerd config
/// has the k7 runtime, RuntimeClass exists, and k3s is running.
/// This is idempotent — safe to call before every kubectl test.
fn ensure_shim_installed() -> common::LeakGuard {
    use std::process::Command;

    // internal notes, Milestone 2: best-effort teardown of orphan
    // virtiofsd/shim processes and stale /tmp/k7d-shim mounts left by
    // earlier tests/binaries before we (re)install the shim.
    common::cleanup_k7_runtime_leaks();

    let shim_src = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("target/release/containerd-shim-k7-v1");

    // Always build: cargo no-ops in ~a second when the binary is
    // fresh, and skipping the build when `shim_src` merely *exists*
    // deploys a stale shim after source edits (bit us twice — the
    // increment-4 crash-recovery hooks were first tested against the
    // increment-3 binary; see `ensure_k7d_daemon_running` for the
    // first time).
    let status = Command::new("cargo")
        .args(["build", "--release", "-p", "containerd-shim-k7-v1"])
        .status()
        .expect("cargo build should run");
    assert!(status.success(), "shim build failed");

    let installed = std::path::Path::new("/usr/local/bin/containerd-shim-k7-v1");
    let need_install = if installed.exists() {
        let src_meta = std::fs::metadata(&shim_src).unwrap();
        let dst_meta = std::fs::metadata(installed).unwrap();
        src_meta.len() != dst_meta.len()
            || src_meta.modified().unwrap() > dst_meta.modified().unwrap()
    } else {
        true
    };

    if need_install {
        eprintln!("  installing shim to /usr/local/bin/");
        let _ = Command::new("pkill")
            .args(["-9", "-f", "containerd-shim-k7-v1"])
            .status();
        std::thread::sleep(Duration::from_millis(500));
        // Unlink first: copying over a binary some straggler shim still
        // executes fails with ETXTBSY; a fresh inode never does.
        let _ = std::fs::remove_file(installed);
        std::fs::copy(&shim_src, installed).expect("copy shim binary");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(installed, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let _ = Command::new("systemctl").args(["restart", "k3s"]).status();
        common::wait_for_k3s_ready();
    }

    let rc_check = Command::new("kubectl")
        .args(["get", "runtimeclass", "k7"])
        .output()
        .expect("kubectl should run");
    if !rc_check.status.success() {
        eprintln!("  creating RuntimeClass k7");
        let _ = Command::new("kubectl")
            .args(["apply", "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child.stdin.as_mut().unwrap().write_all(
                    b"apiVersion: node.k8s.io/v1\nkind: RuntimeClass\nmetadata:\n  name: k7\nhandler: k7\n",
                ).unwrap();
                child.wait()
            })
            .expect("create RuntimeClass");
    }

    // internal notes: the shim's sandbox Create now requires a running k7d
    // daemon (it owns the VMs); install and start it.
    common::ensure_k7d_daemon_running();

    common::LeakGuard
}

fn kubectl_apply(yaml: &str) -> Result<(), String> {
    let output = std::process::Command::new("kubectl")
        .args(["apply", "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(yaml.as_bytes())
                .unwrap();
            child.wait_with_output()
        })
        .map_err(|e| format!("kubectl apply failed: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// internal notes, Phase B0 — defence-in-depth alongside the spec-10h
/// product fix that unblocks the test_volumes trio.
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

    timed!("kubectl delete (cleanup)", {
        let _ = kubectl_delete("pod", "test-k7d-shim");
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
        wait_for_pod_ready("test-k7d-shim", Duration::from_secs(120)).unwrap()
    });
    eprintln!("       (pod ready latency: {pod_ready_time:.2?})");

    timed!("kubectl exec: echo", {
        let output = kubectl_exec("test-k7d-shim", &["echo", "k7d works"]).unwrap();
        assert_eq!(output.trim(), "k7d works");
    });

    timed!("kubectl exec: cat /proc/cmdline", {
        let cmdline = kubectl_exec("test-k7d-shim", &["cat", "/proc/cmdline"]).unwrap();
        assert!(
            cmdline.contains("virtio_mmio.device="),
            "should run in our KVM VM"
        );
    });

    // internal notes: a volume-less kubectl pod rides the block path —
    // ZERO virtiofs shares (rootfs is a cached erofs image on
    // virtio-blk, runc comes from the tools erofs image), so the pod
    // stays CoW-warm-forkable.
    timed!("daemon vm_status: zero-virtiofs invariant", {
        let vm = common::pod_vm_state("test-k7d-shim");
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
    });

    timed!("kubectl delete pod", {
        kubectl_delete("pod", "test-k7d-shim").unwrap();
    });

    let delete_time = timed!("Wait for pod gone", {
        wait_for_pod_gone("test-k7d-shim", Duration::from_secs(30)).unwrap()
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

/// internal notes: a kubectl pod with only block-supported volume
/// classes (emptyDir here) warm-forks on the CoW path end to end
/// through the daemon — the fork's memory is `MAP_PRIVATE` CoW over
/// the source snapshot, NOT a full memfd copy, and the forked guest
/// answers on vsock.
#[test]
fn test_kubectl_pod_block_path_warm_fork_cow() {
    let _leak_guard = ensure_shim_installed();
    let _ = kubectl_delete("pod", "test-k7d-cowfork");
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
    wait_for_pod_ready("test-k7d-cowfork", Duration::from_secs(120)).unwrap();

    let src = common::pod_vm_state("test-k7d-cowfork");
    assert_eq!(
        src.virtiofs_shares, 0,
        "emptyDir pod must be block-backed (zero virtiofs)"
    );

    // Fork through the daemon. internal notes: preparing a share-less
    // fork source swaps the VM for a restored copy on the SAME vsock
    // CID (historically a new CID — CHALLENGES.md #39 — which broke
    // every later kubectl exec against the source); the post-fork
    // exec below proves the pod's shim-cached CID still answers.
    let mut daemon = k7d::control::Client::connect_env().expect("connect k7d daemon");
    let forked = daemon
        .call(&k7d::control::Request::ForkVm {
            vm_id: src.vm_id.clone(),
        })
        .expect("fork_vm");
    let (fork_id, fork_cid) = match forked {
        k7d::control::Response::VmForked {
            vm_id, guest_cid, ..
        } => (vm_id, guest_cid),
        other => panic!("unexpected fork_vm response: {other:?}"),
    };

    // The CoW invariant this whole spec exists for: no virtiofs ⇒
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
        .args(["exec", "test-k7d-cowfork", "--", "echo", "src-alive"])
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
    let _ = kubectl_delete("pod", "test-k7d-cowfork");
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
struct PodGuard(&'static str);
impl Drop for PodGuard {
    fn drop(&mut self) {
        let _ = kubectl_delete("pod", self.0);
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

/// internal notes: a kubectl pod with two containers of DISTINCT
/// images. The VM boots at the first workload Create with only that
/// container's rootfs attached; the second image arrives post-boot
/// and rides a spare image slot (host FICLONE/copy fill + agent
/// `mount_blk`). Exec, logs, and a shared emptyDir must work in both.
#[test]
fn test_kubectl_pod_two_images() {
    let _leak_guard = ensure_shim_installed();
    let _ = kubectl_delete("pod", "test-k7d-twoimg");
    let _pod_guard = PodGuard("test-k7d-twoimg");
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
    wait_for_pod_ready("test-k7d-twoimg", Duration::from_secs(180)).unwrap();
    wait_for_all_containers_ready("test-k7d-twoimg", Duration::from_secs(60)).unwrap();

    // Exec works in BOTH containers (both rootfs mounts are live).
    let out = kubectl_exec_c("test-k7d-twoimg", "web", &["sh", "-c", "echo web-ok"]).unwrap();
    assert_eq!(out.trim(), "web-ok");
    let out = kubectl_exec_c("test-k7d-twoimg", "side", &["sh", "-c", "echo side-ok"]).unwrap();
    assert_eq!(out.trim(), "side-ok");

    // The images are genuinely distinct: nginx exists in web only.
    let out =
        kubectl_exec_c("test-k7d-twoimg", "web", &["nginx", "-v"]).map(|o| o.trim().to_string());
    // nginx -v prints to stderr; success of the exec is the signal.
    assert!(out.is_ok(), "nginx binary must exist in web: {out:?}");
    let err = kubectl_exec_c("test-k7d-twoimg", "side", &["nginx", "-v"])
        .expect_err("busybox side container must NOT have nginx");
    assert!(!err.is_empty());

    // Shared emptyDir is visible from both sides.
    kubectl_exec_c(
        "test-k7d-twoimg",
        "side",
        &["sh", "-c", "echo cross-container > /shared/x"],
    )
    .unwrap();
    let out = kubectl_exec_c("test-k7d-twoimg", "web", &["cat", "/shared/x"]).unwrap();
    assert_eq!(out.trim(), "cross-container");

    // Logs from both containers. nginx logs access lines to stdout —
    // generate them over pod-local loopback, from the web container
    // itself AND from the sidecar (containers of a pod share the
    // guest netns, so cross-container localhost must work).
    kubectl_exec_c(
        "test-k7d-twoimg",
        "web",
        &["wget", "-qO-", "http://127.0.0.1/"],
    )
    .unwrap();
    kubectl_exec_c(
        "test-k7d-twoimg",
        "side",
        &["wget", "-qO-", "http://127.0.0.1/"],
    )
    .unwrap();
    let side_logs = kubectl_logs_c("test-k7d-twoimg", "side").unwrap();
    assert!(side_logs.contains("side-started"), "side logs: {side_logs}");
    let web_logs = kubectl_logs_c("test-k7d-twoimg", "web").unwrap();
    assert!(web_logs.contains("GET /"), "web logs: {web_logs}");

    // The pod stays on the zero-virtiofs block path; the device list
    // includes tools + boot rootfs + the 4 default spare slots.
    let vm = common::pod_vm_state("test-k7d-twoimg");
    assert_eq!(
        vm.virtiofs_shares, 0,
        "two-image pod must stay zero-virtiofs"
    );
    assert!(
        vm.block_devices >= 6,
        "expected tools + rootfs + 4 spare slots, got {}",
        vm.block_devices
    );

    kubectl_delete("pod", "test-k7d-twoimg").unwrap();
}

/// internal notes: a two-distinct-image pod on the zero-virtiofs
/// block path warm-forks via the daemon on the CoW path
/// (`fork_memory_full_copy == false`). Image slots are RO virtio-blk
/// by construction and must not force a full memfd copy; the forked
/// guest answers on vsock and the source pod's CID stays usable.
#[test]
fn test_multi_image_pod_warm_fork_cow() {
    let _leak_guard = ensure_shim_installed();
    let _ = kubectl_delete("pod", "test-k7d-mimg-cow");
    let _pod_guard = PodGuard("test-k7d-mimg-cow");
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
    wait_for_pod_ready("test-k7d-mimg-cow", Duration::from_secs(180)).unwrap();
    wait_for_all_containers_ready("test-k7d-mimg-cow", Duration::from_secs(60)).unwrap();

    let src = common::pod_vm_state("test-k7d-mimg-cow");
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
        .args([
            "exec",
            "test-k7d-mimg-cow",
            "-c",
            "side",
            "--",
            "echo",
            "src-alive",
        ])
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
    let _ = kubectl_delete("pod", "test-k7d-mimg-cow");
}

/// internal notes: more distinct images than spare slots must fail
/// LOUD, with the workload Create error naming the
/// `k7d.katakate.org/image-slots` annotation (visible in pod events).
#[test]
fn test_image_slot_exhaustion_fails_loud() {
    let _leak_guard = ensure_shim_installed();
    // The image-slots annotation only reaches the shim when containerd
    // forwards k7d.katakate.org/* pod annotations into the OCI spec.
    common::ensure_pod_annotations_forwarded();
    let _ = kubectl_delete("pod", "test-k7d-slotfull");
    let _pod_guard = PodGuard("test-k7d-slotfull");
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
            .args(["describe", "pod", "test-k7d-slotfull"])
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
    // The error must name the annotation knob.
    let event_tail = describe
        .split("no free image slot")
        .nth(1)
        .expect("split on matched needle");
    assert!(
        event_tail.contains("k7d.katakate.org/image-slots"),
        "exhaustion error must name the image-slots annotation; describe:\n{describe}"
    );

    let _ = kubectl_delete("pod", "test-k7d-slotfull");
}

fn pod_jsonpath(name: &str, path: &str) -> String {
    let output = std::process::Command::new("kubectl")
        .args(["get", "pod", name, "-o", &format!("jsonpath={{{path}}}")])
        .output()
        .expect("kubectl get");
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// internal notes: a container that exits ON ITS OWN (no Kill) must be
/// reported Terminated with its REAL exit code, and
/// `restartPolicy: Always` must then restart it (new containerd id;
/// the same image dedupes onto the existing erofs mount).
#[test]
fn test_container_natural_exit() {
    let _leak_guard = ensure_shim_installed();
    let _ = kubectl_delete("pod", "test-k7d-natexit");
    let _pod_guard = PodGuard("test-k7d-natexit");
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
        let id = pod_jsonpath(
            "test-k7d-natexit",
            ".status.containerStatuses[0].containerID",
        );
        if !id.is_empty() {
            let rc = pod_jsonpath(
                "test-k7d-natexit",
                ".status.containerStatuses[0].restartCount",
            );
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
            "test-k7d-natexit",
            ".status.containerStatuses[0].lastState.terminated.exitCode",
        );
        let current = pod_jsonpath(
            "test-k7d-natexit",
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
        let restart_count = pod_jsonpath(
            "test-k7d-natexit",
            ".status.containerStatuses[0].restartCount",
        );
        let running = pod_jsonpath(
            "test-k7d-natexit",
            ".status.containerStatuses[0].state.running.startedAt",
        );
        let id = pod_jsonpath(
            "test-k7d-natexit",
            ".status.containerStatuses[0].containerID",
        );
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

    kubectl_delete("pod", "test-k7d-natexit").unwrap();
}

/// internal notes: init containers sequence end-to-end with NO shim
/// special-casing — kubelet drives plain CRI Create/Start/Wait off
/// the natural-exit observation (Inc 2) and the distinct init image
/// rides a spare slot (Inc 1). Two init containers run IN ORDER
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
    let _ = kubectl_delete("pod", "test-k7d-initseq");
    let _pod_guard = PodGuard("test-k7d-initseq");
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
    wait_for_pod_ready("test-k7d-initseq", Duration::from_secs(240)).unwrap();
    wait_for_all_containers_ready("test-k7d-initseq", Duration::from_secs(60)).unwrap();

    // Both init containers report Terminated/Completed with the REAL
    // exit code 0 (Inc 2 natural-exit observation).
    for (idx, name) in [(0, "init-marker"), (1, "init-same")] {
        let got_name = pod_jsonpath(
            "test-k7d-initseq",
            &format!(".status.initContainerStatuses[{idx}].name"),
        );
        assert_eq!(got_name, name, "init container order in pod status");
        let exit_code = pod_jsonpath(
            "test-k7d-initseq",
            &format!(".status.initContainerStatuses[{idx}].state.terminated.exitCode"),
        );
        assert_eq!(exit_code, "0", "{name} must terminate with exit 0");
        let reason = pod_jsonpath(
            "test-k7d-initseq",
            &format!(".status.initContainerStatuses[{idx}].state.terminated.reason"),
        );
        assert_eq!(reason, "Completed", "{name} termination reason");
    }

    // Ordering straight from pod status: each stage may only start
    // after the previous one finished. Kubelet timestamps are RFC3339
    // UTC of equal length, so lexicographic comparison is
    // chronological.
    let init1_finished = pod_jsonpath(
        "test-k7d-initseq",
        ".status.initContainerStatuses[0].state.terminated.finishedAt",
    );
    let init2_started = pod_jsonpath(
        "test-k7d-initseq",
        ".status.initContainerStatuses[1].state.terminated.startedAt",
    );
    let init2_finished = pod_jsonpath(
        "test-k7d-initseq",
        ".status.initContainerStatuses[1].state.terminated.finishedAt",
    );
    let main_started = pod_jsonpath(
        "test-k7d-initseq",
        ".status.containerStatuses[0].state.running.startedAt",
    );
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
    let main_logs = kubectl_logs_c("test-k7d-initseq", "main").unwrap();
    assert!(
        main_logs.contains("main-saw-marker"),
        "main must see the init marker at startup; logs: {main_logs}"
    );
    let out = kubectl_exec_c("test-k7d-initseq", "main", &["cat", "/shared/init-done"]).unwrap();
    assert_eq!(out.trim(), "from-init");

    // ── Same-image share survives init Delete ──
    // Remove the exited alpine init through the CRI, exactly like
    // kubelet's container GC would. The shim's Delete releases the
    // init's claim on the shared erofs key and must NOT unmount the
    // rootfs the main container still runs from (it fails loud if
    // the refcount invariant is violated — which would fail the rm).
    let main_id_before = pod_jsonpath(
        "test-k7d-initseq",
        ".status.containerStatuses[0].containerID",
    );
    let sandbox_id = common::pod_sandbox_id("test-k7d-initseq");
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
    let out = kubectl_exec_c("test-k7d-initseq", "main", &["cat", "/etc/os-release"]).unwrap();
    assert!(out.contains("Alpine"), "rootfs read after init rm: {out}");
    let out = kubectl_exec_c(
        "test-k7d-initseq",
        "main",
        &["sh", "-c", "echo still-alive"],
    )
    .unwrap();
    assert_eq!(out.trim(), "still-alive");

    // And the removal did not disturb the main container.
    std::thread::sleep(Duration::from_secs(3));
    let main_id_after = pod_jsonpath(
        "test-k7d-initseq",
        ".status.containerStatuses[0].containerID",
    );
    assert_eq!(
        main_id_before, main_id_after,
        "main must not be restarted when the exited init is removed"
    );

    kubectl_delete("pod", "test-k7d-initseq").unwrap();
}

/// internal notes: two containers with different memory limits.
/// Guest runc enforces each cgroup independently — a 40 Mi write
/// OOMs inside the 32Mi container but succeeds in the 256Mi sibling.
/// (Assert via kubectl exec rather than kubelet OOMKilled: Inc 2
/// exit observation is not required for limit enforcement.)
#[test]
fn test_kubectl_pod_per_container_memory_limits() {
    let _leak_guard = ensure_shim_installed();
    let _ = kubectl_delete("pod", "test-k7d-ctrmem");
    let _pod_guard = PodGuard("test-k7d-ctrmem");
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
    wait_for_pod_ready("test-k7d-ctrmem", Duration::from_secs(180)).unwrap();
    wait_for_all_containers_ready("test-k7d-ctrmem", Duration::from_secs(60)).unwrap();

    // 40 Mi into the overlay tmpfs: over small's 32Mi cgroup limit,
    // under big's 256Mi. Guest OOM kills the small exec (exit 137).
    let small_hog = kubectl_exec_c(
        "test-k7d-ctrmem",
        "small",
        &["dd", "if=/dev/zero", "of=/tmp/hog", "bs=1M", "count=40"],
    );
    assert!(
        small_hog.is_err(),
        "40Mi write in 32Mi cgroup must fail, got: {small_hog:?}"
    );
    let err = small_hog.unwrap_err();
    assert!(
        err.contains("137") || err.contains("Killed") || err.contains("oom"),
        "small hog should look like OOM/SIGKILL, got: {err}"
    );

    // Same write in the sibling must succeed — proves the limits are
    // per-container, not a shared VM-wide cap alone.
    kubectl_exec_c(
        "test-k7d-ctrmem",
        "big",
        &["dd", "if=/dev/zero", "of=/tmp/hog", "bs=1M", "count=40"],
    )
    .expect("40Mi write in 256Mi cgroup must succeed");
    let out = kubectl_exec_c("test-k7d-ctrmem", "big", &["echo", "still-alive"]).unwrap();
    assert!(out.contains("still-alive"));

    // Small's main process survived the exec OOM (process-level).
    let out = kubectl_exec_c("test-k7d-ctrmem", "small", &["echo", "small-alive"]).unwrap();
    assert!(out.contains("small-alive"));

    let _ = kubectl_delete("pod", "test-k7d-ctrmem");
}

/// kubectl logs latency.
#[test]
fn test_kubectl_logs_works() {
    let total = Instant::now();
    eprintln!("\n=== test_kubectl_logs_works: latency report ===");

    let _leak_guard = ensure_shim_installed();

    let _ = kubectl_delete("pod", "test-k7d-logs");
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
        wait_for_pod_ready("test-k7d-logs", Duration::from_secs(120)).unwrap();
    });

    std::thread::sleep(Duration::from_secs(3));

    timed!("kubectl logs", {
        let logs = kubectl_logs("test-k7d-logs").unwrap();
        assert!(logs.contains("hello-from-k7d"), "kubectl logs: {:?}", logs);
    });

    timed!("kubectl delete + cleanup", {
        kubectl_delete("pod", "test-k7d-logs").unwrap();
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

    let _ = kubectl_delete("pod", "test-k7d-exec");
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
        wait_for_pod_ready("test-k7d-exec", Duration::from_secs(120)).unwrap();
    });

    timed!("kubectl exec: echo (1st)", {
        let output = kubectl_exec("test-k7d-exec", &["echo", "k7d-exec"]).unwrap();
        assert_eq!(output.trim(), "k7d-exec");
    });

    timed!("kubectl exec: write file", {
        kubectl_exec("test-k7d-exec", &["sh", "-c", "echo persist > /tmp/test"]).unwrap();
    });

    timed!("kubectl exec: read file", {
        let read = kubectl_exec("test-k7d-exec", &["cat", "/tmp/test"]).unwrap();
        assert_eq!(read.trim(), "persist");
    });

    timed!("5x sequential kubectl exec", {
        for i in 0..5 {
            let r = kubectl_exec("test-k7d-exec", &["echo", &format!("iter-{i}")]).unwrap();
            assert_eq!(r.trim(), format!("iter-{i}"));
        }
    });

    timed!("kubectl delete", {
        kubectl_delete("pod", "test-k7d-exec").unwrap();
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

/// internal notes� crash recovery: killing a pod's shim must
/// not wedge the pod or leak its VM.
///
/// Empirically (k3s 1.36 / containerd 2.3), containerd does NOT
/// respawn a killed shim: kubelet stops the dead sandbox (containerd
/// runs the shim binary's `delete` subcommand — cleanup-after-dead-
/// shim) and recreates it under a NEW sandbox id. This test therefore
/// asserts the two things a crashed shim must guarantee:
///
/// 1. the orphaned VM is stopped in the k7d daemon and its reattach
///    record removed (pre-increment-4 it leaked forever, and its
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

    let _ = kubectl_delete("pod", "test-k7d-crash");
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
        wait_for_pod_ready("test-k7d-crash", Duration::from_secs(120)).unwrap();
    });

    timed!("kubectl exec: write marker", {
        kubectl_exec("test-k7d-crash", &["sh", "-c", "echo persist > /tmp/m"]).unwrap();
        let read = kubectl_exec("test-k7d-crash", &["cat", "/tmp/m"]).unwrap();
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
                .args([
                    "get",
                    "pod",
                    "test-k7d-crash",
                    "-o",
                    "jsonpath={.status.phase}",
                ])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default();
            if phase == "Running" {
                if let Ok(out) = kubectl_exec("test-k7d-crash", &["echo", "recovered"]) {
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
        kubectl_delete("pod", "test-k7d-crash").unwrap();
        wait_for_pod_gone("test-k7d-crash", Duration::from_secs(30)).unwrap();
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

    let _ = kubectl_delete("pod", "test-k7d-cleanup");
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
        wait_for_pod_ready("test-k7d-cleanup", Duration::from_secs(120)).unwrap();
    });

    timed!("kubectl delete pod", {
        kubectl_delete("pod", "test-k7d-cleanup").unwrap();
    });

    let teardown = timed!("Wait for pod gone (VM shutdown + cleanup)", {
        wait_for_pod_gone("test-k7d-cleanup", Duration::from_secs(30)).unwrap()
    });
    eprintln!("       (teardown latency: {teardown:.2?})");

    eprintln!("  ⏱  {:.<50} {:>8.2?}", "TOTAL", total.elapsed());
    eprintln!();
}

// ── internal notes: multi-vCPU kubectl / annotation path ───────────────────

/// The k7d daemon's cgroup v2 directory (per-VM CPU cgroups live here).
fn k7d_service_cgroup() -> std::path::PathBuf {
    use std::process::Command;
    let out = Command::new("systemctl")
        .args(["show", "-p", "MainPID", "--value", "k7d"])
        .output()
        .expect("systemctl show k7d");
    let pid: u32 = String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("k7d MainPID");
    assert!(pid > 0, "k7d.service has no main PID — is it running?");
    let cg = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).expect("read k7d cgroup");
    let rel = cg
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .expect("cgroup v2 entry")
        .trim();
    std::path::PathBuf::from("/sys/fs/cgroup").join(rel.trim_start_matches('/'))
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

/// internal notes: a kubectl pod with `cpu: "2"` warm-forks via the daemon;
/// the child sees 2 CPUs and both vCPU TIDs land in a CFS-capped
/// cgroup (`vcpu0`/`vcpu1`). Also asserts the sandbox reattach record
/// persisted `vcpus: 2`.
#[test]
fn test_kubectl_pod_multi_vcpu_fork() {
    let _leak_guard = ensure_shim_installed();
    let pod = "test-k7d-mvcpu-fork";
    let _ = kubectl_delete("pod", pod);
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
    wait_for_pod_ready(pod, Duration::from_secs(120)).expect("pod ready");

    let nproc = kubectl_exec(pod, &["nproc"]).expect("nproc");
    assert_eq!(nproc.trim(), "2", "cpu: \"2\" pod must see 2 vCPUs");

    let src = common::pod_vm_state(pod);
    let sandbox_id = common::pod_sandbox_id(pod);
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
    let src_alive = kubectl_exec(pod, &["echo", "src-alive"]).expect("kubectl exec source");
    assert!(src_alive.contains("src-alive"));

    let _ = daemon.call(&k7d::control::Request::StopVm { vm_id: fork_id });
    let _ = kubectl_delete("pod", pod);
}

/// internal notes: annotation-driven cluster fork with mixed per-member vCPU
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
        format!("test-k7d-mixvcpu-0-{}", std::process::id()),
        format!("test-k7d-mixvcpu-1-{}", std::process::id()),
        format!("test-k7d-mixvcpu-2-{}", std::process::id()),
    ];
    let vcpu_counts: [u32; 3] = [1, 2, 1];
    let trigger = format!("test-k7d-mixvcpu-trig-{}", std::process::id());
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
        wait_for_pod_ready(pod, Duration::from_secs(180))
            .unwrap_or_else(|e| panic!("pod {pod} ready: {e}"));
    }
    for (pod, &want) in pods.iter().zip(&vcpu_counts) {
        let nproc = kubectl_exec(pod, &["nproc"]).expect("nproc");
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

    let mut daemon = k7d::control::Client::connect_env().expect("connect k7d daemon");
    match daemon.call(&k7d::control::Request::TreeNodes {
        tree_id: tree_id.clone(),
    }) {
        Ok(k7d::control::Response::TreeNodeList { nodes }) => {
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
