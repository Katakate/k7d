//! Integration test for Milestone 5: Container lifecycle inside VM.
//! Requires KVM (/dev/kvm), vhost-vsock, virtiofsd, runc in guest rootfs,
//! built guest kernel with namespaces/cgroups, and built initramfs.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use k7d::api::{AgentClient, AgentError, PtyEvent, PtyExecSession};
use k7d::vm::Vm;
use k7d::vsock::allocate_cid;

fn workspace_path(relative: &str) -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join(relative)
}

/// Place the runc binary on the virtiofs share so the guest agent can find it.
fn place_runc_on_virtiofs(state_dir: &Path) {
    let runc_src = workspace_path("guest/rootfs/runc.amd64");
    assert!(
        runc_src.exists(),
        "runc.amd64 not found at {runc_src:?} — download it: \
         curl -fsSL https://github.com/opencontainers/runc/releases/download/v1.2.5/runc.amd64 \
         -o guest/rootfs/runc.amd64 && chmod +x guest/rootfs/runc.amd64"
    );
    let runc_dst = state_dir.join("bin");
    std::fs::create_dir_all(&runc_dst).unwrap();
    std::fs::copy(&runc_src, runc_dst.join("runc")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            runc_dst.join("runc"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
}

/// Prepare a minimal OCI bundle at `state_dir/containers/{name}/`
/// with default entrypoint `sleep infinity`.
fn prepare_oci_bundle(state_dir: &Path, name: &str) {
    prepare_oci_bundle_with_args(state_dir, name, &["sleep", "infinity"]);
}

/// Prepare an OCI bundle with a custom entrypoint command.
/// Creates a rootfs with busybox and a config.json suitable for runc.
fn prepare_oci_bundle_with_args(state_dir: &Path, name: &str, args: &[&str]) {
    let bundle_dir = state_dir.join("containers").join(name);
    let rootfs_dir = bundle_dir.join("rootfs");
    std::fs::create_dir_all(&rootfs_dir).unwrap();
    std::fs::create_dir_all(rootfs_dir.join("bin")).unwrap();
    std::fs::create_dir_all(rootfs_dir.join("proc")).unwrap();
    std::fs::create_dir_all(rootfs_dir.join("dev")).unwrap();
    std::fs::create_dir_all(rootfs_dir.join("tmp")).unwrap();

    let busybox_src = PathBuf::from("/bin/busybox");
    if busybox_src.exists() {
        std::fs::copy(&busybox_src, rootfs_dir.join("bin/busybox")).unwrap();
        for cmd in &["sh", "echo", "cat", "ls", "sleep", "env", "mkdir"] {
            std::os::unix::fs::symlink("busybox", rootfs_dir.join("bin").join(cmd)).unwrap();
        }
    }

    let config = serde_json::json!({
        "ociVersion": "1.0.2",
        "process": {
            "terminal": false,
            "user": { "uid": 0, "gid": 0 },
            "args": args,
            "env": [
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            ],
            "cwd": "/"
        },
        "root": {
            "path": "rootfs",
            "readonly": false
        },
        "linux": {
            "namespaces": [
                { "type": "pid" },
                { "type": "mount" },
                { "type": "ipc" },
                { "type": "uts" }
            ]
        },
        "mounts": [
            {
                "destination": "/proc",
                "type": "proc",
                "source": "proc"
            },
            {
                "destination": "/dev",
                "type": "tmpfs",
                "source": "tmpfs",
                "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]
            },
            {
                "destination": "/tmp",
                "type": "tmpfs",
                "source": "tmpfs",
                "options": ["nosuid", "nodev"]
            },
            // devpts is required for PTY exec: `runc exec -t`
            // allocates the container-side PTY from the container's own
            // /dev/pts. runc creates the /dev/ptmx -> pts/ptmx symlink.
            {
                "destination": "/dev/pts",
                "type": "devpts",
                "source": "devpts",
                "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"]
            }
        ]
    });

    std::fs::write(
        bundle_dir.join("config.json"),
        serde_json::to_string_pretty(&config).unwrap(),
    )
    .unwrap();
}

#[test]
fn test_run_container_inside_vm() {
    let _ = env_logger::builder().is_test(true).try_init();

    let kernel = workspace_path("guest/kernel/vmlinux");
    let initrd = workspace_path("guest/rootfs/initramfs.cpio.gz");

    let state_dir = tempfile::tempdir().unwrap();
    place_runc_on_virtiofs(state_dir.path());
    prepare_oci_bundle(state_dir.path(), "sandbox");

    let mut vm = Vm::builder()
        .kernel(&kernel)
        .initrd(&initrd)
        .memory_mb(512)
        .vsock(true)
        // Pre-existing test-infra fix: every `runtimeClassName: k7`
        // pod's shim creates its VM with the default vsock CID
        // (`DEFAULT_GUEST_CID = 3`). In any deployed cluster the
        // `k7-api` pod permanently holds that CID, so any test that
        // also defaults to it hits `vhost SET_GUEST_CID: Address
        // already in use`. Allocate a unique CID from the 100+
        // pool. Same brittleness affects other test files; this PR
        // only fixes the one that was reproducibly failing in the
        // 10a follow-up cycle — broader fix (and a real fix to the
        // shim's hardcoded CID) lands separately.
        .guest_cid(allocate_cid())
        .virtiofs(state_dir.path(), "/mnt/state")
        .build()
        .expect("VM should create");

    vm.start().expect("VM should start");
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect to agent");

    // Wait for virtiofs mount
    std::thread::sleep(Duration::from_secs(3));

    // Verify bundle is visible in guest
    let ls = agent
        .exec(&["ls", "/mnt/state/containers/sandbox/"])
        .expect("ls should work");
    assert!(
        ls.stdout.contains("config.json"),
        "bundle should be visible in guest: {}",
        ls.stdout
    );

    // Start container
    agent
        .container_start("sandbox", "/mnt/state/containers/sandbox")
        .expect("container start should succeed");

    // Exec inside container
    let result = agent
        .container_exec("sandbox", &["echo", "hello from container"])
        .expect("container exec should succeed");
    assert_eq!(result.exit_code, 0, "exec stderr: {}", result.stderr);
    assert_eq!(result.stdout.trim(), "hello from container");

    // List containers
    let list = agent
        .container_list()
        .expect("container list should succeed");
    assert!(
        list.containers.contains(&"sandbox".to_string()),
        "sandbox should be in container list: {:?}",
        list.containers
    );

    // Stop container
    agent
        .container_stop("sandbox")
        .expect("container stop should succeed");

    // Verify container is no longer listed
    let list_after = agent
        .container_list()
        .expect("container list should succeed");
    assert!(
        !list_after.containers.contains(&"sandbox".to_string()),
        "sandbox should not be in list after stop: {:?}",
        list_after.containers
    );

    vm.shutdown();
}

#[test]
fn test_multi_container_sidecar() {
    let _ = env_logger::builder().is_test(true).try_init();

    let kernel = workspace_path("guest/kernel/vmlinux");
    let initrd = workspace_path("guest/rootfs/initramfs.cpio.gz");

    let state_dir = tempfile::tempdir().unwrap();
    place_runc_on_virtiofs(state_dir.path());
    prepare_oci_bundle(state_dir.path(), "sandbox");
    prepare_oci_bundle(state_dir.path(), "sidecar");

    let mut vm = Vm::builder()
        .kernel(&kernel)
        .initrd(&initrd)
        .memory_mb(512)
        .vsock(true)
        // Pre-existing test-infra fix: every `runtimeClassName: k7`
        // pod's shim creates its VM with the default vsock CID
        // (`DEFAULT_GUEST_CID = 3`). In any deployed cluster the
        // `k7-api` pod permanently holds that CID, so any test that
        // also defaults to it hits `vhost SET_GUEST_CID: Address
        // already in use`. Allocate a unique CID from the 100+
        // pool. Same brittleness affects other test files; this PR
        // only fixes the one that was reproducibly failing in the
        // 10a follow-up cycle — broader fix (and a real fix to the
        // shim's hardcoded CID) lands separately.
        .guest_cid(allocate_cid())
        .virtiofs(state_dir.path(), "/mnt/state")
        .build()
        .expect("VM should create");

    vm.start().expect("VM should start");
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect to agent");

    std::thread::sleep(Duration::from_secs(3));

    // Start both containers
    agent
        .container_start("sidecar", "/mnt/state/containers/sidecar")
        .expect("sidecar start should succeed");
    agent
        .container_start("sandbox", "/mnt/state/containers/sandbox")
        .expect("sandbox start should succeed");

    // Verify both are listed
    let list = agent
        .container_list()
        .expect("container list should succeed");
    assert_eq!(
        list.containers.len(),
        2,
        "should have 2 containers: {:?}",
        list.containers
    );

    // Exec in each
    let r1 = agent
        .container_exec("sandbox", &["echo", "from-sandbox"])
        .expect("sandbox exec");
    assert_eq!(r1.stdout.trim(), "from-sandbox");

    let r2 = agent
        .container_exec("sidecar", &["echo", "from-sidecar"])
        .expect("sidecar exec");
    assert_eq!(r2.stdout.trim(), "from-sidecar");

    // Stop both
    agent.container_stop("sandbox").expect("stop sandbox");
    agent.container_stop("sidecar").expect("stop sidecar");

    let list_after = agent.container_list().expect("final list");
    assert!(list_after.containers.is_empty(), "all containers stopped");

    vm.shutdown();
}

#[test]
fn test_container_error_paths() {
    let _ = env_logger::builder().is_test(true).try_init();

    let kernel = workspace_path("guest/kernel/vmlinux");
    let initrd = workspace_path("guest/rootfs/initramfs.cpio.gz");

    let state_dir = tempfile::tempdir().unwrap();
    place_runc_on_virtiofs(state_dir.path());
    prepare_oci_bundle(state_dir.path(), "sandbox");

    let mut vm = Vm::builder()
        .kernel(&kernel)
        .initrd(&initrd)
        .memory_mb(512)
        .vsock(true)
        // Pre-existing test-infra fix: every `runtimeClassName: k7`
        // pod's shim creates its VM with the default vsock CID
        // (`DEFAULT_GUEST_CID = 3`). In any deployed cluster the
        // `k7-api` pod permanently holds that CID, so any test that
        // also defaults to it hits `vhost SET_GUEST_CID: Address
        // already in use`. Allocate a unique CID from the 100+
        // pool. Same brittleness affects other test files; this PR
        // only fixes the one that was reproducibly failing in the
        // 10a follow-up cycle — broader fix (and a real fix to the
        // shim's hardcoded CID) lands separately.
        .guest_cid(allocate_cid())
        .virtiofs(state_dir.path(), "/mnt/state")
        .build()
        .expect("VM should create");

    vm.start().expect("VM should start");
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect to agent");

    std::thread::sleep(Duration::from_secs(3));

    // Exec in nonexistent container should return error, not crash
    let err = agent.container_exec("ghost", &["echo", "hi"]);
    assert!(err.is_err(), "exec in nonexistent container should fail");

    // Stop nonexistent container should return error
    let err = agent.container_stop("ghost");
    assert!(err.is_err(), "stop nonexistent container should fail");

    // Output for nonexistent container should return error
    let err = agent.container_output("ghost", 0, 0);
    assert!(err.is_err(), "output for nonexistent container should fail");

    // Start container
    agent
        .container_start("sandbox", "/mnt/state/containers/sandbox")
        .expect("start should succeed");

    // Duplicate start should return error
    let err = agent.container_start("sandbox", "/mnt/state/containers/sandbox");
    assert!(err.is_err(), "duplicate start should fail");

    // Exec a failing command — should return non-zero exit code, not error
    let result = agent
        .container_exec("sandbox", &["sh", "-c", "exit 42"])
        .expect("exec of failing command should not be a protocol error");
    assert_eq!(result.exit_code, 42, "should propagate exit code");

    // Agent should still respond after all error cases
    let pong = agent.ping().expect("agent should still be alive");
    assert_eq!(pong.version, "0.1.0");

    agent.container_stop("sandbox").expect("stop should work");

    // Stop already-stopped container should return error
    let err = agent.container_stop("sandbox");
    assert!(err.is_err(), "stop after stop should fail");

    vm.shutdown();
}

/// Read PTY session output until `needle` appears (panics on exit,
/// stream error, or deadline). Requires a read timeout on the session.
fn pty_read_until(s: &mut PtyExecSession, needle: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    let mut acc = String::new();
    while Instant::now() < deadline {
        match s.read_event() {
            Ok(PtyEvent::Stdout(bytes)) => {
                acc.push_str(&String::from_utf8_lossy(&bytes));
                if acc.contains(needle) {
                    return acc;
                }
            }
            Ok(PtyEvent::Exit(code)) => {
                panic!("exec exited (code {code}) before {needle:?}; output: {acc:?}")
            }
            Err(AgentError::Timeout) => {}
            Err(e) => panic!("pty stream error waiting for {needle:?}: {e}; output: {acc:?}"),
        }
    }
    panic!("timeout waiting for {needle:?}; output so far: {acc:?}");
}

/// Send `cmd` repeatedly until `needle` appears in the output.
///
/// Polling (vs send-once) absorbs the session-startup race: `runc exec
/// -t` applies the initial window size to the container-side PTY once,
/// right after its console proxy comes up — a command typed *before*
/// that can query `TIOCGWINSZ` and still see 0x0. Real terminal clients
/// behave the same way (redraw on winch); only a one-shot query races.
fn pty_expect(s: &mut PtyExecSession, cmd: &str, needle: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    let mut acc = String::new();
    loop {
        s.send_stdin(cmd.as_bytes()).unwrap();
        let attempt_deadline = std::cmp::min(Instant::now() + Duration::from_secs(2), deadline);
        while Instant::now() < attempt_deadline {
            match s.read_event() {
                Ok(PtyEvent::Stdout(bytes)) => {
                    acc.push_str(&String::from_utf8_lossy(&bytes));
                    if acc.contains(needle) {
                        return;
                    }
                }
                Ok(PtyEvent::Exit(code)) => {
                    panic!("exec exited (code {code}) before {needle:?}; output: {acc:?}")
                }
                Err(AgentError::Timeout) => {}
                Err(e) => panic!("pty stream error waiting for {needle:?}: {e}; output: {acc:?}"),
            }
        }
        assert!(
            Instant::now() < deadline,
            "timeout waiting for {needle:?}; output so far: {acc:?}"
        );
    }
}

/// Drain PTY session output until the exit event; returns the exit code.
fn pty_wait_exit(s: &mut PtyExecSession, timeout: Duration) -> i32 {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match s.read_event() {
            Ok(PtyEvent::Stdout(_)) => {}
            Ok(PtyEvent::Exit(code)) => return code,
            Err(AgentError::Timeout) => {}
            Err(e) => panic!("pty stream error waiting for exit: {e}"),
        }
    }
    panic!("timeout waiting for PTY exec exit event");
}

/// internal notes: `container_exec_pty` over vsock
/// against a real VM — window size + resize (TIOCSWINSZ/SIGWINCH),
/// Ctrl+C through the line discipline, exit-code propagation, detach
/// (`eof` ⇒ SIGHUP), concurrent isolated sessions, and the
/// nonexistent-container error path. No k3s needed.
#[test]
fn test_container_exec_pty_protocol() {
    let _ = env_logger::builder().is_test(true).try_init();

    let kernel = workspace_path("guest/kernel/vmlinux");
    let initrd = workspace_path("guest/rootfs/initramfs.cpio.gz");

    let state_dir = tempfile::tempdir().unwrap();
    place_runc_on_virtiofs(state_dir.path());
    prepare_oci_bundle(state_dir.path(), "sandbox");

    let mut vm = Vm::builder()
        .kernel(&kernel)
        .initrd(&initrd)
        .memory_mb(512)
        .vsock(true)
        .guest_cid(allocate_cid())
        .virtiofs(state_dir.path(), "/mnt/state")
        .build()
        .expect("VM should create");

    vm.start().expect("VM should start");
    let cid = vm.guest_cid();
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect to agent");

    std::thread::sleep(Duration::from_secs(3));

    agent
        .container_start("sandbox", "/mnt/state/containers/sandbox")
        .expect("container start should succeed");

    // Handshake against a nonexistent container fails loudly.
    let err = AgentClient::connect_pty_exec(
        cid,
        Duration::from_secs(10),
        "ghost",
        "pty-ghost",
        &["sh"],
        "xterm",
        24,
        80,
    );
    assert!(err.is_err(), "pty exec in nonexistent container must fail");

    // ── Session 1: window size, resize, Ctrl+C, exit code ──
    let mut s = AgentClient::connect_pty_exec(
        cid,
        Duration::from_secs(10),
        "sandbox",
        "pty-1",
        &["sh"],
        "xterm",
        24,
        80,
    )
    .expect("pty handshake");
    s.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();

    // Initial window from the handshake.
    pty_expect(
        &mut s,
        "echo \"SZ=$(/bin/busybox stty size)\"\n",
        "SZ=24 80",
        Duration::from_secs(20),
    );

    // winch → TIOCSWINSZ → SIGWINCH → runc resizes the container PTY.
    s.send_winch(40, 120).unwrap();
    pty_expect(
        &mut s,
        "echo \"SZ=$(/bin/busybox stty size)\"\n",
        "SZ=40 120",
        Duration::from_secs(20),
    );

    // Ctrl+C: the line discipline delivers SIGINT to the foreground
    // job (sleep, exit 130); the shell survives and keeps working —
    // this only holds if the PTY really is the controlling terminal.
    s.send_stdin(b"sleep 100\n").unwrap();
    std::thread::sleep(Duration::from_secs(1));
    s.send_stdin(&[0x03]).unwrap();
    s.send_stdin(b"echo RC=$?\n").unwrap();
    pty_read_until(&mut s, "RC=130", Duration::from_secs(20));

    // Exit codes propagate through runc exec.
    s.send_stdin(b"exit 7\n").unwrap();
    assert_eq!(pty_wait_exit(&mut s, Duration::from_secs(20)), 7);
    drop(s);

    // ── Session 2: detach (eof) hangs the session up ──
    let mut s2 = AgentClient::connect_pty_exec(
        cid,
        Duration::from_secs(10),
        "sandbox",
        "pty-2",
        &["sh"],
        "xterm",
        24,
        80,
    )
    .expect("pty handshake (detach session)");
    s2.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    s2.send_stdin(b"echo READY\n").unwrap();
    pty_read_until(&mut s2, "READY", Duration::from_secs(20));
    let hangup_start = Instant::now();
    s2.send_eof().unwrap();
    let code = pty_wait_exit(&mut s2, Duration::from_secs(10));
    assert_ne!(code, 0, "hangup exit should be 129 (SIGHUP) or 137");
    assert!(
        hangup_start.elapsed() < Duration::from_secs(5),
        "hangup should tear the session down promptly, took {:?}",
        hangup_start.elapsed()
    );
    drop(s2);

    // ── Concurrent sessions on the same container stay isolated ──
    let mut sessions = Vec::new();
    for i in 0..3u16 {
        let s = AgentClient::connect_pty_exec(
            cid,
            Duration::from_secs(10),
            "sandbox",
            &format!("pty-conc-{i}"),
            &["sh"],
            "xterm",
            30 + i,
            100 + i,
        )
        .expect("concurrent pty handshake");
        s.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        sessions.push(s);
    }
    for (i, s) in sessions.iter_mut().enumerate() {
        let needle = format!("M-{i}: {} {}", 30 + i, 100 + i);
        let cmd = format!("echo \"M-{i}: $(/bin/busybox stty size)\"\n");
        pty_expect(s, &cmd, &needle, Duration::from_secs(20));
        s.send_stdin(b"exit\n").unwrap();
        assert_eq!(pty_wait_exit(s, Duration::from_secs(20)), 0);
    }
    drop(sessions);

    // The classic non-PTY exec path still works alongside.
    let result = agent
        .container_exec("sandbox", &["echo", "non-pty-still-works"])
        .expect("non-pty exec");
    assert_eq!(result.stdout.trim(), "non-pty-still-works");

    agent.container_stop("sandbox").expect("stop sandbox");
    vm.shutdown();
}

#[test]
fn test_container_stdout_streamed_to_host() {
    let _ = env_logger::builder().is_test(true).try_init();

    let kernel = workspace_path("guest/kernel/vmlinux");
    let initrd = workspace_path("guest/rootfs/initramfs.cpio.gz");

    let state_dir = tempfile::tempdir().unwrap();
    place_runc_on_virtiofs(state_dir.path());
    // Container that writes to stdout then sleeps
    prepare_oci_bundle_with_args(
        state_dir.path(),
        "writer",
        &["sh", "-c", "echo 'line1'; echo 'line2'; sleep infinity"],
    );

    let mut vm = Vm::builder()
        .kernel(&kernel)
        .initrd(&initrd)
        .memory_mb(512)
        .vsock(true)
        // Pre-existing test-infra fix: every `runtimeClassName: k7`
        // pod's shim creates its VM with the default vsock CID
        // (`DEFAULT_GUEST_CID = 3`). In any deployed cluster the
        // `k7-api` pod permanently holds that CID, so any test that
        // also defaults to it hits `vhost SET_GUEST_CID: Address
        // already in use`. Allocate a unique CID from the 100+
        // pool. Same brittleness affects other test files; this PR
        // only fixes the one that was reproducibly failing in the
        // 10a follow-up cycle — broader fix (and a real fix to the
        // shim's hardcoded CID) lands separately.
        .guest_cid(allocate_cid())
        .virtiofs(state_dir.path(), "/mnt/state")
        .build()
        .expect("VM should create");

    vm.start().expect("VM should start");
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect to agent");

    std::thread::sleep(Duration::from_secs(3));

    agent
        .container_start("writer", "/mnt/state/containers/writer")
        .expect("container start should succeed");

    // Give the container time to produce output
    std::thread::sleep(Duration::from_secs(2));

    // Read stdout from the container's main process (offset 0, default limit)
    let output = agent
        .container_output("writer", 0, 0)
        .expect("container_output should succeed");
    assert!(
        output.stdout.contains("line1"),
        "should contain line1: {:?}",
        output.stdout
    );
    assert!(
        output.stdout.contains("line2"),
        "should contain line2: {:?}",
        output.stdout
    );

    agent.container_stop("writer").expect("stop writer");
    vm.shutdown();
}
