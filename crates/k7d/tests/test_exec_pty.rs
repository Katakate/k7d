//! internal notes: interactive `kubectl exec -it` with a real PTY —
//! end-to-end kubectl coverage.
//!
//! Each test allocates a **local** PTY pair and runs `kubectl exec
//! -it` with the slave as its stdio, so kubectl genuinely negotiates a
//! TTY (with a pipe for stdin kubectl silently downgrades `-t`). The
//! test drives the session through the local master: keystrokes,
//! Ctrl+C bytes, `TIOCSWINSZ` resizes (kernel delivers SIGWINCH to
//! kubectl, which forwards the resize through the CRI streaming
//! stack), and SIGKILL-the-client detach.
//!
//! Like `test_shim.rs`, this file is kubectl-based: it self-installs
//! the freshly built shim + k7d daemon and needs the node's k3s.

use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::process::CommandExt;
use std::time::{Duration, Instant};

mod common;

// ---- shim/kubectl plumbing (mirror of test_shim.rs helpers) ----

fn ensure_shim_installed() -> common::LeakGuard {
    use std::process::Command;

    common::cleanup_k7_runtime_leaks();

    let shim_src = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("target/release/containerd-shim-k7-v1");

    // Always build: skipping when `shim_src` merely exists deploys a
    // stale shim after source edits (see test_shim.rs).
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
                child.stdin.as_mut().unwrap().write_all(
                    b"apiVersion: node.k8s.io/v1\nkind: RuntimeClass\nmetadata:\n  name: k7\nhandler: k7\n",
                ).unwrap();
                child.wait()
            })
            .expect("create RuntimeClass");
    }

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
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(yaml.as_bytes())
                .unwrap();
            child.wait_with_output()
        })
        .map_err(|e| format!("kubectl apply: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Graceful pod delete (see test_cni.rs / internal notes).
fn kubectl_delete_pod(name: &str) {
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
        .output();
    let wait_ok = graceful.as_ref().is_ok_and(|o| o.status.success());

    if wait_ok {
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
    } else {
        let _ = std::process::Command::new("kubectl")
            .args([
                "delete",
                "pod",
                name,
                "--ignore-not-found",
                "--force",
                "--grace-period=0",
            ])
            .output();
    }
}

/// Non-interactive `kubectl exec` (the classic path — also serves as a
/// cross-check that PTY sessions don't break it).
fn kubectl_exec(pod: &str, cmd: &[&str]) -> Result<String, String> {
    let mut args = vec!["exec", pod, "--"];
    args.extend_from_slice(cmd);
    let output = std::process::Command::new("kubectl")
        .args(&args)
        .output()
        .map_err(|e| format!("kubectl exec: {e}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(format!(
            "exit {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

fn wait_for_pod_ready(name: &str, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let output = std::process::Command::new("kubectl")
            .args(["get", "pod", name, "-o", "jsonpath={.status.phase}"])
            .output()
            .map_err(|e| format!("{e}"))?;
        if String::from_utf8_lossy(&output.stdout) == "Running" {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Err(format!("pod {name} not ready within {timeout:?}"))
}

/// Create the test pod (alpine, sleep infinity) and wait for Running.
fn create_pty_pod(name: &str) {
    kubectl_delete_pod(name);
    std::thread::sleep(Duration::from_secs(2));
    kubectl_apply(&common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {name}
spec:
  runtimeClassName: k7
  containers:
  - name: sandbox
    image: alpine:3.20
    command: ["sleep", "infinity"]
"#
    )))
    .expect("kubectl apply");
    wait_for_pod_ready(name, Duration::from_secs(120)).expect("pod ready");
}

// ---- local PTY harness for kubectl ----

/// Allocate a local PTY pair via `/dev/ptmx` (raw ioctls, no libutil).
fn open_local_pty(rows: u16, cols: u16) -> (std::fs::File, std::fs::File) {
    let master = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY)
        .open("/dev/ptmx")
        .expect("open /dev/ptmx");
    let unlock: libc::c_int = 0;
    // SAFETY: valid ptmx fd; TIOCSPTLCK reads an int.
    assert!(
        unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSPTLCK as _, &raw const unlock) } >= 0,
        "TIOCSPTLCK"
    );
    let mut pty_num: libc::c_uint = 0;
    // SAFETY: valid ptmx fd; TIOCGPTN writes an unsigned int.
    assert!(
        unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCGPTN as _, &raw mut pty_num) } >= 0,
        "TIOCGPTN"
    );
    let slave = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY)
        .open(format!("/dev/pts/{pty_num}"))
        .expect("open pty slave");
    set_winsize(&master, rows, cols);
    (master, slave)
}

fn set_winsize(master: &std::fs::File, rows: u16, cols: u16) {
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: valid PTY master fd; TIOCSWINSZ reads a winsize struct.
    unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ as _, &raw const ws) };
}

/// `kubectl exec -it` running on a real local PTY.
struct TtyKubectl {
    master: std::fs::File,
    child: std::process::Child,
    acc: String,
}

impl TtyKubectl {
    /// Spawn `kubectl <args>` with a fresh PTY slave as its stdio and
    /// controlling terminal, sized `rows`×`cols`.
    fn spawn(args: &[&str], rows: u16, cols: u16) -> Self {
        let (master, slave) = open_local_pty(rows, cols);
        let mut cmd = std::process::Command::new("kubectl");
        cmd.args(args)
            .stdin(std::process::Stdio::from(slave.try_clone().unwrap()))
            .stdout(std::process::Stdio::from(slave.try_clone().unwrap()))
            .stderr(std::process::Stdio::from(slave));
        // SAFETY: pre_exec runs in the forked child before exec and
        // only calls async-signal-safe functions; fd 0 is the slave.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn().expect("spawn kubectl");
        // Non-blocking master so read_until can poll with a deadline.
        // SAFETY: valid master fd; setting O_NONBLOCK.
        unsafe {
            let flags = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
            libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        Self {
            master,
            child,
            acc: String::new(),
        }
    }

    /// Type into the session.
    fn send(&mut self, s: &str) {
        let mut data = s.as_bytes();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !data.is_empty() {
            match self.master.write(data) {
                Ok(n) => data = &data[n..],
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "PTY master write stalled");
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("PTY master write: {e}"),
            }
        }
    }

    /// Re-send `cmd` every 2 s until `needle` shows up. Same pattern
    /// as `pty_expect` in `test_container.rs` (CHALLENGES.md #14):
    /// runc's console lifecycle has an inherent window right after
    /// the handshake where `TIOCGWINSZ` reports 0 rows and busybox
    /// `stty size` fails with `stty: standard input` — poll instead
    /// of send-once.
    fn send_until(&mut self, cmd: &str, needle: &str, timeout: Duration) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        loop {
            self.send(cmd);
            let attempt = std::cmp::min(Duration::from_secs(2), timeout);
            if self.read_until(needle, attempt).is_ok() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "timeout waiting for {needle:?}; output: {:?}",
                    self.acc
                ));
            }
        }
    }

    /// Resize the local terminal; the kernel sends kubectl SIGWINCH
    /// and kubectl forwards the new size through the exec stream.
    fn resize(&self, rows: u16, cols: u16) {
        set_winsize(&self.master, rows, cols);
    }

    /// Accumulate session output until `needle` shows up.
    fn read_until(&mut self, needle: &str, timeout: Duration) -> Result<String, String> {
        let deadline = Instant::now() + timeout;
        let mut buf = [0u8; 8192];
        while Instant::now() < deadline {
            match self.master.read(&mut buf) {
                Ok(0) => return Err(format!("PTY closed; output: {:?}", self.acc)),
                Ok(n) => {
                    self.acc.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if self.acc.contains(needle) {
                        return Ok(self.acc.clone());
                    }
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    if let Ok(Some(status)) = self.child.try_wait() {
                        // Late output may still be buffered; drain once.
                        if let Ok(n) = self.master.read(&mut buf) {
                            self.acc.push_str(&String::from_utf8_lossy(&buf[..n]));
                        }
                        if self.acc.contains(needle) {
                            return Ok(self.acc.clone());
                        }
                        return Err(format!(
                            "kubectl exited ({status}) before {needle:?}; output: {:?}",
                            self.acc
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
                // EIO once kubectl exits and the slave side closes.
                Err(e) => return Err(format!("PTY read: {e}; output: {:?}", self.acc)),
            }
        }
        Err(format!(
            "timeout waiting for {needle:?}; output: {:?}",
            self.acc
        ))
    }

    /// Wait for kubectl to exit; returns its exit code.
    fn wait_exit(&mut self, timeout: Duration) -> Result<i32, String> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(status)) => return Ok(status.code().unwrap_or(-1)),
                Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                Err(e) => return Err(format!("wait kubectl: {e}")),
            }
        }
        Err("timeout waiting for kubectl exit".to_string())
    }

    /// Simulate an abrupt client disconnect.
    fn kill_client(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for TtyKubectl {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Poll an interactive shell until `stty size` reports `rows cols`.
fn expect_stty_size(t: &mut TtyKubectl, rows: u16, cols: u16, timeout: Duration) {
    let needle = format!("{rows} {cols}");
    let deadline = Instant::now() + timeout;
    loop {
        t.send("stty size\n");
        match t.read_until(&needle, Duration::from_secs(3)) {
            Ok(_) => return,
            Err(e) => assert!(
                Instant::now() < deadline,
                "stty size never reported {needle:?}: {e}"
            ),
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

// ---- the internal notes

/// `kubectl exec -it` gets the client's window size, and resizing the
/// client terminal mid-session propagates (SIGWINCH → resize stream →
/// shim ResizePty → agent TIOCSWINSZ → guest SIGWINCH).
#[test]
fn test_kubectl_exec_pty_resize() {
    let _leak_guard = ensure_shim_installed();
    let pod = "test-k7d-pty-resize";
    create_pty_pod(pod);

    let mut t = TtyKubectl::spawn(&["exec", "-it", pod, "--", "sh"], 24, 80);
    expect_stty_size(&mut t, 24, 80, Duration::from_secs(60));

    t.resize(40, 120);
    expect_stty_size(&mut t, 40, 120, Duration::from_secs(30));

    t.send("exit\n");
    assert_eq!(t.wait_exit(Duration::from_secs(30)), Ok(0));
    drop(t);

    kubectl_delete_pod(pod);
}

/// Ctrl+C reaches the foreground job via the PTY line discipline: the
/// job dies with SIGINT (130) and the shell survives.
#[test]
fn test_kubectl_exec_pty_ctrl_c() {
    let _leak_guard = ensure_shim_installed();
    let pod = "test-k7d-pty-intr";
    create_pty_pod(pod);

    let mut t = TtyKubectl::spawn(&["exec", "-it", pod, "--", "sh"], 24, 80);
    // Wait for the shell before starting the job so ^C can't race the
    // prompt.
    t.send("echo SH''ELL-UP\n");
    t.read_until("SHELL-UP", Duration::from_secs(60)).unwrap();

    t.send("sleep 100\n");
    std::thread::sleep(Duration::from_secs(2));
    t.send("\x03"); // Ctrl+C
    t.send("echo RC=$?\n");
    t.read_until("RC=130", Duration::from_secs(30)).unwrap();

    // The shell is still alive and interactive.
    t.send("echo STILL''-ALIVE\n");
    t.read_until("STILL-ALIVE", Duration::from_secs(30))
        .unwrap();

    t.send("exit\n");
    assert_eq!(t.wait_exit(Duration::from_secs(30)), Ok(0));
    drop(t);

    kubectl_delete_pod(pod);
}

/// Detach mid-session: killing the kubectl client hangs the exec
/// process up (SIGHUP through the PTY) — it must be gone shortly
/// after, and the pod keeps working.
#[test]
fn test_kubectl_exec_pty_detach_sighup() {
    let _leak_guard = ensure_shim_installed();
    let pod = "test-k7d-pty-detach";
    create_pty_pod(pod);

    let mut t = TtyKubectl::spawn(
        &[
            "exec",
            "-it",
            pod,
            "--",
            "sh",
            "-c",
            "echo PTY-READY; exec sleep 31337",
        ],
        24,
        80,
    );
    t.read_until("PTY-READY", Duration::from_secs(60)).unwrap();

    // The exec process is visible inside the container's pid ns.
    let ps = kubectl_exec(pod, &["sh", "-c", "ps -o args | grep -c 'slee[p] 31337'"])
        .expect("ps in container");
    assert_eq!(ps.trim(), "1", "exec process should be running: {ps:?}");

    // Abrupt client disconnect (kubectl SIGKILLed). The stream close
    // propagates apiserver → kubelet → containerd → shim (CloseIO /
    // stdin FIFO EOF) → agent hangup (SIGHUP, in-guest delivery is
    // immediate); the 5s budget absorbs the network propagation.
    t.kill_client();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let count = kubectl_exec(
            pod,
            &["sh", "-c", "ps -o args | grep -c 'slee[p] 31337' || true"],
        )
        .expect("ps in container");
        if count.trim() == "0" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "exec process still alive 5s after client detach (count={count:?})"
        );
        std::thread::sleep(Duration::from_millis(250));
    }

    // The pod (and a fresh PTY session — no leaked PTY state) still works.
    let mut t2 = TtyKubectl::spawn(&["exec", "-it", pod, "--", "sh"], 24, 80);
    t2.send("echo AFTER''-DETACH\n");
    t2.read_until("AFTER-DETACH", Duration::from_secs(60))
        .unwrap();
    t2.send("exit\n");
    assert_eq!(t2.wait_exit(Duration::from_secs(30)), Ok(0));
    drop(t2);

    kubectl_delete_pod(pod);
}

/// Five parallel interactive sessions on the same pod: isolated I/O
/// and per-session window sizes.
#[test]
fn test_kubectl_exec_pty_concurrent() {
    let _leak_guard = ensure_shim_installed();
    let pod = "test-k7d-pty-conc";
    create_pty_pod(pod);

    let handles: Vec<_> = (0..5u16)
        .map(|i| {
            std::thread::spawn(move || -> Result<(), String> {
                let rows = 20 + i;
                let cols = 90 + i;
                let mut t = TtyKubectl::spawn(
                    &["exec", "-it", "test-k7d-pty-conc", "--", "sh"],
                    rows,
                    cols,
                );
                t.send_until(
                    &format!("echo \"M-{i}: $(stty size)\"\n"),
                    &format!("M-{i}: {rows} {cols}"),
                    Duration::from_secs(90),
                )?;
                t.send("exit\n");
                match t.wait_exit(Duration::from_secs(30)) {
                    Ok(0) => Ok(()),
                    Ok(c) => Err(format!("session {i}: kubectl exited {c}")),
                    Err(e) => Err(format!("session {i}: {e}")),
                }
            })
        })
        .collect();

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    for (i, r) in results.iter().enumerate() {
        assert!(r.is_ok(), "concurrent session {i} failed: {r:?}");
    }

    kubectl_delete_pod(pod);
}
