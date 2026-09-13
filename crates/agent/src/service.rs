//! Guest service supervisor: dockerd as a child of PID 1.
//!
//! Kept small on purpose (rule of two). One instance: docker.

use std::fs::{self, OpenOptions};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const DOCKER_SOCK_DIR: &str = "/run/k7d/docker";
const DOCKER_SOCK: &str = "/run/k7d/docker/docker.sock";
const DOCKER_PIDFILE: &str = "/run/k7d/docker/dockerd.pid";
const DOCKER_LOG: &str = "/run/k7d/docker/dockerd.log";
const DOCKERD: &str = "/run/k7d/docker-tools/bin/dockerd";
const DOCKER_CLI: &str = "/run/k7d/docker-tools/bin/docker";
const SSL_CERT_FILE: &str = "/run/k7d/docker-tools/etc/ssl/certs/ca-certificates.crt";
const TOOLS_PATH: &str =
    "/run/k7d/docker-tools/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Snapshot of one supervised service, as reported on `Pong`.
#[derive(Debug, Clone)]
pub struct ServiceStatus {
    pub name: String,
    pub pid: u32,
    pub ready: bool,
    pub restarts: u32,
}

/// One supervised process. `ready` is a probe, not a cached flag.
pub struct Service {
    pub name: &'static str,
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
    /// Probe; stored on the struct as the design requires. The loop
    /// calls [`docker_ready`] directly so it can drop the lock first.
    #[allow(dead_code)]
    pub ready: fn() -> Result<(), String>,
    pub restarts: u32,
    pub pid: Option<u32>,
    child: Option<Child>,
    last_error: String,
    fatal: Option<String>,
}

/// Supervises the docker service when `k7d.docker=1` is on the cmdline.
pub struct Supervisor {
    inner: Mutex<Inner>,
}

struct Inner {
    docker: Option<Service>,
}

impl Supervisor {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner { docker: None }),
        })
    }

    /// `true` when this guest was booted with `k7d.docker=1`.
    #[must_use]
    pub fn docker_enabled() -> bool {
        docker_cmdline()
    }

    /// Create `/run/k7d/docker`, start the supervisor thread. Call once
    /// from `main` after the cmdline mounts, before the vsock listener.
    pub fn start_docker(self: &Arc<Self>) {
        if let Err(e) = fs::create_dir_all(format!("{DOCKER_SOCK_DIR}/exec")) {
            eprintln!("k7-agent: mkdir {DOCKER_SOCK_DIR}/exec failed: {e}");
        }
        {
            let mut inner = self.inner.lock().unwrap();
            inner.docker = Some(Service {
                name: "docker",
                argv: vec![
                    DOCKERD.to_string(),
                    "--host".into(),
                    format!("unix://{DOCKER_SOCK}"),
                    "--tls=false".into(),
                    "--storage-driver=overlay2".into(),
                    "--data-root=/var/lib/docker".into(),
                    format!("--exec-root={DOCKER_SOCK_DIR}/exec"),
                    format!("--pidfile={DOCKER_PIDFILE}"),
                ],
                env: vec![
                    ("PATH".into(), TOOLS_PATH.into()),
                    ("DOCKER_HOST".into(), format!("unix://{DOCKER_SOCK}")),
                    ("SSL_CERT_FILE".into(), SSL_CERT_FILE.into()),
                    // Guest `/` is initramfs rootfs; pivot_root(2) returns
                    // EINVAL there (man 2 pivot_root). Dockerd maps this to
                    // runc --no-pivot. Do not switch_root the guest.
                    ("DOCKER_RAMDISK".into(), "1".into()),
                ],
                ready: docker_ready,
                restarts: 0,
                pid: None,
                child: None,
                last_error: String::new(),
                fatal: None,
            });
        }
        let sup = Arc::clone(self);
        thread::spawn(move || sup.run_loop());
    }

    #[must_use]
    pub fn watches_docker(&self) -> bool {
        self.inner.lock().unwrap().docker.is_some()
    }

    #[must_use]
    pub fn status(&self) -> Vec<ServiceStatus> {
        let snapshot = {
            let inner = self.inner.lock().unwrap();
            let Some(svc) = inner.docker.as_ref() else {
                return Vec::new();
            };
            (
                svc.name.to_string(),
                svc.pid.unwrap_or(0),
                svc.restarts,
                svc.fatal.clone(),
            )
        };
        let (name, pid, restarts, fatal) = snapshot;
        let ready = fatal.is_none() && docker_ready().is_ok();
        vec![ServiceStatus {
            name,
            pid,
            ready,
            restarts,
        }]
    }

    /// Block until docker reports overlay2, or `timeout`. vfs fails
    /// immediately (do not wait out the bound).
    pub fn wait_ready(&self, timeout: Duration) -> Result<(), String> {
        if !self.watches_docker() {
            return Ok(());
        }
        let deadline = Instant::now() + timeout;
        loop {
            {
                let inner = self.inner.lock().unwrap();
                if let Some(fatal) = inner.docker.as_ref().and_then(|s| s.fatal.clone()) {
                    return Err(fatal);
                }
            }
            match docker_ready() {
                Ok(()) => return Ok(()),
                Err(e) if is_vfs(&e) => return Err(e),
                Err(e) => {
                    if Instant::now() >= deadline {
                        return Err(format!("docker not ready within {timeout:?}: {e}"));
                    }
                }
            }
            thread::sleep(Duration::from_millis(200));
        }
    }

    fn run_loop(&self) {
        let mut backoff = Duration::from_secs(1);
        loop {
            let fatal = {
                let inner = self.inner.lock().unwrap();
                inner.docker.as_ref().and_then(|s| s.fatal.clone())
            };
            if fatal.is_some() {
                thread::sleep(Duration::from_secs(1));
                continue;
            }
            self.poll_once(&mut backoff);
            thread::sleep(Duration::from_millis(500));
        }
    }

    #[allow(clippy::too_many_lines)]
    fn poll_once(&self, backoff: &mut Duration) {
        let mut inner = self.inner.lock().unwrap();
        let Some(svc) = inner.docker.as_mut() else {
            return;
        };
        if svc.child.is_some() {
            let pid = i32::try_from(svc.pid.unwrap_or(0)).unwrap_or(0);
            let waited = svc.child.as_mut().expect("just checked").try_wait();
            match waited {
                Ok(Some(status)) => {
                    eprintln!("k7-agent: dockerd exited ({status}); reaping process group");
                    svc.child = None;
                    svc.pid = None;
                    svc.restarts = svc.restarts.saturating_add(1);
                    drop(inner);
                    reap_group(pid);
                    thread::sleep(*backoff);
                    *backoff = (*backoff * 2).min(Duration::from_secs(30));
                    return;
                }
                Ok(None) => {
                    drop(inner);
                    match docker_ready() {
                        Ok(()) => {
                            *backoff = Duration::from_secs(1);
                            if let Ok(mut inner) = self.inner.lock() {
                                if let Some(svc) = inner.docker.as_mut() {
                                    svc.last_error.clear();
                                }
                            }
                        }
                        Err(e) => {
                            if is_vfs(&e) {
                                eprintln!(
                                    "k7-agent: docker storage driver is vfs; refusing to continue"
                                );
                                if let Ok(mut inner) = self.inner.lock() {
                                    if let Some(svc) = inner.docker.as_mut() {
                                        svc.fatal = Some(e.clone());
                                        svc.last_error.clone_from(&e);
                                    }
                                }
                            } else if let Ok(mut inner) = self.inner.lock() {
                                if let Some(svc) = inner.docker.as_mut() {
                                    svc.last_error = e;
                                }
                            }
                        }
                    }
                    return;
                }
                Err(e) => {
                    eprintln!("k7-agent: wait dockerd: {e}");
                    svc.child = None;
                    svc.pid = None;
                    return;
                }
            }
        }
        if !guest_resolv_usable() {
            svc.last_error = "waiting for /etc/resolv.conf nameserver".into();
            return;
        }
        match spawn_dockerd(svc) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("k7-agent: spawn dockerd: {e}");
                svc.last_error = e;
                drop(inner);
                thread::sleep(*backoff);
                *backoff = (*backoff * 2).min(Duration::from_secs(30));
            }
        }
    }
}

fn spawn_dockerd(svc: &mut Service) -> Result<(), String> {
    if !std::path::Path::new(DOCKERD).exists() {
        return Err(format!(
            "{DOCKERD} missing — docker payload slot did not mount"
        ));
    }
    if !std::path::Path::new(SSL_CERT_FILE).exists() {
        return Err(format!(
            "{SSL_CERT_FILE} missing — docker payload has no CA bundle; registry pulls would fail x509 unknown-authority"
        ));
    }
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(DOCKER_LOG)
        .map_err(|e| format!("open {DOCKER_LOG}: {e}"))?;
    let log_err = log
        .try_clone()
        .map_err(|e| format!("clone {DOCKER_LOG}: {e}"))?;
    let mut cmd = Command::new(&svc.argv[0]);
    cmd.args(&svc.argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err));
    for (k, v) in &svc.env {
        cmd.env(k, v);
    }
    // SAFETY: runs in the child after fork, before exec; the child is
    // single-threaded. setsid() makes dockerd a session/process-group
    // leader so a crash can be reaped without waitpid(-1), which would
    // steal CRI container init pids (the agent is PID 1).
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd.spawn().map_err(|e| format!("spawn dockerd: {e}"))?;
    svc.pid = Some(child.id());
    eprintln!("k7-agent: started dockerd pid={}", child.id());
    svc.child = Some(child);
    Ok(())
}

fn guest_resolv_usable() -> bool {
    let Ok(text) = fs::read_to_string("/etc/resolv.conf") else {
        return false;
    };
    text.lines().any(|line| {
        let mut parts = line.split_whitespace();
        if parts.next() != Some("nameserver") {
            return false;
        }
        match parts.next() {
            Some("127.0.0.1" | "127.0.0.53" | "::1") | None => false,
            Some(_) => true,
        }
    })
}

fn reap_group(pid: i32) {
    if pid <= 1 {
        return;
    }
    // SAFETY: pid is a process-group we created via setsid in the child.
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    loop {
        // SAFETY: waiting on our own process group; WNOHANG so we never
        // block the supervisor on an unrelated PID 1 child.
        let r = unsafe { libc::waitpid(-pid, std::ptr::null_mut(), libc::WNOHANG) };
        if r <= 0 {
            break;
        }
    }
}

fn docker_ready() -> Result<(), String> {
    let output = Command::new(DOCKER_CLI)
        .args(["info"])
        .env("DOCKER_HOST", format!("unix://{DOCKER_SOCK}"))
        .env("PATH", TOOLS_PATH)
        .output()
        .map_err(|e| format!("docker info: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");
    if is_vfs(&combined) {
        return Err(
            "docker storage driver is vfs; overlay2 is required (graph disk missing or not ext4)"
                .into(),
        );
    }
    if output.status.success()
        && stdout.contains("Server:")
        && stdout.contains("Storage Driver: overlay2")
    {
        return Ok(());
    }
    Err(format!("docker info: {}", combined.trim()))
}

fn is_vfs(msg: &str) -> bool {
    msg.contains("Storage Driver: vfs")
        || msg.contains("storage driver is vfs")
        || msg.contains("driver vfs")
}

/// `k7d.docker=1` as a cmdline token (not a prefix of something else).
#[must_use]
pub fn docker_cmdline() -> bool {
    fs::read_to_string("/proc/cmdline")
        .is_ok_and(|c| c.split_ascii_whitespace().any(|tok| tok == "k7d.docker=1"))
}
