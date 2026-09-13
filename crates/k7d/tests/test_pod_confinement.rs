//! Pod `securityContext` reaches guest runc.
//!
//! A RuntimeDefault + drop-ALL pod must show Seccomp filtering,
//! NoNewPrivs, a zero CapBnd, EPERM on `mknod`, a masked `/proc/kcore`,
//! and EROFS on `/proc/sysrq-trigger`. A privileged pod must still
//! be able to `mknod` (the CHALLENGES #36 inner-k3s / `/dev/kmsg`
//! case, now only for privileged).

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

mod common;

fn ensure_shim_installed() -> common::LeakGuard {
    common::cleanup_k7_runtime_leaks();

    let shim_src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("target/release/containerd-shim-k7-v1");

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
                )?;
                child.wait()
            })
            .expect("create RuntimeClass");
    }

    common::ensure_k7d_daemon_running();
    common::LeakGuard
}

fn kubectl_apply(yaml: &str) -> Result<(), String> {
    common::kubectl_apply(yaml)
}

/// Deletes the pod on drop so a mid-test panic cannot leak a k7 VM
/// onto `10.200.0.2` (that blackholes the gym Ubuntu smoke).
struct DeletePod(String);

impl Drop for DeletePod {
    fn drop(&mut self) {
        kubectl_delete_pod(&self.0);
    }
}

fn kubectl_delete_pod(name: &str) {
    let graceful = Command::new("kubectl")
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
            let probe = Command::new("kubectl")
                .args(["get", "pod", name, "--ignore-not-found", "-o", "name"])
                .output();
            match probe {
                Ok(o) if o.status.success() && o.stdout.is_empty() => break,
                _ => std::thread::sleep(Duration::from_millis(250)),
            }
        }
    } else {
        let _ = Command::new("kubectl")
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

fn kubectl_exec(pod: &str, cmd: &[&str]) -> Result<String, String> {
    let mut args = vec!["exec", pod, "--"];
    args.extend_from_slice(cmd);
    let output = Command::new("kubectl")
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
        let output = Command::new("kubectl")
            .args(["get", "pod", name, "-o", "jsonpath={.status.phase}"])
            .output()
            .map_err(|e| format!("{e}"))?;
        if String::from_utf8_lossy(&output.stdout) == "Running" {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    let describe = Command::new("kubectl")
        .args(["describe", "pod", name])
        .output()
        .ok();
    let extra = describe
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    Err(format!("pod {name} not ready within {timeout:?}\n{extra}"))
}

fn status_value(pod: &str, field: &str) -> String {
    let out = kubectl_exec(pod, &["grep", &format!("{field}:"), "/proc/1/status"])
        .unwrap_or_else(|e| panic!("grep {field} /proc/1/status: {e}"));
    out.split_once(':')
        .map(|(_, v)| v.trim().to_string())
        .unwrap_or_else(|| panic!("parse {field} from {out:?}"))
}

#[test]
fn test_pod_runtime_default_confinement() {
    let _leak_guard = ensure_shim_installed();
    let pod = common::unique_name("test-k7d-confine");
    let _cleanup = DeletePod(pod.clone());
    kubectl_delete_pod(&pod);

    kubectl_apply(&common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {pod}
spec:
  runtimeClassName: k7
  containers:
  - name: main
    image: alpine:3.20
    command: ["sleep", "infinity"]
    securityContext:
      allowPrivilegeEscalation: false
      seccompProfile:
        type: RuntimeDefault
      capabilities:
        drop: ["ALL"]
"#
    )))
    .expect("kubectl apply confined pod");
    wait_for_pod_ready(&pod, Duration::from_secs(120)).expect("confined pod ready");

    assert_eq!(
        status_value(&pod, "Seccomp"),
        "2",
        "RuntimeDefault must install a seccomp filter in the guest"
    );
    assert_eq!(
        status_value(&pod, "NoNewPrivs"),
        "1",
        "allowPrivilegeEscalation: false must set no_new_privs"
    );
    let cap_bnd = status_value(&pod, "CapBnd");
    assert!(
        cap_bnd.chars().all(|c| c == '0'),
        "drop ALL must zero CapBnd, got {cap_bnd}"
    );

    let mknod = kubectl_exec(
        &pod,
        &[
            "sh",
            "-c",
            "mknod /tmp/x b 254 0 2>/tmp/mknod.err; echo EXIT:$?; cat /tmp/mknod.err",
        ],
    )
    .expect("mknod probe");
    assert!(
        mknod.contains("EXIT:1") && mknod.to_ascii_lowercase().contains("not permitted"),
        "unprivileged mknod must be EPERM, got {mknod}"
    );

    let vd = kubectl_exec(
        &pod,
        &[
            "sh",
            "-c",
            "n=0; for d in /dev/vd*; do [ -e \"$d\" ] || continue; \
             cat \"$d\" >/dev/null 2>/tmp/vd.err; echo OPEN:$d:$?; cat /tmp/vd.err; n=1; \
             done; [ \"$n\" = 0 ] && echo NO_VDX",
        ],
    )
    .expect("vdX probe");
    assert!(
        vd.contains("NO_VDX")
            || vd.to_ascii_lowercase().contains("not permitted")
            || vd.to_ascii_lowercase().contains("permission denied"),
        "unprivileged container must not open /dev/vdX, got {vd}"
    );

    let kcore = kubectl_exec(
        &pod,
        &[
            "sh",
            "-c",
            "n=$(head -c 1 /proc/kcore | wc -c); echo KCORE:$n",
        ],
    )
    .expect("kcore probe");
    assert!(
        kcore.contains("KCORE:0"),
        "/proc/kcore must be masked (empty), got {kcore}"
    );

    // Guest config-minimal has no CONFIG_MAGIC_SYSRQ, so
    // /proc/sysrq-trigger is absent and runc skips that readonlyPath.
    // drop ALL also makes a sysctl write fail with EPERM, which is
    // not evidence of the bind. Check the mount instead: CRI
    // readonlyPaths bind /proc/sys onto itself as ro.
    let mounts = kubectl_exec(&pod, &["cat", "/proc/mounts"]).expect("cat /proc/mounts");
    assert!(
        mounts.lines().any(|l| {
            let cols: Vec<&str> = l.split_whitespace().collect();
            cols.len() >= 4 && cols[1] == "/proc/sys" && cols[3].split(',').any(|f| f == "ro")
        }),
        "/proc/sys must be a read-only bind (readonlyPaths), mounts:\n{mounts}"
    );
}

#[test]
fn test_pod_privileged_can_mknod() {
    let _leak_guard = ensure_shim_installed();
    let pod = common::unique_name("test-k7d-priv-mknod");
    let _cleanup = DeletePod(pod.clone());
    kubectl_delete_pod(&pod);

    kubectl_apply(&common::pin_to_local_node(&format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: {pod}
spec:
  runtimeClassName: k7
  containers:
  - name: main
    image: alpine:3.20
    command: ["sleep", "infinity"]
    securityContext:
      privileged: true
"#
    )))
    .expect("kubectl apply privileged pod");
    wait_for_pod_ready(&pod, Duration::from_secs(120)).expect("privileged pod ready");

    let mknod = kubectl_exec(
        &pod,
        &[
            "sh",
            "-c",
            "mknod /tmp/x b 254 0 && test -b /tmp/x && echo MKNOD_OK",
        ],
    )
    .expect("privileged mknod");
    assert!(
        mknod.contains("MKNOD_OK"),
        "privileged container must keep the CRI allow-all device cgroup, got {mknod}"
    );
}
