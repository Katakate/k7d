//! Pod CPU/memory requests and limits → VM sizing + host
//! cgroup caps — kubectl-level end-to-end coverage.
//!
//! Like `test_shim.rs` / `test_exec_pty.rs`, this file self-installs
//! the freshly built shim + k7d daemon and needs the node's k3s.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

mod common;

// ---- shim/kubectl plumbing (mirror of test_exec_pty.rs helpers) ----

fn ensure_shim_installed() -> common::LeakGuard {
    common::cleanup_k7_runtime_leaks();

    let shim_src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
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
    let output = Command::new("kubectl")
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

/// Graceful pod delete (see test_cni.rs / for the rationale).
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
    Err(format!("pod {name} not ready within {timeout:?}"))
}

// ---- helpers ----

/// The guest's `/proc/meminfo` MemTotal in kB — the VM sizing as the
/// container actually sees it.
fn guest_mem_total_kb(pod: &str) -> u64 {
    let meminfo = kubectl_exec(pod, &["cat", "/proc/meminfo"]).expect("read guest meminfo");
    meminfo
        .lines()
        .find_map(|l| l.strip_prefix("MemTotal:"))
        .map(|v| {
            v.trim()
                .trim_end_matches("kB")
                .trim()
                .parse()
                .expect("parse MemTotal")
        })
        .unwrap_or_else(|| panic!("no MemTotal in guest meminfo: {meminfo:?}"))
}

/// The k7d daemon's cgroup v2 directory (where per-VM CPU cgroups
/// live), resolved from the service's main PID.
fn k7d_service_cgroup() -> PathBuf {
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
    PathBuf::from("/sys/fs/cgroup").join(rel.trim_start_matches('/'))
}

/// All `vm-*` CPU cgroups currently present under the daemon.
fn vm_cpu_cgroups() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(k7d_service_cgroup())
        .expect("read k7d service cgroup")
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_dir()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("vm-"))
        })
        .collect();
    dirs.sort();
    dirs
}

/// The per-VM CPU cgroups that appeared since `baseline` was sampled,
/// i.e. the ones the test's own pod is responsible for. Every k7d VM on
/// the node shares `k7d.service`, so absolute counts would also see
/// unrelated k7 workloads (a bench deployment, another suite's pod) and
/// fail for reasons that have nothing to do with the code under test.
fn vm_cpu_cgroups_since(baseline: &[PathBuf]) -> Vec<PathBuf> {
    vm_cpu_cgroups()
        .into_iter()
        .filter(|p| !baseline.contains(p))
        .collect()
}

/// `usage_usec` from a cgroup's `cpu.stat`.
fn cgroup_usage_usec(dir: &std::path::Path) -> u64 {
    std::fs::read_to_string(dir.join("cpu.stat"))
        .expect("read cpu.stat")
        .lines()
        .find_map(|l| l.strip_prefix("usage_usec "))
        .expect("usage_usec in cpu.stat")
        .trim()
        .parse()
        .expect("parse usage_usec")
}

/// Count of host-side OOM kill events in the kernel log. The guest's
/// OOM killer logs to the *guest* kernel log, so any increase here
/// means the host (not the VM) OOMed — exactly what forbids.
fn host_oom_kill_count() -> u64 {
    let out = Command::new("sh")
        .arg("-c")
        .arg("dmesg 2>/dev/null | grep -ci 'out of memory\\|oom-kill' || true")
        .output()
        .expect("dmesg");
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .unwrap_or(0)
}

// ---- the tests ----

/// A pod with `memory: 256Mi` boots a VM sized limit + 64 MB overhead:
/// the guest sees 256–320 MB, and an in-guest allocation blowing past
/// the limit is OOM-killed *inside the VM* — the pod survives and the
/// host kernel never OOMs.
#[test]
fn test_pod_memory_limit_sizes_vm() {
    let _leak_guard = ensure_shim_installed();
    let pod = "test-k7d-res-mem";
    kubectl_delete_pod(pod);
    let host_oom_before = host_oom_kill_count();

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
    resources:
      limits:
        memory: 256Mi
"#
    )))
    .expect("kubectl apply");
    wait_for_pod_ready(pod, Duration::from_secs(120)).expect("pod ready");

    // 256 Mi limit + 64 MB overhead = 320 MB VM; the guest kernel
    // reserves ~18 MB, so MemTotal lands between the pod limit and
    // the raw VM size.
    let mem_total_kb = guest_mem_total_kb(pod);
    assert!(
        (256 * 1024..=320 * 1024).contains(&mem_total_kb),
        "guest MemTotal {mem_total_kb} kB outside expected 256–320 MB for a 256Mi pod"
    );

    // Allocate past the per-container cgroup limit (the shim
    // preserves linux.resources.memory.limit). Process-level OOM
    // kills the hog exec; the main sleep (and agent) survive.
    let start = Instant::now();
    let hog = kubectl_exec(pod, &["sh", "-c", "a=x; while true; do a=\"$a$a\"; done"]);
    assert!(
        hog.is_err(),
        "in-guest allocation past 256Mi cgroup limit should OOM, got: {hog:?}"
    );
    assert!(
        start.elapsed() < Duration::from_secs(60),
        "guest OOM kill took {:?} — suspiciously long for a 256Mi cgroup / 320 MB VM",
        start.elapsed()
    );

    // The pod (and its agent plumbing) survived the in-guest OOM.
    let alive = kubectl_exec(pod, &["echo", "still-alive"]).expect("pod alive after guest OOM");
    assert!(alive.contains("still-alive"));

    // ... and the host kernel never OOMed.
    let host_oom_after = host_oom_kill_count();
    assert_eq!(
        host_oom_before, host_oom_after,
        "host kernel logged new OOM kill events — guest memory must be contained in the VM"
    );

    kubectl_delete_pod(pod);
}

/// A pod asking for 8Gi boots a VM whose RAM straddles the
/// 32-bit MMIO hole — low RAM below `0xfe00_0000`, the rest at 4 GiB —
/// reaches Ready, reports the matching `MemTotal`, and can actually use
/// the memory past 4 GiB.
///
/// Before 19a the initrd was placed at the top of guest RAM and its
/// address truncated to the 32-bit `boot_params.hdr.ramdisk_image`, so
/// any pod over ~4 GiB booted a kernel with no initramfs
/// ("VFS: Unable to mount root fs"), the agent never started, and the
/// shim failed with `agent connect failed: Connection timed out`.
#[test]
fn test_pod_large_memory_boots() {
    let _leak_guard = ensure_shim_installed();
    let pod = "test-k7d-res-mem-8gi";
    kubectl_delete_pod(pod);
    let _pod_guard = PodGuard(pod);

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
    resources:
      limits:
        memory: 8Gi
      requests:
        memory: 8Gi
"#
    )))
    .expect("kubectl apply");
    wait_for_pod_ready(pod, Duration::from_secs(180)).expect("8Gi pod ready");

    // 8 Gi limit + 64 MB overhead = 8256 MB of guest RAM; the guest
    // kernel reserves ~230 MB of it (mostly `struct page`), so MemTotal
    // must land comfortably above 4 GiB and never above the VM size.
    let mem_total_kb = guest_mem_total_kb(pod);
    assert!(
        (7 * 1024 * 1024..=8256 * 1024).contains(&mem_total_kb),
        "guest MemTotal {mem_total_kb} kB outside expected 7 GiB–8256 MB for an 8Gi pod \
         (RAM past the 32-bit MMIO hole missing?)"
    );

    // ZONE_NORMAL only exists when the guest has RAM past 4 GiB — proof
    // the high region reached the E820 map and the guest accepted it.
    let zones = kubectl_exec(pod, &["cat", "/proc/zoneinfo"]).expect("read guest zoneinfo");
    assert!(
        zones.contains("zone   Normal"),
        "guest has no ZONE_NORMAL — RAM past 4 GiB never made it into the E820 map"
    );

    // Use a GiB of it and read every byte back: Linux allocates from the
    // highest zone first, so this exercises the region past 4 GiB. A byte
    // outside the `yes` pattern would mean that GPA range is not backed by
    // real RAM (e.g. aliased onto the LAPIC / IOAPIC / KVM TSS windows).
    let stray = kubectl_exec(
        pod,
        &[
            "sh",
            "-c",
            "yes | head -c 1073741824 >/tmp/blob && tr -d 'y\\n' </tmp/blob | wc -c",
        ],
    )
    .expect("write + verify 1 GiB inside the guest");
    assert_eq!(
        stray.trim(),
        "0",
        "guest memory past 4 GiB returned bytes outside the written pattern"
    );

    kubectl_delete_pod(pod);
}

/// A pod with `cpu: "0.5"` gets its vCPU thread capped host-side: four
/// busy-loop workers inside the guest burn ≤ ~55% of one host core
/// (sampled from the per-VM CPU cgroup, i.e. the vCPU thread itself —
/// not the shim process).
#[test]
fn test_pod_cpu_limit_caps_host_usage() {
    let _leak_guard = ensure_shim_installed();
    let pod = "test-k7d-res-cpu";
    kubectl_delete_pod(pod);
    let baseline = vm_cpu_cgroups();

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
    command: ["sh", "-c", "for i in 1 2 3 4; do (while :; do :; done) & done; sleep infinity"]
    resources:
      limits:
        cpu: "0.5"
"#
    )))
    .expect("kubectl apply");
    wait_for_pod_ready(pod, Duration::from_secs(120)).expect("pod ready");

    // Exactly one capped VM (this pod's) with the pod's CFS quota.
    let cgroups = vm_cpu_cgroups_since(&baseline);
    assert_eq!(
        cgroups.len(),
        1,
        "expected exactly one new per-VM CPU cgroup, found: {cgroups:?}"
    );
    let cg = &cgroups[0];
    let cpu_max = std::fs::read_to_string(cg.join("cpu.max")).expect("read cpu.max");
    assert_eq!(
        cpu_max.trim(),
        "50000 100000",
        "cpu.max should carry the pod's CFS quota"
    );
    let threads = std::fs::read_to_string(cg.join("cgroup.threads")).expect("read cgroup.threads");
    assert!(
        !threads.trim().is_empty(),
        "the vCPU thread should be in the VM cgroup"
    );

    // Sample the vCPU thread's host CPU usage over ~10 s while the
    // four in-guest busy loops spin.
    std::thread::sleep(Duration::from_secs(2)); // let the workers spin up
    let usage_before = cgroup_usage_usec(cg);
    let start = Instant::now();
    std::thread::sleep(Duration::from_secs(10));
    let used_usec = cgroup_usage_usec(cg) - usage_before;
    let elapsed_usec = start.elapsed().as_micros() as u64;

    #[allow(clippy::cast_precision_loss)]
    let utilization = used_usec as f64 / elapsed_usec as f64;
    assert!(
        utilization <= 0.55,
        "vCPU thread used {utilization:.2} of one host core; the 0.5-CPU cap must hold"
    );
    assert!(
        utilization >= 0.30,
        "vCPU thread used only {utilization:.2} of one host core — were the busy loops running?"
    );

    kubectl_delete_pod(pod);

    // Teardown removes the per-VM cgroup (Vm drop joins the vCPU
    // thread first, then the cgroup drops).
    let deadline = Instant::now() + Duration::from_secs(15);
    while !vm_cpu_cgroups_since(&baseline).is_empty() {
        assert!(
            Instant::now() < deadline,
            "per-VM CPU cgroup not removed after pod delete: {:?}",
            vm_cpu_cgroups_since(&baseline)
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

// ---- the multi-vCPU tests ----

/// Deletes the named pod on drop — panic-safe cleanup so a failing
/// test doesn't leak its pod (whose per-VM CPU cgroup would break the
/// `vm_cpu_cgroups().len() == 1` assertions of every later test).
struct PodGuard(&'static str);
impl Drop for PodGuard {
    fn drop(&mut self) {
        kubectl_delete_pod(self.0);
    }
}

/// Apply a `cpu: "2"` pod (4 in-guest busy-loop workers) and wait for
/// it to be Running. Shared by the tests.
fn apply_multi_vcpu_pod(pod: &str) {
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
    command: ["sh", "-c", "for i in 1 2 3 4; do (while :; do :; done) & done; sleep infinity"]
    resources:
      limits:
        cpu: "2"
"#
    )))
    .expect("kubectl apply");
    wait_for_pod_ready(pod, Duration::from_secs(120)).expect("pod ready");
}

/// A pod with `cpu: "2"` boots a 2-vCPU guest (`nproc` = 2)
/// and the pod's CFS quota caps the whole VM: four busy-loop workers
/// burn ≤ ~2.2 host cores (sampled from the per-VM CPU cgroup, which
/// contains both vCPU threads) — and > 1.2 cores, proving the second
/// vCPU actually runs in parallel.
#[test]
fn test_pod_cpu_limit_multi_vcpu() {
    let _leak_guard = ensure_shim_installed();
    let pod = "test-k7d-res-mvcpu";
    kubectl_delete_pod(pod);
    let baseline = vm_cpu_cgroups();
    let _pod_guard = PodGuard(pod);
    apply_multi_vcpu_pod(pod);

    let nproc = kubectl_exec(pod, &["nproc"]).expect("nproc in guest");
    assert_eq!(nproc.trim(), "2", "cpu: \"2\" pod must see 2 vCPUs");

    let cgroups = vm_cpu_cgroups_since(&baseline);
    assert_eq!(
        cgroups.len(),
        1,
        "expected exactly one new per-VM CPU cgroup, found: {cgroups:?}"
    );
    let cg = &cgroups[0];
    let cpu_max = std::fs::read_to_string(cg.join("cpu.max")).expect("read cpu.max");
    assert_eq!(
        cpu_max.trim(),
        "200000 100000",
        "cpu.max should carry the pod's 2-CPU CFS quota"
    );

    // Sample both vCPU threads' host CPU usage over ~10 s while the
    // four in-guest busy loops spin across the 2 guest CPUs.
    std::thread::sleep(Duration::from_secs(2)); // let the workers spin up
    let usage_before = cgroup_usage_usec(cg);
    let start = Instant::now();
    std::thread::sleep(Duration::from_secs(10));
    let used_usec = cgroup_usage_usec(cg) - usage_before;
    let elapsed_usec = start.elapsed().as_micros() as u64;

    #[allow(clippy::cast_precision_loss)]
    let utilization = used_usec as f64 / elapsed_usec as f64;
    assert!(
        utilization <= 2.2,
        "VM used {utilization:.2} host cores; the 2-CPU cap must hold across both vCPU threads"
    );
    assert!(
        utilization >= 1.2,
        "VM used only {utilization:.2} host cores — is the second vCPU actually running?"
    );

    kubectl_delete_pod(pod);
}

/// Every vCPU kernel TID lands in the per-VM cgroup's
/// `cgroup.threads` — a quota that only caps the BSP is a silent
/// escape hatch for the second vCPU. The cgroup legitimately holds
/// more than the vCPU threads: virtio device workers spawned *by* a
/// vCPU thread inherit its cgroup (cgroup v2 threaded semantics),
/// which is desirable — device work is VM work and the quota must cap
/// it too. So identify the vCPU threads by name (`vcpu0`/`vcpu1`,
/// set in `Vm::start`) rather than counting.
#[test]
fn test_multi_vcpu_all_tids_in_cgroup() {
    let _leak_guard = ensure_shim_installed();
    let pod = "test-k7d-res-mvcpu-tids";
    kubectl_delete_pod(pod);
    let baseline = vm_cpu_cgroups();
    let _pod_guard = PodGuard(pod);
    apply_multi_vcpu_pod(pod);

    let cgroups = vm_cpu_cgroups_since(&baseline);
    assert_eq!(
        cgroups.len(),
        1,
        "expected exactly one new per-VM CPU cgroup, found: {cgroups:?}"
    );
    let threads_raw =
        std::fs::read_to_string(cgroups[0].join("cgroup.threads")).expect("read cgroup.threads");
    let mut vcpu_names: Vec<String> = threads_raw
        .split_whitespace()
        .filter_map(|tid| std::fs::read_to_string(format!("/proc/{tid}/comm")).ok())
        .map(|comm| comm.trim().to_string())
        .filter(|comm| comm.starts_with("vcpu"))
        .collect();
    vcpu_names.sort();
    assert_eq!(
        vcpu_names,
        ["vcpu0", "vcpu1"],
        "both vCPU kernel TIDs must be in cgroup.threads; threads found: {threads_raw:?}"
    );
}

/// Regression guard for CHALLENGES.md §23: a 2-vCPU pod
/// deletes within 15 s and the per-VM CPU cgroup disappears (both
/// vCPU threads joined, cgroup rmdir'd).
#[test]
fn test_multi_vcpu_teardown() {
    let _leak_guard = ensure_shim_installed();
    let pod = "test-k7d-res-mvcpu-teardown";
    kubectl_delete_pod(pod);
    let baseline = vm_cpu_cgroups();
    let _pod_guard = PodGuard(pod);
    apply_multi_vcpu_pod(pod);
    assert_eq!(
        vm_cpu_cgroups_since(&baseline).len(),
        1,
        "the capped VM's cgroup should exist while the pod runs"
    );

    let start = Instant::now();
    kubectl_delete_pod(pod);
    assert!(
        start.elapsed() <= Duration::from_secs(15),
        "2-vCPU pod delete took {:?} (> 15 s) — teardown must join both vCPU threads promptly",
        start.elapsed()
    );

    let deadline = Instant::now() + Duration::from_secs(15);
    while !vm_cpu_cgroups_since(&baseline).is_empty() {
        assert!(
            Instant::now() < deadline,
            "per-VM CPU cgroup not removed after 2-vCPU pod delete: {:?}",
            vm_cpu_cgroups_since(&baseline)
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// A pod with no resources (BestEffort) keeps today's defaults: a
/// 256 MB single-vCPU VM, and no host-side CPU cap.
#[test]
fn test_besteffort_pod_gets_defaults() {
    let _leak_guard = ensure_shim_installed();
    let pod = "test-k7d-res-be";
    kubectl_delete_pod(pod);
    let baseline = vm_cpu_cgroups();
    let _pod_guard = PodGuard(pod);

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
"#
    )))
    .expect("kubectl apply");
    wait_for_pod_ready(pod, Duration::from_secs(120)).expect("pod ready");

    // 256 MB VM: the guest kernel reserves ~18 MB, so MemTotal sits
    // just under 256 MB.
    let mem_total_kb = guest_mem_total_kb(pod);
    assert!(
        (200 * 1024..=256 * 1024).contains(&mem_total_kb),
        "guest MemTotal {mem_total_kb} kB outside expected range for the 256 MB default VM"
    );

    let nproc = kubectl_exec(pod, &["nproc"]).expect("nproc in guest");
    assert_eq!(nproc.trim(), "1", "BestEffort pod should get 1 vCPU");

    // No CPU limit -> no per-VM cgroup, vCPU thread uncapped.
    let cgroups = vm_cpu_cgroups_since(&baseline);
    assert!(
        cgroups.is_empty(),
        "BestEffort pod must not get a CPU cap, found: {cgroups:?}"
    );
}
