//! Integration tests: a `runtimeClassName: k7` pod annotated
//! `k7d.katakate.org/backend: firecracker` on stock Firecracker under
//! the stock jailer.
//!
//! Everything here goes through kubectl, because the claim being tested
//! is not "the daemon can boot Firecracker" but "a pod
//! the kubelet creates lands on Firecracker with its erofs rootfs, its
//! writable disks, its network, `kubectl exec`, and `kubectl logs`
//! working" — and every one of those crosses the shim.
//!
//! The negative half matters as much: virtiofs, time warp and dilation
//! have no Firecracker implementation, and each must fail by name
//! rather than degrade into a pod that boots without the thing it
//! asked for.

mod common;

use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

/// Annotation that puts a pod on Firecracker.
const BACKEND_ANN: &str = "k7d.katakate.org/backend";

/// Pods on this backend cold-boot a VM, pull an image and mount an
/// erofs — the same budget the native block-path suite gives itself.
const POD_READY: Duration = Duration::from_secs(240);

/// Bring the node to the state every test here assumes: pinned
/// Firecracker + jailer installed, the shim built and registered with
/// containerd, the `k7` RuntimeClass present, the k7d daemon live, and
/// containerd forwarding `k7d.katakate.org/*` pod annotations into the
/// sandbox OCI spec (without which the shim never sees `backend`).
fn ensure_fc_node() -> common::LeakGuard {
    common::ensure_firecracker_installed();
    common::ensure_pod_annotations_forwarded();
    common::ensure_shim_installed()
}

/// Deletes the named pod on drop, so a failing assertion cannot leak a
/// jailed Firecracker process into the next test.
struct PodGuard(String);

impl Drop for PodGuard {
    fn drop(&mut self) {
        let _ = Command::new("kubectl")
            .args([
                "delete",
                "pod",
                &self.0,
                "--ignore-not-found",
                "--wait=true",
                "--timeout=60s",
                "--grace-period=1",
            ])
            .output();
    }
}

fn kubectl_apply(yaml: &str) -> Result<(), String> {
    common::kubectl_apply(&common::pin_to_local_node(yaml))
}

fn kubectl_delete_pod(name: &str) {
    let _ = Command::new("kubectl")
        .args([
            "delete",
            "pod",
            name,
            "--ignore-not-found",
            "--wait=true",
            "--timeout=60s",
            "--grace-period=1",
        ])
        .output();
}

fn kubectl_exec(pod: &str, container: Option<&str>, cmd: &[&str]) -> Result<String, String> {
    let mut args = vec!["exec".to_string(), pod.to_string()];
    if let Some(c) = container {
        args.push("-c".to_string());
        args.push(c.to_string());
    }
    args.push("--".to_string());
    args.extend(cmd.iter().map(ToString::to_string));
    let out = Command::new("kubectl")
        .args(&args)
        .output()
        .map_err(|e| format!("kubectl exec: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

fn wait_for_pod_ready(name: &str, timeout: Duration) -> Result<Duration, String> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        let out = Command::new("kubectl")
            .args(["get", "pod", name, "-o", "jsonpath={.status.phase}"])
            .output()
            .map_err(|e| e.to_string())?;
        match String::from_utf8_lossy(&out.stdout).trim() {
            "Running" => return Ok(start.elapsed()),
            "Failed" => return Err(format!("pod {name} went Failed")),
            _ => std::thread::sleep(Duration::from_secs(1)),
        }
    }
    Err(format!(
        "pod {name} not Running within {timeout:?}: {}",
        pod_diagnosis(name)
    ))
}

fn wait_for_all_containers_ready(name: &str, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        let out = Command::new("kubectl")
            .args([
                "get",
                "pod",
                name,
                "-o",
                "jsonpath={.status.containerStatuses[*].ready}",
            ])
            .output()
            .map_err(|e| e.to_string())?;
        let ready = String::from_utf8_lossy(&out.stdout);
        let flags: Vec<&str> = ready.split_whitespace().collect();
        if !flags.is_empty() && flags.iter().all(|f| *f == "true") {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "pod {name} containers not ready within {timeout:?} (ready={ready}): {}",
                pod_diagnosis(name)
            ));
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Pod events plus the daemon's log tail. A Firecracker pod that never
/// reaches Running usually failed in the jailer or the drive staging,
/// neither of which is visible in `kubectl get pod`.
fn pod_diagnosis(name: &str) -> String {
    let describe = Command::new("kubectl")
        .args(["describe", "pod", name])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let events: Vec<&str> = describe
        .lines()
        .skip_while(|l| !l.starts_with("Events:"))
        .take(20)
        .collect();
    let journal = Command::new("journalctl")
        .args(["-u", "k7d", "-n", "40", "--no-pager"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    format!("\n{}\n--- k7d ---\n{journal}", events.join("\n"))
}

/// The daemon's own answer for the VM behind `pod`: backend, jailed
/// pid/uid/chroot, drive count.
fn fc_vm_info(pod: &str) -> k7d::control::VmInfo {
    let vm_id = common::pod_vm_id(pod);
    let mut client = k7d::control::Client::connect_env().expect("connect k7d daemon");
    let k7d::control::Response::VmList { vms } = client
        .call(&k7d::control::Request::ListVms)
        .expect("list_vms")
    else {
        panic!("unexpected list_vms response");
    };
    vms.into_iter()
        .find(|v| v.vm_id == vm_id)
        .unwrap_or_else(|| panic!("daemon does not list {vm_id} for pod {pod}"))
}

fn assert_on_firecracker(pod: &str) -> k7d::control::VmInfo {
    let info = fc_vm_info(pod);
    assert_eq!(
        info.backend,
        k7d::guest::Backend::Firecracker,
        "pod {pod} carries {BACKEND_ANN}=firecracker but the daemon booted it on \
         {:?} — the annotation did not reach VmConfig",
        info.backend
    );
    let jail = info
        .jail
        .as_ref()
        .unwrap_or_else(|| panic!("Firecracker VM {} reports no jail", info.vm_id));
    assert!(
        Path::new(&format!("/proc/{}", jail.pid)).is_dir(),
        "jailed pid {} is not alive",
        jail.pid
    );
    assert!(
        jail.uid >= k7d::fc::stage::DEFAULT_UID_BASE,
        "Firecracker must run as an unprivileged uid, got {}",
        jail.uid
    );
    info
}

// ── 1. Ubuntu pod: erofs rootfs, scratch overlay, exec, logs ─────────

/// The headline claim: an `ubuntu:24.04` pod annotated onto Firecracker
/// reaches Running, `kubectl exec` and `kubectl logs` work, the rootfs
/// is the read-only erofs image the shim built, and the container's
/// writes land on the scratch **disk** rather than guest RAM.
#[test]
fn test_fc_pod_ubuntu_erofs_scratch_exec_logs() {
    let _guard = ensure_fc_node();
    let pod = common::unique_name("test-fc-ubuntu");
    kubectl_delete_pod(&pod);
    let _pod = PodGuard(pod.clone());

    kubectl_apply(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-fc-ubuntu
  annotations:
    k7d.katakate.org/backend: firecracker
spec:
  runtimeClassName: k7
  containers:
  - name: main
    image: ubuntu:24.04
    command: ["sh", "-c", "echo fc-logs-marker && sleep infinity"]
"#,
    )
    .unwrap();
    wait_for_pod_ready(&pod, POD_READY).unwrap();
    wait_for_all_containers_ready(&pod, Duration::from_secs(120)).unwrap();

    let info = assert_on_firecracker(&pod);
    let drives = common::vm_state(&info.vm_id).block_devices;
    assert!(
        drives >= 3,
        "expected at least tools + rootfs + scratch drives, got {drives}"
    );

    let os = kubectl_exec(&pod, None, &["cat", "/etc/os-release"]).expect("kubectl exec");
    assert!(
        os.contains("Ubuntu") && os.contains("24.04"),
        "exec did not reach the ubuntu rootfs: {os}"
    );

    let logs = Command::new("kubectl")
        .args(["logs", &pod])
        .output()
        .expect("kubectl logs");
    assert!(
        String::from_utf8_lossy(&logs.stdout).contains("fc-logs-marker"),
        "kubectl logs did not stream from the Firecracker guest: {:?} {:?}",
        String::from_utf8_lossy(&logs.stdout),
        String::from_utf8_lossy(&logs.stderr)
    );

    // The rootfs is an overlay whose lower is the erofs image; the
    // upper has to be on the scratch disk, or the pod's writes are
    // guest RAM inside a `memory.max`-capped cgroup.
    let mounts = kubectl_exec(&pod, None, &["cat", "/proc/mounts"]).expect("read /proc/mounts");
    let root_line = mounts
        .lines()
        .find(|l| l.split_whitespace().nth(1) == Some("/"))
        .unwrap_or_else(|| panic!("no root mount in\n{mounts}"));
    assert!(
        root_line.contains("overlay"),
        "root is not the erofs overlay: {root_line}"
    );

    // `/proc/mounts` rather than `df`: the initramfs busybox is
    // deliberately symlink-poor (guest/rootfs/build.sh) and has no df,
    // and the device name is the thing being asserted anyway.
    let guest_mounts = agent_exec(&pod, &["cat", "/proc/mounts"]);
    let scratch_line = guest_mounts
        .lines()
        .find(|l| l.split_whitespace().nth(1) == Some(k7d::disks::SCRATCH_GUEST_MOUNT))
        .unwrap_or_else(|| {
            panic!(
                "{} is not mounted in the guest:\n{guest_mounts}",
                k7d::disks::SCRATCH_GUEST_MOUNT
            )
        });
    assert!(
        scratch_line.starts_with("/dev/vd"),
        "{} is not a virtio-blk disk on Firecracker: {scratch_line}",
        k7d::disks::SCRATCH_GUEST_MOUNT
    );
    assert!(
        guest_mounts.contains("erofs"),
        "no erofs mount in the guest:\n{guest_mounts}"
    );
}

/// Run a command in the *guest* (not the container) through the agent,
/// which is how the scratch and erofs mounts — outside every
/// container's mount namespace — are observable.
fn agent_exec(pod: &str, cmd: &[&str]) -> String {
    let sandbox_id = common::pod_sandbox_id(pod);
    let mut client = k7d::control::Client::connect_env().expect("connect k7d daemon");
    let endpoint = match client
        .call(&k7d::control::Request::LookupSandbox {
            sandbox_id: sandbox_id.clone(),
        })
        .expect("lookup_sandbox")
    {
        k7d::control::Response::SandboxFound {
            agent_endpoint: Some(endpoint),
            ..
        } => endpoint,
        other => panic!("no agent endpoint for pod {pod} (sandbox {sandbox_id}): {other:?}"),
    };
    assert!(
        matches!(endpoint, k7d::guest::AgentEndpoint::FcUds { .. }),
        "a Firecracker pod's agent must be reached over the microVM's vsock UDS, got {endpoint:?}"
    );
    let mut agent = k7d::api::AgentClient::connect_endpoint(&endpoint, Duration::from_secs(20))
        .expect("connect guest agent");
    let out = agent.exec(cmd).expect("agent exec");
    format!("{}{}", out.stdout, out.stderr)
}

// ── 2. Container scratch and named data disks ────────────────────────

/// Per-container scratch and a named data disk are Firecracker drives
/// like any other, and the data disk's whole contract — content that
/// outlives the pod — has to survive delete + recreate under the same
/// id. That is the one place a reflink would have been wrong: a CoW
/// copy of the disk would take the writes and be thrown away with the
/// chroot.
#[test]
fn test_fc_pod_container_scratch_and_data_disk() {
    let _guard = ensure_fc_node();
    let disk_id = common::unique_name("fcdata");
    let pod = common::unique_name("test-fc-disks");
    kubectl_delete_pod(&pod);

    let manifest = format!(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-fc-disks
  annotations:
    k7d.katakate.org/backend: firecracker
    k7d.katakate.org/container-scratch-size: "main=256Mi"
    k7d.katakate.org/data-disks: "{disk_id}:256Mi:/mnt/keep"
spec:
  runtimeClassName: k7
  containers:
  - name: main
    image: busybox:1.36
    command: ["sh", "-c", "sleep infinity"]
"#
    );

    {
        let _pod = PodGuard(pod.clone());
        kubectl_apply(&manifest).unwrap();
        wait_for_pod_ready(&pod, POD_READY).unwrap();
        wait_for_all_containers_ready(&pod, Duration::from_secs(120)).unwrap();
        assert_on_firecracker(&pod);

        let mounts = agent_exec(&pod, &["cat", "/proc/mounts"]);
        assert!(
            mounts.contains("/mnt/keep"),
            "the named data disk is not mounted in the guest:\n{mounts}"
        );
        let cscratch = format!("{}/main", k7d::disks::CONTAINER_SCRATCH_GUEST_ROOT);
        assert!(
            mounts.contains(&cscratch),
            "the per-container scratch disk is not mounted at {cscratch}:\n{mounts}"
        );

        agent_exec(&pod, &["sh", "-c", "echo fc-persisted > /mnt/keep/marker"]);
        let back = agent_exec(&pod, &["cat", "/mnt/keep/marker"]);
        assert!(back.contains("fc-persisted"), "{back}");
    }

    // Recreate with the same disk id: the marker must still be there.
    kubectl_delete_pod(&pod);
    let _pod = PodGuard(pod.clone());
    kubectl_apply(&manifest).unwrap();
    wait_for_pod_ready(&pod, POD_READY).unwrap();
    wait_for_all_containers_ready(&pod, Duration::from_secs(120)).unwrap();
    assert_on_firecracker(&pod);
    let back = agent_exec(&pod, &["cat", "/mnt/keep/marker"]);
    assert!(
        back.contains("fc-persisted"),
        "data disk {disk_id} lost its content across pod delete + recreate — the \
         drive was a copy, not the host file:\n{back}"
    );

    drop(_pod);
    kubectl_delete_pod(&pod);
    let mut client = k7d::control::Client::connect_env().expect("connect k7d daemon");
    let _ = client.call(&k7d::control::Request::DeleteDataDisk { id: disk_id });
}

// ── 3. Cluster bridge and CNI pod netns ──────────────────────────────

/// Two Firecracker pods on one `cluster-id` share a bridge and must
/// reach each other, and the CNI path has to survive
/// `attach_to_pod_netns` moving the TAP *after* the VMM has it open —
/// the property the native backend relies on too, asserted here
/// against a VMM that is a different process.
#[test]
fn test_fc_pods_cluster_bridge_and_cni() {
    let _guard = ensure_fc_node();
    let cluster = common::unique_name("fccluster");
    let a = common::unique_name("test-fc-neta");
    let b = common::unique_name("test-fc-netb");
    kubectl_delete_pod(&a);
    kubectl_delete_pod(&b);
    let _ga = PodGuard(a.clone());
    let _gb = PodGuard(b.clone());

    for (name, tag) in [(&a, "test-fc-neta"), (&b, "test-fc-netb")] {
        kubectl_apply(&format!(
            r#"
apiVersion: v1
kind: Pod
metadata:
  name: {tag}
  annotations:
    k7d.katakate.org/backend: firecracker
    k7d.katakate.org/cluster-id: "{cluster}"
spec:
  runtimeClassName: k7
  containers:
  - name: main
    image: busybox:1.36
    command: ["sh", "-c", "sleep infinity"]
"#
        ))
        .unwrap();
        wait_for_pod_ready(name, POD_READY).unwrap();
    }
    wait_for_all_containers_ready(&a, Duration::from_secs(120)).unwrap();
    wait_for_all_containers_ready(&b, Duration::from_secs(120)).unwrap();

    let info_a = assert_on_firecracker(&a);
    let info_b = assert_on_firecracker(&b);
    assert_ne!(
        info_a.vm_id, info_b.vm_id,
        "the two pods must be two VMs on one bridge"
    );

    // Guest-to-guest over the cluster bridge.
    let peer_ip = guest_ip(&b);
    let ping = agent_exec(&a, &["ping", "-c", "3", "-W", "5", &peer_ip]);
    assert!(
        ping.contains(" 0% packet loss"),
        "Firecracker pod {a} cannot reach {b} ({peer_ip}) over the cluster bridge:\n{ping}"
    );

    // CNI: the pod IP kubelet assigned is reachable from the node,
    // which only holds once the TAP has been moved into the pod netns
    // and the NAT installed — after the VMM opened it.
    let pod_ip = String::from_utf8_lossy(
        &Command::new("kubectl")
            .args(["get", "pod", &a, "-o", "jsonpath={.status.podIP}"])
            .output()
            .expect("kubectl get podIP")
            .stdout,
    )
    .trim()
    .to_string();
    assert!(!pod_ip.is_empty(), "pod {a} has no CNI IP");
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let out = Command::new("ping")
            .args(["-c", "3", "-W", "5", &pod_ip])
            .output()
            .expect("ping should run");
        let last = String::from_utf8_lossy(&out.stdout).into_owned();
        if last.contains(" 0% packet loss") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "pod IP {pod_ip} of Firecracker pod {a} is not reachable from the node \
             after attach_to_pod_netns:\n{last}"
        );
        std::thread::sleep(Duration::from_secs(2));
    }
}

/// The guest's own address on the cluster bridge (`eth0` inside the
/// microVM), which is what a peer VM pings.
fn guest_ip(pod: &str) -> String {
    let out = agent_exec(pod, &["ip", "-4", "-o", "addr", "show", "eth0"]);
    out.split_whitespace()
        .skip_while(|t| *t != "inet")
        .nth(1)
        .and_then(|cidr| cidr.split('/').next())
        .unwrap_or_else(|| panic!("no IPv4 on eth0 of pod {pod}:\n{out}"))
        .to_string()
}

// ── 4. Image-slot late fill via PATCH /drives ────────────────────────

/// A second container with a *distinct* image arrives after the VM has
/// booted, so its erofs rides a spare image slot. On Firecracker the
/// slot's boot-time file is a link staged into the chroot, and on a
/// node whose erofs cache and jail filesystems differ that link is a
/// copy — so the shim's in-place fill is invisible to the guest unless
/// the daemon repoints the drive. This is the `PATCH /drives` path.
#[test]
fn test_fc_pod_image_slot_late_fill() {
    let _guard = ensure_fc_node();
    let pod = common::unique_name("test-fc-slot");
    kubectl_delete_pod(&pod);
    let _pod = PodGuard(pod.clone());

    kubectl_apply(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-fc-slot
  annotations:
    k7d.katakate.org/backend: firecracker
spec:
  runtimeClassName: k7
  containers:
  - name: first
    image: busybox:1.36
    command: ["sh", "-c", "echo first-up && sleep infinity"]
  - name: second
    image: alpine:3.20
    command: ["sh", "-c", "echo second-up && sleep infinity"]
"#,
    )
    .unwrap();
    wait_for_pod_ready(&pod, POD_READY).unwrap();
    wait_for_all_containers_ready(&pod, Duration::from_secs(180)).unwrap();
    assert_on_firecracker(&pod);

    // Each container must be running from its own image: the second
    // one is the slot that was filled and PATCHed after boot.
    let first = kubectl_exec(&pod, Some("first"), &["sh", "-c", "ls /bin/busybox"])
        .expect("exec in the boot-time image");
    assert!(first.contains("/bin/busybox"), "{first}");
    let second = kubectl_exec(&pod, Some("second"), &["cat", "/etc/alpine-release"])
        .expect("exec in the late-filled image");
    assert!(
        second.trim().starts_with("3.20"),
        "the second container is not running alpine — the image slot fill did not \
         reach the guest: {second}"
    );
}

// ── 5. Everything Firecracker cannot do, refused by name ─────────────

/// A hostPath volume has no Firecracker implementation (virtiofs is
/// native-only, forever), and a `WarpClock` against an FC VM has none
/// either. Both must say so.
#[test]
fn test_fc_pod_hostpath_and_warp_are_refused() {
    let _guard = ensure_fc_node();
    let pod = common::unique_name("test-fc-hostpath");
    kubectl_delete_pod(&pod);
    let _pod = PodGuard(pod.clone());

    kubectl_apply(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-fc-hostpath
  annotations:
    k7d.katakate.org/backend: firecracker
spec:
  runtimeClassName: k7
  containers:
  - name: main
    image: busybox:1.36
    command: ["sh", "-c", "sleep infinity"]
    volumeMounts:
    - name: hp
      mountPath: /host
  volumes:
  - name: hp
    hostPath:
      path: /var/log
      type: Directory
"#,
    )
    .unwrap();

    // The pod must never reach Running: it asked for a volume this
    // backend cannot give it.
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut saw_message = false;
    while Instant::now() < deadline {
        let describe = Command::new("kubectl")
            .args(["describe", "pod", &pod])
            .output()
            .expect("kubectl describe");
        let text = String::from_utf8_lossy(&describe.stdout);
        if text.contains("backend firecracker has no virtiofs") {
            saw_message = true;
            break;
        }
        let phase = Command::new("kubectl")
            .args(["get", "pod", &pod, "-o", "jsonpath={.status.phase}"])
            .output()
            .expect("kubectl get");
        assert_ne!(
            String::from_utf8_lossy(&phase.stdout).trim(),
            "Running",
            "a hostPath pod reached Running on Firecracker — the volume was \
             silently dropped"
        );
        std::thread::sleep(Duration::from_secs(2));
    }
    assert!(
        saw_message,
        "hostPath on Firecracker must fail Create naming the backend: {}",
        pod_diagnosis(&pod)
    );

    // And the time-warp verbs, against a live FC VM.
    let live = common::unique_name("test-fc-warp");
    kubectl_delete_pod(&live);
    let _live_guard = PodGuard(live.clone());
    kubectl_apply(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-fc-warp
  annotations:
    k7d.katakate.org/backend: firecracker
    k7d.katakate.org/cluster-id: "fc-warp-cluster"
spec:
  runtimeClassName: k7
  containers:
  - name: main
    image: busybox:1.36
    command: ["sh", "-c", "sleep infinity"]
"#,
    )
    .unwrap();
    wait_for_pod_ready(&live, POD_READY).unwrap();
    assert_on_firecracker(&live);

    let mut client = k7d::control::Client::connect_env().expect("connect k7d daemon");
    match client
        .call(&k7d::control::Request::WarpClock {
            cluster_id: "fc-warp-cluster".to_string(),
            delta_ms: 60_000,
        })
        .expect("warp_clock")
    {
        k7d::control::Response::Error { message } => assert!(
            message.contains("warp_clock") && message.contains("Firecracker"),
            "warp_clock on Firecracker must name the op and the backend: {message}"
        ),
        other => panic!("warp_clock must be Unsupported on Firecracker: {other:?}"),
    }
}

// ── 6. The jail, audited from the host ───────────────────────────────

/// Everything the jailed VMM has open is inside its chroot, except the
/// two things that cannot be: `/dev/kvm` and the TAP. And its
/// `memory.max` is the pod's limit plus the VMM's own overhead — a cap
/// at exactly the guest's RAM would OOM-kill the VMM instead of the
/// workload.
#[test]
fn test_fc_pod_jail_fds_and_memory_max() {
    let _guard = ensure_fc_node();
    let pod = common::unique_name("test-fc-jail");
    kubectl_delete_pod(&pod);
    let _pod = PodGuard(pod.clone());

    kubectl_apply(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-fc-jail
  annotations:
    k7d.katakate.org/backend: firecracker
    k7d.katakate.org/cluster-id: "fc-jail-cluster"
spec:
  runtimeClassName: k7
  containers:
  - name: main
    image: busybox:1.36
    command: ["sh", "-c", "sleep infinity"]
    resources:
      limits:
        memory: "512Mi"
"#,
    )
    .unwrap();
    wait_for_pod_ready(&pod, POD_READY).unwrap();
    let info = assert_on_firecracker(&pod);
    let jail = info.jail.expect("jailed process info");

    // A chrooted process' `/proc/<pid>/fd` links read back **relative
    // to its own root**, so an fd opened after the chroot shows up as
    // `/img/rootfs.erofs` and one opened before it (the jailer's
    // `stderr.log`) as the full host path. Neither string can be
    // compared to the chroot directly: the test is whether the fd and
    // the same path resolved *inside* the jail are the same inode.
    let fd_dir = format!("/proc/{}/fd", jail.pid);
    let chroot = std::fs::canonicalize(&jail.chroot).expect("canonicalize the jail chroot");
    let mut outside = BTreeSet::new();
    for entry in std::fs::read_dir(&fd_dir).expect("read the jailed process' fd table") {
        let entry = entry.expect("fd entry");
        let Ok(target) = std::fs::read_link(entry.path()) else {
            continue;
        };
        let text = target.to_string_lossy().into_owned();
        // Pipes, sockets and eventfds have no path; the TAP and
        // /dev/kvm are the two host devices a VMM must hold, and
        // /dev/null is what the jailer points the daemon-inherited
        // std streams at before it drops privileges.
        if !text.starts_with('/')
            || text.starts_with("/dev/kvm")
            || text.starts_with("/dev/net/tun")
            || text == "/dev/null"
        {
            continue;
        }
        if std::fs::canonicalize(&text).is_ok_and(|p| p.starts_with(&chroot)) {
            continue;
        }
        let in_jail = format!("/proc/{}/root{text}", jail.pid);
        let same_inode = match (std::fs::metadata(entry.path()), std::fs::metadata(&in_jail)) {
            (Ok(fd_meta), Ok(jail_meta)) => {
                fd_meta.dev() == jail_meta.dev() && fd_meta.ino() == jail_meta.ino()
            }
            _ => false,
        };
        if !same_inode {
            outside.insert(text);
        }
    }
    assert!(
        outside.is_empty(),
        "jailed Firecracker {} holds files outside its chroot {}: {outside:?}",
        jail.pid,
        jail.chroot
    );

    let cgroup = Path::new("/sys/fs/cgroup").join(k7d::fc::spawn::cgroup_rel_path(&info.vm_id));
    let memory_max = std::fs::read_to_string(cgroup.join("memory.max"))
        .unwrap_or_else(|e| panic!("read {}: {e}", cgroup.join("memory.max").display()))
        .trim()
        .parse::<u64>()
        .expect("memory.max is a byte count");
    let guest_bytes = memory_max - k7d::fc::spawn::MEMORY_OVERHEAD_BYTES;
    assert!(
        guest_bytes >= 512 * 1024 * 1024,
        "memory.max {memory_max} leaves {guest_bytes} for a 512Mi pod"
    );
    assert_eq!(
        memory_max,
        k7d::fc::spawn::memory_max_bytes(guest_bytes / (1024 * 1024)),
        "memory.max must be the guest's RAM plus the VMM overhead, nothing else"
    );
}
