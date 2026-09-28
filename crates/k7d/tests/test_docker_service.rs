//! `dockerd` as an agent-supervised guest service.
//!
//! kubectl + `runtimeClassName: k7` + `k7d.katakate.org/docker=true`.
//! No `#[ignore]`. Payload is built on the node if missing.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

mod common;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn ensure_docker_payload() {
    let dockerd = workspace_root().join("guest/docker/payload/bin/dockerd");
    let iptables = workspace_root().join("guest/docker/payload/bin/iptables");
    let ca = workspace_root().join("guest/docker/payload/etc/ssl/certs/ca-certificates.crt");
    if dockerd.is_file() && iptables.is_file() && ca.is_file() {
        return;
    }
    eprintln!("  building docker payload (guest/docker/build.sh)");
    let status = Command::new("bash")
        .arg(workspace_root().join("guest/docker/build.sh"))
        .status()
        .expect("guest/docker/build.sh should run");
    assert!(status.success(), "guest/docker/build.sh failed");
    assert!(
        dockerd.is_file() && iptables.is_file() && ca.is_file(),
        "payload missing after build: {} / {} / {}",
        dockerd.display(),
        iptables.display(),
        ca.display()
    );
}

fn ensure_shim_installed() -> common::LeakGuard {
    common::cleanup_k7_runtime_leaks();
    ensure_docker_payload();

    let shim_src = workspace_root().join("target/release/containerd-shim-k7-v1");
    let status = Command::new("cargo")
        .args(["build", "--release", "-p", "containerd-shim-k7-v1"])
        .status()
        .expect("cargo build should run");
    assert!(status.success(), "shim build failed");

    let installed = Path::new("/usr/local/bin/containerd-shim-k7-v1");
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
                child
                    .stdin
                    .as_mut()
                    .unwrap()
                    .write_all(
                        b"apiVersion: node.k8s.io/v1\nkind: RuntimeClass\nmetadata:\n  name: k7\nhandler: k7\n",
                    )
                    .unwrap();
                child.wait()
            })
            .expect("create RuntimeClass");
    }

    common::ensure_k7d_daemon_running();
    common::ensure_pod_annotations_forwarded();
    common::LeakGuard
}

fn kubectl_apply(yaml: &str) -> Result<(), String> {
    common::kubectl_apply(yaml)
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
    if !graceful.as_ref().is_ok_and(|o| o.status.success()) {
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

struct PodGuard(String);
impl Drop for PodGuard {
    fn drop(&mut self) {
        kubectl_delete_pod(&self.0);
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

const DOCKER_POD_YAML: &str = r#"
apiVersion: v1
kind: Pod
metadata:
  name: {name}
  annotations:
    k7d.katakate.org/docker: "true"
    k7d.katakate.org/docker-disk: "4Gi"
    {extra_ann}
spec:
  runtimeClassName: k7
  restartPolicy: Never
  containers:
  - name: app
    image: ubuntu:24.04
    imagePullPolicy: IfNotPresent
    command: ["sleep", "infinity"]
    resources:
      requests:
        memory: "1536Mi"
        cpu: "2"
      limits:
        memory: "1536Mi"
        cpu: "2"
"#;

fn apply_docker_pod(name: &str, extra_ann: &str) {
    let yaml = DOCKER_POD_YAML
        .replace("{name}", name)
        .replace("{extra_ann}", extra_ann);
    kubectl_apply(&common::pin_to_local_node(&yaml))
        .unwrap_or_else(|e| panic!("apply {name}: {e}"));
}

fn pod_guest_cid(pod: &str) -> u64 {
    let sandbox_id = common::pod_sandbox_id(pod);
    let mut client = k7d::control::Client::connect_env().expect("connect k7d daemon");
    match client
        .call(&k7d::control::Request::LookupSandbox {
            sandbox_id: sandbox_id.clone(),
        })
        .expect("lookup_sandbox")
    {
        k7d::control::Response::SandboxFound { guest_cid, .. } => guest_cid,
        other => panic!("lookup_sandbox {sandbox_id}: {other:?}"),
    }
}

fn agent_sh(cid: u64, script: &str) -> String {
    let mut agent =
        k7d::api::AgentClient::connect_vsock(cid, Duration::from_secs(30)).expect("agent connect");
    let out = agent
        .exec(&["sh", "-c", script])
        .unwrap_or_else(|e| panic!("agent exec {script:?}: {e}"));
    assert_eq!(
        out.exit_code, 0,
        "agent {script:?} exit {}: stdout={} stderr={}",
        out.exit_code, out.stdout, out.stderr
    );
    out.stdout
}

fn sha256_file(path: &Path) -> String {
    let out = Command::new("sha256sum")
        .arg(path)
        .output()
        .expect("sha256sum");
    assert!(
        out.status.success(),
        "sha256sum {}: {out:?}",
        path.display()
    );
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .expect("hash")
        .to_string()
}

fn pin(name: &str) -> String {
    let text =
        std::fs::read_to_string(workspace_root().join("guest/docker/pins.env")).expect("pins.env");
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(&format!("{name}=")) {
            return rest.trim().to_string();
        }
    }
    panic!("pin {name} missing from guest/docker/pins.env");
}

fn docker_payload_images() -> Vec<PathBuf> {
    let dir = Path::new(k7d::erofs::DEFAULT_CACHE_DIR);
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = rd
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("docker-payload-") && n.ends_with(".erofs"))
        })
        .collect();
    out.sort();
    out
}

fn docker_graph_path(vm_id: &str) -> PathBuf {
    PathBuf::from(k7d::disks::DISKS_DIR).join(format!("scratch-{vm_id}-docker.img"))
}

fn find_forked_docker_graph(parent: &Path) -> PathBuf {
    let parent_name = parent.file_name().unwrap().to_string_lossy();
    let mut found = Vec::new();
    let walker = Command::new("find")
        .args([k7d::disks::DISKS_DIR, "-name", &format!("*{parent_name}")])
        .output()
        .expect("find docker graph clones");
    for line in String::from_utf8_lossy(&walker.stdout).lines() {
        let p = PathBuf::from(line);
        if p != parent {
            found.push(p);
        }
    }
    assert!(
        !found.is_empty(),
        "no forked docker graph sibling of {}",
        parent.display()
    );
    found.pop().unwrap()
}

/// overlay2, virtio-blk graph, hello-world, compose, buildx, path export,
/// sandbox not privileged.
#[test]
fn test_docker_info_cli_and_path_export() {
    let _leak = ensure_shim_installed();
    let pod = common::unique_name("test-k7d-dock");
    kubectl_delete_pod(&pod);
    let _guard = PodGuard(pod.clone());
    apply_docker_pod(&pod, "#");
    wait_for_pod_ready(&pod, Duration::from_secs(240)).expect("pod ready");

    let info = kubectl_exec(&pod, &["docker", "info"]).expect("docker info");
    assert!(
        info.contains("Storage Driver: overlay2"),
        "want overlay2:\n{info}"
    );
    assert!(
        !info.contains("Storage Driver: vfs"),
        "vfs is a loud failure:\n{info}"
    );

    let cid = pod_guest_cid(&pod);
    let df = agent_sh(cid, "df /var/lib/docker");
    assert!(
        df.contains("/dev/vd"),
        "graph must be on virtio-blk, not tmpfs:\n{df}"
    );
    assert!(!df.contains("tmpfs"), "graph must not be tmpfs:\n{df}");

    let hw = kubectl_exec(&pod, &["docker", "run", "--rm", "hello-world"]).expect("hello-world");
    assert!(hw.contains("Hello from Docker"), "hello-world:\n{hw}");

    let compose = kubectl_exec(&pod, &["docker", "compose", "version"]).expect("compose");
    assert!(
        compose.to_lowercase().contains("compose"),
        "compose version:\n{compose}"
    );
    let buildx = kubectl_exec(&pod, &["docker", "buildx", "version"]).expect("buildx");
    assert!(
        buildx.to_lowercase().contains("buildx"),
        "buildx version:\n{buildx}"
    );

    kubectl_exec(
        &pod,
        &[
            "sh",
            "-c",
            "cat > /tmp/compose.yml <<'EOF'\nservices:\n  web:\n    image: alpine:3.20\n    command: [\"sleep\", \"3\"]\nEOF\ndocker compose -f /tmp/compose.yml up -d && docker compose -f /tmp/compose.yml down",
        ],
    )
    .expect("compose up/down");

    kubectl_exec(&pod, &["sh", "-c", "mkdir -p /tmp/x && touch /tmp/x/f"]).unwrap();
    let ls = kubectl_exec(
        &pod,
        &[
            "docker",
            "run",
            "--rm",
            "-v",
            "/tmp/x:/x",
            "alpine:3.20",
            "ls",
            "/x",
        ],
    )
    .expect("path export docker run");
    assert!(ls.contains('f'), "path export missing f:\n{ls}");

    let capbnd =
        kubectl_exec(&pod, &["sh", "-c", "grep '^CapBnd:' /proc/self/status"]).expect("CapBnd");
    let hex = capbnd.split_whitespace().nth(1).unwrap_or("");
    assert_ne!(
        hex, "000001ffffffffff",
        "sandbox must not be privileged: {capbnd}"
    );
}

#[test]
fn test_docker_supervisor_restarts_without_container_action() {
    let _leak = ensure_shim_installed();
    let pod = common::unique_name("test-k7d-dkrst");
    kubectl_delete_pod(&pod);
    let _guard = PodGuard(pod.clone());
    apply_docker_pod(&pod, "#");
    wait_for_pod_ready(&pod, Duration::from_secs(240)).expect("pod ready");

    let cid = pod_guest_cid(&pod);
    let mut agent =
        k7d::api::AgentClient::connect_vsock(cid, Duration::from_secs(30)).expect("agent");
    let pong = agent.ping().expect("ping");
    let docker = pong
        .services
        .iter()
        .find(|s| s.name == "docker")
        .unwrap_or_else(|| panic!("Pong.services missing docker: {:?}", pong.services));
    assert!(docker.ready, "docker not ready: {docker:?}");
    assert!(docker.pid > 1, "docker pid: {docker:?}");
    let before = docker.restarts;

    agent
        .exec(&["sh", "-c", "kill $(cat /run/k7d/docker/dockerd.pid)"])
        .expect("kill dockerd");

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let pong = agent.ping().expect("ping after kill");
        let docker = pong
            .services
            .iter()
            .find(|s| s.name == "docker")
            .expect("docker service");
        if docker.restarts > before && docker.ready {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "dockerd did not restart within 30s: before={before} now={docker:?}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }

    let info = kubectl_exec(&pod, &["docker", "info"]).expect("docker info after restart");
    assert!(
        info.contains("Storage Driver: overlay2"),
        "directory bind must survive dockerd restart:\n{info}"
    );
}

#[test]
fn test_docker_warm_fork_nginx_survives() {
    let _leak = ensure_shim_installed();
    let cluster_id = format!("dk{}", std::process::id() % 10_000);
    assert!(cluster_id.len() <= 9);
    let pod = common::unique_name("test-k7d-dkfk");
    let trigger = common::unique_name("test-k7d-dkfk-t");
    let tree_id = format!("dkfk-{}", std::process::id());

    kubectl_delete_pod(&pod);
    kubectl_delete_pod(&trigger);
    let _g1 = PodGuard(pod.clone());
    let _g2 = PodGuard(trigger.clone());

    apply_docker_pod(&pod, &format!("k7d.katakate.org/cluster-id: {cluster_id}"));
    wait_for_pod_ready(&pod, Duration::from_secs(240)).expect("source ready");

    kubectl_exec(
        &pod,
        &[
            "docker",
            "run",
            "-d",
            "--name",
            "web",
            "-p",
            "8080:80",
            "nginx:1.27-alpine",
        ],
    )
    .expect("nginx");
    kubectl_exec(
        &pod,
        &[
            "sh",
            "-c",
            "docker volume create markervol >/dev/null && \
             docker run --rm -v markervol:/data alpine:3.20 sh -c 'echo parent > /data/marker-src'",
        ],
    )
    .expect("marker volume");

    let src_cid = pod_guest_cid(&pod);
    let src_page = agent_sh(src_cid, "wget -qO- http://127.0.0.1:8080 | head -c 200");
    assert!(
        src_page.to_lowercase().contains("nginx") || src_page.contains("html"),
        "parent nginx: {src_page:?}"
    );

    let src_state = common::pod_vm_state(&pod);
    let parent_graph = docker_graph_path(&src_state.vm_id);
    assert!(
        parent_graph.exists(),
        "parent graph missing: {}",
        parent_graph.display()
    );

    let budget = serde_json::to_string(&k7d::tree::TreeBudget {
        max_live_vms: 8,
        max_live_ram_bytes: 16 * 1024 * 1024 * 1024,
        max_disk_bytes: 32 * 1024 * 1024 * 1024,
        max_chain_depth: 8,
    })
    .unwrap();
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
    wait_for_pod_ready(&trigger, Duration::from_secs(300)).expect("trigger");
    common::mark_test_tree(&tree_id);

    let mut daemon = k7d::control::Client::connect_env().expect("daemon");
    let child_cids = match daemon.call(&k7d::control::Request::TreeNodes {
        tree_id: tree_id.clone(),
    }) {
        Ok(k7d::control::Response::TreeNodeList {
            nodes,
            live_guest_cids,
            ..
        }) => {
            let warm = nodes
                .iter()
                .find(|n| n.label == "warm")
                .unwrap_or_else(|| panic!("no warm node: {nodes:?}"));
            let cids = live_guest_cids.get(&warm.id).cloned().unwrap_or_default();
            assert!(!cids.is_empty(), "warm node has no live CIDs");
            cids
        }
        other => panic!("TreeNodes: {other:?}"),
    };

    let child_cid = child_cids[0];
    let mut child = k7d::api::AgentClient::connect_vsock(child_cid, Duration::from_secs(30))
        .expect("child agent");
    let ps = child
        .exec(&[
            "sh",
            "-c",
            "DOCKER_HOST=unix:///run/k7d/docker/docker.sock \
             /run/k7d/docker-tools/bin/docker ps",
        ])
        .expect("child docker ps");
    assert_eq!(
        ps.exit_code, 0,
        "child docker ps: {} {}",
        ps.stdout, ps.stderr
    );
    assert!(
        ps.stdout.contains("nginx") || ps.stdout.contains("web"),
        "child docker ps missing nginx:\n{}",
        ps.stdout
    );
    let page = child
        .exec(&["sh", "-c", "wget -qO- http://127.0.0.1:8080 | head -c 200"])
        .expect("child wget");
    assert_eq!(
        page.exit_code, 0,
        "child wget: {} {}",
        page.stdout, page.stderr
    );
    assert!(
        page.stdout.to_lowercase().contains("nginx") || page.stdout.contains("html"),
        "child nginx: {}",
        page.stdout
    );

    child
        .exec(&[
            "sh",
            "-c",
            "DOCKER_HOST=unix:///run/k7d/docker/docker.sock \
             /run/k7d/docker-tools/bin/docker run --rm -v markervol:/data alpine:3.20 \
             sh -c 'echo child > /data/marker-child'",
        ])
        .expect("child volume write");

    let parent_child_file = kubectl_exec(
        &pod,
        &[
            "docker",
            "run",
            "--rm",
            "-v",
            "markervol:/data",
            "alpine:3.20",
            "sh",
            "-c",
            "test ! -f /data/marker-child && cat /data/marker-src",
        ],
    )
    .expect("parent volume after child write");
    assert!(
        parent_child_file.contains("parent"),
        "parent volume polluted or marker-src gone: {parent_child_file}"
    );

    let parent_page = agent_sh(src_cid, "wget -qO- http://127.0.0.1:8080 | head -c 80");
    assert!(
        parent_page.to_lowercase().contains("nginx") || parent_page.contains("html"),
        "parent nginx still serves: {parent_page:?}"
    );

    let child_graph = find_forked_docker_graph(&parent_graph);
    let parent_ext = common::ubuntu::physical_extents(&parent_graph);
    let child_ext = common::ubuntu::physical_extents(&child_graph);
    assert!(
        !parent_ext.is_disjoint(&child_ext),
        "child graph {} must share extents with parent {}",
        child_graph.display(),
        parent_graph.display()
    );

    // Tree members are not in ListVms (no daemon vm_id). A second
    // fork from the adopted root reports the CoW flag the annotation
    // fork used — same prepare/fork path.
    match daemon.call(&k7d::control::Request::TreeFork {
        tree_id: tree_id.clone(),
        source_id: "root".into(),
        label: "cow".into(),
        dilation: None,
        dilation_policy: None,
        dilation_config: None,
    }) {
        Ok(k7d::control::Response::TreeForked {
            fork_memory_full_copy,
            ..
        }) => {
            assert!(
                fork_memory_full_copy.iter().all(|full| !*full),
                "child fork must be CoW: {fork_memory_full_copy:?}"
            );
        }
        other => panic!("TreeFork cow: {other:?}"),
    }

    let _ = daemon.call(&k7d::control::Request::TreeDrop {
        tree_id: tree_id.clone(),
    });
    let _ = std::fs::remove_dir_all(format!("/var/lib/k7d/trees/{tree_id}"));
}

#[test]
fn test_docker_payload_ro_host_enforced() {
    let _leak = ensure_shim_installed();
    let pod = common::unique_name("test-k7d-dkro");
    kubectl_delete_pod(&pod);
    let _guard = PodGuard(pod.clone());
    apply_docker_pod(&pod, "#");
    wait_for_pod_ready(&pod, Duration::from_secs(240)).expect("pod ready");

    let before: Vec<(PathBuf, String)> = docker_payload_images()
        .into_iter()
        .map(|p| {
            let h = sha256_file(&p);
            (p, h)
        })
        .collect();
    assert!(
        !before.is_empty(),
        "no docker-payload-*.erofs under {}",
        k7d::erofs::DEFAULT_CACHE_DIR
    );

    let cid = pod_guest_cid(&pod);
    let dev = agent_sh(
        cid,
        "awk '$2==\"/run/k7d/docker-tools\"{print $1; exit}' /proc/mounts",
    )
    .trim()
    .to_string();
    assert!(dev.starts_with("/dev/vd"), "payload mount device: {dev:?}");

    let dd = kubectl_exec(
        &pod,
        &[
            "sh",
            "-c",
            &format!(
                "docker run --rm --privileged --device={dev} alpine:3.20 \
                 dd if=/dev/zero of={dev} bs=4k count=1; echo exit:$?"
            ),
        ],
    )
    .unwrap_or_else(|e| e);
    assert!(
        !dd.contains("exit:0")
            || dd.contains("I/O error")
            || dd.contains("Operation not permitted")
            || dd.contains("Permission denied")
            || dd.contains("error"),
        "payload write must fail: {dd}"
    );

    for (path, hash) in &before {
        assert_eq!(
            sha256_file(path),
            *hash,
            "host payload image {} mutated",
            path.display()
        );
    }

    let pod2 = common::unique_name("test-k7d-dkro2");
    kubectl_delete_pod(&pod2);
    let _g2 = PodGuard(pod2.clone());
    apply_docker_pod(&pod2, "#");
    wait_for_pod_ready(&pod2, Duration::from_secs(240)).expect("second pod");
    let info = kubectl_exec(&pod2, &["docker", "info"]).expect("second docker info");
    assert!(
        info.contains("Storage Driver: overlay2"),
        "next pod dockerd must start:\n{info}"
    );
}

#[test]
fn test_docker_guest_sources_unchanged() {
    let root = workspace_root();
    assert_eq!(
        sha256_file(&root.join("guest/kernel/config-minimal")),
        pin("KERNEL_CONFIG_SHA256"),
        "guest/kernel/config-minimal changed"
    );
    assert_eq!(
        sha256_file(&root.join("guest/rootfs/init.sh")),
        pin("INIT_SH_SHA256"),
        "guest/rootfs/init.sh changed"
    );
    assert_eq!(
        sha256_file(&root.join("guest/rootfs/Dockerfile")),
        pin("ROOTFS_DOCKERFILE_SHA256"),
        "guest/rootfs/Dockerfile changed"
    );
    assert_eq!(
        sha256_file(&root.join("guest/rootfs/build.sh")),
        pin("ROOTFS_BUILD_SHA256"),
        "guest/rootfs/build.sh changed"
    );
    let tree = Command::new("bash")
        .arg("-c")
        .arg("find guest/ubuntu -type f | sort | xargs sha256sum | sha256sum")
        .current_dir(&root)
        .output()
        .expect("ubuntu tree hash");
    assert!(tree.status.success(), "ubuntu tree hash failed: {tree:?}");
    let got = String::from_utf8_lossy(&tree.stdout)
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();
    assert_eq!(got, pin("UBUNTU_TREE_SHA256"), "guest/ubuntu tree changed");
}
