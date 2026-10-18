//! kubernetes-sigs/agent-sandbox on the `k7` and `k7-fc` RuntimeClasses.
//!
//! One test per backend. Each installs agent-sandbox (pinned,
//! `utils/agent-sandbox/install.sh`) in setup and uninstalls it from a
//! guard's `Drop`, runs the validation rows V1-V3 and V5-V11 plus V13
//! against the shipped `examples/agent-sandbox/` manifests, then asserts
//! nothing leaked. V4 (sandboxd) has no published image, V12 needs the
//! pod-UID fork annotation and V14 is upstream's own e2e
//! (`utils/agent-sandbox/upstream-e2e.sh`).

mod common;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use k7d::control::{Client, Request, Response};
use serde_json::Value;

const PINS: &str = include_str!("../../../utils/agent-sandbox/pins.env");
const SANDBOX: &str = include_str!("../../../examples/agent-sandbox/sandbox-k7.yaml");
const POOL: &str =
    include_str!("../../../examples/agent-sandbox/template-warmpool-claim-k7-fc.yaml");
const DOCKER: &str = include_str!("../../../examples/agent-sandbox/template-docker-k7.yaml");
const HELLO: &str = "docker.io/library/hello-world@sha256:5e22040d441e5fb3aed38368acbe8486b575d7018df38dbdfbc7311fbb2ef3a9";
const READY: Duration = Duration::from_secs(240);

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn pin(key: &str) -> &'static str {
    PINS.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}=")))
        .unwrap_or_else(|| panic!("{key} missing from utils/agent-sandbox/pins.env"))
}

fn run(cmd: &mut Command) -> Result<String, String> {
    let out = cmd.output().map_err(|e| format!("{cmd:?}: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.success() {
        Ok(stdout)
    } else {
        Err(format!(
            "{cmd:?}: {stdout}{}",
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

fn script(name: &str) -> Result<String, String> {
    run(Command::new("bash").arg(repo().join("utils/agent-sandbox").join(name)))
}

/// Installs agent-sandbox; uninstalls it on drop, panicking if that fails
/// (unless the test is already panicking, so the first failure is kept).
struct AgentSandbox;

impl AgentSandbox {
    fn install() -> Self {
        script("install.sh").unwrap_or_else(|e| panic!("agent-sandbox install: {e}"));
        AgentSandbox
    }
}

impl Drop for AgentSandbox {
    fn drop(&mut self) {
        if let Err(e) = script("uninstall.sh") {
            assert!(std::thread::panicking(), "agent-sandbox uninstall: {e}");
            eprintln!("agent-sandbox uninstall: {e}");
        }
    }
}

struct Ns(String);

impl Ns {
    fn create(base: &str) -> Self {
        let name = common::unique_name(base);
        common::kubectl_apply(&format!(
            "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {name}\n"
        ))
        .unwrap_or_else(|e| panic!("create namespace {name}: {e}"));
        Ns(name)
    }

    fn kubectl(&self, args: &[&str]) -> Result<String, String> {
        run(Command::new("kubectl").arg("-n").arg(&self.0).args(args))
    }

    fn apply(&self, yaml: &str) {
        let mut child = Command::new("kubectl")
            .args(["-n", &self.0, "apply", "-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("kubectl apply");
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(yaml.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "kubectl apply: {}\n{yaml}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn json(&self, what: &str) -> Value {
        let s = self
            .kubectl(&["get", what, "-o", "json"])
            .unwrap_or_else(|e| panic!("{e}"));
        serde_json::from_str(&s).expect("kubectl json")
    }

    fn exists(&self, what: &str) -> bool {
        self.kubectl(&["get", what, "--ignore-not-found", "-o", "name"])
            .is_ok_and(|s| !s.trim().is_empty())
    }

    /// Poll until `pred` holds, failing with `what` and a describe dump.
    fn wait(&self, what: &str, timeout: Duration, mut pred: impl FnMut() -> bool) -> Duration {
        let start = Instant::now();
        while !pred() {
            if start.elapsed() > timeout {
                let pods = self.kubectl(&["get", "pods,sandboxes,sandboxclaims", "-o", "wide"]);
                let events = self.kubectl(&["get", "events", "--sort-by=.lastTimestamp"]);
                panic!(
                    "[{}] {what}: not within {timeout:?}\n{pods:?}\n{events:?}",
                    self.0
                );
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        start.elapsed()
    }

    fn ready(&self, what: &str) -> bool {
        self.kubectl(&[
            "get",
            what,
            "-o",
            "jsonpath={.status.conditions[?(@.type==\"Ready\")].status}",
        ])
        .is_ok_and(|s| s.trim() == "True")
    }

    fn wait_ready(&self, what: &str) -> Duration {
        self.wait(&format!("{what} Ready"), READY, || self.ready(what))
    }

    /// Exec in the pod's first container; Ok(stdout) on exit 0.
    fn exec(&self, pod: &str, cmd: &str) -> Result<String, String> {
        self.kubectl(&["exec", pod, "--", "sh", "-c", cmd])
    }

    fn restarts(&self, pod: &str) -> u64 {
        self.json(&format!("pod/{pod}"))["status"]["containerStatuses"]
            .as_array()
            .expect("containerStatuses")
            .iter()
            .map(|c| c["restartCount"].as_u64().unwrap())
            .sum()
    }

    fn claim_pod(&self, claim: &str) -> String {
        let v = self.json(&format!("sandboxclaim/{claim}"));
        v["status"]["sandbox"]["name"]
            .as_str()
            .expect("claim sandbox name")
            .to_string()
    }
}

impl Drop for Ns {
    fn drop(&mut self) {
        let _ = run(Command::new("kubectl").args([
            "delete",
            "namespace",
            &self.0,
            "--wait=true",
            "--timeout=300s",
        ]));
    }
}

fn daemon(req: &Request) -> Response {
    Client::connect_env()
        .expect("k7d socket")
        .call(req)
        .expect("k7d call")
}

fn vms() -> Vec<k7d::control::VmInfo> {
    match daemon(&Request::ListVms) {
        Response::VmList { vms } => vms,
        other => panic!("list_vms: {other:?}"),
    }
}

fn disk_images() -> usize {
    std::fs::read_dir(k7d::disks::DISKS_DIR)
        .map(|d| d.flatten().filter(|e| e.path().is_file()).count())
        .unwrap_or(0)
}

/// Every `runtimeClassName:` line of an example set to `rc`; `None`
/// drops it (the cluster default, runc).
fn on_rc(yaml: &str, rc: Option<&str>) -> String {
    let mut out = String::new();
    for line in yaml.lines() {
        match (line.trim_start().starts_with("runtimeClassName:"), rc) {
            (true, Some(rc)) => {
                let pad = &line[..line.len() - line.trim_start().len()];
                out.push_str(&format!("{pad}runtimeClassName: {rc}\n"));
            }
            (true, None) => {}
            (false, _) => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    out
}

fn on(yaml: &str, rc: &str) -> String {
    on_rc(yaml, Some(rc))
}

/// Keep only the documents of `kinds` from a multi-document example.
fn docs(yaml: &str, kinds: &[&str]) -> String {
    yaml.split("\n---\n")
        .filter(|d| kinds.iter().any(|k| d.contains(&format!("\nkind: {k}\n"))))
        .collect::<Vec<_>>()
        .join("\n---\n")
}

fn assert_backend(pod: &str, rc: &str) -> String {
    let vm_id = common::pod_vm_id(pod);
    let vm = vms()
        .into_iter()
        .find(|v| v.vm_id == vm_id)
        .expect("daemon lists the pod VM");
    let want = if rc == "k7-fc" {
        k7d::guest::Backend::Firecracker
    } else {
        k7d::guest::Backend::Native
    };
    assert_eq!(vm.backend, want, "pod {pod} on {rc}");
    vm_id
}

/// `python3 -c` TCP connect from a python-runtime pod: true if it connects.
fn connects(ns: &Ns, pod: &str, host: &str, port: u16) -> bool {
    let py = format!(
        "import socket; socket.create_connection(('{host}', {port}), 4); print('CONNECTED')"
    );
    ns.kubectl(&["exec", pod, "--", "python3", "-c", &py])
        .is_ok_and(|s| s.contains("CONNECTED"))
}

struct PortForward(Child);

impl Drop for PortForward {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn http_ok(url: &str) -> bool {
    run(Command::new("curl").args(["-sf", "-m", "5", "-o", "/dev/null", url])).is_ok()
}

fn sdk_venv() -> PathBuf {
    let venv = PathBuf::from(format!(
        "/var/tmp/k7d-agent-sandbox-venv-{}",
        pin("SDK_VERSION")
    ));
    if !venv.join("bin/python").exists() {
        run(Command::new("python3").arg("-m").arg("venv").arg(&venv))
            .unwrap_or_else(|e| panic!("python3 -m venv (python3-venv installed?): {e}"));
        let req = repo().join("examples/agent-sandbox/requirements.txt");
        run(Command::new(venv.join("bin/pip"))
            .args(["install", "-q", "--require-hashes", "-r"])
            .arg(req))
        .unwrap_or_else(|e| panic!("pip install SDK: {e}"));
    }
    venv
}

fn suite(rc: &str) {
    let _shim = common::ensure_shim_installed();
    if rc == "k7-fc" {
        common::ensure_firecracker_installed();
        common::ensure_k7_fc_runtime_registered();
    }
    // A PVC on k7 rides the virtiofs fallback, so the RWO PVC check
    // needs the local-path provisioner k3s ships.
    run(Command::new("kubectl").args([
        "-n",
        "kube-system",
        "rollout",
        "status",
        "deploy/local-path-provisioner",
        "--timeout=120s",
    ]))
    .expect("local-path provisioner");
    let vms_before = vms().len();
    let disks_before = disk_images();
    let tag = rc.replace('-', "");
    let install = AgentSandbox::install();
    let ns = Ns::create(&format!("test-asbx-{tag}"));
    for (img, key) in [
        (SANDBOX, "PYTHON_RUNTIME_IMAGE"),
        (POOL, "PYTHON_RUNTIME_IMAGE"),
        (DOCKER, "UBUNTU_IMAGE"),
    ] {
        assert!(
            img.contains(&format!("image: {}\n", pin(key))),
            "example image must match pins.env {key}"
        );
    }

    // V1: cold Sandbox -> Ready, with pod IP and service FQDN.
    ns.apply(&on(SANDBOX, rc));
    let cold = ns.wait_ready("sandbox/python-k7");
    let sbx = ns.json("sandbox/python-k7");
    assert!(sbx["status"]["podIPs"][0].is_string(), "V1 podIPs: {sbx}");
    assert!(
        sbx["status"]["serviceFQDN"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "V1 serviceFQDN: {sbx}"
    );
    let cold_vm = assert_backend("python-k7", rc);
    eprintln!(
        "[{rc}] V1 cold Sandbox -> Ready: {:.2}s",
        cold.as_secs_f64()
    );

    // V3: kubectl port-forward into the VM pod (dials localhost in the pod netns).
    let pf = PortForward(
        Command::new("kubectl")
            .args(["-n", &ns.0, "port-forward", "pod/python-k7", "18888:8888"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("port-forward"),
    );
    ns.wait("V3 port-forward HTTP 200", Duration::from_secs(20), || {
        http_ok("http://127.0.0.1:18888/")
    });
    drop(pf);
    eprintln!("[{rc}] V3 kubectl port-forward: ok");

    // V5: template + warm pool(3) + claim. Adoption keeps pod and VM.
    ns.apply(&on(
        &docs(POOL, &["SandboxTemplate", "SandboxWarmPool"]),
        rc,
    ));
    ns.wait("V5 pool readyReplicas=3", READY, || {
        ns.json("sandboxwarmpool/python-k7-fc-pool")["status"]["readyReplicas"].as_u64() == Some(3)
    });
    let pool_vms: Vec<(String, String)> = ns
        .kubectl(&["get", "pods", "-o", "jsonpath={.items[*].metadata.name}"])
        .unwrap()
        .split_whitespace()
        .filter(|p| p.starts_with("python-k7-fc-pool-"))
        .map(|p| (p.to_string(), common::pod_vm_id(p)))
        .collect();
    assert_eq!(pool_vms.len(), 3, "V5 pool pods: {pool_vms:?}");
    ns.apply(&docs(POOL, &["SandboxClaim"]));
    let warm = ns.wait_ready("sandboxclaim/python-k7-fc-claim");
    let adopted = ns.claim_pod("python-k7-fc-claim");
    let (_, vm_before) = pool_vms
        .iter()
        .find(|(p, _)| *p == adopted)
        .expect("V5 claim adopted a pool pod");
    assert_eq!(
        &common::pod_vm_id(&adopted),
        vm_before,
        "V5 adoption must keep the VM"
    );
    assert_eq!(ns.restarts(&adopted), 0, "V5 adopted pod restarted");
    assert_backend(&adopted, rc);
    eprintln!("[{rc}] V5 warm claim -> Ready: {:.2}s", warm.as_secs_f64());

    // V5 baseline: the same claim against a runc pool must not be much faster.
    let runc = on_rc(POOL, None)
        .replace("python-k7-fc", "python-runc")
        .replace("replicas: 3", "replicas: 1");
    ns.apply(&docs(&runc, &["SandboxTemplate", "SandboxWarmPool"]));
    ns.wait("runc pool ready", READY, || {
        ns.json("sandboxwarmpool/python-runc-pool")["status"]["readyReplicas"].as_u64() == Some(1)
    });
    ns.apply(&docs(&runc, &["SandboxClaim"]));
    let runc_warm = ns.wait_ready("sandboxclaim/python-runc-claim");
    eprintln!(
        "[{rc}] V5 runc warm claim -> Ready: {:.2}s",
        runc_warm.as_secs_f64()
    );
    assert!(
        warm <= runc_warm.mul_f64(1.5) + Duration::from_secs(1),
        "V5 warm claim {warm:?} vs runc {runc_warm:?}"
    );

    // V6: managed default NetworkPolicy, checked against the runc claim pod
    // under the same policy. A ClusterIP is no 10/8 probe: kube-proxy DNATs
    // 10.43.0.1 to the node IP before the policy sees it, on runc too.
    let runc_pod = ns.claim_pod("python-runc-claim");
    let router_ip = run(Command::new("kubectl").args([
        "-n",
        "agent-sandbox-system",
        "get",
        "pod",
        "-l",
        "app=sandbox-router",
        "-o",
        "jsonpath={.items[0].status.podIP}",
    ]))
    .unwrap();
    assert!(
        connects(&ns, "python-k7", &router_ip, 8080),
        "V6 control: unmanaged pod reaches the router pod IP"
    );
    for (host, port, allowed) in [
        ("1.1.1.1", 80, true),
        (router_ip.as_str(), 8080, false),
        ("169.254.169.254", 80, false),
    ] {
        assert_eq!(
            connects(&ns, &runc_pod, host, port),
            allowed,
            "V6 runc baseline {host}:{port}"
        );
        assert_eq!(
            connects(&ns, &adopted, host, port),
            allowed,
            "V6 {host}:{port}"
        );
    }
    let adopted_ip = ns.json(&format!("pod/{adopted}"))["status"]["podIP"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        !connects(&ns, "python-k7", &adopted_ip, 8888),
        "V6 ingress from a non-router pod"
    );
    eprintln!(
        "[{rc}] V6 kube API ClusterIP reachable under the managed policy: runc={} {rc}={}",
        connects(&ns, &runc_pod, "10.43.0.1", 443),
        connects(&ns, &adopted, "10.43.0.1", 443)
    );
    eprintln!("[{rc}] V6 managed NetworkPolicy: ok");

    // V2: upstream Python SDK through the router (ingress from the router only).
    let venv = sdk_venv();
    let sdk = run(Command::new(venv.join("bin/python"))
        .arg(repo().join("examples/agent-sandbox/sdk_smoke.py"))
        .args([&ns.0, "python-k7-fc-pool"])
        .env("KUBECONFIG", "/etc/rancher/k3s/k3s.yaml"))
    .unwrap_or_else(|e| panic!("V2 SDK: {e}"));
    assert!(sdk.contains("SDK_OK"), "V2 SDK: {sdk}");
    eprintln!(
        "[{rc}] V2 SDK via router: {}",
        sdk.lines().next().unwrap_or("")
    );

    // V9: startup + exec liveness probes, a burst of four, no restarts.
    let probes = on(SANDBOX, rc).replace(
        "        readinessProbe:",
        "        startupProbe: {httpGet: {path: /, port: 8888}, periodSeconds: 1, failureThreshold: 120}\n        \
         livenessProbe: {exec: {command: [python3, -c, '1']}, periodSeconds: 2, timeoutSeconds: 5}\n        readinessProbe:",
    );
    let burst: Vec<String> = (0..4).map(|i| format!("probe-{i}")).collect();
    for b in &burst {
        ns.apply(&probes.replace("name: python-k7\n", &format!("name: {b}\n")));
    }
    for b in &burst {
        ns.wait_ready(&format!("sandbox/{b}"));
    }
    std::thread::sleep(Duration::from_secs(30));
    for b in &burst {
        assert_eq!(ns.restarts(b), 0, "V9 {b} restarted under probes");
    }
    for b in &burst {
        ns.kubectl(&["delete", "sandbox", b, "--wait=true"])
            .unwrap();
    }
    eprintln!("[{rc}] V9 probes under burst: ok");

    // V13: out-of-band pause behind the controller's back.
    if let Response::Error { message } = daemon(&Request::PauseVm {
        vm_id: cold_vm.clone(),
    }) {
        panic!("V13 pause: {message}");
    }
    let not_ready = ns.wait(
        "V13 Sandbox Ready=False while paused",
        Duration::from_secs(90),
        || !ns.ready("sandbox/python-k7"),
    );
    if let Response::Error { message } = daemon(&Request::ResumeVm {
        vm_id: cold_vm.clone(),
    }) {
        panic!("V13 resume: {message}");
    }
    ns.wait_ready("sandbox/python-k7");
    eprintln!(
        "[{rc}] V13 paused VM: Sandbox Ready=False after {:.0}s, Ready again after resume; restarts={}",
        not_ready.as_secs_f64(),
        ns.restarts("python-k7")
    );

    // V7: operatingMode Suspended deletes the pod and VM; Running cold-boots.
    let sid = common::pod_sandbox_id("python-k7");
    ns.kubectl(&[
        "patch",
        "sandbox",
        "python-k7",
        "--type=merge",
        "-p",
        r#"{"spec":{"operatingMode":"Suspended"}}"#,
    ])
    .unwrap();
    ns.wait("V7 pod deleted", READY, || !ns.exists("pod/python-k7"));
    ns.wait("V7 VM gone", Duration::from_secs(60), || {
        matches!(
            daemon(&Request::LookupSandbox {
                sandbox_id: sid.clone()
            }),
            Response::Error { .. }
        )
    });
    ns.kubectl(&[
        "patch",
        "sandbox",
        "python-k7",
        "--type=merge",
        "-p",
        r#"{"spec":{"operatingMode":"Running"}}"#,
    ])
    .unwrap();
    ns.wait_ready("sandbox/python-k7");
    assert_ne!(
        common::pod_vm_id("python-k7"),
        cold_vm,
        "V7 resume must cold-boot a new VM"
    );
    v7_pvc(&ns, rc);
    eprintln!("[{rc}] V7 suspend/resume: ok");

    // V8: shutdownTime expiry deletes the Sandbox and its pod.
    let at =
        run(Command::new("date").args(["-u", "-d", "+20 seconds", "+%Y-%m-%dT%H:%M:%SZ"])).unwrap();
    let expiring = on(SANDBOX, rc)
        .replace("name: python-k7\n", "name: expiring\n")
        .replace(
            "spec:\n  service: true\n",
            &format!(
                "spec:\n  service: true\n  shutdownTime: \"{}\"\n  shutdownPolicy: Delete\n",
                at.trim()
            ),
        );
    ns.apply(&expiring);
    ns.wait(
        "V8 shutdownTime deletes the Sandbox",
        Duration::from_secs(180),
        || !ns.exists("sandbox/expiring"),
    );
    ns.wait("V8 pod gone", Duration::from_secs(60), || {
        !ns.exists("pod/expiring")
    });
    eprintln!("[{rc}] V8 shutdownTime: ok");

    // V10: a projected SA token must follow kubelet rotation into the guest.
    v10_token(&ns, rc);

    // V11: Docker-in-VM from the example template.
    v11_docker(&ns, rc);

    drop(ns);
    drop(install);
    let wait = Instant::now();
    while vms().len() != vms_before || disk_images() != disks_before {
        assert!(
            wait.elapsed() < Duration::from_secs(120),
            "leak after teardown: {} VMs (before {vms_before}), {} disk images (before {disks_before})",
            vms().len(),
            disk_images()
        );
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn v7_pvc(ns: &Ns, rc: &str) {
    let pvc = on(SANDBOX, rc).replace("name: python-k7\n", "name: pvc\n").replace(
        "        resources:\n",
        "        volumeMounts: [{name: data, mountPath: /data}]\n        resources:\n",
    ) + "  volumeClaimTemplates:\n  - metadata: {name: data}\n    spec:\n      accessModes: [ReadWriteOnce]\n      \
         storageClassName: local-path\n      resources: {requests: {storage: 1Gi}}\n";
    ns.apply(&pvc);
    if rc == "k7-fc" {
        ns.wait(
            "V7 k7-fc refuses the hostPath-backed PVC loudly",
            READY,
            || {
                ns.kubectl(&[
                    "get",
                    "events",
                    "--field-selector",
                    "involvedObject.name=pvc",
                ])
                .is_ok_and(|e| e.contains("backend firecracker has no virtiofs"))
            },
        );
        ns.kubectl(&["delete", "sandbox", "pvc", "--wait=true"])
            .unwrap();
        return;
    }
    ns.wait_ready("sandbox/pvc");
    ns.exec("pvc", "echo kept > /data/marker").unwrap();
    for mode in ["Suspended", "Running"] {
        ns.kubectl(&[
            "patch",
            "sandbox",
            "pvc",
            "--type=merge",
            "-p",
            &format!(r#"{{"spec":{{"operatingMode":"{mode}"}}}}"#),
        ])
        .unwrap();
        if mode == "Suspended" {
            ns.wait("V7 pvc pod deleted", READY, || !ns.exists("pod/pvc"));
        }
    }
    ns.wait_ready("sandbox/pvc");
    assert_eq!(
        ns.exec("pvc", "cat /data/marker").unwrap().trim(),
        "kept",
        "V7 PVC data"
    );
    ns.kubectl(&["delete", "sandbox", "pvc", "--wait=true"])
        .unwrap();
}

fn v10_token(ns: &Ns, rc: &str) {
    let tok = on(SANDBOX, rc).replace("name: python-k7\n", "name: token\n").replace(
        "        resources:\n",
        "        volumeMounts: [{name: tok, mountPath: /var/run/secrets/tokens, readOnly: true}]\n        resources:\n",
    ) + "      volumes:\n      - name: tok\n        projected:\n          sources:\n          \
         - serviceAccountToken: {path: t, expirationSeconds: 600}\n";
    ns.apply(&tok);
    ns.wait_ready("sandbox/token");
    let first = ns.exec("token", "cat /var/run/secrets/tokens/t").unwrap();
    assert!(first.starts_with("eyJ"), "V10 token in guest: {first}");
    // kubelet refreshes a projected token once it is 80% through its TTL.
    // Documented gap (docs/agent-sandbox.md): RO kubelet volumes are one
    // erofs image built at Create, so the rotation never reaches the guest.
    // When a refresh path lands this assertion flips; update the doc with it.
    let uid = ns.json("pod/token")["metadata"]["uid"]
        .as_str()
        .unwrap()
        .to_string();
    let host = format!("/var/lib/kubelet/pods/{uid}/volumes/kubernetes.io~projected/tok/t");
    let rotated = ns.wait(
        "V10 kubelet rotates the token on the host",
        Duration::from_secs(900),
        || {
            std::thread::sleep(Duration::from_secs(10));
            std::fs::read_to_string(&host).is_ok_and(|t| t != first)
        },
    );
    assert_eq!(
        ns.exec("token", "cat /var/run/secrets/tokens/t").unwrap(),
        first,
        "V10 the rotated token reached the guest: update docs/agent-sandbox.md"
    );
    eprintln!(
        "[{rc}] V10 known gap: host token rotated after {:.0}s, guest copy stays stale",
        rotated.as_secs_f64()
    );
    ns.kubectl(&["delete", "sandbox", "token", "--wait=true"])
        .unwrap();
}

fn v11_docker(ns: &Ns, rc: &str) {
    ns.apply(&on(DOCKER, rc));
    ns.wait_ready("sandboxclaim/docker-k7-claim");
    let pod = ns.claim_pod("docker-k7-claim");
    assert_backend(&pod, rc);
    let info = ns
        .exec(
            &pod,
            "docker info --format '{{.Driver}} {{json .DriverStatus}}'",
        )
        .unwrap_or_else(|e| panic!("V11 docker info: {e}"));
    assert!(info.starts_with("overlay2 "), "V11 storage driver: {info}");
    assert!(
        info.contains("extfs"),
        "V11 graph must be on the ext4 disk, not tmpfs: {info}"
    );
    let hello = ns
        .exec(&pod, &format!("docker run --rm {HELLO}"))
        .unwrap_or_else(|e| panic!("V11 docker run: {e}"));
    assert!(
        hello.contains("Hello from Docker!"),
        "V11 hello-world: {hello}"
    );
    let caps = ns.exec(&pod, "grep CapEff /proc/self/status").unwrap();
    assert!(
        caps.trim().ends_with("0000000000000000"),
        "V11 workload must keep drop ALL: {caps}"
    );
    let spec = ns.json(&format!("pod/{pod}"));
    assert!(
        spec["spec"]["containers"][0]["securityContext"]["privileged"].is_null(),
        "V11 privileged"
    );
    eprintln!("[{rc}] V11 docker-in-VM: ok");
}

#[test]
fn test_agent_sandbox_k7() {
    suite("k7");
}

#[test]
fn test_agent_sandbox_k7_fc() {
    suite("k7-fc");
}
