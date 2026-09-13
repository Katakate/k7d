//! Continuous time dilation: swept
//! over N, changed on a live cluster, tracked both ways, and forked.
//!
//! Not part of `make check`: every test here needs the carried KVM patch
//! (`utils/kvm-dilation`) loaded, and every other spec's `remote-check`
//! runs on stock modules. `make dilation-test` (`make
//! remote-dilation-test`) is the entry point, and the target is
//! `test = false` in `Cargo.toml` so a bare `cargo test` skips it too.
//!
//! When the patch is *not* loaded these tests fail, loudly, with the
//! command that installs it. They never skip: a dilation suite that
//! passes on a stock host is a suite that proves nothing.
//!
//! What is measured, and why each thing is here:
//!
//! - **Rate** (`test_dilation_single_vm_runs_guest_time_8x`): all three
//!   guest clocks advance 8x wall, a guest `sleep 8` costs ~1 s of wall
//!   time, and the kernel says nothing about it. This is the mechanism.
//! - **I/O** (same test, and the cluster's pod-to-pod RTT): real I/O
//!   does not dilate, so at N a 1 ms fsync looks like N ms of guest
//!   time. The clock survey bounded CPU headroom and explicitly could not
//!   bound this, which makes it the central risk rather than a
//!   footnote.
//! - **Fidelity sweep** (`test_dilation_three_node_k3s_fidelity_sweep`):
//!   the same scripted episode at N ∈ {1, 2, 4, 8, 12, 16}, three runs
//!   each from a fresh cluster. N=1 on patched modules is the control.
//!   The test names the largest N that still has zero unscripted
//!   restarts, NotReady lapses and dmesg splats, and fails only if that
//!   knee is below 4. Probe failures and churn rounds are plotted, not
//!   thresholded. Busy-phase mean awake vCPUs are compared to the survey's
//!   `n_cpus / mean_awake` ceiling.
//! - **Forks** (`test_dilation_fork_*`): a warm fork, a cold
//!   snapshot/restore, and a whole 3-node cluster fork of a dilated
//!   VM come back at the source's factor, on the source's clock, with
//!   the time at rest counted in guest time. There is also a
//!   child at a *different* N (×8 → ×1, ×1 → ×8, batch shares one
//!   factor). `make remote-dilation-fork-test` runs every
//!   `test_dilation_fork_*`.
//! - **Live change** (the `test_dilation_live_*` and
//!   `test_dilation_policy_*` tests): the factor of a *running* VM
//!   comes down *or* up while every vCPU is paused, its clocks change
//!   slope without jumping, a runnable vCPU makes the kernel say
//!   `EBUSY`, one factor lands across a 3-node cluster in one pause
//!   window, `DilationPolicy` walks 8 → 4 → 2 → 1 and never back up,
//!   and `TrackingPolicy` walks back up after the load goes away.
//! - **Four-policy episode** (`test_dilation_four_policy_idle_busy_idle`):
//!   the same 240 s guest-time script under fixed8 / fixed4 / down /
//!   track, idle/busy/idle in 80 s guest windows. Shape, not values.
//!
//! Episode kubectl talks to the API server from *inside* the guest
//! (CHALLENGES #191): at N=16 the serving cert's `notBefore` is far
//! enough in the host's future that host-side kubectl would sit out
//! the run.

#![allow(clippy::cast_precision_loss)]

mod common;

use std::time::{Duration, Instant};

use k7d::api::AgentClient;
use k7d::control::{NetConfig, Request, Response, VmConfig};
use k7d::vm::{TimeSample, Vm};

use common::ubuntu::{
    build_node_vm_sized, connect_or_dump, node_image, sh_ok, NodeCmdlineExtra, NodeSize, VmDisk,
    NODE_VCPUS,
};
use common::ubuntu_k3s::{
    bring_up_cluster_sized, guest_apply_yaml, guest_kubectl, guest_nodes_ready,
    wait_nodes_ready_via_guest, UbuntuCluster, UbuntuCni, BUSYBOX, CHURN_PAUSE, CONVERGE,
};
use common::warp::{check_clocksource, check_no_ntp_client, check_no_splats, guest_clocks};

/// Rate-check and fork-child factor: the single validated point.
const RATE_N: u32 = 8;

/// The sweep. N=1 on patched modules is the control.
/// Override with `K7_DILATION_SWEEP=16` (comma-separated) to rerun one
/// factor; the default is the full curve.
const SWEEP: [u32; 6] = [1, 2, 4, 8, 12, 16];

fn sweep_factors() -> Vec<u32> {
    match std::env::var("K7_DILATION_SWEEP") {
        Ok(s) => s
            .split(',')
            .map(|p| {
                p.trim().parse::<u32>().unwrap_or_else(|e| {
                    panic!("K7_DILATION_SWEEP={s:?} is not a comma-separated list of factors: {e}")
                })
            })
            .collect(),
        Err(_) => SWEEP.to_vec(),
    }
}

/// Three runs per N — one run is an anecdote.
const RUNS: usize = 3;

/// A patch that cannot keep restarts / NotReady / splats at zero
/// through 4× is broken, not merely at its limit.
const KNEE_MIN: u32 = 4;

/// The survey's measured CPU-side ceilings, for the comparison the
/// success criteria ask for.
const CEILING_STEADY: f64 = 10.3;
const CEILING_WAIT: f64 = 14.9;
const CEILING_BUSY: f64 = 1.6;

/// How long the rate is measured over. Long enough that the boot-time
/// transient and the agent round trips are noise against it.
const RATE_WINDOW: Duration = Duration::from_secs(20);

/// The measured rate has to be this close to N. The slack is for the
/// two agent round trips at the window's ends, not for the mechanism:
/// a factor that is off by more than this is off by a bug.
const RATE_TOLERANCE: f64 = 0.10;

/// One guest-time step of the fidelity episode. Under dilation this is
/// N times cheaper in wall time, which is the whole point; the episode
/// is defined in guest time so both arms run the same workload.
const EPISODE_GUEST: Duration = Duration::from_secs(240);

fn require_patched_host() {
    if let Err(e) = k7d::vm::host_supports_dilation() {
        panic!(
            "this host does not expose per-VM time dilation ({e}) — \
             install utils/kvm-dilation (bash utils/kvm-dilation/install.sh) \
             and re-run; this suite never passes on stock modules"
        );
    }
    // "Patched" is not sharp enough: the modules are built from a file
    // in this tree, and an edited patch whose rebuild was skipped
    // presents as a patched host that answers EBUSY to every live
    // change — which reads as a bug in `set_dilation_live` rather than
    // a stale install (see `install.sh`'s patch.sha256 check).
    let abi = k7d::vm::host_dilation_abi().expect("a patched host reports its patch generation");
    assert!(
        abi >= k7d::vm::DILATION_ABI_LIVE_SET,
        "the loaded KVM modules are generation {abi} of utils/kvm-dilation, and the live \
         factor change needs {} — rebuild them (bash utils/kvm-dilation/install.sh)",
        k7d::vm::DILATION_ABI_LIVE_SET
    );
}

/// Boot one Ubuntu node VM (no k3s) at dilation `n`.
fn boot_node(tag: &str, n: u32) -> (Vm, AgentClient, k7d::network::ClusterNetwork, VmDisk) {
    let image = node_image();
    let disk = VmDisk::clone_of(&image.base_image(), tag);
    let mut net = k7d::network::ClusterNetwork::create(tag).expect("bridge");
    let tap = net.add_tap().expect("tap");
    let mut vm = build_node_vm_sized(
        &image,
        &disk,
        tap,
        NodeCmdlineExtra {
            k3s: None,
            cni: None,
        },
        &[],
        NodeSize::DEFAULT.dilated(n),
    );
    vm.start().expect("dilated Ubuntu node should start");
    let agent = connect_or_dump(&mut vm, tag);
    (vm, agent, net, disk)
}

/// Guest-visible cost of a durable 4 KiB write, in milliseconds of
/// *guest* time — the number a workload inside the VM would see.
///
/// Real I/O does not dilate: the disk takes the wall time it takes, and
/// the guest's clock is running N times faster while it waits, so this
/// is expected to be ~N times the undilated figure. It is measured
/// rather than argued because it is the cost that decides whether
/// dilation is usable, and the survey could not bound it.
fn guest_fsync_ms(agent: &mut AgentClient, whose: &str) -> f64 {
    let out = sh_ok(
        agent,
        "rm -f /var/tmp/k7-fsync; \
         s=$(date +%s.%N); \
         for i in $(seq 1 20); do dd if=/dev/zero of=/var/tmp/k7-fsync bs=4096 count=1 \
             conv=fsync oflag=append status=none; done; \
         e=$(date +%s.%N); rm -f /var/tmp/k7-fsync; \
         awk -v s=$s -v e=$e 'BEGIN{printf \"%.3f\", (e-s)*1000/20}'",
    );
    out.trim()
        .parse()
        .unwrap_or_else(|e| panic!("{whose}: fsync timing {out:?} is not a number: {e}"))
}

/// Observed guest-time per wall-time over `window`, from all three
/// guest clocks (`CLOCK_REALTIME`, `CLOCK_MONOTONIC`, `CLOCK_BOOTTIME`).
fn measured_rates(agent: &mut AgentClient, whose: &str, window: Duration) -> [f64; 3] {
    let before = guest_clocks(agent, whose);
    let t0 = Instant::now();
    std::thread::sleep(window);
    let after = guest_clocks(agent, whose);
    let wall = t0.elapsed().as_secs_f64();
    [0, 1, 2].map(|i| (after[i] - before[i]) / wall)
}

#[test]
fn test_dilation_single_vm_runs_guest_time_8x() {
    let _ = env_logger::builder().is_test(true).try_init();
    require_patched_host();

    let (mut vm, mut agent, _net, _disk) = boot_node("dil-one", RATE_N);
    check_clocksource(&mut agent, "dilated");
    // Without this the guest steps CLOCK_REALTIME back to true time and
    // the rate below reads 1x on one clock and 8x on the others
    // (CHALLENGES #180).
    check_no_ntp_client(&mut agent, "dilated");

    let rates = measured_rates(&mut agent, "dilated", RATE_WINDOW);
    let names = ["CLOCK_REALTIME", "CLOCK_MONOTONIC", "CLOCK_BOOTTIME"];
    for (rate, name) in rates.iter().zip(names) {
        eprintln!("MEASUREMENT single-VM {name} guest-per-wall {rate:.3}x (asked {RATE_N}x)");
        assert!(
            (rate - f64::from(RATE_N)).abs() <= f64::from(RATE_N) * RATE_TOLERANCE,
            "{name} advanced {rate:.3}x wall time, not {RATE_N}x — the pvclock scale and the \
             hardware TSC multiplier disagree"
        );
    }

    // A guest that believes 8 seconds passed after 1 second of wall
    // time is the mechanism working end to end: `sleep` is armed off
    // the same clock the timers are.
    let t0 = Instant::now();
    let slept = sh_ok(
        &mut agent,
        "s=$(date +%s.%N); sleep 8; date +%s.%N | \
         awk -v s=$s '{printf \"%.3f\", $1-s}'",
    );
    let wall = t0.elapsed().as_secs_f64();
    let guest: f64 = slept.trim().parse().expect("guest sleep duration");
    eprintln!(
        "MEASUREMENT single-VM `sleep 8`: {guest:.3} s guest in {wall:.3} s wall \
         ({:.2}x)",
        guest / wall
    );
    assert!(
        guest >= 8.0,
        "the guest slept {guest:.3} s of its own time, less than the 8 s it asked for"
    );
    assert!(
        wall < 8.0 / f64::from(RATE_N) * (1.0 + RATE_TOLERANCE) + 0.5,
        "`sleep 8` cost {wall:.3} s of wall time; at {RATE_N}x it should cost about 1 s"
    );

    // The I/O side of the same coin: the disk is as slow as it ever
    // was, so in guest time it is N times slower.
    let fsync = guest_fsync_ms(&mut agent, "dilated");
    eprintln!(
        "MEASUREMENT single-VM guest-visible fsync {fsync:.3} ms/4KiB at {RATE_N}x \
         (~{:.3} ms of wall time)",
        fsync / f64::from(RATE_N)
    );

    check_no_splats(&mut agent, "dilated");
    eprintln!(
        "MEASUREMENT CPU ceilings from the survey for reference: \
         steady {CEILING_STEADY}x, wait {CEILING_WAIT}x, busy {CEILING_BUSY}x"
    );
    vm.shutdown();
}

/// What one run of the fidelity episode produced.
struct Fidelity {
    /// Wall time the fixed guest-time episode cost.
    wall: Duration,
    /// Guest time the cluster observed passing.
    guest: Duration,
    /// Liveness-probe failures the API server recorded (sum of event counts).
    probe_failures: u64,
    /// Container restarts beyond the scripted ones.
    restarts: u64,
    /// etcd leader elections (0 on a healthy single-server k3s).
    leader_elections: u64,
    /// Polls at which some node was not `Ready`.
    not_ready_lapses: u64,
    /// Clock/stall complaints in the nodes' `dmesg`.
    splats: u64,
    /// Churn rounds the in-guest loop completed.
    churn_rounds: u64,
    /// Guest-visible fsync cost, ms per 4 KiB.
    fsync_ms: f64,
    /// Pod-to-pod round trip, ms of guest time.
    rtt_ms: f64,
    /// Mean awake vCPUs during the busy/churn window (the survey's reading).
    mean_awake: f64,
    /// vCPUs in the cluster (3 × 2).
    n_cpus: f64,
    /// How many pause→sample→resume observations the mean rests on.
    awake_samples: usize,
}

impl Fidelity {
    /// Restarts, NotReady lapses and splats are the hard columns: a
    /// cluster that is faster and broken is not a result.
    fn hard_clean(&self) -> bool {
        self.restarts == 0 && self.not_ready_lapses == 0 && self.splats == 0
    }

    fn observed(&self) -> f64 {
        self.guest.as_secs_f64() / self.wall.as_secs_f64()
    }

    /// The CPU-side ceiling from this run's own awake reading.
    fn predicted_ceiling(&self) -> f64 {
        if self.mean_awake > 0.0 {
            self.n_cpus / self.mean_awake
        } else {
            f64::INFINITY
        }
    }
}

fn guest_event_count(agent: &mut AgentClient, reason: &str) -> u64 {
    guest_kubectl(
        agent,
        &[
            "get",
            "events",
            "-A",
            "--field-selector",
            &format!("reason={reason}"),
            "-o",
            "jsonpath={range .items[*]}{.count}{'\\n'}{end}",
        ],
    )
    .unwrap_or_default()
    .lines()
    .filter_map(|l| l.trim().parse::<u64>().ok())
    .sum()
}

fn guest_total_restarts(agent: &mut AgentClient) -> u64 {
    guest_kubectl(
        agent,
        &[
            "get",
            "pods",
            "-A",
            "-o",
            "jsonpath={.items[*].status.containerStatuses[*].restartCount}",
        ],
    )
    .unwrap_or_default()
    .split_whitespace()
    .filter_map(|v| v.parse::<u64>().ok())
    .sum()
}

fn splat_count(agent: &mut AgentClient) -> u64 {
    sh_ok(
        agent,
        "dmesg | grep -ci 'soft lockup\\|clocksource.*unstable\\|rcu_sched detected\\|\
         BUG: soft' || true",
    )
    .trim()
    .parse()
    .unwrap_or(0)
}

/// Pause all three node VMs, sample them, resume them (the survey's reading).
fn sample_cluster(vms: &mut [&mut Vm; 3]) -> (Vec<TimeSample>, Duration) {
    let started = Instant::now();
    let mut guard = scopeguard::guard(vms, |vms| {
        for vm in vms.iter_mut() {
            vm.resume().expect("every VM resumes after a sample");
        }
    });
    for vm in guard.iter_mut() {
        vm.pause().expect("every VM pauses for a sample");
    }
    let samples: Vec<TimeSample> = guard
        .iter()
        .map(|vm| {
            vm.sample_time_state()
                .expect("a paused VM samples its time state")
        })
        .collect();
    drop(guard);
    (samples, started.elapsed())
}

fn awake_from(samples: &[TimeSample]) -> (usize, usize) {
    let n_cpus: usize = samples.iter().map(|s| s.cpus.len()).sum();
    let awake = samples
        .iter()
        .flat_map(|s| s.cpus.iter())
        .filter(|c| !c.is_halted())
        .count();
    (awake, n_cpus)
}

/// Two pods on the cluster network, pinging each other. The RTT is real
/// wall time that the dilated guest measures with a clock running N
/// times faster, so it is the network half of the I/O cost.
fn pod_to_pod_rtt_ms(agent: &mut AgentClient) -> f64 {
    for (name, cmd) in [("rtt-server", "sleep 3600"), ("rtt-client", "sleep 3600")] {
        guest_apply_yaml(
            agent,
            name,
            &format!(
                r"apiVersion: v1
kind: Pod
metadata:
  name: {name}
spec:
  restartPolicy: Never
  containers:
  - name: p
    image: {BUSYBOX}
    imagePullPolicy: IfNotPresent
    command: ['sh', '-c', '{cmd}']
"
            ),
        );
    }
    let started = Instant::now();
    let server_ip = loop {
        let ip = guest_kubectl(
            agent,
            &["get", "pod", "rtt-server", "-o", "jsonpath={.status.podIP}"],
        )
        .unwrap_or_default();
        if !ip.trim().is_empty() {
            break ip.trim().to_string();
        }
        assert!(
            started.elapsed() < CONVERGE,
            "rtt-server never got a pod IP"
        );
        std::thread::sleep(Duration::from_secs(2));
    };
    let out = loop {
        match guest_kubectl(
            agent,
            &[
                "exec",
                "rtt-client",
                "--",
                "ping",
                "-c",
                "20",
                "-q",
                &server_ip,
            ],
        ) {
            Ok(out) if out.contains("min/avg") => break out,
            _ => {
                assert!(
                    started.elapsed() < CONVERGE * 2,
                    "rtt-client never pinged {server_ip}"
                );
                std::thread::sleep(Duration::from_secs(3));
            }
        }
    };
    for pod in ["rtt-server", "rtt-client"] {
        let _ = guest_kubectl(
            agent,
            &[
                "delete",
                "pod",
                pod,
                "--ignore-not-found",
                "--force",
                "--grace-period=0",
            ],
        );
    }
    out.split("= ")
        .nth(1)
        .and_then(|tail| tail.split('/').nth(1))
        .and_then(|avg| avg.trim().parse().ok())
        .unwrap_or_else(|| panic!("no average RTT in {out:?}"))
}

fn guest_settle(agent: &mut AgentClient, tag: &str) {
    let pod = format!("{tag}-settle");
    guest_apply_yaml(
        agent,
        &pod,
        &format!(
            r"apiVersion: v1
kind: Pod
metadata:
  name: {pod}
spec:
  restartPolicy: Never
  containers:
  - name: ok
    image: {BUSYBOX}
    imagePullPolicy: IfNotPresent
    command: ['sh', '-c', 'exit 0']
"
        ),
    );
    let started = Instant::now();
    loop {
        let phase = guest_kubectl(
            agent,
            &["get", "pod", &pod, "-o", "jsonpath={.status.phase}"],
        )
        .unwrap_or_default();
        if phase.trim() == "Succeeded" {
            eprintln!(
                "cluster settled via guest kubectl in {:?}",
                started.elapsed()
            );
            break;
        }
        assert!(
            started.elapsed() < CONVERGE * 3,
            "no pod could run before the episode started (phase {phase:?})"
        );
        std::thread::sleep(Duration::from_secs(3));
    }
    let _ = guest_kubectl(
        agent,
        &[
            "delete",
            "pod",
            &pod,
            "--ignore-not-found",
            "--force",
            "--grace-period=0",
        ],
    );
}

/// Poll a Deployment's readyReplicas instead of `rollout status`.
/// The latter is one exec that can outlive the agent's 30 s window.
fn guest_wait_rollout(agent: &mut AgentClient, deploy: &str, tag: &str) {
    let started = Instant::now();
    loop {
        let got = guest_kubectl(
            agent,
            &[
                "get",
                "deploy",
                deploy,
                "-o",
                "jsonpath={.status.readyReplicas}/{.spec.replicas}",
            ],
        )
        .unwrap_or_default();
        let ready = got.trim();
        if let Some((a, b)) = ready.split_once('/') {
            if !a.is_empty() && a == b {
                return;
            }
        }
        assert!(
            started.elapsed() < CONVERGE * 3,
            "{tag}: deploy/{deploy} never Ready (last {ready:?})"
        );
        std::thread::sleep(Duration::from_secs(2));
    }
}

const CHURN_DEPLOY: &str = "dil-churn";
const BURNER_POD: &str = "dil-burner";
const CHURN_HIGH: u32 = 6;
const CHURN_LOW: u32 = 2;
const READY_EVERY: u32 = 2;
/// Wall time between clock polls. Also the sample cadence: a 500 ms
/// reconnect+pause loop burned the agent's 30 s exec window by the
/// time the episode tried to delete the RTT pods.
const POLL: Duration = Duration::from_secs(2);
const SAMPLE_EVERY: u32 = 2;

/// The published stock numbers. N=1 on patched modules must land here.
const STOCK_WALL_S: f64 = 240.3;
const STOCK_FSYNC_MS: f64 = 2.295;

/// The scripted episode, identical in *guest* time at every N: a
/// rollout, a scale down/up, an in-guest churn loop, and a wait long
/// enough for the kubelet's liveness probes to run many periods.
fn run_episode(cluster: &mut UbuntuCluster, tag: &str) -> Fidelity {
    let whose = ["server", "agent-1", "agent-2"];
    let names = cluster.names();
    let mut server = connect_or_dump(&mut cluster.server, "server");
    guest_settle(&mut server, tag);

    let probes_before = guest_event_count(&mut server, "Unhealthy");
    let restarts_before = guest_total_restarts(&mut server);
    let elections_before = guest_event_count(&mut server, "LeaderElection");
    let clock_before = guest_clocks(&mut server, "server");
    let t0 = Instant::now();

    guest_apply_yaml(
        &mut server,
        "dil-probe",
        &format!(
            r"apiVersion: apps/v1
kind: Deployment
metadata:
  name: dil-probe
spec:
  replicas: 6
  selector:
    matchLabels: {{app: dil-probe}}
  template:
    metadata:
      labels: {{app: dil-probe}}
    spec:
      containers:
      - name: p
        image: {BUSYBOX}
        imagePullPolicy: IfNotPresent
        command: ['sh', '-c', 'sleep 3600']
        livenessProbe:
          exec:
            command: ['true']
          periodSeconds: 10
"
        ),
    );
    guest_wait_rollout(&mut server, "dil-probe", tag);

    for replicas in ["2", "6"] {
        guest_kubectl(
            &mut server,
            &[
                "scale",
                "deployment/dil-probe",
                &format!("--replicas={replicas}"),
            ],
        )
        .unwrap_or_else(|e| panic!("{tag}: scale to {replicas}: {e}"));
        guest_wait_rollout(&mut server, "dil-probe", tag);
    }

    guest_apply_yaml(
        &mut server,
        CHURN_DEPLOY,
        &format!(
            r"apiVersion: apps/v1
kind: Deployment
metadata:
  name: {CHURN_DEPLOY}
spec:
  replicas: {CHURN_HIGH}
  selector:
    matchLabels: {{app: {CHURN_DEPLOY}}}
  template:
    metadata:
      labels: {{app: {CHURN_DEPLOY}}}
    spec:
      containers:
      - name: pause
        image: {CHURN_PAUSE}
        imagePullPolicy: IfNotPresent
---
apiVersion: v1
kind: Pod
metadata:
  name: {BURNER_POD}
spec:
  restartPolicy: Never
  containers:
  - name: burn
    image: {BUSYBOX}
    imagePullPolicy: IfNotPresent
    command: ['sh', '-c', 'while true; do :; done']
    resources:
      limits:
        cpu: 200m
"
        ),
    );
    guest_wait_rollout(&mut server, CHURN_DEPLOY, tag);

    // One brief exec starts a loop that then lives in guest time.
    sh_ok(
        &mut server,
        &format!(
            "rm -f /tmp/dil-churn.stop /tmp/dil-churn.rounds; \
             setsid nohup sh -c 'while [ ! -f /tmp/dil-churn.stop ]; do \
               for n in {CHURN_LOW} {CHURN_HIGH}; do \
                 k3s kubectl scale deploy/{CHURN_DEPLOY} --replicas=$n >/dev/null 2>&1; \
                 echo x >> /tmp/dil-churn.rounds; \
                 sleep 2; \
               done; \
             done' </dev/null >/dev/null 2>&1 & echo started"
        ),
    );
    drop(server);

    let deadline_guest = clock_before[1] + EPISODE_GUEST.as_secs_f64();
    let mut not_ready_lapses = 0_u64;
    let mut awake_sum = 0_u64;
    let mut n_cpus_last = 0_usize;
    let mut awake_samples = 0_usize;
    let mut polls = 0_u32;
    loop {
        let mut server = connect_or_dump(&mut cluster.server, "server");
        let now = guest_clocks(&mut server, "server");
        if now[1] >= deadline_guest {
            drop(server);
            break;
        }
        polls += 1;
        if polls % READY_EVERY == 0 && !guest_nodes_ready(&mut server, &names) {
            not_ready_lapses += 1;
        }
        drop(server);
        assert!(
            t0.elapsed() < Duration::from_secs(1800),
            "{tag}: the guest never reached {EPISODE_GUEST:?} of episode time"
        );

        if polls % SAMPLE_EVERY == 0 {
            let mut vms = [
                &mut cluster.server,
                &mut cluster.agent1,
                &mut cluster.agent2,
            ];
            let (samples, _) = sample_cluster(&mut vms);
            let (awake, n_cpus) = awake_from(&samples);
            awake_sum += awake as u64;
            n_cpus_last = n_cpus;
            awake_samples += 1;
        }

        std::thread::sleep(POLL);
    }

    let wall = t0.elapsed();
    let mut server = connect_or_dump(&mut cluster.server, "server");
    let clock_after = guest_clocks(&mut server, "server");
    let churn_rounds = sh_ok(
        &mut server,
        "touch /tmp/dil-churn.stop; wc -l < /tmp/dil-churn.rounds || echo 0",
    )
    .trim()
    .parse::<u64>()
    .unwrap_or(0);
    let rtt_ms = pod_to_pod_rtt_ms(&mut server);
    let fsync_ms = guest_fsync_ms(&mut server, "server");
    let probe_failures = guest_event_count(&mut server, "Unhealthy").saturating_sub(probes_before);
    let restarts = guest_total_restarts(&mut server).saturating_sub(restarts_before);
    let leader_elections =
        guest_event_count(&mut server, "LeaderElection").saturating_sub(elections_before);
    let _ = guest_kubectl(
        &mut server,
        &[
            "delete",
            "deployment",
            "dil-probe",
            CHURN_DEPLOY,
            "--ignore-not-found",
        ],
    );
    let _ = guest_kubectl(
        &mut server,
        &[
            "delete",
            "pod",
            BURNER_POD,
            "--ignore-not-found",
            "--force",
            "--grace-period=0",
        ],
    );
    drop(server);

    let mut agents = [
        connect_or_dump(&mut cluster.server, whose[0]),
        connect_or_dump(&mut cluster.agent1, whose[1]),
        connect_or_dump(&mut cluster.agent2, whose[2]),
    ];
    let splats = agents.iter_mut().map(splat_count).sum::<u64>();

    let mean_awake = if awake_samples == 0 {
        0.0
    } else {
        awake_sum as f64 / awake_samples as f64
    };

    Fidelity {
        wall,
        guest: Duration::from_secs_f64(clock_after[1] - clock_before[1]),
        probe_failures,
        restarts,
        leader_elections,
        not_ready_lapses,
        splats,
        churn_rounds,
        fsync_ms,
        rtt_ms,
        mean_awake,
        n_cpus: n_cpus_last as f64,
        awake_samples,
    }
}

fn median_f64(xs: &[f64]) -> f64 {
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    v[v.len() / 2]
}

fn median_u64(xs: &[u64]) -> u64 {
    let mut v = xs.to_vec();
    v.sort_unstable();
    v[v.len() / 2]
}

fn min_max_f64(xs: &[f64]) -> (f64, f64) {
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    (v[0], v[v.len() - 1])
}

#[test]
fn test_dilation_three_node_k3s_fidelity_sweep() {
    let _ = env_logger::builder().is_test(true).try_init();
    require_patched_host();

    let mut by_n: Vec<(u32, Vec<Fidelity>)> = Vec::new();
    for n in sweep_factors() {
        let mut runs = Vec::new();
        for i in 0..RUNS {
            let tag = format!("n{n}r{i}");
            let mut cluster = bring_up_cluster_sized(
                UbuntuCni::Flannel,
                &tag,
                None,
                NodeSize::DEFAULT.dilated(n),
            );
            let run = run_episode(&mut cluster, &tag);
            eprintln!(
                "MEASUREMENT N={n} run {i}: wall {:.1}s guest {:.1}s \
                 ({:.2}x) probes {} restarts {} elections {} notready {} \
                 splats {} churn {} fsync {:.3} rtt {:.3} awake {:.3}/{} \
                 (n={}/mean_awake ceiling {:.1}x vs busy {CEILING_BUSY}x)",
                run.wall.as_secs_f64(),
                run.guest.as_secs_f64(),
                run.observed(),
                run.probe_failures,
                run.restarts,
                run.leader_elections,
                run.not_ready_lapses,
                run.splats,
                run.churn_rounds,
                run.fsync_ms,
                run.rtt_ms,
                run.mean_awake,
                run.n_cpus,
                run.awake_samples,
                run.predicted_ceiling(),
            );
            drop(cluster);
            runs.push(run);
        }
        by_n.push((n, runs));
    }

    eprintln!(
        "\n| N | wall (s) | guest (s) | observed | probes | restarts | elections | \
         NotReady | splats | churn | fsync ms | RTT ms | mean awake | pred. ceiling |\n\
         |---|---|---|---|---|---|---|---|---|---|---|---|---|---|"
    );
    for (n, runs) in &by_n {
        let walls: Vec<f64> = runs.iter().map(|r| r.wall.as_secs_f64()).collect();
        let guests: Vec<f64> = runs.iter().map(|r| r.guest.as_secs_f64()).collect();
        let obs: Vec<f64> = runs.iter().map(Fidelity::observed).collect();
        let probes: Vec<u64> = runs.iter().map(|r| r.probe_failures).collect();
        let restarts: Vec<u64> = runs.iter().map(|r| r.restarts).collect();
        let elections: Vec<u64> = runs.iter().map(|r| r.leader_elections).collect();
        let lapses: Vec<u64> = runs.iter().map(|r| r.not_ready_lapses).collect();
        let splats: Vec<u64> = runs.iter().map(|r| r.splats).collect();
        let churn: Vec<u64> = runs.iter().map(|r| r.churn_rounds).collect();
        let fsync: Vec<f64> = runs.iter().map(|r| r.fsync_ms).collect();
        let rtt: Vec<f64> = runs.iter().map(|r| r.rtt_ms).collect();
        let awake: Vec<f64> = runs.iter().map(|r| r.mean_awake).collect();
        let ceil: Vec<f64> = runs.iter().map(Fidelity::predicted_ceiling).collect();
        let (wlo, whi) = min_max_f64(&walls);
        eprintln!(
            "| {n} | {:.1} ({wlo:.1}–{whi:.1}) | {:.1} | {:.2}× | {} | {} | {} | {} | {} | {} | \
             {:.2} | {:.3} | {:.3} | {:.1}× |",
            median_f64(&walls),
            median_f64(&guests),
            median_f64(&obs),
            median_u64(&probes),
            median_u64(&restarts),
            median_u64(&elections),
            median_u64(&lapses),
            median_u64(&splats),
            median_u64(&churn),
            median_f64(&fsync),
            median_f64(&rtt),
            median_f64(&awake),
            median_f64(&ceil),
        );
    }

    if let Some((_, n1)) = by_n.iter().find(|(n, _)| *n == 1) {
        for (i, run) in n1.iter().enumerate() {
            // A single unscripted kube-apiserver restart at N=1 is the
            // flake we documented at other N and sampled at N=1
            // (in the results). The dilation map is the
            // identity at N=1, so this is k3s, not the patch. Fail on
            // NotReady/splats, on more than one restart, or if *every*
            // N=1 run restarted.
            assert_eq!(
                run.not_ready_lapses, 0,
                "N=1 run {i} went NotReady — the control is broken"
            );
            assert_eq!(
                run.splats, 0,
                "N=1 run {i} splatted — the control is broken"
            );
            assert!(
                run.restarts <= 1,
                "N=1 run {i} had {} restarts — the documented flake is one, not this",
                run.restarts
            );
            let wall = run.wall.as_secs_f64();
            assert!(
                (wall - STOCK_WALL_S).abs() / STOCK_WALL_S <= 0.20,
                "N=1 run {i} wall {wall:.1}s is not the stock {STOCK_WALL_S}s — \
             the patch costs something when it is not asked for"
            );
            assert!(
                (run.observed() - 1.0).abs() <= RATE_TOLERANCE,
                "N=1 run {i} observed {:.2}×, not 1×",
                run.observed()
            );
            assert!(
                (run.fsync_ms - STOCK_FSYNC_MS).abs() / STOCK_FSYNC_MS <= 1.5,
                "N=1 run {i} fsync {:.3} ms is not the stock {STOCK_FSYNC_MS} ms",
                run.fsync_ms
            );
            assert_eq!(
                run.leader_elections, 0,
                "N=1 run {i} recorded a leader election on single-server k3s"
            );
        }
        assert!(
            n1.iter().any(Fidelity::hard_clean),
            "every N=1 run restarted — that is a broken control, not the \
             single-restart flake we documented"
        );
    }

    let knee = by_n
        .iter()
        .rev()
        .find(|(_, runs)| runs.iter().all(Fidelity::hard_clean))
        .map(|(n, _)| *n)
        .unwrap_or(0);
    eprintln!(
        "MEASUREMENT knee: largest N with zero restarts, NotReady lapses \
         and splats on every run = {knee} (fail below {KNEE_MIN})"
    );
    if by_n.iter().any(|(n, _)| *n <= KNEE_MIN) {
        assert!(
            knee >= KNEE_MIN,
            "the largest hard-clean N is {knee}, below {KNEE_MIN} — the patch cannot \
             manage 4×, which is broken rather than at its limit"
        );
    }

    for (n, runs) in &by_n {
        if *n >= 2 {
            for (i, run) in runs.iter().enumerate() {
                assert!(
                    run.observed() <= f64::from(*n) * 1.10,
                    "N={n} run {i} observed {:.2}× above the {n}× that was asked for — \
                     an accounting bug, not a faster cluster",
                    run.observed()
                );
            }
        }
        let awake = median_f64(&runs.iter().map(|r| r.mean_awake).collect::<Vec<_>>());
        let pred = if awake > 0.0 {
            runs[0].n_cpus / awake
        } else {
            f64::INFINITY
        };
        eprintln!(
            "MEASUREMENT N={n} busy-phase mean awake {awake:.3} / {} \
             → n_cpus/mean_awake {pred:.1}× (busy ceiling {CEILING_BUSY}×). \
             Asked {n}× {} the prediction.",
            runs[0].n_cpus,
            if f64::from(*n) > pred {
                "exceeds"
            } else {
                "is inside"
            }
        );
    }
}

/// The ladder: start at the operating point, drop to the
/// factor the sweep called essentially free.
const DROP_FROM: u32 = 8;
const DROP_TO: u32 = 4;

/// How long the rate is re-measured over after a live change. Shorter
/// than `RATE_WINDOW` because two of these run per test and the factor
/// is either right or wrong, not slightly off.
const REMEASURE: Duration = Duration::from_secs(10);

/// Guest seconds the change itself is allowed to be worth. The daemon's
/// pause → set → resume is sub-millisecond of wall (measured
/// 0.79–0.83 ms on 3 VMs) and the two agent round-trips around
/// it are tens of milliseconds, so at 8× even a slow read pair is worth
/// well under a second of guest time. A *jump* — the failure this
/// bounds — would be the whole affine base, seconds or minutes.
const CONTINUITY_SLACK_S: f64 = 2.0;

/// What the guest's clocks read on either side of a factor change, and
/// the host wall time between the two readings.
struct Across {
    before: [f64; 3],
    after: [f64; 3],
    wall: f64,
    host_before: f64,
    host_after: f64,
}

fn host_realtime_s() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("host clock is after 1970")
        .as_secs_f64()
}

/// Read the guest's clocks, run `change`, read them again — and hold on
/// to the host's own clock on both sides, because the thing that must
/// not happen when the factor drops is the guest's `CLOCK_REALTIME`
/// coming *back* towards the host's (CHALLENGES #191).
fn across_change<F: FnOnce()>(agent: &mut AgentClient, whose: &str, change: F) -> Across {
    let before = guest_clocks(agent, whose);
    let host_before = host_realtime_s();
    let t0 = Instant::now();
    change();
    let after = guest_clocks(agent, whose);
    Across {
        before,
        after,
        wall: t0.elapsed().as_secs_f64(),
        host_before,
        host_after: host_realtime_s(),
    }
}

impl Across {
    /// No clock went backwards, and none of them jumped: the most guest
    /// time any of them may have gained is the old factor's worth of the
    /// wall time between the readings, plus slack for the round trips.
    fn assert_continuous(&self, whose: &str, old: u32) {
        let names = ["CLOCK_REALTIME", "CLOCK_MONOTONIC", "CLOCK_BOOTTIME"];
        let budget = self.wall * f64::from(old) + CONTINUITY_SLACK_S;
        for ((b, a), name) in self.before.iter().zip(&self.after).zip(names) {
            let delta = a - b;
            eprintln!(
                "MEASUREMENT {whose} {name} across the change: +{delta:.3} s guest \
                 in {:.3} s wall (budget {budget:.3} s at x{old})",
                self.wall
            );
            assert!(
                delta >= 0.0,
                "{whose}: {name} went backwards by {:.3} s — changing the factor changes \
                 slope, it never rewinds (CHALLENGES #191)",
                -delta
            );
            assert!(
                delta <= budget,
                "{whose}: {name} gained {delta:.3} s of guest time across a {:.3} s wall \
                 change — the affine base jumped instead of changing slope",
                self.wall
            );
        }
    }

    /// The guest is ahead of the host by however much dilation has given
    /// it, and lowering the factor does not hand any of that back — it
    /// only stops the gap growing so fast.
    fn assert_keeps_its_lead(&self, whose: &str) {
        let lead_before = self.before[0] - self.host_before;
        let lead_after = self.after[0] - self.host_after;
        eprintln!(
            "MEASUREMENT {whose} CLOCK_REALTIME ahead of the host: \
             {lead_before:.3} s → {lead_after:.3} s"
        );
        assert!(
            lead_after >= lead_before - CONTINUITY_SLACK_S,
            "{whose}: the guest gave back {:.3} s of its lead on the host — a lower factor \
             must not rewind CLOCK_REALTIME (CHALLENGES #191)",
            lead_before - lead_after
        );
    }
}

fn assert_rate(agent: &mut AgentClient, whose: &str, want: u32, window: Duration) -> [f64; 3] {
    let rates = measured_rates(agent, whose, window);
    let names = ["CLOCK_REALTIME", "CLOCK_MONOTONIC", "CLOCK_BOOTTIME"];
    for (rate, name) in rates.iter().zip(names) {
        eprintln!("MEASUREMENT {whose} {name} guest-per-wall {rate:.3}x (asked {want}x)");
        assert!(
            (rate - f64::from(want)).abs() <= f64::from(want) * RATE_TOLERANCE,
            "{whose}: {name} advanced {rate:.3}x wall time, not {want}x"
        );
    }
    rates
}

/// The mechanism the adaptive policy adds: the factor of a *live* VM comes down, its
/// clocks change slope, and nothing about them jumps.
///
/// Both halves matter and they fail differently. A factor that does not
/// take is a stale hardware TSC multiplier — the rate stays at 8. A
/// factor that takes without the affine base being re-pinned is a rate
/// of 4 with a one-time step of the whole accumulated dilation, which a
/// rate measurement taken afterwards would not notice at all.
#[test]
fn test_dilation_live_drop_changes_slope_not_the_clock() {
    let _ = env_logger::builder().is_test(true).try_init();
    require_patched_host();

    let (mut vm, mut agent, _net, _disk) = boot_node("dil-live", DROP_FROM);
    check_clocksource(&mut agent, "live");
    check_no_ntp_client(&mut agent, "live");
    assert_eq!(vm.dilation(), DROP_FROM);
    assert_rate(&mut agent, "live", DROP_FROM, RATE_WINDOW);

    let mut latency = Duration::ZERO;
    let across = across_change(&mut agent, "live", || {
        let started = Instant::now();
        vm.pause().expect("the VM pauses for a factor change");
        vm.set_dilation_live(DROP_TO)
            .expect("a paused VM takes a live factor change");
        vm.resume().expect("the VM resumes after a factor change");
        latency = started.elapsed();
    });
    eprintln!("MEASUREMENT single-VM pause → set x{DROP_TO} → resume: {latency:?}");
    assert_eq!(vm.dilation(), DROP_TO);
    across.assert_continuous("live", DROP_FROM);
    across.assert_keeps_its_lead("live");

    assert_rate(&mut agent, "live", DROP_TO, REMEASURE);

    // A `sleep` is armed off the same clocks, so it is the end-to-end
    // check that the LAPIC and the TSC agree about the new factor.
    let t0 = Instant::now();
    let slept = sh_ok(
        &mut agent,
        "s=$(date +%s.%N); sleep 8; date +%s.%N | awk -v s=$s '{printf \"%.3f\", $1-s}'",
    );
    let wall = t0.elapsed().as_secs_f64();
    let guest: f64 = slept.trim().parse().expect("guest sleep duration");
    eprintln!(
        "MEASUREMENT single-VM `sleep 8` after the drop: {guest:.3} s guest in \
         {wall:.3} s wall ({:.2}x)",
        guest / wall
    );
    assert!(
        guest >= 8.0,
        "the guest slept only {guest:.3} s of its own time"
    );
    assert!(
        wall > 8.0 / f64::from(DROP_FROM) * 1.5,
        "`sleep 8` still cost {wall:.3} s of wall time — that is the x{DROP_FROM} price, so \
         the drop to x{DROP_TO} never reached the guest's timers"
    );
    assert!(
        wall < 8.0 / f64::from(DROP_TO) * (1.0 + RATE_TOLERANCE) + 0.5,
        "`sleep 8` cost {wall:.3} s of wall time; at x{DROP_TO} it should cost about 2 s"
    );

    // The bottom rung is a legal factor; the peak still names the
    // highest this VM has run at. Capture records the *current*
    // factor — 1 — because that is the rate restore must apply (the
    // fork refusal is lifted). The guest clock sitting in the host's
    // future is already in kvmclock.clock_ns.
    vm.pause().expect("pause");
    vm.set_dilation_live(1)
        .expect("the bottom rung is a legal factor");
    vm.resume().expect("resume");
    assert_eq!(vm.dilation(), 1);
    assert_eq!(vm.dilation_peak(), DROP_FROM);
    let state = k7d::snapshot::capture_vm_state(&vm)
        .expect("a VM that has been dilated is capturable at x1");
    assert_eq!(
        state.dilation, 1,
        "capture records the current factor, not the peak"
    );

    check_no_splats(&mut agent, "live");
    vm.shutdown();
}

/// The kernel's half of the contract, which is the one that matters:
/// `KVM_SET_DEVICE_ATTR(KVM_VM_DILATION)` is `EBUSY` while any vCPU is
/// runnable. Without it, a factor change would reprogram some vCPUs'
/// TSC multipliers while others kept running at the old rate, and a VM
/// whose vCPUs disagree about the rate has no clock at all.
///
/// Both halves are asserted because they fail independently: k7d's
/// `require_paused` refuses before the ioctl, so the kernel's refusal is
/// otherwise never reached from this codebase.
#[test]
fn test_dilation_live_set_is_refused_while_a_vcpu_runs() {
    let _ = env_logger::builder().is_test(true).try_init();
    require_patched_host();

    let (mut vm, mut agent, _net, _disk) = boot_node("dil-busy", DROP_FROM);
    // Something for the vCPUs to be inside KVM_RUN for.
    sh_ok(
        &mut agent,
        "setsid nohup sh -c 'while true; do :; done' </dev/null >/dev/null 2>&1 & echo spinning",
    );

    let err = vm
        .set_dilation_live(DROP_TO)
        .expect_err("a running VM must refuse a factor change");
    eprintln!("MEASUREMENT host-side refusal: {err}");
    assert!(
        matches!(err, k7d::vm::VmError::NotPaused { op, .. } if op == "set_dilation_live"),
        "the host-side refusal was not the paused check: {err}"
    );

    let err = vm
        .set_dilation_raw(DROP_TO)
        .expect_err("the kernel must refuse a factor change under a runnable vCPU");
    eprintln!("MEASUREMENT kernel-side refusal: {err}");
    let text = err.to_string();
    assert!(
        text.contains("Device or resource busy") || text.contains("EBUSY"),
        "the kernel refused for the wrong reason (wanted EBUSY): {err}"
    );
    assert_eq!(
        vm.dilation(),
        DROP_FROM,
        "the refused change must not have landed"
    );
    assert_rate(&mut agent, "busy", DROP_FROM, REMEASURE);

    // And the same VM takes the change the moment it is paused, so the
    // refusal above is about the pause and not about the factor.
    vm.pause().expect("pause");
    vm.set_dilation_live(DROP_TO)
        .expect("the same factor is fine once every vCPU is paused");
    vm.resume().expect("resume");
    assert_eq!(vm.dilation(), DROP_TO);

    check_no_splats(&mut agent, "busy");
    vm.shutdown();
}

/// The policy, driven by the named signal: busy-phase mean
/// awake vCPUs from `Vm::sample_time_state`, not probe failures.
///
/// An idle guest must *not* spend a rung — that is the half of the test
/// that can fail quietly — and a guest whose every vCPU is spinning must
/// drop, once, and never come back up.
#[test]
fn test_dilation_policy_drops_under_a_cpu_burner() {
    let _ = env_logger::builder().is_test(true).try_init();
    require_patched_host();

    let (mut vm, mut agent, _net, _disk) = boot_node("dil-pol", DROP_FROM);
    check_clocksource(&mut agent, "policy");
    check_no_ntp_client(&mut agent, "policy");

    // A wider window than the library default: this node has 2 vCPUs, so
    // one observation can only read 0, 0.5 or 1.0 of them awake, and a
    // 3-sample mean on that granularity is coarse enough that a single
    // systemd timer could look like saturation.
    let mut policy = k7d::dilation::DilationPolicy::new(POLICY_WINDOW, k7d::dilation::SATURATED);
    assert_eq!(
        policy.factor(),
        DROP_FROM,
        "the policy starts at the operating point"
    );

    // 1. Idle. Sampling is a pause, so this is also the assertion that
    //    repeated pause → sample → resume cycles cost nothing.
    std::thread::sleep(Duration::from_secs(5));
    for i in 0..2 * POLICY_WINDOW {
        let verdict = observe_once(&mut vm, &mut policy);
        eprintln!("MEASUREMENT idle sample {i}: {verdict:?}");
        assert!(
            !matches!(verdict, k7d::dilation::Verdict::Drop(_)),
            "sample {i} of an idle guest spent a rung: {verdict:?}"
        );
    }
    assert_eq!(policy.factor(), DROP_FROM);
    assert_eq!(policy.drops(), 0);

    // 2. Every vCPU spinning. The survey's busy phase drew 3.74 of 6; this
    //    draws all of them, which is the saturation the ladder is for.
    // Each burner records its own pid, because the obvious way to stop
    // them again — `pkill -f 'while true'` — matches the shell the agent
    // is running *that* command in and kills the exec instead.
    sh_ok(&mut agent, &format!("rm -f {BURNERS}; echo cleared"));
    for cpu in 0..NODE_VCPUS {
        sh_ok(
            &mut agent,
            &format!(
                "setsid nohup sh -c 'echo $$ >> {BURNERS}; while true; do :; done' \
                 </dev/null >/dev/null 2>&1 & echo burner-{cpu}"
            ),
        );
    }
    std::thread::sleep(Duration::from_secs(2));

    let mut applied = Vec::new();
    for i in 0..4 * POLICY_WINDOW {
        if let k7d::dilation::Verdict::Drop(factor) = observe_once(&mut vm, &mut policy) {
            eprintln!("MEASUREMENT sample {i}: saturated, dropping to x{factor}");
            vm.pause().expect("pause for the drop");
            vm.set_dilation_live(factor)
                .expect("the drop the policy asked for");
            vm.resume().expect("resume after the drop");
            applied.push(factor);
            assert_eq!(vm.dilation(), factor);
        }
    }
    assert!(
        !applied.is_empty(),
        "every vCPU was spinning and the policy never dropped a rung — the awake reading \
         is not reaching it"
    );
    assert_eq!(
        applied,
        k7d::dilation::LADDER[1..=applied.len()].to_vec(),
        "the drops must walk the ladder in order, one rung each"
    );
    assert!(
        applied.windows(2).all(|w| w[0] > w[1]),
        "the factor rose mid-episode: {applied:?}"
    );
    let landed = *applied.last().expect("at least one drop");
    assert_eq!(policy.factor(), landed);

    // 3. And it stays down. The burners are gone, the guest is idle, and
    //    the factor does not climb back — a rate that tracks host load
    //    makes every guest-time measurement in an episode uncomparable.
    sh_ok(
        &mut agent,
        &format!("kill $(cat {BURNERS}) 2>/dev/null; rm -f {BURNERS}; echo stopped"),
    );
    std::thread::sleep(Duration::from_secs(5));
    for _ in 0..2 * POLICY_WINDOW {
        let verdict = observe_once(&mut vm, &mut policy);
        assert!(
            !matches!(verdict, k7d::dilation::Verdict::Drop(f) if f > landed),
            "the policy tried to raise the factor once the guest went quiet: {verdict:?}"
        );
    }
    assert_eq!(policy.factor(), landed);
    assert_eq!(vm.dilation(), landed);
    assert_rate(&mut agent, "policy", landed, REMEASURE);

    check_no_splats(&mut agent, "policy");
    vm.shutdown();
}

/// Observations the policy under test decides on, and the wall time
/// between them. Both are the test's, not the library's: the library's
/// defaults are sized for a 6-vCPU cluster.
const POLICY_WINDOW: usize = 5;
const POLICY_CADENCE: Duration = Duration::from_secs(1);

/// Where the CPU burners record their pids, so they can be stopped by
/// pid rather than by a pattern that matches the stopping command too.
const BURNERS: &str = "/var/tmp/k7-burners";

/// One pause → sample → resume, fed to the policy.
fn observe_once(vm: &mut Vm, policy: &mut k7d::dilation::DilationPolicy) -> k7d::dilation::Verdict {
    vm.pause().expect("a VM pauses for a sample");
    let sample = vm
        .sample_time_state()
        .expect("a paused VM samples its time state");
    vm.resume().expect("a VM resumes after a sample");
    std::thread::sleep(POLICY_CADENCE);
    policy.observe_samples(std::slice::from_ref(&sample))
}

/// The cluster version: one factor for every member, switched under one
/// pause window, because a rate skew — unlike the offset skew a jump
/// risks — diverges without bound.
#[test]
fn test_dilation_live_set_on_a_three_node_lockstep_cluster() {
    let _ = env_logger::builder().is_test(true).try_init();
    require_patched_host();

    let mut cluster = bring_up_cluster_sized(
        UbuntuCni::Flannel,
        "dil8",
        None,
        NodeSize::DEFAULT.dilated(DROP_FROM),
    );
    let names = cluster.names();
    let whose = ["server", "agent-1", "agent-2"];

    {
        let mut server = connect_or_dump(&mut cluster.server, whose[0]);
        assert!(
            guest_nodes_ready(&mut server, &names),
            "the cluster must be Ready before its rate changes"
        );
        assert_rate(&mut server, whose[0], DROP_FROM, RATE_WINDOW);
    }

    let mut before = Vec::new();
    let mut agents = [
        connect_or_dump(&mut cluster.server, whose[0]),
        connect_or_dump(&mut cluster.agent1, whose[1]),
        connect_or_dump(&mut cluster.agent2, whose[2]),
    ];
    for (agent, who) in agents.iter_mut().zip(whose) {
        before.push((guest_clocks(agent, who), host_realtime_s(), Instant::now()));
    }
    drop(agents);

    let mut vms: Vec<&mut Vm> = vec![
        &mut cluster.server,
        &mut cluster.agent1,
        &mut cluster.agent2,
    ];
    let latency = k7d::vm::set_dilation_lockstep(&mut vms, DROP_TO)
        .expect("a paused cluster takes one factor across every member");
    drop(vms);
    eprintln!("MEASUREMENT 3-node pause → set x{DROP_TO} → resume: {latency:?}");
    for vm in [&cluster.server, &cluster.agent1, &cluster.agent2] {
        assert_eq!(vm.dilation(), DROP_TO);
    }

    let mut agents = [
        connect_or_dump(&mut cluster.server, whose[0]),
        connect_or_dump(&mut cluster.agent1, whose[1]),
        connect_or_dump(&mut cluster.agent2, whose[2]),
    ];
    for ((agent, who), (clocks, host, since)) in agents.iter_mut().zip(whose).zip(&before) {
        let across = Across {
            before: *clocks,
            after: guest_clocks(agent, who),
            wall: since.elapsed().as_secs_f64(),
            host_before: *host,
            host_after: host_realtime_s(),
        };
        across.assert_continuous(who, DROP_FROM);
        across.assert_keeps_its_lead(who);
    }
    for (agent, who) in agents.iter_mut().zip(whose) {
        assert_rate(agent, who, DROP_TO, REMEASURE);
    }
    let splats: u64 = agents.iter_mut().map(splat_count).sum();
    assert_eq!(
        splats, 0,
        "a member's kernel complained about the rate change"
    );
    drop(agents);

    // The cluster is the point: it has to still be a cluster afterwards.
    let mut server = connect_or_dump(&mut cluster.server, whose[0]);
    guest_settle(&mut server, "dil8");
    assert!(
        guest_nodes_ready(&mut server, &names),
        "a node went NotReady across the rate change"
    );
    assert_eq!(
        guest_event_count(&mut server, "LeaderElection"),
        0,
        "the rate change cost an etcd leader election"
    );
    drop(server);
}

/// The same live `SET` in the other direction. The adaptive policy's
/// kernel path already accepts a raise — this is the missing test, not
/// a missing ioctl.
const RAISE_FROM: u32 = 4;
const RAISE_TO: u32 = 8;

#[test]
fn test_dilation_live_raise_changes_slope_not_the_clock() {
    let _ = env_logger::builder().is_test(true).try_init();
    require_patched_host();

    let (mut vm, mut agent, _net, _disk) = boot_node("dil-raise", RAISE_FROM);
    check_clocksource(&mut agent, "raise");
    check_no_ntp_client(&mut agent, "raise");
    assert_eq!(vm.dilation(), RAISE_FROM);
    assert_rate(&mut agent, "raise", RAISE_FROM, RATE_WINDOW);

    let mut latency = Duration::ZERO;
    let across = across_change(&mut agent, "raise", || {
        let started = Instant::now();
        vm.pause().expect("the VM pauses for a factor change");
        vm.set_dilation_live(RAISE_TO)
            .expect("a paused VM takes a live raise");
        vm.resume().expect("the VM resumes after a factor change");
        latency = started.elapsed();
    });
    eprintln!("MEASUREMENT single-VM pause → set x{RAISE_TO} → resume: {latency:?}");
    assert_eq!(vm.dilation(), RAISE_TO);
    across.assert_continuous("raise", RAISE_FROM);
    across.assert_keeps_its_lead("raise");

    assert_rate(&mut agent, "raise", RAISE_TO, REMEASURE);

    let t0 = Instant::now();
    let slept = sh_ok(
        &mut agent,
        "s=$(date +%s.%N); sleep 8; date +%s.%N | awk -v s=$s '{printf \"%.3f\", $1-s}'",
    );
    let wall = t0.elapsed().as_secs_f64();
    let guest: f64 = slept.trim().parse().expect("guest sleep duration");
    eprintln!(
        "MEASUREMENT single-VM `sleep 8` after the raise: {guest:.3} s guest in \
         {wall:.3} s wall ({:.2}x)",
        guest / wall
    );
    assert!(
        guest >= 8.0,
        "the guest slept only {guest:.3} s of its own time"
    );
    assert!(
        wall < 8.0 / f64::from(RAISE_TO) * (1.0 + RATE_TOLERANCE) + 0.5,
        "`sleep 8` cost {wall:.3} s of wall time; at x{RAISE_TO} it should cost about 1 s"
    );

    check_no_splats(&mut agent, "raise");
    vm.shutdown();
}

#[test]
fn test_dilation_live_raise_on_a_three_node_lockstep_cluster() {
    let _ = env_logger::builder().is_test(true).try_init();
    require_patched_host();

    let mut cluster = bring_up_cluster_sized(
        UbuntuCni::Flannel,
        "dil9",
        None,
        NodeSize::DEFAULT.dilated(RAISE_FROM),
    );
    let names = cluster.names();
    let whose = ["server", "agent-1", "agent-2"];

    {
        let mut server = connect_or_dump(&mut cluster.server, whose[0]);
        assert!(
            guest_nodes_ready(&mut server, &names),
            "the cluster must be Ready before its rate changes"
        );
        assert_rate(&mut server, whose[0], RAISE_FROM, RATE_WINDOW);
    }

    let mut before = Vec::new();
    let mut agents = [
        connect_or_dump(&mut cluster.server, whose[0]),
        connect_or_dump(&mut cluster.agent1, whose[1]),
        connect_or_dump(&mut cluster.agent2, whose[2]),
    ];
    for (agent, who) in agents.iter_mut().zip(whose) {
        before.push((guest_clocks(agent, who), host_realtime_s(), Instant::now()));
    }
    drop(agents);

    let mut vms: Vec<&mut Vm> = vec![
        &mut cluster.server,
        &mut cluster.agent1,
        &mut cluster.agent2,
    ];
    let latency = k7d::vm::set_dilation_lockstep(&mut vms, RAISE_TO)
        .expect("a paused cluster takes one raise across every member");
    drop(vms);
    eprintln!("MEASUREMENT 3-node pause → set x{RAISE_TO} → resume: {latency:?}");
    for vm in [&cluster.server, &cluster.agent1, &cluster.agent2] {
        assert_eq!(vm.dilation(), RAISE_TO);
    }

    let mut agents = [
        connect_or_dump(&mut cluster.server, whose[0]),
        connect_or_dump(&mut cluster.agent1, whose[1]),
        connect_or_dump(&mut cluster.agent2, whose[2]),
    ];
    for ((agent, who), (clocks, host, since)) in agents.iter_mut().zip(whose).zip(&before) {
        let across = Across {
            before: *clocks,
            after: guest_clocks(agent, who),
            wall: since.elapsed().as_secs_f64(),
            host_before: *host,
            host_after: host_realtime_s(),
        };
        across.assert_continuous(who, RAISE_FROM);
        across.assert_keeps_its_lead(who);
    }
    for (agent, who) in agents.iter_mut().zip(whose) {
        assert_rate(agent, who, RAISE_TO, REMEASURE);
    }
    let splats: u64 = agents.iter_mut().map(splat_count).sum();
    assert_eq!(
        splats, 0,
        "a member's kernel complained about the rate change"
    );
    drop(agents);

    let mut server = connect_or_dump(&mut cluster.server, whose[0]);
    guest_settle(&mut server, "dil9");
    assert!(
        guest_nodes_ready(&mut server, &names),
        "a node went NotReady across the rate change"
    );
    assert_eq!(
        guest_event_count(&mut server, "LeaderElection"),
        0,
        "the rate change cost an etcd leader election"
    );
    drop(server);
}

/// `TrackingPolicy` on a live VM: idle stays at 8, every vCPU spinning
/// walks down, idle walks back up. The deadband is the unit tests';
/// this is the assertion that the signal reaches the type.
#[test]
fn test_dilation_policy_tracks_load_both_ways() {
    let _ = env_logger::builder().is_test(true).try_init();
    require_patched_host();

    let (mut vm, mut agent, _net, _disk) = boot_node("dil-trk", DROP_FROM);
    check_clocksource(&mut agent, "track");
    check_no_ntp_client(&mut agent, "track");

    let mut policy = k7d::dilation::TrackingPolicy::new(
        POLICY_WINDOW,
        k7d::dilation::SATURATED,
        k7d::dilation::QUIET,
    );
    assert_eq!(policy.factor(), DROP_FROM);

    std::thread::sleep(Duration::from_secs(5));
    for i in 0..2 * POLICY_WINDOW {
        let verdict = observe_track(&mut vm, &mut policy);
        eprintln!("MEASUREMENT idle sample {i}: {verdict:?}");
        assert!(
            !matches!(verdict, k7d::dilation::Verdict::Drop(_)),
            "sample {i} of an idle guest spent a rung: {verdict:?}"
        );
    }
    assert_eq!(policy.factor(), DROP_FROM);
    assert_eq!(policy.drops(), 0);

    sh_ok(&mut agent, &format!("rm -f {BURNERS}; echo cleared"));
    for cpu in 0..NODE_VCPUS {
        sh_ok(
            &mut agent,
            &format!(
                "setsid nohup sh -c 'echo $$ >> {BURNERS}; while true; do :; done' \
                 </dev/null >/dev/null 2>&1 & echo burner-{cpu}"
            ),
        );
    }
    std::thread::sleep(Duration::from_secs(2));

    let mut dropped = Vec::new();
    for i in 0..4 * POLICY_WINDOW {
        if let k7d::dilation::Verdict::Drop(factor) = observe_track(&mut vm, &mut policy) {
            eprintln!("MEASUREMENT sample {i}: saturated, dropping to x{factor}");
            vm.pause().expect("pause for the drop");
            vm.set_dilation_live(factor)
                .expect("the drop the policy asked for");
            vm.resume().expect("resume after the drop");
            dropped.push(factor);
        }
    }
    assert!(
        !dropped.is_empty(),
        "every vCPU was spinning and the policy never dropped a rung"
    );
    assert_eq!(
        dropped,
        k7d::dilation::LADDER[1..=dropped.len()].to_vec(),
        "the drops must walk the ladder in order, one rung each"
    );
    let landed = *dropped.last().expect("at least one drop");

    sh_ok(
        &mut agent,
        &format!("kill $(cat {BURNERS}) 2>/dev/null; rm -f {BURNERS}; echo stopped"),
    );
    std::thread::sleep(Duration::from_secs(5));

    let mut raised = Vec::new();
    for i in 0..4 * POLICY_WINDOW {
        if let k7d::dilation::Verdict::Raise(factor) = observe_track(&mut vm, &mut policy) {
            eprintln!("MEASUREMENT sample {i}: quiet, raising to x{factor}");
            vm.pause().expect("pause for the raise");
            vm.set_dilation_live(factor)
                .expect("the raise the policy asked for");
            vm.resume().expect("resume after the raise");
            raised.push(factor);
        }
    }
    assert!(
        !raised.is_empty(),
        "the guest went idle and TrackingPolicy never raised — the deadband ate the signal \
         or the burners are still running"
    );
    assert!(
        raised.windows(2).all(|w| w[0] < w[1]),
        "a raise walked the ladder the wrong way: {raised:?}"
    );
    assert!(
        *raised.last().expect("raised") > landed,
        "the last raise x{} did not climb above the drop x{landed}",
        raised.last().expect("raised")
    );
    assert_eq!(policy.factor(), *raised.last().expect("raised"));
    assert_eq!(vm.dilation(), policy.factor());
    assert_rate(&mut agent, "track", policy.factor(), REMEASURE);

    check_no_splats(&mut agent, "track");
    vm.shutdown();
}

fn observe_track(
    vm: &mut Vm,
    policy: &mut k7d::dilation::TrackingPolicy,
) -> k7d::dilation::Verdict {
    vm.pause().expect("a VM pauses for a sample");
    let sample = vm
        .sample_time_state()
        .expect("a paused VM samples its time state");
    vm.resume().expect("a VM resumes after a sample");
    std::thread::sleep(POLICY_CADENCE);
    policy.observe_samples(std::slice::from_ref(&sample))
}

/// The four-policy episode: same 240 s of guest time, load
/// script idle / busy / idle in 80 s *guest* windows, three runs each
/// from a fresh cluster. Shape, not values.
///
/// Override with `K7_DILATION_POLICIES=track` (comma-separated) to rerun
/// one arm; the default is all four.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PolicyArm {
    Fixed8,
    Fixed4,
    Down,
    Track,
}

impl PolicyArm {
    fn name(self) -> &'static str {
        match self {
            Self::Fixed8 => "fixed8",
            Self::Fixed4 => "fixed4",
            Self::Down => "down",
            Self::Track => "track",
        }
    }

    fn start(self) -> u32 {
        match self {
            Self::Fixed4 => 4,
            Self::Fixed8 | Self::Down | Self::Track => 8,
        }
    }
}

const POLICY_ARMS: [PolicyArm; 4] = [
    PolicyArm::Fixed8,
    PolicyArm::Fixed4,
    PolicyArm::Down,
    PolicyArm::Track,
];

fn policy_arms() -> Vec<PolicyArm> {
    match std::env::var("K7_DILATION_POLICIES") {
        Ok(s) => s
            .split(',')
            .map(|p| match p.trim() {
                "fixed8" => PolicyArm::Fixed8,
                "fixed4" => PolicyArm::Fixed4,
                "down" => PolicyArm::Down,
                "track" => PolicyArm::Track,
                other => panic!(
                    "K7_DILATION_POLICIES={s:?}: unknown arm {other:?} \
                     (want fixed8,fixed4,down,track)"
                ),
            })
            .collect(),
        Err(_) => POLICY_ARMS.to_vec(),
    }
}

const PHASE_GUEST: Duration = Duration::from_secs(80);
const EPISODE_SAMPLE: Duration = Duration::from_secs(1);

#[derive(Clone, Copy)]
enum LoadPhase {
    Idle,
    Busy,
}

struct Sleep8 {
    guest: f64,
    wall: f64,
}

struct PolicyRun {
    fidelity: Fidelity,
    trajectory: Vec<u32>,
    sets: u32,
    drops: u32,
    raises: u32,
    straddles: u32,
    sleep_idle: [Sleep8; 2],
    factor_after_busy: u32,
    factor_end: u32,
}

enum LivePolicy {
    Fixed,
    Down(k7d::dilation::DilationPolicy),
    Track(k7d::dilation::TrackingPolicy),
}

impl LivePolicy {
    fn new(arm: PolicyArm) -> Self {
        match arm {
            PolicyArm::Fixed8 | PolicyArm::Fixed4 => Self::Fixed,
            PolicyArm::Down => Self::Down(k7d::dilation::DilationPolicy::default()),
            PolicyArm::Track => Self::Track(k7d::dilation::TrackingPolicy::default()),
        }
    }

    fn observe(&mut self, samples: &[TimeSample]) -> k7d::dilation::Verdict {
        match self {
            Self::Fixed => k7d::dilation::Verdict::Headroom,
            Self::Down(p) => p.observe_samples(samples),
            Self::Track(p) => p.observe_samples(samples),
        }
    }

    fn factor(&self, start: u32) -> u32 {
        match self {
            Self::Fixed => start,
            Self::Down(p) => p.factor(),
            Self::Track(p) => p.factor(),
        }
    }
}

fn guest_sleep8(agent: &mut AgentClient, whose: &str) -> Sleep8 {
    let t0 = Instant::now();
    let slept = sh_ok(
        agent,
        "s=$(date +%s.%N); sleep 8; date +%s.%N | awk -v s=$s '{printf \"%.3f\", $1-s}'",
    );
    let wall = t0.elapsed().as_secs_f64();
    let guest: f64 = slept.trim().parse().expect("guest sleep duration");
    eprintln!(
        "MEASUREMENT {whose} `sleep 8`: {guest:.3} s guest in {wall:.3} s wall \
         ({:.2}x)",
        guest / wall
    );
    assert!(
        guest >= 8.0,
        "{whose}: the guest slept only {guest:.3} s of its own time"
    );
    Sleep8 { guest, wall }
}

fn start_node_burners(agent: &mut AgentClient, whose: &str) {
    sh_ok(agent, &format!("rm -f {BURNERS}; echo cleared"));
    for cpu in 0..NODE_VCPUS {
        sh_ok(
            agent,
            &format!(
                "setsid nohup sh -c 'echo $$ >> {BURNERS}; while true; do :; done' \
                 </dev/null >/dev/null 2>&1 & echo {whose}-burner-{cpu}"
            ),
        );
    }
}

fn stop_node_burners(agent: &mut AgentClient) {
    sh_ok(
        agent,
        &format!("kill $(cat {BURNERS}) 2>/dev/null; rm -f {BURNERS}; echo stopped"),
    );
}

fn run_policy_episode(cluster: &mut UbuntuCluster, arm: PolicyArm, tag: &str) -> PolicyRun {
    let names = cluster.names();
    let start = arm.start();
    let mut policy = LivePolicy::new(arm);
    let mut server = connect_or_dump(&mut cluster.server, "server");
    guest_settle(&mut server, tag);

    guest_apply_yaml(
        &mut server,
        "dil-probe",
        &format!(
            r"apiVersion: apps/v1
kind: Deployment
metadata:
  name: dil-probe
spec:
  replicas: 6
  selector:
    matchLabels: {{app: dil-probe}}
  template:
    metadata:
      labels: {{app: dil-probe}}
    spec:
      containers:
      - name: p
        image: {BUSYBOX}
        imagePullPolicy: IfNotPresent
        command: ['sh', '-c', 'sleep 3600']
        livenessProbe:
          exec:
            command: ['true']
          periodSeconds: 10
"
        ),
    );
    guest_wait_rollout(&mut server, "dil-probe", tag);

    let probes_before = guest_event_count(&mut server, "Unhealthy");
    let restarts_before = guest_total_restarts(&mut server);
    let elections_before = guest_event_count(&mut server, "LeaderElection");
    let clock_before = guest_clocks(&mut server, "server");
    drop(server);

    let t0 = Instant::now();
    let mut trajectory = vec![start];
    let mut sets = 0_u32;
    let mut drops = 0_u32;
    let mut raises = 0_u32;
    let mut straddles = 0_u32;
    let mut window_phase: Option<LoadPhase> = None;
    let mut not_ready_lapses = 0_u64;
    let mut awake_sum = 0_u64;
    let mut n_cpus_last = 0_usize;
    let mut awake_samples = 0_usize;
    let mut sleep_idle = [
        Sleep8 {
            guest: 0.0,
            wall: 0.0,
        },
        Sleep8 {
            guest: 0.0,
            wall: 0.0,
        },
    ];
    let mut factor_after_busy = start;

    for (phase_i, phase) in [LoadPhase::Idle, LoadPhase::Busy, LoadPhase::Idle]
        .into_iter()
        .enumerate()
    {
        let mut server = connect_or_dump(&mut cluster.server, "server");
        let deadline = guest_clocks(&mut server, "server")[1] + PHASE_GUEST.as_secs_f64();

        match phase {
            LoadPhase::Idle => {
                if phase_i == 2 {
                    drop(server);
                    let mut agents = [
                        connect_or_dump(&mut cluster.server, "server"),
                        connect_or_dump(&mut cluster.agent1, "agent-1"),
                        connect_or_dump(&mut cluster.agent2, "agent-2"),
                    ];
                    for agent in &mut agents {
                        stop_node_burners(agent);
                    }
                    std::thread::sleep(Duration::from_secs(2));
                    sleep_idle[1] = guest_sleep8(&mut agents[0], &format!("{tag} idle2"));
                    drop(agents);
                } else {
                    sleep_idle[0] = guest_sleep8(&mut server, &format!("{tag} idle1"));
                    drop(server);
                }
            }
            LoadPhase::Busy => {
                drop(server);
                let mut agents = [
                    connect_or_dump(&mut cluster.server, "server"),
                    connect_or_dump(&mut cluster.agent1, "agent-1"),
                    connect_or_dump(&mut cluster.agent2, "agent-2"),
                ];
                for (agent, who) in agents.iter_mut().zip(["server", "agent-1", "agent-2"]) {
                    start_node_burners(agent, who);
                }
                drop(agents);
                std::thread::sleep(Duration::from_secs(2));
            }
        }

        let mut polls = 0_u32;
        loop {
            let mut server = connect_or_dump(&mut cluster.server, "server");
            let now = guest_clocks(&mut server, "server");
            if now[1] >= deadline {
                drop(server);
                break;
            }
            polls += 1;
            if polls % READY_EVERY == 0 && !guest_nodes_ready(&mut server, &names) {
                not_ready_lapses += 1;
            }
            drop(server);
            assert!(
                t0.elapsed() < Duration::from_secs(1800),
                "{tag}: the guest never reached the end of phase {phase_i}"
            );

            let mut vms = [
                &mut cluster.server,
                &mut cluster.agent1,
                &mut cluster.agent2,
            ];
            let (samples, _) = sample_cluster(&mut vms);
            let (awake, n_cpus) = awake_from(&samples);
            awake_sum += awake as u64;
            n_cpus_last = n_cpus;
            awake_samples += 1;

            if matches!(policy, LivePolicy::Fixed) {
                std::thread::sleep(EPISODE_SAMPLE);
                continue;
            }

            let verdict = policy.observe(&samples);
            match verdict {
                k7d::dilation::Verdict::Warming => {
                    if window_phase.is_none() {
                        window_phase = Some(phase);
                    }
                }
                other => {
                    if let Some(started) = window_phase {
                        if !matches!(
                            (started, phase),
                            (LoadPhase::Idle, LoadPhase::Idle) | (LoadPhase::Busy, LoadPhase::Busy)
                        ) {
                            straddles += 1;
                        }
                    }
                    window_phase = None;
                    match other {
                        k7d::dilation::Verdict::Drop(factor) => {
                            apply_cluster_factor(cluster, factor);
                            sets += 1;
                            drops += 1;
                            trajectory.push(factor);
                        }
                        k7d::dilation::Verdict::Raise(factor) => {
                            apply_cluster_factor(cluster, factor);
                            sets += 1;
                            raises += 1;
                            trajectory.push(factor);
                        }
                        _ => {
                            let f = policy.factor(start);
                            if trajectory.last().copied() != Some(f) {
                                trajectory.push(f);
                            }
                        }
                    }
                }
            }
            std::thread::sleep(EPISODE_SAMPLE);
        }

        if matches!(phase, LoadPhase::Busy) {
            factor_after_busy = policy.factor(start);
        }
    }

    let wall = t0.elapsed();
    let mut server = connect_or_dump(&mut cluster.server, "server");
    let clock_after = guest_clocks(&mut server, "server");
    let fsync_ms = guest_fsync_ms(&mut server, "server");
    let probe_failures = guest_event_count(&mut server, "Unhealthy").saturating_sub(probes_before);
    let restarts = guest_total_restarts(&mut server).saturating_sub(restarts_before);
    let leader_elections =
        guest_event_count(&mut server, "LeaderElection").saturating_sub(elections_before);
    let _ = guest_kubectl(
        &mut server,
        &["delete", "deployment", "dil-probe", "--ignore-not-found"],
    );
    drop(server);

    let mut agents = [
        connect_or_dump(&mut cluster.server, "server"),
        connect_or_dump(&mut cluster.agent1, "agent-1"),
        connect_or_dump(&mut cluster.agent2, "agent-2"),
    ];
    let splats = agents.iter_mut().map(splat_count).sum::<u64>();
    drop(agents);

    let mean_awake = if awake_samples == 0 {
        0.0
    } else {
        awake_sum as f64 / awake_samples as f64
    };
    let factor_end = policy.factor(start);

    PolicyRun {
        fidelity: Fidelity {
            wall,
            guest: Duration::from_secs_f64(clock_after[1] - clock_before[1]),
            probe_failures,
            restarts,
            leader_elections,
            not_ready_lapses,
            splats,
            churn_rounds: 0,
            fsync_ms,
            rtt_ms: 0.0,
            mean_awake,
            n_cpus: n_cpus_last as f64,
            awake_samples,
        },
        trajectory,
        sets,
        drops,
        raises,
        straddles,
        sleep_idle,
        factor_after_busy,
        factor_end,
    }
}

fn apply_cluster_factor(cluster: &mut UbuntuCluster, factor: u32) {
    let mut vms: Vec<&mut Vm> = vec![
        &mut cluster.server,
        &mut cluster.agent1,
        &mut cluster.agent2,
    ];
    k7d::vm::set_dilation_lockstep(&mut vms, factor)
        .unwrap_or_else(|e| panic!("lockstep SET x{factor}: {e}"));
}

#[test]
fn test_dilation_four_policy_idle_busy_idle() {
    let _ = env_logger::builder().is_test(true).try_init();
    require_patched_host();

    let mut by_arm: Vec<(PolicyArm, Vec<PolicyRun>)> = Vec::new();
    for arm in policy_arms() {
        let mut runs = Vec::new();
        for i in 0..RUNS {
            let tag = format!("{}r{i}", arm.name());
            let mut cluster = bring_up_cluster_sized(
                UbuntuCni::Flannel,
                &tag,
                None,
                NodeSize::DEFAULT.dilated(arm.start()),
            );
            let run = run_policy_episode(&mut cluster, arm, &tag);
            eprintln!(
                "MEASUREMENT {} run {i}: wall {:.1}s guest {:.1}s ({:.2}x) \
                 probes {} restarts {} elections {} notready {} splats {} \
                 fsync {:.3} sets {} drops {} raises {} straddles {} \
                 traj {:?} after_busy x{} end x{} \
                 sleep8 idle1 {:.3}/{:.3}s idle2 {:.3}/{:.3}s (guest/wall)",
                arm.name(),
                run.fidelity.wall.as_secs_f64(),
                run.fidelity.guest.as_secs_f64(),
                run.fidelity.observed(),
                run.fidelity.probe_failures,
                run.fidelity.restarts,
                run.fidelity.leader_elections,
                run.fidelity.not_ready_lapses,
                run.fidelity.splats,
                run.fidelity.fsync_ms,
                run.sets,
                run.drops,
                run.raises,
                run.straddles,
                run.trajectory,
                run.factor_after_busy,
                run.factor_end,
                run.sleep_idle[0].guest,
                run.sleep_idle[0].wall,
                run.sleep_idle[1].guest,
                run.sleep_idle[1].wall,
            );
            drop(cluster);
            runs.push(run);
        }
        by_arm.push((arm, runs));
    }

    eprintln!(
        "\n| arm | wall s | guest s | obs. | probes | rest. | elect. | NotR. | splat | \
         fsync ms | sets | drops | raises | straddles | after busy | end | sleep8 idle1 | \
         sleep8 idle2 |\n\
         |---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"
    );
    for (arm, runs) in &by_arm {
        let walls: Vec<f64> = runs.iter().map(|r| r.fidelity.wall.as_secs_f64()).collect();
        let guests: Vec<f64> = runs
            .iter()
            .map(|r| r.fidelity.guest.as_secs_f64())
            .collect();
        let obs: Vec<f64> = runs.iter().map(|r| r.fidelity.observed()).collect();
        let probes: Vec<u64> = runs.iter().map(|r| r.fidelity.probe_failures).collect();
        let restarts: Vec<u64> = runs.iter().map(|r| r.fidelity.restarts).collect();
        let elections: Vec<u64> = runs.iter().map(|r| r.fidelity.leader_elections).collect();
        let lapses: Vec<u64> = runs.iter().map(|r| r.fidelity.not_ready_lapses).collect();
        let splats: Vec<u64> = runs.iter().map(|r| r.fidelity.splats).collect();
        let fsync: Vec<f64> = runs.iter().map(|r| r.fidelity.fsync_ms).collect();
        let sets: Vec<u64> = runs.iter().map(|r| u64::from(r.sets)).collect();
        let drops: Vec<u64> = runs.iter().map(|r| u64::from(r.drops)).collect();
        let raises: Vec<u64> = runs.iter().map(|r| u64::from(r.raises)).collect();
        let straddles: Vec<u64> = runs.iter().map(|r| u64::from(r.straddles)).collect();
        let after: Vec<u64> = runs
            .iter()
            .map(|r| u64::from(r.factor_after_busy))
            .collect();
        let end: Vec<u64> = runs.iter().map(|r| u64::from(r.factor_end)).collect();
        let s1: Vec<f64> = runs.iter().map(|r| r.sleep_idle[0].wall).collect();
        let s2: Vec<f64> = runs.iter().map(|r| r.sleep_idle[1].wall).collect();
        eprintln!(
            "| {} | {:.1} | {:.1} | {:.2}× | {} | {} | {} | {} | {} | {:.2} | {} | {} | {} | \
             {} | x{} | x{} | {:.2}s | {:.2}s |",
            arm.name(),
            median_f64(&walls),
            median_f64(&guests),
            median_f64(&obs),
            median_u64(&probes),
            median_u64(&restarts),
            median_u64(&elections),
            median_u64(&lapses),
            median_u64(&splats),
            median_f64(&fsync),
            median_u64(&sets),
            median_u64(&drops),
            median_u64(&raises),
            median_u64(&straddles),
            median_u64(&after),
            median_u64(&end),
            median_f64(&s1),
            median_f64(&s2),
        );
    }

    for (arm, runs) in &by_arm {
        for (i, run) in runs.iter().enumerate() {
            match arm {
                PolicyArm::Fixed8 | PolicyArm::Fixed4 => {
                    assert_eq!(
                        run.sets,
                        0,
                        "{} run {i} issued a live SET: {:?}",
                        arm.name(),
                        run.trajectory
                    );
                    assert_eq!(
                        run.factor_end,
                        arm.start(),
                        "{} run {i} ended at x{}, not x{}",
                        arm.name(),
                        run.factor_end,
                        arm.start()
                    );
                }
                PolicyArm::Down => {
                    assert!(
                        run.drops >= 1,
                        "down run {i} never dropped during busy: traj {:?}",
                        run.trajectory
                    );
                    assert_eq!(
                        run.raises, 0,
                        "down run {i} raised — DilationPolicy is monotone: {:?}",
                        run.trajectory
                    );
                    assert!(
                        run.factor_end <= run.factor_after_busy,
                        "down run {i} climbed after busy (x{} → x{})",
                        run.factor_after_busy,
                        run.factor_end
                    );
                }
                PolicyArm::Track => {
                    assert!(
                        run.drops >= 1,
                        "track run {i} never dropped during busy: traj {:?}",
                        run.trajectory
                    );
                    assert!(
                        run.raises >= 1,
                        "track run {i} never raised after busy: traj {:?}",
                        run.trajectory
                    );
                    assert!(
                        run.factor_end > run.factor_after_busy,
                        "track run {i} did not climb after busy (x{} → x{})",
                        run.factor_after_busy,
                        run.factor_end
                    );
                }
            }
        }
    }
}

/// Rate window for the fork tests. Shorter than [`RATE_WINDOW`]: three
/// or more of them run per test, and the mechanism was already proven
/// at 20 s above — here the question is only whether it survived.
const FORK_RATE_WINDOW: Duration = Duration::from_secs(10);

/// How far a fork's clock may sit from its source's at the same wall
/// instant, in guest seconds. The reads are two agent round trips
/// apart, each a few ms of wall and so a few × N ms of guest time; a
/// full second is an order of magnitude above that, and an order of
/// magnitude below the `(N-1) × at_rest` a restore that forgot to
/// scale its rest by N would land at for a multi-second rest.
const LOCKSTEP_SLACK: f64 = 1.0;

/// Wall time the cold snapshot sits on disk before it is restored.
/// Long enough that "rest counts N×" and "rest counts 1×" are
/// `(N-1) × REST` = 21 s of guest time apart, far outside every
/// tolerance here.
const REST: Duration = Duration::from_secs(3);

fn assert_rates(rates: [f64; 3], whose: &str, n: u32) {
    let names = ["CLOCK_REALTIME", "CLOCK_MONOTONIC", "CLOCK_BOOTTIME"];
    for (rate, name) in rates.iter().zip(names) {
        eprintln!("MEASUREMENT {whose} {name} guest-per-wall {rate:.3}x (asked {n}x)");
        assert!(
            (rate - f64::from(n)).abs() <= f64::from(n) * RATE_TOLERANCE,
            "{whose}: {name} advanced {rate:.3}x wall time, not {n}x"
        );
    }
}

/// A warm fork of a dilated VM runs at the source's factor and lands
/// on the source's clock.
///
/// Two restores are exercised: `prepare_fork_source` swaps the source
/// for a copy restored from its own keyframe (the cold path,
/// `restore_vm_preserving_cid`), and the fork itself is the warm path
/// (`restore_vm_from_state`). Both must carry the factor; the source
/// losing it at prepare would be the quieter failure.
#[test]
fn test_dilation_fork_warm_child_runs_at_source_rate() {
    let _ = env_logger::builder().is_test(true).try_init();
    require_patched_host();

    let (mut vm, mut agent, net, _disk) = boot_node("dil-fsrc", RATE_N);
    check_clocksource(&mut agent, "source");
    check_no_ntp_client(&mut agent, "source");
    drop(agent);

    vm.prepare_fork_source()
        .expect("a dilated VM prepares as a fork source");
    assert_eq!(
        vm.dilation(),
        RATE_N,
        "the source came back from its prepare-swap restore undilated"
    );
    let mut agent = connect_or_dump(&mut vm, "source");
    assert_rates(
        measured_rates(&mut agent, "source", FORK_RATE_WINDOW),
        "source after prepare",
        RATE_N,
    );

    let src_before = guest_clocks(&mut agent, "source");
    let t_fork = Instant::now();
    let mut sources: Vec<(&mut Vm, u32)> = vec![(&mut vm, 0)];
    let (fork_net, mut forks) = k7d::fork::fork_cluster_warm(
        &net,
        &mut sources,
        "dil-fchild",
        &[None],
        &[None],
        &["dil-fork-0"],
    )
    .expect("warm fork of a dilated VM");
    let fork_wall = t_fork.elapsed();
    let mut child = forks.pop().expect("one fork");
    assert_eq!(child.dilation(), RATE_N, "the fork lost its dilation");
    child.start().expect("the fork starts");
    let mut child_agent = connect_or_dump(&mut child, "child");
    let child_first = guest_clocks(&mut child_agent, "child");
    let src_after = guest_clocks(&mut agent, "source");
    eprintln!(
        "MEASUREMENT warm fork of a x{RATE_N} VM in {fork_wall:?}; child clock at first \
         read sits {:+.3} s of guest time from the source's next read",
        child_first[0] - src_after[0]
    );
    for (i, name) in ["CLOCK_REALTIME", "CLOCK_MONOTONIC", "CLOCK_BOOTTIME"]
        .iter()
        .enumerate()
    {
        assert!(
            child_first[i] >= src_before[i],
            "child {name} {:.3} is behind the source's pre-fork {:.3}: the fork's clock went \
             backwards",
            child_first[i],
            src_before[i]
        );
        assert!(
            child_first[i] <= src_after[i] + LOCKSTEP_SLACK,
            "child {name} {:.3} is ahead of the source's later read {:.3}",
            child_first[i],
            src_after[i]
        );
        assert!(
            child_first[i]
                >= src_after[i] - LOCKSTEP_SLACK - f64::from(RATE_N) * fork_wall.as_secs_f64(),
            "child {name} {:.3} lags the source {:.3} by more than the fork itself took: the \
             rest was not handed back in guest time",
            child_first[i],
            src_after[i]
        );
    }

    assert_rates(
        measured_rates(&mut child_agent, "child", FORK_RATE_WINDOW),
        "child",
        RATE_N,
    );
    check_no_splats(&mut child_agent, "child");
    check_no_splats(&mut agent, "source");
    drop((child_agent, agent));
    child.shutdown();
    drop(child);
    drop(fork_net);
    vm.shutdown();
}

/// A cold snapshot records the factor, a restore applies it, and the
/// time the snapshot spent on disk is handed back in guest
/// time — `N × wall` — so the restored clock reads what the source's
/// would have had it never been snapshotted (a pause of the same wall
/// duration does exactly that).
#[test]
fn test_dilation_fork_cold_snapshot_restore_rests_in_guest_time() {
    let _ = env_logger::builder().is_test(true).try_init();
    require_patched_host();

    let (mut vm, mut agent, _net, _disk) = boot_node("dil-csrc", RATE_N);
    check_clocksource(&mut agent, "source");
    let before = guest_clocks(&mut agent, "source");
    let t_before = Instant::now();
    drop(agent);

    // Pause, snapshot, and shut the source down without resuming it:
    // the cold restore reopens the same root disk, and a source still
    // writing to it would leave the restored guest on a disk newer than
    // its memory.
    let dir = tempfile::tempdir().expect("tempdir");
    vm.pause().expect("pause the source");
    k7d::snapshot::snapshot_vm(&vm, dir.path()).expect("snapshot a dilated VM");
    vm.shutdown();
    drop(vm);
    let meta: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join("metadata.json")).expect("metadata.json"),
    )
    .expect("metadata.json parses");
    assert_eq!(
        meta["dilation"],
        serde_json::json!(RATE_N),
        "metadata.json does not record the factor: {meta}"
    );

    std::thread::sleep(REST);

    let mut restored = Vm::restore(dir.path()).expect("restore a dilated snapshot");
    assert_eq!(
        restored.dilation(),
        RATE_N,
        "the restored VM lost its dilation"
    );
    restored.start().expect("the restored VM starts");
    let mut agent = connect_or_dump(&mut restored, "restored");
    let after = guest_clocks(&mut agent, "restored");
    let wall = t_before.elapsed().as_secs_f64();
    for (i, name) in ["CLOCK_REALTIME", "CLOCK_MONOTONIC", "CLOCK_BOOTTIME"]
        .iter()
        .enumerate()
    {
        let rate = (after[i] - before[i]) / wall;
        eprintln!(
            "MEASUREMENT {name} across snapshot + {REST:?} rest + restore: \
             {:.3} s guest over {wall:.3} s wall = {rate:.3}x",
            after[i] - before[i]
        );
        assert!(
            (rate - f64::from(RATE_N)).abs() <= f64::from(RATE_N) * RATE_TOLERANCE,
            "{name} advanced {rate:.3}x across the rest, not {RATE_N}x — the time on disk was \
             not handed back in guest time"
        );
    }
    assert_rates(
        measured_rates(&mut agent, "restored", FORK_RATE_WINDOW),
        "restored",
        RATE_N,
    );
    check_no_splats(&mut agent, "restored");
    drop(agent);
    restored.shutdown();
}

/// The shape the gym uses: a 3-node k3s cluster at N=8
/// is warm-forked whole, and the child cluster is Ready, dilated, and
/// quiet, while the source is undisturbed.
#[test]
fn test_dilation_fork_cluster_warm_child_is_ready_and_dilated() {
    let _ = env_logger::builder().is_test(true).try_init();
    require_patched_host();

    let mut cluster = bring_up_cluster_sized(
        UbuntuCni::Flannel,
        "dil-cf",
        None,
        NodeSize::DEFAULT.dilated(RATE_N),
    );
    let names = cluster.names();
    for (vm, whose) in [
        (&mut cluster.server, "server"),
        (&mut cluster.agent1, "agent-1"),
        (&mut cluster.agent2, "agent-2"),
    ] {
        vm.prepare_fork_source()
            .unwrap_or_else(|e| panic!("prepare {whose}: {e}"));
        assert_eq!(
            vm.dilation(),
            RATE_N,
            "{whose} lost its dilation at prepare"
        );
    }

    let mut sources: Vec<(&mut Vm, u32)> = vec![
        (&mut cluster.server, 0),
        (&mut cluster.agent1, 1),
        (&mut cluster.agent2, 2),
    ];
    let t_fork = Instant::now();
    let (fork_net, mut forks) = k7d::fork::fork_cluster_warm(
        &cluster.net,
        &mut sources,
        "dil-cfc",
        &[None, None, None],
        &[None, None, None],
        &["dil-k3s-0", "dil-k3s-1", "dil-k3s-2"],
    )
    .expect("warm fork of a dilated k3s cluster");
    eprintln!(
        "MEASUREMENT 3-node k3s cluster warm fork at x{RATE_N}: {:?}",
        t_fork.elapsed()
    );
    assert_eq!(forks.len(), 3);
    for (i, child) in forks.iter_mut().enumerate() {
        assert_eq!(child.dilation(), RATE_N, "child-{i} lost its dilation");
        child
            .start()
            .unwrap_or_else(|e| panic!("child-{i} start: {e}"));
    }

    let mut child_server = connect_or_dump(&mut forks[0], "child server");
    wait_nodes_ready_via_guest(&mut child_server, &names, CONVERGE * 2);
    assert_rates(
        measured_rates(&mut child_server, "child server", FORK_RATE_WINDOW),
        "child server",
        RATE_N,
    );
    drop(child_server);
    for (i, child) in forks.iter_mut().enumerate() {
        let mut ag = connect_or_dump(child, &format!("child-{i}"));
        check_no_splats(&mut ag, &format!("child-{i}"));
    }

    let mut server = connect_or_dump(&mut cluster.server, "source server");
    assert!(
        guest_nodes_ready(&mut server, &names),
        "the source cluster is no longer Ready after being forked"
    );
    check_no_splats(&mut server, "source server");
    drop(server);

    for child in &mut forks {
        child.shutdown();
    }
    drop(forks);
    drop(fork_net);
}

fn assert_lockstep(
    child_first: [f64; 3],
    src_before: [f64; 3],
    src_after: [f64; 3],
    source_n: u32,
    fork_wall: Duration,
) {
    for (i, name) in ["CLOCK_REALTIME", "CLOCK_MONOTONIC", "CLOCK_BOOTTIME"]
        .iter()
        .enumerate()
    {
        assert!(
            child_first[i] >= src_before[i],
            "child {name} {:.3} is behind the source's pre-fork {:.3}: the fork's clock went \
             backwards",
            child_first[i],
            src_before[i]
        );
        assert!(
            child_first[i] <= src_after[i] + LOCKSTEP_SLACK,
            "child {name} {:.3} is ahead of the source's later read {:.3}",
            child_first[i],
            src_after[i]
        );
        assert!(
            child_first[i]
                >= src_after[i] - LOCKSTEP_SLACK - f64::from(source_n) * fork_wall.as_secs_f64(),
            "child {name} {:.3} lags the source {:.3} by more than the fork itself took: the \
             rest was not handed back in the *source's* guest time",
            child_first[i],
            src_after[i]
        );
    }
}

/// A ×8 source warm-forks a ×1 child that lands on the source's clock,
/// then advances at 1× while the source stays at 8×.
#[test]
fn test_dilation_fork_child_at_one_from_source_at_eight() {
    let _ = env_logger::builder().is_test(true).try_init();
    require_patched_host();

    let (mut vm, mut agent, net, _disk) = boot_node("dil-8to1", RATE_N);
    check_clocksource(&mut agent, "source");
    check_no_ntp_client(&mut agent, "source");
    drop(agent);

    vm.prepare_fork_source()
        .expect("a dilated VM prepares as a fork source");
    assert_eq!(vm.dilation(), RATE_N);
    let mut agent = connect_or_dump(&mut vm, "source");

    let src_before = guest_clocks(&mut agent, "source");
    let t_fork = Instant::now();
    let mut sources: Vec<(&mut Vm, u32)> = vec![(&mut vm, 0)];
    let (fork_net, mut forks) = k7d::fork::fork_cluster_warm_dilated(
        &net,
        &mut sources,
        "dil-8to1c",
        &[None],
        &[None],
        &["dil-8to1-0"],
        Some(1),
    )
    .expect("warm fork at child dilation 1");
    let fork_wall = t_fork.elapsed();
    let mut child = forks.pop().expect("one fork");
    assert_eq!(child.dilation(), 1, "the child did not take the override");
    child.start().expect("the fork starts");
    let mut child_agent = connect_or_dump(&mut child, "child");
    let child_first = guest_clocks(&mut child_agent, "child");
    let src_after = guest_clocks(&mut agent, "source");
    eprintln!(
        "MEASUREMENT x{RATE_N} -> x1 warm fork in {fork_wall:?}; child clock at first \
         read sits {:+.3} s of guest time from the source's next read",
        child_first[0] - src_after[0]
    );
    assert_lockstep(child_first, src_before, src_after, RATE_N, fork_wall);
    assert_rates(
        measured_rates(&mut child_agent, "child", FORK_RATE_WINDOW),
        "child",
        1,
    );
    assert_rates(
        measured_rates(&mut agent, "source", FORK_RATE_WINDOW),
        "source",
        RATE_N,
    );
    check_no_splats(&mut child_agent, "child");
    check_no_splats(&mut agent, "source");
    drop((child_agent, agent));
    child.shutdown();
    drop(child);
    drop(fork_net);
    vm.shutdown();
}

/// The reverse — a ×1 source warm-forks a ×8 child.
#[test]
fn test_dilation_fork_child_at_eight_from_source_at_one() {
    let _ = env_logger::builder().is_test(true).try_init();
    require_patched_host();

    let (mut vm, mut agent, net, _disk) = boot_node("dil-1to8", 1);
    check_clocksource(&mut agent, "source");
    check_no_ntp_client(&mut agent, "source");
    drop(agent);

    vm.prepare_fork_source()
        .expect("an undilated VM prepares as a fork source");
    assert_eq!(vm.dilation(), 1);
    let mut agent = connect_or_dump(&mut vm, "source");

    let src_before = guest_clocks(&mut agent, "source");
    let t_fork = Instant::now();
    let mut sources: Vec<(&mut Vm, u32)> = vec![(&mut vm, 0)];
    let (fork_net, mut forks) = k7d::fork::fork_cluster_warm_dilated(
        &net,
        &mut sources,
        "dil-1to8c",
        &[None],
        &[None],
        &["dil-1to8-0"],
        Some(RATE_N),
    )
    .expect("warm fork at child dilation 8");
    let fork_wall = t_fork.elapsed();
    let mut child = forks.pop().expect("one fork");
    assert_eq!(
        child.dilation(),
        RATE_N,
        "the child did not take the override"
    );
    child.start().expect("the fork starts");
    let mut child_agent = connect_or_dump(&mut child, "child");
    let child_first = guest_clocks(&mut child_agent, "child");
    let src_after = guest_clocks(&mut agent, "source");
    eprintln!(
        "MEASUREMENT x1 -> x{RATE_N} warm fork in {fork_wall:?}; child clock at first \
         read sits {:+.3} s of guest time from the source's next read",
        child_first[0] - src_after[0]
    );
    assert_lockstep(child_first, src_before, src_after, 1, fork_wall);
    assert_rates(
        measured_rates(&mut child_agent, "child", FORK_RATE_WINDOW),
        "child",
        RATE_N,
    );
    assert_rates(
        measured_rates(&mut agent, "source", FORK_RATE_WINDOW),
        "source",
        1,
    );
    check_no_splats(&mut child_agent, "child");
    check_no_splats(&mut agent, "source");
    drop((child_agent, agent));
    child.shutdown();
    drop(child);
    drop(fork_net);
    vm.shutdown();
}

/// `tree_fork_batch` applies one child factor to every
/// member of every fork.
#[test]
fn test_dilation_fork_batch_shares_one_factor() {
    let _ = env_logger::builder().is_test(true).try_init();
    require_patched_host();
    let _ = k7d::network::cleanup_stale_k7_bridges();

    let daemon = DilationDaemon::spawn("dilbat");
    let (tree_id, root_id) = match daemon.call(&Request::TreeCreateCluster {
        vm_count: 2,
        config: VmConfig {
            kernel: Some(workspace_path("guest/kernel/vmlinux")),
            initrd: Some(workspace_path("guest/rootfs/initramfs.cpio.gz")),
            ..VmConfig::default()
        },
        budget: None,
        tree_id: Some("dilbat".to_string()),
        egress: None,
    }) {
        Response::TreeCreated {
            tree_id, root_id, ..
        } => (tree_id, root_id),
        other => panic!("unexpected tree_create_cluster: {other:?}"),
    };

    let forks = match daemon.call(&Request::TreeForkBatch {
        tree_id: tree_id.clone(),
        source_id: root_id.clone(),
        labels: vec!["a".into(), "b".into()],
        dilation: Some(RATE_N),
    }) {
        Response::TreeForkBatch { forks, .. } => forks,
        other => panic!("unexpected tree_fork_batch: {other:?}"),
    };
    assert_eq!(forks.len(), 2);
    for f in &forks {
        assert_eq!(f.dilation, RATE_N, "branch {} is not x{RATE_N}", f.node_id);
    }

    match daemon.call(&Request::TreeNodes {
        tree_id: tree_id.clone(),
    }) {
        Response::TreeNodeList { live_dilation, .. } => {
            assert_eq!(
                live_dilation.get(&root_id).copied(),
                Some(1),
                "source should stay x1: {live_dilation:?}"
            );
            for f in &forks {
                assert_eq!(
                    live_dilation.get(&f.node_id).copied(),
                    Some(RATE_N),
                    "fork {} should be x{RATE_N}: {live_dilation:?}",
                    f.node_id
                );
            }
        }
        other => panic!("unexpected tree_nodes: {other:?}"),
    }

    assert!(matches!(
        daemon.call(&Request::TreeDrop { tree_id }),
        Response::Ok
    ));
}

/// The control-plane half: `Request::SetDilation`
/// through the real daemon's socket.
///
/// The mechanism is the tests above. What is only reachable from here is
/// the op's *bookkeeping*: it has to find the cluster's VMs by
/// `cluster_id` and nothing else's, report them in `vm_index` order,
/// leave them running, and refuse a factor the kernel would refuse and a
/// cluster that does not exist. Those are the ways this op fails
/// silently — a `set_dilation` that finds no members and says so is a
/// bug in the caller; a `set_dilation` that quietly switches half a
/// cluster, or a VM on a different bridge, is a bug here.
///
/// Minimal-guest VMs, deliberately: this is the daemon's request path,
/// so the guest only has to have a clock. The substrate question belongs
/// to the Ubuntu tests above.
#[test]
fn test_dilation_set_through_the_daemon_finds_exactly_one_cluster() {
    let _ = env_logger::builder().is_test(true).try_init();
    require_patched_host();
    let _ = k7d::network::cleanup_stale_k7_bridges();

    let daemon = DilationDaemon::spawn("dilset");
    let cluster_id = "dilsetc";
    let on_cluster = |dilation: u32| VmConfig {
        kernel: Some(workspace_path("guest/kernel/vmlinux")),
        initrd: Some(workspace_path("guest/rootfs/initramfs.cpio.gz")),
        dilation: Some(dilation),
        network: Some(NetConfig {
            cluster_id: cluster_id.to_string(),
            vm_index: None,
            pod_netns: None,
        }),
        ..VmConfig::default()
    };

    let (vm_a, cid_a) = daemon.create_vm(on_cluster(DROP_FROM));
    let (vm_b, cid_b) = daemon.create_vm(on_cluster(DROP_FROM));
    // A dilated VM on *another* bridge. The op resolves members by
    // cluster, so this one must keep the factor it was created with.
    let (vm_off, cid_off) = daemon.create_vm(VmConfig {
        network: Some(NetConfig {
            cluster_id: "dilsetother".to_string(),
            vm_index: None,
            pod_netns: None,
        }),
        ..on_cluster(DROP_FROM)
    });

    let before = [cid_a, cid_b, cid_off].map(guest_boottime_rate);
    for (rate, who) in before.iter().zip(["A", "B", "off-cluster"]) {
        eprintln!("MEASUREMENT daemon VM {who} before: {rate:.2}x wall");
        assert!(
            (rate - f64::from(DROP_FROM)).abs() <= f64::from(DROP_FROM) * DAEMON_RATE_TOLERANCE,
            "VM {who} booted at {rate:.2}x, not x{DROP_FROM}"
        );
    }

    // Both ways of asking for nothing are errors, not quiet successes.
    for (what, req) in [
        (
            "a factor the hardware TSC multiplier cannot express",
            Request::SetDilation {
                cluster_id: cluster_id.to_string(),
                factor: k7d::vm::MAX_DILATION + 1,
            },
        ),
        (
            "a factor of zero",
            Request::SetDilation {
                cluster_id: cluster_id.to_string(),
                factor: 0,
            },
        ),
        (
            "a cluster with no VMs on it",
            Request::SetDilation {
                cluster_id: "no-such-cluster".to_string(),
                factor: DROP_TO,
            },
        ),
    ] {
        assert!(
            matches!(daemon.call(&req), Response::Error { .. }),
            "set_dilation accepted {what}"
        );
    }

    match daemon.call(&Request::SetDilation {
        cluster_id: cluster_id.to_string(),
        factor: DROP_TO,
    }) {
        Response::DilationSet {
            cluster_id: echoed,
            vm_ids,
            factor,
            latency_ns,
        } => {
            assert_eq!(echoed, cluster_id);
            assert_eq!(factor, DROP_TO);
            assert_eq!(
                vm_ids,
                vec![vm_a.clone(), vm_b.clone()],
                "the op must switch exactly the cluster's VMs, in vm_index order"
            );
            assert!(latency_ns > 0, "the daemon must report its own latency");
            eprintln!(
                "MEASUREMENT daemon set_dilation x{DROP_TO} on 2 VMs: {:.2} ms",
                latency_ns as f64 / 1e6
            );
        }
        other => panic!("unexpected set_dilation response: {other:?}"),
    }

    // Switched VMs are running VMs: the resume is part of the op, and
    // the new rate is what the guests actually see.
    for (cid, who) in [(cid_a, "A"), (cid_b, "B")] {
        let rate = guest_boottime_rate(cid);
        eprintln!("MEASUREMENT daemon VM {who} after: {rate:.2}x wall");
        assert!(
            (rate - f64::from(DROP_TO)).abs() <= f64::from(DROP_TO) * DAEMON_RATE_TOLERANCE,
            "VM {who} runs at {rate:.2}x after the op, not x{DROP_TO}"
        );
    }
    let off = guest_boottime_rate(cid_off);
    eprintln!("MEASUREMENT daemon off-cluster VM after: {off:.2}x wall");
    assert!(
        (off - f64::from(DROP_FROM)).abs() <= f64::from(DROP_FROM) * DAEMON_RATE_TOLERANCE,
        "a VM on another bridge was switched too: it runs at {off:.2}x, not x{DROP_FROM}"
    );

    for vm_id in [vm_a, vm_b, vm_off] {
        assert!(matches!(
            daemon.call(&Request::StopVm { vm_id }),
            Response::Ok
        ));
    }
}

/// Slack on the daemon test's rate readings. Wider than
/// [`RATE_TOLERANCE`]: this window is short (the point is which factor,
/// not how exact it is) and `/proc/uptime` has 10 ms of resolution.
const DAEMON_RATE_TOLERANCE: f64 = 0.20;

/// Wall time the daemon test measures a guest's rate over.
const DAEMON_RATE_WINDOW: Duration = Duration::from_secs(3);

/// Guest `CLOCK_BOOTTIME` seconds per wall second, from `/proc/uptime`.
///
/// `/proc/uptime` rather than [`guest_clocks`] because the guest here is
/// the minimal initramfs: no `date +%s.%N`, no `/proc/timer_list`.
fn guest_boottime_rate(cid: u64) -> f64 {
    let mut agent = AgentClient::connect_vsock(cid, Duration::from_secs(90))
        .expect("connect the guest agent over vsock");
    let uptime = |agent: &mut AgentClient| -> f64 {
        let out = agent
            .exec(&["sh", "-c", "cut -d' ' -f1 /proc/uptime"])
            .expect("agent exec");
        assert_eq!(out.exit_code, 0, "reading /proc/uptime: {}", out.stderr);
        out.stdout
            .trim()
            .parse()
            .unwrap_or_else(|e| panic!("`{}` is not an uptime: {e}", out.stdout.trim()))
    };
    let before = uptime(&mut agent);
    let t0 = Instant::now();
    std::thread::sleep(DAEMON_RATE_WINDOW);
    let after = uptime(&mut agent);
    (after - before) / t0.elapsed().as_secs_f64()
}

/// A real `k7d` process on its own socket, killed on drop so a failed
/// assertion cannot leak it or the VMs it owns.
struct DilationDaemon {
    child: std::process::Child,
    socket: std::path::PathBuf,
    tree_root: std::path::PathBuf,
}

impl Drop for DilationDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_dir_all(&self.tree_root);
    }
}

impl DilationDaemon {
    fn spawn(tag: &str) -> Self {
        let socket =
            std::env::temp_dir().join(format!("k7d-test-{tag}-{}.sock", std::process::id()));
        let tree_root =
            std::env::temp_dir().join(format!("k7d-test-trees-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_file(&socket);
        let child = std::process::Command::new(env!("CARGO_BIN_EXE_k7d"))
            .arg("--socket")
            .arg(&socket)
            .env("RUST_LOG", "info")
            .env("K7D_TREE_ROOT", &tree_root)
            .spawn()
            .expect("spawn the k7d daemon");
        let daemon = Self {
            child,
            socket,
            tree_root,
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        while !daemon.socket.exists() {
            assert!(
                Instant::now() < deadline,
                "the daemon never bound its socket"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        daemon
    }

    fn call(&self, req: &Request) -> Response {
        k7d::control::Client::connect(self.socket.to_str().expect("utf-8 socket path"))
            .expect("connect the control socket")
            .call(req)
            .expect("control-plane call")
    }

    fn create_vm(&self, config: VmConfig) -> (String, u64) {
        match self.call(&Request::CreateVm { config }) {
            Response::VmCreated {
                vm_id, guest_cid, ..
            } => (vm_id, guest_cid),
            other => panic!("unexpected create_vm response: {other:?}"),
        }
    }
}

fn workspace_path(relative: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join(relative);
    assert!(path.exists(), "the minimal guest is not built: {path:?}");
    path.to_string_lossy().into_owned()
}
