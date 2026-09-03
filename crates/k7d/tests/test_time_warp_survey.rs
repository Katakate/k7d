//! the referenced work — how much wall time could a guest-clock time-warp
//! delete on the real 3-node Ubuntu k3s cluster?
//!
//! Read-only by construction. The survey pauses all three node VMs,
//! reads `KVM_GET_CLOCK`, each vCPU's `KVM_GET_MP_STATE`, `IA32_TSC`
//! and `IA32_TSC_DEADLINE`, and resumes. It writes no clock, no MSR and
//! no TSC offset — a warp mechanism that did would invalidate the
//! numbers it is being sized from.
//!
//! Two distributions decide whether the later increments of the referenced work
//! are worth building: how often *every* vCPU across all three nodes is
//! halted at once, and how far away the nearest armed timer deadline is
//! at those moments. This measures both across three phases (idle
//! steady state, a CrashLoopBackOff wait, a kubectl-churn busy period)
//! and asserts only that the survey itself was sound. The idle fraction
//! and the gap sizes are the measurement, never a requirement.

mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use k7d::vm::{TimeSample, Vm};

use common::ubuntu::{connect_or_dump, sh, sh_ok};
use common::ubuntu_k3s::{
    apply_yaml, bring_up_cluster, kubectl, pod_restarts, settle_cluster, wait_nodes_ready,
    UbuntuCluster, BUSYBOX, CONVERGE,
};

/// Wall time spent sampling in each phase.
const PHASE: Duration = Duration::from_secs(60);

/// Fewest samples a phase may contribute and still be worth reading.
const MIN_SAMPLES: usize = 500;

/// A sampler that freezes the cluster for longer than this is measuring
/// its own overhead more than the guest's idleness.
const MAX_P90_SAMPLER_COST: Duration = Duration::from_millis(5);

/// Assumed cost of one pause-warp-resume cycle when turning the
/// measured gaps into a speedup bound. Deliberately a round number: the
/// real figure is inc2's to measure, and the sampler cost printed below
/// is the honest lower bound for it.
const ASSUMED_JUMP_COST_MS: f64 = 1.0;

/// Quantum for the micro-jump bound. the referenced work's inc3 fallback jumps a
/// fixed amount regardless of any deadline, so its bound is computable
/// from the measured idle fraction and the measured cycle cost even
/// when no deadline is ever armed.
const MICRO_JUMP_QUANTUM_MS: f64 = 50.0;

const PAUSE: &str = "docker.io/rancher/mirrored-pause:3.6";

/// Restarts to wait for before sampling the backoff phase. The kubelet's
/// CrashLoopBackOff sequence is 10 s, 20 s, 40 s, …, so at three
/// restarts the pod is in a ≥ 40 s wait and the 60 s window is mostly
/// backoff rather than mostly container churn.
const CRASHLOOP_RESTARTS: u64 = 3;

/// xorshift64*, so the sample cadence is jittered without a `rand`
/// dependency. A fixed cadence would beat against the guests' own
/// periodic timers and bias the idle fraction.
struct Rng(u64);

impl Rng {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0x2545_F491_4F6C_DD1D, |d| u64::from(d.subsec_nanos()));
        Self(nanos | 1)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// The spec's 20–50 ms cadence.
    fn cadence(&mut self) -> Duration {
        Duration::from_millis(20 + self.next_u64() % 31)
    }
}

/// One cluster-wide observation.
struct Sample {
    /// Every vCPU of every node was in `HLT`.
    all_halted: bool,
    /// vCPUs *not* in `HLT` across the whole cluster — the host CPU the
    /// cluster is actually drawing, which is what bounds dilation.
    awake_cpus: usize,
    /// vCPUs in the cluster (3 nodes × their vCPU count).
    n_cpus: usize,
    /// Smallest armed deadline across the whole cluster, in µs. `None`
    /// when no vCPU anywhere had an armed `IA32_TSC_DEADLINE`.
    min_gap_us: Option<f64>,
    /// pause → sample → resume wall time.
    cost: Duration,
}

/// Pause all three node VMs, sample them, resume them.
///
/// The resume is a `scopeguard`, so a failed sample or a panicking
/// assert still hands the cluster back rather than leaving three frozen
/// VMs and a hung k3s.
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

/// Cluster-wide idleness and nearest deadline from one round of
/// per-VM samples.
fn derive(per_vm: &[TimeSample], cost: Duration) -> Sample {
    let all_halted = per_vm
        .iter()
        .all(|s| s.cpus.iter().all(k7d::vm::CpuTimeSample::is_halted));
    // Discrete jumps need *every* vCPU halted, so one busy vCPU out of
    // six blocks a jump entirely. Dilation is bounded by something
    // else: how much host CPU the cluster actually draws. Count the
    // awake vCPUs too, or the survey silently answers only the first
    // question (see the dilation table).
    let n_cpus: usize = per_vm.iter().map(|s| s.cpus.len()).sum();
    let awake = per_vm
        .iter()
        .flat_map(|s| s.cpus.iter())
        .filter(|c| !c.is_halted())
        .count();
    let mut min_gap_us: Option<f64> = None;
    for s in per_vm {
        // TSC ticks are only ever divided by that VM's own tsc_khz —
        // never mixed with kvmclock_ns, which is a different clock.
        let khz = f64::from(s.tsc_khz);
        for cpu in &s.cpus {
            if let Some(ticks) = cpu.ticks_to_deadline() {
                let us = ticks as f64 / khz * 1000.0;
                min_gap_us = Some(min_gap_us.map_or(us, |m| m.min(us)));
            }
        }
    }
    Sample {
        all_halted,
        awake_cpus: awake,
        n_cpus,
        min_gap_us,
        cost,
    }
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let idx = (((sorted.len() - 1) as f64) * p).round() as usize;
    sorted[idx]
}

fn sorted_by_value(mut v: Vec<f64>) -> Vec<f64> {
    v.sort_by(f64::total_cmp);
    v
}

/// Everything the phase table prints, kept so the summary table can be
/// re-printed at the end in one block for pasting into the spec.
struct PhaseStats {
    name: &'static str,
    samples: usize,
    all_idle_frac: f64,
    p50_gap_us: f64,
    p90_gap_us: f64,
    mean_gap_us: f64,
    no_deadline_while_idle_frac: f64,
    mean_cost_us: f64,
    p90_cost_us: f64,
    speedup_bound: f64,
    micro_jump_bound: f64,
    mean_awake_cpus: f64,
    n_cpus: usize,
    dilation_bound: f64,
}

/// NaN is a result here ("no vCPU ever armed a deadline"), not a bug —
/// print it as such rather than as the word NaN.
fn cell(v: f64, width: usize, decimals: usize) -> String {
    if v.is_nan() {
        format!("{:>width$}", "n/a")
    } else {
        format!("{v:>width$.decimals$}")
    }
}

impl PhaseStats {
    fn compute(name: &'static str, samples: &[Sample]) -> Self {
        let n = samples.len();
        let idle: Vec<&Sample> = samples.iter().filter(|s| s.all_halted).collect();
        let n_cpus = samples.first().map_or(0, |s| s.n_cpus);
        let mean_awake_cpus = samples.iter().map(|s| s.awake_cpus as f64).sum::<f64>() / n as f64;
        let gaps = sorted_by_value(idle.iter().filter_map(|s| s.min_gap_us).collect());
        let costs = sorted_by_value(
            samples
                .iter()
                .map(|s| s.cost.as_secs_f64() * 1e6)
                .collect::<Vec<f64>>(),
        );
        let all_idle_frac = idle.len() as f64 / n as f64;
        let mean_gap_us = if gaps.is_empty() {
            f64::NAN
        } else {
            gaps.iter().sum::<f64>() / gaps.len() as f64
        };
        // 1 / (busy_fraction + jump_cost / mean_gap): the fraction of
        // wall time a perfect jump-to-deadline scheme cannot delete,
        // plus what it spends jumping.
        let busy_frac = 1.0 - all_idle_frac;
        let speedup_bound = if mean_gap_us.is_nan() || mean_gap_us <= 0.0 {
            f64::NAN
        } else {
            1.0 / (busy_frac + ASSUMED_JUMP_COST_MS * 1000.0 / mean_gap_us)
        };
        Self {
            name,
            samples: n,
            all_idle_frac,
            p50_gap_us: percentile(&gaps, 0.50),
            p90_gap_us: percentile(&gaps, 0.90),
            mean_gap_us,
            no_deadline_while_idle_frac: if idle.is_empty() {
                f64::NAN
            } else {
                idle.iter().filter(|s| s.min_gap_us.is_none()).count() as f64 / idle.len() as f64
            },
            mean_cost_us: costs.iter().sum::<f64>() / costs.len() as f64,
            p90_cost_us: percentile(&costs, 0.90),
            speedup_bound,
            // Same shape, with the fixed quantum standing in for the
            // gap and the measured cycle cost for the jump cost.
            micro_jump_bound: 1.0
                / (busy_frac
                    + (costs.iter().sum::<f64>() / costs.len() as f64)
                        / (MICRO_JUMP_QUANTUM_MS * 1000.0)),
            mean_awake_cpus,
            n_cpus,
            // Dilation by N makes the guest live N seconds per host
            // second, so it draws N × its current host CPU. Give each
            // vCPU at most one core and it runs out at
            // `n_cpus / mean_awake_cpus`. This bounds *CPU* only —
            // dilation also stretches every real disk/network latency
            // by N in guest time, which this survey does not measure.
            dilation_bound: if mean_awake_cpus <= 0.0 {
                f64::INFINITY
            } else {
                n_cpus as f64 / mean_awake_cpus
            },
        }
    }

    fn row(&self) -> String {
        format!(
            "| {:<6} | {:>7} | {:>9.1}% | {} | {} | {:>12.1}% | {:>9.0} | {:>8.0} | {} | {} |",
            self.name,
            self.samples,
            self.all_idle_frac * 100.0,
            cell(self.p50_gap_us / 1000.0, 10, 1),
            cell(self.p90_gap_us / 1000.0, 10, 1),
            self.no_deadline_while_idle_frac * 100.0,
            self.mean_cost_us,
            self.p90_cost_us,
            cell(self.speedup_bound, 10, 2),
            cell(self.micro_jump_bound, 12, 2),
        )
    }

    /// Discrete jumps and dilation are bounded by different quantities,
    /// so they get their own table. `awake %` is the mean share of
    /// vCPUs out of `HLT`; `blocked %` is the share of wall time a jump
    /// was impossible because *at least one* vCPU was awake. The two
    /// coming apart is the whole point: one busy vCPU out of six
    /// forbids a jump while drawing a sixth of the CPU dilation cares
    /// about.
    fn dilation_row(&self) -> String {
        format!(
            "| {:<6} | {:>10.3} / {:<2} | {:>7.1}% | {:>9.1}% | {} |",
            self.name,
            self.mean_awake_cpus,
            self.n_cpus,
            self.mean_awake_cpus / self.n_cpus as f64 * 100.0,
            (1.0 - self.all_idle_frac) * 100.0,
            cell(self.dilation_bound, 14, 1),
        )
    }
}

const HEADER: &str = "\
| phase  | samples | all-idle % | p50 gap ms | p90 gap ms | no-deadline % | mean µs/s | p90 µs/s | jump bound | µjump bound |
|--------|---------|------------|------------|------------|---------------|-----------|----------|------------|-------------|";

const DILATION_HEADER: &str = "\
| phase  | awake vCPUs   | awake % | blocked % | dilation bound |
|--------|---------------|---------|-----------|----------------|";

/// Sample the cluster for `PHASE`, jittered.
fn run_phase(name: &'static str, cluster: &mut UbuntuCluster, rng: &mut Rng) -> Vec<Sample> {
    let mut vms = [
        &mut cluster.server,
        &mut cluster.agent1,
        &mut cluster.agent2,
    ];
    let deadline = Instant::now() + PHASE;
    let mut out = Vec::new();
    while Instant::now() < deadline {
        let (per_vm, cost) = sample_cluster(&mut vms);
        out.push(derive(&per_vm, cost));
        std::thread::sleep(rng.cadence());
    }
    eprintln!("phase {name}: {} samples", out.len());
    out
}

/// `kubectl get nodes`, printed between phases. A survey that quietly
/// knocked a node out would otherwise only surface at the end.
fn report_nodes(kubeconfig: &Path, when: &str) {
    match kubectl(kubeconfig, &["get", "nodes", "--no-headers"]) {
        Ok(text) => eprintln!("nodes {when}:\n{}", text.trim_end()),
        Err(e) => eprintln!("nodes {when}: kubectl failed: {e}"),
    }
}

/// Deploy a pod that exits 1 forever and wait until the kubelet has
/// backed off to a ≥ 40 s wait.
fn start_crashloop(kubeconfig: &Path) {
    apply_yaml(
        kubeconfig,
        "crashloop",
        &format!(
            r"apiVersion: v1
kind: Pod
metadata:
  name: warp-crashloop
spec:
  restartPolicy: Always
  containers:
  - name: crash
    image: {BUSYBOX}
    imagePullPolicy: IfNotPresent
    command: ['sh', '-c', 'exit 1']
"
        ),
    );
    let started = Instant::now();
    loop {
        let restarts = pod_restarts(kubeconfig, "warp-crashloop");
        if restarts >= CRASHLOOP_RESTARTS {
            eprintln!(
                "warp-crashloop: {restarts} restarts after {:?} — backoff is ≥ 40 s",
                started.elapsed()
            );
            return;
        }
        assert!(
            started.elapsed() < CONVERGE * 3,
            "warp-crashloop never reached {CRASHLOOP_RESTARTS} restarts (at {restarts}): {}",
            kubectl(kubeconfig, &["describe", "pod", "warp-crashloop"]).unwrap_or_else(|e| e)
        );
        if started.elapsed().as_secs() % 30 < 3 {
            report_nodes(kubeconfig, "while waiting for the crash loop");
        }
        std::thread::sleep(Duration::from_secs(3));
    }
}

/// A 10-replica pause Deployment plus a CPU burner capped at 200m.
fn start_busy(kubeconfig: &Path) {
    apply_yaml(
        kubeconfig,
        "busy",
        &format!(
            r"apiVersion: apps/v1
kind: Deployment
metadata:
  name: warp-churn
spec:
  replicas: 10
  selector:
    matchLabels:
      app: warp-churn
  template:
    metadata:
      labels:
        app: warp-churn
    spec:
      containers:
      - name: pause
        image: {PAUSE}
        imagePullPolicy: IfNotPresent
---
apiVersion: v1
kind: Pod
metadata:
  name: warp-burner
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
    let _ = kubectl(
        kubeconfig,
        &["rollout", "status", "deploy/warp-churn", "--timeout=180s"],
    );
}

/// Scale the churn Deployment between 2 and 10 replicas every ~2 s
/// until told to stop. Returns the joiner and the stop flag.
fn spawn_churn(kubeconfig: PathBuf) -> (std::thread::JoinHandle<u32>, Arc<AtomicBool>) {
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let handle = std::thread::spawn(move || {
        let mut rounds = 0;
        let mut up = false;
        while !flag.load(Ordering::SeqCst) {
            up = !up;
            let replicas = if up { "--replicas=10" } else { "--replicas=2" };
            // Best-effort: an API blip during the churn is churn, not a
            // test failure. The survey asserts on the cluster's health
            // afterwards, not on every scale call.
            let _ = kubectl(&kubeconfig, &["scale", "deploy/warp-churn", replicas]);
            rounds += 1;
            std::thread::sleep(Duration::from_secs(2));
        }
        rounds
    });
    (handle, stop)
}

/// `sh_ok` that says what the guest was doing when it refused.
///
/// The agent reports a guest-side spawn failure as exit `-1` with the
/// error in stderr, which `sh_ok` would surface as a bare
/// `left: -1, right: 0`. After thousands of pause/resume cycles the
/// interesting question is *why* the guest could not run `sh`, so dump
/// the kernel console (which needs no guest process) before giving up.
fn sh_retry(agent: &mut k7d::api::AgentClient, vm: &Vm, whose: &str, cmd: &str) -> String {
    for attempt in 1..=5 {
        let (code, stdout, stderr) = sh(agent, cmd);
        if code == 0 {
            return stdout;
        }
        eprintln!("{whose}: `{cmd}` attempt {attempt} exited {code}: {stdout}{stderr}");
        std::thread::sleep(Duration::from_secs(2));
    }
    panic!(
        "{whose}: the guest could not run `{cmd}` after the survey\n--- serial ---\n{}",
        vm.serial_output(Duration::from_secs(1))
    );
}

fn cleanup(kubeconfig: &Path) {
    for args in [
        vec!["delete", "deploy", "warp-churn", "--ignore-not-found"],
        vec![
            "delete",
            "pod",
            "warp-crashloop",
            "warp-burner",
            "--ignore-not-found",
            "--force",
            "--grace-period=0",
        ],
    ] {
        let _ = kubectl(kubeconfig, &args);
    }
}

#[test]
fn test_time_warp_idle_and_deadline_survey() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut cluster = bring_up_cluster();
    let names = cluster.names();
    let kubeconfig = cluster.kubeconfig.clone();

    // The clock the survey reads is the clock the guest reads.
    {
        let mut agent = connect_or_dump(&mut cluster.server, "server");
        let clocksource = sh_ok(
            &mut agent,
            "cat /sys/devices/system/clocksource/clocksource0/current_clocksource",
        );
        assert_eq!(
            clocksource.trim(),
            "kvm-clock",
            "server is not reading the clock k7d owns"
        );
        // Trap: `IA32_TSC_DEADLINE` only ever holds a jump target if the
        // guest actually arms the TSC-deadline timer. Record which
        // clockevent device each vCPU is really on, so a
        // no-deadline-while-idle bucket below is read as the guest's
        // timer choice and not as a broken MSR read.
        eprintln!(
            "server timer devices:\n{}",
            sh_ok(
                &mut agent,
                "for d in /sys/devices/system/clockevents/clockevent*/current_device; do \
                 echo \"$d = $(cat $d)\"; done; \
                 echo \"cpuid tsc_deadline_timer: \
                 $(grep -c tsc_deadline_timer /proc/cpuinfo)/$(nproc) cpus\"; \
                 dmesg | grep -iE 'apic|clockevent|tsc.deadline' | head -30 || true"
            )
        );
    }

    settle_cluster(&kubeconfig, "warp-survey");

    let mut rng = Rng::new();
    let mut stats = Vec::new();

    report_nodes(&kubeconfig, "before the survey");
    stats.push(PhaseStats::compute(
        "steady",
        &run_phase("steady", &mut cluster, &mut rng),
    ));
    report_nodes(&kubeconfig, "after the steady phase");

    start_crashloop(&kubeconfig);
    stats.push(PhaseStats::compute(
        "wait",
        &run_phase("wait", &mut cluster, &mut rng),
    ));
    report_nodes(&kubeconfig, "after the wait phase");

    start_busy(&kubeconfig);
    let (churn, stop) = spawn_churn(kubeconfig.clone());
    let busy = run_phase("busy", &mut cluster, &mut rng);
    stop.store(true, Ordering::SeqCst);
    let rounds = churn.join().expect("churn thread joins");
    eprintln!("busy phase: {rounds} kubectl scale rounds");
    stats.push(PhaseStats::compute("busy", &busy));
    report_nodes(&kubeconfig, "after the busy phase");

    eprintln!(
        "\nMEASUREMENT 34a-inc0 time-warp survey (jump cost assumed {ASSUMED_JUMP_COST_MS} ms)"
    );
    eprintln!("{HEADER}");
    for s in &stats {
        eprintln!("{}", s.row());
    }
    eprintln!(
        "µjump bound assumes a {MICRO_JUMP_QUANTUM_MS} ms quantum and the measured cycle cost; \
         jump bound assumes {ASSUMED_JUMP_COST_MS} ms and the measured mean deadline gap"
    );
    eprintln!("\nDilation bound  — CPU headroom only:");
    eprintln!("{DILATION_HEADER}");
    for s in &stats {
        eprintln!("{}", s.dilation_row());
    }
    eprintln!(
        "dilation bound = vCPUs / mean awake vCPUs: the factor at which the cluster would \
         need every vCPU's full core. It ignores I/O — dilation by N also makes every real \
         disk/network latency look N× longer to the guest, which this survey cannot see."
    );
    for s in &stats {
        eprintln!(
            "  {}: mean deadline gap {}",
            s.name,
            cell(s.mean_gap_us / 1000.0, 1, 1)
        );
    }
    eprintln!();

    cleanup(&kubeconfig);

    // Survey sanity only — never a gate on how idle the cluster was.
    for s in &stats {
        assert!(
            s.samples >= MIN_SAMPLES,
            "phase {} produced only {} samples (< {MIN_SAMPLES})",
            s.name,
            s.samples
        );
        assert!(
            s.p90_cost_us < MAX_P90_SAMPLER_COST.as_secs_f64() * 1e6,
            "phase {}: p90 sampler cost {:.0} µs over {MAX_P90_SAMPLER_COST:?} — \
             the sampler is measuring itself",
            s.name,
            s.p90_cost_us
        );
    }

    // A survey that left the cluster ill would be measuring a cluster
    // nobody would run.
    wait_nodes_ready(&kubeconfig, &names, CONVERGE);
    for (vm, whose) in [
        (&mut cluster.server, "server"),
        (&mut cluster.agent1, "agent-1"),
        (&mut cluster.agent2, "agent-2"),
    ] {
        let mut agent = connect_or_dump(vm, whose);
        let splats = sh_retry(
            &mut agent,
            vm,
            whose,
            "dmesg | grep -ci 'soft lockup\\|clocksource.*unstable\\|rcu_sched detected\\|\
             BUG: soft' || true",
        );
        assert_eq!(
            splats.trim(),
            "0",
            "{whose}: the kernel complained about the clock or a stall across the survey:\n{}",
            sh_retry(&mut agent, vm, whose, "dmesg | tail -40")
        );
    }
}
