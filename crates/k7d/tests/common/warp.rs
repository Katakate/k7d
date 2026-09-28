//! Shared machinery for the time-warp tests.
//!
//! Everything here is evidence-gathering rather than plumbing: the three
//! guest clocks, the preconditions a warp is only meaningful under, and
//! the CrashLoopBackOff pod that is the only functional proof that a
//! guest whose clock moved also re-armed its timers.
//!
//! It lives in `common/` because `test_warp_clock.rs` (the warp
//! primitive) and `test_auto_warp.rs` (the policy that drives it)
//! have to agree on all of it. Two copies would drift, and the one that
//! drifted would be the one whose assertions quietly stopped meaning
//! anything.

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use k7d::api::AgentClient;

use super::ubuntu::sh_ok;
use super::ubuntu_k3s::{apply_yaml, kubectl, pod_phase, pod_restarts, BUSYBOX, CONVERGE};

/// How far a guest's wall clock may sit from the host's, and how far
/// two guests of one cluster may sit from each other after a warp.
/// Same bound `test_clock.rs` holds a forked guest to.
pub const MAX_SKEW: f64 = 2.0;

/// The kubelet's crash-loop backoff schedule: `backOffPeriod` = 10 s,
/// doubling per restart, capped at `MaxContainerBackOff` = 300 s.
pub const BACKOFF_SCHEDULE: [u64; 6] = [10, 20, 40, 80, 160, 300];

/// Name of the crash-looping pod both tests plant.
pub const CRASHLOOP_POD: &str = "warp-crashloop";

/// Host `CLOCK_REALTIME` in seconds.
#[must_use]
pub fn host_epoch() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("host clock is past the epoch")
        .as_secs_f64()
}

/// How far this guest's wall clock sits ahead of the host's, in
/// seconds. Sub-second precision matters: the lockstep claim is about
/// the spread *between* nodes, and a whole-second `date +%s` would hide
/// everything below the bound it is checked against.
pub fn guest_ahead_of_host(agent: &mut AgentClient, whose: &str) -> f64 {
    let guest: f64 = sh_ok(agent, "date +%s.%N")
        .trim()
        .parse()
        .unwrap_or_else(|e| panic!("{whose}: `date +%s.%N` is not a number: {e}"));
    guest - host_epoch()
}

/// The guest's three clocks, in seconds: `CLOCK_REALTIME` (`date`),
/// `CLOCK_MONOTONIC` (`/proc/timer_list`'s "now at", which is what Go's
/// `time.Since` — and so the kubelet's backoff — measures with) and
/// `CLOCK_BOOTTIME` (`/proc/uptime`).
///
/// A warp that moved only `CLOCK_REALTIME` would pass every `date`
/// assertion and change no timer in the cluster.
pub fn guest_clocks(agent: &mut AgentClient, whose: &str) -> [f64; 3] {
    let out = sh_ok(
        agent,
        "date +%s.%N; awk '/now at/ {print $3/1000000000}' /proc/timer_list; \
         cut -d' ' -f1 /proc/uptime",
    );
    let mut vals = out.split_whitespace().map(|v| {
        v.parse::<f64>()
            .unwrap_or_else(|e| panic!("{whose}: `{v}` is not a clock reading: {e}"))
    });
    let realtime = vals
        .next()
        .unwrap_or_else(|| panic!("{whose}: no CLOCK_REALTIME"));
    let monotonic = vals
        .next()
        .unwrap_or_else(|| panic!("{whose}: no CLOCK_MONOTONIC"));
    let boottime = vals
        .next()
        .unwrap_or_else(|| panic!("{whose}: no CLOCK_BOOTTIME"));
    [realtime, monotonic, boottime]
}

/// Assert the clock k7d owns is the clock the guest reads. Left to
/// itself the guest picks `tsc`, which no warp can reach.
pub fn check_clocksource(agent: &mut AgentClient, whose: &str) {
    let clocksource = sh_ok(
        agent,
        "cat /sys/devices/system/clocksource/clocksource0/current_clocksource",
    );
    assert_eq!(
        clocksource.trim(),
        "kvm-clock",
        "{whose} is not reading the clock k7d owns"
    );
}

/// Name the clockevent device the guest actually arms its timers on.
///
/// Two answers are legitimate, and which one a guest gives is decided
/// by the host, not the guest image:
///
/// * `lapic` — the one-shot count-down timer. What Linux registers when
///   `KVM_GET_SUPPORTED_CPUID` does not report `CPUID.1:ECX[24]`
///   (host kernel 6.8, AMD or Intel). `IA32_TSC_DEADLINE` reads zero
///   on every vCPU, the deadline write-back in `Vm::warp_clock` re-arms
///   nothing, and the policy's jump target comes from `KVM_GET_LAPIC`
///   (`TMCCT`). Whether a jump then fires it is a second host fact —
///   see [`host_runs_lapic_timer_on_preemption_timer`].
/// * `lapic-deadline` — the TSC-deadline timer. What Linux registers
///   when the bit is advertised (the Intel node on host kernel 7.0). The
///   LVT mode is 2, `TMCCT` is meaningless, `IA32_TSC_DEADLINE` holds
///   the armed expiry in guest-TSC units, `Vm::sample_timers` surveys
///   it as `TimerSource::TscDeadline`, and step 3 of `Vm::warp_vcpus`
///   rewrites the MSR after the offset write so KVM recomputes its
///   hrtimer against the advanced TSC.
///
/// Anything else is a guest this suite has never measured, and the
/// assertion says so rather than letting the CrashLoopBackOff proof
/// quietly rest on an unread re-arm story (that is how the second
/// answer was found: the assertion below used to admit only `lapic`).
///
/// The broadcast device is returned alongside, because it is the other
/// half of the same story: the LAPIC one-shot counter is 32 bits over a
/// divided bus clock, so a deeply idle NOHZ CPU whose next timer is
/// further out than that hands the wakeup to `tick_broadcast` — here the
/// PIT. A warp has to be survived by whichever of the two is armed, and
/// the safety predicate declines whenever the PIT's expiry is the one
/// KVM will not export.
pub struct Clockevents {
    /// `lapic` or `lapic-deadline`.
    pub per_cpu: String,
    /// The `tick_broadcast` device (`hpet`, `pit`, or `<NULL>`).
    pub broadcast: String,
}

pub fn check_clockevent(agent: &mut AgentClient, whose: &str) -> Clockevents {
    let per_cpu = sh_ok(
        agent,
        "grep -A1 '^Per CPU device:' /proc/timer_list \
         | awk '/Clock Event Device:/ {print $4}' | sort -u | paste -sd,",
    );
    assert!(
        matches!(per_cpu.trim(), "lapic" | "lapic-deadline"),
        "{whose} arms its timers on {:?}, which is neither the LAPIC one-shot timer nor \
         the TSC-deadline timer — the warp re-arm story in `Vm::warp_vcpus` covers only \
         those two, so re-read what this guest needs re-armed",
        per_cpu.trim()
    );
    let broadcast = sh_ok(
        agent,
        "grep -A1 '^Broadcast device' /proc/timer_list \
         | awk '/Clock Event Device:/ {print $4}'",
    );
    eprintln!(
        "MEASUREMENT {whose} clockevents: per-CPU {}, broadcast {}",
        per_cpu.trim(),
        broadcast.trim()
    );
    Clockevents {
        per_cpu: per_cpu.trim().to_string(),
        broadcast: broadcast.trim().to_string(),
    }
}

/// Whether this host's KVM runs a guest's LAPIC timer on the VMX
/// preemption timer, which decides what a jump does to an armed
/// one-shot.
///
/// KVM keeps a one-shot's expiry twice: `target_expiration` in host
/// time, which the hrtimer and `TMCCT` use, and `tscdeadline` in
/// guest-TSC units, which `vmx_set_hv_timer` compares against the
/// guest's TSC. `vcpu_block` swaps the preemption timer for the hrtimer
/// while a vCPU halts and swaps it back when anything wakes it — the
/// policy's own pause signal included. That swap-back reads the
/// guest-TSC copy against the TSC the warp just advanced, so a jumped
/// one-shot fires at the next pause, as a rewritten deadline does. SVM
/// has no `set_hv_timer`: only the host-time copy exists and a jump
/// never fires the timer (CHALLENGES #264).
///
/// k7d never disables MWAIT or HLT exits, the only per-VM way
/// (`kvm_can_use_hv_timer`) to lose the preemption timer on a host that
/// has it, so the module parameter is the whole answer.
pub fn host_runs_lapic_timer_on_preemption_timer() -> bool {
    if Path::new("/sys/module/kvm_amd").exists() {
        return false;
    }
    let param = "/sys/module/kvm_intel/parameters/preemption_timer";
    let value = std::fs::read_to_string(param)
        .unwrap_or_else(|e| panic!("neither kvm_amd nor kvm_intel is loaded ({param}: {e})"));
    value.trim() == "Y"
}

/// No in-guest NTP client, because there is no sharing the clock with
/// one. The Ubuntu node image ships `systemd-timesyncd` enabled and the
/// bridge MASQUERADEs the guest out to the internet, so left alone it
/// reaches `ntp.ubuntu.com`, sees the offset, and *steps*
/// `CLOCK_REALTIME` back to true time within seconds of a warp —
/// `CLOCK_MONOTONIC` stays warped, so the jump assertions still pass on
/// the nodes it has not got to yet and only the functional proof fails,
/// with no hint why (CHALLENGES #180). `build-node-image.sh` masks it;
/// this is the guardrail that says so if it ever comes back.
///
/// It matters more to the policy than to the primitive: a loop warping at 20 Hz
/// does not merely have one warp undone, it is fought continuously, and
/// the two clocks diverge without bound.
pub fn check_no_ntp_client(agent: &mut AgentClient, whose: &str) {
    let clients = sh_ok(
        agent,
        "systemctl is-enabled systemd-timesyncd.service 2>/dev/null || true; \
         pgrep -l 'chronyd|ntpd|timesyncd' || true",
    );
    assert_eq!(
        clients.trim(),
        "masked",
        "{whose} can correct its own clock — an in-guest NTP client steps CLOCK_REALTIME \
         back to true time and silently undoes the warp"
    );
}

/// The kernel said nothing about the clock jumps.
pub fn check_no_splats(agent: &mut AgentClient, whose: &str) {
    let splats = sh_ok(
        agent,
        "dmesg | grep -ci 'soft lockup\\|clocksource.*unstable\\|rcu_sched detected\\|\
         BUG: soft' || true",
    );
    assert_eq!(
        splats.trim(),
        "0",
        "{whose}: the kernel complained about the clock jumps:\n{}",
        sh_ok(agent, "dmesg | tail -40")
    );
}

/// A pod that crashes forever, so the kubelet backs off between
/// restarts.
pub fn start_crashloop(kubeconfig: &Path) {
    apply_yaml(
        kubeconfig,
        CRASHLOOP_POD,
        &format!(
            r"apiVersion: v1
kind: Pod
metadata:
  name: {CRASHLOOP_POD}
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
}

/// Delete the crash-looping pod, best-effort.
pub fn delete_crashloop(kubeconfig: &Path) {
    let _ = kubectl(
        kubeconfig,
        &[
            "delete",
            "pod",
            CRASHLOOP_POD,
            "--ignore-not-found",
            "--force",
            "--grace-period=0",
        ],
    );
}

/// Wait until the pod has just restarted out of a wait at least
/// `min_backoff` long, and return `(restart count, when we saw it, how
/// long the wait before it was)`.
///
/// **Wall time.** Only usable on a cluster whose clocks nobody is
/// moving — under a policy loop the wait it measures is the compressed
/// one, and it would never see `min_backoff`. `test_auto_warp.rs`
/// counts restarts and reads the guest-observed gap out of the API
/// instead ([`observed_backoff_secs`]).
pub fn wait_for_long_backoff(kubeconfig: &Path, min_backoff: Duration) -> (u64, Instant, Duration) {
    let started = Instant::now();
    let mut last = (pod_restarts(kubeconfig, CRASHLOOP_POD), Instant::now());
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let restarts = pod_restarts(kubeconfig, CRASHLOOP_POD);
        if restarts > last.0 {
            let waited = last.1.elapsed();
            let seen_at = Instant::now();
            eprintln!("{CRASHLOOP_POD}: restart {restarts} after a {waited:?} wait");
            if waited >= min_backoff {
                return (restarts, seen_at, waited);
            }
            last = (restarts, seen_at);
        }
        assert!(
            started.elapsed() < CONVERGE * 3,
            "{CRASHLOOP_POD} never reached a {min_backoff:?} backoff: {}",
            kubectl(kubeconfig, &["describe", "pod", CRASHLOOP_POD]).unwrap_or_else(|e| e)
        );
    }
}

/// The backoff the kubelet is *now* waiting out, named from the one we
/// just watched it wait out.
///
/// The observed wait carries the poll lag and the container's own
/// start-and-exit time, so doubling it directly would drift a few
/// seconds per restart and eventually claim a pending wait longer than
/// the warp covers. Rounding down onto [`BACKOFF_SCHEDULE`] first drops
/// the lag: the schedule is what the kubelet actually holds.
#[must_use]
pub fn pending_backoff(observed: Duration) -> Duration {
    let nominal = BACKOFF_SCHEDULE
        .iter()
        .rev()
        .find(|&&s| s <= observed.as_secs())
        .copied()
        .unwrap_or_else(|| {
            panic!(
                "an observed backoff of {observed:?} is below the kubelet's shortest \
                 ({}s) — this is not the schedule this proof assumes",
                BACKOFF_SCHEDULE[0]
            )
        });
    let next = BACKOFF_SCHEDULE
        .iter()
        .find(|&&s| s > nominal)
        .copied()
        .unwrap_or(nominal);
    Duration::from_secs(next)
}

/// When the pod's *previous* container instance died, in Unix seconds
/// of guest time, or `None` before it has restarted at least once.
///
/// This is the clock a warp is moving: the timestamp is stamped by a
/// kubelet whose `CLOCK_REALTIME` the policy loop advances, and
/// forwarded through the API server. Two readings a restart apart give
/// the backoff the *cluster* believes it waited, against which the
/// host's own wall clock says how little that actually cost.
///
/// `lastState.terminated` is used rather than the current instance's
/// `startedAt` because it is the only one of the two that is present at
/// every moment after the first restart: a crash-looping container is
/// back in `waiting: CrashLoopBackOff` within a second of starting, and
/// a poll that lands there would read no timestamp at all.
///
/// Resolution is one second (RFC 3339 as Kubernetes emits it), which is
/// more than two orders of magnitude finer than the ~300 s gap it
/// measures.
#[must_use]
pub fn last_terminated_secs(kubeconfig: &Path, pod: &str) -> Option<i64> {
    let stamp = kubectl(
        kubeconfig,
        &[
            "get",
            "pod",
            pod,
            "-o",
            "jsonpath={.status.containerStatuses[0].lastState.terminated.finishedAt}",
        ],
    )
    .ok()?;
    rfc3339_secs(stamp.trim())
}

/// RFC 3339 to Unix seconds, via the host's `date`. Test-only: `date`
/// is on every node this suite runs on, and a hand-rolled civil-days
/// conversion is a second thing that can be wrong about a measurement.
fn rfc3339_secs(stamp: &str) -> Option<i64> {
    if stamp.is_empty() {
        return None;
    }
    let out = Command::new("date")
        .args(["-u", "-d", stamp, "+%s"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

/// One kubectl round-trip, end to end: a pod is scheduled, runs, and is
/// deleted. Proves the API server, the scheduler and a kubelet all
/// still work on the far side of a warp.
pub fn kubectl_round_trip(kubeconfig: &Path, pod: &str) {
    apply_yaml(
        kubeconfig,
        pod,
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
    command: ['sh', '-c', 'echo warped']
"
        ),
    );
    let started = Instant::now();
    loop {
        let phase = pod_phase(kubeconfig, pod);
        if phase == "Succeeded" {
            eprintln!(
                "post-warp kubectl round-trip: {pod} Succeeded in {:?}",
                started.elapsed()
            );
            break;
        }
        assert!(
            started.elapsed() < CONVERGE,
            "post-warp pod {pod} never Succeeded (phase {phase:?}): {}",
            kubectl(kubeconfig, &["describe", "pod", pod]).unwrap_or_else(|e| e)
        );
        std::thread::sleep(Duration::from_secs(2));
    }
    kubectl(kubeconfig, &["delete", "pod", pod, "--ignore-not-found"])
        .unwrap_or_else(|e| panic!("delete {pod}: {e}"));
}
