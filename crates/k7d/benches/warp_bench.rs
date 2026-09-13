//! One RL-episode-shaped workload, run under four arms.
//!
//! | Arm | Mechanism | Modules |
//! |---|---|---|
//! | A baseline | nothing | stock |
//! | B jump | daemon `AutoWarp { mode: jump }` | stock |
//! | C dilation | continuous dilation at [`DILATION`]× | patched |
//! | D both | dilation *and* the jump policy on top | patched |
//!
//! A and B need the stock KVM modules and C and D need
//! `utils/kvm-dilation` loaded, so one process runs one of the two
//! pairs; [`main`] asserts which before the first run rather than after
//! it. `make remote-warp-bench` is A and B, `make
//! remote-warp-bench-dilated` installs the patch, runs C and D, and
//! reverts.
//!
//! Three things decide the shape of everything below.
//!
//! **1. The workload is fixed in guest time, and every wait is a
//! cluster-observed state transition.** A host-side `sleep` in the
//! harness would cap arm B at the harness' own cadence and report the
//! cap as the policy's ceiling. So each phase ends when the *cluster*
//! says so — a restart count, a rollout going Ready, a pod that slept
//! 180 s of its own guest time reaching `Succeeded`, a liveness probe
//! failing its twelfth period. Even the busy phase's churn loop runs
//! *inside* the server guest (`sleep 2` there is guest time), so arm B
//! churns the same amount per guest minute as arm A rather than
//! shrinking the workload in proportion to its own speedup.
//!
//! **2. Arm B runs through the daemon op, not `Driver::cycle` inline.**
//! The policy test interleaved `kubectl` polls with policy cycles on one
//! thread, so the loop was stopped for the better part of a second
//! around every poll. `Request::AutoWarp` runs it on its own thread
//! while the caller polls, which is what a caller actually gets — and
//! it is why the whole cluster here is daemon-owned (`CreateVm` with a
//! `NetConfig`) rather than built from `Vm`s the harness holds.
//! Anything driving a guest from *outside* the daemon — the vsock
//! `exec` this harness uses to read the guest's own clock — takes
//! `AutoWarpHold` first ([`Hold`]). `kubectl` to the in-guest API
//! server does not: it is guest-side work, not a host action against a
//! member.
//!
//! **3. Compression is `(wall × N + added) / wall`, over the whole
//! run**, for a dilation factor `N` of 1 in the undilated arms. Guest
//! time also passes while the cluster runs, so the counters'
//! guest-per-paused-nanosecond ratio is *not* the speedup
//! ([`AutoWarpStats::guest_per_wall_paused`] says so in its own docs).
//! And the ceiling is the survey's all-idle fraction scaled by `N`: a jump
//! can only delete idle time, so `1/(1 − 0.734) = 3.76×` is arithmetic
//! rather than a target, while dilation multiplies every second — idle
//! or not — so the two compose as `N × 3.76×`. A run that beats its
//! ceiling has an accounting bug, and this asserts that rather than
//! publishing it.
//!
//! A `cargo bench` target because arm A alone is ~10 minutes of guest
//! time per run and six runs plus six cluster bring-ups is over an
//! hour — `make check` must not pay for it. Run it with
//! `make remote-warp-bench`.

// A measurement harness: every ratio here is an `f64` derived from
// nanosecond counters, and every counter is a `u64` that has to reach
// one. Nanoseconds cross an `f64` mantissa after 52 days.
#![allow(clippy::cast_precision_loss)]

#[path = "../tests/common/mod.rs"]
mod common;

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use k7d::api::AgentClient;
use k7d::autowarp::{AutoWarpMode, AutoWarpStats, MAX_JUMP};
use k7d::control::{BlockDeviceConfig, Daemon, NetConfig, Request, Response, VmConfig};
use k7d::latency::BOOT_UBUNTU_K3S_CLUSTER_3NODE;

use common::ubuntu::{
    failed_units, node_cmdline_with, node_image, systemd_state, NodeCmdlineExtra, NodeImage,
    NodeSize, VmDisk, BOOT_TO_AGENT_CEILING,
};
use common::ubuntu_k3s::{
    apply_yaml, kubectl, pod_phase, pod_restarts, settle_cluster, snapshot_via_kubectl,
    wait_guest_readyz, wait_nodes_ready, write_host_kubeconfig, UbuntuCluster, BUSYBOX,
    CHURN_PAUSE, CONVERGE, K3S_TOKEN,
};
use common::warp::{
    check_clockevent, check_clocksource, check_no_ntp_client, delete_crashloop, guest_clocks,
    kubectl_round_trip, start_crashloop, CRASHLOOP_POD,
};

/// Runs per arm. One run is an anecdote; three
/// give a median and a spread.
const RUNS: usize = 3;

/// Shortest phase the compression ceiling is asserted against. Shorter
/// than this and a single jump landing next to the phase boundary
/// dominates the ratio — see the assertion in [`report_run`].
const CEILING_MIN_WALL: Duration = Duration::from_secs(60);

/// Fraction of guest time the survey measured the 3-node cluster all-idle in
/// its backoff-wait phase, and so the compression ceiling: idle time is
/// the only time a jump can delete. The policy measured 2.34× against it.
const ALL_IDLE_WAITING: f64 = 0.734;

/// Restarts phase 1 waits for.
///
/// Five, for the spec's *four* backoffs: the kubelet restarts a
/// just-crashed container immediately and only then starts doubling, so
/// the 10/20/40/80 s prefix the spec sizes the phase by (≈ 2.5 min of
/// guest time) ends at the fifth restart, not the fourth. Measured, not
/// assumed — waiting for four came back at 80–101 s of guest time,
/// which is the 10/20/40 prefix. Counting restarts against a nominal
/// schedule is how we first mistook an 81 s window for the 300 s cap
/// (`CHALLENGES.md` #184).
const BACKOFF_RESTARTS: u64 = 5;

/// Guest seconds phase 3's timer pod sleeps — the busy phase's length,
/// measured by the cluster rather than by this process.
const BUSY_GUEST_SECS: u64 = 180;

/// Liveness probe period and failure threshold of phase 4's pod: 12
/// periods of 10 guest seconds each.
const PROBE_PERIOD_SECS: u64 = 10;
const PROBE_FAILURES: u64 = 12;

/// Replicas phase 2 reconciles, and phase 3 churns between.
const RECONCILE_REPLICAS: u32 = 10;
const CHURN_LOW_REPLICAS: u32 = 2;

/// Wall time any one phase may take before the harness gives up. A
/// ceiling for hang detection, never a pacing device: arm A's longest
/// phase is ~180 s of guest time at 1×.
const PHASE_CEILING: Duration = Duration::from_secs(900);

/// How long between `kubectl` polls. Sets the resolution with which a
/// phase boundary is placed, so it is short — but it is a *detection*
/// lag, never what ends a phase.
const POLL: Duration = Duration::from_millis(500);

/// Poll node readiness every this many phase polls. A node that went
/// `NotReady` because a jump expired its 40 s lease stays that way for
/// seconds (measured ~9 s), so it cannot hide between checks.
const READY_EVERY: u32 = 6;

/// Node names for the pods this bench plants, kept apart from the
/// survey's and the policy's so a leftover cannot be mistaken for ours.
const RECON_DEPLOY: &str = "bench-recon";
const CHURN_DEPLOY: &str = "bench-churn";
const BURNER_POD: &str = "bench-burner";
const TIMER_POD: &str = "bench-timer";
const PROBE_POD: &str = "bench-probe";

/// Which arm a run is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arm {
    /// Nothing running; the cluster keeps host time.
    Baseline,
    /// `AutoWarp { mode: jump }` on the daemon, for the whole run.
    Jump,
    /// Continuous dilation at [`DILATION`], nothing else.
    Dilation,
    /// Dilation *and* the jump policy on top of it.
    Both,
}

/// Every arm, in the order they are run and tabulated.
const ALL_ARMS: [Arm; 4] = [Arm::Baseline, Arm::Jump, Arm::Dilation, Arm::Both];

/// The dilation factor arms C and D run at (the validated N).
const DILATION: u32 = 8;

impl Arm {
    fn as_str(self) -> &'static str {
        match self {
            Arm::Baseline => "A baseline",
            Arm::Jump => "B jump",
            Arm::Dilation => "C dilation",
            Arm::Both => "D both",
        }
    }

    fn tag(self) -> &'static str {
        match self {
            Arm::Baseline => "a",
            Arm::Jump => "b",
            Arm::Dilation => "c",
            Arm::Both => "d",
        }
    }

    /// Guest nanoseconds per wall nanosecond this arm's VMs run at,
    /// before any jump. 1 unless the arm dilates.
    fn dilation(self) -> u32 {
        match self {
            Arm::Baseline | Arm::Jump => 1,
            Arm::Dilation | Arm::Both => DILATION,
        }
    }

    /// Does the daemon run the auto-warp policy loop for this arm?
    fn jumps(self) -> bool {
        matches!(self, Arm::Jump | Arm::Both)
    }
}

/// The auto-warp hold, released on drop.
///
/// The fifth safety check in its explicit form: a `kubectl`
/// call is guest-side work the policy loop is allowed to interrupt, but
/// an `exec` this process runs over vsock is a host action against a
/// member, invisible to the registry lock the loop holds. Without the
/// hold, the guest sees its clock jump mid-syscall.
///
/// Taken even in arm A. There is no loop to hold off there, and a hold
/// nobody contends costs one mutex — but a harness that only takes it
/// in the arm that needs it is one edit away from not taking it at all.
struct Hold<'a> {
    daemon: &'a Daemon,
    cluster_id: String,
}

impl<'a> Hold<'a> {
    fn take(daemon: &'a Daemon, cluster_id: &str) -> Self {
        match daemon.handle(Request::AutoWarpHold {
            cluster_id: cluster_id.to_string(),
            holder: "warp-bench".to_string(),
            hold: true,
        }) {
            Response::AutoWarp { holders, .. } => assert!(
                holders.iter().any(|h| h == "warp-bench"),
                "the hold was not recorded: {holders:?}"
            ),
            other => panic!("taking the auto-warp hold: {other:?}"),
        }
        Self {
            daemon,
            cluster_id: cluster_id.to_string(),
        }
    }
}

impl Drop for Hold<'_> {
    fn drop(&mut self) {
        match self.daemon.handle(Request::AutoWarpHold {
            cluster_id: self.cluster_id.clone(),
            holder: "warp-bench".to_string(),
            hold: false,
        }) {
            Response::AutoWarp { .. } => {}
            // Loud rather than fatal: a leaked hold stops every later
            // warp, and a panic here would hide the one that unwound.
            other => eprintln!("WARNING: releasing the auto-warp hold: {other:?}"),
        }
    }
}

/// A 3-node Ubuntu k3s cluster the **daemon** owns.
///
/// The whole point of building it this way rather than with
/// `common::ubuntu_k3s::bring_up_cluster`: `Request::AutoWarp` finds a
/// cluster's members in the daemon's own VM registry by `cluster_id`,
/// and runs its policy on a daemon thread that takes that registry for
/// each cycle. A cluster of harness-owned `Vm`s can only be driven by
/// calling `Driver::cycle` inline, which is not what a caller gets.
struct DaemonCluster {
    daemon: Daemon,
    cluster_id: String,
    /// Factor every member is created with, lockstep by construction.
    dilation: u32,
    agents: Vec<AgentClient>,
    kubeconfig: PathBuf,
    certs_dir: PathBuf,
    names: [String; 3],
    boot_to_ready: Duration,
    /// Per-node reflink copies of the base image, removed after the VMs
    /// are gone (this struct's `Drop` runs before its fields').
    disks: Vec<VmDisk>,
    image: NodeImage,
}

/// Node names, in cluster order.
const WHOSE: [&str; 3] = ["server", "agent-1", "agent-2"];

impl DaemonCluster {
    /// Boot server then agents on one daemon-owned bridge, and wait for
    /// three `Ready` nodes.
    fn bring_up(tag: &str, dilation: u32) -> Self {
        let _ = k7d::network::cleanup_stale_k7_bridges();
        let image = node_image();
        let started = Instant::now();
        let daemon = Daemon::new();
        let cluster_id = format!("wb{tag}");
        assert!(
            cluster_id.len() <= 9,
            "cluster_id {cluster_id:?} is too long for a k7-br- bridge name"
        );

        let disks: Vec<VmDisk> = (0..3)
            .map(|i| VmDisk::clone_of(&image.base_image(), &format!("{tag}-{i}")))
            .collect();
        let server_ip = Self::guest_ip(0);

        let mut cluster = Self {
            daemon,
            cluster_id,
            dilation,
            agents: Vec::new(),
            kubeconfig: PathBuf::new(),
            certs_dir: PathBuf::new(),
            names: UbuntuCluster::node_names(server_ip),
            boot_to_ready: Duration::ZERO,
            disks,
            image,
        };

        // Server first: an agent that races the server's TLS bootstrap
        // never joins.
        let mut server = cluster.create_node(0, "server");
        wait_guest_readyz(&mut server, WHOSE[0], BOOT_UBUNTU_K3S_CLUSTER_3NODE);
        let (kubeconfig, certs_dir) = write_host_kubeconfig(&mut server, server_ip, "warpbench");
        cluster.kubeconfig = kubeconfig;
        cluster.certs_dir = certs_dir;
        cluster.agents.push(server);
        for i in 1..3 {
            let agent = cluster.create_node(u32::try_from(i).expect("index fits"), "agent");
            cluster.agents.push(agent);
        }

        let names = cluster.names.clone();
        wait_nodes_ready(&cluster.kubeconfig, &names, BOOT_UBUNTU_K3S_CLUSTER_3NODE);
        cluster.boot_to_ready = started.elapsed();
        eprintln!(
            "MEASUREMENT daemon-owned cluster boot-to-Ready: {:?}",
            cluster.boot_to_ready
        );

        // The preconditions every warp number rests on: the guest reads
        // the clock k7d owns, arms the LAPIC one-shot the survey measured, and
        // runs no NTP client to step a warp back out (CHALLENGES #180).
        for (agent, whose) in cluster.agents.iter_mut().zip(WHOSE) {
            let (state, _) = systemd_state(agent, whose);
            let failed = failed_units(agent, whose);
            assert!(
                (state == "running" || state == "degraded") && failed.is_empty(),
                "{whose}: systemd is {state} with failed units {failed:?}"
            );
            check_clocksource(agent, whose);
            check_clockevent(agent, whose);
            check_no_ntp_client(agent, whose);
        }
        cluster
    }

    /// `10.200.0.{2 + vm_index}` — what the daemon's bridge hands a TAP
    /// at that index, and so what the node's cmdline has to say.
    fn guest_ip(vm_index: u32) -> Ipv4Addr {
        Ipv4Addr::new(
            10,
            200,
            0,
            u8::try_from(2 + vm_index).expect("vm_index fits a /24"),
        )
    }

    /// Ask the daemon for one node VM and connect to its agent.
    fn create_node(&self, vm_index: u32, role: &str) -> AgentClient {
        let ip = Self::guest_ip(vm_index);
        let k3s = format!("{role},{},{K3S_TOKEN}", Self::guest_ip(0));
        let cmdline = node_cmdline_with(
            ip,
            NodeCmdlineExtra {
                k3s: Some(&k3s),
                cni: None,
            },
        );
        let disk = &self.disks[vm_index as usize];
        let config = VmConfig {
            kernel: Some(self.image.kernel().to_string_lossy().into_owned()),
            // Ubuntu boots systemd off `root=/dev/vda`; an initrd here
            // would be the RuntimeClass busybox pair (CHALLENGES #72).
            initrd: None,
            cmdline: Some(cmdline),
            memory_mb: NodeSize::DEFAULT.memory_mb,
            vcpus: NodeSize::DEFAULT.vcpus,
            vsock: true,
            block_devices: vec![BlockDeviceConfig {
                host_path: disk.path.to_string_lossy().into_owned(),
                readonly: false,
                guest_mount: None,
                fstype: None,
            }],
            network: Some(NetConfig {
                cluster_id: self.cluster_id.clone(),
                vm_index: Some(vm_index),
                pod_netns: None,
            }),
            // One factor for the whole cluster, from one place: every
            // member is created from this literal, so lockstep is a
            // property of the construction rather than of a loop that
            // has to remember.
            dilation: (self.dilation > 1).then_some(self.dilation),
            ..VmConfig::default()
        };
        let guest_cid = match self.daemon.handle(Request::CreateVm { config }) {
            Response::VmCreated {
                guest_cid,
                vm_index: got,
                ..
            } => {
                assert_eq!(
                    got,
                    Some(vm_index),
                    "the daemon put the node on the wrong bridge index, so its IP is not \
                     the one on its cmdline"
                );
                guest_cid
            }
            other => panic!("create_vm for {role} {ip}: {other:?}"),
        };
        let mut agent = AgentClient::connect_vsock(guest_cid, BOOT_TO_AGENT_CEILING)
            .unwrap_or_else(|e| panic!("no agent on {role} {ip} (cid {guest_cid}): {e}"));
        // Strict rp_filter drops cross-node pod sources on this bridge
        // (CHALLENGES #117) — the same fix the harness-owned fixture
        // applies, needed for the same reason.
        common::ubuntu::relax_guest_rp_filter(&mut agent, role);
        agent
    }

    /// Every member's `CLOCK_MONOTONIC`, in seconds, read under a hold.
    ///
    /// `CLOCK_MONOTONIC` and not `date`: it is what Go's `time.Since` —
    /// and so every kubelet backoff, probe period and lease renewal —
    /// measures with, and the one an NTP client could not have undone.
    fn guest_monotonic(&mut self) -> [f64; 3] {
        // Destructured so the hold's borrow of the daemon and the
        // `exec`'s borrow of the agents are disjoint.
        let Self {
            daemon,
            cluster_id,
            agents,
            ..
        } = self;
        let _hold = Hold::take(daemon, cluster_id);
        let mut out = [0.0; 3];
        for (i, agent) in agents.iter_mut().enumerate().take(3) {
            out[i] = guest_clocks(agent, WHOSE[i])[1];
        }
        out
    }

    /// Run one short shell command on the server node, under a hold.
    fn server_sh(&mut self, cmd: &str) -> String {
        let Self {
            daemon,
            cluster_id,
            agents,
            ..
        } = self;
        let _hold = Hold::take(daemon, cluster_id);
        common::ubuntu::sh_ok(&mut agents[0], cmd)
    }

    /// Start or stop the policy loop, returning the counters the reply
    /// carries. `off` is how a finished run's accounting is collected.
    fn auto_warp(&self, mode: AutoWarpMode) -> AutoWarpStats {
        match self.daemon.handle(Request::AutoWarp {
            cluster_id: self.cluster_id.clone(),
            mode,
        }) {
            Response::AutoWarp {
                stats, mode: got, ..
            } => {
                assert_eq!(got, mode, "the daemon reported a different mode");
                stats
            }
            other => panic!("auto_warp({}): {other:?}", mode.as_str()),
        }
    }

    /// Counters as of now, without changing the mode.
    fn auto_warp_stats(&self) -> AutoWarpStats {
        match self.daemon.handle(Request::AutoWarpStatus {
            cluster_id: self.cluster_id.clone(),
        }) {
            Response::AutoWarp { stats, .. } => stats,
            other => panic!("auto_warp_status: {other:?}"),
        }
    }

    /// Are all three nodes `Ready` right now, without waiting?
    fn nodes_all_ready(&self) -> bool {
        let Ok(out) = kubectl(
            &self.kubeconfig,
            &[
                "get",
                "nodes",
                "-o",
                "jsonpath={range .items[*]}{.metadata.name}={.status.conditions[?(@.type=='Ready')].status}{'\\n'}{end}",
            ],
        ) else {
            return false;
        };
        self.names
            .iter()
            .all(|n| out.contains(&format!("{n}=True")))
    }
}

impl Drop for DaemonCluster {
    fn drop(&mut self) {
        // Stops any policy loop (joined, so no cycle still owns a pause)
        // before the VMs, bridge and TAPs go.
        self.daemon.shutdown_all();
        let _ = std::fs::remove_file(&self.kubeconfig);
        let _ = std::fs::remove_dir_all(&self.certs_dir);
    }
}

/// What one phase cost and what it bought.
#[derive(Debug, Clone)]
struct Phase {
    name: &'static str,
    /// Host wall time.
    wall: Duration,
    /// Guest `CLOCK_MONOTONIC` advance, meaned over the three nodes.
    guest: Duration,
    /// Guest time the policy added inside this phase (0 in arm A).
    added: Duration,
    /// Policy cycles and warps inside this phase.
    cycles: u64,
    warps: u64,
    /// The arm's dilation factor, so `compression` can account for the
    /// guest time dilation hands over without any jump.
    dilation: u32,
}

impl Phase {
    /// `(wall × N + added) / wall` — what the caller's own clock and the
    /// counters agree the phase was compressed by. Dilation hands the
    /// guest `N` seconds per wall second before a single jump is taken,
    /// so it is a factor here and not a term.
    fn compression(&self) -> f64 {
        compression(self.wall, self.added, self.dilation)
    }

    /// The same ratio as the guests measured it, with no counter
    /// involved. The two disagreeing means a warp the policy asked for
    /// was not one a guest kept.
    fn observed(&self) -> f64 {
        self.guest.as_secs_f64() / self.wall.as_secs_f64()
    }
}

/// The distortion column: what the cluster did that the script did not
/// ask for.
#[derive(Debug, Clone, Default)]
struct Fidelity {
    /// `Unhealthy` events, summed over their `count`. Phase 4 scripts
    /// [`PROBE_FAILURES`] of them, so the arm-to-arm delta is the cost.
    probe_failures: u64,
    /// Container restarts beyond the ones the script asked for.
    excess_restarts: u64,
    /// Polls at which some node was not `Ready`.
    notready_lapses: u32,
    /// Clock/stall complaints in the nodes' `dmesg`.
    splats: u64,
    /// Churn rounds the *in-guest* loop completed in phase 3, and the
    /// guest seconds it had to do them in. Not a distortion: the check
    /// that the workload really is fixed in guest time, since a
    /// host-paced loop would do ~1/compression as many per guest second
    /// in arm B as in arm A.
    churn_rounds: u64,
}

/// One run of the workload under one arm.
#[derive(Debug, Clone)]
struct Run {
    arm: Arm,
    phases: Vec<Phase>,
    wall: Duration,
    guest: Duration,
    added: Duration,
    stats: AutoWarpStats,
    fidelity: Fidelity,
    boot_to_ready: Duration,
}

impl Run {
    fn compression(&self) -> f64 {
        compression(self.wall, self.added, self.arm.dilation())
    }

    fn observed(&self) -> f64 {
        self.guest.as_secs_f64() / self.wall.as_secs_f64()
    }

    /// Mean jump size over the run's warps.
    fn mean_jump(&self) -> Duration {
        if self.stats.warps == 0 {
            return Duration::ZERO;
        }
        Duration::from_nanos(self.stats.guest_ns_added / self.stats.warps)
    }

    /// Share of wall time the cluster spent paused by the policy.
    fn paused_share(&self) -> f64 {
        self.stats.wall_ns_paused as f64 / self.wall.as_nanos() as f64
    }
}

/// Guest seconds per wall second: `N` from dilation, plus whatever the
/// jump policy deleted on top of it.
fn compression(wall: Duration, added: Duration, dilation: u32) -> f64 {
    (wall.as_secs_f64() * f64::from(dilation) + added.as_secs_f64()) / wall.as_secs_f64()
}

/// The compression idleness allows at this dilation factor:
/// `N/(1 − all-idle fraction)`. A jump can only delete idle time, and
/// dilation multiplies every second — idle or not — by `N`, so the two
/// mechanisms compose as a product rather than a sum.
fn ceiling(dilation: u32) -> f64 {
    f64::from(dilation) / (1.0 - ALL_IDLE_WAITING)
}

/// Wait until `done` says the cluster has moved on, polling at [`POLL`].
///
/// The only waiting primitive in this harness, so there is exactly one
/// place a host-side sleep could creep in and cap arm B: the sleep here
/// is between *polls* of cluster state, never a substitute for one.
fn wait_for(
    cluster: &DaemonCluster,
    what: &str,
    lapses: &mut u32,
    mut done: impl FnMut(&DaemonCluster) -> bool,
) {
    let started = Instant::now();
    let mut polls = 0_u32;
    loop {
        if done(cluster) {
            eprintln!("{what}: after {:?} of wall time", started.elapsed());
            return;
        }
        polls += 1;
        if polls % READY_EVERY == 0 && !cluster.nodes_all_ready() {
            *lapses += 1;
        }
        assert!(
            started.elapsed() < PHASE_CEILING,
            "{what} never happened in {PHASE_CEILING:?} of wall time:\n{}",
            kubectl(&cluster.kubeconfig, &["get", "pods", "-o", "wide"]).unwrap_or_else(|e| e)
        );
        std::thread::sleep(POLL);
    }
}

/// Phase 1 — wait-heavy: a pod parked in the kubelet's crash-loop
/// backoff, waited out to [`BACKOFF_RESTARTS`] (10+20+40+80 s of guest
/// time). The phase the survey found idlest and the policy measured against.
fn phase_wait(cluster: &mut DaemonCluster, lapses: &mut u32) {
    start_crashloop(&cluster.kubeconfig);
    wait_for(
        cluster,
        &format!("{CRASHLOOP_POD} reached {BACKOFF_RESTARTS} restarts"),
        lapses,
        |c| pod_restarts(&c.kubeconfig, CRASHLOOP_POD) >= BACKOFF_RESTARTS,
    );
    delete_crashloop(&cluster.kubeconfig);
}

/// Phase 2 — reconcile: a 10-replica Deployment rolled and rescaled,
/// each step waited out by the cluster's own readiness rather than by a
/// timer. Dense, short-waited work, which is the regime jumps are
/// *worst* in.
fn phase_reconcile(cluster: &mut DaemonCluster) {
    apply_yaml(
        &cluster.kubeconfig,
        RECON_DEPLOY,
        &deployment_yaml(RECON_DEPLOY, RECONCILE_REPLICAS),
    );
    let rollout = |what: &str| {
        kubectl(
            &cluster.kubeconfig,
            &[
                "rollout",
                "status",
                &format!("deploy/{RECON_DEPLOY}"),
                "--timeout=600s",
            ],
        )
        .unwrap_or_else(|e| panic!("{what}: rollout never went Ready: {e}"));
    };
    rollout("initial rollout");
    kubectl(
        &cluster.kubeconfig,
        &["rollout", "restart", &format!("deploy/{RECON_DEPLOY}")],
    )
    .expect("rollout restart");
    rollout("restarted rollout");
    for replicas in [CHURN_LOW_REPLICAS, RECONCILE_REPLICAS] {
        kubectl(
            &cluster.kubeconfig,
            &[
                "scale",
                &format!("deploy/{RECON_DEPLOY}"),
                &format!("--replicas={replicas}"),
            ],
        )
        .unwrap_or_else(|e| panic!("scale to {replicas}: {e}"));
        rollout(&format!("scale to {replicas}"));
    }
    let _ = kubectl(
        &cluster.kubeconfig,
        &[
            "delete",
            "deploy",
            RECON_DEPLOY,
            "--ignore-not-found",
            "--wait=false",
        ],
    );
}

/// Phase 3 — busy: the survey's churn loop (scale between 2 and 10 replicas
/// every ~2 s, plus a CPU burner capped at 200m) for
/// [`BUSY_GUEST_SECS`] of guest time.
///
/// Two things make this a *guest-time* phase rather than a host-time
/// one, and both matter:
///
/// * The length is a pod that sleeps [`BUSY_GUEST_SECS`] and then
///   `Succeeded`s. `sleep` in a container is guest time.
/// * The churn loop runs **inside the server guest**, so its `sleep 2`
///   is guest time too. A host-side churn loop would do
///   `1/compression` as many rounds per guest second in arm B as in
///   arm A — the same workload name over a quieter cluster, which
///   would flatter the policy exactly where the survey says it should
///   struggle.
///
/// Returns the churn rounds the guest loop completed.
fn phase_busy(cluster: &mut DaemonCluster, lapses: &mut u32) -> u64 {
    apply_yaml(
        &cluster.kubeconfig,
        CHURN_DEPLOY,
        &format!(
            "{}---\n{}",
            deployment_yaml(CHURN_DEPLOY, RECONCILE_REPLICAS),
            burner_yaml()
        ),
    );
    kubectl(
        &cluster.kubeconfig,
        &[
            "rollout",
            "status",
            &format!("deploy/{CHURN_DEPLOY}"),
            "--timeout=600s",
        ],
    )
    .expect("churn rollout");

    // One brief exec starts a loop that then lives in guest time. It
    // stops on a marker file rather than a signal so stopping it is
    // also one brief exec.
    cluster.server_sh(&format!(
        "rm -f /tmp/bench-churn.stop /tmp/bench-churn.rounds; \
             setsid nohup sh -c 'while [ ! -f /tmp/bench-churn.stop ]; do \
               for n in {CHURN_LOW_REPLICAS} {RECONCILE_REPLICAS}; do \
                 k3s kubectl scale deploy/{CHURN_DEPLOY} --replicas=$n >/dev/null 2>&1; \
                 echo x >> /tmp/bench-churn.rounds; \
                 sleep 2; \
               done; \
             done' </dev/null >/dev/null 2>&1 & echo started"
    ));

    apply_yaml(&cluster.kubeconfig, TIMER_POD, &timer_yaml());
    wait_for(
        cluster,
        &format!("{TIMER_POD} slept {BUSY_GUEST_SECS}s of its own guest time"),
        lapses,
        |c| pod_phase(&c.kubeconfig, TIMER_POD) == "Succeeded",
    );

    let rounds = cluster
        .server_sh("touch /tmp/bench-churn.stop; wc -l < /tmp/bench-churn.rounds")
        .trim()
        .parse::<u64>()
        .expect("the in-guest churn loop counted its rounds");
    for args in [
        vec!["delete", "deploy", CHURN_DEPLOY, "--ignore-not-found"],
        vec![
            "delete",
            "pod",
            BURNER_POD,
            TIMER_POD,
            "--ignore-not-found",
            "--force",
            "--grace-period=0",
        ],
    ] {
        let _ = kubectl(&cluster.kubeconfig, &args);
    }
    rounds
}

/// Phase 4 — probes: a pod whose liveness probe fails every period,
/// waited out to the kubelet's [`PROBE_FAILURES`]th failure (12 periods
/// of [`PROBE_PERIOD_SECS`] guest seconds). The restart is the cluster
/// saying the twelfth period elapsed; nothing here counts periods.
fn phase_probes(cluster: &mut DaemonCluster, lapses: &mut u32) {
    apply_yaml(&cluster.kubeconfig, PROBE_POD, &probe_yaml());
    wait_for(
        cluster,
        &format!("{PROBE_POD} failed {PROBE_FAILURES} liveness periods"),
        lapses,
        |c| pod_restarts(&c.kubeconfig, PROBE_POD) >= 1,
    );
}

fn deployment_yaml(name: &str, replicas: u32) -> String {
    format!(
        r"apiVersion: apps/v1
kind: Deployment
metadata:
  name: {name}
spec:
  replicas: {replicas}
  selector:
    matchLabels:
      app: {name}
  template:
    metadata:
      labels:
        app: {name}
    spec:
      containers:
      - name: pause
        image: {CHURN_PAUSE}
        imagePullPolicy: IfNotPresent
"
    )
}

fn burner_yaml() -> String {
    format!(
        r"apiVersion: v1
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
    )
}

fn timer_yaml() -> String {
    format!(
        r"apiVersion: v1
kind: Pod
metadata:
  name: {TIMER_POD}
spec:
  restartPolicy: Never
  containers:
  - name: sleep
    image: {BUSYBOX}
    imagePullPolicy: IfNotPresent
    command: ['sh', '-c', 'sleep {BUSY_GUEST_SECS}']
"
    )
}

fn probe_yaml() -> String {
    format!(
        r"apiVersion: v1
kind: Pod
metadata:
  name: {PROBE_POD}
spec:
  restartPolicy: Always
  containers:
  - name: probed
    image: {BUSYBOX}
    imagePullPolicy: IfNotPresent
    command: ['sh', '-c', 'rm -f /tmp/live; sleep 3600']
    livenessProbe:
      exec:
        command: ['cat', '/tmp/live']
      initialDelaySeconds: 1
      periodSeconds: {PROBE_PERIOD_SECS}
      timeoutSeconds: 2
      failureThreshold: {PROBE_FAILURES}
"
    )
}

/// `Unhealthy` events, summed over their occurrence counts.
fn probe_failure_events(kubeconfig: &Path) -> u64 {
    kubectl(
        kubeconfig,
        &[
            "get",
            "events",
            "-A",
            "--field-selector",
            "reason=Unhealthy",
            "-o",
            "jsonpath={range .items[*]}{.count}{'\\n'}{end}",
        ],
    )
    .unwrap_or_default()
    .lines()
    .filter_map(|l| l.trim().parse::<u64>().ok())
    .sum()
}

/// Container restarts across `kube-system` and `default`, keyed by pod.
fn restarts_by_pod(kubeconfig: &Path) -> BTreeMap<String, u64> {
    snapshot_via_kubectl(kubeconfig)
        .into_iter()
        .map(|(pod, (_uid, restarts))| (pod, restarts.values().sum()))
        .collect()
}

/// Clock/stall complaints in one node's ring buffer.
fn splat_count(agent: &mut AgentClient) -> u64 {
    common::ubuntu::sh_ok(
        agent,
        "dmesg | grep -ci 'soft lockup\\|clocksource.*unstable\\|rcu_sched detected\\|\
         BUG: soft' || true",
    )
    .trim()
    .parse()
    .unwrap_or(0)
}

/// One run: fresh cluster, four phases, one arm.
fn run_arm(arm: Arm, index: usize) -> Run {
    let tag = format!("{}{index}", arm.tag());
    let mut cluster = DaemonCluster::bring_up(&tag, arm.dilation());
    settle_cluster(&cluster.kubeconfig, "warp-bench");

    if arm.jumps() {
        let started = cluster.auto_warp(AutoWarpMode::Jump);
        assert_eq!(
            started.cycles, 0,
            "the policy loop reported cycles before the workload started"
        );
    }

    let mut fidelity = Fidelity::default();
    let mut phases = Vec::new();
    let run_started = Instant::now();
    let mut mark = cluster.guest_monotonic();
    let mut added = Duration::ZERO;
    let mut cycles = 0_u64;
    let mut warps = 0_u64;
    let mut phase_started = Instant::now();

    let close = |cluster: &mut DaemonCluster,
                 name: &'static str,
                 mark: &mut [f64; 3],
                 added: &mut Duration,
                 cycles: &mut u64,
                 warps: &mut u64,
                 phase_started: &mut Instant|
     -> Phase {
        let wall = phase_started.elapsed();
        let now = cluster.guest_monotonic();
        let guest = (0..3).map(|i| now[i] - mark[i]).sum::<f64>() / 3.0;
        let stats = if arm.jumps() {
            cluster.auto_warp_stats()
        } else {
            AutoWarpStats::default()
        };
        let phase = Phase {
            name,
            wall,
            guest: Duration::from_secs_f64(guest.max(0.0)),
            added: Duration::from_nanos(stats.guest_ns_added).saturating_sub(*added),
            cycles: stats.cycles - *cycles,
            warps: stats.warps - *warps,
            dilation: arm.dilation(),
        };
        *mark = now;
        *added = Duration::from_nanos(stats.guest_ns_added);
        *cycles = stats.cycles;
        *warps = stats.warps;
        *phase_started = Instant::now();
        eprintln!(
            "MEASUREMENT {} phase {name}: {:.1}s wall, {:.1}s guest \
             ({:.2}× observed), policy added {:.1}s over {} warps of {} cycles \
             ({:.2}× accounted)",
            arm.as_str(),
            phase.wall.as_secs_f64(),
            phase.guest.as_secs_f64(),
            phase.observed(),
            phase.added.as_secs_f64(),
            phase.warps,
            phase.cycles,
            phase.compression(),
        );
        phase
    };

    phase_wait(&mut cluster, &mut fidelity.notready_lapses);
    phases.push(close(
        &mut cluster,
        "wait",
        &mut mark,
        &mut added,
        &mut cycles,
        &mut warps,
        &mut phase_started,
    ));

    phase_reconcile(&mut cluster);
    phases.push(close(
        &mut cluster,
        "reconcile",
        &mut mark,
        &mut added,
        &mut cycles,
        &mut warps,
        &mut phase_started,
    ));

    fidelity.churn_rounds = phase_busy(&mut cluster, &mut fidelity.notready_lapses);
    phases.push(close(
        &mut cluster,
        "busy",
        &mut mark,
        &mut added,
        &mut cycles,
        &mut warps,
        &mut phase_started,
    ));

    phase_probes(&mut cluster, &mut fidelity.notready_lapses);
    phases.push(close(
        &mut cluster,
        "probes",
        &mut mark,
        &mut added,
        &mut cycles,
        &mut warps,
        &mut phase_started,
    ));

    let wall = run_started.elapsed();
    // `off` stops the loop (joined) and hands back the finished run's
    // accounting — the whole point of collecting it from the op rather
    // than from a driver this process owns.
    let stats = if arm.jumps() {
        cluster.auto_warp(AutoWarpMode::Off)
    } else {
        cluster.auto_warp_stats()
    };

    fidelity.probe_failures = probe_failure_events(&cluster.kubeconfig);
    // Phase 1's crash-looping pod is deleted with the phase, so the
    // only restarts the script asked for that are still on the cluster
    // are phase 4's probe pod's.
    let scripted = pod_restarts(&cluster.kubeconfig, PROBE_POD);
    let total_restarts: u64 = restarts_by_pod(&cluster.kubeconfig).values().sum();
    fidelity.excess_restarts = total_restarts.saturating_sub(scripted);
    fidelity.splats = cluster.agents.iter_mut().map(splat_count).sum::<u64>();

    let guest = phases.iter().map(|p| p.guest).sum();
    let run = Run {
        arm,
        phases,
        wall,
        guest,
        added: Duration::from_nanos(stats.guest_ns_added),
        stats,
        fidelity,
        boot_to_ready: cluster.boot_to_ready,
    };
    report_run(&run);

    // The cluster is still one a caller would want, on the far side of
    // however many jumps the arm took.
    wait_nodes_ready(&cluster.kubeconfig, &cluster.names.clone(), CONVERGE);
    kubectl_round_trip(&cluster.kubeconfig, "warp-bench-after");
    for (agent, whose) in cluster.agents.iter_mut().zip(WHOSE) {
        check_clocksource(agent, whose);
        check_no_ntp_client(agent, whose);
    }
    assert_eq!(
        run.fidelity.splats, 0,
        "the guests' kernels complained about the clock or a stall"
    );
    run
}

/// Everything one run measured, in the shape the policy test's `report()` printed
/// it — plus the assertions that make a number publishable.
fn report_run(run: &Run) {
    let declines = if run.stats.declines.is_empty() {
        "none".to_string()
    } else {
        run.stats
            .declines
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    eprintln!(
        "MEASUREMENT {} run: {:.1}s wall ({:?} of it cluster bring-up, not counted), \
         {:.1}s guest, {:.2}× accounted, {:.2}× observed; \
         {} cycles, {} warps, +{:.1}s guest added, mean jump {:?}, \
         {:.1}ms paused ({:.2}% of wall), APIC bus cycle {}fs; \
         fidelity: {} probe failures, {} unscripted restarts, {} NotReady lapses, \
         {} splats, {} in-guest churn rounds; declines: {declines}",
        run.arm.as_str(),
        run.wall.as_secs_f64(),
        run.boot_to_ready,
        run.guest.as_secs_f64(),
        run.compression(),
        run.observed(),
        run.stats.cycles,
        run.stats.warps,
        run.added.as_secs_f64(),
        run.mean_jump(),
        run.stats.wall_ns_paused as f64 / 1e6,
        run.paused_share() * 100.0,
        run.stats
            .apic_bus_cycle_fs
            .map_or_else(|| "unmeasured".to_string(), |fs| fs.to_string()),
        run.fidelity.probe_failures,
        run.fidelity.excess_restarts,
        run.fidelity.notready_lapses,
        run.fidelity.splats,
        run.fidelity.churn_rounds,
    );

    assert_eq!(
        run.stats.resume_failures, 0,
        "a member failed to resume after a cycle — that is a stopped node, not a faster one"
    );
    assert_eq!(
        run.fidelity.notready_lapses,
        0,
        "a node went NotReady during the run — the {MAX_JUMP:?} single-jump cap exists so an \
         automatic policy never expires a 40 s node lease (mean jump {:?})",
        run.mean_jump()
    );
    assert!(
        run.mean_jump() <= MAX_JUMP,
        "the mean jump was {:?}, over the {MAX_JUMP:?} cap",
        run.mean_jump()
    );
    for phase in &run.phases {
        // Only over a window long enough for the survey's idle *fraction* to
        // describe: a 6 s reconcile phase that happens to contain one
        // 25 s jump reads as 5×, and that is a phase boundary landing
        // next to a jump rather than time being invented. The claim the
        // ceiling bounds is the run's.
        if phase.wall < CEILING_MIN_WALL {
            continue;
        }
        assert!(
            phase.compression() <= ceiling(run.arm.dilation()),
            "phase {} compressed {:.2}×, past the {:.2}× that the survey's {:.1}% all-idle \
             fraction allows at {}× dilation — idle time is the only time there is to \
             delete, so this is an accounting bug rather than a faster policy",
            phase.name,
            phase.compression(),
            ceiling(run.arm.dilation()),
            ALL_IDLE_WAITING * 100.0,
            run.arm.dilation()
        );
    }
    assert!(
        run.compression() <= ceiling(run.arm.dilation()),
        "the run compressed {:.2}×, past the {:.2}× ceiling",
        run.compression(),
        ceiling(run.arm.dilation())
    );
    if !run.arm.jumps() {
        assert_eq!(
            run.stats,
            AutoWarpStats::default(),
            "an arm with no jump policy ran a policy loop — the arms are not comparable"
        );
    } else {
        assert!(
            run.stats.warps > 0,
            "the policy warped nothing in {:?} of wall time; declines: {declines}",
            run.wall
        );
    }
}

/// Median of a sample, and its min/max. All `NaN` for an empty sample —
/// a table printed for an arm that was not run says so rather than
/// indexing past the end of it.
fn median(mut xs: Vec<f64>) -> (f64, f64, f64) {
    if xs.is_empty() {
        return (f64::NAN, f64::NAN, f64::NAN);
    }
    xs.sort_by(f64::total_cmp);
    let lo = xs[0];
    let hi = xs[xs.len() - 1];
    let mid = if xs.len() % 2 == 1 {
        xs[xs.len() / 2]
    } else {
        (xs[xs.len() / 2 - 1] + xs[xs.len() / 2]) / 2.0
    };
    (mid, lo, hi)
}

/// The spec's `## Results` table, ready to paste.
fn print_tables(runs: &[Run]) {
    eprintln!("\nMEASUREMENT results ({RUNS} runs per arm, fresh cluster per run)\n");
    eprintln!(
        "| arm | wall (s) | guest (s) | compression | paused % | warps | mean jump | \
         declines (top) |"
    );
    eprintln!("|---|---|---|---|---|---|---|---|");
    for arm in ALL_ARMS {
        let of: Vec<&Run> = runs.iter().filter(|r| r.arm == arm).collect();
        if of.is_empty() {
            continue;
        }
        let stat = |f: &dyn Fn(&Run) -> f64| median(of.iter().map(|r| f(r)).collect());
        let (wall, wlo, whi) = stat(&|r: &Run| r.wall.as_secs_f64());
        let (guest, glo, ghi) = stat(&|r: &Run| r.guest.as_secs_f64());
        let (comp, clo, chi) = stat(&|r: &Run| r.compression());
        let (paused, _, _) = stat(&|r: &Run| r.paused_share() * 100.0);
        let (warps, _, _) = stat(&|r: &Run| r.stats.warps as f64);
        let (jump, _, _) = stat(&|r: &Run| r.mean_jump().as_secs_f64() * 1e3);
        let top = of
            .iter()
            .flat_map(|r| r.stats.declines.iter())
            .fold(BTreeMap::<&str, u64>::new(), |mut acc, (k, v)| {
                *acc.entry(k.as_str()).or_default() += v;
                acc
            })
            .into_iter()
            .max_by_key(|(_, v)| *v)
            .map_or_else(|| "none".to_string(), |(k, v)| format!("{k}={v}"));
        eprintln!(
            "| {} | {wall:.0} ({wlo:.0}–{whi:.0}) | {guest:.0} ({glo:.0}–{ghi:.0}) | \
             {comp:.2}× ({clo:.2}–{chi:.2}) | {paused:.2} | {warps:.0} | {jump:.0} ms | {top} |",
            arm.as_str()
        );
    }

    eprintln!("\nPer phase (median compression, wall seconds):\n");
    let names: Vec<&'static str> = runs
        .first()
        .map(|r| r.phases.iter().map(|p| p.name).collect())
        .unwrap_or_default();
    // A row per (arm, phase) rather than a column per arm, so a run of
    // one arm prints its own half of the table instead of NaNs.
    eprintln!("| arm | phase | wall (s) | guest (s) | compression | warps |");
    eprintln!("|---|---|---|---|---|---|");
    for arm in ALL_ARMS {
        for (i, name) in names.iter().enumerate() {
            let per = |f: &dyn Fn(&Phase) -> f64| {
                median(
                    runs.iter()
                        .filter(|r| r.arm == arm)
                        .map(|r| f(&r.phases[i]))
                        .collect(),
                )
                .0
            };
            if per(&|p: &Phase| p.wall.as_secs_f64()).is_nan() {
                continue;
            }
            eprintln!(
                "| {} | {name} | {:.0} | {:.0} | {:.2}× | {:.0} |",
                arm.as_str(),
                per(&|p: &Phase| p.wall.as_secs_f64()),
                per(&|p: &Phase| p.guest.as_secs_f64()),
                per(&|p: &Phase| p.compression()),
                per(&|p: &Phase| p.warps as f64),
            );
        }
    }

    eprintln!("\nFidelity (medians; the deltas vs arm A are the distortion cost):\n");
    eprintln!(
        "| arm | probe failures | unscripted restarts | NotReady lapses | splats | \
         in-guest churn rounds |"
    );
    eprintln!("|---|---|---|---|---|---|");
    for arm in ALL_ARMS {
        let of: Vec<&Run> = runs.iter().filter(|r| r.arm == arm).collect();
        if of.is_empty() {
            continue;
        }
        let stat = |f: &dyn Fn(&Run) -> f64| median(of.iter().map(|r| f(r)).collect()).0;
        eprintln!(
            "| {} | {:.0} | {:.0} | {:.0} | {:.0} | {:.0} |",
            arm.as_str(),
            stat(&|r: &Run| r.fidelity.probe_failures as f64),
            stat(&|r: &Run| r.fidelity.excess_restarts as f64),
            stat(&|r: &Run| f64::from(r.fidelity.notready_lapses)),
            stat(&|r: &Run| r.fidelity.splats as f64),
            stat(&|r: &Run| r.fidelity.churn_rounds as f64),
        );
    }
}

/// Between runs: the cluster is gone, but its pods' images are still in
/// the node's page cache and its bridge may still be in the kernel's
/// tables. Sweep what a fresh bring-up would otherwise inherit, so no
/// two arms are compared from different node states (trap 1).
fn between_runs() {
    let _ = k7d::network::cleanup_stale_k7_bridges();
    // Let the node's TAP/bridge teardown and the guests' dirty pages
    // settle before the next bring-up measures its own boot.
    let _ = Command::new("sync").status();
    std::thread::sleep(Duration::from_secs(10));
}

fn main() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .try_init();

    let arms: Vec<Arm> = std::env::args()
        .find_map(|a| a.strip_prefix("--arms=").map(str::to_string))
        .map_or_else(
            || ALL_ARMS.to_vec(),
            |list| {
                list.split(',')
                    .map(|a| {
                        *ALL_ARMS
                            .iter()
                            .find(|arm| arm.tag() == a)
                            .unwrap_or_else(|| panic!("unknown arm {a:?}: this bench has a–d"))
                    })
                    .collect()
            },
        );

    // Arms C and D need the carried patch loaded and A and B need it
    // gone, and the two sets cannot share a process: KVM's modules are
    // swapped between them (`utils/kvm-dilation/{install,revert}.sh`).
    // Checking up front means a mixed request fails before the first
    // 9-minute run rather than after it.
    let dilating = arms.iter().any(|a| a.dilation() > 1);
    let plain = arms.iter().any(|a| a.dilation() == 1);
    let patched = k7d::vm::host_supports_dilation();
    assert!(
        !(dilating && plain),
        "arms {:?} mix dilated and undilated arms in one process, but they need different \
         KVM modules loaded — run `--arms=a,b` on stock and `--arms=c,d` on patched",
        arms.iter().map(|a| a.tag()).collect::<Vec<_>>()
    );
    if dilating {
        patched.unwrap_or_else(|e| {
            panic!(
                "arms c/d need the carried dilation patch ({e}) — \
                 run `bash utils/kvm-dilation/install.sh` first"
            )
        });
    } else {
        assert!(
            patched.is_err(),
            "arms a/b are the stock-module baseline and this host is running the carried \
             dilation patch — `bash utils/kvm-dilation/revert.sh` first"
        );
    }

    let mut runs = Vec::new();
    // Arm A first, in full: its runtime is what decides whether this is
    // a bench target at all, and a baseline measured after the policy
    // has churned the node is not a baseline.
    for arm in arms {
        for index in 0..RUNS {
            eprintln!("\n==> arm {} run {}/{RUNS}\n", arm.as_str(), index + 1);
            runs.push(run_arm(arm, index));
            between_runs();
        }
    }
    print_tables(&runs);
}
