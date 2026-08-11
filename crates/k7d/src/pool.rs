//! Warm VM pool (internal notes/ internal notes, adapted
//! to the daemon architecture): the daemon keeps `size` pre-booted,
//! agent-ready VMs so a pool-compatible `create_vm` hands out a running
//! VM in well under 100 ms ([`crate::latency::POOL_ACQUIRE`]) instead
//! of paying the full kernel-boot latency.
//!
//! # Design decision: fork-workload-only pool
//!
//! Virtio-fs devices are fixed at boot (virtio-mmio has no hot-plug)
//! and the fork/restore path intentionally does not respawn virtiofsd
//! for snapshotted shares (see `fork.rs`). Swapping the vhost-user
//! backend under a placeholder share would require implementing
//! vhost-user session re-negotiation in the VMM — real surgery, out of
//! scope for this increment. So the pool serves **fork/tree-style
//! workloads only**: vsock-only VMs with no virtiofs shares and no
//! network. `create_vm` requests carrying `virtiofs` entries or a
//! `network` config bypass the pool and cold-boot exactly as before
//! ([`Pool::compatible`] is the single gate).
//!
//! # Mechanics
//!
//! [`Pool::start`] spawns one background *filler* thread that boots the
//! template VM, waits for its agent, prepares it as a fork source once
//! (`prepare_fork_source` — cold snapshot + restore + dirty tracking),
//! then keeps the idle list topped up with warm forks, each verified
//! agent-ready before it becomes acquirable. [`Pool::acquire`] pops an
//! idle VM and wakes the filler; an empty pool returns `None` so the
//! caller cold-boots — a pod create is never blocked on a refill.
//!
//! Acquired VMs are **never returned** to the pool ([`Pool::release`]
//! just destroys them): forks are cheap and reuse would be a
//! cross-tenant leak risk.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::config::PoolConfig;
use crate::control::VmConfig;
use crate::vm::Vm;

/// How long the filler waits for the *template's* guest agent to come
/// up at cold boot, polled in short slices so shutdown stays prompt.
const TEMPLATE_AGENT_TIMEOUT: Duration = Duration::from_secs(90);

/// Snapshot of pool sizing and counters for the `pool_status` op.
#[derive(Debug, Default, Clone, Copy)]
pub struct PoolStatus {
    /// Configured target of idle warm VMs (0 = pool disabled).
    pub size: usize,
    /// Idle agent-ready VMs currently acquirable.
    pub idle: usize,
    /// `create_vm` requests served from the pool.
    pub hits: u64,
    /// Pool-enabled `create_vm` requests NOT served from the pool
    /// (incompatible config, or the pool was momentarily empty).
    pub misses: u64,
}

/// State shared between the pool handle and the filler thread.
struct PoolShared {
    /// Idle, agent-ready warm forks awaiting [`Pool::acquire`].
    idle: Mutex<Vec<Vm>>,
    /// Wakes the filler after an acquire (refill) or on shutdown.
    wakeup: Condvar,
    shutdown: AtomicBool,
    hits: AtomicU64,
    misses: AtomicU64,
}

/// The warm pool. One per daemon, created at startup when
/// `K7D_POOL_SIZE > 0` ([`PoolConfig::from_env`]).
pub struct Pool {
    config: PoolConfig,
    shared: Arc<PoolShared>,
    /// Filler thread handle; the template VM lives on that thread's
    /// stack until shutdown. `Mutex<Option<..>>` so [`Pool::shutdown`]
    /// works through `&self` (the daemon holds the pool in an `Arc`).
    filler: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl Pool {
    /// Create the pool and start its background filler thread. Returns
    /// immediately — template boot and pre-warming never block daemon
    /// startup.
    #[must_use]
    pub fn start(config: PoolConfig) -> Self {
        let shared = Arc::new(PoolShared {
            idle: Mutex::new(Vec::with_capacity(config.size)),
            wakeup: Condvar::new(),
            shutdown: AtomicBool::new(false),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        });
        let filler = {
            let shared = Arc::clone(&shared);
            let config = config.clone();
            std::thread::Builder::new()
                .name("k7d-pool-filler".to_string())
                .spawn(move || run_filler(&config, &shared))
                .expect("spawn pool filler thread")
        };
        Self {
            config,
            shared,
            filler: Mutex::new(Some(filler)),
        }
    }

    /// Whether a `create_vm` request can be served from this pool:
    /// vsock-only (no virtiofs, no virtio-blk, no guest dirs, no
    /// network — see the module docs for why; block devices and
    /// `k7d.mkdir=` dirs are declared on the kernel cmdline at boot,
    /// which a pre-booted VM can't retrofit — internal notes), same
    /// memory size, same vCPU count as the pool's prefill config
    /// (internal notes: the operator chooses the pool's vCPU count via
    /// `K7D_POOL_VCPUS`; default 1), no CPU cap (internal notes: pooled VMs
    /// are pre-booted uncapped; a request carrying a quota must
    /// cold-boot so the cap is actually applied), and the same
    /// kernel/initrd the template booted.
    #[must_use]
    pub fn compatible(&self, config: &VmConfig) -> bool {
        if !config.vsock
            || !config.virtiofs.is_empty()
            || !config.block_devices.is_empty()
            || !config.guest_dirs.is_empty()
            || config.network.is_some()
            || config.memory_mb != self.config.memory_mb
            || config.vcpus != self.config.vcpus
            || config.cpu_quota.is_some()
        {
            return false;
        }
        let Ok((kernel, initrd)) =
            crate::config::resolve_guest_paths(config.kernel.as_deref(), config.initrd.as_deref())
        else {
            // Unresolvable paths fail loudly on the cold path.
            return false;
        };
        same_path(&kernel, &self.config.kernel) && same_path(&initrd, &self.config.initrd)
    }

    /// Hand out one idle, agent-ready VM and wake the filler to refill
    /// back to target. `None` when the pool is empty — the caller must
    /// cold-boot (never block a pod create on a refill).
    #[must_use]
    pub fn acquire(&self) -> Option<Vm> {
        let vm = self.shared.idle.lock().unwrap().pop();
        if let Some(vm) = vm {
            self.shared.hits.fetch_add(1, Ordering::SeqCst);
            self.shared.wakeup.notify_all();
            log::info!(
                "pool: acquired warm VM (guest_cid={}); refill triggered",
                vm.guest_cid()
            );
            Some(vm)
        } else {
            self.note_miss();
            None
        }
    }

    /// Count one pool miss (incompatible request, or [`Pool::acquire`]
    /// found the pool empty — the latter records it itself).
    pub fn note_miss(&self) {
        self.shared.misses.fetch_add(1, Ordering::SeqCst);
    }

    /// Destroy a pool-acquired VM and free its resources (`Vm::drop`
    /// tears down the vCPU thread and device workers). Pooled VMs are
    /// never returned to the pool — forks are cheap and reuse is a
    /// cross-tenant leak risk. Equivalent to dropping `vm`.
    pub fn release(vm: Vm) {
        log::info!("pool: releasing VM (guest_cid={})", vm.guest_cid());
        drop(vm);
    }

    /// Current sizing + hit/miss counters.
    #[must_use]
    pub fn status(&self) -> PoolStatus {
        PoolStatus {
            size: self.config.size,
            idle: self.shared.idle.lock().unwrap().len(),
            hits: self.shared.hits.load(Ordering::SeqCst),
            misses: self.shared.misses.load(Ordering::SeqCst),
        }
    }

    /// Tear the pool down: stop the filler (which drops the template
    /// VM) and destroy every idle VM. Idempotent; also runs on `Drop`.
    pub fn shutdown(&self) {
        self.shared.shutdown.store(true, Ordering::SeqCst);
        self.shared.wakeup.notify_all();
        if let Some(handle) = self.filler.lock().unwrap().take() {
            if let Err(e) = handle.join() {
                log::error!("pool: filler thread panicked: {e:?}");
            }
        }
        let drained: Vec<Vm> = self.shared.idle.lock().unwrap().drain(..).collect();
        for vm in drained {
            log::info!(
                "pool: shutdown dropping idle VM (guest_cid={})",
                vm.guest_cid()
            );
            drop(vm);
        }
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Path equality after canonicalization (falls back to string equality
/// when a path does not resolve — the cold path will report that
/// loudly).
fn same_path(a: &str, b: &str) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => a == b,
    }
}

/// Filler thread body: boot + prepare the template, then keep the idle
/// list topped up until shutdown. The template `Vm` lives here so its
/// teardown is unambiguous (thread exit drops it).
fn run_filler(config: &PoolConfig, shared: &PoolShared) {
    let mut template = match boot_template(config, shared) {
        Ok(Some(vm)) => vm,
        Ok(None) => return, // shutdown during boot
        Err(e) => {
            log::error!(
                "pool: template boot failed — pool stays EMPTY, every request cold-boots: {e}"
            );
            return;
        }
    };
    log::info!(
        "pool: template ready (guest_cid={}); pre-warming {} VM(s)",
        template.guest_cid(),
        config.size
    );

    let mut fork_seq: u64 = 0;
    while !shared.shutdown.load(Ordering::SeqCst) {
        // Wait until the idle list is below target (or shutdown).
        {
            let mut idle = shared.idle.lock().unwrap();
            while idle.len() >= config.size && !shared.shutdown.load(Ordering::SeqCst) {
                let (guard, _) = shared
                    .wakeup
                    .wait_timeout(idle, Duration::from_millis(500))
                    .unwrap();
                idle = guard;
            }
            if shared.shutdown.load(Ordering::SeqCst) {
                break;
            }
        }

        // Fork + verify outside the idle lock — acquire must never wait
        // on a refill in progress.
        let fork_id = format!("pool-{}-{fork_seq}", std::process::id());
        fork_seq += 1;
        match fork_ready_vm(&mut template, &fork_id) {
            Ok(fork) => {
                let mut idle = shared.idle.lock().unwrap();
                idle.push(fork);
                log::info!("pool: warm VM ready ({}/{} idle)", idle.len(), config.size);
            }
            Err(e) => {
                log::error!("pool: refill fork {fork_id} failed: {e}");
                // Back off so a persistent failure doesn't spin the CPU.
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
    log::info!(
        "pool: filler stopping; dropping template (guest_cid={})",
        template.guest_cid()
    );
}

/// Boot the template VM, wait for its agent, and prepare it as a fork
/// source. Returns `Ok(None)` when shutdown was requested mid-boot.
fn boot_template(config: &PoolConfig, shared: &PoolShared) -> Result<Option<Vm>, String> {
    let mut vm = Vm::builder()
        .kernel(&config.kernel)
        .initrd(&config.initrd)
        .memory_mb(config.memory_mb)
        .vcpus(config.vcpus)
        .vsock(true)
        .build()
        .map_err(|e| format!("build template VM: {e}"))?;
    vm.start().map_err(|e| format!("start template VM: {e}"))?;

    // Wait agent-ready in short slices so a daemon shutdown during the
    // boot doesn't leave `Pool::shutdown` joining a 90 s wait.
    let deadline = Instant::now() + TEMPLATE_AGENT_TIMEOUT;
    let agent = loop {
        if shared.shutdown.load(Ordering::SeqCst) {
            return Ok(None);
        }
        match vm.connect_agent(Duration::from_secs(2)) {
            Ok(agent) => break agent,
            Err(e) if Instant::now() >= deadline => {
                return Err(format!("template agent never became ready: {e}"));
            }
            Err(_) => {}
        }
    };

    // Keep the agent connection open across the fork-source snapshot so
    // the guest's vsock state has an established connection for the
    // injected TRANSPORT_RESET to reset (the internal notes�
    // see `Daemon::boot_tree_member`), then drop it.
    vm.prepare_fork_source()
        .map_err(|e| format!("prepare template as fork source: {e}"))?;
    drop(agent);

    // prepare_fork_source replaced the template with a restored copy on
    // a fresh CID — every fork inherits that state, so prove the agent
    // answers before pre-warming from it.
    vm.connect_agent(Duration::from_secs(30))
        .and_then(|mut agent| agent.ping().map(|_| ()).map_err(crate::vm::VmError::Agent))
        .map_err(|e| format!("template agent dead after prepare_fork_source: {e}"))?;
    Ok(Some(vm))
}

/// Warm-fork one VM off the template, start it, and verify its agent
/// answers a ping — only agent-ready VMs may enter the idle list
/// (acquire hands them out with zero further wait).
fn fork_ready_vm(template: &mut Vm, fork_id: &str) -> Result<Vm, String> {
    let mut fork = template
        .fork_warm(fork_id)
        .map_err(|e| format!("fork_warm: {e}"))?;
    // fork_warm hands the fork back paused; it runs from here.
    fork.start().map_err(|e| format!("start fork: {e}"))?;
    fork.connect_agent(crate::latency::FORK_AGENT_RECONNECT)
        .and_then(|mut agent| agent.ping().map(|_| ()).map_err(crate::vm::VmError::Agent))
        .map_err(|e| format!("fork agent (cid {}) not ready: {e}", fork.guest_cid()))?;
    Ok(fork)
}
