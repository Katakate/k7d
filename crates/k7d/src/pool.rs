//! Warm VM pool (adapted
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
//! scope for now. So the pool serves **fork/tree-style
//! workloads only**: vsock-only VMs with no virtiofs shares, no
//! network, no data disks, and stock (1×) kvmclock. `create_vm`
//! requests carrying `virtiofs` entries, a `network` config, a
//! non-empty `data_disks`, or `dilation` other than 1× bypass the
//! pool and cold-boot exactly as before ([`Pool::compatible`] is
//! the single gate).
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
use crate::guest::{Backend, Guest};

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
    idle: Mutex<Vec<Guest>>,
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

    /// Handle with no filler thread, for [`Pool::compatible`] unit tests.
    #[cfg(test)]
    #[must_use]
    fn for_tests(config: PoolConfig) -> Self {
        Self {
            config,
            shared: Arc::new(PoolShared {
                idle: Mutex::new(Vec::new()),
                wakeup: Condvar::new(),
                shutdown: AtomicBool::new(true),
                hits: AtomicU64::new(0),
                misses: AtomicU64::new(0),
            }),
            filler: Mutex::new(None),
        }
    }

    /// Whether a `create_vm` request can be served from this pool:
    /// vsock-only (no virtiofs, no virtio-blk, no guest dirs, no
    /// network, no data disks — see the module docs for why; block
    /// devices and `k7d.mkdir=` dirs are declared on the kernel cmdline
    /// at boot, which a pre-booted VM can't retrofit —), same
    /// memory size, same vCPU count as the pool's prefill config
    /// (the operator chooses the pool's vCPU count via
    /// `K7D_POOL_VCPUS`; default 1), no CPU cap (pooled VMs
    /// are pre-booted uncapped; a request carrying a quota must
    /// cold-boot so the cap is actually applied), no scratch disk
    /// (the scratch device is another boot-time virtio-blk
    /// declaration, and serving such a request from the pool would
    /// hand back a VM whose containers write to RAM), no time
    /// dilation other than 1× (`None` / `Some(1)` — a pooled VM
    /// is stock kvmclock and cannot be retrofitted), and the same
    /// kernel/initrd the template booted.
    ///
    /// Every [`VmConfig`] field is named in the destructure: adding a
    /// field is a compile error until it is classified pool-ok or miss.
    /// `cpu_period` only travels with `cpu_quota` (the quota gate
    /// covers it). `sandbox_id` is identity, not construction.
    #[must_use]
    pub fn compatible(&self, config: &VmConfig) -> bool {
        let VmConfig {
            kernel,
            initrd,
            cmdline,
            memory_mb,
            vcpus,
            cpu_quota,
            cpu_period: _,
            vsock,
            virtiofs,
            block_devices,
            guest_dirs,
            scratch_size_bytes,
            container_scratch,
            data_disks,
            docker,
            sandbox_id: _,
            network,
            dilation,
            backend,
            transport,
        } = config;
        // Pooled VMs are pre-booted on virtio-mmio; a bus is a boot-time
        // property, so a PCI request always cold-boots.
        if *transport != crate::virtio_mmio::Transport::Mmio {
            return false;
        }
        let has_backend = match backend {
            Backend::Native => self.config.native_size > 0,
            Backend::Firecracker => self.config.fc_size > 0,
        };
        if !has_backend
            || !vsock
            || !virtiofs.is_empty()
            || !block_devices.is_empty()
            || !guest_dirs.is_empty()
            || scratch_size_bytes.is_some()
            || !container_scratch.is_empty()
            || docker.is_some()
            || network.is_some()
            || *memory_mb != self.config.memory_mb
            || *vcpus != self.config.vcpus
            || cpu_quota.is_some()
            || cmdline.is_some()
            || !data_disks.is_empty()
            || !matches!(dilation, None | Some(1))
        {
            return false;
        }
        let Ok((kernel, initrd)) =
            crate::config::resolve_guest_paths(kernel.as_deref(), initrd.as_deref())
        else {
            // Unresolvable paths fail loudly on the cold path.
            return false;
        };
        same_path(&kernel, &self.config.kernel) && same_path(&initrd, &self.config.initrd)
    }

    /// Hand out one idle, agent-ready VM of `backend` and wake the
    /// filler to refill back to target. `None` when no matching idle
    /// member — the caller must cold-boot (never block a pod create on
    /// a refill).
    #[must_use]
    pub fn acquire(&self, backend: Backend) -> Option<Guest> {
        let vm = {
            let mut idle = self.shared.idle.lock().unwrap();
            idle.iter()
                .rposition(|g| g.backend() == backend)
                .map(|i| idle.remove(i))
        };
        if let Some(vm) = vm {
            self.shared.hits.fetch_add(1, Ordering::SeqCst);
            self.shared.wakeup.notify_all();
            log::info!(
                "pool: acquired warm {:?} VM (guest_cid={:?}); refill triggered",
                backend,
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
    pub fn release(vm: Guest) {
        log::info!("pool: releasing VM (guest_cid={:?})", vm.guest_cid());
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
        let drained: Vec<Guest> = self.shared.idle.lock().unwrap().drain(..).collect();
        for vm in drained {
            log::info!(
                "pool: shutdown dropping idle VM (guest_cid={:?})",
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
    let mut native_tpl = if config.native_size > 0 {
        match boot_template(config, shared) {
            Ok(Some(vm)) => Some(vm),
            Ok(None) => return,
            Err(e) => {
                log::error!("pool: native template boot failed — native slot stays EMPTY: {e}");
                None
            }
        }
    } else {
        None
    };
    let mut fc_tpl = if config.fc_size > 0 {
        match boot_fc_template(config, shared) {
            Ok(Some(vm)) => Some(vm),
            Ok(None) => return,
            Err(e) => {
                log::error!("pool: firecracker template boot failed — fc slot stays EMPTY: {e}");
                None
            }
        }
    } else {
        None
    };
    if native_tpl.is_none() && fc_tpl.is_none() {
        log::error!("pool: no template ready — pool stays EMPTY, every request cold-boots");
        return;
    }
    log::info!(
        "pool: templates ready (native={} fc={}); pre-warming {} VM(s)",
        native_tpl.as_ref().and_then(Guest::guest_cid).is_some(),
        fc_tpl.is_some(),
        config.size
    );

    let mut fork_seq: u64 = 0;
    while !shared.shutdown.load(Ordering::SeqCst) {
        let (need_native, need_fc) = {
            let mut idle = shared.idle.lock().unwrap();
            loop {
                let n = idle
                    .iter()
                    .filter(|g| g.backend() == Backend::Native)
                    .count();
                let f = idle
                    .iter()
                    .filter(|g| g.backend() == Backend::Firecracker)
                    .count();
                let full_native = n >= config.native_size || native_tpl.is_none();
                let full_fc = f >= config.fc_size || fc_tpl.is_none();
                if full_native && full_fc && !shared.shutdown.load(Ordering::SeqCst) {
                    let (guard, _) = shared
                        .wakeup
                        .wait_timeout(idle, Duration::from_millis(500))
                        .unwrap();
                    idle = guard;
                    continue;
                }
                break (
                    n < config.native_size && native_tpl.is_some(),
                    f < config.fc_size && fc_tpl.is_some(),
                );
            }
        };
        if shared.shutdown.load(Ordering::SeqCst) {
            break;
        }

        let fork_id = format!("pool-{}-{fork_seq}", std::process::id());
        fork_seq += 1;
        let result = if need_native {
            native_tpl.as_mut().map(|t| fork_ready_vm(t, &fork_id))
        } else if need_fc {
            fc_tpl.as_mut().map(|t| fork_ready_vm(t, &fork_id))
        } else {
            None
        };
        match result {
            Some(Ok(fork)) => {
                let mut idle = shared.idle.lock().unwrap();
                idle.push(fork);
                log::info!("pool: warm VM ready ({}/{} idle)", idle.len(), config.size);
            }
            Some(Err(e)) => {
                log::error!("pool: refill fork {fork_id} failed: {e}");
                std::thread::sleep(Duration::from_secs(1));
            }
            None => {}
        }
    }
    log::info!("pool: filler stopping; dropping templates");
}

/// Boot the template VM, wait for its agent, and prepare it as a fork
/// source. Returns `Ok(None)` when shutdown was requested mid-boot.
fn boot_template(config: &PoolConfig, shared: &PoolShared) -> Result<Option<Guest>, String> {
    let mut vm = Guest::from(
        crate::vm::Vm::builder()
            .kernel(&config.kernel)
            .initrd(&config.initrd)
            .memory_mb(config.memory_mb)
            .vcpus(config.vcpus)
            .vsock(true)
            .build()
            .map_err(|e| format!("build template VM: {e}"))?,
    );
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
    // injected TRANSPORT_RESET to reset (the pattern —
    // see `Daemon::boot_tree_member`), then drop it.
    vm.prepare_fork_source()
        .map_err(|e| format!("prepare template as fork source: {e}"))?;
    drop(agent);

    // prepare_fork_source replaced the template with a restored copy on
    // a fresh CID — every fork inherits that state, so prove the agent
    // answers before pre-warming from it.
    vm.connect_agent(Duration::from_secs(30))
        .and_then(|mut agent| {
            agent
                .ping()
                .map(|_| ())
                .map_err(|e| crate::guest::GuestError::Vm(crate::vm::VmError::Agent(e)))
        })
        .map_err(|e| format!("template agent dead after prepare_fork_source: {e}"))?;
    Ok(Some(vm))
}

fn boot_fc_template(config: &PoolConfig, shared: &PoolShared) -> Result<Option<Guest>, String> {
    let fc_config = crate::fc::FcConfig {
        vm_id: format!("pool-fc-tpl-{}", std::process::id()),
        memory_mb: config.memory_mb,
        vcpus: config.vcpus,
        kernel: std::path::PathBuf::from(&config.kernel),
        initrd: Some(std::path::PathBuf::from(&config.initrd)),
        cmdline: crate::vm::DEFAULT_GUEST_CMDLINE.to_string(),
        cpu_quota_us: None,
        cpu_period_us: None,
        drives: Vec::new(),
        net: None,
        track_dirty_pages: true,
    };
    let mut vm = Guest::from(
        crate::fc::FcVm::create(&fc_config, None)
            .map_err(|e| format!("build firecracker template: {e}"))?,
    );
    vm.start()
        .map_err(|e| format!("start firecracker template: {e}"))?;

    let deadline = Instant::now() + TEMPLATE_AGENT_TIMEOUT;
    let agent = loop {
        if shared.shutdown.load(Ordering::SeqCst) {
            return Ok(None);
        }
        match vm.connect_agent(Duration::from_secs(2)) {
            Ok(agent) => break agent,
            Err(e) if Instant::now() >= deadline => {
                return Err(format!(
                    "firecracker template agent never became ready: {e}"
                ));
            }
            Err(_) => {}
        }
    };
    vm.prepare_fork_source()
        .map_err(|e| format!("prepare firecracker template as fork source: {e}"))?;
    drop(agent);
    vm.connect_agent(Duration::from_secs(30))
        .and_then(|mut agent| {
            agent.ping().map(|_| ()).map_err(|e| {
                crate::guest::GuestError::Fc(crate::fc::FcError::Agent {
                    path: std::path::PathBuf::from("pool-fc-tpl"),
                    message: e.to_string(),
                })
            })
        })
        .map_err(|e| format!("firecracker template agent dead after prepare_fork_source: {e}"))?;
    Ok(Some(vm))
}

/// Warm-fork one VM off the template, start it, and verify its agent
/// answers a ping — only agent-ready VMs may enter the idle list
/// (acquire hands them out with zero further wait).
fn fork_ready_vm(template: &mut Guest, fork_id: &str) -> Result<Guest, String> {
    let mut forks = template
        .fork_batch(&[fork_id], None)
        .map_err(|e| format!("fork_warm: {e}"))?;
    let mut fork = forks.pop().expect("single fork");
    // Native fork_warm hands the fork back paused. Firecracker children
    // load with `resume_vm: true` and are already running — InstanceStart
    // on a running VM fails.
    if !fork.is_running() {
        fork.start().map_err(|e| format!("start fork: {e}"))?;
    }
    fork.connect_agent(crate::latency::FORK_AGENT_RECONNECT)
        .and_then(|mut agent| {
            agent
                .ping()
                .map(|_| ())
                .map_err(|e| crate::guest::GuestError::Vm(crate::vm::VmError::Agent(e)))
        })
        .map_err(|e| format!("fork agent (cid {:?}) not ready: {e}", fork.guest_cid()))?;
    Ok(fork)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{DataDiskConfig, VmConfig};
    use crate::guest::Backend;

    fn native_pool() -> Pool {
        Pool::for_tests(PoolConfig {
            size: 1,
            memory_mb: 256,
            vcpus: 1,
            kernel: "/tmp/k7d-pool-pred-kernel".into(),
            initrd: "/tmp/k7d-pool-pred-initrd".into(),
            native_size: 1,
            fc_size: 0,
        })
    }

    fn fc_pool() -> Pool {
        Pool::for_tests(PoolConfig {
            size: 1,
            memory_mb: 256,
            vcpus: 1,
            kernel: "/tmp/k7d-pool-pred-kernel".into(),
            initrd: "/tmp/k7d-pool-pred-initrd".into(),
            native_size: 0,
            fc_size: 1,
        })
    }

    fn hit_config() -> VmConfig {
        VmConfig {
            kernel: Some("/tmp/k7d-pool-pred-kernel".into()),
            initrd: Some("/tmp/k7d-pool-pred-initrd".into()),
            ..VmConfig::default()
        }
    }

    #[test]
    fn compatible_sees_every_vmconfig_field() {
        let pool = native_pool();
        assert!(
            pool.compatible(&hit_config()),
            "stock vsock request must hit"
        );

        let mut dilation_one = hit_config();
        dilation_one.dilation = Some(1);
        assert!(pool.compatible(&dilation_one), "Some(1) is 1× and pool-ok");

        let mut sandbox = hit_config();
        sandbox.sandbox_id = Some("sb-identity".into());
        assert!(
            pool.compatible(&sandbox),
            "sandbox_id is identity, not construction"
        );

        let mut period = hit_config();
        period.cpu_period = Some(100_000);
        assert!(
            pool.compatible(&period),
            "cpu_period without quota is masked by the quota gate"
        );

        let mut dilated = hit_config();
        dilated.dilation = Some(10);
        assert!(!pool.compatible(&dilated), "dilation != 1 must miss");

        let mut disks = hit_config();
        disks.data_disks = vec![DataDiskConfig {
            id: "d0".into(),
            size_bytes: 16 * 1024 * 1024,
            guest_mount: "/mnt/d0".into(),
        }];
        assert!(!pool.compatible(&disks), "data_disks must miss");

        let fc = fc_pool();
        let mut fc_cfg = hit_config();
        fc_cfg.backend = Backend::Firecracker;
        assert!(fc.compatible(&fc_cfg), "plain FC request hits an FC pool");
        fc_cfg.dilation = Some(10);
        assert!(
            !fc.compatible(&fc_cfg),
            "FC+dilation must miss so deny_fc_unsupported can fire on the cold path"
        );
        assert!(
            !pool.compatible(&fc_cfg),
            "FC request must miss a native-only pool"
        );
    }
}
