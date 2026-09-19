//! `k7d` daemon entrypoint.
//!
//! Long-running, one per node, root. Owns VM lifecycle and serves the
//! control plane. VMs it creates outlive
//! any single client (shim), which is what the warm pool, cluster
//! snapshot tree, and crash recovery all require.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use k7d::control::{self, Daemon};

/// Set by the SIGTERM/SIGINT handler to break the serve loop.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
    // systemd signals the whole cgroup, so the spawner is being asked to
    // stop at the same moment. Tell its watchdog that, or the race
    // between the two makes an ordinary `systemctl restart` exit 1
    // (CHALLENGES #245).
    k7d::spawner::mark_shutting_down();
}

fn install_signal_handlers() {
    // SAFETY: `on_signal` only stores to an atomic — async-signal-safe.
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as libc::sighandler_t);
    }
}

/// Resolve the control-socket path: `--socket <path>`, else env
/// `K7D_SOCKET`, else the default.
fn socket_path() -> String {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--socket" {
            if let Some(p) = args.next() {
                return p;
            }
        } else if let Some(p) = arg.strip_prefix("--socket=") {
            return p.to_string();
        }
    }
    control::socket_path_from_env()
}

/// `--version` / `--help` / `doctor` / `quickstart` must be answered
/// before anything else happens. Without this they fell through to
/// "start a daemon", so an operator checking which version was
/// installed booted a second daemon that took the control socket from
/// the running one and deleted it on the way out.
fn handle_info_flags() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "doctor") {
        run_doctor();
    }
    if args.iter().any(|a| a == "quickstart") {
        run_quickstart(&args);
    }
    for arg in &args {
        match arg.as_str() {
            "--version" | "-V" => {
                println!("k7d {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--help" | "-h" => {
                println!(
                    "k7d {} — microVM runtime daemon (one per node, root)\n\n\
                     Usage:\n\
                     \x20 k7d [--socket <path>]     start the daemon\n\
                     \x20 k7d doctor                check /dev/kvm, vhost-vsock, tun, cgroup v2\n\
                     \x20 k7d quickstart            busybox 3-node tree + 4 forks (needs a running daemon)\n\n\
                     Options:\n\
                     \x20 --socket <path>  control socket (default: {}; env K7D_SOCKET)\n\
                     \x20 -V, --version    print version and exit\n\
                     \x20 -h, --help       print this help and exit\n\n\
                     Guest artifacts are required and come from the environment:\n\
                     \x20 K7D_KERNEL       guest kernel (vmlinux)\n\
                     \x20 K7D_INITRD       guest initramfs\n\n\
                     Five-minute try path (fetches the release tarball):\n\
                     \x20 sudo ./scripts/quickstart.sh\n",
                    env!("CARGO_PKG_VERSION"),
                    control::DEFAULT_SOCKET,
                );
                std::process::exit(0);
            }
            _ => {}
        }
    }
}

fn run_doctor() {
    let report = k7d::doctor::run();
    let code = k7d::doctor::print_and_exit_code(&report);
    std::process::exit(code);
}

fn run_quickstart(args: &[String]) {
    let keep = args.iter().any(|a| a == "--keep");
    let report = k7d::doctor::run();
    let code = k7d::doctor::print_and_exit_code(&report);
    if code != 0 {
        std::process::exit(code);
    }

    let socket = socket_path();
    let mut client = match k7d::control::Client::connect(&socket) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "quickstart: cannot connect to {socket}: {e}\n\
                 start the daemon first (`sudo k7d` or `systemctl start k7d`),\n\
                 or run `sudo ./scripts/quickstart.sh` to fetch + install + boot"
            );
            std::process::exit(1);
        }
    };
    match client.call(&k7d::control::Request::Ping) {
        Ok(k7d::control::Response::Pong { version, .. }) => {
            println!("quickstart: k7d {version} at {socket}");
        }
        Ok(other) => {
            eprintln!("quickstart: ping: unexpected {other:?}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("quickstart: ping {socket}: {e}");
            std::process::exit(1);
        }
    }

    let tree_id = format!("qs-{}", std::process::id());
    match k7d::quickstart::run_busybox_demo(&mut client, &tree_id, 4, keep, None, None) {
        Ok(clocks) => {
            k7d::quickstart::print_clocks(&clocks);
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("quickstart: {e}");
            std::process::exit(1);
        }
    }
}

/// Put the snapshot-tree root on the reflink XFS and say so in the log.
///
/// Not fatal: a tree on ext4 still works, it just pays a full guest-RAM
/// dump for every keyframe instead of cloning its ancestor's. The
/// per-keyframe fallback is loud on its own, so the point of doing it
/// here is that an operator reading the startup log knows which regime
/// the node is in before the first fork.
fn prepare_tree_root() {
    // An operator who pointed `K7D_TREE_ROOT` somewhere specific owns
    // that path; probe it and report, but never relocate it.
    if let Ok(custom) = std::env::var("K7D_TREE_ROOT") {
        match k7d::disks::assert_reflink_capable(std::path::Path::new(&custom)) {
            Ok(()) => log::info!("tree root {custom} (K7D_TREE_ROOT) is reflink-capable"),
            Err(e) => log::warn!(
                "tree root {custom} (K7D_TREE_ROOT) is NOT reflink-capable ({e}) — every \
                 snapshot-tree keyframe there costs a full guest-RAM dump"
            ),
        }
        return;
    }
    if let Err(e) = k7d::disks::ensure_reflink_tree_root() {
        log::warn!(
            "could not put the snapshot-tree root on the reflink XFS ({e}) — keyframes \
             will fall back to full guest-RAM dumps; run \
             `your node provisioning` on this node"
        );
    }
}

/// Put the Firecracker jailer chroot base on the reflink XFS, unless
/// the operator pinned it with
/// `K7D_FC_CHROOT_BASE`.
///
/// A warning, not a fatal: a node that never creates a
/// `backend: firecracker` VM does not need this at all, and one that
/// does gets the honest error from `fc::stage` naming both
/// filesystems when it tries to link a disk in.
fn prepare_fc_chroot_base() {
    // Split, `/var/lib/k7d/fc` is root-owned 0700 and every jail under
    // it is staged by the node broker (`fc.*` verbs). This process cannot
    // probe it, and the warning it would print — "a firecracker VM with
    // a disk will fail to stage it" — is the opposite of true.
    if k7d::broker::client::is_split() {
        log::info!("split: the Firecracker jailer chroot base is the node broker's");
        return;
    }
    if let Ok(custom) = std::env::var("K7D_FC_CHROOT_BASE") {
        log::info!("Firecracker jailer chroot base {custom} (K7D_FC_CHROOT_BASE)");
        return;
    }
    if let Err(e) = k7d::disks::ensure_reflink_fc_root() {
        log::warn!(
            "could not put the Firecracker jailer chroot base on the reflink XFS ({e}) — \
             a `backend: firecracker` VM with a disk will fail to stage it; run \
             `your node provisioning` on this node"
        );
    }
}

fn main() {
    handle_info_flags();

    // Privilege separation: the node broker forks off here, before anything else,
    // and this call returns only in the child. Two reasons it is first:
    // the same one the spawner has below (a `fork` after a thread or a
    // logger exists hands the child their locks), and the credential
    // change itself — the uid drop and the bounding-set drop are what the
    // rest of this function then runs under. `K7D_PRIVSEP` off (the
    // default for this increment) returns `Unsplit` and changes nothing.
    let role = match k7d::broker::start() {
        Ok(role) => role,
        Err(e) => {
            eprintln!("k7d: privilege separation: {e}");
            std::process::exit(1);
        }
    };

    // The spawner is forked here and nowhere else: it must exist while
    // this process is still single-threaded (a `fork` after
    // `env_logger::init()` hands the child the logger's and malloc's
    // locks, and the spawner allocates — CHALLENGES #245), before the
    // signal handlers (the child must keep the default dispositions),
    // and before `seccomp::install()` removes `execve` from this
    // process for good. There is no second chance: a spawner forked
    // after the filter is installed inherits it and dies on its first
    // helper.
    let spawner_pid = match k7d::spawner::start() {
        Ok(pid) => pid,
        Err(e) => {
            eprintln!("k7d: spawner: {e}");
            std::process::exit(1);
        }
    };

    env_logger::init();
    log::info!("helper spawner forked (pid {spawner_pid}) before the daemon's seccomp filter");
    match role {
        k7d::broker::Role::VmBroker => log::info!(
            "running as the VM broker (pid {}, generation {}, empty capability set); privileged \
             work is a node-broker verb",
            std::process::id(),
            k7d::broker::client::restart_epoch()
        ),
        k7d::broker::Role::Unsplit => {
            log::info!("K7D_PRIVSEP is off: one process, root, as before privilege separation")
        }
    }
    let socket = socket_path();
    log::info!("k7d starting (socket={socket})");

    // Systemd's default soft RLIMIT_NOFILE is 1024 even when the hard
    // limit is 524288 — far too low for a daemon that may hold hundreds
    // of live VMs (each TAP/KVM/vsock fd). Raise early and fail loud
    // (50× cluster batch; CHALLENGES #49).
    if let Err(e) = k7d::fork::ensure_nofile_headroom(262_144) {
        log::error!("RLIMIT_NOFILE: {e}");
        std::process::exit(1);
    }

    install_signal_handlers();

    // Installed before the first VM (and before the
    // pool's threads) exists: a filter on this thread is inherited by
    // every thread created afterwards, which is what
    // makes a daemon-wide filter possible at all in a process that owns
    // every tree's VMs as threads. Defaults to `enforce`. This is the
    // *daemon's* allowlist only — the helpers' lives on the spawner
    // forked above.
    let installed = match role {
        k7d::broker::Role::VmBroker => k7d::seccomp::install_for_vm_broker(),
        k7d::broker::Role::Unsplit => k7d::seccomp::install(),
    };
    match installed {
        Ok(mode) => log::info!("seccomp mode: {mode:?}"),
        Err(e) => {
            log::error!("seccomp: {e}");
            std::process::exit(1);
        }
    }

    // Warm pool from env (K7D_POOL_SIZE > 0
    // enables it). A malformed pool config must stop the daemon loudly
    // — silently running without the pool the operator asked for would
    // hide the misconfiguration behind slow pod creates.
    let pool = match k7d::config::PoolConfig::from_env() {
        Ok(Some(cfg)) => {
            log::info!(
                "warm pool enabled: size={} memory_mb={}",
                cfg.size,
                cfg.memory_mb
            );
            Some(k7d::pool::Pool::start(cfg))
        }
        Ok(None) => None,
        Err(e) => {
            log::error!("invalid pool configuration: {e}");
            std::process::exit(1);
        }
    };

    let daemon = Arc::new(Daemon::with_pool(pool));
    // VM-broker restart: a successor VM broker takes over the Firecracker
    // sandboxes the node broker kept back from its predecessor. Before
    // the stale-record GC below, which would otherwise delete the very
    // reattach records those sandboxes are found by.
    daemon.readopt_fc_sandboxes();
    // GC sandbox reattach records orphaned by a
    // previous daemon (its VMs died with it — they must not be
    // resurrected from JSON alone).
    daemon.clean_stale_sandbox_records();
    // GC per-VM CPU cgroups a crashed previous daemon left
    // under this service's cgroup (their vCPU threads died with it).
    k7d::cgroup::clean_stale_vm_cgroups();
    // Same contract for the tree jail's leftovers: an empty
    // cgroup is harmless, but a stale nft table silently filters the
    // next bridge that reuses the name.
    k7d::cgroup::clean_stale_tree_cgroups();
    // Re-open on-disk cluster trees a previous daemon left behind
    // (kill -9 / crash). After cgroup GC so `open()` does not collide
    // with a stale jail. Nodes come back Suspended — live KVM died
    // with the process. Not in Daemon::new: in-process
    // tests must not sweep /var/lib/k7d/trees.
    daemon.rehydrate_trees_from_disk();
    // nft needs root. Split, the node broker has already done both of
    // these in `sweep_orphans()` before this process existed; running
    // them again here only logs `you must be root` twice a restart and
    // teaches the reader to ignore an error that is usually real.
    if k7d::broker::client::is_split() {
        log::info!("split: stale net jails are the node broker's sweep");
    } else {
        let reaped_jails = k7d::netjail::clean_stale_jails();
        if !reaped_jails.is_empty() {
            log::warn!("reaped stale net jails: {reaped_jails:?}");
        }
        let reaped_tap_jails = k7d::netjail::clean_stale_tap_jails();
        if !reaped_tap_jails.is_empty() {
            log::warn!("reaped stale tap anti-spoof jails: {reaped_tap_jails:?}");
        }
    }
    prepare_tree_root();
    prepare_fc_chroot_base();
    // A bad K7D_FC_FORK_SNAPSHOT would otherwise surface only at the
    // first Firecracker fork point.
    match k7d::fc::snapshot::fork_mode() {
        Ok(mode) => log::info!("Firecracker fork snapshot mode: {mode:?}"),
        Err(e) => {
            eprintln!("k7d: {e}");
            std::process::exit(1);
        }
    }
    let shutdown = Arc::new(AtomicBool::new(false));

    // Bridge the C signal handler's static flag into the Arc the serve
    // loop polls: a tiny watcher thread copies it across.
    {
        let shutdown = Arc::clone(&shutdown);
        std::thread::spawn(move || loop {
            if SHUTDOWN.load(Ordering::SeqCst) {
                shutdown.store(true, Ordering::SeqCst);
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        });
    }

    // A daemon that could not serve must exit non-zero: logging and
    // returning 0 told systemd the unit succeeded, so a k7d that never
    // bound its socket looked like a clean shutdown.
    let serve_result = control::serve(&socket, &daemon, &shutdown);
    if let Err(e) = &serve_result {
        log::error!("serve failed: {e}");
    }

    log::info!("k7d draining {} VM(s)", daemon.vm_count());
    daemon.shutdown_all();
    // The node broker keeps serving verbs throughout `shutdown_all` —
    // every `StopVm` on the way out issues `vm.release` — and only this
    // tells it there will be no more, so that `systemctl stop` exits 0
    // instead of looking like the VM broker crashed.
    if role == k7d::broker::Role::VmBroker {
        if let Err(e) = k7d::broker::client::shutdown() {
            log::error!("telling the node broker that shutdown_all finished: {e}");
        }
    }
    log::info!("k7d stopped");

    if serve_result.is_err() {
        std::process::exit(1);
    }
}
