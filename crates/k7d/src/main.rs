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

/// `--version` and `--help` must be answered before anything else happens.
/// Without this they fell through to "start a daemon", so an operator
/// checking which version was installed booted a second daemon that took
/// the control socket from the running one and deleted it on the way out.
fn handle_info_flags() {
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--version" | "-V" => {
                println!("k7d {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--help" | "-h" => {
                println!(
                    "k7d {} — microVM runtime daemon (one per node, root)\n\n\
                     Usage: k7d [--socket <path>]\n\n\
                     Options:\n\
                     \x20 --socket <path>  control socket (default: {}; env K7D_SOCKET)\n\
                     \x20 -V, --version    print version and exit\n\
                     \x20 -h, --help       print this help and exit\n\n\
                     Guest artifacts are required and come from the environment:\n\
                     \x20 K7D_KERNEL       guest kernel (vmlinux)\n\
                     \x20 K7D_INITRD       guest initramfs\n",
                    env!("CARGO_PKG_VERSION"),
                    control::DEFAULT_SOCKET,
                );
                std::process::exit(0);
            }
            _ => {}
        }
    }
}

fn main() {
    handle_info_flags();
    env_logger::init();
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
    // GC sandbox reattach records orphaned by a
    // previous daemon (its VMs died with it — they must not be
    // resurrected from JSON alone).
    daemon.clean_stale_sandbox_records();
    // GC per-VM CPU cgroups a crashed previous daemon left
    // under this service's cgroup (their vCPU threads died with it).
    k7d::cgroup::clean_stale_vm_cgroups();
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
    log::info!("k7d stopped");

    if serve_result.is_err() {
        std::process::exit(1);
    }
}
