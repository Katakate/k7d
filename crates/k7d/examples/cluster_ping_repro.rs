//! Diagnostic repro loop for the interrupt-injection bug (ICMP variant): cluster warm fork →
//! fork0→fork1 ping, N times.
//!
//! Not a test. Run manually on the node (needs KVM + vhost-vsock + TUN):
//!
//! ```sh
//! RUST_LOG=warn cargo run --release -p k7d --example cluster_ping_repro -- 100
//! ```
//!
//! Mirrors `test_cluster_fork_warm_fork_tcp_works` up to its first ping.
//! On a ping failure it keeps the fork cluster alive and gathers evidence
//! from both guests (neighbour tables, interface counters, interrupt
//! counts, ping retries in both directions) and from the host (tap link
//! stats, bridge forwarding table) before moving on.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

use k7d::api::AgentClient;
use k7d::fork::fork_cluster_warm;
use k7d::network::ClusterNetwork;
use k7d::vm::Vm;

fn workspace_path(relative: &str) -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join(relative)
}

fn create_vm_on_cluster(net: &mut ClusterNetwork) -> Vm {
    let kernel = workspace_path("guest/kernel/vmlinux");
    let initrd = workspace_path("guest/rootfs/initramfs.cpio.gz");
    let tap = net.add_tap().expect("add_tap");
    Vm::builder()
        .kernel(&kernel)
        .initrd(&initrd)
        .memory_mb(256)
        .vsock(true)
        .guest_cid(k7d::vsock::allocate_cid())
        .network(tap)
        .build()
        .expect("VM build")
}

fn configure_eth0(agent: &mut AgentClient, ip: Ipv4Addr) {
    let r = agent
        .exec(&[
            "ifconfig",
            "eth0",
            &ip.to_string(),
            "netmask",
            "255.255.255.0",
            "up",
        ])
        .expect("ifconfig eth0");
    assert_eq!(r.exit_code, 0, "ifconfig eth0 failed: {}", r.stderr);
}

fn guest_diag(tag: &str, agent: &mut AgentClient) {
    for cmd in [
        vec!["ip", "neigh", "show"],
        vec!["cat", "/proc/net/dev"],
        vec!["cat", "/proc/interrupts"],
        vec!["dmesg"],
    ] {
        match agent.exec(&cmd) {
            Ok(out) => eprintln!("--- {tag} `{}`:\n{}", cmd.join(" "), out.stdout),
            Err(e) => eprintln!("--- {tag} `{}` failed: {e:?}", cmd.join(" ")),
        }
    }
}

fn host_diag(bridge: &str) {
    for args in [
        vec!["-s", "link", "show"],
        vec!["link", "show", "master", bridge],
    ] {
        match std::process::Command::new("ip").args(&args).output() {
            Ok(out) => eprintln!(
                "--- host `ip {}`:\n{}",
                args.join(" "),
                String::from_utf8_lossy(&out.stdout)
            ),
            Err(e) => eprintln!("--- host `ip {}` failed: {e}", args.join(" ")),
        }
    }
    match std::process::Command::new("bridge")
        .args(["fdb", "show", "br", bridge])
        .output()
    {
        Ok(out) => eprintln!(
            "--- host `bridge fdb show br {bridge}`:\n{}",
            String::from_utf8_lossy(&out.stdout)
        ),
        Err(e) => eprintln!("--- host `bridge fdb` failed: {e}"),
    }
}

#[allow(clippy::too_many_lines)]
fn main() {
    env_logger::init();
    let iters: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);

    let mut failures = 0usize;
    for i in 0..iters {
        // Full test sequence per iteration — fresh bridge, fresh VMs,
        // prepare, fork, ping — matching
        // test_cluster_fork_warm_fork_tcp_works one to one: the failure
        // never reproduced with long-lived reused sources.
        let _ = k7d::network::cleanup_stale_k7_bridges();
        let mut src_net = ClusterNetwork::create("pngr-src").expect("source bridge");
        let mut vm0 = create_vm_on_cluster(&mut src_net);
        let mut vm1 = create_vm_on_cluster(&mut src_net);
        let vm0_ip = vm0.guest_ip().expect("vm0 ip");
        let vm1_ip = vm1.guest_ip().expect("vm1 ip");

        vm0.start().expect("vm0 start");
        vm1.start().expect("vm1 start");
        let mut a0 = vm0
            .connect_agent(Duration::from_secs(90))
            .expect("vm0 agent");
        let mut a1 = vm1
            .connect_agent(Duration::from_secs(90))
            .expect("vm1 agent");

        std::thread::sleep(Duration::from_secs(2));
        configure_eth0(&mut a0, vm0_ip);
        configure_eth0(&mut a1, vm1_ip);
        let _ = a0.exec(&["ping", "-c", "1", "-W", "2", &vm1_ip.to_string()]);
        let _ = a1.exec(&["ping", "-c", "1", "-W", "2", &vm0_ip.to_string()]);

        drop(a0);
        drop(a1);
        vm0.prepare_fork_source().expect("vm0 prepare");
        vm1.prepare_fork_source().expect("vm1 prepare");
        let _ = vm0
            .connect_agent(Duration::from_secs(30))
            .expect("vm0 reconnect");
        let _ = vm1
            .connect_agent(Duration::from_secs(30))
            .expect("vm1 reconnect");

        let mut sources: Vec<(&mut Vm, u32)> = vec![(&mut vm0, 0), (&mut vm1, 1)];
        let (fork_net, mut forks) = fork_cluster_warm(
            &src_net,
            &mut sources,
            &format!("pngr-f{i}"),
            &[],
            &[],
            &[&format!("pngr-f{i}-0"), &format!("pngr-f{i}-1")],
        )
        .expect("cluster warm fork");

        forks[0].start().expect("fork0 start");
        forks[1].start().expect("fork1 start");
        let mut f0 = forks[0]
            .connect_agent(Duration::from_secs(30))
            .expect("fork0 agent");
        let mut f1 = forks[1]
            .connect_agent(Duration::from_secs(30))
            .expect("fork1 agent");

        // Pre-ping counters so a failure report can show whether the echo
        // request ever left fork0 / reached fork1.
        let pre_f0 = f0.exec(&["cat", "/proc/net/dev"]).expect("f0 pre dev");
        let pre_f1 = f1.exec(&["cat", "/proc/net/dev"]).expect("f1 pre dev");
        let pre_n0 = f0.exec(&["ip", "neigh", "show"]).expect("f0 pre neigh");
        let pre_n1 = f1.exec(&["ip", "neigh", "show"]).expect("f1 pre neigh");

        let ping = f0
            .exec(&["ping", "-c", "1", "-W", "3", &vm1_ip.to_string()])
            .expect("fork0 ping exec");
        if ping.exit_code != 0 {
            failures += 1;
            eprintln!(
                "=== iteration {i}: fork0→fork1 ping failed (stdout={:?} stderr={:?})",
                ping.stdout, ping.stderr
            );
            // Does a retry work? Distinguishes first-packet loss from a
            // dead datapath.
            let retry = f0
                .exec(&["ping", "-c", "3", "-W", "3", &vm1_ip.to_string()])
                .expect("fork0 ping retry");
            eprintln!(
                "iteration {i}: retry x3 exit={} stdout={:?}",
                retry.exit_code, retry.stdout
            );
            let rev = f1
                .exec(&["ping", "-c", "1", "-W", "3", &vm0_ip.to_string()])
                .expect("fork1 reverse ping");
            eprintln!("iteration {i}: reverse ping exit={}", rev.exit_code);
            eprintln!(
                "--- fork0 pre-ping /proc/net/dev:\n{}\n--- fork0 pre-ping neigh:\n{}",
                pre_f0.stdout, pre_n0.stdout
            );
            eprintln!(
                "--- fork1 pre-ping /proc/net/dev:\n{}\n--- fork1 pre-ping neigh:\n{}",
                pre_f1.stdout, pre_n1.stdout
            );
            guest_diag("fork0", &mut f0);
            guest_diag("fork1", &mut f1);
            host_diag(fork_net.bridge_name());
        }

        drop(f0);
        drop(f1);
        for mut f in forks {
            f.shutdown();
        }
        drop(fork_net);
        if i % 10 == 9 {
            eprintln!(
                "progress: {}/{iters} iterations, {failures} failures",
                i + 1
            );
        }
    }
    eprintln!("done: {iters} iterations, {failures} failures");
    if failures > 0 {
        std::process::exit(1);
    }
}
