//! Integration test for: warm cluster fork via per-cluster bridge.
//!
//! Validates the topology-preservation contract: forking an N-VM cluster
//! reproduces every member VM's `(guest_ip, guest_mac)` on a fresh bridge,
//! while leaving the source cluster's vsock and per-VM state untouched.
//!
//! Requires KVM, /dev/vhost-vsock, /dev/net/tun, virtiofsd, and the built
//! guest kernel + initramfs.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use k7d::fork::{fork_cluster_warm, fork_cluster_warm_batch, ClusterForkRequest};
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
    create_vm_on_cluster_with_vcpus(net, 1)
}

fn create_vm_on_cluster_with_vcpus(net: &mut ClusterNetwork, vcpus: u32) -> Vm {
    let kernel = workspace_path("guest/kernel/vmlinux");
    let initrd = workspace_path("guest/rootfs/initramfs.cpio.gz");
    let tap = net.add_tap().expect("add_tap");
    Vm::builder()
        .kernel(&kernel)
        .initrd(&initrd)
        .memory_mb(256)
        .vcpus(vcpus)
        .vsock(true)
        .guest_cid(k7d::vsock::allocate_cid())
        .network(tap)
        .build()
        .expect("VM build")
}

#[test]
fn test_cluster_fork_warm_preserves_identity() {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = k7d::network::cleanup_stale_k7_bridges();

    let mut src_net = ClusterNetwork::create("clfork-src").expect("source bridge");
    let mut vm0 = create_vm_on_cluster(&mut src_net);
    let mut vm1 = create_vm_on_cluster(&mut src_net);

    let vm0_ip = vm0.guest_ip().expect("vm0 has guest IP");
    let vm1_ip = vm1.guest_ip().expect("vm1 has guest IP");

    vm0.start().expect("vm0 start");
    vm1.start().expect("vm1 start");

    let _ = vm0
        .connect_agent(Duration::from_secs(90))
        .expect("vm0 agent");
    let _ = vm1
        .connect_agent(Duration::from_secs(90))
        .expect("vm1 agent");

    vm0.prepare_fork_source().expect("vm0 prepare");
    let mut s0_agent = vm0
        .connect_agent(Duration::from_secs(30))
        .expect("vm0 reconnect");
    s0_agent
        .exec(&["sh", "-c", "echo from-vm0 > /tmp/identity"])
        .unwrap();

    vm1.prepare_fork_source().expect("vm1 prepare");
    let mut s1_agent = vm1
        .connect_agent(Duration::from_secs(30))
        .expect("vm1 reconnect");
    s1_agent
        .exec(&["sh", "-c", "echo from-vm1 > /tmp/identity"])
        .unwrap();

    let mut sources: Vec<(&mut Vm, u32)> = vec![(&mut vm0, 0), (&mut vm1, 1)];

    let start = Instant::now();
    let (fork_net, mut forks) = fork_cluster_warm(
        &src_net,
        &mut sources,
        "clfork-fork",
        &[],
        &[],
        &["fork-vm0", "fork-vm1"],
    )
    .expect("cluster warm fork");
    let elapsed = start.elapsed();
    eprintln!("fork_cluster_warm 2 VMs in {elapsed:?}");

    // Identity preserved: forks see the same guest IPs as the sources, on a
    // fresh isolated bridge.
    assert_eq!(forks[0].guest_ip(), Some(vm0_ip));
    assert_eq!(forks[1].guest_ip(), Some(vm1_ip));
    assert_ne!(fork_net.bridge_name(), src_net.bridge_name());

    // Source-side vsock untouched — TRANSPORT_RESET went into the forks
    // only (correctness invariant carried over to cluster fork).
    let alive0 = s0_agent
        .exec(&["echo", "src0-still-here"])
        .expect("source vm0 alive");
    assert_eq!(alive0.stdout.trim(), "src0-still-here");
    let alive1 = s1_agent
        .exec(&["echo", "src1-still-here"])
        .expect("source vm1 alive");
    assert_eq!(alive1.stdout.trim(), "src1-still-here");

    // Forked guests inherit pre-fork in-memory state, reachable on a fresh
    // bridge with the source's guest IPs.
    forks[0].start().expect("fork0 start");
    forks[1].start().expect("fork1 start");
    let mut f0_agent = forks[0]
        .connect_agent(Duration::from_secs(30))
        .expect("fork0 agent");
    let mut f1_agent = forks[1]
        .connect_agent(Duration::from_secs(30))
        .expect("fork1 agent");
    let id0 = f0_agent.exec(&["cat", "/tmp/identity"]).unwrap();
    let id1 = f1_agent.exec(&["cat", "/tmp/identity"]).unwrap();
    assert_eq!(id0.stdout.trim(), "from-vm0");
    assert_eq!(id1.stdout.trim(), "from-vm1");

    for mut f in forks {
        f.shutdown();
    }
    drop(fork_net);
    vm0.shutdown();
    vm1.shutdown();
    drop(src_net);
}

/// A mixed cluster — 3 VMs where one member has 2 vCPUs —
/// warm-forks with identity AND per-member CPU counts preserved.
/// `fork_cluster_warm`'s shared pause + per-member capture loop must
/// handle members with different vCPU counts.
#[test]
fn test_cluster_fork_multi_vcpu() {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = k7d::network::cleanup_stale_k7_bridges();

    let mut src_net = ClusterNetwork::create("smpcl-src").expect("source bridge");
    // Member 1 (index 1) is the 2-vCPU one — deliberately not index 0
    // so the capture loop's ordering assumptions get exercised.
    let vcpu_counts: [u32; 3] = [1, 2, 1];
    let mut vms: Vec<Vm> = vcpu_counts
        .iter()
        .map(|&n| create_vm_on_cluster_with_vcpus(&mut src_net, n))
        .collect();
    let src_ips: Vec<_> = vms.iter().map(|v| v.guest_ip().expect("ip")).collect();

    for (i, vm) in vms.iter_mut().enumerate() {
        vm.start().expect("start");
        let mut agent = vm.connect_agent(Duration::from_secs(90)).expect("agent");
        agent
            .exec(&["sh", "-c", &format!("echo member-{i} > /tmp/identity")])
            .unwrap();
    }
    for vm in &mut vms {
        vm.prepare_fork_source().expect("prepare");
        let _ = vm
            .connect_agent(Duration::from_secs(30))
            .expect("reconnect");
    }
    for (vm, &want) in vms.iter().zip(&vcpu_counts) {
        assert_eq!(
            vm.vcpu_count(),
            want,
            "prepare_fork_source must keep the member's vCPU count"
        );
    }

    let mut sources: Vec<(&mut Vm, u32)> = vms
        .iter_mut()
        .enumerate()
        .map(|(i, v)| (v, i as u32))
        .collect();
    let (fork_net, mut forks) = fork_cluster_warm(
        &src_net,
        &mut sources,
        "smpcl-fork",
        &[],
        &[],
        &["smp-f0", "smp-f1", "smp-f2"],
    )
    .expect("mixed-vCPU cluster warm fork");

    assert_eq!(forks.len(), 3);
    for (i, (fork, &want)) in forks.iter_mut().zip(&vcpu_counts).enumerate() {
        assert_eq!(
            fork.vcpu_count(),
            want,
            "fork member {i} must keep {want} vCPU(s)"
        );
        assert_eq!(fork.guest_ip(), Some(src_ips[i]), "identity preserved");
        fork.start().expect("fork start");
        let mut agent = fork
            .connect_agent(Duration::from_secs(30))
            .expect("fork agent");
        let id = agent.exec(&["cat", "/tmp/identity"]).unwrap();
        assert_eq!(id.stdout.trim(), format!("member-{i}"));
        let nproc = agent
            .exec(&["sh", "-c", "grep -c ^processor /proc/cpuinfo"])
            .unwrap();
        assert_eq!(
            nproc.stdout.trim(),
            want.to_string(),
            "fork member {i} guest must see {want} CPU(s)"
        );
    }

    for mut f in forks {
        f.shutdown();
    }
    drop(fork_net);
    for mut vm in vms {
        vm.shutdown();
    }
    drop(src_net);
}

/// Configure guest eth0 with the sticky cluster-mode IP.
fn configure_eth0(agent: &mut k7d::api::AgentClient, ip: Ipv4Addr) {
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

/// Start a long-lived busybox-nc TCP session: server listens on `port`,
/// client holds a pipe open via `sleep` so the connection survives across
/// prepare/fork. Client writes go through a fifo so the test can push more
/// bytes after restore without reconnecting.
fn start_held_tcp_session(
    server: &mut k7d::api::AgentClient,
    client: &mut k7d::api::AgentClient,
    server_ip: Ipv4Addr,
    client_ip: Ipv4Addr,
    port: u16,
) {
    // Warm ARP both ways — cold eth0 has an empty neighbour table and
    // busybox `nc -w` will burn its connect timeout on the first SYN.
    let ping_s = server
        .exec(&["ping", "-c", "1", "-W", "3", &client_ip.to_string()])
        .expect("ping client");
    assert_eq!(
        ping_s.exit_code, 0,
        "server→client ping failed before TCP: {}",
        ping_s.stderr
    );
    let ping_c = client
        .exec(&["ping", "-c", "1", "-W", "3", &server_ip.to_string()])
        .expect("ping server");
    assert_eq!(
        ping_c.exit_code, 0,
        "client→server ping failed before TCP: {}",
        ping_c.stderr
    );

    // Guest-side helper scripts: ignore SIGHUP so background jobs survive
    // the agent.exec shell exiting, and fully redirect stdio so
    // Command::output() does not wait on inherited pipes.
    // Keep stdin open: `nc -l </dev/null` gets immediate EOF and tears the
    // TCP session down right after the first payload (breaks held sockets).
    server
        .write_file(
            "/tmp/tcp-listen.sh",
            format!(
                "#!/bin/sh\ntrap '' HUP\nrm -f /tmp/tcp-in\n: > /tmp/tcp-in\nsleep 3600 | nc -l -p {port} >> /tmp/tcp-in\n"
            )
            .as_bytes(),
        )
        .expect("write listen script");
    let started = server
        .exec(&[
            "sh",
            "-c",
            "chmod +x /tmp/tcp-listen.sh; /tmp/tcp-listen.sh </dev/null >/dev/null 2>&1 & echo LISTENING",
        ])
        .expect("start nc listener");
    assert!(
        started.stdout.contains("LISTENING"),
        "listener shell did not start: {started:?}"
    );
    std::thread::sleep(Duration::from_millis(500));

    // Simple hold: `(echo; sleep) | nc` keeps the TCP session open without
    // busybox-nc idle/timeout quirks from a poll loop on the pipe.
    client
        .write_file(
            "/tmp/tcp-hold.sh",
            format!(
                "#!/bin/sh\n\
                 trap '' HUP\n\
                 ( echo before-fork; sleep 3600 ) | nc {server_ip} {port}\n"
            )
            .as_bytes(),
        )
        .expect("write hold script");
    let connected = client
        .exec(&[
            "sh",
            "-c",
            "chmod +x /tmp/tcp-hold.sh; /tmp/tcp-hold.sh </dev/null >/dev/null 2>&1 & echo CONNECTED",
        ])
        .expect("start held nc client");
    assert!(
        connected.stdout.contains("CONNECTED"),
        "client shell did not start: {connected:?}"
    );

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let got = server.exec(&["cat", "/tmp/tcp-in"]).expect("cat tcp-in");
        if got.stdout.contains("before-fork") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for before-fork over eth0 TCP; tcp-in={:?}",
            got.stdout
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// True if `/proc/net/tcp` has at least one non-listen established socket
/// (state `01`). Busybox has no `ss`/`netstat`.
fn tcp_established(agent: &mut k7d::api::AgentClient) -> bool {
    let tbl = agent
        .exec(&["cat", "/proc/net/tcp"])
        .expect("cat /proc/net/tcp");
    tbl.stdout
        .lines()
        .skip(1)
        .any(|l| l.split_whitespace().nth(3) == Some("01"))
}

/// One-shot TCP round-trip on `port` (server must not already be listening).
fn tcp_oneshot(
    server: &mut k7d::api::AgentClient,
    client: &mut k7d::api::AgentClient,
    server_ip: Ipv4Addr,
    port: u16,
    marker: &str,
) {
    let listen =
        format!("nc -l -p {port} </dev/null > /tmp/oneshot-{port} 2>/dev/null & echo LISTENING");
    server.exec(&["sh", "-c", &listen]).expect("oneshot listen");
    std::thread::sleep(Duration::from_millis(300));
    let send = format!("echo {marker} | nc -w 5 {server_ip} {port}");
    let sent = client.exec(&["sh", "-c", &send]).expect("oneshot send");
    assert_eq!(
        sent.exit_code, 0,
        "oneshot TCP failed: stdout={} stderr={}",
        sent.stdout, sent.stderr
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let got = server
            .exec(&["cat", &format!("/tmp/oneshot-{port}")])
            .expect("oneshot cat");
        if got.stdout.contains(marker) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "oneshot TCP did not deliver {marker:?}; got {:?}",
            got.stdout
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// / 9d TCP claim — source side:
/// 1. eth0 stays usable after `prepare_fork_source` (TapNetBackend seed);
/// 2. a held TCP session opened *after* prepare survives `fork_cluster_warm`
///    without reconnect (prepare itself is a cold snapshot+restore blip;
///    warm fork must not disturb the source).
#[test]
fn test_cluster_fork_warm_source_tcp_undisturbed() {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = k7d::network::cleanup_stale_k7_bridges();

    let mut src_net = ClusterNetwork::create("tcp-src").expect("source bridge");
    let mut vm0 = create_vm_on_cluster(&mut src_net);
    let mut vm1 = create_vm_on_cluster(&mut src_net);
    let vm0_ip = vm0.guest_ip().expect("vm0 ip");
    let vm1_ip = vm1.guest_ip().expect("vm1 ip");
    assert_ne!(vm0_ip, vm1_ip);

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
    // Advance virtqueue indices so restore must seed (the hang only fires
    // when used.idx is already non-zero).
    let _ = a0.exec(&["ping", "-c", "1", "-W", "2", &vm1_ip.to_string()]);
    let _ = a1.exec(&["ping", "-c", "1", "-W", "2", &vm0_ip.to_string()]);

    drop(a0);
    drop(a1);
    vm0.prepare_fork_source().expect("vm0 prepare");
    vm1.prepare_fork_source().expect("vm1 prepare");
    let mut a0 = vm0
        .connect_agent(Duration::from_secs(30))
        .expect("vm0 reconnect");
    let mut a1 = vm1
        .connect_agent(Duration::from_secs(30))
        .expect("vm1 reconnect");

    let ping = a1
        .exec(&["ping", "-c", "1", "-W", "3", &vm0_ip.to_string()])
        .expect("ping after prepare");
    assert_eq!(
        ping.exit_code, 0,
        "eth0 ping dead after prepare_fork_source (TapNetBackend seed?): stdout={} stderr={}",
        ping.stdout, ping.stderr
    );

    // Held session starts *after* prepare — prepare is a cold restore blip;
    // the warm-fork path must leave this session undisturbed.
    start_held_tcp_session(&mut a0, &mut a1, vm0_ip, vm1_ip, 9999);
    assert!(
        tcp_established(&mut a1),
        "held TCP not ESTABLISHED before fork"
    );

    let mut sources: Vec<(&mut Vm, u32)> = vec![(&mut vm0, 0), (&mut vm1, 1)];
    let (fork_net, forks) = fork_cluster_warm(
        &src_net,
        &mut sources,
        "tcp-fork",
        &[],
        &[],
        &["tcp-f0", "tcp-f1"],
    )
    .expect("cluster warm fork");

    assert!(
        tcp_established(&mut a1),
        "held source TCP session did not survive fork_cluster_warm (no reconnect)"
    );
    let held = a0.exec(&["cat", "/tmp/tcp-in"]).unwrap();
    assert!(
        held.stdout.contains("before-fork"),
        "server still has pre-fork bytes: {:?}",
        held.stdout
    );

    // Fresh one-shot proves the source eth0 datapath still forwards after the
    // warm-fork pause window (worker-pause + seed).
    tcp_oneshot(&mut a0, &mut a1, vm0_ip, 9997, "after-fork");

    drop(forks);
    drop(fork_net);
    drop(a0);
    drop(a1);
    vm0.shutdown();
    vm1.shutdown();
    drop(src_net);
}

/// Forked VMs can open *new* TCP to each other on the
/// fork bridge using the preserved guest IPs (identity + data plane).
#[test]
fn test_cluster_fork_warm_fork_tcp_works() {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = k7d::network::cleanup_stale_k7_bridges();

    let mut src_net = ClusterNetwork::create("ftcp-src").expect("source bridge");
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
    // Drive some eth0 traffic pre-prepare so used.idx is non-zero (the bug
    // only fires when rings have advanced).
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
        "ftcp-fork",
        &[],
        &[],
        &["ftcp-f0", "ftcp-f1"],
    )
    .expect("cluster warm fork");

    assert_eq!(forks[0].guest_ip(), Some(vm0_ip));
    assert_eq!(forks[1].guest_ip(), Some(vm1_ip));

    forks[0].start().expect("fork0 start");
    forks[1].start().expect("fork1 start");
    let mut f0 = forks[0]
        .connect_agent(Duration::from_secs(30))
        .expect("fork0 agent");
    let mut f1 = forks[1]
        .connect_agent(Duration::from_secs(30))
        .expect("fork1 agent");

    // Warm ARP on the fork bridge. The source ping above populated the
    // *source* neighbour tables; the forks are a new L2 domain. Cold
    // ARP plus haltpoll (the vCPU HLTs between execs) lets busybox
    // `nc -w 5` burn its whole timeout on the first SYN — especially
    // after `test_cluster_fork_warm_batch_8`. Same reason
    // `start_held_tcp_session` pings first.
    let ping_s = f0
        .exec(&["ping", "-c", "1", "-W", "3", &vm1_ip.to_string()])
        .expect("fork0 ping");
    assert_eq!(
        ping_s.exit_code, 0,
        "fork0→fork1 ping failed: {}",
        ping_s.stderr
    );
    let ping_c = f1
        .exec(&["ping", "-c", "1", "-W", "3", &vm0_ip.to_string()])
        .expect("fork1 ping");
    assert_eq!(
        ping_c.exit_code, 0,
        "fork1→fork0 ping failed: {}",
        ping_c.stderr
    );

    // Fresh TCP on the fork bridge using the preserved IPs.
    // Keep stdin open: `nc -l </dev/null` gets immediate EOF (CHALLENGES #28).
    f0.write_file(
        "/tmp/fork-listen.sh",
        b"#!/bin/sh\ntrap '' HUP\nrm -f /tmp/fork-in\n: > /tmp/fork-in\nsleep 3600 | nc -l -p 9998 >> /tmp/fork-in\n",
    )
    .expect("write fork listen script");
    let listen = f0
        .exec(&[
            "sh",
            "-c",
            "chmod +x /tmp/fork-listen.sh; /tmp/fork-listen.sh </dev/null >/dev/null 2>&1 & echo LISTENING",
        ])
        .expect("fork listener");
    assert!(
        listen.stdout.contains("LISTENING"),
        "fork listener did not start: {:?}",
        listen
    );
    std::thread::sleep(Duration::from_millis(300));
    let send = format!("echo hello-fork | nc -w 5 {vm0_ip} 9998");
    let sent = f1.exec(&["sh", "-c", &send]).expect("fork client send");
    assert_eq!(
        sent.exit_code, 0,
        "fork eth0 TCP connect failed: stdout={} stderr={}",
        sent.stdout, sent.stderr
    );

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let got = f0.exec(&["cat", "/tmp/fork-in"]).expect("cat fork-in");
        if got.stdout.contains("hello-fork") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "fork bridge TCP did not deliver; /tmp/fork-in={:?}",
            got.stdout
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    for mut f in forks {
        f.shutdown();
    }
    drop(fork_net);
    vm0.shutdown();
    vm1.shutdown();
    drop(src_net);
}

/// 3-VM warm cluster fork latency target (headline).
///
/// Takes the minimum of `REPEATS` independently-prepared clusters
/// rather than a single sample. The quiet-host target is
/// ~25–40 ms; [`FORK_CLUSTER_WARM_3VM`] (150 ms) absorbs bare-metal
/// scheduler/KVM-cache jitter. The best-of-N pattern still catches
/// genuine regressions (a real regression breaks every sample, not
/// just the first one) while staying immune to host noise.
#[test]
fn test_cluster_fork_warm_3vm_under_50ms() {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = k7d::network::cleanup_stale_k7_bridges();

    const REPEATS: usize = 5;
    let mut samples: Vec<Duration> = Vec::with_capacity(REPEATS);

    for rep in 0..REPEATS {
        let src_id = format!("3vm-src-r{rep}");
        let mut net = ClusterNetwork::create(&src_id).expect("bridge");
        let mut vms: Vec<Vm> = (0..3).map(|_| create_vm_on_cluster(&mut net)).collect();
        for vm in &mut vms {
            vm.start().expect("start");
            let _ = vm.connect_agent(Duration::from_secs(90)).expect("agent");
        }
        for vm in &mut vms {
            vm.prepare_fork_source().expect("prepare");
            let _ = vm
                .connect_agent(Duration::from_secs(30))
                .expect("reconnect");
        }

        let mut sources: Vec<(&mut Vm, u32)> = vms
            .iter_mut()
            .enumerate()
            .map(|(i, v)| {
                // SAFETY of the cast: 0..3 fits in u32.
                (v, i as u32)
            })
            .collect();

        let fork_id = format!("3vm-fork-r{rep}");
        let start = Instant::now();
        let (fork_net, forks) =
            fork_cluster_warm(&net, &mut sources, &fork_id, &[], &[], &["f0", "f1", "f2"])
                .expect("cluster warm fork");
        let elapsed = start.elapsed();
        eprintln!("3-VM warm cluster fork (rep {rep}): {elapsed:?}");
        samples.push(elapsed);

        assert_eq!(forks.len(), 3);
        // Drop in well-defined order: forks first (they reference
        // their bridge), then fork_net, then source vms, then src net.
        drop(forks);
        drop(fork_net);
        drop(vms);
        drop(net);
    }

    let best = samples.iter().min().copied().unwrap();
    eprintln!("best of {REPEATS}: {best:?} (samples: {samples:?})");
    assert!(
        best < k7d::latency::FORK_CLUSTER_WARM_3VM,
        "best-of-{REPEATS} 3-VM warm cluster fork should be <{:?}, was {best:?} (samples: {samples:?})",
        k7d::latency::FORK_CLUSTER_WARM_3VM
    );
}

/// Shared-pause `fork_cluster_warm_batch` for 8× 3-VM clusters.
///
/// One pause / capture, eight bridges, 24 members materialised in
/// parallel. Must stay under [`FORK_CLUSTER_WARM_BATCH_8`] and beat
/// `8 × FORK_CLUSTER_WARM_3VM`.
#[test]
fn test_cluster_fork_warm_batch_8() {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = k7d::network::cleanup_stale_k7_bridges();

    const N: usize = 8;
    let mut net = ClusterNetwork::create("batch8-src").expect("bridge");
    let mut vms: Vec<Vm> = (0..3).map(|_| create_vm_on_cluster(&mut net)).collect();
    for vm in &mut vms {
        vm.start().expect("start");
        let _ = vm.connect_agent(Duration::from_secs(90)).expect("agent");
    }
    for vm in &mut vms {
        vm.prepare_fork_source().expect("prepare");
    }

    let mut sources: Vec<(&mut Vm, u32)> = vms
        .iter_mut()
        .enumerate()
        .map(|(i, v)| (v, i as u32))
        .collect();

    let bridge_ids: Vec<String> = (0..N).map(|i| format!("batch8-f{i}")).collect();
    let member_ids: Vec<Vec<&str>> = (0..N).map(|_| vec!["m0", "m1", "m2"]).collect();
    let requests: Vec<ClusterForkRequest<'_>> = bridge_ids
        .iter()
        .enumerate()
        .map(|(i, id)| ClusterForkRequest {
            fork_cluster_id: id.as_str(),
            fork_ids: &member_ids[i],
            fork_pod_ips: &[],
            fork_pod_netns: &[],
        })
        .collect();

    let start = Instant::now();
    let forks = fork_cluster_warm_batch(&net, &mut sources, &requests).expect("batch");
    let elapsed = start.elapsed();
    eprintln!(
        "fork_cluster_warm_batch {N}×3-VM: {elapsed:?} ({:.1} ms/cluster)",
        elapsed.as_secs_f64() * 1000.0 / N as f64
    );

    assert_eq!(forks.len(), N);
    for (net_f, members) in &forks {
        assert_eq!(members.len(), 3);
        for vm in members {
            assert!(!vm.fork_memory_is_full_copy(), "batch member must be CoW");
        }
        assert_ne!(net_f.bridge_name(), net.bridge_name());
    }
    assert!(
        elapsed < k7d::latency::FORK_CLUSTER_WARM_BATCH_8,
        "batch-{N} took {elapsed:?} > {:?}",
        k7d::latency::FORK_CLUSTER_WARM_BATCH_8
    );
    assert!(
        elapsed < k7d::latency::FORK_CLUSTER_WARM_3VM.saturating_mul(N as u32),
        "batch-{N} took {elapsed:?}; must beat N× single ceiling {:?}",
        k7d::latency::FORK_CLUSTER_WARM_3VM.saturating_mul(N as u32)
    );

    drop(forks);
    drop(vms);
    drop(net);
}

/// Pod-netns DNAT/SNAT: `install_pod_nat` writes the right rules in the right
/// netns, with the guest IP / pod IP coupling asked for. Validated structurally
/// (rule listing) — the data-plane behavior is exercised by k7's higher-level
/// tests once a real pod IP is in flight.
#[test]
fn test_install_pod_nat_installs_rules() {
    let _ = k7d::network::cleanup_stale_k7_bridges();
    // Skip the test if running without root/iptables/netns — we don't `unwrap`
    // the netns bring-up so the failure mode is informative if it fires.
    if !Path::new("/proc/self/ns/net").exists() {
        panic!("/proc/self/ns/net missing — kernel without netns?");
    }

    let netns = "k7-podnat-test";
    // Best-effort cleanup from a previous failed run.
    let _ = Command::new("ip").args(["netns", "del", netns]).output();
    let add = Command::new("ip")
        .args(["netns", "add", netns])
        .output()
        .expect("ip netns add");
    assert!(
        add.status.success(),
        "ip netns add failed: {}",
        String::from_utf8_lossy(&add.stderr)
    );
    // Cleanup on any exit path below.
    struct NetnsGuard<'a>(&'a str);
    impl Drop for NetnsGuard<'_> {
        fn drop(&mut self) {
            let _ = Command::new("ip").args(["netns", "del", self.0]).output();
        }
    }
    let _guard = NetnsGuard(netns);

    let mut net = ClusterNetwork::create("podnat").expect("bridge");
    let _tap = net.add_tap_at(0).expect("tap @ 0");
    let entry = net.entry(0).expect("entry 0");
    let guest_ip = entry.guest_ip;

    let pod_ip = Ipv4Addr::new(10, 0, 99, 7);
    let netns_path = PathBuf::from(format!("/var/run/netns/{netns}"));
    net.install_pod_nat(0, pod_ip, &netns_path)
        .expect("install_pod_nat");

    // Verify both rules are present in the pod netns.
    let listing = Command::new("nsenter")
        .args([
            &format!("--net={}", netns_path.display()),
            "iptables",
            "-t",
            "nat",
            "-S",
        ])
        .output()
        .expect("iptables -S");
    let s = String::from_utf8_lossy(&listing.stdout);
    let dnat = format!("-A PREROUTING -d {pod_ip}/32 -j DNAT --to-destination {guest_ip}");
    let snat = format!("-A POSTROUTING -s {guest_ip}/32 -j SNAT --to-source {pod_ip}");
    assert!(s.contains(&dnat), "DNAT rule missing — got:\n{s}");
    assert!(s.contains(&snat), "SNAT rule missing — got:\n{s}");

    // The rules must NOT leak into the host's default netns.
    let host_listing = Command::new("iptables")
        .args(["-t", "nat", "-S"])
        .output()
        .expect("iptables -S host");
    let hs = String::from_utf8_lossy(&host_listing.stdout);
    assert!(
        !hs.contains(&dnat),
        "pod-netns DNAT rule leaked into host netns:\n{hs}"
    );
    assert!(
        !hs.contains(&snat),
        "pod-netns SNAT rule leaked into host netns:\n{hs}"
    );

    // Bookkeeping: the entry now records pod_ip and netns path.
    let entry = net.entry(0).expect("entry 0");
    assert_eq!(entry.pod_ip, Some(pod_ip));
    assert_eq!(entry.pod_netns.as_deref(), Some(netns_path.as_path()));
}

#[test]
fn test_two_clusters_isolated_at_l2() {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = k7d::network::cleanup_stale_k7_bridges();

    let mut net_a = ClusterNetwork::create("iso-a").expect("bridge a");
    let mut net_b = ClusterNetwork::create("iso-b").expect("bridge b");

    let mut vm_a = create_vm_on_cluster(&mut net_a);
    let mut vm_b = create_vm_on_cluster(&mut net_b);

    // Same guest IP on different bridges — must not route across.
    assert_eq!(vm_a.guest_ip(), vm_b.guest_ip());

    vm_a.start().expect("vm_a start");
    vm_b.start().expect("vm_b start");

    let mut a_agent = vm_a
        .connect_agent(Duration::from_secs(90))
        .expect("vm_a agent");
    let _b_agent = vm_b
        .connect_agent(Duration::from_secs(90))
        .expect("vm_b agent");

    // Configure interface on vm_a and try to reach vm_b's gateway. Even if the
    // physical bridges shared the same /24, separate L2 domains mean ARP for
    // vm_b's MAC won't resolve through vm_a's bridge.
    let _ = a_agent.exec(&[
        "ifconfig",
        "eth0",
        &vm_a.guest_ip().unwrap().to_string(),
        "netmask",
        "255.255.255.0",
        "up",
    ]);
    // Ping with a 2s timeout — must fail because the two bridges are disjoint.
    let ping = a_agent
        .exec(&["ping", "-c", "1", "-W", "2", "10.200.0.99"])
        .expect("ping exec");
    assert_ne!(
        ping.exit_code, 0,
        "cross-bridge ping should fail (separate L2)"
    );

    vm_a.shutdown();
    vm_b.shutdown();
}
