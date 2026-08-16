//! Integration test: boot a VM and see serial output.
//! Requires KVM (/dev/kvm) and a built guest kernel at guest/kernel/vmlinux.

use std::path::PathBuf;
use std::time::Duration;

use k7d::vm::Vm;

/// Resolve a path relative to the workspace root (two levels up from crate dir).
fn workspace_path(relative: &str) -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join(relative)
}

#[test]
fn test_vm_boots_and_prints_to_serial() {
    let _ = env_logger::builder().is_test(true).try_init();

    let kernel = workspace_path("guest/kernel/vmlinux");
    assert!(
        kernel.exists(),
        "guest kernel not found at {kernel:?} — run `make build-guest-kernel` on the node first"
    );

    let mut vm = Vm::builder()
        .kernel(&kernel)
        .memory_mb(256)
        .build()
        .expect("VM should create");

    vm.start().expect("VM should start");

    let output = vm.serial_output(Duration::from_secs(30));
    assert!(
        output.contains("Linux version"),
        "kernel should boot — serial output:\n{}",
        &output[..output.len().min(2000)]
    );
    assert!(
        output.contains("Kernel panic") || output.contains("Freeing"),
        "kernel should reach init — serial output (last 2000 chars):\n{}",
        &output[output.len().saturating_sub(2000)..]
    );

    vm.shutdown();
}

/// A 2-vCPU VM boots with both CPUs online — the guest
/// discovers the second CPU from the MP table (ACPI is compiled out)
/// and brings it up via INIT/SIPI. The CPU count through the agent
/// must report 2, both vCPU threads must publish kernel TIDs, and
/// teardown must join both run-loop threads.
#[test]
fn test_boot_multi_vcpu() {
    let _ = env_logger::builder().is_test(true).try_init();

    let kernel = workspace_path("guest/kernel/vmlinux");
    let initrd = workspace_path("guest/rootfs/initramfs.cpio.gz");
    assert!(kernel.exists(), "guest kernel not found at {kernel:?}");
    assert!(initrd.exists(), "initramfs not found at {initrd:?}");

    let mut vm = Vm::builder()
        .kernel(&kernel)
        .initrd(&initrd)
        .memory_mb(256)
        .vcpus(2)
        .vsock(true)
        .build()
        .expect("2-vCPU VM should build");

    vm.start().expect("VM should start");

    // Both run-loop threads publish their kernel TIDs.
    let tids = vm
        .vcpu_kernel_tids(Duration::from_secs(5))
        .expect("both vCPU threads should publish TIDs");
    assert_eq!(tids.len(), 2, "expected 2 vCPU kernel TIDs, got {tids:?}");
    assert!(tids[0] != tids[1], "vCPU TIDs must be distinct: {tids:?}");

    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("agent should connect on a 2-vCPU guest");

    // The busybox initramfs has no `nproc`; count CPUs from /proc.
    let nproc = agent
        .exec(&["sh", "-c", "grep -c ^processor /proc/cpuinfo"])
        .expect("cpu count should run");
    assert_eq!(nproc.exit_code, 0);
    assert_eq!(
        nproc.stdout.trim(),
        "2",
        "guest must see 2 CPUs (MP table + SMP bring-up); serial:\n{}",
        vm.serial_output(Duration::from_secs(1))
    );

    // Pause joins both threads and recovers both vCPU fds; resume
    // restarts both.
    vm.pause().expect("pause should join both vCPU threads");
    assert!(vm.vcpu_fd().is_some(), "vCPU fds recovered on pause");
    vm.resume()
        .expect("resume should restart both vCPU threads");
    let exec = agent.exec(&["echo", "alive"]).expect("exec after resume");
    assert_eq!(exec.stdout.trim(), "alive");

    vm.shutdown();
}

/// A 2-vCPU VM snapshots and restores like a 1-vCPU VM.
/// Both CPUs run a counter before the snapshot; after the `CoW`
/// restore the guest still sees 2 CPUs, both counters advance (both
/// vCPUs execute), and dmesg is free of TSC-unstable / soft-lockup
/// splats (clock sanity).
#[test]
fn test_multi_vcpu_snapshot_restore_roundtrip() {
    let _ = env_logger::builder().is_test(true).try_init();

    let kernel = workspace_path("guest/kernel/vmlinux");
    let initrd = workspace_path("guest/rootfs/initramfs.cpio.gz");
    assert!(kernel.exists(), "guest kernel not found at {kernel:?}");
    assert!(initrd.exists(), "initramfs not found at {initrd:?}");

    let mut vm = Vm::builder()
        .kernel(&kernel)
        .initrd(&initrd)
        .memory_mb(256)
        .vcpus(2)
        .vsock(true)
        .build()
        .expect("2-vCPU VM should build");
    vm.start().expect("VM should start");
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("agent should connect");

    // One counter per CPU (busybox has no taskset; two background
    // loops on a 2-CPU guest schedule across both CPUs). Fully
    // redirect the background jobs' stdio or the exec waits on the
    // inherited pipes forever; write-then-rename keeps reads atomic.
    agent
        .exec(&[
            "sh",
            "-c",
            "for i in 0 1; do (c=0; while true; do c=$((c+1)); \
             echo $c > /tmp/ctr$i.tmp && mv /tmp/ctr$i.tmp /tmp/ctr$i; done) \
             </dev/null >/dev/null 2>&1 & echo $! > /tmp/ctrpid$i; done",
        ])
        .expect("counters should start");
    std::thread::sleep(Duration::from_millis(300));

    let snapshot_dir = tempfile::tempdir().unwrap();
    vm.snapshot(snapshot_dir.path())
        .expect("2-vCPU snapshot should succeed");
    vm.shutdown();
    drop(vm);

    let restore_start = std::time::Instant::now();
    let mut restored = Vm::restore(snapshot_dir.path()).expect("2-vCPU restore should succeed");
    let restore_elapsed = restore_start.elapsed();
    assert_eq!(restored.vcpu_count(), 2, "restored VM must carry 2 vCPUs");
    assert!(
        restore_elapsed <= k7d::latency::RESTORE_2VCPU,
        "2-vCPU CoW restore took {restore_elapsed:?} (budget {:?})",
        k7d::latency::RESTORE_2VCPU
    );
    restored.start().expect("restored VM should start");
    let mut agent2 = restored
        .connect_agent(Duration::from_secs(30))
        .expect("agent should reconnect after restore");

    let nproc = agent2
        .exec(&["sh", "-c", "grep -c ^processor /proc/cpuinfo"])
        .expect("cpu count should run");
    assert_eq!(
        nproc.stdout.trim(),
        "2",
        "restored guest must still see 2 CPUs"
    );

    // Both counters must advance post-restore (both vCPUs execute).
    for i in 0..2 {
        let path = format!("/tmp/ctr{i}");
        let before = agent2.exec(&["cat", &path]).expect("read counter");
        std::thread::sleep(Duration::from_millis(500));
        let after = agent2.exec(&["cat", &path]).expect("read counter");
        let (b, a): (u64, u64) = (
            before.stdout.trim().parse().expect("counter is a number"),
            after.stdout.trim().parse().expect("counter is a number"),
        );
        assert!(a > b, "counter {i} must advance post-restore ({b} -> {a})");
    }

    // Stop the spin loops — two busy vCPUs starve the remaining
    // agent execs on a 2-CPU guest.
    agent2
        .exec(&["sh", "-c", "kill $(cat /tmp/ctrpid0) $(cat /tmp/ctrpid1)"])
        .expect("counters should stop");

    // Clock sanity: no TSC-unstable / soft-lockup splats.
    let dmesg = agent2
        .exec(&[
            "sh",
            "-c",
            "dmesg | grep -ci 'tsc unstable\\|soft lockup\\|clocksource.*unstable' || true",
        ])
        .expect("dmesg should run");
    assert_eq!(
        dmesg.stdout.trim(),
        "0",
        "restored 2-vCPU guest logged clock instability"
    );

    // Guest time is monotonic and alive: /proc/uptime must advance
    // across a host-side sleep (shell builtins only — the busybox
    // initramfs has no `date` symlink). A frozen clock (CHALLENGES.md
    // #40 class of bug) would return the same value twice.
    let read_uptime = |agent: &mut k7d::api::AgentClient| -> f64 {
        let out = agent
            .exec(&["sh", "-c", "read up rest < /proc/uptime; echo $up"])
            .expect("uptime read should run");
        assert_eq!(
            out.exit_code, 0,
            "uptime read failed: stdout={:?} stderr={:?}",
            out.stdout, out.stderr
        );
        out.stdout.trim().parse().expect("uptime seconds")
    };
    let s1 = read_uptime(&mut agent2);
    std::thread::sleep(Duration::from_millis(1100));
    let s2 = read_uptime(&mut agent2);
    assert!(
        s2 > s1,
        "guest clock frozen or backwards after restore: {s1} -> {s2}"
    );

    restored.shutdown();
}

/// Host USER_HZ. Asserted rather than assumed so a different value
/// cannot silently rescale the 10% idle-vCPU bound.
fn host_clk_tck() -> u64 {
    let out = std::process::Command::new("getconf")
        .arg("CLK_TCK")
        .output()
        .expect("getconf CLK_TCK should run");
    assert!(
        out.status.success(),
        "getconf CLK_TCK failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let reported = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert_eq!(
        reported, "100",
        "host USER_HZ is {reported}, not 100; the idle-vCPU bound would be wrong"
    );
    100
}

/// Host CPU time of a kernel thread, in clock ticks, from
/// `/proc/<tid>/stat` (utime + stime).
fn thread_cpu_ticks(tid: u32) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{tid}/stat"))
        .unwrap_or_else(|e| panic!("read /proc/{tid}/stat: {e}"));
    let rest = stat
        .rsplit_once(')')
        .unwrap_or_else(|| panic!("malformed /proc/{tid}/stat: {stat}"))
        .1;
    let mut fields = rest.split_whitespace();
    // After `)`: state ppid … utime(index 11) stime(index 12).
    let utime: u64 = fields
        .nth(11)
        .unwrap_or_else(|| panic!("utime missing in /proc/{tid}/stat: {stat}"))
        .parse()
        .unwrap_or_else(|e| panic!("utime parse: {e}"));
    let stime: u64 = fields
        .next()
        .unwrap_or_else(|| panic!("stime missing in /proc/{tid}/stat: {stat}"))
        .parse()
        .unwrap_or_else(|e| panic!("stime parse: {e}"));
    utime + stime
}

/// An idle vCPU must not burn a host core. `idle=poll` did (100%);
/// haltpoll + HLT at a 200 µs window should sit under 2% over a 5 s
/// sample (a 2 ms window measured 8.2–8.6%). Without this test the
/// work can "succeed" by silently leaving poll-forever behaviour in
/// place.
#[test]
fn test_idle_vcpu_is_cheap() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut vm = Vm::builder()
        .kernel_and_initrd()
        .memory_mb(256)
        .vsock(true)
        .build()
        .expect("VM should build");
    vm.start().expect("VM should start");
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("agent should connect");

    let cmdline = agent
        .exec(&["cat", "/proc/cmdline"])
        .expect("guest /proc/cmdline");
    assert_eq!(cmdline.exit_code, 0, "cat /proc/cmdline: {cmdline:?}");
    assert!(
        !cmdline.stdout.contains("idle=poll"),
        "idle=poll is still on the cmdline; haltpoll will refuse to load: {}",
        cmdline.stdout.trim()
    );
    assert!(
        cmdline.stdout.contains("cpuidle_haltpoll.force=1"),
        "cpuidle_haltpoll.force=1 missing; the driver will not install without \
         KVM_HINTS_REALTIME, which k7d does not advertise: {}",
        cmdline.stdout.trim()
    );
    assert!(
        cmdline
            .stdout
            .contains("haltpoll.guest_halt_poll_allow_shrink=0"),
        "haltpoll shrink still on; a warm-pool idle collapses poll_limit_ns \
         back to plain HLT: {}",
        cmdline.stdout.trim()
    );

    let cfg = agent
        .exec(&[
            "sh",
            "-c",
            "zcat /proc/config.gz | grep -E '^CONFIG_(CPU_IDLE|CPU_IDLE_GOV_HALTPOLL|HALTPOLL_CPUIDLE|NO_HZ_IDLE)='",
        ])
        .expect("guest /proc/config.gz");
    assert_eq!(cfg.exit_code, 0, "config.gz grep: {cfg:?}");
    for want in [
        "CONFIG_CPU_IDLE=y",
        "CONFIG_CPU_IDLE_GOV_HALTPOLL=y",
        "CONFIG_HALTPOLL_CPUIDLE=y",
        "CONFIG_NO_HZ_IDLE=y",
    ] {
        assert!(
            cfg.stdout.lines().any(|l| l.trim() == want),
            "booted guest kernel is missing {want}: {}",
            cfg.stdout.trim()
        );
    }

    let gov = agent
        .exec(&["cat", "/sys/devices/system/cpu/cpuidle/current_governor"])
        .expect("cpuidle governor");
    assert_eq!(
        gov.exit_code, 0,
        "cpuidle governor sysfs missing (haltpoll did not install): {gov:?}"
    );
    assert_eq!(
        gov.stdout.trim(),
        "haltpoll",
        "guest idle governor is {}, not haltpoll — the force=1 gate failed or \
         the driver lost to ladder",
        gov.stdout.trim()
    );

    // The governor starts poll_limit_ns at 0 and shrinks it after a
    // long idle. If these params did not take, a warm-pool VM is back
    // to plain HLT on the next request (the virtiofs-write pattern).
    let params = agent
        .exec(&[
            "sh",
            "-c",
            "for f in /sys/module/haltpoll/parameters/*; do echo \"$(basename $f)=$(cat $f)\"; done",
        ])
        .expect("haltpoll module params");
    assert_eq!(params.exit_code, 0, "haltpoll params: {params:?}");
    eprintln!("haltpoll params:\n{}", params.stdout.trim());
    assert!(
        params
            .stdout
            .lines()
            .any(|l| l.trim() == "guest_halt_poll_ns=200000"),
        "guest_halt_poll_ns not 200 µs: {}",
        params.stdout.trim()
    );
    assert!(
        params.stdout.contains("guest_halt_poll_allow_shrink=N")
            || params.stdout.contains("guest_halt_poll_allow_shrink=0"),
        "shrink still enabled: {}",
        params.stdout.trim()
    );

    let tid = vm
        .vcpu_kernel_tid(Duration::from_secs(5))
        .expect("vCPU thread should publish its kernel TID");

    let clk_tck = host_clk_tck();
    let sample = Duration::from_secs(5);
    let t0 = thread_cpu_ticks(tid);
    let wall0 = std::time::Instant::now();
    std::thread::sleep(sample);
    let t1 = thread_cpu_ticks(tid);
    let wall = wall0.elapsed();

    let delta_ticks = t1.saturating_sub(t0);
    let cpu_frac = delta_ticks as f64 / clk_tck as f64 / wall.as_secs_f64();
    eprintln!(
        "idle vCPU tid={tid}: {delta_ticks} ticks over {wall:?} = {:.1}% of a host core",
        cpu_frac * 100.0
    );
    assert!(
        cpu_frac < 0.02,
        "idle vCPU used {:.1}% of a host core over {wall:?} (budget 2%); \
         leftover PIT ticks are still charging a too-wide poll window",
        cpu_frac * 100.0
    );

    vm.shutdown();
}
