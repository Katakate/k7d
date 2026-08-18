//! Repro loop for CHALLENGES #97: `test_fork_requeues_interrupted_injection`
//! in a loop, dumping the deaf fork's serial tail on each failure.
//!
//! Args: `<iterations> <vector>`. Vector `0` skips the forced injection
//! entirely, which is the control arm — that is how the flake was pinned on
//! the forcing rather than on the fork path itself (0 failures in 150).
//! Any non-zero vector reproduces, so it is not specific to the `0x35` the
//! test uses. Run it against two `guest/kernel/vmlinux` builds to compare
//! rates; on this guest the flake predates the 24a-inc1 kernel.
use std::time::Duration;

use k7d::api::AgentClient;
use k7d::vm::Vm;

fn main() {
    env_logger::init();
    let iters: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);
    let vector: u8 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0x35);

    let mut failures = 0usize;
    for i in 0..iters {
        let mut source = Vm::builder()
            .kernel_and_initrd()
            .memory_mb(256)
            .vsock(true)
            .build()
            .expect("build");
        source.start().expect("start");
        let _ = source
            .connect_agent(Duration::from_secs(90))
            .expect("agent");
        source.prepare_fork_source().expect("prepare");
        let mut agent = source
            .connect_agent(Duration::from_secs(30))
            .expect("reconnect");
        agent.exec(&["echo", "warm"]).expect("exec");

        let base = source
            .fork_source_base_path()
            .expect("prepared")
            .to_path_buf();
        source.pause().expect("pause");
        let dirty = source.get_and_accumulate_dirty().unwrap().to_vec();
        let mut state = k7d::snapshot::capture_vm_state(&source).expect("capture");
        let src_mem = source.mem_host_addr();
        if vector != 0 {
            let ev = state.cpus[0].vcpu_events.as_mut().expect("events");
            ev.data[8] = 1;
            ev.data[9] = vector;
        }
        let fork = k7d::fork::restore_vm_from_state(&base, &dirty, src_mem, &state, "reinject");
        source.resume().expect("resume");
        let mut fork = fork.expect("materialise");
        fork.start().expect("start fork");
        match AgentClient::connect_vsock(fork.guest_cid(), Duration::from_secs(10)) {
            Ok(_) => eprintln!("iter {i}: ok"),
            Err(e) => {
                failures += 1;
                eprintln!("iter {i}: DEAF ({e})");
                let serial = fork.serial_output(Duration::from_secs(1));
                eprintln!(
                    "--- fork serial tail ---\n{}\n--- end ---",
                    &serial[serial.len().saturating_sub(3000)..]
                );
            }
        }
        fork.shutdown();
        source.shutdown();
    }
    eprintln!("done: {iters} iterations, {failures} failures");
}
