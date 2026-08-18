//! Diagnostic repro loop for the referenced work: warm fork → vsock connect, N times.
//!
//! Not a test. Run manually on the node (needs KVM + vhost-vsock + guest):
//!
//! ```sh
//! RUST_LOG=info cargo run --release -p k7d --example fork_repro -- 300
//! ```
//!
//! Each iteration drives agent traffic on the source (to keep vsock
//! interrupts in flight), captures the source state by hand (the same
//! capture `fork_warm` performs) so the captured `vcpu_events` / LAPIC
//! are inspectable, materialises a fork, and probes its agent with a
//! short 3 s connect (normal is < 100 ms). On a probe failure it keeps
//! trying for the full 30 s the real tests use, then pauses the deaf
//! fork and dumps its LAPIC ISR/IRR, `vcpu_events`, `mp_state` and the
//! IOAPIC redirection table — the evidence the referenced work asks for.

use std::time::Duration;

use k7d::api::AgentClient;
use k7d::snapshot::CpuState;
use k7d::vm::Vm;

/// Decode the 256-bit IRR/ISR register banks out of raw LAPIC bytes.
/// Each of the 8 banks is 4 bytes wide at stride 0x10.
fn lapic_bank(lapic: &[u8], base: usize) -> [u32; 8] {
    let mut out = [0u32; 8];
    for (i, slot) in out.iter_mut().enumerate() {
        let off = base + i * 0x10;
        if off + 4 <= lapic.len() {
            *slot =
                u32::from_le_bytes([lapic[off], lapic[off + 1], lapic[off + 2], lapic[off + 3]]);
        }
    }
    out
}

fn vectors(banks: &[u32; 8]) -> Vec<u32> {
    let mut v = Vec::new();
    for (i, &bank) in banks.iter().enumerate() {
        for bit in 0..32 {
            if bank & (1 << bit) != 0 {
                v.push((i as u32) * 32 + bit);
            }
        }
    }
    v
}

fn decode_events(data: &[u8]) -> String {
    // kvm_vcpu_events layout: exception{injected,nr,has_error_code,pending}
    // @0, error_code @4, interrupt{injected,nr,soft,shadow} @8,
    // nmi{injected,pending,masked} @12, sipi_vector @16, flags @20.
    if data.len() < 24 {
        return format!("short ({} bytes)", data.len());
    }
    format!(
        "exception(injected={} nr={} pending={}) interrupt(injected={} nr={} soft={} shadow={}) \
         nmi(injected={} pending={} masked={}) sipi={} flags={:#x}",
        data[0],
        data[1],
        data[3],
        data[8],
        data[9],
        data[10],
        data[11],
        data[12],
        data[13],
        data[14],
        u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
        u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
    )
}

fn summarize_captured(tag: &str, cpu: &CpuState) {
    let irr = vectors(&lapic_bank(&cpu.lapic, 0x200));
    let isr = vectors(&lapic_bank(&cpu.lapic, 0x100));
    let events = cpu
        .vcpu_events
        .as_ref()
        .map_or_else(|| "none".to_string(), |e| decode_events(&e.data));
    eprintln!(
        "{tag}: mp_state={:?} lapic_irr={irr:?} lapic_isr={isr:?} events: {events}",
        cpu.mp_state
    );
}

fn dump_fork_state(fork: &mut Vm) {
    fork.pause().expect("pause deaf fork");
    let Some(vcpu) = fork.vcpu_fd() else {
        eprintln!("deaf fork: no vcpu fd after pause");
        return;
    };
    match vcpu.get_lapic() {
        Ok(lapic) => {
            let bytes: Vec<u8> = lapic.regs.iter().map(|&b| b as u8).collect();
            let irr = vectors(&lapic_bank(&bytes, 0x200));
            let isr = vectors(&lapic_bank(&bytes, 0x100));
            eprintln!("deaf fork LAPIC: irr={irr:?} isr={isr:?}");
        }
        Err(e) => eprintln!("deaf fork KVM_GET_LAPIC: {e}"),
    }
    match vcpu.get_vcpu_events() {
        Ok(ev) => {
            // SAFETY: kvm_vcpu_events is plain-old-data; reading it as bytes
            // for decoding is always valid.
            let bytes: &[u8] = unsafe {
                std::slice::from_raw_parts(
                    std::ptr::from_ref(&ev).cast::<u8>(),
                    std::mem::size_of_val(&ev),
                )
            };
            eprintln!("deaf fork vcpu_events: {}", decode_events(bytes));
        }
        Err(e) => eprintln!("deaf fork KVM_GET_VCPU_EVENTS: {e}"),
    }
    match vcpu.get_mp_state() {
        Ok(mp) => eprintln!("deaf fork mp_state: {}", mp.mp_state),
        Err(e) => eprintln!("deaf fork KVM_GET_MP_STATE: {e}"),
    }
    match vcpu.get_regs() {
        Ok(regs) => eprintln!("deaf fork rip={:#x} rflags={:#x}", regs.rip, regs.rflags),
        Err(e) => eprintln!("deaf fork KVM_GET_REGS: {e}"),
    }
    let mut chip = kvm_bindings::kvm_irqchip {
        chip_id: kvm_bindings::KVM_IRQCHIP_IOAPIC,
        ..Default::default()
    };
    match fork.vm_fd().get_irqchip(&mut chip) {
        Ok(()) => {
            // SAFETY: chip_id requested IOAPIC, so the union holds ioapic.
            let ioapic = unsafe { chip.chip.ioapic };
            for (pin, entry) in ioapic.redirtbl.iter().enumerate() {
                // SAFETY: kvm_ioapic_entry is a union of bits/fields.
                let bits = unsafe { entry.bits };
                if bits != 0 {
                    let vector = bits & 0xff;
                    let remote_irr = (bits >> 14) & 1;
                    let masked = (bits >> 16) & 1;
                    eprintln!(
                        "deaf fork IOAPIC pin {pin}: vector={vector} \
                         remote_irr={remote_irr} masked={masked} irr_bit={}",
                        (ioapic.irr >> pin) & 1
                    );
                }
            }
        }
        Err(e) => eprintln!("deaf fork KVM_GET_IRQCHIP: {e}"),
    }
}

#[allow(clippy::too_many_lines)]
fn main() {
    env_logger::init();
    let iters: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);

    let mut source = Vm::builder()
        .kernel_and_initrd()
        .memory_mb(256)
        .vsock(true)
        .build()
        .expect("build source VM");
    source.start().expect("start source");
    let mut agent = source
        .connect_agent(Duration::from_secs(90))
        .expect("connect source agent");
    agent.ping().expect("ping source");
    source.prepare_fork_source().expect("prepare_fork_source");
    let mut agent = source
        .connect_agent(Duration::from_secs(30))
        .expect("reconnect after prepare_fork_source");

    let mut failures = 0usize;
    for i in 0..iters {
        // Traffic right before the pause keeps vsock interrupts in flight —
        // the window the flake lives in.
        agent
            .exec(&["sh", "-c", "echo x > /tmp/m"])
            .expect("source exec");

        // Replicate fork_warm_batch by hand so the captured state stays
        // inspectable after a failure.
        let base_path = source
            .fork_source_base_path()
            .expect("fork source prepared")
            .to_path_buf();
        source.pause().expect("pause source");
        let dirty = source
            .get_and_accumulate_dirty()
            .expect("dirty bitmap")
            .to_vec();
        let state = k7d::snapshot::capture_vm_state(&source).expect("capture state");
        let src_mem = source.mem_host_addr();
        let fork_id = format!("repro-{i}");
        let fork = k7d::fork::restore_vm_from_state(&base_path, &dirty, src_mem, &state, &fork_id);
        source.resume().expect("resume source");
        let mut fork = fork.expect("materialise fork");

        fork.start().expect("start fork");
        let probe = AgentClient::connect_vsock(fork.guest_cid(), Duration::from_secs(3));
        match probe {
            Ok(mut fork_agent) => {
                fork_agent.ping().expect("fork ping");
                drop(fork_agent);
            }
            Err(e) => {
                failures += 1;
                eprintln!("=== iteration {i}: fork deaf after 3 s probe: {e}");
                summarize_captured("captured source vCPU0", &state.cpus[0]);
                // Confirm permanent deafness with the full window the real
                // tests use before dumping state.
                let retry = AgentClient::connect_vsock(fork.guest_cid(), Duration::from_secs(27));
                match retry {
                    Ok(_) => eprintln!("iteration {i}: fork answered late (within 30 s)"),
                    Err(e2) => {
                        eprintln!("iteration {i}: fork still deaf after 30 s: {e2}");
                        dump_fork_state(&mut fork);
                    }
                }
            }
        }
        fork.shutdown();
        drop(fork);
        if i % 25 == 24 {
            let fds = std::fs::read_dir("/proc/self/fd").map_or(0, Iterator::count);
            eprintln!(
                "progress: {}/{iters} iterations, {failures} failures, {fds} open fds",
                i + 1
            );
        }
    }
    // Summarise the process fd table so leaks (fds surviving fork Drop)
    // are attributable by kind.
    let mut kinds: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    if let Ok(dir) = std::fs::read_dir("/proc/self/fd") {
        for entry in dir.flatten() {
            let target = std::fs::read_link(entry.path())
                .map_or_else(|_| "?".into(), |p| p.to_string_lossy().into_owned());
            let kind: String = target
                .chars()
                .map(|c| if c.is_ascii_digit() { 'N' } else { c })
                .collect();
            *kinds.entry(kind).or_default() += 1;
        }
    }
    for (kind, count) in &kinds {
        eprintln!("fd kind {kind}: {count}");
    }
    eprintln!("done: {iters} iterations, {failures} failures");
    if failures > 0 {
        std::process::exit(1);
    }
}
