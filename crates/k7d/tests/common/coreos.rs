//! Shared helpers for CoreOS-family guests (RHCOS, CentOS Stream
//! CoreOS) booted on k7d's virtio-pci bus: sha256-pinned artifact
//! fetch, Ignition snippets whose units write to ttyS0, and the serial
//! console assertions every such boot uses.

use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use k7d::vm::Vm;

/// Markers the Ignition-injected units print on ttyS0.
pub const PROBE_BEGIN: &str = "K7D-PROBE-BEGIN";
pub const PROBE_END: &str = "K7D-PROBE-END";
pub const HEARTBEAT: &str = "K7D-HEARTBEAT";

pub fn sha256_of(path: &Path) -> String {
    let out = Command::new("sha256sum")
        .arg(path)
        .output()
        .expect("sha256sum");
    assert!(out.status.success(), "sha256sum {}", path.display());
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string()
}

/// Fetch `mirror/name` into `cache_dir` unless a copy with the pinned
/// digest is already there. A cached file with the wrong digest is
/// replaced, never trusted.
pub fn fetch(cache_dir: &str, mirror: &str, spec: (&str, &str)) -> PathBuf {
    let (name, want) = spec;
    fs::create_dir_all(cache_dir).expect("create artifact cache dir");
    let dest = Path::new(cache_dir).join(name);
    if dest.is_file() && sha256_of(&dest) == want {
        return dest;
    }
    let part = dest.with_extension("part");
    let _ = fs::remove_file(&part);
    eprintln!("==> downloading {mirror}/{name}");
    let status = Command::new("curl")
        .args(["-fsSL", "--retry", "3", "-o"])
        .arg(&part)
        .arg(format!("{mirror}/{name}"))
        .status()
        .expect("run curl");
    assert!(status.success(), "download of {name} failed");
    let got = sha256_of(&part);
    assert_eq!(got, want, "{name}: sha256 mismatch after download");
    fs::rename(&part, &dest).expect("move artifact into place");
    dest
}

/// Live kernel plus a single initrd: the initramfs with the rootfs
/// cpio appended, which CoreOS documents as equivalent to
/// `coreos.live.rootfs_url`.
pub fn live_artifacts(
    cache_dir: &str,
    mirror: &str,
    kernel: (&str, &str),
    initramfs: (&str, &str),
    rootfs: (&str, &str),
) -> (PathBuf, PathBuf) {
    let kernel = fetch(cache_dir, mirror, kernel);
    let initramfs_path = fetch(cache_dir, mirror, initramfs);
    let rootfs_path = fetch(cache_dir, mirror, rootfs);
    let combined = Path::new(cache_dir).join(format!(
        "live-initrd-{}-{}.img",
        &initramfs.1[..12],
        &rootfs.1[..12]
    ));
    if !combined.is_file() {
        let part = combined.with_extension("part");
        let mut data = fs::read(&initramfs_path).expect("read initramfs");
        data.extend(fs::read(&rootfs_path).expect("read rootfs"));
        fs::write(&part, &data).expect("write combined initrd");
        fs::rename(&part, &combined).expect("move combined initrd");
    }
    (kernel, combined)
}

pub fn base64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n =
            chunk.iter().fold(0u32, |acc, &b| (acc << 8) | u32::from(b)) << (8 * (3 - chunk.len()));
        for i in 0..=chunk.len() {
            out.push(T[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
        }
        for _ in chunk.len()..3 {
            out.push('=');
        }
    }
    out
}

/// An uncompressed SVR4 ("newc") cpio archive holding one regular
/// file, to append to a live initramfs. CoreOS's initramfs copies
/// `/config.ign` from there into Ignition's user-config slot
/// (`coreos-ignition-setup-user`), which is how a config too big for
/// the kernel command line reaches a PXE-style boot.
pub fn cpio_with_file(name: &str, data: &[u8]) -> Vec<u8> {
    fn entry(out: &mut Vec<u8>, name: &str, mode: u32, data: &[u8]) {
        let nsize = name.len() + 1;
        out.extend_from_slice(
            format!(
                "070701{:08x}{mode:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{nsize:08x}{:08x}",
                1, 0, 0, 1, 0, data.len(), 0, 0, 0, 0, 0
            )
            .as_bytes(),
        );
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out.extend_from_slice(data);
        while out.len() % 4 != 0 {
            out.push(0);
        }
    }
    let mut out = Vec::with_capacity(data.len() + 512);
    entry(&mut out, name, 0o100_644, data);
    entry(&mut out, "TRAILER!!!", 0, &[]);
    while out.len() % 512 != 0 {
        out.push(0);
    }
    out
}

/// The bus, the kernel, the address, and a ping — what every boot of
/// a CoreOS guest in these tests has to show on ttyS0.
pub fn probe_script(gateway: Ipv4Addr, extra: &str) -> String {
    format!(
        "echo {PROBE_BEGIN}; lspci -n; \
         for d in /sys/bus/virtio/devices/*; do echo \\\"$(basename $d) -> $(readlink -f $d)\\\"; done; \
         for d in /sys/bus/pci/devices/*; do echo \\\"$(basename $d) $(cat $d/vendor):$(cat $d/device) irq=$(cat $d/irq)\\\"; done; \
         uname -r; grep -m1 PRETTY_NAME /etc/os-release; {extra}\
         n=0; until ping -c1 -W1 {gateway} >/dev/null 2>&1 || [ $n -ge 90 ]; do n=$((n+1)); sleep 1; done; \
         echo K7D-ADDR $(ip -4 -o addr show dev eth0 2>&1); \
         ping -c1 -W3 {gateway} >/dev/null && echo K7D-PING-OK after $n s; \
         echo {PROBE_END}"
    )
}

/// A systemd unit as an Ignition `systemd.units` element, writing
/// straight to ttyS0. systemd expands `$WORD` in ExecStart; `$$` is a
/// literal dollar.
pub fn unit(name: &str, body: &str) -> String {
    let body = body.replace('$', "$$");
    format!(
        r#"{{"name":"{name}","enabled":true,"contents":"[Unit]\nDescription={name}\nAfter=network-online.target\n[Service]\nStandardOutput=tty\nTTYPath=/dev/ttyS0\nExecStart=/bin/sh -c '{body}'\n[Install]\nWantedBy=multi-user.target\n"}}"#
    )
}

pub fn heartbeat_unit() -> String {
    heartbeat_unit_every(1)
}

/// A heartbeat every `secs` seconds; a long-running install does not
/// need one per second on its console.
pub fn heartbeat_unit_every(secs: u32) -> String {
    unit(
        "k7d-heartbeat.service",
        &format!(
            "while :; do echo {HEARTBEAT} $(cut -d\\\" \\\" -f1 /proc/uptime); sleep {secs}; done"
        ),
    )
}

/// Ignition 3.4 config with the given units. agetty on ttyS0 would
/// vhangup() the units' console fds a few seconds in (the first run of
/// the live test lost both after one heartbeat); this is a probe, not a
/// login console.
pub fn ignition(units: &[String]) -> String {
    format!(
        r#"{{"ignition":{{"version":"3.4.0"}},"systemd":{{"units":[{{"name":"serial-getty@ttyS0.service","mask":true}},{}]}}}}"#,
        units.join(",")
    )
}

/// Block until `needle` shows up on the VM's COM1, or panic with the
/// whole console so far.
pub fn wait_serial(vm: &Vm, whose: &str, needle: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        let out = vm.serial_output(Duration::from_millis(500));
        if out.contains(needle) {
            return out;
        }
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            !out.contains("Kernel panic"),
            "{whose}: guest panicked\n--- serial ---\n{out}"
        );
        assert!(
            Instant::now() < deadline,
            "{whose}: no {needle:?} on serial within {timeout:?}\n--- serial ---\n{out}"
        );
    }
}

/// Number of heartbeat lines on the console so far.
pub fn heartbeats(vm: &Vm) -> usize {
    vm.serial_output(Duration::from_millis(100))
        .matches(HEARTBEAT)
        .count()
}

/// The guest is scheduled: a new heartbeat lands within 30 s.
pub fn assert_alive(vm: &Vm, whose: &str) {
    let before = heartbeats(vm);
    let deadline = Instant::now() + Duration::from_secs(30);
    while heartbeats(vm) <= before {
        assert!(
            Instant::now() < deadline,
            "{whose}: no new heartbeat on serial in 30 s (had {before})\n--- serial (tail) ---\n{}",
            tail(&vm.serial_output(Duration::from_millis(100)), 40)
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

pub fn tail(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

/// Block until the guest has torn itself down (a reboot ends the VM:
/// without ACPI the kernel pulses the i8042 reset line and k7d takes
/// that as the reset, CHALLENGES #308), or panic with the console.
pub fn wait_guest_exit(vm: &Vm, whose: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !vm.guest_exited() {
        assert!(
            Instant::now() < deadline,
            "{whose}: guest still running {timeout:?} after asking for a reboot\n--- serial (tail) ---\n{}",
            tail(&vm.serial_output(Duration::from_millis(100)), 40)
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// The virtio-pci functions k7d puts on the bus with one disk and one
/// NIC, as the probe prints them: host bridge, blk at 00:01.0 on IRQ 5,
/// net at 00:02.0 on IRQ 6, both virtio devices hanging off them, an
/// address on eth0, and the gateway answering.
pub fn assert_pci_probe(probe: &str, whose: &str) {
    for (what, needle) in [
        ("host bridge", "0000:00:00.0 0x8086:0x1237"),
        ("virtio-blk function", "0000:00:01.0 0x1af4:0x1042 irq=5"),
        ("virtio-net function", "0000:00:02.0 0x1af4:0x1041 irq=6"),
        ("lspci blk", "1af4:1042"),
        ("lspci net", "1af4:1041"),
        (
            "virtio0 on the bus",
            "virtio0 -> /sys/devices/pci0000:00/0000:00:01.0/virtio0",
        ),
        (
            "virtio1 on the bus",
            "virtio1 -> /sys/devices/pci0000:00/0000:00:02.0/virtio1",
        ),
        ("eth0 addressed", "K7D-ADDR 2: eth0 inet 10.200.0."),
        ("gateway reachable over virtio-net", "K7D-PING-OK"),
    ] {
        assert!(
            probe.contains(needle),
            "{whose}: {what} missing ({needle:?})"
        );
    }
}

/// The probe section of a console transcript (from `PROBE_BEGIN` to
/// `PROBE_END`, or to the end if the probe is still running).
pub fn probe_section(out: &str) -> &str {
    let start = out.find(PROBE_BEGIN).unwrap_or(0);
    let end = out[start..]
        .find(PROBE_END)
        .map_or(out.len(), |e| start + e);
    &out[start..end]
}
