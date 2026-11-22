//! The smallest open-source cluster on k7d's virtio-pci bus: a
//! single-node OKD, installed from public registries with no Red Hat
//! pull secret and no commercial installer, until the node is `Ready`
//! and one pod is `Running`.
//!
//! OKD 4.22 runs on CentOS Stream CoreOS 10 (`6.12.0-*.el10` kernel,
//! `# CONFIG_VIRTIO_MMIO is not set`, `CONFIG_VIRTIO_PCI=y`), so like
//! RHCOS it needs the PCI transport, and since it boots from its own
//! ostree deployment it needs the disk-boot path from
//! `test_rhcos_boot.rs` (`crates/k7d/src/bls.rs`).
//!
//! The flow is OKD's documented single-node "bootstrap in place":
//!
//! 1. `openshift-install create single-node-ignition-config` with a
//!    placeholder pull secret (every image is public on `quay.io/okd`)
//!    gives one Ignition config for the live system. k7d appends it to
//!    the live initramfs as `/config.ign` — it is 300 KiB, far past the
//!    kernel command line, and the live PXE path reads it from there.
//! 2. The live SCOS boots on `transport: pci`, runs the bootstrap
//!    control plane, `coreos-installer`s itself onto `/dev/vda` with
//!    `master.ign`, and reboots. The reboot ends the VM.
//! 3. k7d reads the installed disk's BLS entry and boots it. The node
//!    may reboot itself again (node-image pull, MCO); each exit is
//!    answered by another boot from the disk's then-current entry.
//! 4. The host's `oc`, with the installer's admin kubeconfig, watches
//!    the API at the guest's address until the node is `Ready` and a
//!    pod is `Running`.
//!
//! Not in scope: more nodes, workloads beyond the cluster's own pods,
//! anything that needs a pull secret.

mod common;

use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use common::coreos::{
    assert_alive, assert_pci_probe, base64, cpio_with_file, fetch, heartbeat_unit_every, ignition,
    live_artifacts, probe_script, probe_section, tail, unit, wait_serial, PROBE_END,
};
use k7d::bls::DiskBoot;
use k7d::network::{ClusterNetwork, TapDevice};
use k7d::virtio_mmio::Transport;
use k7d::vm::Vm;
use serde_json::{json, Value};

const CACHE_DIR: &str = "/var/cache/k7d-okd";

/// OKD release: installer and client from the project's GitHub
/// releases (open source, no Red Hat account), payload on `quay.io/okd`.
const OKD_RELEASE: &str = "4.22.0-okd-scos.9";
const OKD_MIRROR: &str = "https://github.com/okd-project/okd/releases/download/4.22.0-okd-scos.9";
const INSTALLER: (&str, &str) = (
    "openshift-install-linux-4.22.0-okd-scos.9.tar.gz",
    "97d3aa143f6f9f06a5657ca49a9252a57267d09e34f34b6779e7d30413042974",
);
const CLIENT: (&str, &str) = (
    "openshift-client-linux-4.22.0-okd-scos.9.tar.gz",
    "388fd080e2006fb1277ff0d37a16172fa084bd90d1caf120e056eb8d72850bc9",
);

/// The machine OS that release's `stream.json` points at: CentOS
/// Stream CoreOS 10.0.20251103-0, live PXE artifacts.
const SCOS_MIRROR: &str =
    "https://rhcos.mirror.openshift.com/art/storage/prod/streams/c10s/builds/10.0.20251103-0/x86_64";
const KERNEL: (&str, &str) = (
    "scos-10.0.20251103-0-live-kernel.x86_64",
    "8e179034e341e611bb806f63749053f1956d4afcf57c38f9ef336a3419376921",
);
const INITRAMFS: (&str, &str) = (
    "scos-10.0.20251103-0-live-initramfs.x86_64.img",
    "e3e7db3e3c866bb42a21e9e55f1d240a29aa63413fcfd8ce62c63eba74f156f8",
);
const ROOTFS: (&str, &str) = (
    "scos-10.0.20251103-0-live-rootfs.x86_64.img",
    "839292fe670cfadfb07a46caa0905138d48ead3938176fed91303e54855573be",
);

/// OKD's single-node floor: 8 vCPUs, 16 GiB, 120 GiB. The disk is
/// sparse; the install and the node image write ~15 GiB of it.
const VCPUS: u32 = 8;
const MEMORY_MB: u64 = 16 * 1024;
const DISK_BYTES: u64 = 120 << 30;

const CLUSTER: &str = "okd";
const DOMAIN: &str = "k7d.test";
const HOSTNAME: &str = "okd";
/// `{"auths":{"fake":{"auth":"aWQ6cGFzcwo="}}}` — OKD's documented
/// placeholder; the installer insists on the field, no registry sees it.
const PULL_SECRET: &str = r#"{\"auths\":{\"fake\":{\"auth\":\"aWQ6cGFzcwo=\"}}}"#;

/// The live boot carries an 850 MiB initrd and pulls the node image
/// before `multi-user.target`; measured 360-560 s on the Ryzen 5 node.
const BOOT_CEILING: Duration = Duration::from_secs(900);
/// Bootstrap: pull the release payload and the node image, run the
/// bootstrap control plane, install to disk.
const BOOTSTRAP_CEILING: Duration = Duration::from_secs(60 * 60);
/// From the first boot off the disk to node `Ready` + a running pod,
/// across however many reboots the node gives itself.
const CLUSTER_CEILING: Duration = Duration::from_secs(60 * 60);
const MAX_DISK_BOOTS: usize = 6;

fn gateway() -> Ipv4Addr {
    Ipv4Addr::new(10, 200, 0, 1)
}

/// Unpack `binary` from the release tarball into the cache once.
fn okd_binary(tarball: (&str, &str), binary: &str) -> PathBuf {
    let dest = Path::new(CACHE_DIR).join(binary);
    let archive = fetch(CACHE_DIR, OKD_MIRROR, tarball);
    if !dest.is_file() {
        let status = Command::new("tar")
            .args(["xzf"])
            .arg(&archive)
            .args(["-C", CACHE_DIR, binary])
            .status()
            .expect("run tar");
        assert!(status.success(), "unpack {binary} from {}", tarball.0);
    }
    dest
}

fn run(cmd: &mut Command) -> String {
    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("spawn {cmd:?}: {e}"));
    assert!(
        out.status.success(),
        "{cmd:?} failed\n--- stdout ---\n{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Decode an Ignition `data:` URL (base64 or percent-encoded).
fn data_url_decode(src: &str) -> Vec<u8> {
    let (meta, body) = src
        .strip_prefix("data:")
        .and_then(|s| s.split_once(','))
        .unwrap_or_else(|| panic!("not a data URL: {src}"));
    if meta.ends_with(";base64") {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = Vec::with_capacity(body.len() / 4 * 3);
        let mut acc = 0u32;
        let mut bits = 0;
        for c in body.bytes().filter(|c| *c != b'=') {
            let v = T.iter().position(|t| *t == c).expect("base64 alphabet") as u32;
            acc = (acc << 6) | v;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
            }
        }
        out
    } else {
        let b = body.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' && i + 2 < b.len() {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).expect("utf8");
                out.push(u8::from_str_radix(hex, 16).expect("percent escape"));
                i += 3;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        out
    }
}

fn data_url(contents: &str) -> String {
    format!(
        "data:text/plain;charset=utf-8;base64,{}",
        base64(contents.as_bytes())
    )
}

/// Name resolution the cluster needs and this bridge does not offer:
/// `api.` and `api-int.` are the node itself.
fn hosts_file(guest_ip: Ipv4Addr) -> Value {
    json!({
        "path": "/etc/hosts",
        "overwrite": true,
        "mode": 420,
        "contents": {"source": data_url(&format!(
            "127.0.0.1 localhost localhost.localdomain\n::1 localhost\n\
             {guest_ip} api.{CLUSTER}.{DOMAIN} api-int.{CLUSTER}.{DOMAIN} {HOSTNAME}\n"
        ))}
    })
}

/// The kargs GRUB would have to pass for this VMM (CHALLENGES #308 for
/// `reboot=k`, the MP table's IOAPIC for `noapic`), plus the static
/// address and a resolver, since nothing on the bridge hands those out.
fn kargs(guest_ip: Ipv4Addr) -> String {
    format!(
        "console=ttyS0,115200 noapic reboot=k panic=1 net.ifnames=0 \
         ip={guest_ip}::{}:255.255.255.0:{HOSTNAME}:eth0:none nameserver=1.1.1.1",
        gateway()
    )
}

/// Units merged into both Ignition configs: no agetty on the probe
/// console, the PCI probe, a heartbeat, and a journal tail of the
/// services that carry the install forward.
fn probe_units(services: &str) -> Vec<Value> {
    let units = ignition(&[
        unit("k7d-probe.service", &probe_script(gateway(), "")),
        heartbeat_unit_every(10),
        unit(
            "k7d-progress.service",
            &format!("journalctl -f -o short-monotonic --no-hostname -u {services}"),
        ),
    ]);
    let mut v: Value = serde_json::from_str(&units).expect("units json");
    v["systemd"]["units"]
        .as_array_mut()
        .expect("units array")
        .clone()
}

/// A MachineConfig for the installed node: the same probe, plus
/// `/etc/hosts`. This is how the config reaches `master.ign`, which
/// bootkube renders on the live system from the manifests.
fn probe_machine_config(guest_ip: Ipv4Addr) -> Value {
    json!({
        "apiVersion": "machineconfiguration.openshift.io/v1",
        "kind": "MachineConfig",
        "metadata": {
            "name": "99-master-k7d-probe",
            "labels": {"machineconfiguration.openshift.io/role": "master"}
        },
        "spec": {"config": {
            "ignition": {"version": "3.2.0"},
            "storage": {"files": [hosts_file(guest_ip)]},
            "systemd": {"units": probe_units(
                "bootstrap-in-place-post-reboot.service -u node-image-pull.service \
                 -u crio.service"
            )}
        }}
    })
}

/// `openshift-install` end to end: install-config, manifests plus our
/// MachineConfig, the bootstrap-in-place Ignition. Returns that config
/// (patched for this VMM) and the admin kubeconfig.
fn generate_ignition(installer: &Path, dir: &Path, guest_ip: Ipv4Addr) -> (Vec<u8>, PathBuf) {
    fs::create_dir_all(dir).expect("install dir");
    fs::write(
        dir.join("install-config.yaml"),
        format!(
            "apiVersion: v1\nbaseDomain: {DOMAIN}\nmetadata:\n  name: {CLUSTER}\n\
             compute:\n- name: worker\n  replicas: 0\n\
             controlPlane:\n  name: master\n  replicas: 1\n\
             networking:\n  clusterNetwork:\n  - cidr: 10.128.0.0/14\n    hostPrefix: 23\n  \
             machineNetwork:\n  - cidr: 10.200.0.0/24\n  networkType: OVNKubernetes\n  \
             serviceNetwork:\n  - 172.30.0.0/16\n\
             platform:\n  none: {{}}\n\
             bootstrapInPlace:\n  installationDisk: /dev/vda\n\
             pullSecret: \"{PULL_SECRET}\"\n"
        ),
    )
    .expect("write install-config");
    run(Command::new(installer)
        .args(["create", "manifests", "--dir"])
        .arg(dir));
    fs::write(
        dir.join("openshift/99-master-k7d-probe.yaml"),
        serde_json::to_string_pretty(&probe_machine_config(guest_ip)).expect("mc json"),
    )
    .expect("write machineconfig");
    run(Command::new(installer)
        .args(["create", "single-node-ignition-config", "--dir"])
        .arg(dir));

    let mut ign: Value = serde_json::from_slice(
        &fs::read(dir.join("bootstrap-in-place-for-live-iso.ign")).expect("read bip ignition"),
    )
    .expect("bip ignition json");
    // The installer's install-to-disk writes the live image's defaults
    // to the BLS entry; this VMM needs its own kargs there (same list
    // the RHCOS install test passes), and `-n` keeps the live network
    // config on top.
    let files = ign["storage"]["files"]
        .as_array_mut()
        .expect("storage.files");
    let script = files
        .iter_mut()
        .find(|f| f["path"] == "/usr/local/bin/install-to-disk.sh")
        .expect("install-to-disk.sh in the bip ignition");
    let text = String::from_utf8(data_url_decode(
        script["contents"]["source"].as_str().expect("source"),
    ))
    .expect("script utf8");
    let needle = "coreos-installer install -n -i /opt/openshift/master.ign /dev/vda";
    assert!(
        text.contains(needle),
        "install-to-disk.sh changed shape:\n{text}"
    );
    let extra = kargs(guest_ip)
        .split_whitespace()
        .fold(String::new(), |s, k| s + " --append-karg " + k);
    script["contents"]["source"] =
        Value::String(data_url(&text.replace(needle, &format!("{needle}{extra}"))));
    files.push(hosts_file(guest_ip));
    ign["systemd"]["units"]
        .as_array_mut()
        .expect("systemd.units")
        .extend(probe_units(
            "release-image.service -u node-image-pull.service -u bootkube.service \
             -u install-to-disk.service",
        ));
    (
        serde_json::to_vec(&ign).expect("serialize ignition"),
        dir.join("auth/kubeconfig"),
    )
}

/// `oc` against the guest's API from wherever the bridge lives, with
/// the installer's admin kubeconfig. The server name on the cert is
/// `api.<cluster>.<domain>`, which only `/etc/hosts` in the guest knows.
struct Api<'a> {
    client: &'a Path,
    kubeconfig: PathBuf,
    netns: Option<PathBuf>,
    guest_ip: Ipv4Addr,
}

fn oc(api: &Api, args: &[&str]) -> Result<String, String> {
    let client = api.client;
    let mut cmd = match &api.netns {
        Some(ns) => {
            let mut c = Command::new("nsenter");
            c.arg(format!("--net={}", ns.display())).arg(client);
            c
        }
        None => Command::new(client),
    };
    cmd.arg("--kubeconfig")
        .arg(&api.kubeconfig)
        .arg(format!("--server=https://{}:6443", api.guest_ip))
        .arg(format!("--tls-server-name=api.{CLUSTER}.{DOMAIN}"))
        .arg("--request-timeout=20s")
        .args(args);
    let out = cmd.output().map_err(|e| format!("spawn oc: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// The live system's bootstrap, to install-to-disk.sh's last words
/// before `shutdown -r +1`. A guest that leaves earlier is a failure
/// with its whole console attached.
fn wait_bootstrap(vm: &Vm) -> String {
    let deadline = Instant::now() + BOOTSTRAP_CEILING;
    loop {
        let out = vm.serial_output(Duration::from_millis(500));
        if out.contains("Going to reboot") {
            return out;
        }
        assert!(
            !vm.guest_exited(),
            "bootstrap: the live system reset before install-to-disk finished\n--- serial ---\n{out}"
        );
        assert!(
            !out.contains("Kernel panic"),
            "bootstrap: guest panicked\n--- serial (tail) ---\n{}",
            tail(&out, 80)
        );
        assert!(
            Instant::now() < deadline,
            "bootstrap: not installed within {BOOTSTRAP_CEILING:?}\n--- serial (tail) ---\n{}",
            tail(&out, 120)
        );
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn boot_installed(boot: &DiskBoot, disk: &Path, tap: TapDevice, whose: &str) -> Vm {
    eprintln!(
        "{whose}: BLS entry {} ({}) linux={} firstboot={}\n  options: {}",
        boot.entry.name, boot.entry.title, boot.entry.linux, boot.firstboot, boot.cmdline
    );
    assert!(boot.cmdline.contains(" noapic"), "{}", boot.cmdline);
    assert!(boot.cmdline.contains(" reboot=k"), "{}", boot.cmdline);
    let mut vm = Vm::builder()
        .boot_from(boot)
        .memory_mb(MEMORY_MB)
        .vcpus(VCPUS)
        .vsock(false)
        .transport(Transport::Pci)
        .block_device(disk, false)
        .network(tap)
        .build()
        .unwrap_or_else(|e| panic!("{whose}: installed OKD node should build: {e}"));
    assert_eq!(vm.transport(), Transport::Pci);
    vm.start()
        .unwrap_or_else(|e| panic!("{whose}: installed OKD node should start: {e}"));
    vm
}

/// `Ready` node plus the running pods, once the API answers.
fn cluster_state(api: &Api) -> Result<(bool, Vec<String>), String> {
    let ready = oc(
        api,
        &[
            "get",
            "nodes",
            "-o",
            r#"jsonpath={range .items[*]}{.metadata.name} {.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}"#,
        ],
    )?;
    let pods = oc(
        api,
        &[
            "get",
            "pods",
            "-A",
            "--field-selector=status.phase=Running",
            "--no-headers",
        ],
    )?;
    let node_ready = ready.lines().any(|l| l == format!("{HOSTNAME} True"));
    Ok((node_ready, pods.lines().map(str::to_string).collect()))
}

#[test]
fn test_okd_single_node_comes_up_on_virtio_pci_and_runs_a_pod() {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = k7d::network::cleanup_stale_k7_bridges();

    let installer = okd_binary(INSTALLER, "openshift-install");
    let client = okd_binary(CLIENT, "oc");
    let (kernel, live_initrd) = live_artifacts(CACHE_DIR, SCOS_MIRROR, KERNEL, INITRAMFS, ROOTFS);
    eprintln!(
        "OKD {OKD_RELEASE}: {}",
        run(Command::new(&installer).arg("version"))
            .lines()
            .next()
            .unwrap_or_default()
    );

    let work = tempfile::tempdir().expect("workdir");
    let disk = work.path().join("okd.img");
    fs::File::create(&disk)
        .expect("create disk")
        .set_len(DISK_BYTES)
        .expect("size disk");

    let mut net = ClusterNetwork::create("okd").expect("bridge");
    let tap = net.add_tap().expect("tap");
    let guest_ip = tap.guest_ip();
    // The node keeps this address for life (it is in its BLS options),
    // so every boot must own the same per-TAP identity (CHALLENGES #307).
    let vm_index = tap.vm_index();

    // --- 1. Installer output, appended to the live initramfs. ---
    let (ign, kubeconfig) = generate_ignition(&installer, &work.path().join("install"), guest_ip);
    let api = Api {
        client: &client,
        kubeconfig,
        netns: tap.netns_path(),
        guest_ip,
    };
    eprintln!("bootstrap-in-place ignition: {} bytes", ign.len());
    let initrd = work.path().join("live-initrd.img");
    let mut data = fs::read(&live_initrd).expect("read live initrd");
    data.extend(cpio_with_file("config.ign", &ign));
    fs::write(&initrd, &data).expect("write initrd with config");

    // --- 2. Live system: bootstrap in place, install to /dev/vda. ---
    let mut live = Vm::builder()
        .kernel(&kernel)
        .initrd(&initrd)
        .cmdline(&format!(
            "{} ignition.firstboot ignition.platform.id=metal rd.neednet=1",
            kargs(guest_ip)
        ))
        .memory_mb(MEMORY_MB)
        .vcpus(VCPUS)
        .vsock(false)
        .transport(Transport::Pci)
        .block_device(&disk, false)
        .network(tap)
        .build()
        .expect("SCOS live VM should build");
    assert_eq!(live.transport(), Transport::Pci);
    let t0 = Instant::now();
    live.start().expect("SCOS live VM should start");
    wait_serial(&live, "live", "Multi-User System", BOOT_CEILING);
    eprintln!(
        "MEASUREMENT scos 10 live boot to multi-user.target: {:?}",
        t0.elapsed()
    );
    let out = wait_serial(&live, "live", PROBE_END, BOOT_CEILING);
    let probe = probe_section(&out);
    eprintln!("live: probe output:\n{probe}");
    assert!(probe.contains(".el10."), "SCOS 10 kernel: {probe}");
    assert!(
        probe.contains("CentOS Stream CoreOS"),
        "SCOS userspace: {probe}"
    );
    assert_pci_probe(probe, "live");

    // install-to-disk.sh's last words before `shutdown -r +1`.
    let out = wait_bootstrap(&live);
    eprintln!(
        "MEASUREMENT okd bootstrap-in-place to install-to-disk done: {:?}",
        t0.elapsed()
    );
    eprintln!(
        "bootstrap: progress lines:\n{}",
        out.lines()
            .filter(|l| {
                l.contains("install-to-disk.sh[")
                    || l.contains("bootkube.sh[")
                    || l.contains("release-image.sh[")
            })
            .collect::<Vec<_>>()
            .join("\n")
    );
    common::coreos::wait_guest_exit(&live, "bootstrap", Duration::from_secs(180));
    drop(live);

    // --- 3. Boot from the disk until the node is Ready and runs a pod. ---
    let deadline = Instant::now() + CLUSTER_CEILING;
    let mut boots = 0;
    let mut last_err = String::new();
    'boots: while boots < MAX_DISK_BOOTS {
        boots += 1;
        let whose = format!("disk-boot-{boots}");
        let boot = DiskBoot::load(&disk, &work.path().join(format!("boot{boots}")))
            .unwrap_or_else(|e| panic!("{whose}: read the installed disk: {e}"));
        net.remove_entry(vm_index);
        let tap = net.add_tap_at(vm_index).expect("tap");
        let t = Instant::now();
        let vm = boot_installed(&boot, &disk, tap, &whose);
        let mut next_poll = Instant::now();
        loop {
            assert!(
                Instant::now() < deadline,
                "{whose}: no Ready node with a running pod within {CLUSTER_CEILING:?} of the first disk boot (last oc error: {last_err})\n--- serial (tail) ---\n{}",
                tail(&vm.serial_output(Duration::from_millis(100)), 80)
            );
            if vm.guest_exited() {
                eprintln!(
                    "{whose}: the node rebooted itself after {:?}\n--- serial (tail) ---\n{}",
                    t.elapsed(),
                    tail(&vm.serial_output(Duration::from_millis(100)), 30)
                );
                continue 'boots;
            }
            let out = vm.serial_output(Duration::from_millis(100));
            assert!(
                !out.contains("Kernel panic"),
                "{whose}: guest panicked\n--- serial (tail) ---\n{}",
                tail(&out, 80)
            );
            if Instant::now() >= next_poll {
                next_poll = Instant::now() + Duration::from_secs(30);
                match cluster_state(&api) {
                    Ok((ready, pods)) => {
                        eprintln!(
                            "{whose} +{:?}: node ready={ready}, {} running pods",
                            t.elapsed(),
                            pods.len()
                        );
                        if ready && !pods.is_empty() {
                            eprintln!(
                                "MEASUREMENT okd single node Ready with a running pod: {:?} after the first disk boot, {} disk boots\n{}",
                                t.elapsed(),
                                boots,
                                pods.join("\n")
                            );
                            eprintln!(
                                "{}",
                                oc(&api, &["get", "nodes", "-o", "wide"]).unwrap_or_default()
                            );
                            assert_alive(&vm, &whose);
                            return;
                        }
                    }
                    Err(e) => last_err = e,
                }
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    panic!("the node rebooted {MAX_DISK_BOOTS} times without reaching Ready with a pod (last oc error: {last_err})");
}
