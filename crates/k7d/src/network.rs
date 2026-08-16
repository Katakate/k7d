//! TAP device creation, IP assignment, bridge/NAT setup, userspace virtio-net.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use vm_memory::Address;
use vmm_sys_util::eventfd::EventFd;

use crate::virtio_mmio::{VirtioBackend, VirtqueueState};

const VIRTIO_ID_NET: u32 = 1;
const NET_NUM_QUEUES: usize = 2; // RX + TX
const NET_QUEUE_SIZE: u16 = 256;

// TUN/TAP ioctls
const TUNSETIFF: libc::c_ulong = 0x4004_54CA;
const TUNSETOFFLOAD: libc::c_ulong = 0x4004_54D0;
const TUNSETVNETHDRSZ: libc::c_ulong = 0x4004_54D8;

// Virtio net feature bits
const VIRTIO_NET_F_CSUM: u64 = 1 << 0;
const VIRTIO_NET_F_GUEST_CSUM: u64 = 1 << 1;
const VIRTIO_NET_F_MAC: u64 = 1 << 5;
const VIRTIO_NET_F_GUEST_TSO4: u64 = 1 << 7;
const VIRTIO_NET_F_GUEST_TSO6: u64 = 1 << 8;
const VIRTIO_NET_F_GUEST_ECN: u64 = 1 << 9;
const VIRTIO_NET_F_GUEST_UFO: u64 = 1 << 10;
const VIRTIO_NET_F_HOST_TSO4: u64 = 1 << 11;
const VIRTIO_NET_F_HOST_TSO6: u64 = 1 << 12;
const VIRTIO_NET_F_HOST_ECN: u64 = 1 << 13;
const VIRTIO_NET_F_HOST_UFO: u64 = 1 << 14;
const VIRTIO_NET_F_MRG_RXBUF: u64 = 1 << 15;

/// Standard virtio-net features to advertise to the guest.
const VIRTIO_NET_DEVICE_FEATURES: u64 = VIRTIO_NET_F_CSUM
    | VIRTIO_NET_F_GUEST_CSUM
    | VIRTIO_NET_F_MAC
    | VIRTIO_NET_F_GUEST_TSO4
    | VIRTIO_NET_F_GUEST_TSO6
    | VIRTIO_NET_F_GUEST_ECN
    | VIRTIO_NET_F_GUEST_UFO
    | VIRTIO_NET_F_HOST_TSO4
    | VIRTIO_NET_F_HOST_TSO6
    | VIRTIO_NET_F_HOST_ECN
    | VIRTIO_NET_F_HOST_UFO
    | VIRTIO_NET_F_MRG_RXBUF;

/// Guest network subnet base: 10.200.0.0/24 (avoids conflict with k3s pod CIDR 10.42.0.0/24).
const GUEST_SUBNET_BASE: [u8; 4] = [10, 200, 0, 0];
const GUEST_GATEWAY: [u8; 4] = [10, 200, 0, 1];

#[repr(C)]
struct Ifreq {
    ifr_name: [u8; libc::IFNAMSIZ],
    ifr_flags: libc::c_short,
    _pad: [u8; 22],
}

/// A TAP device attached to a bridge.
pub struct TapDevice {
    fd: RawFd,
    name: String,
    mac: [u8; 6],
    guest_ip: Ipv4Addr,
    vm_index: u32,
}

impl TapDevice {
    /// Create a TAP device and attach it to the given bridge.
    ///
    /// The TAP device name is derived from `bridge_name` and `vm_index` so two
    /// bridges (e.g. source and fork) can each host a TAP for the same
    /// `vm_index` without colliding on the kernel-side interface name.
    pub fn create(bridge_name: &str, vm_index: u32) -> Result<Self, String> {
        let guest_ip = Ipv4Addr::new(
            GUEST_SUBNET_BASE[0],
            GUEST_SUBNET_BASE[1],
            GUEST_SUBNET_BASE[2],
            2 + vm_index as u8,
        );
        let mac = [0xaa, 0xbb, 0x00, 0x00, 0x00, 2 + vm_index as u8];

        // SAFETY: valid C string path, valid flags.
        let fd = unsafe {
            libc::open(
                c"/dev/net/tun".as_ptr(),
                libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(format!(
                "open /dev/net/tun: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Derive a per-bridge TAP name so two bridges (source + fork) can host
        // the same `vm_index` without colliding. Linux IFNAMSIZ is 16 bytes
        // (including the NUL); cap the suffix at 13 chars to leave room for it.
        // Bridge names are `k7-br-{cluster_id[..10]}` (≤16 chars). Use a 5-char
        // hash of the bridge name + `t{vm_index}` (e.g. `t12ab3t0`) so the name
        // fits and stays unique across bridges.
        let bridge_short = bridge_short_tag(bridge_name);
        let tap_name = format!("t{bridge_short}t{vm_index}");
        if tap_name.len() >= libc::IFNAMSIZ {
            // SAFETY: fd is valid.
            unsafe { libc::close(fd) };
            return Err(format!("TAP name '{tap_name}' too long for IFNAMSIZ"));
        }
        let mut ifreq = Ifreq {
            ifr_name: [0u8; libc::IFNAMSIZ],
            ifr_flags: (libc::IFF_TAP | libc::IFF_NO_PI | libc::IFF_VNET_HDR) as libc::c_short,
            _pad: [0u8; 22],
        };
        let name_bytes = tap_name.as_bytes();
        let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
        ifreq.ifr_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        // SAFETY: fd is a valid TUN fd; ifreq is properly initialized.
        if unsafe { libc::ioctl(fd, TUNSETIFF, std::ptr::from_mut(&mut ifreq)) } < 0 {
            // SAFETY: fd is valid.
            unsafe { libc::close(fd) };
            return Err(format!("TUNSETIFF: {}", std::io::Error::last_os_error()));
        }

        // virtio_net_hdr_v1 is 12 bytes (includes num_buffers for MRG_RXBUF)
        let vnet_hdr_sz: libc::c_int = 12;
        // SAFETY: fd is valid TAP; setting vnet header size.
        if unsafe { libc::ioctl(fd, TUNSETVNETHDRSZ, std::ptr::from_ref(&vnet_hdr_sz)) } < 0 {
            // SAFETY: fd is valid.
            unsafe { libc::close(fd) };
            return Err(format!(
                "TUNSETVNETHDRSZ: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Enable offloads matching the virtio features we advertise
        let offload: libc::c_uint =
            libc::TUN_F_CSUM | libc::TUN_F_TSO4 | libc::TUN_F_TSO6 | libc::TUN_F_TSO_ECN;
        // SAFETY: fd is valid TAP; setting offload flags.
        if unsafe { libc::ioctl(fd, TUNSETOFFLOAD, offload as libc::c_ulong) } < 0 {
            log::warn!(
                "TUNSETOFFLOAD: {} (non-fatal)",
                std::io::Error::last_os_error()
            );
        }

        // TAP MAC must differ from guest MAC to avoid bridge "own source address" drops.
        let tap_mac_str = format!(
            "fe:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[1], mac[2], mac[3], mac[4], mac[5]
        );

        run_cmd(
            "ip",
            &["link", "set", "dev", &tap_name, "address", &tap_mac_str],
        )?;
        run_cmd(
            "ip",
            &["link", "set", "dev", &tap_name, "master", bridge_name],
        )?;
        run_cmd("ip", &["link", "set", "dev", &tap_name, "up"])?;

        log::info!("TAP {tap_name} created: tap_mac={tap_mac_str} guest_ip={guest_ip}");

        Ok(Self {
            fd,
            name: tap_name,
            mac,
            guest_ip,
            vm_index,
        })
    }

    /// Get the TAP file descriptor.
    #[must_use]
    pub fn fd(&self) -> RawFd {
        self.fd
    }

    /// Get the host-side TAP interface name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the MAC address (for the guest virtio-net device).
    #[must_use]
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Get the assigned guest IP address.
    #[must_use]
    pub fn guest_ip(&self) -> Ipv4Addr {
        self.guest_ip
    }

    /// Get the per-bridge VM index that determined this TAP's IP and MAC.
    #[must_use]
    pub fn vm_index(&self) -> u32 {
        self.vm_index
    }
}

/// Derive a short, deterministic tag for a bridge name. Used to keep TAP
/// interface names unique per bridge while staying within IFNAMSIZ.
fn bridge_short_tag(bridge_name: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a 64-bit offset basis
    for &b in bridge_name.as_bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    // 5 hex chars (~20 bits). Keeps `t{tag}t{vm_index}` short.
    format!("{:05x}", h & 0xf_ffff)
}

impl Drop for TapDevice {
    fn drop(&mut self) {
        // SAFETY: fd is valid; closing TAP device.
        unsafe { libc::close(self.fd) };
        let _ = Command::new("ip")
            .args(["link", "delete", &self.name])
            .output();
    }
}

/// Identity of a single VM allocated on a `ClusterNetwork`.
///
/// The triple `(vm_index, guest_ip, guest_mac)` is what defines the VM's
/// network identity inside the guest. A cluster fork reproduces these tuples
/// onto a new bridge so the guest sees an unchanged IP/MAC, while host-side
/// pod IPs differ per pod.
#[derive(Clone, Debug)]
pub struct VmNetworkEntry {
    /// Allocator index on this bridge (`0`, `1`, …). Stable across forks.
    pub vm_index: u32,
    /// Host-side TAP interface name for this VM.
    pub tap_name: String,
    /// Guest-visible IPv4 address (`10.200.0.{2 + vm_index}`).
    pub guest_ip: Ipv4Addr,
    /// Guest-visible MAC address (`aa:bb:00:00:00:{2 + vm_index}`).
    pub guest_mac: [u8; 6],
    /// Pod IP from the CNI — unique per pod, may differ between source/fork.
    pub pod_ip: Option<Ipv4Addr>,
    /// Pod network namespace path used to scope NAT rules, when set.
    pub pod_netns: Option<PathBuf>,
}

/// Per-cluster Linux bridge for VM networking.
///
/// Each cluster gets its own `k7-br-{id}` bridge. Inside the bridge the guest
/// IPs come from `10.200.0.0/24` and are stable across forks: a forked cluster
/// reuses the source's `(vm_index, guest_ip, guest_mac)` tuples on a fresh
/// bridge, so guest-visible network state survives the fork unchanged while
/// the two clusters remain isolated at L2.
pub struct ClusterNetwork {
    bridge_name: String,
    /// Subnet base (currently constant `10.200.0.0/24`). Kept here so a
    /// future config change is local.
    subnet_base: [u8; 4],
    /// Sequential allocator for new VMs in this cluster.
    next_vm_index: u32,
    /// VM identities allocated on this bridge, keyed by `vm_index`. Lets a
    /// forked cluster look up "what IP/MAC did source VM N have?".
    entries: HashMap<u32, VmNetworkEntry>,
}

impl ClusterNetwork {
    /// Create a new bridge for a cluster.
    ///
    /// If a bridge with the derived name already exists (e.g. another shim
    /// process on the same node already created it for the same cluster), the
    /// existing bridge is reused instead of being re-created. This makes the
    /// call idempotent across cooperating pods sharing a cluster.
    pub fn create(cluster_id: &str) -> Result<Self, String> {
        // IFNAMSIZ is 16 (15 chars + NUL). Reserve 6 for the `k7-br-` prefix
        // and cap the cluster suffix at 9 chars. To keep distinct cluster IDs
        // mapping to distinct bridges even after truncation, mix in a short
        // FNV-1a hash for IDs that exceed the budget.
        const MAX_SUFFIX: usize = 9;
        let suffix = if cluster_id.len() <= MAX_SUFFIX {
            cluster_id.to_string()
        } else {
            // 3-char prefix from the cluster_id + 5-char hash, joined by `-`.
            let h = bridge_short_tag(cluster_id);
            format!("{}-{}", &cluster_id[..3], &h[..5])
        };
        let bridge_name = format!("k7-br-{suffix}");

        // Idempotent attach without a TOCTOU race: just attempt `link add` and
        // accept "File exists" (kernel returns EEXIST when the link is already
        // there). Doing show-then-add would let two concurrent shim processes
        // both observe "missing" and both try to create the bridge, with the
        // loser failing loudly even though the post-condition is satisfied.
        // pidfd-based wait — under sustained shim load Tokio's
        // SIGCHLD reaper races `Command::output()`'s `waitpid(pid)`
        // and surfaces as `ip link add: No child processes (os
        // error 10)`. `run_capture` opens a `pidfd` immediately
        // after spawn and waits on that instead, race-free.
        let (add_status, _, add_stderr) = crate::netns::run_capture(
            "ip",
            &["link", "add", "name", &bridge_name, "type", "bridge"],
        )
        .map_err(|e| format!("ip link add: {e}"))?;
        if !add_status.success() {
            // `ip` prints `RTNETLINK answers: File exists` for EEXIST.
            if !add_stderr.contains("File exists") {
                return Err(format!(
                    "ip link add name {bridge_name} type bridge failed: {}",
                    add_stderr.trim()
                ));
            }
        }
        let gw = format!(
            "{}.{}.{}.{}",
            GUEST_GATEWAY[0], GUEST_GATEWAY[1], GUEST_GATEWAY[2], GUEST_GATEWAY[3]
        );
        // `addr add` returns EEXIST when the address is already on the bridge —
        // tolerate it to keep `create()` idempotent on shared bridges.
        let _ = crate::netns::run_capture(
            "ip",
            &["addr", "add", &format!("{gw}/24"), "dev", &bridge_name],
        );
        run_cmd("ip", &["link", "set", "dev", &bridge_name, "up"])?;

        let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1");
        // `net.bridge.bridge-nf-call-iptables` is GLOBAL to the root netns,
        // not per-bridge. kube-proxy's Service DNAT depends on it being 1:
        // with it off, a same-node backend's reply crosses flannel's cni0 as
        // a pure L2 frame, skips conntrack un-DNAT, and the client sees the
        // pod IP instead of the Service IP and drops the reply — breaking
        // every ClusterIP on the node (we shipped exactly that bug by
        // writing 0 here). Set it to 1 explicitly; our own bridge's frames
        // are whitelisted by the FORWARD/INPUT/OUTPUT ACCEPT rules below.
        let _ = std::fs::write("/proc/sys/net/bridge/bridge-nf-call-iptables", "1");
        let _ = std::fs::write("/proc/sys/net/bridge/bridge-nf-call-ip6tables", "1");
        // Route every `iptables` invocation through the pidfd
        // helper too — silent `Command::output()` calls return
        // `Err(ECHILD)` under Tokio SIGCHLD-reaper contention,
        // and silently dropping the error meant the rule never
        // got installed, breaking pod-to-pod connectivity for
        // any later sandbox.
        let _ = crate::netns::run_capture(
            "iptables",
            &["-I", "FORWARD", "-i", &bridge_name, "-j", "ACCEPT"],
        );
        let _ = crate::netns::run_capture(
            "iptables",
            &["-I", "FORWARD", "-o", &bridge_name, "-j", "ACCEPT"],
        );
        // Disable reverse path filtering on bridge (strict rp_filter blocks responses)
        let _ = std::fs::write(
            format!("/proc/sys/net/ipv4/conf/{bridge_name}/rp_filter"),
            "0",
        );
        let _ = std::fs::write("/proc/sys/net/ipv4/conf/all/rp_filter", "0");
        // Accept all traffic from/to our bridge in INPUT (before kube-router rules)
        let _ = crate::netns::run_capture(
            "iptables",
            &["-I", "INPUT", "-i", &bridge_name, "-j", "ACCEPT"],
        );
        let _ = crate::netns::run_capture(
            "iptables",
            &["-I", "OUTPUT", "-o", &bridge_name, "-j", "ACCEPT"],
        );
        let default_iface = default_route_iface();
        let _ = crate::netns::run_capture(
            "iptables",
            &[
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                "10.200.0.0/24",
                "-o",
                &default_iface,
                "-j",
                "MASQUERADE",
            ],
        );

        log::info!("bridge {bridge_name} created with gateway {gw}/24");

        Ok(Self {
            bridge_name,
            subnet_base: GUEST_SUBNET_BASE,
            next_vm_index: 0,
            entries: HashMap::new(),
        })
    }

    /// Create a TAP device on this bridge for a new VM.
    ///
    /// The next sequential `vm_index` is allocated. Use [`add_tap_at`] to
    /// allocate a specific index (required when reproducing a source cluster's
    /// per-VM identity on a forked bridge).
    pub fn add_tap(&mut self) -> Result<TapDevice, String> {
        // Skip past any indices already populated (e.g. by an out-of-order
        // `add_tap_at`). This keeps every allocated index unique.
        while self.entries.contains_key(&self.next_vm_index) {
            self.next_vm_index += 1;
        }
        let idx = self.next_vm_index;
        self.next_vm_index += 1;
        self.create_tap_at_index(idx)
    }

    /// Create a TAP device for a specific `vm_index`.
    ///
    /// Used by cluster fork to recreate the source's per-VM identity (same
    /// guest IP and MAC) on a fresh bridge. Fails if `vm_index` is already
    /// allocated on this bridge.
    pub fn add_tap_at(&mut self, vm_index: u32) -> Result<TapDevice, String> {
        if self.entries.contains_key(&vm_index) {
            return Err(format!(
                "vm_index {vm_index} already allocated on bridge {}",
                self.bridge_name
            ));
        }
        if vm_index >= self.next_vm_index {
            self.next_vm_index = vm_index + 1;
        }
        self.create_tap_at_index(vm_index)
    }

    fn create_tap_at_index(&mut self, vm_index: u32) -> Result<TapDevice, String> {
        let tap = TapDevice::create(&self.bridge_name, vm_index)?;
        let entry = VmNetworkEntry {
            vm_index,
            tap_name: tap.name().to_string(),
            guest_ip: tap.guest_ip(),
            guest_mac: tap.mac(),
            pod_ip: None,
            pod_netns: None,
        };
        self.entries.insert(vm_index, entry);
        Ok(tap)
    }

    /// Look up the network entry for a previously allocated `vm_index`.
    #[must_use]
    pub fn entry(&self, vm_index: u32) -> Option<&VmNetworkEntry> {
        self.entries.get(&vm_index)
    }

    /// Free a previously allocated `vm_index` after its VM stopped.
    ///
    /// The TAP link itself is deleted by `TapDevice::drop` (the `Vm`
    /// owns the TAP); this only releases the index/IP/MAC identity so
    /// `add_tap` can hand it to a later VM on the same shared bridge.
    /// Returns the removed entry, or `None` if the index was never
    /// allocated.
    pub fn remove_entry(&mut self, vm_index: u32) -> Option<VmNetworkEntry> {
        self.entries.remove(&vm_index)
    }

    /// Iterate over all allocated network entries on this bridge.
    pub fn entries(&self) -> impl Iterator<Item = &VmNetworkEntry> {
        self.entries.values()
    }

    /// Get the configured subnet base (currently `10.200.0.0`).
    #[must_use]
    pub fn subnet_base(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.subnet_base[0],
            self.subnet_base[1],
            self.subnet_base[2],
            self.subnet_base[3],
        )
    }

    /// Get the bridge name.
    #[must_use]
    pub fn bridge_name(&self) -> &str {
        &self.bridge_name
    }

    /// Clone the topology of an existing cluster onto a new bridge.
    ///
    /// The new bridge is named `k7-br-{fork_cluster_id[..10]}`. Every VM index
    /// allocated on `source` is reproduced on the new bridge with the same
    /// guest IP and MAC, so the forked guests see identical network state
    /// while the two bridges stay isolated at L2.
    pub fn fork_from(source: &Self, fork_cluster_id: &str) -> Result<Self, String> {
        let mut fork = Self::create(fork_cluster_id)?;
        // We do **not** allocate the TAPs here: TAP ownership is one-per-VM,
        // so `fork_cluster_warm` calls `add_tap_at(vm_index)` per fork VM and
        // moves the resulting `TapDevice` into the `Vm`. We just align the
        // index allocator so any post-fork `add_tap()` call doesn't clash
        // with the indices the caller is about to populate.
        fork.next_vm_index = source.next_vm_index;
        Ok(fork)
    }

    /// Install pod-netns scoped DNAT/SNAT rules linking a pod IP to a VM's
    /// guest IP.
    ///
    /// The pod's network namespace becomes a private routing realm:
    ///
    /// * Inbound packets destined for `pod_ip` are DNAT'd to `guest_ip`.
    /// * Outbound packets sourced from `guest_ip` are SNAT'd to `pod_ip`.
    ///
    /// Two pods on the same host can therefore share the `10.200.0.0/24`
    /// subnet without colliding because each pod has its own netns.
    pub fn install_pod_nat(
        &mut self,
        vm_index: u32,
        pod_ip: Ipv4Addr,
        pod_netns: &Path,
    ) -> Result<(), String> {
        let entry = self
            .entries
            .get_mut(&vm_index)
            .ok_or_else(|| format!("vm_index {vm_index} not allocated"))?;
        let guest_ip = entry.guest_ip.to_string();
        let pod_ip_s = pod_ip.to_string();
        let netns = pod_netns.to_string_lossy().into_owned();
        // Use `nsenter --net=<path>` so any netns reachable as a path works
        // (CNI hands us /var/run/netns/<name>, but kubelet passes raw bind-
        // mounted paths like /proc/<pid>/ns/net for which `ip netns exec
        // <name>` would not find a match in /var/run/netns).
        let nsenter = format!("--net={netns}");

        run_cmd(
            "nsenter",
            &[
                &nsenter,
                "iptables",
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-d",
                &pod_ip_s,
                "-j",
                "DNAT",
                "--to-destination",
                &guest_ip,
            ],
        )?;
        run_cmd(
            "nsenter",
            &[
                &nsenter,
                "iptables",
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                &guest_ip,
                "-j",
                "SNAT",
                "--to-source",
                &pod_ip_s,
            ],
        )?;
        entry.pod_ip = Some(pod_ip);
        entry.pod_netns = Some(pod_netns.to_path_buf());
        log::info!(
            "pod NAT installed on bridge {}: pod {pod_ip_s} ↔ guest {guest_ip} (vm_index={vm_index})",
            self.bridge_name
        );
        Ok(())
    }

    /// Attach the VM at `vm_index` to a CNI-assigned pod netns.
    ///
    /// Builds on top of [`Self::install_pod_nat`] and [`crate::netns`]:
    ///
    /// 1. Move the host-side TAP link `entry.tap_name` into `pod_netns`
    ///    (the TAP fd held by k7d remains valid; only the kernel link
    ///    moves).
    /// 2. Inside `pod_netns`, create a Linux bridge `k7-podbr0` and
    ///    enslave both `eth0` (the CNI veth, with the pod's
    ///    Kubernetes-routable IP) and the freshly-moved TAP to it.
    ///    `eth0` keeps its IP; the TAP has none. `bridge-nf-call-iptables`
    ///    is set to `0` inside the netns so kube-proxy's host-side
    ///    iptables rules don't re-process bridged frames.
    /// 3. Install the pod-netns DNAT/SNAT rules so the rest of
    ///    Kubernetes still sees the pod's CNI IP, but the guest VM
    ///    continues to see its stable `10.200.0.{2 + vm_index}`
    ///    address.
    ///
    /// After this returns, the pod netns has:
    ///
    /// ```text
    ///     eth0 ──┐                            ┌── tap (TAP fd held by k7d,
    ///            │                            │      virtio-net backend
    ///            ├──── k7-podbr0 (bridge) ────┤      reads/writes the fd)
    ///            │                            │
    ///   pod_ip on eth0                  no IP on tap
    ///   PREROUTING DNAT pod_ip → guest_ip
    ///   POSTROUTING SNAT guest_ip → pod_ip
    /// ```
    ///
    /// Pre-conditions:
    /// - `vm_index` was previously allocated on this `ClusterNetwork`
    ///   via `add_tap` / `add_tap_at`; the entry's `tap_name` is
    ///   currently a link in the **host root** netns enslaved to the
    ///   per-cluster bridge.
    /// - `pod_netns` is an absolute path to an existing netns that
    ///   contains an `eth0` with `pod_ip` already assigned by CNI.
    ///
    /// Post-conditions:
    /// - The TAP link is in `pod_netns` and enslaved to `k7-podbr0`.
    /// - `eth0` is enslaved to `k7-podbr0`.
    /// - DNAT/SNAT rules are installed in the pod netns (idempotent).
    /// - `entry.pod_ip` and `entry.pod_netns` are populated.
    pub fn attach_to_pod_netns(
        &mut self,
        vm_index: u32,
        pod_netns: &Path,
        pod_ip: Ipv4Addr,
    ) -> Result<(), String> {
        // Resolve the entry first — return early without mutating state
        // if the caller passes a bogus vm_index. Clone the fields we
        // need later so we don't hold a borrow across `install_pod_nat`.
        let (tap_name, guest_ip, guest_mac) = {
            let entry = self
                .entries
                .get(&vm_index)
                .ok_or_else(|| format!("vm_index {vm_index} not allocated"))?;
            (entry.tap_name.clone(), entry.guest_ip, entry.guest_mac)
        };

        debug_log_cni(&format!(
            "attach_to_pod_netns: start vm_index={vm_index} tap={tap_name} \
             pod_netns={} pod_ip={pod_ip}",
            pod_netns.display()
        ));

        // 1. Move the TAP link into the pod netns. We do this BEFORE
        //    creating the in-netns bridge so the bridge has a TAP to
        //    enslave on the same call. If this fails, the TAP is still
        //    on the host bridge — calling code can retry or give up
        //    cleanly.
        if let Err(e) = crate::netns::move_link_to_netns(&tap_name, pod_netns) {
            let msg = format!("move {tap_name} into pod netns: {e}");
            debug_log_cni(&format!("attach_to_pod_netns: STEP1 FAIL {msg}"));
            return Err(msg);
        }
        debug_log_cni("attach_to_pod_netns: STEP1 OK (move_link_to_netns)");

        // 2. Create k7-podbr0 inside the pod netns and enslave ONLY
        //    the TAP. Earlier iterations of this code also enslaved
        //    `eth0` (the CNI veth), but that turned out to be wrong:
        //    when eth0 and the TAP are both on the same bridge and
        //    the bridge has an IP, the kernel's egress path for
        //    reply traffic (TAP -> bridge -> route -> eth0) hits a
        //    hairpin/STP loop-prevention check, the L2 frame is
        //    never put on the wire, and host->pod traffic times out
        //    silently. Keeping eth0 standalone preserves the
        //    standard NAT topology used by every container runtime:
        //    eth0 has the CNI-assigned IP, the bridge is a separate
        //    L3 gateway sitting in front of the VM, and conntrack
        //    handles the eth0<->bridge plumbing.
        if let Err(e) = crate::netns::create_bridge_in_netns(pod_netns, "k7-podbr0", &[&tap_name]) {
            let msg = format!("create k7-podbr0 in pod netns: {e}");
            debug_log_cni(&format!("attach_to_pod_netns: STEP2 FAIL {msg}"));
            return Err(msg);
        }
        debug_log_cni("attach_to_pod_netns: STEP2 OK (create_bridge_in_netns)");

        // 3. Install the pod-netns DNAT/SNAT translating
        //    pod_ip ↔ guest_ip. This populates
        //    entry.pod_ip and entry.pod_netns as a side effect.
        if let Err(e) = self.install_pod_nat(vm_index, pod_ip, pod_netns) {
            debug_log_cni(&format!("attach_to_pod_netns: STEP3 FAIL {e}"));
            return Err(e);
        }
        debug_log_cni("attach_to_pod_netns: STEP3 OK (install_pod_nat)");

        // 4. Make the in-netns bridge a proper L3 gateway for the
        //    guest:
        //      - net.ipv4.ip_forward=1 in the pod netns so the kernel
        //        is willing to forward bridged-then-routed packets.
        //      - 10.200.0.1/24 on `k7-podbr0` — this gives the bridge
        //        an IP, auto-installs a connected route for
        //        10.200.0.0/24 via the bridge, and gives the guest
        //        VM a default-route ARP target that lives in the pod
        //        netns. Without it the kernel has nowhere to deliver
        //        post-DNAT packets (`10.200.0.X` had no route) and
        //        guest-egress packets have no gateway to ARP for.
        let nsenter_arg = format!("--net={}", pod_netns.display());
        let _ = crate::netns::run_capture(
            "nsenter",
            &[&nsenter_arg, "sysctl", "-q", "-w", "net.ipv4.ip_forward=1"],
        );
        // Add 10.200.0.1/24 to k7-podbr0. Tolerate EEXIST so a
        // re-run of attach_to_pod_netns (shim retry) is a no-op.
        let addr_res = crate::netns::run_capture(
            "nsenter",
            &[
                &nsenter_arg,
                "ip",
                "addr",
                "add",
                "10.200.0.1/24",
                "dev",
                "k7-podbr0",
            ],
        );
        if let Ok((status, _, stderr)) = addr_res {
            if !status.success() && !stderr.contains("File exists") {
                debug_log_cni(&format!(
                    "attach_to_pod_netns: STEP4 addr add warn: {stderr}"
                ));
            }
        }
        debug_log_cni("attach_to_pod_netns: STEP4 OK (forward + gateway IP)");

        // 5. Install a permanent ARP entry mapping the guest IP to
        //    the guest's MAC. Without this the kernel ARPs for
        //    `guest_ip` and the bridge floods the request out of
        //    `eth0` as well as into the TAP — random pods on the
        //    cluster (or stale entries on flannel's cni0) can reply
        //    first with a wrong MAC, and the pod-netns kernel locks
        //    in the bogus binding. With a static entry the kernel
        //    never ARPs and frames go straight to our TAP via the
        //    bridge's FDB.
        let guest_mac_str = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            guest_mac[0], guest_mac[1], guest_mac[2], guest_mac[3], guest_mac[4], guest_mac[5]
        );
        let guest_ip_str = guest_ip.to_string();
        // Replace any existing (possibly bogus) entry. `ip neigh
        // replace` is idempotent.
        let neigh_res = crate::netns::run_capture(
            "nsenter",
            &[
                &nsenter_arg,
                "ip",
                "neigh",
                "replace",
                &guest_ip_str,
                "lladdr",
                &guest_mac_str,
                "dev",
                "k7-podbr0",
                "nud",
                "permanent",
            ],
        );
        if let Ok((status, _, stderr)) = neigh_res {
            if !status.success() {
                debug_log_cni(&format!(
                    "attach_to_pod_netns: STEP5 ip neigh warn: {stderr}"
                ));
            }
        }
        debug_log_cni(&format!(
            "attach_to_pod_netns: STEP5 OK (static ARP {guest_ip_str} -> {guest_mac_str})"
        ));

        log::info!(
            "attached vm_index={vm_index} (tap={tap_name}) to pod netns {} \
             with pod_ip={pod_ip}",
            pod_netns.display(),
        );
        debug_log_cni("attach_to_pod_netns: DONE");
        Ok(())
    }

    /// Best-effort reverse of [`Self::attach_to_pod_netns`] for the
    /// pod-delete path.
    ///
    /// Containerd usually destroys the pod netns immediately after the
    /// shim's `Delete` returns, so this call is mostly a no-op in
    /// practice — the bridge and NAT rules go away with the netns.
    /// We still attempt to delete `k7-podbr0` for the rare case where
    /// the netns outlives the sandbox (e.g. a CRI test rig).
    ///
    /// The TAP is **not** moved back to the host root netns — the
    /// link's original parent context (the per-cluster bridge) is
    /// already torn down by `ClusterNetwork::Drop` if this is the last
    /// VM on the cluster.
    pub fn detach_from_pod_netns(&self, _vm_index: u32, pod_netns: &Path) -> Result<(), String> {
        // Best-effort; pod netns is usually gone already.
        let _ = crate::netns::delete_bridge_in_netns(pod_netns, "k7-podbr0");
        Ok(())
    }

    /// Destroy the bridge and clean up.
    ///
    /// Removes the iptables rules added by `create()` (FORWARD/INPUT/OUTPUT
    /// ACCEPTs scoped to the bridge, and one MASQUERADE on the subnet) before
    /// deleting the bridge link. Without this cleanup, repeated test runs on
    /// the same host accumulate stale rules; in particular, the gateway IP
    /// `10.200.0.1` ends up bound to a stale bridge so a freshly-created
    /// bridge can't claim it, breaking NAT for the new VMs.
    pub fn destroy(&self) -> Result<(), String> {
        // iptables rules first (best-effort: -D may fail if rule wasn't there).
        let bridge = self.bridge_name.as_str();
        for args in [
            &["-D", "FORWARD", "-i", bridge, "-j", "ACCEPT"][..],
            &["-D", "FORWARD", "-o", bridge, "-j", "ACCEPT"][..],
            &["-D", "INPUT", "-i", bridge, "-j", "ACCEPT"][..],
            &["-D", "OUTPUT", "-o", bridge, "-j", "ACCEPT"][..],
        ] {
            let _ = std::process::Command::new("iptables").args(args).output();
        }
        // MASQUERADE is keyed on the subnet, not the bridge — only remove it
        // when this is the last bridge using the subnet, i.e. when no other
        // `k7-br-*` link still exists. Conservative: count siblings.
        if !any_other_k7_bridge_exists(bridge) {
            let _ = std::process::Command::new("iptables")
                .args([
                    "-t",
                    "nat",
                    "-D",
                    "POSTROUTING",
                    "-s",
                    "10.200.0.0/24",
                    "-o",
                    &default_route_iface(),
                    "-j",
                    "MASQUERADE",
                ])
                .output();
        }
        // The bridge link last — addr/route entries are auto-removed with it.
        let _ = std::process::Command::new("ip")
            .args(["link", "set", "dev", bridge, "down"])
            .output();
        run_cmd("ip", &["link", "delete", bridge, "type", "bridge"])?;
        Ok(())
    }
}

/// Debugging: append a timestamped line to /tmp/k7-shim.log.
/// containerd hands the shim /dev/null for stderr, so this is the only
/// way to see what `attach_to_pod_netns` is doing on a live cluster.
/// Best-effort; we ignore IO errors.
fn debug_log_cni(msg: &str) {
    use std::io::Write as _;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/k7-shim.log")
    {
        let _ = writeln!(
            f,
            "[{}] [k7-shim] {msg}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        );
    }
}

/// Whether any `k7-br-*` link other than `exclude` exists on the host.
/// Used by `destroy()` to decide if the shared MASQUERADE rule can go.
fn any_other_k7_bridge_exists(exclude: &str) -> bool {
    list_k7_bridges().into_iter().any(|n| n != exclude)
}

/// Enumerate `k7-br-*` links currently on the host.
fn list_k7_bridges() -> Vec<String> {
    let out = std::process::Command::new("ip")
        .args(["-o", "link", "show"])
        .output();
    let Ok(out) = out else { return Vec::new() };
    let s = String::from_utf8_lossy(&out.stdout);
    s.lines()
        .filter_map(|line| {
            // Format: `N: name@... : <FLAGS> ...` — extract the name.
            let after_idx = line.split(':').nth(1)?;
            let name = after_idx.trim().split('@').next()?.trim();
            if name.starts_with("k7-br-") {
                Some(name.to_string())
            } else {
                None
            }
        })
        .collect()
}

/// Sweep every `k7-br-*` bridge and its iptables ACCEPT/MASQUERADE rules
/// from the host kernel. Best-effort, idempotent.
///
/// This is **test-setup hygiene** — production k7d never needs it because
/// [`ClusterNetwork::Drop`] already runs `destroy()` on scope exit. The
/// problem is integration tests that panic / are killed / segfault before
/// `Drop` can run; they leave a stale bridge holding the `10.200.0.1/24`
/// gateway address. A freshly-created bridge then can't claim the gateway
/// (the kernel returns `EEXIST` on `ip addr add` and we tolerate it), but
/// it routes through whichever bridge originally claimed the IP — usually
/// a `NO-CARRIER` zombie with no live TAPs. Ping to the gateway fails,
/// ARP doesn't resolve, and the next test that tries to use the bridge
/// (e.g. `test_vm_has_network_interface`) flakes with a misleading
/// "100% packet loss" assertion failure.
///
/// Calling this at the start of an integration test guarantees the test
/// gets a clean L2/L3 substrate regardless of what prior tests left
/// behind. Tests that don't touch [`ClusterNetwork`] don't need to call
/// it; tests that do should treat it as the equivalent of
/// `ensure_shim_installed()` in `test_shim.rs` — call once, idempotent.
///
/// Returns the names of the bridges that were swept (informational; the
/// caller may want to log them). Not `#[must_use]` — tests typically
/// fire-and-forget with `let _ = cleanup_stale_k7_bridges();`.
#[allow(clippy::must_use_candidate)]
pub fn cleanup_stale_k7_bridges() -> Vec<String> {
    let bridges = list_k7_bridges();
    for bridge in &bridges {
        // Remove the per-bridge ACCEPT rules first; failure is fine
        // (the rule may already be gone).
        for args in [
            &["-D", "FORWARD", "-i", bridge, "-j", "ACCEPT"][..],
            &["-D", "FORWARD", "-o", bridge, "-j", "ACCEPT"][..],
            &["-D", "INPUT", "-i", bridge, "-j", "ACCEPT"][..],
            &["-D", "OUTPUT", "-o", bridge, "-j", "ACCEPT"][..],
        ] {
            let _ = std::process::Command::new("iptables").args(args).output();
        }
        let _ = std::process::Command::new("ip")
            .args(["link", "set", "dev", bridge, "down"])
            .output();
        let _ = std::process::Command::new("ip")
            .args(["link", "delete", bridge, "type", "bridge"])
            .output();
    }
    // Once every `k7-br-*` is gone, the shared `10.200.0.0/24`
    // MASQUERADE rule is safe to remove — there's no live bridge using
    // the subnet anymore. Repeat the delete to drain duplicates that
    // accumulated across test crashes.
    let iface = default_route_iface();
    loop {
        let out = std::process::Command::new("iptables")
            .args([
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-s",
                "10.200.0.0/24",
                "-o",
                &iface,
                "-j",
                "MASQUERADE",
            ])
            .output();
        let Ok(out) = out else { break };
        if !out.status.success() {
            // `iptables -D` returns non-zero when the rule isn't there;
            // that's our termination condition (no more duplicates).
            break;
        }
    }
    bridges
}

impl Drop for ClusterNetwork {
    fn drop(&mut self) {
        let _ = self.destroy();
    }
}

fn default_route_iface() -> String {
    Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .nth(4)
                .map(String::from)
        })
        .unwrap_or_else(|| "eth0".to_string())
}

fn run_cmd(cmd: &str, args: &[&str]) -> Result<(), String> {
    // Use the pidfd-based wait in netns.rs::run_capture so we don't
    // race the Tokio runtime's SIGCHLD reaper when called from the
    // shim's async create path. The previous std::process::Command::output()
    // path failed with "No child processes (os error 10)" because
    // Tokio reaped our child before our `waitpid` could collect it,
    // silently breaking every `attach_to_pod_netns` call on
    // a live cluster. See crate::netns::run_capture for the full
    // background.
    let (status, _stdout, stderr) =
        crate::netns::run_capture(cmd, args).map_err(|e| format!("{cmd} failed: {e}"))?;
    if !status.success() {
        return Err(format!(
            "{cmd} {} failed: {}",
            args.join(" "),
            stderr.trim()
        ));
    }
    Ok(())
}

// --- Virtio-net config space ---

/// Virtio-net config space: MAC + status.
#[repr(C, packed)]
struct VirtioNetConfig {
    mac: [u8; 6],
    status: u16,
    max_virtqueue_pairs: u16,
}

// --- Virtqueue structures for userspace processing ---
// Shared with `crate::block` (the userspace virtio-blk backend reuses the
// same split-ring plumbing).

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct VirtqDesc {
    pub(crate) addr: u64,
    pub(crate) len: u32,
    pub(crate) flags: u16,
    pub(crate) next: u16,
}

pub(crate) const VIRTQ_DESC_F_NEXT: u16 = 1;
pub(crate) const VIRTQ_DESC_F_WRITE: u16 = 2;

/// Userspace virtio-net backend. Spawns a thread that handles RX/TX between
/// TAP and guest virtqueues, like Firecracker.
pub struct TapNetBackend {
    mac: [u8; 6],
    mem_addr: u64,
    tap_fd: RawFd,
    acked_features: u64,
    tx_kick: Option<EventFd>,
    worker: Option<std::thread::JoinHandle<()>>,
    running: Arc<AtomicBool>,
    /// When true the worker skips TAP/virtqueue processing (warm-fork pause).
    paused: Arc<AtomicBool>,
    /// Seeded `last_avail`/`last_used` for RX (queue 0). Zero on cold boot;
    /// set via [`Self::seed_indices_from_guest`] before activate on restore.
    rx_idx_seed: u16,
    /// Seeded `last_avail`/`last_used` for TX (queue 1).
    tx_idx_seed: u16,
}

impl TapNetBackend {
    /// Create a userspace virtio-net backend using the TAP fd.
    #[must_use]
    pub fn new(mac: [u8; 6], tap_fd: RawFd, mem_addr: u64) -> Self {
        Self {
            mac,
            mem_addr,
            tap_fd,
            acked_features: 0,
            tx_kick: None,
            worker: None,
            running: Arc::new(AtomicBool::new(false)),
            paused: Arc::new(AtomicBool::new(false)),
            rx_idx_seed: 0,
            tx_idx_seed: 0,
        }
    }

    /// Seed worker virtqueue indices from guest `used.idx` before activate.
    ///
    /// On restore / warm-fork the guest driver state (and thus ring indices)
    /// survived in guest memory. Restarting the userspace worker at 0 would
    /// re-process already-serviced descriptors, corrupt the used ring, and
    /// hang the guest's networking softirq (next eth0 `agent.exec` stalls).
    /// Both `last_avail` and `last_used` are seeded to `used.idx` so pending
    /// available-but-not-yet-used descriptors (avail.idx > used.idx) are still
    /// drained after the worker starts.
    pub fn seed_indices_from_guest(&mut self, queues: &[VirtqueueState]) {
        if queues.len() < 2 {
            return;
        }
        self.rx_idx_seed = read_used_idx(self.mem_addr, &queues[0]);
        self.tx_idx_seed = read_used_idx(self.mem_addr, &queues[1]);
        log::info!(
            "virtio-net seed indices from guest: rx={} tx={}",
            self.rx_idx_seed,
            self.tx_idx_seed
        );
    }
}

impl VirtioBackend for TapNetBackend {
    fn device_type(&self) -> u32 {
        VIRTIO_ID_NET
    }

    fn device_features(&self) -> u64 {
        VIRTIO_NET_DEVICE_FEATURES
    }

    fn ack_features(&mut self, features: u64) {
        self.acked_features = features;
    }

    fn num_queues(&self) -> usize {
        NET_NUM_QUEUES
    }

    fn max_queue_size(&self) -> u16 {
        NET_QUEUE_SIZE
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let config = VirtioNetConfig {
            mac: self.mac,
            status: 1,
            max_virtqueue_pairs: 1,
        };
        // SAFETY: config is repr(C, packed), 10 bytes; pointer and length are valid.
        let config_bytes = unsafe {
            std::slice::from_raw_parts(
                (&raw const config).cast::<u8>(),
                std::mem::size_of::<VirtioNetConfig>(),
            )
        };
        let start = offset as usize;
        let end = (start + data.len()).min(config_bytes.len());
        if start < config_bytes.len() {
            let len = end - start;
            data[..len].copy_from_slice(&config_bytes[start..end]);
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {}

    fn queue_notify(&self, queue_index: u32) {
        if queue_index == 1 {
            if let Some(ref kick) = self.tx_kick {
                let _ = kick.write(1);
            }
        }
    }

    fn set_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::SeqCst);
        // Wake only on unpause so the worker leaves its sleep promptly.
        // Kicking on pause can race with the vCPU's MMIO lock and inflate
        // warm-fork latency.
        if !paused {
            if let Some(ref kick) = self.tx_kick {
                let _ = kick.write(1);
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn activate(&mut self, queues: &[VirtqueueState], irq_evt: &EventFd) -> Result<(), String> {
        if queues.len() < 2 {
            return Err("need at least 2 queues (RX + TX)".to_string());
        }

        let rx_q = queues[0].clone();
        let tx_q = queues[1].clone();

        if !rx_q.ready || !tx_q.ready {
            return Err("queues not ready".to_string());
        }

        let tx_kick = EventFd::new(libc::EFD_NONBLOCK).map_err(|e| format!("eventfd: {e}"))?;
        let tx_kick_fd = tx_kick.as_raw_fd();

        let mem_addr = self.mem_addr;
        let tap_fd = self.tap_fd;
        let irq_fd = irq_evt.as_raw_fd();
        let running = Arc::clone(&self.running);
        let paused = Arc::clone(&self.paused);
        let rx_idx_seed = self.rx_idx_seed;
        let tx_idx_seed = self.tx_idx_seed;
        running.store(true, Ordering::SeqCst);
        self.paused.store(false, Ordering::SeqCst);

        // Dup the TAP fd so the worker thread owns its copy
        // SAFETY: tap_fd is valid; dup returns a new fd.
        let worker_tap_fd = unsafe { libc::dup(tap_fd) };
        if worker_tap_fd < 0 {
            return Err(format!("dup tap: {}", std::io::Error::last_os_error()));
        }

        // Dup irq eventfd for the worker
        // SAFETY: irq_fd is valid.
        let worker_irq_fd = unsafe { libc::dup(irq_fd) };
        // Dup tx_kick for the worker
        // SAFETY: tx_kick_fd is valid.
        let worker_tx_kick_fd = unsafe { libc::dup(tx_kick_fd) };

        // Named so it doesn't inherit the activating vCPU thread's comm
        // (device activation runs on a vCPU thread — see).
        let builder = std::thread::Builder::new().name("virtio-net".to_string());
        let handle = builder.spawn(move || {
            net_worker(
                worker_tap_fd,
                worker_irq_fd,
                worker_tx_kick_fd,
                mem_addr,
                &rx_q,
                &tx_q,
                &running,
                &paused,
                (rx_idx_seed, tx_idx_seed),
            );
            // SAFETY: closing our dup'd fds.
            unsafe {
                libc::close(worker_tap_fd);
                libc::close(worker_irq_fd);
                libc::close(worker_tx_kick_fd);
            }
        });
        let handle = handle.map_err(|e| {
            // The closure never ran, so its dup'd fds must be closed here.
            // SAFETY: the fds are valid and owned by the unspawned closure.
            unsafe {
                libc::close(worker_tap_fd);
                libc::close(worker_irq_fd);
                libc::close(worker_tx_kick_fd);
            }
            format!("spawn virtio-net worker: {e}")
        })?;

        self.tx_kick = Some(tx_kick);
        self.worker = Some(handle);

        log::info!(
            "virtio-net activated (userspace): mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.mac[0],
            self.mac[1],
            self.mac[2],
            self.mac[3],
            self.mac[4],
            self.mac[5]
        );

        Ok(())
    }
}

impl TapNetBackend {
    /// Stop the worker thread. Must be called before guest memory is freed.
    pub fn shutdown(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(ref kick) = self.tx_kick {
            let _ = kick.write(1);
        }
        if let Some(h) = self.worker.take() {
            let _ = h.join();
        }
    }
}

impl Drop for TapNetBackend {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Read guest `used.idx` (offset +2 in `{flags:u16, idx:u16, ring[]}`).
pub(crate) fn read_used_idx(mem_base: u64, q: &VirtqueueState) -> u16 {
    if !q.ready || q.used_addr.raw_value() == 0 {
        return 0;
    }
    let used_base = mem_base + q.used_addr.raw_value();
    // SAFETY: used_base + 2 points at the idx field in guest RAM (memfd-backed).
    unsafe { std::ptr::read_volatile((used_base + 2) as *const u16) }
}

/// Worker thread: poll TAP for RX, poll `tx_kick` for TX, process virtqueues.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn net_worker(
    tap_fd: RawFd,
    irq_fd: RawFd,
    tx_kick_fd: RawFd,
    mem_base: u64,
    rx_q: &VirtqueueState,
    tx_q: &VirtqueueState,
    running: &AtomicBool,
    paused: &AtomicBool,
    idx_seed: (u16, u16),
) {
    // Both last_avail and last_used start at used.idx (see seed_indices_from_guest).
    let (rx_idx_seed, tx_idx_seed) = idx_seed;
    let mut rx_last_avail = rx_idx_seed;
    let mut tx_last_avail = tx_idx_seed;
    let mut rx_last_used = rx_idx_seed;
    let mut tx_last_used = tx_idx_seed;

    let mut pkt_buf = vec![0u8; 65536];

    // Small delay to let the guest driver finish initializing
    std::thread::sleep(std::time::Duration::from_millis(100));

    while running.load(Ordering::SeqCst) {
        // Warm-fork pause: do not touch TAP or guest rings while the vCPU is
        // stopped for dirty-page capture. Leave frames in the kernel TAP
        // buffer until resume.
        if paused.load(Ordering::SeqCst) {
            // Short sleep so unpause is snappy; tx_kick also wakes us.
            std::thread::sleep(std::time::Duration::from_millis(5));
            continue;
        }

        // Poll TAP (for RX) and tx_kick (for TX) with timeout
        let mut fds = [
            libc::pollfd {
                fd: tap_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: tx_kick_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: fds is valid, timeout 100ms.
        let ret = unsafe { libc::poll(fds.as_mut_ptr(), 2, 100) };
        if ret < 0 {
            continue;
        }

        // Process RX: read from TAP, write to guest RX queue (drain all available)
        if fds[0].revents & libc::POLLIN != 0 {
            loop {
                // SAFETY: tap_fd is valid; pkt_buf is valid.
                let n = unsafe {
                    libc::read(
                        tap_fd,
                        pkt_buf.as_mut_ptr().cast::<libc::c_void>(),
                        pkt_buf.len(),
                    )
                };
                if n <= 0 {
                    break;
                }
                let pkt_len = n as usize;
                // Set num_buffers=1 in vnet header (bytes 10-11) for MRG_RXBUF
                if pkt_len >= 12 {
                    pkt_buf[10] = 1;
                    pkt_buf[11] = 0;
                }
                if let Some(desc_idx) = get_avail_desc(mem_base, rx_q, &mut rx_last_avail) {
                    write_to_desc_chain(mem_base, rx_q, desc_idx, &pkt_buf[..pkt_len]);
                    put_used_desc(mem_base, rx_q, &mut rx_last_used, desc_idx, pkt_len as u32);
                    signal_irq(irq_fd);
                } else {
                    break;
                }
            }
        }

        // Process TX: read from guest TX queue, write to TAP
        if fds[1].revents & libc::POLLIN != 0 {
            // Consume the eventfd
            let mut val = 0u64;
            // SAFETY: tx_kick_fd is valid.
            unsafe {
                libc::read(tx_kick_fd, (&raw mut val).cast::<libc::c_void>(), 8);
            }

            while let Some(desc_idx) = get_avail_desc(mem_base, tx_q, &mut tx_last_avail) {
                let len = read_from_desc_chain(mem_base, tx_q, desc_idx, &mut pkt_buf);
                if len > 0 {
                    // SAFETY: tap_fd is valid; pkt_buf[..len] is valid.
                    unsafe {
                        libc::write(tap_fd, pkt_buf.as_ptr().cast::<libc::c_void>(), len);
                    }
                }
                put_used_desc(mem_base, tx_q, &mut tx_last_used, desc_idx, 0);
                signal_irq(irq_fd);
            }
        }
    }
}

fn signal_irq(irq_fd: RawFd) {
    let val: u64 = 1;
    // SAFETY: irq_fd is a valid eventfd.
    unsafe {
        libc::write(irq_fd, (&raw const val).cast::<libc::c_void>(), 8);
    }
}

/// Get the next available descriptor index from the avail ring.
pub(crate) fn get_avail_desc(
    mem_base: u64,
    q: &VirtqueueState,
    last_avail: &mut u16,
) -> Option<u16> {
    let avail_base = mem_base + q.avail_addr.raw_value();
    // avail ring layout: flags(u16), idx(u16), ring[size](u16 each)
    // SAFETY: avail_base points to valid guest memory (memfd-backed).
    let avail_idx = unsafe { std::ptr::read_volatile((avail_base + 2) as *const u16) };
    if *last_avail == avail_idx {
        return None;
    }
    let ring_offset = 4 + (*last_avail % q.size) as u64 * 2;
    // SAFETY: ring entry is within the avail ring in guest memory.
    let desc_idx = unsafe { std::ptr::read_volatile((avail_base + ring_offset) as *const u16) };
    *last_avail = last_avail.wrapping_add(1);
    Some(desc_idx)
}

/// Write data to a descriptor chain (for RX: TAP -> guest).
fn write_to_desc_chain(mem_base: u64, q: &VirtqueueState, first_desc: u16, data: &[u8]) {
    let desc_base = mem_base + q.desc_addr.raw_value();
    let mut desc_idx = first_desc;
    let mut offset = 0usize;

    loop {
        // SAFETY: desc_base + idx*16 points to a valid VirtqDesc in guest memory.
        let desc: VirtqDesc = unsafe {
            std::ptr::read_volatile((desc_base + u64::from(desc_idx) * 16) as *const VirtqDesc)
        };

        if desc.flags & VIRTQ_DESC_F_WRITE != 0 && desc.addr != 0 {
            let copy_len = (data.len() - offset).min(desc.len as usize);
            // SAFETY: mem_base + desc.addr points to guest memory (memfd-backed);
            // desc.addr is a GPA within guest RAM.
            unsafe {
                let dst = (mem_base + desc.addr) as *mut u8;
                std::ptr::copy_nonoverlapping(data[offset..].as_ptr(), dst, copy_len);
            }
            offset += copy_len;
        }

        if desc.flags & VIRTQ_DESC_F_NEXT != 0 && offset < data.len() {
            desc_idx = desc.next;
        } else {
            break;
        }
    }
}

/// Read data from a descriptor chain (for TX: guest -> TAP).
fn read_from_desc_chain(
    mem_base: u64,
    q: &VirtqueueState,
    first_desc: u16,
    buf: &mut [u8],
) -> usize {
    let desc_base = mem_base + q.desc_addr.raw_value();
    let mut desc_idx = first_desc;
    let mut offset = 0usize;

    loop {
        // SAFETY: desc_base + idx*16 points to a valid VirtqDesc in guest memory.
        let desc: VirtqDesc = unsafe {
            std::ptr::read_volatile((desc_base + u64::from(desc_idx) * 16) as *const VirtqDesc)
        };

        if desc.flags & VIRTQ_DESC_F_WRITE == 0 && desc.addr != 0 {
            let copy_len = (buf.len() - offset).min(desc.len as usize);
            // SAFETY: mem_base + desc.addr points to guest memory (memfd-backed);
            // desc.addr is a GPA within guest RAM.
            unsafe {
                let src = (mem_base + desc.addr) as *const u8;
                std::ptr::copy_nonoverlapping(src, buf[offset..].as_mut_ptr(), copy_len);
            }
            offset += copy_len;
        }

        if desc.flags & VIRTQ_DESC_F_NEXT != 0 {
            desc_idx = desc.next;
        } else {
            break;
        }
    }
    offset
}

/// Put a descriptor in the used ring.
pub(crate) fn put_used_desc(
    mem_base: u64,
    q: &VirtqueueState,
    last_used: &mut u16,
    desc_idx: u16,
    len: u32,
) {
    let used_base = mem_base + q.used_addr.raw_value();
    // used ring layout: flags(u16), idx(u16), ring[size]({id:u32, len:u32}) each
    let ring_offset = 4 + (*last_used % q.size) as u64 * 8;
    // SAFETY: used ring entry is within guest memory.
    unsafe {
        let entry_ptr = (used_base + ring_offset) as *mut u32;
        std::ptr::write_volatile(entry_ptr, u32::from(desc_idx));
        std::ptr::write_volatile(entry_ptr.add(1), len);
    }
    *last_used = last_used.wrapping_add(1);
    // Update used idx
    // SAFETY: used_base + 2 points to the idx field.
    unsafe {
        std::ptr::write_volatile((used_base + 2) as *mut u16, *last_used);
    }
}
