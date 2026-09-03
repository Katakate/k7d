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

use crate::virtio_mmio::{VirtioBackend, VirtqueueState, PARK_POLL, UNPARK_POLL};

const VIRTIO_ID_NET: u32 = 1;
const NET_NUM_QUEUES: usize = 2; // RX + TX
const NET_QUEUE_SIZE: u16 = 256;

// TUN/TAP ioctls
const TUNSETIFF: libc::c_ulong = 0x4004_54CA;
const TUNSETOFFLOAD: libc::c_ulong = 0x4004_54D0;
const TUNSETVNETHDRSZ: libc::c_ulong = 0x4004_54D8;

// Virtio net feature bits
const VIRTIO_NET_F_CSUM: u64 = 1 << 0;
const VIRTIO_NET_F_MAC: u64 = 1 << 5;
const VIRTIO_NET_F_MRG_RXBUF: u64 = 1 << 15;

const VIRTIO_NET_HDR_LEN: usize = 12;
const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;

/// Virtio-net features advertised to the guest.
///
/// CSUM only — never TSO. TAP `TUN_F_TSO4` made the kernel deliver
/// 16–64 KiB GRO aggregates that `num_buffers=1` truncated, collapsing
/// guest NAT to ~50 KB/s (CHALLENGES.md #117). The TAP stays offload
/// none so GRO cannot come back; the TX worker completes `NEEDS_CSUM`
/// in userspace before the write. Cilium BPF native routing
/// `bpf_redirect`s `CHECKSUM_PARTIAL` onto eth0 and skips
/// `validate_xmit_skb`; without this completion the SYN is incomplete
/// on the k7 bridge and cross-node pod wget times out while host-ns
/// curl (stack-completed csum) still works.
const VIRTIO_NET_DEVICE_FEATURES: u64 =
    VIRTIO_NET_F_CSUM | VIRTIO_NET_F_MAC | VIRTIO_NET_F_MRG_RXBUF;

/// Guest network subnet base: 10.200.0.0/24 (avoids conflict with k3s pod CIDR 10.42.0.0/24).
const GUEST_SUBNET_BASE: [u8; 4] = [10, 200, 0, 0];
const GUEST_GATEWAY: [u8; 4] = [10, 200, 0, 1];

/// Policy-routing table for guest overlay prefixes forwarded across a
/// k7 bridge. Must not be the main table: an `ip route replace` there
/// once stole host k3s `cni0`'s connected route, and deleting the
/// bridge left the prefix unroutable — `CoreDNS` probes timed out
/// (CHALLENGES.md #117). The guest CIDRs no longer overlap the host's
/// (#121), but a scoped table stays self-cleaning and cannot regress.
pub const GUEST_OVERLAY_TABLE: u32 = 200;
/// Guest k3s pod overlay. Keep in step with `POD_CIDR` in
/// `tests/common/ubuntu_k3s.rs` and `guest/ubuntu/k7d-k3sconfig` —
/// off k3s' default `10.42/16` because the host running these VMs is
/// itself a k3s node on that range (CHALLENGES.md #121).
pub const GUEST_POD_OVERLAY: &str = "10.244.0.0/16";
/// Guest k3s `ClusterIP` overlay (`SERVICE_CIDR` in the same places).
pub const GUEST_SERVICE_OVERLAY: &str = "10.245.0.0/16";
const GUEST_OVERLAY_POD_PREF: u32 = 200;
const GUEST_OVERLAY_SVC_PREF: u32 = 201;

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
    /// Per-TAP L2 anti-spoof chain . `None` only when
    /// `K7D_NET_JAIL=off`. Dropping it deletes the netdev table; the
    /// struct's own `Drop` (close fd, delete link) runs first, and
    /// `delete table` tolerates the device already being gone.
    anti_spoof: Option<crate::netjail::TapAntiSpoof>,
}

impl TapDevice {
    /// Create a TAP device and attach it to the given bridge.
    ///
    /// The TAP device name is derived from `bridge_name` and `vm_index` so two
    /// bridges (e.g. source and fork) can each host a TAP for the same
    /// `vm_index` without colliding on the kernel-side interface name.
    pub fn create(bridge_name: &str, vm_index: u32) -> Result<Self, String> {
        let mut tap = Self::create_unpinned(bridge_name, vm_index)?;
        // Per-TAP L2 anti-spoof : the MAC/IP identity is
        // assigned right here, so this is where the pin goes on. All
        // bridges share 10.200.0.0/24 and forks reuse guest IPs — the
        // pin must be per-TAP, never a global source-IP set.
        tap.anti_spoof = crate::netjail::TapAntiSpoof::install(&tap.name, tap.mac, tap.guest_ip)?;
        Ok(tap)
    }

    /// [`create`](Self::create) without the anti-spoof pin — for the
    /// batch fork path, which pins a whole cluster's TAPs in ONE `nft`
    /// invocation ([`crate::netjail::TapAntiSpoof::install_batch`])
    /// instead of one process per TAP. Callers MUST attach the batch
    /// guards before any guest traffic can flow (the VMs don't exist
    /// yet at this point on the fork path).
    fn create_unpinned(bridge_name: &str, vm_index: u32) -> Result<Self, String> {
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

        // Must match advertised virtio features (no CSUM/TSO). Zero is
        // a real offload set, not a fallback — fail loud if the TAP
        // cannot take it.
        let offload: libc::c_uint = 0;
        // SAFETY: fd is valid TAP; setting offload flags.
        if unsafe { libc::ioctl(fd, TUNSETOFFLOAD, offload as libc::c_ulong) } < 0 {
            let err = std::io::Error::last_os_error();
            // SAFETY: fd is valid.
            unsafe { libc::close(fd) };
            return Err(format!("TUNSETOFFLOAD none: {err}"));
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

        // Build the struct before pinning so its `Drop` (close fd,
        // delete link) cleans up if a later anti-spoof install fails.
        Ok(Self {
            fd,
            name: tap_name,
            mac,
            guest_ip,
            vm_index,
            anti_spoof: None,
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

    /// Whether the host side of this TAP has a frame queued for the
    /// guest .
    ///
    /// Read-only and non-destructive: `poll` with a zero timeout tells
    /// us the bridge has handed the TAP something the VMM has not yet
    /// put in the guest's RX ring, without consuming it. The
    /// guest-to-bridge direction needs no separate check — a frame the
    /// guest handed over shows up as an undrained virtio-net TX queue.
    pub fn has_pending_frame(&self) -> Result<bool, String> {
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pfd` is a live, correctly initialised pollfd holding
        // this TAP's own fd, which the `TapDevice` keeps open. Timeout 0
        // means poll never blocks and never reads anything.
        let rc = unsafe { libc::poll(&raw mut pfd, 1, 0) };
        if rc < 0 {
            return Err(format!(
                "poll({}) for a queued frame: {}",
                self.name,
                std::io::Error::last_os_error()
            ));
        }
        Ok(pfd.revents & libc::POLLIN != 0)
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

#[cfg(test)]
mod bridge_name_tests {
    use super::{bridge_short_tag, VirtqDesc, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};

    #[test]
    fn long_cluster_id_matches_gym_k7_bridge_name() {
        let cluster_id = "gym-src-test-ubuntu-605268-lease-abc-0001";
        let h = bridge_short_tag(cluster_id);
        let name = format!("k7-br-{}-{}", &cluster_id[..3], &h[..5]);
        assert_eq!(name, format!("k7-br-gym-{}", &h[..5]));
        assert!(
            name.len() <= 15,
            "{name} is {} chars (IFNAMSIZ-1 is 15)",
            name.len()
        );
    }

    #[test]
    fn default_route_iface_names_an_existing_link() {
        let iface = super::default_route_iface().expect("host has a default route");
        assert!(
            std::path::Path::new("/sys/class/net").join(&iface).exists(),
            "default route iface {iface} does not exist — refusing the eth0 fallback"
        );
    }

    #[test]
    fn ipv4_network_masks_host_bits() {
        let (prefix, src) = super::ipv4_network("10.42.0.1/24").expect("parse");
        assert_eq!(prefix, "10.42.0.0/24");
        assert_eq!(src, "10.42.0.1");
        assert!(super::ipv4_network("10.42.0.1").is_err());
        assert!(super::ipv4_network("10.42.0.1/33").is_err());
    }

    #[test]
    fn host_wan_has_no_leftover_shaping() {
        let iface = super::default_route_iface().expect("host has a default route");
        super::assert_no_leftover_shaping(&iface)
            .expect("IFB / tc leftovers on the WAN path (CHALLENGES.md #117)");
    }

    #[test]
    fn desc_chain_writable_len_sums_write_descs() {
        let mem = [
            VirtqDesc {
                addr: 0x1000,
                len: 2048,
                flags: VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT,
                next: 1,
            },
            VirtqDesc {
                addr: 0x2000,
                len: 1024,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
        ];
        let q = crate::virtio_mmio::VirtqueueState {
            max_size: 8,
            size: 8,
            ready: true,
            desc_addr: vm_memory::GuestAddress(0),
            avail_addr: vm_memory::GuestAddress(0),
            used_addr: vm_memory::GuestAddress(0),
        };
        let base = mem.as_ptr() as u64;
        assert_eq!(super::desc_chain_writable_len(base, &q, 0), 3072);
    }

    fn fold(mut sum: u32) -> u16 {
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum as u16
    }

    /// Minimal eth+IPv4+TCP SYN with Linux CHECKSUM_PARTIAL in the virtio hdr.
    fn partial_tcp_syn() -> (Vec<u8>, u16) {
        let mut pkt = vec![0u8; 14 + 20 + 20];
        pkt[12] = 0x08;
        pkt[13] = 0x00;
        pkt[14] = 0x45;
        pkt[16] = 0x00;
        pkt[17] = 40;
        pkt[22] = 64;
        pkt[23] = 6;
        pkt[26..30].copy_from_slice(&[10, 42, 1, 10]);
        pkt[30..34].copy_from_slice(&[10, 42, 2, 20]);
        pkt[34..36].copy_from_slice(&1234u16.to_be_bytes());
        pkt[36..38].copy_from_slice(&8080u16.to_be_bytes());
        pkt[46] = 0x50;
        pkt[47] = 0x02;

        let mut pseudo = 0u32;
        for w in pkt[26..34].chunks_exact(2) {
            pseudo += u16::from_be_bytes([w[0], w[1]]) as u32;
        }
        pseudo += 6;
        pseudo += 20;
        // Linux `th->check = ~tcp_v4_check(len, s, d, 0)` = fold(pseudo).
        let partial_field = fold(pseudo);
        pkt[50..52].copy_from_slice(&partial_field.to_be_bytes());

        let mut full = pseudo;
        let mut tcp = pkt[34..].to_vec();
        tcp[16] = 0;
        tcp[17] = 0;
        for c in tcp.chunks_exact(2) {
            full += u16::from_be_bytes([c[0], c[1]]) as u32;
        }
        let expected = !fold(full);

        let mut buf = vec![0u8; super::VIRTIO_NET_HDR_LEN + pkt.len()];
        buf[0] = super::VIRTIO_NET_HDR_F_NEEDS_CSUM;
        buf[6..8].copy_from_slice(&34u16.to_le_bytes());
        buf[8..10].copy_from_slice(&16u16.to_le_bytes());
        buf[super::VIRTIO_NET_HDR_LEN..].copy_from_slice(&pkt);
        (buf, expected)
    }

    #[test]
    fn prepare_guest_tx_completes_tcp_partial_csum() {
        let (mut buf, expected) = partial_tcp_syn();
        super::prepare_guest_tx(&mut buf).expect("complete");
        assert_eq!(buf[0] & super::VIRTIO_NET_HDR_F_NEEDS_CSUM, 0);
        let got = u16::from_be_bytes([
            buf[super::VIRTIO_NET_HDR_LEN + 50],
            buf[super::VIRTIO_NET_HDR_LEN + 51],
        ]);
        assert_eq!(got, expected, "TCP checksum after NEEDS_CSUM completion");

        let mut verify = 0u32;
        for w in buf[super::VIRTIO_NET_HDR_LEN + 26..super::VIRTIO_NET_HDR_LEN + 34].chunks_exact(2)
        {
            verify += u16::from_be_bytes([w[0], w[1]]) as u32;
        }
        verify += 6;
        verify += 20;
        for c in buf[super::VIRTIO_NET_HDR_LEN + 34..].chunks_exact(2) {
            verify += u16::from_be_bytes([c[0], c[1]]) as u32;
        }
        assert_eq!(fold(verify), 0xffff, "receiver sees a valid TCP checksum");
    }

    #[test]
    fn prepare_guest_tx_leaves_complete_frames_alone() {
        let mut buf = vec![0u8; super::VIRTIO_NET_HDR_LEN + 64];
        buf[20] = 0xaa;
        let before = buf.clone();
        super::prepare_guest_tx(&mut buf).expect("no-csum frame");
        assert_eq!(buf, before);
    }

    #[test]
    fn prepare_guest_tx_refuses_gso() {
        let mut buf = vec![0u8; super::VIRTIO_NET_HDR_LEN + 64];
        buf[1] = 1; // VIRTIO_NET_HDR_GSO_TCPV4
        let err = super::prepare_guest_tx(&mut buf).expect_err("GSO must fail loud");
        assert!(err.contains("GSO"), "{err}");
    }

    #[test]
    fn prepare_guest_tx_refuses_truncated_csum_field() {
        let mut buf = vec![0u8; super::VIRTIO_NET_HDR_LEN + 20];
        buf[0] = super::VIRTIO_NET_HDR_F_NEEDS_CSUM;
        buf[6..8].copy_from_slice(&30u16.to_le_bytes());
        buf[8..10].copy_from_slice(&16u16.to_le_bytes());
        let err = super::prepare_guest_tx(&mut buf).expect_err("short csum field");
        assert!(err.contains("NEEDS_CSUM"), "{err}");
    }
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
    /// This bridge's nftables jail . `None` only when
    /// `K7D_NET_JAIL=off`. Dropping it deletes the table, which is why
    /// it is a field rather than a side effect of `create`.
    jail: Option<crate::netjail::TreeNetJail>,
    /// This tree's egress posture . Forks inherit it via
    /// [`ClusterNetwork::fork_from`]; suspend/resume persists it in
    /// `cluster.json`.
    egress: crate::netjail::EgressPolicy,
    /// The host default-route interface the jail was installed
    /// against — kept so [`ClusterNetwork::set_egress`] can re-render
    /// without re-detecting a possibly-changed route mid-flight.
    default_iface: String,
}

impl ClusterNetwork {
    /// Create a new bridge for a cluster.
    ///
    /// If a bridge with the derived name already exists (e.g. another shim
    /// process on the same node already created it for the same cluster), the
    /// existing bridge is reused instead of being re-created. This makes the
    /// call idempotent across cooperating pods sharing a cluster.
    pub fn create(cluster_id: &str) -> Result<Self, String> {
        Self::create_with_egress(cluster_id, crate::netjail::EgressPolicy::default())
    }

    /// [`ClusterNetwork::create`] with an explicit egress policy
    /// . `create` delegates here with the `Open` default,
    /// which is byte-identical to pre-29b behaviour.
    pub fn create_with_egress(
        cluster_id: &str,
        egress: crate::netjail::EgressPolicy,
    ) -> Result<Self, String> {
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

        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")
            .map_err(|e| format!("enable ip_forward: {e}"))?;
        // `net.bridge.bridge-nf-call-iptables` is GLOBAL. Host kube-proxy
        // ClusterIP DNAT needs it 1 (writing 0 here broke every host
        // Service). FORWARD ACCEPT on this bridge does **not** stop the
        // host flannel `MASQUERADE 10.42.0.0/16` in nat POSTROUTING —
        // bridged guest pod SYNs became `10.200.0.1` (world) and Cilium
        // NetworkPolicy denied them (CHALLENGES.md #117). Keep the
        // global sysctl 1; turn netfilter off on *this* bridge only.
        std::fs::write("/proc/sys/net/bridge/bridge-nf-call-iptables", "1")
            .map_err(|e| format!("enable bridge-nf-call-iptables: {e}"))?;
        std::fs::write("/proc/sys/net/bridge/bridge-nf-call-ip6tables", "1")
            .map_err(|e| format!("enable bridge-nf-call-ip6tables: {e}"))?;
        disable_bridge_nf_call(&bridge_name)?;
        let default_iface = default_route_iface()?;
        assert_no_leftover_shaping(&default_iface)?;
        install_bridge_forward_rules(&bridge_name)?;
        // Disable reverse path filtering on bridge (strict rp_filter blocks responses)
        std::fs::write(
            format!("/proc/sys/net/ipv4/conf/{bridge_name}/rp_filter"),
            "0",
        )
        .map_err(|e| format!("clear {bridge_name} rp_filter: {e}"))?;
        std::fs::write("/proc/sys/net/ipv4/conf/all/rp_filter", "0")
            .map_err(|e| format!("clear all rp_filter: {e}"))?;
        ensure_iptables(
            Some("nat"),
            &[
                "POSTROUTING",
                "-s",
                "10.200.0.0/24",
                "-o",
                &default_iface,
                "-j",
                "MASQUERADE",
            ],
        )?;

        // The FORWARD ACCEPT rules above make this bridge reachable from
        // every other `k7-br-*` on the node. The jail (evaluated one
        // priority ahead of them) is what stops one tree from routing
        // into another's guests, and  owns the egress and
        // guest→host input decisions — see `crate::netjail`.
        let jail = crate::netjail::TreeNetJail::install(
            &bridge_name,
            &crate::netjail::JailIfaces::detect(&default_iface),
            &egress,
        )?;

        log::info!("bridge {bridge_name} created with gateway {gw}/24 via {default_iface}");

        Ok(Self {
            bridge_name,
            subnet_base: GUEST_SUBNET_BASE,
            next_vm_index: 0,
            entries: HashMap::new(),
            jail,
            egress,
            default_iface,
        })
    }

    /// This tree's egress policy.
    #[must_use]
    pub fn egress(&self) -> &crate::netjail::EgressPolicy {
        &self.egress
    }

    /// Replace this bridge's egress policy, atomically re-installing
    /// the jail ruleset (the referenced work: `tree_adopt_cluster` may adopt a
    /// bridge born `Open` into a tree with a stricter posture). When
    /// `K7D_NET_JAIL=off` the policy is recorded but nothing is
    /// enforced — same contract as `create`.
    pub fn set_egress(&mut self, egress: crate::netjail::EgressPolicy) -> Result<(), String> {
        egress.validate()?;
        if let Some(old) = self.jail.take() {
            match crate::netjail::TreeNetJail::install(
                &self.bridge_name,
                &crate::netjail::JailIfaces::detect(&self.default_iface),
                &egress,
            ) {
                Ok(new) => {
                    // The install atomically replaced the SAME table the
                    // old guard owns — running the old guard's Drop now
                    // would delete the freshly installed ruleset.
                    std::mem::forget(old);
                    self.jail = new;
                }
                Err(e) => {
                    // `nft -f` is transactional: on failure the old
                    // ruleset is still in place, so the old guard stays.
                    self.jail = Some(old);
                    return Err(e);
                }
            }
        }
        self.egress = egress;
        Ok(())
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
        self.register_tap_entry(&tap);
        Ok(tap)
    }

    fn register_tap_entry(&mut self, tap: &TapDevice) {
        let entry = VmNetworkEntry {
            vm_index: tap.vm_index(),
            tap_name: tap.name().to_string(),
            guest_ip: tap.guest_ip(),
            guest_mac: tap.mac(),
            pod_ip: None,
            pod_netns: None,
        };
        self.entries.insert(tap.vm_index(), entry);
    }

    /// [`add_tap_at`](Self::add_tap_at) for a whole cluster's worth of
    /// indices at once, pinning every TAP's anti-spoof in a single
    /// `nft` transaction — the fork path's per-cluster host-net cost is
    /// dominated by `nft` process spawns, so the batch keeps the
    /// 50-cluster fork budget honest . Returns the TAPs in
    /// `indices` order; on any failure every TAP created so far is
    /// dropped (link + netdev table teardown via `Drop`).
    pub fn add_taps_at(&mut self, indices: &[u32]) -> Result<Vec<TapDevice>, String> {
        for &idx in indices {
            if self.entries.contains_key(&idx) {
                return Err(format!(
                    "vm_index {idx} already allocated on bridge {}",
                    self.bridge_name
                ));
            }
        }
        let mut taps = Vec::with_capacity(indices.len());
        for &idx in indices {
            taps.push(TapDevice::create_unpinned(&self.bridge_name, idx)?);
            if idx >= self.next_vm_index {
                self.next_vm_index = idx + 1;
            }
        }
        let specs: Vec<(String, [u8; 6], Ipv4Addr)> = taps
            .iter()
            .map(|t| (t.name().to_string(), t.mac(), t.guest_ip()))
            .collect();
        if let Some(guards) = crate::netjail::TapAntiSpoof::install_batch(&specs)? {
            for (tap, guard) in taps.iter_mut().zip(guards) {
                tap.anti_spoof = Some(guard);
            }
        }
        for tap in &taps {
            self.register_tap_entry(tap);
        }
        Ok(taps)
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
        // Fork inherits the source's egress posture : a
        // contained tree must not mint an Open child.
        let mut fork = Self::create_with_egress(fork_cluster_id, source.egress.clone())?;
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
        // The jail names this device; a table left behind would filter
        // the next bridge that reuses the name .
        if let Some(jail) = &self.jail {
            if let Err(e) = jail.remove() {
                log::error!("remove net jail for {bridge}: {e}");
            }
        }
        remove_bridge_forward_rules(bridge);
        // MASQUERADE is keyed on the subnet, not the bridge — only remove it
        // when this is the last bridge using the subnet, i.e. when no other
        // `k7-br-*` link still exists. Conservative: count siblings.
        if !any_other_k7_bridge_exists(bridge) {
            if let Ok(iface) = default_route_iface() {
                let _ = delete_iptables(
                    Some("nat"),
                    &[
                        "POSTROUTING",
                        "-s",
                        "10.200.0.0/24",
                        "-o",
                        &iface,
                        "-j",
                        "MASQUERADE",
                    ],
                );
            }
        }
        // Overlay policy rules/routes first — they name this device.
        remove_guest_overlay_routes(bridge);
        // The bridge link last — kernel connected routes go with it.
        // Guest overlay routes installed with `ip route replace` in
        // the *main* table do not come back: they replaced host
        // `cni0`'s `10.42.0.0/24`. Restore that explicitly.
        let _ = std::process::Command::new("ip")
            .args(["link", "set", "dev", bridge, "down"])
            .output();
        run_cmd("ip", &["link", "delete", bridge, "type", "bridge"])?;
        purge_main_table_guest_via_routes();
        restore_host_cni_connected_route()?;
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

/// Install guest podCIDR / `ClusterIP` routes in [`GUEST_OVERLAY_TABLE`].
///
/// Only packets arriving on `bridge` destined to [`GUEST_POD_OVERLAY`]
/// or [`GUEST_SERVICE_OVERLAY`] look up this table. The host main
/// table stays untouched, so host k3s (`cni0`, `10.42/16`) cannot be
/// disturbed (CHALLENGES.md #117).
///
/// `routes` is `(prefix, via)` — each guest node's podCIDR via its
/// `InternalIP`, plus [`GUEST_SERVICE_OVERLAY`] via the first node.
pub fn install_guest_overlay_routes(bridge: &str, routes: &[(&str, &str)]) -> Result<(), String> {
    if bridge.is_empty() || !bridge.starts_with("k7-br-") {
        return Err(format!(
            "install_guest_overlay_routes: bridge {bridge:?} is not a k7-br-* device"
        ));
    }
    if routes.is_empty() {
        return Err("install_guest_overlay_routes: no overlay routes".into());
    }
    let table = GUEST_OVERLAY_TABLE.to_string();
    for (prefix, via) in routes {
        if prefix.is_empty() || via.is_empty() {
            return Err(format!("empty overlay route prefix={prefix:?} via={via:?}"));
        }
        run_cmd(
            "ip",
            &[
                "route", "replace", prefix, "via", via, "dev", bridge, "table", &table,
            ],
        )?;
    }
    ensure_ip_rule(
        GUEST_OVERLAY_POD_PREF,
        &["iif", bridge, "to", GUEST_POD_OVERLAY, "lookup", &table],
    )?;
    ensure_ip_rule(
        GUEST_OVERLAY_SVC_PREF,
        &["iif", bridge, "to", GUEST_SERVICE_OVERLAY, "lookup", &table],
    )?;
    Ok(())
}

/// Drop policy rules and table-200 routes that name `bridge`.
/// Also drains rules for the pre-#121 overlay prefixes (`10.42/16`,
/// `10.43/16`) so nodes provisioned before the CIDR split come clean.
pub fn remove_guest_overlay_routes(bridge: &str) {
    let table = GUEST_OVERLAY_TABLE.to_string();
    for (pref, dest) in [
        (GUEST_OVERLAY_POD_PREF, GUEST_POD_OVERLAY),
        (GUEST_OVERLAY_SVC_PREF, GUEST_SERVICE_OVERLAY),
        (GUEST_OVERLAY_POD_PREF, "10.42.0.0/16"),
        (GUEST_OVERLAY_SVC_PREF, "10.43.0.0/16"),
    ] {
        loop {
            if delete_ip_rule(pref, &["iif", bridge, "to", dest, "lookup", table.as_str()]).is_err()
            {
                break;
            }
        }
    }
    let Ok((_, stdout, _)) =
        crate::netns::run_capture("ip", &["-4", "route", "show", "table", &table])
    else {
        return;
    };
    let needle = format!(" dev {bridge}");
    for line in stdout.lines() {
        if !line.contains(&needle) {
            continue;
        }
        let Some(prefix) = line.split_whitespace().next() else {
            continue;
        };
        let _ = run_cmd("ip", &["route", "del", prefix, "table", &table]);
    }
}

/// Delete leftover `10.42…` / `10.43… via 10.200…` routes in the main
/// table. Those were installed by an older `ip route replace` helper
/// and steal host k3s when the k7 bridge disappears.
pub fn purge_main_table_guest_via_routes() {
    let Ok((_, stdout, _)) = crate::netns::run_capture("ip", &["-4", "route", "show"]) else {
        return;
    };
    for line in stdout.lines() {
        if !line.contains("via 10.200.") {
            continue;
        }
        let Some(prefix) = line.split_whitespace().next() else {
            continue;
        };
        // Old (pre-#121) and current guest overlay prefixes; anything
        // guest-shaped that routes via the k7 gateway is a leftover.
        if !prefix.starts_with("10.42.")
            && !prefix.starts_with("10.43.")
            && !prefix.starts_with("10.244.")
            && !prefix.starts_with("10.245.")
        {
            continue;
        }
        let _ = run_cmd("ip", &["route", "del", prefix]);
    }
}

/// If host `cni0` is up with an IPv4 prefix but the main table has no
/// connected route (or a leftover `via 10.200` stole it), put the
/// kernel connected route back. No-op when `cni0` is absent.
pub fn restore_host_cni_connected_route() -> Result<(), String> {
    let (status, stdout, stderr) =
        crate::netns::run_capture("ip", &["-4", "-o", "addr", "show", "dev", "cni0"])
            .map_err(|e| format!("ip addr show cni0: {e}"))?;
    if !status.success() {
        if stderr.contains("does not exist") || stderr.contains("Cannot find device") {
            return Ok(());
        }
        if stdout.is_empty() && !Path::new("/sys/class/net/cni0").exists() {
            return Ok(());
        }
        return Err(format!("ip addr show cni0 failed: {}", stderr.trim()));
    }
    let Some(slash) = stdout
        .split_whitespace()
        .skip_while(|w| *w != "inet")
        .nth(1)
    else {
        return Ok(());
    };
    let (prefix, src) = ipv4_network(slash)?;
    let (_, shown, _) = crate::netns::run_capture("ip", &["-4", "route", "show", &prefix])
        .map_err(|e| format!("ip route show {prefix}: {e}"))?;
    let connected = shown
        .lines()
        .any(|l| l.starts_with(&prefix) && l.contains("dev cni0") && !l.contains("via "));
    if connected {
        return Ok(());
    }
    if !shown.trim().is_empty() {
        let _ = run_cmd("ip", &["route", "del", &prefix]);
    }
    run_cmd(
        "ip",
        &[
            "route", "add", &prefix, "dev", "cni0", "proto", "kernel", "scope", "link", "src", &src,
        ],
    )
}

fn ipv4_network(addr_slash: &str) -> Result<(String, String), String> {
    let (ip, bits) = addr_slash
        .split_once('/')
        .ok_or_else(|| format!("cni0 addr {addr_slash:?} is not ip/prefix"))?;
    let ip: Ipv4Addr = ip.parse().map_err(|e| format!("cni0 addr {ip:?}: {e}"))?;
    let bits: u32 = bits
        .parse()
        .map_err(|e| format!("cni0 prefix {bits:?}: {e}"))?;
    if bits > 32 {
        return Err(format!("cni0 prefix /{bits} is not a valid IPv4 length"));
    }
    let host = u32::from(ip);
    let mask = if bits == 0 { 0 } else { !0u32 << (32 - bits) };
    let net = Ipv4Addr::from(host & mask);
    Ok((format!("{net}/{bits}"), ip.to_string()))
}

fn ensure_ip_rule(pref: u32, spec: &[&str]) -> Result<(), String> {
    if ip_rule_present(pref, spec) {
        return Ok(());
    }
    let pref_s = pref.to_string();
    let mut args = Vec::with_capacity(spec.len() + 4);
    args.extend_from_slice(&["rule", "add", "pref", pref_s.as_str()]);
    args.extend_from_slice(spec);
    let (status, _, stderr) =
        crate::netns::run_capture("ip", &args).map_err(|e| format!("ip rule add: {e}"))?;
    if status.success() || stderr.contains("File exists") {
        return Ok(());
    }
    Err(format!("ip {} failed: {}", args.join(" "), stderr.trim()))
}

fn ip_rule_present(pref: u32, spec: &[&str]) -> bool {
    let pref_s = pref.to_string();
    let Ok((_, stdout, _)) =
        crate::netns::run_capture("ip", &["-4", "rule", "show", "pref", &pref_s])
    else {
        return false;
    };
    stdout
        .lines()
        .any(|line| spec.iter().all(|tok| line.contains(tok)))
}

fn delete_ip_rule(pref: u32, spec: &[&str]) -> Result<(), String> {
    let pref_s = pref.to_string();
    let mut args = Vec::with_capacity(spec.len() + 4);
    args.extend_from_slice(&["rule", "del", "pref", pref_s.as_str()]);
    args.extend_from_slice(spec);
    run_cmd("ip", &args)
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
        // Remove the per-bridge ACCEPT / TCPMSS rules first; failure is
        // fine (the rule may already be gone).
        remove_bridge_forward_rules(bridge);
        let _ = std::process::Command::new("ip")
            .args(["link", "set", "dev", bridge, "down"])
            .output();
        remove_guest_overlay_routes(bridge);
        let _ = std::process::Command::new("ip")
            .args(["link", "delete", bridge, "type", "bridge"])
            .output();
    }
    purge_main_table_guest_via_routes();
    let _ = restore_host_cni_connected_route();
    // Once every `k7-br-*` is gone, the shared `10.200.0.0/24`
    // MASQUERADE rule is safe to remove — there's no live bridge using
    // the subnet anymore. Repeat the delete to drain duplicates that
    // accumulated across test crashes.
    if let Ok(iface) = default_route_iface() {
        loop {
            if delete_iptables(
                Some("nat"),
                &[
                    "POSTROUTING",
                    "-s",
                    "10.200.0.0/24",
                    "-o",
                    &iface,
                    "-j",
                    "MASQUERADE",
                ],
            )
            .is_err()
            {
                // `iptables -D` returns non-zero when the rule isn't there;
                // that's our termination condition (no more duplicates).
                break;
            }
        }
    }
    bridges
}

impl Drop for ClusterNetwork {
    fn drop(&mut self) {
        let _ = self.destroy();
    }
}

/// Host `br_netfilter` + flannel `MASQUERADE 10.42.0.0/16` SNATs
/// bridged guest pod SYNs to the k7 gateway (`10.200.0.1`). Cilium
/// then classifies the source as `reserved:world` and a `NetworkPolicy`
/// that allows only `role=cil-client` drops them. Per-bridge sysfs
/// keeps the global `bridge-nf-call-iptables=1` the host kube-proxy
/// needs.
fn disable_bridge_nf_call(bridge: &str) -> Result<(), String> {
    for name in ["nf_call_iptables", "nf_call_ip6tables", "nf_call_arptables"] {
        let path = format!("/sys/class/net/{bridge}/bridge/{name}");
        std::fs::write(&path, "0").map_err(|e| format!("write {path}: {e}"))?;
        let got = std::fs::read_to_string(&path).map_err(|e| format!("read {path}: {e}"))?;
        if got.trim() != "0" {
            return Err(format!(
                "{path} is {:?} after write 0 — host flannel would SNAT bridged guest pods to {bridge}",
                got.trim()
            ));
        }
    }
    Ok(())
}

/// Fail loud if a previous experiment left IFB / tc shaping on the
/// WAN path. That is one of the #117 traps: host pulls stay full
/// speed (they do not traverse IFB) while guest NAT is rate-limited
/// to tens of KB/s. `fq` / `fq_codel` / `mq` / `noqueue` are fine.
fn assert_no_leftover_shaping(wan: &str) -> Result<(), String> {
    let (status, stdout, stderr) =
        crate::netns::run_capture("ip", &["-o", "link", "show", "type", "ifb"])
            .map_err(|e| format!("ip link show type ifb: {e}"))?;
    if !status.success() {
        return Err(format!("ip link show type ifb failed: {}", stderr.trim()));
    }
    if !stdout.trim().is_empty() {
        return Err(format!(
            "IFB leftover on the host (CHALLENGES.md #117 guest-egress trap):\n{}",
            stdout.trim()
        ));
    }
    let (status, qdisc, stderr) = crate::netns::run_capture("tc", &["qdisc", "show", "dev", wan])
        .map_err(|e| format!("tc qdisc show {wan}: {e}"))?;
    if !status.success() {
        return Err(format!("tc qdisc show {wan} failed: {}", stderr.trim()));
    }
    for line in qdisc.lines() {
        let lower = line.to_ascii_lowercase();
        if ["tbf", "htb", "netem"]
            .iter()
            .any(|kw| lower.split_whitespace().any(|w| w == *kw))
            || lower.split_whitespace().any(|w| w.starts_with("ifb"))
            || lower.split_whitespace().any(|w| w == "ingress")
        {
            return Err(format!(
                "tc shaping leftover on {wan} (CHALLENGES.md #117): {line}"
            ));
        }
    }
    Ok(())
}

fn default_route_iface() -> Result<String, String> {
    let out = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .map_err(|e| format!("ip route show default: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "ip route show default failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout
        .lines()
        .find(|l| l.starts_with("default "))
        .ok_or_else(|| format!("no default route — guest NAT has nowhere to egress:\n{stdout}"))?;
    let mut words = line.split_whitespace();
    while let Some(word) = words.next() {
        if word == "dev" {
            return words
                .next()
                .map(str::to_string)
                .ok_or_else(|| format!("default route has no device name: {line}"));
        }
    }
    Err(format!("default route has no `dev`: {line}"))
}

/// Insert `spec` unless `iptables -C` already sees it. Never swallows a
/// failed insert — a missing FORWARD/MASQUERADE/TCPMSS rule is a silent
/// black hole for guest egress (CHALLENGES.md #117).
fn ensure_iptables(table: Option<&str>, spec: &[&str]) -> Result<(), String> {
    let mut check = Vec::with_capacity(spec.len() + 4);
    if let Some(t) = table {
        check.extend_from_slice(&["-t", t]);
    }
    check.push("-C");
    check.extend_from_slice(spec);
    let (status, _, _) =
        crate::netns::run_capture("iptables", &check).map_err(|e| format!("iptables -C: {e}"))?;
    if status.success() {
        return Ok(());
    }
    let mut insert = Vec::with_capacity(spec.len() + 4);
    if let Some(t) = table {
        insert.extend_from_slice(&["-t", t]);
    }
    insert.push("-I");
    insert.extend_from_slice(spec);
    run_cmd("iptables", &insert)
}

fn delete_iptables(table: Option<&str>, spec: &[&str]) -> Result<(), String> {
    let mut args = Vec::with_capacity(spec.len() + 4);
    if let Some(t) = table {
        args.extend_from_slice(&["-t", t]);
    }
    args.push("-D");
    args.extend_from_slice(spec);
    run_cmd("iptables", &args)
}

fn install_bridge_forward_rules(bridge: &str) -> Result<(), String> {
    ensure_iptables(None, &["FORWARD", "-i", bridge, "-j", "ACCEPT"])?;
    ensure_iptables(None, &["FORWARD", "-o", bridge, "-j", "ACCEPT"])?;
    // The jail's `input` chain (priority filter - 1, `crate::netjail`)
    // owns the guest→host decision since the referenced work — an unconditional
    // iptables `INPUT -i <bridge> -j ACCEPT` here would sit AFTER the
    // jail (which is fine) but also document a hole that no longer
    // exists. Drain any copy a pre-29b daemon left behind so long-lived
    // nodes converge; the loop handles historical duplicates.
    while delete_iptables(None, &["INPUT", "-i", bridge, "-j", "ACCEPT"]).is_ok() {}
    ensure_iptables(None, &["OUTPUT", "-o", bridge, "-j", "ACCEPT"])?;
    // While guest k3s shared the host's 10.42/16 (pre-#121), the
    // global br_netfilter hook let host flannel MASQUERADE SNAT
    // bridged guest pod SYNs to 10.200.0.1 and Cilium denied them as
    // `world` (#117). Guests are on 10.244/16 now, which host flannel
    // does not match, so no skip rule is needed — but drain the old
    // one so pre-#121 nodes do not keep a stale NAT exemption.
    let _ = delete_iptables(
        Some("nat"),
        &[
            "POSTROUTING",
            "-s",
            "10.42.0.0/16",
            "-d",
            "10.42.0.0/16",
            "-m",
            "physdev",
            "--physdev-is-bridged",
            "-j",
            "RETURN",
        ],
    );
    Ok(())
}

fn remove_bridge_forward_rules(bridge: &str) {
    let _ = delete_iptables(None, &["FORWARD", "-i", bridge, "-j", "ACCEPT"]);
    let _ = delete_iptables(None, &["FORWARD", "-o", bridge, "-j", "ACCEPT"]);
    let _ = delete_iptables(None, &["INPUT", "-i", bridge, "-j", "ACCEPT"]);
    let _ = delete_iptables(None, &["OUTPUT", "-o", bridge, "-j", "ACCEPT"]);
    // Drain leftover TCPMSS rules from earlier bring-up attempts.
    for dir in ["-i", "-o"] {
        let _ = delete_iptables(
            Some("mangle"),
            &[
                "FORWARD",
                dir,
                bridge,
                "-p",
                "tcp",
                "--tcp-flags",
                "SYN,RST",
                "SYN",
                "-j",
                "TCPMSS",
                "--clamp-mss-to-pmtu",
            ],
        );
    }
    if let Ok(wan) = default_route_iface() {
        let _ = delete_iptables(
            Some("mangle"),
            &[
                "FORWARD",
                "-i",
                bridge,
                "-o",
                &wan,
                "-p",
                "tcp",
                "--tcp-flags",
                "SYN,RST",
                "SYN",
                "-j",
                "TCPMSS",
                "--clamp-mss-to-pmtu",
            ],
        );
        let _ = delete_iptables(
            Some("mangle"),
            &[
                "FORWARD",
                "-i",
                &wan,
                "-o",
                bridge,
                "-p",
                "tcp",
                "--tcp-flags",
                "SYN,RST",
                "SYN",
                "-j",
                "TCPMSS",
                "--clamp-mss-to-pmtu",
            ],
        );
    }
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

const PAGE_SIZE: u64 = 4096;

/// Mark the pages covering guest-physical range `[gpa, gpa + len)` dirty in
/// a device-DMA bitmap (one bit per 4 KiB page, `u64` words). Out-of-range
/// pages are ignored (the bitmap is sized to guest memory and every write
/// is bounds-checked before it happens). Shared by the userspace virtio-net
/// and virtio-blk workers: KVM's dirty log only sees vCPU writes, so device
/// writes through the host mapping must be recorded here or warm forks on
/// the base.mem + dirty-delta path silently miss them.
pub(crate) fn mark_dirty(dirty: &[std::sync::atomic::AtomicU64], gpa: u64, len: u64) {
    if len == 0 {
        return;
    }
    let first = gpa / PAGE_SIZE;
    let last = (gpa + len - 1) / PAGE_SIZE;
    for page in first..=last {
        let word = (page / 64) as usize;
        if let Some(w) = dirty.get(word) {
            w.fetch_or(1u64 << (page % 64), Ordering::Relaxed);
        }
    }
}

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
    /// True while the worker is parked in the paused state (or exited) —
    /// i.e. no more guest-memory writes will happen until unpause. Without
    /// this the fork memcpy can race a mid-flight used-ring update and hand
    /// the fork a torn ring (CHALLENGES.md #79).
    parked: Arc<AtomicBool>,
    /// Pages this device wrote through the host mapping (RX payloads,
    /// used-ring entries + idx). Merged into the warm-fork dirty delta;
    /// KVM's dirty log cannot see these writes (CHALLENGES.md #79).
    dirty: Arc<Vec<std::sync::atomic::AtomicU64>>,
    /// Seeded `last_avail`/`last_used` for RX (queue 0). Zero on cold boot;
    /// set via [`Self::seed_indices_from_guest`] before activate on restore.
    rx_idx_seed: u16,
    /// Seeded `last_avail`/`last_used` for TX (queue 1).
    tx_idx_seed: u16,
}

impl TapNetBackend {
    /// Create a userspace virtio-net backend using the TAP fd. `mem_size`
    /// is the guest-physical span the device-DMA dirty bitmap must cover.
    #[must_use]
    pub fn new(mac: [u8; 6], tap_fd: RawFd, mem_addr: u64, mem_size: u64) -> Self {
        let words = (mem_size.div_ceil(PAGE_SIZE) as usize).div_ceil(64);
        let dirty = (0..words)
            .map(|_| std::sync::atomic::AtomicU64::new(0))
            .collect();
        Self {
            mac,
            mem_addr,
            tap_fd,
            acked_features: 0,
            tx_kick: None,
            worker: None,
            running: Arc::new(AtomicBool::new(false)),
            paused: Arc::new(AtomicBool::new(false)),
            parked: Arc::new(AtomicBool::new(true)),
            dirty: Arc::new(dirty),
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
        // Wake the worker in both directions: on pause so it leaves its
        // (up to 100 ms) poll and parks promptly — `Vm::pause` waits for
        // the park via `wait_quiescent` — and on unpause so it resumes
        // processing promptly. The eventfd write takes no locks.
        if let Some(ref kick) = self.tx_kick {
            let _ = kick.write(1);
        }
    }

    fn wait_quiescent(&self) {
        if self.worker.is_none() {
            return;
        }
        // Same bound as virtio-blk: above the 100 ms poll, far below the
        // 1 s cluster-fork budget (CHALLENGES #162).
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(200);
        while !self.parked.load(Ordering::SeqCst) && self.running.load(Ordering::SeqCst) {
            if std::time::Instant::now() >= deadline {
                log::warn!(
                    "virtio-net: worker did not park within 200ms — fork memory \
                     capture may race in-flight ring writes"
                );
                return;
            }
            std::thread::sleep(PARK_POLL);
        }
    }

    fn is_quiescent(&self) -> bool {
        self.worker.is_none()
            || !self.running.load(Ordering::SeqCst)
            || self.parked.load(Ordering::SeqCst)
    }

    fn merge_dirty_pages(&self, acc: &mut [u64]) {
        for (i, w) in self.dirty.iter().enumerate() {
            if i >= acc.len() {
                break;
            }
            acc[i] |= w.load(Ordering::SeqCst);
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
        let parked = Arc::clone(&self.parked);
        let dirty = Arc::clone(&self.dirty);
        let rx_idx_seed = self.rx_idx_seed;
        let tx_idx_seed = self.tx_idx_seed;
        running.store(true, Ordering::SeqCst);
        self.paused.store(false, Ordering::SeqCst);
        self.parked.store(false, Ordering::SeqCst);

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
                &parked,
                &dirty,
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

        // A fork/restore can capture the source between the guest's TX kick
        // and the worker draining it: the kick lives in the source's eventfd,
        // which does not survive the fork, and virtio drivers never re-notify
        // for descriptors already made available. Without this self-kick the
        // pending TX frames sit in the ring forever — the guest's TX queue
        // stays stopped waiting for completions and dies with NETDEV WATCHDOG
        // (CHALLENGES.md #79). Harmless on cold boot (the ring is empty).
        if let Some(ref kick) = self.tx_kick {
            let _ = kick.write(1);
        }

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

/// Read guest `avail.idx` (offset +2 in `{flags:u16, idx:u16, ring[]}`).
///
/// Paired with [`read_used_idx`] by the auto-warp safety predicate
/// : on a queue the driver fills with requests, the two
/// being equal is the #79 "nothing in flight" handshake.
pub(crate) fn read_avail_idx(mem_base: u64, q: &VirtqueueState) -> u16 {
    if !q.ready || q.avail_addr.raw_value() == 0 {
        return 0;
    }
    let avail_base = mem_base + q.avail_addr.raw_value();
    // SAFETY: avail_base + 2 points at the idx field in guest RAM, in the
    // caller's live mapping; the caller has paused the vCPUs and parked
    // the device workers, so nothing is writing it.
    unsafe { std::ptr::read_volatile((avail_base + 2) as *const u16) }
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
    parked: &AtomicBool,
    dirty: &[std::sync::atomic::AtomicU64],
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
        // stopped for memory capture. Leave frames in the kernel TAP buffer
        // until resume. Park so `wait_quiescent` (called by `Vm::pause`)
        // knows no ring write is in flight — a fork memcpy racing a
        // mid-flight `put_used_desc` hands the fork a torn used ring and the
        // guest driver marks the queue broken forever (CHALLENGES.md #79).
        if paused.load(Ordering::SeqCst) {
            parked.store(true, Ordering::SeqCst);
            while paused.load(Ordering::SeqCst) && running.load(Ordering::SeqCst) {
                std::thread::sleep(UNPARK_POLL);
            }
            parked.store(false, Ordering::SeqCst);
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
                if !rx_deliver_merged(
                    &mut pkt_buf[..pkt_len],
                    mem_base,
                    rx_q,
                    &mut rx_last_avail,
                    &mut rx_last_used,
                    dirty,
                    irq_fd,
                ) {
                    // Guest has no RX buffers; leave the rest in the TAP.
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
                    if let Err(e) = prepare_guest_tx(&mut pkt_buf[..len]) {
                        log::error!("virtio-net TX dropped ({e}) — refusing a broken TAP write");
                    } else {
                        // SAFETY: tap_fd is valid; pkt_buf[..len] is valid.
                        let wrote = unsafe {
                            libc::write(tap_fd, pkt_buf.as_ptr().cast::<libc::c_void>(), len)
                        };
                        if wrote < 0 {
                            log::error!(
                                "TAP write {len} bytes failed: {}",
                                std::io::Error::last_os_error()
                            );
                        } else if wrote as usize != len {
                            log::error!("TAP short write: {wrote} of {len}");
                        }
                    }
                }
                let slot = u64::from(tx_last_used % tx_q.size);
                put_used_desc(mem_base, tx_q, &mut tx_last_used, desc_idx, 0);
                let used_gpa = tx_q.used_addr.raw_value();
                mark_dirty(dirty, used_gpa + 4 + slot * 8, 8);
                mark_dirty(dirty, used_gpa + 2, 2);
                signal_irq(irq_fd);
            }
        }
    }
    // Report quiescence on exit too, so wait_quiescent never hangs on a
    // shut-down device.
    parked.store(true, Ordering::SeqCst);
}

/// Finish a guest TX frame so a TAP with offload-none can inject it.
///
/// Completes `NEEDS_CSUM` (Cilium BPF `CHECKSUM_PARTIAL` via
/// `bpf_redirect`) and refuses GSO — the TAP has no TSO, and a silent
/// `EINVAL` write would black-hole the SYN (CHALLENGES.md #117).
fn prepare_guest_tx(buf: &mut [u8]) -> Result<(), String> {
    if buf.len() < VIRTIO_NET_HDR_LEN {
        return Err(format!(
            "TX frame {} bytes is shorter than virtio_net_hdr_v1",
            buf.len()
        ));
    }
    let gso_type = buf[1] & 0x7f;
    if gso_type != VIRTIO_NET_HDR_GSO_NONE {
        return Err(format!(
            "guest TX GSO type {gso_type} on a no-TSO virtio-net; TAP would EINVAL"
        ));
    }
    if buf[0] & VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
        complete_partial_csum(buf)?;
        buf[0] &= !VIRTIO_NET_HDR_F_NEEDS_CSUM;
    }
    Ok(())
}

/// Linux `skb_checksum_help` for a virtio-net TX buffer: ones-complement
/// from `csum_start` through the end of the packet (the field already
/// holds the pseudo-header contribution) and store `csum_fold` there.
fn complete_partial_csum(buf: &mut [u8]) -> Result<(), String> {
    let csum_start = u16::from_le_bytes([buf[6], buf[7]]) as usize;
    let csum_offset = u16::from_le_bytes([buf[8], buf[9]]) as usize;
    let pkt_len = buf.len() - VIRTIO_NET_HDR_LEN;
    let field = csum_start
        .checked_add(csum_offset)
        .ok_or_else(|| "csum_start+csum_offset overflow".to_string())?;
    let field_end = field
        .checked_add(2)
        .ok_or_else(|| "csum field past usize".to_string())?;
    if csum_start >= pkt_len || field_end > pkt_len {
        return Err(format!(
            "NEEDS_CSUM start={csum_start} offset={csum_offset} but L2 packet is {pkt_len} bytes"
        ));
    }
    let csum = inet_checksum(&buf[VIRTIO_NET_HDR_LEN + csum_start..]);
    let field_at = VIRTIO_NET_HDR_LEN + field;
    buf[field_at] = (csum >> 8) as u8;
    buf[field_at + 1] = csum as u8;
    Ok(())
}

fn inet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for c in chunks.by_ref() {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let Some(&b) = chunks.remainder().first() {
        sum += u16::from_be_bytes([b, 0]) as u32;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
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

/// Maximum `MRG_RXBUF` fragments for one TAP frame. A 64 KiB GRO
/// aggregate into 512-byte guest bufs is 128; anything larger is a
/// TAP/offload bug we refuse to silently truncate (#117).
const MAX_RX_MERGE: usize = 128;

/// Place one TAP frame into the guest RX queue, splitting across
/// mergeable buffers when the frame is larger than a single desc chain.
///
/// `num_buffers` in the virtio-net header is set to the fragment
/// count. `used.idx` is published once after every fragment is written
/// so the guest never observes a partial merge. Returns `false` if the
/// guest has no RX buffers (caller should stop draining the TAP).
fn rx_deliver_merged(
    pkt: &mut [u8],
    mem_base: u64,
    rx_q: &VirtqueueState,
    rx_last_avail: &mut u16,
    rx_last_used: &mut u16,
    dirty: &[std::sync::atomic::AtomicU64],
    irq_fd: RawFd,
) -> bool {
    let pkt_len = pkt.len();
    let avail_at_start = *rx_last_avail;
    let mut chains = [0u16; MAX_RX_MERGE];
    let mut caps = [0usize; MAX_RX_MERGE];
    let mut n_chains = 0usize;
    let mut space = 0usize;

    while space < pkt_len {
        if n_chains == MAX_RX_MERGE {
            *rx_last_avail = avail_at_start;
            log::error!(
                "RX packet {pkt_len} bytes needs more than {MAX_RX_MERGE} MRG_RXBUF fragments \
                 — refusing to truncate (CHALLENGES.md #117)"
            );
            return true;
        }
        let Some(idx) = get_avail_desc(mem_base, rx_q, rx_last_avail) else {
            *rx_last_avail = avail_at_start;
            return false;
        };
        let cap = desc_chain_writable_len(mem_base, rx_q, idx);
        if cap == 0 {
            *rx_last_avail = avail_at_start;
            log::error!("RX desc chain {idx} has zero writable length");
            return false;
        }
        chains[n_chains] = idx;
        caps[n_chains] = cap;
        n_chains += 1;
        space += cap;
    }

    let num_buffers = n_chains as u16;
    if pkt_len >= 12 {
        pkt[10] = num_buffers as u8;
        pkt[11] = (num_buffers >> 8) as u8;
    }

    let mut offset = 0usize;
    let used_gpa = rx_q.used_addr.raw_value();
    for i in 0..n_chains {
        let chunk = (pkt_len - offset).min(caps[i]);
        let written = write_to_desc_chain(
            mem_base,
            rx_q,
            chains[i],
            &pkt[offset..offset + chunk],
            dirty,
        );
        if written != chunk {
            log::error!(
                "RX desc chain {} wrote {written} of {chunk} (CHALLENGES.md #117)",
                chains[i]
            );
        }
        let slot = u64::from(*rx_last_used % rx_q.size);
        write_used_elem(mem_base, rx_q, rx_last_used, chains[i], written as u32);
        mark_dirty(dirty, used_gpa + 4 + slot * 8, 8);
        offset += written;
    }
    publish_used_idx(mem_base, rx_q, *rx_last_used);
    mark_dirty(dirty, used_gpa + 2, 2);
    signal_irq(irq_fd);
    true
}

/// Sum of writable descriptor lengths in one chain.
fn desc_chain_writable_len(mem_base: u64, q: &VirtqueueState, first_desc: u16) -> usize {
    let desc_base = mem_base + q.desc_addr.raw_value();
    let mut desc_idx = first_desc;
    let mut total = 0usize;
    // Bound the walk: a corrupt NEXT loop must not hang the net worker.
    for _ in 0..q.size {
        // SAFETY: desc_base + idx*16 points to a valid VirtqDesc in guest memory.
        let desc: VirtqDesc = unsafe {
            std::ptr::read_volatile((desc_base + u64::from(desc_idx) * 16) as *const VirtqDesc)
        };
        if desc.flags & VIRTQ_DESC_F_WRITE != 0 && desc.addr != 0 {
            total += desc.len as usize;
        }
        if desc.flags & VIRTQ_DESC_F_NEXT == 0 {
            break;
        }
        desc_idx = desc.next;
    }
    total
}

/// Write data to a descriptor chain (for RX: TAP -> guest), recording every
/// written page in the device-DMA dirty bitmap. Returns bytes copied.
fn write_to_desc_chain(
    mem_base: u64,
    q: &VirtqueueState,
    first_desc: u16,
    data: &[u8],
    dirty: &[std::sync::atomic::AtomicU64],
) -> usize {
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
            mark_dirty(dirty, desc.addr, copy_len as u64);
            offset += copy_len;
        }

        if desc.flags & VIRTQ_DESC_F_NEXT != 0 && offset < data.len() {
            desc_idx = desc.next;
        } else {
            break;
        }
    }
    offset
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

/// Write one used-ring element and advance `last_used`. Does **not**
/// publish `used.idx` — call [`publish_used_idx`] after the last
/// element of a multi-buffer RX packet so the guest never observes a
/// partial `MRG_RXBUF` merge.
fn write_used_elem(
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
}

fn publish_used_idx(mem_base: u64, q: &VirtqueueState, last_used: u16) {
    let used_base = mem_base + q.used_addr.raw_value();
    // SAFETY: used_base + 2 points to the idx field.
    unsafe {
        std::ptr::write_volatile((used_base + 2) as *mut u16, last_used);
    }
}

/// Put a descriptor in the used ring and publish `used.idx`.
pub(crate) fn put_used_desc(
    mem_base: u64,
    q: &VirtqueueState,
    last_used: &mut u16,
    desc_idx: u16,
    len: u32,
) {
    write_used_elem(mem_base, q, last_used, desc_idx, len);
    publish_used_idx(mem_base, q, *last_used);
}
