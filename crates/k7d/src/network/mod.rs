//! TAP device creation, IP assignment, bridge/NAT setup, userspace virtio-net.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use vmm_sys_util::eventfd::EventFd;

use crate::virtio_mmio::{
    wait_for_park, DescMeta, NotQuiescent, ValidatedQueue, VirtioBackend, VirtqueueState,
    UNPARK_POLL,
};

#[cfg(test)]
use crate::virtio_mmio::{VirtqDesc, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};

// The guest-facing virtio-net device lives in a child module: it sees the
// constants above unchanged, and `crate::network::*` paths keep resolving
// through the re-export.
mod virtio_net;
pub use virtio_net::*;

const VIRTIO_ID_NET: u32 = 1;
const NET_NUM_QUEUES: usize = 2; // RX + TX
const NET_QUEUE_SIZE: u16 = 256;

// TUN/TAP ioctls
const TUNSETIFF: libc::c_ulong = 0x4004_54CA;
const TUNSETOFFLOAD: libc::c_ulong = 0x4004_54D0;
const TUNSETVNETHDRSZ: libc::c_ulong = 0x4004_54D8;
/// `_IOW('T', 203, int)` — keep the device after the last fd closes,
/// so an out-of-process VMM can claim it by name.
const TUNSETPERSIST: libc::c_ulong = 0x4004_54CB;
/// `TUNSETOWNER` / `TUNSETGROUP` — the uid/gid allowed to attach to a
/// persistent TAP without `CAP_NET_ADMIN`. Jailed Firecracker has
/// neither the capability nor a way to get it, so without these its
/// `TUNSETIFF` comes back `EPERM`.
const TUNSETOWNER: libc::c_ulong = 0x4004_54CC;
const TUNSETGROUP: libc::c_ulong = 0x4004_54CE;

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

/// Host policy-routing table guest overlay prefixes used before they
/// moved into each network's namespace (the per-network netns spec);
/// only drained now.
/// It was never the main table: an `ip route replace` there once stole
/// host k3s `cni0`'s connected route (CHALLENGES.md #117).
const GUEST_OVERLAY_TABLE: u32 = 200;
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
#[derive(Debug)]
pub struct TapDevice {
    fd: RawFd,
    name: String,
    mac: [u8; 6],
    guest_ip: Ipv4Addr,
    vm_index: u32,
    /// Per-TAP L2 anti-spoof chain. `None` only when
    /// `K7D_NET_JAIL=off`. Dropping it deletes the netdev table; the
    /// struct's own `Drop` (close fd, delete link) runs first, and
    /// `delete table` tolerates the device already being gone.
    ///
    /// Also `None` under privilege separation: the pin belongs to the
    /// node broker's copy of the device, next to the `CAP_NET_ADMIN`
    /// that installing and removing it needs.
    anti_spoof: Option<crate::netjail::TapAntiSpoof>,
    /// Tree this TAP was allocated on, when the **node broker** made it.
    /// `Some` exactly when the privileged half of this device's
    /// lifetime — the `ip link delete`, the `TUNSETOWNER` hand-over —
    /// is a verb rather than a syscall here.
    tree_id: Option<String>,
    /// The network namespace this TAP was placed in — its network's,
    /// named like the bridge (the per-network netns spec). `None`
    /// while it sits unplaced in the host namespace, waiting to be
    /// moved into a pod's.
    netns: Option<String>,
}

impl TapDevice {
    /// Create a TAP device and, with `netns`, place it on the bridge
    /// inside that network namespace (the per-network netns spec).
    /// Without, it stays unplaced in the host namespace for a pod
    /// attach to move.
    ///
    /// The TAP device name is derived from `bridge_name` and `vm_index` so two
    /// bridges (e.g. source and fork) can each host a TAP for the same
    /// `vm_index` without colliding on the kernel-side interface name.
    fn create(bridge_name: &str, vm_index: u32, netns: Option<&str>) -> Result<Self, String> {
        let mut tap = Self::create_unpinned(bridge_name, vm_index, netns)?;
        // Per-TAP L2 anti-spoof: the MAC/IP identity is
        // assigned right here, so this is where the pin goes on. All
        // bridges share 10.200.0.0/24 and forks reuse guest IPs — the
        // pin must be per-TAP, never a global source-IP set.
        tap.anti_spoof = crate::netjail::TapAntiSpoof::install(
            &tap.name,
            tap.mac,
            tap.guest_ip,
            tap.netns_path().as_deref(),
        )?;
        Ok(tap)
    }

    /// [`create`](Self::create) without the anti-spoof pin — for the
    /// batch fork path, which pins a whole cluster's TAPs in ONE `nft`
    /// invocation ([`crate::netjail::TapAntiSpoof::install_batch`])
    /// instead of one process per TAP. Callers MUST attach the batch
    /// guards before any guest traffic can flow (the VMs don't exist
    /// yet at this point on the fork path).
    fn create_unpinned(
        bridge_name: &str,
        vm_index: u32,
        netns: Option<&str>,
    ) -> Result<Self, String> {
        let mut taps = [Self::open(bridge_name, vm_index, netns)?];
        Self::place(&mut taps, bridge_name)?;
        let [tap] = taps;
        Ok(tap)
    }

    /// The TAP device itself, down and off the bridge —
    /// [`Self::place`] next. With `netns` it is created in that
    /// namespace.
    fn open(bridge_name: &str, vm_index: u32, netns: Option<&str>) -> Result<Self, String> {
        use std::os::fd::IntoRawFd;
        let (tap_name, mac, guest_ip) = tap_identity(bridge_name, vm_index);

        let fd = match netns {
            Some(ns) => crate::spawner::open_tun_in(&netns_path(ns))
                .map_err(|e| format!("open /dev/net/tun in {ns}: {e}"))?
                .into_raw_fd(),
            // SAFETY: valid C string path, valid flags.
            None => unsafe {
                libc::open(
                    c"/dev/net/tun".as_ptr(),
                    libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            },
        };
        if fd < 0 {
            return Err(format!(
                "open /dev/net/tun: {}",
                std::io::Error::last_os_error()
            ));
        }

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

        // Built before placing so its `Drop` (close fd, delete link)
        // cleans up if placing or pinning fails.
        Ok(Self {
            fd,
            name: tap_name,
            mac,
            guest_ip,
            vm_index,
            anti_spoof: None,
            tree_id: None,
            netns: netns.map(str::to_string),
        })
    }

    /// Give each of `taps` its host-side MAC and bring it up — on the
    /// bridge, for TAPs opened in its namespace. One `ip -batch`
    /// however many TAPs.
    fn place(taps: &mut [Self], bridge_name: &str) -> Result<(), String> {
        // TAP MAC must differ from guest MAC to avoid bridge "own source address" drops.
        let tap_mac = |t: &Self| {
            let m = t.mac;
            format!(
                "fe:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                m[1], m[2], m[3], m[4], m[5]
            )
        };
        let netns = taps[0].netns.clone();
        let lines: Vec<String> = taps
            .iter()
            .map(|t| match netns {
                Some(_) => format!(
                    "link set dev {} address {} master {bridge_name} up",
                    t.name,
                    tap_mac(t)
                ),
                None => format!("link set dev {} address {} up", t.name, tap_mac(t)),
            })
            .collect();
        let file = format!("{}-{bridge_name}-t{}", std::process::id(), taps[0].vm_index);
        ip_batch(netns.as_deref(), &file, &lines)?;
        for t in taps.iter() {
            log::info!(
                "TAP {} created: tap_mac={} guest_ip={} netns={netns:?}",
                t.name,
                tap_mac(t),
                t.guest_ip
            );
        }
        Ok(())
    }

    /// Path of the network namespace this TAP was placed in, `None`
    /// when it is in the host namespace (or is a node-broker mirror).
    /// An external VMM must run there to open the TAP by name.
    #[must_use]
    pub fn netns_path(&self) -> Option<PathBuf> {
        self.netns.as_deref().map(netns_path)
    }

    /// `(tree id, index)` of a TAP the node broker holds, which is how
    /// `fc.spawn` names it — that side knows where it was placed.
    #[must_use]
    pub fn broker_ref(&self) -> Option<(String, u32)> {
        self.tree_id.clone().map(|t| (t, self.vm_index))
    }

    /// Adopt a TAP the node broker created: the descriptor came over
    /// `SCM_RIGHTS`, the name, MAC and address came with it, and the
    /// device's privileged lifetime stays on the other side.
    fn adopt(tree_id: &str, info: &crate::broker::TapInfo, fd: std::os::fd::OwnedFd) -> Self {
        use std::os::fd::IntoRawFd;
        Self {
            fd: fd.into_raw_fd(),
            name: info.name.clone(),
            mac: info.mac,
            guest_ip: match info.ip.parse() {
                Ok(ip) => ip,
                Err(e) => crate::broker::protocol_abort(&format!(
                    "the node broker sent {:?} as TAP {}'s address: {e}",
                    info.ip, info.name
                )),
            },
            vm_index: info.vm_index,
            anti_spoof: None,
            tree_id: Some(tree_id.to_string()),
            netns: None,
        }
    }

    /// The mirror of a TAP the node broker holds and a jailed
    /// Firecracker already opened — what a successor VM broker rebuilds
    /// for a re-adopted VM (`K7D_VM_BROKER_RESTART`). No descriptor: the previous VM
    /// broker's copy was closed at `detach_for_vmm`, which is the state
    /// this device is in for the rest of its life. The identity is the
    /// deterministic one [`Self::create_unpinned`] derives from the
    /// bridge and the index, so it names the same kernel device.
    /// Dropping it is still `net.tap_destroy`.
    fn adopt_detached(tree_id: &str, bridge_name: &str, vm_index: u32) -> Self {
        let (name, mac, guest_ip) = tap_identity(bridge_name, vm_index);
        Self {
            fd: -1,
            name,
            mac,
            guest_ip,
            vm_index,
            anti_spoof: None,
            tree_id: Some(tree_id.to_string()),
            netns: None,
        }
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
    /// guest (the fourth safety check).
    ///
    /// Read-only and non-destructive: `poll` with a zero timeout tells
    /// us the bridge has handed the TAP something the VMM has not yet
    /// put in the guest's RX ring, without consuming it. The
    /// guest-to-bridge direction needs no separate check — a frame the
    /// guest handed over shows up as an undrained virtio-net TX queue.
    pub fn has_pending_frame(&self) -> Result<bool, String> {
        if self.fd < 0 {
            return Err(format!(
                "TAP {} was released to an external VMM; k7d has no descriptor to poll",
                self.name
            ));
        }
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

    /// Hand this TAP to an out-of-process VMM.
    ///
    /// Gives the device to `uid`, marks it `IFF_PERSIST` and closes
    /// k7d's descriptor, so Firecracker can claim it by name. All three
    /// are required: a TAP with no owning fd disappears unless it is
    /// persistent; a single-queue TAP that k7d still holds answers a
    /// second `TUNSETIFF` with `EBUSY`; and attaching to a TAP one does
    /// not own needs `CAP_NET_ADMIN`, which is exactly what the jailer
    /// took away. Everything else about the device — its bridge
    /// membership, its MAC/IP anti-spoof pin, and its
    /// deletion by [`Drop`] — is unchanged, which is what lets
    /// [`ClusterNetwork::attach_to_pod_netns`] move it after boot: that
    /// works by interface name, not by descriptor.
    pub fn detach_for_vmm(&mut self, uid: u32) -> Result<(), String> {
        if self.fd < 0 {
            return Ok(());
        }
        if let Some(tree_id) = self.tree_id.clone() {
            // The node broker still holds its own descriptor on this
            // device — which is why it can make it persistent *after*
            // this side lets go, instead of having to `TUNSETIFF` its
            // way back onto a single-queue TAP.
            crate::broker::client::ok(&crate::broker::Verb::NetTapDetach {
                tree_id,
                vm_index: self.vm_index,
                uid,
            })
            .map_err(|e| format!("net.tap_detach({}, {uid}): {e}", self.name))?;
            // SAFETY: fd is valid and owned by this struct; it is marked
            // gone immediately after so nothing closes or polls it twice.
            unsafe { libc::close(self.fd) };
            self.fd = -1;
            return Ok(());
        }
        for (ioctl, label) in [(TUNSETOWNER, "TUNSETOWNER"), (TUNSETGROUP, "TUNSETGROUP")] {
            // SAFETY: `self.fd` is this TAP's own live TUN fd; both
            // ioctls take an integer argument and touch no memory.
            if unsafe { libc::ioctl(self.fd, ioctl, libc::c_ulong::from(uid)) } < 0 {
                return Err(format!(
                    "{label}({uid}) on {}: {}",
                    self.name,
                    std::io::Error::last_os_error()
                ));
            }
        }
        // SAFETY: `self.fd` is this TAP's own live TUN fd; TUNSETPERSIST
        // takes an integer argument and touches no memory.
        if unsafe { libc::ioctl(self.fd, TUNSETPERSIST, 1 as libc::c_ulong) } < 0 {
            return Err(format!(
                "TUNSETPERSIST on {}: {}",
                self.name,
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: fd is valid and owned by this struct; it is marked
        // gone immediately after so nothing closes or polls it twice.
        unsafe { libc::close(self.fd) };
        self.fd = -1;
        log::info!(
            "TAP {} persisted, owned by {uid}:{uid} and released for an external VMM",
            self.name
        );
        Ok(())
    }

    /// Whether k7d still holds this TAP's descriptor. `false` after
    /// [`Self::detach_for_vmm`] — the frame-level helpers
    /// ([`Self::fd`], [`Self::has_pending_frame`]) have no fd to work
    /// with then, and the VMM that does is another process.
    #[must_use]
    pub fn is_owned(&self) -> bool {
        self.fd >= 0
    }

    /// Get the per-bridge VM index that determined this TAP's IP and MAC.
    #[must_use]
    pub fn vm_index(&self) -> u32 {
        self.vm_index
    }
}

/// `(tap name, guest MAC, guest IP)` of the TAP at `vm_index` on
/// `bridge_name`. A pure function of its inputs on purpose: the node
/// broker derives it when it creates the device, and a successor VM
/// broker derives it again to name a device that already exists
/// ([`TapDevice::adopt_detached`]).
///
/// The name is per-bridge so two bridges (source + fork) can host the
/// same `vm_index` without colliding. Linux IFNAMSIZ is 16 bytes
/// (including the NUL); bridge names are `k7-br-{cluster_id[..10]}`, so
/// a 5-char hash of the bridge name + `t{vm_index}` (e.g. `t12ab3t0`)
/// fits and stays unique across bridges.
fn tap_identity(bridge_name: &str, vm_index: u32) -> (String, [u8; 6], Ipv4Addr) {
    let guest_ip = Ipv4Addr::new(
        GUEST_SUBNET_BASE[0],
        GUEST_SUBNET_BASE[1],
        GUEST_SUBNET_BASE[2],
        2 + vm_index as u8,
    );
    let mac = [0xaa, 0xbb, 0x00, 0x00, 0x00, 2 + vm_index as u8];
    let name = format!("t{}t{vm_index}", bridge_short_tag(bridge_name));
    (name, mac, guest_ip)
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
        // 32 KiB of guest RAM: an 8-descriptor table at GPA 0, the avail
        // and used rings after it, and two writable buffers at 0x1000 and
        // 0x2000 that the chain hands the device.
        let span = 32 * 1024;
        let mut mem = vec![0u8; span as usize];
        let descs = [
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
        for (i, d) in descs.iter().enumerate() {
            let at = i * 16;
            mem[at..at + 8].copy_from_slice(&d.addr.to_le_bytes());
            mem[at + 8..at + 12].copy_from_slice(&d.len.to_le_bytes());
            mem[at + 12..at + 14].copy_from_slice(&d.flags.to_le_bytes());
            mem[at + 14..at + 16].copy_from_slice(&d.next.to_le_bytes());
        }
        let q = crate::virtio_mmio::VirtqueueState {
            max_size: 8,
            size: 8,
            ready: true,
            desc_addr: vm_memory::GuestAddress(0),
            avail_addr: vm_memory::GuestAddress(0x80),
            used_addr: vm_memory::GuestAddress(0x200),
        };
        let vq = crate::virtio_mmio::ValidatedQueue::new(&q, mem.as_ptr() as u64, span)
            .expect("geometry");
        let mut chain = Vec::new();
        assert_eq!(
            super::desc_chain_writable_len(&vq, 0, &mut chain).expect("walk"),
            3072
        );
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
        if self.fd >= 0 {
            // SAFETY: fd is valid; closing TAP device.
            unsafe { libc::close(self.fd) };
        }
        if let Some(tree_id) = &self.tree_id {
            // Also the only thing that removes a TAP handed to a jailed
            // Firecracker: `detach_for_vmm` made it `IFF_PERSIST`, so
            // closing the descriptor above does not take the link down.
            if let Err(e) = crate::broker::client::ok(&crate::broker::Verb::NetTapDestroy {
                tree_id: tree_id.clone(),
                vm_index: self.vm_index,
            }) {
                log::error!("net.tap_destroy({}): {e}", self.name);
            }
            return;
        }
        // `ip link delete` removes the device whether or not it was
        // marked persistent for an external VMM. A namespace already
        // deleted took the device with it.
        let mut args = vec!["link", "delete", self.name.as_str()];
        if let Some(ns) = &self.netns {
            args.splice(0..0, ["-n", ns.as_str()]);
        }
        let _ = crate::spawner::command("ip").args(&args).output();
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
    /// This bridge's nftables jail. `None` only when
    /// `K7D_NET_JAIL=off`. Dropping it deletes the table, which is why
    /// it is a field rather than a side effect of `create`.
    jail: Option<crate::netjail::TreeNetJail>,
    /// This tree's egress posture. Forks inherit it via
    /// [`ClusterNetwork::fork_from`]; suspend/resume persists it in
    /// `cluster.json`.
    egress: crate::netjail::EgressPolicy,
    /// The host default-route interface the jail was installed
    /// against — kept so [`ClusterNetwork::set_egress`] can re-render
    /// without re-detecting a possibly-changed route mid-flight. Empty
    /// under privilege separation: the jail lives on the node broker's
    /// side, and so does the route detection it needs.
    default_iface: String,
    /// Tree id, when this object is the VM broker's **mirror** of a
    /// bridge the node broker owns.
    ///
    /// The mirror is not a thin handle: it keeps the same `entries`,
    /// the same allocator and the same derived names as the real thing,
    /// because every mutation of it is a verb and the two therefore
    /// cannot drift. What it does not keep is the part that needs
    /// `CAP_NET_ADMIN` — the `jail` guard and the `ip`/`nft`/`nsenter`
    /// calls, which are the other side's.
    tree_id: Option<String>,
    /// This network's uplink slot once its namespace is built — the
    /// first placed TAP builds it ([`Self::materialize`]). `None` for a
    /// mirror and for a network only pod-attached TAPs ever used.
    uplink: Option<Uplink>,
    /// Whether new TAPs go onto the bridge in the network's namespace
    /// (`true`) or stay unplaced in the host for a pod attach to move.
    place_taps: bool,
}

/// Guest-facing range every network reuses; its gateway is the host.
const GUEST_SUBNET: &str = "10.200.0.0/24";

/// Where each network's uplink `/30` comes from (RFC 2544 benchmarking
/// space: not used by k3s, flannel, Cilium or the nodes). One slot per
/// live network; host end `.1`, namespace end `.2` of the slot.
pub const UPLINK_RANGE: &str = "198.18.0.0/15";
const UPLINK_BASE: u32 = u32::from_be_bytes([198, 18, 0, 0]);
const UPLINK_SLOTS: u32 = 1 << 15;
/// Namespace end of the uplink veth. The host end is named like the
/// bridge, so everything on the host keyed on `k7-br-*` keeps working.
const UPLINK_PEER: &str = "k7-up";
/// Pinned bridge MAC: guests cache the gateway's MAC, and a fork's
/// guest must find the same one on its new bridge.
const BRIDGE_MAC: &str = "aa:bb:00:00:00:01";
const NETNS_DIR: &str = "/run/netns";
/// Serialises uplink allocation across processes (daemon, node broker,
/// in-process tests).
const NETNS_LOCK: &str = "/run/k7d-netns.lock";
const NSFS_MAGIC: i64 = 0x6e73_6673;

/// `/run/netns/<name>`.
#[must_use]
pub fn netns_path(name: &str) -> PathBuf {
    Path::new(NETNS_DIR).join(name)
}

#[derive(Debug, Clone, Copy)]
struct Uplink {
    slot: u32,
}

impl Uplink {
    fn host(self) -> Ipv4Addr {
        Ipv4Addr::from(UPLINK_BASE + 4 * self.slot + 1)
    }
    fn peer(self) -> Ipv4Addr {
        Ipv4Addr::from(UPLINK_BASE + 4 * self.slot + 2)
    }
}

/// Lowest uplink slot no host address claims. Callers hold
/// [`NETNS_LOCK`] until the slot's address is on a link.
fn allocate_uplink() -> Result<Uplink, String> {
    let mut used = std::collections::HashSet::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `head` with a list freed below.
    if unsafe { libc::getifaddrs(&raw mut head) } != 0 {
        return Err(format!("getifaddrs: {}", std::io::Error::last_os_error()));
    }
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a node of the list getifaddrs returned.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: a non-null ifa_addr points at a sockaddr.
        let family = unsafe { (*ifa.ifa_addr).sa_family };
        if i32::from(family) != libc::AF_INET {
            continue;
        }
        // SAFETY: as above; unaligned, only sockaddr's alignment is promised.
        let sin = unsafe { ifa.ifa_addr.cast::<libc::sockaddr_in>().read_unaligned() };
        let a = u32::from_be(sin.sin_addr.s_addr);
        if a.wrapping_sub(UPLINK_BASE) < 4 * UPLINK_SLOTS {
            used.insert((a - UPLINK_BASE) / 4);
        }
    }
    // SAFETY: `head` came from getifaddrs and is freed once.
    unsafe { libc::freeifaddrs(head) };
    (0..UPLINK_SLOTS)
        .find(|s| !used.contains(s))
        .map(|slot| Uplink { slot })
        .ok_or_else(|| {
            format!("every uplink /30 in {UPLINK_RANGE} is in use ({UPLINK_SLOTS} live networks)")
        })
}

/// The inside of network `ns`'s namespace: bridge, uplink end, routes,
/// proxy-ARP for the gateway and the SNAT to the uplink address.
fn build_inside(ns: &str, uplink: Uplink) -> Result<(), String> {
    let (u1, u2) = (uplink.host().to_string(), uplink.peer().to_string());
    let gw = Ipv4Addr::from(GUEST_GATEWAY).to_string();
    ip_batch(
        Some(ns),
        &format!("{ns}-in"),
        &[
            "link set dev lo up".into(),
            // Bridged guest↔guest frames are pure L2: no conntrack or
            // IP hooks in this namespace (CHALLENGES #117 was the host's
            // flannel SNAT seeing them).
            format!(
                "link add {ns} address {BRIDGE_MAC} type bridge \
                 nf_call_iptables 0 nf_call_ip6tables 0 nf_call_arptables 0"
            ),
            format!("link set dev {ns} up"),
            format!("addr add {u2}/30 dev {UPLINK_PEER}"),
            format!("link set dev {UPLINK_PEER} up"),
            format!("route add {GUEST_SUBNET} dev {ns}"),
            format!("route add {gw}/32 via {u1} dev {UPLINK_PEER}"),
            format!("route add default via {u1} dev {UPLINK_PEER}"),
        ],
    )?;
    let enter = format!("--net={}", netns_path(ns).display());
    // One process for the sysctls and the SNAT (`/proc/sys/net` is the
    // writer's namespace's). The bridge answers ARP for the gateway
    // (routed up the uplink), at once.
    let nat = format!(
        "add table ip k7nat; \
         add chain ip k7nat post {{ type nat hook postrouting priority srcnat; }}; \
         add rule ip k7nat post oifname \"{UPLINK_PEER}\" ip saddr {GUEST_SUBNET} snat to {u2}"
    );
    run_cmd(
        "nsenter",
        &[
            &enter,
            "sh",
            "-ec",
            "s=/proc/sys/net/ipv4; echo 1 >$s/ip_forward; echo 0 >$s/conf/all/rp_filter; \
             echo 0 >$s/conf/$1/rp_filter; echo 1 >$s/conf/$1/proxy_arp; \
             echo 0 >$s/neigh/$1/proxy_delay; exec nft \"$2\"",
            "sh",
            ns,
            &nat,
        ],
    )?;
    Ok(())
}

struct NetnsLock {
    _file: std::fs::File,
}

impl NetnsLock {
    fn acquire() -> Result<Self, String> {
        use std::os::fd::AsRawFd;
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(NETNS_LOCK)
            .map_err(|e| format!("open {NETNS_LOCK}: {e}"))?;
        // SAFETY: `f` is an open file; flock takes no pointers.
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(format!(
                "flock {NETNS_LOCK}: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self { _file: f })
    }
}

/// Whether `path` is a mounted network namespace (not just the empty
/// file `ip netns add` leaves behind once the mount is gone).
#[must_use]
pub fn is_mounted_netns(path: &Path) -> bool {
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) else {
        return false;
    };
    // SAFETY: zeroed statfs is a valid out-buffer; `c` is NUL-terminated.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    let rc = unsafe { libc::statfs(c.as_ptr(), &raw mut st) };
    #[allow(clippy::unnecessary_cast)]
    let magic = st.f_type as i64;
    rc == 0 && magic == NSFS_MAGIC
}

/// Remove `/run/netns/k7-br-*` files that no longer name a namespace.
///
/// k7d runs in a private mount namespace (`ProtectSystem=strict`), so
/// the bind mount behind each of its network namespaces dies with the
/// process and the kernel frees the namespace — but the empty file
/// stays in `/run/netns`, and `ip netns add` refuses that name until it
/// is gone. A file whose host uplink still exists belongs to a live
/// network in another mount namespace and is left alone. Returns the
/// names removed.
#[must_use]
pub fn reap_stale_netns_files() -> Vec<String> {
    let Ok(dir) = std::fs::read_dir(NETNS_DIR) else {
        return Vec::new();
    };
    let mut removed = Vec::new();
    for entry in dir.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with("k7-br-") || Path::new("/sys/class/net").join(&name).exists() {
            continue;
        }
        if is_mounted_netns(&entry.path()) {
            continue;
        }
        match std::fs::remove_file(entry.path()) {
            Ok(()) => removed.push(name),
            Err(e) => log::error!("remove stale {}: {e}", entry.path().display()),
        }
    }
    removed
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

    /// [`ClusterNetwork::create`] with an explicit egress policy.
    /// `create` delegates here with the `Open` default,
    /// which is byte-identical to legacy behaviour.
    pub fn create_with_egress(
        cluster_id: &str,
        egress: crate::netjail::EgressPolicy,
    ) -> Result<Self, String> {
        // IFNAMSIZ is 16 (15 chars + NUL). Reserve 6 for the `k7-br-`
        // prefix and cap the cluster suffix at 9 chars.
        const MAX_SUFFIX: usize = 9;
        if crate::broker::client::is_split() {
            // The node broker runs this same function on its side and
            // sends back the name it derived, so the truncation and
            // hashing below stay in one place rather than two that have
            // to agree.
            let bridge_name = crate::broker::client::net_tree_create(cluster_id, &egress)
                .map_err(|e| format!("net.tree_create({cluster_id}): {e}"))?;
            return Ok(Self {
                bridge_name,
                subnet_base: GUEST_SUBNET_BASE,
                next_vm_index: 0,
                entries: HashMap::new(),
                jail: None,
                egress,
                default_iface: String::new(),
                tree_id: Some(cluster_id.to_string()),
                uplink: None,
                place_taps: true,
            });
        }
        // To keep distinct cluster IDs mapping to distinct bridges even
        // after truncation, mix in a short FNV-1a hash for IDs that
        // exceed the budget. The name is also a token in `ip -batch`
        // lines, so anything outside `[A-Za-z0-9._-]` is hashed too.
        let safe = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
        let suffix = if cluster_id.len() <= MAX_SUFFIX && cluster_id.chars().all(safe) {
            cluster_id.to_string()
        } else {
            // 3-char prefix from the cluster_id + 5-char hash, joined by `-`.
            let h = bridge_short_tag(cluster_id);
            let prefix: String = cluster_id
                .chars()
                .take(3)
                .map(|c| if safe(c) { c } else { '-' })
                .collect();
            format!("{prefix}-{}", &h[..5])
        };
        let bridge_name = format!("k7-br-{suffix}");
        // Nothing touches the host until a TAP is placed (the
        // per-network netns spec): a network whose TAPs all go to pods
        // never needs a namespace.
        egress.validate()?;
        Ok(Self {
            bridge_name,
            subnet_base: GUEST_SUBNET_BASE,
            next_vm_index: 0,
            entries: HashMap::new(),
            jail: None,
            egress,
            default_iface: String::new(),
            tree_id: None,
            uplink: None,
            place_taps: true,
        })
    }

    /// Whether this network's namespace, uplink and jail exist yet.
    #[must_use]
    pub fn is_materialized(&self) -> bool {
        self.uplink.is_some()
    }

    /// Choose whether TAPs created from now on are placed on the bridge
    /// (the default) or left in the host for a pod attach to move.
    pub fn set_place_taps(&mut self, place: bool) {
        self.place_taps = place;
    }

    /// Build this network's namespace, if it does not exist yet:
    ///
    /// ```text
    /// netns <bridge>:  bridge <bridge> (no address, proxy-ARP 10.200.0.1)
    ///                  10.200.0.1/32 + default via U1, SNAT guests → U2
    ///                  k7-up U2/30
    ///                    │ veth
    /// host:            <bridge> U1/30 + 10.200.0.1/32, jail, MASQUERADE
    /// ```
    ///
    /// Every network reuses 10.200.0.0/24 (a fork's guests keep their
    /// addresses), so it cannot be routed in the host namespace — two
    /// live copies would share one FIB entry (CHALLENGES #283). Here the
    /// host only ever sees each network's own uplink address.
    ///
    /// The first placed TAP calls this; call it directly to bring the
    /// gateway address up before any guest exists (a host service that
    /// binds `10.200.0.1`). Not on a node-broker mirror.
    pub fn materialize(&mut self) -> Result<(), String> {
        if self.uplink.is_some() {
            return Ok(());
        }
        if let Some(tree_id) = &self.tree_id {
            return Err(format!(
                "materialize on tree {tree_id}: the node broker owns this network"
            ));
        }
        let ns = self.bridge_name.clone();
        let _lock = NetnsLock::acquire()?;
        if Path::new("/sys/class/net").join(&ns).exists() {
            return Err(format!(
                "host link {ns} already exists — another live network has this name"
            ));
        }
        let path = netns_path(&ns);
        if path.exists() {
            if is_mounted_netns(&path) {
                return Err(format!(
                    "{} is a live network namespace with no host uplink — a crashed                      user's leftover (cleanup_stale_k7_bridges removes it)",
                    path.display()
                ));
            }
            std::fs::remove_file(&path)
                .map_err(|e| format!("remove stale {}: {e}", path.display()))?;
        }
        let uplink = allocate_uplink()?;
        self.uplink = Some(uplink);
        if let Err(e) = self.build_namespace(uplink) {
            self.teardown();
            self.jail = None;
            self.uplink = None;
            return Err(format!("network {ns}: {e}"));
        }
        Ok(())
    }

    fn build_namespace(&mut self, uplink: Uplink) -> Result<(), String> {
        let ns = self.bridge_name.clone();
        let ns = ns.as_str();
        let (u1, u2) = (uplink.host().to_string(), uplink.peer().to_string());
        let gw = Ipv4Addr::from(GUEST_GATEWAY).to_string();
        ip_batch(
            None,
            &format!("{ns}-host"),
            &[
                format!("netns add {ns}"),
                format!("link add {ns} type veth peer name {UPLINK_PEER} netns {ns}"),
                format!("addr add {u1}/30 dev {ns}"),
                format!("addr add {gw}/32 dev {ns}"),
                format!("link set dev {ns} up"),
                // The host's own way in — `curl --interface <bridge>`
                // and the like; guest traffic never uses it, it
                // arrives SNATed to U2. `append`: every live network
                // adds one for the same prefix.
                format!("route append {GUEST_SUBNET} via {u2} dev {ns} src {gw}"),
            ],
        )?;
        std::fs::write(format!("/proc/sys/net/ipv4/conf/{ns}/rp_filter"), "0")
            .map_err(|e| format!("clear {ns} rp_filter: {e}"))?;

        build_inside(ns, uplink)?;

        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")
            .map_err(|e| format!("enable ip_forward: {e}"))?;
        std::fs::write("/proc/sys/net/ipv4/conf/all/rp_filter", "0")
            .map_err(|e| format!("clear all rp_filter: {e}"))?;
        let default_iface = default_route_iface()?;
        assert_no_leftover_shaping(&default_iface)?;
        install_bridge_forward_rules(ns)?;
        ensure_iptables(
            Some("nat"),
            &[
                "POSTROUTING",
                "-s",
                UPLINK_RANGE,
                "-o",
                &default_iface,
                "-j",
                "MASQUERADE",
            ],
        )?;
        // The FORWARD ACCEPTs above make this uplink reachable from
        // every other `k7-br-*` on the node. The jail (evaluated one
        // priority ahead of them) is what stops one tree from routing
        // into another's, and owns the egress and guest→host input
        // decisions — see `crate::netjail`.
        self.jail = crate::netjail::TreeNetJail::install(
            ns,
            &crate::netjail::JailIfaces::detect(&default_iface),
            &self.egress,
        )?;
        self.default_iface = default_iface;
        log::info!(
            "network {ns}: namespace up, uplink {u1}/30 <-> {u2}/30 via {}",
            self.default_iface
        );
        Ok(())
    }

    /// Undo [`Self::materialize`], tolerating whatever part of it never
    /// happened. The host end goes first: deleting it kills the pair at
    /// once, so the name and the uplink slot are free even while a VMM
    /// still pins the namespace.
    fn teardown(&self) {
        let ns = self.bridge_name.clone();
        if let Some(jail) = &self.jail {
            if let Err(e) = jail.remove() {
                log::error!("remove net jail for {ns}: {e}");
            }
        }
        remove_bridge_forward_rules(&ns);
        let _ = crate::netns::run_capture("ip", &["link", "delete", &ns]);
        let _ = crate::netns::run_capture("ip", &["netns", "delete", &ns]);
        if !any_other_k7_bridge_exists(&ns) {
            drop_shared_masquerade();
        }
    }

    /// This tree's egress policy.
    #[must_use]
    pub fn egress(&self) -> &crate::netjail::EgressPolicy {
        &self.egress
    }

    /// Replace this bridge's egress policy, atomically re-installing
    /// the jail ruleset (`tree_adopt_cluster` may adopt a
    /// bridge born `Open` into a tree with a stricter posture). When
    /// `K7D_NET_JAIL=off` the policy is recorded but nothing is
    /// enforced — same contract as `create`.
    pub fn set_egress(&mut self, egress: crate::netjail::EgressPolicy) -> Result<(), String> {
        egress.validate()?;
        if let Some(tree_id) = &self.tree_id {
            // `net.tree_create` is an upsert, which is exactly this.
            crate::broker::client::net_tree_create(tree_id, &egress)
                .map_err(|e| format!("net.tree_create({tree_id}) re-policy: {e}"))?;
            self.egress = egress;
            return Ok(());
        }
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

    /// Take over the identity slot of a TAP the node broker already
    /// holds for `vm_index` on this (mirrored) bridge, for a re-adopted
    /// VM (`K7D_VM_BROKER_RESTART`). Nothing is created: the device exists and a
    /// jailed Firecracker is reading from it. Only meaningful on a
    /// mirror; an un-split process has no node broker holding TAPs
    /// for it.
    pub fn adopt_tap(&mut self, vm_index: u32) -> Result<TapDevice, String> {
        let Some(tree_id) = self.tree_id.clone() else {
            return Err(format!(
                "adopt_tap({vm_index}) on bridge {}: not a node-broker mirror",
                self.bridge_name
            ));
        };
        if self.entries.contains_key(&vm_index) {
            return Err(format!(
                "vm_index {vm_index} already allocated on bridge {}",
                self.bridge_name
            ));
        }
        if vm_index >= self.next_vm_index {
            self.next_vm_index = vm_index + 1;
        }
        let tap = TapDevice::adopt_detached(&tree_id, &self.bridge_name, vm_index);
        self.register_tap_entry(&tap);
        Ok(tap)
    }

    fn create_tap_at_index(&mut self, vm_index: u32) -> Result<TapDevice, String> {
        let tap = if let Some(tree_id) = self.tree_id.clone() {
            Self::taps_from_broker(&tree_id, &[vm_index], self.place_taps)?
                .pop()
                .expect("one index asked for, one TAP checked back")
        } else {
            let ns = self.placement()?;
            TapDevice::create(&self.bridge_name, vm_index, ns.as_deref())?
        };
        self.register_tap_entry(&tap);
        Ok(tap)
    }

    /// Ask the node broker for one TAP per index and adopt the
    /// descriptors it sends back.
    ///
    /// The anti-spoof pin is *not* installed here in split mode: the
    /// node broker pins the whole batch in the single `nft` transaction
    /// [`Self::add_taps_at`] relies on, on the side that has the
    /// `CAP_NET_ADMIN` for it.
    fn taps_from_broker(
        tree_id: &str,
        indices: &[u32],
        place: bool,
    ) -> Result<Vec<TapDevice>, String> {
        let made = crate::broker::client::net_tap_create(tree_id, indices, place)
            .map_err(|e| format!("net.tap_create({tree_id}, {indices:?}): {e}"))?;
        Ok(made
            .into_iter()
            .map(|(info, fd)| TapDevice::adopt(tree_id, &info, fd))
            .collect())
    }

    /// The namespace new TAPs go into — built on first use — or `None`
    /// when they stay in the host for a pod attach.
    fn placement(&mut self) -> Result<Option<String>, String> {
        if !self.place_taps {
            return Ok(None);
        }
        self.materialize()?;
        Ok(Some(self.bridge_name.clone()))
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
    /// 50-cluster fork budget honest. Returns the TAPs in
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
        if let Some(tree_id) = self.tree_id.clone() {
            let taps = Self::taps_from_broker(&tree_id, indices, self.place_taps)?;
            for &idx in indices {
                if idx >= self.next_vm_index {
                    self.next_vm_index = idx + 1;
                }
            }
            for tap in &taps {
                self.register_tap_entry(tap);
            }
            return Ok(taps);
        }
        let ns = self.placement()?;
        let mut taps = Vec::with_capacity(indices.len());
        for &idx in indices {
            taps.push(TapDevice::open(&self.bridge_name, idx, ns.as_deref())?);
            if idx >= self.next_vm_index {
                self.next_vm_index = idx + 1;
            }
        }
        if !taps.is_empty() {
            TapDevice::place(&mut taps, &self.bridge_name)?;
        }
        let specs: Vec<(String, [u8; 6], Ipv4Addr)> = taps
            .iter()
            .map(|t| (t.name().to_string(), t.mac(), t.guest_ip()))
            .collect();
        let ns_path = ns.as_deref().map(netns_path);
        if let Some(guards) =
            crate::netjail::TapAntiSpoof::install_batch(&specs, ns_path.as_deref())?
        {
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
        // Fork inherits the source's egress posture: a
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
        if self.tree_id.is_some() {
            return self.pod_verb(vm_index, pod_netns, pod_ip, false);
        }
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
        // CRI port-forward (`kubectl port-forward`) dials 127.0.0.1:<port>
        // from inside the pod netns, where nothing listens: the workload
        // is in the guest. Send loopback TCP to the guest too. A
        // 127.0.0.0/8 source may only leave `lo` with route_localnet
        // (this netns only), and it is masqueraded so the guest's reply
        // has a route back.
        run_cmd(
            "nsenter",
            &[
                &nsenter,
                "sysctl",
                "-q",
                "-w",
                "net.ipv4.conf.all.route_localnet=1",
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
                "OUTPUT",
                "-d",
                "127.0.0.1",
                "-p",
                "tcp",
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
                "127.0.0.0/8",
                "-d",
                &guest_ip,
                "-j",
                "MASQUERADE",
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
        if self.tree_id.is_some() {
            return self.pod_verb(vm_index, pod_netns, pod_ip, true);
        }
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
    pub fn detach_from_pod_netns(&self, vm_index: u32, pod_netns: &Path) -> Result<(), String> {
        if let Some(tree_id) = &self.tree_id {
            // Best-effort on both sides: a failed detach is logged by
            // the node broker and is not something this caller — which
            // is already tearing the pod down — can act on.
            if let Err(e) = crate::broker::client::ok(&crate::broker::Verb::NetPodDetach {
                tree_id: tree_id.clone(),
                vm_index,
                netns: netns_arg(pod_netns),
            }) {
                log::warn!("net.pod_detach({tree_id}[{vm_index}]): {e}");
            }
            return Ok(());
        }
        // Best-effort; pod netns is usually gone already.
        let _ = crate::netns::delete_bridge_in_netns(pod_netns, "k7-podbr0");
        Ok(())
    }

    /// The split-mode body of [`Self::attach_to_pod_netns`] and
    /// [`Self::install_pod_nat`]: one verb, then the same bookkeeping
    /// the privileged version does, so `entry()` answers the same on
    /// both sides of the boundary.
    fn pod_verb(
        &mut self,
        vm_index: u32,
        pod_netns: &Path,
        pod_ip: Ipv4Addr,
        move_link: bool,
    ) -> Result<(), String> {
        let tree_id = self.tree_id.clone().expect("split mode");
        let netns = netns_arg(pod_netns);
        let ip = pod_ip.to_string();
        let verb = if move_link {
            crate::broker::Verb::NetPodAttach {
                tree_id: tree_id.clone(),
                vm_index,
                netns,
                pod_ip: ip,
            }
        } else {
            crate::broker::Verb::NetPodNat {
                tree_id: tree_id.clone(),
                vm_index,
                netns,
                pod_ip: ip,
            }
        };
        crate::broker::client::ok(&verb)
            .map_err(|e| format!("{verb:?} on {tree_id}[{vm_index}]: {e}"))?;
        self.record_pod(vm_index, pod_ip, pod_netns)
    }

    /// Mirror what the node broker just recorded about a pod hand-off.
    fn record_pod(
        &mut self,
        vm_index: u32,
        pod_ip: Ipv4Addr,
        pod_netns: &Path,
    ) -> Result<(), String> {
        let entry = self
            .entries
            .get_mut(&vm_index)
            .ok_or_else(|| format!("vm_index {vm_index} not allocated"))?;
        entry.pod_ip = Some(pod_ip);
        entry.pod_netns = Some(pod_netns.to_path_buf());
        Ok(())
    }

    /// Destroy the network: jail, host rules, uplink, namespace (with
    /// the bridge, its TAPs and its NAT inside), and the shared
    /// MASQUERADE once no other network is left. Idempotent.
    pub fn destroy(&self) -> Result<(), String> {
        if let Some(tree_id) = &self.tree_id {
            return crate::broker::client::ok(&crate::broker::Verb::NetTreeDestroy {
                tree_id: tree_id.clone(),
            })
            .map_err(|e| format!("net.tree_destroy({tree_id}): {e}"));
        }
        if self.uplink.is_some() {
            self.teardown();
        }
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

/// Remove the host MASQUERADE every network's uplink shares, and the
/// pre-netns `10.200.0.0/24` one (looping drains duplicates).
fn drop_shared_masquerade() {
    let Ok(iface) = default_route_iface() else {
        return;
    };
    for src in [UPLINK_RANGE, GUEST_SUBNET] {
        while delete_iptables(
            Some("nat"),
            &["POSTROUTING", "-s", src, "-o", &iface, "-j", "MASQUERADE"],
        )
        .is_ok()
        {}
    }
}

/// Whether any `k7-br-*` link other than `exclude` exists on the host.
/// Used by `destroy()` to decide if the shared MASQUERADE rule can go.
fn any_other_k7_bridge_exists(exclude: &str) -> bool {
    list_k7_bridges().into_iter().any(|n| n != exclude)
}

/// Enumerate `k7-br-*` links currently on the host.
fn list_k7_bridges() -> Vec<String> {
    let out = crate::spawner::command("ip")
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

/// Route guest podCIDR / `ClusterIP` prefixes between the guests of
/// network `bridge`, inside its namespace (the per-network netns spec).
///
/// The namespace holds nothing but that network, so the routes go in
/// its main table; the host's tables — and host k3s (`cni0`,
/// `10.42/16`, CHALLENGES.md #117) — are never touched. Fails loud when
/// the network has no namespace yet (no TAP placed on it).
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
    if !is_mounted_netns(&netns_path(bridge)) {
        return Err(format!(
            "install_guest_overlay_routes: network {bridge} has no namespace ({})",
            netns_path(bridge).display()
        ));
    }
    for (prefix, via) in routes {
        if prefix.is_empty() || via.is_empty() {
            return Err(format!("empty overlay route prefix={prefix:?} via={via:?}"));
        }
        run_cmd(
            "ip",
            &[
                "-n", bridge, "route", "replace", prefix, "via", via, "dev", bridge,
            ],
        )?;
    }
    Ok(())
}

/// Drop host policy rules and table-200 routes that name `bridge` —
/// what overlay routes were before they moved into the network's
/// namespace — including the pre-#121 prefixes (`10.42/16`,
/// `10.43/16`), so long-lived nodes come clean.
fn remove_guest_overlay_routes(bridge: &str) {
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

fn delete_ip_rule(pref: u32, spec: &[&str]) -> Result<(), String> {
    let pref_s = pref.to_string();
    let mut args = Vec::with_capacity(spec.len() + 4);
    args.extend_from_slice(&["rule", "del", "pref", pref_s.as_str()]);
    args.extend_from_slice(spec);
    run_cmd("ip", &args)
}

/// Sweep every `k7-br-*` network from the host: uplinks (and legacy
/// host bridges), their namespaces, rules, jails and the shared
/// MASQUERADE. Best-effort, idempotent.
///
/// This is **test-setup hygiene** — production k7d never needs it because
/// [`ClusterNetwork::Drop`] already runs `destroy()` on scope exit. The
/// problem is integration tests that panic / are killed / segfault before
/// `Drop` can run: their namespace stays mounted in the host's mount
/// namespace (unlike the daemon's, which dies with it) and its uplink
/// keeps its slot and its name, so the next network of that name fails
/// to build.
///
/// Calling this at the start of an integration test guarantees the test
/// gets a clean L2/L3 substrate regardless of what prior tests left
/// behind. Tests that don't touch [`ClusterNetwork`] don't need to call
/// it; tests that do should treat it as the equivalent of
/// `ensure_shim_installed()` in `test_shim.rs` — call once, idempotent.
///
/// Returns the names of the networks that were swept (informational;
/// the caller may want to log them). Not `#[must_use]` — tests typically
/// fire-and-forget with `let _ = cleanup_stale_k7_bridges();`.
#[allow(clippy::must_use_candidate)]
pub fn cleanup_stale_k7_bridges() -> Vec<String> {
    let mut swept = list_k7_bridges();
    for link in &swept {
        remove_bridge_forward_rules(link);
        remove_guest_overlay_routes(link);
        let _ = crate::netns::run_capture("ip", &["link", "delete", link]);
    }
    if let Ok(dir) = std::fs::read_dir(NETNS_DIR) {
        for entry in dir.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("k7-br-") {
                let _ = crate::netns::run_capture("ip", &["netns", "delete", &name]);
                if !swept.contains(&name) {
                    swept.push(name);
                }
            }
        }
    }
    purge_main_table_guest_via_routes();
    let _ = restore_host_cni_connected_route();
    drop_shared_masquerade();
    let _ = crate::netjail::clean_stale_jails();
    swept
}

impl Drop for ClusterNetwork {
    fn drop(&mut self) {
        let _ = self.destroy();
    }
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
    let out = crate::spawner::command("ip")
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
    // owns the guest→host decision — an unconditional
    // iptables `INPUT -i <bridge> -j ACCEPT` here would sit AFTER the
    // jail (which is fine) but also document a hole that no longer
    // exists. Drain any copy a legacy daemon left behind so long-lived
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

/// A network-namespace path as a `net.pod_*` parameter.
///
/// Lossy, and safe to be: the node broker re-resolves the string against
/// the §5 netns allowlist with `RESOLVE_NO_SYMLINKS` and an `fstatfs`
/// that must say `NSFS_MAGIC` before it hands it to `nsenter`, so a byte
/// this side mangles is a refusal there rather than a namespace the VM
/// broker talked the node broker into entering.
fn netns_arg(pod_netns: &Path) -> String {
    pod_netns.to_string_lossy().into_owned()
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

/// Run `lines` as one `ip [-n netns] -batch` — one process instead of
/// one per command, which is most of a network's bring-up time on the
/// warm fork path. `file` names the batch under `/run/k7d` and must be
/// unique among concurrent callers.
fn ip_batch(netns: Option<&str>, file: &str, lines: &[String]) -> Result<(), String> {
    let path = PathBuf::from("/run/k7d").join(format!("{file}.ip"));
    std::fs::create_dir_all("/run/k7d").map_err(|e| format!("create /run/k7d: {e}"))?;
    std::fs::write(&path, lines.join("\n") + "\n")
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    let p = path.to_string_lossy();
    let result = match netns {
        Some(ns) => run_cmd("ip", &["-n", ns, "-batch", &p]),
        None => run_cmd("ip", &["-batch", &p]),
    };
    let _ = std::fs::remove_file(&path);
    result.map_err(|e| format!("{e}\nbatch:\n{}", lines.join("\n")))
}

// --- Virtio-net config space ---
