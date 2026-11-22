//! Virtio transport layer: the device status machine, queue validation
//! and the virtio-MMIO register decode (virtio 1.x, non-legacy).
//!
//! [`MmioDevice`] is the transport-neutral core every backend sits
//! behind. It decodes virtio-mmio itself; a device placed on the PCI
//! bus ([`Transport::Pci`]) carries a [`VirtioPciFunction`] and is
//! decoded by the virtio-pci methods in [`crate::pci`] against the same
//! core.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kvm_ioctls::VmFd;
use serde::{Deserialize, Serialize};
use vm_memory::{Address, GuestAddress};
use vmm_sys_util::eventfd::EventFd;

pub use crate::pci::Transport;
use crate::pci::{PciBus, PciFunctionState, VirtioPciFunction};

// Virtio-MMIO register offsets (all 32-bit, little-endian)
const MMIO_MAGIC: u64 = 0x000;
const MMIO_VERSION: u64 = 0x004;
const MMIO_DEVICE_ID: u64 = 0x008;
const MMIO_DEVICE_FEATURES: u64 = 0x010;
const MMIO_DEVICE_FEATURES_SEL: u64 = 0x014;
const MMIO_DRIVER_FEATURES: u64 = 0x020;
const MMIO_DRIVER_FEATURES_SEL: u64 = 0x024;
const MMIO_QUEUE_SEL: u64 = 0x030;
const MMIO_QUEUE_NUM_MAX: u64 = 0x034;
const MMIO_QUEUE_NUM: u64 = 0x038;
const MMIO_QUEUE_READY: u64 = 0x044;
const MMIO_QUEUE_NOTIFY: u64 = 0x050;
const MMIO_INTERRUPT_STATUS: u64 = 0x060;
const MMIO_INTERRUPT_ACK: u64 = 0x064;
const MMIO_STATUS: u64 = 0x070;
const MMIO_QUEUE_DESC_LOW: u64 = 0x080;
const MMIO_QUEUE_DESC_HIGH: u64 = 0x084;
const MMIO_QUEUE_AVAIL_LOW: u64 = 0x090;
const MMIO_QUEUE_AVAIL_HIGH: u64 = 0x094;
const MMIO_QUEUE_USED_LOW: u64 = 0x0a0;
const MMIO_QUEUE_USED_HIGH: u64 = 0x0a4;
const MMIO_CONFIG_GENERATION: u64 = 0x0fc;

const MAGIC_VALUE: u32 = 0x7472_6976; // "virt"
const MMIO_VERSION_2: u32 = 2;

// Device status bits
const _STATUS_ACKNOWLEDGE: u32 = 1;
const STATUS_DRIVER: u32 = 2;
const STATUS_DRIVER_OK: u32 = 4;
const STATUS_FEATURES_OK: u32 = 8;
const STATUS_FAILED: u32 = 128;

// Interrupt status bits
pub(crate) const INT_VRING: u32 = 0x01;
const INT_CONFIG: u32 = 0x02;

/// `VIRTIO_F_VERSION_1` — bit 32 in the feature bitmap (word 1, bit 0).
const VIRTIO_F_VERSION_1: u64 = 1 << 32;

/// Per-device MMIO region size.
pub const MMIO_DEVICE_SIZE: u64 = 0x1000;

/// Virtio device-type ID for `virtio-vsock`. The only vhost device whose
/// rings live in guest memory this process maps, hence the only one whose
/// kernel-side DMA has to be reported to the warm-fork dirty delta by hand.
pub const VIRTIO_ID_VSOCK: u32 = 19;

/// Virtio device-type ID for `virtio-net`. Only its queue *direction*
/// matters here — see [`queue_is_driver_filled`].
pub const VIRTIO_ID_NET: u32 = 1;

/// How often a backend's `wait_quiescent` re-reads its worker's `parked`
/// flag while `Vm::pause` waits for it.
///
/// It is the *floor* on a pause, not a timeout: `set_paused` kicks the
/// worker's eventfd, so the worker leaves its 100 ms `poll` and parks
/// within tens of microseconds — but the waiter only notices one poll
/// interval later, and every device of every VM pays that serially. At
/// the 1 ms this used to be, the auto-warp policy loop
/// measured a 6.3 ms mean pause across a 3-node cluster and spent more
/// wall time stopping the guests than the warps gave back
/// (`CHALLENGES.md` #183). Fork pays it once and did not notice; a
/// policy loop pays it 30 times a second.
pub(crate) const PARK_POLL: std::time::Duration = std::time::Duration::from_micros(50);

/// Bound on [`VirtioBackend::wait_quiescent`].
///
/// Must stay 200 ms: it is above the worker's 100 ms `poll`, and the old
/// 2 s bound blew `FORK_INNER_K3S_CLUSTER_3VM` (CHALLENGES #162). A
/// missed deadline is no longer a warning — the fork path fails rather
/// than copying a torn used ring (`docs/bug-candidates.md` #59).
pub const QUIESCE_DEADLINE: Duration = Duration::from_millis(200);

/// A virtio worker did not park before [`QUIESCE_DEADLINE`].
///
/// Named so the fork path can fail loudly instead of proceeding with a
/// dirty delta that would omit host-side device writes (CHALLENGES #79, #101).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotQuiescent {
    /// Device identity, e.g. `virtio-blk (/var/lib/k7d/scratch.img)` or
    /// `virtio-net mac=fe:00:00:00:00:01`.
    pub device: String,
    /// How long `wait_quiescent` waited before giving up.
    pub waited: Duration,
}

impl std::fmt::Display for NotQuiescent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} did not park within {:?} (deadline {:?})",
            self.device, self.waited, QUIESCE_DEADLINE
        )
    }
}

impl std::error::Error for NotQuiescent {}

/// Process-wide count of forks that hit a non-quiescent virtio-blk worker.
static FORK_NONQUIESCENT_BLK: AtomicU64 = AtomicU64::new(0);
/// Process-wide count of forks that hit a non-quiescent virtio-net worker.
static FORK_NONQUIESCENT_NET: AtomicU64 = AtomicU64::new(0);
/// Process-wide count of forks that hit any other non-quiescent device.
static FORK_NONQUIESCENT_OTHER: AtomicU64 = AtomicU64::new(0);

/// Process-wide counters for forks that hit a missed quiescence deadline.
///
/// The point of the counter is to answer "is 200 ms actually enough on
/// real workloads?" with data instead of a guess (`docs/bug-candidates.md`
/// #59).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkNonquiescentCounts {
    /// Forks that named a `virtio-blk` device in the miss.
    pub virtio_blk: u64,
    /// Forks that named a `virtio-net` device in the miss.
    pub virtio_net: u64,
    /// Any other device type.
    pub other: u64,
}

/// Snapshot of [`FORK_NONQUIESCENT_BLK`] / net / other.
#[must_use]
pub fn fork_nonquiescent_counts() -> ForkNonquiescentCounts {
    ForkNonquiescentCounts {
        virtio_blk: FORK_NONQUIESCENT_BLK.load(Ordering::Relaxed),
        virtio_net: FORK_NONQUIESCENT_NET.load(Ordering::Relaxed),
        other: FORK_NONQUIESCENT_OTHER.load(Ordering::Relaxed),
    }
}

/// Record one fork that took the full-dump path because `missed` was
/// non-empty. Increments once per named device.
pub fn record_fork_nonquiescent(missed: &[NotQuiescent]) {
    for m in missed {
        if m.device.starts_with("virtio-blk") {
            FORK_NONQUIESCENT_BLK.fetch_add(1, Ordering::Relaxed);
        } else if m.device.starts_with("virtio-net") {
            FORK_NONQUIESCENT_NET.fetch_add(1, Ordering::Relaxed);
        } else {
            FORK_NONQUIESCENT_OTHER.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Poll `parked` until it is true, the worker has exited, or
/// [`QUIESCE_DEADLINE`] elapses.
///
/// `hold` is the test-only wedge: when true the waiter ignores `parked`
/// and always waits out the deadline (the worker itself is not changed).
pub(crate) fn wait_for_park(
    parked: &AtomicBool,
    running: &AtomicBool,
    hold: bool,
    device: impl FnOnce() -> String,
) -> Result<(), NotQuiescent> {
    let start = Instant::now();
    let deadline = start + QUIESCE_DEADLINE;
    while running.load(Ordering::SeqCst) && (hold || !parked.load(Ordering::SeqCst)) {
        if Instant::now() >= deadline {
            return Err(NotQuiescent {
                device: device(),
                waited: start.elapsed(),
            });
        }
        std::thread::sleep(PARK_POLL);
    }
    Ok(())
}

/// How often a parked worker re-reads `paused` while it waits to be let
/// go again.
///
/// This is dead time on the resumed guest's device: frames sit in the
/// TAP buffer and requests sit in the ring for up to this long after
/// `Vm::resume` returns. Fork resumes once, so the 2 ms it used to be
/// cost nothing; a policy loop pausing 30 times a second was handing
/// the guests a device that was idle a third of the time. Longer than
/// [`PARK_POLL`] because a parked worker polls for the whole of a
/// multi-second fork pause, where the waiter polls only for the tens of
/// microseconds a park takes.
pub(crate) const UNPARK_POLL: std::time::Duration = std::time::Duration::from_micros(200);

/// A virtio split-ring descriptor, exactly as the guest publishes it.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct VirtqDesc {
    /// Guest-physical address of the buffer.
    pub addr: u64,
    /// Buffer length in bytes.
    pub len: u32,
    /// `VIRTQ_DESC_F_*` flags.
    pub flags: u16,
    /// Next descriptor in the chain, when `VIRTQ_DESC_F_NEXT` is set.
    pub next: u16,
}

/// Virtio descriptor flag: the chain continues at `next`.
pub const VIRTQ_DESC_F_NEXT: u16 = 1;
/// Virtio descriptor flag: the buffer is device-writable.
pub const VIRTQ_DESC_F_WRITE: u16 = 2;
/// Virtio descriptor flag: `addr` points at an indirect descriptor table,
/// not at a buffer. k7d never advertises `VIRTIO_F_INDIRECT_DESC`.
pub const VIRTQ_DESC_F_INDIRECT: u16 = 4;

/// Metadata of one descriptor in a chain, as read from the guest's
/// descriptor table: guest-physical address, length, and whether the
/// buffer is device-writable (`VIRTQ_DESC_F_WRITE`).
#[derive(Clone, Copy, Debug)]
pub struct DescMeta {
    /// Guest-physical address of the buffer.
    pub addr: u64,
    /// Buffer length in bytes.
    pub len: u32,
    /// Device-writable (`VIRTQ_DESC_F_WRITE`).
    pub write: bool,
}

/// Why a guest's virtqueue geometry cannot be walked by the host.
#[derive(Debug, thiserror::Error)]
pub enum QueueGeometryError {
    /// The device has no guest-memory mapping to validate against.
    #[error("no guest memory mapping to validate the queue against")]
    NoGuestMemory,
    /// `QUEUE_NUM` was never programmed (or programmed to zero). Every
    /// consumer indexes its rings with `% size`.
    #[error("queue size is 0")]
    ZeroSize,
    /// The driver asked for more descriptors than the device advertised
    /// through `QUEUE_NUM_MAX`.
    #[error("queue size {size} exceeds the device maximum of {max}")]
    SizeAboveMax {
        /// Size the driver programmed.
        size: u16,
        /// Size the device advertised.
        max: u16,
    },
    /// Virtio 1.x requires a power-of-two queue size; the ring-slot
    /// arithmetic here relies on it.
    #[error("queue size {0} is not a power of two")]
    SizeNotPowerOfTwo(u16),
    /// One of the three rings does not fit inside the guest's own RAM.
    #[error(
        "{ring} ring at {gpa:#x} spanning {len} bytes escapes the {span:#x}-byte guest memory"
    )]
    RingOutOfRange {
        /// Which ring (`descriptor`, `avail`, `used`).
        ring: &'static str,
        /// Guest-physical address the driver programmed.
        gpa: u64,
        /// Computed span of the ring.
        len: u64,
        /// Guest-physical span available.
        span: u64,
    },
}

/// Why a descriptor chain the guest published cannot be serviced.
#[derive(Debug, thiserror::Error)]
pub enum DescChainError {
    /// The guest named a descriptor outside its own table.
    #[error("descriptor index {idx} is outside the {size}-descriptor table")]
    IndexOutOfRange {
        /// Index the guest published.
        idx: u16,
        /// Queue size.
        size: u16,
    },
    /// More `NEXT` hops than the queue has descriptors — a chain that
    /// points back at itself would otherwise spin the worker forever.
    #[error("descriptor chain is longer than the {0}-descriptor queue (cycle?)")]
    TooLong(u16),
    /// A buffer the chain points at is not inside the guest's RAM.
    #[error("descriptor {idx} buffer {addr:#x}+{len} escapes the {span:#x}-byte guest memory")]
    BufferOutOfRange {
        /// Index of the offending descriptor.
        idx: u16,
        /// Buffer address the guest published.
        addr: u64,
        /// Buffer length the guest published.
        len: u32,
        /// Guest-physical span available.
        span: u64,
    },
}

/// The geometry of one guest virtqueue, checked once against the guest's
/// own RAM mapping.
///
/// Every host-side walk of a virtqueue is `mem_base + <a u64 the guest
/// wrote>`. [`ValidatedQueue::new`] is the only way to obtain one of
/// these, so a queue whose rings cannot be walked in bounds never
/// reaches a device worker at all: the arithmetic is checked once at
/// activation instead of on every descriptor
/// (`docs/bug-candidates.md` #1, #8, #40–#45).
///
/// Ring layouts (virtio 1.x split ring, no `VIRTIO_F_EVENT_IDX` padding
/// assumptions beyond the trailing `u16`):
/// - descriptor table: `size` × 16 bytes;
/// - avail ring: `flags:u16 + idx:u16 + ring[size]:u16 + used_event:u16`;
/// - used ring: `flags:u16 + idx:u16 + elem[size]:{id:u32,len:u32} + avail_event:u16`.
#[derive(Clone, Debug)]
pub struct ValidatedQueue {
    mem_base: u64,
    mem_span: u64,
    size: u16,
    desc_gpa: u64,
    avail_gpa: u64,
    used_gpa: u64,
}

impl ValidatedQueue {
    /// Validate a live queue's geometry against the guest mapping at
    /// `mem_base` spanning `mem_span` guest-physical bytes.
    pub fn new(
        q: &VirtqueueState,
        mem_base: u64,
        mem_span: u64,
    ) -> Result<Self, QueueGeometryError> {
        Self::build(
            q.size,
            q.max_size,
            q.desc_addr.raw_value(),
            q.avail_addr.raw_value(),
            q.used_addr.raw_value(),
            mem_base,
            mem_span,
        )
    }

    /// Validate a snapshotted queue's geometry. `max_size` comes from the
    /// device that is about to own the queue, never from the snapshot —
    /// the snapshot carries only what the *driver* chose
    /// (`docs/bug-candidates.md` #45).
    pub fn from_snapshot(
        qs: &VirtqueueSnapshot,
        max_size: u16,
        mem_base: u64,
        mem_span: u64,
    ) -> Result<Self, QueueGeometryError> {
        Self::build(
            qs.size,
            max_size,
            qs.desc_addr,
            qs.avail_addr,
            qs.used_addr,
            mem_base,
            mem_span,
        )
    }

    fn build(
        size: u16,
        max_size: u16,
        desc_gpa: u64,
        avail_gpa: u64,
        used_gpa: u64,
        mem_base: u64,
        mem_span: u64,
    ) -> Result<Self, QueueGeometryError> {
        if mem_span == 0 {
            return Err(QueueGeometryError::NoGuestMemory);
        }
        if size == 0 {
            return Err(QueueGeometryError::ZeroSize);
        }
        if size > max_size {
            return Err(QueueGeometryError::SizeAboveMax {
                size,
                max: max_size,
            });
        }
        if !size.is_power_of_two() {
            return Err(QueueGeometryError::SizeNotPowerOfTwo(size));
        }
        let n = u64::from(size);
        for (ring, gpa, len) in [
            ("descriptor", desc_gpa, n * 16),
            ("avail", avail_gpa, 6 + n * 2),
            ("used", used_gpa, 6 + n * 8),
        ] {
            let fits = gpa.checked_add(len).is_some_and(|end| end <= mem_span);
            if !fits {
                return Err(QueueGeometryError::RingOutOfRange {
                    ring,
                    gpa,
                    len,
                    span: mem_span,
                });
            }
        }
        Ok(Self {
            mem_base,
            mem_span,
            size,
            desc_gpa,
            avail_gpa,
            used_gpa,
        })
    }

    /// Queue size in descriptors (non-zero, a power of two).
    #[must_use]
    pub fn size(&self) -> u16 {
        self.size
    }

    /// Host address the guest's RAM is mapped at.
    #[must_use]
    pub fn mem_base(&self) -> u64 {
        self.mem_base
    }

    /// Guest-physical span of that mapping.
    #[must_use]
    pub fn mem_span(&self) -> u64 {
        self.mem_span
    }

    /// Guest-physical address and byte span of the descriptor table.
    #[must_use]
    pub fn desc_ring(&self) -> (u64, u64) {
        (self.desc_gpa, u64::from(self.size) * 16)
    }

    /// Guest-physical address and byte span of the available ring.
    #[must_use]
    pub fn avail_ring_span(&self) -> (u64, u64) {
        (self.avail_gpa, 6 + u64::from(self.size) * 2)
    }

    /// Guest-physical address and byte span of the used ring.
    #[must_use]
    pub fn used_ring_span(&self) -> (u64, u64) {
        (self.used_gpa, 6 + u64::from(self.size) * 8)
    }

    /// Host pointer to descriptor `idx`, or `None` when the guest named a
    /// descriptor outside its own table.
    #[must_use]
    pub fn desc(&self, idx: u16) -> Option<*const VirtqDesc> {
        if idx >= self.size {
            return None;
        }
        Some((self.mem_base + self.desc_gpa + u64::from(idx) * 16) as *const VirtqDesc)
    }

    /// Host pointer to the available ring's `idx` field.
    #[must_use]
    pub fn avail_idx(&self) -> *const u16 {
        (self.mem_base + self.avail_gpa + 2) as *const u16
    }

    /// Host pointer to available-ring slot `i`, wrapped into the ring.
    #[must_use]
    pub fn avail_ring(&self, i: u16) -> *const u16 {
        (self.mem_base + self.avail_gpa + 4 + u64::from(i % self.size) * 2) as *const u16
    }

    /// Host pointer to the used ring's `idx` field.
    #[must_use]
    pub fn used_idx(&self) -> *mut u16 {
        (self.mem_base + self.used_gpa + 2) as *mut u16
    }

    /// Guest-physical address of the used ring's `idx` field.
    #[must_use]
    pub fn used_idx_gpa(&self) -> u64 {
        self.used_gpa + 2
    }

    /// Host pointer to used-ring element `i` (`{id:u32, len:u32}`),
    /// wrapped into the ring.
    #[must_use]
    pub fn used_ring(&self, i: u16) -> *mut u32 {
        (self.mem_base + self.used_ring_gpa(i)) as *mut u32
    }

    /// Guest-physical address of used-ring element `i`.
    #[must_use]
    pub fn used_ring_gpa(&self, i: u16) -> u64 {
        self.used_gpa + 4 + u64::from(i % self.size) * 8
    }

    /// Host address of the guest buffer `[gpa, gpa + len)`, or `None`
    /// when it does not fit entirely inside guest RAM.
    #[must_use]
    pub fn buffer(&self, gpa: u64, len: u64) -> Option<u64> {
        let end = gpa.checked_add(len)?;
        if end > self.mem_span {
            return None;
        }
        Some(self.mem_base + gpa)
    }

    /// Walk the descriptor chain starting at `head`.
    ///
    /// The one chain walker in the daemon: `block.rs` and `network.rs`
    /// both go through it, so a lying guest gets the same refusal from
    /// every device. Bounded at `size` hops (a `next` pointing back at
    /// itself is a refusal, not a spinning worker), rejects a descriptor
    /// index outside the table, and checks every `addr + len` against
    /// the guest's RAM span with checked arithmetic before the caller
    /// can copy a byte.
    ///
    /// Descriptors land in `out`, which is cleared first, so a hot RX/TX
    /// path reuses one allocation.
    pub fn walk_chain<'a>(
        &self,
        head: u16,
        out: &'a mut Vec<DescMeta>,
    ) -> Result<&'a [DescMeta], DescChainError> {
        out.clear();
        let mut idx = head;
        loop {
            if out.len() >= self.size as usize {
                return Err(DescChainError::TooLong(self.size));
            }
            let Some(ptr) = self.desc(idx) else {
                return Err(DescChainError::IndexOutOfRange {
                    idx,
                    size: self.size,
                });
            };
            // SAFETY: `desc` only yields pointers inside the descriptor
            // table this geometry placed within the caller's live guest
            // mapping, which outlives the walk.
            let d: VirtqDesc = unsafe { std::ptr::read_volatile(ptr) };
            if self.buffer(d.addr, u64::from(d.len)).is_none() {
                return Err(DescChainError::BufferOutOfRange {
                    idx,
                    addr: d.addr,
                    len: d.len,
                    span: self.mem_span,
                });
            }
            out.push(DescMeta {
                addr: d.addr,
                len: d.len,
                write: d.flags & VIRTQ_DESC_F_WRITE != 0,
            });
            if d.flags & VIRTQ_DESC_F_NEXT == 0 {
                return Ok(out);
            }
            idx = d.next;
        }
    }
}

/// State of a single virtqueue as programmed by the guest.
#[derive(Debug, Clone, Default)]
pub struct VirtqueueState {
    /// Maximum queue size the device supports.
    pub max_size: u16,
    /// Queue size chosen by the driver.
    pub size: u16,
    /// Whether the queue is ready.
    pub ready: bool,
    /// Guest physical address of the descriptor table.
    pub desc_addr: GuestAddress,
    /// Guest physical address of the available ring.
    pub avail_addr: GuestAddress,
    /// Guest physical address of the used ring.
    pub used_addr: GuestAddress,
}

/// Trait for a virtio device backend (vsock, net, fs, etc.).
pub trait VirtioBackend: Send {
    /// Virtio device type ID (e.g. 19 for vsock).
    fn device_type(&self) -> u32;
    /// Device features (64-bit).
    fn device_features(&self) -> u64;
    /// Accept driver features.
    fn ack_features(&mut self, features: u64);
    /// Number of virtqueues.
    fn num_queues(&self) -> usize;
    /// Maximum queue size for each queue.
    fn max_queue_size(&self) -> u16;
    /// The guest-memory mapping this device's queues live in:
    /// `(host base address, guest-physical span)`.
    ///
    /// [`MmioDevice::handle_status_write`] validates every ready queue's
    /// geometry against it before activating, so a backend that cannot
    /// answer is a backend whose rings nobody is checking — hence no
    /// default.
    fn guest_mapping(&self) -> (u64, u64);
    /// Read device-specific config space.
    fn read_config(&self, offset: u64, data: &mut [u8]);
    /// Write device-specific config space.
    fn write_config(&mut self, offset: u64, data: &[u8]);
    /// Called when the device reaches `DRIVER_OK`.
    /// `irq_evt` is the eventfd wired to KVM irqfd for guest interrupt injection.
    fn activate(&mut self, queues: &[VirtqueueState], irq_evt: &EventFd) -> Result<(), String>;
    /// Called when the guest writes to `QUEUE_NOTIFY` with a queue index.
    fn queue_notify(&self, queue_index: u32);
    /// Pause or unpause userspace workers that touch guest memory.
    ///
    /// Warm-fork pauses the vCPU for a consistent dirty-page capture; userspace
    /// virtio workers (e.g. `TapNetBackend`) must stop mutating rings for the
    /// same window or in-flight TCP on the source dies across the pause.
    /// Default: no-op (vhost backends are paused via the vCPU/irq path).
    fn set_paused(&self, _paused: bool) {}
    /// Block (bounded by [`QUIESCE_DEADLINE`]) until the backend's paused
    /// workers have stopped touching guest memory.
    ///
    /// Called by `Vm::pause` after `set_paused(true)` and the vCPU join so
    /// that snapshot/fork memory captures never race in-flight device DMA
    /// (e.g. a virtio-blk read completing mid-memcpy). Default: instantly
    /// quiescent (no worker). A miss is reported, not logged-and-ignored:
    /// `Vm::pause` records it and the fork path fails.
    fn wait_quiescent(&self) -> Result<(), NotQuiescent> {
        Ok(())
    }
    /// Test-only wedge: when `hold` is true, [`Self::wait_quiescent`]
    /// ignores the worker's `parked` flag and waits out the deadline.
    /// Default: no-op. The worker itself is not changed, so the source VM
    /// stays healthy for the integration test.
    fn hold_park_for_test(&self, _hold: bool) {}
    /// Whether paused workers have stopped touching the backing file
    /// and guest memory. Default true (no worker). Used so a fork can
    /// delay `FICLONE` until a stuck virtio-blk `pwrite` finishes —
    /// cloning an 8 GiB scratch while the worker holds the inode has
    /// been measured at 4–7 s (CHALLENGES #162).
    fn is_quiescent(&self) -> bool {
        true
    }
    /// Drain the backend's device-DMA dirty page bitmap into `acc` (one
    /// bit per 4 KiB guest page, `u64` words): OR it in and clear it, so
    /// the next call reports only pages written since this one. A worker
    /// marks a page only after writing it, so a drained bit means the
    /// bytes are visible to the caller's copy.
    ///
    /// KVM dirty logging only sees vCPU writes; an in-process worker that
    /// writes guest memory through k7d's own mapping (virtio-blk reads,
    /// used-ring updates) must report those pages itself or warm forks on
    /// the `base.mem + dirty delta` path silently miss them (the host-side
    /// CHALLENGES.md #27 class of bug). Default: no-op.
    ///
    /// A vhost device has no userspace worker to report anything, but the
    /// kernel DMAs into its rings just as invisibly — those pages are
    /// marked by [`MmioDevice::merge_dirty_pages`] instead, so a vsock-only
    /// VM on the `CoW` fork path is not exempt from this class of bug.
    fn merge_dirty_pages(&self, _acc: &mut [u64]) {}
}

/// A virtio-MMIO device instance.
pub struct MmioDevice {
    /// Base MMIO address in guest physical space.
    pub base_addr: u64,
    /// IRQ number for this device.
    pub irq: u32,
    /// The backend device.
    backend: Box<dyn VirtioBackend>,
    /// Virtqueue states.
    queues: Vec<VirtqueueState>,
    /// Currently selected queue index.
    queue_sel: u32,
    /// Device status register.
    device_status: u32,
    /// Feature selection registers.
    features_sel: u32,
    driver_features_sel: u32,
    /// Acked driver features.
    acked_features: u64,
    /// Interrupt status (atomic for IRQ delivery from other threads).
    interrupt_status: Arc<AtomicU32>,
    /// `EventFd` for IRQ delivery via irqfd.
    irq_evt: Arc<EventFd>,
    /// Config generation counter.
    config_generation: u32,
    /// Whether the device has been activated.
    activated: bool,
    /// For vhost devices, always report `INT_VRING` (Firecracker pattern).
    is_vhost: bool,
    /// The PCI function this device is, when it sits on the PCI bus.
    /// `None` is a virtio-mmio device at `base_addr`.
    pci: Option<VirtioPciFunction>,
}

impl MmioDevice {
    /// Create a new MMIO device at the given base address and IRQ.
    #[must_use]
    pub fn new(
        base_addr: u64,
        irq: u32,
        irq_evt: Arc<EventFd>,
        backend: Box<dyn VirtioBackend>,
    ) -> Self {
        let num_queues = backend.num_queues();
        let max_size = backend.max_queue_size();
        let queues = (0..num_queues)
            .map(|_| VirtqueueState {
                max_size,
                ..Default::default()
            })
            .collect();

        Self {
            base_addr,
            irq,
            backend,
            queues,
            queue_sel: 0,
            device_status: 0,
            features_sel: 0,
            driver_features_sel: 0,
            acked_features: 0,
            interrupt_status: Arc::new(AtomicU32::new(0)),
            irq_evt,
            config_generation: 0,
            activated: false,
            is_vhost: false,
            pci: None,
        }
    }

    /// Mark this device as a vhost device (`interrupt_status` always shows `INT_VRING`).
    pub fn set_vhost(&mut self, is_vhost: bool) {
        self.is_vhost = is_vhost;
    }

    /// Whether this is a vhost device (see [`Self::set_vhost`]).
    #[must_use]
    pub fn is_vhost(&self) -> bool {
        self.is_vhost
    }

    /// Put this device on the PCI bus in `slot`, with its BAR at
    /// `base_addr` and INTA# on `irq`. After this the device answers at
    /// the BAR the guest programs, not at `base_addr`.
    pub fn attach_pci(&mut self, slot: u8) -> Result<(), String> {
        let f = VirtioPciFunction::new(slot, self.backend.device_type(), self.base_addr, self.irq)?;
        self.pci = Some(f);
        Ok(())
    }

    /// Which bus this device sits on.
    #[must_use]
    pub fn transport(&self) -> Transport {
        if self.pci.is_some() {
            Transport::Pci
        } else {
            Transport::Mmio
        }
    }

    /// The PCI function, when this device is on the PCI bus.
    #[must_use]
    pub fn pci_function(&self) -> Option<&VirtioPciFunction> {
        self.pci.as_ref()
    }

    pub(crate) fn pci_function_mut(&mut self) -> Option<&mut VirtioPciFunction> {
        self.pci.as_mut()
    }

    /// The guest-physical window this device currently decodes:
    /// the fixed 4 KiB virtio-mmio window, or the BAR the guest
    /// programmed (`None` while PCI memory decoding is disabled).
    #[must_use]
    pub fn window(&self) -> Option<(u64, u64)> {
        match &self.pci {
            None => Some((self.base_addr, MMIO_DEVICE_SIZE)),
            Some(f) => f.bar_window(),
        }
    }

    /// Dispatch a read inside [`Self::window`] to the right decode.
    pub fn window_read(&self, offset: u64, data: &mut [u8]) {
        match self.transport() {
            Transport::Mmio => self.mmio_read(offset, data),
            Transport::Pci => self.pci_bar_read(offset, data),
        }
    }

    /// Dispatch a write inside [`Self::window`] to the right decode.
    pub fn window_write(&mut self, offset: u64, data: &[u8]) {
        match self.transport() {
            Transport::Mmio => self.mmio_write(offset, data),
            Transport::Pci => self.pci_bar_write(offset, data),
        }
    }

    // --- transport-neutral register primitives -------------------------
    //
    // Both decoders (`mmio_read`/`mmio_write` here, `pci_bar_read`/
    // `pci_bar_write` in `pci.rs`) go through these, so the gates on
    // feature and queue writes are stated once.

    pub(crate) fn features_sel(&self) -> u32 {
        self.features_sel
    }

    pub(crate) fn set_features_sel(&mut self, sel: u32) {
        self.features_sel = sel;
    }

    pub(crate) fn driver_features_sel(&self) -> u32 {
        self.driver_features_sel
    }

    pub(crate) fn set_driver_features_sel(&mut self, sel: u32) {
        self.driver_features_sel = sel;
    }

    /// The device-feature word `features_sel` selects, with
    /// `VIRTIO_F_VERSION_1` always set.
    pub(crate) fn device_features_word(&self) -> u32 {
        let features = self.backend.device_features() | VIRTIO_F_VERSION_1;
        if self.features_sel == 0 {
            features as u32
        } else {
            (features >> 32) as u32
        }
    }

    /// The acked-feature word `driver_features_sel` selects.
    pub(crate) fn driver_features_word(&self) -> u32 {
        if self.driver_features_sel == 0 {
            self.acked_features as u32
        } else {
            (self.acked_features >> 32) as u32
        }
    }

    /// Driver writes one feature word; accepted only once the driver
    /// has announced itself (`DRIVER`) and before `DRIVER_OK`.
    pub(crate) fn write_driver_features_word(&mut self, val: u32) {
        if self.features_ok() || self.device_status & STATUS_DRIVER != 0 {
            let word = if self.driver_features_sel == 0 {
                u64::from(val)
            } else {
                u64::from(val) << 32
            };
            self.acked_features |= word;
        }
    }

    pub(crate) fn queue_sel(&self) -> u32 {
        self.queue_sel
    }

    /// Select a queue. Out of range is still *stored*: the virtio spec
    /// makes a driver read the queue maximum after selecting, and 0
    /// tells it the queue does not exist, which is how Linux probes.
    /// What must not happen is what used to: every subsequent `QUEUE_*`
    /// write silently dropped on the floor, leaving a device the driver
    /// believes it configured (`docs/bug-candidates.md` #41).
    pub(crate) fn select_queue(&mut self, val: u32) {
        if val as usize >= self.queues.len() {
            log::error!(
                "virtio (type={}): driver selected queue {val} of {} — \
                 its QUEUE_NUM/DESC/AVAIL/USED writes will be discarded",
                self.backend.device_type(),
                self.queues.len()
            );
        }
        self.queue_sel = val;
    }

    pub(crate) fn write_queue_size(&mut self, val: u32) {
        if self.features_ok() || self.device_status & STATUS_DRIVER != 0 {
            if let Some(q) = self.selected_queue_mut() {
                q.size = (val & 0xffff) as u16;
            }
        }
    }

    pub(crate) fn write_queue_ready(&mut self, ready: bool) {
        if let Some(q) = self.selected_queue_mut() {
            q.ready = ready;
        }
    }

    /// Guest kick of queue `queue`; ignored until the device is live.
    pub(crate) fn notify(&self, queue: u32) {
        if self.activated {
            self.backend.queue_notify(queue);
        }
    }

    pub(crate) fn status(&self) -> u32 {
        self.device_status
    }

    pub(crate) fn write_status(&mut self, val: u32) {
        self.handle_status_write(val);
    }

    pub(crate) fn config_generation(&self) -> u32 {
        self.config_generation
    }

    pub(crate) fn backend_read_config(&self, offset: u64, data: &mut [u8]) {
        self.backend.read_config(offset, data);
    }

    pub(crate) fn backend_write_config(&mut self, offset: u64, data: &[u8]) {
        self.backend.write_config(offset, data);
    }

    /// Get the interrupt status (for injection from backend).
    #[must_use]
    pub fn interrupt_status(&self) -> Arc<AtomicU32> {
        Arc::clone(&self.interrupt_status)
    }

    /// Virtio device type of the backend.
    #[must_use]
    pub fn device_type(&self) -> u32 {
        self.backend.device_type()
    }

    /// The queue state the guest has programmed so far.
    #[must_use]
    pub fn queues(&self) -> &[VirtqueueState] {
        &self.queues
    }

    /// Get the IRQ eventfd (for injection from backend).
    #[must_use]
    pub fn irq_eventfd(&self) -> Arc<EventFd> {
        Arc::clone(&self.irq_evt)
    }

    pub(crate) fn selected_queue(&self) -> Option<&VirtqueueState> {
        self.queues.get(self.queue_sel as usize)
    }

    pub(crate) fn selected_queue_mut(&mut self) -> Option<&mut VirtqueueState> {
        self.queues.get_mut(self.queue_sel as usize)
    }

    fn features_ok(&self) -> bool {
        self.device_status & STATUS_FEATURES_OK != 0
            && self.device_status & (STATUS_DRIVER_OK | STATUS_FAILED) == 0
    }

    /// Handle an MMIO read from the guest.
    pub fn mmio_read(&self, offset: u64, data: &mut [u8]) {
        if data.len() != 4 && offset < 0x100 {
            data.fill(0);
            return;
        }

        if offset >= 0x100 {
            self.backend.read_config(offset - 0x100, data);
            return;
        }

        let val: u32 = match offset {
            MMIO_MAGIC => MAGIC_VALUE,
            MMIO_VERSION => MMIO_VERSION_2,
            MMIO_DEVICE_ID => self.backend.device_type(),
            MMIO_DEVICE_FEATURES => self.device_features_word(),
            MMIO_QUEUE_NUM_MAX => self.selected_queue().map_or(0, |q| q.max_size as u32),
            MMIO_QUEUE_READY => self.selected_queue().map_or(0, |q| u32::from(q.ready)),
            MMIO_INTERRUPT_STATUS => {
                if self.is_vhost {
                    // For vhost devices, always report INT_VRING since the
                    // backend manages its own interrupt state (Firecracker pattern).
                    // Also include any pending config change interrupts.
                    INT_VRING | self.interrupt_status.load(Ordering::SeqCst)
                } else {
                    self.interrupt_status.load(Ordering::SeqCst)
                }
            }
            MMIO_STATUS => self.device_status,
            MMIO_CONFIG_GENERATION => self.config_generation,
            _ => 0,
        };

        if data.len() == 4 {
            data.copy_from_slice(&val.to_le_bytes());
        }
    }

    /// Handle an MMIO write from the guest.
    pub fn mmio_write(&mut self, offset: u64, data: &[u8]) {
        if data.len() != 4 && offset < 0x100 {
            return;
        }

        if offset >= 0x100 {
            self.backend.write_config(offset - 0x100, data);
            return;
        }

        let val = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

        match offset {
            MMIO_DEVICE_FEATURES_SEL => self.set_features_sel(val),
            MMIO_DRIVER_FEATURES => self.write_driver_features_word(val),
            MMIO_DRIVER_FEATURES_SEL => self.set_driver_features_sel(val),
            MMIO_QUEUE_SEL => self.select_queue(val),
            MMIO_QUEUE_NUM => self.write_queue_size(val),
            MMIO_QUEUE_READY => self.write_queue_ready(val == 1),
            MMIO_QUEUE_NOTIFY => self.notify(val),
            MMIO_INTERRUPT_ACK => {
                if self.device_status & STATUS_DRIVER_OK != 0 {
                    self.interrupt_status.fetch_and(!val, Ordering::SeqCst);
                }
            }
            MMIO_STATUS => {
                self.handle_status_write(val);
            }
            MMIO_QUEUE_DESC_LOW => {
                if let Some(q) = self.selected_queue_mut() {
                    let addr = q.desc_addr.raw_value();
                    q.desc_addr = GuestAddress((addr & !0xFFFF_FFFF) | val as u64);
                }
            }
            MMIO_QUEUE_DESC_HIGH => {
                if let Some(q) = self.selected_queue_mut() {
                    let addr = q.desc_addr.raw_value();
                    q.desc_addr = GuestAddress((addr & 0xFFFF_FFFF) | ((val as u64) << 32));
                }
            }
            MMIO_QUEUE_AVAIL_LOW => {
                if let Some(q) = self.selected_queue_mut() {
                    let addr = q.avail_addr.raw_value();
                    q.avail_addr = GuestAddress((addr & !0xFFFF_FFFF) | val as u64);
                }
            }
            MMIO_QUEUE_AVAIL_HIGH => {
                if let Some(q) = self.selected_queue_mut() {
                    let addr = q.avail_addr.raw_value();
                    q.avail_addr = GuestAddress((addr & 0xFFFF_FFFF) | ((val as u64) << 32));
                }
            }
            MMIO_QUEUE_USED_LOW => {
                if let Some(q) = self.selected_queue_mut() {
                    let addr = q.used_addr.raw_value();
                    q.used_addr = GuestAddress((addr & !0xFFFF_FFFF) | val as u64);
                }
            }
            MMIO_QUEUE_USED_HIGH => {
                if let Some(q) = self.selected_queue_mut() {
                    let addr = q.used_addr.raw_value();
                    q.used_addr = GuestAddress((addr & 0xFFFF_FFFF) | ((val as u64) << 32));
                }
            }
            _ => {}
        }
    }

    fn handle_status_write(&mut self, val: u32) {
        if val == 0 {
            // Device reset
            self.device_status = 0;
            self.activated = false;
            for q in &mut self.queues {
                q.size = 0;
                q.ready = false;
                q.desc_addr = GuestAddress(0);
                q.avail_addr = GuestAddress(0);
                q.used_addr = GuestAddress(0);
            }
            return;
        }

        self.device_status = val;

        if val & STATUS_FEATURES_OK != 0 && val & STATUS_DRIVER_OK == 0 {
            self.backend.ack_features(self.acked_features);
        }

        if val & STATUS_DRIVER_OK != 0 && !self.activated {
            // Validate the geometry the guest programmed *before* a worker
            // thread exists to walk it. A ready queue whose rings do not
            // fit in the guest's own RAM, or whose size is 0 / above the
            // advertised maximum / not a power of two, fails the device
            // instead of handing a lying guest an out-of-bounds host walk
            // (`docs/bug-candidates.md` #8, #40, #41, #42).
            if let Err(e) = self.validate_ready_queues() {
                log::error!(
                    "virtio-mmio: refusing activation (type={}): {e}",
                    self.backend.device_type()
                );
                self.device_status |= STATUS_FAILED;
                return;
            }
            let queues: Vec<VirtqueueState> = self.queues.clone();
            match self.backend.activate(&queues, &self.irq_evt) {
                Ok(()) => {
                    self.activated = true;
                    log::info!(
                        "virtio-mmio: device activated (type={})",
                        self.backend.device_type()
                    );
                }
                Err(e) => {
                    log::error!("virtio-mmio: activation failed: {e}");
                    self.device_status |= STATUS_FAILED;
                }
            }
        }
    }

    /// Build the validated geometry of every queue the driver marked
    /// ready, discarding the result: this is the activation gate, and the
    /// backends rebuild their own from the same `(mem_base, mem_span)`.
    ///
    /// Queues the driver never readied are not validated — an unused
    /// queue nobody walks is not a boundary.
    fn validate_ready_queues(&self) -> Result<(), String> {
        let (mem_base, mem_span) = self.backend.guest_mapping();
        for (i, q) in self.queues.iter().enumerate() {
            if !q.ready {
                continue;
            }
            ValidatedQueue::new(q, mem_base, mem_span).map_err(|e| format!("queue {i}: {e}"))?;
        }
        Ok(())
    }

    /// Restore MMIO register state from a snapshot (without activating backend).
    ///
    /// Used during VM restore after the backend has been separately activated
    /// with correct vring base indices. This sets the MMIO device status,
    /// features, and queue addresses so the guest kernel's MMIO reads return
    /// the expected values.
    pub fn restore_state(&mut self, state: &MmioDeviceState) -> Result<(), String> {
        self.device_status = state.device_status;
        self.acked_features = state.acked_features;
        self.activated = state.activated;
        self.features_sel = state.features_sel;
        self.driver_features_sel = state.driver_features_sel;
        self.queue_sel = state.queue_sel;

        for (i, qs) in state.queues.iter().enumerate() {
            if i < self.queues.len() {
                self.queues[i].size = qs.size;
                self.queues[i].ready = qs.ready;
                self.queues[i].desc_addr = GuestAddress(qs.desc_addr);
                self.queues[i].avail_addr = GuestAddress(qs.avail_addr);
                self.queues[i].used_addr = GuestAddress(qs.used_addr);
            }
        }

        // The guest's memory assumes the BAR and command bits it
        // programmed; a child rebuilt with the boot-time defaults would
        // have a device at an address the driver no longer uses.
        match (&mut self.pci, &state.pci) {
            (None, None) => Ok(()),
            (Some(f), Some(s)) => f.restore(s),
            (Some(_), None) => Err(format!(
                "device type {} was rebuilt on the PCI bus but its snapshot carries no PCI state",
                state.device_type
            )),
            (None, Some(_)) => Err(format!(
                "device type {} snapshot carries PCI state but the device was rebuilt on virtio-mmio",
                state.device_type
            )),
        }
    }

    /// Trigger a vring interrupt to the guest.
    pub fn trigger_vring_irq(&self) {
        self.interrupt_status.fetch_or(INT_VRING, Ordering::SeqCst);
        let _ = self.irq_evt.write(1);
    }

    /// Trigger a config change interrupt to the guest.
    pub fn trigger_config_irq(&self) {
        self.interrupt_status.fetch_or(INT_CONFIG, Ordering::SeqCst);
        let _ = self.irq_evt.write(1);
    }

    /// Pause or unpause the backend's userspace workers (see [`VirtioBackend::set_paused`]).
    pub fn set_paused(&self, paused: bool) {
        self.backend.set_paused(paused);
    }

    /// Wait (bounded) for paused workers to quiesce (see
    /// [`VirtioBackend::wait_quiescent`]).
    pub fn wait_quiescent(&self) -> Result<(), NotQuiescent> {
        self.backend.wait_quiescent()
    }

    /// See [`VirtioBackend::hold_park_for_test`].
    pub fn hold_park_for_test(&self, hold: bool) {
        self.backend.hold_park_for_test(hold);
    }

    /// See [`VirtioBackend::is_quiescent`].
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        self.backend.is_quiescent()
    }

    /// Merge the backend's device-DMA dirty pages into `acc` (see
    /// [`VirtioBackend::merge_dirty_pages`]), then — for vhost-vsock — mark
    /// the pages the kernel vhost worker DMAs into.
    ///
    /// `KVM_GET_DIRTY_LOG` only reports vCPU writes, so a warm fork that
    /// copies `base.mem` plus that log carries vsock rings as they were when
    /// `base.mem` was dumped. Restore then programs `VHOST_SET_VRING_BASE`
    /// from that stale `used.idx` and the guest's vsock stack is deaf
    /// (CHALLENGES.md #101).
    pub fn merge_dirty_pages(&self, acc: &mut [u64], mem_host_addr: u64, mem_span: u64) {
        self.backend.merge_dirty_pages(acc);
        if self.backend.device_type() == VIRTIO_ID_VSOCK {
            mark_virtqueue_pages_dirty(&self.queues, acc, mem_host_addr, mem_span);
        }
    }
}

/// Whether queue `index` of a `device_type` device is one the **driver**
/// fills with requests, so `avail.idx == used.idx` means "nothing in
/// flight" (the third safety check).
///
/// The distinction is the whole check. On a receive queue — virtio-net
/// RX, vsock RX — a guest at rest keeps buffers posted for traffic that
/// has not arrived, so `avail.idx` legitimately runs ahead of `used.idx`
/// forever; reading that as work in flight would decline every warp on
/// every cluster. Only the driver-to-device direction is a handshake.
///
/// Unknown device types are reported as driver-filled: a device this
/// function has not been taught is one whose queues should hold up a
/// jump until someone teaches it.
#[must_use]
pub fn queue_is_driver_filled(device_type: u32, index: usize) -> bool {
    match device_type {
        // virtio-net: even queues are RX (device-filled), odd are TX.
        VIRTIO_ID_NET => index % 2 == 1,
        // vsock: queue 0 RX (device-filled), 1 TX, 2 event (device-filled).
        VIRTIO_ID_VSOCK => index == 1,
        // virtio-blk and virtio-fs are request/response throughout.
        _ => true,
    }
}

/// Mark every ready virtqueue's rings — and the buffers its descriptors
/// point at — dirty in `acc`.
///
/// vhost-vsock DMA-writes both the used ring and RX payloads, so copying the
/// rings without their buffers would hand the fork completions that point at
/// stale bytes. The cost is bounded by the queue size (256 descriptors of at
/// most a page each on both vsock queues), which is why this is limited to
/// vsock: a net or blk descriptor `len` can legitimately be megabytes, and
/// walking those would mark gigabytes on every fork.
///
/// Avail ring is `flags:u16 + idx:u16 + ring[size]:u16 + used_event:u16`.
/// Used ring is `flags:u16 + idx:u16 + elem[size]:{id:u32,len:u32} + avail_event:u16`.
/// Descriptor table is `size` 16-byte entries.
fn mark_virtqueue_pages_dirty(
    queues: &[VirtqueueState],
    acc: &mut [u64],
    mem_host_addr: u64,
    mem_span: u64,
) {
    for (i, q) in queues.iter().enumerate() {
        if !q.ready {
            continue;
        }
        // A queue whose geometry does not validate is a queue the kernel
        // vhost worker could not have DMA'd into either (it would have
        // taken EFAULT on the same addresses), and activation now refuses
        // it outright — so there is nothing to mark. Say so rather than
        // reading past the mapping to find out.
        let vq = match ValidatedQueue::new(q, mem_host_addr, mem_span) {
            Ok(vq) => vq,
            Err(e) => {
                log::error!(
                    "virtqueue {i} geometry is unwalkable ({e}) — not marking its \
                     vhost DMA for the warm-fork dirty delta"
                );
                continue;
            }
        };
        for (gpa, len) in [vq.desc_ring(), vq.avail_ring_span(), vq.used_ring_span()] {
            mark_gpa_range_dirty(acc, gpa, len);
        }
        for idx in 0..vq.size() {
            let Some(ptr) = vq.desc(idx) else { continue };
            // SAFETY: `desc` only yields pointers inside the descriptor
            // table this geometry placed within the caller's live guest
            // mapping, which outlives this call. The caller has paused the
            // vCPUs, so the guest is not rewriting the table.
            let d: VirtqDesc = unsafe { std::ptr::read_volatile(ptr) };
            // An indirect descriptor's `addr` is a descriptor table, not a
            // buffer; the ring pages above already cover what vhost writes.
            if d.flags & VIRTQ_DESC_F_INDIRECT != 0 || d.addr == 0 || d.len == 0 {
                continue;
            }
            if vq.buffer(d.addr, u64::from(d.len)).is_none() {
                continue;
            }
            mark_gpa_range_dirty(acc, d.addr, u64::from(d.len));
        }
    }
}

/// Set the bits covering `[gpa, gpa + len)` in a warm-fork dirty bitmap (one
/// bit per 4 KiB page, `u64` words). A range that starts past the bitmap is a
/// bug in the caller's queue state, not something to paper over — it means
/// the fork will miss that DMA, so say so.
fn mark_gpa_range_dirty(acc: &mut [u64], gpa: u64, len: u64) {
    if len == 0 {
        return;
    }
    // A wrapping (gpa, len) used to mark from `gpa/4096` up to a tiny
    // `last`, i.e. nothing — or, worse, the wrong pages. Silent wrong
    // dirty bits produce a corrupt fork child with no error anywhere
    // (`docs/bug-candidates.md` #43), so refuse loudly instead.
    let Some(end) = gpa.checked_add(len - 1) else {
        log::error!(
            "virtqueue dirty range {gpa:#x}+{len} wraps the address space — \
             a warm fork will miss this vhost DMA"
        );
        return;
    };
    let first = gpa / 4096;
    let last = end / 4096;
    let last_tracked = (acc.len() as u64).saturating_mul(64).saturating_sub(1);
    if first > last_tracked {
        log::error!(
            "virtqueue dirty range {gpa:#x}+{len} is outside the {}-word bitmap — \
             a warm fork will miss this vhost DMA",
            acc.len()
        );
        return;
    }
    for page in first..=last.min(last_tracked) {
        acc[(page / 64) as usize] |= 1u64 << (page % 64);
    }
}

/// Registry of virtio devices for the vCPU run loop dispatcher: every
/// virtio-mmio window and every PCI BAR, plus the PCI bus itself once a
/// PCI device is registered.
pub struct MmioDeviceRegistry {
    devices: Vec<Arc<Mutex<MmioDevice>>>,
    pci_bus: Option<PciBus>,
}

impl MmioDeviceRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            devices: Vec::new(),
            pci_bus: None,
        }
    }

    /// Register a device. The first PCI function brings the bus (host
    /// bridge + config-space latch) with it.
    pub fn add(&mut self, device: Arc<Mutex<MmioDevice>>) {
        if device.lock().unwrap().transport() == Transport::Pci {
            self.pci_bus.get_or_insert_with(PciBus::new);
        }
        self.devices.push(device);
    }

    /// Whether this VM has a PCI bus (at least one PCI device).
    #[must_use]
    pub fn has_pci_bus(&self) -> bool {
        self.pci_bus.is_some()
    }

    /// Dispatch an MMIO read to the device whose window holds `addr`.
    #[must_use]
    pub fn handle_read(&self, addr: u64, data: &mut [u8]) -> bool {
        for dev in &self.devices {
            let dev = dev.lock().unwrap();
            if let Some((base, size)) = dev.window() {
                if addr >= base && addr < base + size {
                    let offset = addr - base;
                    dev.window_read(offset, data);
                    log::trace!("mmio read addr={addr:#x} offset={offset:#x}");
                    return true;
                }
            }
        }
        false
    }

    /// Dispatch an MMIO write to the device whose window holds `addr`.
    #[must_use]
    pub fn handle_write(&self, addr: u64, data: &[u8]) -> bool {
        for dev in &self.devices {
            let mut dev = dev.lock().unwrap();
            if let Some((base, size)) = dev.window() {
                if addr >= base && addr < base + size {
                    let offset = addr - base;
                    log::trace!("mmio write addr={addr:#x} offset={offset:#x}");
                    dev.window_write(offset, data);
                    return true;
                }
            }
        }
        false
    }

    /// Whether `port` is a PCI configuration port this VM answers.
    #[must_use]
    pub fn handles_pio(&self, port: u16) -> bool {
        self.pci_bus.is_some() && PciBus::handles_port(port)
    }

    /// Guest `in` from a PCI configuration port. Returns `false` (data
    /// untouched) when this VM has no PCI bus.
    #[must_use]
    pub fn pio_read(&self, port: u16, data: &mut [u8]) -> bool {
        let Some(bus) = &self.pci_bus else {
            return false;
        };
        if port < crate::pci::PCI_CONFIG_DATA_PORT {
            bus.read_address(port, data);
            return true;
        }
        let Some(target) = bus.target() else {
            data.fill(0xff);
            return true;
        };
        let offset = usize::from(target.offset) + PciBus::data_byte_offset(port);
        if target.slot == 0 {
            bus.host_bridge().read(offset, data);
        } else {
            match self.pci_slot(target.slot) {
                Some(dev) => dev.lock().unwrap().pci_cfg_read(offset, data),
                None => data.fill(0xff),
            }
        }
        true
    }

    /// Guest `out` to a PCI configuration port.
    pub fn pio_write(&mut self, port: u16, data: &[u8]) {
        let Some(bus) = &mut self.pci_bus else {
            return;
        };
        if port < crate::pci::PCI_CONFIG_DATA_PORT {
            bus.write_address(port, data);
            return;
        }
        let Some(target) = bus.target() else {
            return;
        };
        let offset = usize::from(target.offset) + PciBus::data_byte_offset(port);
        if target.slot == 0 {
            bus.host_bridge_mut().write(offset, data);
        } else if let Some(dev) = self.pci_slot(target.slot) {
            dev.lock().unwrap().pci_cfg_write(offset, data);
        }
    }

    fn pci_slot(&self, slot: u8) -> Option<&Arc<Mutex<MmioDevice>>> {
        self.devices.iter().find(|d| {
            d.lock()
                .unwrap()
                .pci_function()
                .is_some_and(|f| f.slot() == slot)
        })
    }
}

impl Default for MmioDeviceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MmioDeviceRegistry {
    /// Drop every registered device, ensuring backend worker threads (e.g.
    /// `TapNetBackend`'s RX/TX poll loop) are joined.
    ///
    /// Called from `Vm::Drop` before guest memory is released so that no
    /// worker is left dereferencing a soon-to-be-unmapped raw pointer
    /// (cloud-hypervisor #4868: "ensure all references to tap FDs are
    /// dropped"). Idempotent — after the first call the registry is empty.
    pub fn shutdown_all(&mut self) {
        self.devices.clear();
    }

    /// Pause or unpause every backend's userspace workers.
    pub fn set_paused_all(&self, paused: bool) {
        for dev in &self.devices {
            dev.lock().unwrap().set_paused(paused);
        }
    }

    /// Wait (bounded) for every paused backend's workers to quiesce.
    ///
    /// Returns every device that missed [`QUIESCE_DEADLINE`]. An empty
    /// vec means every worker parked (or had no worker). `Vm::pause`
    /// records the list; it does not fail.
    #[must_use]
    pub fn wait_quiescent_all(&self) -> Vec<NotQuiescent> {
        let mut missed = Vec::new();
        for dev in &self.devices {
            if let Err(e) = dev.lock().unwrap().wait_quiescent() {
                missed.push(e);
            }
        }
        missed
    }

    /// See [`VirtioBackend::hold_park_for_test`].
    pub fn hold_park_for_test_all(&self, hold: bool) {
        for dev in &self.devices {
            dev.lock().unwrap().hold_park_for_test(hold);
        }
    }

    /// True when every backend reports [`VirtioBackend::is_quiescent`].
    #[must_use]
    pub fn all_quiescent(&self) -> bool {
        self.devices
            .iter()
            .all(|d| d.lock().unwrap().is_quiescent())
    }

    /// Device-bound virtqueues with work the guest has handed over and
    /// not yet had completed — one description per queue, empty when
    /// every device is idle (CHALLENGES #79's `avail`/`used` handshake).
    ///
    /// Reads the live queues rather than a snapshot so the geometry is
    /// validated against the device's own advertised maximum before
    /// either index is dereferenced. Only queues the *driver* fills are
    /// compared (see [`queue_is_driver_filled`]).
    #[must_use]
    pub fn queues_in_flight(&self, mem_host_addr: u64, mem_span: u64) -> Vec<String> {
        let mut busy = Vec::new();
        for dev in &self.devices {
            let dev = dev.lock().unwrap();
            let device_type = dev.device_type();
            for (i, q) in dev.queues().iter().enumerate() {
                if !q.ready || !queue_is_driver_filled(device_type, i) {
                    continue;
                }
                let Ok(vq) = ValidatedQueue::new(q, mem_host_addr, mem_span) else {
                    continue;
                };
                // SAFETY: both pointers are the `idx` fields of rings this
                // geometry placed inside the caller's live guest mapping.
                // The caller has paused the vCPUs and parked the device
                // workers, so nothing is writing them.
                let (avail, used) = unsafe {
                    (
                        std::ptr::read_volatile(vq.avail_idx()),
                        std::ptr::read_volatile(vq.used_idx().cast_const()),
                    )
                };
                if avail != used {
                    busy.push(format!(
                        "virtio type {device_type} queue {i}: avail.idx {avail} != used.idx {used}"
                    ));
                }
            }
        }
        busy
    }

    /// Merge every backend's device-DMA dirty pages into `acc`. `mem_host_addr`
    /// and `mem_span` describe the caller's guest mapping, which vsock ring
    /// walking reads through (see [`MmioDevice::merge_dirty_pages`]).
    pub fn merge_dirty_pages_all(&self, acc: &mut [u64], mem_host_addr: u64, mem_span: u64) {
        for dev in &self.devices {
            dev.lock()
                .unwrap()
                .merge_dirty_pages(acc, mem_host_addr, mem_span);
        }
    }
}

/// Serializable state of a single virtqueue (for snapshot).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtqueueSnapshot {
    /// Queue size chosen by the driver.
    pub size: u16,
    /// Whether the queue is ready.
    pub ready: bool,
    /// Descriptor table GPA.
    pub desc_addr: u64,
    /// Available ring GPA.
    pub avail_addr: u64,
    /// Used ring GPA.
    pub used_addr: u64,
}

/// Rebuild live queue state from a snapshot, taking `max_size` from the
/// device that is about to own the queues (`backend.max_queue_size()`).
///
/// `max_size` is a *device* constant the guest reads back through
/// `MMIO_QUEUE_NUM_MAX`. Copying the snapshot's `size` into it laundered
/// the driver's last choice into the device's own limit, so every forked
/// VM — and every pool member is a fork — reported its negotiated size as
/// the maximum and made the activation check a no-op
/// (`docs/bug-candidates.md` #45). The snapshot carries only `size`.
#[must_use]
pub fn restore_queues(snapshots: &[VirtqueueSnapshot], max_size: u16) -> Vec<VirtqueueState> {
    snapshots
        .iter()
        .map(|qs| VirtqueueState {
            max_size,
            size: qs.size,
            ready: qs.ready,
            desc_addr: GuestAddress(qs.desc_addr),
            avail_addr: GuestAddress(qs.avail_addr),
            used_addr: GuestAddress(qs.used_addr),
        })
        .collect()
}

/// Serializable state of a single MMIO device (for snapshot).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MmioDeviceState {
    /// Base MMIO address.
    pub base_addr: u64,
    /// IRQ number.
    pub irq: u32,
    /// Device type ID.
    pub device_type: u32,
    /// Device status register.
    pub device_status: u32,
    /// Acked features.
    pub acked_features: u64,
    /// Whether the device was activated.
    pub activated: bool,
    /// Whether this is a vhost device.
    pub is_vhost: bool,
    /// Virtqueue states.
    pub queues: Vec<VirtqueueSnapshot>,
    /// Interrupt status.
    pub interrupt_status: u32,
    /// Which bus the device was on. Absent in snapshots written before
    /// the PCI bus existed, which were all virtio-mmio.
    #[serde(default)]
    pub transport: Transport,
    /// The guest-programmed PCI registers; present iff `transport` is
    /// [`Transport::Pci`].
    #[serde(default)]
    pub pci: Option<PciFunctionState>,
    /// `device_feature_select` / `DeviceFeaturesSel`.
    #[serde(default)]
    pub features_sel: u32,
    /// `driver_feature_select` / `DriverFeaturesSel`.
    #[serde(default)]
    pub driver_features_sel: u32,
    /// `queue_select` / `QueueSel`.
    #[serde(default)]
    pub queue_sel: u32,
}

impl MmioDevice {
    /// Capture the current device state for snapshot.
    #[must_use]
    pub fn snapshot_state(&self) -> MmioDeviceState {
        MmioDeviceState {
            base_addr: self.base_addr,
            irq: self.irq,
            device_type: self.backend.device_type(),
            device_status: self.device_status,
            acked_features: self.acked_features,
            activated: self.activated,
            is_vhost: self.is_vhost,
            transport: self.transport(),
            pci: self.pci.as_ref().map(VirtioPciFunction::state),
            features_sel: self.features_sel,
            driver_features_sel: self.driver_features_sel,
            queue_sel: self.queue_sel,
            queues: self
                .queues
                .iter()
                .map(|q| VirtqueueSnapshot {
                    size: q.size,
                    ready: q.ready,
                    desc_addr: q.desc_addr.raw_value(),
                    avail_addr: q.avail_addr.raw_value(),
                    used_addr: q.used_addr.raw_value(),
                })
                .collect(),
            interrupt_status: self.interrupt_status.load(Ordering::SeqCst),
        }
    }
}

impl MmioDeviceRegistry {
    /// Snapshot all device states for serialization.
    #[must_use]
    pub fn snapshot_device_states(&self) -> Vec<MmioDeviceState> {
        self.devices
            .iter()
            .map(|dev| dev.lock().unwrap().snapshot_state())
            .collect()
    }
}

/// Shared MMIO device registry.
pub type SharedMmioRegistry = Arc<Mutex<MmioDeviceRegistry>>;

/// First PIC line handed to virtio devices (COM1 = 4, COM2 = 3). Device
/// `idx` takes `VIRTIO_IRQ_BASE + idx` on either transport.
pub const VIRTIO_IRQ_BASE: u32 = 5;

/// Where one virtio device sits: its virtio-mmio window or boot-time
/// BAR base, its PIC line, and — on the PCI bus — its slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Placement {
    /// virtio-mmio window base, or the BAR base the device boots with.
    pub base_addr: u64,
    /// PIC line (`PCI_INTERRUPT_LINE` on the PCI bus).
    pub irq: u32,
    /// Slot on PCI bus 0; `None` for virtio-mmio.
    pub pci_slot: Option<u8>,
}

impl Placement {
    /// The `idx`-th device (0-based, creation order) of a fresh VM on
    /// `transport`. Slot and IRQ budgets are the caller's to check.
    #[must_use]
    pub fn for_index(transport: Transport, idx: u32) -> Self {
        let irq = VIRTIO_IRQ_BASE + idx;
        match transport {
            Transport::Mmio => Self {
                base_addr: crate::mem_layout::MMIO_HOLE_START + u64::from(idx) * MMIO_DEVICE_SIZE,
                irq,
                pci_slot: None,
            },
            Transport::Pci => Self {
                base_addr: crate::pci::PCI_BAR_BASE + u64::from(idx) * crate::pci::PCI_BAR_STRIDE,
                irq,
                pci_slot: Some((idx + 1) as u8),
            },
        }
    }

    /// Where a snapshotted device sat. A `transport` tag that
    /// disagrees with the presence of PCI state is a corrupt snapshot.
    pub fn of_state(state: &MmioDeviceState) -> Result<Self, String> {
        let pci_slot = match (state.transport, &state.pci) {
            (Transport::Mmio, None) => None,
            (Transport::Pci, Some(p)) => Some(p.slot),
            (t, p) => {
                return Err(format!(
                    "device type {} snapshot says transport {t} but pci state is {}",
                    state.device_type,
                    if p.is_some() { "present" } else { "absent" }
                ))
            }
        };
        Ok(Self {
            base_addr: state.base_addr,
            irq: state.irq,
            pci_slot,
        })
    }

    /// Which bus this placement is on.
    #[must_use]
    pub fn transport(&self) -> Transport {
        if self.pci_slot.is_some() {
            Transport::Pci
        } else {
            Transport::Mmio
        }
    }
}

/// Wire one backend into a VM: irqfd on `placement.irq`, the device
/// object on the right bus, optional snapshot state, registry entry.
///
/// The one place a device is attached — the builder and both fork
/// rebuild paths go through it, so the PCI/MMIO choice is made here
/// and nowhere else. `make_backend` receives the irqfd because a
/// rebuilt backend activates against it *before* the device object
/// exists (the snapshot's queues, the seeded worker counters).
///
/// Every device is marked vhost: in-process workers signal the irqfd
/// themselves, so `INTERRUPT_STATUS` / ISR must always report
/// `INT_VRING`.
pub fn attach_device<B: VirtioBackend + 'static>(
    vm_fd: &VmFd,
    registry: &SharedMmioRegistry,
    placement: Placement,
    restore: Option<&MmioDeviceState>,
    make_backend: impl FnOnce(&Arc<EventFd>) -> Result<B, String>,
) -> Result<Arc<Mutex<MmioDevice>>, String> {
    let irq_evt =
        crate::fdutil::eventfd_cloexec(libc::EFD_NONBLOCK).map_err(|e| format!("eventfd: {e}"))?;
    vm_fd
        .register_irqfd(&irq_evt, placement.irq)
        .map_err(|e| format!("register irqfd for IRQ {}: {e}", placement.irq))?;
    let irq_evt = Arc::new(irq_evt);
    let backend = make_backend(&irq_evt)?;
    let mut dev = MmioDevice::new(
        placement.base_addr,
        placement.irq,
        irq_evt,
        Box::new(backend),
    );
    dev.set_vhost(true);
    if let Some(slot) = placement.pci_slot {
        dev.attach_pci(slot)?;
    }
    if let Some(state) = restore {
        dev.restore_state(state)?;
    }
    let dev = Arc::new(Mutex::new(dev));
    registry.lock().unwrap().add(Arc::clone(&dev));
    Ok(dev)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready_queue(desc: u64, avail: u64, used: u64) -> VirtqueueState {
        VirtqueueState {
            max_size: 256,
            size: 256,
            ready: true,
            desc_addr: GuestAddress(desc),
            avail_addr: GuestAddress(avail),
            used_addr: GuestAddress(used),
        }
    }

    fn is_dirty(acc: &[u64], page: u64) -> bool {
        acc[(page / 64) as usize] & (1u64 << (page % 64)) != 0
    }

    #[test]
    fn mark_gpa_range_covers_every_page_it_touches() {
        let mut acc = vec![0u64; 4];
        mark_gpa_range_dirty(&mut acc, 4090, 16);
        assert!(is_dirty(&acc, 0) && is_dirty(&acc, 1), "spans the boundary");
        assert!(!is_dirty(&acc, 2));
    }

    #[test]
    fn mark_gpa_range_ignores_a_range_past_the_bitmap() {
        let mut acc = vec![0u64; 1];
        mark_gpa_range_dirty(&mut acc, 1 << 40, 4096);
        assert_eq!(acc[0], 0);
    }

    #[test]
    fn mark_gpa_range_ignores_a_wrapping_range() {
        let mut acc = vec![0u64; 4];
        mark_gpa_range_dirty(&mut acc, u64::MAX - 16, 4096);
        assert_eq!(
            acc, [0; 4],
            "a wrapping range marks nothing, not the wrong pages"
        );
    }

    #[test]
    fn ring_pages_are_marked_when_no_descriptor_points_anywhere() {
        // 64 pages of zeroed guest RAM: every descriptor reads `addr = 0`,
        // so only the three rings are marked.
        let span = 64 * 4096;
        let mem = vec![0u8; span as usize];
        let mut acc = vec![0u64; 4];
        mark_virtqueue_pages_dirty(
            &[ready_queue(0x1000, 0x2000, 0x3000)],
            &mut acc,
            mem.as_ptr() as u64,
            span,
        );
        assert!(is_dirty(&acc, 1), "descriptor table");
        assert!(is_dirty(&acc, 2), "avail ring");
        assert!(is_dirty(&acc, 3), "used ring");
        assert!(!is_dirty(&acc, 5));
    }

    #[test]
    fn a_queue_the_guest_never_readied_is_skipped() {
        let mut acc = vec![0u64; 4];
        let mut q = ready_queue(0x1000, 0x2000, 0x3000);
        q.ready = false;
        mark_virtqueue_pages_dirty(&[q], &mut acc, 0, 0);
        assert_eq!(acc, [0; 4]);
    }

    #[test]
    fn an_unwalkable_queue_marks_nothing() {
        // Rings programmed past the end of RAM: nothing to mark, and the
        // device would have failed activation.
        let mut acc = vec![0u64; 4];
        mark_virtqueue_pages_dirty(
            &[ready_queue(1 << 40, 1 << 40, 1 << 40)],
            &mut acc,
            4096,
            4096,
        );
        assert_eq!(acc, [0; 4]);
    }

    /// Lay out `descs` at GPA `0x1000` in a fresh `span`-byte guest RAM.
    fn mem_with_descs(span: u64, descs: &[VirtqDesc]) -> Vec<u8> {
        let mut mem = vec![0u8; span as usize];
        for (i, d) in descs.iter().enumerate() {
            let at = 0x1000 + i * 16;
            mem[at..at + 8].copy_from_slice(&d.addr.to_le_bytes());
            mem[at + 8..at + 12].copy_from_slice(&d.len.to_le_bytes());
            mem[at + 12..at + 14].copy_from_slice(&d.flags.to_le_bytes());
            mem[at + 14..at + 16].copy_from_slice(&d.next.to_le_bytes());
        }
        mem
    }

    fn desc(addr: u64, len: u32, flags: u16, next: u16) -> VirtqDesc {
        VirtqDesc {
            addr,
            len,
            flags,
            next,
        }
    }

    #[test]
    fn descriptor_buffers_are_marked_and_bogus_ones_rejected() {
        // A one-descriptor queue whose buffer sits at page 8, plus a second
        // descriptor pointing outside the span and a third marked indirect.
        let span = 64 * 4096;
        let mem = mem_with_descs(
            span,
            &[
                desc(8 * 4096, 4096, 0, 0),
                desc(span + 4096, 4096, 0, 0),
                desc(9 * 4096, 4096, VIRTQ_DESC_F_INDIRECT, 0),
            ],
        );

        let mut q = ready_queue(0x1000, 0x2000, 0x3000);
        q.size = 4;
        let mut acc = vec![0u64; 1];
        mark_virtqueue_pages_dirty(&[q], &mut acc, mem.as_ptr() as u64, span);
        assert!(is_dirty(&acc, 8), "buffer of a plain descriptor");
        assert!(!is_dirty(&acc, 9), "indirect descriptor is not a buffer");
    }

    #[test]
    fn geometry_rejects_every_kind_of_hostile_size() {
        let span = 1 << 20;
        let mut q = ready_queue(0, 0x1000, 0x2000);
        q.size = 0;
        assert!(matches!(
            ValidatedQueue::new(&q, 0, span),
            Err(QueueGeometryError::ZeroSize)
        ));
        q.size = 65535;
        assert!(matches!(
            ValidatedQueue::new(&q, 0, span),
            Err(QueueGeometryError::SizeAboveMax {
                size: 65535,
                max: 256
            })
        ));
        q.size = 100;
        assert!(matches!(
            ValidatedQueue::new(&q, 0, span),
            Err(QueueGeometryError::SizeNotPowerOfTwo(100))
        ));
        q.size = 256;
        assert!(matches!(
            ValidatedQueue::new(&q, 0, 0),
            Err(QueueGeometryError::NoGuestMemory)
        ));
        assert!(ValidatedQueue::new(&q, 0, span).is_ok());
    }

    #[test]
    fn geometry_rejects_each_ring_crossing_the_end_of_ram() {
        // size 256 ⇒ desc 4096 bytes, avail 518, used 2054.
        let span = 1 << 20;
        let ok = ready_queue(0, 0x2000, 0x3000);
        assert!(ValidatedQueue::new(&ok, 0, span).is_ok());

        for (label, q) in [
            ("descriptor", ready_queue(span - 4095, 0x2000, 0x3000)),
            ("avail", ready_queue(0, span - 517, 0x3000)),
            ("used", ready_queue(0, 0x2000, span - 2053)),
            ("overflow", ready_queue(u64::MAX - 8, 0x2000, 0x3000)),
        ] {
            assert!(
                matches!(
                    ValidatedQueue::new(&q, 0, span),
                    Err(QueueGeometryError::RingOutOfRange { .. })
                ),
                "{label} ring crossing mem_span must be rejected"
            );
        }
    }

    #[test]
    fn walker_refuses_a_self_referential_chain() {
        let span = 64 * 4096;
        let mem = mem_with_descs(span, &[desc(4096, 16, VIRTQ_DESC_F_NEXT, 0)]);
        let mut q = ready_queue(0x1000, 0x2000, 0x3000);
        q.size = 4;
        let vq = ValidatedQueue::new(&q, mem.as_ptr() as u64, span).expect("geometry");
        let mut out = Vec::new();
        assert!(matches!(
            vq.walk_chain(0, &mut out),
            Err(DescChainError::TooLong(4))
        ));
    }

    #[test]
    fn walker_refuses_an_index_past_the_table_and_a_buffer_past_ram() {
        let span = 64 * 4096;
        let mem = mem_with_descs(
            span,
            &[
                desc(4096, 16, VIRTQ_DESC_F_NEXT, 9),
                desc(span, 16, 0, 0),
                desc(span - 8, 16, 0, 0),
            ],
        );
        let mut q = ready_queue(0x1000, 0x2000, 0x3000);
        q.size = 4;
        let vq = ValidatedQueue::new(&q, mem.as_ptr() as u64, span).expect("geometry");
        let mut out = Vec::new();
        assert!(matches!(
            vq.walk_chain(0, &mut out),
            Err(DescChainError::IndexOutOfRange { idx: 9, size: 4 })
        ));
        assert!(matches!(
            vq.walk_chain(1, &mut out),
            Err(DescChainError::BufferOutOfRange { idx: 1, .. })
        ));
        assert!(
            matches!(
                vq.walk_chain(2, &mut out),
                Err(DescChainError::BufferOutOfRange { idx: 2, .. })
            ),
            "addr + len must be checked, not just addr"
        );
        assert!(vq.desc(4).is_none(), "desc index == size is out of range");
    }

    #[test]
    fn walker_returns_a_well_formed_chain() {
        let span = 64 * 4096;
        let mem = mem_with_descs(
            span,
            &[
                desc(4096, 16, VIRTQ_DESC_F_NEXT, 1),
                desc(8192, 32, VIRTQ_DESC_F_WRITE, 0),
            ],
        );
        let mut q = ready_queue(0x1000, 0x2000, 0x3000);
        q.size = 4;
        let vq = ValidatedQueue::new(&q, mem.as_ptr() as u64, span).expect("geometry");
        let mut out = Vec::new();
        let chain = vq.walk_chain(0, &mut out).expect("well-formed chain");
        assert_eq!(chain.len(), 2);
        assert_eq!(
            (chain[0].addr, chain[0].len, chain[0].write),
            (4096, 16, false)
        );
        assert_eq!(
            (chain[1].addr, chain[1].len, chain[1].write),
            (8192, 32, true)
        );
    }

    struct StubBackend {
        parked: Arc<AtomicBool>,
        running: Arc<AtomicBool>,
        name: String,
    }

    impl VirtioBackend for StubBackend {
        fn device_type(&self) -> u32 {
            2
        }
        fn device_features(&self) -> u64 {
            0
        }
        fn ack_features(&mut self, _: u64) {}
        fn num_queues(&self) -> usize {
            1
        }
        fn max_queue_size(&self) -> u16 {
            256
        }
        fn guest_mapping(&self) -> (u64, u64) {
            (0, 4096)
        }
        fn read_config(&self, _: u64, _: &mut [u8]) {}
        fn write_config(&mut self, _: u64, _: &[u8]) {}
        fn activate(&mut self, _: &[VirtqueueState], _: &EventFd) -> Result<(), String> {
            Ok(())
        }
        fn queue_notify(&self, _: u32) {}
        fn wait_quiescent(&self) -> Result<(), NotQuiescent> {
            wait_for_park(&self.parked, &self.running, false, || self.name.clone())
        }
    }

    fn mmio_with(backend: StubBackend) -> Arc<Mutex<MmioDevice>> {
        let irq = crate::fdutil::eventfd_cloexec(0).expect("eventfd");
        Arc::new(Mutex::new(MmioDevice::new(
            0,
            5,
            Arc::new(irq),
            Box::new(backend),
        )))
    }

    #[test]
    fn wait_quiescent_all_names_a_never_parking_device() {
        let parked = Arc::new(AtomicBool::new(false));
        let running = Arc::new(AtomicBool::new(true));
        let mut reg = MmioDeviceRegistry::new();
        reg.add(mmio_with(StubBackend {
            parked,
            running: Arc::clone(&running),
            name: "virtio-blk (/tmp/wedged.img)".into(),
        }));
        let start = Instant::now();
        let missed = reg.wait_quiescent_all();
        let elapsed = start.elapsed();
        running.store(false, Ordering::SeqCst);
        assert_eq!(missed.len(), 1, "{missed:?}");
        assert_eq!(missed[0].device, "virtio-blk (/tmp/wedged.img)");
        assert!(
            elapsed >= QUIESCE_DEADLINE && elapsed < Duration::from_millis(400),
            "deadline must stay 200 ms (CHALLENGES #162), was {elapsed:?}"
        );
    }

    #[test]
    fn wait_quiescent_all_skips_a_device_that_parks_on_the_second_poll() {
        let parked = Arc::new(AtomicBool::new(false));
        let running = Arc::new(AtomicBool::new(true));
        let flag = Arc::clone(&parked);
        std::thread::spawn(move || {
            std::thread::sleep(PARK_POLL + PARK_POLL);
            flag.store(true, Ordering::SeqCst);
        });
        let mut reg = MmioDeviceRegistry::new();
        reg.add(mmio_with(StubBackend {
            parked,
            running: Arc::clone(&running),
            name: "virtio-blk (/tmp/ok.img)".into(),
        }));
        let missed = reg.wait_quiescent_all();
        running.store(false, Ordering::SeqCst);
        assert!(
            missed.is_empty(),
            "a worker that parks on the second poll must not be reported: {missed:?}"
        );
    }
}
