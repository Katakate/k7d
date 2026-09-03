//! Virtio-MMIO transport layer.
//!
//! Implements the virtio-MMIO register interface (virtio 1.x, non-legacy)
//! so the guest kernel can discover and configure virtio devices.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use vm_memory::{Address, GuestAddress};
use vmm_sys_util::eventfd::EventFd;

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
const INT_VRING: u32 = 0x01;
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
    /// Block (bounded) until the backend's paused workers have stopped
    /// touching guest memory.
    ///
    /// Called by `Vm::pause` after `set_paused(true)` and the vCPU join so
    /// that snapshot/fork memory captures never race in-flight device DMA
    /// (e.g. a virtio-blk read completing mid-memcpy). Default: no-op.
    fn wait_quiescent(&self) {}
    /// Whether paused workers have stopped touching the backing file
    /// and guest memory. Default true (no worker). Used so a fork can
    /// delay `FICLONE` until a stuck virtio-blk `pwrite` finishes —
    /// cloning an 8 GiB scratch while the worker holds the inode has
    /// been measured at 4–7 s (CHALLENGES #162).
    fn is_quiescent(&self) -> bool {
        true
    }
    /// OR the backend's device-DMA dirty page bitmap into `acc` (one bit
    /// per 4 KiB guest page, `u64` words).
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
        }
    }

    /// Mark this device as a vhost device (`interrupt_status` always shows `INT_VRING`).
    pub fn set_vhost(&mut self, is_vhost: bool) {
        self.is_vhost = is_vhost;
    }

    /// Get the interrupt status (for injection from backend).
    #[must_use]
    pub fn interrupt_status(&self) -> Arc<AtomicU32> {
        Arc::clone(&self.interrupt_status)
    }

    /// Get the IRQ eventfd (for injection from backend).
    #[must_use]
    pub fn irq_eventfd(&self) -> Arc<EventFd> {
        Arc::clone(&self.irq_evt)
    }

    fn selected_queue(&self) -> Option<&VirtqueueState> {
        self.queues.get(self.queue_sel as usize)
    }

    fn selected_queue_mut(&mut self) -> Option<&mut VirtqueueState> {
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
            MMIO_DEVICE_FEATURES => {
                let mut features = self.backend.device_features();
                features |= VIRTIO_F_VERSION_1;
                if self.features_sel == 0 {
                    features as u32
                } else {
                    (features >> 32) as u32
                }
            }
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
            MMIO_DEVICE_FEATURES_SEL => self.features_sel = val,
            MMIO_DRIVER_FEATURES => {
                if self.features_ok() || self.device_status & STATUS_DRIVER != 0 {
                    let word = if self.driver_features_sel == 0 {
                        val as u64
                    } else {
                        (val as u64) << 32
                    };
                    self.acked_features |= word;
                }
            }
            MMIO_DRIVER_FEATURES_SEL => self.driver_features_sel = val,
            MMIO_QUEUE_SEL => self.queue_sel = val,
            MMIO_QUEUE_NUM => {
                if self.features_ok() || self.device_status & STATUS_DRIVER != 0 {
                    if let Some(q) = self.selected_queue_mut() {
                        q.size = (val & 0xffff) as u16;
                    }
                }
            }
            MMIO_QUEUE_READY => {
                if let Some(q) = self.selected_queue_mut() {
                    q.ready = val == 1;
                }
            }
            MMIO_QUEUE_NOTIFY => {
                if self.activated {
                    self.backend.queue_notify(val);
                }
            }
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

    /// Restore MMIO register state from a snapshot (without activating backend).
    ///
    /// Used during VM restore after the backend has been separately activated
    /// with correct vring base indices. This sets the MMIO device status,
    /// features, and queue addresses so the guest kernel's MMIO reads return
    /// the expected values.
    pub fn restore_state(&mut self, state: &MmioDeviceState) {
        self.device_status = state.device_status;
        self.acked_features = state.acked_features;
        self.activated = state.activated;

        for (i, qs) in state.queues.iter().enumerate() {
            if i < self.queues.len() {
                self.queues[i].size = qs.size;
                self.queues[i].ready = qs.ready;
                self.queues[i].desc_addr = GuestAddress(qs.desc_addr);
                self.queues[i].avail_addr = GuestAddress(qs.avail_addr);
                self.queues[i].used_addr = GuestAddress(qs.used_addr);
            }
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
    pub fn wait_quiescent(&self) {
        self.backend.wait_quiescent();
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
/// flight" .
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

/// Virtio descriptor flag: the descriptor points at an indirect table, not
/// at a buffer.
const VIRTQ_DESC_F_INDIRECT: u16 = 4;

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
    for q in queues {
        if !q.ready || q.size == 0 {
            continue;
        }
        let n = u64::from(q.size);
        let desc_gpa = q.desc_addr.raw_value();
        mark_gpa_range_dirty(acc, desc_gpa, n * 16);
        mark_gpa_range_dirty(acc, q.avail_addr.raw_value(), 6 + n * 2);
        mark_gpa_range_dirty(acc, q.used_addr.raw_value(), 6 + n * 8);
        if mem_host_addr == 0 || mem_span == 0 {
            continue;
        }
        for i in 0..n {
            let desc_hva = mem_host_addr + desc_gpa + i * 16;
            // SAFETY: desc_hva is a descriptor of a ready virtqueue inside the
            // caller's live guest mapping, which outlives this call. The caller
            // has paused the vCPUs, so the guest is not rewriting the table.
            let (buf_gpa, buf_len, flags) = unsafe {
                (
                    std::ptr::read_volatile(desc_hva as *const u64),
                    u64::from(std::ptr::read_volatile((desc_hva + 8) as *const u32)),
                    std::ptr::read_volatile((desc_hva + 12) as *const u16),
                )
            };
            // An indirect descriptor's `addr` is a descriptor table, not a
            // buffer; the ring pages above already cover what vhost writes.
            if flags & VIRTQ_DESC_F_INDIRECT != 0 || buf_gpa == 0 || buf_len == 0 {
                continue;
            }
            if buf_gpa >= mem_span || buf_len > mem_span - buf_gpa {
                continue;
            }
            mark_gpa_range_dirty(acc, buf_gpa, buf_len);
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
    let first = gpa / 4096;
    let last = (gpa + len - 1) / 4096;
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

/// Registry of MMIO devices for the vCPU run loop dispatcher.
pub struct MmioDeviceRegistry {
    devices: Vec<Arc<Mutex<MmioDevice>>>,
}

impl MmioDeviceRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            devices: Vec::new(),
        }
    }

    /// Register a device.
    pub fn add(&mut self, device: Arc<Mutex<MmioDevice>>) {
        self.devices.push(device);
    }

    /// Dispatch an MMIO read to the appropriate device.
    #[must_use]
    pub fn handle_read(&self, addr: u64, data: &mut [u8]) -> bool {
        for dev in &self.devices {
            let dev = dev.lock().unwrap();
            if addr >= dev.base_addr && addr < dev.base_addr + MMIO_DEVICE_SIZE {
                let offset = addr - dev.base_addr;
                dev.mmio_read(offset, data);
                log::trace!("mmio read addr={addr:#x} offset={offset:#x}");
                return true;
            }
        }
        false
    }

    /// Dispatch an MMIO write to the appropriate device.
    #[must_use]
    pub fn handle_write(&self, addr: u64, data: &[u8]) -> bool {
        for dev in &self.devices {
            let mut dev = dev.lock().unwrap();
            if addr >= dev.base_addr && addr < dev.base_addr + MMIO_DEVICE_SIZE {
                let offset = addr - dev.base_addr;
                log::trace!("mmio write addr={addr:#x} offset={offset:#x}");
                dev.mmio_write(offset, data);
                return true;
            }
        }
        false
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
    pub fn wait_quiescent_all(&self) {
        for dev in &self.devices {
            dev.lock().unwrap().wait_quiescent();
        }
    }

    /// True when every backend reports [`VirtioBackend::is_quiescent`].
    #[must_use]
    pub fn all_quiescent(&self) -> bool {
        self.devices
            .iter()
            .all(|d| d.lock().unwrap().is_quiescent())
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
    fn ring_pages_are_marked_without_a_mapping_to_walk() {
        let mut acc = vec![0u64; 4];
        mark_virtqueue_pages_dirty(&[ready_queue(0x1000, 0x2000, 0x3000)], &mut acc, 0, 0);
        assert!(is_dirty(&acc, 1), "descriptor table");
        assert!(is_dirty(&acc, 2), "avail ring");
        assert!(is_dirty(&acc, 3), "used ring");
        assert!(!is_dirty(&acc, 4));
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
    fn descriptor_buffers_are_marked_and_bogus_ones_rejected() {
        // A one-descriptor queue whose buffer sits at page 8, plus a second
        // descriptor pointing outside the span and a third marked indirect.
        let span = 64 * 4096;
        let mut mem = vec![0u8; span as usize];
        let write_desc = |mem: &mut [u8], i: usize, addr: u64, len: u32, flags: u16| {
            let at = 0x1000 + i * 16;
            mem[at..at + 8].copy_from_slice(&addr.to_le_bytes());
            mem[at + 8..at + 12].copy_from_slice(&len.to_le_bytes());
            mem[at + 12..at + 14].copy_from_slice(&flags.to_le_bytes());
        };
        write_desc(&mut mem, 0, 8 * 4096, 4096, 0);
        write_desc(&mut mem, 1, span + 4096, 4096, 0);
        write_desc(&mut mem, 2, 9 * 4096, 4096, VIRTQ_DESC_F_INDIRECT);

        let mut q = ready_queue(0x1000, 0x2000, 0x3000);
        q.size = 3;
        let mut acc = vec![0u64; 1];
        mark_virtqueue_pages_dirty(&[q], &mut acc, mem.as_ptr() as u64, span);
        assert!(is_dirty(&acc, 8), "buffer of a plain descriptor");
        assert!(!is_dirty(&acc, 9), "indirect descriptor is not a buffer");
    }
}
