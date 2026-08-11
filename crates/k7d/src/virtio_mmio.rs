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
    /// OR the backend's device-DMA dirty page bitmap into `acc` (one bit
    /// per 4 KiB guest page, `u64` words).
    ///
    /// KVM dirty logging only sees vCPU writes; an in-process worker that
    /// writes guest memory through k7d's own mapping (virtio-blk reads,
    /// used-ring updates) must report those pages itself or warm forks on
    /// the `base.mem + dirty delta` path silently miss them (the host-side
    /// CHALLENGES.md #27 class of bug). Default: no-op (vhost devices force
    /// the full-memfd fork path instead).
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

    /// Merge the backend's device-DMA dirty pages into `acc` (see
    /// [`VirtioBackend::merge_dirty_pages`]).
    pub fn merge_dirty_pages(&self, acc: &mut [u64]) {
        self.backend.merge_dirty_pages(acc);
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

    /// Merge every backend's device-DMA dirty pages into `acc`.
    pub fn merge_dirty_pages_all(&self, acc: &mut [u64]) {
        for dev in &self.devices {
            dev.lock().unwrap().merge_dirty_pages(acc);
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
