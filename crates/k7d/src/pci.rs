//! A legacy PCI bus beside the virtio-mmio bus, selected per VM.
//!
//! The bus is what a kernel built without `CONFIG_VIRTIO_MMIO` (RHCOS,
//! every RHEL 9/10 x86 kernel) needs before it can see any k7d device.
//! It is deliberately the smallest bus Linux accepts without ACPI:
//!
//! - type-1 configuration access on I/O ports `0xCF8`/`0xCFC`, bus 0
//!   only, function 0 only ([`PciBus`]);
//! - a host bridge at `00:00.0`, because `pci_sanity_check`
//!   (`arch/x86/pci/direct.c`) believes in type-1 access only if bus 0
//!   holds one;
//! - one virtio-pci *modern* function per device at `00:01.0` upward,
//!   with a single 32-bit memory BAR carrying the four vendor
//!   capabilities ([`VirtioPciFunction`]);
//! - `INTx` on the same 8259 lines virtio-mmio uses today
//!   (`PCI_INTERRUPT_LINE = 5 + idx`), raised through the same irqfd.
//!   With `noapic` Linux keeps the line it reads from config space
//!   (`pirq_enable_irq`, `arch/x86/pci/irq.c`) and the PIC stays
//!   edge-triggered, which is what an irqfd pulse needs.
//!
//! No ACPI, no MSI-X, no legacy (I/O-port) virtio-pci, no hotplug. The
//! virtio status machine, queue validation and backends are the ones
//! [`crate::virtio_mmio::MmioDevice`] already owns; this module only
//! adds the second register decode in front of them.

use std::sync::atomic::Ordering;

use serde::{Deserialize, Serialize};
use vm_memory::{Address, GuestAddress};

use crate::virtio_mmio::MmioDevice;

/// First I/O port of the type-1 configuration window
/// (`CONFIG_ADDRESS`, 4 bytes).
pub const PCI_CONFIG_ADDRESS_PORT: u16 = 0xCF8;
/// `CONFIG_DATA`, 4 bytes.
pub const PCI_CONFIG_DATA_PORT: u16 = 0xCFC;
/// Last port of the configuration window.
pub const PCI_CONFIG_PORT_END: u16 = 0xCFF;

/// Guest-physical base of the first virtio-pci BAR. Above the
/// virtio-mmio windows (`MMIO_HOLE_START + idx * 4 KiB`, at most
/// `0xfe00_b000`) and well below the IOAPIC at `0xfec0_0000`; 31 slots
/// fit in 2 MiB.
pub const PCI_BAR_BASE: u64 = 0xfe80_0000;
/// Stride between consecutive devices' BARs.
pub const PCI_BAR_STRIDE: u64 = 0x1_0000;
/// Size of each device's single memory BAR.
pub const PCI_BAR_SIZE: u64 = 0x4000;

/// Highest slot number on bus 0 (host bridge is slot 0).
pub const PCI_MAX_SLOT: u8 = 31;

const PCI_VENDOR_INTEL: u16 = 0x8086;
/// Intel 440FX host bridge, the id kvmtool and QEMU i440fx expose.
const PCI_DEVICE_I440FX: u16 = 0x1237;
const PCI_CLASS_HOST_BRIDGE: u32 = 0x0006_0000;

/// Red Hat / virtio vendor id.
pub const PCI_VENDOR_VIRTIO: u16 = 0x1af4;
/// Modern virtio-pci device ids are `0x1040 + device type`.
const PCI_DEVICE_VIRTIO_BASE: u16 = 0x1040;
const VIRTIO_PCI_REVISION_MODERN: u8 = 1;

const PCI_STATUS_CAP_LIST: u16 = 0x0010;
const PCI_CAP_ID_VNDR: u8 = 0x09;
const PCI_CAPABILITY_LIST_START: usize = 0x40;

const PCI_COMMAND_MEMORY: u16 = 0x0002;
/// Command bits the guest may set: I/O, memory, bus master, parity,
/// SERR, `INTx` disable. Everything else reads back as zero.
const PCI_COMMAND_WRITABLE: u16 = 0x0547;

const OFF_COMMAND: usize = 0x04;
const OFF_BAR0: usize = 0x10;
const OFF_INTERRUPT_LINE: usize = 0x3c;

// virtio-pci capability types (virtio 1.x §4.1.4).
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

// Layout of the one BAR. Each region sits on its own page so a guest
// cannot reach a neighbour through a wide access.
const BAR_COMMON_OFFSET: u64 = 0x0000;
const BAR_COMMON_LEN: u64 = 0x40;
const BAR_ISR_OFFSET: u64 = 0x1000;
const BAR_ISR_LEN: u64 = 0x4;
const BAR_DEVICE_OFFSET: u64 = 0x2000;
const BAR_DEVICE_LEN: u64 = 0x1000;
const BAR_NOTIFY_OFFSET: u64 = 0x3000;
const BAR_NOTIFY_LEN: u64 = 0x1000;
/// Queue `q` is kicked at `BAR_NOTIFY_OFFSET + q * NOTIFY_OFF_MULTIPLIER`.
const NOTIFY_OFF_MULTIPLIER: u32 = 4;

// virtio_pci_common_cfg field offsets.
const COMMON_DEVICE_FEATURE_SELECT: u64 = 0;
const COMMON_DEVICE_FEATURE: u64 = 4;
const COMMON_DRIVER_FEATURE_SELECT: u64 = 8;
const COMMON_DRIVER_FEATURE: u64 = 12;
const COMMON_MSIX_CONFIG: u64 = 16;
const COMMON_NUM_QUEUES: u64 = 18;
const COMMON_DEVICE_STATUS: u64 = 20;
const COMMON_CONFIG_GENERATION: u64 = 21;
const COMMON_QUEUE_SELECT: u64 = 22;
const COMMON_QUEUE_SIZE: u64 = 24;
const COMMON_QUEUE_MSIX_VECTOR: u64 = 26;
const COMMON_QUEUE_ENABLE: u64 = 28;
const COMMON_QUEUE_NOTIFY_OFF: u64 = 30;
const COMMON_QUEUE_DESC: u64 = 32;
const COMMON_QUEUE_DRIVER: u64 = 40;
const COMMON_QUEUE_DEVICE: u64 = 48;
/// "No MSI-X vector" — what every `*_msix_vector` register reads.
const VIRTIO_MSI_NO_VECTOR: u16 = 0xffff;

/// Which bus a VM's virtio devices sit on. Chosen once per VM; the two
/// never mix inside one guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// virtio-mmio, version 2 — every k7d guest so far.
    #[default]
    Mmio,
    /// virtio-pci modern functions behind the legacy bus in this module.
    Pci,
}

impl std::fmt::Display for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Mmio => "mmio",
            Self::Pci => "pci",
        })
    }
}

/// The guest-programmed part of one PCI function, carried in
/// `MmioDeviceState` so a fork rebuilds the transport the guest's memory
/// already assumes instead of re-deriving it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PciFunctionState {
    /// Slot on bus 0 (`00:<slot>.0`).
    pub slot: u8,
    /// BAR 0 as the guest last wrote it (base address, low bits zero).
    pub bar0: u32,
    /// `PCI_COMMAND` (memory decode, bus master, `INTx` disable).
    pub command: u16,
    /// `PCI_INTERRUPT_LINE` as the guest sees it.
    pub interrupt_line: u8,
}

/// A 256-byte type-0 configuration header with per-byte write masks.
///
/// BAR sizing needs no special case: BAR 0's writable mask is
/// `!(size - 1)`, so the guest's `0xffff_ffff` probe reads back as the
/// size mask and its restore write lands as the base.
#[derive(Debug, Clone)]
pub struct PciConfigSpace {
    regs: [u8; 256],
    writable: [u8; 256],
    /// Offset of the next free capability byte, dword aligned.
    next_cap: usize,
    /// Offset of the previous capability's `cap_next` byte.
    last_cap_next: Option<usize>,
}

impl PciConfigSpace {
    /// A header with vendor/device/class/subsystem ids, no BARs, no
    /// capabilities, no interrupt pin.
    #[must_use]
    pub fn new(
        vendor: u16,
        device: u16,
        class_code: u32,
        revision: u8,
        subsystem_vendor: u16,
        subsystem_id: u16,
    ) -> Self {
        let mut cfg = Self {
            regs: [0; 256],
            writable: [0; 256],
            next_cap: PCI_CAPABILITY_LIST_START,
            last_cap_next: None,
        };
        cfg.put_u16(0x00, vendor);
        cfg.put_u16(0x02, device);
        cfg.regs[0x08] = revision;
        // class_code is `class << 16 | subclass << 8 | prog_if`.
        cfg.regs[0x09] = (class_code & 0xff) as u8;
        cfg.regs[0x0a] = ((class_code >> 8) & 0xff) as u8;
        cfg.regs[0x0b] = ((class_code >> 16) & 0xff) as u8;
        cfg.put_u16(0x2c, subsystem_vendor);
        cfg.put_u16(0x2e, subsystem_id);
        // Command: the guest's bits. Cache line size + latency timer:
        // Linux writes them (`pcibios_set_master`), nobody reads them.
        cfg.writable[OFF_COMMAND] = (PCI_COMMAND_WRITABLE & 0xff) as u8;
        cfg.writable[OFF_COMMAND + 1] = (PCI_COMMAND_WRITABLE >> 8) as u8;
        cfg.writable[0x0c] = 0xff;
        cfg.writable[0x0d] = 0xff;
        cfg
    }

    /// The host bridge at `00:00.0`.
    #[must_use]
    pub fn host_bridge() -> Self {
        Self::new(
            PCI_VENDOR_INTEL,
            PCI_DEVICE_I440FX,
            PCI_CLASS_HOST_BRIDGE,
            0,
            0,
            0,
        )
    }

    fn put_u16(&mut self, off: usize, v: u16) {
        self.regs[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn put_u32(&mut self, off: usize, v: u32) {
        self.regs[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn get_u16(&self, off: usize) -> u16 {
        u16::from_le_bytes([self.regs[off], self.regs[off + 1]])
    }

    fn get_u32(&self, off: usize) -> u32 {
        u32::from_le_bytes([
            self.regs[off],
            self.regs[off + 1],
            self.regs[off + 2],
            self.regs[off + 3],
        ])
    }

    /// Program BAR 0 as a 32-bit non-prefetchable memory BAR of `size`
    /// bytes (a power of two, at least 16) at `base`.
    pub fn set_bar0_mem32(&mut self, base: u32, size: u32) -> Result<(), String> {
        if !size.is_power_of_two() || size < 16 {
            return Err(format!("BAR size {size:#x} is not a power of two >= 16"));
        }
        if base & (size - 1) != 0 {
            return Err(format!("BAR base {base:#x} is not aligned to {size:#x}"));
        }
        let mask = !(size - 1);
        self.put_u32(OFF_BAR0, base);
        self.writable[OFF_BAR0..OFF_BAR0 + 4].copy_from_slice(&mask.to_le_bytes());
        Ok(())
    }

    /// Set the interrupt line and pin (`1` = INTA#).
    pub fn set_interrupt(&mut self, line: u8, pin: u8) {
        self.regs[OFF_INTERRUPT_LINE] = line;
        self.regs[OFF_INTERRUPT_LINE + 1] = pin;
        self.writable[OFF_INTERRUPT_LINE] = 0xff;
    }

    /// Append a capability. `body` starts at `cap_vndr` and already
    /// carries its own id; `cap_next` (byte 1) is overwritten here.
    pub fn add_capability(&mut self, body: &[u8]) -> Result<usize, String> {
        let len = (body.len() + 3) & !3;
        let off = self.next_cap;
        if body.len() < 2 || off + len > 256 {
            return Err(format!(
                "capability of {} bytes does not fit at {off:#x}",
                body.len()
            ));
        }
        self.regs[off..off + body.len()].copy_from_slice(body);
        self.regs[off + 1] = 0;
        if let Some(prev) = self.last_cap_next {
            self.regs[prev] = off as u8;
        } else {
            self.regs[0x34] = off as u8;
            let status = self.get_u16(0x06) | PCI_STATUS_CAP_LIST;
            self.put_u16(0x06, status);
        }
        self.last_cap_next = Some(off + 1);
        self.next_cap = off + len;
        Ok(off)
    }

    /// Read `data.len()` bytes at `offset`. Past the header reads as
    /// all-ones, like an absent function.
    pub fn read(&self, offset: usize, data: &mut [u8]) {
        for (i, b) in data.iter_mut().enumerate() {
            *b = self.regs.get(offset + i).copied().unwrap_or(0xff);
        }
    }

    /// Write `data` at `offset`, honouring the per-byte write masks.
    pub fn write(&mut self, offset: usize, data: &[u8]) {
        for (i, b) in data.iter().enumerate() {
            let Some(off) = offset.checked_add(i).filter(|o| *o < 256) else {
                return;
            };
            let mask = self.writable[off];
            self.regs[off] = (self.regs[off] & !mask) | (b & mask);
        }
    }

    /// `PCI_COMMAND`.
    #[must_use]
    pub fn command(&self) -> u16 {
        self.get_u16(OFF_COMMAND)
    }

    /// Overwrite `PCI_COMMAND` (restore only; masks still apply).
    pub fn set_command(&mut self, command: u16) {
        self.write(OFF_COMMAND, &command.to_le_bytes());
    }

    /// BAR 0 as the guest last programmed it.
    #[must_use]
    pub fn bar0(&self) -> u32 {
        self.get_u32(OFF_BAR0)
    }

    /// Overwrite BAR 0 (restore only; the size mask still applies).
    pub fn set_bar0(&mut self, bar0: u32) {
        self.write(OFF_BAR0, &bar0.to_le_bytes());
    }

    /// `PCI_INTERRUPT_LINE`.
    #[must_use]
    pub fn interrupt_line(&self) -> u8 {
        self.regs[OFF_INTERRUPT_LINE]
    }

    /// Overwrite `PCI_INTERRUPT_LINE` (restore only).
    pub fn set_interrupt_line(&mut self, line: u8) {
        self.regs[OFF_INTERRUPT_LINE] = line;
    }

    /// Whether memory-space decoding is enabled.
    #[must_use]
    pub fn memory_enabled(&self) -> bool {
        self.command() & PCI_COMMAND_MEMORY != 0
    }
}

/// What the `CONFIG_ADDRESS` latch currently points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigTarget {
    /// Slot on bus 0.
    pub slot: u8,
    /// Dword-aligned register offset in that function's header.
    pub offset: u8,
}

/// The type-1 configuration mechanism: the `0xCF8` address latch plus
/// the host bridge. Device functions live in the device registry; the
/// bus only decodes which one an access names.
#[derive(Debug, Clone)]
pub struct PciBus {
    address: u32,
    host_bridge: PciConfigSpace,
}

impl Default for PciBus {
    fn default() -> Self {
        Self::new()
    }
}

impl PciBus {
    /// An empty bus with the host bridge at `00:00.0`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            address: 0,
            host_bridge: PciConfigSpace::host_bridge(),
        }
    }

    /// Whether `port` belongs to the configuration window.
    #[must_use]
    pub fn handles_port(port: u16) -> bool {
        (PCI_CONFIG_ADDRESS_PORT..=PCI_CONFIG_PORT_END).contains(&port)
    }

    /// Guest read of `CONFIG_ADDRESS` (any width, any byte offset).
    pub fn read_address(&self, port: u16, data: &mut [u8]) {
        let bytes = self.address.to_le_bytes();
        let off = usize::from(port - PCI_CONFIG_ADDRESS_PORT);
        for (i, b) in data.iter_mut().enumerate() {
            *b = bytes.get(off + i).copied().unwrap_or(0);
        }
    }

    /// Guest write of `CONFIG_ADDRESS`.
    pub fn write_address(&mut self, port: u16, data: &[u8]) {
        let mut bytes = self.address.to_le_bytes();
        let off = usize::from(port - PCI_CONFIG_ADDRESS_PORT);
        for (i, b) in data.iter().enumerate() {
            if let Some(slot) = bytes.get_mut(off + i) {
                *slot = *b;
            }
        }
        // Bits 0-1 are reserved and always read as zero.
        self.address = u32::from_le_bytes(bytes) & !0b11;
    }

    /// Decode the latch: `None` when the enable bit is clear or the
    /// access names a bus or function this bridge does not have.
    #[must_use]
    pub fn target(&self) -> Option<ConfigTarget> {
        if self.address & 0x8000_0000 == 0 {
            return None;
        }
        let bus = (self.address >> 16) & 0xff;
        let slot = ((self.address >> 11) & 0x1f) as u8;
        let function = (self.address >> 8) & 0x7;
        if bus != 0 || function != 0 {
            return None;
        }
        Some(ConfigTarget {
            slot,
            offset: (self.address & 0xfc) as u8,
        })
    }

    /// Byte offset within the addressed dword for a `CONFIG_DATA` port.
    #[must_use]
    pub fn data_byte_offset(port: u16) -> usize {
        usize::from(port - PCI_CONFIG_DATA_PORT)
    }

    /// The host bridge's configuration header.
    #[must_use]
    pub fn host_bridge(&self) -> &PciConfigSpace {
        &self.host_bridge
    }

    /// Mutable host bridge header (guest writes land here).
    pub fn host_bridge_mut(&mut self) -> &mut PciConfigSpace {
        &mut self.host_bridge
    }
}

/// PCI class code for a virtio device type — what `lspci` prints next
/// to the function. Linux binds on vendor/device id and never reads it.
fn virtio_class_code(device_type: u32) -> u32 {
    match device_type {
        crate::virtio_mmio::VIRTIO_ID_NET => 0x0002_0000,
        2 => 0x0001_0000,  // virtio-blk: SCSI storage controller
        26 => 0x0001_8000, // virtio-fs: other mass storage
        _ => 0x0007_8000,  // vsock and the rest: other communication
    }
}

fn virtio_cap(cfg_type: u8, offset: u64, length: u64) -> [u8; 16] {
    let mut cap = [0u8; 16];
    cap[0] = PCI_CAP_ID_VNDR;
    cap[2] = 16;
    cap[3] = cfg_type;
    cap[4] = 0; // BAR 0
    cap[8..12].copy_from_slice(&(offset as u32).to_le_bytes());
    cap[12..16].copy_from_slice(&(length as u32).to_le_bytes());
    cap
}

/// The PCI side of one virtio device: its configuration header and
/// slot. The virtio registers behind the BAR are decoded by
/// [`MmioDevice::pci_bar_read`] / [`MmioDevice::pci_bar_write`].
#[derive(Debug, Clone)]
pub struct VirtioPciFunction {
    slot: u8,
    cfg: PciConfigSpace,
}

impl VirtioPciFunction {
    /// Build the header for device `device_type` in `slot`, with its BAR
    /// at `bar_base` and INTA# on `irq`.
    pub fn new(slot: u8, device_type: u32, bar_base: u64, irq: u32) -> Result<Self, String> {
        if slot == 0 || slot > PCI_MAX_SLOT {
            return Err(format!("PCI slot {slot} is not in 1..={PCI_MAX_SLOT}"));
        }
        let bar_base = u32::try_from(bar_base)
            .map_err(|_| format!("BAR base {bar_base:#x} is not a 32-bit address"))?;
        let irq = u8::try_from(irq).map_err(|_| format!("IRQ {irq} is not an 8259 line"))?;
        let device_id = PCI_DEVICE_VIRTIO_BASE
            + u16::try_from(device_type)
                .map_err(|_| format!("virtio device type {device_type} out of range"))?;
        let mut cfg = PciConfigSpace::new(
            PCI_VENDOR_VIRTIO,
            device_id,
            virtio_class_code(device_type),
            VIRTIO_PCI_REVISION_MODERN,
            PCI_VENDOR_VIRTIO,
            device_type as u16,
        );
        cfg.set_bar0_mem32(bar_base, PCI_BAR_SIZE as u32)?;
        cfg.set_interrupt(irq, 1);
        cfg.add_capability(&virtio_cap(
            VIRTIO_PCI_CAP_COMMON_CFG,
            BAR_COMMON_OFFSET,
            BAR_COMMON_LEN,
        ))?;
        cfg.add_capability(&virtio_cap(
            VIRTIO_PCI_CAP_ISR_CFG,
            BAR_ISR_OFFSET,
            BAR_ISR_LEN,
        ))?;
        cfg.add_capability(&virtio_cap(
            VIRTIO_PCI_CAP_DEVICE_CFG,
            BAR_DEVICE_OFFSET,
            BAR_DEVICE_LEN,
        ))?;
        let mut notify = [0u8; 20];
        notify[..16].copy_from_slice(&virtio_cap(
            VIRTIO_PCI_CAP_NOTIFY_CFG,
            BAR_NOTIFY_OFFSET,
            BAR_NOTIFY_LEN,
        ));
        notify[2] = 20;
        notify[16..20].copy_from_slice(&NOTIFY_OFF_MULTIPLIER.to_le_bytes());
        cfg.add_capability(&notify)?;
        Ok(Self { slot, cfg })
    }

    /// Slot on bus 0.
    #[must_use]
    pub fn slot(&self) -> u8 {
        self.slot
    }

    /// The configuration header.
    #[must_use]
    pub fn config(&self) -> &PciConfigSpace {
        &self.cfg
    }

    /// Mutable configuration header (guest writes land here).
    pub fn config_mut(&mut self) -> &mut PciConfigSpace {
        &mut self.cfg
    }

    /// The guest-physical window the BAR currently decodes, or `None`
    /// while memory decoding is off (the device must not respond).
    #[must_use]
    pub fn bar_window(&self) -> Option<(u64, u64)> {
        if !self.cfg.memory_enabled() {
            return None;
        }
        Some((u64::from(self.cfg.bar0() & !0xf), PCI_BAR_SIZE))
    }

    /// Capture the guest-programmed registers for a snapshot.
    #[must_use]
    pub fn state(&self) -> PciFunctionState {
        PciFunctionState {
            slot: self.slot,
            bar0: self.cfg.bar0(),
            command: self.cfg.command(),
            interrupt_line: self.cfg.interrupt_line(),
        }
    }

    /// Put the guest-programmed registers back.
    pub fn restore(&mut self, state: &PciFunctionState) -> Result<(), String> {
        if state.slot != self.slot {
            return Err(format!(
                "PCI state names slot {} but the device was rebuilt in slot {}",
                state.slot, self.slot
            ));
        }
        self.cfg.set_bar0(state.bar0);
        self.cfg.set_command(state.command);
        self.cfg.set_interrupt_line(state.interrupt_line);
        Ok(())
    }
}

fn le_bytes(val: u64, data: &mut [u8]) {
    let bytes = val.to_le_bytes();
    for (i, b) in data.iter_mut().enumerate() {
        *b = bytes.get(i).copied().unwrap_or(0);
    }
}

fn le_value(data: &[u8]) -> u64 {
    let mut v = 0u64;
    for (i, b) in data.iter().take(8).enumerate() {
        v |= u64::from(*b) << (i * 8);
    }
    v
}

impl MmioDevice {
    /// The `virtio_pci_common_cfg` structure as the guest would read it
    /// in one go. Built per access — sixteen fields — so a read of any
    /// width at any offset is one slice.
    fn common_cfg_image(&self) -> [u8; BAR_COMMON_LEN as usize] {
        let mut img = [0u8; BAR_COMMON_LEN as usize];
        let put = |img: &mut [u8], off: u64, v: u64, n: usize| {
            let off = off as usize;
            img[off..off + n].copy_from_slice(&v.to_le_bytes()[..n]);
        };
        put(
            &mut img,
            COMMON_DEVICE_FEATURE_SELECT,
            self.features_sel().into(),
            4,
        );
        put(
            &mut img,
            COMMON_DEVICE_FEATURE,
            self.device_features_word().into(),
            4,
        );
        put(
            &mut img,
            COMMON_DRIVER_FEATURE_SELECT,
            self.driver_features_sel().into(),
            4,
        );
        put(
            &mut img,
            COMMON_DRIVER_FEATURE,
            self.driver_features_word().into(),
            4,
        );
        put(&mut img, COMMON_MSIX_CONFIG, VIRTIO_MSI_NO_VECTOR.into(), 2);
        put(&mut img, COMMON_NUM_QUEUES, self.queues().len() as u64, 2);
        put(&mut img, COMMON_DEVICE_STATUS, self.status().into(), 1);
        put(
            &mut img,
            COMMON_CONFIG_GENERATION,
            self.config_generation().into(),
            1,
        );
        put(&mut img, COMMON_QUEUE_SELECT, self.queue_sel().into(), 2);
        if let Some(q) = self.selected_queue() {
            // Before the driver picks a size this reads the maximum
            // (virtio 1.x §4.1.4.3: "on reset, specifies the maximum
            // queue size supported by the device"); 0 means no queue.
            let size = if q.size == 0 { q.max_size } else { q.size };
            put(&mut img, COMMON_QUEUE_SIZE, size.into(), 2);
            put(&mut img, COMMON_QUEUE_ENABLE, u64::from(q.ready), 2);
            put(&mut img, COMMON_QUEUE_DESC, q.desc_addr.raw_value(), 8);
            put(&mut img, COMMON_QUEUE_DRIVER, q.avail_addr.raw_value(), 8);
            put(&mut img, COMMON_QUEUE_DEVICE, q.used_addr.raw_value(), 8);
        }
        put(
            &mut img,
            COMMON_QUEUE_MSIX_VECTOR,
            VIRTIO_MSI_NO_VECTOR.into(),
            2,
        );
        put(
            &mut img,
            COMMON_QUEUE_NOTIFY_OFF,
            self.queue_sel().into(),
            2,
        );
        img
    }

    /// Guest read at `offset` into this device's BAR.
    pub fn pci_bar_read(&self, offset: u64, data: &mut [u8]) {
        let len = data.len() as u64;
        if offset < BAR_COMMON_OFFSET + BAR_COMMON_LEN {
            if offset + len <= BAR_COMMON_LEN {
                let img = self.common_cfg_image();
                data.copy_from_slice(&img[offset as usize..(offset + len) as usize]);
            } else {
                data.fill(0);
            }
        } else if (BAR_ISR_OFFSET..BAR_ISR_OFFSET + BAR_ISR_LEN).contains(&offset) {
            // Read-to-clear: the ISR is also the INTx acknowledgement.
            le_bytes(self.isr_read_and_clear().into(), data);
        } else if (BAR_DEVICE_OFFSET..BAR_DEVICE_OFFSET + BAR_DEVICE_LEN).contains(&offset) {
            self.backend_read_config(offset - BAR_DEVICE_OFFSET, data);
        } else {
            data.fill(0);
        }
    }

    /// Guest write at `offset` into this device's BAR.
    pub fn pci_bar_write(&mut self, offset: u64, data: &[u8]) {
        let len = data.len() as u64;
        if offset < BAR_COMMON_OFFSET + BAR_COMMON_LEN {
            self.common_cfg_write(offset, data);
        } else if (BAR_DEVICE_OFFSET..BAR_DEVICE_OFFSET + BAR_DEVICE_LEN).contains(&offset) {
            self.backend_write_config(offset - BAR_DEVICE_OFFSET, data);
        } else if (BAR_NOTIFY_OFFSET..BAR_NOTIFY_OFFSET + BAR_NOTIFY_LEN).contains(&offset) {
            // The notify address names the queue (`queue_notify_off *
            // multiplier`); the value the driver writes is the same
            // index, so the address is what is trusted.
            let queue = ((offset - BAR_NOTIFY_OFFSET) / u64::from(NOTIFY_OFF_MULTIPLIER)) as u32;
            self.notify(queue);
        } else if (BAR_ISR_OFFSET..BAR_ISR_OFFSET + BAR_ISR_LEN).contains(&offset) {
            // ISR is read-only.
        } else {
            log::warn!(
                "virtio-pci (type={}): write of {len} bytes at BAR offset {offset:#x} ignored",
                self.device_type()
            );
        }
    }

    fn common_cfg_write(&mut self, offset: u64, data: &[u8]) {
        let val = le_value(data);
        let v32 = val as u32;
        match (offset, data.len()) {
            (COMMON_DEVICE_FEATURE_SELECT, 4) => self.set_features_sel(v32),
            (COMMON_DRIVER_FEATURE_SELECT, 4) => self.set_driver_features_sel(v32),
            (COMMON_DRIVER_FEATURE, 4) => self.write_driver_features_word(v32),
            (COMMON_DEVICE_STATUS, 1) => self.write_status(u32::from(data[0])),
            (COMMON_QUEUE_SELECT, 2) => self.select_queue(v32),
            (COMMON_QUEUE_SIZE, 2) => self.write_queue_size(v32),
            (COMMON_QUEUE_ENABLE, 2) => self.write_queue_ready(v32 == 1),
            // No MSI-X capability is advertised, so a vector write is a
            // driver bug; the register keeps reading NO_VECTOR.
            (COMMON_MSIX_CONFIG | COMMON_QUEUE_MSIX_VECTOR, 2) => {}
            (COMMON_QUEUE_DESC | COMMON_QUEUE_DRIVER | COMMON_QUEUE_DEVICE, 8) => {
                self.set_selected_queue_addr(offset, val);
            }
            (off, 4) if (COMMON_QUEUE_DESC..COMMON_QUEUE_DEVICE + 8).contains(&off) => {
                // Linux writes the 64-bit address registers as two
                // dwords (`vp_iowrite64_twopart`).
                let reg = off & !7;
                let Some(q) = self.selected_queue() else {
                    return;
                };
                let cur = match reg {
                    COMMON_QUEUE_DESC => q.desc_addr.raw_value(),
                    COMMON_QUEUE_DRIVER => q.avail_addr.raw_value(),
                    _ => q.used_addr.raw_value(),
                };
                let merged = if off & 4 == 0 {
                    (cur & !0xffff_ffff) | u64::from(v32)
                } else {
                    (cur & 0xffff_ffff) | (u64::from(v32) << 32)
                };
                self.set_selected_queue_addr(reg, merged);
            }
            (off, n) => log::warn!(
                "virtio-pci (type={}): unsupported common-cfg write of {n} bytes at {off:#x}",
                self.device_type()
            ),
        }
    }

    fn set_selected_queue_addr(&mut self, reg: u64, addr: u64) {
        if let Some(q) = self.selected_queue_mut() {
            match reg {
                COMMON_QUEUE_DESC => q.desc_addr = GuestAddress(addr),
                COMMON_QUEUE_DRIVER => q.avail_addr = GuestAddress(addr),
                _ => q.used_addr = GuestAddress(addr),
            }
        }
    }

    /// Guest read of this function's configuration header.
    pub fn pci_cfg_read(&self, offset: usize, data: &mut [u8]) {
        match self.pci_function() {
            Some(f) => f.config().read(offset, data),
            None => data.fill(0xff),
        }
    }

    /// Guest write to this function's configuration header.
    pub fn pci_cfg_write(&mut self, offset: usize, data: &[u8]) {
        let device_type = self.device_type();
        if let Some(f) = self.pci_function_mut() {
            let before = f.state();
            f.config_mut().write(offset, data);
            let after = f.state();
            if before.bar0 != after.bar0 || before.command != after.command {
                log::debug!(
                    "virtio-pci (type={device_type}) slot {}: bar0 {:#x} command {:#06x}",
                    after.slot,
                    after.bar0,
                    after.command
                );
            }
        }
    }

    /// Placement of the ISR interrupt-status bits: the ISR read must
    /// report pending config changes exactly as `INTERRUPT_STATUS` does.
    fn isr_read_and_clear(&self) -> u32 {
        let pending = self.interrupt_status().swap(0, Ordering::SeqCst);
        if self.is_vhost() {
            crate::virtio_mmio::INT_VRING | pending
        } else {
            pending
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_bridge_is_an_intel_host_bridge_without_bars() {
        let mut hb = PciConfigSpace::host_bridge();
        let mut v = [0u8; 4];
        hb.read(0, &mut v);
        assert_eq!(u16::from_le_bytes([v[0], v[1]]), PCI_VENDOR_INTEL);
        let mut class = [0u8; 4];
        hb.read(0x08, &mut class);
        assert_eq!((class[3], class[2]), (0x06, 0x00), "class HOST bridge");
        let mut bar = [0u8; 4];
        hb.write(OFF_BAR0, &0xffff_ffffu32.to_le_bytes());
        hb.read(OFF_BAR0, &mut bar);
        assert_eq!(bar, [0; 4], "no BAR: sizing reads back zero");
    }

    #[test]
    fn bar_sizing_and_relocation_follow_the_write_mask() {
        let mut cfg = PciConfigSpace::new(PCI_VENDOR_VIRTIO, 0x1042, 0x0001_0000, 1, 0, 0);
        cfg.set_bar0_mem32(0xfe80_0000, 0x4000).unwrap();
        assert_eq!(cfg.bar0(), 0xfe80_0000);
        cfg.write(OFF_BAR0, &0xffff_ffffu32.to_le_bytes());
        assert_eq!(cfg.bar0(), 0xffff_c000, "size probe reads the size mask");
        cfg.write(OFF_BAR0, &0xfe81_0000u32.to_le_bytes());
        assert_eq!(cfg.bar0(), 0xfe81_0000, "relocation lands");
        cfg.write(OFF_BAR0, &0xfe81_0123u32.to_le_bytes());
        assert_eq!(cfg.bar0(), 0xfe81_0000, "low bits are hardwired");
        assert!(cfg.set_bar0_mem32(0x1000, 0x3000).is_err());
        assert!(
            cfg.set_bar0_mem32(0x1000, 0x4000).is_err(),
            "misaligned base"
        );
    }

    #[test]
    fn command_honours_only_its_writable_bits() {
        let mut cfg = PciConfigSpace::new(1, 2, 3, 4, 5, 6);
        assert!(!cfg.memory_enabled());
        cfg.write(OFF_COMMAND, &0xffffu16.to_le_bytes());
        assert_eq!(cfg.command(), PCI_COMMAND_WRITABLE);
        assert!(cfg.memory_enabled());
        // Status is write-1-to-clear in hardware; here it is read-only.
        cfg.write(0x06, &0xffffu16.to_le_bytes());
        let mut st = [0u8; 2];
        cfg.read(0x06, &mut st);
        assert_eq!(st, [0, 0]);
    }

    #[test]
    fn capabilities_chain_from_the_status_bit() {
        let f = VirtioPciFunction::new(3, 2, PCI_BAR_BASE + PCI_BAR_STRIDE, 7).unwrap();
        let cfg = f.config();
        let mut st = [0u8; 2];
        cfg.read(0x06, &mut st);
        assert_ne!(u16::from_le_bytes(st) & PCI_STATUS_CAP_LIST, 0);
        let mut ptr = [0u8; 1];
        cfg.read(0x34, &mut ptr);
        let mut seen = Vec::new();
        let mut off = usize::from(ptr[0]);
        while off != 0 {
            let mut hdr = [0u8; 16];
            cfg.read(off, &mut hdr);
            assert_eq!(hdr[0], PCI_CAP_ID_VNDR);
            seen.push((
                hdr[3],
                u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]),
            ));
            off = usize::from(hdr[1]);
        }
        assert_eq!(
            seen,
            vec![
                (VIRTIO_PCI_CAP_COMMON_CFG, 0x0000),
                (VIRTIO_PCI_CAP_ISR_CFG, 0x1000),
                (VIRTIO_PCI_CAP_DEVICE_CFG, 0x2000),
                (VIRTIO_PCI_CAP_NOTIFY_CFG, 0x3000),
            ]
        );
        let mut mult = [0u8; 4];
        cfg.read(0x70 + 16, &mut mult);
        assert_eq!(u32::from_le_bytes(mult), NOTIFY_OFF_MULTIPLIER);
        let mut ids = [0u8; 4];
        cfg.read(0, &mut ids);
        assert_eq!(
            u16::from_le_bytes([ids[2], ids[3]]),
            0x1042,
            "blk = 0x1040 + 2"
        );
        let mut irq = [0u8; 2];
        cfg.read(OFF_INTERRUPT_LINE, &mut irq);
        assert_eq!(irq, [7, 1], "line 7, INTA#");
        assert!(f.bar_window().is_none(), "no decode until Command.MEM");
    }

    #[test]
    fn function_state_round_trips_and_refuses_the_wrong_slot() {
        let mut f = VirtioPciFunction::new(1, 1, PCI_BAR_BASE, 5).unwrap();
        f.config_mut().write(OFF_COMMAND, &0x0406u16.to_le_bytes());
        f.config_mut()
            .write(OFF_BAR0, &0xfe90_0000u32.to_le_bytes());
        let s = f.state();
        assert_eq!(
            s,
            PciFunctionState {
                slot: 1,
                bar0: 0xfe90_0000,
                command: 0x0406,
                interrupt_line: 5
            }
        );
        assert_eq!(f.bar_window(), Some((0xfe90_0000, PCI_BAR_SIZE)));
        let mut fresh = VirtioPciFunction::new(1, 1, PCI_BAR_BASE, 5).unwrap();
        fresh.restore(&s).unwrap();
        assert_eq!(fresh.state(), s);
        let mut other = VirtioPciFunction::new(2, 1, PCI_BAR_BASE, 5).unwrap();
        assert!(other.restore(&s).is_err());
        assert!(VirtioPciFunction::new(0, 1, PCI_BAR_BASE, 5).is_err());
        assert!(VirtioPciFunction::new(32, 1, PCI_BAR_BASE, 5).is_err());
    }

    #[test]
    fn config_address_decodes_type1_and_reads_back() {
        let mut bus = PciBus::new();
        assert!(bus.target().is_none(), "enable bit clear");
        // What `pci_check_type1` does: write 0x80000000, read it back.
        bus.write_address(PCI_CONFIG_ADDRESS_PORT, &0x8000_0000u32.to_le_bytes());
        let mut back = [0u8; 4];
        bus.read_address(PCI_CONFIG_ADDRESS_PORT, &mut back);
        assert_eq!(u32::from_le_bytes(back), 0x8000_0000);
        assert_eq!(bus.target(), Some(ConfigTarget { slot: 0, offset: 0 }));
        // bus 0, slot 3, fn 0, register 0x3c, with the reserved low bits set.
        bus.write_address(
            PCI_CONFIG_ADDRESS_PORT,
            &(0x8000_0000u32 | (3 << 11) | 0x3f).to_le_bytes(),
        );
        assert_eq!(
            bus.target(),
            Some(ConfigTarget {
                slot: 3,
                offset: 0x3c
            })
        );
        assert_eq!(PciBus::data_byte_offset(0xCFE), 2);
        // Function 1 and bus 1 are not here.
        bus.write_address(
            PCI_CONFIG_ADDRESS_PORT,
            &(0x8000_0000u32 | (1 << 8)).to_le_bytes(),
        );
        assert!(bus.target().is_none());
        bus.write_address(
            PCI_CONFIG_ADDRESS_PORT,
            &(0x8000_0000u32 | (1 << 16)).to_le_bytes(),
        );
        assert!(bus.target().is_none());
        // A byte write into the middle of the latch merges.
        bus.write_address(PCI_CONFIG_ADDRESS_PORT, &0x8000_0000u32.to_le_bytes());
        bus.write_address(PCI_CONFIG_ADDRESS_PORT + 1, &[0x08]);
        assert_eq!(bus.target().unwrap().slot, 1);
    }

    #[test]
    fn transport_serde_is_lowercase_and_defaults_to_mmio() {
        assert_eq!(serde_json::to_string(&Transport::Pci).unwrap(), "\"pci\"");
        assert_eq!(
            serde_json::from_str::<Transport>("\"mmio\"").unwrap(),
            Transport::Mmio
        );
        assert_eq!(Transport::default(), Transport::Mmio);
    }
}
