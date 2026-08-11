//! Intel MP (`MultiProcessor` Specification 1.4) table for SMP CPU
//! discovery — internal notes
//!
//! The guest kernel has ACPI compiled out, so the only way for Linux to
//! discover secondary CPUs is the legacy MP table. We write a Floating
//! Pointer Structure + configuration table at [`MPTABLE_START`]
//! (`0x9fc00`, the last KiB of conventional memory), which
//! `default_find_smp_config()` scans unconditionally (`639*0x400`).
//!
//! Layout and entry contents copy Firecracker's
//! `src/vmm/src/arch/x86_64/mptable.rs` (itself derived from CrosVM):
//! one processor entry per vCPU (BSP flag on CPU 0), one ISA bus, one
//! IOAPIC, one interrupt-source entry per legacy IRQ line, and the two
//! local-interrupt entries. The guest boots with `noapic`, so the
//! IOAPIC/intsrc entries are parsed but unused (PIC routing); the
//! processor entries are what make `nproc` report N.
//!
//! Only emitted when a VM is built with `vcpus > 1` — single-vCPU boots
//! stay byte-identical so snapshots and the fork/tree suites are
//! untouched (see `VmBuilder::build`).

use vm_memory::{Address, ByteValued, Bytes, GuestAddress, GuestMemoryMmap};

/// Guest physical address of the MP floating pointer structure: the
/// start of the last KiB of conventional memory (639 KiB), one of the
/// three ranges Linux's `default_find_smp_config()` scans. The E820 map
/// already ends usable low RAM here (`[0, 0x9fc00)`), so the table
/// lives outside guest-allocatable memory.
pub const MPTABLE_START: u64 = 0x9fc00;

/// Ceiling on vCPUs enforced by the table's placement: everything must
/// fit in the `[0x9fc00, 0xa0000)` KiB. `mptable_size(32)` = 924 bytes.
/// (The guest kernel's `CONFIG_NR_CPUS=16` is the practical limit.)
pub const MAX_SUPPORTED_CPUS: u8 = 32;

/// Legacy IRQ lines get one `mpc_intsrc` entry each (0..=15, the
/// PIC-era range Firecracker's `GSI_LEGACY_END` covers). Our
/// virtio-mmio IRQs 5..=23 are PIC-routed anyway (`noapic`), and the
/// PIC only has 16 lines.
const IRQ_MAX: u8 = 15;

// Intel MP Spec 1.4 constants (mirrors Linux's mpspec_def.h).
const SMP_MAGIC_IDENT: [u8; 4] = *b"_MP_";
const MPC_SIGNATURE: [u8; 4] = *b"PCMP";
const MPC_SPEC: i8 = 4;
const MPC_OEM: [u8; 8] = *b"K7D     ";
const MPC_PRODUCT_ID: [u8; 12] = *b"000000000000";
const BUS_TYPE_ISA: [u8; 6] = *b"ISA   ";
const IO_APIC_DEFAULT_PHYS_BASE: u32 = 0xfec0_0000;
const APIC_DEFAULT_PHYS_BASE: u32 = 0xfee0_0000;
const APIC_VERSION: u8 = 0x14;
const CPU_STEPPING: u32 = 0x600;
const CPU_FEATURE_APIC: u32 = 0x200;
const CPU_FEATURE_FPU: u32 = 0x001;

// Entry type tags.
const MP_PROCESSOR: u8 = 0;
const MP_BUS: u8 = 1;
const MP_IOAPIC: u8 = 2;
const MP_INTSRC: u8 = 3;
const MP_LINTSRC: u8 = 4;

// Processor entry flags.
const CPU_ENABLED: u8 = 1;
const CPU_BOOTPROCESSOR: u8 = 2;

// IOAPIC flags.
const MPC_APIC_USABLE: u8 = 1;

// Interrupt source types (`mp_irq_source_types`).
const MP_IRQ_INT: u8 = 0;
const MP_IRQ_NMI: u8 = 1;
const MP_IRQ_EXTINT: u8 = 3;
const MP_IRQPOL_DEFAULT: u16 = 0;

/// Errors from MP table construction.
#[derive(Debug, thiserror::Error)]
pub enum MptableError {
    /// The requested CPU count exceeds [`MAX_SUPPORTED_CPUS`].
    #[error("{0} vCPUs exceed the MP table maximum of {MAX_SUPPORTED_CPUS}")]
    TooManyCpus(u8),
    /// Guest memory write failed.
    #[error("failed to write MP table to guest memory: {0}")]
    WriteMem(vm_memory::GuestMemoryError),
}

// The MP structures below mirror Linux's `mpspec_def.h` layouts. All
// are `repr(C)` without implicit padding (verified by the size
// assertions in the tests), so treating them as plain bytes is sound.

/// MP floating pointer structure (`mpf_intel`), 16 bytes.
#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
struct MpfIntel {
    signature: [u8; 4],
    physptr: u32,
    length: u8,
    specification: u8,
    checksum: u8,
    feature1: u8,
    feature2: u8,
    feature3: u8,
    feature4: u8,
    feature5: u8,
}
// SAFETY: plain-old-data, no padding (4+4+8 = 16 bytes, align 4).
unsafe impl ByteValued for MpfIntel {}

/// MP configuration table header (`mpc_table`), 44 bytes.
#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
struct MpcTable {
    signature: [u8; 4],
    length: u16,
    spec: i8,
    checksum: i8,
    oem: [u8; 8],
    productid: [u8; 12],
    oemptr: u32,
    oemsize: u16,
    oemcount: u16,
    lapic: u32,
    reserved: u32,
}
// SAFETY: plain-old-data, no padding (44 bytes, align 4).
unsafe impl ByteValued for MpcTable {}

/// Processor entry (`mpc_cpu`), 20 bytes.
#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
struct MpcCpu {
    type_: u8,
    apicid: u8,
    apicver: u8,
    cpuflag: u8,
    cpufeature: u32,
    featureflag: u32,
    reserved: [u32; 2],
}
// SAFETY: plain-old-data, no padding (20 bytes, align 4).
unsafe impl ByteValued for MpcCpu {}

/// Bus entry (`mpc_bus`), 8 bytes.
#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
struct MpcBus {
    type_: u8,
    busid: u8,
    bustype: [u8; 6],
}
// SAFETY: plain-old-data, no padding (8 bytes, align 1).
unsafe impl ByteValued for MpcBus {}

/// IOAPIC entry (`mpc_ioapic`), 8 bytes.
#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
struct MpcIoapic {
    type_: u8,
    apicid: u8,
    apicver: u8,
    flags: u8,
    apicaddr: u32,
}
// SAFETY: plain-old-data, no padding (8 bytes, align 4).
unsafe impl ByteValued for MpcIoapic {}

/// Interrupt source entry (`mpc_intsrc`), 8 bytes.
#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
struct MpcIntsrc {
    type_: u8,
    irqtype: u8,
    irqflag: u16,
    srcbus: u8,
    srcbusirq: u8,
    dstapic: u8,
    dstirq: u8,
}
// SAFETY: plain-old-data, no padding (8 bytes, align 2).
unsafe impl ByteValued for MpcIntsrc {}

/// Local interrupt source entry (`mpc_lintsrc`), 8 bytes.
#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
struct MpcLintsrc {
    type_: u8,
    irqtype: u8,
    irqflag: u16,
    srcbusid: u8,
    srcbusirq: u8,
    destapic: u8,
    destapiclint: u8,
}
// SAFETY: plain-old-data, no padding (8 bytes, align 2).
unsafe impl ByteValued for MpcLintsrc {}

fn compute_checksum<T: ByteValued>(v: &T) -> u8 {
    v.as_slice().iter().fold(0u8, |a, &b| a.wrapping_add(b))
}

fn mpf_intel_compute_checksum(v: &MpfIntel) -> u8 {
    let checksum = compute_checksum(v).wrapping_sub(v.checksum);
    (!checksum).wrapping_add(1)
}

/// Total bytes the MP table occupies for `num_cpus` processors,
/// starting at [`MPTABLE_START`].
#[must_use]
pub fn mptable_size(num_cpus: u8) -> usize {
    std::mem::size_of::<MpfIntel>()
        + std::mem::size_of::<MpcTable>()
        + std::mem::size_of::<MpcCpu>() * usize::from(num_cpus)
        + std::mem::size_of::<MpcBus>()
        + std::mem::size_of::<MpcIoapic>()
        + std::mem::size_of::<MpcIntsrc>() * (usize::from(IRQ_MAX) + 1)
        + std::mem::size_of::<MpcLintsrc>() * 2
}

/// Write the MP table for `num_cpus` into guest memory at
/// [`MPTABLE_START`]. Returns the number of bytes written so the caller
/// can reserve the region in the E820 map.
#[allow(clippy::too_many_lines)] // linear table construction, one block per entry type
pub fn setup_mptable(mem: &GuestMemoryMmap, num_cpus: u8) -> Result<usize, MptableError> {
    if num_cpus > MAX_SUPPORTED_CPUS {
        return Err(MptableError::TooManyCpus(num_cpus));
    }
    let mp_size = mptable_size(num_cpus);
    // The IOAPIC gets the APIC ID after the last CPU (Firecracker
    // convention) so it never collides with a processor's LAPIC ID.
    let ioapicid: u8 = num_cpus + 1;

    let mut base_mp = GuestAddress(MPTABLE_START);
    let mut checksum: u8 = 0;
    let mut mp_num_entries: u16 = 0;

    mem.write_slice(&vec![0u8; mp_size], base_mp)
        .map_err(MptableError::WriteMem)?;

    {
        let size = std::mem::size_of::<MpfIntel>() as u64;
        let mut mpf = MpfIntel {
            signature: SMP_MAGIC_IDENT,
            physptr: (base_mp.raw_value() + size) as u32,
            length: 1,
            specification: 4,
            ..MpfIntel::default()
        };
        mpf.checksum = mpf_intel_compute_checksum(&mpf);
        mem.write_obj(mpf, base_mp)
            .map_err(MptableError::WriteMem)?;
        base_mp = base_mp.unchecked_add(size);
    }

    // The config table header is filled in last (its `length` covers
    // every entry that follows it).
    let table_base = base_mp;
    base_mp = base_mp.unchecked_add(std::mem::size_of::<MpcTable>() as u64);

    for cpu_id in 0..num_cpus {
        let cpu = MpcCpu {
            type_: MP_PROCESSOR,
            apicid: cpu_id,
            apicver: APIC_VERSION,
            cpuflag: CPU_ENABLED | if cpu_id == 0 { CPU_BOOTPROCESSOR } else { 0 },
            cpufeature: CPU_STEPPING,
            featureflag: CPU_FEATURE_APIC | CPU_FEATURE_FPU,
            ..MpcCpu::default()
        };
        mem.write_obj(cpu, base_mp)
            .map_err(MptableError::WriteMem)?;
        base_mp = base_mp.unchecked_add(std::mem::size_of::<MpcCpu>() as u64);
        checksum = checksum.wrapping_add(compute_checksum(&cpu));
        mp_num_entries += 1;
    }
    {
        let bus = MpcBus {
            type_: MP_BUS,
            busid: 0,
            bustype: BUS_TYPE_ISA,
        };
        mem.write_obj(bus, base_mp)
            .map_err(MptableError::WriteMem)?;
        base_mp = base_mp.unchecked_add(std::mem::size_of::<MpcBus>() as u64);
        checksum = checksum.wrapping_add(compute_checksum(&bus));
        mp_num_entries += 1;
    }
    {
        let ioapic = MpcIoapic {
            type_: MP_IOAPIC,
            apicid: ioapicid,
            apicver: APIC_VERSION,
            flags: MPC_APIC_USABLE,
            apicaddr: IO_APIC_DEFAULT_PHYS_BASE,
        };
        mem.write_obj(ioapic, base_mp)
            .map_err(MptableError::WriteMem)?;
        base_mp = base_mp.unchecked_add(std::mem::size_of::<MpcIoapic>() as u64);
        checksum = checksum.wrapping_add(compute_checksum(&ioapic));
        mp_num_entries += 1;
    }
    for i in 0..=IRQ_MAX {
        let intsrc = MpcIntsrc {
            type_: MP_INTSRC,
            irqtype: MP_IRQ_INT,
            irqflag: MP_IRQPOL_DEFAULT,
            srcbus: 0,
            srcbusirq: i,
            dstapic: ioapicid,
            dstirq: i,
        };
        mem.write_obj(intsrc, base_mp)
            .map_err(MptableError::WriteMem)?;
        base_mp = base_mp.unchecked_add(std::mem::size_of::<MpcIntsrc>() as u64);
        checksum = checksum.wrapping_add(compute_checksum(&intsrc));
        mp_num_entries += 1;
    }
    {
        let lintsrc = MpcLintsrc {
            type_: MP_LINTSRC,
            irqtype: MP_IRQ_EXTINT,
            irqflag: MP_IRQPOL_DEFAULT,
            srcbusid: 0,
            srcbusirq: 0,
            destapic: 0,
            destapiclint: 0,
        };
        mem.write_obj(lintsrc, base_mp)
            .map_err(MptableError::WriteMem)?;
        base_mp = base_mp.unchecked_add(std::mem::size_of::<MpcLintsrc>() as u64);
        checksum = checksum.wrapping_add(compute_checksum(&lintsrc));
        mp_num_entries += 1;
    }
    {
        let lintsrc = MpcLintsrc {
            type_: MP_LINTSRC,
            irqtype: MP_IRQ_NMI,
            irqflag: MP_IRQPOL_DEFAULT,
            srcbusid: 0,
            srcbusirq: 0,
            destapic: 0xff,
            destapiclint: 1,
        };
        mem.write_obj(lintsrc, base_mp)
            .map_err(MptableError::WriteMem)?;
        base_mp = base_mp.unchecked_add(std::mem::size_of::<MpcLintsrc>() as u64);
        checksum = checksum.wrapping_add(compute_checksum(&lintsrc));
        mp_num_entries += 1;
    }

    let table_end = base_mp;
    {
        let mut table = MpcTable {
            signature: MPC_SIGNATURE,
            length: table_end.unchecked_offset_from(table_base) as u16,
            spec: MPC_SPEC,
            oem: MPC_OEM,
            productid: MPC_PRODUCT_ID,
            oemcount: mp_num_entries,
            lapic: APIC_DEFAULT_PHYS_BASE,
            ..MpcTable::default()
        };
        debug_assert_eq!(
            usize::from(table.length) + std::mem::size_of::<MpfIntel>(),
            mp_size
        );
        checksum = checksum.wrapping_add(compute_checksum(&table));
        #[allow(clippy::cast_possible_wrap)]
        {
            table.checksum = (!checksum).wrapping_add(1) as i8;
        }
        mem.write_obj(table, table_base)
            .map_err(MptableError::WriteMem)?;
    }

    log::info!("mptable: {num_cpus} CPUs, {mp_size} bytes at {MPTABLE_START:#x}");
    Ok(mp_size)
}

#[cfg(kani)]
mod verification {
    use super::*;

    /// The table for any supported CPU count fits inside the last KiB
    /// of conventional memory (`[0x9fc00, 0xa0000)`), so it can never
    /// overlap guest-usable RAM or the EBDA boundary.
    #[kani::proof]
    fn verify_mptable_fits_below_640k() {
        let num_cpus: u8 = kani::any();
        kani::assume(num_cpus <= MAX_SUPPORTED_CPUS);
        let size = mptable_size(num_cpus);
        assert!(MPTABLE_START + size as u64 <= 0xa0000);
    }

    /// `mptable_size` is monotone in the CPU count and never overflows.
    #[kani::proof]
    fn verify_mptable_size_monotone() {
        let a: u8 = kani::any();
        let b: u8 = kani::any();
        kani::assume(a <= b && b <= MAX_SUPPORTED_CPUS);
        assert!(mptable_size(a) <= mptable_size(b));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_mem() -> GuestMemoryMmap {
        // Cover [0, 1 MiB) so MPTABLE_START is in range.
        GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10_0000)]).unwrap()
    }

    #[test]
    fn struct_sizes_match_mpspec() {
        assert_eq!(std::mem::size_of::<MpfIntel>(), 16);
        assert_eq!(std::mem::size_of::<MpcTable>(), 44);
        assert_eq!(std::mem::size_of::<MpcCpu>(), 20);
        assert_eq!(std::mem::size_of::<MpcBus>(), 8);
        assert_eq!(std::mem::size_of::<MpcIoapic>(), 8);
        assert_eq!(std::mem::size_of::<MpcIntsrc>(), 8);
        assert_eq!(std::mem::size_of::<MpcLintsrc>(), 8);
    }

    #[test]
    fn too_many_cpus_rejected() {
        let mem = test_mem();
        assert!(matches!(
            setup_mptable(&mem, MAX_SUPPORTED_CPUS + 1).unwrap_err(),
            MptableError::TooManyCpus(n) if n == MAX_SUPPORTED_CPUS + 1
        ));
    }

    #[test]
    fn mpf_intel_checksum_valid() {
        let mem = test_mem();
        setup_mptable(&mem, 2).unwrap();
        let mpf: MpfIntel = mem.read_obj(GuestAddress(MPTABLE_START)).unwrap();
        assert_eq!(mpf.signature, SMP_MAGIC_IDENT);
        assert_eq!(mpf_intel_compute_checksum(&mpf), mpf.checksum);
    }

    #[test]
    fn mpc_table_checksum_valid() {
        let mem = test_mem();
        let size = setup_mptable(&mem, 4).unwrap();
        assert_eq!(size, mptable_size(4));
        let mpf: MpfIntel = mem.read_obj(GuestAddress(MPTABLE_START)).unwrap();
        let table_addr = GuestAddress(u64::from(mpf.physptr));
        let table: MpcTable = mem.read_obj(table_addr).unwrap();
        assert_eq!(table.signature, MPC_SIGNATURE);
        // The byte sum of the whole config table must be zero.
        let mut buf = vec![0u8; usize::from(table.length)];
        mem.read_slice(&mut buf, table_addr).unwrap();
        assert_eq!(buf.iter().fold(0u8, |a, &b| a.wrapping_add(b)), 0);
    }

    #[test]
    fn cpu_entries_match_count_and_bsp_flag() {
        let mem = test_mem();
        for n in 1..=8u8 {
            setup_mptable(&mem, n).unwrap();
            let mpf: MpfIntel = mem.read_obj(GuestAddress(MPTABLE_START)).unwrap();
            let table_addr = GuestAddress(u64::from(mpf.physptr));
            let table: MpcTable = mem.read_obj(table_addr).unwrap();
            let mut offset = table_addr.unchecked_add(std::mem::size_of::<MpcTable>() as u64);
            let end = table_addr.unchecked_add(u64::from(table.length));
            let mut cpus = 0u8;
            while offset < end {
                let entry_type: u8 = mem.read_obj(offset).unwrap();
                let entry_size = match entry_type {
                    MP_PROCESSOR => {
                        let cpu: MpcCpu = mem.read_obj(offset).unwrap();
                        assert_eq!(cpu.apicid, cpus, "APIC IDs must be 0..n in order");
                        let want_bsp = if cpus == 0 { CPU_BOOTPROCESSOR } else { 0 };
                        assert_eq!(cpu.cpuflag, CPU_ENABLED | want_bsp);
                        cpus += 1;
                        std::mem::size_of::<MpcCpu>()
                    }
                    MP_BUS => std::mem::size_of::<MpcBus>(),
                    MP_IOAPIC => std::mem::size_of::<MpcIoapic>(),
                    MP_INTSRC => std::mem::size_of::<MpcIntsrc>(),
                    MP_LINTSRC => std::mem::size_of::<MpcLintsrc>(),
                    other => panic!("unknown MP entry type {other}"),
                };
                offset = offset.unchecked_add(entry_size as u64);
            }
            assert_eq!(cpus, n);
        }
    }
}
