//! Guest physical memory layout.
//!
//! Guest RAM is not one contiguous block at GPA 0: the x86 platform
//! pins a handful of MMIO windows just below the 4 GiB boundary, and
//! RAM that aliased them would be silently shadowed by the device.
//! Everything below [`MMIO_HOLE_START`] is RAM; the hole
//! `[MMIO_HOLE_START, HIGH_MEM_START)` holds
//!
//! * the virtio-mmio device windows (`MMIO_HOLE_START + idx * 4 KiB`),
//! * KVM's in-kernel IOAPIC (`0xfec0_0000`) and LAPIC (`0xfee0_0000`),
//! * KVM's identity-map page and TSS (`0xfffb_c000..0xfffc_0000`) —
//!   which `KVM_SET_TSS_ADDR` documents must sit outside guest memory,
//!
//! and any RAM past the hole resumes at [`HIGH_MEM_START`], exactly as
//! on a PC with more than ~4 GiB installed.
//!
//! The host mapping stays **linear**: one mapping of [`MemLayout::span`]
//! bytes where a guest physical address `gpa` always lives at host
//! address `base + gpa`, with the hole left as untouched (sparse) pages
//! of the backing memfd. Every virtio backend can therefore keep
//! translating with a single addition, and snapshots/forks keep treating
//! guest memory as one blob — of `span` rather than RAM bytes.
//!
//! Guests that fit entirely below the hole (`ram <= MMIO_HOLE_START`)
//! get exactly the original layout: one RAM region, `span == ram`, no
//! high region.

/// Start of the 32-bit MMIO hole. Guest RAM never crosses this GPA.
pub const MMIO_HOLE_START: u64 = 0xfe00_0000;

/// First GPA past the 32-bit hole; guest RAM above the hole resumes here.
pub const HIGH_MEM_START: u64 = 0x1_0000_0000;

/// Split of a requested guest RAM size into the low (sub-hole) and high
/// (past-4 GiB) regions. Construct with [`MemLayout::from_ram`] (from a
/// requested RAM size) or [`MemLayout::from_span`] (from a recorded
/// mapping span, e.g. a snapshot's `memory.bin` length).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemLayout {
    /// RAM below the hole: `min(ram, MMIO_HOLE_START)`, at GPA 0.
    pub low_size: u64,
    /// RAM above the hole: `ram - low_size`, at [`HIGH_MEM_START`].
    pub high_size: u64,
}

impl MemLayout {
    /// Split `ram` bytes of guest RAM across the hole.
    #[must_use]
    pub const fn from_ram(ram: u64) -> Self {
        let low_size = if ram < MMIO_HOLE_START {
            ram
        } else {
            MMIO_HOLE_START
        };
        Self {
            low_size,
            high_size: ram - low_size,
        }
    }

    /// Recover the layout from a mapping span (the inverse of
    /// [`Self::span`]). A span at or below [`MMIO_HOLE_START`] is a
    /// legacy single-region guest; anything larger must be a
    /// two-region guest, so a span that lands inside the hole is
    /// impossible and reported loudly.
    pub fn from_span(span: u64) -> Result<Self, String> {
        if span <= MMIO_HOLE_START {
            return Ok(Self {
                low_size: span,
                high_size: 0,
            });
        }
        if span <= HIGH_MEM_START {
            return Err(format!(
                "guest memory span {span:#x} lands inside the 32-bit MMIO hole \
                 [{MMIO_HOLE_START:#x}, {HIGH_MEM_START:#x}) — not a layout k7d produces"
            ));
        }
        Ok(Self {
            low_size: MMIO_HOLE_START,
            high_size: span - HIGH_MEM_START,
        })
    }

    /// Total guest RAM in bytes (what the guest reports as `MemTotal`
    /// before kernel reservations).
    #[must_use]
    pub const fn ram_size(&self) -> u64 {
        self.low_size + self.high_size
    }

    /// Length of the guest physical address space, and therefore of the
    /// host mapping / `memory.bin` / dirty bitmaps: RAM plus the hole
    /// when a high region exists.
    #[must_use]
    pub const fn span(&self) -> u64 {
        if self.high_size == 0 {
            self.low_size
        } else {
            HIGH_MEM_START + self.high_size
        }
    }

    /// Whether this guest has RAM past the 32-bit hole.
    #[must_use]
    pub const fn has_high_mem(&self) -> bool {
        self.high_size > 0
    }

    /// The KVM memory slots for this layout as `(slot, gpa, size)`.
    /// Because the host mapping is linear, each slot's `userspace_addr`
    /// is `mapping_base + gpa`.
    #[must_use]
    pub fn slots(&self) -> Vec<(u32, u64, u64)> {
        let mut slots = vec![(0, 0, self.low_size)];
        if self.high_size > 0 {
            slots.push((1, HIGH_MEM_START, self.high_size));
        }
        slots
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_guests_keep_the_pre_19a_layout() {
        for mb in [1u64, 128, 256, 3072, 4063] {
            let l = MemLayout::from_ram(mb * 1024 * 1024);
            assert_eq!(l.high_size, 0, "{mb} MiB must stay single-region");
            assert_eq!(l.span(), l.ram_size());
            assert_eq!(l.slots(), vec![(0, 0, mb * 1024 * 1024)]);
        }
    }

    #[test]
    fn large_guests_split_across_the_hole() {
        let l = MemLayout::from_ram(8 * 1024 * 1024 * 1024);
        assert_eq!(l.low_size, MMIO_HOLE_START);
        assert_eq!(l.high_size, 8 * 1024 * 1024 * 1024 - MMIO_HOLE_START);
        assert_eq!(l.ram_size(), 8 * 1024 * 1024 * 1024);
        assert_eq!(l.span(), HIGH_MEM_START + l.high_size);
        assert_eq!(
            l.slots(),
            vec![(0, 0, MMIO_HOLE_START), (1, HIGH_MEM_START, l.high_size),]
        );
    }

    #[test]
    fn span_round_trips_to_the_same_layout() {
        for mb in [128u64, 4063, 4064, 4065, 4160, 8256, 65536] {
            let l = MemLayout::from_ram(mb * 1024 * 1024);
            assert_eq!(
                MemLayout::from_span(l.span()).expect("span is well-formed"),
                l,
                "{mb} MiB round trip"
            );
        }
    }

    #[test]
    fn spans_inside_the_hole_are_rejected() {
        assert!(MemLayout::from_span(MMIO_HOLE_START + 4096).is_err());
        assert!(MemLayout::from_span(HIGH_MEM_START).is_err());
    }

    /// The dirty-bitmap merge relies on both region boundaries being
    /// whole `u64` words of a 4 KiB-page bitmap, so slot 1's bits can be
    /// OR'd in at a word offset without any bit shifting.
    #[test]
    fn region_boundaries_are_bitmap_word_aligned() {
        for boundary in [MMIO_HOLE_START, HIGH_MEM_START] {
            assert_eq!(boundary % (4096 * 64), 0, "{boundary:#x}");
        }
    }

    /// Every virtio-mmio window must fit in the hole below the IOAPIC.
    #[test]
    fn mmio_windows_fit_below_the_ioapic() {
        const IOAPIC_BASE: u64 = 0xfec0_0000;
        let last_window = MMIO_HOLE_START + 19 * 0x1000;
        assert!(last_window < IOAPIC_BASE);
    }
}
