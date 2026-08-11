#![no_main]
//! Fuzz the virtio-blk request parsing layer: header
//! decode, descriptor-chain validation, and sector arithmetic must never
//! panic, and every accepted layout must respect guest-memory and device
//! bounds.
use k7d::block::{
    io_byte_offset, parse_request_header, validate_request_layout, DescMeta, SECTOR_SIZE,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Header parse never panics, any length.
    let _ = parse_request_header(data);

    if data.len() < 16 {
        return;
    }
    let mem_size = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let sector = u64::from_le_bytes(data[8..16].try_into().unwrap());

    // Interpret the rest as a descriptor chain: 13 bytes per descriptor
    // (addr u64 LE, len u32 LE, flags byte).
    let descs: Vec<DescMeta> = data[16..]
        .chunks_exact(13)
        .map(|c| DescMeta {
            addr: u64::from_le_bytes(c[0..8].try_into().unwrap()),
            len: u32::from_le_bytes(c[8..12].try_into().unwrap()),
            write: c[12] & 1 != 0,
        })
        .collect();

    if let Ok(layout) = validate_request_layout(&descs, mem_size) {
        for d in &descs {
            assert!(u128::from(d.addr) + u128::from(d.len) <= u128::from(mem_size));
        }
        assert!(!layout.header.write && layout.header.len >= 16);
        assert!(layout.status.write && layout.status.len >= 1);

        // Sector arithmetic never lets a transfer escape the device.
        let capacity_sectors = mem_size / SECTOR_SIZE;
        if let Some(off) = io_byte_offset(sector, layout.data_len, capacity_sectors) {
            assert_eq!(off % SECTOR_SIZE, 0);
            assert_eq!(off / SECTOR_SIZE, sector);
            assert!(
                u128::from(off) + u128::from(layout.data_len)
                    <= u128::from(capacity_sectors) * u128::from(SECTOR_SIZE)
            );
        }
    }
});
