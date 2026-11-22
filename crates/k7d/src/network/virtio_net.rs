//! The virtio-net device: the guest-facing half of [`super::TapDevice`].
//!
//! Moved out of `network/mod.rs` verbatim so the machine core (device
//! emulation) can be counted apart from host network plumbing
//! (bridges, netns, iptables) in `utils/loc.py`.

use super::{
    wait_for_park, Arc, AsRawFd, AtomicBool, DescMeta, EventFd, NotQuiescent, Ordering, RawFd,
    ValidatedQueue, VirtioBackend, VirtqueueState, NET_NUM_QUEUES, NET_QUEUE_SIZE, UNPARK_POLL,
    VIRTIO_ID_NET, VIRTIO_NET_DEVICE_FEATURES, VIRTIO_NET_HDR_F_NEEDS_CSUM,
    VIRTIO_NET_HDR_GSO_NONE, VIRTIO_NET_HDR_LEN,
};

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
            w.fetch_or(1u64 << (page % 64), Ordering::Release);
        }
    }
}

/// Userspace virtio-net backend. Spawns a thread that handles RX/TX between
/// TAP and guest virtqueues, like Firecracker.
pub struct TapNetBackend {
    mac: [u8; 6],
    mem_addr: u64,
    mem_size: u64,
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
    /// Test-only: when true, `wait_quiescent` ignores `parked` and waits
    /// out the 200 ms deadline.
    hold_park: Arc<AtomicBool>,
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
            mem_size,
            tap_fd,
            acked_features: 0,
            tx_kick: None,
            worker: None,
            running: Arc::new(AtomicBool::new(false)),
            paused: Arc::new(AtomicBool::new(false)),
            parked: Arc::new(AtomicBool::new(true)),
            hold_park: Arc::new(AtomicBool::new(false)),
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
    pub fn seed_indices_from_guest(&mut self, queues: &[VirtqueueState]) -> Result<(), String> {
        if queues.len() < 2 {
            return Err(format!(
                "virtio-net needs RX + TX queues to seed from, got {}",
                queues.len()
            ));
        }
        self.rx_idx_seed = self.seed_from(&queues[0], "RX")?;
        self.tx_idx_seed = self.seed_from(&queues[1], "TX")?;
        log::info!(
            "virtio-net seed indices from guest: rx={} tx={}",
            self.rx_idx_seed,
            self.tx_idx_seed
        );
        Ok(())
    }

    /// The guest's `used.idx` on one queue, or 0 for a queue the driver
    /// never readied (nothing was ever completed on it).
    fn seed_from(&self, q: &VirtqueueState, label: &str) -> Result<u16, String> {
        if !q.ready {
            return Ok(0);
        }
        let vq = ValidatedQueue::new(q, self.mem_addr, self.mem_size)
            .map_err(|e| format!("virtio-net {label} queue geometry: {e}"))?;
        Ok(read_used_idx(&vq))
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

    fn guest_mapping(&self) -> (u64, u64) {
        (self.mem_addr, self.mem_size)
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

    fn wait_quiescent(&self) -> Result<(), NotQuiescent> {
        if self.worker.is_none() {
            return Ok(());
        }
        // Same bound as virtio-blk: above the 100 ms poll, far below the
        // 1 s cluster-fork budget (CHALLENGES #162).
        wait_for_park(
            &self.parked,
            &self.running,
            self.hold_park.load(Ordering::SeqCst),
            || {
                format!(
                    "virtio-net mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    self.mac[0], self.mac[1], self.mac[2], self.mac[3], self.mac[4], self.mac[5]
                )
            },
        )
    }

    fn hold_park_for_test(&self, hold: bool) {
        self.hold_park.store(hold, Ordering::SeqCst);
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
            acc[i] |= w.swap(0, Ordering::AcqRel);
        }
    }

    #[allow(clippy::too_many_lines)]
    fn activate(&mut self, queues: &[VirtqueueState], irq_evt: &EventFd) -> Result<(), String> {
        if queues.len() < 2 {
            return Err("need at least 2 queues (RX + TX)".to_string());
        }

        if !queues[0].ready || !queues[1].ready {
            return Err("queues not ready".to_string());
        }
        // The worker only ever sees geometry that fits in the guest's own
        // RAM: a hostile `QUEUE_NUM` / ring GPA fails activation here
        // rather than becoming an out-of-bounds host write on the first
        // frame (`docs/bug-candidates.md` #40, #42).
        let rx_q = ValidatedQueue::new(&queues[0], self.mem_addr, self.mem_size)
            .map_err(|e| format!("virtio-net RX queue geometry: {e}"))?;
        let tx_q = ValidatedQueue::new(&queues[1], self.mem_addr, self.mem_size)
            .map_err(|e| format!("virtio-net TX queue geometry: {e}"))?;

        let tx_kick = crate::fdutil::eventfd_cloexec(libc::EFD_NONBLOCK)
            .map_err(|e| format!("eventfd: {e}"))?;
        let tx_kick_fd = tx_kick.as_raw_fd();

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

        // Dup the TAP fd so the worker thread owns its copy. F_DUPFD_CLOEXEC,
        // not `dup`: a plain dup strips the CLOEXEC the source carries.
        // SAFETY: tap_fd is valid; F_DUPFD_CLOEXEC returns a new fd.
        let worker_tap_fd = unsafe { libc::fcntl(tap_fd, libc::F_DUPFD_CLOEXEC, 0) };
        if worker_tap_fd < 0 {
            return Err(format!("dup tap: {}", std::io::Error::last_os_error()));
        }

        // Dup irq eventfd for the worker
        // SAFETY: irq_fd is valid.
        let worker_irq_fd = unsafe { libc::fcntl(irq_fd, libc::F_DUPFD_CLOEXEC, 0) };
        // Dup tx_kick for the worker
        // SAFETY: tx_kick_fd is valid.
        let worker_tx_kick_fd = unsafe { libc::fcntl(tx_kick_fd, libc::F_DUPFD_CLOEXEC, 0) };

        // Named so it doesn't inherit the activating vCPU thread's comm
        // (device activation runs on a vCPU thread — see).
        let builder = std::thread::Builder::new().name("virtio-net".to_string());
        let handle = builder.spawn(move || {
            net_worker(
                worker_tap_fd,
                worker_irq_fd,
                worker_tx_kick_fd,
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
pub(crate) fn read_used_idx(q: &ValidatedQueue) -> u16 {
    // SAFETY: `used_idx` is the idx field of a ring this geometry placed
    // inside the caller's live guest mapping (memfd-backed).
    unsafe { std::ptr::read_volatile(q.used_idx().cast_const()) }
}

/// Worker thread: poll TAP for RX, poll `tx_kick` for TX, process virtqueues.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn net_worker(
    tap_fd: RawFd,
    irq_fd: RawFd,
    tx_kick_fd: RawFd,
    rx_q: &ValidatedQueue,
    tx_q: &ValidatedQueue,
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
    // Reused by every chain walk so the RX/TX path allocates nothing.
    let mut chain: Vec<DescMeta> = Vec::with_capacity(4);

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
                    rx_q,
                    &mut rx_last_avail,
                    &mut rx_last_used,
                    &mut chain,
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

            while let Some(desc_idx) = get_avail_desc(tx_q, &mut tx_last_avail) {
                let len = read_from_desc_chain(tx_q, desc_idx, &mut pkt_buf, &mut chain);
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
                let slot_gpa = tx_q.used_ring_gpa(tx_last_used);
                put_used_desc(tx_q, &mut tx_last_used, desc_idx, 0);
                mark_dirty(dirty, slot_gpa, 8);
                mark_dirty(dirty, tx_q.used_idx_gpa(), 2);
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
pub(super) fn prepare_guest_tx(buf: &mut [u8]) -> Result<(), String> {
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
///
/// The index is whatever the guest wrote — [`ValidatedQueue::walk_chain`]
/// is what refuses one that is not a descriptor of this queue.
pub(crate) fn get_avail_desc(q: &ValidatedQueue, last_avail: &mut u16) -> Option<u16> {
    // SAFETY: the pointer addresses the avail ring's idx field, which this
    // geometry placed inside the live guest mapping (memfd-backed).
    let avail_idx = unsafe { std::ptr::read_volatile(q.avail_idx()) };
    if *last_avail == avail_idx {
        return None;
    }
    // SAFETY: `avail_ring` wraps into the same validated ring.
    let desc_idx = unsafe { std::ptr::read_volatile(q.avail_ring(*last_avail)) };
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
#[allow(clippy::too_many_arguments)]
fn rx_deliver_merged(
    pkt: &mut [u8],
    rx_q: &ValidatedQueue,
    rx_last_avail: &mut u16,
    rx_last_used: &mut u16,
    chain: &mut Vec<DescMeta>,
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
        let Some(idx) = get_avail_desc(rx_q, rx_last_avail) else {
            *rx_last_avail = avail_at_start;
            return false;
        };
        let cap = match desc_chain_writable_len(rx_q, idx, chain) {
            Ok(cap) => cap,
            Err(e) => {
                *rx_last_avail = avail_at_start;
                log::error!("RX desc chain {idx} refused: {e}");
                return false;
            }
        };
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
    for i in 0..n_chains {
        let chunk = (pkt_len - offset).min(caps[i]);
        let written = match write_to_desc_chain(
            rx_q,
            chains[i],
            &pkt[offset..offset + chunk],
            chain,
            dirty,
        ) {
            Ok(written) => written,
            Err(e) => {
                // The same chain validated a moment ago on the same
                // paused-free path, so this is a guest rewriting its
                // table under us: stop, do not complete it.
                log::error!("RX desc chain {} refused mid-merge: {e}", chains[i]);
                return false;
            }
        };
        if written != chunk {
            log::error!(
                "RX desc chain {} wrote {written} of {chunk} (CHALLENGES.md #117)",
                chains[i]
            );
        }
        let slot_gpa = rx_q.used_ring_gpa(*rx_last_used);
        write_used_elem(rx_q, rx_last_used, chains[i], written as u32);
        mark_dirty(dirty, slot_gpa, 8);
        offset += written;
    }
    publish_used_idx(rx_q, *rx_last_used);
    mark_dirty(dirty, rx_q.used_idx_gpa(), 2);
    signal_irq(irq_fd);
    true
}

/// Sum of writable descriptor lengths in one chain.
pub(super) fn desc_chain_writable_len(
    q: &ValidatedQueue,
    first_desc: u16,
    chain: &mut Vec<DescMeta>,
) -> Result<usize, crate::virtio_mmio::DescChainError> {
    let descs = q.walk_chain(first_desc, chain)?;
    Ok(descs
        .iter()
        .filter(|d| d.write && d.addr != 0)
        .map(|d| d.len as usize)
        .sum())
}

/// Write data to a descriptor chain (for RX: TAP -> guest), recording every
/// written page in the device-DMA dirty bitmap. Returns bytes copied.
fn write_to_desc_chain(
    q: &ValidatedQueue,
    first_desc: u16,
    data: &[u8],
    chain: &mut Vec<DescMeta>,
    dirty: &[std::sync::atomic::AtomicU64],
) -> Result<usize, crate::virtio_mmio::DescChainError> {
    let descs = q.walk_chain(first_desc, chain)?;
    let mut offset = 0usize;
    for d in descs {
        if offset >= data.len() {
            break;
        }
        if !d.write || d.addr == 0 {
            continue;
        }
        let copy_len = (data.len() - offset).min(d.len as usize);
        // SAFETY: `walk_chain` checked `addr + len` against the guest's RAM
        // span, and `copy_len <= d.len`, so the destination lies inside the
        // live guest mapping (memfd-backed) which outlives the worker.
        unsafe {
            let dst = (q.mem_base() + d.addr) as *mut u8;
            std::ptr::copy_nonoverlapping(data[offset..].as_ptr(), dst, copy_len);
        }
        mark_dirty(dirty, d.addr, copy_len as u64);
        offset += copy_len;
    }
    Ok(offset)
}

/// Read data from a descriptor chain (for TX: guest -> TAP).
fn read_from_desc_chain(
    q: &ValidatedQueue,
    first_desc: u16,
    buf: &mut [u8],
    chain: &mut Vec<DescMeta>,
) -> usize {
    let descs = match q.walk_chain(first_desc, chain) {
        Ok(descs) => descs,
        Err(e) => {
            log::error!("TX desc chain {first_desc} refused: {e}");
            return 0;
        }
    };
    let mut offset = 0usize;
    for d in descs {
        if d.write || d.addr == 0 {
            continue;
        }
        let copy_len = (buf.len() - offset).min(d.len as usize);
        // SAFETY: `walk_chain` checked `addr + len` against the guest's RAM
        // span, and `copy_len <= d.len`, so the source lies inside the live
        // guest mapping (memfd-backed) which outlives the worker.
        unsafe {
            let src = (q.mem_base() + d.addr) as *const u8;
            std::ptr::copy_nonoverlapping(src, buf[offset..].as_mut_ptr(), copy_len);
        }
        offset += copy_len;
        if offset == buf.len() {
            break;
        }
    }
    offset
}

/// Write one used-ring element and advance `last_used`. Does **not**
/// publish `used.idx` — call [`publish_used_idx`] after the last
/// element of a multi-buffer RX packet so the guest never observes a
/// partial `MRG_RXBUF` merge.
fn write_used_elem(q: &ValidatedQueue, last_used: &mut u16, desc_idx: u16, len: u32) {
    // SAFETY: `used_ring` wraps into the used ring this geometry placed
    // inside the live guest mapping; the element is `{id:u32, len:u32}`
    // and both words are inside the validated span.
    unsafe {
        let entry_ptr = q.used_ring(*last_used);
        std::ptr::write_volatile(entry_ptr, u32::from(desc_idx));
        std::ptr::write_volatile(entry_ptr.add(1), len);
    }
    *last_used = last_used.wrapping_add(1);
}

fn publish_used_idx(q: &ValidatedQueue, last_used: u16) {
    // SAFETY: `used_idx` is the idx field of the validated used ring.
    unsafe {
        std::ptr::write_volatile(q.used_idx(), last_used);
    }
}

/// Put a descriptor in the used ring and publish `used.idx`.
pub(crate) fn put_used_desc(q: &ValidatedQueue, last_used: &mut u16, desc_idx: u16, len: u32) {
    write_used_elem(q, last_used, desc_idx, len);
    publish_used_idx(q, *last_used);
}
