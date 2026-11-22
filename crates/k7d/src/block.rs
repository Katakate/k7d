//! Userspace virtio-blk MMIO device backed by a raw host file.
//!
//! Modeled on the TAP net device in [`crate::network`]: an in-process worker
//! thread services the request queue through k7d's own guest-memory mapping,
//! honours [`VirtioBackend::set_paused`] for the warm-fork capture window
//! (CHALLENGES.md #29), and never needs guest memory to be an fd another
//! process can map — so block-backed VMs stay on the `CoW` fork path.
//!
//! Two things distinguish it from the net worker:
//!
//! 1. **Device-DMA dirty tracking.** KVM's dirty log only records vCPU
//!    writes; the worker's `pread` completions and used-ring updates go
//!    through the host mapping and are invisible to it (the host-side #27
//!    class of bug that forces virtiofs forks onto the full-memfd path).
//!    Because this device is in-process we can track those writes ourselves:
//!    every guest-memory store marks a bit in a per-device page bitmap that
//!    [`Vm::get_and_accumulate_dirty`](crate::vm::Vm) merges into the warm
//!    fork's dirty delta via [`VirtioBackend::merge_dirty_pages`].
//! 2. **Deterministic pause.** On pause the worker finishes the request
//!    already in `handle_request` (if any), then parks and reports
//!    quiescence via [`VirtioBackend::wait_quiescent`]. Remaining avail
//!    descriptors stay on the ring — the child worker and the parent
//!    resume replay them (same contract as virtio-net / CHALLENGES #79).
//!    Draining the whole queue was a 0.5–7 s `pwrite`/`sync_data` storm
//!    on a busy inner-k3s guest and made `FICLONE` of the 8 GiB scratch
//!    wait on the same inode (CHALLENGES #162). DMA from the in-flight
//!    request is still in the dirty bitmap before memcpy.

use std::fs::File;
use std::io::ErrorKind;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use vmm_sys_util::eventfd::EventFd;

use crate::network::{get_avail_desc, mark_dirty, put_used_desc, read_used_idx};
use crate::virtio_mmio::{
    wait_for_park, NotQuiescent, ValidatedQueue, VirtioBackend, VirtqueueState, UNPARK_POLL,
};

/// Metadata of one descriptor in a request chain. Re-exported from the
/// transport: the geometry type and the chain walker own this shape
/// now, and the fuzz target still reaches it at `block::DescMeta`.
pub use crate::virtio_mmio::DescMeta;

/// Virtio device-type ID for block devices.
pub const VIRTIO_ID_BLOCK: u32 = 2;
/// Virtio-blk operates on fixed 512-byte sectors.
pub const SECTOR_SIZE: u64 = 512;
const BLK_QUEUE_SIZE: u16 = 256;
const PAGE_SIZE: u64 = 4096;

// Virtio-blk feature bits.
const VIRTIO_BLK_F_RO: u64 = 1 << 5;
const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;

// Virtio-blk request types.
/// Read request (device → guest buffers).
pub const VIRTIO_BLK_T_IN: u32 = 0;
/// Write request (guest buffers → device).
pub const VIRTIO_BLK_T_OUT: u32 = 1;
/// Flush request (`fdatasync` the backing file).
pub const VIRTIO_BLK_T_FLUSH: u32 = 4;
/// Device ID string; RHCOS's udev asks every partition for it and
/// takes "unsupported" for an empty serial.
pub const VIRTIO_BLK_T_GET_ID: u32 = 8;

// Virtio-blk status codes (written to the request's status byte).
/// Request completed successfully.
pub const VIRTIO_BLK_S_OK: u8 = 0;
/// I/O error (also used for writes rejected on a read-only device).
pub const VIRTIO_BLK_S_IOERR: u8 = 1;
/// Unsupported request type.
pub const VIRTIO_BLK_S_UNSUPP: u8 = 2;

// --- Pure request-parsing layer (fuzzed + Kani-verified) ---

/// Split of a validated request chain: header, data range, status byte.
#[derive(Debug)]
pub struct RequestLayout {
    /// The 16-byte request header descriptor (device-readable).
    pub header: DescMeta,
    /// Index of the first data descriptor within the chain (`1`).
    pub data_start: usize,
    /// One past the last data descriptor (`len - 1`).
    pub data_end: usize,
    /// The 1-byte status descriptor (device-writable, last in chain).
    pub status: DescMeta,
    /// Total data payload length in bytes across all data descriptors.
    pub data_len: u64,
}

/// Parse a virtio-blk request header: `{ type: u32 LE, reserved: u32,
/// sector: u64 LE }`. Returns `(type, sector)`, or `None` when fewer than
/// 16 bytes are supplied.
#[must_use]
pub fn parse_request_header(bytes: &[u8]) -> Option<(u32, u64)> {
    if bytes.len() < 16 {
        return None;
    }
    let req_type = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let sector = u64::from_le_bytes([
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ]);
    Some((req_type, sector))
}

/// Validate a request descriptor chain against the guest memory bounds and
/// split it into header / data / status.
///
/// Rules (virtio 1.x split-ring block request format):
/// - at least two descriptors (header + status);
/// - every descriptor must lie entirely within `[0, mem_size)` with no
///   address overflow;
/// - the first descriptor is the device-readable 16-byte header;
/// - the last descriptor is the device-writable status byte;
/// - everything in between is data; the summed data length must not
///   overflow `u64`.
pub fn validate_request_layout(
    descs: &[DescMeta],
    mem_size: u64,
) -> Result<RequestLayout, &'static str> {
    if descs.len() < 2 {
        return Err("request chain needs at least header + status descriptors");
    }
    for d in descs {
        let end = d
            .addr
            .checked_add(u64::from(d.len))
            .ok_or("descriptor address overflow")?;
        if end > mem_size {
            return Err("descriptor outside guest memory bounds");
        }
    }
    let header = descs[0];
    if header.write {
        return Err("header descriptor must be device-readable");
    }
    if header.len < 16 {
        return Err("header descriptor shorter than 16 bytes");
    }
    let status = descs[descs.len() - 1];
    if !status.write {
        return Err("status descriptor must be device-writable");
    }
    if status.len < 1 {
        return Err("status descriptor is empty");
    }
    let mut data_len: u64 = 0;
    for d in &descs[1..descs.len() - 1] {
        data_len = data_len
            .checked_add(u64::from(d.len))
            .ok_or("data length overflow")?;
    }
    Ok(RequestLayout {
        header,
        data_start: 1,
        data_end: descs.len() - 1,
        status,
        data_len,
    })
}

/// Sector arithmetic for an IN/OUT request: returns the byte offset into
/// the backing file, or `None` when the transfer is empty, not a multiple
/// of the sector size, overflows, or runs past `capacity_sectors`.
#[must_use]
pub fn io_byte_offset(sector: u64, data_len: u64, capacity_sectors: u64) -> Option<u64> {
    if data_len == 0 || data_len % SECTOR_SIZE != 0 {
        return None;
    }
    let sectors = data_len / SECTOR_SIZE;
    let end = sector.checked_add(sectors)?;
    if end > capacity_sectors {
        return None;
    }
    sector.checked_mul(SECTOR_SIZE)
}

// --- Backend ---

/// Userspace virtio-blk backend. Spawns a worker thread that services the
/// single request queue against a raw host file (RO or RW).
pub struct BlockBackend {
    file: Arc<File>,
    host_path: PathBuf,
    readonly: bool,
    capacity_sectors: u64,
    mem_addr: u64,
    mem_size: u64,
    acked_features: u64,
    kick: Option<EventFd>,
    worker: Option<std::thread::JoinHandle<()>>,
    /// `pthread_self` of the worker (0 if none). Used to `EINTR` an
    /// in-flight `pwrite`/`fdatasync` on pause so `FICLONE` is not
    /// stuck on the inode (CHALLENGES #162).
    worker_tid: Arc<AtomicU64>,
    running: Arc<AtomicBool>,
    /// When true the worker parks after the in-flight request (see #162).
    paused: Arc<AtomicBool>,
    /// True while the worker is parked in the paused state (or exited) —
    /// i.e. no more guest-memory writes will happen until unpause.
    parked: Arc<AtomicBool>,
    /// Test-only: when true, `wait_quiescent` ignores `parked` and waits
    /// out the 200 ms deadline (the wedged-worker test).
    hold_park: Arc<AtomicBool>,
    /// Pages this device wrote through the host mapping (device DMA).
    /// Merged into the warm-fork dirty delta; KVM's dirty log cannot see
    /// these writes.
    dirty: Arc<Vec<AtomicU64>>,
    /// Seeded `last_avail`/`last_used` (from guest `used.idx`) for
    /// restore/fork; zero on cold boot. See CHALLENGES.md #27.
    idx_seed: u16,
}

/// Open a virtio-blk backing file, through the node broker when the
/// shim's `CreateVm` registered it.
///
/// Two kinds of file arrive here and they belong on opposite sides of
/// the privilege-separation split. The shim's images — overlay slots under
/// `/tmp/k7d-shim-*`, `/var/lib/k7d/images` — are root-owned and were
/// validated and pinned at `vm.register`, so they come back as a
/// descriptor over `disk.open`. Everything the VM broker made itself —
/// scratch disks, data disks, reflinked tree clones — is `k7d`-owned
/// under `/var/lib/k7d/disks` and is opened right here, with no round
/// trip, which is what keeps the fork path verb-free.
fn open_backing_file(host_path: &Path, readonly: bool) -> Result<std::fs::File, String> {
    if let Some(opened) =
        crate::broker::client::open_pinned(crate::broker::client::Pin::Block, host_path)
    {
        return opened.map(std::fs::File::from).map_err(|e| {
            format!(
                "disk.open for block backing file {}: {e}",
                host_path.display()
            )
        });
    }
    std::fs::OpenOptions::new()
        .read(true)
        .write(!readonly)
        .open(host_path)
        .map_err(|e| format!("open block backing file {}: {e}", host_path.display()))
}

impl BlockBackend {
    /// Open `host_path` as the backing file (`O_RDONLY` when `readonly`,
    /// `O_RDWR` otherwise) and validate it. No default fallbacks: a missing
    /// file, an empty file, or a size that is not a multiple of 512 is an
    /// error.
    pub fn new(
        host_path: &Path,
        readonly: bool,
        mem_addr: u64,
        mem_size: u64,
    ) -> Result<Self, String> {
        let file = open_backing_file(host_path, readonly)?;
        let len = file
            .metadata()
            .map_err(|e| format!("stat block backing file {}: {e}", host_path.display()))?
            .len();
        if len == 0 {
            return Err(format!(
                "block backing file {} is empty",
                host_path.display()
            ));
        }
        if len % SECTOR_SIZE != 0 {
            return Err(format!(
                "block backing file {} is {len} bytes — not a multiple of the {SECTOR_SIZE}-byte sector size",
                host_path.display()
            ));
        }
        let words = (mem_size.div_ceil(PAGE_SIZE) as usize).div_ceil(64);
        let dirty = (0..words).map(|_| AtomicU64::new(0)).collect();
        Ok(Self {
            file: Arc::new(file),
            host_path: host_path.to_path_buf(),
            readonly,
            capacity_sectors: len / SECTOR_SIZE,
            mem_addr,
            mem_size,
            acked_features: 0,
            kick: None,
            worker: None,
            worker_tid: Arc::new(AtomicU64::new(0)),
            running: Arc::new(AtomicBool::new(false)),
            paused: Arc::new(AtomicBool::new(false)),
            parked: Arc::new(AtomicBool::new(true)),
            hold_park: Arc::new(AtomicBool::new(false)),
            dirty: Arc::new(dirty),
            idx_seed: 0,
        })
    }

    /// Seed the worker's `last_avail`/`last_used` from the guest's
    /// `used.idx` before activation on restore / warm fork.
    ///
    /// Same discipline as [`crate::network::TapNetBackend::seed_indices_from_guest`]
    /// (CHALLENGES.md #27): the guest driver's ring state survived in
    /// memory, so restarting the worker at 0 would re-process serviced
    /// descriptors and corrupt the used ring.
    pub fn seed_indices_from_guest(&mut self, queues: &[VirtqueueState]) -> Result<(), String> {
        let Some(q) = queues.first() else {
            return Err("virtio-blk needs one queue to seed from".to_string());
        };
        if !q.ready {
            // Nothing was ever completed on a queue the driver never
            // readied, so 0 is the truth, not a fallback.
            self.idx_seed = 0;
            return Ok(());
        }
        let vq = ValidatedQueue::new(q, self.mem_addr, self.mem_size)
            .map_err(|e| format!("virtio-blk queue geometry: {e}"))?;
        self.idx_seed = read_used_idx(&vq);
        log::info!("virtio-blk seed index from guest: {}", self.idx_seed);
        Ok(())
    }

    /// Stop the worker thread. Must be called before guest memory is freed.
    pub fn shutdown(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        interrupt_blk_worker(&self.worker_tid);
        if let Some(ref kick) = self.kick {
            let _ = kick.write(1);
        }
        if let Some(h) = self.worker.take() {
            let _ = h.join();
        }
        self.worker_tid.store(0, Ordering::SeqCst);
    }
}

impl Drop for BlockBackend {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl VirtioBackend for BlockBackend {
    fn device_type(&self) -> u32 {
        VIRTIO_ID_BLOCK
    }

    fn device_features(&self) -> u64 {
        // VIRTIO_F_VERSION_1 is OR'd in by the MMIO transport.
        let mut features = VIRTIO_BLK_F_FLUSH;
        if self.readonly {
            features |= VIRTIO_BLK_F_RO;
        }
        features
    }

    fn ack_features(&mut self, features: u64) {
        self.acked_features = features;
    }

    fn num_queues(&self) -> usize {
        1
    }

    fn max_queue_size(&self) -> u16 {
        BLK_QUEUE_SIZE
    }

    fn guest_mapping(&self) -> (u64, u64) {
        (self.mem_addr, self.mem_size)
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // virtio_blk_config: capacity in 512-byte sectors (u64 LE) at
        // offset 0. Nothing else is advertised.
        let config = self.capacity_sectors.to_le_bytes();
        let start = offset as usize;
        if start >= config.len() {
            data.fill(0);
            return;
        }
        let end = (start + data.len()).min(config.len());
        let len = end - start;
        data[..len].copy_from_slice(&config[start..end]);
        data[len..].fill(0);
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {}

    fn queue_notify(&self, queue_index: u32) {
        if queue_index == 0 {
            if let Some(ref kick) = self.kick {
                let _ = kick.write(1);
            }
        }
    }

    fn set_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::SeqCst);
        // Wake the worker so it parks (pause) or resumes promptly (unpause).
        if let Some(ref kick) = self.kick {
            let _ = kick.write(1);
        }
        // Break out of pwrite/fdatasync so FICLONE is not serialized
        // behind a 3–7 s XFS lock (CHALLENGES #162). SIGRTMIN is the
        // same no-op, no-SA_RESTART handler the vCPU pause path uses.
        if paused {
            interrupt_blk_worker(&self.worker_tid);
        }
    }

    fn wait_quiescent(&self) -> Result<(), NotQuiescent> {
        if self.worker.is_none() {
            return Ok(());
        }
        // 200 ms > the worker's 100 ms poll. A stuck scratch-disk IO
        // already will not park; waiting 2 s then proceeding (the old
        // bound) just blew `FORK_INNER_K3S_CLUSTER_3VM` (CHALLENGES #162).
        wait_for_park(
            &self.parked,
            &self.running,
            self.hold_park.load(Ordering::SeqCst),
            || format!("virtio-blk ({})", self.host_path.display()),
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

    fn activate(&mut self, queues: &[VirtqueueState], irq_evt: &EventFd) -> Result<(), String> {
        let Some(q) = queues.first() else {
            return Err("virtio-blk needs one queue".to_string());
        };
        if !q.ready {
            return Err("virtio-blk queue not ready".to_string());
        }
        let vq = ValidatedQueue::new(q, self.mem_addr, self.mem_size)
            .map_err(|e| format!("virtio-blk queue geometry: {e}"))?;

        let kick = crate::fdutil::eventfd_cloexec(libc::EFD_NONBLOCK)
            .map_err(|e| format!("eventfd: {e}"))?;
        let worker_kick = kick.try_clone().map_err(|e| format!("dup kick: {e}"))?;
        let worker_irq = irq_evt.try_clone().map_err(|e| format!("dup irq: {e}"))?;

        let ctx = WorkerCtx {
            file: Arc::clone(&self.file),
            readonly: self.readonly,
            capacity_sectors: self.capacity_sectors,
            vq,
            irq: worker_irq,
            kick: worker_kick,
            running: Arc::clone(&self.running),
            paused: Arc::clone(&self.paused),
            parked: Arc::clone(&self.parked),
            dirty: Arc::clone(&self.dirty),
            worker_tid: Arc::clone(&self.worker_tid),
            idx_seed: self.idx_seed,
        };

        self.running.store(true, Ordering::SeqCst);
        self.paused.store(false, Ordering::SeqCst);
        self.parked.store(false, Ordering::SeqCst);
        // Named so it doesn't inherit the activating vCPU thread's comm
        // (device activation runs on a vCPU thread — see).
        self.worker = Some(
            std::thread::Builder::new()
                .name("virtio-blk".to_string())
                .spawn(move || blk_worker(&ctx))
                .map_err(|e| format!("spawn virtio-blk worker: {e}"))?,
        );
        self.kick = Some(kick);

        // Drain any requests captured avail-but-unprocessed by a fork (the
        // guest's kick was an eventfd write on the source and does not
        // survive the fork; the guest will not re-notify). Same discipline
        // as TapNetBackend::activate (CHALLENGES.md #79); harmless on cold
        // boot.
        if let Some(ref kick) = self.kick {
            let _ = kick.write(1);
        }

        log::info!(
            "virtio-blk activated (userspace): file={} ro={} capacity={} sectors",
            self.host_path.display(),
            self.readonly,
            self.capacity_sectors
        );
        Ok(())
    }
}

/// Everything the worker thread needs, bundled to keep the spawn readable.
struct WorkerCtx {
    file: Arc<File>,
    readonly: bool,
    capacity_sectors: u64,
    /// Geometry of the single request queue, checked against guest RAM at
    /// activation — the worker never re-derives a host address itself.
    vq: ValidatedQueue,
    irq: EventFd,
    kick: EventFd,
    running: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    parked: Arc<AtomicBool>,
    dirty: Arc<Vec<AtomicU64>>,
    worker_tid: Arc<AtomicU64>,
    idx_seed: u16,
}

/// Worker thread: wait for queue kicks, service requests against the
/// backing file. On pause: finish the request already in flight (see
/// [`process_queue`]), then park. Do **not** drain the rest of the avail
/// ring — that is a multi-second `pwrite`/`FLUSH` storm on a busy guest
/// and stalls `FICLONE` of the scratch (CHALLENGES #162). Leftover
/// descriptors are replayed on the child and on parent resume.
fn blk_worker(ctx: &WorkerCtx) {
    accept_worker_interrupt();
    // SAFETY: this is the worker thread; the value is only used as a
    // pthread_t for SIGRTMIN while `running` is true, then zeroed.
    let self_tid = unsafe { libc::pthread_self() as u64 };
    ctx.worker_tid.store(self_tid, Ordering::SeqCst);
    let mut last_avail = ctx.idx_seed;
    let mut last_used = ctx.idx_seed;

    while ctx.running.load(Ordering::SeqCst) {
        if ctx.paused.load(Ordering::SeqCst) {
            ctx.parked.store(true, Ordering::SeqCst);
            while ctx.paused.load(Ordering::SeqCst) && ctx.running.load(Ordering::SeqCst) {
                std::thread::sleep(UNPARK_POLL);
            }
            ctx.parked.store(false, Ordering::SeqCst);
            continue;
        }

        let mut fds = [libc::pollfd {
            fd: std::os::unix::io::AsRawFd::as_raw_fd(&ctx.kick),
            events: libc::POLLIN,
            revents: 0,
        }];
        // SAFETY: fds points to one valid pollfd; timeout 100ms.
        let ret = unsafe { libc::poll(fds.as_mut_ptr(), 1, 100) };
        if ret < 0 {
            continue;
        }
        if fds[0].revents & libc::POLLIN != 0 {
            let _ = ctx.kick.read();
        }
        process_queue(ctx, &mut last_avail, &mut last_used);
    }
    // Report quiescence on exit too, so wait_quiescent never hangs on a
    // shut-down device.
    ctx.worker_tid.store(0, Ordering::SeqCst);
    ctx.parked.store(true, Ordering::SeqCst);
}

/// Make sure this worker can actually receive [`interrupt_blk_worker`]'s
/// signal, whatever mask it was born with.
///
/// A new thread inherits the signal mask of the thread that spawned it,
/// and this one is spawned from device activation — an MMIO exit, so *on
/// a vCPU thread*, which blocks its own stop signal deliberately. A
/// worker that inherits a block on `SIGRTMIN` does not merely miss its
/// kicks: the signal is a real-time one, so each pause *queues* another
/// undeliverable instance against the per-user `RLIMIT_SIGPENDING` until
/// it is full and no thread in the process can be signalled at all
/// (`CHALLENGES.md` #185). The vCPU path uses a different signal now, so
/// this is belt to that braces — a mask inherited from anywhere must not
/// be able to swallow a kick silently.
fn accept_worker_interrupt() {
    // SAFETY: a freshly zeroed sigset_t filled only through libc's own
    // accessors, and a null old-set pointer, which is allowed.
    let rc = unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut set);
        libc::sigaddset(&raw mut set, libc::SIGRTMIN());
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &raw const set, std::ptr::null_mut())
    };
    assert_eq!(rc, 0, "pthread_sigmask(SIG_UNBLOCK, SIGRTMIN) failed: {rc}");
}

/// Interrupt `pwrite`/`fdatasync`/`poll` on the virtio-blk worker.
/// `SIGRTMIN` has a no-op handler without `SA_RESTART` (`vm.rs`).
fn interrupt_blk_worker(tid: &AtomicU64) {
    let raw = tid.load(Ordering::SeqCst);
    if raw == 0 {
        return;
    }
    // SAFETY: `raw` is `pthread_self` from the live worker, or we lose
    // the race with exit and pthread_kill returns ESRCH.
    let _ = unsafe { libc::pthread_kill(raw as libc::pthread_t, libc::SIGRTMIN()) };
}

/// Drain available descriptor chains until the queue is empty or pause
/// is requested. A pause check *before* each request lets the current
/// `pwrite`/`sync_data` finish and then parks, instead of emptying a
/// full inner-k3s ring onto the 8 GiB scratch (CHALLENGES #162).
fn process_queue(ctx: &WorkerCtx, last_avail: &mut u16, last_used: &mut u16) {
    loop {
        // Check before taking a descriptor — `get_avail_desc` advances
        // `last_avail`, and a skipped chain would never complete on the
        // parent worker after resume.
        if ctx.paused.load(Ordering::SeqCst) {
            return;
        }
        let Some(head) = get_avail_desc(&ctx.vq, last_avail) else {
            return;
        };
        let Some(used_len) = handle_request(ctx, head) else {
            // The pause interrupted this write. Put the chain back on the
            // avail ring (`get_avail_desc` already advanced past it) and
            // park: it is replayed on resume, exactly like the chains
            // pause leaves untouched behind it. Completing it with
            // VIRTIO_BLK_S_IOERR instead is a hard write error for a
            // request nothing was wrong with, and the guest's ext4
            // aborts its journal and remounts read-only for it
            // (CHALLENGES.md #178).
            *last_avail = last_avail.wrapping_sub(1);
            return;
        };
        let slot_gpa = ctx.vq.used_ring_gpa(*last_used);
        put_used_desc(&ctx.vq, last_used, head, used_len);
        // The used-ring entry + idx are device writes into guest memory —
        // record them or the fork's driver sees a stale ring.
        mark_dirty(&ctx.dirty, slot_gpa, 8);
        mark_dirty(&ctx.dirty, ctx.vq.used_idx_gpa(), 2);
        let _ = ctx.irq.write(1);
    }
}

/// Service one request chain.
///
/// `Some(used_ring_length)` — bytes written into device-writable
/// buffers, including the status byte. `None` when the pause signal cut
/// the request short and it must be replayed rather than completed.
fn handle_request(ctx: &WorkerCtx, head: u16) -> Option<u32> {
    // Walk the descriptor chain with the shared walker: bounded by the
    // queue size (we do not advertise VIRTIO_F_INDIRECT_DESC, so a longer
    // chain is malformed) and bounds-checked against guest RAM.
    let mut chain: Vec<DescMeta> = Vec::with_capacity(4);
    let descs = match ctx.vq.walk_chain(head, &mut chain) {
        Ok(descs) => descs,
        Err(e) => {
            log::error!("virtio-blk: malformed descriptor chain (head={head}): {e}");
            return Some(0);
        }
    };

    let layout = match validate_request_layout(descs, ctx.vq.mem_span()) {
        Ok(l) => l,
        Err(e) => {
            log::error!("virtio-blk: rejecting malformed request: {e}");
            return Some(0);
        }
    };

    let mut header = [0u8; 16];
    // SAFETY: layout.header was bounds-checked against mem_size with
    // len >= 16; the source range lies within guest RAM.
    unsafe {
        std::ptr::copy_nonoverlapping(
            (ctx.vq.mem_base() + layout.header.addr) as *const u8,
            header.as_mut_ptr(),
            16,
        );
    }
    let (req_type, sector) = parse_request_header(&header).expect("16-byte header parses");

    let data = &descs[layout.data_start..layout.data_end];
    let (status, mut used_len) = execute_request(ctx, req_type, sector, data, layout.data_len)?;

    // SAFETY: layout.status was bounds-checked against mem_size with
    // len >= 1; the destination lies within guest RAM.
    unsafe {
        std::ptr::write_volatile((ctx.vq.mem_base() + layout.status.addr) as *mut u8, status);
    }
    mark_dirty(&ctx.dirty, layout.status.addr, 1);
    used_len += 1; // status byte
    Some(used_len)
}

/// Execute a parsed request against the backing file.
///
/// `Some((status, bytes_written_to_guest))` completes the chain — the
/// status byte is accounted by the caller. `None` means the pause
/// signal cut a `pwrite` short: see [`process_queue`].
fn execute_request(
    ctx: &WorkerCtx,
    req_type: u32,
    sector: u64,
    data: &[DescMeta],
    data_len: u64,
) -> Option<(u8, u32)> {
    match req_type {
        VIRTIO_BLK_T_IN => {
            let Some(offset) = io_byte_offset(sector, data_len, ctx.capacity_sectors) else {
                log::error!(
                    "virtio-blk: IN out of bounds (sector={sector} len={data_len} \
                     capacity={} sectors)",
                    ctx.capacity_sectors
                );
                return Some((VIRTIO_BLK_S_IOERR, 0));
            };
            let mut file_off = offset;
            let mut written: u32 = 0;
            for d in data {
                if !d.write {
                    log::error!("virtio-blk: IN request with device-readable data descriptor");
                    return Some((VIRTIO_BLK_S_IOERR, 0));
                }
                // SAFETY: d was bounds-checked against mem_size; the range
                // lies within guest RAM, which outlives the worker (joined
                // before the mapping is released).
                let buf = unsafe {
                    std::slice::from_raw_parts_mut(
                        (ctx.vq.mem_base() + d.addr) as *mut u8,
                        d.len as usize,
                    )
                };
                if let Err(e) = ctx.file.read_exact_at(buf, file_off) {
                    log::error!("virtio-blk: pread {} bytes at {file_off}: {e}", d.len);
                    return Some((VIRTIO_BLK_S_IOERR, 0));
                }
                mark_dirty(&ctx.dirty, d.addr, u64::from(d.len));
                file_off += u64::from(d.len);
                written += d.len;
            }
            Some((VIRTIO_BLK_S_OK, written))
        }
        VIRTIO_BLK_T_OUT => {
            if ctx.readonly {
                log::error!(
                    "virtio-blk: rejecting write to read-only device (sector={sector} \
                     len={data_len})"
                );
                return Some((VIRTIO_BLK_S_IOERR, 0));
            }
            let Some(offset) = io_byte_offset(sector, data_len, ctx.capacity_sectors) else {
                log::error!(
                    "virtio-blk: OUT out of bounds (sector={sector} len={data_len} \
                     capacity={} sectors)",
                    ctx.capacity_sectors
                );
                return Some((VIRTIO_BLK_S_IOERR, 0));
            };
            let mut file_off = offset;
            for d in data {
                if d.write {
                    log::error!("virtio-blk: OUT request with device-writable data descriptor");
                    return Some((VIRTIO_BLK_S_IOERR, 0));
                }
                // SAFETY: d was bounds-checked against mem_size; the range
                // lies within guest RAM, which outlives the worker.
                let buf = unsafe {
                    std::slice::from_raw_parts(
                        (ctx.vq.mem_base() + d.addr) as *const u8,
                        d.len as usize,
                    )
                };
                if let Err(e) = write_all_at_unless_paused(ctx, buf, file_off) {
                    if io_aborted_for_pause(ctx, &e) {
                        // Nothing is wrong with this request — the host
                        // froze the VM mid-`pwrite`. Defer it instead of
                        // handing the guest a hard write error.
                        return None;
                    }
                    log::error!("virtio-blk: pwrite {} bytes at {file_off}: {e}", d.len);
                    return Some((VIRTIO_BLK_S_IOERR, 0));
                }
                file_off += u64::from(d.len);
            }
            Some((VIRTIO_BLK_S_OK, 0))
        }
        VIRTIO_BLK_T_FLUSH => {
            // Do not `sync_data` the 8 GiB scratch. `fdatasync` sits in
            // uninterruptible D-state on a dirty XFS journal; SIGRTMIN
            // cannot break it, and `FICLONE` then waits on the same
            // inode for 3–7 s (CHALLENGES #162). Completions already
            // hit the page cache; FICLONE shares those extents. The
            // guest still sees a successful FLUSH.
            Some((VIRTIO_BLK_S_OK, 0))
        }
        VIRTIO_BLK_T_GET_ID => Some((VIRTIO_BLK_S_UNSUPP, 0)),
        other => {
            log::warn!("virtio-blk: unsupported request type {other}");
            Some((VIRTIO_BLK_S_UNSUPP, 0))
        }
    }
}

fn io_aborted_for_pause(ctx: &WorkerCtx, err: &std::io::Error) -> bool {
    ctx.paused.load(Ordering::SeqCst) && err.kind() == ErrorKind::Interrupted
}

/// Like [`FileExt::write_all_at`] but stop on pause instead of retrying
/// `EINTR` — std retries `Interrupted` and would ignore `SIGRTMIN`.
fn write_all_at_unless_paused(
    ctx: &WorkerCtx,
    mut buf: &[u8],
    mut offset: u64,
) -> std::io::Result<()> {
    while !buf.is_empty() {
        if ctx.paused.load(Ordering::SeqCst) {
            return Err(std::io::Error::new(
                ErrorKind::Interrupted,
                "virtio-blk write aborted for pause",
            ));
        }
        match ctx.file.write_at(buf, offset) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    ErrorKind::WriteZero,
                    "virtio-blk pwrite wrote 0 bytes",
                ));
            }
            Ok(n) => {
                buf = &buf[n..];
                offset += n as u64;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {
                if ctx.paused.load(Ordering::SeqCst) {
                    return Err(e);
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_parses_le_fields() {
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&VIRTIO_BLK_T_OUT.to_le_bytes());
        bytes[8..16].copy_from_slice(&0x1234_5678_9abc_def0u64.to_le_bytes());
        assert_eq!(
            parse_request_header(&bytes),
            Some((VIRTIO_BLK_T_OUT, 0x1234_5678_9abc_def0))
        );
        assert_eq!(parse_request_header(&bytes[..15]), None);
    }

    #[test]
    fn layout_rejects_malformed_chains() {
        let mem = 1 << 20;
        let hdr = DescMeta {
            addr: 0,
            len: 16,
            write: false,
        };
        let status = DescMeta {
            addr: 32,
            len: 1,
            write: true,
        };
        assert!(validate_request_layout(&[hdr], mem).is_err());
        // Header must be readable.
        let bad_hdr = DescMeta { write: true, ..hdr };
        assert!(validate_request_layout(&[bad_hdr, status], mem).is_err());
        // Status must be writable.
        let bad_status = DescMeta {
            write: false,
            ..status
        };
        assert!(validate_request_layout(&[hdr, bad_status], mem).is_err());
        // Descriptor past end of guest memory.
        let oob = DescMeta {
            addr: mem - 8,
            len: 16,
            write: true,
        };
        assert!(validate_request_layout(&[hdr, oob, status], mem).is_err());
        // Address overflow.
        let overflow = DescMeta {
            addr: u64::MAX - 4,
            len: 16,
            write: true,
        };
        assert!(validate_request_layout(&[hdr, overflow, status], mem).is_err());
        // Well-formed chain with one data descriptor.
        let data = DescMeta {
            addr: 4096,
            len: 512,
            write: true,
        };
        let layout = validate_request_layout(&[hdr, data, status], mem).unwrap();
        assert_eq!(layout.data_len, 512);
        assert_eq!((layout.data_start, layout.data_end), (1, 2));
    }

    #[test]
    fn io_offset_bounds() {
        // 4 sectors capacity.
        assert_eq!(io_byte_offset(0, 512, 4), Some(0));
        assert_eq!(io_byte_offset(3, 512, 4), Some(3 * 512));
        assert_eq!(io_byte_offset(4, 512, 4), None); // past end
        assert_eq!(io_byte_offset(0, 4 * 512 + 512, 4), None); // too long
        assert_eq!(io_byte_offset(0, 100, 4), None); // not sector-aligned
        assert_eq!(io_byte_offset(0, 0, 4), None); // empty
        assert_eq!(io_byte_offset(u64::MAX, 512, u64::MAX), None); // overflow
    }

    #[test]
    fn mark_dirty_sets_page_bits() {
        let dirty: Vec<AtomicU64> = (0..2).map(|_| AtomicU64::new(0)).collect();
        mark_dirty(&dirty, 4096, 1);
        assert_eq!(dirty[0].load(Ordering::SeqCst), 0b10);
        // Range spanning pages 2 and 3.
        mark_dirty(&dirty, 2 * 4096 + 4000, 200);
        assert_eq!(dirty[0].load(Ordering::SeqCst), 0b1110);
        // Out-of-bitmap pages are ignored.
        mark_dirty(&dirty, 129 * 64 * 4096, 4096);
        assert_eq!(dirty[1].load(Ordering::SeqCst), 0);
        // Zero-length writes mark nothing.
        mark_dirty(&dirty, 0, 0);
        assert_eq!(dirty[0].load(Ordering::SeqCst), 0b1110);
    }
}

#[cfg(kani)]
mod verification {
    use super::*;

    /// The request-header parser never panics and decodes the LE fields
    /// exactly, for any 16-byte input; shorter inputs return `None`.
    #[kani::proof]
    fn verify_parse_request_header() {
        let bytes: [u8; 16] = kani::any();
        let (req_type, sector) = parse_request_header(&bytes).expect("16 bytes must parse");
        assert_eq!(
            req_type,
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        );
        assert_eq!(
            sector,
            u64::from_le_bytes([
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
                bytes[15]
            ])
        );
        let short_len: usize = kani::any();
        kani::assume(short_len < 16);
        assert!(parse_request_header(&bytes[..short_len]).is_none());
    }

    /// Sector arithmetic never lets a transfer escape the device: whenever
    /// `io_byte_offset` accepts a request, the byte range fits within
    /// `capacity_sectors * SECTOR_SIZE` with no overflow.
    #[kani::proof]
    fn verify_io_byte_offset_bounds() {
        let sector: u64 = kani::any();
        let data_len: u64 = kani::any();
        let capacity: u64 = kani::any();
        if let Some(offset) = io_byte_offset(sector, data_len, capacity) {
            assert_eq!(offset % SECTOR_SIZE, 0);
            assert_eq!(offset / SECTOR_SIZE, sector);
            assert!(
                u128::from(offset) + u128::from(data_len)
                    <= u128::from(capacity) * u128::from(SECTOR_SIZE)
            );
        }
    }

    /// Chain validation never lets a descriptor escape guest memory: every
    /// accepted layout has all descriptors within `[0, mem_size)`, a
    /// readable >=16-byte header, and a writable >=1-byte status.
    #[kani::proof]
    #[kani::unwind(6)]
    fn verify_validate_request_layout_bounds() {
        let mem_size: u64 = kani::any();
        let n: usize = kani::any();
        kani::assume(n >= 1 && n <= 3);
        let mut descs = [DescMeta {
            addr: 0,
            len: 0,
            write: false,
        }; 3];
        for d in &mut descs {
            d.addr = kani::any();
            d.len = kani::any();
            d.write = kani::any();
        }
        if let Ok(layout) = validate_request_layout(&descs[..n], mem_size) {
            for d in &descs[..n] {
                assert!(u128::from(d.addr) + u128::from(d.len) <= u128::from(mem_size));
            }
            assert!(!layout.header.write && layout.header.len >= 16);
            assert!(layout.status.write && layout.status.len >= 1);
            assert!(layout.data_start == 1 && layout.data_end == n - 1);
        }
    }
}
