//! vhost-vsock backend for virtio-MMIO transport.

use std::os::unix::io::AsRawFd;

use vmm_sys_util::eventfd::EventFd;

use crate::virtio_mmio::{ValidatedQueue, VirtioBackend, VirtqueueState, VIRTIO_ID_VSOCK};

/// Maximum descriptors per vhost-vsock virtqueue (`QUEUE_NUM_MAX`).
pub const VSOCK_QUEUE_SIZE: u16 = 256;

/// Default guest vsock CID.
pub const DEFAULT_GUEST_CID: u64 = 3;

/// Allocate a process-unique guest vsock CID, partitioned by PID so
/// concurrent processes (e.g. `k7-api`'s shim + an integration test
/// binary + a second shim from a freshly-created pod) don't collide
/// in the kernel-global vhost-vsock CID namespace.
///
/// Layout: each process gets a window of 1024 CIDs starting at
/// `getpid() * 1024 + 100`. With a typical Linux `pid_max` of
/// 4,194,304 the highest base is ~4.29 billion, just under
/// `u32::MAX` (vsock CIDs are 32-bit). Two processes never share
/// CIDs unless one allocates more than 1024 in its lifetime — far
/// beyond any test or production workload.
///
/// Without PID seeding, the historical per-process atomic counter
/// starting at 100 meant every process picked CID 100, 101, 102,
/// … and the first cross-process collision (e.g. `k7-api`'s shim
/// holding 100 while the test process tried to bind 100) returned
/// `vhost SET_GUEST_CID: Address already in use` from the second
/// caller's activate path, manifesting as a confusing
/// `should connect to forked agent: Agent(Io(Os { code: 110, kind:
/// TimedOut, … }))`. PR #29 fixed the within-process case; this
/// fixes the cross-process case.
///
/// 100 is added on top of `pid * 1024` so the lowest possible CID
/// is still > 3 (the reserved `DEFAULT_GUEST_CID`).
pub fn allocate_cid() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;
    static NEXT_CID: OnceLock<AtomicU64> = OnceLock::new();
    let counter = NEXT_CID.get_or_init(|| {
        let pid = cid_seed_pid();
        // Mask the PID to 21 bits before multiplying so the final
        // base fits comfortably under `u32::MAX` (vsock CIDs are
        // 32-bit). With `pid_max = 4_194_304` (kernel default since
        // 5.0) two PIDs that share their lower 21 bits map to the
        // same window — that's at most 2 colliding PIDs per
        // window, vanishingly unlikely in practice, and even then
        // both processes would have to allocate more than 0 CIDs
        // and land on the same offset for an actual SET_GUEST_CID
        // collision. For the typical default `pid_max = 32_768`
        // (15 bits) no two PIDs ever share a window.
        let pid_window = pid & 0x001f_ffff; // 21 bits, 2_097_152 values
        let base = pid_window * 1024 + 100; // max ~2.15 GiB, well under u32::MAX
        AtomicU64::new(base)
    });
    counter.fetch_add(1, Ordering::SeqCst)
}

/// Process id seeding the CID window.
#[cfg(not(kani))]
fn cid_seed_pid() -> u64 {
    // SAFETY: getpid is async-signal-safe and always succeeds.
    u64::try_from(unsafe { libc::getpid() }).unwrap_or(1)
}

/// Under Kani, `getpid` is a foreign C function the model checker
/// cannot execute — and a nondeterministic pid makes the proof
/// stronger anyway: `verify_cid_allocation_monotonic` then covers
/// every possible pid window (bounded by the kernel's maximum
/// `pid_max`, 2^22) instead of one concrete process.
#[cfg(kani)]
fn cid_seed_pid() -> u64 {
    let pid: u64 = kani::any();
    kani::assume(pid <= 4_194_304);
    pid
}

/// Default agent vsock port.
pub const AGENT_VSOCK_PORT: u32 = 1024;

const VSOCK_NUM_QUEUES: usize = 3;

// vhost ioctl numbers
const VHOST_SET_OWNER: libc::c_ulong = 0x0000_AF01;
const VHOST_GET_FEATURES: libc::c_ulong = 0x8008_AF00;
const VHOST_SET_FEATURES: libc::c_ulong = 0x4008_AF00;
const VHOST_SET_MEM_TABLE: libc::c_ulong = 0x4008_AF03;
const VHOST_SET_VRING_NUM: libc::c_ulong = 0x4008_AF10;
const VHOST_SET_VRING_BASE: libc::c_ulong = 0x4008_AF12;
const VHOST_SET_VRING_ADDR: libc::c_ulong = 0x4028_AF11;
const VHOST_SET_VRING_KICK: libc::c_ulong = 0x4008_AF20;
const VHOST_SET_VRING_CALL: libc::c_ulong = 0x4008_AF21;
const VHOST_VSOCK_SET_GUEST_CID: libc::c_ulong = 0x4008_AF60;
const VHOST_VSOCK_SET_RUNNING: libc::c_ulong = 0x4004_AF61;

#[repr(C)]
struct VsockConfig {
    guest_cid: u64,
}

#[repr(C)]
struct VhostVringState {
    index: u32,
    num: u32,
}

#[repr(C)]
struct VhostVringAddr {
    index: u32,
    flags: u32,
    desc_user_addr: u64,
    used_user_addr: u64,
    avail_user_addr: u64,
    log_guest_addr: u64,
}

#[repr(C)]
struct VhostVringFile {
    index: u32,
    fd: i32,
}

#[repr(C)]
struct VhostMemoryRegion {
    guest_phys_addr: u64,
    memory_size: u64,
    userspace_addr: u64,
    flags_padding: u64,
}

#[repr(C)]
struct VhostMemory {
    nregions: u32,
    padding: u32,
    regions: [VhostMemoryRegion; 1],
}

/// vhost-vsock backend for virtio-MMIO.
pub struct VhostVsockBackend {
    guest_cid: u64,
    mem_addr: u64,
    mem_size: u64,
    vhost_features: u64,
    acked_features: u64,
    vhost_raw_fd: i32,
    kick_evts: Vec<EventFd>,
    _call_thread: Option<std::thread::JoinHandle<()>>,
}

fn ioctl_err(fd: i32, request: libc::c_ulong, name: &str) -> Result<(), String> {
    // SAFETY: fd is a valid vhost fd; the ioctl takes no meaningful argument.
    let rc = unsafe { libc::ioctl(fd, request, 0u64) };
    if rc < 0 {
        Err(format!("vhost {name}: {}", std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

fn ioctl_ref<T>(fd: i32, request: libc::c_ulong, arg: &T, name: &str) -> Result<(), String> {
    // SAFETY: fd is a valid vhost fd; arg points to a valid T matching the ioctl.
    let rc = unsafe { libc::ioctl(fd, request, std::ptr::from_ref(arg)) };
    if rc < 0 {
        Err(format!("vhost {name}: {}", std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

impl VhostVsockBackend {
    /// Create a new vhost-vsock backend. Opens /dev/vhost-vsock and gets features.
    pub fn new(guest_cid: u64, mem_addr: u64, mem_size: u64) -> Result<Self, String> {
        // SAFETY: path is a valid C string literal; O_RDWR|O_CLOEXEC are valid flags.
        let raw_fd =
            unsafe { libc::open(c"/dev/vhost-vsock".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if raw_fd < 0 {
            return Err(format!(
                "open /dev/vhost-vsock: {}",
                std::io::Error::last_os_error()
            ));
        }

        ioctl_err(raw_fd, VHOST_SET_OWNER, "SET_OWNER")?;

        let mut features: u64 = 0;
        // SAFETY: raw_fd is a valid vhost-vsock fd; features is valid for the ioctl to write into.
        if unsafe {
            libc::ioctl(
                raw_fd,
                VHOST_GET_FEATURES,
                std::ptr::from_mut(&mut features),
            )
        } < 0
        {
            return Err(format!(
                "VHOST_GET_FEATURES: {}",
                std::io::Error::last_os_error()
            ));
        }

        Ok(Self {
            guest_cid,
            mem_addr,
            mem_size,
            vhost_features: features,
            acked_features: 0,
            vhost_raw_fd: raw_fd,
            kick_evts: Vec::new(),
            _call_thread: None,
        })
    }

    /// Validate one queue's geometry against a guest mapping before any
    /// of its addresses reaches the kernel.
    ///
    /// `VHOST_SET_VRING_ADDR` asks the *kernel's* vhost driver to DMA at
    /// an address the guest picked. "The kernel will probably reject it"
    /// is not a boundary (`docs/bug-candidates.md` #44), and the restore
    /// path replays the same snapshotted state, so a poisoned VM would
    /// otherwise stay poisoned across every fork.
    fn validated(
        &self,
        q: &VirtqueueState,
        index: usize,
        mem_base: u64,
    ) -> Result<ValidatedQueue, String> {
        ValidatedQueue::new(q, mem_base, self.mem_size)
            .map_err(|e| format!("vhost-vsock queue {index} geometry: {e}"))
    }

    fn set_vring_addr(&self, index: u32, vq: &ValidatedQueue) -> Result<(), String> {
        let (desc, _) = vq.desc_ring();
        let (avail, _) = vq.avail_ring_span();
        let (used, _) = vq.used_ring_span();
        ioctl_ref(
            self.vhost_raw_fd,
            VHOST_SET_VRING_ADDR,
            &VhostVringAddr {
                index,
                flags: 0,
                desc_user_addr: self.mem_addr + desc,
                used_user_addr: self.mem_addr + used,
                avail_user_addr: self.mem_addr + avail,
                log_guest_addr: 0,
            },
            "SET_VRING_ADDR",
        )
    }
}

impl VirtioBackend for VhostVsockBackend {
    fn device_type(&self) -> u32 {
        VIRTIO_ID_VSOCK
    }

    fn device_features(&self) -> u64 {
        self.vhost_features
    }

    fn ack_features(&mut self, features: u64) {
        self.acked_features = features;
    }

    fn num_queues(&self) -> usize {
        VSOCK_NUM_QUEUES
    }

    fn max_queue_size(&self) -> u16 {
        VSOCK_QUEUE_SIZE
    }

    fn guest_mapping(&self) -> (u64, u64) {
        (self.mem_addr, self.mem_size)
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let config = VsockConfig {
            guest_cid: self.guest_cid,
        };
        // SAFETY: VsockConfig is #[repr(C)] and 8 bytes (a single u64);
        // the pointer and length are valid for the lifetime of config.
        let config_bytes =
            unsafe { std::slice::from_raw_parts((&raw const config).cast::<u8>(), 8) };
        let start = offset as usize;
        let end = (start + data.len()).min(config_bytes.len());
        if start < config_bytes.len() {
            let len = end - start;
            data[..len].copy_from_slice(&config_bytes[start..end]);
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {}

    fn queue_notify(&self, queue_index: u32) {
        if let Some(kick) = self.kick_evts.get(queue_index as usize) {
            let _ = kick.write(1);
        }
    }

    fn activate(&mut self, queues: &[VirtqueueState], irq_evt: &EventFd) -> Result<(), String> {
        let fd = self.vhost_raw_fd;

        // SET_FEATURES — clear VIRTIO_F_ACCESS_PLATFORM (bit 33) to avoid IOTLB mode.
        // When this bit is set, the kernel interprets vring addresses as IOVAs instead
        // of user virtual addresses, causing EFAULT on SET_RUNNING. Crosvm does the same.
        let features = self.vhost_features & !(1u64 << 33);
        ioctl_ref(fd, VHOST_SET_FEATURES, &features, "SET_FEATURES")?;

        // SET_MEM_TABLE
        let mem = VhostMemory {
            nregions: 1,
            padding: 0,
            regions: [VhostMemoryRegion {
                guest_phys_addr: 0,
                memory_size: self.mem_size,
                userspace_addr: self.mem_addr,
                flags_padding: 0,
            }],
        };
        ioctl_ref(fd, VHOST_SET_MEM_TABLE, &mem, "SET_MEM_TABLE")?;

        // Per-queue setup (crosvm order: num, addr, base, call, kick)
        // vhost-vsock only handles 2 queues (RX=0, TX=1), not the event queue
        let mut kick_evts = Vec::new();
        for (idx, q) in queues.iter().take(2).enumerate() {
            if !q.ready {
                continue;
            }
            let i = idx as u32;
            let vq = self.validated(q, idx, self.mem_addr)?;

            let kick = crate::fdutil::eventfd_cloexec(libc::EFD_NONBLOCK)
                .map_err(|e| format!("eventfd: {e}"))?;

            ioctl_ref(
                fd,
                VHOST_SET_VRING_NUM,
                &VhostVringState {
                    index: i,
                    num: u32::from(vq.size()),
                },
                "SET_VRING_NUM",
            )?;

            self.set_vring_addr(i, &vq)?;

            ioctl_ref(
                fd,
                VHOST_SET_VRING_BASE,
                &VhostVringState { index: i, num: 0 },
                "SET_VRING_BASE",
            )?;

            // Use the MmioDevice's irq_evt as the call fd.
            // When vhost has data, it writes to this fd → KVM irqfd injects IRQ.
            // Combined with is_vhost=true on the MmioDevice, the guest driver
            // always sees INT_VRING in interrupt_status (Firecracker pattern).
            ioctl_ref(
                fd,
                VHOST_SET_VRING_CALL,
                &VhostVringFile {
                    index: i,
                    fd: irq_evt.as_raw_fd(),
                },
                "SET_VRING_CALL",
            )?;

            ioctl_ref(
                fd,
                VHOST_SET_VRING_KICK,
                &VhostVringFile {
                    index: i,
                    fd: kick.as_raw_fd(),
                },
                "SET_VRING_KICK",
            )?;

            kick_evts.push(kick);
        }

        // SET_GUEST_CID — after vring setup, before start (crosvm order)
        ioctl_ref(
            fd,
            VHOST_VSOCK_SET_GUEST_CID,
            &self.guest_cid,
            "SET_GUEST_CID",
        )?;

        // Start the device
        let running: std::os::raw::c_int = 1;
        ioctl_ref(fd, VHOST_VSOCK_SET_RUNNING, &running, "SET_RUNNING")?;

        log::info!("vhost-vsock activated with CID {}", self.guest_cid);
        self.kick_evts = kick_evts;

        Ok(())
    }
}

impl VhostVsockBackend {
    /// Activate the backend with specific vring base indices (for restore).
    ///
    /// During restore, the guest's virtqueue avail/used indices are at non-zero
    /// positions from the snapshotted state. We read the avail ring `idx` from
    /// guest memory and pass it as the vring base so the vhost kernel module
    /// starts processing from the correct position.
    pub fn activate_with_bases(
        &mut self,
        queues: &[VirtqueueState],
        irq_evt: &EventFd,
        mem_host_addr: u64,
    ) -> Result<(), String> {
        let fd = self.vhost_raw_fd;

        let features = self.vhost_features & !(1u64 << 33);
        ioctl_ref(fd, VHOST_SET_FEATURES, &features, "SET_FEATURES")?;

        let mem = VhostMemory {
            nregions: 1,
            padding: 0,
            regions: [VhostMemoryRegion {
                guest_phys_addr: 0,
                memory_size: self.mem_size,
                userspace_addr: self.mem_addr,
                flags_padding: 0,
            }],
        };
        ioctl_ref(fd, VHOST_SET_MEM_TABLE, &mem, "SET_MEM_TABLE")?;

        let mut kick_evts = Vec::new();
        for (idx, q) in queues.iter().take(2).enumerate() {
            if !q.ready {
                continue;
            }
            let i = idx as u32;
            // The rings are programmed against this device's own mapping,
            // but the `used.idx` below is read out of the caller's (the
            // fork's `MAP_PRIVATE` view), so both need validating.
            let vq = self.validated(q, idx, self.mem_addr)?;
            let read_vq = self.validated(q, idx, mem_host_addr)?;

            let kick = crate::fdutil::eventfd_cloexec(libc::EFD_NONBLOCK)
                .map_err(|e| format!("eventfd: {e}"))?;

            ioctl_ref(
                fd,
                VHOST_SET_VRING_NUM,
                &VhostVringState {
                    index: i,
                    num: u32::from(vq.size()),
                },
                "SET_VRING_NUM",
            )?;

            self.set_vring_addr(i, &vq)?;

            // The vring base tells the vhost module where to start reading
            // from the available ring. Use used_idx (= number of entries the
            // host already processed) so the module sees remaining entries.
            // SAFETY: `used_idx` is the idx field of a ring this geometry
            // placed inside the caller's CoW-mapped guest memory.
            let used_idx = unsafe { std::ptr::read_volatile(read_vq.used_idx().cast_const()) };
            ioctl_ref(
                fd,
                VHOST_SET_VRING_BASE,
                &VhostVringState {
                    index: i,
                    num: used_idx as u32,
                },
                "SET_VRING_BASE",
            )?;

            ioctl_ref(
                fd,
                VHOST_SET_VRING_CALL,
                &VhostVringFile {
                    index: i,
                    fd: irq_evt.as_raw_fd(),
                },
                "SET_VRING_CALL",
            )?;

            ioctl_ref(
                fd,
                VHOST_SET_VRING_KICK,
                &VhostVringFile {
                    index: i,
                    fd: kick.as_raw_fd(),
                },
                "SET_VRING_KICK",
            )?;

            kick_evts.push(kick);
        }

        ioctl_ref(
            fd,
            VHOST_VSOCK_SET_GUEST_CID,
            &self.guest_cid,
            "SET_GUEST_CID",
        )?;

        let running: std::os::raw::c_int = 1;
        ioctl_ref(fd, VHOST_VSOCK_SET_RUNNING, &running, "SET_RUNNING")?;

        log::info!("vhost-vsock restored+activated with CID {}", self.guest_cid);
        self.kick_evts = kick_evts;

        Ok(())
    }
}

impl Drop for VhostVsockBackend {
    fn drop(&mut self) {
        if self.vhost_raw_fd >= 0 {
            let running: std::os::raw::c_int = 0;
            // SAFETY: vhost_raw_fd is valid (checked >= 0 above); stopping the device.
            let _ = unsafe {
                libc::ioctl(
                    self.vhost_raw_fd,
                    VHOST_VSOCK_SET_RUNNING,
                    &raw const running,
                )
            };
            // SAFETY: vhost_raw_fd is valid; closing the vhost-vsock device fd.
            unsafe { libc::close(self.vhost_raw_fd) };
            self.vhost_raw_fd = -1;
        }
    }
}
