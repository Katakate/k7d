//! Guest clock ownership: LAPIC / PIT / TSC survey, kvmclock warp and
//! continuous time dilation (`KVM_VM_DILATION`).
//!
//! Moved out of `vm/mod.rs` verbatim so the machine core can be counted
//! apart from the clock (`utils/loc.py`). Native backend only: the
//! Firecracker backend refuses warp and dilation.

use super::{AsRawFd, Duration, Instant, Kvm, VcpuFd, Vm, VmError, VmFd};

/// APIC register offsets inside the 1 KiB page `KVM_GET_LAPIC` returns.
/// `KVM_GET_LAPIC` recomputes `TMCCT` from the backing host hrtimer as
/// it copies the page out, so the value read here is live and not the
/// stale one the guest last saw.
const APIC_LVTT: usize = 0x320;
const APIC_TMICT: usize = 0x380;
const APIC_TMCCT: usize = 0x390;
const APIC_TDCR: usize = 0x3E0;

/// LVT mask bit — a masked timer counts down and delivers nothing.
const APIC_LVT_MASKED: u32 = 1 << 16;
/// LVT timer bits 18:17.
const APIC_LVT_TIMER_MODE_SHIFT: u32 = 17;
const APIC_LVT_TIMER_MODE_MASK: u32 = 3 << APIC_LVT_TIMER_MODE_SHIFT;

/// i8254 input frequency. The PIT counts down at this rate regardless
/// of anything the host or the guest can change.
const PIT_FREQ_HZ: u64 = 1_193_182;

/// Femtoseconds in a nanosecond. The APIC bus cycle is ~1 ns on this
/// host, so it is carried in femtoseconds: nanosecond units would round
/// the very ratio the calibration exists to measure down to nothing.
const FS_PER_NS: u64 = 1_000_000;

/// What the LAPIC timer of one vCPU is programmed to do (LVT bits 18:17).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LapicTimerMode {
    /// Counts `TMICT` down once and fires. What a NOHZ Linux guest arms
    /// for every wakeup, and the only mode that yields a jump target.
    OneShot,
    /// Reloads `TMICT` and fires forever — a tick rate, not a deadline.
    Periodic,
    /// Fires when `IA32_TSC` passes `IA32_TSC_DEADLINE`. Needs
    /// `CPUID.1:ECX[24]`: not reported by host kernel 6.8, reported by
    /// 7.0, so Ubuntu guests on 7.0
    /// register `lapic-deadline` and this is the mode they run in.
    TscDeadline,
    /// Bits 18:17 = 3, reserved by the SDM.
    Reserved,
}

/// One vCPU's LAPIC timer programming, read via `KVM_GET_LAPIC`.
#[derive(Debug, Clone, Copy)]
pub struct LapicTimerState {
    /// LVT timer mode.
    pub mode: LapicTimerMode,
    /// LVT mask bit: the countdown runs but nothing is delivered.
    pub masked: bool,
    /// Initial count the guest programmed (0 = never armed).
    pub tmict: u32,
    /// Live current count. **Zero means unarmed or already expired** —
    /// KVM returns 0 both when `TMICT` is 0 and when the backing
    /// hrtimer's expiry is already in the past.
    pub tmcct: u32,
    /// `TDCR` decoded to its divisor (1, 2, 4, … 128).
    pub divide: u32,
}

impl LapicTimerState {
    /// APIC bus cycles until this vCPU's one-shot timer fires, or `None`
    /// when nothing is armed that can wake this vCPU.
    ///
    /// Periodic is deliberately not a target: it is a rate the guest
    /// asked for, and a forward jump changes how many of its ticks fall
    /// in a guest second exactly the way suspend/resume does — which is
    /// what `KVM_KVMCLOCK_CTRL` tells the guest happened. A deadline is
    /// a promise about *when*; a tick is not.
    #[must_use]
    pub fn armed_bus_cycles(&self) -> Option<u64> {
        if self.mode != LapicTimerMode::OneShot || self.masked || self.tmcct == 0 {
            return None;
        }
        Some(u64::from(self.tmcct) * u64::from(self.divide))
    }

    /// Period of a free-running periodic timer, in APIC bus cycles.
    /// Measurement only — see [`Self::armed_bus_cycles`].
    #[must_use]
    pub fn periodic_bus_cycles(&self) -> Option<u64> {
        if self.mode != LapicTimerMode::Periodic || self.masked || self.tmict == 0 {
            return None;
        }
        Some(u64::from(self.tmict) * u64::from(self.divide))
    }
}

/// Read a 32-bit APIC register out of the page `KVM_GET_LAPIC` filled.
fn lapic_reg(regs: &[::std::os::raw::c_char; 1024], offset: usize) -> u32 {
    let mut bytes = [0u8; 4];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = regs[offset + i] as u8;
    }
    u32::from_le_bytes(bytes)
}

/// `TDCR` → divisor, the same decode KVM's `update_divide_count` does.
fn decode_divide(tdcr: u32) -> u32 {
    let low = tdcr & 0xf;
    let exp = ((low & 0x3) | ((low & 0x8) >> 1)) + 1;
    1u32 << (exp & 0x7)
}

/// What Linux has left PIT channel 0 — the guest's `tick_broadcast`
/// device (measured as the PIT) — programmed to do.
///
/// Read from the mode byte, because that is the only thing about the
/// broadcast device `KVM_GET_PIT2` actually tells the truth about:
/// channel 0's live count comes from `hrtimer_get_remaining` inside
/// KVM (`kpit_elapsed`), and `count_load_time` is written only at reset
/// and on a gate rising edge — never by the count writes Linux uses to
/// arm the thing. So "when does the PIT next fire" is **not** readable,
/// and the mode is what decides whether a jump may proceed at all.
///
/// The classification is Linux's own state machine
/// (`arch/x86/kernel/i8253.c`), not the i8254 datasheet's: `pit_shutdown`
/// writes mode 0, `pit_set_periodic` mode 2, `pit_set_oneshot` mode 4,
/// and `pit_next_event` re-arms by writing the count with the mode left
/// at 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PitClass {
    /// Mode 0 — Linux's `pit_shutdown`. The broadcast device is off.
    ///
    /// KVM does arm one hrtimer for the count that write carries (its
    /// mode-0 case goes to `create_pit_timer`), so for at most one
    /// 54.9 ms span after a shutdown there is a stray pending IRQ0 this
    /// class does not account for. Bounded by the counter's 16 bits.
    ShutDown,
    /// Mode 2 or 3 — a rate generator is running.
    Periodic,
    /// Mode 1, 4 or 5 — a one-shot is in service (`pit_set_oneshot`
    /// plus `pit_next_event`). When it fires is not exported.
    OneShotOpaque,
    /// Any other mode byte, including the 0xff KVM leaves at reset:
    /// `pit_load_count` destroys the hrtimer, so nothing is armed.
    NoTimer,
}

/// PIT channel 0 as read by [`Vm::pit_channel0`].
#[derive(Debug, Clone, Copy)]
pub struct PitChannel0 {
    /// Raw mode byte (0xff before the guest programs it).
    pub mode: u8,
    /// Programmed initial count; 0 means 65536 on the i8254.
    pub count: u32,
    /// `count / 1_193_182` — the full span of the current program, and
    /// so the longest a PIT program can ever be (54.9 ms).
    pub span: Duration,
    /// What that means for a clock jump.
    pub class: PitClass,
}

/// Where an armed timer that a forward jump must not leap over was read
/// from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerSource {
    /// A vCPU's LAPIC one-shot timer (`TMCCT`).
    LapicOneShot,
    /// A vCPU's `IA32_TSC_DEADLINE`.
    TscDeadline,
    /// PIT channel 0 in one-shot mode — the broadcast device.
    PitOneShot,
}

impl TimerSource {
    /// Short name for counters and log lines.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            TimerSource::LapicOneShot => "lapic_one_shot",
            TimerSource::TscDeadline => "tsc_deadline",
            TimerSource::PitOneShot => "pit_one_shot",
        }
    }
}

/// One armed timer and how long it has left, in host time.
#[derive(Debug, Clone, Copy)]
pub struct ArmedTimer {
    /// Which of the three sources reported it.
    pub source: TimerSource,
    /// vCPU it belongs to; `None` for the VM-scoped PIT.
    pub cpu: Option<usize>,
    /// Host wall time until it fires.
    pub expires_in: Duration,
}

/// Every timer of one paused VM, read without writing anything.
///
/// Produced by [`Vm::sample_timers`]. The three lists are deliberately
/// separate: only `armed` bounds a jump, `periodic` is measurement, and
/// a non-empty `unmodelled` means the caller has no business jumping at
/// all.
#[derive(Debug, Clone, Default)]
pub struct TimerSurvey {
    /// Deadlines. A forward jump must land before the earliest of them.
    pub armed: Vec<ArmedTimer>,
    /// Free-running periodic timers, described and with their period.
    pub periodic: Vec<(String, Duration)>,
    /// Timer programming whose expiry this reader cannot read. A
    /// non-empty list means the caller must decline: an opaque timer is
    /// a timer that could be about to fire.
    pub unmodelled: Vec<String>,
    /// PIT channel 0 as it was read, kept for the measurement tables.
    /// `None` only on a survey that never reached the PIT.
    pub pit: Option<PitChannel0>,
}

impl TimerSurvey {
    /// Earliest armed deadline, or `None` when nothing is armed —
    /// which is never a licence to invent one.
    #[must_use]
    pub fn earliest(&self) -> Option<Duration> {
        self.armed.iter().map(|t| t.expires_in).min()
    }

    /// Fold another member's survey in, so a cluster-wide minimum is
    /// the minimum over every member.
    pub fn absorb(&mut self, other: Self) {
        self.armed.extend(other.armed);
        self.periodic.extend(other.periodic);
        self.unmodelled.extend(other.unmodelled);
        self.pit = self.pit.or(other.pit);
    }
}

/// `IA32_TSC` — the vCPU's timestamp counter.
const MSR_IA32_TSC: u32 = 0x0000_0010;
/// `IA32_TSC_DEADLINE` — the armed one-shot LAPIC deadline, in TSC
/// units. Zero means *unarmed*, not "a deadline at TSC zero".
const MSR_IA32_TSC_DEADLINE: u32 = 0x0000_06E0;

/// One vCPU's timekeeping state at a single instant, read while the VM
/// is paused. See [`Vm::sample_time_state`].
#[derive(Debug, Clone, Copy)]
pub struct CpuTimeSample {
    /// `KVM_GET_MP_STATE`. See [`Self::is_halted`].
    pub mp_state: u32,
    /// `IA32_TSC`.
    pub tsc: u64,
    /// `IA32_TSC_DEADLINE`. **Zero means unarmed**, so a gap must never
    /// be computed from a zero here.
    pub tsc_deadline: u64,
}

impl CpuTimeSample {
    /// Whether this vCPU was in `HLT` — the state an idle guest CPU
    /// parks in once the haltpoll window expires.
    #[must_use]
    pub fn is_halted(&self) -> bool {
        self.mp_state == kvm_bindings::KVM_MP_STATE_HALTED
    }

    /// TSC ticks until this vCPU's armed deadline; `None` when the
    /// deadline timer is unarmed, and `Some(0)` when it is armed but
    /// already past (the timer is about to fire).
    ///
    /// Divide by [`TimeSample::tsc_khz`] to get milliseconds — TSC
    /// units and `kvmclock_ns` are different clocks and must never be
    /// mixed.
    #[must_use]
    pub fn ticks_to_deadline(&self) -> Option<u64> {
        if self.tsc_deadline == 0 {
            return None;
        }
        Some(self.tsc_deadline.saturating_sub(self.tsc))
    }
}

/// A paused VM's clocks and per-vCPU timer state. Read-only; produced
/// by [`Vm::sample_time_state`].
#[derive(Debug, Clone)]
pub struct TimeSample {
    /// `KVM_GET_CLOCK` — the kvmclock nanoseconds the guest reads.
    pub kvmclock_ns: u64,
    /// vCPU 0's TSC frequency: the only legal divisor for TSC deltas.
    pub tsc_khz: u32,
    /// Per-vCPU state, in vCPU-index order.
    pub cpus: Vec<CpuTimeSample>,
}

/// Read one MSR off a paused vCPU.
fn read_msr(vcpu_fd: &VcpuFd, cpu: usize, index: u32) -> Result<u64, VmError> {
    let entries = [kvm_bindings::kvm_msr_entry {
        index,
        reserved: 0,
        data: 0,
    }];
    let mut msrs = kvm_bindings::Msrs::from_entries(&entries).map_err(|e| VmError::GetMsr {
        index,
        cpu,
        reason: format!("building the MSR list failed: {e:?}"),
    })?;
    match vcpu_fd.get_msrs(&mut msrs) {
        Ok(1) => Ok(msrs.as_slice()[0].data),
        Ok(n) => Err(VmError::GetMsr {
            index,
            cpu,
            reason: format!("KVM_GET_MSRS returned {n} entries, wanted 1"),
        }),
        Err(e) => Err(VmError::GetMsr {
            index,
            cpu,
            reason: format!("KVM_GET_MSRS: {e}"),
        }),
    }
}

/// Write one MSR on a paused vCPU. `Err` carries the reason only — the
/// caller knows which vCPU and which step it was on.
fn write_msr(vcpu_fd: &VcpuFd, index: u32, data: u64) -> Result<(), String> {
    let entries = [kvm_bindings::kvm_msr_entry {
        index,
        reserved: 0,
        data,
    }];
    let msrs = kvm_bindings::Msrs::from_entries(&entries)
        .map_err(|e| format!("building the MSR list failed: {e:?}"))?;
    match vcpu_fd.set_msrs(&msrs) {
        Ok(1) => Ok(()),
        Ok(n) => Err(format!("KVM_SET_MSRS wrote {n} entries, wanted 1")),
        Err(e) => Err(format!("KVM_SET_MSRS: {e}")),
    }
}

/// The `KVM_VCPU_TSC_CTRL` / `KVM_VCPU_TSC_OFFSET` vCPU device
/// attribute, reading from (set) or writing to (get) `addr`.
fn tsc_offset_attr(addr: u64) -> kvm_bindings::kvm_device_attr {
    kvm_bindings::kvm_device_attr {
        flags: 0,
        group: kvm_bindings::KVM_VCPU_TSC_CTRL,
        attr: u64::from(kvm_bindings::KVM_VCPU_TSC_OFFSET),
        addr,
    }
}

/// `_IOW(KVMIO, nr, struct kvm_device_attr)`. kvm-ioctls 0.19 wraps the
/// vCPU device-attribute ioctls for aarch64 only, so on `x86_64` all
/// three are raw calls — same style as `fork.rs`'s `KVM_KVMCLOCK_CTRL`.
const fn kvm_device_attr_ioctl(nr: libc::c_ulong) -> libc::c_ulong {
    0x4000_0000
        | ((std::mem::size_of::<kvm_bindings::kvm_device_attr>() as libc::c_ulong) << 16)
        | (0xAE << 8)
        | nr
}
const KVM_SET_DEVICE_ATTR: libc::c_ulong = kvm_device_attr_ioctl(0xE1);
const KVM_GET_DEVICE_ATTR: libc::c_ulong = kvm_device_attr_ioctl(0xE2);
const KVM_HAS_DEVICE_ATTR: libc::c_ulong = kvm_device_attr_ioctl(0xE3);

/// Issue one device-attribute ioctl on a **paused** vCPU.
fn device_attr_ioctl(
    vcpu_fd: &VcpuFd,
    request: libc::c_ulong,
    attr: &kvm_bindings::kvm_device_attr,
    what: &str,
) -> Result<(), String> {
    // SAFETY: `vcpu_fd` is a live vCPU fd of a paused VM, so no
    // `KVM_RUN` is in flight on it. `attr` outlives the call and — for
    // the requests that use it — `attr.addr` points at a live `u64`
    // KVM reads or writes exactly 8 bytes of.
    if unsafe { libc::ioctl(vcpu_fd.as_raw_fd(), request, attr) } < 0 {
        return Err(format!("{what}: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

/// The VM-scoped device-attribute group the carried KVM patch in
/// `utils/kvm-dilation` adds (`'dila'`), and its attributes: the `u32`
/// dilation factor, and the patch's own read-only ABI generation. No
/// mainline kernel answers device attributes on a VM fd at all, so a
/// stock host fails the `KVM_HAS_DEVICE_ATTR` probe with `ENOTTY` and
/// can never be mistaken for a patched one.
const KVM_VM_DILATION: u32 = 0x6469_6c61;
const KVM_VM_DILATION_FACTOR: u64 = 0;
const KVM_VM_DILATION_ABI: u64 = 1;

/// The patch generation that added a live factor change.
/// Generation 1 answers `EBUSY` once any vCPU exists.
pub const DILATION_ABI_LIVE_SET: u32 = 2;

/// Largest factor the carried patch accepts (`KVM_MAX_DILATION`). The
/// hardware TSC multiplier bounds it further, per vCPU frequency, and
/// the kernel refuses out-of-range ratios rather than clamping them.
pub const MAX_DILATION: u32 = 64;

fn dilation_attr(addr: u64) -> kvm_bindings::kvm_device_attr {
    kvm_bindings::kvm_device_attr {
        flags: 0,
        group: KVM_VM_DILATION,
        attr: KVM_VM_DILATION_FACTOR,
        addr,
    }
}

/// Generation of the carried patch the loaded modules were built from.
///
/// The modules are built from a file in this tree and swapped in and out
/// around a test suite, so "is this host patched" is not a sharp enough
/// question: an edited patch whose rebuild was skipped presents as a
/// patched host missing the behaviour the edit added, which reads as a
/// bug in the caller rather than a stale install. Generation 1 predates
/// the attribute and is inferred from its absence.
///
/// # Errors
/// `/dev/kvm` is unusable, or the loaded modules are stock.
pub fn host_dilation_abi() -> Result<u32, String> {
    let kvm = Kvm::new().map_err(|e| format!("open /dev/kvm: {e}"))?;
    let vm_fd = kvm.create_vm().map_err(|e| format!("KVM_CREATE_VM: {e}"))?;
    vm_supports_dilation(&vm_fd)?;
    let mut abi: u32 = 0;
    let attr = kvm_bindings::kvm_device_attr {
        attr: KVM_VM_DILATION_ABI,
        ..dilation_attr(std::ptr::from_mut(&mut abi) as u64)
    };
    match vm_device_attr_ioctl(
        &vm_fd,
        KVM_GET_DEVICE_ATTR,
        &attr,
        "KVM_GET_DEVICE_ATTR(KVM_VM_DILATION_ABI)",
    ) {
        Ok(()) => Ok(abi),
        Err(_) => Ok(1),
    }
}

/// Issue one device-attribute ioctl on a VM fd.
fn vm_device_attr_ioctl(
    vm_fd: &VmFd,
    request: libc::c_ulong,
    attr: &kvm_bindings::kvm_device_attr,
    what: &str,
) -> Result<(), String> {
    // SAFETY: `vm_fd` is a live VM fd, `attr` outlives the call, and
    // `attr.addr` — where the request uses it — points at a live `u32`
    // KVM reads or writes exactly 4 bytes of.
    if unsafe { libc::ioctl(vm_fd.as_raw_fd(), request, attr) } < 0 {
        return Err(format!("{what}: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Whether this host runs the carried time-dilation patch.
fn vm_supports_dilation(vm_fd: &VmFd) -> Result<(), String> {
    vm_device_attr_ioctl(
        vm_fd,
        KVM_HAS_DEVICE_ATTR,
        &dilation_attr(0),
        "KVM_HAS_DEVICE_ATTR(KVM_VM_DILATION)",
    )
}

/// Whether this host runs the carried time-dilation patch
/// (`utils/kvm-dilation`), asked of a throwaway VM fd.
///
/// The answer comes from KVM, not from a module version string, so a
/// stock host can never be mistaken for a dilating one.
///
/// # Errors
/// The reason the host cannot dilate: either `/dev/kvm` is unusable or
/// the loaded modules are stock.
pub fn host_supports_dilation() -> Result<(), String> {
    let kvm = Kvm::new().map_err(|e| format!("open /dev/kvm: {e}"))?;
    let vm_fd = kvm.create_vm().map_err(|e| format!("KVM_CREATE_VM: {e}"))?;
    vm_supports_dilation(&vm_fd)
}

/// Set this VM's dilation factor.
///
/// Legal before any vCPU exists and also on a live VM whose every
/// vCPU is paused. The kernel is the
/// one that decides: a runnable vCPU is `EBUSY`, because the factor
/// rides on each vCPU's hardware TSC multiplier and half a cluster at
/// the new rate is worse than a refusal. `pub(crate)` so restore
/// can apply a snapshot's factor before the first vCPU
/// exists.
pub(crate) fn set_dilation(vm_fd: &VmFd, factor: u32) -> Result<(), String> {
    vm_supports_dilation(vm_fd).map_err(|e| {
        format!("this host does not expose per-VM time dilation ({e}) — install utils/kvm-dilation")
    })?;
    let attr = dilation_attr(std::ptr::from_ref(&factor) as u64);
    vm_device_attr_ioctl(
        vm_fd,
        KVM_SET_DEVICE_ATTR,
        &attr,
        &format!("KVM_SET_DEVICE_ATTR(KVM_VM_DILATION) = {factor}"),
    )?;
    let mut got: u32 = 0;
    let attr = dilation_attr(std::ptr::from_mut(&mut got) as u64);
    vm_device_attr_ioctl(
        vm_fd,
        KVM_GET_DEVICE_ATTR,
        &attr,
        "KVM_GET_DEVICE_ATTR(KVM_VM_DILATION)",
    )?;
    if got != factor {
        return Err(format!(
            "the kernel kept dilation at {got} after being asked for {factor}"
        ));
    }
    Ok(())
}

/// Whether this vCPU's kernel knows the TSC-offset attribute at all
/// (`KVM_CAP_VCPU_ATTRIBUTES`, Linux 5.18+). `addr` is ignored.
fn has_tsc_offset_attr(vcpu_fd: &VcpuFd) -> Result<(), String> {
    device_attr_ioctl(
        vcpu_fd,
        KVM_HAS_DEVICE_ATTR,
        &tsc_offset_attr(0),
        "KVM_HAS_DEVICE_ATTR(KVM_VCPU_TSC_CTRL/KVM_VCPU_TSC_OFFSET)",
    )
}

/// `KVM_KVMCLOCK_CTRL` — `_IO(KVMIO, 0xad)`. Tells the guest its
/// pvclock page was "guest stopped", so a forward jump is a suspend it
/// touches its watchdogs for instead of a stall it reports.
const KVM_KVMCLOCK_CTRL: libc::c_ulong = (0xAE << 8) | 0xAD;

/// Mark one paused vCPU's pvclock page "guest stopped".
///
/// `EINVAL` means this vCPU never registered a pvclock page
/// (`MSR_KVM_SYSTEM_TIME_NEW`), so there is nowhere to record the
/// suspend — the honest answer for a guest that has no kvmclock.
pub(crate) fn kvmclock_ctrl(vcpu_fd: &VcpuFd) -> Result<(), String> {
    // SAFETY: `vcpu_fd` is a live vCPU fd of a stopped/paused VM;
    // KVM_KVMCLOCK_CTRL takes no argument.
    if unsafe { libc::ioctl(vcpu_fd.as_raw_fd(), KVM_KVMCLOCK_CTRL) } < 0 {
        return Err(format!(
            "KVM_KVMCLOCK_CTRL: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Read one paused vCPU's TSC offset (guest TSC − host TSC, in that
/// vCPU's own ticks).
fn read_tsc_offset(vcpu_fd: &VcpuFd) -> Result<u64, String> {
    let mut offset: u64 = 0;
    let attr = tsc_offset_attr(std::ptr::from_mut(&mut offset) as u64);
    device_attr_ioctl(
        vcpu_fd,
        KVM_GET_DEVICE_ATTR,
        &attr,
        "KVM_GET_DEVICE_ATTR(KVM_VCPU_TSC_OFFSET)",
    )?;
    Ok(offset)
}

/// Write one paused vCPU's TSC offset.
fn write_tsc_offset(vcpu_fd: &VcpuFd, offset: u64) -> Result<(), String> {
    let attr = tsc_offset_attr(std::ptr::from_ref(&offset) as u64);
    device_attr_ioctl(
        vcpu_fd,
        KVM_SET_DEVICE_ATTR,
        &attr,
        &format!("KVM_SET_DEVICE_ATTR(KVM_VCPU_TSC_OFFSET) = {offset:#x}"),
    )
}

impl Vm {
    /// This VM's time dilation factor **now**: guest time runs this many
    /// times faster than wall time. 1 unless [`VmBuilder::dilation`]
    /// asked for more, the snapshot it was restored from
    /// was taken at more, or [`Self::set_dilation_live`]
    /// changed it since.
    #[must_use]
    pub fn dilation(&self) -> u32 {
        self.dilation
    }

    /// The highest factor this VM has ever run at.
    ///
    /// Not the same question as [`Self::dilation`]: a VM whose factor
    /// has been dropped back to 1 has a stock *rate* but a guest clock
    /// still sitting in the host's future (CHALLENGES #191). Capture
    /// records the *current* factor; the peak is for
    /// observers, not a fork refusal.
    #[must_use]
    pub fn dilation_peak(&self) -> u32 {
        self.dilation_peak
    }

    /// Read this VM's clocks and per-vCPU timer state without writing
    /// anything (the clock survey).
    ///
    /// **Paused-only.** Between [`Self::start`] and [`Self::pause`] the
    /// `VcpuFd`s live inside the run threads, so any vCPU ioctl issued
    /// here would race `KVM_RUN`. This returns [`VmError::NotPaused`]
    /// rather than sampling whatever subset of fds happens to be back.
    ///
    /// Nothing in this path writes a clock, an MSR, or a TSC offset.
    pub fn sample_time_state(&self) -> Result<TimeSample, VmError> {
        let want = self.require_paused("sample_time_state")?;
        let clock = self.vm_fd.get_clock().map_err(VmError::GetClock)?;
        let tsc_khz = self.vcpu_fds[0].get_tsc_khz().map_err(VmError::GetTscKhz)?;
        let mut cpus = Vec::with_capacity(want);
        for (cpu, vcpu_fd) in self.vcpu_fds.iter().enumerate() {
            let mp_state = vcpu_fd.get_mp_state().map_err(VmError::GetMpState)?;
            cpus.push(CpuTimeSample {
                mp_state: mp_state.mp_state,
                tsc: read_msr(vcpu_fd, cpu, MSR_IA32_TSC)?,
                tsc_deadline: read_msr(vcpu_fd, cpu, MSR_IA32_TSC_DEADLINE)?,
            });
        }
        Ok(TimeSample {
            kvmclock_ns: clock.clock,
            tsc_khz,
            cpus,
        })
    }

    /// One paused vCPU's LAPIC timer programming.
    ///
    /// On a host whose `KVM_GET_SUPPORTED_CPUID` does not report
    /// `CPUID.1:ECX[24]` (AMD, kernel 6.8) `IA32_TSC_DEADLINE` reads
    /// zero on every vCPU and this — the LAPIC one-shot counter — is the
    /// timer an auto-warp policy has to read. Where the bit is reported
    /// (Intel, kernel 7.0) the mode here is [`LapicTimerMode::TscDeadline`],
    /// `TMCCT` is meaningless, and the deadline MSR is the target.
    pub fn lapic_timer(&self, cpu: usize) -> Result<LapicTimerState, VmError> {
        self.require_paused("lapic_timer")?;
        let regs = self.vcpu_fds[cpu]
            .get_lapic()
            .map_err(|e| VmError::GetLapic {
                cpu,
                reason: format!("KVM_GET_LAPIC: {e}"),
            })?
            .regs;
        let lvtt = lapic_reg(&regs, APIC_LVTT);
        let mode = match (lvtt & APIC_LVT_TIMER_MODE_MASK) >> APIC_LVT_TIMER_MODE_SHIFT {
            0 => LapicTimerMode::OneShot,
            1 => LapicTimerMode::Periodic,
            2 => LapicTimerMode::TscDeadline,
            _ => LapicTimerMode::Reserved,
        };
        Ok(LapicTimerState {
            mode,
            masked: lvtt & APIC_LVT_MASKED != 0,
            tmict: lapic_reg(&regs, APIC_TMICT),
            tmcct: lapic_reg(&regs, APIC_TMCCT),
            divide: decode_divide(lapic_reg(&regs, APIC_TDCR)),
        })
    }

    /// PIT channel 0 — the guest's `tick_broadcast` device. See
    /// [`PitClass`] for why this reports a classification and not a
    /// time to expiry.
    pub fn pit_channel0(&self) -> Result<PitChannel0, VmError> {
        let pit = self
            .vm_fd
            .get_pit2()
            .map_err(|e| VmError::GetPit(e.to_string()))?;
        let ch = &pit.channels[0];
        // Count 0 means 65536 on the i8254, never "no timer".
        let count = if ch.count == 0 { 65_536 } else { ch.count };
        let class = if ch.gate == 0 {
            PitClass::NoTimer
        } else {
            match ch.mode {
                0 => PitClass::ShutDown,
                2 | 3 => PitClass::Periodic,
                1 | 4 | 5 => PitClass::OneShotOpaque,
                _ => PitClass::NoTimer,
            }
        };
        Ok(PitChannel0 {
            mode: ch.mode,
            count,
            span: Duration::from_nanos(u64::from(count) * 1_000_000_000 / PIT_FREQ_HZ),
            class,
        })
    }

    /// Every timer of this paused VM that a forward clock jump must not
    /// leap over.
    ///
    /// `bus_cycle_fs` is the measured length of one APIC bus cycle in
    /// **femtoseconds** — [`Self::calibrate_apic_bus_cycle_fs`]
    /// produces it. Passing a guessed one turns every `TMCCT` reading
    /// into a wrong deadline, which is why it is a parameter and not a
    /// constant; femtoseconds because a cycle is ~1 ns here, so
    /// nanosecond units would round the ratio to nothing. `None` is
    /// "not calibrated": legitimate for a guest whose vCPUs all run the
    /// TSC-deadline timer (there is no count to convert), and any
    /// one-shot or periodic count met without it is reported as
    /// unmodelled rather than converted by a guess.
    pub fn sample_timers(&self, bus_cycle_fs: Option<u64>) -> Result<TimerSurvey, VmError> {
        let want = self.require_paused("sample_timers")?;
        let mut survey = TimerSurvey::default();
        // A 32-bit count at divisor 128 is 5.5e11 cycles, so the
        // product stays inside a u64 for any bus cycle under ~30 µs.
        let bus = |cycles: u64| {
            bus_cycle_fs.map(|fs| Duration::from_nanos(cycles.saturating_mul(fs) / FS_PER_NS))
        };

        for cpu in 0..want {
            let vcpu_fd = &self.vcpu_fds[cpu];
            let lapic = self.lapic_timer(cpu)?;
            if let Some(cycles) = lapic.armed_bus_cycles() {
                match bus(cycles) {
                    Some(expires_in) => survey.armed.push(ArmedTimer {
                        source: TimerSource::LapicOneShot,
                        cpu: Some(cpu),
                        expires_in,
                    }),
                    None => survey.unmodelled.push(format!(
                        "vCPU {cpu} LAPIC one-shot armed ({cycles} bus cycles) with the APIC \
                         bus cycle uncalibrated"
                    )),
                }
            }
            if let Some(cycles) = lapic.periodic_bus_cycles() {
                match bus(cycles) {
                    Some(period) => survey
                        .periodic
                        .push((format!("vCPU {cpu} LAPIC periodic"), period)),
                    None => survey.unmodelled.push(format!(
                        "vCPU {cpu} LAPIC periodic ({cycles} bus cycles) with the APIC bus \
                         cycle uncalibrated"
                    )),
                }
            }
            if lapic.mode == LapicTimerMode::Reserved && !lapic.masked {
                survey
                    .unmodelled
                    .push(format!("vCPU {cpu} LVT timer mode 3 (reserved)"));
            }

            // Zero is unarmed, never "a deadline at TSC zero". Never
            // armed where the host kernel does not advertise
            // CPUID.1:ECX[24] (6.8); the live timer of every Ubuntu
            // vCPU where it does (7.0).
            let deadline = read_msr(vcpu_fd, cpu, MSR_IA32_TSC_DEADLINE)?;
            if deadline != 0 {
                let tsc = read_msr(vcpu_fd, cpu, MSR_IA32_TSC)?;
                let tsc_khz = vcpu_fd.get_tsc_khz().map_err(VmError::GetTscKhz)?;
                let ticks = deadline.saturating_sub(tsc);
                survey.armed.push(ArmedTimer {
                    source: TimerSource::TscDeadline,
                    cpu: Some(cpu),
                    expires_in: Duration::from_nanos(
                        ticks.saturating_mul(1_000_000) / u64::from(tsc_khz).max(1),
                    ),
                });
            }
        }

        let pit = self.pit_channel0()?;
        survey.pit = Some(pit);
        match pit.class {
            PitClass::ShutDown | PitClass::NoTimer => {}
            PitClass::Periodic => survey
                .periodic
                .push(("PIT channel 0 rate generator".to_string(), pit.span)),
            // The broadcast device is in service and KVM exports no
            // remaining time for it. This is the one case the spec
            // singles out — the wakeup of the *most* idle CPU — so it
            // is a decline, not a bound invented from `count`.
            PitClass::OneShotOpaque => survey.unmodelled.push(format!(
                "PIT channel 0 one-shot in service (mode {}, span {:?}); \
                 KVM_GET_PIT2 exports no remaining time for channel 0",
                pit.mode, pit.span
            )),
        }
        Ok(survey)
    }

    /// Whether any vCPU of this paused VM has a one-shot LAPIC count
    /// running — the only thing [`Self::calibrate_apic_bus_cycle_fs`]
    /// can measure against, and the only reading that needs its result.
    /// `false` on a guest whose vCPUs all arm the TSC-deadline timer
    /// (Intel hosts that advertise `CPUID.1:ECX[24]`): there, a
    /// calibration attempt would fail every cycle, forever, for a
    /// number nothing would consume.
    pub fn has_armed_lapic_one_shot(&self) -> Result<bool, VmError> {
        let want = self.require_paused("has_armed_lapic_one_shot")?;
        for cpu in 0..want {
            if self.lapic_timer(cpu)?.armed_bus_cycles().is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Measure how long one APIC bus cycle is, in femtoseconds, on this
    /// host.
    ///
    /// KVM computes `TMCCT` as `(target_expiration − now) / (bus cycle ×
    /// divisor)`, and `now` is host time that keeps running while the
    /// guest is paused. So two reads of one armed one-shot timer,
    /// `window` apart, give the bus cycle directly — no constant lifted
    /// out of a kernel header that a later kernel made a module
    /// parameter.
    ///
    /// **Paused-only**, and it costs `window` of pause: call it once and
    /// keep the answer. Fails loudly when no vCPU has an armed one-shot
    /// timer far enough out to measure against, because a policy with
    /// no calibration must decline rather than guess.
    pub fn calibrate_apic_bus_cycle_fs(&self, window: Duration) -> Result<u64, VmError> {
        let want = self.require_paused("calibrate_apic_bus_cycle_fs")?;
        // The vCPU whose one-shot timer is furthest out: it is the one
        // most likely to still be counting after the window.
        let mut best: Option<(usize, LapicTimerState)> = None;
        for cpu in 0..want {
            let st = self.lapic_timer(cpu)?;
            if st.armed_bus_cycles().is_some()
                && best.is_none_or(|(_, b)| st.armed_bus_cycles() > b.armed_bus_cycles())
            {
                best = Some((cpu, st));
            }
        }
        let (cpu, before) = best.ok_or_else(|| VmError::ApicUncalibrated {
            reason: "no vCPU has an armed one-shot LAPIC timer to measure against".to_string(),
        })?;

        let started = Instant::now();
        std::thread::sleep(window);
        let elapsed_ns = started.elapsed().as_nanos();
        let after = self.lapic_timer(cpu)?;

        if after.mode != before.mode || after.divide != before.divide {
            return Err(VmError::ApicUncalibrated {
                reason: format!(
                    "vCPU {cpu}'s timer was reprogrammed mid-window \
                     ({:?}/{} → {:?}/{})",
                    before.mode, before.divide, after.mode, after.divide
                ),
            });
        }
        let dropped = before.tmcct.checked_sub(after.tmcct).filter(|d| *d > 0);
        let Some(dropped) = dropped.filter(|_| after.tmcct > 0) else {
            return Err(VmError::ApicUncalibrated {
                reason: format!(
                    "vCPU {cpu}'s count went {} → {} over {elapsed_ns}ns — \
                     the timer expired inside the window",
                    before.tmcct, after.tmcct
                ),
            });
        };
        let cycles = u128::from(dropped) * u128::from(before.divide);
        // The window is wall time; the count drained in guest time, which
        // under dilation runs `dilation` times faster. Reporting the guest
        // figure is what keeps every consumer of this number — ε, the
        // minimum jump, the 30 s cap, the deadline a jump targets — in the
        // one unit the guest's own timers are in. At 1x it
        // is the identity.
        let guest_ns = elapsed_ns * u128::from(self.dilation);
        let bus_cycle_fs = u64::try_from(guest_ns * u128::from(FS_PER_NS) / cycles).unwrap_or(0);
        // The SDM fixes no bus frequency, and KVM's is a compile-time
        // 1 ns on this kernel (a module parameter from 6.12). Anything
        // outside 0.1–100 ns is a misread, not a host with an unusual
        // APIC.
        if !(100_000..=100_000_000).contains(&bus_cycle_fs) {
            return Err(VmError::ApicUncalibrated {
                reason: format!(
                    "measured {bus_cycle_fs}fs per bus cycle from a {dropped}-count drop \
                     over {elapsed_ns}ns at divisor {} — outside any plausible band",
                    before.divide
                ),
            });
        }
        log::info!(
            "auto-warp: APIC bus cycle measured at {bus_cycle_fs}fs \
             (vCPU {cpu}, divisor {}, {dropped} counts over {elapsed_ns}ns)",
            before.divide
        );
        Ok(bus_cycle_fs)
    }

    /// vCPUs whose `KVM_RUN` was cancelled between KVM staging an event
    /// injection and the VM entry that would have delivered it
    /// (CHALLENGES #78's check).
    ///
    /// The fork path re-queues such an event on restore; a warp has
    /// nowhere to put it, so the only correct move is to decline and
    /// let the next sample find the vCPU clean.
    pub fn vcpus_mid_injection(&self) -> Result<Vec<usize>, VmError> {
        let want = self.require_paused("vcpus_mid_injection")?;
        let mut out = Vec::new();
        for cpu in 0..want {
            let ev = self.vcpu_fds[cpu]
                .get_vcpu_events()
                .map_err(|e| VmError::GetLapic {
                    cpu,
                    reason: format!("KVM_GET_VCPU_EVENTS: {e}"),
                })?;
            if ev.interrupt.injected != 0 || ev.nmi.injected != 0 || ev.nmi.pending != 0 {
                out.push(cpu);
            }
        }
        Ok(out)
    }

    /// Change this **paused** VM's dilation factor in place: guest
    /// time runs `factor` nanoseconds per wall
    /// nanosecond from here on.
    ///
    /// **Paused-only, slope-only.** The kernel re-pins the affine map
    /// at the instant of the change, so the guest's `CLOCK_MONOTONIC`
    /// changes *slope* and does not jump, and it reprograms every
    /// vCPU's hardware TSC multiplier with a matching offset so the
    /// guest's own counter is continuous too. A runnable vCPU is
    /// `EBUSY` — the whole cluster is paused first, exactly as it is
    /// for [`Self::warp_clock`].
    ///
    /// Lowering the factor does not rewind anything: the guest keeps
    /// every nanosecond it has already been given (CHALLENGES #191),
    /// it just stops accumulating them so fast. Which is also why
    /// dropping back to 1 does **not** make this VM forkable again —
    /// see [`Self::dilation_peak`].
    pub fn set_dilation_live(&mut self, factor: u32) -> Result<(), VmError> {
        self.require_paused("set_dilation_live")?;
        self.set_dilation_raw(factor)?;
        self.dilation = factor;
        self.dilation_peak = self.dilation_peak.max(factor);
        Ok(())
    }

    /// `KVM_SET_DEVICE_ATTR(KVM_VM_DILATION)` on this VM's fd, with no
    /// host-side pause check.
    ///
    /// [`Self::set_dilation_live`] is the one to call — it refuses before
    /// the ioctl and keeps `dilation` in step with what the kernel
    /// believes. This is here because the kernel's own refusal (`EBUSY`
    /// while any vCPU is runnable) is the invariant the whole mechanism
    /// rests on, and an invariant only ever reached through a Rust guard
    /// that fires first is an untested one.
    pub fn set_dilation_raw(&self, factor: u32) -> Result<(), VmError> {
        if factor == 0 || factor > MAX_DILATION {
            return Err(VmError::DilationFactor(factor));
        }
        set_dilation(&self.vm_fd, factor).map_err(|reason| VmError::SetDilation { factor, reason })
    }

    /// Advance this paused VM's guest-visible clock by `delta`, so
    /// the guest's backoffs, probe periods and
    /// lease TTLs behave as if that much time had passed.
    ///
    /// **Paused-only, forward-only, all-or-nothing.** The clock the
    /// guest reads (`KVM_SET_CLOCK`) and the counter its armed timers
    /// compare against (the per-vCPU TSC offset) move by the same
    /// amount: moving one without the other either does nothing or
    /// fires timers wrong. `KVM_KVMCLOCK_CTRL` then tells each vCPU
    /// the jump was a suspend, which is what stops the guest reporting
    /// it as a stalled CPU.
    ///
    /// An error mid-warp restores the original TSC offsets and puts
    /// the kvmclock back (never behind where it started — the rollback
    /// adds the wall time the failed attempt took), and names the vCPU
    /// it died on.
    ///
    /// Caller contract: no guest work may be in flight. The cluster is
    /// paused, so an agent `exec` waiting on a reply sees its guest
    /// jump forward mid-syscall.
    pub fn warp_clock(&self, delta: Duration) -> Result<(), VmError> {
        let delta_ns = u64::try_from(delta.as_nanos())
            .ok()
            .filter(|ns| *ns > 0)
            .ok_or(VmError::WarpDelta(delta))?;
        self.require_paused("warp_clock")?;
        // Probe before the first write: a kernel without the attribute
        // must fail the whole warp, not the tail of it. `addr` is
        // ignored by KVM_HAS_DEVICE_ATTR.
        has_tsc_offset_attr(&self.vcpu_fds[0]).map_err(VmError::WarpNoTscOffsetAttr)?;

        // Everything the rollback needs, read before anything moves.
        let read_at = Instant::now();
        let clock_before = self.vm_fd.get_clock().map_err(VmError::GetClock)?.clock;
        let mut offsets = Vec::with_capacity(self.vcpu_fds.len());
        for (cpu, vcpu_fd) in self.vcpu_fds.iter().enumerate() {
            offsets.push(
                read_tsc_offset(vcpu_fd).map_err(|reason| VmError::WarpVcpu {
                    cpu,
                    what: "reading the TSC offset",
                    reason,
                    rollback: "nothing had been written yet".to_string(),
                })?,
            );
        }

        // 1. The clock the guest reads. Flags are an input only for
        //    KVM_CLOCK_REALTIME (see `fork::restore_kvmclock`).
        let data = kvm_bindings::kvm_clock_data {
            clock: clock_before.saturating_add(delta_ns),
            flags: 0,
            ..Default::default()
        };
        self.vm_fd
            .set_clock(&data)
            .map_err(|e| VmError::WarpSetClock {
                delta_ns,
                reason: e.to_string(),
            })?;

        match self.warp_vcpus(delta_ns, &offsets) {
            Ok(()) => {
                // `debug`, not `info`: the auto-warp policy loop calls
                // this up to 20 times a second per member, and a
                // per-VM info line at that rate buries
                // every other line in the daemon's journal.
                log::debug!(
                    "warp_clock: +{}ms on {} vCPUs (kvmclock {clock_before} → {})",
                    delta_ns / 1_000_000,
                    self.vcpu_fds.len(),
                    data.clock
                );
                Ok(())
            }
            Err((cpu, what, reason)) => Err(VmError::WarpVcpu {
                cpu,
                what,
                reason,
                rollback: self.unwarp(clock_before, read_at, &offsets),
            }),
        }
    }

    /// Per-vCPU half of [`Self::warp_clock`]. `Err` names the vCPU, the
    /// step, and the reason; the caller rolls back.
    fn warp_vcpus(
        &self,
        delta_ns: u64,
        offsets: &[u64],
    ) -> Result<(), (usize, &'static str, String)> {
        for ((cpu, vcpu_fd), before) in self.vcpu_fds.iter().enumerate().zip(offsets) {
            // 2. What this vCPU's armed timers compare against, in
            //    *this* vCPU's tick units — never a constant frequency.
            let tsc_khz = vcpu_fd
                .get_tsc_khz()
                .map_err(|e| (cpu, "reading tsc_khz", e.to_string()))?;
            let ticks = u64::try_from(u128::from(delta_ns) * u128::from(tsc_khz) / 1_000_000)
                .map_err(|_| {
                    (
                        cpu,
                        "converting the delta to TSC ticks",
                        format!("{delta_ns}ns at {tsc_khz}kHz overflows a u64"),
                    )
                })?;
            write_tsc_offset(vcpu_fd, before.wrapping_add(ticks))
                .map_err(|reason| (cpu, "writing the TSC offset", reason))?;

            // 3. A deadline armed before the warp holds a guest-TSC
            //    value that the advanced offset has just put in the
            //    past; rewriting it *unchanged* makes KVM recompute the
            //    host-side hrtimer (or VMX preemption timer) against the
            //    new offset, so the timer fires on the next entry — the
            //    jump lands ε before it, and it goes off. That is the
            //    semantics `autowarp::EPSILON` is written for.
            //
            //    Never armed under host kernel 6.8, which does not
            //    advertise CPUID.1:ECX[24]: the guest runs the LAPIC
            //    one-shot, not touched here. Its KVM hrtimer is
            //    host-anchored, but on VMX the preemption timer re-reads
            //    a guest-TSC copy of the expiry whenever a pause wakes
            //    the vCPU, so there a jumped one-shot fires at the next
            //    pause and on SVM it never does (CHALLENGES #264). The
            //    live timer of every Ubuntu vCPU under kernel 7.0
            //    (`lapic-deadline`). It is
            //    not shifted along with the offset to mirror the
            //    one-shot's host expiry: measured, that makes every idle
            //    cycle re-jump the same still-armed deadline, fabricating
            //    guest time at up to R²/cycle per host wait — a 160 s
            //    kubelet backoff stamped as 245 s, 5.00× "compression"
            //    past the 3.76× idleness ceiling (CHALLENGES #261).
            let deadline = read_msr(vcpu_fd, cpu, MSR_IA32_TSC_DEADLINE)
                .map_err(|e| (cpu, "reading IA32_TSC_DEADLINE", e.to_string()))?;
            if deadline != 0 {
                write_msr(vcpu_fd, MSR_IA32_TSC_DEADLINE, deadline)
                    .map_err(|reason| (cpu, "rewriting IA32_TSC_DEADLINE", reason))?;
            }

            // 4. Tell the guest it was suspended, not stalled.
            kvmclock_ctrl(vcpu_fd).map_err(|reason| {
                (
                    cpu,
                    "KVM_KVMCLOCK_CTRL",
                    format!(
                        "{reason} — this guest has no kvmclock page registered, so it \
                         cannot be told the jump was a suspend"
                    ),
                )
            })?;
        }
        Ok(())
    }

    /// Undo a failed warp: original TSC offsets back, kvmclock back to
    /// where it was plus the wall time the attempt took (forward-only
    /// holds even on the error path). Returns what was restored, for
    /// the error message.
    fn unwarp(&self, clock_before: u64, read_at: Instant, offsets: &[u64]) -> String {
        let mut failures = Vec::new();
        // Forward-only holds on the error path too: put the clock back
        // where it was *plus* what the attempt cost, so a failed warp is
        // a few microseconds of stall and never a step backwards.
        // `read_at` is microseconds old, so the conversion cannot fail
        // short of 584 years of elapsed time — and 0 would cost only
        // those microseconds, which is why it is not worth a second
        // failure mode inside a rollback.
        let elapsed_ns = u64::try_from(read_at.elapsed().as_nanos()).unwrap_or(0);
        let data = kvm_bindings::kvm_clock_data {
            clock: clock_before.saturating_add(elapsed_ns),
            flags: 0,
            ..Default::default()
        };
        if let Err(e) = self.vm_fd.set_clock(&data) {
            failures.push(format!("kvmclock: {e}"));
        }
        for ((cpu, vcpu_fd), before) in self.vcpu_fds.iter().enumerate().zip(offsets) {
            if let Err(e) = write_tsc_offset(vcpu_fd, *before) {
                failures.push(format!("vCPU {cpu} TSC offset: {e}"));
            }
        }
        if failures.is_empty() {
            "the original TSC offsets and kvmclock were restored".to_string()
        } else {
            format!(
                "ROLLBACK INCOMPLETE, this VM's clock is now inconsistent: {}",
                failures.join("; ")
            )
        }
    }
}

/// Advance the guest-visible clock of every VM in `vms` by the same
/// `delta`, with all of them paused for the whole write,
/// and hand back the host wall time the pause → warp → resume cycle
/// took.
///
/// Lockstep or nothing: etcd heartbeats, lease TTLs and TLS skew checks
/// tolerate a uniform jump across a cluster, not a skewed one, so the
/// clocks only move while every member is stopped.
///
/// Every VM is resumed on every path — a warp that failed on member 2
/// still hands members 0 and 1 back running, and a resume that itself
/// fails is an error, not a log line.
pub fn warp_clock_lockstep(vms: &mut [&mut Vm], delta: Duration) -> Result<Duration, VmError> {
    if vms.is_empty() {
        return Err(VmError::WarpNoVms);
    }
    let started = Instant::now();
    let count = vms.len();
    let resume_failures = std::cell::RefCell::new(Vec::<String>::new());
    let mut guard = scopeguard::guard(vms, |vms| {
        for (i, vm) in vms.iter_mut().enumerate() {
            if let Err(e) = vm.resume() {
                log::error!("warp_clock_lockstep: VM {i} did not resume: {e}");
                resume_failures.borrow_mut().push(format!("VM {i} ({e})"));
            }
        }
    });
    for vm in guard.iter_mut() {
        vm.pause()?;
    }
    for vm in guard.iter() {
        vm.warp_clock(delta)?;
    }
    drop(guard);

    let elapsed = started.elapsed();
    let failures = resume_failures.into_inner();
    if !failures.is_empty() {
        return Err(VmError::WarpResume(failures.join(", ")));
    }
    log::info!(
        "warp_clock_lockstep: +{}ms on {count} VMs in {elapsed:?}",
        delta.as_millis()
    );
    Ok(elapsed)
}

/// Change the dilation factor of every VM in `vms` to `factor`, with all
/// of them paused for the whole write, and hand back the
/// host wall time the pause → set → resume cycle took.
///
/// One factor for the cluster, for the same reason a warp is lockstep:
/// members whose clocks run at *different* rates diverge without bound,
/// which is worse than the bounded offset skew a jump risks. Every VM is
/// resumed on every path, and a resume that fails is an error.
pub fn set_dilation_lockstep(vms: &mut [&mut Vm], factor: u32) -> Result<Duration, VmError> {
    if vms.is_empty() {
        return Err(VmError::DilationNoVms);
    }
    let started = Instant::now();
    let count = vms.len();
    let resume_failures = std::cell::RefCell::new(Vec::<String>::new());
    let mut guard = scopeguard::guard(vms, |vms| {
        for (i, vm) in vms.iter_mut().enumerate() {
            if let Err(e) = vm.resume() {
                log::error!("set_dilation_lockstep: VM {i} did not resume: {e}");
                resume_failures.borrow_mut().push(format!("VM {i} ({e})"));
            }
        }
    });
    let before: Vec<u32> = guard.iter().map(|vm| vm.dilation()).collect();
    for vm in guard.iter_mut() {
        vm.pause()?;
    }
    for i in 0..count {
        if let Err(e) = guard[i].set_dilation_live(factor) {
            // Members already switched are at a rate the rest are not.
            // Rates diverge without bound, so put them back before
            // returning — and say so if even that fails.
            let mut undone = Vec::new();
            for j in 0..i {
                if let Err(e) = guard[j].set_dilation_live(before[j]) {
                    undone.push(format!("VM {j} stuck at x{factor} ({e})"));
                }
            }
            drop(guard);
            return Err(if undone.is_empty() {
                e
            } else {
                VmError::SetDilation {
                    factor,
                    reason: format!("{e}; rolling the cluster back left {}", undone.join(", ")),
                }
            });
        }
    }
    drop(guard);

    let elapsed = started.elapsed();
    let failures = resume_failures.into_inner();
    if !failures.is_empty() {
        return Err(VmError::DilationResume(failures.join(", ")));
    }
    log::info!("set_dilation_lockstep: x{factor} on {count} VMs in {elapsed:?}");
    Ok(elapsed)
}
