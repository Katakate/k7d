//! Engine-agnostic guest handle (`enum Guest`).
//!
//! Today it ships a single arm, [`Guest::Native`], wrapping the in-process
//! KVM [`Vm`](crate::vm::Vm); `Firecracker(FcVm)` follows. The control
//! plane, tree, cluster tree and pool hold this type instead of `Vm` so
//! those modules do not grow a second engine later.
//!
//! Coarse operations the daemon needs live on [`Guest`]. Fine-grained
//! fork internals (`mem_span`, dirty bitmaps, `prepare_fork_source_in`,
//! …) go through [`Guest::as_native`] / [`Guest::as_native_mut`], which
//! cannot fail today and return [`GuestError::Unsupported`] once a
//! non-native arm exists.

use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::api::AgentClient;
use crate::fc::{FcError, FcVm};
use crate::fork::ForkError;
use crate::snapshot::SnapshotError;
use crate::vm::{VirtiofsConfig, Vm, VmError};

/// VMM engine a VM is created on.
///
/// Serde names are `"native"` and `"firecracker"`. Omitted fields
/// deserialise as [`Backend::Native`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    /// In-process KVM VMM (`crates/k7d/src/vm.rs`).
    #[default]
    Native,
    /// Stock Firecracker + jailer. The arm does not exist yet —
    /// `CreateVm` with this backend returns [`GuestError::Unsupported`].
    Firecracker,
}

/// How a host-side client reaches the guest agent.
///
/// Native guests listen on vsock. Firecracker adds a vsock-UDS variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentEndpoint {
    /// `AF_VSOCK` connect to `cid` on the host.
    Vsock {
        /// Guest vsock CID.
        cid: u64,
    },
    /// Firecracker's vsock Unix-socket proxy: connect to `path`, send
    /// `CONNECT <agent port>\n`, expect `OK <port>\n`
    /// ([`AgentClient::connect_fc_uds`]).
    FcUds {
        /// Host path of the microVM's `run/v.sock`.
        path: String,
    },
}

/// A running (or paused) guest, regardless of VMM engine.
///
/// Single-variant today. Dropping a [`Guest`] drops the inner [`Vm`],
/// which tears down vCPU threads, device workers, virtiofsd children
/// and the TAP — the same `Drop` order [`crate::control`] relies on
/// when a [`Guest`] field precedes `cpu_cgroup`.
pub enum Guest {
    /// In-process KVM VMM. Boxed because a [`Vm`] owns every device's
    /// state inline; an unboxed variant would size every `Guest` — and
    /// every `VmEntry` in the daemon's map — to it.
    Native(Box<Vm>),
    /// Stock Firecracker under the stock jailer. Boxed for
    /// the same reason: its drive and disk bookkeeping is inline.
    Firecracker(Box<FcVm>),
}

/// Failures from [`Guest`] operations.
#[derive(Debug, thiserror::Error)]
pub enum GuestError {
    /// The requested operation has no implementation on this backend.
    #[error("{op} is not supported on backend {backend:?}")]
    Unsupported {
        /// Engine that refused the op.
        backend: Backend,
        /// Control-plane / method name (`create_vm`, `warp_clock`, …).
        op: &'static str,
    },
    /// Inner native VMM error.
    #[error(transparent)]
    Vm(#[from] VmError),
    /// Inner native fork error.
    #[error(transparent)]
    Fork(#[from] ForkError),
    /// Inner native snapshot error.
    #[error(transparent)]
    Snapshot(#[from] SnapshotError),
    /// Inner Firecracker error.
    #[error(transparent)]
    Fc(#[from] FcError),
}

impl From<Vm> for Guest {
    fn from(vm: Vm) -> Self {
        Self::Native(Box::new(vm))
    }
}

impl From<FcVm> for Guest {
    fn from(vm: FcVm) -> Self {
        Self::Firecracker(Box::new(vm))
    }
}

/// Build a [`GuestError::Unsupported`] for a Firecracker guest.
fn fc_unsupported<T>(op: &'static str) -> Result<T, GuestError> {
    Err(GuestError::Unsupported {
        backend: Backend::Firecracker,
        op,
    })
}

impl Guest {
    /// Engine this guest is running on.
    #[must_use]
    pub fn backend(&self) -> Backend {
        match self {
            Self::Native(_) => Backend::Native,
            Self::Firecracker(_) => Backend::Firecracker,
        }
    }

    /// Borrow the in-process [`Vm`].
    ///
    /// A Firecracker guest has no in-process VMM, so that arm returns
    /// [`GuestError::Unsupported`] rather than panicking.
    pub fn as_native(&self) -> Result<&Vm, GuestError> {
        match self {
            Self::Native(vm) => Ok(vm),
            Self::Firecracker(_) => fc_unsupported("native VMM access"),
        }
    }

    /// Mutably borrow the in-process [`Vm`].
    ///
    /// A Firecracker guest has no in-process VMM, so that arm returns
    /// [`GuestError::Unsupported`] rather than panicking.
    pub fn as_native_mut(&mut self) -> Result<&mut Vm, GuestError> {
        match self {
            Self::Native(vm) => Ok(vm),
            Self::Firecracker(_) => fc_unsupported("native VMM access"),
        }
    }

    /// Borrow the Firecracker VM.
    pub fn as_fc(&self) -> Result<&FcVm, GuestError> {
        match self {
            Self::Firecracker(vm) => Ok(vm),
            Self::Native(_) => Err(GuestError::Unsupported {
                backend: Backend::Native,
                op: "Firecracker VMM access",
            }),
        }
    }

    /// Mutably borrow the Firecracker VM.
    pub fn as_fc_mut(&mut self) -> Result<&mut FcVm, GuestError> {
        match self {
            Self::Firecracker(vm) => Ok(vm),
            Self::Native(_) => Err(GuestError::Unsupported {
                backend: Backend::Native,
                op: "Firecracker VMM access",
            }),
        }
    }

    /// Start vCPU run loops. Native: [`Vm::start`]. Firecracker:
    /// `PUT /actions InstanceStart`.
    pub fn start(&mut self) -> Result<(), GuestError> {
        match self {
            Self::Native(vm) => vm.start()?,
            Self::Firecracker(vm) => vm.start()?,
        }
        Ok(())
    }

    /// Pause vCPUs (and userspace virtio workers). Native:
    /// [`Vm::pause`]. Firecracker: `PATCH /vm {state: Paused}`.
    pub fn pause(&mut self) -> Result<(), GuestError> {
        match self {
            Self::Native(vm) => vm.pause()?,
            Self::Firecracker(vm) => vm.pause()?,
        }
        Ok(())
    }

    /// Resume a paused guest. Native: [`Vm::resume`]. Firecracker:
    /// `PATCH /vm {state: Resumed}`.
    pub fn resume(&mut self) -> Result<(), GuestError> {
        match self {
            Self::Native(vm) => vm.resume()?,
            Self::Firecracker(vm) => vm.resume()?,
        }
        Ok(())
    }

    /// Whether the vCPU threads are parked after [`Self::pause`].
    #[must_use]
    pub fn paused(&self) -> bool {
        match self {
            Self::Native(vm) => vm.paused(),
            Self::Firecracker(vm) => vm.paused(),
        }
    }

    /// Whether vCPUs are executing guest code.
    #[must_use]
    pub fn is_running(&self) -> bool {
        match self {
            Self::Native(vm) => vm.is_running(),
            Self::Firecracker(vm) => vm.is_running(),
        }
    }

    /// Shut down vCPU threads. Native: [`Vm::shutdown`]. Firecracker:
    /// kill the jailed VMM (the chroot, cgroup and uid go with the
    /// `FcVm` when it drops).
    pub fn stop(&mut self) -> Result<(), GuestError> {
        match self {
            Self::Native(vm) => vm.shutdown(),
            Self::Firecracker(vm) => vm.stop(),
        }
        Ok(())
    }

    /// Guest RAM in MiB (the create-time size, not the GPA span).
    #[must_use]
    pub fn memory_mb(&self) -> u64 {
        match self {
            Self::Native(vm) => vm.memory_size() / (1024 * 1024),
            Self::Firecracker(vm) => vm.memory_mb(),
        }
    }

    /// Guest vCPU count.
    #[must_use]
    pub fn vcpu_count(&self) -> u32 {
        match self {
            Self::Native(vm) => vm.vcpu_count(),
            Self::Firecracker(vm) => vm.vcpu_count(),
        }
    }

    /// How a host client should reach the guest agent.
    #[must_use]
    pub fn agent_endpoint(&self) -> AgentEndpoint {
        match self {
            Self::Native(vm) => AgentEndpoint::Vsock {
                cid: vm.guest_cid(),
            },
            Self::Firecracker(vm) => AgentEndpoint::FcUds {
                path: vm.agent_uds().to_string_lossy().into_owned(),
            },
        }
    }

    /// Guest vsock CID. Native: always `Some`.
    ///
    /// Firecracker: always `None`. Its guest CID is private to the
    /// microVM (every FC guest is CID 3) and the host does not reach it
    /// through the vsock namespace at all — callers want
    /// [`Self::agent_endpoint`].
    #[must_use]
    pub fn guest_cid(&self) -> Option<u64> {
        match self {
            Self::Native(vm) => Some(vm.guest_cid()),
            Self::Firecracker(_) => None,
        }
    }

    /// Named persistent data disks attached to this guest, in
    /// declaration order. Native: [`Vm::data_disks`]. Firecracker: the
    /// [`crate::fc::FcDisk::Data`] entries of the VM.
    #[must_use]
    pub fn data_disks(&self) -> Vec<&crate::disks::DataDisk> {
        match self {
            Self::Native(vm) => vm.data_disks().iter().collect(),
            Self::Firecracker(vm) => vm.data_disks(),
        }
    }

    /// Accumulated serial / console output. Native: [`Vm::serial_output`].
    /// Firecracker: the jailer's `stderr.log` ([`crate::fc::spawn::STDERR_FILE`]);
    /// an empty file is a successful empty dump.
    pub fn serial_output(&self, timeout: Duration) -> Result<String, GuestError> {
        match self {
            Self::Native(vm) => Ok(vm.serial_output(timeout)),
            Self::Firecracker(vm) => Ok(vm.serial_output()?),
        }
    }

    /// Connect to the guest agent. Native: [`Vm::connect_agent`] over
    /// `AF_VSOCK`. Firecracker: over the vsock UDS proxy.
    pub fn connect_agent(&self, timeout: Duration) -> Result<AgentClient, GuestError> {
        match self {
            Self::Native(vm) => Ok(vm.connect_agent(timeout)?),
            Self::Firecracker(vm) => Ok(vm.connect_agent(timeout)?),
        }
    }

    /// Repoint the `index`-th block device at `host_path` on a running
    /// guest (the image-slot late fill).
    ///
    /// Firecracker only. The native backend needs no daemon call at
    /// all: its block backend holds the slot's fd from boot, so the
    /// shim fills the backing file in place and the guest sees the new
    /// bytes through that same inode. Asking for this on a native VM is
    /// a caller bug, not a fallback.
    pub fn update_drive(&mut self, index: usize, host_path: &Path) -> Result<(), GuestError> {
        match self {
            Self::Native(_) => Err(GuestError::Unsupported {
                backend: Backend::Native,
                op: "update_drive (the native backend fills a slot in place)",
            }),
            Self::Firecracker(vm) => Ok(vm.update_drive(index, host_path)?),
        }
    }

    /// Snapshot to `dir`. Native: [`Vm::snapshot`]. Firecracker: a
    /// Full point exported as `vmstate` + `memory.bin` ([`FcVm::snapshot`]).
    pub fn snapshot(&mut self, dir: &Path) -> Result<(), GuestError> {
        match self {
            Self::Native(vm) => vm.snapshot(dir)?,
            Self::Firecracker(vm) => vm.snapshot(dir)?,
        }
        Ok(())
    }

    /// Make this guest a warm fork source and return the file its
    /// children will map. Native: one-time cold snapshot + restore
    /// ([`Vm::prepare_fork_source`]). Firecracker: a snapshot point
    /// ([`FcVm::prepare_fork_source`]); the path is `restore-N.mem`.
    pub fn prepare_fork_source(&mut self) -> Result<std::path::PathBuf, GuestError> {
        match self {
            Self::Native(vm) => Ok(vm.prepare_fork_source()?),
            Self::Firecracker(vm) => Ok(vm.prepare_fork_source()?.restore_mem),
        }
    }

    /// Batched warm fork. Native: wraps [`Vm::fork_warm_batch`].
    /// Firecracker: a point plus one `LoadSnapshot` per child
    /// ([`FcVm::fork_batch`]); `dilation` is refused by name.
    pub fn fork_batch(
        &mut self,
        fork_ids: &[&str],
        dilation: Option<u32>,
    ) -> Result<Vec<Guest>, GuestError> {
        match self {
            Self::Native(vm) => {
                let vms = vm.fork_warm_batch(fork_ids, dilation)?;
                Ok(vms.into_iter().map(Guest::from).collect())
            }
            Self::Firecracker(vm) => {
                if dilation.is_some() {
                    return fc_unsupported("fork_batch with dilation");
                }
                let (_, children) = vm.fork_batch(fork_ids.len())?;
                Ok(children.into_iter().map(Guest::from).collect())
            }
        }
    }

    /// Whether this guest's memory is a full copy of its fork source
    /// rather than copy-on-write. Native: [`Vm::fork_memory_is_full_copy`].
    /// Firecracker: always `false` — a fork whose `load.mem` shared no
    /// extents with the parent's restore point failed instead of
    /// existing ([`FcVm::fork_memory_cow`]).
    #[must_use]
    pub fn fork_memory_is_full_copy(&self) -> bool {
        match self {
            Self::Native(vm) => vm.fork_memory_is_full_copy(),
            Self::Firecracker(_) => false,
        }
    }

    /// virtiofs shares. Native: the VM's configured shares. Firecracker
    /// later: empty (virtiofs is unsupported).
    #[must_use]
    pub fn virtiofs_shares(&self) -> &[VirtiofsConfig] {
        match self {
            Self::Native(vm) => vm.virtiofs_shares(),
            // Firecracker has no vhost-user-fs device; a share is
            // refused at create, so a live FC guest never has one.
            Self::Firecracker(_) => &[],
        }
    }

    /// Estimated non-reclaimable private RAM in bytes.
    ///
    /// Native: accumulated dirty pages × 4096 (the figure
    /// [`crate::cluster_tree::ClusterPayload::est_ram_bytes`] used).
    #[must_use]
    pub fn est_private_bytes(&self) -> u64 {
        match self {
            Self::Native(vm) => vm
                .accumulated_dirty_pages()
                .unwrap_or(0)
                .saturating_mul(4096),
            // No dirty bitmap on this path — the VMM is another
            // process, so its `Private_Dirty` is the honest figure.
            Self::Firecracker(vm) => vm.private_dirty_bytes(),
        }
    }

    /// Advance the guest-visible clock. Native: [`Vm::warp_clock`].
    ///
    /// Firecracker: unsupported, permanently. Time warp is an RL-only
    /// feature built on k7d owning the guest's kvmclock; Firecracker
    /// exposes no API for it.
    pub fn warp_clock(&self, delta: Duration) -> Result<(), GuestError> {
        match self {
            Self::Native(vm) => vm.warp_clock(delta)?,
            Self::Firecracker(_) => return fc_unsupported("warp_clock"),
        }
        Ok(())
    }

    /// Change the live dilation factor. Native:
    /// [`Vm::set_dilation_live`]. Firecracker: unsupported,
    /// permanently — same reason as [`Self::warp_clock`].
    pub fn set_dilation(&mut self, factor: u32) -> Result<(), GuestError> {
        match self {
            Self::Native(vm) => vm.set_dilation_live(factor)?,
            Self::Firecracker(_) => return fc_unsupported("set_dilation"),
        }
        Ok(())
    }

    /// Kernel TIDs of running vCPU threads. Native: [`Vm::vcpu_kernel_tids`].
    #[must_use]
    pub fn vcpu_kernel_tids(&self, timeout: Duration) -> Option<Vec<u32>> {
        match self {
            Self::Native(vm) => vm.vcpu_kernel_tids(timeout),
            // vCPUs are threads of another process; the jailer's
            // cgroup caps them, not `VmCpuCgroup`.
            Self::Firecracker(_) => None,
        }
    }
}

/// Unwrap a slice of [`Guest::Native`] for native-only fork internals
/// such as [`crate::fork::fork_cluster_warm_batch`].
///
/// Errors if any member is not native — impossible today, required
/// once Firecracker lands so a mixed-backend cluster fails loudly
/// instead of panicking.
pub fn native_vms_mut(guests: &mut [Guest]) -> Result<Vec<&mut Vm>, GuestError> {
    guests.iter_mut().map(Guest::as_native_mut).collect()
}

/// Unwrap a slice of [`Guest::Firecracker`].
pub fn fc_vms_mut(guests: &mut [Guest]) -> Result<Vec<&mut FcVm>, GuestError> {
    guests.iter_mut().map(Guest::as_fc_mut).collect()
}

/// `max − min` of pause-completion timestamps, in nanoseconds.
///
/// The Firecracker cluster-fork skew: native lockstep
/// has none; FC pauses members on separate threads.
#[must_use]
pub fn pause_skew_ns(timestamps: &[Instant]) -> u64 {
    let Some(&first) = timestamps.first() else {
        return 0;
    };
    let mut min = first;
    let mut max = first;
    for &t in timestamps.iter().skip(1) {
        if t < min {
            min = t;
        }
        if t > max {
            max = t;
        }
    }
    u64::try_from(max.duration_since(min).as_nanos()).unwrap_or(u64::MAX)
}

/// Pause every Firecracker guest in parallel, one thread per member.
///
/// Returns each member's pause-completion timestamp in member order.
/// Skew is [`pause_skew_ns`].
pub fn pause_fc_parallel(guests: &mut [Guest]) -> Result<Vec<Instant>, GuestError> {
    std::thread::scope(|s| {
        let mut joins = Vec::with_capacity(guests.len());
        for g in guests.iter_mut() {
            joins.push(s.spawn(move || {
                let fc = g.as_fc_mut()?;
                fc.pause()?;
                Ok(Instant::now())
            }));
        }
        joins
            .into_iter()
            .map(|j| match j.join() {
                Ok(r) => r,
                Err(_) => Err(GuestError::Unsupported {
                    backend: Backend::Firecracker,
                    op: "parallel pause (thread panicked)",
                }),
            })
            .collect()
    })
}

/// Resume every Firecracker guest in parallel.
pub fn resume_fc_parallel(guests: &mut [Guest]) -> Result<(), GuestError> {
    std::thread::scope(|s| {
        let mut joins = Vec::with_capacity(guests.len());
        for g in guests.iter_mut() {
            joins.push(s.spawn(move || {
                g.as_fc_mut()?.resume()?;
                Ok(())
            }));
        }
        for j in joins {
            match j.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    return Err(GuestError::Unsupported {
                        backend: Backend::Firecracker,
                        op: "parallel resume (thread panicked)",
                    });
                }
            }
        }
        Ok(())
    })
}
