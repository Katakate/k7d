//! Loopback-XFS disk provisioning for writable volume images
//!
//! Warm forks clone a VM's read-write virtio-blk images with `FICLONE`
//! reflinks — O(1), never a byte copy (see `fork::reflink_file`). That
//! requires a reflink-capable filesystem, and the node's root FS is
//! ext4 on md RAID (no reflink). Rather than repartition, we provision
//! **one sparse XFS image** (`mkfs.xfs -m reflink=1`) loop-mounted at
//! [`DISKS_DIR`], and every writable volume image (emptyDir-on-disk,
//! k7d-provisioned RWO PVCs) is a raw ext4 image file created inside
//! it. Reflinking a fork's copy next to the source image stays on the
//! same filesystem, so `FICLONE` succeeds.
//!
//! Everything here fails loud per the invariant: no reflink
//! support ⇒ error, never a silent full copy.

use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

/// Where writable raw volume images live on the host. Backed by the
/// loopback XFS provisioned by [`ensure_loopback_xfs`] (also done at
/// node-reset time by `your node provisioning`).
pub const DISKS_DIR: &str = "/var/lib/k7d/disks";

/// Default backing image for the loopback XFS behind [`DISKS_DIR`].
pub const DISKS_IMAGE: &str = "/var/lib/k7d/disks.img";

/// Root-only (`0700`) scratch directory for material the daemon stages
/// briefly on the host — kubelet Secret and projected-token trees on
/// their way into an erofs image (`volumes_blk`). Not `/tmp`: a
/// world-traversable, guessably-named directory downgraded kubelet's
/// `0400` to the daemon's umask for the length of the pack
/// (bug-candidates #57).
pub const STAGE_DIR: &str = "/var/lib/k7d/stage";

/// Where snapshot trees live on the reflink XFS: a subdirectory of
/// [`DISKS_DIR`], so an incremental keyframe's `FICLONE` of its
/// ancestor's `memory.bin` has source and destination on one
/// reflink-capable filesystem. The node's root FS is ext4
/// and cannot clone at all.
pub const TREES_SUBDIR: &str = "trees";

/// The conventional tree root the daemon and every test path use.
/// [`ensure_reflink_tree_root`] makes this a symlink onto the XFS.
pub const TREES_LINK: &str = "/var/lib/k7d/trees";

/// Where Firecracker jailer chroots live on the reflink XFS: a
/// subdirectory of [`DISKS_DIR`], so hard-linking a
/// VM's scratch / data / docker image into its jail — and
/// `FICLONE`ing a child's memory file next to its parent's — stays on
/// one filesystem.
pub const FC_SUBDIR: &str = "fc";

/// The jailer chroot base every FC VM is staged under
/// (`fc::stage::chroot_base`'s default, `K7D_FC_CHROOT_BASE`'s).
/// [`ensure_reflink_fc_root`] makes this a symlink onto the XFS.
pub const FC_LINK: &str = "/var/lib/k7d/fc";

/// Default size of the sparse XFS backing image: 96 GiB. Sparse — real
/// disk usage grows with actual volume writes only.
///
/// Sized for the Ubuntu bare-VM ladder rather than the minimal guest: a
/// 3-node cluster is three reflinks of a 16 GiB node image, each growing
/// by whatever its containerd pulls (a CSI stack is several GiB per
/// node), plus the fork's three children and a data disk each. At 32 GiB
/// that ran the XFS out of space mid-install, which surfaces as a
/// `DiskPressure` eviction inside the *guest* — a long way from the
/// host filesystem that actually filled up. [`ensure_loopback_xfs`]
/// grows an existing smaller image to this size rather than silently
/// keeping the capacity it was created with.
pub const DISKS_IMAGE_SIZE: u64 = 96 * 1024 * 1024 * 1024;

/// In-VM mount point of a sandbox's writable **scratch** disk.
/// The guest agent puts every container's overlay
/// `upper`/`work` under it, so a container's writes land on this
/// host-backed ext4 image instead of guest RAM.
pub const SCRATCH_GUEST_MOUNT: &str = "/run/k7d/scratch";

/// In-VM root under which a container's **own** scratch disk is
/// mounted, one ext4 image per container that asked for a
/// writable-space limit. A container whose name has a mount here gets
/// its overlay `upper`/`work` on that image instead of on the shared
/// sandbox scratch, so its `ENOSPC` is its own and its siblings keep
/// writing.
///
/// Deliberately NOT a subdirectory of [`SCRATCH_GUEST_MOUNT`]. Nesting
/// them would put a mount point where the shared-scratch path expects a
/// plain per-container directory it creates, empties and removes — the
/// agent would be `remove_dir_all`-ing a live mount, and a `statfs` of
/// the shared disk would silently answer for the nested one instead.
pub const CONTAINER_SCRATCH_GUEST_ROOT: &str = "/run/k7d/cscratch";

/// In-VM mount point of `name`'s own scratch disk. `name` is the
/// **Kubernetes** container name (what the annotation names), which
/// the agent reads back off the bundle's CRI annotations — the guest
/// runc name is the containerd container id and is not known when the
/// device is declared at sandbox create.
#[must_use]
pub fn container_scratch_mount(name: &str) -> String {
    format!("{CONTAINER_SCRATCH_GUEST_ROOT}/{name}")
}

/// Documented default capacity of a sandbox's scratch disk: 8 GiB,
/// sparse (host blocks allocate as the guest writes).
///
/// Deliberately a **fixed** number and NOT a function of guest RAM —
/// decoupling writable space from the memory budget is the whole point
/// of. Override per pod with the
/// `k7d.katakate.org/scratch-size` annotation.
pub const DEFAULT_SCRATCH_SIZE: u64 = 8 * 1024 * 1024 * 1024;

/// Smallest scratch disk we will format: below this `mkfs.ext4` yields
/// a filesystem with no usable space after metadata, which would
/// surface as an inscrutable ENOSPC on the first container write.
pub const MIN_SCRATCH_SIZE: u64 = 16 * 1024 * 1024;

/// In-VM mount point of a sandbox's Docker graph disk.
/// Overlay2's data-root; a dedicated scratch image, not a `DataDisk`.
pub const DOCKER_GRAPH_GUEST_MOUNT: &str = "/var/lib/docker";

/// Documented default capacity of the Docker graph disk: 20 GiB,
/// sparse. Override per pod with `k7d.katakate.org/docker-disk`.
pub const DEFAULT_DOCKER_DISK_SIZE: u64 = 20 * 1024 * 1024 * 1024;

/// A sandbox's writable scratch image on the reflink-capable
/// [`DISKS_DIR`], owned by the VM it is attached to and
/// **removed on `Drop`** — scratch is scratch, it never outlives its
/// sandbox.
///
/// Attach it with [`crate::vm::VmBuilder::scratch_disk`], which mounts
/// it read-write at [`SCRATCH_GUEST_MOUNT`] and hands the handle to the
/// [`crate::vm::Vm`]. Warm forks reflink the image like any other
/// read-write virtio-blk device (`fork::reflink_file`), so a fork
/// inherits the parent's writable layer as `CoW` and its own writes
/// stay private.
#[derive(Debug)]
pub struct ScratchDisk {
    path: PathBuf,
    size_bytes: u64,
}

impl ScratchDisk {
    /// Provision a fresh scratch image for `key` (a sandbox or VM id)
    /// of `size_bytes`, ensuring the reflink loopback XFS behind
    /// [`DISKS_DIR`] exists first.
    ///
    /// Fails loudly on a too-small size, an unusable `key`, a
    /// non-reflink filesystem, or a `mkfs.ext4` error — there is no
    /// fallback, because the fallback was RAM.
    pub fn create(key: &str, size_bytes: u64) -> Result<Self, DiskError> {
        if size_bytes < MIN_SCRATCH_SIZE {
            return Err(DiskError::ScratchSize {
                size_bytes,
                min: MIN_SCRATCH_SIZE,
            });
        }
        Self::validate_key(key)?;
        ensure_loopback_xfs(
            Path::new(DISKS_IMAGE),
            Path::new(DISKS_DIR),
            DISKS_IMAGE_SIZE,
        )?;
        let dir = Path::new(DISKS_DIR);
        let name = format!("scratch-{key}.img");
        if dir.join(&name).exists() {
            // A leftover from a crashed sandbox with the same id: scratch
            // is never reused (out-of-scope), so reformat — but
            // say so, because it means an earlier teardown lost its Drop.
            log::warn!(
                "scratch: reformatting leftover image {DISKS_DIR}/{name} \
                 (previous sandbox teardown did not remove it)"
            );
        }
        let path = create_ext4_volume(dir, &name, size_bytes)?;
        log::info!(
            "scratch: sandbox {key} writable layer is {} ({} MiB, sparse)",
            path.display(),
            size_bytes / (1024 * 1024)
        );
        Ok(Self { path, size_bytes })
    }

    /// Take ownership of a scratch image an earlier VM broker created
    /// for a VM this process is re-adopting (`K7D_VM_BROKER_RESTART`): the file is
    /// removed when the handle drops, exactly as if this process had
    /// created it. Only for a path directly under [`DISKS_DIR`] with the
    /// `scratch-` prefix — anything else is not scratch and must not be
    /// unlinked at teardown.
    pub fn adopt(path: &Path) -> Result<Self, DiskError> {
        let is_scratch = path.parent() == Some(Path::new(DISKS_DIR))
            && path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("scratch-"))
            && path.extension().is_some_and(|ext| ext == "img");
        if !is_scratch {
            return Err(DiskError::ScratchKey {
                key: path.display().to_string(),
            });
        }
        let size_bytes = std::fs::metadata(path)
            .map_err(|err| DiskError::Io {
                path: path.to_path_buf(),
                err,
            })?
            .len();
        Ok(Self {
            path: path.to_path_buf(),
            size_bytes,
        })
    }

    /// Reject a key that cannot be a single filename component.
    /// Public so callers can fail at annotation-parse time
    /// rather than at VM boot.
    pub fn validate_key(key: &str) -> Result<(), DiskError> {
        if key.is_empty() || key.contains('/') || key.contains("..") {
            return Err(DiskError::ScratchKey {
                key: key.to_string(),
            });
        }
        Ok(())
    }

    /// Host path of the image.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Configured capacity in bytes.
    #[must_use]
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
}

impl Drop for ScratchDisk {
    fn drop(&mut self) {
        match std::fs::remove_file(&self.path) {
            Ok(()) => log::info!("scratch: removed {}", self.path.display()),
            Err(e) => log::error!("scratch: remove {} failed: {e}", self.path.display()),
        }
    }
}

/// Subdirectory of [`DISKS_DIR`] holding **persistent** data-disk
/// images, one per `id`.
///
/// A subdirectory and not [`DISKS_DIR`] itself for the same reason the
/// Ubuntu base images live in one (CHALLENGES #106): everything directly
/// under [`DISKS_DIR`] is by contract a per-VM image the test suite's
/// hygiene sweep deletes as soon as no live VM holds it open, and a
/// retained disk there would be reaped between two VMs that are supposed
/// to share it. Still the same filesystem, so a fork's `FICLONE` of the
/// image lands next to it.
pub const DATA_DISKS_SUBDIR: &str = "data";

/// Smallest data disk we will format, same reasoning as
/// [`MIN_SCRATCH_SIZE`]: below this `mkfs.ext4` leaves no usable space.
pub const MIN_DATA_DISK_SIZE: u64 = 16 * 1024 * 1024;

/// Where persistent data-disk images live: `<DISKS_DIR>/data`.
#[must_use]
pub fn data_disks_dir() -> PathBuf {
    Path::new(DISKS_DIR).join(DATA_DISKS_SUBDIR)
}

/// Host path of the image backing data disk `id`.
#[must_use]
pub fn data_disk_path(id: &str) -> PathBuf {
    data_disks_dir().join(format!("{id}.img"))
}

/// A **named, persistent** read-write disk that outlives the VM it is
/// attached to.
///
/// The image is `<DISKS_DIR>/data/<id>.img` on the reflink XFS — never
/// the node's root FS, which is ext4 on md RAID and cannot `FICLONE`, so
/// a disk provisioned there would silently cost every warm fork a byte
/// copy. First attach creates it sparse and `mkfs.ext4`'s it; every later
/// attach of the same `id` reuses it **as-is**, which is what makes
/// `/var/lib/longhorn` survive the VM that was the node.
///
/// Unlike [`ScratchDisk`] there is **no `Drop`**: retention is the whole
/// point. Deleting the data is the explicit [`DataDisk::delete`]
/// (the daemon's `delete_data_disk`), and orphans are reaped by the
/// age-gated orphan sweep. Attach it with
/// [`crate::vm::VmBuilder::data_disk`].
///
/// A warm fork clones each attached image into the child's own file
/// through the generic read-write virtio-blk path (`fork::reflink_file`),
/// so two live VMs never write one ext4.
#[derive(Debug, Clone)]
pub struct DataDisk {
    id: String,
    path: PathBuf,
    size_bytes: u64,
    guest_mount: String,
}

impl DataDisk {
    /// Attach the disk named `id`, creating it only if its image does not
    /// exist yet, and mount it in the guest at `guest_mount`.
    ///
    /// Loud on every disagreement: an unusable `id`, a size below
    /// [`MIN_DATA_DISK_SIZE`], a relative `guest_mount`, a
    /// non-reflink-capable disks directory, or a `size_bytes` that does
    /// not match an existing image (a silent resize would either lose
    /// the caller's capacity assumption or truncate live data).
    pub fn attach(id: &str, size_bytes: u64, guest_mount: &str) -> Result<Self, DiskError> {
        Self::validate_id(id)?;
        if size_bytes < MIN_DATA_DISK_SIZE {
            return Err(DiskError::DataDiskSize {
                id: id.to_string(),
                size_bytes,
                min: MIN_DATA_DISK_SIZE,
            });
        }
        if !guest_mount.starts_with('/') || guest_mount.contains(',') || guest_mount.contains(':') {
            return Err(DiskError::DataDiskMount {
                id: id.to_string(),
                guest_mount: guest_mount.to_string(),
            });
        }
        ensure_loopback_xfs(
            Path::new(DISKS_IMAGE),
            Path::new(DISKS_DIR),
            DISKS_IMAGE_SIZE,
        )?;
        let dir = data_disks_dir();
        std::fs::create_dir_all(&dir).map_err(|e| io_err(&dir, e))?;
        let name = format!("{id}.img");
        let path = dir.join(&name);
        let padded = size_bytes.div_ceil(crate::block::SECTOR_SIZE) * crate::block::SECTOR_SIZE;
        if path.exists() {
            let existing = std::fs::metadata(&path)
                .map_err(|e| io_err(&path, e))?
                .len();
            if existing != padded {
                return Err(DiskError::DataDiskResize {
                    id: id.to_string(),
                    existing,
                    requested: padded,
                });
            }
            log::info!(
                "data-disk {id}: reusing {} ({} MiB) at guest {guest_mount}",
                path.display(),
                existing / (1024 * 1024)
            );
        } else {
            create_ext4_volume(&dir, &name, padded)?;
            log::info!(
                "data-disk {id}: created {} ({} MiB, sparse) for guest {guest_mount}",
                path.display(),
                padded / (1024 * 1024)
            );
        }
        Ok(Self {
            id: id.to_string(),
            path,
            size_bytes: padded,
            guest_mount: guest_mount.to_string(),
        })
    }

    /// Remove the image behind `id`. The **only** way its data goes
    /// away: `delete_vm` deliberately leaves it. A missing image is a
    /// loud error, not a silent success — a caller that thinks it
    /// deleted a disk that was never there is a caller looking at the
    /// wrong `id`.
    pub fn delete(id: &str) -> Result<(), DiskError> {
        Self::validate_id(id)?;
        let path = data_disk_path(id);
        std::fs::remove_file(&path).map_err(|e| io_err(&path, e))?;
        log::info!("data-disk {id}: removed {}", path.display());
        Ok(())
    }

    /// Reject an `id` that cannot be a single filename component, so a
    /// bad annotation fails at parse time rather than at VM boot.
    pub fn validate_id(id: &str) -> Result<(), DiskError> {
        if id.is_empty() || id.contains('/') || id.contains("..") || id.starts_with('.') {
            return Err(DiskError::DataDiskId { id: id.to_string() });
        }
        Ok(())
    }

    /// The persistent identity of this disk.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Host path of the image.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Capacity in bytes (rounded up to a virtio-blk sector).
    #[must_use]
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Where the guest agent mounts it.
    #[must_use]
    pub fn guest_mount(&self) -> &str {
        &self.guest_mount
    }
}

/// Errors from disk provisioning. All loud, no fallbacks.
#[derive(Debug, thiserror::Error)]
pub enum DiskError {
    /// Filesystem operation failed.
    #[error("disks I/O at {path}: {err}")]
    Io {
        /// Path the operation touched.
        path: PathBuf,
        /// Underlying error.
        err: std::io::Error,
    },
    /// An external command (`mkfs.xfs`, `mkfs.ext4`, `mount`) failed.
    #[error("{cmd} failed: {stderr}")]
    Command {
        /// The command that failed.
        cmd: String,
        /// Captured stderr.
        stderr: String,
    },
    /// The directory is not on a reflink-capable filesystem.
    #[error(
        "{dir} is not reflink-capable (FICLONE probe failed: {probe}) — \
         writable volume images require reflink for O(1) warm forks; \
         provision the loopback XFS (`ensure_loopback_xfs`, see \
 / your node provisioning)"
    )]
    NoReflink {
        /// The directory that failed the probe.
        dir: PathBuf,
        /// The FICLONE errno.
        probe: String,
    },
    /// A requested scratch disk is too small to hold an
    /// ext4 filesystem with usable space.
    #[error(
        "scratch size {size_bytes} bytes is below the {min}-byte minimum — \
         set k7d.katakate.org/scratch-size to at least {min} bytes"
    )]
    ScratchSize {
        /// Requested size.
        size_bytes: u64,
        /// Enforced minimum.
        min: u64,
    },
    /// The sandbox/VM key naming a scratch image is not usable as a
    /// filename component.
    #[error("scratch key {key:?} is empty or contains '/' or '..'")]
    ScratchKey {
        /// The offending key.
        key: String,
    },
    /// A data-disk `id` is not usable as a filename component.
    #[error("data-disk id {id:?} is empty, hidden, or contains '/' or '..'")]
    DataDiskId {
        /// The offending id.
        id: String,
    },
    /// A requested data disk is too small to hold an ext4 filesystem
    /// with usable space.
    #[error("data-disk {id}: size {size_bytes} bytes is below the {min}-byte minimum")]
    DataDiskSize {
        /// The disk's id.
        id: String,
        /// Requested size.
        size_bytes: u64,
        /// Enforced minimum.
        min: u64,
    },
    /// A data disk's guest mount point is not an absolute path, or
    /// contains a character the `k7d.blk=` cmdline encoding uses as a
    /// separator.
    #[error(
        "data-disk {id}: guest mount {guest_mount:?} must be absolute and free of ',' and ':'"
    )]
    DataDiskMount {
        /// The disk's id.
        id: String,
        /// The offending mount point.
        guest_mount: String,
    },
    /// The loopback XFS backing [`DISKS_DIR`] could not be grown to the
    /// size this build asks for.
    #[error("cannot grow loopback image {image}: {detail}")]
    LoopbackGrow {
        /// The backing image.
        image: PathBuf,
        /// What went wrong.
        detail: String,
    },
    /// An existing data-disk image has a different capacity than the
    /// attach asked for. Resizing is out of scope, and silently
    /// honouring either number loses data or capacity.
    #[error(
        "data-disk {id}: image is {existing} bytes but attach asked for {requested} — \
         resizing a data disk is not supported; delete it explicitly or ask for its real size"
    )]
    DataDiskResize {
        /// The disk's id.
        id: String,
        /// Size on disk.
        existing: u64,
        /// Size requested.
        requested: u64,
    },
}

fn io_err(path: &Path, err: std::io::Error) -> DiskError {
    DiskError::Io {
        path: path.to_path_buf(),
        err,
    }
}

fn run(cmd: &str, args: &[&str]) -> Result<(), DiskError> {
    let output = crate::spawner::command(cmd)
        .args(args)
        .output()
        .map_err(|e| io_err(Path::new(cmd), e))?;
    if !output.status.success() {
        return Err(DiskError::Command {
            cmd: format!("{cmd} {}", args.join(" ")),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(())
}

/// Like [`run`], returning the command's stdout for callers that have
/// to parse it (`losetup -j`).
fn run_stdout(cmd: &str, args: &[&str]) -> Result<String, DiskError> {
    let output = crate::spawner::command(cmd)
        .args(args)
        .output()
        .map_err(|e| io_err(Path::new(cmd), e))?;
    if !output.status.success() {
        return Err(DiskError::Command {
            cmd: format!("{cmd} {}", args.join(" ")),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Probe whether `dir` supports `FICLONE` reflinks by cloning a tiny
/// scratch file onto a sibling. Returns `Ok(())` on support, loud
/// [`DiskError::NoReflink`] otherwise. Both probe files are removed.
pub fn assert_reflink_capable(dir: &Path) -> Result<(), DiskError> {
    let seq = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let src = dir.join(format!(".reflink-probe-src-{}-{seq}", std::process::id()));
    let dst = dir.join(format!(".reflink-probe-dst-{}-{seq}", std::process::id()));
    let result = (|| {
        std::fs::write(&src, b"probe").map_err(|e| io_err(&src, e))?;
        // FICLONE requires the source fd open for reading (EBADF otherwise).
        let f = std::fs::File::open(&src).map_err(|e| io_err(&src, e))?;
        let d = std::fs::File::create(&dst).map_err(|e| io_err(&dst, e))?;
        // SAFETY: both fds are valid for the duration of the call; FICLONE
        // takes the source fd as its integer argument.
        let rc = unsafe { libc::ioctl(d.as_raw_fd(), libc::FICLONE, f.as_raw_fd()) };
        if rc < 0 {
            return Err(DiskError::NoReflink {
                dir: dir.to_path_buf(),
                probe: std::io::Error::last_os_error().to_string(),
            });
        }
        Ok(())
    })();
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dst);
    result
}

/// Ensure a reflink-capable (`reflink=1`) XFS is loop-mounted at
/// `mount_point`, provisioning a sparse backing image at `image` on
/// first use. Idempotent: an already-mounted, reflink-capable
/// `mount_point` returns immediately.
///
/// The systemd unit mounts this from `ExecStartPre=+` via
/// `packaging/k7d-mount-disks.sh` so the mount lives in the **host**
/// namespace (`ProtectSystem=strict` would otherwise hide a daemon-side
/// `mount` from the host and from tests). Node resets call that same
/// script. This function is the programmatic equivalent that
/// in-process tests use to self-provision, and a fallback if the
/// unit's `ExecStartPre` has not run. Requires root (mount).
pub fn ensure_loopback_xfs(
    image: &Path,
    mount_point: &Path,
    size_bytes: u64,
) -> Result<(), DiskError> {
    std::fs::create_dir_all(mount_point).map_err(|e| io_err(mount_point, e))?;
    if is_mounted(mount_point)? {
        // Already mounted — but never trust it silently: the whole
        // point is reflink, so verify or fail loud.
        assert_reflink_capable(mount_point)?;
        return grow_loopback_to(image, mount_point, size_bytes);
    }

    if !image.exists() {
        if let Some(parent) = image.parent() {
            std::fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;
        }
        let f = std::fs::File::create(image).map_err(|e| io_err(image, e))?;
        f.set_len(size_bytes).map_err(|e| io_err(image, e))?;
        drop(f);
        // reflink=1 is the default on modern mkfs.xfs but we pass it
        // explicitly — it is the reason this filesystem exists.
        if let Err(e) = run(
            "mkfs.xfs",
            &["-q", "-m", "reflink=1", &image.to_string_lossy()],
        ) {
            let _ = std::fs::remove_file(image);
            return Err(e);
        }
        log::info!(
            "disks: created sparse XFS image {} ({} GiB, reflink=1)",
            image.display(),
            size_bytes / (1024 * 1024 * 1024)
        );
    }

    run(
        "mount",
        &[
            "-o",
            "loop",
            &image.to_string_lossy(),
            &mount_point.to_string_lossy(),
        ],
    )?;
    log::info!(
        "disks: loop-mounted {} at {}",
        image.display(),
        mount_point.display()
    );
    assert_reflink_capable(mount_point)?;
    grow_loopback_to(image, mount_point, size_bytes)
}

/// Put the snapshot-tree root on the reflink XFS.
///
/// Ensures the loopback XFS behind [`DISKS_DIR`] is mounted, creates
/// `<DISKS_DIR>/trees` on it, and points [`TREES_LINK`] at that
/// directory so every existing `/var/lib/k7d/trees/...` path lands on a
/// filesystem where `FICLONE` works. Returns the directory trees
/// actually live in.
///
/// Idempotent, and never moves data behind the operator's back: an
/// existing **non-empty** real directory at [`TREES_LINK`] is left
/// exactly where it is, with a loud warning — those trees keep working
/// on ext4, they just pay a full dump per keyframe. An empty one is
/// replaced by the symlink.
///
/// The node-reset script does the same provisioning before the daemon
/// ever starts (`your node provisioning`); this is the
/// programmatic equivalent for the daemon and the integration tests.
pub fn ensure_reflink_tree_root() -> Result<PathBuf, DiskError> {
    let target = link_onto_reflink_xfs(
        Path::new(TREES_LINK),
        TREES_SUBDIR,
        StaleDir::Keep,
        "every snapshot-tree keyframe there costs a FULL guest-RAM dump instead of \
         O(divergence)",
    )?;
    if target == Path::new(TREES_LINK) {
        return Ok(target);
    }
    assert_reflink_capable(&target)?;
    log::info!(
        "disks: snapshot-tree root {} is reflink-capable — incremental keyframes on",
        target.display()
    );
    Ok(target)
}

/// Put the Firecracker jailer chroot base on the reflink XFS.
///
/// The jail is not merely a directory: every file the jailed
/// Firecracker opens has to be *inside* it, so each VM's disks are
/// linked in from wherever k7d keeps them. Both link operations are
/// single-filesystem by construction — `link(2)` returns `EXDEV`
/// across mounts and so does `FICLONE` — and the disks k7d hands a VM
/// live on the loopback XFS at [`DISKS_DIR`], not on the node's ext4
/// root. So the chroot base has to be on that XFS too, which is what
/// this does: [`FC_LINK`] (the path `K7D_FC_CHROOT_BASE` defaults to)
/// becomes a symlink onto `<DISKS_DIR>/fc`.
///
/// [`FC_LINK`] could once be a plain ext4 directory, because the
/// only things staged were the guest kernel and initrd, which sit
/// on the ext4 root next to it. Staging disks too makes those two
/// requirements point at different filesystems; this resolves it in
/// favour of the disks, and `fc::stage` carries the read-only
/// artifacts across the remaining boundary through a node-wide cache.
pub fn ensure_reflink_fc_root() -> Result<PathBuf, DiskError> {
    let target = link_onto_reflink_xfs(
        Path::new(FC_LINK),
        FC_SUBDIR,
        StaleDir::Park,
        "a Firecracker VM there cannot be given a disk at all — `link(2)` of a \
         disk image on the XFS into an ext4 jail is EXDEV",
    )?;
    if target == Path::new(FC_LINK) {
        return Ok(target);
    }
    assert_reflink_capable(&target)?;
    log::info!(
        "disks: Firecracker jailer chroot base {} is on the reflink XFS",
        target.display()
    );
    Ok(target)
}

/// What to do with a non-empty real directory found where the symlink
/// onto the XFS belongs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StaleDir {
    /// Leave it, warn, and keep using it. For content that is the
    /// operator's — snapshot trees hold guest state nothing else has.
    Keep,
    /// Rename it aside and put the symlink in its place. For content
    /// that cannot outlive the daemon that made it: a jailer chroot
    /// belongs to one Firecracker process, and that process died with
    /// the previous daemon.
    Park,
}

/// Seconds since the epoch, for naming a parked directory.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Point `link` at `<DISKS_DIR>/<subdir>` on the reflink XFS, mounting
/// the loopback filesystem first. Returns the directory that is
/// actually in use.
///
/// Idempotent, and never moves data behind the operator's back: an
/// existing **non-empty** real directory at `link` is left exactly
/// where it is and returned unchanged, with a warning that quotes
/// `consequence`. An empty one is replaced by the symlink.
///
/// The node-reset script does the same provisioning before the daemon
/// ever starts (`your node provisioning`); this is the
/// programmatic equivalent for the daemon and the integration tests.
fn link_onto_reflink_xfs(
    link: &Path,
    subdir: &str,
    stale: StaleDir,
    consequence: &str,
) -> Result<PathBuf, DiskError> {
    ensure_loopback_xfs(
        Path::new(DISKS_IMAGE),
        Path::new(DISKS_DIR),
        DISKS_IMAGE_SIZE,
    )?;
    let target = Path::new(DISKS_DIR).join(subdir);
    std::fs::create_dir_all(&target).map_err(|e| io_err(&target, e))?;

    match std::fs::symlink_metadata(link) {
        // Already a symlink: accept it if it points at the XFS, replace
        // it if it points somewhere stale.
        Ok(md) if md.file_type().is_symlink() => {
            let current = std::fs::read_link(link).map_err(|e| io_err(link, e))?;
            if current != target {
                std::fs::remove_file(link).map_err(|e| io_err(link, e))?;
                std::os::unix::fs::symlink(&target, link).map_err(|e| io_err(link, e))?;
                log::info!(
                    "disks: repointed {} from {} to the reflink XFS at {}",
                    link.display(),
                    current.display(),
                    target.display()
                );
            }
        }
        Ok(_) => {
            let empty = std::fs::read_dir(link)
                .map_err(|e| io_err(link, e))?
                .next()
                .is_none();
            if empty {
                std::fs::remove_dir(link).map_err(|e| io_err(link, e))?;
                std::os::unix::fs::symlink(&target, link).map_err(|e| io_err(link, e))?;
                log::info!(
                    "disks: moved the empty {} onto the reflink XFS at {}",
                    link.display(),
                    target.display()
                );
            } else if stale == StaleDir::Park {
                let parked = link.with_extension(format!("ext4-{}", unix_now()));
                std::fs::rename(link, &parked).map_err(|e| io_err(link, e))?;
                std::os::unix::fs::symlink(&target, link).map_err(|e| io_err(link, e))?;
                log::warn!(
                    "disks: parked the old off-XFS {} at {} and pointed it at {} — \
                     otherwise {consequence}",
                    link.display(),
                    parked.display(),
                    target.display()
                );
            } else {
                log::warn!(
                    "disks: {} is a non-empty real directory, so it is NOT on the \
                     reflink XFS at {} — leaving it alone, but {consequence}. Move \
                     or remove it and re-run `your node provisioning`.",
                    link.display(),
                    DISKS_DIR
                );
                return Ok(link.to_path_buf());
            }
        }
        Err(_) => {
            if let Some(parent) = link.parent() {
                std::fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;
            }
            std::os::unix::fs::symlink(&target, link).map_err(|e| io_err(link, e))?;
            log::info!(
                "disks: {} -> reflink XFS {}",
                link.display(),
                target.display()
            );
        }
    }
    Ok(target)
}

/// Grow the loopback XFS at `mount_point` to `size_bytes` when its
/// backing `image` is smaller, and do nothing when it is not.
///
/// A node keeps `disks.img` across reboots and code changes, so raising
/// [`DISKS_IMAGE_SIZE`] would otherwise be a no-op on every node that
/// already has one: the filesystem stays at the size it was created
/// with, and the extra capacity the new constant promised turns into an
/// `ENOSPC` (or a guest-side `DiskPressure` eviction) partway through a
/// test. Shrinking is not attempted — XFS cannot — and is not an error,
/// because a node provisioned with a bigger image than this build asks
/// for is fine.
fn grow_loopback_to(image: &Path, mount_point: &Path, size_bytes: u64) -> Result<(), DiskError> {
    let current = std::fs::metadata(image)
        .map_err(|e| io_err(image, e))?
        .len();
    if current >= size_bytes {
        return Ok(());
    }
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(image)
        .map_err(|e| io_err(image, e))?;
    f.set_len(size_bytes).map_err(|e| io_err(image, e))?;
    drop(f);
    // The loop device caches the backing file's size at attach, so the
    // kernel has to be told to re-read it before `xfs_growfs` can see
    // the new blocks.
    let listed = run_stdout("losetup", &["-j", &image.to_string_lossy()])?;
    let dev = listed
        .lines()
        .next()
        .and_then(|l| l.split(':').next())
        .map(str::to_string)
        .ok_or_else(|| DiskError::LoopbackGrow {
            image: image.to_path_buf(),
            detail: format!("no loop device backs it: {listed}"),
        })?;
    run("losetup", &["-c", &dev])?;
    run("xfs_growfs", &[&mount_point.to_string_lossy()])?;
    log::info!(
        "disks: grew {} from {} to {} GiB via {dev} (xfs_growfs {})",
        image.display(),
        current / (1024 * 1024 * 1024),
        size_bytes / (1024 * 1024 * 1024),
        mount_point.display()
    );
    Ok(())
}

/// Create a raw ext4 volume image of `size_bytes` at `dir/name`,
/// for attaching to a guest via
/// [`crate::vm::VmBuilder::block_device_mounted`] (`fstype = "ext4"`).
///
/// `dir` must be reflink-capable ([`assert_reflink_capable`]) — a
/// writable image that cannot be reflinked would silently force every
/// warm fork onto the fail-loud `FICLONE` error path, so we refuse to
/// create it in the wrong place at all. `size_bytes` is rounded up to
/// a 512-byte multiple (the virtio-blk sector size). The image is
/// sparse: real blocks are allocated as the guest writes.
pub fn create_ext4_volume(dir: &Path, name: &str, size_bytes: u64) -> Result<PathBuf, DiskError> {
    assert_reflink_capable(dir)?;
    let path = dir.join(name);
    let padded = size_bytes.div_ceil(crate::block::SECTOR_SIZE) * crate::block::SECTOR_SIZE;
    let f = std::fs::File::create(&path).map_err(|e| io_err(&path, e))?;
    f.set_len(padded).map_err(|e| io_err(&path, e))?;
    drop(f);
    if let Err(e) = run("mkfs.ext4", &["-F", "-q", &path.to_string_lossy()]) {
        let _ = std::fs::remove_file(&path);
        return Err(e);
    }
    log::info!(
        "disks: created ext4 volume image {} ({} MiB)",
        path.display(),
        padded / (1024 * 1024)
    );
    Ok(path)
}

/// Idempotent [`create_ext4_volume`]: when
/// `dir/name` already exists it is returned as-is — this is the
/// "PVC outlives the pod" semantic for k7d-provisioned RWO volumes
/// (a pod restart reattaches the same image with its data intact).
/// Only a missing image is created and formatted.
pub fn ensure_ext4_volume(dir: &Path, name: &str, size_bytes: u64) -> Result<PathBuf, DiskError> {
    let path = dir.join(name);
    if path.exists() {
        log::info!(
            "disks: reusing existing ext4 volume image {}",
            path.display()
        );
        return Ok(path);
    }
    create_ext4_volume(dir, name, size_bytes)
}

/// Whether `mount_point` is currently a mount point (an entry in
/// `/proc/mounts` names it exactly).
fn is_mounted(mount_point: &Path) -> Result<bool, DiskError> {
    let mounts = std::fs::read_to_string("/proc/mounts")
        .map_err(|e| io_err(Path::new("/proc/mounts"), e))?;
    let want = mount_point.to_string_lossy();
    Ok(mounts
        .lines()
        .filter_map(|l| l.split_whitespace().nth(1))
        .any(|mp| mp == want))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reflink_probe_fails_loud_on_tmpfs_or_ext4() {
        // The build/test hosts run /tmp on tmpfs or ext4 — neither
        // supports FICLONE, so the probe must fail with the loud
        // NoReflink error (naming the dir), never a silent pass.
        let dir = tempfile::tempdir().unwrap();
        match assert_reflink_capable(dir.path()) {
            Err(DiskError::NoReflink { dir: d, .. }) => assert_eq!(d, dir.path()),
            Ok(()) => {
                // A dev box with /tmp on btrfs/XFS legitimately passes;
                // nothing to assert beyond "no probe files leak".
            }
            Err(other) => panic!("expected NoReflink, got {other}"),
        }
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            0,
            "probe files must not leak"
        );
    }

    #[test]
    fn create_ext4_volume_refuses_non_reflink_dir() {
        let dir = tempfile::tempdir().unwrap();
        if assert_reflink_capable(dir.path()).is_ok() {
            // Reflink-capable tmp: the refusal path can't be exercised
            // here; covered by the loud error type test above.
            return;
        }
        let err = create_ext4_volume(dir.path(), "vol.img", 8 * 1024 * 1024).unwrap_err();
        assert!(
            matches!(err, DiskError::NoReflink { .. }),
            "must refuse to create a writable image on a non-reflink fs, got {err}"
        );
        assert!(!dir.path().join("vol.img").exists());
    }

    #[test]
    fn scratch_create_validates_before_touching_the_host() {
        // Both checks run before any mount / mkfs, so this is a pure
        // unit test — and both must be loud (no silent
        // fallback to a RAM-backed writable layer).
        assert!(matches!(
            ScratchDisk::create("sandbox", 4096),
            Err(DiskError::ScratchSize { .. })
        ));
        for bad in ["", "../escape", "nested/key"] {
            assert!(
                matches!(
                    ScratchDisk::create(bad, DEFAULT_SCRATCH_SIZE),
                    Err(DiskError::ScratchKey { .. })
                ),
                "key {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn data_disk_attach_validates_before_touching_the_host() {
        // id, size and mount point are all checked before any mount or
        // mkfs, so this stays a pure unit test — and every rejection is
        // loud, because a data disk in the wrong place silently costs
        // O(1) forks and a wrong size silently loses data.
        for bad in ["", "../escape", "nested/id", ".hidden"] {
            assert!(
                matches!(
                    DataDisk::attach(bad, 1024 * 1024 * 1024, "/var/lib/longhorn"),
                    Err(DiskError::DataDiskId { .. })
                ),
                "id {bad:?} must be rejected"
            );
        }
        assert!(matches!(
            DataDisk::attach("longhorn", 4096, "/var/lib/longhorn"),
            Err(DiskError::DataDiskSize { .. })
        ));
        for bad in [
            "var/lib/longhorn",
            "/var/lib/long,horn",
            "/var/lib:longhorn",
        ] {
            assert!(
                matches!(
                    DataDisk::attach("longhorn", MIN_DATA_DISK_SIZE, bad),
                    Err(DiskError::DataDiskMount { .. })
                ),
                "guest mount {bad:?} must be rejected"
            );
        }
        assert!(matches!(
            DataDisk::delete("../escape"),
            Err(DiskError::DataDiskId { .. })
        ));
    }

    #[test]
    fn data_disk_paths_live_under_the_reflink_subdir() {
        assert_eq!(data_disks_dir(), Path::new(DISKS_DIR).join("data"));
        assert_eq!(
            data_disk_path("longhorn-0"),
            Path::new(DISKS_DIR).join("data/longhorn-0.img")
        );
    }

    #[test]
    fn is_mounted_detects_root() {
        assert!(is_mounted(Path::new("/")).unwrap());
        assert!(!is_mounted(Path::new("/definitely-not-a-mount-point-k7d")).unwrap());
    }
}
