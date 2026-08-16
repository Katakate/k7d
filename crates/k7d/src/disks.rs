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
use std::process::Command;

/// Where writable raw volume images live on the host. Backed by the
/// loopback XFS provisioned by [`ensure_loopback_xfs`] (also done at
/// node-reset time by `your node provisioning`).
pub const DISKS_DIR: &str = "/var/lib/k7d/disks";

/// Default backing image for the loopback XFS behind [`DISKS_DIR`].
pub const DISKS_IMAGE: &str = "/var/lib/k7d/disks.img";

/// Default size of the sparse XFS backing image: 32 GiB. Sparse — real
/// disk usage grows with actual volume writes only.
pub const DISKS_IMAGE_SIZE: u64 = 32 * 1024 * 1024 * 1024;

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
}

fn io_err(path: &Path, err: std::io::Error) -> DiskError {
    DiskError::Io {
        path: path.to_path_buf(),
        err,
    }
}

fn run(cmd: &str, args: &[&str]) -> Result<(), DiskError> {
    let output = Command::new(cmd)
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
/// Node resets run the same provisioning from
/// `your node provisioning` (plus an `/etc/fstab` entry so the
/// mount survives reboots); this function is the programmatic
/// equivalent that integration tests and the daemon can call to
/// self-provision. Requires root (mount).
pub fn ensure_loopback_xfs(
    image: &Path,
    mount_point: &Path,
    size_bytes: u64,
) -> Result<(), DiskError> {
    std::fs::create_dir_all(mount_point).map_err(|e| io_err(mount_point, e))?;
    if is_mounted(mount_point)? {
        // Already mounted — but never trust it silently: the whole
        // point is reflink, so verify or fail loud.
        return assert_reflink_capable(mount_point);
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
    assert_reflink_capable(mount_point)
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
    fn is_mounted_detects_root() {
        assert!(is_mounted(Path::new("/")).unwrap());
        assert!(!is_mounted(Path::new("/definitely-not-a-mount-point-k7d")).unwrap());
    }
}
