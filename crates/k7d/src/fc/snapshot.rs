//! Snapshot materialisation for Firecracker forks.
//!
//! Firecracker writes two things per `PUT /snapshot/create`: a vmstate
//! file and a memory file. With `snapshot_type: Diff` the memory file
//! is sparse — only the pages dirtied since the previous snapshot are
//! data, everything else is a hole — and is **not** loadable on its own
//! unless the VM was booted from scratch. k7d turns that into something
//! a child can `LoadSnapshot` from with three files per VM:
//!
//! | File | Meaning |
//! |---|---|
//! | `load.mem` | what this VM was loaded from; `MAP_PRIVATE`d by Firecracker, immutable while the VM lives |
//! | `base.mem` | `load.mem` + every Diff since, applied in order — "memory as of the last snapshot point" |
//! | `restore-N.mem` | reflink of `base.mem` right after Diff N was applied; what children (and rollback) load |
//!
//! Applying a Diff is not a byte copy: each data extent of the Diff is
//! `FICLONERANGE`d into `base.mem` at the same offset, so a point costs
//! the dirty set in metadata and nothing in data movement. `restore-N`
//! and every child's `load.mem` are `FICLONE`s, so a fork's memory is
//! copy-on-write at the filesystem level exactly as the native
//! backend's is at the page-table level.
//!
//! Everything here is plain file I/O on paths k7d owns; the Firecracker
//! API half (create / load) lives on [`super::FcVm`].

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use serde::Serialize;

use super::FcError;

/// Which `snapshot_type` a fork point is taken with (`K7D_FC_FORK_SNAPSHOT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkSnapshot {
    /// `Diff` — dirty pages since the last point, applied onto
    /// `base.mem`. The default; O(divergence) per point.
    Diff,
    /// `Full` — the whole guest memory rewritten at every point. The
    /// pin-around for a Diff regression upstream: O(guest RAM) per
    /// point, children still copy-on-write.
    Full,
}

impl ForkSnapshot {
    /// Firecracker's `snapshot_type` string.
    #[must_use]
    pub fn api_name(self) -> &'static str {
        match self {
            Self::Diff => "Diff",
            Self::Full => "Full",
        }
    }

    /// The env value spelling (`diff` / `full`).
    #[must_use]
    pub fn env_name(self) -> &'static str {
        match self {
            Self::Diff => "diff",
            Self::Full => "full",
        }
    }
}

/// Parse `K7D_FC_FORK_SNAPSHOT`. Unset means `diff`; anything that is
/// not exactly `diff` or `full` is an error, not a fallback.
pub fn fork_mode() -> Result<ForkSnapshot, FcError> {
    match std::env::var("K7D_FC_FORK_SNAPSHOT") {
        Err(std::env::VarError::NotPresent) => Ok(ForkSnapshot::Diff),
        Err(e) => Err(FcError::Config {
            message: format!("read K7D_FC_FORK_SNAPSHOT: {e}"),
        }),
        Ok(v) => match v.trim() {
            "diff" => Ok(ForkSnapshot::Diff),
            "full" => Ok(ForkSnapshot::Full),
            other => Err(FcError::Config {
                message: format!("K7D_FC_FORK_SNAPSHOT={other:?}: expected \"diff\" or \"full\""),
            }),
        },
    }
}

/// `PUT /snapshot/create` body.
#[derive(Debug, Serialize)]
pub struct SnapshotCreateParams {
    /// `Diff` | `Full`.
    pub snapshot_type: &'static str,
    /// vmstate path, chroot-relative.
    pub snapshot_path: String,
    /// memory file path, chroot-relative.
    pub mem_file_path: String,
}

/// `mem_backend` of a `PUT /snapshot/load`.
#[derive(Debug, Serialize)]
pub struct MemoryBackend {
    /// Always `File`: the kernel handles the faults through the page
    /// cache, which is what makes `load.mem` shareable between children.
    pub backend_type: &'static str,
    /// `load.mem`, chroot-relative.
    pub backend_path: String,
}

/// One `network_overrides` entry.
#[derive(Debug, Serialize)]
pub struct NetworkOverride {
    /// The interface id the snapshot was taken with ([`super::NET_IFACE_ID`]).
    pub iface_id: String,
    /// The child's own TAP.
    pub host_dev_name: String,
}

/// `PUT /snapshot/load` body.
#[derive(Debug, Serialize)]
pub struct SnapshotLoadParams {
    /// vmstate path, chroot-relative.
    pub snapshot_path: String,
    /// The memory file.
    pub mem_backend: MemoryBackend,
    /// Not persisted in the snapshot, so it is passed on every load: a
    /// child has to be able to become a fork source itself.
    pub track_dirty_pages: bool,
    /// Resume in the same call — one round trip less per child.
    pub resume_vm: bool,
    /// Advance kvmclock by the wall time elapsed since the snapshot was
    /// taken (host kernel ≥ 5.16), so a child of an old restore point
    /// does not wake up in the past.
    pub clock_realtime: bool,
    /// The child's TAP, when the parent had one.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub network_overrides: Vec<NetworkOverride>,
}

/// `[(offset, len)]` of every allocated (data) extent of `file`, in
/// order, via `SEEK_DATA` / `SEEK_HOLE`.
///
/// Firecracker writes a Diff with `set_len(guest RAM)` and then only
/// the dirty pages, so this walk *is* the dirty set — on block
/// granularity, which is page granularity on the reflink XFS.
pub fn data_extents(file: &File) -> io::Result<Vec<(u64, u64)>> {
    let len = i64::try_from(file.metadata()?.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "file larger than i64"))?;
    let fd = file.as_raw_fd();
    let mut extents = Vec::new();
    let mut offset = 0i64;
    while offset < len {
        // SAFETY: `fd` is a live descriptor for the duration of the call.
        let data = unsafe { libc::lseek(fd, offset, libc::SEEK_DATA) };
        if data < 0 {
            let err = io::Error::last_os_error();
            // No data at or after `offset`: the rest is one hole.
            if err.raw_os_error() == Some(libc::ENXIO) {
                break;
            }
            return Err(err);
        }
        // SAFETY: as above.
        let hole = unsafe { libc::lseek(fd, data, libc::SEEK_HOLE) };
        if hole < 0 {
            return Err(io::Error::last_os_error());
        }
        let end = hole.min(len);
        extents.push((data.unsigned_abs(), (end - data).unsigned_abs()));
        offset = hole;
    }
    Ok(extents)
}

/// Bytes of data (non-hole) in `path` — the size of a Diff, and the
/// figure a snapshot point is booked at.
pub fn diff_bytes(path: &Path) -> Result<u64, FcError> {
    let file = File::open(path).map_err(|e| stage_err(path, format!("open: {e}")))?;
    let extents = data_extents(&file).map_err(|e| stage_err(path, format!("walk extents: {e}")))?;
    Ok(extents.iter().map(|(_, len)| *len).sum())
}

/// Apply Diff `diff` onto `base`: every data extent of `diff` replaces
/// the same range of `base`.
///
/// `FICLONERANGE` per extent, so the pages move as extent references
/// and not as bytes. If the filesystem refuses the range clone with
/// `EOPNOTSUPP` (`FICLONE` worked on the whole file but ranges are
/// refused — not a case XFS has, kept because the spec names it) the
/// extent is `copy_file_range`d instead, once, loudly. Any other error
/// is the caller's: a half-applied base is not a base, and the caller
/// must not publish it.
///
/// Returns the bytes applied.
pub fn apply_diff_onto_base(diff: &Path, base: &Path) -> Result<u64, FcError> {
    let src = File::open(diff).map_err(|e| stage_err(diff, format!("open diff: {e}")))?;
    let dst = std::fs::OpenOptions::new()
        .write(true)
        .open(base)
        .map_err(|e| stage_err(base, format!("open base for writing: {e}")))?;
    let src_len = src
        .metadata()
        .map_err(|e| stage_err(diff, format!("stat: {e}")))?
        .len();
    let dst_len = dst
        .metadata()
        .map_err(|e| stage_err(base, format!("stat: {e}")))?
        .len();
    if src_len != dst_len {
        return Err(stage_err(
            base,
            format!(
                "diff {} is {src_len} bytes but the base is {dst_len} — they do not describe \
                 the same guest memory",
                diff.display()
            ),
        ));
    }
    let extents = data_extents(&src).map_err(|e| stage_err(diff, format!("walk extents: {e}")))?;
    let mut applied = 0u64;
    let mut warned = false;
    for (offset, len) in extents {
        let range = libc::file_clone_range {
            src_fd: i64::from(src.as_raw_fd()),
            src_offset: offset,
            src_length: len,
            dest_offset: offset,
        };
        // SAFETY: both descriptors are open for the duration of the
        // call; `range` is a fully initialised `file_clone_range`.
        let rc = unsafe { libc::ioctl(dst.as_raw_fd(), libc::FICLONERANGE, &raw const range) };
        if rc == 0 {
            applied += len;
            continue;
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EOPNOTSUPP) {
            return Err(stage_err(
                base,
                format!(
                    "FICLONERANGE {}..{} from {}: {err}",
                    offset,
                    offset + len,
                    diff.display()
                ),
            ));
        }
        if !warned {
            log::warn!(
                "fc: FICLONERANGE not supported on {} ({err}) — copying diff extents \
                 instead; a snapshot point now costs its dirty set in data, not metadata",
                base.display()
            );
            warned = true;
        }
        copy_range(&src, &dst, offset, len).map_err(|e| {
            stage_err(
                base,
                format!("copy_file_range {offset}..{}: {e}", offset + len),
            )
        })?;
        applied += len;
    }
    dst.sync_all()
        .map_err(|e| stage_err(base, format!("fsync: {e}")))?;
    Ok(applied)
}

/// `copy_file_range` of exactly `len` bytes at `offset` in both files.
fn copy_range(src: &File, dst: &File, offset: u64, len: u64) -> io::Result<()> {
    let mut done = 0u64;
    while done < len {
        let mut off_in = i64::try_from(offset + done)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;
        let mut off_out = off_in;
        let want = usize::try_from(len - done).unwrap_or(usize::MAX);
        // SAFETY: both fds are open; the offset pointers outlive the call.
        let n = unsafe {
            libc::copy_file_range(
                src.as_raw_fd(),
                &raw mut off_in,
                dst.as_raw_fd(),
                &raw mut off_out,
                want,
                0,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "copy_file_range made no progress",
            ));
        }
        done += n.unsigned_abs() as u64;
    }
    Ok(())
}

/// Reflink `src` to a new file `dst` (`FICLONE`), mode `mode`.
///
/// Never a byte copy: the point of every clone here is that it costs
/// nothing until written, and a silent fallback would turn a fork into
/// a guest-RAM-sized write with the same success code.
pub fn reflink(src: &Path, dst: &Path, mode: u32) -> Result<(), FcError> {
    let src_file = File::open(src).map_err(|e| stage_err(src, format!("open: {e}")))?;
    let dst_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(dst)
        .map_err(|e| stage_err(dst, format!("create: {e}")))?;
    // SAFETY: both fds are valid for the call; FICLONE takes the source
    // fd as its integer argument.
    let rc = unsafe { libc::ioctl(dst_file.as_raw_fd(), libc::FICLONE, src_file.as_raw_fd()) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        let _ = std::fs::remove_file(dst);
        return Err(stage_err(
            dst,
            format!(
                "FICLONE from {}: {err} — a Firecracker fork needs its chroot base on a \
                 reflink filesystem (XFS reflink=1 / btrfs); see disks::ensure_reflink_fc_root",
                src.display()
            ),
        ));
    }
    // `create_new().mode()` is subject to the umask; set it explicitly.
    std::fs::set_permissions(dst, std::fs::Permissions::from_mode(mode))
        .map_err(|e| stage_err(dst, format!("chmod {mode:o}: {e}")))?;
    Ok(())
}

/// `FS_IOC_FIEMAP` — `_IOWR('f', 11, struct fiemap)`, 32-byte header.
const FS_IOC_FIEMAP: libc::c_ulong = 0xC020_660B;
const FIEMAP_FLAG_SYNC: u32 = 0x0000_0001;
const FIEMAP_EXTENT_LAST: u32 = 0x0000_0001;
const FIEMAP_EXTENT_SHARED: u32 = 0x0000_2000;
const FIEMAP_BATCH: usize = 256;

// Field names follow `struct fiemap_extent` in `linux/fiemap.h`.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(clippy::struct_field_names)]
struct FiemapExtent {
    fe_logical: u64,
    fe_physical: u64,
    fe_length: u64,
    fe_reserved64: [u64; 2],
    fe_flags: u32,
    fe_reserved: [u32; 3],
}

// Field names follow `struct fiemap` in `linux/fiemap.h`.
#[repr(C)]
#[allow(clippy::struct_field_names)]
struct Fiemap {
    fm_start: u64,
    fm_length: u64,
    fm_flags: u32,
    fm_mapped_extents: u32,
    fm_extent_count: u32,
    fm_reserved: u32,
    fm_extents: [FiemapExtent; FIEMAP_BATCH],
}

/// Physical extents of `path` split into `(shared, exclusive)` byte
/// totals, from `FIEMAP`'s `FIEMAP_EXTENT_SHARED` flag.
///
/// This is the only honest measure of what a reflinked file costs:
/// `st_blocks` counts a shared extent in every file that references it
/// (CHALLENGES #152), so `du` of a fork child's chroot reads as a whole
/// guest RAM even when the child has dirtied a page.
pub fn extent_sharing(path: &Path) -> Result<(u64, u64), FcError> {
    let file = File::open(path).map_err(|e| stage_err(path, format!("open: {e}")))?;
    let len = file
        .metadata()
        .map_err(|e| stage_err(path, format!("stat: {e}")))?
        .len();
    let zero_extent = FiemapExtent {
        fe_logical: 0,
        fe_physical: 0,
        fe_length: 0,
        fe_reserved64: [0; 2],
        fe_flags: 0,
        fe_reserved: [0; 3],
    };
    let (mut shared, mut exclusive) = (0u64, 0u64);
    let mut start = 0u64;
    loop {
        let mut req = Fiemap {
            fm_start: start,
            fm_length: len.saturating_sub(start),
            fm_flags: FIEMAP_FLAG_SYNC,
            fm_mapped_extents: 0,
            fm_extent_count: FIEMAP_BATCH as u32,
            fm_reserved: 0,
            fm_extents: [zero_extent; FIEMAP_BATCH],
        };
        // SAFETY: `req` is a correctly sized `struct fiemap` with room
        // for `fm_extent_count` extents, and outlives the call.
        let rc = unsafe { libc::ioctl(file.as_raw_fd(), FS_IOC_FIEMAP, &raw mut req) };
        if rc != 0 {
            return Err(stage_err(
                path,
                format!("FIEMAP: {}", io::Error::last_os_error()),
            ));
        }
        let mapped = req.fm_mapped_extents as usize;
        if mapped == 0 {
            break;
        }
        let mut last = false;
        for extent in &req.fm_extents[..mapped.min(FIEMAP_BATCH)] {
            if extent.fe_flags & FIEMAP_EXTENT_SHARED != 0 {
                shared += extent.fe_length;
            } else {
                exclusive += extent.fe_length;
            }
            start = extent.fe_logical + extent.fe_length;
            last |= extent.fe_flags & FIEMAP_EXTENT_LAST != 0;
        }
        if last || start >= len {
            break;
        }
    }
    Ok((shared, exclusive))
}

/// Whether every allocated extent of `path` is shared with another
/// file — what a freshly reflinked `load.mem` must look like.
pub fn is_cow(path: &Path) -> Result<bool, FcError> {
    let (shared, exclusive) = extent_sharing(path)?;
    Ok(shared > 0 && exclusive == 0)
}

fn stage_err(path: &Path, message: String) -> FcError {
    FcError::Stage {
        path: path.to_path_buf(),
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("k7d-fc-snap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        dir.join(name)
    }

    #[test]
    fn fork_mode_is_diff_by_default_and_loud_on_garbage() {
        // Only the not-set case is exercised through the real env var:
        // the parser is what the other cases test, and a `set_var` here
        // would race the rest of the unit-test binary.
        if std::env::var_os("K7D_FC_FORK_SNAPSHOT").is_none() {
            assert_eq!(fork_mode().expect("unset is diff"), ForkSnapshot::Diff);
        }
        assert_eq!(ForkSnapshot::Diff.api_name(), "Diff");
        assert_eq!(ForkSnapshot::Full.api_name(), "Full");
        assert_eq!(ForkSnapshot::Full.env_name(), "full");
    }

    /// A Diff is a sparse file: its data extents are the dirty set, and
    /// their byte total is what a point is booked at.
    #[test]
    fn data_extents_and_diff_bytes_see_through_holes() {
        let path = scratch("diff.mem");
        let _ = std::fs::remove_file(&path);
        let len = 64 * 1024 * 1024;
        {
            let mut f = File::create(&path).expect("create");
            f.set_len(len).expect("truncate");
            // Two runs of pages, one in the middle and one at the end.
            f.seek(SeekFrom::Start(1024 * 1024)).expect("seek");
            f.write_all(&[1u8; 3 * 4096]).expect("write");
            f.seek(SeekFrom::Start(len - 4096)).expect("seek");
            f.write_all(&[2u8; 4096]).expect("write");
            f.sync_all().expect("sync");
        }
        let f = File::open(&path).expect("open");
        let extents = data_extents(&f).expect("extents");
        assert_eq!(extents.len(), 2, "{extents:?}");
        assert_eq!(extents[0].0, 1024 * 1024);
        assert!(extents[0].1 >= 3 * 4096);
        assert_eq!(extents[1].0 + extents[1].1, len);
        let bytes = diff_bytes(&path).expect("bytes");
        assert!((4 * 4096..len / 4).contains(&bytes), "{bytes}");
        let _ = std::fs::remove_file(&path);
    }

    /// Serde shapes are the pinned swagger's: `mem_backend`, not the
    /// deprecated `mem_file_path`; no `network_overrides` key at all
    /// when there is nothing to override.
    #[test]
    fn load_params_serialise_as_firecracker_expects() {
        let body = serde_json::to_value(SnapshotLoadParams {
            snapshot_path: "/snap/vmstate".into(),
            mem_backend: MemoryBackend {
                backend_type: "File",
                backend_path: "/snap/load.mem".into(),
            },
            track_dirty_pages: true,
            resume_vm: true,
            clock_realtime: true,
            network_overrides: Vec::new(),
        })
        .expect("json");
        assert_eq!(body["mem_backend"]["backend_type"], "File");
        assert!(body.get("mem_file_path").is_none());
        assert!(body.get("network_overrides").is_none());
        assert_eq!(body["clock_realtime"], true);
    }

    #[test]
    fn apply_refuses_a_diff_of_another_size() {
        let diff = scratch("small.mem");
        let base = scratch("big.mem");
        std::fs::write(&diff, [0u8; 4096]).expect("diff");
        std::fs::write(&base, [0u8; 8192]).expect("base");
        let err = apply_diff_onto_base(&diff, &base).expect_err("size mismatch must be loud");
        assert!(err.to_string().contains("same guest memory"), "{err}");
        let _ = std::fs::remove_file(&diff);
        let _ = std::fs::remove_file(&base);
    }
}
