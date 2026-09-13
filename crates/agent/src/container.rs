//! Container lifecycle via runc inside the VM.
//!
//! Design decisions:
//! - `start`: uses `runc run --detach` so the agent returns immediately.
//! - `exec`: spawns `runc exec` in a background thread. Returns an exec ID
//!   instantly. The host polls `wait_exec(id)` for the result, so the
//!   connection is never blocked by a long-running exec.
//! - `output`: reads container stdout/stderr from files with byte offset,
//!   so the host can incrementally tail logs without loading everything.
//! - `stop`: `runc kill SIGTERM`, brief wait, `runc delete --force`.
//!   No busy-poll loop — runc delete --force handles cleanup regardless
//!   of whether the process has exited.

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

const CONTAINER_RUN_DIR: &str = "/run/k7/containers";

/// In-VM mount point of the sandbox's host-backed scratch
/// disk, where every container's overlay `upper`/`work` lives so a
/// container's writes land on a host image instead of guest RAM.
///
/// Must equal `k7d::disks::SCRATCH_GUEST_MOUNT`. The agent is a
/// standalone musl binary with no dependency on the host crate, so the
/// string is duplicated; the host puts the device here via `k7d.blk=`
/// and [`scratch_promised`] looks for exactly this mount point in the
/// kernel cmdline.
const SCRATCH_MOUNT: &str = "/run/k7d/scratch";

/// Root under which a container's **own** scratch disk is
/// mounted, one ext4 image per container that asked for a
/// writable-space limit. Must equal
/// `k7d::disks::CONTAINER_SCRATCH_GUEST_ROOT`; duplicated for the same
/// reason as [`SCRATCH_MOUNT`].
const CONTAINER_SCRATCH_ROOT: &str = "/run/k7d/cscratch";

/// CRI annotation carrying the Kubernetes container name. The runc
/// container name the agent is given is the containerd container id,
/// which does not exist when the host declares a container's scratch
/// device at sandbox create — so the *bundle* is what tells us which
/// mount under [`CONTAINER_SCRATCH_ROOT`] belongs to this container.
const CRI_CONTAINER_NAME: &str = "io.kubernetes.cri.container-name";

/// Size of the bounded tmpfs the writable layer falls back to when the
/// host attached **no** scratch disk (bare `Vm`-API callers; the shim
/// always attaches one).
///
/// The point of the `size=` option is that writable space
/// stops being "50% of guest RAM". This fallback is small, fixed, and
/// announced with a warning on every container start — a pod that
/// needs real writable space gets a scratch disk, and one that silently
/// got RAM instead is the failure mode this replaces.
const FALLBACK_TMPFS_SIZE: &str = "128m";
const RUNC_VIRTIOFS: &str = "/mnt/state/bin/runc";
/// The shim attaches a cached "tools" erofs image
/// (containing the static runc) as a read-only virtio-blk device
/// mounted here, so block-path pods carry no virtiofs share at all.
const RUNC_BLOCK_TOOLS: &str = "/run/k7d/tools/runc";
const RUNC_LOCAL: &str = "/usr/local/bin/runc";

pub(crate) fn runc_path() -> &'static str {
    if std::path::Path::new(RUNC_VIRTIOFS).exists() {
        RUNC_VIRTIOFS
    } else if std::path::Path::new(RUNC_BLOCK_TOOLS).exists() {
        RUNC_BLOCK_TOOLS
    } else {
        RUNC_LOCAL
    }
}

/// Tracks running containers managed by runc.
pub struct ContainerManager {
    containers: Mutex<HashMap<String, ContainerState>>,
    execs: Arc<Mutex<HashMap<String, ExecState>>>,
}

#[allow(clippy::struct_field_names)]
struct ContainerState {
    _bundle_path: String,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    /// Overlay rootfs mounts to tear down when the container goes away
    /// (erofs lower + tmpfs upper).
    overlay: Option<OverlayMounts>,
    /// The container init pid (from runc's `--pid-file`). The agent is
    /// guest PID 1, so `runc run --detach` reparents init to us and its
    /// real exit status is collectable via `waitpid`.
    init_pid: libc::pid_t,
    /// Cached exit code once the init process has been reaped, so every
    /// later `poll_exit`/`wait` caller observes the same code.
    exit_code: Option<i32>,
}

/// Mounts backing an overlay container rootfs, torn down in order on
/// cleanup: first the overlay (`merged`), then the fallback tmpfs
/// holding upper/work when there is one, then the upper/work directory
/// tree.
struct OverlayMounts {
    merged: PathBuf,
    /// `upper_root` is the mount point of this container's
    /// own scratch disk rather than a directory inside the shared one.
    /// Teardown must then empty it instead of removing it (the device
    /// stays mounted for the life of the VM), and usage is a `statfs`
    /// of an image nobody else writes to.
    dedicated: bool,
    /// Per-container tmpfs carrying `upper`/`work`, for the
    /// fallback path only. `None` when the writable layer is the
    /// host-backed scratch disk: that device is mounted once at boot
    /// and shared by every container in the pod, so it must survive
    /// this container's teardown.
    tmpfs: Option<PathBuf>,
    /// Directory holding `upper` and `work`, removed after the
    /// unmounts.
    upper_root: PathBuf,
    /// Guest-root bind mounts of container paths exported to dockerd.
    /// Unmounted *before* the overlay in [`cleanup_overlay`].
    exports: Vec<PathBuf>,
}

fn cleanup_overlay(overlay: &OverlayMounts) {
    // Path-export binds must come off before the overlay: they hold
    // the merged dir busy. Reverse order of mount.
    for mnt in overlay.exports.iter().rev() {
        let out = Command::new("umount").arg(mnt).output();
        if let Ok(out) = out {
            if !out.status.success() {
                eprintln!(
                    "k7-agent: umount export {} failed: {}",
                    mnt.display(),
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
        }
    }
    let mut mounts = vec![&overlay.merged];
    mounts.extend(overlay.tmpfs.as_ref());
    for mnt in mounts {
        let out = Command::new("umount").arg(mnt).output();
        if let Ok(out) = out {
            if !out.status.success() {
                eprintln!(
                    "k7-agent: umount {} failed: {}",
                    mnt.display(),
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
        }
    }
    if overlay.tmpfs.is_none() {
        // Scratch-disk path: reclaim this container's writable bytes.
        // (In the tmpfs path the directories died with the unmount, and
        // the mountpoint lives under the run dir the caller removes.)
        let reclaimed = if overlay.dedicated {
            // Its own device: empty the mount point, never remove it.
            clear_dir_contents(&overlay.upper_root)
        } else {
            fs::remove_dir_all(&overlay.upper_root)
        };
        if let Err(e) = reclaimed {
            eprintln!(
                "k7-agent: remove writable layer {} failed: {e}",
                overlay.upper_root.display()
            );
        }
    }
}

/// A container's writable-layer usage, measured inside the
/// guest. The host cannot compute this: it sees only the sparse image's
/// allocated blocks, which never shrink when the guest deletes a file
/// and say nothing about which container wrote them.
pub struct WritableUsage {
    /// Bytes the container's writable layer currently occupies.
    pub used_bytes: u64,
    /// Capacity of the filesystem that layer lives on.
    pub capacity_bytes: u64,
    /// Whether that filesystem is this container's alone. When false
    /// the capacity is shared with every other container in the pod,
    /// so it is a pod-level number, not a limit on this container.
    pub dedicated: bool,
}

/// `(used, capacity)` in bytes for the filesystem holding `path`.
fn statfs_bytes(path: &Path) -> Result<(u64, u64), String> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|e| format!("statfs path {}: {e}", path.display()))?;
    // SAFETY: an all-zero `statfs` is a valid initial value — every
    // field is an integer the kernel overwrites on success.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c_path` is a valid NUL-terminated string that outlives
    // the call, and `st` is a live, correctly sized statfs.
    let rc = unsafe { libc::statfs(c_path.as_ptr(), &raw mut st) };
    if rc != 0 {
        return Err(format!(
            "statfs {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    let frsize = u64::try_from(st.f_frsize).unwrap_or(0);
    let capacity = st.f_blocks.saturating_mul(frsize);
    let used = st
        .f_blocks
        .saturating_sub(st.f_bfree)
        .saturating_mul(frsize);
    Ok((used, capacity))
}

/// Bytes actually allocated under `dir`, summing `st_blocks` so sparse
/// files and holes count the way the filesystem counts them.
///
/// Only used for the shared-scratch case, where there is no cheaper
/// answer: a directory has no `statfs` of its own. Callers must not
/// poll this in a hot loop (the shim samples it on an interval).
fn tree_bytes(dir: &Path) -> Result<u64, String> {
    let mut total = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(path) = stack.pop() {
        let entries = match fs::read_dir(&path) {
            Ok(e) => e,
            // Raced with container teardown: the tree is going away,
            // so what is left of it is what it now uses.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("read {}: {e}", path.display())),
        };
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(format!("read entry under {}: {e}", path.display())),
            };
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(format!("stat {}: {e}", entry.path().display())),
            };
            total = total.saturating_add(meta.blocks().saturating_mul(512));
            if meta.is_dir() {
                stack.push(entry.path());
            }
        }
    }
    Ok(total)
}

/// Remove everything inside `dir`, leaving `dir` itself in place.
fn clear_dir_contents(dir: &Path) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            fs::remove_dir_all(&path)?;
        } else {
            fs::remove_file(&path)?;
        }
    }
    Ok(())
}

/// Filesystem type of the mount that `path` lives on, per
/// `/proc/mounts` (longest mountpoint prefix wins). `None` when the
/// path resolves to no mount (should not happen — `/` always matches).
fn mount_fstype_of(path: &Path) -> Option<String> {
    let mounts = fs::read_to_string("/proc/mounts").ok()?;
    let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let mut best: Option<(usize, String)> = None;
    for line in mounts.lines() {
        let mut fields = line.split_whitespace();
        let (Some(_dev), Some(mnt), Some(fstype)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let mnt_path = Path::new(mnt);
        if path.starts_with(mnt_path) && best.as_ref().is_none_or(|(len, _)| mnt.len() >= *len) {
            best = Some((mnt.len(), fstype.to_string()));
        }
    }
    best.map(|(_, fstype)| fstype)
}

/// Whether the host promised a scratch disk at [`SCRATCH_MOUNT`], per
/// the `k7d.blk=` kernel cmdline param. The promise is what
/// makes a missing mount an error rather than a configuration choice.
fn scratch_promised(cmdline: &str) -> bool {
    crate::parse_blk_mounts(cmdline)
        .is_some_and(|mounts| mounts.iter().any(|m| m.mount == SCRATCH_MOUNT))
}

/// Whether `path` is the mount point of an ext4 device, as opposed to
/// a plain directory. Both scratch paths live on the initramfs root
/// otherwise, which reports `rootfs`/`tmpfs` — so an ext4 answer means
/// the host really did attach the image (CHALLENGES #63:
/// `Path::exists()` cannot tell a mount from a mount point).
fn is_ext4_mount(path: &Path) -> bool {
    matches!(mount_fstype_of(path).as_deref(), Some("ext4"))
}

/// Where `name`'s **own** scratch disk would be mounted, from
/// the bundle's CRI annotations. `None` when the bundle carries no
/// usable Kubernetes container name (a bare `Vm`-API caller), which is
/// simply a container that cannot have asked for its own image.
///
/// The path existing says nothing about a device being there — see
/// [`is_ext4_mount`].
fn container_scratch_mount(config: &serde_json::Value) -> Option<PathBuf> {
    let k8s_name = config
        .get("annotations")
        .and_then(|a| a.get(CRI_CONTAINER_NAME))
        .and_then(serde_json::Value::as_str)
        .filter(|n| !n.is_empty() && !n.contains('/') && !n.contains(".."))?;
    Some(Path::new(CONTAINER_SCRATCH_ROOT).join(k8s_name))
}

/// Whether the host declared a per-container scratch device at `mount`,
/// per `k7d.blk=`. Same role as [`scratch_promised`] one level down: a
/// declared device that did not mount is an error, not a licence to
/// fall back onto the shared sandbox scratch the container was
/// explicitly moved off.
fn container_scratch_promised(cmdline: &str, mount: &Path) -> bool {
    crate::parse_blk_mounts(cmdline)
        .is_some_and(|mounts| mounts.iter().any(|m| Path::new(&m.mount) == mount))
}

/// Where a container's overlay `upper`/`work` will live.
enum WritableLayer {
    /// A per-container directory on the host-backed scratch disk. The
    /// device was mounted once at boot, so there is nothing to unmount
    /// when the container goes away.
    Scratch(PathBuf),
    /// The container's **own** host-backed image, mounted at
    /// [`CONTAINER_SCRATCH_ROOT`]`/<k8s name>`. Filling it gives this
    /// container `ENOSPC` and leaves its siblings untouched.
    ContainerScratch(PathBuf),
    /// A bounded per-container tmpfs, mounted here. Used only when the
    /// host attached no scratch disk.
    Tmpfs(PathBuf),
}

/// Decide (and set up) where `name`'s writable layer lives.
///
/// - Host promised a scratch disk and it is mounted ⇒ a directory on
///   it. Container writes go to the host image; capacity comes from the
///   `k7d.katakate.org/scratch-size` annotation, not from guest RAM.
/// - Host promised one and it is **not** mounted ⇒ hard error. The pod
///   was admitted on the promise of host-backed writable space;
///   quietly handing it RAM instead is precisely the regression this
///   contract exists to prevent.
/// - Host promised none ⇒ a bounded [`FALLBACK_TMPFS_SIZE`] tmpfs, with
///   a warning naming the annotation. Never an unsized tmpfs, whose
///   capacity would again be half of guest RAM.
fn prepare_writable_layer(
    run_dir: &Path,
    name: &str,
    config: &serde_json::Value,
) -> Result<WritableLayer, String> {
    let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();

    // A container that was given its own image wins over the
    // shared sandbox scratch — that is the whole point of asking.
    if let Some(mount) = container_scratch_mount(config) {
        let promised = container_scratch_promised(&cmdline, &mount);
        if promised && !is_ext4_mount(&mount) {
            return Err(format!(
                "the host declared a per-container scratch disk at {} (k7d.blk=) but it is \
                 not mounted (filesystem there is {:?}, want ext4) — refusing to run {name} \
                 on the pod's shared writable layer, whose capacity is not the limit it was \
                 given",
                mount.display(),
                mount_fstype_of(&mount)
            ));
        }
        if promised {
            // A leftover under this mount (a container restart, or a
            // warm fork's inherited copy) must not become the new
            // overlay's upper: stale whiteouts would mask files the
            // image legitimately has. Emptying it — rather than
            // removing it — keeps the device's mount point in place.
            clear_dir_contents(&mount)
                .map_err(|e| format!("clear stale writable layer {}: {e}", mount.display()))?;
            eprintln!(
                "k7-agent: {name} writable layer on its own scratch disk at {}",
                mount.display()
            );
            return Ok(WritableLayer::ContainerScratch(mount));
        }
    }

    if scratch_promised(&cmdline) {
        let fstype = mount_fstype_of(Path::new(SCRATCH_MOUNT));
        // A bare directory on the initramfs root reports `rootfs`/
        // `tmpfs` here: the device never mounted, so the promise was
        // not kept.
        if !matches!(fstype.as_deref(), Some("ext4")) {
            return Err(format!(
                "the host declared a scratch disk at {SCRATCH_MOUNT} (k7d.blk=) but it is \
                 not mounted (filesystem there is {fstype:?}, want ext4) — refusing to run \
                 {name} on a RAM-backed writable layer it was not sized for"
            ));
        }
        let root = Path::new(SCRATCH_MOUNT).join(name);
        // A leftover from an earlier container of the same name (a
        // restart inside a warm-forked guest) must not be inherited as
        // an overlay upper: stale whiteouts would mask files the new
        // image legitimately has.
        if root.exists() {
            fs::remove_dir_all(&root)
                .map_err(|e| format!("clear stale writable layer {}: {e}", root.display()))?;
        }
        fs::create_dir_all(&root).map_err(|e| format!("create {}: {e}", root.display()))?;
        eprintln!(
            "k7-agent: {name} writable layer on host-backed scratch disk at {}",
            root.display()
        );
        return Ok(WritableLayer::Scratch(root));
    }

    let tmpfs = run_dir.join("overlay");
    fs::create_dir_all(&tmpfs).map_err(|e| format!("create {}: {e}", tmpfs.display()))?;
    let out = Command::new("mount")
        .args([
            "-t",
            "tmpfs",
            "-o",
            &format!("size={FALLBACK_TMPFS_SIZE}"),
            "tmpfs",
        ])
        .arg(&tmpfs)
        .output()
        .map_err(|e| format!("mount tmpfs: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "mount tmpfs at {}: {}",
            tmpfs.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    eprintln!(
        "k7-agent: WARNING: no scratch disk attached; {name} writable layer is a \
         {FALLBACK_TMPFS_SIZE} guest tmpfs at {} and its writes consume guest RAM. Set \
         k7d.katakate.org/scratch-size on the pod for host-backed writable space",
        tmpfs.display()
    );
    Ok(WritableLayer::Tmpfs(tmpfs))
}

/// When the bundle's rootfs lives on a read-only erofs
/// block mount, runc cannot use it directly (no upper layer to write
/// to). Assemble `overlay(lower=<erofs rootfs>, upper+work=<writable
/// layer>)` and return a patched bundle whose `root.path` is the
/// overlay's merged dir. Returns the bundle to hand runc plus the
/// mounts to tear down; `(original bundle, None)` when the rootfs is
/// not on erofs.
///
/// The writable layer is the sandbox's host-backed scratch
/// disk ([`prepare_writable_layer`]), so a container's writes no longer
/// come out of the pod's memory budget.
#[allow(clippy::too_many_lines)]
fn prepare_rootfs_overlay(
    bundle: &Path,
    run_dir: &Path,
    name: &str,
) -> Result<(PathBuf, Option<OverlayMounts>), String> {
    let config_raw = fs::read_to_string(bundle.join("config.json"))
        .map_err(|e| format!("read config.json: {e}"))?;
    let mut config: serde_json::Value =
        serde_json::from_str(&config_raw).map_err(|e| format!("parse config.json: {e}"))?;
    let root_path = config
        .get("root")
        .and_then(|r| r.get("path"))
        .and_then(|p| p.as_str())
        .unwrap_or("rootfs");
    let rootfs = if root_path.starts_with('/') {
        PathBuf::from(root_path)
    } else {
        bundle.join(root_path)
    };
    if mount_fstype_of(&rootfs).as_deref() != Some("erofs") {
        return Ok((bundle.to_path_buf(), None));
    }

    // upper + work must live on the same writable filesystem: the
    // host-backed scratch disk, or the bounded tmpfs fallback.
    let mut overlay = match prepare_writable_layer(run_dir, name, &config)? {
        WritableLayer::Scratch(root) => OverlayMounts {
            // `merged` is only a mount point, so it stays on the guest
            // tmpfs run dir — the bytes behind it are the lower erofs
            // and the scratch upper.
            merged: run_dir.join("merged"),
            dedicated: false,
            tmpfs: None,
            upper_root: root,
            exports: Vec::new(),
        },
        WritableLayer::ContainerScratch(root) => OverlayMounts {
            merged: run_dir.join("merged"),
            dedicated: true,
            tmpfs: None,
            upper_root: root,
            exports: Vec::new(),
        },
        WritableLayer::Tmpfs(tmpfs) => OverlayMounts {
            merged: tmpfs.join("merged"),
            dedicated: false,
            tmpfs: Some(tmpfs.clone()),
            upper_root: tmpfs,
            exports: Vec::new(),
        },
    };
    let result = (|| {
        let upper = overlay.upper_root.join("upper");
        let work = overlay.upper_root.join("work");
        for d in [&upper, &work, &overlay.merged] {
            fs::create_dir_all(d).map_err(|e| format!("create {}: {e}", d.display()))?;
        }
        let opts = format!(
            "lowerdir={},upperdir={},workdir={}",
            rootfs.display(),
            upper.display(),
            work.display()
        );
        let out = Command::new("mount")
            .args(["-t", "overlay", "overlay", "-o", &opts])
            .arg(&overlay.merged)
            .output()
            .map_err(|e| format!("mount overlay: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "mount overlay ({opts}): {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }

        // Patched bundle: same config, root.path = the merged dir.
        let patched_bundle = run_dir.join("bundle");
        fs::create_dir_all(&patched_bundle)
            .map_err(|e| format!("create {}: {e}", patched_bundle.display()))?;
        config["root"]["path"] =
            serde_json::Value::String(overlay.merged.to_string_lossy().into_owned());
        fs::write(
            patched_bundle.join("config.json"),
            serde_json::to_string(&config).map_err(|e| format!("serialize config: {e}"))?,
        )
        .map_err(|e| format!("write patched config.json: {e}"))?;
        eprintln!(
            "k7-agent: erofs rootfs {} overlaid at {} (upper on {})",
            rootfs.display(),
            overlay.merged.display(),
            overlay.upper_root.display()
        );
        if crate::service::docker_cmdline() {
            overlay.exports = export_container_paths(&overlay.merged)?;
        }
        Ok(patched_bundle)
    })();
    match result {
        Ok(patched_bundle) => {
            if crate::service::docker_cmdline() {
                match export_container_paths(&overlay.merged) {
                    Ok(exports) => overlay.exports = exports,
                    Err(e) => {
                        cleanup_overlay(&overlay);
                        return Err(e);
                    }
                }
            }
            Ok((patched_bundle, Some(overlay)))
        }
        Err(e) => {
            cleanup_overlay(&overlay);
            Err(e)
        }
    }
}

enum ExecState {
    Running,
    Done(ExecOutput),
}

/// Result of a container exec operation.
pub struct ExecOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Captured output from a container's main process.
pub struct ContainerOutput {
    pub stdout: String,
    pub stderr: String,
}

fn container_dir(name: &str) -> PathBuf {
    PathBuf::from(CONTAINER_RUN_DIR).join(name)
}

/// Paths of the container merged rootfs bind-mounted onto the same
/// path in the guest root mount namespace so dockerd's `-v /tmp/x:/x`
/// sees the sandbox's files. Never `/mnt/state`, never
/// the container `/`.
const PATH_EXPORTS: &[&str] = &["/home", "/root", "/tmp", "/opt", "/workspace"];

fn export_container_paths(merged: &Path) -> Result<Vec<PathBuf>, String> {
    let mut exported = Vec::new();
    for p in PATH_EXPORTS {
        let src = merged.join(p.trim_start_matches('/'));
        if !src.is_dir() {
            continue;
        }
        fs::create_dir_all(p).map_err(|e| format!("mkdir {p} for docker path export: {e}"))?;
        let out = Command::new("mount")
            .args(["--bind", &src.to_string_lossy(), p])
            .output()
            .map_err(|e| format!("bind {p} for docker path export: {e}"))?;
        if !out.status.success() {
            for mnt in exported.iter().rev() {
                let _ = Command::new("umount").arg(mnt).output();
            }
            return Err(format!(
                "mount --bind {} {p}: {}",
                src.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        eprintln!("k7-agent: docker path export {} -> {p}", src.display());
        exported.push(PathBuf::from(p));
    }
    Ok(exported)
}

/// After `runc run`, the container's `/run` is a fresh tmpfs, so the
/// docker socket/CLI have to be planted via `runc exec`.
fn install_docker_symlinks(name: &str) -> Result<(), String> {
    let script = "mkdir -p /usr/local/bin /usr/local/lib/docker \
&& ln -sfn /run/k7d/docker/docker.sock /run/docker.sock \
&& ln -sfn /run/k7d/docker-tools/bin/docker /usr/local/bin/docker \
&& ln -sfn /run/k7d/docker-tools/cli-plugins /usr/local/lib/docker/cli-plugins";
    let output = Command::new(runc_path())
        .args(["exec", name, "sh", "-c", script])
        .output()
        .map_err(|e| format!("runc exec docker symlinks: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "runc exec {name} sh -c docker-symlinks failed (image has no sh?): {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    eprintln!("k7-agent: docker socket/CLI symlinks installed in {name}");
    Ok(())
}

fn read_from_offset(path: &Path, offset: u64, limit: usize) -> String {
    let Ok(mut f) = fs::File::open(path) else {
        return String::new();
    };
    if f.seek(SeekFrom::Start(offset)).is_err() {
        return String::new();
    }
    let mut buf = vec![0u8; limit];
    let n = f.read(&mut buf).unwrap_or(0);
    buf.truncate(n);
    String::from_utf8_lossy(&buf).to_string()
}

impl ContainerManager {
    pub fn new() -> Self {
        Self {
            containers: Mutex::new(HashMap::new()),
            execs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Start a container from an OCI bundle at `bundle_path`.
    /// The bundle must contain a `config.json` and a `rootfs/` directory.
    ///
    /// Uses `runc run --detach` so this returns as soon as runc forks the
    /// container init process. Stdout/stderr are captured to files under
    /// `/run/k7/containers/{name}/`.
    #[allow(clippy::too_many_lines)]
    pub fn start(&self, name: &str, bundle_path: &str) -> Result<(), String> {
        {
            let containers = self.containers.lock().unwrap();
            if containers.contains_key(name) {
                return Err(format!("container {name} already exists"));
            }
        }

        let bundle = Path::new(bundle_path);
        if !bundle.join("config.json").exists() {
            return Err(format!("no config.json in bundle at {bundle_path}"));
        }

        let run_dir = container_dir(name);
        fs::create_dir_all(&run_dir)
            .map_err(|e| format!("failed to create run dir {}: {e}", run_dir.display()))?;

        // Rootfs on a read-only erofs block mount gets
        // an overlay; runc receives the patched bundle. The
        // overlay's upper lives on the sandbox's host-backed scratch
        // disk, so this container's writes never touch guest RAM.
        let (runc_bundle, overlay) = match prepare_rootfs_overlay(bundle, &run_dir, name) {
            Ok(v) => v,
            Err(e) => {
                let _ = fs::remove_dir_all(&run_dir);
                return Err(format!("prepare rootfs overlay: {e}"));
            }
        };
        let runc_bundle_str = runc_bundle.to_string_lossy().into_owned();

        let stdout_path = run_dir.join("stdout");
        let stderr_path = run_dir.join("stderr");
        // Runc writes the init pid here at create time,
        // BEFORE start — reliable even for containers that exit
        // instantly (`runc state` would already report pid 0).
        let pid_file = run_dir.join("pid");

        let result = (|| {
            let stdout_file =
                fs::File::create(&stdout_path).map_err(|e| format!("create stdout file: {e}"))?;
            let stderr_file =
                fs::File::create(&stderr_path).map_err(|e| format!("create stderr file: {e}"))?;

            let child = Command::new(runc_path())
                .args([
                    "run",
                    "--detach",
                    "--no-pivot",
                    "--pid-file",
                    &pid_file.to_string_lossy(),
                    "--bundle",
                    &runc_bundle_str,
                    name,
                ])
                .stdin(Stdio::null())
                .stdout(stdout_file)
                .stderr(stderr_file)
                .spawn()
                .map_err(|e| format!("failed to spawn runc run: {e}"))?;

            // `runc run --detach` forks the container init and exits quickly.
            let output = child
                .wait_with_output()
                .map_err(|e| format!("runc run wait failed: {e}"))?;

            if !output.status.success() {
                let err_detail = fs::read_to_string(&stderr_path).unwrap_or_default();
                let _ = Command::new(runc_path())
                    .args(["delete", "--force", name])
                    .output();
                return Err(format!("runc run failed: {err_detail}"));
            }

            // Fail loud when the pid is unreadable: exit-code observation
            // is a correctness feature — restartPolicy
            // and init-container sequencing depend on it.
            let pid: libc::pid_t = fs::read_to_string(&pid_file)
                .map_err(|e| format!("read runc pid-file {}: {e}", pid_file.display()))?
                .trim()
                .parse()
                .map_err(|e| format!("parse runc pid-file {}: {e}", pid_file.display()))?;
            Ok(pid)
        })();
        let init_pid = match result {
            Ok(pid) => pid,
            Err(e) => {
                if let Some(ref ov) = overlay {
                    cleanup_overlay(ov);
                }
                let _ = fs::remove_dir_all(&run_dir);
                return Err(e);
            }
        };

        if crate::service::docker_cmdline() {
            if let Err(e) = install_docker_symlinks(name) {
                if let Some(ref ov) = overlay {
                    cleanup_overlay(ov);
                }
                let _ = Command::new(runc_path())
                    .args(["delete", "--force", name])
                    .output();
                let _ = fs::remove_dir_all(&run_dir);
                return Err(e);
            }
        }

        let mut containers = self.containers.lock().unwrap();
        containers.insert(
            name.to_string(),
            ContainerState {
                _bundle_path: bundle_path.to_string(),
                stdout_path,
                stderr_path,
                overlay,
                init_pid,
                exit_code: None,
            },
        );

        Ok(())
    }

    /// Execute a command inside a running container.
    ///
    /// Spawns `runc exec` in a background thread and returns immediately.
    /// The caller gets back an exec ID to poll with `wait_exec`.
    pub fn exec(&self, name: &str, exec_id: &str, args: &[String]) -> Result<(), String> {
        {
            let containers = self.containers.lock().unwrap();
            if !containers.contains_key(name) {
                return Err(format!("container {name} not found"));
            }
        }

        if args.is_empty() {
            return Err("empty command".to_string());
        }

        {
            let mut execs = self.execs.lock().unwrap();
            execs.insert(exec_id.to_string(), ExecState::Running);
        }

        let name = name.to_string();
        let exec_id = exec_id.to_string();
        let args: Vec<String> = args.to_vec();
        let execs = Arc::clone(&self.execs);

        thread::spawn(move || {
            let mut cmd = Command::new(runc_path());
            cmd.args(["exec", &name]);
            for arg in &args {
                cmd.arg(arg);
            }

            let result = match cmd.output() {
                Ok(output) => ExecOutput {
                    exit_code: output.status.code().unwrap_or(-1),
                    stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                    stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                },
                Err(e) => ExecOutput {
                    exit_code: -1,
                    stdout: String::new(),
                    stderr: format!("failed to run runc exec: {e}"),
                },
            };

            let mut execs = execs.lock().unwrap();
            execs.insert(exec_id, ExecState::Done(result));
        });

        Ok(())
    }

    /// Poll for the result of a background exec. Returns `None` if still
    /// running, `Some(ExecOutput)` if finished (consuming the result).
    pub fn wait_exec(&self, exec_id: &str) -> Option<ExecOutput> {
        let mut execs = self.execs.lock().unwrap();
        match execs.get(exec_id) {
            Some(ExecState::Running) => None,
            Some(ExecState::Done(_)) => {
                let ExecState::Done(output) = execs.remove(exec_id).unwrap() else {
                    unreachable!()
                };
                Some(output)
            }
            None => Some(ExecOutput {
                exit_code: -1,
                stdout: String::new(),
                stderr: format!("exec {exec_id} not found"),
            }),
        }
    }

    /// Read stdout/stderr from a container's main process, starting at
    /// byte `offset` and reading up to `limit` bytes.
    pub fn output(&self, name: &str, offset: u64, limit: usize) -> Result<ContainerOutput, String> {
        let containers = self.containers.lock().unwrap();
        let state = containers
            .get(name)
            .ok_or_else(|| format!("container {name} not found"))?;

        let stdout = read_from_offset(&state.stdout_path, offset, limit);
        let stderr = read_from_offset(&state.stderr_path, offset, limit);

        Ok(ContainerOutput { stdout, stderr })
    }

    /// Stop and delete a running container.
    ///
    /// Sends SIGTERM, waits briefly for graceful exit, then force-deletes.
    /// `runc delete --force` kills and removes the container regardless of
    /// its current state.
    pub fn stop(&self, name: &str) -> Result<(), String> {
        {
            let containers = self.containers.lock().unwrap();
            if !containers.contains_key(name) {
                return Err(format!("container {name} not found"));
            }
        }

        // SIGTERM for graceful shutdown
        let _ = Command::new(runc_path())
            .args(["kill", name, "SIGTERM"])
            .output();

        // Brief grace period, then force-delete
        thread::sleep(std::time::Duration::from_millis(200));

        let output = Command::new(runc_path())
            .args(["delete", "--force", name])
            .output()
            .map_err(|e| format!("failed to run runc delete: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("runc delete warning: {stderr}");
        }

        let mut containers = self.containers.lock().unwrap();
        if let Some(state) = containers.remove(name) {
            if let Some(ref ov) = state.overlay {
                cleanup_overlay(ov);
            }
            let _ = fs::remove_dir_all(state.stdout_path.parent().unwrap_or(Path::new("/")));
        }

        // Container stop is the durability point for
        // writable virtio-blk volumes (k7d RWO disk images). The VM is
        // torn down without a guest-side unmount, so anything still in
        // the guest page cache when the vCPUs stop would be lost —
        // flush it to the device now.
        // SAFETY: sync(2) takes no arguments and cannot fail.
        unsafe { libc::sync() };

        Ok(())
    }

    /// Whether a container with this name is tracked (PTY
    /// exec handshake validation).
    pub fn contains(&self, name: &str) -> bool {
        self.containers.lock().unwrap().contains_key(name)
    }

    /// List all running container names.
    pub fn list(&self) -> Vec<String> {
        let containers = self.containers.lock().unwrap();
        containers.keys().cloned().collect()
    }

    /// How much writable space `name` is using, and out of
    /// what capacity.
    ///
    /// A container with its **own** scratch disk gets an exact,
    /// constant-cost `statfs` of an image nobody else writes to — and
    /// the capacity is a real limit. A container sharing the sandbox
    /// scratch needs its `upper` tree walked, and the capacity it is
    /// reported against belongs to the whole pod.
    pub fn usage(&self, name: &str) -> Result<WritableUsage, String> {
        let (root, dedicated) = {
            let containers = self.containers.lock().unwrap();
            let state = containers
                .get(name)
                .ok_or_else(|| format!("container {name} not found"))?;
            match state.overlay {
                Some(ref ov) => (ov.upper_root.clone(), ov.dedicated),
                // No overlay means the rootfs was not on erofs, so
                // there is no writable layer of ours to measure. Say so
                // rather than reporting a zero that looks like "empty".
                None => {
                    return Err(format!(
                        "container {name} has no k7d-managed writable layer \
                         (its rootfs is not an overlay)"
                    ))
                }
            }
        };
        let (statfs_used, capacity_bytes) = statfs_bytes(&root)?;
        let used_bytes = if dedicated {
            statfs_used
        } else {
            tree_bytes(&root.join("upper"))?
        };
        Ok(WritableUsage {
            used_bytes,
            capacity_bytes,
            dedicated,
        })
    }

    /// Non-blocking exit probe. Returns `Ok(None)`
    /// while the init process runs, `Ok(Some(code))` once it exited.
    ///
    /// The agent is guest PID 1, so a detached container's init
    /// reparents to us when runc exits — a targeted
    /// `waitpid(pid, WNOHANG)` reaps it and yields the REAL exit code
    /// (`runc state` only ever says "stopped"). The first reap is
    /// cached so every later caller observes the same code. Killed by
    /// signal follows the shell convention: `128 + signum`.
    pub fn poll_exit(&self, name: &str) -> Result<Option<i32>, String> {
        let mut containers = self.containers.lock().unwrap();
        let state = containers
            .get_mut(name)
            .ok_or_else(|| format!("container {name} not found"))?;
        if let Some(code) = state.exit_code {
            return Ok(Some(code));
        }
        let mut status: libc::c_int = 0;
        // SAFETY: init_pid is our reparented child; WNOHANG makes this
        // non-blocking and status is a valid out-pointer.
        let ret = unsafe { libc::waitpid(state.init_pid, &raw mut status, libc::WNOHANG) };
        if ret == 0 {
            return Ok(None);
        }
        if ret != state.init_pid {
            // ECHILD etc. — the init was never (or is no longer) our
            // child. Loud: silently reporting Running-forever would
            // reintroduce the exact bug this exists to fix.
            return Err(format!(
                "waitpid({}) for container {name}: {}",
                state.init_pid,
                std::io::Error::last_os_error()
            ));
        }
        let code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else if libc::WIFSIGNALED(status) {
            128 + libc::WTERMSIG(status)
        } else {
            -1
        };
        state.exit_code = Some(code);
        Ok(Some(code))
    }

    /// Block until a container's init process exits. Returns the real
    /// exit code (previously this polled `runc state`
    /// and always returned 0).
    pub fn wait(&self, name: &str) -> Result<i32, String> {
        loop {
            if let Some(code) = self.poll_exit(name)? {
                return Ok(code);
            }
            thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    /// Send a signal to a container's init process.
    pub fn signal(&self, name: &str, signal: i32) -> Result<(), String> {
        {
            let containers = self.containers.lock().unwrap();
            if !containers.contains_key(name) {
                return Err(format!("container {name} not found"));
            }
        }

        let sig_name = match signal {
            1 => "SIGHUP",
            2 => "SIGINT",
            9 => "SIGKILL",
            15 => "SIGTERM",
            _ => return Err(format!("unsupported signal: {signal}")),
        };

        let output = Command::new(runc_path())
            .args(["kill", name, sig_name])
            .output()
            .map_err(|e| format!("runc kill failed: {e}"))?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!("runc kill failed: {stderr}"))
        }
    }
}

impl Drop for ContainerManager {
    fn drop(&mut self) {
        let containers = self.containers.get_mut().unwrap();
        for (name, state) in containers.drain() {
            let _ = Command::new(runc_path())
                .args(["kill", &name, "SIGKILL"])
                .output();
            let _ = Command::new(runc_path())
                .args(["delete", "--force", &name])
                .output();
            if let Some(ref ov) = state.overlay {
                cleanup_overlay(ov);
            }
            let _ = fs::remove_dir_all(state.stdout_path.parent().unwrap_or(Path::new("/")));
        }
    }
}
