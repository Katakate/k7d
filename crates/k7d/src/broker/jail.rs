//! The node broker's half of the Firecracker family (`fc.*` verbs).
//!
//! What crosses the boundary here is staging, spawning, `chown`ing and
//! killing — not the VMM's HTTP API and not the guest agent's vsock
//! traffic, which stay parsed in the unprivileged half. So this module
//! is [`crate::fc::stage`] and [`crate::fc::spawn`] called from root,
//! plus the bookkeeping that makes `vm.release` total, and nothing
//! about Firecracker's protocol at all.
//!
//! ## Who owns what, and how uid `k7d` still reaches it
//!
//! ```text
//! /var/lib/k7d/fc/                   root  0700    never traversed by name
//! └── firecracker/<vm_id>/           root  0711    `<vm_dir>`; search only
//!     ├── snap/                      k7d   0700    the VM broker's points
//!     └── root/                      jail:k7d 0710 `<root>`; the chroot
//!         ├── vmlinux, initramfs…    root  0444    hard links, shared
//!         ├── img/, disk/            root  0755    staged by this module
//!         ├── snap/                  jail  0755    what Firecracker writes
//!         └── run/                   jail:k7d 02710 firecracker.socket, v.sock
//! ```
//!
//! The VM broker never has a usable *name* for any of it: `<base>` is
//! `0700` root, so every ancestor path is closed to uid `k7d`. What it
//! gets is an `O_PATH` descriptor of `<vm_dir>`, and
//! `/proc/self/fd/<n>/…` resolves from there without consulting the
//! ancestors at all. That is why `<vm_dir>` is `0711` rather than
//! `0700`: search permission on the directory a descriptor refers to is
//! the one thing the magic link does not grant for free, and it is
//! enough — `k7d` can traverse `<vm_dir>`, write in `snap/` because it
//! owns it, reach the sockets through `root/run/`, and write nothing
//! inside the jail.
//!
//! ## Three permission facts the jailer decides, not us
//!
//! The stock jailer, *after* it has `chroot`ed and *before* it execs
//! Firecracker, runs `setup_jailed_folder` over `["/", "/dev",
//! "/dev/net", "/run"]`: each becomes `chmod 0700` + `chown jail:jail`.
//! So whatever [`crate::fc::stage::stage`] set on `<root>` and
//! `<root>/run` is gone by the time there is a socket to reach, and the
//! re-opening has to happen *after* [`crate::fc::spawn::spawn`]
//! returns. That is [`open_the_jail_to_the_vm_broker`].
//!
//! Second, Firecracker binds both sockets with a plain
//! `UnixListener::bind`, which takes `0777 & ~umask`. The jailer sets no
//! umask, so the one this module spawns it with is the one Firecracker
//! creates its sockets under — and connecting to a Unix socket needs
//! **write** permission on the socket file. Hence
//! [`crate::fc::spawn::JAIL_UMASK`] (`0007`): `srwxrwx---`, plus the
//! setgid bit on `run/` so the group is `k7d` and not the jail's.
//!
//! Third, that is only in time for `firecracker.socket`. `v.sock` does
//! not exist until the VM broker's `PUT /vsock`, long after `fc.spawn`
//! answered, which is the whole reason [`super::Verb::FcConnect`]
//! exists: the setgid-plus-umask pair is what normally makes it
//! reachable by name, and the verb is the loud repair when it is not.

use std::collections::HashMap;
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::paths::Pinned;
use super::{FcRestore, FcSocket, ImageRef, Reply};
use crate::fc::{spawn, stage};

/// Everything the node broker holds for one Firecracker jail.
///
/// Field order is the teardown order and is load-bearing, the same way
/// [`crate::fc::FcVm`]'s is: the process dies, then its cgroup goes,
/// then the chroot (whose hard links must be gone before a scratch
/// image is unlinked), then the uid returns to the allocator.
struct Jail {
    pid: u32,
    cgroup_dir: PathBuf,
    /// Writable drives, as `(jail name, host source)` — what a snapshot
    /// export has to clone, and what a re-adopting VM broker points its
    /// `FcConfig` at. A restored VM's clones are the jail's own files
    /// under `<vm_dir>/root/disk/`.
    writable: Vec<(String, PathBuf)>,
    /// What the spawn asked for, for `fc.list` (§9.3): the successor VM
    /// broker rebuilds its `FcConfig` from these.
    vcpus: u32,
    memory_mb: u64,
    cpu: Option<(u64, u64)>,
    restored_from: Option<u32>,
    /// Read-only images staged into `img/`, as `(jail name, host
    /// source)`, kept current by [`update_drive`].
    ///
    /// Only a fork child reads this, and it is the whole reason a child
    /// costs one round trip and not one per image: a child's read-only
    /// set *is* its parent's, so [`Verb::FcSpawn`] can leave `images`
    /// empty and the node broker re-links the sources it validated when
    /// the parent registered them.
    ///
    /// [`Verb::FcSpawn`]: super::Verb::FcSpawn
    read_only: Vec<(String, PathBuf)>,
    /// Guest pair, inherited by a fork child for the same reason.
    kernel: PathBuf,
    initrd: Option<PathBuf>,
    /// Whether the jail was given a TAP, for `fc.list` (§9.3).
    tap: bool,
    chroot: stage::Chroot,
    uid: stage::UidLease,
}

static JAILS: Mutex<Option<HashMap<String, Jail>>> = Mutex::new(None);

fn jails<T>(f: impl FnOnce(&mut HashMap<String, Jail>) -> T) -> T {
    let mut guard = JAILS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f(guard.get_or_insert_with(HashMap::new))
}

/// Refuse a jail-relative file name that is anything but one plain
/// component.
///
/// The name decides where a `link(2)` and a `chown(2)` land, so it is as
/// much a path parameter as anything `vm.register` takes — it is just a
/// short one. `../../../etc/shadow` is the reason this is checked rather
/// than trusted.
fn component(kind: &str, name: &str) -> Result<(), Reply> {
    let plain = !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\0');
    if plain {
        return Ok(());
    }
    Err(Reply::failed(
        libc::EINVAL,
        format!("{kind} {name:?} is not a single plain file name"),
    ))
}

fn staging_failed(what: &str, e: &crate::fc::FcError) -> Reply {
    Reply::failed(0, format!("{what}: {e}"))
}

fn io_failed(what: &str, e: &io::Error) -> Reply {
    Reply::failed(e.raw_os_error().unwrap_or(0), format!("{what}: {e}"))
}

fn unknown_jail(vm_id: &str) -> Reply {
    Reply::failed(
        libc::ENOENT,
        format!("vm {vm_id} has no Firecracker jail — fc.spawn must come first"),
    )
}

/// How the caller turns a registered block index into the host path the
/// node broker validated for it. The `VmTable` lives in
/// [`super::node`], so the lookup is passed in rather than reached for.
pub type Resolve<'a> = dyn Fn(u16) -> Result<PathBuf, Reply> + 'a;

/// One [`super::Verb::FcSpawn`], as the node broker reads it.
pub struct SpawnRequest<'a> {
    /// Id the jail is known by, and the jailer's `--id`.
    pub vm_id: &'a str,
    /// vCPU count.
    pub vcpus: u32,
    /// Guest RAM in MiB, and the jailer's `memory.max`.
    pub memory_mb: u64,
    /// CFS `(quota, period)` in µs, when the pod capped them.
    pub cpu: Option<(u64, u64)>,
    /// Whether the VM was given a TAP, for `fc.list` (§9.3).
    pub tap: bool,
    /// Files to link into the jail, by registered index.
    pub images: &'a [ImageRef],
    /// Guest state to load, for a fork child or a resume.
    pub restore_from: Option<&'a FcRestore>,
}

/// `fc.spawn`: stage a jail, load a point into it when there is one, and
/// exec the jailer.
#[must_use]
pub fn spawn_jail(req: &SpawnRequest<'_>, resolve: &Resolve<'_>) -> (Reply, Vec<OwnedFd>) {
    match spawn_jail_inner(req, resolve) {
        Ok(out) => out,
        Err(reply) => (reply, Vec::new()),
    }
}

/// uid and gid of the VM broker, which most of this module's `chown`s
/// are towards.
fn broker_owner() -> Result<(u32, u32), Reply> {
    let uid = super::lookup_uid(super::VM_BROKER_USER).map_err(|e| Reply::failed(0, e))?;
    let gid = super::lookup_gid(super::VM_BROKER_USER).map_err(|e| Reply::failed(0, e))?;
    Ok((uid, gid))
}

fn spawn_jail_inner(
    req: &SpawnRequest<'_>,
    resolve: &Resolve<'_>,
) -> Result<(Reply, Vec<OwnedFd>), Reply> {
    let vm_id = req.vm_id;
    if jails(|j| j.contains_key(vm_id)) {
        return Err(Reply::failed(
            libc::EEXIST,
            format!("vm {vm_id} already has a live Firecracker jail"),
        ));
    }
    let owner = broker_owner()?;

    let images = resolve_images(req, resolve)?;
    let staged = stage_jail(req, resolve, &images, owner)?;
    let Staged {
        chroot,
        lease,
        writable,
        base,
        fc_binary,
        jailer_binary,
    } = staged;

    let vm_dir = chroot.vm_dir().to_path_buf();
    let spawned = spawn::spawn(
        &spawn::JailerArgs {
            vm_id,
            exec_file: &fc_binary,
            jailer: &jailer_binary,
            chroot_base: &base,
            uid: lease.uid(),
            memory_mb: req.memory_mb,
            cpu_quota_us: req.cpu.map(|(q, _)| q),
            cpu_period_us: req.cpu.map(|(_, p)| p),
        },
        &chroot,
    )
    .map_err(|e| staging_failed(&format!("fc.spawn({vm_id})"), &e))?;

    // From here a Firecracker process is running, so every remaining
    // failure kills it before the chroot and the uid unwind.
    let started = Started {
        pid: spawned.pid,
        cgroup_dir: spawned.cgroup_dir,
    };
    let fds = match finish_spawn(vm_id, &chroot, &started, owner.1) {
        Ok(fds) => fds,
        Err(reply) => {
            crate::fc::kill_and_wait(started.pid);
            crate::fc::remove_cgroup(&started.cgroup_dir);
            return Err(reply);
        }
    };

    log::info!(
        "fc.spawn({vm_id}): firecracker pid {} as uid {} ({} vcpu, {} MiB, tap={}) in {}",
        started.pid,
        lease.uid(),
        req.vcpus,
        req.memory_mb,
        req.tap,
        vm_dir.display()
    );
    let reply = Reply::FcSpawned {
        vm_dir: vm_dir.display().to_string(),
        pid: started.pid,
        uid: lease.uid(),
    };
    jails(|j| {
        j.insert(
            vm_id.to_string(),
            Jail {
                pid: started.pid,
                cgroup_dir: started.cgroup_dir.clone(),
                writable,
                vcpus: req.vcpus,
                memory_mb: req.memory_mb,
                cpu: req.cpu,
                restored_from: match req.restore_from {
                    Some(FcRestore::Point { generation, .. }) => Some(*generation),
                    Some(FcRestore::Exported { .. }) => Some(0),
                    None => None,
                },
                read_only: images.read_only,
                kernel: images.kernel,
                initrd: images.initrd,
                tap: req.tap,
                chroot,
                uid: lease,
            },
        );
    });
    Ok((reply, fds))
}

/// A jail with everything in it, and nothing running in it yet.
struct Staged {
    chroot: stage::Chroot,
    lease: stage::UidLease,
    writable: Vec<(String, PathBuf)>,
    base: PathBuf,
    fc_binary: PathBuf,
    jailer_binary: PathBuf,
}

/// Build the chroot, link every image into it, hand `snap/` to the VM
/// broker and load a point when there is one.
fn stage_jail(
    req: &SpawnRequest<'_>,
    resolve: &Resolve<'_>,
    images: &Images,
    owner: (u32, u32),
) -> Result<Staged, Reply> {
    let vm_id = req.vm_id;
    let fc_binary = crate::fc::firecracker_binary().map_err(|e| staging_failed("fc.spawn", &e))?;
    let jailer_binary = crate::fc::jailer_binary().map_err(|e| staging_failed("fc.spawn", &e))?;
    let exec_name =
        spawn::exec_file_name(&fc_binary).map_err(|e| staging_failed("fc.spawn", &e))?;
    let base = stage::chroot_base();
    std::fs::create_dir_all(&base)
        .map_err(|e| io_failed(&format!("create jailer chroot base {}", base.display()), &e))?;

    // Declared before `stage` and therefore dropped after it on every
    // `?` below, for the reason `FcVm::spawn_unconfigured` spells out: a
    // uid must never return to the allocator while a process still runs
    // under it in a chroot that still exists.
    let lease = stage::UidLease::acquire().map_err(|e| staging_failed("fc.spawn", &e))?;
    let chroot = stage::stage(
        &base,
        &exec_name,
        vm_id,
        &images.kernel,
        images.initrd.as_deref(),
        lease.uid(),
    )
    .map_err(|e| staging_failed(&format!("fc.spawn({vm_id})"), &e))?;

    for (name, src) in &images.read_only {
        chroot
            .link_read_only(name, src)
            .map_err(|e| staging_failed(&format!("fc.spawn({vm_id}) img/{name}"), &e))?;
    }
    let mut writable = Vec::new();
    for (name, src) in &images.read_write {
        chroot
            .link_read_write(name, src)
            .map_err(|e| staging_failed(&format!("fc.spawn({vm_id}) disk/{name}"), &e))?;
        writable.push((name.clone(), src.clone()));
    }

    // The VM broker's own half of the jail: `snap/` is where it applies
    // diffs, mints `restore-N.mem` and keeps a point. `<vm_dir>` itself
    // stays root's and only gains the search bit, so a compromised VM
    // broker can traverse into `snap/` and rename nothing above it.
    //
    // Before the restore staging, because that writes `load.mem` into
    // this directory and the VM broker has to be able to read it back.
    stage::chown_gid(&chroot.snap_dir(), owner.0, owner.1)
        .map_err(|e| staging_failed(&format!("fc.spawn({vm_id}) snap dir"), &e))?;
    stage::chmod(chroot.vm_dir(), 0o711)
        .map_err(|e| staging_failed(&format!("fc.spawn({vm_id}) vm dir"), &e))?;
    if let Some(restore) = req.restore_from {
        stage_restore(vm_id, &chroot, restore, resolve, &mut writable, owner)?;
    }
    Ok(Staged {
        chroot,
        lease,
        writable,
        base,
        fc_binary,
        jailer_binary,
    })
}

struct Started {
    pid: u32,
    cgroup_dir: PathBuf,
}

/// Everything that has to be inside a jail before Firecracker looks for
/// it, as host paths this process may `link(2)`.
struct Images {
    kernel: PathBuf,
    initrd: Option<PathBuf>,
    read_only: Vec<(String, PathBuf)>,
    read_write: Vec<(String, PathBuf)>,
}

/// Turn a spawn's `images` into paths, inheriting a fork child's
/// read-only set from the jail it forks off.
///
/// The inheritance is what keeps the fork hot path at one round trip. A
/// child's guest pair and read-only images are its parent's by
/// definition — same `FcConfig`, cloned — so making the VM broker name
/// them would cost a `vm.register_disk` per image per child for paths
/// this process already validated once and is still holding a link to.
/// An `images` list that *does* name a kernel overrides, which is the
/// resume-from-disk case: there the source jail is long gone.
fn resolve_images(req: &SpawnRequest<'_>, resolve: &Resolve<'_>) -> Result<Images, Reply> {
    let vm_id = req.vm_id;
    let mut kernel = None;
    let mut initrd = None;
    let mut read_only = Vec::new();
    let mut read_write = Vec::new();
    for image in req.images {
        match image {
            ImageRef::Kernel { device_idx } => kernel = Some(resolve(*device_idx)?),
            ImageRef::Initrd { device_idx } => initrd = Some(resolve(*device_idx)?),
            ImageRef::ReadOnly { device_idx, name } => {
                component("image name", name)?;
                read_only.push((name.clone(), resolve(*device_idx)?));
            }
            ImageRef::ReadWrite { device_idx, name } => {
                component("disk name", name)?;
                read_write.push((name.clone(), resolve(*device_idx)?));
            }
        }
    }
    if kernel.is_none() {
        if let Some(FcRestore::Point { source_vm_id, .. }) = req.restore_from {
            let parent = jails(|j| {
                j.get(source_vm_id).map(|jail| {
                    (
                        jail.kernel.clone(),
                        jail.initrd.clone(),
                        jail.read_only.clone(),
                    )
                })
            });
            let Some((parent_kernel, parent_initrd, parent_ro)) = parent else {
                return Err(Reply::failed(
                    libc::ENOENT,
                    format!("fc.spawn({vm_id}) inherits from {source_vm_id}, which has no jail"),
                ));
            };
            kernel = Some(parent_kernel);
            initrd = parent_initrd;
            read_only = parent_ro;
        }
    }
    let Some(kernel) = kernel else {
        return Err(Reply::failed(
            libc::EINVAL,
            format!("fc.spawn({vm_id}) named no kernel image"),
        ));
    };
    Ok(Images {
        kernel,
        initrd,
        read_only,
        read_write,
    })
}

/// Re-open the jail to uid `k7d` and take the two descriptors the reply
/// carries.
fn finish_spawn(
    vm_id: &str,
    chroot: &stage::Chroot,
    started: &Started,
    broker_gid: u32,
) -> Result<Vec<OwnedFd>, Reply> {
    open_the_jail_to_the_vm_broker(chroot, broker_gid)
        .map_err(|e| staging_failed(&format!("fc.spawn({vm_id})"), &e))?;
    let pidfd = crate::seqmsg::pidfd_open(started.pid)
        .map_err(|e| io_failed(&format!("pidfd_open on firecracker {}", started.pid), &e))?;
    let dir = open_path_dir(chroot.vm_dir())
        .map_err(|e| io_failed(&format!("O_PATH {}", chroot.vm_dir().display()), &e))?;
    Ok(vec![pidfd, dir])
}

/// Undo the jailer's `chmod 0700; chown jail:jail` on `<root>` and
/// `<root>/run` far enough that uid `k7d` can reach the two sockets, and
/// no further.
///
/// `<root>` keeps the jail as its owner — Firecracker writes in it — and
/// gains `k7d` as its group with `--x` for it: search, not read, so the
/// VM broker can walk to `run/` and cannot list the chroot. `run/` gains
/// the same plus the **setgid** bit, which is what makes `v.sock` (bound
/// by Firecracker minutes later, at `PUT /vsock`) come out group `k7d`
/// instead of group jail. Together with the `0007` umask the jailer was
/// spawned under, that is a `srwxrwx--- jail:k7d` socket the VM broker
/// can connect to and nobody else can.
fn open_the_jail_to_the_vm_broker(
    chroot: &stage::Chroot,
    broker_gid: u32,
) -> Result<(), crate::fc::FcError> {
    let jail_uid = chroot.uid();
    let root = chroot.root().to_path_buf();
    stage::chown_gid(&root, jail_uid, broker_gid)?;
    stage::chmod(&root, 0o710)?;
    let run = root.join("run");
    stage::chown_gid(&run, jail_uid, broker_gid)?;
    stage::chmod(&run, 0o2710)?;
    // The API socket exists already (`spawn` waited for it to accept),
    // so it predates the setgid bit and is re-grouped by hand.
    let api = chroot.api_socket();
    stage::chown_gid(&api, jail_uid, broker_gid)?;
    stage::chmod(&api, 0o660)
}

/// Put a point's files where the jailed Firecracker will look for them.
///
/// The mirror of what `FcVm::stage_from_point` did in one process: the
/// memory image is **reflinked** (so the child's RAM is copy-on-write of
/// its parent's point and `is_cow` holds), `vmstate` is hard-linked, and
/// each writable disk is reflinked into `disk/` and handed to the jail
/// uid. `load.mem` also gets a reflink into the VM broker's own `snap/`,
/// which is the handle it keeps: the copy inside the chroot is the
/// jail's to unlink.
fn stage_restore(
    vm_id: &str,
    chroot: &stage::Chroot,
    restore: &FcRestore,
    resolve: &Resolve<'_>,
    writable: &mut Vec<(String, PathBuf)>,
    owner: (u32, u32),
) -> Result<(), Reply> {
    let (vmstate, mem, disks) = restore_sources(vm_id, restore, resolve)?;
    let jail_snap = chroot.jail_snap_dir();
    let own_snap = chroot.snap_dir();

    // Never a copy *into* `load.mem`: that file has to share extents
    // with the point or the child's memory is not a fork at all
    // (`FcVm::spawn_from_point` refuses it). A source on another
    // filesystem is imported once and both links are taken from the
    // import (CHALLENGES #225).
    let jail_load = jail_snap.join("load.mem");
    let own_load = own_snap.join("load.mem");
    let named = |what: &str| format!("fc.spawn({vm_id}) {what}");
    match crate::fc::snapshot::reflink(&mem, &jail_load, 0o444) {
        Ok(()) => crate::fc::snapshot::reflink(&mem, &own_load, 0o400)
            .map_err(|e| staging_failed(&named("load.mem"), &e))?,
        Err(e) if crate::fc::is_exdev(&e) => {
            let imported = own_snap.join("imported.mem");
            log::warn!(
                "fc.spawn({vm_id}): {e}; copying {} onto the jail filesystem first",
                mem.display()
            );
            crate::fc::copy_file(&mem, &imported, 0o400)
                .map_err(|e| staging_failed(&named("imported.mem"), &e))?;
            crate::fc::snapshot::reflink(&imported, &jail_load, 0o444)
                .map_err(|e| staging_failed(&named("load.mem"), &e))?;
            crate::fc::snapshot::reflink(&imported, &own_load, 0o400)
                .map_err(|e| staging_failed(&named("load.mem"), &e))?;
        }
        Err(e) => return Err(staging_failed(&named("load.mem"), &e)),
    }
    // `is_cow` opens this file, and the process that calls it is the VM
    // broker. Everything root creates inside the (already `k7d`-owned)
    // `snap/` is root's until it is handed over by name.
    stage::chown_gid(&own_load, owner.0, owner.1)
        .map_err(|e| staging_failed(&named("load.mem"), &e))?;
    crate::fc::hard_link_or_copy(&vmstate, &jail_snap.join("vmstate"))
        .map_err(|e| staging_failed(&named("vmstate"), &e))?;
    for (src, name) in disks {
        let dst = chroot.disk_path(&name);
        crate::fc::clone_or_copy(&src, &dst, 0o600)
            .map_err(|e| staging_failed(&named(&format!("disk/{name}")), &e))?;
        stage::chown(&dst, chroot.uid())
            .map_err(|e| staging_failed(&format!("fc.spawn({vm_id}) disk/{name}"), &e))?;
        writable.push((name, dst));
    }
    Ok(())
}

/// `(vmstate, memory, [(disk, jail name)])` for a restore, from whichever
/// of the two sources the caller named.
type RestoreSources = (PathBuf, PathBuf, Vec<(PathBuf, String)>);

fn restore_sources(
    vm_id: &str,
    restore: &FcRestore,
    resolve: &Resolve<'_>,
) -> Result<RestoreSources, Reply> {
    match restore {
        FcRestore::Point {
            source_vm_id,
            generation,
        } => {
            let source = jails(|j| {
                j.get(source_vm_id).map(|jail| {
                    (
                        jail.chroot.snap_dir(),
                        jail.writable
                            .iter()
                            .map(|(name, _)| name.clone())
                            .collect::<Vec<_>>(),
                    )
                })
            });
            let Some((dir, names)) = source else {
                return Err(Reply::failed(
                    libc::ENOENT,
                    format!(
                        "fc.spawn({vm_id}) restores from {source_vm_id}, which has no live jail"
                    ),
                ));
            };
            Ok((
                dir.join(format!("vmstate-{generation}")),
                dir.join(format!("restore-{generation}.mem")),
                names
                    .into_iter()
                    .map(|name| (dir.join(format!("disk-{generation}-{name}")), name))
                    .collect(),
            ))
        }
        FcRestore::Exported {
            vmstate_idx,
            mem_idx,
            disks,
        } => {
            let mut resolved = Vec::with_capacity(disks.len());
            for disk in disks {
                component("disk name", &disk.name)?;
                resolved.push((resolve(disk.device_idx)?, disk.name.clone()));
            }
            Ok((resolve(*vmstate_idx)?, resolve(*mem_idx)?, resolved))
        }
    }
}

fn open_path_dir(dir: &Path) -> io::Result<OwnedFd> {
    use std::os::fd::FromRawFd;
    let c = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).map_err(io::Error::other)?;
    // SAFETY: `c` is a valid C string that outlives the call.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `open` returned a fresh descriptor this process owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `fc.connect`: make one of the jail's sockets reachable by uid `k7d`
/// and hand over a connected stream.
///
/// The happy path never needs this — the setgid `run/` plus the jailer's
/// `0007` umask already give both sockets `srwxrwx--- jail:k7d`, and the
/// VM broker connects by name through its `<vm_dir>` descriptor. It is
/// the declared fallback for the case where the socket came out
/// with the group or the mode the *default* umask would give it, which
/// the VM broker cannot repair itself: `chown` is root's.
#[must_use]
pub fn connect(vm_id: &str, which: FcSocket) -> (Reply, Vec<OwnedFd>) {
    let found = jails(|j| {
        j.get(vm_id).map(|jail| {
            let path = match which {
                FcSocket::Api => jail.chroot.api_socket(),
                FcSocket::Vsock => jail.chroot.vsock_uds(),
            };
            (path, jail.chroot.uid())
        })
    });
    let Some((path, jail_uid)) = found else {
        return (unknown_jail(vm_id), Vec::new());
    };
    let named = format!("fc.connect({vm_id}, {which:?}) {}", path.display());
    let gid = match super::lookup_gid(super::VM_BROKER_USER) {
        Ok(g) => g,
        Err(e) => return (Reply::failed(0, e), Vec::new()),
    };
    if let Err(e) = stage::chown_gid(&path, jail_uid, gid).and_then(|()| stage::chmod(&path, 0o660))
    {
        return (staging_failed(&named, &e), Vec::new());
    }
    match std::os::unix::net::UnixStream::connect(&path) {
        Ok(stream) => (Reply::Fds, vec![OwnedFd::from(stream)]),
        Err(e) => (io_failed(&named, &e), Vec::new()),
    }
}

/// `fc.update_drive`: link a fill into `img/` under a name Firecracker
/// has not already opened, and unlink the link it replaces.
#[must_use]
pub fn update_drive(vm_id: &str, src: &Path, name: &str, replaces: &str) -> Reply {
    if let Err(reply) = component("fill name", name) {
        return reply;
    }
    if !replaces.is_empty() {
        if let Err(reply) = component("replaced name", replaces) {
            return reply;
        }
    }
    let staged = jails(|j| match j.get_mut(vm_id) {
        None => Err(unknown_jail(vm_id)),
        Some(jail) => {
            let linked = jail.chroot.link_read_only(name, src);
            if linked.is_ok() {
                // A fork child inherits the jail's *current* read-only
                // set, so a fill has to be in it: a child of a VM whose
                // image slot was filled must see the filled image, not
                // the empty backing file the pod booted with.
                jail.read_only.retain(|(n, _)| n != replaces && n != name);
                jail.read_only.push((name.to_string(), src.to_path_buf()));
            }
            Ok((linked, jail.chroot.img_path(replaces)))
        }
    });
    match staged {
        Err(reply) => reply,
        Ok((Err(e), _)) => staging_failed(&format!("fc.update_drive({vm_id}) img/{name}"), &e),
        Ok((Ok(_), stale)) => {
            // Only after the new link is in place: Firecracker still has
            // the previous file open until the VM broker's `PATCH
            // /drives` lands, and unlinking first would leave the guest
            // reading a file with no name if the link had failed.
            if !replaces.is_empty() {
                if let Err(e) = std::fs::remove_file(&stale) {
                    log::warn!("fc.update_drive({vm_id}): remove {}: {e}", stale.display());
                }
            }
            Reply::Ok
        }
    }
}

/// `fc.snapshot_export`: move point `generation` out of the chroot and
/// hand it to `k7d`.
#[must_use]
pub fn snapshot_export(vm_id: &str, generation: u32) -> Reply {
    let uid = match super::lookup_uid(super::VM_BROKER_USER) {
        Ok(u) => u,
        Err(e) => return Reply::failed(0, e),
    };
    let gid = match super::lookup_gid(super::VM_BROKER_USER) {
        Ok(g) => g,
        Err(e) => return Reply::failed(0, e),
    };
    let plan = jails(|j| {
        j.get(vm_id).map(|jail| {
            (
                jail.chroot.jail_snap_dir(),
                jail.chroot.snap_dir(),
                jail.writable
                    .iter()
                    .map(|(name, _)| (jail.chroot.disk_path(name), name.clone()))
                    .collect::<Vec<_>>(),
            )
        })
    });
    let Some((jail_snap, own_snap, disks)) = plan else {
        return unknown_jail(vm_id);
    };
    for name in [
        format!("vmstate-{generation}"),
        format!("diff-{generation}.mem"),
    ] {
        let src = jail_snap.join(&name);
        if !src.exists() {
            // Whether a missing Diff is an error is the VM broker's
            // question — an empty one is a legitimate "nothing changed".
            continue;
        }
        let dst = own_snap.join(&name);
        if let Err(e) = std::fs::rename(&src, &dst) {
            return io_failed(
                &format!("fc.snapshot_export({vm_id}): move {name} out of the jail"),
                &e,
            );
        }
        if let Err(e) = stage::chown_gid(&dst, uid, gid) {
            return staging_failed(&format!("fc.snapshot_export({vm_id}) {name}"), &e);
        }
    }
    // The writable disks are hard links whose inodes the jail uid owns,
    // so the VM broker cannot `FICLONE` them itself. Cloned here, at the
    // same pause as the memory, and handed over.
    for (src, name) in disks {
        let dst = own_snap.join(format!("disk-{generation}-{name}"));
        let _ = std::fs::remove_file(&dst);
        if let Err(e) = crate::fc::snapshot::reflink(&src, &dst, 0o600) {
            return staging_failed(&format!("fc.snapshot_export({vm_id}) disk-{name}"), &e);
        }
        if let Err(e) = stage::chown_gid(&dst, uid, gid) {
            return staging_failed(&format!("fc.snapshot_export({vm_id}) disk-{name}"), &e);
        }
    }
    Reply::Ok
}

/// `fc.kill`: kill the jailed Firecracker, remove its cgroup, remove the
/// chroot and release the uid.
///
/// Idempotent: `FcVm::stop`, `Drop for FcVm` and `vm.release` all reach
/// it, and a jail this node broker never had is the end state anyway.
#[must_use]
pub fn kill(vm_id: &str) -> Reply {
    let Some(jail) = jails(|j| j.remove(vm_id)) else {
        return Reply::Ok;
    };
    crate::fc::kill_and_wait(jail.pid);
    crate::fc::remove_cgroup(&jail.cgroup_dir);
    // The chroot's hard links go before the uid returns to the
    // allocator, which is what the field order in `Jail` buys.
    drop(jail);
    Reply::Ok
}

/// Whether a jail for `vm_id` is held **and** its Firecracker is still
/// running. What the node broker's survival test asks before it keeps a
/// VM back for a successor (`K7D_VM_BROKER_RESTART`): a registered VM whose spawn was
/// in flight when the VM broker died has no jail, and one whose
/// Firecracker died with it has nothing to re-adopt.
#[must_use]
pub fn is_live(vm_id: &str) -> bool {
    let pid = jails(|j| j.get(vm_id).map(|jail| jail.pid));
    let Some(pid) = pid else {
        return false;
    };
    // The jailed process is this process's child and stays unreaped
    // until `kill_and_wait`, so the pid cannot have been reused — but a
    // dead child is a zombie that still has a `/proc` entry, so the
    // state field (the token after the last `)` of the comm) is what
    // says whether anything is running.
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| {
            let after = stat.rsplit(')').next()?;
            let state = after.split_whitespace().next()?;
            Some(state != "Z" && state != "X")
        })
        .unwrap_or(false)
}

/// The jail uid of `vm_id`, when a jail is held for it.
#[must_use]
pub fn uid_of(vm_id: &str) -> Option<u32> {
    jails(|j| j.get(vm_id).map(|jail| jail.uid.uid()))
}

/// How many jails are held.
#[must_use]
pub fn count() -> usize {
    jails(|j| j.len())
}

/// The record `fc.list` publishes for one jail, minus the `sandbox_id`
/// only the VM table knows.
fn record_of(vm_id: &str, jail: &Jail) -> super::FcJailRecord {
    let drive = |(name, path): &(String, PathBuf), read_only: bool| super::FcJailDrive {
        name: name.clone(),
        host_path: path.display().to_string(),
        read_only,
    };
    super::FcJailRecord {
        vm_id: vm_id.to_string(),
        sandbox_id: None,
        pid: jail.pid,
        uid: jail.uid.uid(),
        tap: jail.tap,
        vm_dir: jail.chroot.vm_dir().display().to_string(),
        memory_mb: jail.memory_mb,
        vcpus: jail.vcpus,
        cpu: jail.cpu,
        kernel: jail.kernel.display().to_string(),
        initrd: jail.initrd.as_ref().map(|p| p.display().to_string()),
        drives: jail
            .read_only
            .iter()
            .map(|d| drive(d, true))
            .chain(jail.writable.iter().map(|d| drive(d, false)))
            .collect(),
        restored_from: jail.restored_from,
    }
}

/// One page of `fc.list` (§9.3): the held jails in `vm_id` order, with
/// each record's pidfd and `<vm_dir>` descriptor — the same pair
/// `fc.spawn` hands back, re-opened for the successor. A jail whose
/// descriptors cannot be opened is reported as a failure of the whole
/// page rather than silently left out: a jail the successor does not
/// hear about is one nothing will ever kill.
#[must_use]
pub fn list(page: u32) -> (Reply, Vec<OwnedFd>) {
    let mut ids: Vec<String> = jails(|j| j.keys().cloned().collect());
    ids.sort();
    let start = usize::try_from(page)
        .unwrap_or(usize::MAX)
        .saturating_mul(super::FC_LIST_PAGE);
    let more = ids.len() > start.saturating_add(super::FC_LIST_PAGE);
    let mut records = Vec::new();
    let mut fds = Vec::new();
    for vm_id in ids.iter().skip(start).take(super::FC_LIST_PAGE) {
        let found = jails(|j| {
            j.get(vm_id)
                .map(|jail| (record_of(vm_id, jail), jail.chroot.vm_dir().to_path_buf()))
        });
        let Some((record, vm_dir)) = found else {
            // Killed between the key snapshot and now; the next page
            // will not have it either.
            continue;
        };
        let pidfd = match crate::seqmsg::pidfd_open(record.pid) {
            Ok(fd) => fd,
            Err(e) => {
                return (
                    io_failed(
                        &format!("fc.list: pidfd_open on firecracker {}", record.pid),
                        &e,
                    ),
                    Vec::new(),
                )
            }
        };
        let dir = match open_path_dir(&vm_dir) {
            Ok(fd) => fd,
            Err(e) => {
                return (
                    io_failed(&format!("fc.list: O_PATH {}", vm_dir.display()), &e),
                    Vec::new(),
                )
            }
        };
        records.push(record);
        fds.push(pidfd);
        fds.push(dir);
    }
    (Reply::FcList { records, more }, fds)
}

/// A pinned block, as a path this module can hand to `link(2)`.
///
/// Through `Pinned::path()` and not the descriptor, because `link(2)`
/// needs a name. The name was resolved with `RESOLVE_NO_SYMLINKS`
/// against an allowlisted root at registration, and the `(dev, ino)`
/// recorded then is re-checked here with `lstat` — so a name whose file
/// was swapped, or replaced by a symlink, is refused rather than linked
/// and `chown`ed.
pub fn pinned_path(pinned: &Pinned, what: &str) -> Result<PathBuf, Reply> {
    use std::os::unix::fs::MetadataExt;
    let path = pinned.path().to_path_buf();
    let meta = std::fs::symlink_metadata(&path)
        .map_err(|e| io_failed(&format!("{what}: stat {}", path.display()), &e))?;
    if (meta.dev(), meta.ino()) != pinned.ids() {
        return Err(Reply::failed(
            libc::ESTALE,
            format!(
                "{what}: {} is no longer the object registered for it",
                path.display()
            ),
        ));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A jail file name decides where a `link` and a `chown` land, so it
    /// is validated like the path it is.
    #[test]
    fn a_jail_file_name_must_be_one_plain_component() {
        for bad in ["", ".", "..", "a/b", "../../etc/shadow", "a\0b"] {
            assert!(
                component("image name", bad).is_err(),
                "{bad:?} must be refused"
            );
        }
        for good in ["d0", "scratch.img", "d3-fill2"] {
            assert!(component("image name", good).is_ok(), "{good:?}");
        }
    }

    /// `fc.*` on an id with no jail is `ENOENT` naming the verb that was
    /// missing — never a panic and never a silent success.
    #[test]
    fn verbs_on_an_unknown_jail_are_enoent() {
        let (reply, fds) = connect("no-such-vm", FcSocket::Api);
        assert!(fds.is_empty());
        let Reply::Failed { errno, message } = reply else {
            panic!("must be refused");
        };
        assert_eq!(errno, libc::ENOENT, "{message}");
        assert!(message.contains("fc.spawn must come first"), "{message}");
        assert!(matches!(
            snapshot_export("no-such-vm", 1),
            Reply::Failed { errno, .. } if errno == libc::ENOENT
        ));
        assert!(matches!(
            update_drive("no-such-vm", Path::new("/dev/null"), "d0-fill1", ""),
            Reply::Failed { errno, .. } if errno == libc::ENOENT
        ));
        // …except the release path, which is idempotent by contract.
        assert_eq!(kill("no-such-vm"), Reply::Ok);
        let (reply, fds) = list(0);
        let Reply::FcList { records, more } = reply else {
            panic!("fc.list: {reply:?}");
        };
        assert!(records.iter().all(|r| r.vm_id != "no-such-vm"));
        assert!(!more);
        assert!(fds.is_empty());
    }

    /// A spawn that names no kernel is refused before a uid is leased:
    /// the allocator is a fixed range, and a leak there costs a VM slot.
    #[test]
    fn a_spawn_without_a_kernel_leaks_no_uid() {
        let before = stage::live_uid_count();
        let (reply, fds) = spawn_jail(
            &SpawnRequest {
                vm_id: "vm-no-kernel",
                vcpus: 1,
                memory_mb: 128,
                cpu: None,
                tap: false,
                images: &[ImageRef::ReadOnly {
                    device_idx: 0,
                    name: "d0".into(),
                }],
                restore_from: None,
            },
            &|_| Ok(PathBuf::from("/dev/null")),
        );
        assert!(fds.is_empty());
        let Reply::Failed { errno, message } = reply else {
            panic!("must be refused");
        };
        assert_eq!(errno, libc::EINVAL, "{message}");
        assert!(message.contains("named no kernel"), "{message}");
        assert_eq!(stage::live_uid_count(), before);
    }
}
