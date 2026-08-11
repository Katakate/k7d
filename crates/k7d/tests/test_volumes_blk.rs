//! Integration tests for internal notes: kubelet volumes off virtiofs.
//!
//! - RO volumes (configmap/secret/downwardAPI/projected) packed into a
//!   cached erofs image on virtio-blk, readable in the container at
//!   the kubelet-declared destination, writes rejected.
//! - emptyDir on guest tmpfs: shared between containers, survives a
//!   warm fork on the CoW path.
//! - Writable raw ext4 images on the reflink-capable loopback XFS at
//!   /var/lib/k7d/disks: guest writes persist, `fork_warm` reflinks
//!   them (never a byte copy), forks stay CoW and independent.
//! - Forkability validation: `prepare_fork_source` on a virtiofs-
//!   backed VM fails loudly unless the caller explicitly opts into
//!   slow (full-memfd) forks.
//!
//! Requires KVM, /dev/vhost-vsock, virtiofsd, built guest kernel
//! (CONFIG_EROFS_FS, CONFIG_EXT4_FS, CONFIG_OVERLAY_FS,
//! CONFIG_VIRTIO_BLK), built initramfs, busybox, mkfs.erofs,
//! mkfs.xfs, mkfs.ext4, root (loop mounts), and
//! guest/rootfs/runc.amd64.

use std::path::{Path, PathBuf};
use std::time::Duration;

use k7d::disks;
use k7d::erofs::build_erofs_image;
use k7d::vm::Vm;
use k7d::volumes_blk::{BlockVolumes, GUEST_EMPTYDIR_BASE, VM_VOLUMES_RO_MOUNT};

fn workspace_path(relative: &str) -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join(relative)
}

/// Marker content baked into every test rootfs.
const MARKER: &str = "volblk-rootfs-marker";

/// Build a minimal busybox container rootfs at `dir` (same shape as
/// the Inc 2 tests: /bin/busybox + applet symlinks + runtime dirs).
fn make_busybox_rootfs(dir: &Path) {
    for d in &[
        "bin", "proc", "dev", "tmp", "etc", "etc/app", "scratch", "data",
    ] {
        std::fs::create_dir_all(dir.join(d)).unwrap();
    }
    let busybox = Path::new("/bin/busybox");
    assert!(
        busybox.exists(),
        "busybox required on the host at /bin/busybox"
    );
    std::fs::copy(busybox, dir.join("bin/busybox")).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            dir.join("bin/busybox"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
    for cmd in &["sh", "echo", "cat", "ls", "sleep", "touch"] {
        std::os::unix::fs::symlink("busybox", dir.join("bin").join(cmd)).unwrap();
    }
    std::fs::write(dir.join("etc/marker"), MARKER).unwrap();
}

/// Run a shell command in the guest, asserting success.
fn guest_sh(agent: &mut k7d::api::AgentClient, cmd: &str) -> String {
    let out = agent.exec(&["sh", "-c", cmd]).unwrap();
    assert_eq!(
        out.exit_code, 0,
        "guest command `{cmd}` failed: stdout={} stderr={}",
        out.stdout, out.stderr
    );
    out.stdout
}

/// Push the static runc binary into the guest's tmpfs.
fn push_runc(agent: &mut k7d::api::AgentClient) {
    let runc_src = workspace_path("guest/rootfs/runc.amd64");
    assert!(
        runc_src.exists(),
        "runc.amd64 not found at {runc_src:?} — download it: \
         curl -fsSL https://github.com/opencontainers/runc/releases/download/v1.2.5/runc.amd64 \
         -o guest/rootfs/runc.amd64 && chmod +x guest/rootfs/runc.amd64"
    );
    let bytes = std::fs::read(&runc_src).unwrap();
    agent
        .write_file("/usr/local/bin/runc", &bytes)
        .expect("push runc into guest tmpfs");
    guest_sh(agent, "chmod 755 /usr/local/bin/runc");
}

/// Write an OCI bundle at `bundle_dir` in the guest whose root.path
/// is the agent-mounted erofs rootfs, with `extra_mounts` appended
/// (kubelet-style bind mounts rewritten to in-VM sources).
fn push_bundle(
    agent: &mut k7d::api::AgentClient,
    bundle_dir: &str,
    args: &[&str],
    extra_mounts: &[serde_json::Value],
) {
    let mut mounts = vec![
        serde_json::json!({ "destination": "/proc", "type": "proc", "source": "proc" }),
        serde_json::json!({
            "destination": "/dev",
            "type": "tmpfs",
            "source": "tmpfs",
            "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]
        }),
    ];
    mounts.extend_from_slice(extra_mounts);
    let config = serde_json::json!({
        "ociVersion": "1.0.2",
        "process": {
            "terminal": false,
            "user": { "uid": 0, "gid": 0 },
            "args": args,
            "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            "cwd": "/"
        },
        "root": { "path": "/run/k7d/rootfs", "readonly": false },
        "linux": {
            "namespaces": [
                { "type": "pid" },
                { "type": "mount" },
                { "type": "ipc" },
                { "type": "uts" }
            ]
        },
        "mounts": mounts
    });
    agent
        .write_file(
            &format!("{bundle_dir}/config.json"),
            serde_json::to_string_pretty(&config).unwrap().as_bytes(),
        )
        .expect("push bundle config.json");
}

/// Build a kubelet-shaped volumes tree: one configmap (with kubelet's
/// atomic `..data` symlink layout), one secret, one emptyDir.
fn make_kubelet_volumes(root: &Path) -> PathBuf {
    let volumes = root.join("volumes");
    let cm = volumes.join("kubernetes.io~configmap/app-config");
    std::fs::create_dir_all(&cm).unwrap();
    let ts = cm.join("..2026_08_07_00_00_00.0001");
    std::fs::create_dir_all(&ts).unwrap();
    std::fs::write(ts.join("greeting"), "hello-from-configmap").unwrap();
    std::os::unix::fs::symlink("..2026_08_07_00_00_00.0001", cm.join("..data")).unwrap();
    std::os::unix::fs::symlink("..data/greeting", cm.join("greeting")).unwrap();

    let secret = volumes.join("kubernetes.io~secret/creds");
    std::fs::create_dir_all(&secret).unwrap();
    std::fs::write(secret.join("api-key"), "sk-volblk-test").unwrap();

    std::fs::create_dir_all(volumes.join("kubernetes.io~empty-dir/scratch")).unwrap();
    volumes
}

/// Spec checklist item 1: the RO volume tree is packed to erofs,
/// mounted in the guest, its contents readable in the container at
/// the kubelet-declared destination, and writes are rejected.
#[test]
fn test_ro_volumes_erofs_in_container() {
    let _ = env_logger::builder().is_test(true).try_init();

    let pod = tempfile::tempdir().unwrap();
    let volumes = make_kubelet_volumes(pod.path());
    let cache = tempfile::tempdir().unwrap();
    let bv = BlockVolumes::prepare_from_kubelet_dir(&volumes, cache.path())
        .expect("BlockVolumes::prepare");
    let ro_img = bv.ro_image.clone().expect("RO volumes must pack");

    // Container rootfs as erofs on vda (Inc 2), volumes image on vdb.
    let src = tempfile::tempdir().unwrap();
    make_busybox_rootfs(src.path());
    let dir = tempfile::tempdir().unwrap();
    let rootfs_img = dir.path().join("rootfs.erofs");
    build_erofs_image(src.path(), &rootfs_img).unwrap();

    let builder = Vm::builder()
        .kernel_and_initrd()
        .memory_mb(512)
        .vsock(true)
        .block_device_mounted(&rootfs_img, true, "/run/k7d/rootfs", "erofs");
    let mut vm = bv
        .apply_to_builder(builder)
        .build()
        .expect("VM with rootfs + RO volumes images should build");
    vm.start().unwrap();
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect to agent");

    // The agent mounted the volumes image per k7d.blk=.
    let mounts = guest_sh(
        &mut agent,
        &format!("grep {VM_VOLUMES_RO_MOUNT} /proc/mounts"),
    );
    assert!(
        mounts.contains("erofs") && mounts.contains("ro"),
        "expected a read-only erofs volumes mount, got: {mounts}"
    );

    // The kubelet OCI mount would carry the host source path — the
    // rewrite map translates it to the in-VM path for the bundle.
    let cm_host = volumes.join("kubernetes.io~configmap/app-config");
    let cm_in_vm = bv
        .rewrites
        .translate(&cm_host)
        .expect("configmap must be in the rewrite map");
    let secret_in_vm = bv
        .rewrites
        .translate(&volumes.join("kubernetes.io~secret/creds"))
        .expect("secret must be in the rewrite map");

    push_runc(&mut agent);
    push_bundle(
        &mut agent,
        "/run/k7d/bundle",
        &["sleep", "infinity"],
        &[
            serde_json::json!({
                "destination": "/etc/app",
                "type": "bind",
                "source": cm_in_vm.to_string_lossy(),
                "options": ["rbind", "ro"]
            }),
            serde_json::json!({
                "destination": "/etc/creds",
                "type": "bind",
                "source": secret_in_vm.to_string_lossy(),
                "options": ["rbind", "ro"]
            }),
        ],
    );
    agent
        .container_start("web", "/run/k7d/bundle")
        .expect("container with RO volume binds should start");

    // Contents visible at the kubelet-declared destinations. The
    // configmap is read through kubelet's `..data` symlink chain,
    // which the packed image preserved.
    let greeting = agent
        .container_exec("web", &["cat", "/etc/app/greeting"])
        .expect("exec in container");
    assert_eq!(greeting.exit_code, 0, "stderr: {}", greeting.stderr);
    assert_eq!(greeting.stdout.trim(), "hello-from-configmap");
    let key = agent
        .container_exec("web", &["cat", "/etc/creds/api-key"])
        .expect("exec in container");
    assert_eq!(key.stdout.trim(), "sk-volblk-test");

    // Writes are rejected — in the container and at the guest level.
    let w = agent
        .container_exec("web", &["sh", "-c", "echo x > /etc/app/new"])
        .expect("exec in container");
    assert_ne!(w.exit_code, 0, "write into the RO volume must fail");
    let w2 = agent
        .exec(&[
            "sh",
            "-c",
            &format!("echo x > {VM_VOLUMES_RO_MOUNT}/configmap-app-config/new"),
        ])
        .unwrap();
    assert_ne!(
        w2.exit_code, 0,
        "guest-level write to the erofs mount must fail"
    );

    agent.container_stop("web").expect("stop container");
    vm.shutdown();

    // The packed image is content-addressed and untouched.
    assert!(ro_img.exists());
}

/// Spec checklist item 2: emptyDir on guest tmpfs — two containers in
/// one VM share it, contents survive a warm fork, and the fork stays
/// on the CoW path (zero virtiofs shares anywhere).
#[test]
fn test_emptydir_tmpfs_shared_and_survives_fork() {
    let _ = env_logger::builder().is_test(true).try_init();

    let pod = tempfile::tempdir().unwrap();
    let volumes = make_kubelet_volumes(pod.path());
    let cache = tempfile::tempdir().unwrap();
    let bv = BlockVolumes::prepare_from_kubelet_dir(&volumes, cache.path())
        .expect("BlockVolumes::prepare");
    let emptydir_host = volumes.join("kubernetes.io~empty-dir/scratch");
    let emptydir_in_vm = bv
        .rewrites
        .translate(&emptydir_host)
        .expect("emptyDir must be in the rewrite map");
    assert!(
        emptydir_in_vm.starts_with(GUEST_EMPTYDIR_BASE),
        "emptyDir must rewrite to guest tmpfs, got {emptydir_in_vm:?}"
    );

    let src = tempfile::tempdir().unwrap();
    make_busybox_rootfs(src.path());
    let dir = tempfile::tempdir().unwrap();
    let rootfs_img = dir.path().join("rootfs.erofs");
    build_erofs_image(src.path(), &rootfs_img).unwrap();

    let builder = Vm::builder()
        .kernel_and_initrd()
        .memory_mb(512)
        .vsock(true)
        .block_device_mounted(&rootfs_img, true, "/run/k7d/rootfs", "erofs");
    let mut source = bv
        .apply_to_builder(builder)
        .build()
        .expect("VM should build");
    source.start().unwrap();
    let mut agent = source
        .connect_agent(Duration::from_secs(90))
        .expect("initial agent connect");

    // The agent created the emptyDir tmpfs dir at boot (k7d.mkdir=).
    guest_sh(&mut agent, &format!("test -d {}", emptydir_in_vm.display()));

    // Two containers in the same VM bind the same emptyDir.
    push_runc(&mut agent);
    let bind = serde_json::json!({
        "destination": "/scratch",
        "type": "bind",
        "source": emptydir_in_vm.to_string_lossy(),
        "options": ["rbind", "rw"]
    });
    push_bundle(
        &mut agent,
        "/run/k7d/bundle1",
        &["sleep", "infinity"],
        &[bind.clone()],
    );
    push_bundle(
        &mut agent,
        "/run/k7d/bundle2",
        &["sleep", "infinity"],
        &[bind],
    );
    agent
        .container_start("c1", "/run/k7d/bundle1")
        .expect("c1 start");
    agent
        .container_start("c2", "/run/k7d/bundle2")
        .expect("c2 start");

    let w = agent
        .container_exec("c1", &["sh", "-c", "echo shared-scratch > /scratch/msg"])
        .expect("c1 write");
    assert_eq!(w.exit_code, 0, "stderr: {}", w.stderr);
    let r = agent
        .container_exec("c2", &["cat", "/scratch/msg"])
        .expect("c2 read");
    assert_eq!(r.exit_code, 0, "stderr: {}", r.stderr);
    assert_eq!(
        r.stdout.trim(),
        "shared-scratch",
        "both containers must see the same emptyDir"
    );
    drop(agent);

    source
        .prepare_fork_source()
        .expect("prepare_fork_source with zero virtiofs shares");
    let mut agent = source
        .connect_agent(Duration::from_secs(30))
        .expect("reconnect after prepare_fork_source");

    let mut forked = source.fork_warm("emptydir-fork").expect("warm fork");
    assert!(
        !forked.fork_memory_is_full_copy(),
        "emptyDir-on-tmpfs pod took the full-memfd fork path"
    );
    forked.start().unwrap();
    let mut fork_agent = forked
        .connect_agent(Duration::from_secs(30))
        .expect("forked VM should be reachable");

    // Contents survived the fork through the memory CoW…
    let msg = guest_sh(
        &mut fork_agent,
        &format!("cat {}/msg", emptydir_in_vm.display()),
    );
    assert_eq!(msg.trim(), "shared-scratch");

    // …and the copies are independent.
    guest_sh(
        &mut fork_agent,
        &format!("echo fork-only > {}/fork.txt", emptydir_in_vm.display()),
    );
    let src_check = agent
        .exec(&[
            "sh",
            "-c",
            &format!("cat {}/fork.txt", emptydir_in_vm.display()),
        ])
        .unwrap();
    assert_ne!(
        src_check.exit_code, 0,
        "source must not see the fork's emptyDir write"
    );

    forked.shutdown();
    source.shutdown();
}

/// Spec checklist item 3: a writable raw ext4 image on the loopback
/// XFS — guest writes persist, `fork_warm` reflinks it (never a byte
/// copy: `reflink_file` has no fallback), both VMs see independent
/// copies, and the fork stays on the CoW memory path.
#[test]
fn test_writable_image_on_loopback_xfs_reflink_fork() {
    let _ = env_logger::builder().is_test(true).try_init();

    // Self-provision the loopback XFS exactly as a node reset would
    // (your node provisioning) — idempotent, fail-loud.
    disks::ensure_loopback_xfs(
        Path::new(disks::DISKS_IMAGE),
        Path::new(disks::DISKS_DIR),
        disks::DISKS_IMAGE_SIZE,
    )
    .expect("loopback XFS at /var/lib/k7d/disks");

    let vol = disks::create_ext4_volume(
        Path::new(disks::DISKS_DIR),
        &format!("volblk-test-{}.img", std::process::id()),
        64 * 1024 * 1024,
    )
    .expect("create ext4 volume image on the disks XFS");

    let mut source = Vm::builder()
        .kernel_and_initrd()
        .memory_mb(256)
        .vsock(true)
        .block_device_mounted(&vol, false, "/mnt/data", "ext4")
        .build()
        .expect("VM with writable volume image should build");
    source.start().unwrap();
    let mut agent = source
        .connect_agent(Duration::from_secs(90))
        .expect("initial agent connect");

    // Guest writes land on the image.
    guest_sh(
        &mut agent,
        "echo persisted > /mnt/data/file.txt && sync && cat /mnt/data/file.txt",
    );
    drop(agent);

    source
        .prepare_fork_source()
        .expect("prepare_fork_source with RW volume image");
    let mut agent = source
        .connect_agent(Duration::from_secs(30))
        .expect("reconnect after prepare_fork_source");

    let t = std::time::Instant::now();
    let mut forked = source.fork_warm("xfs-reflink-fork").expect(
        "warm fork must reflink the RW image on the disks XFS \
         (FICLONE has no byte-copy fallback)",
    );
    let fork_elapsed = t.elapsed();
    eprintln!("warm fork with RW volume image: {fork_elapsed:?}");
    assert!(
        !forked.fork_memory_is_full_copy(),
        "RW-image pod took the full-memfd fork path"
    );

    forked.start().unwrap();
    let mut fork_agent = forked
        .connect_agent(Duration::from_secs(30))
        .expect("forked VM should be reachable");

    // Fork sees the pre-fork write through its reflinked copy…
    let seen = guest_sh(&mut fork_agent, "cat /mnt/data/file.txt");
    assert_eq!(seen.trim(), "persisted");

    // …and the copies are independent in both directions.
    guest_sh(
        &mut fork_agent,
        "echo fork-write > /mnt/data/fork.txt && sync",
    );
    guest_sh(
        &mut agent,
        "echo source-write > /mnt/data/source.txt && sync",
    );
    let f = fork_agent
        .exec(&["sh", "-c", "cat /mnt/data/source.txt"])
        .unwrap();
    assert_ne!(
        f.exit_code, 0,
        "fork must not see the source's post-fork write"
    );
    let s = agent.exec(&["sh", "-c", "cat /mnt/data/fork.txt"]).unwrap();
    assert_ne!(s.exit_code, 0, "source must not see the fork's write");

    // The reflinked clone lives next to the source image on the same
    // XFS (FICLONE requires same-filesystem, internal notes).
    let clones: Vec<_> = std::fs::read_dir(disks::DISKS_DIR)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(".k7d-blk-fork-")
        })
        .collect();
    assert!(
        !clones.is_empty(),
        "expected a reflinked fork image dir under {}",
        disks::DISKS_DIR
    );

    forked.shutdown();
    source.shutdown();
    drop(forked);
    let _ = std::fs::remove_file(&vol);
}

/// Spec checklist item 4: `prepare_fork_source` on a VM with a
/// virtiofs share follows the explicit policy — loud error by
/// default, full-memfd forks only after the caller's explicit
/// slow-fork opt-in. No silent degradation.
#[test]
fn test_prepare_fork_source_virtiofs_policy() {
    let _ = env_logger::builder().is_test(true).try_init();

    let state_dir = tempfile::tempdir().unwrap();
    let mut vm = Vm::builder()
        .kernel_and_initrd()
        .memory_mb(256)
        .vsock(true)
        .virtiofs(state_dir.path(), "/mnt/state")
        .build()
        .expect("VM with virtiofs share should build");
    vm.start().unwrap();
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect to agent");

    // Default policy: loud refusal naming the escape hatch.
    let msg = match vm.prepare_fork_source() {
        Ok(_) => panic!("prepare_fork_source on a virtiofs VM must fail without opt-in"),
        Err(e) => format!("{e}"),
    };
    assert!(
        msg.contains("virtiofs") && msg.contains("allow_slow_fork"),
        "error must name the cause and the explicit opt-in, got: {msg}"
    );

    // The refusal must leave the VM fully usable.
    let alive = agent.exec(&["echo", "still-alive"]).unwrap();
    assert_eq!(alive.stdout.trim(), "still-alive");

    // Explicit opt-in: prepare succeeds and forks take the full-memfd
    // path. prepare_fork_source replaces the vsock device, so the old
    // agent connection is gone — reconnect.
    drop(agent);
    vm.allow_slow_fork();
    vm.prepare_fork_source()
        .expect("prepare_fork_source after explicit slow-fork opt-in");
    let mut agent = vm
        .connect_agent(Duration::from_secs(30))
        .expect("reconnect after prepare_fork_source");
    let alive = agent.exec(&["echo", "prepared"]).unwrap();
    assert_eq!(alive.stdout.trim(), "prepared");

    let mut forked = vm.fork_warm("virtiofs-slow-fork").expect("slow fork");
    assert!(
        forked.fork_memory_is_full_copy(),
        "virtiofs-backed fork must be a full memfd copy"
    );
    forked.start().unwrap();
    let mut fork_agent = forked
        .connect_agent(Duration::from_secs(30))
        .expect("forked VM should be reachable");
    fork_agent.ping().unwrap();

    forked.shutdown();
    vm.shutdown();
}
