//! Integration tests for internal notes: erofs container rootfs on
//! virtio-blk — the zero-virtiofs pod. Requires KVM, /dev/vhost-vsock,
//! built guest kernel (CONFIG_EROFS_FS, CONFIG_OVERLAY_FS,
//! CONFIG_VIRTIO_BLK), built initramfs, busybox and mkfs.erofs
//! (erofs-utils) on the host, and guest/rootfs/runc.amd64.

use std::path::{Path, PathBuf};
use std::time::Duration;

use k7d::erofs::{build_erofs_image, cached_erofs_image};
use k7d::vm::Vm;

fn workspace_path(relative: &str) -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join(relative)
}

/// Marker content baked into every test rootfs.
const MARKER: &str = "erofs-rootfs-marker";

/// Build a minimal busybox container rootfs at `dir`: /bin/busybox +
/// applet symlinks, the runtime dirs runc needs, and an /etc/marker.
fn make_busybox_rootfs(dir: &Path) {
    for d in &["bin", "proc", "dev", "tmp", "etc"] {
        std::fs::create_dir_all(dir.join(d)).unwrap();
    }
    let busybox = Path::new("/bin/busybox");
    assert!(
        busybox.exists(),
        "busybox required on the host at /bin/busybox"
    );
    std::fs::copy(busybox, dir.join("bin/busybox")).unwrap();
    #[cfg(unix)]
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

/// Build a VM whose only extra device is the erofs image mounted RO by
/// the agent at /run/k7d/rootfs — zero virtiofs shares.
fn build_vm_with_erofs_rootfs(img: &Path, memory_mb: u64) -> Vm {
    Vm::builder()
        .kernel_and_initrd()
        .memory_mb(memory_mb)
        .vsock(true)
        .block_device_mounted(img, true, "/run/k7d/rootfs", "erofs")
        .build()
        .expect("VM with erofs rootfs should build")
}

/// Push the static runc binary into the guest's tmpfs — the whole
/// point of Inc 2 is that no virtiofs share exists to carry it.
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

/// Write an OCI bundle config into the guest at `/run/k7d/bundle`
/// whose root.path is the agent-mounted erofs rootfs. The agent
/// detects the read-only erofs lower and assembles the overlay.
fn push_bundle(agent: &mut k7d::api::AgentClient, args: &[&str]) {
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
        "mounts": [
            { "destination": "/proc", "type": "proc", "source": "proc" },
            {
                "destination": "/dev",
                "type": "tmpfs",
                "source": "tmpfs",
                "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]
            },
            {
                "destination": "/tmp",
                "type": "tmpfs",
                "source": "tmpfs",
                "options": ["nosuid", "nodev"]
            }
        ]
    });
    agent
        .write_file(
            "/run/k7d/bundle/config.json",
            serde_json::to_string_pretty(&config).unwrap().as_bytes(),
        )
        .expect("push bundle config.json");
}

fn inode_mtime(path: &Path) -> (u64, std::time::SystemTime) {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).unwrap();
    (meta.ino(), meta.modified().unwrap())
}

#[test]
fn test_erofs_image_build_and_cache() {
    let _ = env_logger::builder().is_test(true).try_init();

    let src = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(src.path().join("etc")).unwrap();
    std::fs::write(src.path().join("etc/marker"), "one").unwrap();
    let cache = tempfile::tempdir().unwrap();

    // First build populates the cache; second call must hit it (same
    // path, same inode, same mtime — nothing rebuilt).
    let img1 = cached_erofs_image(cache.path(), src.path(), None).unwrap();
    assert!(img1.exists());
    let meta1 = inode_mtime(&img1);
    assert_eq!(
        std::fs::metadata(&img1).unwrap().len() % 512,
        0,
        "image must be a multiple of the virtio-blk sector size"
    );
    let img2 = cached_erofs_image(cache.path(), src.path(), None).unwrap();
    assert_eq!(img1, img2, "identical content must hit the cache");
    assert_eq!(meta1, inode_mtime(&img2), "cache hit must not rebuild");

    // Different content ⇒ different key ⇒ different image.
    std::fs::write(src.path().join("etc/marker"), "two").unwrap();
    let img3 = cached_erofs_image(cache.path(), src.path(), None).unwrap();
    assert_ne!(img1, img3, "changed content must produce a new image");
    assert!(img1.exists() && img3.exists());

    // Digest-keyed identity wins over content: same digest ⇒ same
    // cached image even after the source changes (the containerd
    // path — the digest IS the identity).
    let img_d1 = cached_erofs_image(cache.path(), src.path(), Some("sha256:cafe01")).unwrap();
    let meta_d1 = inode_mtime(&img_d1);
    assert!(
        img_d1.to_string_lossy().contains("sha256-cafe01"),
        "digest keys the cache file: {img_d1:?}"
    );
    std::fs::write(src.path().join("etc/marker"), "three").unwrap();
    let img_d2 = cached_erofs_image(cache.path(), src.path(), Some("sha256:cafe01")).unwrap();
    assert_eq!(img_d1, img_d2);
    assert_eq!(meta_d1, inode_mtime(&img_d2), "digest hit must not rebuild");
}

#[test]
fn test_guest_mounts_erofs_rootfs() {
    let _ = env_logger::builder().is_test(true).try_init();

    let src = tempfile::tempdir().unwrap();
    make_busybox_rootfs(src.path());
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("rootfs.erofs");
    build_erofs_image(src.path(), &img).unwrap();

    let mut vm = build_vm_with_erofs_rootfs(&img, 256);
    vm.start().unwrap();
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect to agent");

    // The agent mounted the device per k7d.blk= before it started
    // listening, so the files are visible immediately.
    let marker = guest_sh(&mut agent, "cat /run/k7d/rootfs/etc/marker");
    assert_eq!(marker.trim(), MARKER);
    let mounts = guest_sh(&mut agent, "grep /run/k7d/rootfs /proc/mounts");
    assert!(
        mounts.contains("erofs") && mounts.contains("ro"),
        "expected a read-only erofs mount, got: {mounts}"
    );

    // Read-only is enforced end to end.
    let w = agent
        .exec(&["sh", "-c", "echo x > /run/k7d/rootfs/new.txt"])
        .unwrap();
    assert_ne!(w.exit_code, 0, "write to the erofs mount must fail");

    vm.shutdown();
}

#[test]
fn test_container_runs_on_erofs_overlay() {
    let _ = env_logger::builder().is_test(true).try_init();

    let src = tempfile::tempdir().unwrap();
    make_busybox_rootfs(src.path());
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("rootfs.erofs");
    build_erofs_image(src.path(), &img).unwrap();
    let bytes_before = std::fs::read(&img).unwrap();

    let mut vm = build_vm_with_erofs_rootfs(&img, 512);
    vm.start().unwrap();
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("should connect to agent");

    push_runc(&mut agent);
    push_bundle(&mut agent, &["sleep", "infinity"]);

    agent
        .container_start("web", "/run/k7d/bundle")
        .expect("container on erofs overlay should start");

    // The container sees the erofs content through the overlay…
    let marker = agent
        .container_exec("web", &["cat", "/etc/marker"])
        .expect("exec in container");
    assert_eq!(marker.exit_code, 0, "stderr: {}", marker.stderr);
    assert_eq!(marker.stdout.trim(), MARKER);

    // …and writes land in the tmpfs upper, not the erofs lower.
    let w = agent
        .container_exec(
            "web",
            &[
                "sh",
                "-c",
                "echo overlay-write > /wrote.txt && cat /wrote.txt",
            ],
        )
        .expect("write inside container");
    assert_eq!(w.exit_code, 0, "stderr: {}", w.stderr);
    assert_eq!(w.stdout.trim(), "overlay-write");
    guest_sh(
        &mut agent,
        "cat /run/k7/containers/web/overlay/upper/wrote.txt",
    );
    let lower = agent
        .exec(&["sh", "-c", "test -e /run/k7d/rootfs/wrote.txt"])
        .unwrap();
    assert_ne!(lower.exit_code, 0, "write must not reach the erofs lower");

    agent.container_stop("web").expect("stop container");
    vm.shutdown();

    // The RO image is byte-identical after the whole container run.
    let bytes_after = std::fs::read(&img).unwrap();
    assert!(
        bytes_before == bytes_after,
        "erofs image was modified by the container run"
    );
}

#[test]
fn test_zero_virtiofs_pod_warm_fork() {
    let _ = env_logger::builder().is_test(true).try_init();

    let src = tempfile::tempdir().unwrap();
    make_busybox_rootfs(src.path());
    let dir = tempfile::tempdir().unwrap();
    let img = dir.path().join("rootfs.erofs");
    build_erofs_image(src.path(), &img).unwrap();

    // Zero virtiofs shares: rootfs is erofs on virtio-blk, runc and the
    // bundle live in guest tmpfs (pushed over vsock).
    let mut source = build_vm_with_erofs_rootfs(&img, 512);
    source.start().unwrap();
    let mut agent = source
        .connect_agent(Duration::from_secs(90))
        .expect("initial agent connect");
    push_runc(&mut agent);
    push_bundle(&mut agent, &["sleep", "infinity"]);
    drop(agent);

    source
        .prepare_fork_source()
        .expect("prepare_fork_source with erofs rootfs and no virtiofs");
    let mut agent = source
        .connect_agent(Duration::from_secs(30))
        .expect("reconnect after prepare_fork_source");

    let mut forked = source.fork_warm("zero-virtiofs-fork").expect("warm fork");

    // The Inc 2 payoff: with no virtiofs share the fork must stay on
    // the CoW (MAP_PRIVATE base.mem + dirty delta) path, not full-memfd.
    assert!(
        !forked.fork_memory_is_full_copy(),
        "zero-virtiofs pod took the full-memfd fork path"
    );

    forked.start().unwrap();
    let mut fork_agent = forked
        .connect_agent(Duration::from_secs(30))
        .expect("forked VM should be reachable");

    // Both the source and the fork run the container workload on their
    // (shared, RO) erofs rootfs.
    for (label, a) in [("source", &mut agent), ("fork", &mut fork_agent)] {
        a.container_start("c1", "/run/k7d/bundle")
            .unwrap_or_else(|e| panic!("{label}: container start: {e}"));
        let out = a
            .container_exec("c1", &["cat", "/etc/marker"])
            .unwrap_or_else(|e| panic!("{label}: container exec: {e}"));
        assert_eq!(out.exit_code, 0, "{label} stderr: {}", out.stderr);
        assert_eq!(out.stdout.trim(), MARKER, "{label} marker mismatch");
        a.container_stop("c1")
            .unwrap_or_else(|e| panic!("{label}: container stop: {e}"));
    }

    forked.shutdown();
    source.shutdown();
}
