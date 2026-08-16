//! Integration tests for: a container's writable layer is a
//! host-backed virtio-blk scratch disk, not a guest tmpfs.
//!
//! What these assert: writable space is no longer
//! RAM-bound, filling it yields a clean ENOSPC instead of wedging the
//! guest, the bytes do not land in guest RAM, a warm fork gets a
//! reflink-CoW copy that is invisible to its parent and siblings, and
//! teardown removes the host image.
//!
//! Requires KVM, /dev/vhost-vsock, the built guest kernel (EXT4_FS,
//! EROFS_FS, OVERLAY_FS, VIRTIO_BLK) and initramfs, busybox +
//! mkfs.erofs + mkfs.ext4 + mkfs.xfs on the host, and
//! guest/rootfs/runc.amd64.

use std::path::{Path, PathBuf};
use std::time::Duration;

use k7d::disks::{self, ScratchDisk};
use k7d::erofs::build_erofs_image;
use k7d::vm::Vm;

/// Guest RAM for the scratch VMs. Small on purpose: the headline claim
/// of is that a container can write far more than this.
const GUEST_MEMORY_MB: u64 = 512;

/// Marker baked into every test rootfs.
const MARKER: &str = "scratch-rootfs-marker";

fn workspace_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join(relative)
}

/// Minimal busybox container rootfs (same shape as `test_erofs.rs`).
fn make_busybox_rootfs(dir: &Path) {
    for d in &["bin", "proc", "dev", "tmp", "etc"] {
        std::fs::create_dir_all(dir.join(d)).unwrap();
    }
    let busybox = Path::new("/bin/busybox");
    assert!(busybox.exists(), "busybox required at /bin/busybox");
    std::fs::copy(busybox, dir.join("bin/busybox")).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            dir.join("bin/busybox"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
    for cmd in &[
        "sh", "echo", "cat", "ls", "sleep", "dd", "md5sum", "df", "sync", "rm", "true",
    ] {
        std::os::unix::fs::symlink("busybox", dir.join("bin").join(cmd)).unwrap();
    }
    std::fs::write(dir.join("etc/marker"), MARKER).unwrap();
}

fn guest_sh(agent: &mut k7d::api::AgentClient, cmd: &str) -> String {
    let out = agent.exec(&["sh", "-c", cmd]).unwrap();
    assert_eq!(
        out.exit_code, 0,
        "guest command `{cmd}` failed: stdout={} stderr={}",
        out.stdout, out.stderr
    );
    out.stdout
}

fn push_runc(agent: &mut k7d::api::AgentClient) {
    let runc_src = workspace_path("guest/rootfs/runc.amd64");
    assert!(runc_src.exists(), "runc.amd64 not found at {runc_src:?}");
    let bytes = std::fs::read(&runc_src).unwrap();
    agent
        .write_file("/usr/local/bin/runc", &bytes)
        .expect("push runc into guest tmpfs");
    guest_sh(agent, "chmod 755 /usr/local/bin/runc");
}

/// OCI bundle whose `root.path` is the agent-mounted erofs rootfs; the
/// agent assembles the overlay (upper on the scratch disk).
fn push_bundle(agent: &mut k7d::api::AgentClient) {
    let config = serde_json::json!({
        "ociVersion": "1.0.2",
        "process": {
            "terminal": false,
            "user": { "uid": 0, "gid": 0 },
            "args": ["sleep", "infinity"],
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

/// Provision a scratch image for this test process. The returned handle
/// removes the image on drop; the VM it is attached to takes it over.
fn make_scratch(tag: &str, size_bytes: u64) -> ScratchDisk {
    ScratchDisk::create(&format!("test-{tag}-{}", std::process::id()), size_bytes)
        .expect("provision scratch image on the reflink loopback XFS")
}

/// Build the erofs image for a busybox rootfs, keeping the temp dir
/// alive for the caller.
fn build_rootfs_image(dir: &Path) -> PathBuf {
    let src = tempfile::tempdir().unwrap();
    make_busybox_rootfs(src.path());
    let img = dir.join("rootfs.erofs");
    build_erofs_image(src.path(), &img).unwrap();
    img
}

/// Bytes actually allocated on the host for `path` (sparse images
/// report far less than their apparent length).
fn allocated_bytes(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).unwrap().blocks() * 512
}

/// A field of the guest's `/proc/meminfo`, in KiB.
fn guest_meminfo_kb(agent: &mut k7d::api::AgentClient, field: &str) -> u64 {
    let raw = guest_sh(agent, &format!("grep '^{field}:' /proc/meminfo"));
    raw.split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| panic!("cannot parse {field} out of {raw:?}"))
}

/// Boot a VM with an erofs container rootfs plus a scratch disk, and
/// return it with a container named `c1` already running.
fn boot_vm_with_scratch(img: &Path, scratch: ScratchDisk) -> (Vm, k7d::api::AgentClient) {
    let mut vm = Vm::builder()
        .kernel_and_initrd()
        .memory_mb(GUEST_MEMORY_MB)
        .vsock(true)
        .block_device_mounted(img, true, "/run/k7d/rootfs", "erofs")
        .scratch_disk(scratch)
        .build()
        .expect("VM with erofs rootfs + scratch disk should build");
    vm.start().unwrap();
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("agent connect");
    push_runc(&mut agent);
    push_bundle(&mut agent);
    agent
        .container_start("c1", "/run/k7d/bundle")
        .expect("container should start with its upper on the scratch disk");
    (vm, agent)
}

/// Checklist items 1 and 3, in one boot: a container writes
/// **more than guest RAM** to its own filesystem and reads it back
/// intact, the bytes land on the host image, and guest `MemAvailable`
/// stays essentially flat while it happens.
#[test]
fn test_container_writes_exceed_guest_ram_and_stay_off_it() {
    let _ = env_logger::builder().is_test(true).try_init();

    let dir = tempfile::tempdir().unwrap();
    let img = build_rootfs_image(dir.path());
    let scratch = make_scratch("bigwrite", 4 * 1024 * 1024 * 1024);
    let scratch_path = scratch.path().to_path_buf();
    let (mut vm, mut agent) = boot_vm_with_scratch(&img, scratch);

    // The container's writable layer really is the host image, not a
    // guest tmpfs — that is the whole point.
    let upper_fs = guest_sh(&mut agent, "grep ' /run/k7d/scratch ' /proc/mounts");
    assert!(
        upper_fs.contains("ext4"),
        "expected the scratch disk mounted as ext4, got: {upper_fs}"
    );

    let mem_before = guest_meminfo_kb(&mut agent, "MemAvailable");
    let allocated_before = allocated_bytes(&scratch_path);

    // 1 GiB is twice this guest's RAM; the old unsized tmpfs upper
    // would have been capped at 50% of it (256 MiB) and wedged the
    // guest long before here.
    let write_mib: u32 = 1024;
    assert!(
        u64::from(write_mib) > GUEST_MEMORY_MB,
        "the test must write more than guest RAM to mean anything"
    );
    let out = agent
        .container_exec(
            "c1",
            &[
                "sh",
                "-c",
                &format!(
                    "dd if=/dev/urandom of=/big bs=1M count={write_mib} conv=fsync 2>/dev/null && \
                     md5sum /big | cut -d' ' -f1"
                ),
            ],
        )
        .expect("exec the big write");
    assert_eq!(
        out.exit_code, 0,
        "writing {write_mib} MiB into the container filesystem failed: stdout={} stderr={}",
        out.stdout, out.stderr
    );
    let digest_hot = out.stdout.trim().to_string();
    assert_eq!(digest_hot.len(), 32, "expected an md5 digest, got {out:?}");

    // Read it back from the DEVICE, not the page cache: dropping the
    // guest's caches forces every byte to come off the host image, so a
    // matching digest proves the data is really there and intact.
    guest_sh(&mut agent, "sync && echo 3 > /proc/sys/vm/drop_caches");
    let out = agent
        .container_exec("c1", &["sh", "-c", "md5sum /big | cut -d' ' -f1"])
        .expect("re-read the file after dropping guest caches");
    assert_eq!(out.exit_code, 0, "stderr: {}", out.stderr);
    assert_eq!(
        digest_hot,
        out.stdout.trim(),
        "{write_mib} MiB read back off the scratch device does not match what was written"
    );

    // The bytes are on the host image…
    let allocated_after = allocated_bytes(&scratch_path);
    let grew_mib = (allocated_after - allocated_before) / (1024 * 1024);
    assert!(
        grew_mib >= u64::from(write_mib) * 9 / 10,
        "host scratch image grew by only {grew_mib} MiB for a {write_mib} MiB write \
         (before={allocated_before} after={allocated_after})"
    );

    // …and not in guest RAM. The remaining page cache is clean and
    // reclaimable, so MemAvailable barely moves; a tmpfs upper would
    // have taken the full write out of it.
    let mem_after = guest_meminfo_kb(&mut agent, "MemAvailable");
    let dropped_mib = mem_before.saturating_sub(mem_after) / 1024;
    assert!(
        dropped_mib < 128,
        "guest MemAvailable fell {dropped_mib} MiB while writing {write_mib} MiB \
         (before={mem_before} kB after={mem_after} kB) — the writes are landing in RAM"
    );

    agent.container_stop("c1").expect("stop container");
    vm.shutdown();
}

/// Checklist item 2: filling the scratch disk gives the writing
/// process a clean ENOSPC, and the guest keeps running — no wedge, no
/// OOM kill.
#[test]
fn test_scratch_full_yields_enospc_and_guest_survives() {
    let _ = env_logger::builder().is_test(true).try_init();

    let dir = tempfile::tempdir().unwrap();
    let img = build_rootfs_image(dir.path());
    // Deliberately much smaller than guest RAM: if ENOSPC came from
    // memory pressure rather than the device, this test could not tell
    // the difference.
    let scratch = make_scratch("enospc", 64 * 1024 * 1024);
    let (mut vm, mut agent) = boot_vm_with_scratch(&img, scratch);

    let out = agent
        .container_exec(
            "c1",
            &[
                "sh",
                "-c",
                "dd if=/dev/zero of=/fill bs=1M count=512 conv=fsync 2>&1",
            ],
        )
        .expect("the exec itself must succeed — only the write fails");
    assert_ne!(
        out.exit_code, 0,
        "writing 512 MiB into a 64 MiB scratch disk must fail"
    );
    let complaint = format!("{}{}", out.stdout, out.stderr).to_ascii_lowercase();
    assert!(
        complaint.contains("no space left"),
        "expected a clean ENOSPC, got: {complaint}"
    );

    // The guest is still healthy: the container answers, its init was
    // not OOM-killed, and the filesystem reports itself full rather
    // than the guest having died trying.
    let alive = agent
        .container_exec("c1", &["sh", "-c", "rm -f /fill && echo still-here"])
        .expect("container must still be reachable after ENOSPC");
    assert_eq!(alive.exit_code, 0, "stderr: {}", alive.stderr);
    assert_eq!(alive.stdout.trim(), "still-here");
    assert_eq!(
        agent
            .container_wait_poll("c1")
            .expect("poll container exit"),
        None,
        "the container init must still be running (an OOM kill would have reaped it)"
    );

    agent.container_stop("c1").expect("stop container");
    vm.shutdown();
}

/// Checklist item 4: a warm fork inherits its parent's
/// writable layer as a reflink-`CoW` copy of the scratch image — it
/// sees everything written before the fork, and nothing written after
/// it by the parent or by a sibling fork.
#[test]
fn test_warm_fork_scratch_is_cow_and_isolated() {
    let _ = env_logger::builder().is_test(true).try_init();

    let dir = tempfile::tempdir().unwrap();
    let img = build_rootfs_image(dir.path());
    let scratch = make_scratch("fork", 256 * 1024 * 1024);
    let source_image = scratch.path().to_path_buf();

    let mut source = Vm::builder()
        .kernel_and_initrd()
        .memory_mb(GUEST_MEMORY_MB)
        .vsock(true)
        .block_device_mounted(&img, true, "/run/k7d/rootfs", "erofs")
        .scratch_disk(scratch)
        .build()
        .expect("source VM with scratch disk");
    source.start().unwrap();
    let mut agent = source
        .connect_agent(Duration::from_secs(90))
        .expect("initial agent connect");

    // Pre-fork content every fork must inherit.
    guest_sh(
        &mut agent,
        "echo before-fork > /run/k7d/scratch/shared.txt && sync",
    );
    drop(agent);

    source
        .prepare_fork_source()
        .expect("prepare_fork_source with a scratch disk attached");
    let mut agent = source
        .connect_agent(Duration::from_secs(30))
        .expect("reconnect after prepare_fork_source");

    // The scratch image survived the snapshot/restore swap: the
    // restored VM took over the handle instead of the discarded husk
    // unlinking it out from under the live guest.
    assert!(
        source_image.exists(),
        "prepare_fork_source must not remove the source's scratch image at {}",
        source_image.display()
    );

    let mut forks = source
        .fork_warm_batch(&["scratch-fork-a", "scratch-fork-b"])
        .expect("warm fork must reflink the scratch image, never byte-copy it");
    let mut fork_b = forks.pop().unwrap();
    let mut fork_a = forks.pop().unwrap();
    for (label, fork) in [("a", &fork_a), ("b", &fork_b)] {
        assert!(
            !fork.fork_memory_is_full_copy(),
            "fork {label} left the CoW memory path"
        );
        let images: Vec<&Path> = fork
            .block_devices()
            .iter()
            .map(|b| b.host_path.as_path())
            .collect();
        assert!(
            !images.contains(&source_image.as_path()),
            "fork {label} shares the parent's writable image {} — \
             a fork must never write through to its parent's scratch",
            source_image.display()
        );
    }

    fork_a.start().unwrap();
    fork_b.start().unwrap();
    let mut agent_a = fork_a
        .connect_agent(Duration::from_secs(30))
        .expect("fork a agent");
    let mut agent_b = fork_b
        .connect_agent(Duration::from_secs(30))
        .expect("fork b agent");

    // Inherited: both forks see the pre-fork write through their own
    // reflinked copy (the documented behaviour — CoW, not empty).
    for (label, a) in [("a", &mut agent_a), ("b", &mut agent_b)] {
        let seen = guest_sh(a, "cat /run/k7d/scratch/shared.txt");
        assert_eq!(
            seen.trim(),
            "before-fork",
            "fork {label} did not inherit the parent's writable layer"
        );
    }

    // Isolated: three post-fork writes, no crosstalk in any direction.
    guest_sh(&mut agent, "echo p > /run/k7d/scratch/parent.txt && sync");
    guest_sh(&mut agent_a, "echo a > /run/k7d/scratch/a.txt && sync");
    guest_sh(&mut agent_b, "echo b > /run/k7d/scratch/b.txt && sync");
    for (label, a, invisible) in [
        ("parent", &mut agent, ["a.txt", "b.txt"]),
        ("fork a", &mut agent_a, ["parent.txt", "b.txt"]),
        ("fork b", &mut agent_b, ["parent.txt", "a.txt"]),
    ] {
        for other in invisible {
            let probe = a
                .exec(&["sh", "-c", &format!("test -e /run/k7d/scratch/{other}")])
                .unwrap();
            assert_ne!(
                probe.exit_code, 0,
                "{label} can see /run/k7d/scratch/{other} — writable layers are not isolated"
            );
        }
    }

    fork_a.shutdown();
    fork_b.shutdown();
    source.shutdown();
}

/// Checklist item 5: the host image is scratch — it goes away
/// with the VM that owns it, and no earlier step leaks it.
#[test]
fn test_scratch_image_removed_with_the_vm() {
    let _ = env_logger::builder().is_test(true).try_init();

    let dir = tempfile::tempdir().unwrap();
    let img = build_rootfs_image(dir.path());
    let scratch = make_scratch("teardown", 32 * 1024 * 1024);
    let scratch_path = scratch.path().to_path_buf();
    assert!(scratch_path.exists(), "provisioning must create the image");

    {
        let (mut vm, mut agent) = boot_vm_with_scratch(&img, scratch);
        assert!(
            scratch_path.exists(),
            "the image must live as long as the VM using it"
        );
        assert_eq!(
            vm.scratch_disk_path(),
            Some(scratch_path.as_path()),
            "the VM must own the scratch handle"
        );
        agent.container_stop("c1").expect("stop container");
        vm.shutdown();
    }

    assert!(
        !scratch_path.exists(),
        "dropping the VM must remove its scratch image at {} (leak)",
        scratch_path.display()
    );
}

/// The fail-loud rule: when the host declared a scratch device
/// that did not mount, the agent refuses to start the container rather
/// than quietly giving it a RAM-backed writable layer.
///
/// The unformatted image below is how that happens in practice — a
/// promised device whose filesystem is unusable.
#[test]
fn test_promised_but_missing_scratch_fails_loud() {
    let _ = env_logger::builder().is_test(true).try_init();

    let dir = tempfile::tempdir().unwrap();
    let img = build_rootfs_image(dir.path());

    // Right size, right cmdline promise, no filesystem: the guest's
    // boot-time `mount -t ext4` fails and nothing is mounted at the
    // scratch mount point.
    let unformatted = dir.path().join("not-a-filesystem.img");
    let f = std::fs::File::create(&unformatted).unwrap();
    f.set_len(32 * 1024 * 1024).unwrap();
    drop(f);

    let mut vm = Vm::builder()
        .kernel_and_initrd()
        .memory_mb(GUEST_MEMORY_MB)
        .vsock(true)
        .block_device_mounted(&img, true, "/run/k7d/rootfs", "erofs")
        .block_device_mounted(&unformatted, false, disks::SCRATCH_GUEST_MOUNT, "ext4")
        .build()
        .expect("VM should build — the image is only unusable inside the guest");
    vm.start().unwrap();
    let mut agent = vm
        .connect_agent(Duration::from_secs(90))
        .expect("agent connect");
    push_runc(&mut agent);
    push_bundle(&mut agent);

    let err = agent
        .container_start("c1", "/run/k7d/bundle")
        .expect_err("a promised-but-missing scratch disk must fail the container start");
    let err = err.to_string();
    assert!(
        err.contains(disks::SCRATCH_GUEST_MOUNT) && err.contains("not mounted"),
        "the error must name the missing scratch mount, got: {err}"
    );
    assert!(
        !agent
            .container_list()
            .unwrap()
            .containers
            .contains(&"c1".to_string()),
        "no container may be running after the refusal"
    );

    vm.shutdown();
}
