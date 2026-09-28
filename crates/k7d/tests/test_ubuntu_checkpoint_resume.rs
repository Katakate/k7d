//! A tree root is its own nearest checkpoint. After the keyframe it
//! keeps running, and suspend writes that later dirt to `delta.pack`
//! without refreshing `memory.bin`. Resume must apply the pack onto
//! the root's own keyframe. Skipping it (because `base_node == node`)
//! brings the later `vm_state.json` back on keyframe-time RAM.
//!
//! The marker lives on `/dev/shm` (tmpfs), so a surviving root disk
//! cannot hide a dropped guest page.

mod common;

use std::io::Read;
use std::path::Path;
use std::time::Duration;

use k7d::cluster_tree::{ClusterPayload, ClusterSnapshotTree};
use k7d::guest::Guest;
use k7d::network::ClusterNetwork;
use k7d::tree_model::{NodeState, TreeBudget};
use k7d::vm::Vm;

use common::ubuntu::{node_image, sh_ok, VmDisk, BOOT_TO_AGENT_CEILING};

/// Unique to this test. It is not in the Ubuntu image and is written
/// only after `new_cluster` has published the keyframe.
const MARKER: &str = "k7d-ckpt-resume-marker-7e2b94";

#[test]
fn test_ubuntu_root_resume_keeps_post_keyframe_marker() {
    let _ = env_logger::builder().is_test(true).try_init();
    let _ = k7d::network::cleanup_stale_k7_bridges();

    let image = node_image();
    let disk = VmDisk::clone_of(&image.base_image(), "ckpt-resume");
    let mut net = ClusterNetwork::create("ckpt").expect("bridge");
    let tap = net.add_tap().expect("tap");

    let mut vm = common::ubuntu::build_node_vm(&image, &disk, tap);
    vm.start().expect("Ubuntu node should start");
    let mut agent = connect_vm(&mut vm, "boot");
    // The keyframe is taken at `new_cluster`, after this boot. The
    // marker must not exist yet, or a resume that ignores the pack
    // could still find it in `memory.bin`.
    let (code, _, _) = common::ubuntu::sh(
        &mut agent,
        "test ! -e /dev/shm/k7d-marker && findmnt -no FSTYPE /dev/shm",
    );
    assert_eq!(
        code, 0,
        "/dev/shm must be a tmpfs and start without the marker"
    );
    drop(agent);

    let dir = tempfile::tempdir().expect("tree dir");
    let (mut tree, root) = ClusterSnapshotTree::new_cluster(
        ClusterPayload {
            network: net,
            members: vec![Guest::from(vm)],
        },
        dir.path().to_path_buf(),
        TreeBudget {
            max_live_vms: 4,
            max_live_ram_bytes: 8 * 1024 * 1024 * 1024,
            max_disk_bytes: 16 * 1024 * 1024 * 1024,
            max_chain_depth: 1,
        },
    )
    .expect("adopt the booted node as a tree root");
    assert!(
        tree.get_node(&root).unwrap().has_base_snapshot,
        "the root is the checkpoint this test resumes"
    );

    // Prepare replaced the vsock backend. Write the marker only now.
    let mut agent = connect_tree(&mut tree, &root, "after keyframe");
    let fstype = sh_ok(
        &mut agent,
        &format!(
            "findmnt -no FSTYPE /dev/shm && printf '%s' '{MARKER}' > /dev/shm/k7d-marker && cat /dev/shm/k7d-marker"
        ),
    );
    assert!(
        fstype.starts_with("tmpfs\n"),
        "/dev/shm is not tmpfs, so the marker would live on the root disk: {fstype}"
    );
    assert_eq!(
        fstype.trim_start_matches("tmpfs\n").trim(),
        MARKER,
        "guest did not store the marker before suspend"
    );
    drop(agent);

    let needle = MARKER.as_bytes();
    assert!(
        ram_contains(&mut tree, &root, needle),
        "the marker never landed in guest RAM"
    );
    let keyframe = dir
        .path()
        .join("nodes")
        .join(&root)
        .join("members")
        .join("0")
        .join("memory.bin");
    assert!(
        !file_contains(&keyframe, needle),
        "the keyframe already contains the marker, so resume could \
         pass without applying the root's own delta"
    );

    tree.suspend(&root).expect("suspend root");
    let info = tree.get_node(&root).unwrap();
    assert_eq!(info.state, NodeState::Suspended);
    assert!(
        info.dirty_page_count > 0,
        "suspend wrote an empty pack, so this resume would not observe the marker"
    );
    let pack = dir
        .path()
        .join("nodes")
        .join(&root)
        .join("members")
        .join("0")
        .join("delta.pack");
    assert!(
        pack.is_file(),
        "root suspend must write members/0/delta.pack"
    );

    tree.resume(&root).expect("resume root");
    assert!(
        ram_contains(&mut tree, &root, needle),
        "resume of the tree root dropped guest RAM written after the \
         keyframe (its own delta.pack was not applied onto memory.bin)"
    );
    let mut agent = connect_tree(&mut tree, &root, "after resume");
    assert_eq!(
        sh_ok(&mut agent, "cat /dev/shm/k7d-marker").trim(),
        MARKER,
        "the resumed guest cannot read the post-keyframe marker"
    );
    drop(agent);

    // The guest does not rewrite the marker. A second cycle keeps it
    // only when resume re-seeds the dirty bitmap from the pack.
    tree.suspend(&root).expect("second suspend");
    tree.resume(&root).expect("second resume");
    assert!(
        ram_contains(&mut tree, &root, needle),
        "the marker survived one resume but not a second suspend/resume"
    );
    let mut agent = connect_tree(&mut tree, &root, "after second resume");
    assert_eq!(sh_ok(&mut agent, "cat /dev/shm/k7d-marker").trim(), MARKER);

    tree.prune(&root).expect("prune");
}

fn connect_vm(vm: &mut Vm, whose: &str) -> k7d::api::AgentClient {
    match vm.connect_agent(BOOT_TO_AGENT_CEILING) {
        Ok(agent) => agent,
        Err(e) => panic!(
            "{whose}: no agent within {BOOT_TO_AGENT_CEILING:?}: {e}\n--- serial ---\n{}",
            vm.serial_output(Duration::from_secs(1))
        ),
    }
}

fn connect_tree(
    tree: &mut ClusterSnapshotTree,
    node: &String,
    whose: &str,
) -> k7d::api::AgentClient {
    let member = &tree
        .get_payload(node)
        .unwrap_or_else(|| panic!("{whose}: {node} is not live"))
        .members[0];
    match member.connect_agent(Duration::from_secs(90)) {
        Ok(agent) => agent,
        Err(e) => {
            let serial = member
                .as_native()
                .map(|vm| vm.serial_output(Duration::from_secs(1)))
                .unwrap_or_default();
            panic!("{whose}: no agent: {e}\n--- serial ---\n{serial}");
        }
    }
}

/// Pause, scan the live guest mapping, and let the guest run again.
fn ram_contains(tree: &mut ClusterSnapshotTree, node: &String, needle: &[u8]) -> bool {
    let member = &mut tree
        .get_payload_mut(node)
        .unwrap_or_else(|| panic!("{node} is not live"))
        .members[0];
    member.pause().expect("pause to scan guest RAM");
    let found = {
        let vm = member.as_native().expect("native member");
        let span = vm.mem_span() as usize;
        let addr = vm.mem_host_addr() as *const u8;
        // SAFETY: the VM is paused, so this mapping of `mem_span` bytes
        // stays put for the scan. `mem_host_addr` is that mapping's base.
        let bytes = unsafe { std::slice::from_raw_parts(addr, span) };
        bytes_contain(bytes, needle)
    };
    member.resume().expect("resume guest after RAM scan");
    found
}

fn file_contains(path: &Path, needle: &[u8]) -> bool {
    let mut file =
        std::fs::File::open(path).unwrap_or_else(|e| panic!("open {}: {e}", path.display()));
    let mut carry = Vec::new();
    let mut buf = vec![0u8; 8 * 1024 * 1024];
    loop {
        let n = file.read(&mut buf).unwrap_or_else(|e| panic!("read: {e}"));
        if n == 0 {
            return false;
        }
        let mut joined = Vec::with_capacity(carry.len() + n);
        joined.extend_from_slice(&carry);
        joined.extend_from_slice(&buf[..n]);
        if bytes_contain(&joined, needle) {
            return true;
        }
        let keep = needle.len().saturating_sub(1);
        if joined.len() > keep {
            carry = joined[joined.len() - keep..].to_vec();
        } else {
            carry = joined;
        }
    }
}

fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    // SAFETY: both pointers address `haystack.len()` / `needle.len()`
    // readable bytes. `memmem` does not write.
    let hit = unsafe {
        libc::memmem(
            haystack.as_ptr().cast(),
            haystack.len(),
            needle.as_ptr().cast(),
            needle.len(),
        )
    };
    !hit.is_null()
}
