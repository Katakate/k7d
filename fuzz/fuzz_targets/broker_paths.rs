#![no_main]
//! Fuzz the node broker's path validator (`broker::paths`, spec §5).
//!
//! This is the one verb that takes a path from the shim, so it is the
//! one place where a string a container image chose reaches `openat2`
//! in a root process. Two properties matter and neither is expressible
//! as a unit test over hand-picked inputs:
//!
//! * **Total.** No input panics, and none is rejected by unwrapping —
//!   the validator's job is to answer, and an abort in a root process
//!   that holds every VM's descriptors is worse than an accept.
//! * **Sound.** Anything it *accepts* lies under one of the allowlisted
//!   roots for its class, and the path it reports is the one it pinned.
//!   The fuzzer is what covers the spellings a human does not think of:
//!   `//`, `/./`, embedded NULs, non-UTF-8 bytes, a root's name as a
//!   prefix of a sibling (`/var/lib/k7d-evil`), overlong components.
//!
//! Run under `setpriv` as uid `k7d` (`make fuzz`), so an accept that
//! should not have happened cannot open anything either — the §10.4
//! precondition.

use k7d::broker::paths::{self, Class, Root};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let class = match data[0] % 3 {
        0 => Class::ShareDir,
        1 => Class::BlockFile,
        _ => Class::Netns,
    };
    let writable = data[0] & 0x80 != 0;
    // Lossy on purpose: the wire format is JSON, so a path that reaches
    // `vm.register` is already a Rust `String`, and what the fuzzer is
    // for is the *shape* of that string rather than its encoding.
    let path = String::from_utf8_lossy(&data[1..]).into_owned();

    let Ok(pinned) = paths::validate(class, &path, writable) else {
        return;
    };

    // Accepted. The reported path must be absolute, canonical, and under
    // a root for this class — the invariant every later verb relies on
    // when it trusts an index instead of re-checking a name.
    let reported = pinned.path();
    assert!(reported.is_absolute(), "accepted a relative path {path:?}");
    for component in reported.components().skip(1) {
        let name = component.as_os_str();
        assert!(
            name != "." && name != ".." && !name.is_empty(),
            "accepted a non-canonical path {path:?}"
        );
    }
    let under_a_root = paths::roots(class).iter().any(|root| match root {
        Root::Exact(dir) => reported.starts_with(dir),
        Root::Prefixed { parent, prefix } => reported
            .strip_prefix(parent)
            .ok()
            .and_then(|rest| rest.components().next())
            .is_some_and(|first| first.as_os_str().to_string_lossy().starts_with(prefix)),
    });
    let proc_netns = class == Class::Netns && reported.starts_with("/proc");
    assert!(
        under_a_root || proc_netns,
        "accepted {reported:?} (from {path:?}) outside every root for {class:?}"
    );
    // The pin is an open descriptor, so `(dev, ino)` is readable and
    // non-zero: a `Pinned` that fstat'd nothing would make every later
    // identity check vacuous.
    let (dev, ino) = pinned.ids();
    assert!(ino != 0, "pinned {reported:?} with ino 0 (dev {dev})");
});
