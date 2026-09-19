#![no_main]
//! Fuzz the control socket's request decoder (`control::Request`).
//!
//! `/run/k7d/k7d.sock` is the VM broker's only listening socket and the
//! shim is its only intended peer, but "intended" is not a boundary: the
//! socket is `0750` in a directory the pod's containerd can reach, and
//! the JSON on it carries paths, ids and sizes that a container image
//! chose. `handle_connection` decodes one line per request, so a decode
//! that panics is a VM broker that dies with every VM on it.
//!
//! What this asserts is narrow on purpose — no panic, and a decoded
//! request survives a round trip so the shim and the daemon cannot
//! disagree about a field one of them dropped. What it *covers* is the
//! `serde` surface of a large enum: absent fields, wrong types, deeply
//! nested values, duplicate keys, numbers that do not fit, and the
//! variant names an attacker can reach without a shim.
//!
//! Under `setpriv` as uid `k7d` (`make fuzz`) this also holds the §10.4
//! precondition: even a request that decodes cannot mount, cannot make a
//! TAP and cannot create in `/sys/fs/cgroup/k7d`.

use k7d::control::Request;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // One line per request, as `handle_connection` reads them.
    for line in text.lines() {
        let Ok(request) = serde_json::from_str::<Request>(line) else {
            continue;
        };
        let encoded = serde_json::to_string(&request).expect("a decoded request must re-encode");
        let back: Request =
            serde_json::from_str(&encoded).expect("a re-encoded request must decode");
        assert_eq!(
            serde_json::to_string(&back).expect("stable encoding"),
            encoded,
            "request {line:?} is not stable across a round trip"
        );
    }
});
