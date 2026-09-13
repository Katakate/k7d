//! Assert daemon `TreeFork` / `TreeForkBatch` `latency_ns`.
//!
//! Cluster-tree budgets are the daemon's own clock, not the client
//! `Instant` around the Unix-socket call. Suite-tail queueing can make
//! the client RTT exceed the budget while daemon work stays well under
//! (CHALLENGES #156: 1.99 s client vs 114 ms daemon). Do not widen a
//! `latency.rs` constant to absorb that gap.

use std::time::Duration;

/// Assert `latency_ns` against `budget`. Always print both clocks.
/// Client RTT over budget while the daemon stays under is a FINDING,
/// not a failure.
pub fn assert_tree_fork_budget(
    profile: &str,
    client_rtt: Duration,
    latency_ns: u64,
    budget: Duration,
) {
    assert!(
        latency_ns > 0,
        "{profile}: TreeFork reply omitted latency_ns (got 0)"
    );
    let daemon = Duration::from_nanos(latency_ns);
    eprintln!(
        "  {profile} TreeFork client_rtt={client_rtt:?} daemon={daemon:?} \
         budget={budget:?}"
    );
    if client_rtt > budget && daemon <= budget {
        eprintln!(
            "  FINDING (CHALLENGES #156): {profile} client Instant \
             {client_rtt:?} exceeded {budget:?} while daemon latency_ns \
             stayed {daemon:?}; asserting daemon, not client RTT"
        );
    }
    assert!(
        daemon <= budget,
        "{profile} TreeFork latency_ns={daemon:?} > budget {budget:?}; \
         do not widen the latency.rs constant"
    );
}
