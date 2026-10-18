//! Per-vCPU CPU percent from `/proc/<tid>/task/<tid>/stat` tick counters.
//!
//! `KVM_GET_MP_STATE` only answers while the VM is paused, so a 50 ms
//! UI poll cannot use it. vCPU kernel TIDs are already published;
//! utime+stime across those threads, divided by the tick rate, the
//! elapsed wall time, and the vCPU count, is the percent of the VM's
//! own CPUs that were busy. The first sample has no baseline and
//! returns nothing.

use std::fs;
use std::sync::OnceLock;
use std::time::Duration;

/// Clock ticks of user + system time for one kernel thread.
///
/// `None` when the task stat is missing or not shaped like a `stat`
/// line. The comm field is skipped via the last `)`, so a name that
/// contains spaces or parentheses still parses.
///
/// `/proc/<tid>/stat` is the thread-group aggregate (`ps` reads it
/// that way). Summing it once per vCPU multiplies a busy daemon by
/// its thread count, the percent goes past 100, and the UI clamps
/// every node to 100%. `/proc/<tid>/task/<tid>/stat` is that one thread.
#[must_use]
pub fn task_cpu_ticks(tid: u32) -> Option<u64> {
    let text = fs::read_to_string(format!("/proc/{tid}/task/{tid}/stat")).ok()?;
    parse_stat_ticks(&text)
}

/// utime+stime from one `/proc/<tid>/stat` line.
///
/// After the last `)`, utime is the 12th field (index 11) and stime
/// is the next one. See `proc_pid_stat(5)`.
#[must_use]
pub fn parse_stat_ticks(text: &str) -> Option<u64> {
    let rest = text.rsplit_once(')')?.1;
    let mut fields = rest.split_whitespace();
    let utime: u64 = fields.nth(11)?.parse().ok()?;
    let stime: u64 = fields.next()?.parse().ok()?;
    Some(utime.saturating_add(stime))
}

/// Percent of `ncpus` busy between two tick samples.
///
/// `None` when the interval, the vCPU count, or the tick rate is
/// zero. Values above 100 (a thread migrated, or a coarse tick) are
/// clamped so the UI never draws a bar past full.
#[must_use]
pub fn cpu_percent(
    prev_ticks: u64,
    now_ticks: u64,
    elapsed: Duration,
    ncpus: u32,
    hz: u64,
) -> Option<f64> {
    if ncpus == 0 || hz == 0 {
        return None;
    }
    let secs = elapsed.as_secs_f64();
    if secs <= 0.0 {
        return None;
    }
    let delta = now_ticks.saturating_sub(prev_ticks);
    let delta = f64::from(u32::try_from(delta).unwrap_or(u32::MAX));
    let hz = u32::try_from(hz).unwrap_or(u32::MAX);
    let pct = delta / (f64::from(hz) * secs * f64::from(ncpus)) * 100.0;
    Some(pct.clamp(0.0, 100.0))
}

/// `sysconf(_SC_CLK_TCK)`, cached. 100 when the call fails.
#[must_use]
pub fn clk_tck() -> u64 {
    static HZ: OnceLock<u64> = OnceLock::new();
    *HZ.get_or_init(|| {
        // SAFETY: `sysconf(_SC_CLK_TCK)` reads a kernel constant. It
        // takes no pointer and cannot unwind into this process.
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if hz > 0 {
            u64::try_from(hz).unwrap_or(100)
        } else {
            100
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_line_with_spaces_in_comm_sums_utime_and_stime() {
        let line = "12 (k7d worker) R 1 1 1 0 -1 0 0 0 0 0 10 5 0 0";
        assert_eq!(parse_stat_ticks(line), Some(15));
    }

    #[test]
    fn one_cpu_at_one_tick_per_tick_is_100_percent() {
        let pct = cpu_percent(0, 100, Duration::from_secs(1), 1, 100).unwrap();
        assert!((pct - 100.0).abs() < 1e-6, "{pct}");
    }

    #[test]
    fn two_cpus_split_the_same_ticks() {
        let pct = cpu_percent(0, 100, Duration::from_secs(1), 2, 100).unwrap();
        assert!((pct - 50.0).abs() < 1e-6, "{pct}");
    }

    #[test]
    fn over_100_clamps_and_a_zero_interval_is_absent() {
        let pct = cpu_percent(0, 10_000, Duration::from_secs(1), 1, 100).unwrap();
        assert!((pct - 100.0).abs() < 1e-6, "{pct}");
        assert!(cpu_percent(0, 10, Duration::ZERO, 1, 100).is_none());
        assert!(cpu_percent(0, 10, Duration::from_secs(1), 0, 100).is_none());
    }

    /// Two burning threads. `/proc/<tid>/stat` counts the whole
    /// process; the task file counts one thread. `task_cpu_ticks`
    /// must follow the task file, or every vCPU sample includes every
    /// other vCPU and a modestly busy tree clamps to 100%.
    #[test]
    fn task_cpu_ticks_is_one_thread_not_the_process() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{mpsc, Arc};
        use std::thread;

        let stop = Arc::new(AtomicBool::new(false));
        let mut joins = Vec::new();
        let mut tids = Vec::new();
        for _ in 0..2 {
            let stop = Arc::clone(&stop);
            let (tx, rx) = mpsc::channel();
            joins.push(thread::spawn(move || {
                let tid = unsafe { libc::gettid() };
                tx.send(tid).expect("tid");
                let mut n = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    n = n.wrapping_add(1);
                }
                std::hint::black_box(n);
            }));
            tids.push(rx.recv().expect("tid"));
        }
        thread::sleep(Duration::from_millis(300));
        let mine: Vec<u64> = tids
            .iter()
            .map(|tid| task_cpu_ticks(u32::try_from(*tid).expect("tid")).expect("task stat"))
            .collect();
        let group: Vec<u64> = tids
            .iter()
            .map(|tid| {
                let text = fs::read_to_string(format!("/proc/{tid}/stat")).expect("stat");
                parse_stat_ticks(&text).expect("parse")
            })
            .collect();
        stop.store(true, Ordering::Relaxed);
        for join in joins {
            join.join().expect("join");
        }
        for (one, whole) in mine.iter().zip(group.iter()) {
            assert!(
                *whole > *one + 5,
                "thread ticks {one} should be below the process sum {whole}"
            );
        }
    }
}
