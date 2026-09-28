//! Opt-in Kernel Samepage Merging for guest RAM.
//!
//! A tree opts in with `ksm: true` on `tree_create_cluster` /
//! `tree_adopt_cluster` (off by default; forks inherit it). The process
//! that owns the guest mappings — the VM broker under privilege
//! separation, otherwise the daemon — then calls
//! [`advise_mergeable`] on each `MAP_PRIVATE` keyframe VMA **after**
//! the guest is running. That is one `madvise` per mapping: it sets
//! `VM_MERGEABLE` and returns. `ksmd` does the merging later, so a
//! fork's pause does not grow.
//!
//! `PR_SET_MEMORY_MERGE` is process-wide (every tree in the broker,
//! plus the broker's heap) and is not used. `MADV_UNMERGEABLE` unmerges
//! eagerly and can OOM, so the flag is sticky for the life of the
//! mapping.
//!
//! **Same-tenant hosts only.** KSM merges identical pages across every
//! mergeable VMA on the machine, including two trees that both opted
//! in, and that is a cross-VM timing side channel. k7d never writes
//! `/sys/kernel/mm/ksm`. Starting `ksmd` is an operator decision;
//! [`host_ksmd_run`] only reads `run`.
//!
//! Per-VM merged pages come from the smaps `Ksm`/`KSM` line of that
//! guest VMA. `/proc/<pid>/ksm_merging_pages` and `ksm_stat` are
//! process-wide, mode `0400`, and `PR_SET_DUMPABLE=0` makes them
//! root-owned, so the VM broker cannot read its own. The node broker
//! reads them for the VM broker's pid ([`read_proc`]).

use std::fs;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Process-wide counters from `/proc/<pid>/ksm_stat`.
///
/// Every VM in the process shares these numbers. Per-VM merged pages
/// are [`KsmMember::ksm_merging_pages`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KsmProcStat {
    /// `ksm_rmap_items`.
    pub ksm_rmap_items: u64,
    /// `ksm_merging_pages` for the whole process, not one VM.
    pub ksm_merging_pages: u64,
    /// `ksm_process_profit` (bytes). Signed: a process can be negative
    /// while merges are in flight.
    pub ksm_process_profit: i64,
    /// `yes` / `no` from `ksm_merge_any`, empty when the kernel omits it.
    /// k7d never sets `PR_SET_MEMORY_MERGE`, so this stays `no`.
    #[serde(default)]
    pub ksm_merge_any: String,
}

/// KSM counters for one live member, as reported by `tree_nodes`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KsmMember {
    /// Pages of this member's guest VMA that are KSM pages (smaps
    /// `Ksm`/`KSM` kibibytes ÷ 4). Zero when the VMA was not marked
    /// mergeable, or `ksmd` has not merged it yet.
    pub ksm_merging_pages: u64,
    /// The owning process's `ksm_stat`. Same value on every member.
    pub ksm_stat: KsmProcStat,
}

/// One `read_proc` answer: per-range merged pages, plus the process stat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KsmSnapshot {
    /// Same order as the ranges passed to [`read_proc`].
    pub merging_pages: Vec<u64>,
    /// `/proc/<pid>/ksm_stat`, or zeros when the file is absent.
    pub stat: KsmProcStat,
}

/// `/sys/kernel/mm/ksm/run`, if the kernel was built with KSM.
///
/// `1` means `ksmd` is scanning. This function only reads the file.
#[must_use]
pub fn host_ksmd_run() -> Option<u32> {
    let text = fs::read_to_string("/sys/kernel/mm/ksm/run").ok()?;
    text.trim().parse().ok()
}

/// `madvise(MADV_MERGEABLE)` on one guest RAM mapping.
///
/// `addr` and `len` must be page-aligned and describe a mapping this
/// process owns. A `MAP_SHARED` VMA (virtiofs memfd, cold-boot memfd
/// before the restore-swap) is rejected by the kernel with `EINVAL`;
/// that error is returned, not swallowed.
pub fn advise_mergeable(addr: u64, len: u64) -> io::Result<()> {
    const PAGE: u64 = 4096;
    if addr == 0 || len == 0 || addr % PAGE != 0 || len % PAGE != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "madvise(MADV_MERGEABLE) needs a non-empty page-aligned guest \
                 mapping, got addr={addr:#x} len={len}"
            ),
        ));
    }
    // SAFETY: `addr`/`len` describe a live guest-RAM mapping owned by
    // this process for the VM's lifetime. `MADV_MERGEABLE` only sets
    // `VM_MERGEABLE` on that VMA; it does not change page contents and
    // does not merge anything itself. The length is page-aligned and
    // non-zero, checked above.
    let rc = unsafe {
        libc::madvise(
            addr as *mut libc::c_void,
            len as usize,
            libc::MADV_MERGEABLE,
        )
    };
    if rc != 0 {
        let err = io::Error::last_os_error();
        return Err(io::Error::other(format!(
            "madvise(MADV_MERGEABLE) guest RAM {addr:#x}+{len}: {err} \
             (the kernel rejects shared mappings; KSM merges only private pages)"
        )));
    }
    Ok(())
}

/// Read per-range merged pages and `ksm_stat` for `pid`.
///
/// `ranges` are host addresses in that process (`start`, `len`). The
/// node broker calls this with the VM broker's pid; an unsplit daemon
/// calls it with its own. Missing `ksm_stat` (kernel without
/// `CONFIG_KSM`) is zeros. A missing `smaps` is an error.
pub fn read_proc(pid: u32, ranges: &[(u64, u64)]) -> io::Result<KsmSnapshot> {
    if pid == 0 {
        return Err(io::Error::other(
            "ksm: refusing to read /proc/0 (no VM-broker pid)",
        ));
    }
    let smaps = fs::read_to_string(format!("/proc/{pid}/smaps"))?;
    let vmas = parse_smaps(&smaps);
    let merging_pages = ranges
        .iter()
        .map(|(start, len)| merged_pages(&vmas, *start, *len))
        .collect();
    let stat_path = format!("/proc/{pid}/ksm_stat");
    let stat = match fs::read_to_string(&stat_path) {
        Ok(text) => parse_ksm_stat(&text),
        Err(e) if e.kind() == io::ErrorKind::NotFound => KsmProcStat::default(),
        Err(e) => {
            return Err(io::Error::other(format!("read {stat_path}: {e}")));
        }
    };
    Ok(KsmSnapshot {
        merging_pages,
        stat,
    })
}

/// Merged pages of the VMAs that overlap `[start, start+len)`.
fn merged_pages(vmas: &[VmaKsm], start: u64, len: u64) -> u64 {
    let end = start.saturating_add(len);
    let kb: u64 = vmas
        .iter()
        .filter(|v| v.start < end && start < v.end)
        .map(|v| v.ksm_kb)
        .sum();
    // smaps reports kibibytes. A KSM page is 4 KiB, so pages = kB / 4.
    kb / 4
}

struct VmaKsm {
    start: u64,
    end: u64,
    ksm_kb: u64,
}

fn parse_smaps(text: &str) -> Vec<VmaKsm> {
    let mut out = Vec::new();
    let mut cur: Option<VmaKsm> = None;
    for line in text.lines() {
        if let Some((start, end)) = parse_vma_header(line) {
            if let Some(v) = cur.take() {
                out.push(v);
            }
            cur = Some(VmaKsm {
                start,
                end,
                ksm_kb: 0,
            });
        } else if let Some(kb) = parse_ksm_kb(line) {
            if let Some(v) = cur.as_mut() {
                v.ksm_kb = kb;
            }
        }
    }
    if let Some(v) = cur {
        out.push(v);
    }
    out
}

/// `7f8a00000000-7f8a10000000 rw-p ...` → `(start, end)`.
fn parse_vma_header(line: &str) -> Option<(u64, u64)> {
    let addr = line.split_whitespace().next()?;
    let (a, b) = addr.split_once('-')?;
    if a.is_empty() || !a.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    if b.is_empty() || !b.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let start = u64::from_str_radix(a, 16).ok()?;
    let end = u64::from_str_radix(b, 16).ok()?;
    Some((start, end))
}

/// `Ksm:` / `KSM:` kibibytes, when the line is the smaps KSM counter.
fn parse_ksm_kb(line: &str) -> Option<u64> {
    let line = line.trim();
    let rest = line
        .strip_prefix("Ksm:")
        .or_else(|| line.strip_prefix("KSM:"))?;
    rest.split_whitespace().next()?.parse().ok()
}

fn parse_ksm_stat(text: &str) -> KsmProcStat {
    let mut stat = KsmProcStat::default();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else {
            continue;
        };
        let Some(val) = parts.next() else {
            continue;
        };
        match key {
            "ksm_rmap_items" => stat.ksm_rmap_items = val.parse().unwrap_or(0),
            "ksm_merging_pages" => stat.ksm_merging_pages = val.parse().unwrap_or(0),
            "ksm_process_profit" => stat.ksm_process_profit = val.parse().unwrap_or(0),
            "ksm_merge_any:" | "ksm_merge_any" => stat.ksm_merge_any = val.to_string(),
            _ => {}
        }
    }
    stat
}

/// True when `path` is the KSM sysfs directory. Used by the unit test
/// that the library never opens those files for writing.
#[must_use]
pub fn is_ksm_sysfs(path: &Path) -> bool {
    path.starts_with("/sys/kernel/mm/ksm")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advise_rejects_unaligned_length() {
        let err = advise_mergeable(0x1000, 100).expect_err("unaligned");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn smaps_ksm_line_is_per_vma_pages() {
        let text = "\
00400000-00600000 rw-p 00000000 00:20 1 /mem
Size:                2048 kB
Rss:                 2048 kB
Ksm:                 1024 kB
00600000-00700000 rw-p 00000000 00:00 0
Size:                1024 kB
AnonHugePages:          0 kB
";
        let vmas = parse_smaps(text);
        assert_eq!(vmas.len(), 2);
        // 1024 kB / 4 = 256 pages. The second VMA has no Ksm line.
        assert_eq!(merged_pages(&vmas, 0x40_0000, 0x20_0000), 256);
        assert_eq!(merged_pages(&vmas, 0x60_0000, 0x10_0000), 0);
        // A range that misses every VMA is zero, not an error.
        assert_eq!(merged_pages(&vmas, 0x80_0000, 0x1000), 0);
    }

    #[test]
    fn ksm_stat_parses_profit_and_merge_any() {
        let text = "\
ksm_rmap_items 12
ksm_merging_pages 34
ksm_process_profit -8
ksm_merge_any: no
";
        let stat = parse_ksm_stat(text);
        assert_eq!(stat.ksm_rmap_items, 12);
        assert_eq!(stat.ksm_merging_pages, 34);
        assert_eq!(stat.ksm_process_profit, -8);
        assert_eq!(stat.ksm_merge_any, "no");
    }

    #[test]
    fn sysfs_helper_only_matches_the_ksm_directory() {
        // `host_ksmd_run` reads `/sys/kernel/mm/ksm/run`. Nothing in
        // this module opens that directory for writing.
        let src = include_str!("ksm.rs");
        assert!(src.contains("read_to_string(\"/sys/kernel/mm/ksm/run\")"));
        assert!(!src.contains("File::create(\"/sys/kernel/mm/ksm"));
        assert!(is_ksm_sysfs(Path::new("/sys/kernel/mm/ksm/run")));
        assert!(!is_ksm_sysfs(Path::new("/proc/1/smaps")));
    }
}
