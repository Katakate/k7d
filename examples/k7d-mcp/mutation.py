"""One mutating-command classifier for the harness JSONL and the plots.

Keyword-based and deliberately coarse: anything that changes cluster or
host state counts (delete, scale, patch, apply, unit restarts, signals).
plots.py re-applies this to the raw `cmd` of every branch_exec row at
render time, so logs recorded before a keyword was added are re-scored
by the same rule as logs recorded after — the two comparison arms are
never judged by two different classifiers.
"""

from __future__ import annotations

MUTATING_KEYS = (
    "delete",
    "drain",
    "cordon",
    "kill",
    "rm -",
    "kubectl delete",
    "systemctl stop",
    "systemctl restart",
    "systemctl start",
    "iptables",
    "pkill",
    "scale",
    "patch",
    "apply",
    "taint",
    "evict",
    "annotate",
)


def looks_destructive(cmd: str) -> bool:
    s = cmd.lower()
    return any(k in s for k in MUTATING_KEYS)
