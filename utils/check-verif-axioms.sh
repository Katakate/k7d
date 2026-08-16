#!/usr/bin/env bash
# Guard: fail loudly if Aeneas emits an axiom not listed in
# verif/axiom-allowlist.txt (see CHALLENGES.md #24).
#
# Usage (on the node, after Charon+Aeneas):
#   utils/check-verif-axioms.sh [K7d.lean] [allowlist]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LEAN="${1:-$ROOT/verif/Verif/K7d.lean}"
ALLOW="${2:-$ROOT/verif/axiom-allowlist.txt}"

if [[ ! -f "$LEAN" ]]; then
  echo "check-verif-axioms: missing generated Lean file: $LEAN" >&2
  echo "  Run Charon+Aeneas first (make verif-gen)." >&2
  exit 1
fi
if [[ ! -f "$ALLOW" ]]; then
  echo "check-verif-axioms: missing allowlist: $ALLOW" >&2
  exit 1
fi

# Extract axiom names. Shapes seen in Aeneas output:
#   axiom Foo.bar : ...
#   noncomputable axiom Foo.bar : ...
#   @[...] axiom Foo.bar : ...
#   @[...] noncomputable axiom Foo.bar : ...
extract_axioms() {
  # `|| true`: zero axioms is valid (grep would exit 1 under pipefail).
  # LC_ALL=C so `comm` sees the same byte order as `sort`.
  grep -E '^[[:space:]]*(@\[[^]]*\][[:space:]]*)*(noncomputable[[:space:]]+)?axiom[[:space:]]+' "$1" \
    | sed -E 's/^[[:space:]]*//; s/^@\[[^]]*\][[:space:]]*//; s/^noncomputable[[:space:]]+//; s/^axiom[[:space:]]+//; s/[[:space:]].*//' \
    | { grep -E '^[A-Za-z_]' || true; } \
    | LC_ALL=C sort -u
}

# Allowlist: one name per line; `#` starts a comment (whole-line or trailing).
extract_allowlist() {
  sed -E 's/#.*//; s/^[[:space:]]+//; s/[[:space:]]+$//' "$1" \
    | { grep -E '^[A-Za-z_]' || true; } \
    | LC_ALL=C sort -u
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

extract_axioms "$LEAN" >"$tmp/found.txt"
extract_allowlist "$ALLOW" >"$tmp/allowed.txt"

comm -23 "$tmp/found.txt" "$tmp/allowed.txt" >"$tmp/new.txt"
comm -13 "$tmp/found.txt" "$tmp/allowed.txt" >"$tmp/stale.txt"

found_n=$(wc -l <"$tmp/found.txt" | tr -d ' ')
allowed_n=$(wc -l <"$tmp/allowed.txt" | tr -d ' ')
new_n=$(wc -l <"$tmp/new.txt" | tr -d ' ')
stale_n=$(wc -l <"$tmp/stale.txt" | tr -d ' ')

echo "check-verif-axioms: $found_n axiom(s) in $(basename "$LEAN"), $allowed_n allowlisted"

if [[ "$stale_n" -gt 0 ]]; then
  echo "check-verif-axioms: note — $stale_n allowlist entr(y/ies) no longer appear; you can prune:"
  sed 's/^/  /' "$tmp/stale.txt"
fi

if [[ "$new_n" -gt 0 ]]; then
  echo "check-verif-axioms: FAIL — $new_n new axiom(s) not in allowlist:" >&2
  sed 's/^/  /' "$tmp/new.txt" >&2
  echo >&2
  echo "Aeneas axiomatized a primitive that verified code may now reach." >&2
  echo "Either refactor tree_model.rs to avoid it (preferred; see CHALLENGES.md #24)," >&2
  echo "or — only for unverified code paths — add the name to verif/axiom-allowlist.txt" >&2
  echo "with a comment naming the unverified function that pulls it in." >&2
  exit 1
fi

echo "check-verif-axioms: OK — generated axioms ⊆ allowlist"
exit 0
