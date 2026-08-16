#!/usr/bin/env bash
# Install Aeneas + Charon + Lean (elan) on the bare-metal node so
# `make remote-verif` can regenerate `verif/Verif/TreeModel.lean` and
# `lake build` it. See §"Step 2".
#
# Idempotent: each section short-circuits if the tool it installs is
# already on PATH (or available at the well-known location this script
# uses elsewhere).
set -euo pipefail

AENEAS_REPO_URL="${AENEAS_REPO_URL:-https://github.com/AeneasVerif/aeneas}"
# Default rev = the pin in `verif/lakefile.toml`. Bump both together.
AENEAS_REV="${AENEAS_REV:-044c73b72171670cbe3a245ee7bccc4d626f0113}"
OCAML_VERSION="${OCAML_VERSION:-5.3.0}"

log() { printf '\n[install-aeneas] %s\n' "$*"; }

# ---- 0. apt deps ----
log "apt: build deps for OCaml + Charon + Lean"
export DEBIAN_FRONTEND=noninteractive
# Wait up to ~2 min for any concurrent apt holders (parallel agents),
# then install. dpkg lock is the single most common reason this script
# fails on a freshly reset node.
for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
  if apt-get update -y; then break; fi
  log "apt-get update busy (attempt $i); sleeping 10s"; sleep 10
done
apt-get install -y --no-install-recommends \
  build-essential pkg-config m4 git curl ca-certificates \
  libgmp-dev opam zlib1g-dev unzip

# ---- 1. rustup (Charon needs nightly via rustup) ----
if ! [ -x "$HOME/.cargo/bin/rustup" ]; then
  log "rustup: installing"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi
# shellcheck disable=SC1091
source "$HOME/.cargo/env"

# ---- 2. opam + OCaml switch ----
if ! [ -d "$HOME/.opam" ]; then
  log "opam: init (no shell hook; we source manually)"
  opam init --bare --disable-sandboxing -y
fi
# shellcheck disable=SC1091
eval "$(opam env --switch=default 2>/dev/null || true)"
if ! opam switch list --short 2>/dev/null | grep -qx "$OCAML_VERSION"; then
  log "opam: creating switch $OCAML_VERSION"
  opam switch create "$OCAML_VERSION" --yes
fi
eval "$(opam env --switch="$OCAML_VERSION")"
log "opam: installing Aeneas OCaml deps"
# Pin ocamlformat exactly per upstream README (anything else mismatches
# the project's .ocamlformat).
opam install -y \
  ppx_deriving ppx_deriving_yojson visitors easy_logging zarith yojson \
  core_unix odoc ocamlgraph menhir ocamlformat.0.27.0 unionFind progress \
  domainslib

# ---- 3. Aeneas (clones Charon via `make setup-charon`) ----
if ! [ -d "$HOME/aeneas/.git" ]; then
  log "aeneas: cloning $AENEAS_REPO_URL @ $AENEAS_REV"
  git clone "$AENEAS_REPO_URL" "$HOME/aeneas"
  git -C "$HOME/aeneas" checkout "$AENEAS_REV"
fi

cd "$HOME/aeneas"
if ! [ -x charon/bin/charon ]; then
  log "aeneas: setup-charon (clones + builds the pinned Charon)"
  make setup-charon
fi
if ! [ -x bin/aeneas ]; then
  log "aeneas: building"
  make
fi

# ---- 4. elan + Lean toolchain ----
if ! [ -x "$HOME/.elan/bin/elan" ]; then
  log "elan: installing"
  curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf \
    | sh -s -- -y --default-toolchain none
fi
# shellcheck disable=SC1091
source "$HOME/.elan/env"
# Read the toolchain pin from verif/lean-toolchain on the node and install it.
if [ -f /root/k7d/verif/lean-toolchain ]; then
  TOOLCHAIN="$(tr -d '\n' < /root/k7d/verif/lean-toolchain)"
  log "lean: installing toolchain $TOOLCHAIN"
  "$HOME/.elan/bin/elan" toolchain install "$TOOLCHAIN"
  "$HOME/.elan/bin/elan" default "$TOOLCHAIN"
fi

# ---- 5. smoke test ----
log "verifying installs"
"$HOME/aeneas/charon/bin/charon" --help | head -3 || { log "charon --help failed"; exit 1; }
"$HOME/aeneas/bin/aeneas" --help | head -3 || { log "aeneas --help failed"; exit 1; }
"$HOME/.elan/bin/lean" --version || { log "lean --version failed"; exit 1; }

log "done. add the following to your shell rc on the node:"
echo "  source \$HOME/.cargo/env"
echo "  source \$HOME/.elan/env"
echo "  eval \"\$(opam env --switch=$OCAML_VERSION)\""
echo "  export PATH=\$HOME/aeneas/bin:\$HOME/aeneas/charon/bin:\$PATH"
