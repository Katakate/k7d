.PHONY: gen build clean

# Tools (override on the command line if installed elsewhere):
#   make gen CHARON=$$HOME/aeneas/charon/bin/charon AENEAS=$$HOME/aeneas/bin/aeneas
CHARON ?= charon
AENEAS ?= aeneas

# Path to the cargo workspace (one level up).
WORKSPACE := ..

# Translate the verified subset of `crates/k7d` to Aeneas's intermediate
# representation, then to Lean. The `verif` Cargo feature gates out every
# non-pure module from `crates/k7d/src/lib.rs` so Charon only sees
# `tree_model`.
# `-loops-to-rec` extracts every Rust `while` as a recursive `…_loop`
# function (instead of the `Aeneas.Std.loop` combinator), which is the
# shape the equivalence proofs in `Verif/Equiv/` recurse on
# (same style as the Aeneas tutorial / hashmap worked examples).
gen:
	cd $(WORKSPACE) && $(CHARON) cargo --preset=aeneas -- -p k7d --features verif --lib
	$(AENEAS) -backend lean -loops-to-rec $(WORKSPACE)/k7d.llbc -dest Verif

# Build the Lean theorems against the (re-)generated `TreeModel.lean`.
# Requires Lake + a Lean toolchain matching `lean-toolchain`.
build: gen
	lake build

clean:
	rm -rf .lake build
	# Restore the placeholder TreeModel.lean (the generator overwrites it):
	@echo "(re-run `make gen` to regenerate Verif/TreeModel.lean)"
