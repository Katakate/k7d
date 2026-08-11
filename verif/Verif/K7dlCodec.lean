-- Group E — K7DL delta codec round-trip.
--
-- We prove the round-trip property of the pure halves of the K7DL codec
-- in `crate::tree_model`:
--   * `parseHeader (headerBytes pc ms) = ok (pc, ms)`
--   * `parseEntry  (encodeEntry idx page) = (idx, page)`
--
-- The mirror models the four pure helpers (`headerBytes`, `parseHeader`,
-- `encodeEntry`, `parseEntry`) on `BitVec 32` / `BitVec 64` / `BitVec 8`
-- (the same width-typed primitives the Rust source uses underneath
-- `u32`/`u64`/`u8`). Same byte layout as the Rust source — change one,
-- update the other.
--
-- The round-trip proofs close on the mirror: the header proof under
-- `bv_decide` (`pc` and `ms` are the only free variables and they live
-- in the `BitVec` fragment); the entry proof reduces to the same
-- little-endian round-trip on `idx` after separating the page payload,
-- which is preserved verbatim through both halves of the codec.
--
-- Since internal notes**machine-checked equivalent** to
-- the Aeneas translation of the Rust source (`Verif/Equiv/K7dl.lean`,
-- up to `absBytes : Array U8 n → List Byte`), and the round-trips
-- transfer to the generated code as `k7dl_header_roundtrip_rust` /
-- `k7dl_entry_roundtrip_rust` in `Verif/Equiv/Transfer.lean` —
-- inspection is no longer the trust anchor. The unit tests in
-- `crates/k7d/src/tree_model.rs::tests` cover the same surface from
-- the Rust side and must pass for every PR.

import Verif.TreeModel

namespace Verif.K7dlCodec

abbrev Byte := BitVec 8

/-- 4-byte K7DL magic, encoded as a `BitVec 8` list. -/
def magic : List Byte :=
  [BitVec.ofNat 8 0x4B, BitVec.ofNat 8 0x37, BitVec.ofNat 8 0x44, BitVec.ofNat 8 0x4C]

/-- On-disk K7DL version, mirroring `K7DL_VERSION` in `tree_model.rs`. -/
def version : BitVec 32 := 1#32

/-- Errors produced by `parseHeader`, mirroring `tree_model::DeltaError`. -/
inductive DeltaError where
  | badMagic (got : List Byte)
  | unsupportedVersion (got : BitVec 32)
  deriving DecidableEq

/-- Pack `n : BitVec 32` into 4 little-endian bytes. -/
def u32ToLe (n : BitVec 32) : List Byte :=
  [ n.extractLsb' 0 8,
    n.extractLsb' 8 8,
    n.extractLsb' 16 8,
    n.extractLsb' 24 8 ]

/-- Decode 4 little-endian bytes into a `BitVec 32`. -/
def u32FromLe (b0 b1 b2 b3 : Byte) : BitVec 32 :=
  (b3 ++ b2 ++ b1 ++ b0)

/-- Pack `n : BitVec 64` into 8 little-endian bytes. -/
def u64ToLe (n : BitVec 64) : List Byte :=
  [ n.extractLsb' 0 8,
    n.extractLsb' 8 8,
    n.extractLsb' 16 8,
    n.extractLsb' 24 8,
    n.extractLsb' 32 8,
    n.extractLsb' 40 8,
    n.extractLsb' 48 8,
    n.extractLsb' 56 8 ]

/-- Decode 8 little-endian bytes into a `BitVec 64`. -/
def u64FromLe (b0 b1 b2 b3 b4 b5 b6 b7 : Byte) : BitVec 64 :=
  (b7 ++ b6 ++ b5 ++ b4 ++ b3 ++ b2 ++ b1 ++ b0)

/-- Mirror of `crate::tree_model::k7dl_header_bytes`.

Layout: `magic(4) ++ version(4 LE) ++ pc(4 LE) ++ ms(8 LE) ++ reserved(8)`. -/
def headerBytes (pc : BitVec 32) (ms : BitVec 64) : List Byte :=
  magic ++ u32ToLe version ++ u32ToLe pc ++ u64ToLe ms
    ++ List.replicate 8 (BitVec.ofNat 8 0)

/-- Mirror of `crate::tree_model::k7dl_parse_header`. -/
def parseHeader (bs : List Byte) : Except DeltaError (BitVec 32 × BitVec 64) :=
  match bs with
  | b0 :: b1 :: b2 :: b3
      :: v0 :: v1 :: v2 :: v3
      :: p0 :: p1 :: p2 :: p3
      :: m0 :: m1 :: m2 :: m3 :: m4 :: m5 :: m6 :: m7 :: _ =>
    if [b0, b1, b2, b3] = magic then
      let v := u32FromLe v0 v1 v2 v3
      if v = version then
        let pc := u32FromLe p0 p1 p2 p3
        let ms := u64FromLe m0 m1 m2 m3 m4 m5 m6 m7
        .ok (pc, ms)
      else
        .error (.unsupportedVersion v)
    else
      .error (.badMagic [b0, b1, b2, b3])
  | _ => .error (.badMagic [])

/-- Mirror of `crate::tree_model::k7dl_encode_entry`.

Layout: `idx(4 LE) ++ page(4096)`. -/
def encodeEntry (idx : BitVec 32) (page : List Byte) : List Byte :=
  u32ToLe idx ++ page

/-- Mirror of `crate::tree_model::k7dl_parse_entry`. -/
def parseEntry : List Byte → BitVec 32 × List Byte
  | i0 :: i1 :: i2 :: i3 :: rest => (u32FromLe i0 i1 i2 i3, rest)
  | bs => (BitVec.ofNat 32 0, bs)

/-- Helper: little-endian round-trip for `BitVec 32`. Closed under
`bv_decide`; `n` is the only free variable. -/
theorem u32_le_roundtrip (n : BitVec 32) :
    u32FromLe (n.extractLsb' 0 8) (n.extractLsb' 8 8)
        (n.extractLsb' 16 8) (n.extractLsb' 24 8) = n := by
  simp only [u32FromLe]
  bv_decide

/-- Helper: little-endian round-trip for `BitVec 64`. -/
theorem u64_le_roundtrip (n : BitVec 64) :
    u64FromLe (n.extractLsb' 0 8) (n.extractLsb' 8 8)
        (n.extractLsb' 16 8) (n.extractLsb' 24 8)
        (n.extractLsb' 32 8) (n.extractLsb' 40 8)
        (n.extractLsb' 48 8) (n.extractLsb' 56 8) = n := by
  simp only [u64FromLe]
  bv_decide

/-- Group E: header round-trip.

Aeneas's translation of the Rust source threads through monadic
side-effects on `Array Std.U8 28#usize`; the property below is the
same proposition expressed on the transparent `BitVec`-list mirror
(see the file-level note for why we mirror).

The proof unfolds both halves, dispatches the magic and version
checks definitionally (both their inputs are byte-literal closed
terms), and applies the two `BitVec` round-trip lemmas above to
discharge the `pc` / `ms` payload equalities. -/
theorem k7dl_header_roundtrip (pc : BitVec 32) (ms : BitVec 64) :
    parseHeader (headerBytes pc ms) = .ok (pc, ms) := by
  unfold headerBytes parseHeader
  simp only [magic, u32ToLe, version, u64ToLe, List.replicate,
    List.cons_append, List.nil_append]
  -- The two `dite` decisions in `parseHeader` both fire `True`:
  --   * The magic prefix is the literal 4-byte list — `decide`.
  --   * The version byte sequence decodes to `1#32` — `decide`.
  rw [if_pos (by decide), if_pos (by decide)]
  -- Remaining goal: `Except.ok (u32FromLe …, u64FromLe …) = Except.ok (pc, ms)`.
  rw [u32_le_roundtrip pc, u64_le_roundtrip ms]

/-- Group E: entry round-trip. The page payload appears verbatim on
both sides (`encodeEntry` prepends 4 bytes, `parseEntry` consumes them
and returns the suffix), so we split the proof: the second component
is `page = page` (definitionally), the first is the same `BitVec 32`
little-endian round-trip as in the header proof. -/
theorem k7dl_entry_roundtrip (idx : BitVec 32) (page : List Byte) :
    parseEntry (encodeEntry idx page) = (idx, page) := by
  show (u32FromLe _ _ _ _, page) = (idx, page)
  rw [u32_le_roundtrip idx]

end Verif.K7dlCodec
