-- Equivalence for Group E: the Aeneas translations
-- of the four pure K7DL codec halves (`k7dl_header_bytes`,
-- `k7dl_parse_header`, `k7dl_encode_entry`, `k7dl_parse_entry`) compute
-- the `Verif.K7dlCodec` mirrors, up to `absBytes` (`Array U8 n` →
-- `List (BitVec 8)`).
--
-- The generated code is loop-free byte shuffling: ranged `index_mut` +
-- `copy_from_slice` (modelled with `List.setSlice!`/`List.slice`/
-- `List.drop` in `Aeneas.Std` — all axiom-free at the pinned rev) and
-- `to_le_bytes`/`from_le_bytes` (modelled with `BitVec.toLEBytes`/
-- `BitVec.fromLEBytes`). The bridge lemmas below connect those models
-- to the mirror's `extractLsb'`-based byte lists.
--
-- The `parse_header` error path maps `DeltaError` variants exactly
-- (`headerPost` — no collapsing to `Bool`); the two variants the
-- Rust function cannot produce (`MemSizeMismatch`, `PageOutOfBounds`)
-- map to `False`.
--
-- `maxRecDepth`: elaborating `spec_imp_exists` (and friends) at
-- `Array U8 4096#usize`/`4100#usize` recurses once per numeral unit
-- somewhere in unification; the default 512 (and the generated file's
-- 2048) both blow up. 1 000 000 is instant in practice.

import Verif.Equiv.Abs
import Verif.K7dlCodec

namespace Verif.Equiv

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open k7d

set_option maxRecDepth 1000000

-- ## List plumbing (mirror-side, no generated names)

/-- `setSlice!` at offset 0, fully covered by the target. -/
theorem setSlice!_zero {α} (s s' : List α) (h : s'.length ≤ s.length) :
    s.setSlice! 0 s' = s' ++ s.drop s'.length := by
  simp only [List.setSlice!, List.take_zero, List.nil_append, Nat.zero_add]
  rw [min_eq_left (by omega), List.take_length]

/-- `setSlice!` writing exactly at the boundary of a known prefix. -/
theorem setSlice!_append_exact {α} (pre suf s' : List α) (i : Nat)
    (hi : i = pre.length) (h : s'.length ≤ suf.length) :
    (pre ++ suf).setSlice! i s' = pre ++ (s' ++ suf.drop s'.length) := by
  subst hi
  simp only [List.setSlice!, List.length_append]
  rw [min_eq_left (by omega), List.take_length, List.take_left,
    List.drop_append, List.drop_eq_nil_of_le (by omega), List.nil_append,
    Nat.add_sub_cancel_left, List.append_assoc]

/-- A length-4 list is the literal list of its four elements. -/
theorem list_eq_four {α} [Inhabited α] (l : List α) (h : l.length = 4) :
    l = [l[0]!, l[1]!, l[2]!, l[3]!] := by
  rcases l with _|⟨a,_|⟨b,_|⟨c,_|⟨d,_|⟨e,tl⟩⟩⟩⟩⟩ <;> simp_all

/-- A length-8 list is the literal list of its eight elements. -/
theorem list_eq_eight {α} [Inhabited α] (l : List α) (h : l.length = 8) :
    l = [l[0]!, l[1]!, l[2]!, l[3]!, l[4]!, l[5]!, l[6]!, l[7]!] := by
  rcases l with _|⟨a,_|⟨b,_|⟨c,_|⟨d,_|⟨e,_|⟨f,_|⟨g,_|⟨h',_|⟨i,tl⟩⟩⟩⟩⟩⟩⟩⟩⟩ <;>
    simp_all

-- ## Scalar / byte-list bridges

/-- `UScalar` is a single-field structure: equality is `bv` equality. -/
theorem uscalar_eq_iff_bv {ty} (x y : UScalar ty) : x = y ↔ x.bv = y.bv := by
  cases x; cases y; simp

/-- Round-trip `BitVec 8 → U8 → BitVec 8` is the identity (pointwise). -/
theorem map_bv_mk (l : List (BitVec 8)) :
    (l.map (@UScalar.mk .U8)).map U8.bv = l := by
  simp [List.map_map]

/-- Element `k` of `absBytes` is the `bv` of element `k`. -/
theorem absBytes_getElem! {n : Std.Usize} (a : Array Std.U8 n) (k : Nat)
    (h : k < n.val) :
    (absBytes a)[k]! = (a.val[k]!).bv := by
  have hk : k < a.val.length := by scalar_tac
  rw [absBytes, ← List.Inhabited_getElem_eq_getElem! _ _ (by simpa using hk),
    ← List.Inhabited_getElem_eq_getElem! _ _ hk, List.getElem_map]

/-- `absBytes` of a 4-byte `Array.make` literal. -/
theorem absBytes_make4 (x0 x1 x2 x3 : Std.U8) :
    absBytes (Array.make 4#usize [x0, x1, x2, x3])
      = [x0.bv, x1.bv, x2.bv, x3.bv] := by
  simp [absBytes, Array.make]

/-- `absBytes` is injective (`U8.bv` is a bijection on bytes). -/
theorem absBytes_inj {n : Std.Usize} {a a' : Array Std.U8 n}
    (h : absBytes a = absBytes a') : a = a' := by
  have hval : a.val = a'.val :=
    List.map_injective_iff.mpr
      (fun x y hxy => (uscalar_eq_iff_bv x y).mpr hxy) h
  exact Subtype.ext hval

theorem bv_zero_u8 : (0#u8).bv = BitVec.ofNat 8 0 := by decide

-- ## BitVec bridges: Aeneas `toLEBytes`/`fromLEBytes` ↔ mirror lists

/-- Byte `i` of `toLEBytes` is `extractLsb'` at bit offset `8 * i`.
(Unfolding `toLEBytes` with `simp` loops on its own recursion — go
element-wise through `getElem!_toLEBytes` instead.) -/
theorem toLEBytes_getElem! {w : Nat} (n : BitVec w) (i : Nat) :
    n.toLEBytes[i]! = n.extractLsb' (8 * i) 8 := by
  rw [BitVec.eq_iff]
  intro j hj
  rw [BitVec.getElem!_toLEBytes n i j hj]
  simp only [BitVec.getElem!_eq_testBit_toNat, BitVec.extractLsb'_toNat,
    Nat.testBit_mod_two_pow, Nat.testBit_shiftRight, hj, decide_true,
    Bool.true_and]

/-- `BitVec.toLEBytes` at width 32 is the mirror's `u32ToLe`. -/
theorem toLEBytes_u32 (n : BitVec 32) :
    n.toLEBytes = K7dlCodec.u32ToLe n := by
  rw [list_eq_four n.toLEBytes (by simp)]
  simp only [toLEBytes_getElem!]
  norm_num [K7dlCodec.u32ToLe]

/-- `BitVec.toLEBytes` at width 64 is the mirror's `u64ToLe`. -/
theorem toLEBytes_u64 (n : BitVec 64) :
    n.toLEBytes = K7dlCodec.u64ToLe n := by
  rw [list_eq_eight n.toLEBytes (by simp)]
  simp only [toLEBytes_getElem!]
  norm_num [K7dlCodec.u64ToLe]

/-- `BitVec.fromLEBytes` on 4 bytes is the mirror's `u32FromLe`. -/
theorem fromLEBytes_u32 (b0 b1 b2 b3 : BitVec 8) :
    BitVec.fromLEBytes [b0, b1, b2, b3]
      = (K7dlCodec.u32FromLe b0 b1 b2 b3).cast (by simp) := by
  simp only [BitVec.fromLEBytes, K7dlCodec.u32FromLe, List.length_cons,
    List.length_nil]
  norm_num
  bv_decide

/-- `BitVec.fromLEBytes` on 8 bytes is the mirror's `u64FromLe`. -/
theorem fromLEBytes_u64 (b0 b1 b2 b3 b4 b5 b6 b7 : BitVec 8) :
    BitVec.fromLEBytes [b0, b1, b2, b3, b4, b5, b6, b7]
      = (K7dlCodec.u64FromLe b0 b1 b2 b3 b4 b5 b6 b7).cast (by simp) := by
  simp only [BitVec.fromLEBytes, K7dlCodec.u64FromLe, List.length_cons,
    List.length_nil]
  norm_num
  bv_decide

-- ## Generated-constant bridges

/-- The generated magic constant's byte list, evaluated. -/
theorem magic_bytes :
    (↑tree_model.K7DL_MAGIC : List Std.U8) = [75#u8, 55#u8, 68#u8, 76#u8] := by
  simp [tree_model.K7DL_MAGIC, Array.make]

/-- The generated magic constant abstracts to the mirror's `magic`. -/
theorem k7dl_magic_abs : absBytes tree_model.K7DL_MAGIC = K7dlCodec.magic := by
  simp only [absBytes, tree_model.K7DL_MAGIC, Array.make, K7dlCodec.magic,
    List.map_cons, List.map_nil]
  decide

/-- The generated version constant matches the mirror's `version`. -/
theorem k7dl_version_bv : tree_model.K7DL_VERSION.bv = K7dlCodec.version := by
  simp only [tree_model.K7DL_VERSION, K7dlCodec.version]
  decide

-- ## Mirror-side reformulations (getElem! form, for 20+/4+ byte inputs)

/-- `parseHeader` on any list of ≥ 20 bytes, in `getElem!` form. -/
theorem parseHeader_of_length {l : List K7dlCodec.Byte} (h : 20 ≤ l.length) :
    K7dlCodec.parseHeader l =
      if [l[0]!, l[1]!, l[2]!, l[3]!] = K7dlCodec.magic then
        if K7dlCodec.u32FromLe l[4]! l[5]! l[6]! l[7]! = K7dlCodec.version then
          .ok (K7dlCodec.u32FromLe l[8]! l[9]! l[10]! l[11]!,
               K7dlCodec.u64FromLe l[12]! l[13]! l[14]! l[15]! l[16]! l[17]!
                 l[18]! l[19]!)
        else
          .error (.unsupportedVersion
            (K7dlCodec.u32FromLe l[4]! l[5]! l[6]! l[7]!))
      else .error (.badMagic [l[0]!, l[1]!, l[2]!, l[3]!]) := by
  rcases l with _|⟨b0,_|⟨b1,_|⟨b2,_|⟨b3,_|⟨v0,_|⟨v1,_|⟨v2,_|⟨v3,_|⟨p0,_|⟨p1,_|⟨p2,_|⟨p3,_|⟨m0,_|⟨m1,_|⟨m2,_|⟨m3,_|⟨m4,_|⟨m5,_|⟨m6,_|⟨m7,rest⟩⟩⟩⟩⟩⟩⟩⟩⟩⟩⟩⟩⟩⟩⟩⟩⟩⟩⟩⟩ <;>
    simp_all [K7dlCodec.parseHeader]

/-- `parseEntry` on any list of ≥ 4 bytes, in `getElem!` form. -/
theorem parseEntry_of_length {l : List K7dlCodec.Byte} (h : 4 ≤ l.length) :
    K7dlCodec.parseEntry l
      = (K7dlCodec.u32FromLe l[0]! l[1]! l[2]! l[3]!, l.drop 4) := by
  rcases l with _|⟨a,_|⟨b,_|⟨c,_|⟨d,tl⟩⟩⟩⟩ <;> simp_all [K7dlCodec.parseEntry]

/-- The mirror's magic check, element-wise on the abstracted input. -/
theorem magic_cond_iff (b : Array Std.U8 28#usize) :
    ([(absBytes b)[0]!, (absBytes b)[1]!, (absBytes b)[2]!, (absBytes b)[3]!]
        = K7dlCodec.magic)
      ↔ ((↑b : List Std.U8)[0]! = 75#u8 ∧ (↑b : List Std.U8)[1]! = 55#u8
          ∧ (↑b : List Std.U8)[2]! = 68#u8 ∧ (↑b : List Std.U8)[3]! = 76#u8) := by
  rw [absBytes_getElem! b 0 (by scalar_tac), absBytes_getElem! b 1 (by scalar_tac),
    absBytes_getElem! b 2 (by scalar_tac), absBytes_getElem! b 3 (by scalar_tac)]
  simp only [K7dlCodec.magic, List.cons.injEq, and_true,
    uscalar_eq_iff_bv ((↑b : List Std.U8)[0]!) (75#u8),
    uscalar_eq_iff_bv ((↑b : List Std.U8)[1]!) (55#u8),
    uscalar_eq_iff_bv ((↑b : List Std.U8)[2]!) (68#u8),
    uscalar_eq_iff_bv ((↑b : List Std.U8)[3]!) (76#u8)]
  rw [show (75#u8).bv = 75#8 from by decide, show (55#u8).bv = 55#8 from by decide,
    show (68#u8).bv = 68#8 from by decide, show (76#u8).bv = 76#8 from by decide]

-- ## k7dl_header_bytes ≡ K7dlCodec.headerBytes

/-- Equivalence: `tree_model::k7dl_header_bytes` computes the mirror
`K7dlCodec.headerBytes` (and never panics). -/
theorem k7dl_header_bytes_equiv (pc : Std.U32) (ms : Std.U64) :
    tree_model.k7dl_header_bytes pc ms
      ⦃ out => absBytes out = K7dlCodec.headerBytes pc.bv ms.bv ⦄ := by
  unfold tree_model.k7dl_header_bytes
  step as ⟨s, back, hs, hslen, hback⟩
  step as ⟨s1, hs1⟩
  step as ⟨s2, hs2⟩
  step as ⟨s3, back1, hs3, hs3len, hback1⟩
  step as ⟨a, ha⟩
  step as ⟨s4, hs4⟩
  step as ⟨s5, hs5⟩
  step as ⟨s6, back2, hs6, hs6len, hback2⟩
  step as ⟨a1, ha1⟩
  step as ⟨s7, hs7⟩
  step as ⟨s8, hs8⟩
  step as ⟨s9, back3, hs9, hs9len, hback3⟩
  step as ⟨a2, ha2⟩
  step as ⟨s10, hs10⟩
  step as ⟨s11, hs11⟩
  have h28 : (28#usize).val = 28 := by simp
  have hm4 : (↑tree_model.K7DL_MAGIC : List Std.U8).length = 4 := by scalar_tac
  have hv4 : (List.map (@UScalar.mk .U8)
      tree_model.K7DL_VERSION.bv.toLEBytes).length = 4 := by simp
  have hp4 : (List.map (@UScalar.mk .U8) pc.bv.toLEBytes).length = 4 := by simp
  have hm8 : (List.map (@UScalar.mk .U8) ms.bv.toLEBytes).length = 8 := by simp
  have hb1 : (↑(back s2) : List Std.U8)
      = (↑tree_model.K7DL_MAGIC : List Std.U8) ++ List.replicate 24 0#u8 := by
    rw [hback, hs2, hs1, Array.val_to_slice, Array.repeat_val]
    rw [setSlice!_zero _ _ (by simp only [hm4, List.length_replicate]; scalar_tac)]
    rw [hm4, List.drop_replicate, h28]
  have hb2 : (↑(back1 s5) : List Std.U8)
      = (↑tree_model.K7DL_MAGIC : List Std.U8)
        ++ (List.map (@UScalar.mk .U8) tree_model.K7DL_VERSION.bv.toLEBytes
            ++ List.replicate 20 0#u8) := by
    rw [hback1, hs5, hs4, Array.val_to_slice, ha, hb1]
    rw [setSlice!_append_exact _ _ _ _ hm4.symm
      (by simp only [hv4, List.length_replicate]; omega)]
    rw [hv4, List.drop_replicate]
  have hb3 : (↑(back2 s8) : List Std.U8)
      = ((↑tree_model.K7DL_MAGIC : List Std.U8)
          ++ List.map (@UScalar.mk .U8) tree_model.K7DL_VERSION.bv.toLEBytes)
        ++ (List.map (@UScalar.mk .U8) pc.bv.toLEBytes
            ++ List.replicate 16 0#u8) := by
    rw [hback2, hs8, hs7, Array.val_to_slice, ha1, hb2, ← List.append_assoc]
    rw [setSlice!_append_exact _ _ _ _
      (by rw [List.length_append, hm4, hv4])
      (by simp only [hp4, List.length_replicate]; omega)]
    rw [hp4, List.drop_replicate]
  have hout : (↑(back3 s11) : List Std.U8)
      = (((↑tree_model.K7DL_MAGIC : List Std.U8)
          ++ List.map (@UScalar.mk .U8) tree_model.K7DL_VERSION.bv.toLEBytes)
          ++ List.map (@UScalar.mk .U8) pc.bv.toLEBytes)
        ++ (List.map (@UScalar.mk .U8) ms.bv.toLEBytes
            ++ List.replicate 8 0#u8) := by
    rw [hback3, hs11, hs10, Array.val_to_slice, ha2, hb3, ← List.append_assoc]
    rw [setSlice!_append_exact _ _ _ _
      (by rw [List.length_append, List.length_append, hm4, hv4, hp4])
      (by simp only [hm8, List.length_replicate]; omega)]
    rw [hm8, List.drop_replicate]
  have habs : absBytes (back3 s11)
      = ((↑(back3 s11) : List Std.U8)).map U8.bv := rfl
  rw [habs, hout]
  simp only [List.map_append, map_bv_mk, List.map_replicate, bv_zero_u8]
  rw [toLEBytes_u32, toLEBytes_u32, toLEBytes_u64, k7dl_version_bv]
  simp only [K7dlCodec.headerBytes, List.append_assoc]
  rw [show ((↑tree_model.K7DL_MAGIC : List Std.U8)).map U8.bv
      = K7dlCodec.magic from k7dl_magic_abs]

-- ## k7dl_parse_header ≡ K7dlCodec.parseHeader

/-- What `k7dl_parse_header` returns, phrased through the mirror: the
`Ok`/`Err` split and every `DeltaError` payload map exactly. The two
variants the Rust function cannot produce map to `False`. -/
def headerPost (b : Array Std.U8 28#usize)
    (r : core.result.Result (Std.U32 × Std.U64) tree_model.DeltaError) :
    Prop :=
  match r with
  | .Ok (pc, ms) =>
      K7dlCodec.parseHeader (absBytes b) = .ok (pc.bv, ms.bv)
  | .Err (.BadMagic got) =>
      K7dlCodec.parseHeader (absBytes b) = .error (.badMagic (absBytes got))
  | .Err (.UnsupportedVersion v) =>
      K7dlCodec.parseHeader (absBytes b) = .error (.unsupportedVersion v.bv)
  | .Err (.MemSizeMismatch _ _) => False
  | .Err (.PageOutOfBounds _ _) => False

/-- Equivalence: `tree_model::k7dl_parse_header` computes the mirror
`K7dlCodec.parseHeader` (and never panics), error variants included. -/
theorem k7dl_parse_header_equiv (b : Array Std.U8 28#usize) :
    tree_model.k7dl_parse_header b ⦃ r => headerPost b r ⦄ := by
  have hlen : (absBytes b).length = 28 := by
    simp only [absBytes, List.length_map]; scalar_tac
  unfold tree_model.k7dl_parse_header
  step as ⟨i, hi⟩
  replace hi : i = (↑b : List Std.U8)[0]! :=
    hi.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
  step as ⟨i1, hi1⟩
  replace hi1 : i1 = 75#u8 := by
    rw [hi1, List.Inhabited_getElem_eq_getElem!]
    · simp [magic_bytes]
    · scalar_tac
  split
  · -- byte 0 mismatch
    rename_i hne
    simp only [bne_iff_ne, ne_eq, hi1, hi] at hne
    step as ⟨i2, hi2⟩
    replace hi2 : i2 = (↑b : List Std.U8)[1]! :=
      hi2.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
    step as ⟨i3, hi3⟩
    replace hi3 : i3 = (↑b : List Std.U8)[2]! :=
      hi3.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
    step as ⟨i4, hi4⟩
    replace hi4 : i4 = (↑b : List Std.U8)[3]! :=
      hi4.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
    simp only [headerPost]
    rw [parseHeader_of_length (by rw [hlen]; omega)]
    rw [if_neg (by rw [magic_cond_iff]; rintro ⟨h0, -, -, -⟩; exact hne h0)]
    rw [absBytes_getElem! b 0 (by scalar_tac), absBytes_getElem! b 1 (by scalar_tac),
      absBytes_getElem! b 2 (by scalar_tac), absBytes_getElem! b 3 (by scalar_tac),
      absBytes_make4, hi, hi2, hi3, hi4]
  rename_i heq0
  simp only [bne_iff_ne, ne_eq, not_not, hi1, hi] at heq0
  step as ⟨i2, hi2⟩
  replace hi2 : i2 = (↑b : List Std.U8)[1]! :=
    hi2.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
  step as ⟨i3, hi3⟩
  replace hi3 : i3 = 55#u8 := by
    rw [hi3, List.Inhabited_getElem_eq_getElem!]
    · simp [magic_bytes]
    · scalar_tac
  split
  · -- byte 1 mismatch
    rename_i hne
    simp only [bne_iff_ne, ne_eq, hi3, hi2] at hne
    step as ⟨i4, hi4⟩
    replace hi4 : i4 = (↑b : List Std.U8)[2]! :=
      hi4.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
    step as ⟨i5, hi5⟩
    replace hi5 : i5 = (↑b : List Std.U8)[3]! :=
      hi5.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
    simp only [headerPost]
    rw [parseHeader_of_length (by rw [hlen]; omega)]
    rw [if_neg (by rw [magic_cond_iff]; rintro ⟨-, h1, -, -⟩; exact hne h1)]
    rw [absBytes_getElem! b 0 (by scalar_tac), absBytes_getElem! b 1 (by scalar_tac),
      absBytes_getElem! b 2 (by scalar_tac), absBytes_getElem! b 3 (by scalar_tac),
      absBytes_make4, hi, hi2, hi4, hi5]
  rename_i heq1
  simp only [bne_iff_ne, ne_eq, not_not, hi3, hi2] at heq1
  step as ⟨i4, hi4⟩
  replace hi4 : i4 = (↑b : List Std.U8)[2]! :=
    hi4.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
  step as ⟨i5, hi5⟩
  replace hi5 : i5 = 68#u8 := by
    rw [hi5, List.Inhabited_getElem_eq_getElem!]
    · simp [magic_bytes]
    · scalar_tac
  split
  · -- byte 2 mismatch
    rename_i hne
    simp only [bne_iff_ne, ne_eq, hi5, hi4] at hne
    step as ⟨i6, hi6⟩
    replace hi6 : i6 = (↑b : List Std.U8)[3]! :=
      hi6.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
    simp only [headerPost]
    rw [parseHeader_of_length (by rw [hlen]; omega)]
    rw [if_neg (by rw [magic_cond_iff]; rintro ⟨-, -, h2, -⟩; exact hne h2)]
    rw [absBytes_getElem! b 0 (by scalar_tac), absBytes_getElem! b 1 (by scalar_tac),
      absBytes_getElem! b 2 (by scalar_tac), absBytes_getElem! b 3 (by scalar_tac),
      absBytes_make4, hi, hi2, hi4, hi6]
  rename_i heq2
  simp only [bne_iff_ne, ne_eq, not_not, hi5, hi4] at heq2
  step as ⟨i6, hi6⟩
  replace hi6 : i6 = (↑b : List Std.U8)[3]! :=
    hi6.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
  step as ⟨i7, hi7⟩
  replace hi7 : i7 = 76#u8 := by
    rw [hi7, List.Inhabited_getElem_eq_getElem!]
    · simp [magic_bytes]
    · scalar_tac
  split
  · -- byte 3 mismatch (no trailing monadic step: reduce the `ok` by hand)
    rename_i hne
    simp only [bne_iff_ne, ne_eq, hi7, hi6] at hne
    simp only [spec_ok, headerPost]
    rw [parseHeader_of_length (by rw [hlen]; omega)]
    rw [if_neg (by rw [magic_cond_iff]; rintro ⟨-, -, -, h3⟩; exact hne h3)]
    rw [absBytes_getElem! b 0 (by scalar_tac), absBytes_getElem! b 1 (by scalar_tac),
      absBytes_getElem! b 2 (by scalar_tac), absBytes_getElem! b 3 (by scalar_tac),
      absBytes_make4, hi, hi2, hi4, hi6]
  rename_i heq3
  simp only [bne_iff_ne, ne_eq, not_not, hi7, hi6] at heq3
  have hmagic : [(absBytes b)[0]!, (absBytes b)[1]!, (absBytes b)[2]!,
      (absBytes b)[3]!] = K7dlCodec.magic :=
    (magic_cond_iff b).mpr ⟨heq0, heq1, heq2, heq3⟩
  step as ⟨i8, hi8⟩
  replace hi8 : i8 = (↑b : List Std.U8)[4]! :=
    hi8.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
  step as ⟨i9, hi9⟩
  replace hi9 : i9 = (↑b : List Std.U8)[5]! :=
    hi9.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
  step as ⟨i10, hi10⟩
  replace hi10 : i10 = (↑b : List Std.U8)[6]! :=
    hi10.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
  step as ⟨i11, hi11⟩
  replace hi11 : i11 = (↑b : List Std.U8)[7]! :=
    hi11.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
  step as ⟨version, hversion⟩
  replace hversion : version.bv
      = K7dlCodec.u32FromLe ((↑b : List Std.U8)[4]!).bv ((↑b : List Std.U8)[5]!).bv
          ((↑b : List Std.U8)[6]!).bv ((↑b : List Std.U8)[7]!).bv := by
    rw [hversion]
    simp only [Array.make, List.map_cons, List.map_nil]
    rw [fromLEBytes_u32]
    simp only [BitVec.cast_eq]
    rw [hi8, hi9, hi10, hi11]
  split
  · -- version mismatch. `rw` cannot cross `BitVec ty.numBits` vs
    -- `BitVec 32` type indices; the version bridges go through
    -- defeq-tolerant `Eq.trans` term proofs instead.
    rename_i hvne
    simp only [bne_iff_ne, ne_eq] at hvne
    simp only [spec_ok, headerPost]
    rw [parseHeader_of_length (by rw [hlen]; omega)]
    rw [if_pos hmagic]
    rw [absBytes_getElem! b 4 (by scalar_tac), absBytes_getElem! b 5 (by scalar_tac),
      absBytes_getElem! b 6 (by scalar_tac), absBytes_getElem! b 7 (by scalar_tac)]
    rw [if_neg (fun h => hvne ((uscalar_eq_iff_bv _ _).mpr
      (hversion.trans (h.trans k7dl_version_bv.symm))))]
    rw [← hversion]
  rename_i hveq
  simp only [bne_iff_ne, ne_eq, not_not] at hveq
  step as ⟨i12, hi12⟩
  replace hi12 : i12 = (↑b : List Std.U8)[8]! :=
    hi12.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
  step as ⟨i13, hi13⟩
  replace hi13 : i13 = (↑b : List Std.U8)[9]! :=
    hi13.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
  step as ⟨i14, hi14⟩
  replace hi14 : i14 = (↑b : List Std.U8)[10]! :=
    hi14.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
  step as ⟨i15, hi15⟩
  replace hi15 : i15 = (↑b : List Std.U8)[11]! :=
    hi15.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
  step as ⟨page_count, hpc⟩
  replace hpc : page_count.bv
      = K7dlCodec.u32FromLe ((↑b : List Std.U8)[8]!).bv ((↑b : List Std.U8)[9]!).bv
          ((↑b : List Std.U8)[10]!).bv ((↑b : List Std.U8)[11]!).bv := by
    rw [hpc]
    simp only [Array.make, List.map_cons, List.map_nil]
    rw [fromLEBytes_u32]
    simp only [BitVec.cast_eq]
    rw [hi12, hi13, hi14, hi15]
  step as ⟨i16, hi16⟩
  replace hi16 : i16 = (↑b : List Std.U8)[12]! :=
    hi16.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
  step as ⟨i17, hi17⟩
  replace hi17 : i17 = (↑b : List Std.U8)[13]! :=
    hi17.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
  step as ⟨i18, hi18⟩
  replace hi18 : i18 = (↑b : List Std.U8)[14]! :=
    hi18.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
  step as ⟨i19, hi19⟩
  replace hi19 : i19 = (↑b : List Std.U8)[15]! :=
    hi19.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
  step as ⟨i20, hi20⟩
  replace hi20 : i20 = (↑b : List Std.U8)[16]! :=
    hi20.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
  step as ⟨i21, hi21⟩
  replace hi21 : i21 = (↑b : List Std.U8)[17]! :=
    hi21.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
  step as ⟨i22, hi22⟩
  replace hi22 : i22 = (↑b : List Std.U8)[18]! :=
    hi22.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
  step as ⟨i23, hi23⟩
  replace hi23 : i23 = (↑b : List Std.U8)[19]! :=
    hi23.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
  step as ⟨mem_size, hms⟩
  replace hms : mem_size.bv
      = K7dlCodec.u64FromLe ((↑b : List Std.U8)[12]!).bv
          ((↑b : List Std.U8)[13]!).bv ((↑b : List Std.U8)[14]!).bv
          ((↑b : List Std.U8)[15]!).bv ((↑b : List Std.U8)[16]!).bv
          ((↑b : List Std.U8)[17]!).bv ((↑b : List Std.U8)[18]!).bv
          ((↑b : List Std.U8)[19]!).bv := by
    rw [hms]
    simp only [Array.make, List.map_cons, List.map_nil]
    rw [fromLEBytes_u64]
    simp only [BitVec.cast_eq]
    rw [hi16, hi17, hi18, hi19, hi20, hi21, hi22, hi23]
  simp only [headerPost]
  rw [parseHeader_of_length (by rw [hlen]; omega)]
  rw [if_pos hmagic]
  rw [absBytes_getElem! b 4 (by scalar_tac), absBytes_getElem! b 5 (by scalar_tac),
    absBytes_getElem! b 6 (by scalar_tac), absBytes_getElem! b 7 (by scalar_tac)]
  rw [if_pos (hversion.symm.trans
    ((congrArg UScalar.bv hveq).trans k7dl_version_bv))]
  rw [absBytes_getElem! b 8 (by scalar_tac), absBytes_getElem! b 9 (by scalar_tac),
    absBytes_getElem! b 10 (by scalar_tac), absBytes_getElem! b 11 (by scalar_tac),
    absBytes_getElem! b 12 (by scalar_tac), absBytes_getElem! b 13 (by scalar_tac),
    absBytes_getElem! b 14 (by scalar_tac), absBytes_getElem! b 15 (by scalar_tac),
    absBytes_getElem! b 16 (by scalar_tac), absBytes_getElem! b 17 (by scalar_tac),
    absBytes_getElem! b 18 (by scalar_tac), absBytes_getElem! b 19 (by scalar_tac),
    ← hpc, ← hms]

-- ## k7dl_set_base_identity / k7dl_base_identity 

/-- Equivalence: `tree_model::k7dl_set_base_identity` computes the
mirror `K7dlCodec.setBaseIdentity` (and never panics). -/
theorem k7dl_set_base_identity_equiv (hdr : Array Std.U8 28#usize) (bi : Std.U64) :
    tree_model.k7dl_set_base_identity hdr bi
      ⦃ out => absBytes out = K7dlCodec.setBaseIdentity (absBytes hdr) bi.bv ⦄ := by
  unfold tree_model.k7dl_set_base_identity
  step as ⟨s, back, hs, hslen, hback⟩
  step as ⟨a, ha⟩
  step as ⟨s1, hs1⟩
  step as ⟨s2, hs2⟩
  have hhlen : (↑hdr : List Std.U8).length = 28 := by scalar_tac
  have hb8 : (List.map (@UScalar.mk .U8) bi.bv.toLEBytes).length = 8 := by simp
  have hsplit : (↑hdr : List Std.U8)
      = (↑hdr : List Std.U8).take 20 ++ (↑hdr : List Std.U8).drop 20 :=
    (List.take_append_drop 20 _).symm
  have htake : ((↑hdr : List Std.U8).take 20).length = 20 := by
    rw [List.length_take, hhlen]; omega
  have hdrop : ((↑hdr : List Std.U8).drop 20).length = 8 := by
    rw [List.length_drop, hhlen]
  have hout : (↑(back s2) : List Std.U8)
      = (↑hdr : List Std.U8).take 20
        ++ List.map (@UScalar.mk .U8) bi.bv.toLEBytes := by
    rw [hback, hs2, hs1, Array.val_to_slice, ha]
    -- Only the `setSlice!` target splits; the `take 20` on the right of
    -- the goal must stay as it is.
    conv_lhs => rw [hsplit]
    rw [setSlice!_append_exact _ _ _ _ htake.symm (by simp [hb8, hdrop])]
    rw [hb8, List.drop_eq_nil_of_le (by simp [hdrop]), List.append_nil]
  simp only [absBytes, hout, List.map_append, map_bv_mk, List.map_take,
    K7dlCodec.setBaseIdentity, toLEBytes_u64]

/-- Equivalence: `tree_model::k7dl_base_identity` computes the mirror
`K7dlCodec.baseIdentity` (and never panics). -/
theorem k7dl_base_identity_equiv (hdr : Array Std.U8 28#usize) :
    tree_model.k7dl_base_identity hdr
      ⦃ out => out.bv = K7dlCodec.baseIdentity (absBytes hdr) ⦄ := by
  unfold tree_model.k7dl_base_identity
  -- Eight `index_usize` binds, then a plain `ok` — no ninth step.
  step as ⟨i, hi⟩
  replace hi : i = (↑hdr : List Std.U8)[20]! :=
    hi.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
  step as ⟨i1, hi1⟩
  replace hi1 : i1 = (↑hdr : List Std.U8)[21]! :=
    hi1.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
  step as ⟨i2, hi2⟩
  replace hi2 : i2 = (↑hdr : List Std.U8)[22]! :=
    hi2.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
  step as ⟨i3, hi3⟩
  replace hi3 : i3 = (↑hdr : List Std.U8)[23]! :=
    hi3.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
  step as ⟨i4, hi4⟩
  replace hi4 : i4 = (↑hdr : List Std.U8)[24]! :=
    hi4.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
  step as ⟨i5, hi5⟩
  replace hi5 : i5 = (↑hdr : List Std.U8)[25]! :=
    hi5.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
  step as ⟨i6, hi6⟩
  replace hi6 : i6 = (↑hdr : List Std.U8)[26]! :=
    hi6.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
  step as ⟨i7, hi7⟩
  replace hi7 : i7 = (↑hdr : List Std.U8)[27]! :=
    hi7.trans (List.Inhabited_getElem_eq_getElem! _ _ (by scalar_tac))
  -- Unlike `parse_header`, this `from_le_bytes` is not inside a monadic
  -- bind, so no `step` spec unfolded it — do it by hand.
  simp only [core.num.U64.from_le_bytes, Array.make, List.map_cons,
    List.map_nil, BitVec.cast_eq]
  rw [fromLEBytes_u64]
  simp only [BitVec.cast_eq, K7dlCodec.baseIdentity]
  rw [absBytes_getElem! hdr 20 (by scalar_tac),
    absBytes_getElem! hdr 21 (by scalar_tac),
    absBytes_getElem! hdr 22 (by scalar_tac),
    absBytes_getElem! hdr 23 (by scalar_tac),
    absBytes_getElem! hdr 24 (by scalar_tac),
    absBytes_getElem! hdr 25 (by scalar_tac),
    absBytes_getElem! hdr 26 (by scalar_tac),
    absBytes_getElem! hdr 27 (by scalar_tac)]
  rw [hi, hi1, hi2, hi3, hi4, hi5, hi6, hi7]

/-- Equivalence: `tree_model::k7dl_base_identity_ok` computes the
mirror `K7dlCodec.baseIdentityOk` (and never panics). -/
theorem k7dl_base_identity_ok_equiv (pack base : Std.U64) :
    tree_model.k7dl_base_identity_ok pack base
      ⦃ r => r = K7dlCodec.baseIdentityOk pack.bv base.bv ⦄ := by
  unfold tree_model.k7dl_base_identity_ok
  simp only [K7dlCodec.baseIdentityOk, uscalar_eq_iff_bv,
    show (0#u64).bv = 0#64 from by decide]
  split
  · simp_all [spec_ok]
  · split <;> simp_all [spec_ok]

-- ## k7dl_encode_entry ≡ K7dlCodec.encodeEntry

/-- Equivalence: `tree_model::k7dl_encode_entry` computes the mirror
`K7dlCodec.encodeEntry` (and never panics). -/
theorem k7dl_encode_entry_equiv (idx : Std.U32)
    (page : Array Std.U8 4096#usize) :
    tree_model.k7dl_encode_entry idx page
      ⦃ out => absBytes out = K7dlCodec.encodeEntry idx.bv (absBytes page) ⦄ := by
  unfold tree_model.k7dl_encode_entry
  step as ⟨s, back, hs, hslen, hback⟩
  step as ⟨a, ha⟩
  step as ⟨s1, hs1⟩
  step as ⟨s2, hs2⟩
  step as ⟨s3, back1, hs3, hs3len, hback1⟩
  step as ⟨s4, hs4⟩
  step as ⟨s5, hs5⟩
  have h4100 : (4100#usize).val = 4100 := by simp
  have hlen : (List.map (@UScalar.mk .U8) idx.bv.toLEBytes).length = 4 := by
    simp
  have hplen : (↑page : List Std.U8).length = 4096 := by scalar_tac
  have hbs2 : (↑(back s2) : List Std.U8)
      = List.map (@UScalar.mk .U8) idx.bv.toLEBytes
        ++ List.replicate 4096 0#u8 := by
    rw [hback, hs2, hs1, Array.val_to_slice, ha, Array.repeat_val]
    rw [setSlice!_zero _ _ (by simp only [hlen, List.length_replicate]; scalar_tac)]
    rw [hlen, List.drop_replicate, h4100]
  have hout : (↑(back1 s5) : List Std.U8)
      = List.map (@UScalar.mk .U8) idx.bv.toLEBytes ++ (↑page : List Std.U8) := by
    rw [hback1, hs5, hs4, Array.val_to_slice, hbs2]
    rw [setSlice!_append_exact _ _ _ _ hlen.symm
      (by simp only [hplen, List.length_replicate]; omega)]
    rw [hplen, List.drop_replicate]
    norm_num
  simp only [absBytes, hout, List.map_append, map_bv_mk,
    K7dlCodec.encodeEntry, toLEBytes_u32]

-- ## k7dl_parse_entry ≡ K7dlCodec.parseEntry

/-- Equivalence: `tree_model::k7dl_parse_entry` computes the mirror
`K7dlCodec.parseEntry` (and never panics). -/
theorem k7dl_parse_entry_equiv (b : Array Std.U8 4100#usize) :
    tree_model.k7dl_parse_entry b
      ⦃ r => (r.1.bv, absBytes r.2) = K7dlCodec.parseEntry (absBytes b) ⦄ := by
  unfold tree_model.k7dl_parse_entry
  step as ⟨i, hi⟩
  step as ⟨i1, hi1⟩
  step as ⟨i2, hi2⟩
  step as ⟨i3, hi3⟩
  step as ⟨page_idx, hpage_idx⟩
  step as ⟨sl, back, hsl, hback⟩
  step as ⟨s1, hs1⟩
  step as ⟨s2, hs2⟩
  · -- copy_from_slice length side condition
    simp only [Slice.length, hsl, hs1, Array.repeat_val, List.length_replicate,
      List.length_drop, Array.val_to_slice]
    scalar_tac
  · have hlen : (absBytes b).length = 4100 := by
      simp only [absBytes, List.length_map]; scalar_tac
    rw [parseEntry_of_length (by rw [hlen]; omega)]
    simp only [Prod.mk.injEq]
    refine ⟨?_, ?_⟩
    · rw [hpage_idx]
      simp only [Array.make, List.map_cons, List.map_nil]
      rw [fromLEBytes_u32]
      simp only [BitVec.cast_eq]
      rw [absBytes_getElem! b 0 (by scalar_tac),
        absBytes_getElem! b 1 (by scalar_tac),
        absBytes_getElem! b 2 (by scalar_tac),
        absBytes_getElem! b 3 (by scalar_tac)]
      rw [hi, hi1, hi2, hi3]
      rw [List.Inhabited_getElem_eq_getElem!, List.Inhabited_getElem_eq_getElem!,
        List.Inhabited_getElem_eq_getElem!, List.Inhabited_getElem_eq_getElem!]
      all_goals scalar_tac
    · have hs1len : (↑s1 : List Std.U8).length = 4096 := by
        rw [hs1]
        simp only [List.length_drop, Array.val_to_slice]
        scalar_tac
      rw [hback, hs2]
      show (Array.from_slice _ s1).val.map U8.bv = _
      rw [Array.from_slice_val _ _ (by rw [hs1len]; scalar_tac)]
      rw [hs1, Array.val_to_slice, absBytes, List.map_drop]

end Verif.Equiv
