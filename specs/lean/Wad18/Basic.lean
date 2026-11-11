/-!
  # WAD-18 Fixed-Point Arithmetic Formalization
  SSI Axiomatic System v1.0 — Definition 1 & Proof Obligation PO-2.

  Values are represented as 128-bit signed integers scaled by 10^18.
  All arithmetic is integer-only, strictly denying floating point representations.
-/

def WAD_SCALE : Int := 1000000000000000000 -- 10^18
def INT128_MIN : Int := -170141183460469231731687303715884105728
def INT128_MAX : Int := 170141183460469231731687303715884105727

structure Wad18 where
  val : Int
  in_bounds : INT128_MIN ≤ val ∧ val ≤ INT128_MAX

inductive WadError where
  | Overflow
  | Underflow
  | DivisionByZero
  | InexactResult
  deriving Repr, DecidableEq

def wad_add (a b : Wad18) : Except WadError Wad18 :=
  let r := a.val + b.val
  if h1 : r > INT128_MAX then Except.error WadError.Overflow
  else if h2 : r < INT128_MIN then Except.error WadError.Underflow
  else Except.ok ⟨r, by omega⟩

def wad_sub (a b : Wad18) : Except WadError Wad18 :=
  let r := a.val - b.val
  if h1 : r > INT128_MAX then Except.error WadError.Overflow
  else if h2 : r < INT128_MIN then Except.error WadError.Underflow
  else Except.ok ⟨r, by omega⟩

def wad_div (a b : Wad18) : Except WadError Wad18 :=
  if b.val = 0 then Except.error WadError.DivisionByZero
  else
    let num := a.val * WAD_SCALE
    let rem := num % b.val
    if rem ≠ 0 then Except.error WadError.InexactResult
    else
      let q := num / b.val
      if q > INT128_MAX then Except.error WadError.Overflow
      else if q < INT128_MIN then Except.error WadError.Underflow
      else Except.ok ⟨q, by omega⟩

theorem wad_div_zero_strictly_errors (a b : Wad18) (h : b.val = 0) :
    wad_div a b = Except.error WadError.DivisionByZero := by
  unfold wad_div
  split
  · rfl
  · contradiction
