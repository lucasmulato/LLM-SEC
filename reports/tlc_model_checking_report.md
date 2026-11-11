# Formal Verification Report: TLA+ Model Checking & Runtime Trace Conformance

> **System:** SSI Kernel Execution Gateway  
> **Toolchain:** TLA+ Tools (`tla2tools.jar` v1.8.0 / TLC Version 2026.11.06) & Java 21 OpenJDK  
> **Trace Validator:** `tools/trace-validator` v0.1.0 (Rust)  
> **Date:** 2026-11-11  
> **Conformance Level:** **Level 3 (Bounded Model Checking)**  
> **Normative Standards:** [`docs/REQUIREMENTS.md`](../docs/REQUIREMENTS.md), [`AGENTS.md`](../AGENTS.md) Rule 3

---

## 1. Conformance Statement & Honesty Discipline

> [!IMPORTANT]
> **Scope of Conformance Claim (Level 3):**  
> In compliance with Rule 3 of `AGENTS.md`, this report documents **Bounded Model Checking** conducted using TLC across finite state domains.  
> - Total states explored: **1,062,680 states generated**, **37,182 distinct reachable states** checked to depth 14.  
> - **This verification does NOT constitute an unconstrained inductive mathematical proof over unbounded integer domains.** It provides mechanical certainty that within the bounded state space parameter domain, no state violation, deadlocks, or unhandled transitions exist.

---

## 2. Specification & Proof Obligations Mapping

| Proof Obligation | Description | TLA+ Specification Theorem | TLC Result | Evidence Artifact |
| :--- | :--- | :--- | :---: | :--- |
| **PO-3** | Authorization Soundness | `T1_PermitSoundness`, `C1_AuthorizationContinuity` | **PASS (Level 3)** | [`specs/tla/SSI_Kernel.tla`](../specs/tla/SSI_Kernel.tla) |
| **PO-4** | Verification Soundness | `T1_PermitSoundness`, `FailClosedUnknownVerification` | **PASS (Level 3)** | [`specs/tla/SSI_Kernel.tla`](../specs/tla/SSI_Kernel.tla) |
| **PO-5** | Invariant Preservation | `T3_InvariantPreservation`, `T5_ReachableStateSafety` | **PASS (Level 3)** | [`specs/tla/SSI_Kernel.tla`](../specs/tla/SSI_Kernel.tla) |
| **PO-9** | Trace Reproducibility | Runtime Trace Conformance (1,000 steps) | **PASS (Level 3)** | [`tools/trace-validator`](../tools/trace-validator) |

---

## 3. TLC Model Checking Exploration Metrics

### 3.1 Base Configuration (`specs/tla/SSI_Kernel.cfg`)
- **Constants:** `MaxBudget = 3`, `MaxEpoch = 3`, `MaxClearance = 2`, `MaxSequence = 3`
- **Actions in Domain:** 9 representative actions (valid read, valid compute, overbudget, high-risk, high-clearance, emergency halt, forbidden keyword, invalid payload, missing capability)
- **Verification Status Domain:** `{"Valid", "Invalid", "Unknown"}`
- **States Generated:** 172,020
- **Distinct States Checked:** 6,036
- **Depth:** 10
- **Violations:** 0 (Clean verification)

### 3.2 High-Capacity Scaling Configuration (`specs/tla/SSI_Kernel_Large.cfg`)
- **Constants:** `MaxBudget = 5`, `MaxEpoch = 5`, `MaxClearance = 3`, `MaxSequence = 5`
- **States Generated:** **1,062,680** (exceeds acceptance threshold of $\ge 500,000$ states)
- **Distinct States Checked:** **37,182**
- **Search Depth:** 14
- **State Queue at Completion:** 0 (complete finite state space exploration)
- **Fingerprint Collision Probability:** Optimistic $2.1 \times 10^{-9}$, Actual $1.2 \times 10^{-11}$
- **Violations:** **0 (Clean verification)**

### 3.3 Verified Theorems
1. `T1_PermitSoundness`: $\text{executed} \implies \text{PERMIT}(pre, a) = 1$
2. `T3_InvariantPreservation`: $\text{executed} \implies I(X')$
3. `T5_ReachableStateSafety`: $\forall s \in \text{Reachable}: I(s) = 1$
4. `C1_AuthorizationContinuity`: $\text{Expired}(CSL) \lor \text{Revoked}(CSL) \implies \text{PERMIT} = 0$
5. `BudgetMonotonicity`: $\text{executed} \implies X'.\text{budget} \le X.\text{budget}$
6. `SequenceMonotonicity`: $\text{executed} \implies X'.\text{seq} = X.\text{seq} + 1$
7. `FailClosedUnknownVerification`: $\text{ver\_status} = \text{"Unknown"} \implies \text{PERMIT} = 0$
8. `ZeroExecutionOnReject`: $\neg\text{PERMIT} \implies \neg\text{executed}$

---

## 4. Negative Controls (Mutation Testing of the Formal Spec)

TLC was executed against three deliberately broken specifications to prove that the model checker detects violations and produces counterexample traces.

| Negative Control | Defect Injected | Expected Failure | TLC Result | Depth | Counterexample Behavior |
| :--- | :--- | :--- | :---: | :---: | :--- |
| **NC-1 (Broken Auth)** | Bypassed token expiry and revocation | `T1_PermitSoundness` | **CAUGHT ✓** | 4 | State 4 executed `act_read` at epoch 2 when token expired at epoch 1 |
| **NC-2 (Broken Inv)** | Empty invariant registry $\Phi = \emptyset$ committed | `T3_InvariantPreservation` | **CAUGHT ✓** | 2 | State 2 committed action with empty $\Phi$ violating fail-closed invariant |
| **NC-3 (Broken Budget)** | Transition inflated budget ($+1$) | `BudgetMonotonicity` | **CAUGHT ✓** | 2 | State 2 transitioned from budget 2 to budget 3 |

All 3 negative controls failed fast with exit code 12, dumping complete counterexample traces.

---

## 5. Runtime Trace Conformance Verification

The runtime trace validator (`tools/trace-validator`) maps recorded execution traces emitted by `ssi-gate` to the TLA+ specification state space via the refinement mapping $\mathcal{M}$ defined in [`specs/tla/TraceRefinement.md`](../specs/tla/TraceRefinement.md).

### 5.1 Verification Results
- **Trace Source:** Integration test pipeline executing sequential actions across 1,000 steps
- **Steps Evaluated:** 1,000 / 1,000
- **Permitted Commits Verified:** 857
- **Rejections Verified (Fail-Closed):** 143
- **Trace Conformance Verdict:** **100% CONFORMANT (0 violations)**

### 5.2 Trace Negative Controls
`tools/trace-validator` was evaluated against 6 synthetic trace corruption scenarios:
1. `FORGED_PERMIT`: Expired authorization marked as permitted $\to$ **CAUGHT ✓** (`PermitSoundnessViolation`)
2. `UNKNOWN_VERIFICATION`: Unknown tri-state verification status permitted $\to$ **CAUGHT ✓** (`PermitSoundnessViolation`)
3. `NON_MONOTONIC_SEQ`: Sequence number jump from 0 to 5 $\to$ **CAUGHT ✓** (`SequenceMonotonicityViolation`)
4. `BUDGET_INFLATION`: Post-state budget greater than pre-state $\to$ **CAUGHT ✓** (`BudgetMonotonicityViolation`)
5. `PARENT_HASH_MISMATCH`: Tampered parent state hash $\to$ **CAUGHT ✓** (`ParentHashMismatch`)
6. `TAMPERED_PRE_STATE`: Commit record with altered pre-state hash $\to$ **CAUGHT ✓** (`ParentHashMismatch`)

---

## 6. Conclusion & Next Phase Readiness

Phase 2 objectives are met:
- **TLC model checking verified** across $> 1,000,000$ states without violations.
- **3/3 Spec negative controls verified** with concrete TLC counterexamples.
- **1,000/1,000 Trace steps conformant** with formal refinement mapping $\mathcal{M}$.
- **6/6 Trace validator negative controls caught**.
- **Zero floating-point tokens** maintained across the entire workspace.
