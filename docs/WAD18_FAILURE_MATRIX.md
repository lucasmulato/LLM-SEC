# WAD-18 & SSI Gateway Failure Matrix

> **Conformance Target:** PO-1, PO-2, PO-3, PO-4, PO-5, PO-6  
> **Enforcement Policy:** Absolute Fail-Closed Semantics ($\text{Unknown} \equiv \text{REJECT}$)

---

## 1. WAD-18 Fixed-Point Numerical Fault Matrix

| Error Variant | Mathematical Condition | Trigger Scenarios | Fail-Closed Handling | Verified Evidence |
| :--- | :--- | :--- | :--- | :--- |
| `WadError::Overflow` | $a + b > 2^{127}-1$ or $(a \cdot b) / 10^{18} > 2^{127}-1$ | Large addition, multiplication exceeding max bounded `i128`, integer conversion $> 2^{127}-1$ | Returns `Err(WadError::Overflow)` immediately; halts arithmetic pipeline | `crates/wad18/tests/proptests.rs:test_addition_overflow_containment` |
| `WadError::Underflow` | $a + b < -2^{127}$ or $(a \cdot b) / 10^{18} < -2^{127}$ | Subtraction beyond negative bounds, negative product exceeding magnitude | Returns `Err(WadError::Underflow)` immediately; halts pipeline | `crates/wad18/tests/proptests.rs:test_addition_overflow_containment` |
| `WadError::DivisionByZero` | $b = 0$ in $a / b$ or denominator $= 0$ in fraction | Division or ratio construction with zero denominator | Returns `Err(WadError::DivisionByZero)`; zero division never executes | `crates/wad18/tests/proptests.rs:test_failure_matrix_coverage` |
| `WadError::InvalidScale` | $\text{Scale} \neq 10^{18}$ | Parsing or deserialization from non-normative precision | Returns `Err(WadError::InvalidScale)`; rejects alien scaling | `crates/wad18/tests/proptests.rs:test_failure_matrix_coverage` |
| `WadError::InvalidEncoding` | Non-numeric bytes, multiple decimal points, empty strings | Textual parsing of invalid formatted numbers (`"1.2.3"`, `"abc"`, `""`) | Returns `Err(WadError::InvalidEncoding)`; prevents malformed injection | `crates/wad18/tests/proptests.rs:test_failure_matrix_coverage` |
| `WadError::OutOfRange` | $x < \text{Min}$ or $x > \text{Max}$ | Epistemic confidence outside $[0, 1]$, risk bounds exceeded | Returns `Err(WadError::OutOfRange)`; halts gate | `crates/wad18/tests/proptests.rs:test_failure_matrix_coverage` |
| `WadError::InexactResult` | $(a \cdot b) \pmod{10^{18}} \neq 0$ or $(a \cdot 10^{18}) \pmod b \neq 0$ | Repeating fraction division ($1/3$), non-zero fractional digits beyond 18th place | Returns `Err(WadError::InexactResult)`; **silent rounding strictly forbidden** | `crates/wad18/tests/proptests.rs:test_inexact_multiplication_containment` |

---

## 2. SSI Kernel Invariant Evaluation Fault Matrix

| Invariant Clause | Requirement Checked | Failure Trigger | Fail-Closed Handling | Verified Evidence |
| :--- | :--- | :--- | :--- | :--- |
| `EmptyInvariantSet` | $\Phi \neq \emptyset$ | Attempting to initialize gateway with zero invariants | Rejects registry creation: `Err(KernelError::EmptyInvariantSet)` | `crates/ssi-kernel/tests/kernel_tests.rs:test_empty_invariant_set_fails_closed` |
| `InvariantUnknown` | $\text{Eval}(\varphi, X) \in \{1, 0, \bot\}$ | Timeout, unhandled exception, or indeterminate evaluation | Returns `is_valid = false`; $\bot \implies \text{FAIL}$ | `crates/ssi-kernel/tests/kernel_tests.rs:test_unknown_invariant_evaluates_to_fail` |
| `TypeValid` | Well-formed state components | Malformed digests ($\neq 64$ hex), epistemic confidence $> 1.0$ | Fails `TypeValid` clause, aborts gate | `crates/ssi-kernel/tests/kernel_tests.rs:test_epistemic_confidence_out_of_bounds_fails` |
| `KernelValid` | Immutable kernel state | Corrupted scaling constant or halted kernel mode | Fails `KernelValid` clause, trips quarantine | `crates/ssi-kernel/tests/kernel_tests.rs:test_kernel_halt_mode_blocks_evaluation` |
| `CSLValid` | Active containment barriers | `containment_active = false`, barrier breached, or quarantine | Fails `CSLValid` clause, halts tool dispatch | `crates/ssi-kernel/tests/kernel_tests.rs:test_quarantine_flag_fails_csl_clause` |
| `AuthValid` | Valid human signoff | Inactive token, expired epoch, clearance under-privilege | Fails `AuthValid` clause, denies permit | `crates/ssi-kernel/tests/kernel_tests.rs:test_valid_state_passes_global_invariant` |
| `SafetyValid` | Risk containment | $\text{RiskAssessment} > \text{RiskBound}$ or $\text{Margin} < \text{Bound}$ | Fails `SafetyValid` clause, denies permit | `crates/ssi-kernel/tests/kernel_tests.rs:test_risk_exceeding_bound_fails_safety_clause` |
| `ProvValid` | Cryptographic lineage | Non-monotonic sequence, invalid parent hash | Fails `ProvValid` clause, rejects transition | `crates/ssi-kernel/tests/kernel_tests.rs:test_valid_state_passes_global_invariant` |

---

## 3. Execution Gate PERMIT & Pipeline Fault Matrix

| Stage | Evaluated Predicate | Failure Condition | Fail-Closed Handling | Verified Evidence |
| :--- | :--- | :--- | :--- | :--- |
| **VERIFY** | `AUTH(X, a)` | Expired token, clearance under-privilege, missing token | Returns `GateDecision::Reject`; execution stops | `crates/ssi-gate/tests/gate_tests.rs:test_permit_rejects_insufficient_clearance` |
| **VERIFY** | `SAFE_ACTION(X, a)` | Risk exceeds envelope, forbidden keyword (`EXFILTRATE`, etc.) | Returns `GateDecision::Reject`; execution stops | `crates/ssi-gate/tests/gate_tests.rs:test_permit_rejects_forbidden_keyword` |
| **VERIFY** | `VER(X, a)` | Verification status `Unknown` or `Invalid`, cert invalid | Returns `GateDecision::Reject`; execution stops | `crates/ssi-gate/tests/gate_tests.rs:test_permit_fails_closed_on_unknown_verification` |
| **VERIFY** | `CAP(X, a)` | Insufficient cognitive budget, missing whitelisted capability | Returns `GateDecision::Reject`; execution stops | `crates/ssi-gate/tests/gate_tests.rs:test_permit_rejects_budget_overdraft` |
| **TRANSITION** | Sequence & Lineage | $t' \neq t + 1$ or $\text{ParentHash} \neq H(X)$ | Aborts with `GateError::TransitionViolation`; drops candidate | `crates/ssi-gate/tests/gate_tests.rs:test_pipeline_aborts_without_side_effects_on_permit_denial` |
| **INVARIANT_CHECK** | $I(X')$ | Candidate post-state fails any invariant in $\Phi$ | Aborts with `GateError::InvariantViolation`; **zero external effects** | `crates/ssi-gate/tests/gate_tests.rs:test_pipeline_executes_and_commits_successfully` |
| **COMMIT** | Atomic Commitment | Only reached if stages 1-4 pass | Emits `CommitRecord`; external sink unblocked | `crates/ssi-gate/tests/gate_tests.rs:test_pipeline_executes_and_commits_successfully` |

---

## 4. CSL & Ledger Tamper Fault Matrix

| Component | Security Invariant | Tamper / Breach Condition | Detection Mechanism | Verified Evidence |
| :--- | :--- | :--- | :--- | :--- |
| **CSL Envelope** | Ed25519 Authenticity | Forged signature $\Sigma$ or corrupted public key | `CSLEnvelope::verify_signature` returns `CslError::InvalidSignature` | `crates/ssi-csl/tests/csl_tests.rs:test_ed25519_forged_key_fails_verification` |
| **CSL Envelope** | Monotonic Budget | $\text{CumulativeCost} + \text{ActionCost} > \text{TotalLimit}$ | `verify_continuity` returns `CslError::TotalBudgetExceeded` | `crates/ssi-csl/tests/csl_tests.rs:test_csl_monotonic_budget_limit_exceeded_fails` |
| **Append-Only Ledger** | Hash Chain Linkage | Record $k$'s payload modified | Recomputed `record_hash` mismatch | `crates/ssi-ledger/tests/ledger_tests.rs:test_injected_tamper_detected_on_file_replay` |
| **Append-Only Ledger** | Sequence Continuity | Transition injected out of order ($t \to t+2$) | `SequenceDiscontinuity` error detected | `crates/ssi-ledger/tests/ledger_tests.rs:test_injected_tamper_detected_on_file_replay` |
| **Offline Replay CLI** | Replay Verification | Tampered NDJSON ledger file inspected | `replay_audit` prints `[AUDIT_FAIL]` and exits with code 1 | Verified via `replay_audit` integration test |
