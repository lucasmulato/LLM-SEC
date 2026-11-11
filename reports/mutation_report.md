# Adversarial Mutation Testing Report (15 Canonical Mutations)

> **Target:** SSI Execution Gateway Kernel  
> **Tool:** `tools/mutation_engine` (Phase 3a)  
> **Score:** 15/15 Caught (100% Detection Rate)  
> **Date:** 2026-11-11  
> **Normative Reference:** [`docs/REQUIREMENTS.md`](../docs/REQUIREMENTS.md), [`plan.md`](../plan.md) Task Group 3.1

---

## 1. Conformance Scope & Honesty Statement

> [!IMPORTANT]
> **Honest Conformance Notice (AGENTS.md Rule 3):**  
> This mutation engine exercises a canonical set of 15 security-critical mutations targeting each axiomatic pillar of the SSI system.  
> **A finite mutation suite demonstrates resilience against known adversarial failure modes, but does NOT constitute an inductive mathematical proof of all arbitrary program mutations.**

---

## 2. Mutation Detection Matrix

| ID | Mutation Description | Target PO | Detector Mechanism | Verdict | Failure Evidence |
| :---: | :--- | :---: | :--- | :---: | :--- |
| **MUT-01** | Treat Unknown verification as safe | `PO-4` | `gate_tests::test_permit_fails_closed_on_unknown_verification` | **CAUGHT ✓** | `test test_permit_fails_closed_on_unknown_verification ... FAILED` |
| **MUT-02** | Treat empty invariant set as safe | `PO-1 / PO-5` | `kernel_tests::test_empty_invariant_set_fails_closed` | **CAUGHT ✓** | `test test_empty_invariant_set_fails_closed ... FAILED` |
| **MUT-03** | Ignore CSL revocation | `PO-3` | `csl_tests::test_csl_explicit_revocation_fails` | **CAUGHT ✓** | `test test_csl_explicit_revocation_fails ... FAILED` |
| **MUT-04** | Execute on unknown verification result | `PO-4` | `gate_tests::test_pipeline_aborts_on_unknown_verification` | **CAUGHT ✓** | `Test suite failed (exit non-zero)` |
| **MUT-05** | Check invariant AFTER commit (omit pre-commit check) | `PO-5` | `gate_tests::test_pipeline_aborts_when_candidate_violates_invariant` | **CAUGHT ✓** | `test test_pipeline_aborts_when_candidate_violates_invariant ... FAILED` |
| **MUT-06** | Permit an untyped action (bypass payload length check) | `PO-1` | `kernel_tests::test_untyped_action_fails_type_valid_clause` | **CAUGHT ✓** | `test test_untyped_action_fails_type_valid_clause ... FAILED` |
| **MUT-07** | Silently round inexact multiplication | `PO-2` | `proptests::test_inexact_multiplication_containment` | **CAUGHT ✓** | `test test_inexact_multiplication_containment ... FAILED` |
| **MUT-08** | Allow expired authorization | `PO-3` | `gate_tests::test_permit_rejects_expired_authorization` | **CAUGHT ✓** | `test test_permit_rejects_expired_authorization ... FAILED` |
| **MUT-09** | Allow capability escalation | `PO-3 / PO-4` | `gate_tests::test_permit_rejects_missing_capability` | **CAUGHT ✓** | `test test_permit_rejects_missing_capability ... FAILED` |
| **MUT-10** | Ignore state binding of certificate (parent state hash mismatch) | `PO-6` | `gate_tests::test_pipeline_rejects_broken_parent_state_hash` | **CAUGHT ✓** | `test test_pipeline_rejects_broken_parent_state_hash ... FAILED` |
| **MUT-11** | Truncate wide product incorrectly (truncate 256-bit product to 128-bit) | `PO-2` | `proptests::test_failure_matrix_coverage (Wide Overflow)` | **CAUGHT ✓** | `test test_failure_matrix_coverage ... FAILED` |
| **MUT-12** | Remove quotient range check in checked_div | `PO-2` | `proptests::test_failure_matrix_coverage (Quotient Range)` | **CAUGHT ✓** | `test test_failure_matrix_coverage ... FAILED` |
| **MUT-13** | Discard division remainder | `PO-2` | `proptests::test_failure_matrix_coverage (InexactResult)` | **CAUGHT ✓** | `test test_failure_matrix_coverage ... FAILED` |
| **MUT-14** | Lose result sign in multiplication | `PO-2` | `proptests::test_sign_laws_mul` | **CAUGHT ✓** | `test test_sign_laws_mul ... FAILED` |
| **MUT-15** | Accept R3 adoption without kernel equality | `PO-7 / PO-8` | `kernel_tests::test_r3_adoption_requires_kernel_equality` | **CAUGHT ✓** | `test test_r3_adoption_requires_kernel_equality ... FAILED` |

---

## 3. Summary & Acceptance Verdict

- Total Canonical Mutants Evaluated: **15**
- Mutants Caught (Fail-Closed Rejection): **15 / 15**
- Mutants Survived: **0**
- Mutation Score: **100.0%**
- CI Gate: **ACTIVE** (surviving mutant trips non-zero exit code)
