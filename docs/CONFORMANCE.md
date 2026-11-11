# Conformance Specification & Evidence Matrix: LLM-SEC Gateway

> **Status:** Authoritative Conformance Register (SSOT)  
> **Release Target:** `v0.1.0`  
> **Overall Certified Conformance:** **Level 2 (Reproducible)**  
> **Core Protocol Model Checking:** **Level 3 (Bounded Model Checking)**  
> **Governance Authority:** [`AGENTS.md`](../AGENTS.md) Rule 3 (Honest Conformance Discipline)

---

## 1. Conformance Hierarchy & Standards

All claims of safety, soundness, and verification in `LLM-SEC` adhere strictly to the normative 5-tier conformance hierarchy defined in [`docs/REQUIREMENTS.md`](REQUIREMENTS.md#L45-L57). Claims of "proven" or "verified" without machine-checked artifacts are strictly forbidden.

| Level | Code | Name | Formal Criterion | Status in LLM-SEC |
| :---: | :---: | :--- | :--- | :--- |
| **0** | `CONF-0` | **Defined** | Normative specification with formal mathematical equations. | Complete ([`docs/REQUIREMENTS.md`](REQUIREMENTS.md)) |
| **1** | `CONF-1` | **Executable** | Deterministic software passing comprehensive test suites. | Complete (100% pass across all 7 crates + packs) |
| **2** | `CONF-2` | **Reproducible** | Bit-for-bit deterministic reproduction across platforms via hermetic capsule. | **Certified Overall Level** (`Dockerfile`, `make verify`) |
| **3** | `CONF-3` | **Bounded Model Checked** | Machine-checked state space exploration via independent proof/model checker. | Certified for Core Protocol (TLC, depth 10, 172,020 states) |
| **4** | `CONF-4` | **Operationally Certified** | Continuous multi-organization mathematical audit with zero unverified assumptions. | Planned future target (No claims made in v0.1.0) |

---

## 2. Proof Obligations (PO-1 through PO-9) Evidence Matrix

Every pull request and release in `LLM-SEC` maps directly to the nine fundamental Proof Obligations:

| PO | Name | Formal Invariant | Verified Conformance | Primary Verification Artifact |
| :---: | :--- | :--- | :---: | :--- |
| **PO-1** | **Type Safety & Inhabitance** | $\forall X \in \mathcal{S}: X \in \text{Type}(\text{SystemState}) \land \text{WellFormed}(X)$ | **Level 1** *(Executable)* | Compile-time Rust type system + [`crates/ssi-kernel/tests/kernel_tests.rs`](../crates/ssi-kernel/tests/kernel_tests.rs) |
| **PO-2** | **WAD-18 Arithmetic Soundness** | $\forall a, b \in \text{WAD18}: a \circ b \text{ exact or trips fail-closed error}$ | **Level 2** *(Reproducible)* | PURE WAD18 3-Layer Certification ([`reports/pure_wad18_report.md`](../reports/pure_wad18_report.md)) + [`crates/wad18/tests/proptests.rs`](../crates/wad18/tests/proptests.rs) |
| **PO-3** | **Authorization Soundness** | $\neg \text{AUTH}(X, a) \implies \neg \text{EXECUTE}(X, a)$ | **Level 3** *(Bounded Model Checking)* | TLC Model Checker ([`specs/tla/SSI_Kernel.tla`](../specs/tla/SSI_Kernel.tla), 172,020 states, depth 10) + Negative Controls |
| **PO-4** | **Verification Soundness** | $\neg \text{VER}(X, a) \implies \neg \text{EXECUTE}(X, a)$ | **Level 3** *(Bounded Model Checking)* | TLC Model Checker (`SSI_Kernel.tla`) + [`crates/ssi-pco/src/validator.rs`](../crates/ssi-pco/src/validator.rs) |
| **PO-5** | **Invariant Preservation** | $\text{Inv}(X) \land \text{PERMIT}(X, a) \land \text{Next}(X, a, X') \implies \text{Inv}(X')$ | **Level 3** *(Bounded Model Checking)* | TLC Inductive Invariant Check + [`tools/trace-validator`](../tools/trace-validator) (1,000 steps verified) |
| **PO-6** | **Cryptographic Lineage Binding** | $\text{ID}_{X'} = H(\text{ENC}(X')) \land \text{BOUND}(C, X)$ | **Level 1** *(Executable)* | RFC 8785 Canonical Encoding + [`crates/ssi-ledger/tests/ledger_tests.rs`](../crates/ssi-ledger/tests/ledger_tests.rs) + Pre-Action Ledger Commit |
| **PO-7** | **Safety Kernel Immutability** | $R^3(K, M, G) = (K', M', G') \implies K' = K$ | **Level 1** *(Executable)* | `KernelManifest` exact byte comparison + MUT-15 check ([`crates/ssi-r3/tests/r3_tests.rs`](../crates/ssi-r3/tests/r3_tests.rs)) |
| **PO-8** | **Recursive Non-Regression** | $\text{ADOPT}(Y) \implies (\forall \varphi \in \Phi: \varphi(X) = 1 \implies \varphi(Y) = 1)$ | **Level 1** *(Executable)* | Comprehensive invariant suite $\Phi$ + 15 mutation checks on candidate ([`crates/ssi-r3/src/non_regression.rs`](../crates/ssi-r3/src/non_regression.rs)) |
| **PO-9** | **Deterministic Reproducibility** | $\forall \text{trace}: \text{Replay}(\text{trace}) \implies \text{Hash}(X_t) = \text{ExpectedHash}$ | **Level 2** *(Reproducible)* | Hermetic `Dockerfile` + `make verify` + [`crates/ssi-ledger/src/bin/replay_audit.rs`](../crates/ssi-ledger/src/bin/replay_audit.rs) |

---

## 3. Adversarial Hardening: 15-Mutant Security Engine

The gateway was subjected to deliberate axiomatic attacks across 15 canonical fault vectors. All 15 mutants were detected and rejected fail-closed (**100% detection rate**):

| Mutant ID | Description | Targeted Obligation | Detector / Evidence | Result |
| :---: | :--- | :---: | :--- | :---: |
| **MUT-01** | Treat Unknown verification as safe | PO-4 | `gate_tests::test_permit_fails_closed_on_unknown_verification` | ✅ CAUGHT |
| **MUT-02** | Treat empty invariant set as safe | PO-1, PO-5 | `kernel_tests::test_empty_invariant_set_fails_closed` | ✅ CAUGHT |
| **MUT-03** | Ignore CSL revocation | PO-3 | `csl_tests::test_csl_explicit_revocation_fails` | ✅ CAUGHT |
| **MUT-04** | Execute on unknown verification result | PO-4 | `gate_tests::test_pipeline_aborts_on_unknown_verification` | ✅ CAUGHT |
| **MUT-05** | Check invariant AFTER commit | PO-5 | `gate_tests::test_pipeline_aborts_when_candidate_violates_invariant` | ✅ CAUGHT |
| **MUT-06** | Permit an untyped action | PO-1 | `kernel_tests::test_untyped_action_fails_type_valid_clause` | ✅ CAUGHT |
| **MUT-07** | Silently round inexact multiplication | PO-2 | `proptests::test_inexact_multiplication_containment` | ✅ CAUGHT |
| **MUT-08** | Allow expired authorization | PO-3 | `gate_tests::test_permit_rejects_expired_authorization` | ✅ CAUGHT |
| **MUT-09** | Allow capability escalation | PO-3, PO-4 | `gate_tests::test_permit_rejects_missing_capability` | ✅ CAUGHT |
| **MUT-10** | Ignore state binding of certificate | PO-6 | `gate_tests::test_pipeline_rejects_broken_parent_state_hash` | ✅ CAUGHT |
| **MUT-11** | Truncate wide product incorrectly | PO-2 | `proptests::test_failure_matrix_coverage` (Wide Overflow) | ✅ CAUGHT |
| **MUT-12** | Remove quotient range check | PO-2 | `proptests::test_failure_matrix_coverage` (Quotient Range) | ✅ CAUGHT |
| **MUT-13** | Discard division remainder | PO-2 | `proptests::test_failure_matrix_coverage` (InexactResult) | ✅ CAUGHT |
| **MUT-14** | Lose result sign in multiplication | PO-2 | `proptests::test_sign_laws_mul` | ✅ CAUGHT |
| **MUT-15** | Accept R3 adoption without kernel equality | PO-7, PO-8 | `kernel_tests::test_r3_adoption_requires_kernel_equality` | ✅ CAUGHT |

Full audit log available at [`reports/mutation_report.md`](../reports/mutation_report.md).

---

## 4. Known Limitations & Out-of-Scope Preconditions

In accordance with honest engineering principles, the guarantees of `v0.1.0` are bounded by the following explicit limitations:

1. **Host Boundary:** Process isolation of external validators depends on OS process boundary integrity. Compromise of the host kernel is out of scope.
2. **Model Checking Bounds:** TLA+ verification was conducted via bounded model checking (TLC to depth 10, 172,020 explored states). It proves absence of deadlocks and safety invariant preservation within the bounded configuration domain, but is not an unbounded inductive pencil-and-paper proof.
3. **Domain Specification Correctness:** Financial thresholds in the Real-Estate pack (e.g. 75% LTV) are derived from regulatory convention. The gateway guarantees their mechanical enforcement, but does not prove their economic optimality.
4. **Input Authenticity:** The gateway verifies that presented inputs satisfy all formal safety constraints; verifying the external real-world truth of appraisal data is out of scope.
