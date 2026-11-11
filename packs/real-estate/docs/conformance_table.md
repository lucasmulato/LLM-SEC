# Conformance Table — SSI Real-Estate Underwriting Pack

> **Conformance Levels** (per AGENTS.md Rule 3 / docs/CONFORMANCE.md):
>
> - **CONF-0** Specification only (no executable artifact)
> - **CONF-1** Executable tests (unit / integration / property tests)
> - **CONF-2** Property-Based Testing (randomized, QuickCheck/Proptest)
> - **CONF-3** Bounded Model Checking (TLC, depth-bounded)
> - **CONF-4** Full Formal Proof (Lean 4 / Coq proof object, complete state space)

> [!WARNING]
> No component in this pack currently claims CONF-4. All conformance claims are **CONF-1 (executable)** unless explicitly noted otherwise.

## Component Conformance

| Component | Description | Conformance Level | Evidence Artifact | PO Coverage |
|-----------|-------------|-------------------|-------------------|-------------|
| `invariants::verify_real_estate_invariants` | Φ_RE: LTV, DSCR, loan cap, jurisdiction, disclosures, dual approval | **CONF-1** (10 integration tests) | `tests/re_tests.rs` | PO-2, PO-3, PO-4, PO-5 |
| `pipeline::evaluate_loan_proposal` | 5-stage CSL→PERMIT→PCO→Ledger→COMMIT pipeline | **CONF-1** (integration tests + binaries) | `tests/re_tests.rs`, `re_demo`, `re_redteam` | PO-3, PO-4, PO-5, PO-6 |
| `csl_preset::create_underwriting_csl_envelope` | Signed CSL envelope with Ed25519, temporal window, tier-dependent constraints | **CONF-1** (integration tests) | `tests/re_tests.rs` | PO-3 |
| WAD-18 arithmetic (LTV / DSCR computation) | Fixed-point 18-decimal arithmetic, overflow bounds | **CONF-1** (arithmetic in `wad18` crate tests) | `crates/wad18/tests/` | PO-2 |
| `DualHumanApproval` Ed25519 verification | Two-party cryptographic approval for high-value actions | **CONF-1** (test: dual approval success + missing rejection) | `tests/re_tests.rs` | PO-3 |
| `IndependentValidator` interface | Out-of-process proof isolation; crash/unknown → REJECT | **CONF-1** (forged proof test, crash semantics in ssi-pco) | `tests/re_tests.rs`, `crates/ssi-pco/tests/` | PO-4 |
| `PcoLedger::commit_pre_action` | Pre-action ledger seal (Avni et al. 2026/994, §PRE-ACTION) | **CONF-1** (ssi-pco integration tests) | `crates/ssi-pco/tests/` | PO-6 |
| `AppendOnlyLedgerStore` SAC-3 chain | Merkle append-only ledger with state_id chain | **CONF-1** (ssi-ledger tests) | `crates/ssi-ledger/tests/` | PO-6, PO-9 |
| TLA+ specification (SSI kernel protocol) | Formal model of PERMIT, Inv(X), T1/T3/T5/C1 | **CONF-3** (TLC bounded model checking, depth 10) | `specs/tla/`, `reports/tlc_results.md` | PO-1 through PO-5 |
| Mutation testing (15 mutants) | Fail-closed detection of kernel logic mutations | **CONF-1** (15/15 detected, CI gate) | `reports/mutation_report.md` | PO-5, PO-7 |
| R3 adoption gate (kernel equality) | ADOPT = KernelEqual ∧ ProofValid ∧ AuthorizationValid ∧ NonRegression | **CONF-1** (ssi-r3 integration tests) | `crates/ssi-r3/tests/` | PO-7, PO-8 |

## Red-Team Attack Coverage

| Attack | Vector | Gate | Result |
|--------|--------|------|--------|
| A1 | Expired CSL (epoch 50,000 > valid_until 10,000) | CSL temporal check | ✅ REJECTED |
| A2 | LTV 82% > 75% cap | Φ_RE invariant RE-1 | ✅ REJECTED |
| A3 | Forged proof artifact | PCO independent validator | ✅ REJECTED |
| A4 | Prompt-injected action (modified CSL envelope) | Ed25519 signature check | ✅ REJECTED |
| A5 | \$2.5M loan without dual approval | Φ_RE invariant RE-6 | ✅ REJECTED |
| A6 | Prohibited jurisdiction (US-XX) | Φ_RE invariant RE-4 | ✅ REJECTED |

**All 6 red-team attacks caught. 0 false negatives.**

## Proof Obligation Mapping

| PO | Description | Phase 4a Evidence |
|----|-------------|------------------|
| PO-1 | Type Safety & State Inhabitance | Rust type system (compile-time) |
| PO-2 | WAD-18 Arithmetic Soundness | wad18 crate + RE invariant tests |
| PO-3 | Authorization Soundness (¬AUTH ⇒ ¬EXECUTE) | CSL + dual-approval + PERMIT gate tests |
| PO-4 | Verification Soundness (¬VER ⇒ ¬EXECUTE) | IndependentValidator + forged proof test |
| PO-5 | Invariant Preservation | Φ_RE: 10 integration tests (CONF-1) |
| PO-6 | Cryptographic Lineage & State Identification | PcoLedger pre-action + SAC-3 chain |
| PO-7 | Safety Kernel Immutability | R3 adoption gate (ssi-r3 crate) |
| PO-8 | Recursive Non-Regression | Mutation test suite 15/15 |
| PO-9 | Deterministic Reproducibility | Merkle state chain + `run.sh` one-command |

> [!NOTE]
> Conformance levels for PO-5 and PO-3/4 are **CONF-1** (executable tests) for this pack. The TLA+ spec (Phase 2) provides **CONF-3** (bounded model checking) for the core kernel protocol. No CONF-4 claims are made for this pack.
