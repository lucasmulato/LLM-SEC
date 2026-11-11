# Implementation Plan: LLM-SEC Formally Verified AI Execution Gateway

> **Author:** Lead Systems & Verification Engineer  
> **Status:** Proposal for Formal Review  
> **Reference Spec:** [`docs/REQUIREMENTS.md`](docs/REQUIREMENTS.md)  
> **Operational Rules:** [`AGENTS.md`](AGENTS.md)

---

## 1. Executive Summary & Architectural Vision

The objective of this project is to transition `LLM-SEC` from a research Python prototype into an industrial-grade, formally verified execution-gateway product for autonomous AI agents. The gateway stands between untrusted model outputs and external effectors (APIs, databases, financial systems), enforcing the normative **SSI Axiomatic System v1.0** with strict fail-closed semantics.

### Core Architectural Guarantees
1. **Zero Floating-Point in Normative Kernel:** Elimination of IEEE 754 non-determinism via a pure `WAD-18` fixed-point arithmetic engine verified across three independent compilation layers.
2. **Deterministic Gating Order:** Strict $\text{EXECUTE} \to \text{VERIFY} \to \text{TRANSITION} \to \text{INVARIANT\_CHECK} \to \text{COMMIT}$ pipeline where no external side effects can occur prior to atomic invariant commitment.
3. **Machine-Checked Verification:** Transition from unit-tested assertions (Level 1) to mechanically verified proofs (Level 3) utilizing TLA+/TLC model checking and Lean 4 arithmetic proofs.
4. **Adversarial Resilience:** A canonical 15-mutation engine verifying 100% detection rate ($15/15$) against deliberate axiomatic breaches.
5. **Continuous Governance:** Governed configuration evolution ($R^3$) with recursive non-regression guarantees ($\text{ADOPT}(Y)$) and independent Proof-Carrying Output (PCO) validation.

---

## 2. Target Repository Layout

To cleanly separate the immutable kernel $K$, mutable agent logic $M$, formal specifications, verification tools, and legacy differential oracles, the repository will be structured as follows:

```text
LLM-SEC/
├── .agents/
│   └── rules.md                       # Agent efficiency and quality rules
├── docs/
│   ├── REQUIREMENTS.md                # Normative specification (SSOT)
│   ├── CONFORMANCE.md                 # Live, honest conformance table (Levels 0-4)
│   ├── ARCHITECTURE.md                # System design and component boundaries
│   └── DOMAIN_PACKS.md                # Domain pack specifications (Real-Estate, etc.)
├── specs/
│   ├── tla/                           # Formal TLA+ specifications
│   │   ├── SSI_Kernel.tla             # State machine & transition semantics
│   │   ├── SSI_Kernel.cfg             # TLC model checker configuration
│   │   ├── CSL_Ledger.tla             # Authorization continuity & monotonicity
│   │   └── CSL_Ledger.cfg             # TLC configuration for ledger properties
│   └── lean/                          # Optional Lean 4 mechanized proofs
│       ├── Lakefile.lean
│       └── Wad18/
│           ├── Basic.lean             # i256 representation & exact scaling
│           └── Soundness.lean         # Proof of overflow & rounding safety
├── crates/                            # Production Rust Implementation
│   ├── wad18/                         # Zero-float 10^-18 fixed-point arithmetic crate
│   │   ├── Cargo.toml
│   │   └── src/lib.rs
│   ├── llmsec-core/                   # State tuple X, Invariants Φ, SSI predicate
│   │   ├── Cargo.toml
│   │   └── src/
│   ├── llmsec-gate/                   # 4-stage gating pipeline & permit evaluation
│   │   ├── Cargo.toml
│   │   └── src/
│   ├── llmsec-csl/                    # CSL authorization envelope & monotonic engine
│   │   ├── Cargo.toml
│   │   └── src/
│   ├── llmsec-ledger/                 # Append-only hash chain & canonical encoder
│   │   ├── Cargo.toml
│   │   └── src/
│   ├── llmsec-pco/                    # Proof-Carrying Output independent validator
│   │   ├── Cargo.toml
│   │   └── src/
│   └── llmsec-r3/                     # Governed evolution & ADOPT non-regression gate
│       ├── Cargo.toml
│       └── src/
├── tools/
│   ├── pure-wad18-lint/               # Layer 1: AST source scanner for float ban
│   ├── opcode-scan/                   # Layer 3: ELF/WASM opcode scanner
│   ├── mutation-engine/               # 15 canonical mutation testing suite
│   └── trace-validator/               # Runtime execution trace conformance verifier
├── domain-packs/
│   └── real-estate/                   # Real-estate underwriting execution gateway
│       ├── policies/                  # Underwriting rules, loan-to-value limits
│       └── tests/
├── tests/
│   ├── differential/                  # Rust vs Python cross-validation property tests
│   └── integration/                   # Full gateway end-to-end integration tests
├── core/                              # Preserved Python prototype (Differential Oracle)
├── Dockerfile                         # Hermetic reproducible build container
├── AGENTS.md                          # Mandatory agent operational rules
├── Cargo.toml                         # Workspace manifest
└── plan.md                            # This implementation roadmap
```

---

## 3. Four-Phase Implementation Roadmap

```
Phase 1: Rust Core & PURE WAD18 Pipeline (Weeks 1-3)
   │
   ▼
Phase 2: TLA+ Model Checking & Arithmetic Proofs (Weeks 4-5)
   │
   ▼
Phase 3: Mutation Engine, PCO Validator & R3 Adoption Gate (Weeks 6-7)
   │
   ▼
Phase 4: Domain Pack, Reproducibility Capsule & Release (Weeks 8-9)
```

---

### Phase 1: High-Assurance Rust Core & PURE WAD18 Pipeline

#### Objective
Implement the foundational kernel crates in Rust with zero floating-point representation, construct the 3-layer PURE WAD18 compiler/linter pipeline, and establish differential testing against the existing Python oracle.

#### Task Groups
- [x] **Task Group 1.1: `wad18` Fixed-Point Arithmetic Crate**
  - Implement $i256$-backed fixed-point arithmetic scaled by $10^{18}$.
  - Fail-closed checked operations for addition, subtraction, multiplication, division, and modulo.
  - Explicit panic/error types for overflow, underflow, division by zero, invalid scaling, and unrepresentable quotients.
  - Zero silent rounding; mathematically bounded half-up scaling with explicit remainder tracking.
  - *PO Mapping:* PO-2. *Status:* Complete. Verified in `crates/wad18/tests/proptests.rs`.
- [x] **Task Group 1.2: `ssi-kernel` State Tuple & Invariant Engine**
  - Implement typed discrete state $X = (\text{SI}, \text{VS}, \text{HG}, \text{AUTH\_STATE}, \text{VER\_STATE}, \text{PROV})$.
  - Construct invariant evaluation engine over explicit invariant set $\Phi = \{\varphi_1, \dots, \varphi_n\}$.
  - Enforce fail-closed rules: $\Phi = \emptyset \implies \text{FAIL}$; $\text{Unknown} \implies \text{FAIL}$.
  - Implement $\text{SSI}(X)$ evaluation returning structured evaluation verdicts.
  - *PO Mapping:* PO-1, PO-5. *Status:* Complete. Verified in `crates/ssi-kernel/tests/kernel_tests.rs`.
- [x] **Task Group 1.3: `ssi-gate` Minimal Verification Pipeline**
  - Implement $\text{PERMIT}(X, a) = \text{AUTH}(X, a) \land \text{SAFE\_ACTION}(X, a) \land \text{VER}(X, a) \land \text{CAP}(X, a)$.
  - Implement pure forward simulation for $\text{SAFE\_ACTION}(X, a) \iff \forall X': \text{Next}(X, a, X') \implies \text{VS}(X')$.
  - Implement strict 5-stage pipeline: $\text{EXECUTE} \to \text{VERIFY} \to \text{TRANSITION} \to \text{INVARIANT\_CHECK} \to \text{COMMIT}$.
  - Isolate side effects: external effects are gated behind atomic commit stage.
  - *PO Mapping:* PO-3, PO-4, PO-5. *Status:* Complete. Verified in `crates/ssi-gate/tests/gate_tests.rs`.
- [x] **Task Group 1.4: `ssi-csl` & `ssi-ledger`**
  - Implement $\text{CSL} = (\text{AuthId}, \Sigma, E, T, Q)$ with Ed25519 cryptographic signatures (audited `ed25519-dalek`).
  - Enforce monotonic risk and budget consumption during state transitions.
  - Implement canonical deterministic state encoding $\text{ENC}(X)$ conforming to RFC 8785 JSON Canonicalization.
  - Implement append-only cryptographic ledger with rolling SHA-256 hash chaining and offline `replay_audit` CLI tool.
  - *PO Mapping:* PO-6, PO-7, PO-9. *Status:* Complete. Verified in `crates/ssi-csl/tests/csl_tests.rs` and `crates/ssi-ledger/tests/ledger_tests.rs`.
- [x] **Task Group 1.5: PURE WAD18 3-Layer Pipeline**
  - **Layer 1 (Source Lint):** AST source scanner stripping comments and string literals, rejecting `f32`, `f64`, float/exponent literals, and float imports across all 26 workspace crate sources (`tools/pure_wad18/src/layer1_source.rs`).
  - **Layer 2 (Constrained Compilation):** Deterministic pinned compilation for float-free target `wasm32v1-none` (WebAssembly 2.0, zero OS/std, no hardware FP registers; `tools/pure_wad18/src/layer2_build.rs`).
  - **Layer 3 (Opcode Scanner):** WebAssembly bytecode inspection parsing Section 10 (`0x0a` Code Section) in `.rlib`/`.wasm` artifacts, asserting zero floating-point opcodes (`0x43`, `0x44`, `0x8b`..`0xbf`; `tools/pure_wad18/src/layer3_binary.rs`).
  - **Negative Controls:** 3/3 controls verified caught (NC-1 float literal, NC-2 f64 type signature, NC-3 float-enabled compiled crate; `tools/pure_wad18/src/negative_controls.rs`).
  - **Reports & CI:** Generated `reports/pure_wad18_report.md`, `reports/pure_wad18_report.json`, and added `.github/workflows/pure_wad18.yml`.
  - *PO Mapping:* PO-2. *Status:* Complete. Certified Conformance Level 2 (Reproducible).
- [x] **Task Group 1.6: Differential Testing Harness**
  - Cross-validation against Python oracle (`core/gate.py` and `core/kernel.py`).
  - 20/20 bit-identical decisions and sub-predicate match (100% equivalence).
  - *Status:* Complete. Report in `reports/differential_test_phase1b.md`.

#### Phase 1 Acceptance Criteria
1. `cargo test --workspace` passes with 100% test pass rate across all kernel crates.
2. Zero floating-point linter and binary opcode scanner execute in CI and pass with 0 warnings/errors.
3. 1,000,000 random differential property tests match between Python prototype and Rust core (or deviations documented as Python prototype bugs).
4. Any attempt to pass an empty invariant set $\Phi = \emptyset$ or unrepresentable WAD-18 quotient causes hard fail-closed abort.

#### Phase 1 Verification Checkpoint
- CI pipeline executes Layer 1 (lint), Layer 2 (no-std build), and Layer 3 (opcode scan), generating signed verification badge.

#### Phase 1 Definition of Done (DoD)
All Phase 1 crates implemented, documented, tested, and passing PURE WAD18 validation; differential oracle harness active; Conformance Table updated to Level 1 (Executable) with reproducible test outputs.

---

### Phase 2: Formal Model Checking & Mathematical Trace Conformance

#### Objective
Mechanically verify the core SSI state machine and permit gating semantics using TLA+/TLC, establish runtime trace conformance checking, and formalize WAD-18 arithmetic safety in Lean 4.

#### Task Groups
- [x] **Task Group 2.1: Formal TLA+ Specification**
  - Write `specs/tla/SSI_Kernel.tla` specifying typed state $X$, action proposals $a$, permit logic, and transition semantics.
  - Specify invariants:
    - `PermitSoundness`: $\neg\text{PERMIT}(X, a) \implies \neg\text{EXECUTE}(X, a)$
    - `InvariantPreservation`: $\text{Next}(X, a, X') \implies \text{VS}(X')$
    - `ContinuousAuthorization`: $\text{Expired}(CSL) \implies \neg\text{PERMIT}(X, a)$
    - `BudgetMonotonicity`: $X'.\text{Budget} \le X.\text{Budget}$
  - *PO Mapping:* PO-3, PO-4, PO-5.
- [x] **Task Group 2.2: TLC Model Checking Harness**
  - Construct finite-model configurations (`specs/tla/SSI_Kernel.cfg`, `SSI_Kernel_Large.cfg`) bounding state parameters.
  - Execute complete state space exploration with TLC (1,062,680 states generated, 37,182 distinct states).
  - Verify absence of deadlocks, unhandled states, or invariant violations.
  - Evaluate 3 negative controls (`Broken_Auth`, `Broken_Inv`, `Broken_Budget`) — all 3 caught with counterexamples.
  - *PO Mapping:* PO-3, PO-4, PO-5.
- [x] **Task Group 2.3: Runtime Trace Conformance Verifier**
  - Instrument `ssi-gate` to emit execution traces in canonical JSON format (`GateTrace`, `TraceStep`).
  - Write `tools/trace-validator` to replay gateway execution traces against TLA+ specification state steps via refinement mapping $\mathcal{M}$ (`specs/tla/TraceRefinement.md`).
  - Validated 1,000/1,000 sequential execution steps against TLA+ transition rules (857 permits, 143 verified rejections).
  - 6/6 Negative controls caught and rejected by validator.
  - *PO Mapping:* PO-5, PO-9.
- [ ] **Task Group 2.4: Lean 4 Fixed-Point Arithmetic Formalization (Optional / Tier 1)**
  - Write `specs/lean/Wad18/Basic.lean` defining bounded $i256$ fixed-point values.
  - Prove theorem `wad18_mul_bounds`: multiplication is either exact within bounds or returns `WadOverflowError`.
  - Prove theorem `wad18_zero_div`: division by zero strictly produces `WadDivisionByZeroError`.
  - Generate checkable Lean proof certificates.
  - *PO Mapping:* PO-2.

#### Phase 2 Acceptance Criteria
1. [x] TLC model checker verifies `SSI_Kernel.tla` without invariant violations across $\ge 500,000$ states (1,062,680 states checked).
2. [x] Trace conformance verifier validates 1,000 recorded execution traces from integration tests against TLA+ transition rules (1,000/1,000 verified).
3. [ ] Lean 4 theorem files compile without `sorry` axioms, proving arithmetic safety theorems (optional stretch).

#### Phase 2 Verification Checkpoint
- Mechanized proof artifacts committed under `specs/tla/` and validated by TLC in `reports/tlc_model_checking_report.md`.

#### Phase 2 Definition of Done (DoD)
TLA+ specifications and TLC configurations verified; trace validator passing on live Rust execution traces (1,000/1,000 steps); Conformance Table updated to Level 3 (Bounded Model Checking) for PO-3, PO-4, PO-5, PO-9.

---

### Phase 3: Adversarial Mutation Engine, PCO Validator & R3 Adoption Gate

#### Objective
Subject the gateway to an adversarial mutation engine with 15 canonical security mutations (requiring 15/15 detection), build the independent Proof-Carrying Output (PCO) validator, and implement governed model evolution ($R^3$).

#### Task Groups
- [x] **Task Group 3.1: 15 Canonical Mutation Attack Engine (Phase 3a)**
  - Implement automated test suite injecting 15 deliberate axiomatic violations via `tools/mutation_engine`:
    1. *MUT-01:* Treat Unknown verification as safe (PO-4) — caught by `gate_tests`.
    2. *MUT-02:* Treat empty invariant set as safe (PO-1, PO-5) — caught by `kernel_tests`.
    3. *MUT-03:* Ignore CSL revocation (PO-3) — caught by `csl_tests`.
    4. *MUT-04:* Execute on unknown verification result (PO-4) — caught by `gate_tests`.
    5. *MUT-05:* Check invariant AFTER commit (PO-5) — caught by `gate_tests`.
    6. *MUT-06:* Permit an untyped action (PO-1) — caught by `kernel_tests`.
    7. *MUT-07:* Silently round inexact multiplication (PO-2) — caught by `proptests`.
    8. *MUT-08:* Allow expired authorization (PO-3) — caught by `gate_tests`.
    9. *MUT-09:* Allow capability escalation (PO-3, PO-4) — caught by `gate_tests`.
    10. *MUT-10:* Ignore state binding of certificate (PO-6) — caught by `gate_tests`.
    11. *MUT-11:* Truncate wide product incorrectly (PO-2) — caught by `proptests`.
    12. *MUT-12:* Remove quotient range check (PO-2) — caught by `proptests`.
    13. *MUT-13:* Discard division remainder (PO-2) — caught by `proptests`.
    14. *MUT-14:* Lose result sign in multiplication (PO-2) — caught by `proptests`.
    15. *MUT-15:* Accept R3 adoption without kernel equality (PO-7, PO-8) — caught by `kernel_tests`.
  - Verified 15/15 mutants detected (100% catch rate). Output: `reports/mutation_report.md`.
  - CI gate established: `.github/workflows/mutation_engine.yml`.
  - *PO Mapping:* PO-1 through PO-9.
- [x] **Task Group 3.2: PCO (Proof-Carrying Output) Validator Module (Phase 3b)**
  - Implement `ssi-pco` crate per Avni et al. (IACR 2026/994) + SSI Axiomatic System Defs 12-14.
  - 10-Tuple Certificate $C = (\text{Spec}, \text{Policy}, \text{Code}, \text{Model}, \text{Input}, \text{Proof}, \text{Verifier}, \text{Assumptions}, \tau, \Sigma_C)$ with RFC 8785 canonical digest and $\text{BOUND}(C, X)$ exact state/config hash binding.
  - Process-isolated independent validator adapter trait (`IndependentValidator`, `ProcessIsolatedValidator`, `ToyDecidableComplianceValidator`) shelling out to external checker; fail-closed on unknown/timeout/crash.
  - Pre-action ledger commit: writes $(\text{Query}, \text{Spec}, \text{Output}, \text{ValidatorVer}, \tau, \text{ProofDigest})$ to append-only cryptographic hash chain before any external effect; only then PERMIT passes VER.
  - Revocation API (`RevocationRegistry`) invalidating compromised certificates/assets.
  - End-to-end demo binary (`crates/ssi-pco/src/bin/pco_demo.rs`) demonstrating nominal acceptance, forged proof rejection, state-rebound rejection, expired certificate rejection, and revoked certificate rejection.
  - *PO Mapping:* PO-4, PO-6.
- [x] **Task Group 3.3: $R^3(K, M, G)$ Governed Evolution & $\text{ADOPT}(Y)$ Gate (Phase 3c)**
  - Implement `ssi-r3` crate partitioning system into $(K, M, G)$ (SSI Defs 22-25, Theorem 6, §26).
  - Exact `KernelManifest` and `KernelEqual(Y)` byte comparison rejecting intent/similarity (PO-7).
  - Implement adoption predicate:
    $$\text{ADOPT}(Y) \iff \text{KernelEqual}(Y) \land \text{ProofValid}(Y) \land \text{AuthorizationValid}(Y) \land \text{NonRegression}(Y)$$
  - Non-regression engine runs the comprehensive invariant suite $\Phi$ + all 15 mutation checks on candidate $Y$:
    $$\forall \varphi \in \Phi: \varphi(X) = 1 \implies \varphi(Y) = 1$$
  - SACEvidence ledger recording for successful adoption and candidate quarantine with verified rollback for failures.
  - Fixed-point evolution harness demonstrating $R^3(X^*) = X^*$ with reproducible equality check (SSI §26).
  - *PO Mapping:* PO-7, PO-8.

#### Phase 3 Acceptance Criteria
1. [x] 15 Canonical Mutation Engine runs in CI and achieves a **100% detection score (15/15 caught)**.
2. [x] PCO validator operates out-of-process and successfully blocks simulated invalid proofs before external dispatch (all 5/5 demo scenarios & integration tests pass).
3. [x] $R^3$ adoption gate prevents adoption of mutated model configs that degrade safety invariants (MUT-15 rejected, compliant refinement adopted, unauthorized refinement rejected, rollback verified, fixed-point harness passed).

#### Phase 3 Verification Checkpoint
- Automated mutation testing report generated in CI verifying 15/15 catches; PCO independent validation logs verified.

#### Phase 3 Definition of Done (DoD)
Mutation engine passing 15/15; PCO validator crate operational; $R^3$ adoption gate enforcing non-regression; Conformance Table updated to Level 3 for PO-7, PO-8.

---

### Phase 4: Domain Pack, Reproducibility Capsule & v0.1.0 Release

#### Objective
Validate the gateway in a real-world high-stakes domain (Real-Estate Underwriting), construct a hermetic Docker reproducibility capsule, establish the live conformance documentation, and release `v0.1.0`.

#### Task Groups
- [x] **Task Group 4.1: Real-Estate Underwriting Domain Pack**
  - Implement `packs/real-estate/`.
  - Define normative WAD-18 financial metrics: Loan-to-Value (LTV), Debt-Service Coverage Ratio (DSCR), Net Operating Income (NOI).
  - Define formal underwriting invariants $\Phi_{\text{RE}}$ (e.g., $\text{LTV} \le 0.75 \cdot 10^{18}$, $\text{DSCR} \ge 1.25 \cdot 10^{18}$).
  - Implement CSL envelopes defining underwriter clearance tiers and loan size limits.
  - Demonstrate end-to-end PCO proof generation and append-only audit trail for loan approvals.
  - Red-team attack suite catching 6/6 malicious vectors fail-closed.
  - *PO Mapping:* PO-1 through PO-9.
- [x] **Task Group 4.2: Hermetic Reproducibility Capsule**
  - Construct standalone multi-stage `Dockerfile` pinning Rust toolchain, TLA+ tools, and system dependencies.
  - Unified automation via `Makefile` (`make verify`) and `scripts/verify.py` emitting `reports/verification_verdict.json`.
  - Verify deterministic cryptographic replay via `crates/ssi-ledger/src/bin/replay_audit.rs`.
  - *PO Mapping:* PO-9.
- [x] **Task Group 4.3: Product Documentation & Honest Conformance Table**
  - Author comprehensive `docs/CONFORMANCE.md` with explicit Level 0-4 ratings, proof artifacts, and verification evidence for every Proof Obligation.
  - Rewrite `README.md` to remove ungrounded claims and accurately reflect verified status.
  - Author `CHANGELOG.md` tracking transitions from v0.0.1 through formal v0.1.0 release.
- [x] **Task Group 4.4: v0.1.0 Release Tagging & Packaging**
  - `#![forbid(unsafe_code)]` enforced across all 7 kernel crates with zero exceptions.
  - Setup cargo-deny (`deny.toml`), fuzzing harness (`fuzz/`), and automated SBOM generator (`reports/sbom.json`).
  - CI matrix configured in `.github/workflows/ci.yml`.
  - Tag `v0.1.0` release.

#### Phase 4 Acceptance Criteria
1. [x] Real-Estate domain pack executes underwriting demo and 6 red-team attacks; all invariant-violating loan proposals are blocked fail-closed (10/10 tests pass).
2. [x] Reproducibility capsule and unified runner (`make verify`) reproduce verified verdict across all 8 stages.
3. [x] Conformance table in `docs/CONFORMANCE.md` is 100% complete, honest, and links directly to checked proof artifacts.
4. [x] Clean release packaging with zero outstanding compiler warnings, clippy lints, or test failures.

#### Phase 4 Verification Checkpoint
- Independent execution of `scripts/reproduce.sh` in clean VM reproduces identical hash and passes all tests and model checks.

#### Phase 4 Definition of Done (DoD)
All 4 phases complete; domain pack demonstrated; hermetic reproducibility capsule operational; v0.1.0 release tagged; Conformance Table fully verified at Level 3/4.

---

## 4. Proof Obligations (PO) Traceability Matrix

Every task and phase directly discharges one or more Proof Obligations:

| PO | Obligation Name | Phase 1 Verified Artifact (Level 1) | Phase 2 (TLA+ / Lean) | Phase 3 (Mutations / PCO) | Phase 4 (Domain / Capsule) | Current Conformance | Target Conformance |
| :---: | :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **PO-1** | Type Safety & Inhabitance | `crates/ssi-kernel/tests/kernel_tests.rs` (7 tests pass) | TG 2.1 | TG 3.1 (MUT-03, 04) | TG 4.1 | **Level 1** | **Level 3** |
| **PO-2** | WAD-18 Arithmetic Soundness | `crates/wad18/tests/proptests.rs` (7 proptests pass), `reports/pure_wad18_report.md` | TG 2.4 (Lean) | TG 3.1 (MUT-01, 12) | TG 4.1 | **Level 2** | **Level 3** |
| **PO-3** | Authorization Soundness ($\neg\text{AUTH}$) | `crates/ssi-gate/tests/gate_tests.rs`, `crates/ssi-csl/tests/csl_tests.rs`, `reports/differential_test_phase1b.md` | TG 2.1, 2.2 (`specs/tla/SSI_Kernel.tla`, `reports/tlc_model_checking_report.md`) | TG 3.1 (MUT-07, 11) | TG 4.1 | **Level 3** | **Level 3** |
| **PO-4** | Verification Soundness ($\neg\text{VER}$) | `crates/ssi-gate/tests/gate_tests.rs`, `reports/differential_test_phase1b.md` (20/20 oracle match) | TG 2.1, 2.2 (`specs/tla/SSI_Kernel.tla`, `reports/tlc_model_checking_report.md`) | TG 3.1, 3.2 (PCO) | TG 4.1 | **Level 3** | **Level 3** |
| **PO-5** | Invariant Preservation ($I(X')$) | `crates/ssi-gate/tests/gate_tests.rs`, `crates/ssi-kernel/tests/kernel_tests.rs` | TG 2.1, 2.2, 2.3 (`specs/tla/SSI_Kernel.tla`, `tools/trace-validator`) | TG 3.1 (MUT-09) | TG 4.1 | **Level 3** | **Level 3** |
| **PO-6** | Cryptographic Provenance Binding | `crates/ssi-ledger/tests/ledger_tests.rs`, `crates/ssi-csl/tests/csl_tests.rs`, `target/debug/replay_audit` | TG 2.1 | TG 3.1 (MUT-05, 06, 14), TG 3.2 (`crates/ssi-pco`) | TG 4.1 | **Level 1** | **Level 3** |
| **PO-7** | Safety Kernel Immutability | `crates/ssi-kernel/tests/kernel_tests.rs` | TG 2.1 | TG 3.1 (MUT-10, 15), TG 3.3 (`crates/ssi-r3`) | TG 4.2 | **Level 1** | **Level 3** |
| **PO-8** | Recursive Non-Regression ($R^3$) | `crates/ssi-r3/src/non_regression.rs`, `crates/ssi-r3/tests/r3_tests.rs` | TG 2.1 | TG 3.1 (MUT-13), TG 3.3 (`crates/ssi-r3`) | TG 4.1 | **Level 1** | **Level 3** |
| **PO-9** | Deterministic Reproducibility | `crates/ssi-ledger/tests/ledger_tests.rs`, `replay_audit` | TG 2.3 (`tools/trace-validator` 1,000 steps verified) | TG 3.1 (MUT-15) | TG 4.2 | **Level 3** | **Level 4** |

---

## 5. Technical Risk Management & Mitigation Matrix

| Risk ID | Risk Description | Severity | Likelihood | Mitigation Strategy |
| :---: | :--- | :---: | :---: | :--- |
| **R-01** | **Float leakage via third-party crates:** External dependencies pull in floating-point registers or math routines. | **Critical** | Medium | Compile with `no-std` and bare-metal target without SSE/FP features. Enforce Layer 3 binary opcode scanning in CI on every commit. |
| **R-02** | **State Space Explosion in TLC:** TLA+ model checking becomes computationally intractable for full state space. | **High** | Medium | Define finite symmetry sets and bounded domains in `SSI_Kernel.cfg`. Decouple arithmetic invariants to Lean 4, reserving TLA+ for control/concurrency flow. |
| **R-03** | **Performance overhead of 5-stage gating:** Serial verification and cryptographic hashing adds intolerable latency to tool execution. | **Medium** | Low | Optimize canonical hashing with hardware-accelerated SHA-256 instructions (`sha-ni`). Zero-copy serialization via deterministic binary encoding. Benchmark under 100 µs target per gate decision. |
| **R-04** | **Differential divergence between Rust & Python:** Edge-case differences in rounding or string parsing cause differential testing false positives. | **Medium** | High | Standardize exact canonical test vectors (`tests/fixtures/`) defining golden inputs and outputs. Update Python oracle to match formal WAD-18 spec. |
| **R-05** | **Side-effect leak before commit:** Tool handler inadvertently initiates network egress before the verification gate completes. | **Critical** | Low | Strict architectural isolation: tool handlers return execution descriptors / command objects, not direct effect execution. Sinks reside outside the gateway and only execute committed certificates. |

---

## 6. Gap Matrix: Existing Repository vs. Normative Product Target (Final Status)

| # | Spec Requirement | Initial Prototype Status | Final Product State (v0.1.0) | Verified Conformance | Status |
| :---: | :--- | :---: | :--- | :---: | :---: |
| 1 | $\text{SSI}(X)$ 6-Clause Predicate | Heuristic / Tested | Rust struct `SystemState` + TLA+ model `SSI_Kernel.tla` | Level 3 | ✅ CLOSED |
| 2 | Explicit Invariant Set $\Phi$ with Tri-State Fail | Heuristic | Generic invariant evaluator; $\Phi = \emptyset \implies \text{FAIL}$; $\bot \implies \text{FAIL}$ | Level 1 | ✅ CLOSED |
| 3 | $\text{PERMIT}(X,a) \implies \text{EXECUTE}$ | Tested (Python) | Memory-safe, non-bypassable Rust pipeline in `ssi-gate` | Level 3 | ✅ CLOSED |
| 4 | Pipeline Ordering & No Pre-Commit Side Effects | Defective | 5-stage pipeline; pure simulation; pre-action ledger commit | Level 1 | ✅ CLOSED |
| 5 | PURE WAD-18 Deterministic Arithmetic | Defective | Zero-float `wad18` crate + 3-layer verification scanner | Level 2 | ✅ CLOSED |
| 6 | CSL Envelope & Monotonic Revocation | Tested | Formally checked state machine in `ssi-csl` with Ed25519 sigs | Level 3 | ✅ CLOSED |
| 7 | System Partition $(K,M,G)$ & $R^3$ Adoption Gate | Missing | `ssi-r3` crate with non-regression & 15 mutation checks | Level 1 | ✅ CLOSED |
| 8 | 10-Tuple Certificate $C$ Bound to Exact State | Heuristic | Full 10-tuple cryptographic certificate with $\text{BOUND}(C, X)$ | Level 1 | ✅ CLOSED |
| 9 | Canonical State Encoding $\text{ENC}(X)$ | Heuristic | RFC 8785 canonical encoder in `ssi-ledger` | Level 1 | ✅ CLOSED |
| 10 | $\text{SAC}(X,C)$ Revocable Predicate | Missing | First-class SAC-1/2/3 evaluation predicate in `ssi-ledger` | Level 1 | ✅ CLOSED |
| 11 | PCO Independent Validator | Missing | Process-isolated validator in `ssi-pco` + pre-action commit | Level 1 | ✅ CLOSED |
| 12 | PURE WAD18 3-Layer Verification Toolchain | Missing | Pre-commit AST linter + opcode scanner CLI in `tools/pure_wad18` | Level 2 | ✅ CLOSED |
| 13 | 15 Canonical Mutation Attack Suite | Missing | Automated CI test harness catching 15/15 mutations (100%) | Level 1 | ✅ CLOSED |
| 14 | Proof Obligations PO-1..PO-9 | Tested (Level 1) | Machine-checked evidence matrix across TLC, proptests, tests | Level 2 / 3 | ✅ CLOSED |
| 15 | Conformance Matrix with Verified Evidence | Missing | Authoritative `docs/CONFORMANCE.md` citing proof artifacts | Level 2 | ✅ CLOSED |
