# LLM-SEC: Safe Super Intelligence (SSI) Axiomatic System v1.0

High-Assurance Security Architecture, Formal Verification, and Deterministic Gating for Autonomous AI Agents and Red-Teaming Systems.

---

## Overview

`LLM-SEC` is an axiomatic, fail-closed security and verification kernel designed to replace heuristic "LLM-as-a-judge" filters and loose text-matching guardrails with mathematically provable security boundaries. Built upon the **Safe Super Intelligence (SSI) Axiomatic System v1.0**, it provides:

1. **WAD-18 Deterministic Arithmetic (Axioms 1 & 2):** Exact \(10^{-18}\) integer-scaled normative arithmetic avoiding IEEE 754 non-determinism, with fail-closed bounds checking against overflow, underflow, and zero division.
2. **Typed Discrete System State (Definition 3):** Immutable state tuple \(X = (I, S, A, H, V, P)\) representing Intelligence, Safety, Action, Human Authorization, Verification, and Provenance.
3. **Immutable Safety Kernel \(K\) (Definition 15, Axiom 9):** Tamper-proof execution boundary with non-negotiable arithmetic semantics, invariant enforcement, and emergency quarantine/halt triggers.
4. **Execution Permit Gate \(\text{PERMIT}(X, a)\) (Definition 11, Axiom A2):** Strict four-predicate gating (\(\text{AUTH} \land \text{SAFE\_ACTION} \land \text{VER} \land \text{CAP}\)) ensuring that unpermitted actions are never dispatched.
5. **Continuous Authorization & Cognitive State Ledger (CSL) (Definitions 6 & 16, Axiom 10):** Cryptographically signed operational envelopes \(\text{CSL} = (\text{AuthId}, \Sigma, E, T, Q)\) with monotonic revocation if time, risk, or budget bounds are exceeded.
6. **Append-Only Trace Storage & SAC Evidence:** Cryptographic hash-chained audit logging emitting machine-checkable Safety Asset Class (`SAC-1`, `SAC-2`, `SAC-3`) evidence objects.

---

## Core Architecture

```
                          Autonomous Action Proposal (a)
                                       │
                                       ▼
                     ┌───────────────────────────────────┐
                     │     CSL Envelope Check (Axiom 10) │
                     │   T (Time), E (Risk), Q (Rules)   │
                     └─────────────────┬─────────────────┘
                                       │
                                       ▼
                     ┌───────────────────────────────────┐
                     │    PERMIT(X, a) Gate (Def 11)     │
                     │  AUTH ∧ SAFE_ACTION ∧ VER ∧ CAP   │
                     └─────────────────┬─────────────────┘
                                       │ [Axiom A2: NOT PERMIT => REJECT]
                                       ▼
                     ┌───────────────────────────────────┐
                     │    EXECUTE (Controlled Sandbox)   │
                     └─────────────────┬─────────────────┘
                                       │
                                       ▼
                     ┌───────────────────────────────────┐
                     │  VERIFY & Bind Certificate (Def 29)│
                     └─────────────────┬─────────────────┘
                                       │
                                       ▼
                     ┌───────────────────────────────────┐
                     │ Transition Check: I(X') (Thm 3)   │
                     └─────────────────┬─────────────────┘
                                       │
                                       ▼
                     ┌───────────────────────────────────┐
                     │ COMMIT & Append SAC Evidence Log  │
                     └───────────────────────────────────┘
```

### Module Reference

- [`core/kernel.py`](core/kernel.py):
  - `NormativeValue`: WAD-18 fixed-point arithmetic (`WAD_SCALE = 10**18`).
  - `SystemState`: 6-tuple \(X = (I, S, A, H, V, P)\) with canonical state hashing \(H(X)\).
  - `SafetyKernel`: Immutable kernel with global invariant evaluation \(\mathcal{I}(X)\) across Kernel Integrity (KI), Type Validity (TV), CSL Validity, Authorization Validity (AV), Safety Invariant Validity (SIV), and Provenance Validity (PV).
- [`core/gate.py`](core/gate.py):
  - `evaluate_permit()`: Computes \(\text{PERMIT}(X, a)\).
  - `validate_transition()`: Validates sequence monotonicity, parent lineage, budget conservation, and \(\mathcal{I}(X')\) preservation.
  - `DeterministicExecutionGate`: 4-stage pipeline `EXECUTE -> VERIFY -> INVARIANT CHECK -> COMMIT`.
  - `FailClosedGuardrailGate`: High-level security gate for autonomous tools and red-teaming scanners.
- [`core/ledger.py`](core/ledger.py):
  - `CSLEnvelope`: Cryptographically signed authorization envelope \((\text{AuthId}, \Sigma, E, T, Q)\).
  - `verify_authorization_continuity()`: Continuous enforcement of Axiom 10.
  - `canonical_encode_state()` & `compute_state_id()`: Deterministic encoding \(\text{ENC}(X)\) and \(\text{ID}_X = H(\text{ENC}(X))\).
  - `AppendOnlyLedgerStore`: Rolling SHA-256 chained audit storage producing `SACEvidence`.
- [`core/vector_guard.py`](core/vector_guard.py) & [`core/evaluator.py`](core/evaluator.py):
  - Strict WAD-18 normative metrics replacing loose floating-point guardrails.

---

## Formal Proof Obligations (Section 34)

The test suite in [`tests/test_axioms.py`](tests/test_axioms.py) provides machine-checked verification of Core Proof Obligations **PO-1 through PO-9**:

| Obligation | Axiom / Definition | Description | Status |
| :--- | :--- | :--- | :---: |
| **PO-1** | Definition 3 | Type Safety & State Space Inhabitance | **Verified** |
| **PO-2** | Axioms 1 & 2 | WAD-18 Bounded Deterministic Arithmetic & Overflow Containment | **Verified** |
| **PO-3** | Definition 15, Axiom 9 | Safety Kernel Immutability & Supremacy | **Verified** |
| **PO-4** | Definition 11, Axiom A2 | Permit Soundness: \(\neg \text{PERMIT}(X, a) \implies \neg \text{EXECUTE}(X, a)\) | **Verified** |
| **PO-5** | Axiom 10 | Continuous Authorization & Monotonic Envelope Revocation | **Verified** |
| **PO-6** | Theorem 3, Definition 19 | Global System Invariant Preservation \(\mathcal{I}(X')\) | **Verified** |
| **PO-7** | Section 5, Axiom 4 | Fail-Closed Emergency Quarantine on Indeterminate/Crashing State | **Verified** |
| **PO-8** | Definitions 13, 14, 29 | Cryptographic Lineage Binding & Provenance Hash Chain | **Verified** |
| **PO-9** | Section 34.9 | Deterministic Reproducibility & Audit Replay Consistency | **Verified** |

---

## Quickstart & Verification

### Running the Test Suite

All tests execute via the standard Python 3 `unittest` runner:

```bash
# Run formal Proof Obligations PO-1 through PO-9
python3 -m unittest tests/test_axioms.py

# Run kernel, gate, and ledger verification tests
python3 -m unittest tests/test_kernel.py tests/test_gate.py tests/test_ledger.py

# Run complete repository test suite (100+ tests)
python3 -m unittest discover tests
```

### Installation

Requires Python 3.11+. The core axiomatic modules require **zero third-party dependencies**, utilizing pure Python standard library primitives:

```bash
git clone https://github.com/lucasmulato/llm-sec.git
cd llm-sec
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Local Defensive CLI & MCP Server

```bash
# Local defensive PII inspection
llmsec scan 'fixture@example.test' --regex-only --json

# Run document inspection through normative vector guard
llmsec inspect-document 'sample.txt' --json

# Run standard health validation
llmsec health

# Run local MCP stdio server
llmsec-mcp
```
