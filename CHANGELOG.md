# Changelog: LLM-SEC High-Assurance Execution Gateway

All notable changes to this project are documented in this file, conforming to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and adhering to the honest conformance hierarchy of [`AGENTS.md`](AGENTS.md).

---

## [0.1.0] - 2026-11-11

### Added
- **Normative SSI Axiomatic Engine (`crates/ssi-kernel`):**
  - Typed discrete state tuple $X = (\text{SI}, \text{VS}, \text{HG}, \text{AUTH\_STATE}, \text{VER\_STATE}, \text{PROV})$ (PO-1).
  - Explicit global invariant set $\Phi$; empty invariant set $\Phi = \emptyset$ resolves strictly to hard fail-closed abort ($\text{VS}(X) \equiv 0$).
  - Fail-closed tri-state resolution ($\mathbb{B}_3 = \{1, 0, \bot\}$); indeterminate states resolve to REJECT.
- **PURE WAD-18 Zero-Float Fixed-Point Arithmetic (`crates/wad18`, `tools/pure_wad18`):**
  - Pure integer-only 18-decimal fixed-point scaling ($10^{18}$) over 256-bit wide signed integers (PO-2).
  - 3-Layer float-freedom compiler barrier: Layer 1 source AST linter, Layer 2 bare-metal compilation (`wasm32v1-none`), Layer 3 binary opcode scanner.
  - 3/3 negative controls verified caught (float literal, float type, compiled FP opcode).
- **5-Stage Execution Gateway (`crates/ssi-gate`):**
  - Strict non-bypassable gating order: $\text{VERIFY} \to \text{TRANSITION} \to \text{INVARIANT\_CHECK} \to \text{COMMIT}$.
  - Strict isolation: zero side effects prior to atomic commit.
  - Composite PERMIT evaluation: $\text{PERMIT}(X, a) = \text{AUTH} \land \text{SAFE\_ACTION} \land \text{VER} \land \text{CAP}$.
- **Cryptographic Authorization & Monotonic Ledger (`crates/ssi-csl`, `crates/ssi-ledger`):**
  - Cognitive State Ledger (CSL) with Ed25519 digital signatures and monotonic budget/risk consumption (PO-3, PO-6).
  - RFC 8785 deterministic canonical JSON encoding ($\text{ENC}(X)$) and SHA-256 state hashing ($\text{ID}_X$).
  - Append-only hash chain with offline audit replay CLI (`replay_audit`).
- **TLA+ Formal Model Checking (`specs/tla/`):**
  - Complete state-machine specification `SSI_Kernel.tla` verified via TLC (depth 10, 172,020 states generated, 0 invariant breaches).
  - Runtime trace conformance verifier (`tools/trace-validator`) validating live gateway execution traces against TLA+ transition rules (1,000/1,000 steps verified).
- **15-Mutant Adversarial Attack Engine (`tools/mutation_engine`):**
  - Automated CI test harness executing 15 canonical security mutations against kernel code.
  - Achieved **100% detection score (15/15 caught)** with zero false negatives.
- **Proof-Carrying Output (PCO) Module (`crates/ssi-pco`):**
  - 10-Tuple formal certificate $C$ with exact $\text{BOUND}(C, X)$ state hash binding.
  - Process-isolated independent validator adapter trait with fail-closed semantics on crash/timeout.
  - Mandatory PRE-ACTION ledger seal committed before external side effects occur.
- **$R^3$ Governed Evolution Engine (`crates/ssi-r3`):**
  - Tripartite partitioning $(K, M, G)$ with byte-for-byte `KernelManifest` equality comparison (PO-7).
  - $\text{ADOPT}(Y)$ gate enforcing recursive non-regression over full invariant suite $\Phi$ + 15 mutation checks (PO-8).
- **Commercial Real-Estate Domain Pack (`packs/real-estate`):**
  - Formally specified $\Phi_{\text{RE}}$ invariants: statutory 75% LTV cap, 1.25× DSCR floor, jurisdiction whitelisting, mandatory disclosures, and dual human approval for high-value loans ($\ge \$1\text{M}$).
  - End-to-end autonomous underwriting demo and 6-vector adversarial red-team test suite (6/6 attacks rejected fail-closed).
- **Hardening & Reproducibility Capsule:**
  - Multi-stage `Dockerfile` pinning Rust, Java 21, TLC, and Python 3.11.
  - `Makefile` with `make verify` running full verification suite and emitting machine-readable verdict [`reports/verification_verdict.json`](reports/verification_verdict.json).
  - `#![forbid(unsafe_code)]` enforced across all 7 kernel crates with zero exceptions.
  - `deny.toml` configuration for `cargo-deny` and automated SBOM generation.

### Changed
- Preserved Python prototype under `core/` strictly as an executable differential reference oracle (PO-4).
- Promoted test conformance documentation to honest `docs/CONFORMANCE.md`, demoting unsubstantiated "formal proof" claims to Level 1 Executable or Level 3 Bounded Model Checking.

---

## [0.0.1] - 2026-10-05
- Initial Python prototype implementation with preliminary test suite.
