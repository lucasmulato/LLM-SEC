# Quickstart — SSI Real-Estate Underwriting Pack

> **Narrow Superintelligence for Real Estate** (Russell 2026) — a fully gated, formally governed LLM-agent underwriting pipeline.

## Prerequisites

- Rust toolchain (stable ≥ 1.78)
- LLM-SEC workspace cloned at `~/Documents/projects/LLM-SEC`

## One-Command Run

```bash
cd packs/real-estate
bash run.sh
```

This runs three stages in sequence:

| Stage | Binary | Expected Outcome |
|-------|--------|-----------------|
| Demo | `re_demo` | 2 scenarios approved (Scenario 1: $750k / Scenario 2: $2.5M + dual approval) |
| Red-Team | `re_redteam` | 6/6 adversarial attacks caught and rejected |
| Tests | `re_tests` | 10/10 integration tests pass |

## Component Binaries

```bash
# Generate a signing key-pair and produce a signed CSL envelope
cargo run -p ssi-real-estate --bin csl_signer -- --help

# End-to-end demo (two loan scenarios)
cargo run -p ssi-real-estate --bin re_demo

# Adversarial red-team run (6 attack vectors)
cargo run -p ssi-real-estate --bin re_redteam
```

## Pipeline Stages (CSL → PERMIT → PCO → Ledger → COMMIT)

1. **CSL Verification** — Ed25519 signature on the signed underwriting envelope; temporal window and sequence-depth check.
2. **Φ_RE Invariant Evaluation** — WAD-18 LTV cap (75%), DSCR floor (1.25×), loan-size cap, jurisdiction whitelist, mandatory disclosures, dual-human-approval threshold.
3. **PCO Proof Validation** — `IndependentValidator.validate()` verifies the proof artifact; unknown/crash/timeout → hard failure.
4. **Pre-Action Ledger Commit** — `PcoLedger.commit_pre_action()` seals the commitment *before* any external effect (Avni et al. 2026/994, §PRE-ACTION).
5. **Gate PERMIT** — `evaluate_permit()` enforces AUTH ∧ SAFE_ACTION ∧ VER ∧ CAP; partial pass = REJECT.
6. **SAC-3 Ledger Append** — `AppendOnlyLedgerStore.append_transition()` seals the full state transition with Merkle chain.

## Conformance Summary

See [`docs/conformance_table.md`](conformance_table.md) for honest level claims per component.
