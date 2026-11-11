# Threat Model — SSI Real-Estate Underwriting Pack

## Security Boundaries

The SSI Real-Estate pack enforces **defense-in-depth** across six sequential gates. All gates fail-closed: `Unknown ≡ REJECT`.

```
┌─────────────────────────────────────────────────────────────────┐
│  TRUST BOUNDARY: Kernel + Signed CSL Envelope                   │
│                                                                 │
│  LLM Agent is UNTRUSTED — all outputs treated as adversarial.  │
│  Human authorizers sign CSL envelopes offline (air-gap capable) │
└─────────────────────────────────────────────────────────────────┘
```

## Attack Vectors & Mitigations

| # | Attack | Gate That Catches It | Evidence |
|---|--------|---------------------|---------|
| A1 | Expired CSL envelope | CSL temporal check (`is_valid_epoch`) | `re_redteam` Attack 1 ✓ |
| A2 | LTV cap overflow | Φ_RE invariant RE-1 | `re_redteam` Attack 2 ✓ |
| A3 | Forged / tampered PCO proof | `IndependentValidator.validate()` | `re_redteam` Attack 3 ✓ |
| A4 | Prompt-injected out-of-envelope action | CSL signature verification (mutated envelope invalidates sig) | `re_redteam` Attack 4 ✓ |
| A5 | High-value loan without dual approval | Φ_RE invariant RE-6 | `re_redteam` Attack 5 ✓ |
| A6 | Prohibited jurisdiction | Φ_RE invariant RE-4 | `re_redteam` Attack 6 ✓ |
| A7 | Forged underwriter signature | Ed25519 `verify_signature()` on CSL | `test_forged_underwriter_signature_rejected` ✓ |
| A8 | DSCR below floor | Φ_RE invariant RE-2 | `test_dscr_floor_breach_rejected` ✓ |
| A9 | Missing environmental disclosure | Φ_RE invariant RE-5 | `test_missing_environmental_disclosure_rejected` ✓ |
| A10 | PCO certificate bound to wrong state | `cert.check_bound(state)` (state_id mismatch) | PO-6 (ssi-pco test suite) ✓ |

## ASSUMPTIONS (In-Scope Preconditions)

> [!IMPORTANT]
> The following preconditions must hold for the security guarantees to apply. If they are violated, the system's guarantees do NOT extend to those dimensions.

1. **Human signers are trusted and uncompromised.** The Ed25519 signing key used to produce the CSL envelope is assumed to be in the exclusive possession of the authorized human underwriter. Key management, revocation, and HSM usage are out of scope.

2. **Rust host process is uncompromised.** The process isolation of `IndependentValidator` is only as strong as the OS process boundary. Kernel compromise of the host defeats all runtime enforcement.

3. **WAD-18 arithmetic is correctly specified.** The formal invariants (LTV cap, DSCR floor) are only as correct as their specification. This pack does not formally verify the correctness of financial domain thresholds — only their mechanical enforcement.

4. **Input authenticity.** The `LoanApplication` struct is assumed to have been populated from authenticated data sources (appraisal, rent roll, NOI). The gateway enforces invariants *over* the data but cannot verify the data's origin or completeness.

5. **Proof artifacts are semantically meaningful.** `ToyDecidableComplianceValidator` verifies proof format and cost bound, but does not check the mathematical derivation of the proof. A production deployment must substitute a verifier that checks the full proof.

## OUT-OF-SCOPE

> [!WARNING]
> The following are explicitly NOT guaranteed by this pack:

- **Specification correctness**: the formal domain thresholds (75% LTV, 1.25× DSCR) are taken from regulatory convention and not formally derived.
- **Non-kernel host compromise**: an attacker with root/kernel access to the host can bypass all runtime enforcement.
- **Input authenticity**: falsified appraisals, fabricated NOI figures, or fraudulent rent rolls are out of scope — the gateway enforces invariants over presented data.
- **Key management lifecycle**: revocation, rotation, HSM custody, and insider-threat scenarios for human signing keys are not addressed.
- **Completeness of invariant set**: the 6 Φ_RE invariants cover the principal risks identified in Russell 2026 §4.1 but do not claim exhaustive coverage of all real-estate lending risks.
- **Regulatory compliance**: this system is a research/prototype implementation and has not been validated against FIRREA, Basel III capital requirements, or state lending laws.

## Revocation Triggers

Revocation conditions mapped in `sac_mapping.rs`:

| Trigger | Action |
|---------|--------|
| WAD-18 arithmetic anomaly detected | Quarantine candidate, halt transitions |
| Jurisdiction constraint violated | Reject application, log to ledger |
| AML/KYC flag raised post-origination | Revoke certificate, freeze asset |
| Independent validator reports Unknown | Hard REJECT, escalate to human |
| Proof artifact expired (TTL exceeded) | REJECT, require fresh certificate |
