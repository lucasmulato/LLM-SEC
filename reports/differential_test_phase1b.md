# Phase 1b Differential Test Report: Python Oracle vs. Rust ssi-gate

> **Conformance Target:** PO-3, PO-4, PO-5 (Permit Soundness, Authorization Soundness, Verification Soundness)
> **Test Suite:** 20 shared scenarios evaluated across Python (`core/gate.py`) and Rust (`ssi-gate`)
> **Result:** **20/20 (100% Bit-Identical Verdicts)**

## Scenario Verification Matrix

| # | Scenario Name | Status | Python Decision | Rust Decision | Sub-predicates Match? |
| :-: | :--- | :-: | :-: | :-: | :-: |
| 1 | `nominal_pass` | **PASS** | `PERMIT` | `PERMIT` | Yes (AUTH=True, SAFE=True, VER=True, CAP=True) |
| 2 | `nominal_with_req_cap` | **PASS** | `PERMIT` | `PERMIT` | Yes (AUTH=True, SAFE=True, VER=True, CAP=True) |
| 3 | `auth_inactive` | **PASS** | `REJECT` | `REJECT` | Yes (AUTH=False, SAFE=True, VER=True, CAP=True) |
| 4 | `auth_expired` | **PASS** | `REJECT` | `REJECT` | Yes (AUTH=False, SAFE=True, VER=True, CAP=True) |
| 5 | `clearance_insufficient` | **PASS** | `REJECT` | `REJECT` | Yes (AUTH=False, SAFE=True, VER=True, CAP=True) |
| 6 | `empty_token` | **PASS** | `REJECT` | `REJECT` | Yes (AUTH=False, SAFE=True, VER=True, CAP=True) |
| 7 | `empty_nonce` | **PASS** | `REJECT` | `REJECT` | Yes (AUTH=False, SAFE=True, VER=True, CAP=True) |
| 8 | `containment_inactive` | **PASS** | `REJECT` | `REJECT` | Yes (AUTH=True, SAFE=False, VER=True, CAP=True) |
| 9 | `barrier_breached` | **PASS** | `REJECT` | `REJECT` | Yes (AUTH=True, SAFE=False, VER=True, CAP=True) |
| 10 | `quarantine_raised` | **PASS** | `REJECT` | `REJECT` | Yes (AUTH=True, SAFE=False, VER=True, CAP=True) |
| 11 | `emergency_halt_action` | **PASS** | `REJECT` | `REJECT` | Yes (AUTH=True, SAFE=False, VER=True, CAP=True) |
| 12 | `risk_exceeds_bound` | **PASS** | `REJECT` | `REJECT` | Yes (AUTH=True, SAFE=False, VER=True, CAP=True) |
| 13 | `forbidden_keyword_exfiltrate` | **PASS** | `REJECT` | `REJECT` | Yes (AUTH=True, SAFE=False, VER=True, CAP=True) |
| 14 | `forbidden_keyword_exfiltrate_payload` | **PASS** | `REJECT` | `REJECT` | Yes (AUTH=True, SAFE=False, VER=True, CAP=True) |
| 15 | `ver_unknown` | **PASS** | `REJECT` | `REJECT` | Yes (AUTH=True, SAFE=True, VER=False, CAP=True) |
| 16 | `ver_invalid` | **PASS** | `REJECT` | `REJECT` | Yes (AUTH=True, SAFE=True, VER=False, CAP=True) |
| 17 | `cert_marked_invalid` | **PASS** | `REJECT` | `REJECT` | Yes (AUTH=True, SAFE=True, VER=False, CAP=True) |
| 18 | `payload_digest_invalid_len` | **PASS** | `REJECT` | `REJECT` | Yes (AUTH=True, SAFE=True, VER=False, CAP=True) |
| 19 | `budget_overdraft` | **PASS** | `REJECT` | `REJECT` | Yes (AUTH=True, SAFE=True, VER=True, CAP=False) |
| 20 | `missing_capability` | **PASS** | `REJECT` | `REJECT` | Yes (AUTH=True, SAFE=True, VER=True, CAP=False) |

## Sub-predicate Conformance Summary
- **AUTH(X, a):** Exact match on active status, temporal expiry, and clearance level comparisons.
- **SAFE_ACTION(X, a):** Exact match on containment integrity, barrier integrity, risk bounds, and forbidden keywords.
- **VER(X, a):** Exact match on cryptographic digest length (64 hex), certificate validity flag, and tri-state fail-closed resolution (UNKNOWN ⇒ REJECT).
- **CAP(X, a):** Exact match on cognitive budget sufficiency and capability whitelist matching.
- **Fail-Closed Principle:** Verified across all 18 negative test scenarios with zero bypasses.
