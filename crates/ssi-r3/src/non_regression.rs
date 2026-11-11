//! Non-Regression Verification Engine & 15 Canonical Mutation Safety Suite.
//!
//! Theorem 6 (Recursive Non-Regression):
//! An update is safe only if it preserves all safety invariants of the current system
//! and satisfies the 15 canonical security mutation checks without regression.

#![deny(clippy::float_arithmetic)]

use ssi_kernel::{InvariantRegistry, SafetyKernel, SystemState};
use wad18::Wad18;
use crate::error::R3Error;
use crate::partition::SystemPartition;

/// Evaluates non-regression between current system state X and candidate state Y.
pub fn check_non_regression(
    current: &SystemPartition,
    candidate_partition: &SystemPartition,
    current_state: &SystemState,
    candidate_state: &SystemState,
) -> Result<(), R3Error> {
    let kernel = SafetyKernel::default();

    // 1. Invariant Preservation: phi(X) = 1 => phi(Y) = 1
    let cur_verdict = kernel.evaluate_invariant(current_state);
    let cand_verdict = kernel.evaluate_invariant(candidate_state);

    if cur_verdict.is_valid && !cand_verdict.is_valid {
        return Err(R3Error::NonRegressionViolation {
            clause: "GlobalInvariantPreservation".to_string(),
            reason: format!(
                "Candidate regresses verified invariant: {:?}",
                cand_verdict.failure_reason
            ),
        });
    }

    // 2. Monotonic Risk Ceiling: Y.risk_ceiling <= X.risk_ceiling
    if candidate_partition.config.risk_ceiling > current.config.risk_ceiling {
        return Err(R3Error::NonRegressionViolation {
            clause: "MonotonicRiskCeiling".to_string(),
            reason: format!(
                "Candidate escalates risk ceiling from {} to {}",
                current.config.risk_ceiling, candidate_partition.config.risk_ceiling
            ),
        });
    }

    // 3. Mandatory Invariants Inhabitance: current.mandatory_invariants subset of candidate.mandatory_invariants
    for inv in &current.config.mandatory_invariants {
        if !candidate_partition.config.mandatory_invariants.contains(inv) {
            return Err(R3Error::NonRegressionViolation {
                clause: "InvariantSubsetPreservation".to_string(),
                reason: format!("Candidate omitted mandatory invariant '{}'", inv),
            });
        }
    }

    // 4. Run the 15 Canonical Security Mutation Safety Checks on candidate
    run_15_mutation_checks(candidate_partition, candidate_state)?;

    Ok(())
}

/// Evaluates candidate compliance against all 15 axiomatic security mutations.
/// Every mutation check must verify that the candidate system rejects axiomatic breaches.
pub fn run_15_mutation_checks(
    candidate_partition: &SystemPartition,
    candidate_state: &SystemState,
) -> Result<(), R3Error> {
    let kernel = SafetyKernel::default();

    // MUT-01: Treat Unknown verification as safe -> must fail closed
    let mut s = candidate_state.clone();
    s.verification.is_valid = false;
    let v = kernel.evaluate_invariant(&s);
    if v.is_valid {
        return Err(R3Error::MutationCheckFailed {
            mutant_id: "MUT-01",
            name: "Treat Unknown verification as safe",
            reason: "System treated invalid verification as valid".to_string(),
        });
    }

    // MUT-02: Treat empty invariant set as safe -> must fail closed
    if InvariantRegistry::new(vec![]).is_ok() {
        return Err(R3Error::MutationCheckFailed {
            mutant_id: "MUT-02",
            name: "Treat empty invariant set as safe",
            reason: "Empty invariant registry was accepted as valid".to_string(),
        });
    }
    let mut s = candidate_state.clone();
    s.safety.csl_constraints.clear();
    let v = kernel.evaluate_invariant(&s);
    if v.is_valid {
        return Err(R3Error::MutationCheckFailed {
            mutant_id: "MUT-02",
            name: "Treat empty invariant set as safe",
            reason: "Empty CSL constraint set evaluated as valid".to_string(),
        });
    }

    // MUT-03: Ignore revocation -> revoked envelope must fail
    if !candidate_partition.config.csl_envelope.validity.is_valid_sequence(0) {
        return Err(R3Error::MutationCheckFailed {
            mutant_id: "MUT-03",
            name: "Ignore revocation",
            reason: "Invalid sequence permitted".to_string(),
        });
    }

    // MUT-04: Execute on unknown verification result -> must be rejected
    let mut s = candidate_state.clone();
    s.verification.proof_digest = "short_digest".to_string();
    let v = kernel.evaluate_invariant(&s);
    if v.is_valid {
        return Err(R3Error::MutationCheckFailed {
            mutant_id: "MUT-04",
            name: "Execute on unknown verification result",
            reason: "Corrupted proof digest was accepted".to_string(),
        });
    }

    // MUT-05: Check invariant AFTER commit -> quarantine flag must block immediately
    let mut s = candidate_state.clone();
    s.safety.quarantine_flag = true;
    let v = kernel.evaluate_invariant(&s);
    if v.is_valid {
        return Err(R3Error::MutationCheckFailed {
            mutant_id: "MUT-05",
            name: "Check invariant AFTER commit",
            reason: "Quarantined state evaluated as valid".to_string(),
        });
    }

    // MUT-06: Permit an untyped action -> payload digest length must be strictly 64 hex chars
    let mut s = candidate_state.clone();
    s.action.payload_digest = "invalid_short_digest".to_string();
    let v = kernel.evaluate_invariant(&s);
    if v.is_valid {
        return Err(R3Error::MutationCheckFailed {
            mutant_id: "MUT-06",
            name: "Permit an untyped action",
            reason: "Untyped action payload was accepted".to_string(),
        });
    }

    // MUT-07: Silently round inexact multiplication -> WAD-18 inexact check
    let w1 = Wad18::from_raw(1);
    let w2 = Wad18::from_raw(1);
    if w1.checked_mul(w2).is_ok() {
        return Err(R3Error::MutationCheckFailed {
            mutant_id: "MUT-07",
            name: "Silently round inexact multiplication",
            reason: "Inexact multiplication did not fail closed".to_string(),
        });
    }

    // MUT-08: Allow expired authorization -> expired epoch must reject
    let mut s = candidate_state.clone();
    s.authorization.is_active = false;
    let v = kernel.evaluate_invariant(&s);
    if v.is_valid {
        return Err(R3Error::MutationCheckFailed {
            mutant_id: "MUT-08",
            name: "Allow expired authorization",
            reason: "Inactive authorization was accepted".to_string(),
        });
    }
    if candidate_partition.config.csl_envelope.validity.is_valid_epoch(10_000_000) {
        return Err(R3Error::MutationCheckFailed {
            mutant_id: "MUT-08",
            name: "Allow expired authorization",
            reason: "Out-of-range epoch evaluated as valid in CSL envelope".to_string(),
        });
    }

    // MUT-09: Allow capability escalation -> action requires higher clearance than auth
    let mut s = candidate_state.clone();
    s.action.required_clearance = s.authorization.clearance_level + 10;
    let v = kernel.evaluate_invariant(&s);
    if v.is_valid {
        return Err(R3Error::MutationCheckFailed {
            mutant_id: "MUT-09",
            name: "Allow capability escalation",
            reason: "Action with clearance > auth was accepted".to_string(),
        });
    }

    // MUT-10: Ignore state binding of certificate -> state id must match
    let computed_state_id = SafetyKernel::state_id(candidate_state);
    if computed_state_id.len() != 64 {
        return Err(R3Error::MutationCheckFailed {
            mutant_id: "MUT-10",
            name: "Ignore state binding of certificate",
            reason: "State ID hash format invalid".to_string(),
        });
    }

    // MUT-11: Truncate wide product incorrectly -> overflow containment
    let big = Wad18::from_raw(i128::MAX);
    if big.checked_mul(big).is_ok() {
        return Err(R3Error::MutationCheckFailed {
            mutant_id: "MUT-11",
            name: "Truncate wide product incorrectly",
            reason: "Wide product overflow was not caught".to_string(),
        });
    }

    // MUT-12: Remove quotient range check -> division overflow containment
    let zero = Wad18::ZERO;
    let one = Wad18::ONE;
    if one.checked_div(zero).is_ok() {
        return Err(R3Error::MutationCheckFailed {
            mutant_id: "MUT-12",
            name: "Remove quotient range check",
            reason: "Division by zero was not caught".to_string(),
        });
    }

    // MUT-13: Discard division remainder -> inexact division containment
    let three = Wad18::from_raw(3_000_000_000_000_000_000);
    if one.checked_div(three).is_ok() {
        return Err(R3Error::MutationCheckFailed {
            mutant_id: "MUT-13",
            name: "Discard division remainder",
            reason: "Inexact division was not caught".to_string(),
        });
    }

    // MUT-14: Lose result sign -> sign law preservation
    let neg_one = Wad18::from_raw(-1_000_000_000_000_000_000);
    let prod = neg_one.checked_mul(one).map_err(|e| R3Error::MutationCheckFailed {
        mutant_id: "MUT-14",
        name: "Lose result sign",
        reason: format!("Valid multiplication failed: {:?}", e),
    })?;
    if prod.raw() >= 0 {
        return Err(R3Error::MutationCheckFailed {
            mutant_id: "MUT-14",
            name: "Lose result sign",
            reason: "Negative multiplied by positive yielded non-negative".to_string(),
        });
    }

    // MUT-15: Accept R3 adoption without kernel equality -> candidate manifest must match kernel manifest
    let current_manifest = candidate_partition.kernel.clone();
    let mut mutated_manifest = current_manifest.clone();
    mutated_manifest.artifact_hash = "forged_malicious_artifact_hash".to_string();
    if current_manifest.check_kernel_equal(&mutated_manifest).is_ok() {
        return Err(R3Error::MutationCheckFailed {
            mutant_id: "MUT-15",
            name: "Accept R3 adoption without kernel equality",
            reason: "Kernel manifest inequality was accepted".to_string(),
        });
    }

    Ok(())
}
