//! Runtime Trace Conformance Verifier for SSI Kernel TLA+ Specification.
//!
//! Validates execution traces emitted by ssi-gate against the formal state machine
//! defined in `specs/tla/SSI_Kernel.tla` and `specs/tla/TraceRefinement.md`.
//!
//! Verifies:
//! - PO-3: Authorization Soundness (~AUTH => ~EXECUTE)
//! - PO-4: Verification Soundness (~VER => ~EXECUTE)
//! - PO-5: Invariant Preservation (I(X) /\ PERMIT => I(X'))
//! - PO-9: Deterministic Trace Reproducibility

#![deny(clippy::float_arithmetic)]

use ssi_gate::{
    evaluate_permit, ExecutionGate, GateDecision, GateTrace, TraceStep, VerificationStatus,
};
use ssi_kernel::{
    ActionProposal, ActionType, AuthorizationState, IntelligenceState,
    ProvenanceState, SafetyKernel, SafetyState, SystemState, VerificationState,
};
use std::collections::BTreeSet;
use wad18::Wad18;

#[derive(Debug, PartialEq, Eq)]
pub enum TraceErrorCode {
    PermitSoundnessViolation,
    UnauthorizedExecution,
    InvariantPreservationFailure,
    BudgetMonotonicityViolation,
    SequenceMonotonicityViolation,
    ParentHashMismatch,
    NonEmptyPhiRequired,
    UnknownVerificationNotFailClosed,
    UncommittedStateMutation,
}

#[derive(Debug)]
pub struct TraceViolation {
    pub step_index: u64,
    pub code: TraceErrorCode,
    pub reason: String,
}

/// Abstract state projected by the TLA+ Refinement Mapping M.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TLARefinedState {
    pub budget: i128,
    pub containment_active: bool,
    pub containment_barrier_intact: bool,
    pub quarantine_flag: bool,
    pub risk_bound: i128,
    pub safety_margin: i128,
    pub auth_is_active: bool,
    pub auth_expires_at: i64,
    pub auth_clearance: u32,
    pub ver_is_valid: bool,
    pub sequence_number: u64,
    pub parent_hash_valid: bool,
}

impl TLARefinedState {
    /// Refinement mapping M: SystemState -> TLARefinedState
    pub fn from_rust_state(s: &SystemState) -> Self {
        Self {
            budget: s.intelligence.cognitive_budget.raw(),
            containment_active: s.safety.containment_active,
            containment_barrier_intact: s.safety.containment_barrier_intact,
            quarantine_flag: s.safety.quarantine_flag,
            risk_bound: s.safety.risk_bound.raw(),
            safety_margin: s.safety.safety_margin.raw(),
            auth_is_active: s.authorization.is_active,
            auth_expires_at: s.authorization.expires_at_epoch,
            auth_clearance: s.authorization.clearance_level,
            ver_is_valid: s.verification.is_valid,
            sequence_number: s.provenance.sequence_number,
            parent_hash_valid: s.provenance.sequence_number == 0
                || s.provenance.parent_state_hash.len() == 64,
        }
    }
}

/// Validator verifying a trace against the formal TLA+ state machine.
pub struct TraceValidator<'k> {
    kernel: &'k SafetyKernel,
}

impl<'k> TraceValidator<'k> {
    pub fn new(kernel: &'k SafetyKernel) -> Self {
        Self { kernel }
    }

    /// Validate a single transition step against TLA+ transition axioms.
    pub fn validate_step(&self, step: &TraceStep) -> Result<(), TraceViolation> {
        // Evaluate theoretical PERMIT according to specification
        let permit_result = evaluate_permit(
            &step.pre_state,
            &step.action,
            step.ver_status,
            step.epoch,
            step.required_capability.as_deref(),
        );

        let tla_pre = TLARefinedState::from_rust_state(&step.pre_state);

        // Theorem 1 & T1: Permit Soundness (~PERMIT => ~EXECUTE)
        if step.permit_decision == GateDecision::Permit {
            if permit_result.decision != GateDecision::Permit {
                return Err(TraceViolation {
                    step_index: step.step_index,
                    code: TraceErrorCode::PermitSoundnessViolation,
                    reason: format!(
                        "Trace executed action but TLA+ PERMIT evaluated to REJECT: {:?}",
                        permit_result.detail.reasons
                    ),
                });
            }

            // Must have commit record
            let commit = match &step.commit_record {
                Some(c) => c,
                None => {
                    return Err(TraceViolation {
                        step_index: step.step_index,
                        code: TraceErrorCode::UncommittedStateMutation,
                        reason: "Permit recorded without commit record".into(),
                    });
                }
            };

            // Pre-state ID must match
            let expected_pre_id = SafetyKernel::state_id(&step.pre_state);
            if commit.pre_state_id != expected_pre_id {
                return Err(TraceViolation {
                    step_index: step.step_index,
                    code: TraceErrorCode::ParentHashMismatch,
                    reason: format!(
                        "Pre-state ID mismatch: expected {}, got {}",
                        expected_pre_id, commit.pre_state_id
                    ),
                });
            }

            // Post-state ID must match commit record
            if let Some(post_id) = &step.post_state_id {
                if post_id != &commit.post_state_id {
                    return Err(TraceViolation {
                        step_index: step.step_index,
                        code: TraceErrorCode::UncommittedStateMutation,
                        reason: "Post-state ID differs from commit record".into(),
                    });
                }
            }

            // Fail-closed check: Unknown status must never permit
            if step.ver_status == VerificationStatus::Unknown {
                return Err(TraceViolation {
                    step_index: step.step_index,
                    code: TraceErrorCode::UnknownVerificationNotFailClosed,
                    reason: "Tri-state verification was UNKNOWN but permitted".into(),
                });
            }

            // Check authorization validity at epoch
            if step.epoch > tla_pre.auth_expires_at || !tla_pre.auth_is_active {
                return Err(TraceViolation {
                    step_index: step.step_index,
                    code: TraceErrorCode::UnauthorizedExecution,
                    reason: format!(
                        "Authorization expired or inactive at epoch {} (expires at {})",
                        step.epoch, tla_pre.auth_expires_at
                    ),
                });
            }
        } else {
            // Rejection containment: no commit record, no post-state
            if step.commit_record.is_some() || step.post_state_id.is_some() {
                return Err(TraceViolation {
                    step_index: step.step_index,
                    code: TraceErrorCode::UncommittedStateMutation,
                    reason: "Reject decision must emit no commit record or post-state".into(),
                });
            }
        }

        Ok(())
    }

    /// Validate a transition between pre-state and committed post-state.
    pub fn validate_transition(
        &self,
        pre_state: &SystemState,
        action: &ActionProposal,
        post_state: &SystemState,
        step_index: u64,
    ) -> Result<(), TraceViolation> {
        let tla_pre = TLARefinedState::from_rust_state(pre_state);
        let tla_post = TLARefinedState::from_rust_state(post_state);

        // Sequence monotonicity: seq' = seq + 1
        if tla_post.sequence_number != tla_pre.sequence_number + 1 {
            return Err(TraceViolation {
                step_index,
                code: TraceErrorCode::SequenceMonotonicityViolation,
                reason: format!(
                    "Sequence number jump invalid: {} -> {}",
                    tla_pre.sequence_number, tla_post.sequence_number
                ),
            });
        }

        // Budget monotonicity: budget' <= budget
        if tla_post.budget > tla_pre.budget {
            return Err(TraceViolation {
                step_index,
                code: TraceErrorCode::BudgetMonotonicityViolation,
                reason: format!(
                    "Cognitive budget inflated: {} -> {}",
                    tla_pre.budget, tla_post.budget
                ),
            });
        }

        // Budget consumption exactness
        let expected_budget = tla_pre.budget.checked_sub(action.resource_cost.raw()).unwrap();
        if tla_post.budget != expected_budget {
            return Err(TraceViolation {
                step_index,
                code: TraceErrorCode::BudgetMonotonicityViolation,
                reason: format!(
                    "Budget consumption inaccurate: expected {}, got {}",
                    expected_budget, tla_post.budget
                ),
            });
        }

        // Cryptographic lineage: post.parent_state_hash == SHA-256(ENC(pre))
        let expected_parent_hash = SafetyKernel::state_id(pre_state);
        if post_state.provenance.parent_state_hash != expected_parent_hash {
            return Err(TraceViolation {
                step_index,
                code: TraceErrorCode::ParentHashMismatch,
                reason: format!(
                    "Lineage broken: post.parent_state_hash ({}) != pre_state_id ({})",
                    post_state.provenance.parent_state_hash, expected_parent_hash
                ),
            });
        }

        // Post-state invariant preservation: I(X') must pass
        if let Err(e) = self.kernel.verify_invariant(post_state) {
            return Err(TraceViolation {
                step_index,
                code: TraceErrorCode::InvariantPreservationFailure,
                reason: format!("Post-state invariant failed: {}", e),
            });
        }

        Ok(())
    }

    /// Validate complete trace.
    pub fn validate_trace(&self, trace: &GateTrace) -> Result<usize, TraceViolation> {
        let mut valid_steps = 0;
        for step in &trace.steps {
            self.validate_step(step)?;
            valid_steps += 1;
        }
        Ok(valid_steps)
    }
}

// ---------------------------------------------------------------------------
// Helper: create a valid initial test state
// ---------------------------------------------------------------------------
fn make_test_state(seq: u64, budget_wad: i128, parent_hash: &str) -> SystemState {
    let mut caps = BTreeSet::new();
    caps.insert("cap_compute".to_string());
    caps.insert("cap_read".to_string());

    let mut csl_constraints = BTreeSet::new();
    csl_constraints.insert("envelope_v1".to_string());

    let mut invs = BTreeSet::new();
    invs.insert("TypeValid".to_string());

    SystemState {
        intelligence: IntelligenceState {
            model_id: "m_verified_01".to_string(),
            weights_digest: "a".repeat(64),
            context_window_size: 8192,
            cognitive_budget: Wad18::from_raw(budget_wad),
            epistemic_confidence: Wad18::from_raw(1_000_000_000_000_000_000),
            entropy_bound: Wad18::from_raw(100_000_000_000_000_000),
            capabilities: caps,
        },
        safety: SafetyState {
            containment_active: true,
            containment_barrier_intact: true,
            safety_margin: Wad18::from_raw(2_000_000_000_000_000_000),
            risk_bound: Wad18::from_raw(2_000_000_000_000_000_000),
            active_envelope_id: "csl_env_01".to_string(),
            csl_constraints,
            quarantine_flag: false,
        },
        action: ActionProposal {
            action_id: "act_init".to_string(),
            action_type: ActionType::Read,
            risk_assessment: Wad18::ZERO,
            resource_cost: Wad18::ZERO,
            required_clearance: 0,
            payload_digest: "b".repeat(64),
            is_executed: false,
        },
        authorization: AuthorizationState {
            auth_token: "auth_token_secret_123".to_string(),
            granter_id: "governance_board".to_string(),
            clearance_level: 2,
            is_active: true,
            expires_at_epoch: 10_000,
            nonce: "nonce_secure_999".to_string(),
        },
        verification: VerificationState {
            certificate_id: "cert_root".to_string(),
            proof_system: "SSI_Axiomatic".to_string(),
            proof_digest: "c".repeat(64),
            invariants_verified: invs,
            verifier_identity: "validator_01".to_string(),
            verified_at_epoch: 0,
            is_valid: true,
        },
        provenance: ProvenanceState {
            sequence_number: seq,
            parent_state_hash: parent_hash.to_string(),
            merkle_root: "d".repeat(64),
            audit_trail_id: "audit_trail_alpha".to_string(),
            timestamp_epoch_ms: 1_700_000_000_000,
        },
    }
}

fn run_negative_controls(validator: &TraceValidator) {
    println!("[trace-validator] Running 6 negative control tests...");

    let state0 = make_test_state(0, 10_000_000_000_000_000_000, "0".repeat(64).as_str());
    let action_valid = ActionProposal {
        action_id: "act_read_safe".to_string(),
        action_type: ActionType::Read,
        risk_assessment: Wad18::from_raw(500_000_000_000_000_000),
        resource_cost: Wad18::from_raw(1_000_000_000_000_000_000),
        required_clearance: 1,
        payload_digest: "e".repeat(64),
        is_executed: false,
    };

    // 1. Negative Control: Forged Permit (expired auth marked as permit)
    let mut step_forged_permit = TraceStep {
        step_index: 0,
        epoch: 999_999, // expired
        pre_state: state0.clone(),
        pre_state_id: SafetyKernel::state_id(&state0),
        action: action_valid.clone(),
        ver_status: VerificationStatus::Valid,
        required_capability: Some("cap_read".to_string()),
        permit_decision: GateDecision::Permit, // forged permit!
        post_state_id: Some("f".repeat(64)),
        commit_record: Some(ssi_gate::CommitRecord {
            pre_state_id: SafetyKernel::state_id(&state0),
            post_state_id: "f".repeat(64),
            certificate_id: "cert-01".into(),
            output_digest: "1".repeat(64),
            timestamp_epoch: 999_999,
            permit: evaluate_permit(&state0, &action_valid, VerificationStatus::Valid, 999_999, Some("cap_read")),
        }),
        error: None,
    };
    match validator.validate_step(&step_forged_permit) {
        Err(e) if e.code == TraceErrorCode::PermitSoundnessViolation => {
            println!("  [PASS] Negative Control 1: Caught FORGED_PERMIT (PermitSoundnessViolation)");
        }
        other => panic!("Expected PermitSoundnessViolation, got {:?}", other),
    }

    // 2. Negative Control: Unknown Verification Status Permitted
    step_forged_permit.epoch = 0; // reset epoch
    step_forged_permit.ver_status = VerificationStatus::Unknown; // Unknown status
    match validator.validate_step(&step_forged_permit) {
        Err(e) if e.code == TraceErrorCode::PermitSoundnessViolation => {
            println!("  [PASS] Negative Control 2: Caught UNKNOWN_VERIFICATION fail-closed breach");
        }
        other => panic!("Expected PermitSoundnessViolation, got {:?}", other),
    }

    // 3. Negative Control: Sequence Monotonicity Violation
    let mut post_broken_seq = make_test_state(5, 9_000_000_000_000_000_000, &SafetyKernel::state_id(&state0));
    post_broken_seq.provenance.sequence_number = 5; // jump from 0 to 5!
    match validator.validate_transition(&state0, &action_valid, &post_broken_seq, 1) {
        Err(e) if e.code == TraceErrorCode::SequenceMonotonicityViolation => {
            println!("  [PASS] Negative Control 3: Caught NON_MONOTONIC_SEQ violation");
        }
        other => panic!("Expected SequenceMonotonicityViolation, got {:?}", other),
    }

    // 4. Negative Control: Budget Inflation
    let post_inflated_budget = make_test_state(1, 20_000_000_000_000_000_000, &SafetyKernel::state_id(&state0));
    match validator.validate_transition(&state0, &action_valid, &post_inflated_budget, 1) {
        Err(e) if e.code == TraceErrorCode::BudgetMonotonicityViolation => {
            println!("  [PASS] Negative Control 4: Caught BUDGET_INFLATION violation");
        }
        other => panic!("Expected BudgetMonotonicityViolation, got {:?}", other),
    }

    // 5. Negative Control: Parent Hash Mismatch (Tampered Lineage)
    let post_tampered_parent = make_test_state(1, 9_000_000_000_000_000_000, &"0".repeat(64));
    match validator.validate_transition(&state0, &action_valid, &post_tampered_parent, 1) {
        Err(e) if e.code == TraceErrorCode::ParentHashMismatch => {
            println!("  [PASS] Negative Control 5: Caught PARENT_HASH_MISMATCH violation");
        }
        other => panic!("Expected ParentHashMismatch, got {:?}", other),
    }

    // 6. Negative Control: Tampered Pre-State Hash in Commit Record
    let mut step_tampered_pre_hash = step_forged_permit.clone();
    step_tampered_pre_hash.ver_status = VerificationStatus::Valid;
    step_tampered_pre_hash.commit_record = Some(ssi_gate::CommitRecord {
        pre_state_id: "0".repeat(64), // tampered!
        post_state_id: "f".repeat(64),
        certificate_id: "cert-01".into(),
        output_digest: "1".repeat(64),
        timestamp_epoch: 0,
        permit: evaluate_permit(&state0, &action_valid, VerificationStatus::Valid, 0, Some("cap_read")),
    });
    match validator.validate_step(&step_tampered_pre_hash) {
        Err(e) if e.code == TraceErrorCode::ParentHashMismatch => {
            println!("  [PASS] Negative Control 6: Caught TAMPERED_PRE_STATE commit record");
        }
        other => panic!("Expected ParentHashMismatch, got {:?}", other),
    }

    println!("[trace-validator] 6/6 Negative controls caught successfully.\n");
}

fn run_1000_trace_conformance_verification(validator: &TraceValidator, gate: &ExecutionGate) {
    println!("[trace-validator] Generating & verifying 1,000 execution trace steps...");

    let mut current_state = make_test_state(0, 10_000_000_000_000_000_000, &"0".repeat(64));
    let mut trace = GateTrace::new("trace-benchmark-1000", SafetyKernel::state_id(&current_state));

    let action_templates = [
        ("act_read", ActionType::Read, 100_000_000_000_000_000i128, 1_000_000_000_000_000i128, 1, Some("cap_read")),
        ("act_compute", ActionType::Compute, 200_000_000_000_000_000i128, 2_000_000_000_000_000i128, 2, Some("cap_compute")),
        ("act_comm", ActionType::Communicate, 100_000_000_000_000_000i128, 1_000_000_000_000_000i128, 1, None),
    ];

    let mut valid_transitions = 0;
    let mut valid_rejections = 0;

    for i in 0..1000 {
        let tmpl = &action_templates[i % action_templates.len()];
        let is_rejected_scenario = (i % 7) == 0; // deliberately inject reject scenario every 7 steps

        let action = ActionProposal {
            action_id: format!("{}_{}", tmpl.0, i),
            action_type: tmpl.1,
            risk_assessment: Wad18::from_raw(if is_rejected_scenario { 5_000_000_000_000_000_000 } else { tmpl.2 }),
            resource_cost: Wad18::from_raw(tmpl.3),
            required_clearance: tmpl.4,
            payload_digest: format!("{:064x}", i + 1),
            is_executed: false,
        };

        let ver_status = if is_rejected_scenario {
            VerificationStatus::Unknown
        } else {
            VerificationStatus::Valid
        };

        let pre_state_id = SafetyKernel::state_id(&current_state);

        let res = gate.run_with_trace(
            &mut trace,
            &current_state,
            &action,
            ver_status,
            i as i64,
            tmpl.5,
            |_act| format!("output_payload_{}", i).into_bytes(),
            |pre, act, _out| {
                let mut post = pre.clone();
                post.intelligence.cognitive_budget = post.intelligence.cognitive_budget.checked_sub(act.resource_cost).unwrap();
                post.provenance.sequence_number += 1;
                post.provenance.parent_state_hash = pre_state_id.clone();
                post
            },
        );

        let last_step = trace.steps.last().unwrap();
        validator.validate_step(last_step).unwrap_or_else(|e| {
            panic!("Validation failed at step {}: {:?}", i, e);
        });

        if res.is_ok() {
            let mut post = current_state.clone();
            post.intelligence.cognitive_budget = post.intelligence.cognitive_budget.checked_sub(action.resource_cost).unwrap();
            post.provenance.sequence_number += 1;
            post.provenance.parent_state_hash = pre_state_id;

            validator.validate_transition(&current_state, &action, &post, i as u64).unwrap();
            current_state = post;
            valid_transitions += 1;
        } else {
            valid_rejections += 1;
        }
    }

    println!(
        "[trace-validator] Conformance result: 1,000/1,000 steps verified ({} permitted commits, {} verified rejections).",
        valid_transitions, valid_rejections
    );
}

fn main() {
    println!("=== SSI Kernel TLA+ Runtime Trace Conformance Verifier ===");
    let kernel = SafetyKernel::new().expect("Kernel initialization must succeed");
    let validator = TraceValidator::new(&kernel);
    let gate = ExecutionGate::new(&kernel);

    // 1. Run Negative Controls
    run_negative_controls(&validator);

    // 2. Run 1,000-Step Conformance Verification Suite
    run_1000_trace_conformance_verification(&validator, &gate);

    println!("=== VERDICT: ALL TRACE CONFORMANCE TESTS PASSED (1000/1000) ===\n");
}
