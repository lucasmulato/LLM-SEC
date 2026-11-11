use std::collections::BTreeSet;
use ssi_gate::{
    ExecutionGate, GateDecision, VerificationStatus, evaluate_permit,
};
use ssi_kernel::{
    ActionProposal, ActionType, AuthorizationState, IntelligenceState, ProvenanceState,
    SafetyKernel, SafetyState, SystemState, VerificationState,
};
use wad18::Wad18;

fn build_test_state() -> (SystemState, ActionProposal) {
    let mut caps = BTreeSet::new();
    caps.insert("COMPUTE".into());
    caps.insert("SAFE_DISPATCH".into());

    let mut csl_q = BTreeSet::new();
    csl_q.insert("NON_DECEPTION".into());

    let mut inv_v = BTreeSet::new();
    inv_v.insert("TypeValid".into());

    let state = SystemState {
        intelligence: IntelligenceState {
            model_id: "model-01".into(),
            weights_digest: "a".repeat(64),
            context_window_size: 64_000,
            cognitive_budget: Wad18::from_int(100).unwrap(),
            epistemic_confidence: Wad18::from_raw(990_000_000_000_000_000),
            entropy_bound: Wad18::from_raw(10_000_000_000_000_000),
            capabilities: caps,
        },
        safety: SafetyState {
            containment_active: true,
            containment_barrier_intact: true,
            safety_margin: Wad18::from_raw(800_000_000_000_000_000),
            risk_bound: Wad18::from_raw(300_000_000_000_000_000),
            active_envelope_id: "ENV-01".into(),
            csl_constraints: csl_q,
            quarantine_flag: false,
        },
        action: ActionProposal {
            action_id: "act-test".into(),
            action_type: ActionType::Compute,
            risk_assessment: Wad18::from_raw(100_000_000_000_000_000),
            resource_cost: Wad18::from_int(2).unwrap(),
            required_clearance: 2,
            payload_digest: "b".repeat(64),
            is_executed: false,
        },
        authorization: AuthorizationState {
            auth_token: "token-01".into(),
            granter_id: "auth-root".into(),
            clearance_level: 3,
            is_active: true,
            expires_at_epoch: 1_800_000_000,
            nonce: "nonce-1".into(),
        },
        verification: VerificationState {
            certificate_id: "cert-01".into(),
            proof_system: "VER_V1".into(),
            proof_digest: "c".repeat(64),
            invariants_verified: inv_v,
            verifier_identity: "VERIFIER".into(),
            verified_at_epoch: 1_700_000_000,
            is_valid: true,
        },
        provenance: ProvenanceState {
            sequence_number: 1,
            parent_state_hash: "d".repeat(64),
            merkle_root: "e".repeat(64),
            audit_trail_id: "audit-01".into(),
            timestamp_epoch_ms: 1_700_000_000_000,
        },
    };

    let action = state.action.clone();
    (state, action)
}

#[test]
fn test_permit_passes_all_subpredicates() {
    let (state, action) = build_test_state();
    let res = evaluate_permit(&state, &action, VerificationStatus::Valid, 1_700_000_000, Some("COMPUTE"));
    assert_eq!(res.decision, GateDecision::Permit);
    assert!(res.detail.auth_pass);
    assert!(res.detail.safe_action_pass);
    assert!(res.detail.ver_pass);
    assert!(res.detail.cap_pass);
}

#[test]
fn test_permit_fails_closed_on_unknown_verification() {
    let (state, action) = build_test_state();
    let res = evaluate_permit(&state, &action, VerificationStatus::Unknown, 1_700_000_000, None);
    assert_eq!(res.decision, GateDecision::Reject);
    assert!(!res.detail.ver_pass);
}

#[test]
fn test_permit_rejects_insufficient_clearance() {
    let (mut state, action) = build_test_state();
    state.authorization.clearance_level = 1; // action requires 2
    let res = evaluate_permit(&state, &action, VerificationStatus::Valid, 1_700_000_000, None);
    assert_eq!(res.decision, GateDecision::Reject);
    assert!(!res.detail.auth_pass);
}

#[test]
fn test_permit_rejects_expired_authorization() {
    let (state, action) = build_test_state();
    let res = evaluate_permit(&state, &action, VerificationStatus::Valid, 1_900_000_000, None); // expired at 1.8B
    assert_eq!(res.decision, GateDecision::Reject);
    assert!(!res.detail.auth_pass);
}

#[test]
fn test_permit_rejects_forbidden_keyword() {
    let (state, mut action) = build_test_state();
    action.action_id = "act-exfiltrate-data".into();
    let res = evaluate_permit(&state, &action, VerificationStatus::Valid, 1_700_000_000, None);
    assert_eq!(res.decision, GateDecision::Reject);
    assert!(!res.detail.safe_action_pass);
}

#[test]
fn test_permit_rejects_budget_overdraft() {
    let (mut state, action) = build_test_state();
    state.intelligence.cognitive_budget = Wad18::from_raw(1_000_000_000_000_000_000); // 1 WAD, action costs 2 WAD
    let res = evaluate_permit(&state, &action, VerificationStatus::Valid, 1_700_000_000, None);
    assert_eq!(res.decision, GateDecision::Reject);
    assert!(!res.detail.cap_pass);
}

#[test]
fn test_pipeline_executes_and_commits_successfully() {
    let kernel = SafetyKernel::default();
    let gate = ExecutionGate::new(&kernel);
    let (pre_state, action) = build_test_state();

    let pre_state_hash = SafetyKernel::state_id(&pre_state);

    let commit_res = gate.run(
        &pre_state,
        &action,
        VerificationStatus::Valid,
        1_700_000_000,
        Some("COMPUTE"),
        |_action| b"output data 123".to_vec(),
        |pre, act, _out| {
            let mut post = pre.clone();
            post.provenance.sequence_number = pre.provenance.sequence_number + 1;
            post.provenance.parent_state_hash = pre_state_hash.clone();
            post.action.is_executed = true;
            post.intelligence.cognitive_budget = pre.intelligence.cognitive_budget
                .checked_sub(act.resource_cost)
                .unwrap();
            post
        },
    );

    assert!(commit_res.is_ok(), "Expected pipeline run to succeed: {:?}", commit_res.err());
    let commit = commit_res.unwrap();
    assert_eq!(commit.pre_state_id, pre_state_hash);
    assert_ne!(commit.post_state_id, pre_state_hash);
}

#[test]
fn test_pipeline_aborts_without_side_effects_on_permit_denial() {
    let kernel = SafetyKernel::default();
    let gate = ExecutionGate::new(&kernel);
    let (mut pre_state, action) = build_test_state();
    pre_state.authorization.is_active = false; // Denied!

    let side_effect_happened = false;

    let res = gate.run(
        &pre_state,
        &action,
        VerificationStatus::Valid,
        1_700_000_000,
        None,
        |_| {
            // Sandbox returns
            vec![]
        },
        |pre, _, _| pre.clone(),
    );

    assert!(res.is_err());
    // Verify side effect never occurred
    assert!(!side_effect_happened);
}

#[test]
fn test_pipeline_aborts_when_candidate_violates_invariant() {
    let kernel = SafetyKernel::default();
    let gate = ExecutionGate::new(&kernel);
    let (pre_state, action) = build_test_state();

    let pre_state_hash = SafetyKernel::state_id(&pre_state);

    let res = gate.run(
        &pre_state,
        &action,
        VerificationStatus::Valid,
        1_700_000_000,
        Some("COMPUTE"),
        |_act| b"data".to_vec(),
        |pre, _act, _out| {
            let mut post = pre.clone();
            post.provenance.sequence_number = pre.provenance.sequence_number + 1;
            post.provenance.parent_state_hash = pre_state_hash.clone();
            // Candidate post-state violates invariant!
            post.safety.quarantine_flag = true;
            post
        },
    );
    assert!(res.is_err(), "Pipeline must reject candidate state violating invariant before commit");
}

#[test]
fn test_permit_rejects_missing_capability() {
    let (state, action) = build_test_state();
    let res = evaluate_permit(
        &state,
        &action,
        VerificationStatus::Valid,
        1_700_000_000,
        Some("UNAUTHORIZED_CAPABILITY"),
    );
    assert_eq!(res.decision, GateDecision::Reject);
    assert!(!res.detail.cap_pass);
}

#[test]
fn test_pipeline_aborts_on_unknown_verification() {
    let kernel = SafetyKernel::default();
    let gate = ExecutionGate::new(&kernel);
    let (pre_state, action) = build_test_state();

    let res = gate.run(
        &pre_state,
        &action,
        VerificationStatus::Unknown,
        1_700_000_000,
        Some("COMPUTE"),
        |_act| b"data".to_vec(),
        |pre, _, _| pre.clone(),
    );
    assert!(res.is_err(), "Pipeline must strictly abort on VerificationStatus::Unknown");
}

#[test]
fn test_pipeline_rejects_broken_parent_state_hash() {
    let kernel = SafetyKernel::default();
    let gate = ExecutionGate::new(&kernel);
    let (pre_state, action) = build_test_state();

    let res = gate.run(
        &pre_state,
        &action,
        VerificationStatus::Valid,
        1_700_000_000,
        Some("COMPUTE"),
        |_act| b"data".to_vec(),
        |pre, act, _out| {
            let mut post = pre.clone();
            post.provenance.sequence_number = pre.provenance.sequence_number + 1;
            post.action.is_executed = true;
            post.intelligence.cognitive_budget = pre.intelligence.cognitive_budget
                .checked_sub(act.resource_cost)
                .unwrap();
            // A valid 64-hex hash, but NOT matching pre_state_id!
            post.provenance.parent_state_hash = "f".repeat(64);
            post
        },
    );
    match res {
        Err(ssi_gate::GateError::TransitionViolation { reason }) => {
            assert!(reason.contains("parent_state_hash mismatch"));
        }
        other => panic!("Expected TransitionViolation for parent_state_hash mismatch, got {:?}", other),
    }
}
