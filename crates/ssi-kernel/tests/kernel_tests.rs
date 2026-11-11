use std::collections::BTreeSet;
use ssi_kernel::{
    ActionProposal, ActionType, AuthorizationState, IntelligenceState, InvariantClause,
    InvariantRegistry, InvariantResult, KernelError, ProvenanceState, SafetyKernel, SafetyState,
    SystemState, VerificationState,
};
use wad18::Wad18;

pub fn build_valid_state() -> SystemState {
    let mut caps = BTreeSet::new();
    caps.insert("COMPUTE".into());
    caps.insert("READ".into());

    let mut csl_q = BTreeSet::new();
    csl_q.insert("NON_DECEPTION".into());
    csl_q.insert("CONTAINMENT_INTEGRITY".into());

    let mut inv_v = BTreeSet::new();
    inv_v.insert("TypeValid".into());
    inv_v.insert("SafetyValid".into());

    SystemState {
        intelligence: IntelligenceState {
            model_id: "model-ssi-v1".into(),
            weights_digest: "a".repeat(64),
            context_window_size: 128_000,
            cognitive_budget: Wad18::from_int(100).unwrap(),
            epistemic_confidence: Wad18::from_raw(995_000_000_000_000_000), // 0.995
            entropy_bound: Wad18::from_raw(20_000_000_000_000_000),         // 0.02
            capabilities: caps,
        },
        safety: SafetyState {
            containment_active: true,
            containment_barrier_intact: true,
            safety_margin: Wad18::from_raw(800_000_000_000_000_000), // 0.8
            risk_bound: Wad18::from_raw(300_000_000_000_000_000),    // 0.3
            active_envelope_id: "ENV-01".into(),
            csl_constraints: csl_q,
            quarantine_flag: false,
        },
        action: ActionProposal {
            action_id: "act-001".into(),
            action_type: ActionType::Compute,
            risk_assessment: Wad18::from_raw(100_000_000_000_000_000), // 0.1
            resource_cost: Wad18::from_int(1).unwrap(),
            required_clearance: 2,
            payload_digest: "b".repeat(64),
            is_executed: false,
        },
        authorization: AuthorizationState {
            auth_token: "token-xyz".into(),
            granter_id: "sec-officer-01".into(),
            clearance_level: 3,
            is_active: true,
            expires_at_epoch: 2_000_000_000,
            nonce: "nonce-456".into(),
        },
        verification: VerificationState {
            certificate_id: "cert-001".into(),
            proof_system: "SSI_VERIFIER_V1".into(),
            proof_digest: "c".repeat(64),
            invariants_verified: inv_v,
            verifier_identity: "GATE_VERIFIER_ROOT".into(),
            verified_at_epoch: 1_700_000_000,
            is_valid: true,
        },
        provenance: ProvenanceState {
            sequence_number: 1,
            parent_state_hash: "d".repeat(64),
            merkle_root: "e".repeat(64),
            audit_trail_id: "audit-seg-001".into(),
            timestamp_epoch_ms: 1_700_000_000_000,
        },
    }
}

#[test]
fn test_valid_state_passes_global_invariant() {
    let kernel = SafetyKernel::default();
    let state = build_valid_state();
    let result = kernel.verify_invariant(&state);
    assert!(result.is_ok(), "Expected valid state to pass I(X)");
}

#[test]
fn test_empty_invariant_set_fails_closed() {
    let empty_reg = InvariantRegistry::new(vec![]);
    assert_eq!(empty_reg.err(), Some(KernelError::EmptyInvariantSet));
}

#[test]
fn test_unknown_invariant_evaluates_to_fail() {
    let clauses = vec![
        InvariantClause::new("UnknownClause", |_| InvariantResult::Unknown("timed out".into())),
    ];
    let reg = InvariantRegistry::new(clauses).unwrap();
    let kernel = SafetyKernel::with_registry(reg);
    let state = build_valid_state();
    let verdict = kernel.evaluate_invariant(&state);
    assert!(!verdict.is_valid);
    assert!(verdict.failure_reason.unwrap().contains("UnknownClause"));
}

#[test]
fn test_epistemic_confidence_out_of_bounds_fails() {
    let kernel = SafetyKernel::default();
    let mut state = build_valid_state();
    // Exceed 1.0 (WAD_SCALE = 10^18)
    state.intelligence.epistemic_confidence = Wad18::from_raw(1_500_000_000_000_000_000);
    let res = kernel.verify_invariant(&state);
    assert!(res.is_err());
}

#[test]
fn test_risk_exceeding_bound_fails_safety_clause() {
    let kernel = SafetyKernel::default();
    let mut state = build_valid_state();
    // Risk assessment (0.5 WAD) > Risk bound (0.3 WAD)
    state.action.risk_assessment = Wad18::from_raw(500_000_000_000_000_000);
    let res = kernel.verify_invariant(&state);
    assert!(res.is_err());
}

#[test]
fn test_quarantine_flag_fails_csl_clause() {
    let kernel = SafetyKernel::default();
    let mut state = build_valid_state();
    state.safety.quarantine_flag = true;
    let res = kernel.verify_invariant(&state);
    assert!(res.is_err());
}

#[test]
fn test_kernel_halt_mode_blocks_evaluation() {
    let mut kernel = SafetyKernel::default();
    kernel.emergency_halt("Security breach detected");
    let state = build_valid_state();
    let res = kernel.verify_invariant(&state);
    assert!(matches!(res, Err(KernelError::KernelModeViolation(_))));
}

#[test]
fn test_untyped_action_fails_type_valid_clause() {
    let kernel = SafetyKernel::default();
    let mut state = build_valid_state();
    // Untyped / corrupted payload digest (not 64 hex characters)
    state.action.payload_digest = "short_invalid_digest".to_string();
    let res = kernel.verify_invariant(&state);
    assert!(res.is_err(), "Untyped action with invalid payload digest must fail TypeValid");
}

#[test]
fn test_r3_adoption_requires_kernel_equality() {
    let kernel = SafetyKernel::default();
    let current_state = build_valid_state();
    let candidate_state = build_valid_state();

    // 1. Nominal candidate with equal kernel digest succeeds
    let valid_candidate = ssi_kernel::CandidateSystem {
        kernel_digest: kernel.kernel_digest().to_string(),
        model_id: "model-ssi-v2".to_string(),
        weights_digest: "f".repeat(64),
        config_manifest: "manifest_alpha".to_string(),
        proof_valid: true,
        auth_valid: true,
    };
    assert!(kernel.check_adopt(&current_state, &valid_candidate, &candidate_state).is_ok());

    // 2. Mutated candidate with altered kernel digest strictly fails
    let mut forged_candidate = valid_candidate;
    forged_candidate.kernel_digest = "forged_malicious_kernel_digest".to_string();
    let res = kernel.check_adopt(&current_state, &forged_candidate, &candidate_state);
    assert!(res.is_err(), "R^3 adoption without kernel equality must be rejected");
}
