use std::collections::BTreeSet;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use ssi_csl::{CSLEnvelope, CslError, OperatingEnvelope, TemporalValidity};
use ssi_kernel::{
    ActionProposal, ActionType, AuthorizationState, IntelligenceState, ProvenanceState,
    SafetyState, SystemState, VerificationState,
};
use wad18::Wad18;

fn build_csl_state() -> SystemState {
    let mut caps = BTreeSet::new();
    caps.insert("COMPUTE".into());

    let mut q = BTreeSet::new();
    q.insert("NON_DECEPTION".into());
    q.insert("BUDGET_CEILING".into());

    SystemState {
        intelligence: IntelligenceState {
            model_id: "model-csl".into(),
            weights_digest: "a".repeat(64),
            context_window_size: 32_000,
            cognitive_budget: Wad18::from_int(100).unwrap(),
            epistemic_confidence: Wad18::from_raw(990_000_000_000_000_000),
            entropy_bound: Wad18::from_raw(10_000_000_000_000_000),
            capabilities: caps,
        },
        safety: SafetyState {
            containment_active: true,
            containment_barrier_intact: true,
            safety_margin: Wad18::from_raw(800_000_000_000_000_000),
            risk_bound: Wad18::from_raw(200_000_000_000_000_000), // 0.2
            active_envelope_id: "ENV-CSL-1".into(),
            csl_constraints: q,
            quarantine_flag: false,
        },
        action: ActionProposal {
            action_id: "act-csl".into(),
            action_type: ActionType::Compute,
            risk_assessment: Wad18::from_raw(100_000_000_000_000_000), // 0.1
            resource_cost: Wad18::from_int(5).unwrap(),
            required_clearance: 1,
            payload_digest: "b".repeat(64),
            is_executed: false,
        },
        authorization: AuthorizationState {
            auth_token: "tok".into(),
            granter_id: "admin".into(),
            clearance_level: 2,
            is_active: true,
            expires_at_epoch: 2_000_000_000,
            nonce: "nonce".into(),
        },
        verification: VerificationState {
            certificate_id: "c".into(),
            proof_system: "P".into(),
            proof_digest: "c".repeat(64),
            invariants_verified: BTreeSet::new(),
            verifier_identity: "V".into(),
            verified_at_epoch: 1_700_000_000,
            is_valid: true,
        },
        provenance: ProvenanceState {
            sequence_number: 3,
            parent_state_hash: "d".repeat(64),
            merkle_root: "e".repeat(64),
            audit_trail_id: "aud".into(),
            timestamp_epoch_ms: 1_700_000_000_000,
        },
    }
}

fn build_test_envelope() -> (CSLEnvelope, SigningKey) {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);

    let mut allowed_actions = BTreeSet::new();
    allowed_actions.insert(ActionType::Compute);
    allowed_actions.insert(ActionType::Read);

    let mut q = BTreeSet::new();
    q.insert("NON_DECEPTION".into());
    q.insert("BUDGET_CEILING".into());

    let envelope = OperatingEnvelope {
        envelope_id: "ENV-CSL-1".into(),
        max_risk_bound: Wad18::from_raw(300_000_000_000_000_000), // 0.3
        allowed_action_types: allowed_actions,
        max_resource_cost_per_action: Wad18::from_int(10).unwrap(),
        total_budget_limit: Wad18::from_int(50).unwrap(),
    };

    let validity = TemporalValidity {
        valid_from_epoch: 1_600_000_000,
        valid_until_epoch: 1_800_000_000,
        max_transitions: 10,
    };

    let csl = CSLEnvelope::sign_new("AUTH-CSL-999", envelope, validity, q, &signing_key);
    (csl, signing_key)
}

#[test]
fn test_ed25519_signature_validates_cleanly() {
    let (csl, signing_key) = build_test_envelope();
    let verifying_key = signing_key.verifying_key();
    assert!(csl.verify_signature(&verifying_key).is_ok());
}

#[test]
fn test_ed25519_forged_key_fails_verification() {
    let (csl, _) = build_test_envelope();
    let mut csprng = OsRng;
    let wrong_key = SigningKey::generate(&mut csprng).verifying_key();
    assert!(matches!(
        csl.verify_signature(&wrong_key),
        Err(CslError::InvalidSignature(_))
    ));
}

#[test]
fn test_csl_continuity_passes_nominal() {
    let (csl, _) = build_test_envelope();
    let state = build_csl_state();
    let res = csl.verify_continuity(
        &state,
        None,
        1_700_000_000,
        Wad18::from_int(10).unwrap(), // cumulative cost 10 + action 5 = 15 <= 50
        false,
    );
    assert!(res.is_ok(), "Expected continuity to pass: {:?}", res.err());
}

#[test]
fn test_csl_expired_window_fails() {
    let (csl, _) = build_test_envelope();
    let state = build_csl_state();
    let res = csl.verify_continuity(
        &state,
        None,
        1_900_000_000, // expired (> 1.8B)
        Wad18::ZERO,
        false,
    );
    assert!(matches!(res, Err(CslError::TemporalExpired { .. })));
}

#[test]
fn test_csl_max_transitions_depth_exceeded_fails() {
    let (csl, _) = build_test_envelope();
    let mut state = build_csl_state();
    state.provenance.sequence_number = 15; // envelope max is 10
    let res = csl.verify_continuity(&state, None, 1_700_000_000, Wad18::ZERO, false);
    assert!(matches!(res, Err(CslError::MaxTransitionsExceeded { .. })));
}

#[test]
fn test_csl_monotonic_budget_limit_exceeded_fails() {
    let (csl, _) = build_test_envelope();
    let state = build_csl_state();
    let res = csl.verify_continuity(
        &state,
        None,
        1_700_000_000,
        Wad18::from_int(48).unwrap(), // cumulative 48 + action 5 = 53 > limit 50!
        false,
    );
    assert!(matches!(res, Err(CslError::TotalBudgetExceeded { .. })));
}

#[test]
fn test_csl_missing_mandatory_constraint_fails() {
    let (csl, _) = build_test_envelope();
    let mut state = build_csl_state();
    state.safety.csl_constraints.clear(); // Missing constraints!
    let res = csl.verify_continuity(&state, None, 1_700_000_000, Wad18::ZERO, false);
    assert!(matches!(res, Err(CslError::MissingConstraints(_))));
}

#[test]
fn test_csl_explicit_revocation_fails() {
    let (csl, _) = build_test_envelope();
    let state = build_csl_state();
    let res = csl.verify_continuity(&state, None, 1_700_000_000, Wad18::ZERO, true);
    assert!(matches!(res, Err(CslError::Revoked(_))));
}
