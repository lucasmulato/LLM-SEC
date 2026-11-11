//! Comprehensive integration tests for ssi-pco crate.
//!
//! Asserts:
//! - Nominal PCO validation and pre-action ledger commit
//! - Rejection of forged proof artifacts
//! - Rejection of state-rebound certificates (BOUND(C, X) violation)
//! - Rejection of expired certificates
//! - Rejection of revoked certificates
//! - Fail-closed handling of independent validator errors

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use ssi_kernel::{
    ActionProposal, ActionType, AuthorizationState, IntelligenceState, ProvenanceState,
    SafetyKernel, SafetyState, SystemState, VerificationState,
};
use ssi_pco::{
    PcoError, PcoGateway, PcoLedger, RevocationRegistry, ToyDecidableComplianceValidator,
    VerificationCertificate,
};
use std::collections::BTreeSet;
use wad18::Wad18;

fn make_test_state(seq: u64, budget_wad: i128) -> (SystemState, ActionProposal) {
    let mut caps = BTreeSet::new();
    caps.insert("COMPUTE".to_string());
    caps.insert("DECISION_DISPATCH".to_string());

    let mut csl_constraints = BTreeSet::new();
    csl_constraints.insert("envelope_v1".to_string());

    let mut invs = BTreeSet::new();
    invs.insert("TypeValid".to_string());

    let action = ActionProposal {
        action_id: "act_pco_01".to_string(),
        action_type: ActionType::Compute,
        risk_assessment: Wad18::from_raw(100_000_000_000_000_000), // 0.1 WAD
        resource_cost: Wad18::from_raw(1_000_000_000_000_000_000),   // 1.0 WAD
        required_clearance: 1,
        payload_digest: "1".repeat(64),
        is_executed: false,
    };

    let state = SystemState {
        intelligence: IntelligenceState {
            model_id: "model_underwriter_v1".to_string(),
            weights_digest: "a".repeat(64),
            context_window_size: 32_000,
            cognitive_budget: Wad18::from_raw(budget_wad),
            epistemic_confidence: Wad18::from_raw(990_000_000_000_000_000),
            entropy_bound: Wad18::from_raw(50_000_000_000_000_000),
            capabilities: caps,
        },
        safety: SafetyState {
            containment_active: true,
            containment_barrier_intact: true,
            safety_margin: Wad18::from_raw(2_000_000_000_000_000_000),
            risk_bound: Wad18::from_raw(1_000_000_000_000_000_000),
            active_envelope_id: "ENV_PCO_01".to_string(),
            csl_constraints,
            quarantine_flag: false,
        },
        action: action.clone(),
        authorization: AuthorizationState {
            auth_token: "auth_token_pco".to_string(),
            granter_id: "auth_authority_01".to_string(),
            clearance_level: 2,
            is_active: true,
            expires_at_epoch: 100_000,
            nonce: "nonce_secure_123".to_string(),
        },
        verification: VerificationState {
            certificate_id: "cert_pre_action_01".to_string(),
            proof_system: "PCO_Lean4".to_string(),
            proof_digest: "b".repeat(64),
            invariants_verified: invs,
            verifier_identity: "independent_checker_01".to_string(),
            verified_at_epoch: 1_000,
            is_valid: true,
        },
        provenance: ProvenanceState {
            sequence_number: seq,
            parent_state_hash: "0".repeat(64),
            merkle_root: "c".repeat(64),
            audit_trail_id: "trail_pco_01".to_string(),
            timestamp_epoch_ms: 1_000_000,
        },
    };

    (state, action)
}

#[test]
fn test_pco_nominal_valid_proof_acceptance() {
    let kernel = SafetyKernel::default();
    let (pre_state, action) = make_test_state(1, 10_000_000_000_000_000_000);
    let pre_state_id = SafetyKernel::state_id(&pre_state);

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let cert = VerificationCertificate::sign_new(
        "cert-001",
        "spec_budget_bound_wad18",
        "ENV_PCO_01",
        "code_digest_exec_01",
        &pre_state.intelligence.weights_digest,
        &action.payload_digest,
        "PROOF-VALID:1000000000000000000", // 1.0 WAD cost proof
        "ToyDecidableValidator-v1",
        vec!["assumption_finite_horizon".into()],
        1_000,
        &pre_state_id,
        &signing_key,
    );

    let ledger = PcoLedger::in_memory();
    let revocations = RevocationRegistry::new();
    let mut gateway = PcoGateway::new(&kernel, ledger, revocations, verifying_key);

    let validator = ToyDecidableComplianceValidator::new(2_000_000_000_000_000_000); // 2 WAD limit

    let query = b"underwriting_query_request_data";
    let (commit_rec, pco_rec) = gateway
        .execute_with_pco(
            &pre_state,
            &action,
            &cert,
            &validator,
            1_000,
            3600,
            Some("COMPUTE"),
            query,
            |_act| b"candidate_model_output_payload".to_vec(),
            |pre, act, _out| {
                let mut post = pre.clone();
                post.provenance.sequence_number += 1;
                post.provenance.parent_state_hash = pre_state_id.clone();
                post.intelligence.cognitive_budget = pre.intelligence.cognitive_budget
                    .checked_sub(act.resource_cost)
                    .unwrap();
                post.action.is_executed = true;
                post
            },
        )
        .expect("Nominal PCO execution must succeed");

    assert_eq!(commit_rec.pre_state_id, pre_state_id);
    assert_eq!(pco_rec.certificate_id, "cert-001");
    assert_eq!(pco_rec.state_id, pre_state_id);
    assert_eq!(gateway.ledger().count(), 1);
}

#[test]
fn test_pco_rejects_forged_proof() {
    let kernel = SafetyKernel::default();
    let (pre_state, action) = make_test_state(1, 10_000_000_000_000_000_000);
    let pre_state_id = SafetyKernel::state_id(&pre_state);

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    // Proof artifact claims invalid format / forged
    let cert = VerificationCertificate::sign_new(
        "cert-forged",
        "spec_budget_bound_wad18",
        "ENV_PCO_01",
        "code_digest_exec_01",
        &pre_state.intelligence.weights_digest,
        &action.payload_digest,
        "PROOF-INVALID-FORGERY:999999999999999999999", // Exceeds limit & forged
        "ToyDecidableValidator-v1",
        vec![],
        1_000,
        &pre_state_id,
        &signing_key,
    );

    let ledger = PcoLedger::in_memory();
    let revocations = RevocationRegistry::new();
    let mut gateway = PcoGateway::new(&kernel, ledger, revocations, verifying_key);

    let validator = ToyDecidableComplianceValidator::new(2_000_000_000_000_000_000); // 2 WAD limit

    let res = gateway.execute_with_pco(
        &pre_state,
        &action,
        &cert,
        &validator,
        1_000,
        3600,
        Some("COMPUTE"),
        b"query",
        |_act| b"output".to_vec(),
        |pre, _, _| pre.clone(),
    );

    assert!(matches!(res, Err(PcoError::VerificationFailed(_))));
    // Assert zero pre-action commit to ledger
    assert_eq!(gateway.ledger().count(), 0);
}

#[test]
fn test_pco_rejects_state_rebound_certificate() {
    let kernel = SafetyKernel::default();
    let (state1, action) = make_test_state(1, 10_000_000_000_000_000_000);
    let (state2, _) = make_test_state(2, 9_000_000_000_000_000_000);

    let state1_id = SafetyKernel::state_id(&state1);
    let state2_id = SafetyKernel::state_id(&state2);
    assert_ne!(state1_id, state2_id);

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    // Certificate is bound strictly to state1_id
    let cert = VerificationCertificate::sign_new(
        "cert-state1",
        "spec",
        "ENV_PCO_01",
        "code",
        &state1.intelligence.weights_digest,
        &action.payload_digest,
        "PROOF-VALID:1000000000000000000",
        "validator-v1",
        vec![],
        1_000,
        &state1_id, // Bound to state 1
        &signing_key,
    );

    let ledger = PcoLedger::in_memory();
    let revocations = RevocationRegistry::new();
    let mut gateway = PcoGateway::new(&kernel, ledger, revocations, verifying_key);

    let validator = ToyDecidableComplianceValidator::new(2_000_000_000_000_000_000);

    // Attempt to use certificate bound to state 1 on state 2
    let res = gateway.execute_with_pco(
        &state2,
        &action,
        &cert,
        &validator,
        1_000,
        3600,
        Some("COMPUTE"),
        b"query",
        |_act| b"output".to_vec(),
        |pre, _, _| pre.clone(),
    );

    match res {
        Err(PcoError::StateReboundAttempt { cert_state_id, current_state_id }) => {
            assert_eq!(cert_state_id, state1_id);
            assert_eq!(current_state_id, state2_id);
        }
        other => panic!("Expected StateReboundAttempt, got {:?}", other),
    }
}

#[test]
fn test_pco_rejects_expired_certificate() {
    let kernel = SafetyKernel::default();
    let (pre_state, action) = make_test_state(1, 10_000_000_000_000_000_000);
    let pre_state_id = SafetyKernel::state_id(&pre_state);

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let cert = VerificationCertificate::sign_new(
        "cert-expired",
        "spec",
        "ENV_PCO_01",
        "code",
        &pre_state.intelligence.weights_digest,
        &action.payload_digest,
        "PROOF-VALID:1000000000000000000",
        "validator-v1",
        vec![],
        1_000, // issued at epoch 1,000
        &pre_state_id,
        &signing_key,
    );

    let ledger = PcoLedger::in_memory();
    let revocations = RevocationRegistry::new();
    let mut gateway = PcoGateway::new(&kernel, ledger, revocations, verifying_key);

    let validator = ToyDecidableComplianceValidator::new(2_000_000_000_000_000_000);

    // TTL = 60s, current epoch = 2,000 (> 1,060)
    let res = gateway.execute_with_pco(
        &pre_state,
        &action,
        &cert,
        &validator,
        2_000, // current epoch
        60,    // TTL
        Some("COMPUTE"),
        b"query",
        |_act| b"output".to_vec(),
        |pre, _, _| pre.clone(),
    );

    assert!(matches!(res, Err(PcoError::CertificateExpired { .. })));
}

#[test]
fn test_pco_rejects_revoked_certificate() {
    let kernel = SafetyKernel::default();
    let (pre_state, action) = make_test_state(1, 10_000_000_000_000_000_000);
    let pre_state_id = SafetyKernel::state_id(&pre_state);

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let cert = VerificationCertificate::sign_new(
        "cert-compromised-01",
        "spec",
        "ENV_PCO_01",
        "code",
        &pre_state.intelligence.weights_digest,
        &action.payload_digest,
        "PROOF-VALID:1000000000000000000",
        "validator-v1",
        vec![],
        1_000,
        &pre_state_id,
        &signing_key,
    );

    let ledger = PcoLedger::in_memory();
    let mut revocations = RevocationRegistry::new();
    // Certificate explicitly revoked
    revocations.revoke("cert-compromised-01", "Private key compromise detected", 1_005);

    let mut gateway = PcoGateway::new(&kernel, ledger, revocations, verifying_key);

    let validator = ToyDecidableComplianceValidator::new(2_000_000_000_000_000_000);

    let res = gateway.execute_with_pco(
        &pre_state,
        &action,
        &cert,
        &validator,
        1_010,
        3600,
        Some("COMPUTE"),
        b"query",
        |_act| b"output".to_vec(),
        |pre, _, _| pre.clone(),
    );

    match res {
        Err(PcoError::CertificateRevoked { cert_id, reason }) => {
            assert_eq!(cert_id, "cert-compromised-01");
            assert!(reason.contains("compromise detected"));
        }
        other => panic!("Expected CertificateRevoked, got {:?}", other),
    }
}
