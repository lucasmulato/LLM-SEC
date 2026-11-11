//! Comprehensive Integration Test Suite for SSI R^3 Governed Evolution Engine.
//!
//! Validates:
//! 1. Mutation #15 (Adoption without kernel equality) rejected fail-closed (PO-7).
//! 2. Compliant refinement adopted with SAC evidence ledger commit (PO-7, PO-8).
//! 3. Non-regressing but unauthorized refinement rejected fail-closed (PO-3).
//! 4. Failed adoption quarantine and state rollback path verified.
//! 5. Fixed-point evolution harness R^3(X*) = X* (SSI §26).

use std::collections::BTreeSet;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use ssi_csl::{CSLEnvelope, OperatingEnvelope, TemporalValidity};
use ssi_kernel::ActionType;
use ssi_r3::{
    CandidateRefinement, GovernanceAuthorization, GovernedConfig, KernelManifest, MutableModel,
    ProofArtifact, R3Engine, R3Error, SystemPartition,
};
use wad18::Wad18;

fn create_test_fixture() -> (SigningKey, SystemPartition) {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);

    let kernel = KernelManifest::default();

    let mut capabilities = BTreeSet::new();
    capabilities.insert("code_analysis".to_string());
    capabilities.insert("formal_verification".to_string());

    let model = MutableModel::new(
        "model-ssi-v1",
        "1".repeat(64).as_str(),
        32768,
        Wad18::from_raw(1_000_000_000_000_000_000), // 1.0
        Wad18::from_raw(950_000_000_000_000_000),   // 0.95
        Wad18::from_raw(100_000_000_000_000_000),   // 0.10
        capabilities,
        "a".repeat(64).as_str(),
    );

    let mut allowed_actions = BTreeSet::new();
    allowed_actions.insert(ActionType::Read);
    allowed_actions.insert(ActionType::Compute);

    let mut mandatory_invariants = BTreeSet::new();
    mandatory_invariants.insert("phi_safety_margin".to_string());
    mandatory_invariants.insert("phi_monotonic_budget".to_string());

    let envelope = OperatingEnvelope {
        envelope_id: "env-ssi-v1".to_string(),
        max_risk_bound: Wad18::from_raw(100_000_000_000_000_000), // 0.10
        allowed_action_types: allowed_actions.clone(),
        max_resource_cost_per_action: Wad18::from_raw(20_000_000_000_000_000), // 0.02
        total_budget_limit: Wad18::from_raw(10_000_000_000_000_000_000), // 10.0
    };

    let validity = TemporalValidity {
        valid_from_epoch: 0,
        valid_until_epoch: 100_000,
        max_transitions: 1000,
    };

    let mut csl = CSLEnvelope {
        auth_id: "csl-auth-gov-001".to_string(),
        signature: signing_key.sign(&[0u8; 32]),
        envelope,
        validity,
        constraints: mandatory_invariants.clone(),
    };
    csl.signature = signing_key.sign(&csl.canonical_digest_bytes());

    let config = GovernedConfig::new(
        "config-ssi-v1",
        csl,
        Wad18::from_raw(100_000_000_000_000_000), // 0.10
        Wad18::from_raw(10_000_000_000_000_000_000), // 10.0
        allowed_actions,
        mandatory_invariants,
    );

    (signing_key, SystemPartition::new(kernel, model, config))
}

fn create_valid_candidate(
    signing_key: &SigningKey,
    current_partition: &SystemPartition,
    candidate_id: &str,
    new_model_id: &str,
    new_weights: &str,
    epoch: i64,
) -> CandidateRefinement {
    let mut candidate_model = current_partition.model.clone();
    candidate_model.model_id = new_model_id.to_string();
    candidate_model.weights_digest = new_weights.to_string();

    let candidate_partition = SystemPartition::new(
        current_partition.kernel.clone(),
        candidate_model,
        current_partition.config.clone(),
    );

    let proof = ProofArtifact::new(
        "proof-ssi-001",
        "Lean4+TLC",
        "2".repeat(64).as_str(),
        "independent-verifier-process",
        true,
    );

    let pubkey = signing_key.verifying_key().to_bytes();
    let config_id_hash = hex::encode(Sha256::digest(
        candidate_partition.config.config_id.as_bytes(),
    ));

    let mut auth = GovernanceAuthorization::new(
        "gov-auth-001",
        pubkey,
        [0u8; 64],
        epoch + 5000,
        false,
        &candidate_partition.model.weights_digest,
        &config_id_hash,
    );
    let digest_bytes = auth.canonical_digest_bytes();
    let sig = signing_key.sign(&digest_bytes);
    auth.signature_bytes = sig.to_bytes();

    CandidateRefinement::new(
        candidate_id,
        candidate_partition,
        proof,
        auth,
        epoch,
    )
}

#[test]
fn test_mutation_15_rejected_adoption_without_kernel_equality() {
    let (signing_key, initial_partition) = create_test_fixture();
    let mut engine = R3Engine::new(initial_partition.clone());

    let mut candidate = create_valid_candidate(
        &signing_key,
        &initial_partition,
        "candidate-mut15",
        "model-ssi-v2",
        &"2".repeat(64),
        100,
    );

    // MUT-15: Inject altered/mutated kernel manifest
    candidate.partition.kernel.artifact_hash = "forged_malicious_kernel_artifact_hash".to_string();

    let res = engine.propose_and_adopt(candidate);
    assert!(res.is_err(), "Adoption without kernel equality must be rejected");

    match res.unwrap_err() {
        R3Error::KernelEqualityBreach { expected_digest, got_digest, .. } => {
            assert_ne!(expected_digest, got_digest);
        }
        other => panic!("Expected KernelEqualityBreach, got {:?}", other),
    }

    // Verify rollback: active partition is untouched
    assert_eq!(
        engine.active_partition().kernel.manifest_digest(),
        initial_partition.kernel.manifest_digest()
    );
    assert_eq!(
        engine.active_partition().model.model_id,
        initial_partition.model.model_id
    );
}

#[test]
fn test_compliant_refinement_adopted() {
    let (signing_key, initial_partition) = create_test_fixture();
    let mut engine = R3Engine::new(initial_partition.clone());

    let candidate = create_valid_candidate(
        &signing_key,
        &initial_partition,
        "candidate-compliant",
        "model-ssi-v2-optimized",
        &"3".repeat(64),
        200,
    );

    let res = engine.propose_and_adopt(candidate);
    assert!(res.is_ok(), "Compliant refinement must be successfully adopted");

    let active = engine.active_partition();
    assert_eq!(active.model.model_id, "model-ssi-v2-optimized");
    assert_eq!(active.model.weights_digest, "3".repeat(64));
    assert_eq!(active.kernel.manifest_digest(), initial_partition.kernel.manifest_digest());

    // Verify SAC-1 evidence committed to ledger
    let sac_records = engine.ledger.sac_records();
    assert_eq!(sac_records.len(), 1, "Adoption must produce exactly one SAC record");
    assert_eq!(sac_records[0].sac_class.as_str(), "SAC-1");
}

#[test]
fn test_non_regressing_but_unauthorized_refinement_rejected() {
    let (signing_key, initial_partition) = create_test_fixture();
    let mut engine = R3Engine::new(initial_partition.clone());

    let mut candidate = create_valid_candidate(
        &signing_key,
        &initial_partition,
        "candidate-unauth",
        "model-ssi-v2-unauth",
        &"4".repeat(64),
        300,
    );

    // Corrupt the governance signature
    candidate.authorization.signature_bytes[0] ^= 0xFF;

    let res = engine.propose_and_adopt(candidate);
    assert!(res.is_err(), "Non-regressing but unauthorized candidate must be rejected");

    match res.unwrap_err() {
        R3Error::AuthorizationInvalid { reason } => {
            assert!(reason.contains("signature invalid"));
        }
        other => panic!("Expected AuthorizationInvalid, got {:?}", other),
    }

    // Test expired authorization
    let mut candidate_expired = create_valid_candidate(
        &signing_key,
        &initial_partition,
        "candidate-expired",
        "model-ssi-v2-expired",
        &"5".repeat(64),
        10_000,
    );
    candidate_expired.authorization.valid_until_epoch = 5_000; // Expired relative to 10_000

    let res_exp = engine.propose_and_adopt(candidate_expired);
    assert!(res_exp.is_err(), "Expired authorization must be rejected");
}

#[test]
fn test_failed_adoption_rollback_and_quarantine() {
    let (signing_key, initial_partition) = create_test_fixture();
    let mut engine = R3Engine::new(initial_partition.clone());

    let mut candidate = create_valid_candidate(
        &signing_key,
        &initial_partition,
        "candidate-quarantine",
        "model-ssi-v2-failing",
        &"6".repeat(64),
        400,
    );

    // Mark proof invalid
    candidate.proof.is_valid = false;

    let res = engine.propose_and_adopt(candidate);
    assert!(res.is_err());

    // Verify candidate is logged in quarantine
    assert_eq!(engine.ledger.quarantine_log.len(), 1);
    assert_eq!(engine.ledger.quarantine_log[0].candidate_id, "candidate-quarantine");

    // Verify rollback: active system partition completely unchanged
    assert_eq!(engine.active_partition().model.model_id, initial_partition.model.model_id);
    assert_eq!(engine.active_partition().model.weights_digest, initial_partition.model.weights_digest);
    assert_eq!(engine.sequence_number, 0);
}

#[test]
fn test_fixed_point_harness_r3_x_star() {
    let (signing_key, initial_partition) = create_test_fixture();
    let mut engine = R3Engine::new(initial_partition.clone());

    let candidate = create_valid_candidate(
        &signing_key,
        &initial_partition,
        "candidate-fixed-point",
        "model-ssi-fixed-point",
        &"7".repeat(64),
        500,
    );

    let verdict = engine.fixed_point_harness(candidate);
    assert!(verdict.is_ok(), "Fixed-point harness must succeed on compliant candidate");

    let v = verdict.unwrap();
    assert!(v.is_fixed_point);
    assert!(v.ssi_valid);
    assert_eq!(v.candidate_id, "candidate-fixed-point");
    assert_eq!(v.post_state_id.len(), 64);
    assert!(!v.sac_record_hash.is_empty());
}
