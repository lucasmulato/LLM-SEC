//! R^3 Governed Evolution Engine Demonstration Binary (Phase 3c).
//!
//! Demonstrates:
//! [Scenario 1] MUT-15: Attempting adoption with altered/forged kernel manifest -> REJECT
//! [Scenario 2] Compliant refinement Y adopted -> (K, M, G) -> (K, M', G') with SAC-1 commit
//! [Scenario 3] Non-regressing but unauthorized refinement -> REJECT
//! [Scenario 4] Quarantine and verified rollback upon failed adoption
//! [Scenario 5] SSI §26 Fixed-Point Harness demonstrating R^3(X*) = X*

#![deny(clippy::float_arithmetic)]

use std::collections::BTreeSet;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use ssi_csl::{CSLEnvelope, OperatingEnvelope, TemporalValidity};
use ssi_kernel::ActionType;
use ssi_r3::{
    CandidateRefinement, GovernanceAuthorization, GovernedConfig, KernelManifest, MutableModel,
    ProofArtifact, R3Engine, SystemPartition,
};
use wad18::Wad18;

fn main() {
    println!("============================================================");
    println!("   SSI-R^3: Governed Evolution Engine Demonstration");
    println!("   Axiomatic Implementation (SSI Defs 22-25, Theorem 6, §26)");
    println!("============================================================\n");

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

    let initial_partition = SystemPartition::new(kernel, model, config);
    let mut engine = R3Engine::new(initial_partition.clone());

    // Scenario 1: MUT-15 (Adoption without kernel equality)
    println!("[Scenario 1] Submitting candidate with mutated/forged kernel manifest (MUT-15)...");
    let mut cand_mut15 = build_candidate(
        &signing_key,
        &initial_partition,
        "cand-mut15",
        "model-ssi-v2-mutated",
        &"2".repeat(64),
        100,
    );
    cand_mut15.partition.kernel.artifact_hash = "forged_malicious_kernel_artifact_hash".to_string();

    match engine.propose_and_adopt(cand_mut15) {
        Ok(_) => panic!("FATAL: MUT-15 was adopted!"),
        Err(e) => {
            println!("  [PASS] Caught & Rejected: {}", e);
        }
    }

    // Scenario 2: Compliant refinement adopted
    println!("\n[Scenario 2] Submitting compliant refinement with verified proofs and signatures...");
    let cand_compliant = build_candidate(
        &signing_key,
        &initial_partition,
        "cand-compliant",
        "model-ssi-v2-optimized",
        &"3".repeat(64),
        200,
    );

    match engine.propose_and_adopt(cand_compliant) {
        Ok(adopted) => {
            println!("  [PASS] Compliant refinement ADOPTED: (K, M, G) -> (K, M', G')");
            println!("  [PASS] New active model: {}", adopted.model.model_id);
            println!("  [PASS] SAC-1 Evidence sealed into hash-chain: record_hash={}", engine.ledger.last_record_hash());
        }
        Err(e) => panic!("FATAL: Compliant candidate rejected: {:?}", e),
    }

    // Scenario 3: Non-regressing but unauthorized refinement
    println!("\n[Scenario 3] Submitting non-regressing candidate with forged governance signature...");
    let current_active = engine.active_partition().clone();
    let mut cand_unauth = build_candidate(
        &signing_key,
        &current_active,
        "cand-unauth",
        "model-ssi-v3-unauth",
        &"4".repeat(64),
        300,
    );
    cand_unauth.authorization.signature_bytes[0] ^= 0xEE;

    match engine.propose_and_adopt(cand_unauth) {
        Ok(_) => panic!("FATAL: Unauthorized candidate was adopted!"),
        Err(e) => {
            println!("  [PASS] Caught & Rejected: {}", e);
        }
    }

    // Scenario 4: Failed adoption quarantine & rollback
    println!("\n[Scenario 4] Verifying state rollback and quarantine logging...");
    let pre_weights = engine.active_partition().model.weights_digest.clone();
    let mut cand_bad_proof = build_candidate(
        &signing_key,
        &current_active,
        "cand-bad-proof",
        "model-ssi-v4-bad-proof",
        &"5".repeat(64),
        400,
    );
    cand_bad_proof.proof.is_valid = false;

    match engine.propose_and_adopt(cand_bad_proof) {
        Ok(_) => panic!("FATAL: Invalid proof candidate was adopted!"),
        Err(e) => {
            println!("  [PASS] Candidate quarantined: {}", e);
            assert_eq!(
                engine.active_partition().model.weights_digest,
                pre_weights,
                "Rollback violation: active model weights changed after rejected adoption"
            );
            println!("  [PASS] State Rollback Verified: active model partition completely unchanged.");
            println!("  [PASS] Quarantine Log entries count: {}", engine.ledger.quarantine_log.len());
        }
    }

    // Scenario 5: Fixed-point evolution harness R^3(X*) = X* (SSI §26)
    println!("\n[Scenario 5] Fixed-Point Evolution Harness: verifying R^3(X*) = X* (SSI §26)...");
    let stable_active = engine.active_partition().clone();
    let cand_fixed_point = build_candidate(
        &signing_key,
        &stable_active,
        "cand-fixed-point-terminal",
        "model-ssi-terminal-state",
        &"6".repeat(64),
        500,
    );

    match engine.fixed_point_harness(cand_fixed_point) {
        Ok(verdict) => {
            println!("  [PASS] Fixed-point computation: R^3(X*) = X* established.");
            println!("  [PASS] State ID: {}", verdict.post_state_id);
            println!("  [PASS] SSI Predicate verified: {}", verdict.ssi_valid);
            println!("  [PASS] SAC Evidence sealed: record_hash={}", verdict.sac_record_hash);
        }
        Err(e) => panic!("FATAL: Fixed-point harness failed: {:?}", e),
    }

    println!("\n============================================================");
    println!("   VERDICT: ALL 5 R^3 SCENARIOS VERIFIED SUCCESSFULLY");
    println!("============================================================");
}

fn build_candidate(
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
        "proof-ssi-r3-cert",
        "Lean4+TLC",
        "8".repeat(64).as_str(),
        "independent-ssi-validator",
        true,
    );

    let pubkey = signing_key.verifying_key().to_bytes();
    let config_id_hash = hex::encode(Sha256::digest(
        candidate_partition.config.config_id.as_bytes(),
    ));

    let mut auth = GovernanceAuthorization::new(
        "gov-auth-r3",
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
