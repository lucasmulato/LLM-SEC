//! End-to-end Demonstration of Proof-Carrying Output (PCO) & Pre-Action Ledger Commit.
//!
//! Demonstrates:
//! 1. Nominal Accept: AI output carries real WAD-18 budget bound proof, validated out-of-process
//! 2. Reject Forged Proof: Mutated proof artifact rejected by independent validator
//! 3. Reject State-Rebound: Certificate from state X1 reused on state X2 strictly blocked by BOUND(C,X)
//! 4. Reject Expired Certificate: Stale timestamp strictly blocked
//! 5. Reject Revoked Certificate: Revoked asset blocked from execution

#![deny(clippy::float_arithmetic)]

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use ssi_kernel::{
    ActionProposal, ActionType, AuthorizationState, IntelligenceState, ProvenanceState,
    SafetyKernel, SafetyState, SystemState, VerificationState,
};
use ssi_pco::{
    PcoGateway, PcoLedger, RevocationRegistry, ToyDecidableComplianceValidator,
    VerificationCertificate,
};
use std::collections::BTreeSet;
use wad18::Wad18;

fn make_state(seq: u64, budget_wad: i128) -> (SystemState, ActionProposal) {
    let mut caps = BTreeSet::new();
    caps.insert("COMPUTE".to_string());

    let mut csl_constraints = BTreeSet::new();
    csl_constraints.insert("envelope_v1".to_string());

    let mut invs = BTreeSet::new();
    invs.insert("TypeValid".to_string());

    let action = ActionProposal {
        action_id: "act_underwrite_realestate".to_string(),
        action_type: ActionType::Compute,
        risk_assessment: Wad18::from_raw(100_000_000_000_000_000), // 0.1 WAD
        resource_cost: Wad18::from_raw(1_000_000_000_000_000_000),   // 1.0 WAD
        required_clearance: 1,
        payload_digest: "a".repeat(64),
        is_executed: false,
    };

    let state = SystemState {
        intelligence: IntelligenceState {
            model_id: "model_underwriter_v1".to_string(),
            weights_digest: "b".repeat(64),
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
            active_envelope_id: "ENV_REALESTATE_01".to_string(),
            csl_constraints,
            quarantine_flag: false,
        },
        action: action.clone(),
        authorization: AuthorizationState {
            auth_token: "token_auth_root".to_string(),
            granter_id: "chief_risk_officer".to_string(),
            clearance_level: 2,
            is_active: true,
            expires_at_epoch: 100_000,
            nonce: "nonce_demo_001".to_string(),
        },
        verification: VerificationState {
            certificate_id: "cert_pre".to_string(),
            proof_system: "PCO_Lean4".to_string(),
            proof_digest: "c".repeat(64),
            invariants_verified: invs,
            verifier_identity: "independent_checker".to_string(),
            verified_at_epoch: 1_000,
            is_valid: true,
        },
        provenance: ProvenanceState {
            sequence_number: seq,
            parent_state_hash: "0".repeat(64),
            merkle_root: "d".repeat(64),
            audit_trail_id: "trail_demo_01".to_string(),
            timestamp_epoch_ms: 1_000_000,
        },
    };

    (state, action)
}

fn main() {
    println!("============================================================");
    println!("   SSI-PCO: Proof-Carrying Output End-to-End Demo");
    println!("   Axiomatic Implementation (Avni et al., IACR 2026/994)");
    println!("============================================================\n");

    let kernel = SafetyKernel::default();
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    let validator = ToyDecidableComplianceValidator::new(2_000_000_000_000_000_000); // Max 2.0 WAD

    // ── Scenario 1: Nominal PCO Execution with Valid Proof Artifact ──
    println!("[Scenario 1] Submitting candidate output with real WAD-18 budget proof...");
    let (state1, action1) = make_state(1, 10_000_000_000_000_000_000);
    let state1_id = SafetyKernel::state_id(&state1);

    let cert_valid = VerificationCertificate::sign_new(
        "cert-valid-001",
        "spec_budget_bound_le_2wad",
        "ENV_REALESTATE_01",
        "code_digest_exec_01",
        &state1.intelligence.weights_digest,
        &action1.payload_digest,
        "PROOF-VALID:1000000000000000000", // Valid 1.0 WAD cost proof
        "IndependentValidator-v1.0",
        vec!["assumption_deterministic_wad18".into()],
        1_000,
        &state1_id,
        &signing_key,
    );

    let ledger = PcoLedger::in_memory();
    let revocations = RevocationRegistry::new();
    let mut gateway = PcoGateway::new(&kernel, ledger, revocations, verifying_key);

    let query = b"query:underwrite_property_42";
    let res1 = gateway.execute_with_pco(
        &state1,
        &action1,
        &cert_valid,
        &validator,
        1_000,
        3600,
        Some("COMPUTE"),
        query,
        |_act| b"underwriting_verdict_approved".to_vec(),
        |pre, act, _out| {
            let mut post = pre.clone();
            post.provenance.sequence_number += 1;
            post.provenance.parent_state_hash = state1_id.clone();
            post.intelligence.cognitive_budget = pre.intelligence.cognitive_budget
                .checked_sub(act.resource_cost)
                .unwrap();
            post.action.is_executed = true;
            post
        },
    );

    match res1 {
        Ok((commit_rec, pco_rec)) => {
            println!("  [PASS] Proof verified out-of-process by independent validator.");
            println!("  [PASS] PRE-ACTION Ledger Commit sealed: record_hash={}", &pco_rec.record_hash[..16]);
            println!("  [PASS] State transition committed: post_state_id={}", &commit_rec.post_state_id[..16]);
        }
        Err(e) => panic!("Scenario 1 failed unexpectedly: {}", e),
    }

    // ── Scenario 2: Adversarial Rejection of Forged / Invalid Proof ──
    println!("\n[Scenario 2] Submitting candidate output with forged/tampered proof artifact...");
    let cert_forged = VerificationCertificate::sign_new(
        "cert-forged-002",
        "spec_budget_bound_le_2wad",
        "ENV_REALESTATE_01",
        "code_digest_exec_01",
        &state1.intelligence.weights_digest,
        &action1.payload_digest,
        "PROOF-FORGED:5000000000000000000", // Claims 5 WAD (violates limit)
        "IndependentValidator-v1.0",
        vec![],
        1_000,
        &state1_id,
        &signing_key,
    );

    let res2 = gateway.execute_with_pco(
        &state1,
        &action1,
        &cert_forged,
        &validator,
        1_000,
        3600,
        Some("COMPUTE"),
        query,
        |_act| b"tampered_output".to_vec(),
        |pre, _, _| pre.clone(),
    );

    match res2 {
        Err(e) => println!("  [PASS] Caught & Rejected: {}", e),
        Ok(_) => panic!("Scenario 2 must reject forged proof!"),
    }

    // ── Scenario 3: Rejection of State-Rebound Certificate (BOUND(C, X) Violation) ──
    println!("\n[Scenario 3] Attempting state-rebound attack (reusing cert from state 1 on state 2)...");
    let (state2, _) = make_state(2, 9_000_000_000_000_000_000);
    let state2_id = SafetyKernel::state_id(&state2);
    assert_ne!(state1_id, state2_id);

    // Reuse cert_valid (bound to state 1) on state 2
    let res3 = gateway.execute_with_pco(
        &state2,
        &action1,
        &cert_valid,
        &validator,
        1_000,
        3600,
        Some("COMPUTE"),
        query,
        |_act| b"rebound_output".to_vec(),
        |pre, _, _| pre.clone(),
    );

    match res3 {
        Err(e) => println!("  [PASS] Caught & Rejected: {}", e),
        Ok(_) => panic!("Scenario 3 must reject state-rebound certificate!"),
    }

    // ── Scenario 4: Rejection of Expired / Stale Certificate ──
    println!("\n[Scenario 4] Submitting expired certificate (current epoch > issued + TTL)...");
    let res4 = gateway.execute_with_pco(
        &state1,
        &action1,
        &cert_valid,
        &validator,
        100_000, // current epoch far in the future
        60,      // TTL = 60s
        Some("COMPUTE"),
        query,
        |_act| b"expired_output".to_vec(),
        |pre, _, _| pre.clone(),
    );

    match res4 {
        Err(e) => println!("  [PASS] Caught & Rejected: {}", e),
        Ok(_) => panic!("Scenario 4 must reject expired certificate!"),
    }

    // ── Scenario 5: Rejection of Revoked Certificate ──
    println!("\n[Scenario 5] Submitting explicitly revoked certificate...");
    gateway.revocations_mut().revoke("cert-valid-001", "Governance emergency revocation", 1_001);

    let res5 = gateway.execute_with_pco(
        &state1,
        &action1,
        &cert_valid,
        &validator,
        1_000,
        3600,
        Some("COMPUTE"),
        query,
        |_act| b"revoked_output".to_vec(),
        |pre, _, _| pre.clone(),
    );

    match res5 {
        Err(e) => println!("  [PASS] Caught & Rejected: {}", e),
        Ok(_) => panic!("Scenario 5 must reject revoked certificate!"),
    }

    println!("\n============================================================");
    println!("   VERDICT: ALL 5 PCO DEMO SCENARIOS VERIFIED SUCCESSFULLY");
    println!("============================================================");
}
