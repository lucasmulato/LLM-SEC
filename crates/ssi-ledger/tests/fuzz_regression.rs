//! Fuzz regression test for deterministic canonical state encoding and hashing.
//! Validates mathematical stability under varied field encodings and inputs.

use ssi_kernel::{
    ActionProposal, ActionType, AuthorizationState, IntelligenceState, ProvenanceState,
    SafetyState, SystemState, VerificationState,
};
use ssi_ledger::{canonical_encode_state, compute_state_id};
use wad18::Wad18;

#[test]
fn test_fuzz_canonical_state_encoding_determinism() {
    let mut seed: u64 = 0xdeadbeef;
    let mut next_u64 = || {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        seed
    };

    for i in 0..1000 {
        let r1 = next_u64() as i128;
        let r2 = next_u64() as i128;
        let seq = next_u64() % 1_000_000;

        let state = SystemState {
            intelligence: IntelligenceState {
                model_id: format!("model_{}", i),
                weights_digest: format!("{:064x}", next_u64()),
                context_window_size: next_u64() % 128000,
                cognitive_budget: Wad18::from_raw(r1),
                epistemic_confidence: Wad18::from_raw(r2),
                entropy_bound: Wad18::from_raw(100),
                capabilities: std::collections::BTreeSet::new(),
            },
            safety: SafetyState {
                containment_active: (next_u64() % 2) == 0,
                containment_barrier_intact: true,
                safety_margin: Wad18::from_raw(50),
                risk_bound: Wad18::from_raw(1000),
                active_envelope_id: format!("env_{}", next_u64()),
                csl_constraints: std::collections::BTreeSet::new(),
                quarantine_flag: false,
            },
            action: ActionProposal {
                action_id: format!("act_{}", next_u64()),
                action_type: ActionType::Compute,
                risk_assessment: Wad18::from_raw(10),
                resource_cost: Wad18::from_raw(5),
                required_clearance: (next_u64() % 5) as u32,
                payload_digest: format!("{:064x}", next_u64()),
                is_executed: false,
            },
            authorization: AuthorizationState {
                auth_token: format!("token_{}", next_u64()),
                granter_id: "auth_granter".to_string(),
                clearance_level: 2,
                is_active: true,
                expires_at_epoch: (next_u64() % 100000) as i64,
                nonce: format!("nonce_{}", next_u64()),
            },
            verification: VerificationState {
                certificate_id: format!("cert_{}", next_u64()),
                proof_system: "WAD18-PCO".to_string(),
                proof_digest: format!("{:064x}", next_u64()),
                invariants_verified: std::collections::BTreeSet::new(),
                verifier_identity: "verifier".to_string(),
                verified_at_epoch: 100,
                is_valid: true,
            },
            provenance: ProvenanceState {
                sequence_number: seq,
                parent_state_hash: format!("{:064x}", next_u64()),
                merkle_root: format!("{:064x}", next_u64()),
                audit_trail_id: format!("audit_{}", next_u64()),
                timestamp_epoch_ms: (next_u64() % 10000000) as i64,
            },
        };

        // Invariant: Encoding and ID computation must be deterministic
        let enc1 = canonical_encode_state(&state);
        let enc2 = canonical_encode_state(&state);
        assert_eq!(enc1, enc2);

        let id1 = compute_state_id(&state);
        let id2 = compute_state_id(&state);
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 64);
    }
}
