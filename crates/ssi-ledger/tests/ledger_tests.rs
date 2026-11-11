use std::collections::BTreeSet;
use std::fs;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use ssi_csl::{CSLEnvelope, OperatingEnvelope, TemporalValidity};
use ssi_kernel::{
    ActionProposal, ActionType, AuthorizationState, IntelligenceState, ProvenanceState,
    SafetyState, SystemState, VerificationState,
};
use ssi_ledger::{AppendOnlyLedgerStore, LedgerError, SafetyAssetClass};
use wad18::Wad18;

fn build_state(seq: u64, parent_hash: &str) -> SystemState {
    let mut caps = BTreeSet::new();
    caps.insert("COMPUTE".into());

    let mut q = BTreeSet::new();
    q.insert("NON_DECEPTION".into());

    SystemState {
        intelligence: IntelligenceState {
            model_id: "m".into(),
            weights_digest: "a".repeat(64),
            context_window_size: 1000,
            cognitive_budget: Wad18::from_int(50).unwrap(),
            epistemic_confidence: Wad18::ONE,
            entropy_bound: Wad18::ZERO,
            capabilities: caps,
        },
        safety: SafetyState {
            containment_active: true,
            containment_barrier_intact: true,
            safety_margin: Wad18::ONE,
            risk_bound: Wad18::ONE,
            active_envelope_id: "ENV-1".into(),
            csl_constraints: q,
            quarantine_flag: false,
        },
        action: ActionProposal {
            action_id: format!("act-{seq}"),
            action_type: ActionType::Compute,
            risk_assessment: Wad18::ZERO,
            resource_cost: Wad18::ONE,
            required_clearance: 1,
            payload_digest: "b".repeat(64),
            is_executed: true,
        },
        authorization: AuthorizationState {
            auth_token: "t".into(),
            granter_id: "g".into(),
            clearance_level: 1,
            is_active: true,
            expires_at_epoch: 2_000_000_000,
            nonce: "n".into(),
        },
        verification: VerificationState {
            certificate_id: "c".into(),
            proof_system: "P".into(),
            proof_digest: "c".repeat(64),
            invariants_verified: BTreeSet::new(),
            verifier_identity: "V".into(),
            verified_at_epoch: 1,
            is_valid: true,
        },
        provenance: ProvenanceState {
            sequence_number: seq,
            parent_state_hash: parent_hash.into(),
            merkle_root: "e".repeat(64),
            audit_trail_id: "aud".into(),
            timestamp_epoch_ms: 1000 * seq as i64,
        },
    }
}

fn build_csl() -> CSLEnvelope {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);

    let mut allowed = BTreeSet::new();
    allowed.insert(ActionType::Compute);

    let envelope = OperatingEnvelope {
        envelope_id: "ENV".into(),
        max_risk_bound: Wad18::ONE,
        allowed_action_types: allowed,
        max_resource_cost_per_action: Wad18::ONE,
        total_budget_limit: Wad18::from_int(100).unwrap(),
    };
    let validity = TemporalValidity {
        valid_from_epoch: 0,
        valid_until_epoch: 2_000_000_000,
        max_transitions: 100,
    };
    CSLEnvelope::sign_new("AUTH-01", envelope, validity, BTreeSet::new(), &signing_key)
}

#[test]
fn test_append_only_ledger_in_memory_hash_chain() {
    let mut store = AppendOnlyLedgerStore::in_memory();
    let csl = build_csl();

    let s0 = build_state(0, "0".repeat(64).as_str());
    let a1 = s0.action.clone();
    let s1 = build_state(1, ssi_ledger::compute_state_id(&s0).as_str());

    let a2 = s1.action.clone();
    let s2 = build_state(2, ssi_ledger::compute_state_id(&s1).as_str());

    store.append_transition(
        &s0, &a1, &s1, &csl, "cert-1", SafetyAssetClass::Sac3FormalProvenance, "gamma-0", 1000
    ).unwrap();

    store.append_transition(
        &s1, &a2, &s2, &csl, "cert-2", SafetyAssetClass::Sac3FormalProvenance, "gamma-0", 2000
    ).unwrap();

    assert_eq!(store.records().len(), 2);
    assert_eq!(store.verify_integrity().unwrap(), 2);
}

#[test]
fn test_injected_tamper_detected_on_file_replay() {
    let test_dir = std::env::temp_dir().join("ssi_ledger_test");
    let _ = fs::create_dir_all(&test_dir);
    let ledger_file = test_dir.join("tamper_test.ndjson");
    let _ = fs::remove_file(&ledger_file);

    let csl = build_csl();

    // 1. Create a genuine ledger file with 2 records
    {
        let mut store = AppendOnlyLedgerStore::with_file(ledger_file.to_str().unwrap()).unwrap();
        let s0 = build_state(0, "0".repeat(64).as_str());
        let a1 = s0.action.clone();
        let s1 = build_state(1, ssi_ledger::compute_state_id(&s0).as_str());
        let a2 = s1.action.clone();
        let s2 = build_state(2, ssi_ledger::compute_state_id(&s1).as_str());

        store.append_transition(
            &s0, &a1, &s1, &csl, "cert-1", SafetyAssetClass::Sac3FormalProvenance, "gamma-0", 1000
        ).unwrap();
        store.append_transition(
            &s1, &a2, &s2, &csl, "cert-2", SafetyAssetClass::Sac3FormalProvenance, "gamma-0", 2000
        ).unwrap();
    }

    // Verify it loads and verifies cleanly first
    {
        let store = AppendOnlyLedgerStore::with_file(ledger_file.to_str().unwrap()).unwrap();
        assert_eq!(store.records().len(), 2);
        assert_eq!(store.verify_integrity().unwrap(), 2);
    }

    // 2. Inject Tampering: Modify sequence number or action payload in line 1
    let content = fs::read_to_string(&ledger_file).unwrap();
    let tampered_content = content.replacen("\"sequence_number\":1", "\"sequence_number\":99", 1);
    fs::write(&ledger_file, tampered_content).unwrap();

    // 3. Verify that AppendOnlyLedgerStore::with_file catches the tamper!
    let reload_res = AppendOnlyLedgerStore::with_file(ledger_file.to_str().unwrap());
    assert!(reload_res.is_err(), "Expected tampered file load to fail");

    let err = reload_res.err().unwrap();
    assert!(
        matches!(err, LedgerError::TamperedRecord { .. } | LedgerError::SequenceDiscontinuity { .. }),
        "Expected tamper or sequence error, got: {err}"
    );

    // Clean up
    let _ = fs::remove_file(&ledger_file);
}

#[test]
fn test_generate_audit_sample_fixture() {
    let fixture_path = "../../tests/fixtures/audit_sample.ndjson";
    let _ = fs::remove_file(fixture_path);

    let mut store = AppendOnlyLedgerStore::with_file(fixture_path).unwrap();

    let mut csprng = OsRng;
    let key = SigningKey::generate(&mut csprng);

    let csl = CSLEnvelope::sign_new(
        "AUTH-FIXTURE",
        OperatingEnvelope {
            envelope_id: "ENV-FIXTURE".into(),
            max_risk_bound: Wad18::ONE,
            max_resource_cost_per_action: Wad18::from_int(10).unwrap(),
            total_budget_limit: Wad18::from_int(100).unwrap(),
            allowed_action_types: BTreeSet::new(),
        },
        TemporalValidity {
            valid_from_epoch: 0,
            valid_until_epoch: 10000,
            max_transitions: 100,
        },
        BTreeSet::new(),
        &key,
    );

    let s0 = build_state(0, &"0".repeat(64));
    let s1 = build_state(1, "hash-0");
    let a1 = s0.action.clone();
    store.append_transition(&s0, &a1, &s1, &csl, "cert-1", SafetyAssetClass::Sac3FormalProvenance, "gamma-step-1", 1000).unwrap();

    let s2 = build_state(2, "hash-1");
    let a2 = s1.action.clone();
    store.append_transition(&s1, &a2, &s2, &csl, "cert-2", SafetyAssetClass::Sac3FormalProvenance, "gamma-step-2", 2000).unwrap();

    let s3 = build_state(3, "hash-2");
    let a3 = s2.action.clone();
    store.append_transition(&s2, &a3, &s3, &csl, "cert-3", SafetyAssetClass::Sac3FormalProvenance, "gamma-step-3", 3000).unwrap();
}
