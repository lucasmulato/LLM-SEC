//! Integration Test Suite for Real-Estate Underwriting Pack (Russell 2026).

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use ssi_pco::{ToyDecidableComplianceValidator, VerificationCertificate};
use ssi_real_estate::{
    DualHumanApproval, LoanApplication, RealEstateError, RealEstateUnderwritingGateway,
    UnderwritingTier, create_underwriting_csl_envelope,
};
use wad18::Wad18;

fn create_nominal_application() -> LoanApplication {
    LoanApplication {
        application_id: "LOAN-TEST-001".to_string(),
        borrower_id: "BORROWER-CORP".to_string(),
        property_id: "PROP-NY-001".to_string(),
        jurisdiction: "US-NY".to_string(),
        property_value_wad: Wad18::from_raw(1_000_000_000_000_000_000_000_000), // $1M
        requested_loan_wad: Wad18::from_raw(650_000_000_000_000_000_000_000),   // $650k (65% LTV)
        net_operating_income_wad: Wad18::from_raw(150_000_000_000_000_000_000_000), // $150k
        annual_debt_service_wad: Wad18::from_raw(100_000_000_000_000_000_000_000),  // $100k (DSCR 1.5x)
        phase1_environmental_clean: true,
        flood_zone_certified: true,
        rent_roll_certified: true,
        aml_kyc_cleared: true,
        appraisal_digest: "7".repeat(64),
    }
}

fn build_test_cert(
    key: &SigningKey,
    state: &ssi_kernel::SystemState,
    state_id: &str,
    app: &LoanApplication,
    epoch: i64,
    proof_str: &str,
) -> VerificationCertificate {
    VerificationCertificate::sign_new(
        format!("pco-test-{}", app.application_id),
        "SPEC_TEST",
        "POLICY_TEST",
        "CODE_TEST",
        state.intelligence.weights_digest.clone(),
        app.payload_digest(),
        proof_str,
        "toy-decidable-compliance-validator-v1",
        vec!["ASSUME_TEST".to_string()],
        epoch,
        state_id,
        key,
    )
}

#[test]
fn test_nominal_commercial_loan_approval() {
    let mut csprng = OsRng;
    let underwriter_key = SigningKey::generate(&mut csprng);
    let underwriter_pub = underwriter_key.verifying_key().to_bytes();
    let validator = ToyDecidableComplianceValidator::new(50);
    let mut gateway = RealEstateUnderwritingGateway::new();

    let app = create_nominal_application();
    let csl = create_underwriting_csl_envelope(
        &underwriter_key,
        "auth-test-nominal",
        UnderwritingTier::Tier2Standard,
        1000,
        10_000,
        100,
    );

    let state = gateway.build_system_state(&app, &csl, 2000);
    let state_id = ssi_ledger::compute_state_id(&state);
    let cert = build_test_cert(
        &underwriter_key,
        &state,
        &state_id,
        &app,
        2000,
        "PROOF-VALID:10",
    );

    let res = gateway.evaluate_loan_proposal(&app, None, &csl, &underwriter_pub, &cert, &validator, 2000);
    assert!(res.is_ok(), "Nominal loan proposal must be approved");

    let outcome = res.unwrap();
    assert!(outcome.is_approved);
    assert_eq!(outcome.ltv_wad, 650_000_000_000_000_000);
    assert_eq!(outcome.dscr_wad, 1_500_000_000_000_000_000);
    assert!(!outcome.sac_record_hash.is_empty());
}

#[test]
fn test_high_value_loan_dual_approval_success() {
    let mut csprng = OsRng;
    let senior_key = SigningKey::generate(&mut csprng);
    let chair_key = SigningKey::generate(&mut csprng);
    let senior_pub = senior_key.verifying_key().to_bytes();
    let chair_pub = chair_key.verifying_key().to_bytes();

    let validator = ToyDecidableComplianceValidator::new(50);
    let mut gateway = RealEstateUnderwritingGateway::new();

    let mut app = create_nominal_application();
    app.requested_loan_wad = Wad18::from_raw(2_000_000_000_000_000_000_000_000); // $2.0M
    app.property_value_wad = Wad18::from_raw(4_000_000_000_000_000_000_000_000); // $4.0M (50% LTV)
    app.net_operating_income_wad = Wad18::from_raw(300_000_000_000_000_000_000_000);
    app.annual_debt_service_wad = Wad18::from_raw(200_000_000_000_000_000_000_000);

    let csl = create_underwriting_csl_envelope(
        &senior_key,
        "auth-test-dual",
        UnderwritingTier::Tier3Senior,
        1000,
        10_000,
        100,
    );

    let epoch = 2000;
    let digest = DualHumanApproval::canonical_digest_bytes(&app.application_id, app.requested_loan_wad.raw(), epoch);
    let sig_senior = senior_key.sign(&digest);
    let sig_chair = chair_key.sign(&digest);

    let dual_approval = DualHumanApproval {
        senior_underwriter_pubkey: senior_pub,
        senior_underwriter_sig: sig_senior.to_bytes(),
        risk_chair_pubkey: chair_pub,
        risk_chair_sig: sig_chair.to_bytes(),
        approval_epoch: epoch,
    };

    let state = gateway.build_system_state(&app, &csl, epoch);
    let state_id = ssi_ledger::compute_state_id(&state);
    let cert = build_test_cert(
        &senior_key,
        &state,
        &state_id,
        &app,
        epoch,
        "PROOF-VALID:10",
    );

    let res = gateway.evaluate_loan_proposal(
        &app,
        Some(&dual_approval),
        &csl,
        &senior_pub,
        &cert,
        &validator,
        epoch,
    );
    assert!(res.is_ok(), "High value loan with dual approval must be approved");
}

#[test]
fn test_high_value_loan_single_approval_fails() {
    let mut csprng = OsRng;
    let senior_key = SigningKey::generate(&mut csprng);
    let senior_pub = senior_key.verifying_key().to_bytes();
    let validator = ToyDecidableComplianceValidator::new(50);
    let mut gateway = RealEstateUnderwritingGateway::new();

    let mut app = create_nominal_application();
    app.requested_loan_wad = Wad18::from_raw(2_000_000_000_000_000_000_000_000); // $2.0M (> $1M threshold)
    app.property_value_wad = Wad18::from_raw(4_000_000_000_000_000_000_000_000);

    let csl = create_underwriting_csl_envelope(
        &senior_key,
        "auth-test-single",
        UnderwritingTier::Tier3Senior,
        1000,
        10_000,
        100,
    );

    let state = gateway.build_system_state(&app, &csl, 2000);
    let state_id = ssi_ledger::compute_state_id(&state);
    let cert = build_test_cert(
        &senior_key,
        &state,
        &state_id,
        &app,
        2000,
        "PROOF-VALID:10",
    );

    // Omit dual approval (pass None)
    let res = gateway.evaluate_loan_proposal(&app, None, &csl, &senior_pub, &cert, &validator, 2000);
    assert!(res.is_err(), "High value loan without dual approval must fail");
    match res.unwrap_err() {
        RealEstateError::DualHumanApprovalMissing { .. } => {}
        other => panic!("Expected DualHumanApprovalMissing, got {:?}", other),
    }
}

#[test]
fn test_ltv_cap_overflow_rejected() {
    let mut csprng = OsRng;
    let underwriter_key = SigningKey::generate(&mut csprng);
    let underwriter_pub = underwriter_key.verifying_key().to_bytes();
    let validator = ToyDecidableComplianceValidator::new(50);
    let mut gateway = RealEstateUnderwritingGateway::new();

    let mut app = create_nominal_application();
    app.requested_loan_wad = Wad18::from_raw(800_000_000_000_000_000_000_000); // $800k on $1M -> 80% LTV > 75% cap

    let csl = create_underwriting_csl_envelope(
        &underwriter_key,
        "auth-test-ltv",
        UnderwritingTier::Tier2Standard,
        1000,
        10_000,
        100,
    );

    let state = gateway.build_system_state(&app, &csl, 2000);
    let state_id = ssi_ledger::compute_state_id(&state);
    let cert = build_test_cert(
        &underwriter_key,
        &state,
        &state_id,
        &app,
        2000,
        "PROOF-VALID:10",
    );

    let res = gateway.evaluate_loan_proposal(&app, None, &csl, &underwriter_pub, &cert, &validator, 2000);
    assert!(res.is_err());
    match res.unwrap_err() {
        RealEstateError::LtvCapExceeded { .. } => {}
        other => panic!("Expected LtvCapExceeded, got {:?}", other),
    }
}

#[test]
fn test_dscr_floor_breach_rejected() {
    let mut csprng = OsRng;
    let underwriter_key = SigningKey::generate(&mut csprng);
    let underwriter_pub = underwriter_key.verifying_key().to_bytes();
    let validator = ToyDecidableComplianceValidator::new(50);
    let mut gateway = RealEstateUnderwritingGateway::new();

    let mut app = create_nominal_application();
    app.net_operating_income_wad = Wad18::from_raw(110_000_000_000_000_000_000_000); // $110k
    app.annual_debt_service_wad = Wad18::from_raw(100_000_000_000_000_000_000_000);  // $100k -> DSCR = 1.10x < 1.25x

    let csl = create_underwriting_csl_envelope(
        &underwriter_key,
        "auth-test-dscr",
        UnderwritingTier::Tier2Standard,
        1000,
        10_000,
        100,
    );

    let state = gateway.build_system_state(&app, &csl, 2000);
    let state_id = ssi_ledger::compute_state_id(&state);
    let cert = build_test_cert(
        &underwriter_key,
        &state,
        &state_id,
        &app,
        2000,
        "PROOF-VALID:10",
    );

    let res = gateway.evaluate_loan_proposal(&app, None, &csl, &underwriter_pub, &cert, &validator, 2000);
    assert!(res.is_err());
    match res.unwrap_err() {
        RealEstateError::DscrFloorBreached { .. } => {}
        other => panic!("Expected DscrFloorBreached, got {:?}", other),
    }
}

#[test]
fn test_prohibited_jurisdiction_rejected() {
    let mut csprng = OsRng;
    let underwriter_key = SigningKey::generate(&mut csprng);
    let underwriter_pub = underwriter_key.verifying_key().to_bytes();
    let validator = ToyDecidableComplianceValidator::new(50);
    let mut gateway = RealEstateUnderwritingGateway::new();

    let mut app = create_nominal_application();
    app.jurisdiction = "FOREIGN_NON_PERMITTED".to_string();

    let csl = create_underwriting_csl_envelope(
        &underwriter_key,
        "auth-test-jur",
        UnderwritingTier::Tier2Standard,
        1000,
        10_000,
        100,
    );

    let state = gateway.build_system_state(&app, &csl, 2000);
    let state_id = ssi_ledger::compute_state_id(&state);
    let cert = build_test_cert(
        &underwriter_key,
        &state,
        &state_id,
        &app,
        2000,
        "PROOF-VALID:10",
    );

    let res = gateway.evaluate_loan_proposal(&app, None, &csl, &underwriter_pub, &cert, &validator, 2000);
    assert!(res.is_err());
    match res.unwrap_err() {
        RealEstateError::ProhibitedJurisdiction { .. } => {}
        other => panic!("Expected ProhibitedJurisdiction, got {:?}", other),
    }
}

#[test]
fn test_missing_environmental_disclosure_rejected() {
    let mut csprng = OsRng;
    let underwriter_key = SigningKey::generate(&mut csprng);
    let underwriter_pub = underwriter_key.verifying_key().to_bytes();
    let validator = ToyDecidableComplianceValidator::new(50);
    let mut gateway = RealEstateUnderwritingGateway::new();

    let mut app = create_nominal_application();
    app.phase1_environmental_clean = false; // Contaminated property

    let csl = create_underwriting_csl_envelope(
        &underwriter_key,
        "auth-test-env",
        UnderwritingTier::Tier2Standard,
        1000,
        10_000,
        100,
    );

    let state = gateway.build_system_state(&app, &csl, 2000);
    let state_id = ssi_ledger::compute_state_id(&state);
    let cert = build_test_cert(
        &underwriter_key,
        &state,
        &state_id,
        &app,
        2000,
        "PROOF-VALID:10",
    );

    let res = gateway.evaluate_loan_proposal(&app, None, &csl, &underwriter_pub, &cert, &validator, 2000);
    assert!(res.is_err());
    match res.unwrap_err() {
        RealEstateError::MissingMandatoryDisclosure { missing_item, .. } => {
            assert!(missing_item.contains("Environmental"));
        }
        other => panic!("Expected MissingMandatoryDisclosure, got {:?}", other),
    }
}

#[test]
fn test_forged_pco_proof_rejected() {
    let mut csprng = OsRng;
    let underwriter_key = SigningKey::generate(&mut csprng);
    let underwriter_pub = underwriter_key.verifying_key().to_bytes();
    let validator = ToyDecidableComplianceValidator::new(50);
    let mut gateway = RealEstateUnderwritingGateway::new();

    let app = create_nominal_application();
    let csl = create_underwriting_csl_envelope(
        &underwriter_key,
        "auth-test-proof",
        UnderwritingTier::Tier2Standard,
        1000,
        10_000,
        100,
    );

    let state = gateway.build_system_state(&app, &csl, 2000);
    let state_id = ssi_ledger::compute_state_id(&state);
    let cert = build_test_cert(
        &underwriter_key,
        &state,
        &state_id,
        &app,
        2000,
        "PROOF-FORGED-INJECTION:TAMPERED",
    );

    let res = gateway.evaluate_loan_proposal(&app, None, &csl, &underwriter_pub, &cert, &validator, 2000);
    assert!(res.is_err());
    match res.unwrap_err() {
        RealEstateError::PcoValidationFailed { .. } => {}
        other => panic!("Expected PcoValidationFailed, got {:?}", other),
    }
}

#[test]
fn test_expired_csl_envelope_rejected() {
    let mut csprng = OsRng;
    let underwriter_key = SigningKey::generate(&mut csprng);
    let underwriter_pub = underwriter_key.verifying_key().to_bytes();
    let validator = ToyDecidableComplianceValidator::new(50);
    let mut gateway = RealEstateUnderwritingGateway::new();

    let app = create_nominal_application();
    let csl = create_underwriting_csl_envelope(
        &underwriter_key,
        "auth-test-exp",
        UnderwritingTier::Tier2Standard,
        1000,
        5000, // Valid until 5000
        100,
    );

    let current_epoch = 10_000; // Expired
    let state = gateway.build_system_state(&app, &csl, current_epoch);
    let state_id = ssi_ledger::compute_state_id(&state);
    let cert = build_test_cert(
        &underwriter_key,
        &state,
        &state_id,
        &app,
        current_epoch,
        "PROOF-VALID:10",
    );

    let res = gateway.evaluate_loan_proposal(&app, None, &csl, &underwriter_pub, &cert, &validator, current_epoch);
    assert!(res.is_err());
    match res.unwrap_err() {
        RealEstateError::CslEnvelopeViolation { reason } => {
            assert!(reason.contains("expired"));
        }
        other => panic!("Expected CslEnvelopeViolation, got {:?}", other),
    }
}

#[test]
fn test_forged_underwriter_signature_rejected() {
    let mut csprng = OsRng;
    let underwriter_key = SigningKey::generate(&mut csprng);
    let attacker_key = SigningKey::generate(&mut csprng);
    let underwriter_pub = underwriter_key.verifying_key().to_bytes();
    let validator = ToyDecidableComplianceValidator::new(50);
    let mut gateway = RealEstateUnderwritingGateway::new();

    let app = create_nominal_application();
    // Signed by attacker_key instead of authorized underwriter_key
    let csl = create_underwriting_csl_envelope(
        &attacker_key,
        "auth-test-forged",
        UnderwritingTier::Tier2Standard,
        1000,
        10_000,
        100,
    );

    let state = gateway.build_system_state(&app, &csl, 2000);
    let state_id = ssi_ledger::compute_state_id(&state);
    let cert = build_test_cert(
        &underwriter_key,
        &state,
        &state_id,
        &app,
        2000,
        "PROOF-VALID:10",
    );

    // Verify against underwriter_pub (which doesn't match attacker_key signature)
    let res = gateway.evaluate_loan_proposal(&app, None, &csl, &underwriter_pub, &cert, &validator, 2000);
    assert!(res.is_err());
    match res.unwrap_err() {
        RealEstateError::CslEnvelopeViolation { reason } => {
            assert!(reason.contains("signature invalid"));
        }
        other => panic!("Expected CslEnvelopeViolation, got {:?}", other),
    }
}
