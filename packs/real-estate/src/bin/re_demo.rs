//! Real-Estate Underwriting End-to-End Demonstration (Russell 2026).
//!
//! An LLM Agent proposes commercial real-estate loans. Every proposal flows through:
//!   CSL Envelope -> Invariant Verification (Φ_RE) -> PCO Independent Validator -> Pre-Action Ledger -> COMMIT.

#![deny(clippy::float_arithmetic)]

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use ssi_pco::{ToyDecidableComplianceValidator, VerificationCertificate};
use ssi_real_estate::{
    DualHumanApproval, LoanApplication, RealEstateUnderwritingGateway, UnderwritingTier,
    create_underwriting_csl_envelope,
};
use wad18::Wad18;

fn main() {
    println!("============================================================");
    println!("   SSI Real-Estate Underwriting Autonomous Gateway Demo");
    println!("   (Narrow Superintelligence for Real Estate, Russell 2026)");
    println!("============================================================\n");

    let mut csprng = OsRng;
    let underwriter_key = SigningKey::generate(&mut csprng);
    let underwriter_pub = underwriter_key.verifying_key().to_bytes();

    let chair_key = SigningKey::generate(&mut csprng);
    let chair_pub = chair_key.verifying_key().to_bytes();

    let mut gateway = RealEstateUnderwritingGateway::new();

    // -----------------------------------------------------------------------
    // Scenario 1: Standard Commercial Loan ($750k on $1.25M Property)
    // -----------------------------------------------------------------------
    println!("[Scenario 1] LLM Agent proposes standard commercial loan ($750k)...");
    let app1 = LoanApplication {
        application_id: "LOAN-2026-NY-750K".to_string(),
        borrower_id: "BORROWER-ACME-HOLDINGS".to_string(),
        property_id: "PROP-MANHATTAN-OFFICE-01".to_string(),
        jurisdiction: "US-NY".to_string(),
        property_value_wad: Wad18::from_raw(1_250_000_000_000_000_000_000_000), // $1.25M
        requested_loan_wad: Wad18::from_raw(750_000_000_000_000_000_000_000),   // $750k (LTV = 60.0%)
        net_operating_income_wad: Wad18::from_raw(145_000_000_000_000_000_000_000), // $145k/yr
        annual_debt_service_wad: Wad18::from_raw(100_000_000_000_000_000_000_000),  // $100k/yr (DSCR = 1.45x)
        phase1_environmental_clean: true,
        flood_zone_certified: true,
        rent_roll_certified: true,
        aml_kyc_cleared: true,
        appraisal_digest: "a".repeat(64),
    };

    let csl1 = create_underwriting_csl_envelope(
        &underwriter_key,
        "auth-underwriter-tier2",
        UnderwritingTier::Tier2Standard,
        1000,
        100_000,
        100,
    );

    // Initial pre-state for BOUND check
    let pre_state1 = gateway.build_system_state(&app1, &csl1, 2000);
    let state_id1 = ssi_ledger::compute_state_id(&pre_state1);

    let cert1 = build_pco_certificate(&underwriter_key, &pre_state1, &state_id1, &app1, 2000);
    let validator = ToyDecidableComplianceValidator::new(50);

    let outcome1 = gateway
        .evaluate_loan_proposal(
            &app1,
            None,
            &csl1,
            &underwriter_pub,
            &cert1,
            &validator,
            2000,
        )
        .expect("Scenario 1 must be approved");

    println!("  [PASS] Loan approved successfully: application={}", outcome1.application_id);
    println!("  [PASS] WAD-18 LTV: {} WAD (60.0%)", outcome1.ltv_wad);
    println!("  [PASS] WAD-18 DSCR: {} WAD (1.45x)", outcome1.dscr_wad);
    println!("  [PASS] PRE-ACTION Ledger Commit & SAC-3 Evidence sealed: record_hash={}", outcome1.sac_record_hash);

    // -----------------------------------------------------------------------
    // Scenario 2: High-Value Commercial Loan ($2.5M on $4.0M Property) with Dual Human Approval
    // -----------------------------------------------------------------------
    println!("\n[Scenario 2] LLM Agent proposes high-value commercial acquisition ($2.5M) with Dual Human Approval...");
    let app2 = LoanApplication {
        application_id: "LOAN-2026-CA-2.5M".to_string(),
        borrower_id: "BORROWER-PACIFIC-REALTY".to_string(),
        property_id: "PROP-SILICON-VALLEY-IND-02".to_string(),
        jurisdiction: "US-CA".to_string(),
        property_value_wad: Wad18::from_raw(4_000_000_000_000_000_000_000_000), // $4.0M
        requested_loan_wad: Wad18::from_raw(2_500_000_000_000_000_000_000_000), // $2.5M (LTV = 62.5%)
        net_operating_income_wad: Wad18::from_raw(320_000_000_000_000_000_000_000), // $320k/yr
        annual_debt_service_wad: Wad18::from_raw(200_000_000_000_000_000_000_000),  // $200k/yr (DSCR = 1.60x)
        phase1_environmental_clean: true,
        flood_zone_certified: true,
        rent_roll_certified: true,
        aml_kyc_cleared: true,
        appraisal_digest: "b".repeat(64),
    };

    let csl2 = create_underwriting_csl_envelope(
        &underwriter_key,
        "auth-underwriter-tier3",
        UnderwritingTier::Tier3Senior,
        1000,
        100_000,
        100,
    );

    // Sign dual human approval
    let epoch2 = 3000;
    let digest2 = DualHumanApproval::canonical_digest_bytes(
        &app2.application_id,
        app2.requested_loan_wad.raw(),
        epoch2,
    );
    let sig_senior = underwriter_key.sign(&digest2);
    let sig_chair = chair_key.sign(&digest2);

    let dual_approval = DualHumanApproval {
        senior_underwriter_pubkey: underwriter_pub,
        senior_underwriter_sig: sig_senior.to_bytes(),
        risk_chair_pubkey: chair_pub,
        risk_chair_sig: sig_chair.to_bytes(),
        approval_epoch: epoch2,
    };

    let pre_state2 = gateway.build_system_state(&app2, &csl2, epoch2);
    let state_id2 = ssi_ledger::compute_state_id(&pre_state2);

    let cert2 = build_pco_certificate(&underwriter_key, &pre_state2, &state_id2, &app2, epoch2);

    let outcome2 = gateway
        .evaluate_loan_proposal(
            &app2,
            Some(&dual_approval),
            &csl2,
            &underwriter_pub,
            &cert2,
            &validator,
            epoch2,
        )
        .expect("Scenario 2 must be approved with dual approval");

    println!("  [PASS] High-value loan approved with dual human signoff!");
    println!("  [PASS] Application ID: {}", outcome2.application_id);
    println!("  [PASS] Senior Underwriter Pub: {}", hex::encode(dual_approval.senior_underwriter_pubkey));
    println!("  [PASS] Risk Committee Chair Pub: {}", hex::encode(dual_approval.risk_chair_pubkey));
    println!("  [PASS] Post State ID: {}", outcome2.post_state_id);
    println!("  [PASS] SAC-3 Hash Chain Commit: record_hash={}", outcome2.sac_record_hash);

    println!("\n============================================================");
    println!("   VERDICT: REAL-ESTATE GATEWAY DEMO EXECUTED SUCCESSFULLY");
    println!("============================================================");
}

fn build_pco_certificate(
    key: &SigningKey,
    state: &ssi_kernel::SystemState,
    state_id: &str,
    app: &LoanApplication,
    epoch: i64,
) -> VerificationCertificate {
    VerificationCertificate::sign_new(
        format!("pco-cert-{}", app.application_id),
        "SPEC_WAD18_RE_UNDERWRITING_V1",
        "POLICY_CSL_UNDERWRITING_TIER2",
        "CODE_RUST_REAL_ESTATE_KERNEL_V1",
        state.intelligence.weights_digest.clone(),
        app.payload_digest(),
        "PROOF-VALID:10",
        "toy-decidable-compliance-validator-v1",
        vec!["ASSUME_APPRAISER_CERTIFIED".to_string()],
        epoch,
        state_id,
        key,
    )
}
