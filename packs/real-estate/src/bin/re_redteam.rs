//! Real-Estate Red-Team Adversarial Attack Suite (Russell 2026).
//!
//! Evaluates the execution gateway against 6 malicious attack vectors:
//! [Attack 1] Expired CSL Envelope (Attempting action beyond authorization window) -> REJECT
//! [Attack 2] LTV Overflow (Attempting loan exceeding 75% LTV cap) -> REJECT
//! [Attack 3] Forged PCO Certificate (Invalid / tampered proof artifact) -> REJECT
//! [Attack 4] Prompt Injection Outside Envelope (Injecting unauthorized action) -> REJECT
//! [Attack 5] High-Value Loan Missing Mandatory Dual Human Approval -> REJECT
//! [Attack 6] Prohibited Jurisdiction (Attempting underwriting in unvetted territory) -> REJECT
//!
//! All attacks must be caught and rejected fail-closed with audit trail preservation.

#![deny(clippy::float_arithmetic)]

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use ssi_pco::{ToyDecidableComplianceValidator, VerificationCertificate};
use ssi_real_estate::{
    LoanApplication, RealEstateUnderwritingGateway, UnderwritingTier,
    create_underwriting_csl_envelope,
};
use wad18::Wad18;

fn main() {
    println!("============================================================");
    println!("   SSI Real-Estate Underwriting Red-Team Attack Suite");
    println!("   Evaluating Fail-Closed Security Barriers");
    println!("============================================================\n");

    let mut csprng = OsRng;
    let underwriter_key = SigningKey::generate(&mut csprng);
    let underwriter_pub = underwriter_key.verifying_key().to_bytes();
    let validator = ToyDecidableComplianceValidator::new(50);

    let mut gateway = RealEstateUnderwritingGateway::new();

    // Baseline nominal application
    let base_app = LoanApplication {
        application_id: "LOAN-REDTEAM-001".to_string(),
        borrower_id: "BORROWER-CORP".to_string(),
        property_id: "PROP-TARGET-001".to_string(),
        jurisdiction: "US-NY".to_string(),
        property_value_wad: Wad18::from_raw(1_000_000_000_000_000_000_000_000), // $1.0M
        requested_loan_wad: Wad18::from_raw(600_000_000_000_000_000_000_000),   // $600k (LTV = 60%)
        net_operating_income_wad: Wad18::from_raw(150_000_000_000_000_000_000_000), // $150k
        annual_debt_service_wad: Wad18::from_raw(100_000_000_000_000_000_000_000),  // $100k (DSCR = 1.5x)
        phase1_environmental_clean: true,
        flood_zone_certified: true,
        rent_roll_certified: true,
        aml_kyc_cleared: true,
        appraisal_digest: "9".repeat(64),
    };

    let base_csl = create_underwriting_csl_envelope(
        &underwriter_key,
        "auth-underwriter-rt",
        UnderwritingTier::Tier2Standard,
        1000,
        10_000,
        100,
    );

    // -----------------------------------------------------------------------
    // Attack 1: Expired CSL Envelope (Attempting action beyond valid window)
    // -----------------------------------------------------------------------
    println!("[Attack 1] Submitting underwriting proposal with expired CSL window (epoch 50,000 > valid_until 10,000)...");
    let state1 = gateway.build_system_state(&base_app, &base_csl, 50_000);
    let state_id1 = ssi_ledger::compute_state_id(&state1);
    let cert1 = build_cert(&underwriter_key, &state1, &state_id1, &base_app, 50_000, "PROOF-VALID:10");

    match gateway.evaluate_loan_proposal(&base_app, None, &base_csl, &underwriter_pub, &cert1, &validator, 50_000) {
        Ok(_) => panic!("FATAL: Attack 1 was accepted!"),
        Err(e) => println!("  [CAUGHT ✓] Expired CSL rejected: {}", e),
    }

    // -----------------------------------------------------------------------
    // Attack 2: Budget Overflow / LTV Cap Exceeded (LTV = 82% > 75% cap)
    // -----------------------------------------------------------------------
    println!("\n[Attack 2] Submitting loan proposal exceeding statutory 75% LTV cap (82% LTV)...");
    let mut app_ltv = base_app.clone();
    app_ltv.requested_loan_wad = Wad18::from_raw(820_000_000_000_000_000_000_000); // 82% LTV
    let state2 = gateway.build_system_state(&app_ltv, &base_csl, 2000);
    let state_id2 = ssi_ledger::compute_state_id(&state2);
    let cert2 = build_cert(&underwriter_key, &state2, &state_id2, &app_ltv, 2000, "PROOF-VALID:10");

    match gateway.evaluate_loan_proposal(&app_ltv, None, &base_csl, &underwriter_pub, &cert2, &validator, 2000) {
        Ok(_) => panic!("FATAL: Attack 2 was accepted!"),
        Err(e) => println!("  [CAUGHT ✓] LTV cap violation rejected: {}", e),
    }

    // -----------------------------------------------------------------------
    // Attack 3: Forged / Corrupted PCO Proof Artifact
    // -----------------------------------------------------------------------
    println!("\n[Attack 3] Submitting loan proposal carrying forged / corrupted PCO proof artifact...");
    let state3 = gateway.build_system_state(&base_app, &base_csl, 2000);
    let state_id3 = ssi_ledger::compute_state_id(&state3);
    let cert3 = build_cert(&underwriter_key, &state3, &state_id3, &base_app, 2000, "PROOF-FORGED-INJECTION:MALICIOUS");

    match gateway.evaluate_loan_proposal(&base_app, None, &base_csl, &underwriter_pub, &cert3, &validator, 2000) {
        Ok(_) => panic!("FATAL: Attack 3 was accepted!"),
        Err(e) => println!("  [CAUGHT ✓] Forged PCO proof rejected: {}", e),
    }

    // -----------------------------------------------------------------------
    // Attack 4: Prompt Injection Attempt Outside Operating Envelope
    // -----------------------------------------------------------------------
    println!("\n[Attack 4] Prompt-injected proposal attempting out-of-envelope action (ExecuteCode / ExfiltrateData)...");
    let mut csl_restricted = base_csl.clone();
    csl_restricted.envelope.allowed_action_types.remove(&ssi_kernel::ActionType::Compute); // Remove compute
    let state4 = gateway.build_system_state(&base_app, &csl_restricted, 2000);
    let state_id4 = ssi_ledger::compute_state_id(&state4);
    let cert4 = build_cert(&underwriter_key, &state4, &state_id4, &base_app, 2000, "PROOF-VALID:10");

    match gateway.evaluate_loan_proposal(&base_app, None, &csl_restricted, &underwriter_pub, &cert4, &validator, 2000) {
        Ok(_) => panic!("FATAL: Attack 4 was accepted!"),
        Err(e) => println!("  [CAUGHT ✓] Prompt-injected action rejected: {}", e),
    }

    // -----------------------------------------------------------------------
    // Attack 5: High-Value Loan ($2.5M) Missing Mandatory Dual Human Approval
    // -----------------------------------------------------------------------
    println!("\n[Attack 5] High-value loan ($2.5M) submitted without mandatory dual human approval...");
    let mut app_high = base_app.clone();
    app_high.requested_loan_wad = Wad18::from_raw(2_500_000_000_000_000_000_000_000); // $2.5M
    app_high.property_value_wad = Wad18::from_raw(5_000_000_000_000_000_000_000_000); // $5.0M (50% LTV)
    let state5 = gateway.build_system_state(&app_high, &base_csl, 2000);
    let state_id5 = ssi_ledger::compute_state_id(&state5);
    let cert5 = build_cert(&underwriter_key, &state5, &state_id5, &app_high, 2000, "PROOF-VALID:10");

    match gateway.evaluate_loan_proposal(&app_high, None, &base_csl, &underwriter_pub, &cert5, &validator, 2000) {
        Ok(_) => panic!("FATAL: Attack 5 was accepted!"),
        Err(e) => println!("  [CAUGHT ✓] Missing dual approval rejected: {}", e),
    }

    // -----------------------------------------------------------------------
    // Attack 6: Prohibited / Unvetted Jurisdiction
    // -----------------------------------------------------------------------
    println!("\n[Attack 6] Submitting underwriting proposal for property in unvetted territory ('US-XX')...");
    let mut app_jur = base_app.clone();
    app_jur.jurisdiction = "US-XX".to_string(); // Non-permitted jurisdiction
    let state6 = gateway.build_system_state(&app_jur, &base_csl, 2000);
    let state_id6 = ssi_ledger::compute_state_id(&state6);
    let cert6 = build_cert(&underwriter_key, &state6, &state_id6, &app_jur, 2000, "PROOF-VALID:10");

    match gateway.evaluate_loan_proposal(&app_jur, None, &base_csl, &underwriter_pub, &cert6, &validator, 2000) {
        Ok(_) => panic!("FATAL: Attack 6 was accepted!"),
        Err(e) => println!("  [CAUGHT ✓] Prohibited jurisdiction rejected: {}", e),
    }

    println!("\n============================================================");
    println!("   VERDICT: ALL 6 RED-TEAM ATTACKS CAUGHT & REJECTED FAIL-CLOSED");
    println!("============================================================");
}

fn build_cert(
    key: &SigningKey,
    state: &ssi_kernel::SystemState,
    state_id: &str,
    app: &LoanApplication,
    epoch: i64,
    proof_str: &str,
) -> VerificationCertificate {
    VerificationCertificate::sign_new(
        format!("pco-rt-{}", app.application_id),
        "SPEC_RE",
        "POLICY_CSL",
        "CODE_RE_KERNEL",
        state.intelligence.weights_digest.clone(),
        app.payload_digest(),
        proof_str,
        "toy-decidable-compliance-validator-v1",
        vec!["ASSUME_APPRAISER_CERTIFIED".to_string()],
        epoch,
        state_id,
        key,
    )
}
