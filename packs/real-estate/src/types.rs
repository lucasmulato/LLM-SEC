//! Real-Estate Domain Types, Loan Applications & Dual Human Approvals.

#![deny(clippy::float_arithmetic)]

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use wad18::Wad18;
use crate::error::RealEstateError;

/// List of normative permitted property jurisdictions.
pub const PERMITTED_JURISDICTIONS: &[&str] = &["US-NY", "US-CA", "US-TX", "US-FL", "US-IL"];

/// Loan-to-Value (LTV) Cap: 75% (0.75 * 10^18).
pub const LTV_CAP_WAD: i128 = 750_000_000_000_000_000;

/// Debt-Service Coverage Ratio (DSCR) Floor: 1.25x (1.25 * 10^18).
pub const DSCR_FLOOR_WAD: i128 = 1_250_000_000_000_000_000;

/// High-Value Dual-Approval Loan Threshold: $1,000,000 (1_000_000 * 10^18).
pub const DUAL_APPROVAL_LOAN_THRESHOLD_WAD: i128 = 1_000_000_000_000_000_000_000_000;

/// High-Risk LTV Dual-Approval Threshold: 65% (0.65 * 10^18).
pub const DUAL_APPROVAL_LTV_THRESHOLD_WAD: i128 = 650_000_000_000_000_000;

/// Absolute Maximum Single Loan Cap: $5,000,000 (5_000_000 * 10^18).
pub const SINGLE_LOAN_CAP_WAD: i128 = 5_000_000_000_000_000_000_000_000;

/// Real-Estate Underwriting Loan Application data structure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoanApplication {
    pub application_id: String,
    pub borrower_id: String,
    pub property_id: String,
    pub jurisdiction: String,
    pub property_value_wad: Wad18,
    pub requested_loan_wad: Wad18,
    pub net_operating_income_wad: Wad18,
    pub annual_debt_service_wad: Wad18,
    pub phase1_environmental_clean: bool,
    pub flood_zone_certified: bool,
    pub rent_roll_certified: bool,
    pub aml_kyc_cleared: bool,
    /// 64-character SHA-256 digest of certified property appraisal report.
    pub appraisal_digest: String,
}

impl LoanApplication {
    /// Compute exact WAD-18 Loan-to-Value ratio: LTV = Loan / Value.
    pub fn compute_ltv(&self) -> Result<Wad18, RealEstateError> {
        self.requested_loan_wad
            .checked_div(self.property_value_wad)
            .map_err(|e| RealEstateError::ArithmeticError {
                reason: format!("Failed to compute LTV: {:?}", e),
            })
    }

    /// Compute exact WAD-18 Debt-Service Coverage Ratio: DSCR = NOI / ADS.
    pub fn compute_dscr(&self) -> Result<Wad18, RealEstateError> {
        self.net_operating_income_wad
            .checked_div(self.annual_debt_service_wad)
            .map_err(|e| RealEstateError::ArithmeticError {
                reason: format!("Failed to compute DSCR: {:?}", e),
            })
    }

    /// Canonical payload digest (SHA-256) binding the loan application attributes.
    pub fn payload_digest(&self) -> String {
        let payload = format!(
            "LOAN_APP:{}:{}:{}:{}:{}:{}:{}:{}",
            self.application_id,
            self.borrower_id,
            self.property_id,
            self.jurisdiction,
            self.property_value_wad.raw(),
            self.requested_loan_wad.raw(),
            self.net_operating_income_wad.raw(),
            self.annual_debt_service_wad.raw()
        );
        hex::encode(Sha256::digest(payload.as_bytes()))
    }
}

/// Dual Human Approval: Signatures from Senior Underwriter and Risk Committee Chair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DualHumanApproval {
    pub senior_underwriter_pubkey: [u8; 32],
    pub senior_underwriter_sig: [u8; 64],
    pub risk_chair_pubkey: [u8; 32],
    pub risk_chair_sig: [u8; 64],
    pub approval_epoch: i64,
}

impl DualHumanApproval {
    pub fn canonical_digest_bytes(
        application_id: &str,
        loan_amount_wad: i128,
        approval_epoch: i64,
    ) -> [u8; 32] {
        let payload = format!(
            "DUAL_APPROVAL:{}:{}:{}",
            application_id, loan_amount_wad, approval_epoch
        );
        let hash = Sha256::digest(payload.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&hash);
        out
    }

    /// Verifies both human underwriter Ed25519 signatures.
    pub fn verify(
        &self,
        application_id: &str,
        loan_amount_wad: i128,
    ) -> Result<(), RealEstateError> {
        // Assert signatories are two distinct entities
        if self.senior_underwriter_pubkey == self.risk_chair_pubkey {
            return Err(RealEstateError::DualHumanApprovalInvalid {
                signatory: "DualSignatories",
                reason: "Senior Underwriter and Risk Chair must be distinct public keys".to_string(),
            });
        }

        let digest_bytes =
            Self::canonical_digest_bytes(application_id, loan_amount_wad, self.approval_epoch);

        // 1. Verify Senior Underwriter signature
        let vk_underwriter = VerifyingKey::from_bytes(&self.senior_underwriter_pubkey).map_err(
            |e| RealEstateError::DualHumanApprovalInvalid {
                signatory: "SeniorUnderwriter",
                reason: format!("Invalid Senior Underwriter public key: {:?}", e),
            },
        )?;
        let sig_underwriter = Signature::from_bytes(&self.senior_underwriter_sig);
        vk_underwriter.verify(&digest_bytes, &sig_underwriter).map_err(
            |e| RealEstateError::DualHumanApprovalInvalid {
                signatory: "SeniorUnderwriter",
                reason: format!("Senior Underwriter signature verification failed: {:?}", e),
            },
        )?;

        // 2. Verify Risk Committee Chair signature
        let vk_chair = VerifyingKey::from_bytes(&self.risk_chair_pubkey).map_err(|e| {
            RealEstateError::DualHumanApprovalInvalid {
                signatory: "RiskCommitteeChair",
                reason: format!("Invalid Risk Chair public key: {:?}", e),
            }
        })?;
        let sig_chair = Signature::from_bytes(&self.risk_chair_sig);
        vk_chair.verify(&digest_bytes, &sig_chair).map_err(|e| {
            RealEstateError::DualHumanApprovalInvalid {
                signatory: "RiskCommitteeChair",
                reason: format!("Risk Committee Chair signature verification failed: {:?}", e),
            }
        })?;

        Ok(())
    }
}
