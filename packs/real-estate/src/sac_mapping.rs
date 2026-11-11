//! Safety Asset Class (SAC) Mapping & Revocation Triggers for Real Estate.
//!
//! Maps domain underwriting invariants to SAC evidence tiers and defines
//! dynamic revocation triggers to immediately quarantine compromised assets.

#![deny(clippy::float_arithmetic)]

use ssi_ledger::SafetyAssetClass;

/// Real-Estate Underwriting Invariant classification in SAC taxonomy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RealEstateInvariantCategory {
    /// Kernel integrity, pure WAD-18 arithmetic, dual human signoff integrity.
    ControlIntegrity,
    /// CSL underwriting envelope validity, underwriter clearance, temporal bounds.
    AuthorizationContinuity,
    /// Complete cryptographic state transition history, appraisal binding, disclosure hash-chain.
    FormalProvenance,
}

impl RealEstateInvariantCategory {
    pub fn to_sac_class(self) -> SafetyAssetClass {
        match self {
            RealEstateInvariantCategory::ControlIntegrity => SafetyAssetClass::Sac1ControlIntegrity,
            RealEstateInvariantCategory::AuthorizationContinuity => {
                SafetyAssetClass::Sac2AuthorizationContinuity
            }
            RealEstateInvariantCategory::FormalProvenance => SafetyAssetClass::Sac3FormalProvenance,
        }
    }
}

/// Dynamic Revocation Trigger Events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RealEstateRevocationTrigger {
    /// Discovery of forged or material defect in certified appraisal report.
    AppraisalFraudDetected {
        property_id: String,
        reason: String,
    },
    /// Human underwriter signing key exposure or compromise.
    UnderwriterKeyCompromised {
        underwriter_pubkey: String,
        revoked_by: String,
    },
    /// Jurisdiction embargo or regulatory sanctions prohibiting commercial lending.
    JurisdictionSanctioned {
        jurisdiction: String,
        statute: String,
    },
    /// Commercial tenant falsification of lease terms or certified rent roll.
    RentRollFalsification {
        property_id: String,
        tenant_id: String,
    },
}

impl RealEstateRevocationTrigger {
    pub fn trigger_id(&self) -> String {
        match self {
            RealEstateRevocationTrigger::AppraisalFraudDetected { property_id, .. } => {
                format!("rev-appraisal-{}", property_id)
            }
            RealEstateRevocationTrigger::UnderwriterKeyCompromised {
                underwriter_pubkey, ..
            } => format!("rev-key-{}", underwriter_pubkey),
            RealEstateRevocationTrigger::JurisdictionSanctioned { jurisdiction, .. } => {
                format!("rev-jur-{}", jurisdiction)
            }
            RealEstateRevocationTrigger::RentRollFalsification { property_id, tenant_id } => {
                format!("rev-rent-{}-{}", property_id, tenant_id)
            }
        }
    }
}
