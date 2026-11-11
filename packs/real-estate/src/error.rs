//! Real-Estate Underwriting Domain Pack Error Taxonomy (Russell 2026).

#![deny(clippy::float_arithmetic)]

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RealEstateError {
    /// LTV cap exceeded (LTV > 0.75 * 10^18).
    LtvCapExceeded {
        ltv_wad: i128,
        cap_wad: i128,
        reason: String,
    },
    /// DSCR floor breached (DSCR < 1.25 * 10^18).
    DscrFloorBreached {
        dscr_wad: i128,
        floor_wad: i128,
        reason: String,
    },
    /// Single loan size cap exceeded (> $5M).
    LoanSizeCapExceeded {
        loan_amount_wad: i128,
        cap_wad: i128,
    },
    /// Prohibited property jurisdiction.
    ProhibitedJurisdiction {
        jurisdiction: String,
        reason: String,
    },
    /// Missing or invalid mandatory regulatory disclosure.
    MissingMandatoryDisclosure {
        missing_item: &'static str,
        reason: String,
    },
    /// High-value action lacking mandatory dual human approval.
    DualHumanApprovalMissing {
        loan_amount_wad: i128,
        reason: String,
    },
    /// Dual human approval signature invalid or forged.
    DualHumanApprovalInvalid {
        signatory: &'static str,
        reason: String,
    },
    /// CSL envelope expired, exhausted, or unauthorized.
    CslEnvelopeViolation {
        reason: String,
    },
    /// Proof-Carrying Output (PCO) validation failed.
    PcoValidationFailed {
        reason: String,
    },
    /// Pre-action ledger commitment failed.
    LedgerCommitFailed {
        reason: String,
    },
    /// Prompt-injected action falls outside admissible CSL underwriting envelope.
    ActionOutsideOperatingEnvelope {
        action: String,
        envelope_id: String,
    },
    /// Fixed-point arithmetic computation overflow / error.
    ArithmeticError {
        reason: String,
    },
    /// Asset or underwriter credential revoked.
    RevokedAsset {
        asset_id: String,
        reason: String,
    },
}

impl std::fmt::Display for RealEstateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RealEstateError::LtvCapExceeded { ltv_wad, cap_wad, reason } => {
                write!(f, "LtvCapExceeded: ltv_raw={} > cap_raw={} ({})", ltv_wad, cap_wad, reason)
            }
            RealEstateError::DscrFloorBreached { dscr_wad, floor_wad, reason } => {
                write!(f, "DscrFloorBreached: dscr_raw={} < floor_raw={} ({})", dscr_wad, floor_wad, reason)
            }
            RealEstateError::LoanSizeCapExceeded { loan_amount_wad, cap_wad } => {
                write!(f, "LoanSizeCapExceeded: loan_raw={} > cap_raw={}", loan_amount_wad, cap_wad)
            }
            RealEstateError::ProhibitedJurisdiction { jurisdiction, reason } => {
                write!(f, "ProhibitedJurisdiction: '{}' ({})", jurisdiction, reason)
            }
            RealEstateError::MissingMandatoryDisclosure { missing_item, reason } => {
                write!(f, "MissingMandatoryDisclosure: '{}' ({})", missing_item, reason)
            }
            RealEstateError::DualHumanApprovalMissing { loan_amount_wad, reason } => {
                write!(f, "DualHumanApprovalMissing: loan_raw={} ({})", loan_amount_wad, reason)
            }
            RealEstateError::DualHumanApprovalInvalid { signatory, reason } => {
                write!(f, "DualHumanApprovalInvalid: signatory='{}' ({})", signatory, reason)
            }
            RealEstateError::CslEnvelopeViolation { reason } => {
                write!(f, "CslEnvelopeViolation: {}", reason)
            }
            RealEstateError::PcoValidationFailed { reason } => {
                write!(f, "PcoValidationFailed: {}", reason)
            }
            RealEstateError::LedgerCommitFailed { reason } => {
                write!(f, "LedgerCommitFailed: {}", reason)
            }
            RealEstateError::ActionOutsideOperatingEnvelope { action, envelope_id } => {
                write!(f, "ActionOutsideOperatingEnvelope: action='{}' not allowed in envelope '{}'", action, envelope_id)
            }
            RealEstateError::ArithmeticError { reason } => {
                write!(f, "ArithmeticError: {}", reason)
            }
            RealEstateError::RevokedAsset { asset_id, reason } => {
                write!(f, "RevokedAsset: asset '{}' is revoked ({})", asset_id, reason)
            }
        }
    }
}

impl std::error::Error for RealEstateError {}
