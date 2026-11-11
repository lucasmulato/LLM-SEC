//! SSI Real-Estate Underwriting Domain Pack (Russell 2026).
//!
//! Provides formal invariant enforcement, CSL schema presets, SAC evidence mapping,
//! and high-assurance gating for commercial real-estate autonomous underwriting.

#![deny(clippy::float_arithmetic)]

pub mod csl_preset;
pub mod error;
pub mod invariants;
pub mod pipeline;
pub mod sac_mapping;
pub mod types;

pub use csl_preset::{UnderwritingTier, create_underwriting_csl_envelope};
pub use error::RealEstateError;
pub use invariants::verify_real_estate_invariants;
pub use pipeline::{RealEstateUnderwritingGateway, UnderwritingPipelineOutcome};
pub use sac_mapping::{RealEstateInvariantCategory, RealEstateRevocationTrigger};
pub use types::{
    DSCR_FLOOR_WAD, DUAL_APPROVAL_LOAN_THRESHOLD_WAD, DUAL_APPROVAL_LTV_THRESHOLD_WAD,
    DualHumanApproval, LTV_CAP_WAD, LoanApplication, PERMITTED_JURISDICTIONS, SINGLE_LOAN_CAP_WAD,
};
