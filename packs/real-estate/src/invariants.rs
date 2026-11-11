//! Formal Real-Estate Underwriting Invariants Φ_RE (Russell 2026).
//!
//! Enforces:
//! 1. phi_ltv_cap: LTV = Loan / Value <= 0.75 * 10^18
//! 2. phi_dscr_floor: DSCR = NOI / ADS >= 1.25 * 10^18
//! 3. phi_single_loan_cap: Loan <= $5,000,000 * 10^18
//! 4. phi_jurisdiction: Property located within permitted jurisdictions
//! 5. phi_mandatory_disclosures: Phase 1 environmental, flood cert, rent roll, AML/KYC, appraisal
//! 6. phi_dual_approval: Required for Loan > $1,000,000 or LTV > 0.65

#![deny(clippy::float_arithmetic)]

use crate::error::RealEstateError;
use crate::types::{
    DSCR_FLOOR_WAD, DUAL_APPROVAL_LOAN_THRESHOLD_WAD, DUAL_APPROVAL_LTV_THRESHOLD_WAD,
    DualHumanApproval, LTV_CAP_WAD, LoanApplication, PERMITTED_JURISDICTIONS, SINGLE_LOAN_CAP_WAD,
};
use wad18::Wad18;

/// Evaluates the complete set of formal underwriting invariants Φ_RE.
pub fn verify_real_estate_invariants(
    app: &LoanApplication,
    dual_approval: Option<&DualHumanApproval>,
) -> Result<(), RealEstateError> {
    // 1. Invariant: phi_single_loan_cap
    if app.requested_loan_wad > Wad18::from_raw(SINGLE_LOAN_CAP_WAD) {
        return Err(RealEstateError::LoanSizeCapExceeded {
            loan_amount_wad: app.requested_loan_wad.raw(),
            cap_wad: SINGLE_LOAN_CAP_WAD,
        });
    }

    // 2. Invariant: phi_ltv_cap (LTV <= 75%)
    let ltv = app.compute_ltv()?;
    if ltv.raw() > LTV_CAP_WAD {
        return Err(RealEstateError::LtvCapExceeded {
            ltv_wad: ltv.raw(),
            cap_wad: LTV_CAP_WAD,
            reason: format!(
                "Requested loan LTV {} exceeds statutory cap {}",
                ltv.raw(),
                LTV_CAP_WAD
            ),
        });
    }

    // 3. Invariant: phi_dscr_floor (DSCR >= 1.25x)
    let dscr = app.compute_dscr()?;
    if dscr.raw() < DSCR_FLOOR_WAD {
        return Err(RealEstateError::DscrFloorBreached {
            dscr_wad: dscr.raw(),
            floor_wad: DSCR_FLOOR_WAD,
            reason: format!(
                "Debt-Service Coverage Ratio {} is below required floor {}",
                dscr.raw(),
                DSCR_FLOOR_WAD
            ),
        });
    }

    // 4. Invariant: phi_jurisdiction
    if !PERMITTED_JURISDICTIONS.contains(&app.jurisdiction.as_str()) {
        return Err(RealEstateError::ProhibitedJurisdiction {
            jurisdiction: app.jurisdiction.clone(),
            reason: format!(
                "Jurisdiction '{}' not in permitted underwriting territory {:?}",
                app.jurisdiction, PERMITTED_JURISDICTIONS
            ),
        });
    }

    // 5. Invariant: phi_mandatory_disclosures
    if !app.phase1_environmental_clean {
        return Err(RealEstateError::MissingMandatoryDisclosure {
            missing_item: "Phase 1 Environmental ESA",
            reason: "Property lacks certified clean environmental clearance".to_string(),
        });
    }
    if !app.flood_zone_certified {
        return Err(RealEstateError::MissingMandatoryDisclosure {
            missing_item: "FEMA Flood Zone Certification",
            reason: "Property lacks official flood zone determination certification".to_string(),
        });
    }
    if !app.rent_roll_certified {
        return Err(RealEstateError::MissingMandatoryDisclosure {
            missing_item: "Certified Rent Roll & Lease Audit",
            reason: "Commercial tenant lease audit and rent roll not certified".to_string(),
        });
    }
    if !app.aml_kyc_cleared {
        return Err(RealEstateError::MissingMandatoryDisclosure {
            missing_item: "AML/KYC Beneficial Ownership Clearance",
            reason: "Borrower entity has not completed mandatory FinCEN AML audit".to_string(),
        });
    }
    if app.appraisal_digest.len() != 64 {
        return Err(RealEstateError::MissingMandatoryDisclosure {
            missing_item: "Certified Appraisal SHA-256 Digest",
            reason: "Appraisal report digest must be a 64-char hex SHA-256 string".to_string(),
        });
    }

    // 6. Invariant: phi_dual_approval
    // Required when Loan > $1M OR LTV > 65%
    let requires_dual_approval = app.requested_loan_wad.raw() > DUAL_APPROVAL_LOAN_THRESHOLD_WAD
        || ltv.raw() > DUAL_APPROVAL_LTV_THRESHOLD_WAD;

    if requires_dual_approval {
        match dual_approval {
            None => {
                return Err(RealEstateError::DualHumanApprovalMissing {
                    loan_amount_wad: app.requested_loan_wad.raw(),
                    reason: format!(
                        "High-value / high-risk loan (loan_raw={}, ltv_raw={}) mandates dual human approval",
                        app.requested_loan_wad.raw(),
                        ltv.raw()
                    ),
                });
            }
            Some(approval) => {
                approval.verify(&app.application_id, app.requested_loan_wad.raw())?;
            }
        }
    }

    Ok(())
}
