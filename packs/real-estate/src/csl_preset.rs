//! CSL Schema Presets for Real-Estate Underwriting (Russell 2026).
//!
//! Models:
//! - E: Permitted action envelope (Read, Compute, Communicate, MutateEnvironment)
//! - T: Temporal validity window and maximum transition depth
//! - Q: Underwriting constraints {phi_ltv_cap, phi_dscr_floor, phi_disclosures, ...}

#![deny(clippy::float_arithmetic)]

use std::collections::BTreeSet;
use ed25519_dalek::{Signer, SigningKey};
use ssi_csl::{CSLEnvelope, OperatingEnvelope, TemporalValidity};
use ssi_kernel::ActionType;
use wad18::Wad18;

/// Normative Underwriting CSL Envelope Presets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnderwritingTier {
    /// Junior Underwriter: loans up to $250k, low risk bound.
    Tier1Junior,
    /// Standard Underwriter: loans up to $1M, standard risk bound.
    Tier2Standard,
    /// Senior Underwriter & Risk Committee: loans up to $5M, full underwriting envelope.
    Tier3Senior,
}

impl UnderwritingTier {
    pub fn max_risk_bound(self) -> Wad18 {
        match self {
            UnderwritingTier::Tier1Junior => Wad18::from_raw(20_000_000_000_000_000), // 0.02
            UnderwritingTier::Tier2Standard => Wad18::from_raw(50_000_000_000_000_000), // 0.05
            UnderwritingTier::Tier3Senior => Wad18::from_raw(100_000_000_000_000_000), // 0.10
        }
    }

    pub fn max_cost_per_action(self) -> Wad18 {
        match self {
            UnderwritingTier::Tier1Junior => Wad18::from_raw(5_000_000_000_000_000), // 0.005
            UnderwritingTier::Tier2Standard => Wad18::from_raw(10_000_000_000_000_000), // 0.010
            UnderwritingTier::Tier3Senior => Wad18::from_raw(20_000_000_000_000_000), // 0.020
        }
    }

    pub fn total_budget(self) -> Wad18 {
        match self {
            UnderwritingTier::Tier1Junior => Wad18::from_raw(1_000_000_000_000_000_000), // 1.0
            UnderwritingTier::Tier2Standard => Wad18::from_raw(5_000_000_000_000_000_000), // 5.0
            UnderwritingTier::Tier3Senior => Wad18::from_raw(20_000_000_000_000_000_000), // 20.0
        }
    }
}

/// Create a signed CSL envelope preset for real-estate underwriting.
pub fn create_underwriting_csl_envelope(
    signing_key: &SigningKey,
    auth_id: &str,
    tier: UnderwritingTier,
    valid_from_epoch: i64,
    valid_until_epoch: i64,
    max_transitions: u64,
) -> CSLEnvelope {
    let mut allowed_actions = BTreeSet::new();
    allowed_actions.insert(ActionType::Read);
    allowed_actions.insert(ActionType::Compute);
    allowed_actions.insert(ActionType::Communicate);
    allowed_actions.insert(ActionType::MutateEnvironment);

    let mut constraints = BTreeSet::new();
    constraints.insert("phi_single_loan_cap".to_string());
    constraints.insert("phi_ltv_cap".to_string());
    constraints.insert("phi_dscr_floor".to_string());
    constraints.insert("phi_jurisdiction".to_string());
    constraints.insert("phi_mandatory_disclosures".to_string());
    constraints.insert("phi_dual_approval".to_string());

    let envelope = OperatingEnvelope {
        envelope_id: format!("env-re-{}", auth_id),
        max_risk_bound: tier.max_risk_bound(),
        allowed_action_types: allowed_actions,
        max_resource_cost_per_action: tier.max_cost_per_action(),
        total_budget_limit: tier.total_budget(),
    };

    let validity = TemporalValidity {
        valid_from_epoch,
        valid_until_epoch,
        max_transitions,
    };

    let dummy_sig = signing_key.sign(&[0u8; 32]);
    let mut csl = CSLEnvelope {
        auth_id: auth_id.to_string(),
        signature: dummy_sig,
        envelope,
        validity,
        constraints,
    };

    let digest_bytes = csl.canonical_digest_bytes();
    let signature = signing_key.sign(&digest_bytes);
    csl.signature = signature;
    csl
}
