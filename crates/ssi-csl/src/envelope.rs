//! CSL Envelope: CSL = (ID, Σ, E, T, Q) with Ed25519 signatures.

use std::collections::BTreeSet;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use ssi_kernel::{ActionProposal, ActionType, SystemState};
use wad18::Wad18;
use crate::error::CslError;

/// Operating Envelope E: bounded region of admissible model behavior.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperatingEnvelope {
    pub envelope_id: String,
    pub max_risk_bound: Wad18,
    pub allowed_action_types: BTreeSet<ActionType>,
    pub max_resource_cost_per_action: Wad18,
    pub total_budget_limit: Wad18,
}

/// Temporal Validity T: epoch window and transition depth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TemporalValidity {
    pub valid_from_epoch: i64,
    pub valid_until_epoch: i64,
    pub max_transitions: u64,
}

impl TemporalValidity {
    pub fn is_valid_epoch(&self, epoch: i64) -> bool {
        epoch >= self.valid_from_epoch && epoch <= self.valid_until_epoch
    }

    pub fn is_valid_sequence(&self, seq: u64) -> bool {
        seq <= self.max_transitions
    }
}

/// CSL Envelope: CSL = (ID, Σ, E, T, Q)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CSLEnvelope {
    pub auth_id: String,
    /// 64-byte Ed25519 digital signature
    pub signature: Signature,
    pub envelope: OperatingEnvelope,
    pub validity: TemporalValidity,
    pub constraints: BTreeSet<String>,
}

impl CSLEnvelope {
    /// Construct canonical digest bytes for signing/verifying.
    pub fn canonical_digest_bytes(&self) -> [u8; 32] {
        let mut allowed: Vec<&str> = self
            .envelope
            .allowed_action_types
            .iter()
            .map(|a| a.as_str())
            .collect();
        allowed.sort();

        let mut constraints: Vec<&str> = self.constraints.iter().map(|s| s.as_str()).collect();
        constraints.sort();

        let payload = format!(
            "CSL-V1:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.auth_id,
            self.envelope.envelope_id,
            self.envelope.max_risk_bound.raw(),
            allowed.join(","),
            self.envelope.max_resource_cost_per_action.raw(),
            self.envelope.total_budget_limit.raw(),
            self.validity.valid_from_epoch,
            self.validity.valid_until_epoch,
            self.validity.max_transitions,
            constraints.join(",")
        );

        let hash = Sha256::digest(payload.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&hash);
        out
    }

    /// Sign and create a CSLEnvelope using an Ed25519 SigningKey.
    pub fn sign_new(
        auth_id: impl Into<String>,
        envelope: OperatingEnvelope,
        validity: TemporalValidity,
        constraints: BTreeSet<String>,
        signing_key: &SigningKey,
    ) -> Self {
        let auth_id_str = auth_id.into();
        let dummy_sig = Signature::from_bytes(&[0u8; 64]);
        let mut csl = Self {
            auth_id: auth_id_str,
            signature: dummy_sig,
            envelope,
            validity,
            constraints,
        };

        let digest = csl.canonical_digest_bytes();
        let sig = signing_key.sign(&digest);
        csl.signature = sig;
        csl
    }

    /// Verify Ed25519 signature Σ against an authority public key.
    pub fn verify_signature(&self, public_key: &VerifyingKey) -> Result<(), CslError> {
        let digest = self.canonical_digest_bytes();
        public_key
            .verify(&digest, &self.signature)
            .map_err(|e| CslError::InvalidSignature(e.to_string()))
    }

    /// Continuous authorization check under Axiom 10.
    pub fn verify_continuity(
        &self,
        state: &SystemState,
        proposed_action: Option<&ActionProposal>,
        current_epoch: i64,
        cumulative_cost: Wad18,
        is_revoked: bool,
    ) -> Result<(), CslError> {
        if is_revoked {
            return Err(CslError::Revoked("Explicit revocation active".into()));
        }

        if state.safety.quarantine_flag {
            return Err(CslError::Quarantined);
        }

        // Temporal validity T
        if !self.validity.is_valid_epoch(current_epoch) {
            return Err(CslError::TemporalExpired {
                current: current_epoch,
                valid_from: self.validity.valid_from_epoch,
                valid_until: self.validity.valid_until_epoch,
            });
        }

        // Max transitions
        if !self.validity.is_valid_sequence(state.provenance.sequence_number) {
            return Err(CslError::MaxTransitionsExceeded {
                current: state.provenance.sequence_number,
                max: self.validity.max_transitions,
            });
        }

        // Risk bound
        if state.safety.risk_bound > self.envelope.max_risk_bound {
            return Err(CslError::RiskExceeded {
                risk_raw: state.safety.risk_bound.raw(),
                max_risk_raw: self.envelope.max_risk_bound.raw(),
            });
        }

        // Proposed action checks
        let action = proposed_action.unwrap_or(&state.action);

        if !self.envelope.allowed_action_types.contains(&action.action_type) {
            return Err(CslError::ActionTypeDisallowed(action.action_type.to_string()));
        }

        if action.risk_assessment > self.envelope.max_risk_bound {
            return Err(CslError::RiskExceeded {
                risk_raw: action.risk_assessment.raw(),
                max_risk_raw: self.envelope.max_risk_bound.raw(),
            });
        }

        if action.resource_cost > self.envelope.max_resource_cost_per_action {
            return Err(CslError::PerActionCostExceeded {
                cost_raw: action.resource_cost.raw(),
                max_cost_raw: self.envelope.max_resource_cost_per_action.raw(),
            });
        }

        // Monotonic budget conservation: cumulative_cost + action.resource_cost <= total_budget_limit
        let new_cumulative = cumulative_cost
            .checked_add(action.resource_cost)
            .map_err(CslError::Arithmetic)?;

        if new_cumulative > self.envelope.total_budget_limit {
            return Err(CslError::TotalBudgetExceeded {
                cumulative_cost_raw: new_cumulative.raw(),
                limit_raw: self.envelope.total_budget_limit.raw(),
            });
        }

        // Mandatory constraints Q subsumption
        let missing: Vec<String> = self
            .constraints
            .iter()
            .filter(|q| !state.safety.csl_constraints.contains(*q))
            .cloned()
            .collect();

        if !missing.is_empty() {
            return Err(CslError::MissingConstraints(missing));
        }

        Ok(())
    }
}
