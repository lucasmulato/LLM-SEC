//! System Partitioning: System = (K, M, G) — SSI Definition 22.
//!
//! Enforces clear separation of concerns:
//! - K: Immutable Kernel manifest (non-modifiable at runtime)
//! - M: Mutable Model component (weights digest, model ID, capabilities, budget)
//! - G: Governed Configuration (CSL envelope, risk limits, allowed action types)

#![deny(clippy::float_arithmetic)]

use std::collections::BTreeSet;
use sha2::{Digest, Sha256};
use ssi_csl::CSLEnvelope;
use ssi_kernel::{
    ActionProposal, ActionType, AuthorizationState, IntelligenceState, ProvenanceState,
    SafetyState, SystemState, VerificationState,
};
use wad18::Wad18;
use crate::manifest::KernelManifest;

/// Mutable Model Component M: neural network parameters, epistemic boundaries, and cognitive budgets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MutableModel {
    pub model_id: String,
    /// SHA-256 digest of model weights (64 chars).
    pub weights_digest: String,
    pub context_window_size: u64,
    pub cognitive_budget: Wad18,
    pub epistemic_confidence: Wad18,
    pub entropy_bound: Wad18,
    pub capabilities: BTreeSet<String>,
    /// SHA-256 digest of the prompt template manifest (64 chars).
    pub prompt_template_digest: String,
}

impl MutableModel {
    pub fn new(
        model_id: &str,
        weights_digest: &str,
        context_window_size: u64,
        cognitive_budget: Wad18,
        epistemic_confidence: Wad18,
        entropy_bound: Wad18,
        capabilities: BTreeSet<String>,
        prompt_template_digest: &str,
    ) -> Self {
        Self {
            model_id: model_id.to_string(),
            weights_digest: weights_digest.to_string(),
            context_window_size,
            cognitive_budget,
            epistemic_confidence,
            entropy_bound,
            capabilities,
            prompt_template_digest: prompt_template_digest.to_string(),
        }
    }
}

/// Governed Configuration Component G: declarative policy envelopes, risk bounds, and invariants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernedConfig {
    pub config_id: String,
    pub csl_envelope: CSLEnvelope,
    pub risk_ceiling: Wad18,
    pub total_budget_limit: Wad18,
    pub allowed_action_types: BTreeSet<ActionType>,
    pub mandatory_invariants: BTreeSet<String>,
}

impl GovernedConfig {
    pub fn new(
        config_id: &str,
        csl_envelope: CSLEnvelope,
        risk_ceiling: Wad18,
        total_budget_limit: Wad18,
        allowed_action_types: BTreeSet<ActionType>,
        mandatory_invariants: BTreeSet<String>,
    ) -> Self {
        Self {
            config_id: config_id.to_string(),
            csl_envelope,
            risk_ceiling,
            total_budget_limit,
            allowed_action_types,
            mandatory_invariants,
        }
    }
}

/// System Partition: System = (K, M, G).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemPartition {
    pub kernel: KernelManifest,
    pub model: MutableModel,
    pub config: GovernedConfig,
}

impl SystemPartition {
    pub fn new(kernel: KernelManifest, model: MutableModel, config: GovernedConfig) -> Self {
        Self { kernel, model, config }
    }

    /// Project the partitioned system (K, M, G) into a normative SSI SystemState X = (I, S, A, H, V, P).
    pub fn to_system_state(
        &self,
        sequence_number: u64,
        parent_hash: &str,
        current_epoch: i64,
    ) -> SystemState {
        let intelligence = IntelligenceState {
            model_id: self.model.model_id.clone(),
            weights_digest: self.model.weights_digest.clone(),
            context_window_size: self.model.context_window_size,
            cognitive_budget: self.model.cognitive_budget,
            epistemic_confidence: self.model.epistemic_confidence,
            entropy_bound: self.model.entropy_bound,
            capabilities: self.model.capabilities.clone(),
        };

        let safety = SafetyState {
            containment_active: true,
            containment_barrier_intact: true,
            safety_margin: Wad18::from_raw(200_000_000_000_000_000), // 0.20
            risk_bound: self.config.risk_ceiling,
            active_envelope_id: self.config.csl_envelope.envelope.envelope_id.clone(),
            csl_constraints: self.config.csl_envelope.constraints.clone(),
            quarantine_flag: false,
        };

        let action = ActionProposal {
            action_id: format!("action-adopt-{}", sequence_number),
            action_type: ActionType::Compute,
            risk_assessment: Wad18::from_raw(50_000_000_000_000_000), // 0.05
            resource_cost: Wad18::from_raw(10_000_000_000_000_000),   // 0.01
            required_clearance: 2,
            payload_digest: hex::encode(Sha256::digest(
                format!("{}:{}", self.model.model_id, self.config.config_id).as_bytes(),
            )),
            is_executed: true,
        };

        let authorization = AuthorizationState {
            auth_token: self.config.csl_envelope.auth_id.clone(),
            granter_id: "gov-root-authority".to_string(),
            clearance_level: 3,
            is_active: true,
            expires_at_epoch: self.config.csl_envelope.validity.valid_until_epoch,
            nonce: format!("nonce-{}", sequence_number),
        };

        let verification = VerificationState {
            certificate_id: format!("cert-adopt-{}", sequence_number),
            proof_system: "SSI-R3-TLA-Lean4".to_string(),
            proof_digest: self.kernel.manifest_digest(),
            invariants_verified: self.config.mandatory_invariants.clone(),
            verifier_identity: "independent-ssi-validator-v1".to_string(),
            verified_at_epoch: current_epoch,
            is_valid: true,
        };

        let merkle_root = hex::encode(Sha256::digest(
            format!("{}:{}:{}", sequence_number, parent_hash, self.kernel.manifest_digest())
                .as_bytes(),
        ));

        let provenance = ProvenanceState {
            sequence_number,
            parent_state_hash: parent_hash.to_string(),
            merkle_root,
            audit_trail_id: format!("audit-r3-seq-{}", sequence_number),
            timestamp_epoch_ms: current_epoch * 1000,
        };

        SystemState {
            intelligence,
            safety,
            action,
            authorization,
            verification,
            provenance,
        }
    }
}
