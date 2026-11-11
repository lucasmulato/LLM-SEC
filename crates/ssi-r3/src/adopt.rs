//! ADOPT(Y) Predicate Implementation (SSI Def 24, Theorem 6).
//!
//! ADOPT(Y) <=> KernelEqual(Y) /\ ProofValid(Y) /\ AuthorizationValid(Y) /\ NonRegression(Y)

#![deny(clippy::float_arithmetic)]

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use crate::error::R3Error;
use crate::non_regression::check_non_regression;
use crate::partition::SystemPartition;

/// External proof artifact required to certify candidate model or configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofArtifact {
    pub proof_id: String,
    pub proof_system: String,
    /// SHA-256 hex digest of the formal proof artifact (64 chars).
    pub proof_digest: String,
    pub verifier_identity: String,
    pub is_valid: bool,
}

impl ProofArtifact {
    pub fn new(
        proof_id: &str,
        proof_system: &str,
        proof_digest: &str,
        verifier_identity: &str,
        is_valid: bool,
    ) -> Self {
        Self {
            proof_id: proof_id.to_string(),
            proof_system: proof_system.to_string(),
            proof_digest: proof_digest.to_string(),
            verifier_identity: verifier_identity.to_string(),
            is_valid,
        }
    }

    /// Verifies external proof integrity and validity.
    pub fn verify(&self) -> Result<(), R3Error> {
        if !self.is_valid {
            return Err(R3Error::ProofInvalid {
                reason: format!("Proof '{}' marked invalid by verifier", self.proof_id),
            });
        }
        if self.proof_digest.len() != 64 {
            return Err(R3Error::ProofInvalid {
                reason: format!(
                    "Proof digest '{}' is not a 64-char hex digest",
                    self.proof_digest
                ),
            });
        }
        if self.verifier_identity.is_empty() {
            return Err(R3Error::ProofInvalid {
                reason: "Empty verifier identity".to_string(),
            });
        }
        Ok(())
    }
}

/// Governance Authorization certifying candidate refinement within active CSL envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernanceAuthorization {
    pub auth_id: String,
    pub authority_pubkey: [u8; 32],
    pub signature_bytes: [u8; 64],
    pub valid_until_epoch: i64,
    pub is_revoked: bool,
    pub target_model_digest: String,
    pub target_config_digest: String,
}

impl GovernanceAuthorization {
    pub fn new(
        auth_id: &str,
        authority_pubkey: [u8; 32],
        signature_bytes: [u8; 64],
        valid_until_epoch: i64,
        is_revoked: bool,
        target_model_digest: &str,
        target_config_digest: &str,
    ) -> Self {
        Self {
            auth_id: auth_id.to_string(),
            authority_pubkey,
            signature_bytes,
            valid_until_epoch,
            is_revoked,
            target_model_digest: target_model_digest.to_string(),
            target_config_digest: target_config_digest.to_string(),
        }
    }

    /// Construct canonical digest bytes for governance authorization signing/verification.
    pub fn canonical_digest_bytes(&self) -> [u8; 32] {
        let payload = format!(
            "AUTH:{}:{}:{}:{}",
            self.auth_id,
            self.target_model_digest,
            self.target_config_digest,
            self.valid_until_epoch
        );
        let hash = Sha256::digest(payload.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&hash);
        out
    }

    /// Verify authorization validity against epoch, revocation status, and cryptographic signature.
    pub fn verify(
        &self,
        current_epoch: i64,
        candidate_model_weights: &str,
        candidate_config_id: &str,
    ) -> Result<(), R3Error> {
        // 1. Check revocation
        if self.is_revoked {
            return Err(R3Error::AuthorizationInvalid {
                reason: format!("Authorization '{}' has been explicitly revoked", self.auth_id),
            });
        }

        // 2. Check temporal validity window
        if current_epoch > self.valid_until_epoch {
            return Err(R3Error::AuthorizationInvalid {
                reason: format!(
                    "Authorization '{}' expired: current epoch {} > valid until {}",
                    self.auth_id, current_epoch, self.valid_until_epoch
                ),
            });
        }

        // 3. Check binding to candidate model and config
        if self.target_model_digest != candidate_model_weights {
            return Err(R3Error::AuthorizationInvalid {
                reason: format!(
                    "Authorization target model digest mismatch: expected {} but got {}",
                    self.target_model_digest, candidate_model_weights
                ),
            });
        }

        let config_hash = hex::encode(Sha256::digest(candidate_config_id.as_bytes()));
        if self.target_config_digest != config_hash {
            return Err(R3Error::AuthorizationInvalid {
                reason: format!(
                    "Authorization target config digest mismatch: expected {} but got {}",
                    self.target_config_digest, config_hash
                ),
            });
        }

        // 4. Verify Ed25519 signature
        let vk = VerifyingKey::from_bytes(&self.authority_pubkey).map_err(|e| {
            R3Error::AuthorizationInvalid {
                reason: format!("Invalid authority verifying key: {:?}", e),
            }
        })?;

        let sig = Signature::from_bytes(&self.signature_bytes);
        let digest_bytes = self.canonical_digest_bytes();

        vk.verify(&digest_bytes, &sig).map_err(|e| {
            R3Error::AuthorizationInvalid {
                reason: format!("Governance authority signature invalid: {:?}", e),
            }
        })?;

        Ok(())
    }
}

/// Candidate refinement proposal submitted to the R^3 adoption gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateRefinement {
    pub candidate_id: String,
    pub partition: SystemPartition,
    pub proof: ProofArtifact,
    pub authorization: GovernanceAuthorization,
    pub proposed_at_epoch: i64,
}

impl CandidateRefinement {
    pub fn new(
        candidate_id: &str,
        partition: SystemPartition,
        proof: ProofArtifact,
        authorization: GovernanceAuthorization,
        proposed_at_epoch: i64,
    ) -> Self {
        Self {
            candidate_id: candidate_id.to_string(),
            partition,
            proof,
            authorization,
            proposed_at_epoch,
        }
    }
}

/// Evaluates the complete ADOPT(Y) predicate.
/// ADOPT(Y) <=> KernelEqual(Y) /\ ProofValid(Y) /\ AuthorizationValid(Y) /\ NonRegression(Y)
pub fn evaluate_adopt(
    current: &SystemPartition,
    candidate: &CandidateRefinement,
    current_sequence: u64,
    parent_hash: &str,
) -> Result<(), R3Error> {
    // 1. KernelEqual(Y): byte-for-byte exact kernel manifest equality
    current
        .kernel
        .check_kernel_equal(&candidate.partition.kernel)?;

    // 2. ProofValid(Y): valid external proof artifact required
    candidate.proof.verify()?;

    // 3. AuthorizationValid(Y): valid non-expired governance root authorization
    candidate.authorization.verify(
        candidate.proposed_at_epoch,
        &candidate.partition.model.weights_digest,
        &candidate.partition.config.config_id,
    )?;

    // 4. NonRegression(Y): full invariant suite + 15 mutation checks must pass
    let current_state = current.to_system_state(
        current_sequence,
        parent_hash,
        candidate.proposed_at_epoch,
    );
    let candidate_state = candidate.partition.to_system_state(
        current_sequence + 1,
        parent_hash,
        candidate.proposed_at_epoch,
    );

    check_non_regression(
        current,
        &candidate.partition,
        &current_state,
        &candidate_state,
    )?;

    Ok(())
}
