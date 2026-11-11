//! 10-Tuple Formal Verification Certificate C and BOUND(C, X) predicate.
//!
//! Definition 12 & SSI Normative Requirements §8.1:
//! C = (Spec, Policy, Code, Model, Input, Proof, Verifier, Assumptions, τ, Σ_C)
//! BOUND(C, X) <=> C.StateId = ID_X /\ C.Model = X.I.weights_digest /\ C.Input = X.A.payload_digest

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use ssi_kernel::{SafetyKernel, SystemState};
use crate::error::PcoError;

/// Formal Evidence Certificate C (10-tuple).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationCertificate {
    pub certificate_id: String,
    /// Spec: Formal invariant/predicate specification digest (SHA-256 hex).
    pub spec_digest: String,
    /// Policy: Active CSL envelope digest / ID.
    pub policy_digest: String,
    /// Code: Binary / handler executable digest (SHA-256 hex).
    pub code_digest: String,
    /// Model: Model weights digest (SHA-256 hex).
    pub model_digest: String,
    /// Input: Normalized input payload digest (SHA-256 hex).
    pub input_digest: String,
    /// Proof: Serialized formal proof artifact / certificate bytes.
    pub proof_artifact: String,
    /// Verifier: Identifier and version of the independent verifier.
    pub verifier_version: String,
    /// Assumptions: Explicit list of operational assumptions.
    pub assumptions: Vec<String>,
    /// τ: Discrete timestamp of proof generation.
    pub timestamp_epoch: i64,
    /// StateId: Cryptographic hash ID_X to which certificate is strictly bound.
    pub state_id: String,
    /// Σ_C: 64-byte Ed25519 signature over canonical digest of elements.
    pub signature: Signature,
}

impl VerificationCertificate {
    /// Compute canonical digest over certificate elements (excluding signature).
    pub fn canonical_digest_bytes(&self) -> [u8; 32] {
        let mut sorted_assumptions = self.assumptions.clone();
        sorted_assumptions.sort();

        let payload = format!(
            "PCO-C-V1:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.certificate_id,
            self.spec_digest,
            self.policy_digest,
            self.code_digest,
            self.model_digest,
            self.input_digest,
            self.proof_artifact,
            self.verifier_version,
            sorted_assumptions.join(","),
            self.timestamp_epoch,
            self.state_id
        );

        let hash = Sha256::digest(payload.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&hash);
        out
    }

    /// Sign and construct a VerificationCertificate using an Ed25519 SigningKey.
    pub fn sign_new(
        certificate_id: impl Into<String>,
        spec_digest: impl Into<String>,
        policy_digest: impl Into<String>,
        code_digest: impl Into<String>,
        model_digest: impl Into<String>,
        input_digest: impl Into<String>,
        proof_artifact: impl Into<String>,
        verifier_version: impl Into<String>,
        assumptions: Vec<String>,
        timestamp_epoch: i64,
        state_id: impl Into<String>,
        signing_key: &SigningKey,
    ) -> Self {
        let dummy_sig = Signature::from_bytes(&[0u8; 64]);
        let mut cert = Self {
            certificate_id: certificate_id.into(),
            spec_digest: spec_digest.into(),
            policy_digest: policy_digest.into(),
            code_digest: code_digest.into(),
            model_digest: model_digest.into(),
            input_digest: input_digest.into(),
            proof_artifact: proof_artifact.into(),
            verifier_version: verifier_version.into(),
            assumptions,
            timestamp_epoch,
            state_id: state_id.into(),
            signature: dummy_sig,
        };

        let digest = cert.canonical_digest_bytes();
        cert.signature = signing_key.sign(&digest);
        cert
    }

    /// Verify Ed25519 digital signature Σ_C against authority verifying key.
    pub fn verify_signature(&self, public_key: &VerifyingKey) -> Result<(), PcoError> {
        let digest = self.canonical_digest_bytes();
        public_key
            .verify(&digest, &self.signature)
            .map_err(|e| PcoError::InvalidSignature(e.to_string()))
    }

    /// BOUND(C, X) predicate: Binds certificate to exact state X.
    ///
    /// Rejects any attempt to reuse a certificate across differing states or configurations.
    pub fn check_bound(&self, state: &SystemState) -> Result<(), PcoError> {
        let current_state_id = SafetyKernel::state_id(state);

        // 1. Exact State ID match: ID_X == C.StateId
        if self.state_id != current_state_id {
            return Err(PcoError::StateReboundAttempt {
                cert_state_id: self.state_id.clone(),
                current_state_id,
            });
        }

        // 2. Model weights digest match
        if self.model_digest != state.intelligence.weights_digest {
            return Err(PcoError::StateReboundAttempt {
                cert_state_id: format!("model:{}", self.model_digest),
                current_state_id: format!("model:{}", state.intelligence.weights_digest),
            });
        }

        // 3. Input payload digest match
        if self.input_digest != state.action.payload_digest {
            return Err(PcoError::StateReboundAttempt {
                cert_state_id: format!("input:{}", self.input_digest),
                current_state_id: format!("input:{}", state.action.payload_digest),
            });
        }

        Ok(())
    }

    /// Check temporal expiry against current epoch.
    pub fn check_temporal(&self, current_epoch: i64, ttl_seconds: i64) -> Result<(), PcoError> {
        let expiration = self.timestamp_epoch.saturating_add(ttl_seconds);
        if current_epoch > expiration {
            return Err(PcoError::CertificateExpired {
                cert_timestamp: expiration,
                current_epoch,
            });
        }
        Ok(())
    }
}
