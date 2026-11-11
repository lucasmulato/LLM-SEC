//! SafetyKernel: mode management, state hashing, and global invariant enforcement.

use sha2::{Digest, Sha256};
use crate::{
    error::KernelError,
    invariants::{InvariantRegistry, InvariantVerdict},
    state::SystemState,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelMode {
    VerifiedNominal,
    Quarantined,
    Halted,
}

pub struct SafetyKernel {
    mode: KernelMode,
    halt_reason: Option<String>,
    registry: InvariantRegistry,
}

impl SafetyKernel {
    /// Create a SafetyKernel with the standard 7-clause invariant registry.
    pub fn new() -> Result<Self, KernelError> {
        Ok(Self {
            mode: KernelMode::VerifiedNominal,
            halt_reason: None,
            registry: InvariantRegistry::standard()?,
        })
    }

    /// Create with a custom invariant registry (Φ must be non-empty).
    pub fn with_registry(registry: InvariantRegistry) -> Self {
        Self {
            mode: KernelMode::VerifiedNominal,
            halt_reason: None,
            registry,
        }
    }

    pub fn mode(&self) -> KernelMode {
        self.mode
    }

    pub fn halt_reason(&self) -> Option<&str> {
        self.halt_reason.as_deref()
    }

    pub fn emergency_halt(&mut self, reason: impl Into<String>) {
        self.mode = KernelMode::Halted;
        self.halt_reason = Some(reason.into());
    }

    pub fn emergency_quarantine(&mut self, reason: impl Into<String>) {
        self.mode = KernelMode::Quarantined;
        self.halt_reason = Some(reason.into());
    }

    /// Compute deterministic SHA-256 state identifier ID_X = H(ENC(X)).
    pub fn state_id(state: &SystemState) -> String {
        let canonical = state.canonical_dict();
        let json = canonical
            .iter()
            .map(|(k, v)| format!("\"{}\":{}", k, v.to_canonical_json()))
            .collect::<Vec<_>>()
            .join(",");
        let json = format!("{{{}}}", json);
        let hash = Sha256::digest(json.as_bytes());
        hex::encode(hash)
    }

    /// Evaluate global invariant I(X) and return a verdict.
    pub fn evaluate_invariant(&self, state: &SystemState) -> InvariantVerdict {
        if self.mode != KernelMode::VerifiedNominal {
            let reason = format!("Kernel in {:?} mode: {}", self.mode,
                self.halt_reason.as_deref().unwrap_or(""));
            return InvariantVerdict {
                is_valid: false,
                state_id: Self::state_id(state),
                clause_results: vec![],
                failure_reason: Some(reason),
            };
        }
        let sid = Self::state_id(state);
        self.registry.evaluate(state, &sid)
    }

    /// Fail-closed strict enforcement of I(X).
    pub fn verify_invariant(&self, state: &SystemState) -> Result<String, KernelError> {
        if self.mode != KernelMode::VerifiedNominal {
            return Err(KernelError::KernelModeViolation(
                format!("{:?}", self.mode)
            ));
        }
        let sid = Self::state_id(state);
        self.registry.enforce(state, &sid)?;
        Ok(sid)
    }

    /// Immutable kernel cryptographic identity digest.
    pub fn kernel_digest(&self) -> &'static str {
        "ssi_kernel_v1_immutable_digest_e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }

    /// R^3 Adoption Gate: ADOPT(Y) <=> KernelEqual(Y) /\ ProofValid(Y) /\ AuthorizationValid(Y) /\ NonRegression(Y)
    pub fn check_adopt(
        &self,
        current: &SystemState,
        candidate: &CandidateSystem,
        candidate_state: &SystemState,
    ) -> Result<(), KernelError> {
        // 1. KernelEqual: candidate must preserve identical immutable kernel digest (PO-7)
        if candidate.kernel_digest != self.kernel_digest() {
            return Err(KernelError::InvariantFailed {
                clause: "KernelEqual".to_string(),
                reason: format!(
                    "Kernel equality breach: candidate digest {} != kernel digest {}",
                    candidate.kernel_digest,
                    self.kernel_digest()
                ),
            });
        }
        // 2. ProofValid
        if !candidate.proof_valid {
            return Err(KernelError::InvariantFailed {
                clause: "ProofValid".to_string(),
                reason: "Candidate verification proof invalid".to_string(),
            });
        }
        // 3. AuthorizationValid
        if !candidate.auth_valid {
            return Err(KernelError::InvariantFailed {
                clause: "AuthorizationValid".to_string(),
                reason: "Candidate update lacks valid governance authorization".to_string(),
            });
        }
        // 4. NonRegression: all invariants passing on current must pass on candidate (PO-8)
        let cur_verdict = self.evaluate_invariant(current);
        let cand_verdict = self.evaluate_invariant(candidate_state);
        if cur_verdict.is_valid && !cand_verdict.is_valid {
            return Err(KernelError::InvariantFailed {
                clause: "NonRegression".to_string(),
                reason: format!("Candidate regresses invariants: {:?}", cand_verdict.failure_reason),
            });
        }
        Ok(())
    }
}

/// Candidate system descriptor submitted for R^3 governed adoption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateSystem {
    pub kernel_digest: String,
    pub model_id: String,
    pub weights_digest: String,
    pub config_manifest: String,
    pub proof_valid: bool,
    pub auth_valid: bool,
}

impl Default for SafetyKernel {
    fn default() -> Self {
        Self::new().expect("standard registry is non-empty")
    }
}
