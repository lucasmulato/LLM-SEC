//! Error types for Proof-Carrying Output (PCO) module.

use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PcoError {
    /// Certificate state binding violated: attempt to reuse across states.
    StateReboundAttempt {
        cert_state_id: String,
        current_state_id: String,
    },
    /// Certificate temporal window has expired.
    CertificateExpired {
        cert_timestamp: i64,
        current_epoch: i64,
    },
    /// Certificate or asset explicitly revoked.
    CertificateRevoked {
        cert_id: String,
        reason: String,
    },
    /// Cryptographic signature verification failed.
    InvalidSignature(String),
    /// Independent validator subprocess crashed or exited with error.
    ValidatorCrash(String),
    /// Independent validator timed out (fail-closed).
    ValidatorTimeout,
    /// Unknown or indeterminate validation status (fail-closed).
    UnknownValidationStatus(String),
    /// Proof rejected by independent validator.
    VerificationFailed(String),
    /// Pre-action ledger commit failed before execution.
    LedgerCommitFailed(String),
    /// Missing proof artifact.
    MissingProof,
    /// Arithmetic error.
    Arithmetic(wad18::WadError),
}

impl fmt::Display for PcoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PcoError::StateReboundAttempt { cert_state_id, current_state_id } => {
                write!(f, "BOUND(C,X) violation: cert bound to {} but current state is {}", cert_state_id, current_state_id)
            }
            PcoError::CertificateExpired { cert_timestamp, current_epoch } => {
                write!(f, "Certificate expired: cert timestamp {} < current epoch {}", cert_timestamp, current_epoch)
            }
            PcoError::CertificateRevoked { cert_id, reason } => {
                write!(f, "Certificate '{}' is revoked: {}", cert_id, reason)
            }
            PcoError::InvalidSignature(msg) => write!(f, "Invalid signature: {}", msg),
            PcoError::ValidatorCrash(msg) => write!(f, "Validator subprocess crashed: {}", msg),
            PcoError::ValidatorTimeout => write!(f, "Validator timed out (fail-closed REJECT)"),
            PcoError::UnknownValidationStatus(msg) => write!(f, "Unknown validation status: {}", msg),
            PcoError::VerificationFailed(msg) => write!(f, "Verification failed: {}", msg),
            PcoError::LedgerCommitFailed(msg) => write!(f, "Pre-action ledger commit failed: {}", msg),
            PcoError::MissingProof => write!(f, "Missing proof artifact in certificate"),
            PcoError::Arithmetic(e) => write!(f, "Arithmetic error: {:?}", e),
        }
    }
}

impl std::error::Error for PcoError {}

impl From<wad18::WadError> for PcoError {
    fn from(e: wad18::WadError) -> Self {
        PcoError::Arithmetic(e)
    }
}
