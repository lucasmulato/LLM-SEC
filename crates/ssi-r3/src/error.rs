//! R^3 Governed Evolution Engine Error Taxonomy (SSI Defs 22-25, Theorem 6).

#![deny(clippy::float_arithmetic)]

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum R3Error {
    /// PO-7: Safety Kernel Immutability & Supremacy Breach (Kernel manifest mismatch).
    KernelEqualityBreach {
        expected_digest: String,
        got_digest: String,
        reason: String,
    },
    /// PO-4: Candidate verification proof is missing, forged, or invalid.
    ProofInvalid {
        reason: String,
    },
    /// PO-3: Candidate authorization is expired, revoked, or signature invalid.
    AuthorizationInvalid {
        reason: String,
    },
    /// PO-5 / PO-8: Non-regression invariant violation (existing property degraded).
    NonRegressionViolation {
        clause: String,
        reason: String,
    },
    /// PO-8: Candidate failed one of the 15 canonical mutation safety checks.
    MutationCheckFailed {
        mutant_id: &'static str,
        name: &'static str,
        reason: String,
    },
    /// Candidate triggered system quarantine fail-closed.
    QuarantineTriggered {
        candidate_id: String,
        reason: String,
    },
    /// Ledger commitment failure during adoption recording.
    LedgerCommitFailed {
        reason: String,
    },
    /// Fixed-point harness divergence: R^3(X*) != X*.
    FixedPointDivergence {
        reason: String,
    },
}

impl std::fmt::Display for R3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            R3Error::KernelEqualityBreach {
                expected_digest,
                got_digest,
                reason,
            } => write!(
                f,
                "KernelEqualityBreach: expected {} but got {} ({})",
                expected_digest, got_digest, reason
            ),
            R3Error::ProofInvalid { reason } => write!(f, "ProofInvalid: {}", reason),
            R3Error::AuthorizationInvalid { reason } => {
                write!(f, "AuthorizationInvalid: {}", reason)
            }
            R3Error::NonRegressionViolation { clause, reason } => {
                write!(f, "NonRegressionViolation [{}]: {}", clause, reason)
            }
            R3Error::MutationCheckFailed {
                mutant_id,
                name,
                reason,
            } => write!(
                f,
                "MutationCheckFailed [{}: {}]: {}",
                mutant_id, name, reason
            ),
            R3Error::QuarantineTriggered {
                candidate_id,
                reason,
            } => write!(
                f,
                "QuarantineTriggered for candidate '{}': {}",
                candidate_id, reason
            ),
            R3Error::LedgerCommitFailed { reason } => write!(f, "LedgerCommitFailed: {}", reason),
            R3Error::FixedPointDivergence { reason } => {
                write!(f, "FixedPointDivergence: {}", reason)
            }
        }
    }
}

impl std::error::Error for R3Error {}
