//! ssi-pco: Proof-Carrying Output (PCO) Verification and Pre-Action Ledger Commit.
//!
//! Axiomatic Foundation: Avni et al. (IACR 2026/994) & SSI Axiomatic System Defs 12-14.
//!
//! Guarantees:
//! 1. Formal 10-Tuple Certificate C = (Spec, Policy, Code, Model, Input, Proof, Verifier, Assumptions, τ, Σ_C)
//! 2. BOUND(C, X) strictly prevents certificate reuse across differing states.
//! 3. Process-isolated independent validator (kernel does NOT validate its own proofs).
//! 4. Pre-action cryptographic ledger commitment before releasing external effects.
//! 5. Dynamic Revocation API: revoked certificates/assets can never authorize execution.

#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]

pub mod error;
pub mod certificate;
pub mod validator;
pub mod revocation;
pub mod ledger_commit;
pub mod engine;

pub use error::PcoError;
pub use certificate::VerificationCertificate;
pub use validator::{
    IndependentValidator, ProcessIsolatedValidator, ToyDecidableComplianceValidator,
    ValidationVerdict,
};
pub use revocation::{RevocationRecord, RevocationRegistry};
pub use ledger_commit::{PcoLedger, PcoPreActionRecord};
pub use engine::PcoGateway;
