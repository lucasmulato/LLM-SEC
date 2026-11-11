//! SSI R^3 Governed Evolution Engine and ADOPT Non-Regression Gate
//! (SSI Axiomatic System Definitions 22-25, Theorem 6, Section 26).
//!
//! Enforces:
//! - Exact byte-for-byte kernel equality via KernelManifest (PO-7)
//! - ADOPT(Y) = KernelEqual /\ ProofValid /\ AuthorizationValid /\ NonRegression (PO-7, PO-8)
//! - Pre-adoption non-regression verification over full invariant suite + 15 mutation checks
//! - SACEvidence ledger recording for successful adoption and quarantine rollback for failures
//! - SSI §26 Fixed-point evolution harness R^3(X*) = X*

#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]

pub mod adopt;
pub mod engine;
pub mod error;
pub mod ledger;
pub mod manifest;
pub mod non_regression;
pub mod partition;

pub use adopt::{
    CandidateRefinement, GovernanceAuthorization, ProofArtifact, evaluate_adopt,
};
pub use engine::{FixedPointVerdict, R3Engine};
pub use error::R3Error;
pub use ledger::{QuarantineAuditRecord, R3Ledger};
pub use manifest::{KernelManifest, NORMATIVE_SPEC_VERSION, NORMATIVE_WAD_SCALE};
pub use non_regression::{check_non_regression, run_15_mutation_checks};
pub use partition::{GovernedConfig, MutableModel, SystemPartition};
