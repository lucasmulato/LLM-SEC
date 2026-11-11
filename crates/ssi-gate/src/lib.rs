//! SSI Execution Gate — PERMIT predicate and verification pipeline.
//!
//! Pipeline order (strict):
//!   VERIFY → TRANSITION → INVARIANT_CHECK → COMMIT
//!
//! No external effects occur until COMMIT succeeds.
//! Any failure at any stage returns REJECT with no side effect.

#![deny(clippy::float_arithmetic)]

pub mod error;
pub mod permit;
pub mod pipeline;

pub use error::GateError;
pub use permit::{
    GateDecision, PermitResult, PermitVerdictDetail, VerificationStatus, assert_permit,
    evaluate_permit,
};
pub use pipeline::{CommitRecord, ExecutionGate, GateTrace, TraceStep};
