//! SSI Kernel: Typed System State and Global Invariant Evaluation.
//!
//! Implements:
//! - System State X = (I, S, A, H, V, P)
//! - Invariant Registry Φ — empty set is an explicit hard failure
//! - Global Invariant I(X) = TypeValid ∧ KernelValid ∧ CSLValid ∧ AuthValid ∧ SafetyValid ∧ VerValid ∧ ProvValid
//! - Tri-state invariant evaluation: Unknown ⇒ FAIL (fail-closed)

#![deny(clippy::float_arithmetic)]

pub mod error;
pub mod state;
pub mod invariants;
pub mod kernel;

pub use error::KernelError;
pub use state::{
    ActionProposal, ActionType, AuthorizationState, IntelligenceState, ProvenanceState,
    SafetyState, SystemState, VerificationState,
};
pub use invariants::{InvariantClause, InvariantRegistry, InvariantResult, InvariantVerdict};
pub use kernel::{CandidateSystem, SafetyKernel};
