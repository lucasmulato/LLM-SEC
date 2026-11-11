//! SSI Cognitive State Ledger (CSL): CSL = (ID, Σ, E, T, Q)
//! Enforces continuous authorization with Ed25519 digital signatures,
//! temporal validity, operating envelope limits, and monotonic budget conservation.

#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]

pub mod envelope;
pub mod error;

pub use envelope::{CSLEnvelope, OperatingEnvelope, TemporalValidity};
pub use error::CslError;
