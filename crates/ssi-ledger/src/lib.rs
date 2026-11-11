//! SSI Ledger: Canonical encoding ENC(X), state hashing ID_X=SHA-256(ENC(X)),
//! append-only hash-chained storage, SAC evidence objects with provenance Γ,
//! and offline audit/replay verification.

#![deny(clippy::float_arithmetic)]

pub mod error;
pub mod store;

pub use error::LedgerError;
pub use store::{
    AppendOnlyLedgerStore, SACEvidence, SafetyAssetClass, canonical_encode_state, compute_state_id,
};
