//! SSI Ledger error types.

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerError {
    ChainBroken { index: usize, expected_prev: String, actual_prev: String },
    TamperedRecord { index: usize, computed_hash: String, recorded_hash: String },
    SequenceDiscontinuity { index: usize, expected_seq: u64, actual_seq: u64 },
    ParentStateMismatch { index: usize, expected_parent: String, actual_parent: String },
    EncodingError(String),
    IoError(String),
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LedgerError::ChainBroken { index, expected_prev, actual_prev } => {
                write!(f, "Chain broken at index {index}: expected prev '{expected_prev}', got '{actual_prev}'")
            }
            LedgerError::TamperedRecord { index, computed_hash, recorded_hash } => {
                write!(f, "Record tampered at index {index}: computed '{computed_hash}', stored '{recorded_hash}'")
            }
            LedgerError::SequenceDiscontinuity { index, expected_seq, actual_seq } => {
                write!(f, "Sequence discontinuity at index {index}: expected {expected_seq}, got {actual_seq}")
            }
            LedgerError::ParentStateMismatch { index, expected_parent, actual_parent } => {
                write!(f, "Parent mismatch at index {index}: expected '{expected_parent}', got '{actual_parent}'")
            }
            LedgerError::EncodingError(e) => write!(f, "Canonical encoding error: {e}"),
            LedgerError::IoError(e) => write!(f, "Ledger I/O error: {e}"),
        }
    }
}
