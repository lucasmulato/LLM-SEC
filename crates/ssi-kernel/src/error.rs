//! SSI Kernel error types.

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KernelError {
    /// Invariant set Φ is empty — this is never safe.
    EmptyInvariantSet,
    /// A required invariant could not be evaluated (tri-state Unknown).
    InvariantUnknown(String),
    /// An invariant clause failed.
    InvariantFailed { clause: String, reason: String },
    /// State field type is malformed.
    TypeViolation(String),
    /// A WAD-18 arithmetic error from an inner computation.
    Arithmetic(wad18::WadError),
    /// Cryptographic digest is not 64 hex chars.
    InvalidDigest(String),
    /// Kernel mode violation (kernel in HALTED/QUARANTINED state).
    KernelModeViolation(String),
}

impl core::fmt::Display for KernelError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            KernelError::EmptyInvariantSet => write!(f, "FAIL: invariant set Φ is empty"),
            KernelError::InvariantUnknown(c) => write!(f, "FAIL: invariant '{c}' is UNKNOWN"),
            KernelError::InvariantFailed { clause, reason } => {
                write!(f, "FAIL: invariant '{clause}': {reason}")
            }
            KernelError::TypeViolation(msg) => write!(f, "TYPE VIOLATION: {msg}"),
            KernelError::Arithmetic(e) => write!(f, "ARITHMETIC FAULT: {e}"),
            KernelError::InvalidDigest(field) => {
                write!(f, "INVALID DIGEST: '{field}' must be 64 lowercase hex chars")
            }
            KernelError::KernelModeViolation(msg) => write!(f, "KERNEL MODE VIOLATION: {msg}"),
        }
    }
}

impl From<wad18::WadError> for KernelError {
    fn from(e: wad18::WadError) -> Self {
        KernelError::Arithmetic(e)
    }
}
