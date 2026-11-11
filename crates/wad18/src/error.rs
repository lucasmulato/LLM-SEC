//! Error types for WAD-18 fixed-point deterministic arithmetic.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WadError {
    /// Numerical overflow exceeding bounded integer limits.
    Overflow,
    /// Numerical underflow below bounded integer limits.
    Underflow,
    /// Explicit division or modulo by zero.
    DivisionByZero,
    /// Scale factor does not match 10^18.
    InvalidScale,
    /// Canonical encoding or textual representation is invalid.
    InvalidEncoding,
    /// Numerical value falls outside an admissible governance/operational interval.
    OutOfRange,
    /// Operation produces an unrepresentable fractional remainder (silent rounding forbidden).
    InexactResult,
}

impl core::fmt::Display for WadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WadError::Overflow => write!(f, "WAD-18 overflow"),
            WadError::Underflow => write!(f, "WAD-18 underflow"),
            WadError::DivisionByZero => write!(f, "WAD-18 division by zero"),
            WadError::InvalidScale => write!(f, "WAD-18 invalid scaling factor"),
            WadError::InvalidEncoding => write!(f, "WAD-18 invalid encoding or format"),
            WadError::OutOfRange => write!(f, "WAD-18 value out of range"),
            WadError::InexactResult => write!(f, "WAD-18 inexact arithmetic result"),
        }
    }
}
