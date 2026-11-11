//! Gate error types.

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GateError {
    PermitDenied { action_id: String, reasons: Vec<String> },
    TransitionViolation { reason: String },
    InvariantViolation { reason: String },
    UnknownVerification { action_id: String },
    KernelFault(String),
}

impl std::fmt::Display for GateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GateError::PermitDenied { action_id, reasons } => {
                write!(f, "PERMIT DENIED for '{}': {}", action_id, reasons.join("; "))
            }
            GateError::TransitionViolation { reason } => {
                write!(f, "TRANSITION VIOLATION: {}", reason)
            }
            GateError::InvariantViolation { reason } => {
                write!(f, "INVARIANT VIOLATION: {}", reason)
            }
            GateError::UnknownVerification { action_id } => {
                write!(f, "UNKNOWN verification status for '{}': fail-closed REJECT", action_id)
            }
            GateError::KernelFault(msg) => write!(f, "KERNEL FAULT: {}", msg),
        }
    }
}
