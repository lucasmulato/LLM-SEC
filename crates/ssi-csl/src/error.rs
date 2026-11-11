//! CSL error types.

use ssi_kernel::KernelError;
use wad18::WadError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CslError {
    /// CSL digital signature verification failed.
    InvalidSignature(String),
    /// Current time is outside the [valid_from, valid_until] epoch window.
    TemporalExpired { current: i64, valid_from: i64, valid_until: i64 },
    /// State sequence depth exceeds max allowed transitions.
    MaxTransitionsExceeded { current: u64, max: u64 },
    /// Proposed action type is not allowed by envelope.
    ActionTypeDisallowed(String),
    /// Proposed action risk exceeds envelope ceiling.
    RiskExceeded { risk_raw: i128, max_risk_raw: i128 },
    /// Proposed action resource cost exceeds per-action ceiling.
    PerActionCostExceeded { cost_raw: i128, max_cost_raw: i128 },
    /// Cumulative resource cost exceeds total budget limit.
    TotalBudgetExceeded { cumulative_cost_raw: i128, limit_raw: i128 },
    /// State is missing mandatory CSL constraints Q.
    MissingConstraints(Vec<String>),
    /// Authorization has been explicitly revoked.
    Revoked(String),
    /// State quarantine flag raised.
    Quarantined,
    /// Arithmetic fault.
    Arithmetic(WadError),
    /// Kernel error.
    Kernel(KernelError),
}

impl std::fmt::Display for CslError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CslError::InvalidSignature(msg) => write!(f, "CSL Signature Invalid: {msg}"),
            CslError::TemporalExpired { current, valid_from, valid_until } => {
                write!(f, "CSL Expired: epoch {current} outside [{valid_from}, {valid_until}]")
            }
            CslError::MaxTransitionsExceeded { current, max } => {
                write!(f, "CSL Max Transitions Exceeded: {current} > {max}")
            }
            CslError::ActionTypeDisallowed(act) => write!(f, "CSL Action Disallowed: {act}"),
            CslError::RiskExceeded { risk_raw, max_risk_raw } => {
                write!(f, "CSL Risk Exceeded: risk {risk_raw} > max {max_risk_raw}")
            }
            CslError::PerActionCostExceeded { cost_raw, max_cost_raw } => {
                write!(f, "CSL Per-Action Cost Exceeded: cost {cost_raw} > max {max_cost_raw}")
            }
            CslError::TotalBudgetExceeded { cumulative_cost_raw, limit_raw } => {
                write!(f, "CSL Total Budget Exceeded: cumulative {cumulative_cost_raw} > limit {limit_raw}")
            }
            CslError::MissingConstraints(c) => write!(f, "CSL Mandatory Constraints Missing: {:?}", c),
            CslError::Revoked(reason) => write!(f, "CSL Authorization Revoked: {reason}"),
            CslError::Quarantined => write!(f, "CSL Authorization Blocked: state is Quarantined"),
            CslError::Arithmetic(e) => write!(f, "CSL Arithmetic Error: {e}"),
            CslError::Kernel(e) => write!(f, "CSL Kernel Error: {e}"),
        }
    }
}

impl From<WadError> for CslError {
    fn from(e: WadError) -> Self {
        CslError::Arithmetic(e)
    }
}

impl From<KernelError> for CslError {
    fn from(e: KernelError) -> Self {
        CslError::Kernel(e)
    }
}
