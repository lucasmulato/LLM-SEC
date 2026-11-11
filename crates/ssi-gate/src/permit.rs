//! PERMIT(X, a) = AUTH(X, a) ∧ SAFE_ACTION(X, a) ∧ VER(X, a) ∧ CAP(X, a)
//! All sub-predicates must pass simultaneously; partial pass is REJECT.

use ssi_kernel::{ActionProposal, SystemState};
use crate::error::GateError;

/// Tri-state verification status (Unknown ⇒ REJECT).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationStatus {
    Valid,
    Invalid,
    Unknown,
}

/// Overall gate decision (binary — no "partial permit").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateDecision {
    Permit,
    Reject,
}

impl GateDecision {
    pub fn is_permit(self) -> bool {
        self == GateDecision::Permit
    }
}

/// Detailed breakdown of PERMIT evaluation.
#[derive(Clone, Debug)]
pub struct PermitVerdictDetail {
    pub auth_pass: bool,
    pub safe_action_pass: bool,
    pub ver_pass: bool,
    pub cap_pass: bool,
    pub reasons: Vec<String>,
}

/// Full PERMIT evaluation result.
#[derive(Clone, Debug)]
pub struct PermitResult {
    pub decision: GateDecision,
    pub detail: PermitVerdictDetail,
}

/// AUTH(X, a): active authorization with sufficient clearance, non-expired.
pub fn check_auth(
    state: &SystemState,
    action: &ActionProposal,
    current_epoch: i64,
) -> (bool, Option<String>) {
    let h = &state.authorization;

    if !h.is_active {
        return (false, Some("authorization token is inactive".into()));
    }
    if current_epoch > h.expires_at_epoch {
        return (false, Some(format!(
            "authorization expired at {} (now {})", h.expires_at_epoch, current_epoch
        )));
    }
    if h.clearance_level < action.required_clearance {
        return (false, Some(format!(
            "clearance {} < required {}", h.clearance_level, action.required_clearance
        )));
    }
    if h.auth_token.is_empty() || h.nonce.is_empty() {
        return (false, Some("auth_token or nonce is empty".into()));
    }
    (true, None)
}

/// SAFE_ACTION(X, a): action type allowed, risk within bounds, no quarantine.
pub fn check_safe_action(
    state: &SystemState,
    action: &ActionProposal,
) -> (bool, Option<String>) {
    let s = &state.safety;

    if !s.containment_active || !s.containment_barrier_intact {
        return (false, Some("containment barrier inactive or breached".into()));
    }
    if s.quarantine_flag {
        return (false, Some("system is quarantined; all actions forbidden".into()));
    }
    if action.action_type == ssi_kernel::ActionType::SystemHalt {
        return (false, Some("SYSTEM_HALT must use dedicated emergency pathway".into()));
    }
    if action.risk_assessment > s.risk_bound {
        return (false, Some(format!(
            "action risk {} > risk_bound {}", action.risk_assessment.raw(), s.risk_bound.raw()
        )));
    }
    // Check forbidden keywords in action_id
    let id_upper = action.action_id.to_uppercase();
    let forbidden = ["EXFILTRATE", "DISABLE_CONTAINMENT", "OVERRIDE_AUTH", "BYPASS_GATE"];
    for f in &forbidden {
        if id_upper.contains(f) {
            return (false, Some(format!("action_id contains forbidden keyword: {f}")));
        }
    }
    (true, None)
}

/// VER(X, a): proof certificate is valid; Unknown ⇒ REJECT.
pub fn check_ver(
    state: &SystemState,
    action: &ActionProposal,
    status: VerificationStatus,
) -> (bool, Option<String>) {
    match status {
        VerificationStatus::Unknown => {
            return (false, Some("VER is UNKNOWN — fail-closed REJECT".into()));
        }
        VerificationStatus::Invalid => {
            return (false, Some("VER is INVALID".into()));
        }
        VerificationStatus::Valid => {}
    }
    if !state.verification.is_valid {
        return (false, Some(format!(
            "certificate '{}' marked invalid", state.verification.certificate_id
        )));
    }
    if action.payload_digest.len() != 64 {
        return (false, Some(format!(
            "payload_digest length {} ≠ 64", action.payload_digest.len()
        )));
    }
    (true, None)
}

/// CAP(X, a): model has cognitive budget and required capability.
pub fn check_cap(
    state: &SystemState,
    action: &ActionProposal,
    required_capability: Option<&str>,
) -> (bool, Option<String>) {
    let i = &state.intelligence;

    if i.cognitive_budget < action.resource_cost {
        return (false, Some(format!(
            "cognitive_budget {} < resource_cost {}",
            i.cognitive_budget.raw(), action.resource_cost.raw()
        )));
    }
    if let Some(cap) = required_capability {
        if !i.capabilities.contains(cap) {
            return (false, Some(format!("capability '{cap}' not in model capabilities")));
        }
    }
    (true, None)
}

/// Evaluate PERMIT(X, a) = AUTH ∧ SAFE_ACTION ∧ VER ∧ CAP.
pub fn evaluate_permit(
    state: &SystemState,
    action: &ActionProposal,
    ver_status: VerificationStatus,
    current_epoch: i64,
    required_capability: Option<&str>,
) -> PermitResult {
    let mut reasons = Vec::new();

    let (auth_ok, auth_err) = check_auth(state, action, current_epoch);
    if !auth_ok { reasons.push(format!("[AUTH] {}", auth_err.unwrap_or_default())); }

    let (safe_ok, safe_err) = check_safe_action(state, action);
    if !safe_ok { reasons.push(format!("[SAFE_ACTION] {}", safe_err.unwrap_or_default())); }

    let (ver_ok, ver_err) = check_ver(state, action, ver_status);
    if !ver_ok { reasons.push(format!("[VER] {}", ver_err.unwrap_or_default())); }

    let (cap_ok, cap_err) = check_cap(state, action, required_capability);
    if !cap_ok { reasons.push(format!("[CAP] {}", cap_err.unwrap_or_default())); }

    let all_pass = auth_ok && safe_ok && ver_ok && cap_ok;
    PermitResult {
        decision: if all_pass { GateDecision::Permit } else { GateDecision::Reject },
        detail: PermitVerdictDetail {
            auth_pass: auth_ok,
            safe_action_pass: safe_ok,
            ver_pass: ver_ok,
            cap_pass: cap_ok,
            reasons,
        },
    }
}

/// Convenience: returns Err(GateError) on REJECT.
pub fn assert_permit(
    state: &SystemState,
    action: &ActionProposal,
    ver_status: VerificationStatus,
    current_epoch: i64,
    required_capability: Option<&str>,
) -> Result<PermitResult, GateError> {
    let result = evaluate_permit(state, action, ver_status, current_epoch, required_capability);
    if result.decision == GateDecision::Permit {
        Ok(result)
    } else {
        Err(GateError::PermitDenied {
            action_id: action.action_id.clone(),
            reasons: result.detail.reasons,
        })
    }
}
