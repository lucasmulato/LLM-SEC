//! Invariant registry Φ and global invariant evaluation I(X).
//!
//! Rules:
//! - Empty Φ ⇒ immediate FAIL
//! - Unknown tri-state ⇒ FAIL (fail-closed)
//! - All clauses must pass simultaneously

use crate::{error::KernelError, state::SystemState};

/// Tri-state evaluation result for a single invariant clause.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvariantResult {
    Pass,
    Fail(String),
    /// Any unknown is treated as FAIL under fail-closed semantics.
    Unknown(String),
}

impl InvariantResult {
    pub fn is_pass(&self) -> bool {
        matches!(self, InvariantResult::Pass)
    }

    /// Fail-closed: Unknown maps to Fail.
    pub fn fail_closed_pass(&self) -> bool {
        matches!(self, InvariantResult::Pass)
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            InvariantResult::Fail(r) | InvariantResult::Unknown(r) => Some(r),
            InvariantResult::Pass => None,
        }
    }
}

/// A named invariant clause that evaluates over a SystemState.
pub struct InvariantClause {
    pub id: String,
    pub evaluate: Box<dyn Fn(&SystemState) -> InvariantResult + Send + Sync>,
}

impl std::fmt::Debug for InvariantClause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvariantClause").field("id", &self.id).finish()
    }
}

impl InvariantClause {
    pub fn new(id: impl Into<String>, f: impl Fn(&SystemState) -> InvariantResult + Send + Sync + 'static) -> Self {
        Self { id: id.into(), evaluate: Box::new(f) }
    }
}

/// Verdict of global invariant evaluation over state X.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvariantVerdict {
    pub is_valid: bool,
    pub state_id: String,
    pub clause_results: Vec<(String, InvariantResult)>,
    pub failure_reason: Option<String>,
}

/// Invariant registry Φ. Empty set is an explicit violation.
pub struct InvariantRegistry {
    clauses: Vec<InvariantClause>,
}

impl InvariantRegistry {
    /// Create a registry from a set of invariant clauses.
    /// Returns error if clauses is empty (Φ = ∅ ⇒ FAIL).
    pub fn new(clauses: Vec<InvariantClause>) -> Result<Self, KernelError> {
        if clauses.is_empty() {
            return Err(KernelError::EmptyInvariantSet);
        }
        Ok(Self { clauses })
    }

    /// Create the standard 7-clause kernel invariant registry.
    pub fn standard() -> Result<Self, KernelError> {
        Self::new(vec![
            InvariantClause::new("TypeValid", check_type_valid),
            InvariantClause::new("KernelValid", check_kernel_valid),
            InvariantClause::new("CSLValid", check_csl_valid),
            InvariantClause::new("AuthValid", check_auth_valid),
            InvariantClause::new("SafetyValid", check_safety_valid),
            InvariantClause::new("VerValid", check_ver_valid),
            InvariantClause::new("ProvValid", check_prov_valid),
        ])
    }

    /// Evaluate I(X) = conjunction of all Φ clauses.
    pub fn evaluate(&self, state: &SystemState, state_id: &str) -> InvariantVerdict {
        let mut results = Vec::with_capacity(self.clauses.len());
        let mut failures = Vec::new();

        for clause in &self.clauses {
            let result = (clause.evaluate)(state);
            if !result.fail_closed_pass() {
                let reason = result.reason().unwrap_or("unknown").to_string();
                failures.push(format!("[{}] {}", clause.id, reason));
            }
            results.push((clause.id.clone(), result));
        }

        let is_valid = failures.is_empty();
        let failure_reason = if is_valid {
            None
        } else {
            Some(failures.join("; "))
        };

        InvariantVerdict {
            is_valid,
            state_id: state_id.to_string(),
            clause_results: results,
            failure_reason,
        }
    }

    /// Fail-closed strict enforcement. Returns Err on any failure.
    pub fn enforce(&self, state: &SystemState, state_id: &str) -> Result<(), KernelError> {
        let verdict = self.evaluate(state, state_id);
        if verdict.is_valid {
            Ok(())
        } else {
            Err(KernelError::InvariantFailed {
                clause: "GLOBAL".to_string(),
                reason: verdict.failure_reason.unwrap_or_default(),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Standard clause implementations
// ---------------------------------------------------------------------------

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn check_type_valid(state: &SystemState) -> InvariantResult {
    if state.intelligence.model_id.is_empty() {
        return InvariantResult::Fail("model_id is empty".into());
    }
    if !is_hex64(&state.intelligence.weights_digest) {
        return InvariantResult::Fail("weights_digest must be 64 hex chars".into());
    }
    if !is_hex64(&state.action.payload_digest) {
        return InvariantResult::Fail("payload_digest must be 64 hex chars".into());
    }
    if !is_hex64(&state.verification.proof_digest) {
        return InvariantResult::Fail("proof_digest must be 64 hex chars".into());
    }
    // Epistemic confidence in [0,1]
    let zero = wad18::Wad18::ZERO;
    let one = wad18::Wad18::ONE;
    if state.intelligence.epistemic_confidence < zero || state.intelligence.epistemic_confidence > one {
        return InvariantResult::Fail(format!(
            "epistemic_confidence {} outside [0,1]",
            state.intelligence.epistemic_confidence.raw()
        ));
    }
    InvariantResult::Pass
}

fn check_kernel_valid(_state: &SystemState) -> InvariantResult {
    // Kernel validity: WAD scale must be intact
    if wad18::WAD_SCALE != 1_000_000_000_000_000_000 {
        return InvariantResult::Fail("WAD_SCALE corrupted".into());
    }
    InvariantResult::Pass
}

fn check_csl_valid(state: &SystemState) -> InvariantResult {
    if !state.safety.containment_active {
        return InvariantResult::Fail("containment_active is false".into());
    }
    if !state.safety.containment_barrier_intact {
        return InvariantResult::Fail("containment_barrier_intact is false".into());
    }
    if state.safety.quarantine_flag {
        return InvariantResult::Fail("quarantine_flag is raised".into());
    }
    if state.safety.csl_constraints.is_empty() {
        return InvariantResult::Fail("csl_constraints (Q) is empty".into());
    }
    InvariantResult::Pass
}

fn check_auth_valid(state: &SystemState) -> InvariantResult {
    if !state.authorization.is_active {
        return InvariantResult::Fail("authorization is inactive".into());
    }
    if state.authorization.auth_token.is_empty() || state.authorization.nonce.is_empty() {
        return InvariantResult::Fail("auth_token or nonce is empty".into());
    }
    if state.authorization.clearance_level < state.action.required_clearance {
        return InvariantResult::Fail(format!(
            "clearance {} < required {}",
            state.authorization.clearance_level, state.action.required_clearance
        ));
    }
    InvariantResult::Pass
}

fn check_safety_valid(state: &SystemState) -> InvariantResult {
    if state.action.risk_assessment > state.safety.risk_bound {
        return InvariantResult::Fail(format!(
            "action risk {} > risk_bound {}",
            state.action.risk_assessment.raw(), state.safety.risk_bound.raw()
        ));
    }
    if state.safety.safety_margin < state.safety.risk_bound {
        return InvariantResult::Fail(format!(
            "safety_margin {} < risk_bound {}",
            state.safety.safety_margin.raw(), state.safety.risk_bound.raw()
        ));
    }
    InvariantResult::Pass
}

fn check_ver_valid(state: &SystemState) -> InvariantResult {
    if !state.verification.is_valid {
        return InvariantResult::Fail(format!(
            "verification cert '{}' is marked invalid",
            state.verification.certificate_id
        ));
    }
    if state.verification.verifier_identity.is_empty() {
        return InvariantResult::Fail("verifier_identity is empty".into());
    }
    InvariantResult::Pass
}

fn check_prov_valid(state: &SystemState) -> InvariantResult {
    if state.provenance.sequence_number > 0 && !is_hex64(&state.provenance.parent_state_hash) {
        return InvariantResult::Fail("parent_state_hash must be 64 hex chars for seq > 0".into());
    }
    if !is_hex64(&state.provenance.merkle_root) {
        return InvariantResult::Fail("merkle_root must be 64 hex chars".into());
    }
    if state.provenance.audit_trail_id.is_empty() {
        return InvariantResult::Fail("audit_trail_id is empty".into());
    }
    InvariantResult::Pass
}
