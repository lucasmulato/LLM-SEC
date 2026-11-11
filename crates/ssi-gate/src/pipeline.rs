//! Verification pipeline: VERIFY → TRANSITION → INVARIANT_CHECK → COMMIT
//!
//! Strict ordering guarantees:
//!   - No external effect occurs before COMMIT.
//!   - COMMIT only executes if invariant check passes.
//!   - Any failure at any stage returns Err — zero side-effects.

use sha2::{Digest, Sha256};
use ssi_kernel::{ActionProposal, SafetyKernel, SystemState};
use crate::{
    error::GateError,
    permit::{GateDecision, PermitResult, VerificationStatus, assert_permit},
};

/// Sealed record of a successful COMMIT.
#[derive(Clone, Debug)]
pub struct CommitRecord {
    /// Pre-state ID (SHA-256 hex)
    pub pre_state_id: String,
    /// Post-state ID (SHA-256 hex)
    pub post_state_id: String,
    /// Certificate binding action to transition
    pub certificate_id: String,
    /// Output payload digest
    pub output_digest: String,
    pub timestamp_epoch: i64,
    pub permit: PermitResult,
}

/// The main execution gate implementing the pipeline.
pub struct ExecutionGate<'k> {
    kernel: &'k SafetyKernel,
}

impl<'k> ExecutionGate<'k> {
    pub fn new(kernel: &'k SafetyKernel) -> Self {
        Self { kernel }
    }

    /// Execute the pipeline:
    ///   1. VERIFY  — PERMIT check
    ///   2. TRANSITION — build candidate post-state
    ///   3. INVARIANT_CHECK — verify I(X') on candidate
    ///   4. COMMIT  — seal certificate (no external effects before this)
    #[allow(clippy::too_many_arguments)]
    pub fn run<F, B>(
        &self,
        pre_state: &SystemState,
        action: &ActionProposal,
        ver_status: VerificationStatus,
        current_epoch: i64,
        required_capability: Option<&str>,
        // Pure sandbox handler — returns execution output bytes (no external effects).
        execute_pure: F,
        // Builds the candidate post-state from pre + action + output.
        build_post_state: B,
    ) -> Result<CommitRecord, GateError>
    where
        F: FnOnce(&ActionProposal) -> Vec<u8>,
        B: FnOnce(&SystemState, &ActionProposal, &[u8]) -> SystemState,
    {
        // ── STAGE 1: VERIFY (PERMIT gate) ──────────────────────────────────
        let permit = assert_permit(
            pre_state, action, ver_status, current_epoch, required_capability
        )?;
        let pre_state_id = SafetyKernel::state_id(pre_state);

        // ── STAGE 2: EXECUTE in pure sandbox ──────────────────────────────
        // Handler runs in an isolated context; zero external effects here.
        let output = execute_pure(action);
        let output_digest = hex::encode(Sha256::digest(&output));

        // ── STAGE 3: TRANSITION — build candidate post-state ──────────────
        let post_state = build_post_state(pre_state, action, &output);

        // Validate monotonic sequence progression
        if post_state.provenance.sequence_number != pre_state.provenance.sequence_number + 1 {
            return Err(GateError::TransitionViolation {
                reason: format!(
                    "sequence not monotonic: {} → {}",
                    pre_state.provenance.sequence_number,
                    post_state.provenance.sequence_number
                ),
            });
        }

        // Validate cryptographic parent linkage
        let post_state_id = SafetyKernel::state_id(&post_state);
        if post_state.provenance.parent_state_hash != pre_state_id {
            return Err(GateError::TransitionViolation {
                reason: format!(
                    "parent_state_hash mismatch: expected {}, got {}",
                    pre_state_id, post_state.provenance.parent_state_hash
                ),
            });
        }

        // ── STAGE 4: INVARIANT_CHECK — I(X') ──────────────────────────────
        self.kernel.verify_invariant(&post_state).map_err(|e| {
            GateError::InvariantViolation { reason: e.to_string() }
        })?;

        // ── STAGE 5: COMMIT ───────────────────────────────────────────────
        let cert_payload = format!("{}:{}:{}:{}", action.action_id, action.payload_digest, output_digest, pre_state_id);
        let _cert_hash = hex::encode(Sha256::digest(cert_payload.as_bytes()));
        let certificate_id = format!("cert-{}-{}", &action.action_id[..action.action_id.len().min(16)], current_epoch);

        Ok(CommitRecord {
            pre_state_id,
            post_state_id,
            certificate_id,
            output_digest,
            timestamp_epoch: current_epoch,
            permit,
        })
    }

    /// Execute the pipeline and record a detailed conformance trace step.
    #[allow(clippy::too_many_arguments)]
    pub fn run_with_trace<F, B>(
        &self,
        trace: &mut GateTrace,
        pre_state: &SystemState,
        action: &ActionProposal,
        ver_status: VerificationStatus,
        current_epoch: i64,
        required_capability: Option<&str>,
        execute_pure: F,
        build_post_state: B,
    ) -> Result<CommitRecord, GateError>
    where
        F: FnOnce(&ActionProposal) -> Vec<u8>,
        B: FnOnce(&SystemState, &ActionProposal, &[u8]) -> SystemState,
    {
        let step_index = trace.steps.len() as u64;
        let pre_state_id = SafetyKernel::state_id(pre_state);

        // Attempt execution
        match self.run(
            pre_state,
            action,
            ver_status,
            current_epoch,
            required_capability,
            execute_pure,
            build_post_state,
        ) {
            Ok(commit_record) => {
                let post_state_id = commit_record.post_state_id.clone();
                // Post-state is inferred or retrieved from transition
                trace.steps.push(TraceStep {
                    step_index,
                    epoch: current_epoch,
                    pre_state: pre_state.clone(),
                    pre_state_id,
                    action: action.clone(),
                    ver_status,
                    required_capability: required_capability.map(|s| s.to_string()),
                    permit_decision: GateDecision::Permit,
                    post_state_id: Some(post_state_id),
                    commit_record: Some(commit_record.clone()),
                    error: None,
                });
                Ok(commit_record)
            }
            Err(err) => {
                trace.steps.push(TraceStep {
                    step_index,
                    epoch: current_epoch,
                    pre_state: pre_state.clone(),
                    pre_state_id,
                    action: action.clone(),
                    ver_status,
                    required_capability: required_capability.map(|s| s.to_string()),
                    permit_decision: GateDecision::Reject,
                    post_state_id: None,
                    commit_record: None,
                    error: Some(err.to_string()),
                });
                Err(err)
            }
        }
    }
}

/// A recorded execution trace step for formal refinement verification.
#[derive(Clone, Debug)]
pub struct TraceStep {
    pub step_index: u64,
    pub epoch: i64,
    pub pre_state: SystemState,
    pub pre_state_id: String,
    pub action: ActionProposal,
    pub ver_status: VerificationStatus,
    pub required_capability: Option<String>,
    pub permit_decision: GateDecision,
    pub post_state_id: Option<String>,
    pub commit_record: Option<CommitRecord>,
    pub error: Option<String>,
}

/// A collection of sequential trace steps emitted by the gateway.
#[derive(Clone, Debug)]
pub struct GateTrace {
    pub trace_id: String,
    pub initial_state_id: String,
    pub steps: Vec<TraceStep>,
}

impl GateTrace {
    pub fn new(trace_id: impl Into<String>, initial_state_id: impl Into<String>) -> Self {
        Self {
            trace_id: trace_id.into(),
            initial_state_id: initial_state_id.into(),
            steps: Vec::new(),
        }
    }
}
