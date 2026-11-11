//! PCO Execution Gateway Engine.
//!
//! Orchestrates Proof-Carrying Output validation:
//! 1. BOUND(C, X) verification
//! 2. Dynamic Revocation check
//! 3. Cryptographic Signature verification
//! 4. Independent out-of-process validation
//! 5. PRE-ACTION cryptographic ledger commit
//! 6. Gateway execution and state transition

use ed25519_dalek::VerifyingKey;
use ssi_gate::{CommitRecord, ExecutionGate, VerificationStatus};
use ssi_kernel::{ActionProposal, SafetyKernel, SystemState};
use crate::{
    certificate::VerificationCertificate,
    error::PcoError,
    ledger_commit::{PcoLedger, PcoPreActionRecord},
    revocation::RevocationRegistry,
    validator::{IndependentValidator, ValidationVerdict},
};

pub struct PcoGateway<'k> {
    kernel: &'k SafetyKernel,
    gate: ExecutionGate<'k>,
    ledger: PcoLedger,
    revocations: RevocationRegistry,
    authority_public_key: VerifyingKey,
}

impl<'k> PcoGateway<'k> {
    pub fn new(
        kernel: &'k SafetyKernel,
        ledger: PcoLedger,
        revocations: RevocationRegistry,
        authority_public_key: VerifyingKey,
    ) -> Self {
        Self {
            kernel,
            gate: ExecutionGate::new(kernel),
            ledger,
            revocations,
            authority_public_key,
        }
    }

    /// Access the underlying safety kernel.
    pub fn kernel(&self) -> &SafetyKernel {
        self.kernel
    }

    /// Access the revocation registry.
    pub fn revocations_mut(&mut self) -> &mut RevocationRegistry {
        &mut self.revocations
    }

    /// Access the PCO ledger.
    pub fn ledger(&self) -> &PcoLedger {
        &self.ledger
    }

    /// Complete PCO verification and execution pipeline.
    ///
    /// Evaluates:
    /// 1. BOUND(C, X)
    /// 2. Revocation status
    /// 3. Digital signature
    /// 4. Independent validator
    /// 5. Pre-action ledger commit
    /// 6. Gate execution
    #[allow(clippy::too_many_arguments)]
    pub fn execute_with_pco<V, F, B>(
        &mut self,
        pre_state: &SystemState,
        action: &ActionProposal,
        certificate: &VerificationCertificate,
        validator: &V,
        current_epoch: i64,
        certificate_ttl_seconds: i64,
        required_capability: Option<&str>,
        query: &[u8],
        execute_pure: F,
        build_post_state: B,
    ) -> Result<(CommitRecord, PcoPreActionRecord), PcoError>
    where
        V: IndependentValidator,
        F: FnOnce(&ActionProposal) -> Vec<u8>,
        B: FnOnce(&SystemState, &ActionProposal, &[u8]) -> SystemState,
    {
        // ── 1. BOUND(C, X) Check ───────────────────────────────────────────
        certificate.check_bound(pre_state)?;

        // ── 2. Dynamic Revocation Check ────────────────────────────────────
        self.revocations.check_not_revoked(&certificate.certificate_id)?;
        self.revocations.check_not_revoked(&certificate.state_id)?;

        // ── 3. Temporal Validity Check ─────────────────────────────────────
        certificate.check_temporal(current_epoch, certificate_ttl_seconds)?;

        // ── 4. Cryptographic Signature Verification ────────────────────────
        certificate.verify_signature(&self.authority_public_key)?;

        // Pure sandbox execution to generate candidate output bytes
        let candidate_output = execute_pure(action);

        // ── 5. Independent Out-of-Process Proof Validation ──────────────────
        let verdict = validator.validate(certificate, query, &candidate_output)?;
        match verdict {
            ValidationVerdict::Valid { details: _ } => {}
            ValidationVerdict::Invalid { reason } => {
                return Err(PcoError::VerificationFailed(reason));
            }
            ValidationVerdict::Unknown { reason } => {
                // Fail-closed: Unknown => FAIL
                return Err(PcoError::UnknownValidationStatus(reason));
            }
        }

        // ── 6. PRE-ACTION Ledger Commit ────────────────────────────────────
        // Before any external effect or state commit, record proof in append-only ledger
        let pco_record = self.ledger.commit_pre_action(certificate, query, &candidate_output)?;

        // ── 7. Gateway Pipeline Execution ──────────────────────────────────
        // With VER verified and pre-action committed, run the core gate
        let commit_record = self.gate.run(
            pre_state,
            action,
            VerificationStatus::Valid,
            current_epoch,
            required_capability,
            |_| candidate_output.clone(),
            build_post_state,
        ).map_err(|e| PcoError::VerificationFailed(e.to_string()))?;

        Ok((commit_record, pco_record))
    }
}
