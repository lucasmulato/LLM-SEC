//! R^3 Adoption Event Ledgering & SAC Evidence Storage (SSI Def 25).
//!
//! Adoption is itself a ledgered event emitting Safety Asset Class 1 (Control Integrity)
//! evidence. Any failed adoption quarantines the candidate and preserves the current system.

#![deny(clippy::float_arithmetic)]

use ssi_ledger::{AppendOnlyLedgerStore, SACEvidence, SafetyAssetClass};
use crate::adopt::CandidateRefinement;
use crate::error::R3Error;
use crate::partition::SystemPartition;

/// Ledger manager for R^3 governed adoption and quarantine audit logging.
pub struct R3Ledger {
    pub store: AppendOnlyLedgerStore,
    pub quarantine_log: Vec<QuarantineAuditRecord>,
}

/// Audit record for rejected/quarantined candidate refinements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuarantineAuditRecord {
    pub candidate_id: String,
    pub reason: String,
    pub proposed_at_epoch: i64,
    pub sequence_number: u64,
}

impl Default for R3Ledger {
    fn default() -> Self {
        Self::new()
    }
}

impl R3Ledger {
    pub fn new() -> Self {
        Self {
            store: AppendOnlyLedgerStore::in_memory(),
            quarantine_log: Vec::new(),
        }
    }

    /// Record a successful adoption event as a SAC-1 Control Integrity evidence record.
    pub fn record_adoption(
        &mut self,
        current: &SystemPartition,
        candidate: &CandidateRefinement,
        sequence_number: u64,
        parent_hash: &str,
    ) -> Result<String, R3Error> {
        let current_state = current.to_system_state(
            sequence_number,
            parent_hash,
            candidate.proposed_at_epoch,
        );
        let candidate_state = candidate.partition.to_system_state(
            sequence_number + 1,
            parent_hash,
            candidate.proposed_at_epoch,
        );

        let action = candidate_state.action.clone();
        let csl = candidate.partition.config.csl_envelope.clone();

        let gamma = format!(
            "R3_ADOPT[kernel={},model={},config={}]",
            candidate.partition.kernel.manifest_digest(),
            candidate.partition.model.model_id,
            candidate.partition.config.config_id
        );

        let evidence = self
            .store
            .append_transition(
                &current_state,
                &action,
                &candidate_state,
                &csl,
                &candidate.proof.proof_id,
                SafetyAssetClass::Sac1ControlIntegrity,
                &gamma,
                candidate.proposed_at_epoch * 1000,
            )
            .map_err(|e| R3Error::LedgerCommitFailed {
                reason: format!("Failed to record SAC evidence: {:?}", e),
            })?;

        Ok(evidence.record_hash.clone())
    }

    /// Record a failed candidate adoption into the quarantine log.
    pub fn record_quarantine(
        &mut self,
        candidate_id: &str,
        reason: &str,
        proposed_at_epoch: i64,
        sequence_number: u64,
    ) {
        self.quarantine_log.push(QuarantineAuditRecord {
            candidate_id: candidate_id.to_string(),
            reason: reason.to_string(),
            proposed_at_epoch,
            sequence_number,
        });
    }

    /// Retrieve all SAC evidence records.
    pub fn sac_records(&self) -> &[SACEvidence] {
        self.store.records()
    }

    /// Retrieve the last sealed record hash in the chain.
    pub fn last_record_hash(&self) -> &str {
        self.store.last_record_hash()
    }
}
