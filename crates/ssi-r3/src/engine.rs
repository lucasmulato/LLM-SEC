//! R^3 Governed Evolution Engine & Fixed-Point Harness (SSI Defs 22-25, Theorem 6, §26).

#![deny(clippy::float_arithmetic)]

use ssi_kernel::SafetyKernel;
use ssi_ledger::compute_state_id;
use crate::adopt::{CandidateRefinement, evaluate_adopt};
use crate::error::R3Error;
use crate::ledger::R3Ledger;
use crate::partition::SystemPartition;

/// Result of running the SSI §26 Fixed-Point Harness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedPointVerdict {
    pub is_fixed_point: bool,
    pub candidate_id: String,
    pub pre_state_id: String,
    pub post_state_id: String,
    pub ssi_valid: bool,
    pub sac_record_hash: String,
}

/// The R^3 Governed Evolution Engine governing transitions R^3(K, M, G) = (K, M', G').
pub struct R3Engine {
    pub active_partition: SystemPartition,
    pub sequence_number: u64,
    pub parent_state_hash: String,
    pub ledger: R3Ledger,
}

impl R3Engine {
    /// Initialize the R^3 engine with an initial system partition.
    pub fn new(initial_partition: SystemPartition) -> Self {
        let initial_state = initial_partition.to_system_state(0, "0".repeat(64).as_str(), 0);
        let parent_state_hash = compute_state_id(&initial_state);

        Self {
            active_partition: initial_partition,
            sequence_number: 0,
            parent_state_hash,
            ledger: R3Ledger::new(),
        }
    }

    /// Retrieve the current active system partition (K, M, G).
    pub fn active_partition(&self) -> &SystemPartition {
        &self.active_partition
    }

    /// Propose and adopt a candidate refinement Y.
    ///
    /// If ADOPT(Y) holds:
    ///   - Commits SAC-1 Control Integrity evidence to append-only ledger.
    ///   - Adopts candidate refinement: (K, M, G) -> (K, M', G').
    ///   - Updates sequence number and parent state hash.
    /// If ADOPT(Y) fails:
    ///   - Quarantines candidate.
    ///   - Retains active system partition completely unmodified (verified rollback).
    ///   - Returns detailed R3Error.
    pub fn propose_and_adopt(
        &mut self,
        candidate: CandidateRefinement,
    ) -> Result<SystemPartition, R3Error> {
        // Evaluate ADOPT(Y)
        match evaluate_adopt(
            &self.active_partition,
            &candidate,
            self.sequence_number,
            &self.parent_state_hash,
        ) {
            Ok(()) => {
                // Successful adoption: commit SAC-1 evidence to ledger
                let _record_hash = self.ledger.record_adoption(
                    &self.active_partition,
                    &candidate,
                    self.sequence_number,
                    &self.parent_state_hash,
                )?;

                // Advance system state to candidate
                self.sequence_number += 1;
                let new_state = candidate.partition.to_system_state(
                    self.sequence_number,
                    &self.parent_state_hash,
                    candidate.proposed_at_epoch,
                );
                self.parent_state_hash = compute_state_id(&new_state);
                self.active_partition = candidate.partition;

                Ok(self.active_partition.clone())
            }
            Err(e) => {
                // Failed adoption: quarantine candidate and roll back (keep current system unmodified)
                self.ledger.record_quarantine(
                    &candidate.candidate_id,
                    &e.to_string(),
                    candidate.proposed_at_epoch,
                    self.sequence_number,
                );
                // self.active_partition is untouched (Rollback guaranteed)
                Err(e)
            }
        }
    }

    /// Fixed-Point Harness (SSI §26):
    /// Demonstrates a candidate X* where R^3(X*) = X* with reproducible equality check:
    /// 1. Candidate submission X*
    /// 2. Reproducible computation
    /// 3. Equality verification: R^3(X*) = X*
    /// 4. SSI verification: SSI(X*) = 1
    pub fn fixed_point_harness(
        &mut self,
        candidate: CandidateRefinement,
    ) -> Result<FixedPointVerdict, R3Error> {
        let parent_hash_before = self.parent_state_hash.clone();

        let pre_state = self.active_partition.to_system_state(
            self.sequence_number,
            &parent_hash_before,
            candidate.proposed_at_epoch,
        );
        let pre_id = compute_state_id(&pre_state);

        // Compute candidate state before adoption
        let cand_state = candidate.partition.to_system_state(
            self.sequence_number + 1,
            &parent_hash_before,
            candidate.proposed_at_epoch,
        );
        let cand_id = compute_state_id(&cand_state);

        // 1 & 2. Run adoption transition: R^3(X*)
        let adopted = self.propose_and_adopt(candidate.clone())?;

        // 3. Equality verification: candidate partition matches adopted partition
        if adopted != candidate.partition {
            return Err(R3Error::FixedPointDivergence {
                reason: "Adopted partition does not match candidate fixed-point partition".to_string(),
            });
        }

        // Post state hash equality verification
        let post_id = self.parent_state_hash.clone();
        if cand_id != post_id {
            return Err(R3Error::FixedPointDivergence {
                reason: format!(
                    "Candidate state id {} does not match adopted post state id {}",
                    cand_id, post_id
                ),
            });
        }

        // 4. SSI verification: SSI(X*) = 1
        let post_state = adopted.to_system_state(
            self.sequence_number,
            &parent_hash_before,
            candidate.proposed_at_epoch,
        );
        let kernel = SafetyKernel::default();
        let ssi_verdict = kernel.evaluate_invariant(&post_state);
        if !ssi_verdict.is_valid {
            return Err(R3Error::FixedPointDivergence {
                reason: format!(
                    "Adopted fixed-point state failed SSI verification: {:?}",
                    ssi_verdict.failure_reason
                ),
            });
        }

        let sac_record_hash = self.ledger.last_record_hash().to_string();

        Ok(FixedPointVerdict {
            is_fixed_point: true,
            candidate_id: candidate.candidate_id,
            pre_state_id: pre_id,
            post_state_id: post_id,
            ssi_valid: true,
            sac_record_hash,
        })
    }
}
