//! Real-Estate Underwriting Pipeline: CSL -> PERMIT -> PCO -> Ledger -> COMMIT.

#![deny(clippy::float_arithmetic)]

use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use ssi_csl::CSLEnvelope;
use ssi_gate::{GateDecision, VerificationStatus, evaluate_permit};
use ssi_kernel::{
    ActionProposal, ActionType, AuthorizationState, IntelligenceState, ProvenanceState,
    SafetyState, SystemState, VerificationState,
};
use ssi_ledger::{AppendOnlyLedgerStore, SafetyAssetClass, compute_state_id};
use ssi_pco::{IndependentValidator, PcoLedger, VerificationCertificate};
use wad18::Wad18;
use crate::error::RealEstateError;
use crate::invariants::verify_real_estate_invariants;
use crate::types::{DualHumanApproval, LoanApplication};

/// Final result of a completed commercial loan underwriting pipeline evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnderwritingPipelineOutcome {
    pub is_approved: bool,
    pub application_id: String,
    pub loan_amount_wad: i128,
    pub ltv_wad: i128,
    pub dscr_wad: i128,
    pub sac_record_hash: String,
    pub post_state_id: String,
    pub audit_trail_id: String,
}

/// The high-assurance real-estate underwriting gateway.
pub struct RealEstateUnderwritingGateway {
    pub ledger_store: AppendOnlyLedgerStore,
    pub pco_ledger: PcoLedger,
    pub sequence_number: u64,
    pub parent_state_hash: String,
}

impl Default for RealEstateUnderwritingGateway {
    fn default() -> Self {
        Self::new()
    }
}

impl RealEstateUnderwritingGateway {
    pub fn new() -> Self {
        Self {
            ledger_store: AppendOnlyLedgerStore::in_memory(),
            pco_ledger: PcoLedger::in_memory(),
            sequence_number: 0,
            parent_state_hash: "0".repeat(64),
        }
    }

    /// Evaluates a candidate loan application proposal through the full 5-stage gating pipeline:
    /// CSL Verification -> Invariant Evaluation -> PCO Independent Validation -> Pre-Action Ledger Commit -> Gate Commit.
    pub fn evaluate_loan_proposal(
        &mut self,
        app: &LoanApplication,
        dual_approval: Option<&DualHumanApproval>,
        csl: &CSLEnvelope,
        human_underwriter_pubkey: &[u8; 32],
        pco_cert: &VerificationCertificate,
        validator: &dyn IndependentValidator,
        current_epoch: i64,
    ) -> Result<UnderwritingPipelineOutcome, RealEstateError> {
        // 1. CSL Verification: check underwriter signature, temporal window, and transition limits
        let vk = VerifyingKey::from_bytes(human_underwriter_pubkey).map_err(|e| {
            RealEstateError::CslEnvelopeViolation {
                reason: format!("Invalid human authorizer verifying key: {:?}", e),
            }
        })?;
        csl.verify_signature(&vk).map_err(|e| {
            RealEstateError::CslEnvelopeViolation {
                reason: format!("CSL envelope signature invalid: {:?}", e),
            }
        })?;

        if !csl.validity.is_valid_epoch(current_epoch) {
            return Err(RealEstateError::CslEnvelopeViolation {
                reason: format!(
                    "CSL envelope expired: current epoch {} outside window [{}, {}]",
                    current_epoch, csl.validity.valid_from_epoch, csl.validity.valid_until_epoch
                ),
            });
        }

        if !csl.validity.is_valid_sequence(self.sequence_number) {
            return Err(RealEstateError::CslEnvelopeViolation {
                reason: format!(
                    "CSL envelope sequence depth exceeded: seq {} > max {}",
                    self.sequence_number, csl.validity.max_transitions
                ),
            });
        }

        // 2. Real-Estate Invariant Evaluation: Φ_RE
        verify_real_estate_invariants(app, dual_approval)?;

        // 3. Construct System State X representing the underwriting system
        let pre_state = self.build_system_state(app, csl, current_epoch);
        let pre_id = compute_state_id(&pre_state);

        // 4. Exact State Binding BOUND(C, X)
        pco_cert.check_bound(&pre_state).map_err(|e| {
            RealEstateError::PcoValidationFailed {
                reason: format!("PCO BOUND(C, X) violation: {:?}", e),
            }
        })?;

        // 5. Independent Out-of-Process Proof Validation
        let query_bytes = app.payload_digest().into_bytes();
        let output_bytes = format!("RE_OUTPUT:{}", app.application_id).into_bytes();

        let verdict = validator
            .validate(pco_cert, &query_bytes, &output_bytes)
            .map_err(|e| RealEstateError::PcoValidationFailed {
                reason: format!("Independent validator crash/error: {:?}", e),
            })?;

        if !verdict.is_valid() {
            return Err(RealEstateError::PcoValidationFailed {
                reason: format!(
                    "Independent validator returned invalid/unknown verdict: {:?}",
                    verdict
                ),
            });
        }

        // 6. PRE-ACTION Ledger Commit: seal pre-action commitment before external effects
        self.pco_ledger
            .commit_pre_action(pco_cert, &query_bytes, &output_bytes)
            .map_err(|e| RealEstateError::LedgerCommitFailed {
                reason: format!("Pre-action ledger commit failed: {:?}", e),
            })?;

        // 7. Core PERMIT Evaluation: AUTH ∧ SAFE_ACTION ∧ VER ∧ CAP
        let action_proposal = pre_state.action.clone();
        let permit_result = evaluate_permit(
            &pre_state,
            &action_proposal,
            VerificationStatus::Valid,
            current_epoch,
            Some("commercial_underwriting"),
        );

        if permit_result.decision != GateDecision::Permit {
            return Err(RealEstateError::CslEnvelopeViolation {
                reason: format!("Gate PERMIT denied: {:?}", permit_result.detail.reasons),
            });
        }

        // 8. Commit post-state and append SAC-1 / SAC-3 evidence to ledger
        self.sequence_number += 1;
        let post_state = self.build_post_state(app, csl, current_epoch, &pre_id);
        let post_id = compute_state_id(&post_state);

        let gamma = format!(
            "RE_UNDERWRITING[app={},prop={},loan_wad={},ltv_wad={}]",
            app.application_id,
            app.property_id,
            app.requested_loan_wad.raw(),
            app.compute_ltv()?.raw()
        );

        let sac_evidence = self
            .ledger_store
            .append_transition(
                &pre_state,
                &action_proposal,
                &post_state,
                csl,
                &pco_cert.certificate_id,
                SafetyAssetClass::Sac3FormalProvenance,
                &gamma,
                current_epoch * 1000,
            )
            .map_err(|e| RealEstateError::LedgerCommitFailed {
                reason: format!("Failed to append transition to ledger store: {:?}", e),
            })?;

        self.parent_state_hash = post_id.clone();

        Ok(UnderwritingPipelineOutcome {
            is_approved: true,
            application_id: app.application_id.clone(),
            loan_amount_wad: app.requested_loan_wad.raw(),
            ltv_wad: app.compute_ltv()?.raw(),
            dscr_wad: app.compute_dscr()?.raw(),
            sac_record_hash: sac_evidence.record_hash.clone(),
            post_state_id: post_id,
            audit_trail_id: post_state.provenance.audit_trail_id,
        })
    }

    pub fn build_system_state(
        &self,
        app: &LoanApplication,
        csl: &CSLEnvelope,
        current_epoch: i64,
    ) -> SystemState {
        let mut caps = std::collections::BTreeSet::new();
        caps.insert("commercial_underwriting".to_string());
        caps.insert("financial_computation".to_string());

        let intelligence = IntelligenceState {
            model_id: "narrow-superintelligence-re-v1".to_string(),
            weights_digest: "1".repeat(64),
            context_window_size: 65536,
            cognitive_budget: Wad18::from_raw(1_000_000_000_000_000_000), // 1.0
            epistemic_confidence: Wad18::from_raw(980_000_000_000_000_000), // 0.98
            entropy_bound: Wad18::from_raw(50_000_000_000_000_000),       // 0.05
            capabilities: caps,
        };

        let safety = SafetyState {
            containment_active: true,
            containment_barrier_intact: true,
            safety_margin: Wad18::from_raw(200_000_000_000_000_000), // 0.20
            risk_bound: csl.envelope.max_risk_bound,
            active_envelope_id: csl.envelope.envelope_id.clone(),
            csl_constraints: csl.constraints.clone(),
            quarantine_flag: false,
        };

        let action = ActionProposal {
            action_id: format!("loan-action-{}", app.application_id),
            action_type: ActionType::Compute,
            risk_assessment: Wad18::from_raw(10_000_000_000_000_000), // 0.01
            resource_cost: Wad18::from_raw(5_000_000_000_000_000),    // 0.005
            required_clearance: 1,
            payload_digest: app.payload_digest(),
            is_executed: true,
        };

        let authorization = AuthorizationState {
            auth_token: csl.auth_id.clone(),
            granter_id: "human-underwriter-auth".to_string(),
            clearance_level: 2,
            is_active: true,
            expires_at_epoch: csl.validity.valid_until_epoch,
            nonce: format!("re-nonce-{}", self.sequence_number),
        };

        let verification = VerificationState {
            certificate_id: format!("cert-re-{}", app.application_id),
            proof_system: "WAD18-LTV-DSCR-Verifier".to_string(),
            proof_digest: hex::encode(Sha256::digest(b"WAD18_FINANCIAL_INVARIANTS_PROOF")),
            invariants_verified: csl.constraints.clone(),
            verifier_identity: "independent-re-validator-v1".to_string(),
            verified_at_epoch: current_epoch,
            is_valid: true,
        };

        let merkle_root = hex::encode(Sha256::digest(
            format!("{}:{}", self.sequence_number, self.parent_state_hash).as_bytes(),
        ));

        let provenance = ProvenanceState {
            sequence_number: self.sequence_number,
            parent_state_hash: self.parent_state_hash.clone(),
            merkle_root,
            audit_trail_id: format!("re-audit-{}", app.application_id),
            timestamp_epoch_ms: current_epoch * 1000,
        };

        SystemState {
            intelligence,
            safety,
            action,
            authorization,
            verification,
            provenance,
        }
    }

    fn build_post_state(
        &self,
        app: &LoanApplication,
        csl: &CSLEnvelope,
        current_epoch: i64,
        parent_id: &str,
    ) -> SystemState {
        let mut pre = self.build_system_state(app, csl, current_epoch);
        pre.provenance.sequence_number = self.sequence_number;
        pre.provenance.parent_state_hash = parent_id.to_string();
        pre.provenance.merkle_root = hex::encode(Sha256::digest(
            format!("{}:{}", self.sequence_number, parent_id).as_bytes(),
        ));
        pre
    }
}
