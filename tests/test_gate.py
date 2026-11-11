"""Unit tests for Safe Super Intelligence Axiomatic System v1.0 Execution Gate & Verification Engine."""

from __future__ import annotations

import time
import unittest
from typing import Any, Dict, Optional, Tuple

from core.kernel import (
    ActionState,
    ActionType,
    HumanAuthorization,
    IntelligenceState,
    KernelInvariantViolationError,
    KernelMode,
    NormativeValue,
    ProvenanceState,
    SafetyKernel,
    SafetyState,
    SystemState,
    VerificationState,
)
from core.gate import (
    DeterministicExecutionGate,
    ExecutionCommit,
    ExecutionQuarantineError,
    ExecutionResult,
    GateDecision,
    PermitDeniedError,
    PermitResult,
    TransitionInvariantViolationError,
    VerificationStatus,
    check_auth,
    check_cap,
    check_safe_action,
    check_ver,
    evaluate_permit,
    validate_transition,
)


def create_test_baseline(
    current_epoch: int = 1700000000,
    budget_raw: int = 100 * 10**18,     # 100
    cost_raw: int = 1 * 10**18,          # 1.0
    action_risk_raw: int = 1 * 10**17,  # 0.1
    risk_bound_raw: int = 5 * 10**17,   # 0.5
    user_clearance: int = 3,
    required_clearance: int = 2,
    capabilities=("MATH", "CONTAINED_INFERENCE"),
) -> Tuple[SystemState, ActionState]:
    """Helper to generate consistent pre-state and action pair."""
    i_state = IntelligenceState(
        model_id="ssi-sentinel-v1",
        weights_digest="a" * 64,
        context_window_size=128000,
        cognitive_budget=NormativeValue.from_raw(budget_raw),
        epistemic_confidence=NormativeValue.from_str("0.99"),
        entropy_bound=NormativeValue.from_str("0.05"),
        capabilities=frozenset(capabilities),
    )

    s_state = SafetyState(
        containment_active=True,
        containment_barrier_intact=True,
        safety_margin=NormativeValue.from_str("0.8"),
        risk_bound=NormativeValue.from_raw(risk_bound_raw),
        active_envelope_id="ENVELOPE-0",
        csl_constraints=frozenset({"NON_DECEPTION", "CONTAINMENT_INTEGRITY"}),
        quarantine_flag=False,
    )

    a_state = ActionState(
        action_id="compute_proof_matrix",
        action_type=ActionType.COMPUTE,
        risk_assessment=NormativeValue.from_raw(action_risk_raw),
        resource_cost=NormativeValue.from_raw(cost_raw),
        required_clearance=required_clearance,
        payload_digest="b" * 64,
        is_executed=False,
    )

    h_state = HumanAuthorization(
        auth_token="auth-token-123",
        granter_id="lead-safety-officer",
        clearance_level=user_clearance,
        is_active=True,
        expires_at_epoch=current_epoch + 3600,
        nonce="nonce-abc",
    )

    v_state = VerificationState(
        certificate_id="cert-sys-0",
        proof_system="Z3",
        proof_digest="c" * 64,
        invariants_verified=frozenset({"KI", "TV", "CSL", "AV", "SIV", "PV"}),
        verifier_identity="verifier-alpha",
        verified_at_epoch=current_epoch - 50,
        is_valid=True,
    )

    p_state = ProvenanceState(
        sequence_number=1,
        parent_state_hash="d" * 64,
        merkle_root="e" * 64,
        audit_trail_id="audit-trail-seg-0",
        timestamp_epoch_ms=current_epoch * 1000,
    )

    state = SystemState(
        I=i_state,
        S=s_state,
        A=a_state,
        H=h_state,
        V=v_state,
        P=p_state,
    )
    return state, a_state


def deterministic_state_builder(
    pre_state: SystemState,
    action: ActionState,
    result: ExecutionResult,
    verifier_sig: str,
) -> SystemState:
    """Helper post-state builder producing a valid Next(X, a, X') transition."""
    # Deduct cost deterministically
    new_budget = pre_state.I.cognitive_budget - action.resource_cost
    new_I = IntelligenceState(
        model_id=pre_state.I.model_id,
        weights_digest=pre_state.I.weights_digest,
        context_window_size=pre_state.I.context_window_size,
        cognitive_budget=new_budget,
        epistemic_confidence=pre_state.I.epistemic_confidence,
        entropy_bound=pre_state.I.entropy_bound,
        capabilities=pre_state.I.capabilities,
    )

    # Mark action executed
    new_A = ActionState(
        action_id=action.action_id,
        action_type=action.action_type,
        risk_assessment=action.risk_assessment,
        resource_cost=action.resource_cost,
        required_clearance=action.required_clearance,
        payload_digest=action.payload_digest,
        is_executed=True,
    )

    # Monotonic sequence + parent state linkage
    new_P = ProvenanceState(
        sequence_number=pre_state.P.sequence_number + 1,
        parent_state_hash=pre_state.compute_state_hash(),
        merkle_root="f" * 64,
        audit_trail_id=f"audit-seg-{pre_state.P.sequence_number + 1}",
        timestamp_epoch_ms=pre_state.P.timestamp_epoch_ms + 1000,
    )

    return SystemState(
        I=new_I,
        S=pre_state.S,
        A=new_A,
        H=pre_state.H,
        V=pre_state.V,
        P=new_P,
    )


class TestPermitLogic(unittest.TestCase):
    """Test Suite for PERMIT(X, a) Sub-predicates & Evaluation (Definition 11)."""

    def setUp(self):
        self.now = 1700000000
        self.state, self.action = create_test_baseline(current_epoch=self.now)

    def test_nominal_permit_evaluation_succeeds(self):
        res = evaluate_permit(
            self.state,
            self.action,
            required_capability="MATH",
            current_epoch=self.now
        )
        self.assertTrue(res.is_permitted)
        self.assertEqual(res.decision, GateDecision.PERMIT)
        self.assertTrue(res.auth_valid)
        self.assertTrue(res.safe_action_valid)
        self.assertTrue(res.ver_valid)
        self.assertTrue(res.cap_valid)
        self.assertEqual(len(res.failure_reasons), 0)

    def test_auth_subpredicate_failures(self):
        # Expired token
        res_expired = evaluate_permit(
            self.state,
            self.action,
            current_epoch=self.now + 7200  # 2 hours later
        )
        self.assertFalse(res_expired.is_permitted)
        self.assertFalse(res_expired.auth_valid)
        self.assertTrue(any("[AUTH]" in r for r in res_expired.failure_reasons))

        # Insufficient clearance
        state_low_clear, action_high_clear = create_test_baseline(
            current_epoch=self.now,
            user_clearance=1,
            required_clearance=3
        )
        res_clear = evaluate_permit(state_low_clear, action_high_clear, current_epoch=self.now)
        self.assertFalse(res_clear.is_permitted)
        self.assertFalse(res_clear.auth_valid)

    def test_safe_action_subpredicate_failures(self):
        # Risk exceeds risk bound
        state_low_bound, action_high_risk = create_test_baseline(
            current_epoch=self.now,
            action_risk_raw=8 * 10**17,
            risk_bound_raw=2 * 10**17,
        )
        res_risk = evaluate_permit(state_low_bound, action_high_risk, current_epoch=self.now)
        self.assertFalse(res_risk.is_permitted)
        self.assertFalse(res_risk.safe_action_valid)

        # Forbidden security keyword in action_id
        action_forbidden = ActionState(
            action_id="action_exfiltrate_keys",
            action_type=ActionType.COMMUNICATE,
            risk_assessment=NormativeValue.from_str("0.05"),
            resource_cost=NormativeValue.from_str("0.01"),
            required_clearance=1,
            payload_digest="b" * 64,
        )
        res_forbidden = evaluate_permit(self.state, action_forbidden, current_epoch=self.now)
        self.assertFalse(res_forbidden.is_permitted)
        self.assertFalse(res_forbidden.safe_action_valid)

    def test_cap_subpredicate_failures(self):
        # Insufficient cognitive budget
        state_broke, action_expensive = create_test_baseline(
            current_epoch=self.now,
            budget_raw=5 * 10**17,  # 0.5
            cost_raw=10 * 10**17,   # 1.0
        )
        res_budget = evaluate_permit(state_broke, action_expensive, current_epoch=self.now)
        self.assertFalse(res_budget.is_permitted)
        self.assertFalse(res_budget.cap_valid)

        # Missing capability
        res_cap = evaluate_permit(
            self.state,
            self.action,
            required_capability="HARDWARE_GPIO_CONTROL",
            current_epoch=self.now
        )
        self.assertFalse(res_cap.is_permitted)
        self.assertFalse(res_cap.cap_valid)


class TestFailClosedExecutionSemantics(unittest.TestCase):
    """Test Suite for Fail-Closed Execution (Axiom A2, Section 5, Axiom 4)."""

    def setUp(self):
        self.now = 1700000000
        self.kernel = SafetyKernel()
        self.gate = DeterministicExecutionGate(self.kernel)
        self.state, self.action = create_test_baseline(current_epoch=self.now)

    def test_unknown_verification_status_fails_closed(self):
        # Axiom 4: Unknown verification status MUST return REJECT
        res = evaluate_permit(
            self.state,
            self.action,
            verification_status=VerificationStatus.UNKNOWN,
            current_epoch=self.now
        )
        self.assertFalse(res.is_permitted)
        self.assertEqual(res.decision, GateDecision.REJECT)
        self.assertFalse(res.ver_valid)
        self.assertTrue(any("UNKNOWN" in r for r in res.failure_reasons))

    def test_axiom_a2_unpermitted_action_blocks_execution(self):
        # Axiom A2: NOT PERMIT => NOT EXECUTE
        handler_executed = False

        def spy_handler(act: ActionState) -> str:
            nonlocal handler_executed
            handler_executed = True
            return "EXPLOIT_OUTPUT"

        # Force permit denial with excessive clearance requirement
        unauthorized_action = ActionState(
            action_id="root_exec",
            action_type=ActionType.EXECUTE_CODE,
            risk_assessment=NormativeValue.from_str("0.1"),
            resource_cost=NormativeValue.from_str("0.1"),
            required_clearance=5,  # Human only has 3
            payload_digest="b" * 64,
        )

        with self.assertRaises(PermitDeniedError):
            self.gate.execute_and_commit(
                pre_state=self.state,
                action=unauthorized_action,
                execution_handler=spy_handler,
                state_builder=deterministic_state_builder,
                current_epoch=self.now
            )

        # Ensure execution handler was NEVER invoked
        self.assertFalse(handler_executed)


class TestMinimalVerificationKernelFlow(unittest.TestCase):
    """Test Suite for Reference Flow EXECUTE -> VERIFY -> TRANSITION CHECK -> COMMIT (Section 31)."""

    def setUp(self):
        self.now = 1700000000
        self.kernel = SafetyKernel()
        self.gate = DeterministicExecutionGate(self.kernel)
        self.state, self.action = create_test_baseline(current_epoch=self.now)

    def test_full_successful_execution_pipeline(self):
        def safe_handler(act: ActionState) -> Dict[str, Any]:
            return {"status": "SUCCESS", "records_processed": 42}

        commit = self.gate.execute_and_commit(
            pre_state=self.state,
            action=self.action,
            execution_handler=safe_handler,
            state_builder=deterministic_state_builder,
            required_capability="MATH",
            current_epoch=self.now
        )

        self.assertIsInstance(commit, ExecutionCommit)
        self.assertTrue(commit.result.success)
        self.assertEqual(commit.result.output["records_processed"], 42)
        self.assertEqual(commit.post_state.P.sequence_number, 2)
        self.assertEqual(commit.certificate.action_id, self.action.action_id)
        self.assertEqual(commit.certificate.pre_state_hash, self.state.compute_state_hash())
        self.assertEqual(commit.certificate.post_state_hash, commit.post_state.compute_state_hash())

    def test_handler_crash_triggers_emergency_quarantine(self):
        def crashing_handler(act: ActionState):
            raise RuntimeError("Segmentation fault or tool subprocess crash")

        with self.assertRaises(ExecutionQuarantineError):
            self.gate.execute_and_commit(
                pre_state=self.state,
                action=self.action,
                execution_handler=crashing_handler,
                state_builder=deterministic_state_builder,
                current_epoch=self.now
            )

        # Kernel must now be quarantined
        self.assertEqual(self.kernel.mode, KernelMode.QUARANTINED)


class TestTransitionSemanticsAndInvariantPreservation(unittest.TestCase):
    """Test Suite for State Transition Invariant Preservation (Theorem 3)."""

    def setUp(self):
        self.now = 1700000000
        self.kernel = SafetyKernel()
        self.state, self.action = create_test_baseline(current_epoch=self.now)

    def test_valid_transition_preserves_invariants(self):
        post_state = deterministic_state_builder(
            self.state,
            self.action,
            ExecutionResult(output="ok", output_digest="x" * 64, duration_ms=10, success=True),
            verifier_sig="sig-123"
        )
        is_valid = validate_transition(self.kernel, self.state, self.action, post_state, current_epoch=self.now)
        self.assertTrue(is_valid)

    def test_transition_rejects_non_monotonic_sequence(self):
        # Sequence number does not increment
        post_state = deterministic_state_builder(
            self.state,
            self.action,
            ExecutionResult(output="ok", output_digest="x" * 64, duration_ms=10, success=True),
            verifier_sig="sig-123"
        )
        bad_P = ProvenanceState(
            sequence_number=self.state.P.sequence_number,  # Same as pre-state!
            parent_state_hash=self.state.compute_state_hash(),
            merkle_root="f" * 64,
            audit_trail_id="audit-trail-bad",
            timestamp_epoch_ms=self.now * 1000,
        )
        bad_post_state = SystemState(
            I=post_state.I, S=post_state.S, A=post_state.A, H=post_state.H, V=post_state.V, P=bad_P
        )

        with self.assertRaises(TransitionInvariantViolationError):
            validate_transition(self.kernel, self.state, self.action, bad_post_state, current_epoch=self.now)

    def test_transition_rejects_lineage_break(self):
        # Parent state hash does not match pre-state hash
        post_state = deterministic_state_builder(
            self.state,
            self.action,
            ExecutionResult(output="ok", output_digest="x" * 64, duration_ms=10, success=True),
            verifier_sig="sig-123"
        )
        bad_P = ProvenanceState(
            sequence_number=post_state.P.sequence_number,
            parent_state_hash="0" * 64,  # Corrupted lineage
            merkle_root=post_state.P.merkle_root,
            audit_trail_id=post_state.P.audit_trail_id,
            timestamp_epoch_ms=post_state.P.timestamp_epoch_ms,
        )
        bad_post_state = SystemState(
            I=post_state.I, S=post_state.S, A=post_state.A, H=post_state.H, V=post_state.V, P=bad_P
        )

        with self.assertRaises(TransitionInvariantViolationError):
            validate_transition(self.kernel, self.state, self.action, bad_post_state, current_epoch=self.now)

    def test_transition_rejects_resource_budget_inflation(self):
        # Post-state cognitive budget is not properly deducted
        post_state = deterministic_state_builder(
            self.state,
            self.action,
            ExecutionResult(output="ok", output_digest="x" * 64, duration_ms=10, success=True),
            verifier_sig="sig-123"
        )
        bad_I = IntelligenceState(
            model_id=post_state.I.model_id,
            weights_digest=post_state.I.weights_digest,
            context_window_size=post_state.I.context_window_size,
            cognitive_budget=self.state.I.cognitive_budget,  # Did not deduct cost!
            epistemic_confidence=post_state.I.epistemic_confidence,
            entropy_bound=post_state.I.entropy_bound,
            capabilities=post_state.I.capabilities,
        )
        bad_post_state = SystemState(
            I=bad_I, S=post_state.S, A=post_state.A, H=post_state.H, V=post_state.V, P=post_state.P
        )

        with self.assertRaises(TransitionInvariantViolationError):
            validate_transition(self.kernel, self.state, self.action, bad_post_state, current_epoch=self.now)


if __name__ == "__main__":
    unittest.main()
