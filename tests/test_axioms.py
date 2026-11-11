"""Core Proof Obligations Test Harness: PO-1 through PO-9 (SSI Specification Section 34).

This test suite formally validates the nine foundational mathematical proof obligations:
- PO-1: Type Safety & Inhabitance (Section 34.1, Definition 3)
- PO-2: Arithmetic Safety & Bounded Determinism (Section 34.2, Axioms 1 & 2)
- PO-3: Kernel Immutability & Supremacy (Section 34.3, Definition 15, Axiom 9)
- PO-4: Permit Soundness & Non-Bypassing (Section 34.4, Definition 11, Axiom A2)
- PO-5: Authorization Continuity & Monotonic Revocation (Section 34.5, Axiom 10)
- PO-6: Safety Invariant Preservation (Section 34.6, Theorem 3, Definition 19)
- PO-7: Fail-Closed Quarantine on Indeterminate State (Section 34.7, Section 5, Axiom 4)
- PO-8: Cryptographic Lineage & Provenance Chain (Section 34.8, Definitions 13, 14, 29)
- PO-9: Deterministic Reproducibility & Audit Replay (Section 34.9)
"""

from __future__ import annotations

import hashlib
import time
import unittest
from typing import Any, Dict, FrozenSet, Tuple

from core.gate import (
    DeterministicExecutionGate,
    ExecutionCommit,
    ExecutionQuarantineError,
    ExecutionResult,
    FailClosedGuardrailGate,
    GateDecision,
    PermitDeniedError,
    TransitionInvariantViolationError,
    VerificationStatus,
    evaluate_permit,
    validate_transition,
)
from core.kernel import (
    ActionState,
    ActionType,
    AuthorizationValidityViolationError,
    CSLValidityViolationError,
    HumanAuthorization,
    IntelligenceState,
    KernelImmutabilityError,
    KernelIntegrityViolationError,
    KernelMode,
    MAX_WAD_INT,
    MIN_WAD_INT,
    NormativeValue,
    ProvenanceState,
    SafetyInvariantViolationError,
    SafetyKernel,
    SafetyState,
    SystemState,
    TypeValidityViolationError,
    VerificationState,
    WAD_SCALE,
    WadDivisionByZeroError,
    WadOverflowError,
    WadUnderflowError,
)
from core.ledger import (
    AppendOnlyLedgerStore,
    AuthorizationRevokedError,
    BoundVerificationCertificate,
    CSLEnvelope,
    OperatingEnvelope,
    SafetyAssetClass,
    TemporalValidity,
    assert_authorization_continuity,
    bind_verification_certificate,
    canonical_encode_state,
    compute_state_id,
    verify_authorization_continuity,
)


def build_axiom_state(
    sequence: int = 1,
    budget_raw: int = 100 * 10**18,
    cost_raw: int = 1 * 10**18,
    risk_raw: int = 1 * 10**17,
    risk_bound_raw: int = 3 * 10**17,
    safety_margin_raw: int = 8 * 10**17,
    clearance: int = 3,
    required_clearance: int = 2,
    quarantine: bool = False,
    current_epoch: int = 1700000000,
    parent_hash: str = "a" * 64,
) -> Tuple[SystemState, ActionState]:
    """Factory creating a mathematically sound SystemState and ActionState."""
    I = IntelligenceState(
        model_id="ssi-axiom-verifier",
        weights_digest="b" * 64,
        context_window_size=128000,
        cognitive_budget=NormativeValue.from_raw(budget_raw),
        epistemic_confidence=NormativeValue.from_str("0.995"),
        entropy_bound=NormativeValue.from_str("0.02"),
        capabilities=frozenset({"FORMAL_PROVER", "SAFE_DISPATCH"}),
    )
    S = SafetyState(
        containment_active=True,
        containment_barrier_intact=True,
        safety_margin=NormativeValue.from_raw(safety_margin_raw),
        risk_bound=NormativeValue.from_raw(risk_bound_raw),
        active_envelope_id="ENV-AXIOM-0",
        csl_constraints=frozenset({"NON_DECEPTION", "CONTAINMENT_INTEGRITY", "BUDGET_CEILING"}),
        quarantine_flag=quarantine,
    )
    A = ActionState(
        action_id="act-proof-dispatch",
        action_type=ActionType.COMPUTE,
        risk_assessment=NormativeValue.from_raw(risk_raw),
        resource_cost=NormativeValue.from_raw(cost_raw),
        required_clearance=required_clearance,
        payload_digest="c" * 64,
        is_executed=False,
    )
    H = HumanAuthorization(
        auth_token="auth-axiom-token",
        granter_id="lead-safety-architect",
        clearance_level=clearance,
        is_active=True,
        expires_at_epoch=current_epoch + 10000,
        nonce="nonce-axiom-777",
    )
    V = VerificationState(
        certificate_id="cert-axiom-init",
        proof_system="SSI_AXIOMATIC_V1",
        proof_digest="d" * 64,
        invariants_verified=frozenset({"KI", "TV", "CSL", "AV", "SIV", "PV"}),
        verifier_identity="formal-verifier-node-0",
        verified_at_epoch=current_epoch - 10,
        is_valid=True,
    )
    P = ProvenanceState(
        sequence_number=sequence,
        parent_state_hash=parent_hash,
        merkle_root="e" * 64,
        audit_trail_id="audit-trail-po-suite",
        timestamp_epoch_ms=current_epoch * 1000,
    )
    return SystemState(I=I, S=S, A=A, H=H, V=V, P=P), A


def build_axiom_csl(signing_key: str = "AXIOM_SIGNING_KEY") -> CSLEnvelope:
    """Factory creating an authenticated CSL envelope."""
    envelope = OperatingEnvelope(
        envelope_id="AXIOM-OPERATING-ENV",
        max_risk_bound=NormativeValue.from_str("0.4"),
        allowed_action_types=frozenset({ActionType.READ, ActionType.COMPUTE}),
        max_resource_cost_per_action=NormativeValue.from_str("5.0"),
        total_budget_limit=NormativeValue.from_int(1000),
    )
    validity = TemporalValidity(
        valid_from_epoch=1700000000,
        valid_until_epoch=1700050000,
        max_transitions=100,
    )
    return CSLEnvelope.create(
        auth_id="CSL-PO-SUITE-01",
        envelope=envelope,
        validity=validity,
        constraints=frozenset({"NON_DECEPTION", "CONTAINMENT_INTEGRITY", "BUDGET_CEILING"}),
        signing_key=signing_key,
    )


class TestProofObligations(unittest.TestCase):
    """Rigorous Formal Verification Suite for PO-1 through PO-9."""

    def setUp(self):
        self.epoch = 1700000000
        self.kernel = SafetyKernel()
        self.state, self.action = build_axiom_state(current_epoch=self.epoch)
        self.csl = build_axiom_csl()

    # ==========================================================================
    # PO-1: TYPE SAFETY & INHABITANCE (Section 34.1, Definition 3)
    # ==========================================================================
    def test_po1_type_safety_and_inhabitance(self):
        """PO-1: Every state component must be well-formed, correctly typed, and bounded."""
        self.assertIsInstance(self.state, SystemState)
        self.assertEqual(len(self.state.as_tuple()), 6)

        # Inhabitance & bounds verification
        self.assertGreaterEqual(self.state.I.cognitive_budget.raw, 0)
        self.assertLessEqual(self.state.I.epistemic_confidence.raw, WAD_SCALE)

        # Rejection of malformed subcomponents
        with self.assertRaises(TypeError):
            _ = SystemState(
                I="MALFORMED_I",  # type: ignore
                S=self.state.S,
                A=self.state.A,
                H=self.state.H,
                V=self.state.V,
                P=self.state.P,
            )

    # ==========================================================================
    # PO-2: ARITHMETIC SAFETY & BOUNDED DETERMINISM (Section 34.2, Axioms 1 & 2)
    # ==========================================================================
    def test_po2_arithmetic_safety_and_bounded_determinism(self):
        """PO-2: WAD-18 numerical operations must be exact, integer-scaled, and fail-closed."""
        # 1. Exact scale
        one = NormativeValue.one()
        self.assertEqual(one.raw, 10**18)

        # 2. Checked operations with symmetric half-up rounding
        a = NormativeValue.from_str("1.5")
        b = NormativeValue.from_str("2.0")
        self.assertEqual(a * b, NormativeValue.from_str("3.0"))
        self.assertEqual(a / b, NormativeValue.from_str("0.75"))

        # 3. Explicit Division by Zero check
        with self.assertRaises(WadDivisionByZeroError):
            _ = a / NormativeValue.zero()

        # 4. Explicit Overflow check
        with self.assertRaises(WadOverflowError):
            _ = NormativeValue(MAX_WAD_INT + 1)

        # 5. Explicit Underflow check
        with self.assertRaises(WadUnderflowError):
            _ = NormativeValue(MIN_WAD_INT - 1)

    # ==========================================================================
    # PO-3: KERNEL IMMUTABILITY & SUPREMACY (Section 34.3, Axiom 9)
    # ==========================================================================
    def test_po3_kernel_immutability_and_supremacy(self):
        """PO-3: SafetyKernel rules and attributes cannot be mutated or bypassed dynamically."""
        # Mutation attempt must raise KernelImmutabilityError
        with self.assertRaises(KernelImmutabilityError):
            self.kernel.tampered_attribute = "exploit_payload"  # type: ignore

        with self.assertRaises(KernelImmutabilityError):
            del self.kernel._mode  # type: ignore

        # Kernel integrity self-verification
        integrity = self.kernel.verify_kernel_integrity()
        self.assertTrue(integrity.satisfied)

    # ==========================================================================
    # PO-4: PERMIT SOUNDNESS & NON-BYPASSING (Section 34.4, Axiom A2)
    # ==========================================================================
    def test_po4_permit_soundness_and_non_bypassing(self):
        """PO-4: Execution cannot occur without a valid permit: NOT PERMIT => NOT EXECUTE."""
        gate = DeterministicExecutionGate(self.kernel)
        handler_executed = False

        def spy_handler(a: ActionState) -> str:
            nonlocal handler_executed
            handler_executed = True
            return "EXECUTED"

        # Construct an action that fails SAFE_ACTION (risk > bound)
        unpermitted_action = ActionState(
            action_id="act-unsafe-risk",
            action_type=ActionType.COMPUTE,
            risk_assessment=NormativeValue.from_str("0.9"),  # Risk exceeds bound 0.3
            resource_cost=NormativeValue.from_str("0.01"),
            required_clearance=1,
            payload_digest="f" * 64,
        )

        with self.assertRaises(PermitDeniedError):
            gate.execute_and_commit(
                pre_state=self.state,
                action=unpermitted_action,
                execution_handler=spy_handler,
                state_builder=FailClosedGuardrailGate.default_state_builder,
                current_epoch=self.epoch,
            )

        self.assertFalse(handler_executed, "Axiom A2 Violated: Unpermitted action was executed!")

    # ==========================================================================
    # PO-5: AUTHORIZATION CONTINUITY & MONOTONIC REVOCATION (Section 34.5, Axiom 10)
    # ==========================================================================
    def test_po5_authorization_continuity_and_revocation(self):
        """PO-5: Execution remains authorized only within envelope E and window T."""
        # Valid state inside envelope
        eval_ok = verify_authorization_continuity(
            csl=self.csl,
            state=self.state,
            proposed_action=self.action,
            current_epoch=self.epoch,
            signing_key="AXIOM_SIGNING_KEY",
        )
        self.assertTrue(eval_ok.is_authorized)

        # Exceeding temporal window triggers revocation
        expired_epoch = self.epoch + 60000  # Past valid_until_epoch
        with self.assertRaises(AuthorizationRevokedError):
            assert_authorization_continuity(
                csl=self.csl,
                state=self.state,
                proposed_action=self.action,
                current_epoch=expired_epoch,
            )

        # Exceeding permitted action type triggers revocation
        unauthorized_action = ActionState(
            action_id="act-mutate",
            action_type=ActionType.MUTATE_ENVIRONMENT,  # Not in {READ, COMPUTE}
            risk_assessment=NormativeValue.from_str("0.01"),
            resource_cost=NormativeValue.from_str("0.01"),
            required_clearance=1,
            payload_digest="0" * 64,
        )
        with self.assertRaises(AuthorizationRevokedError):
            assert_authorization_continuity(
                csl=self.csl,
                state=self.state,
                proposed_action=unauthorized_action,
                current_epoch=self.epoch,
            )

    # ==========================================================================
    # PO-6: SAFETY INVARIANT PRESERVATION (Section 34.6, Theorem 3)
    # ==========================================================================
    def test_po6_safety_invariant_preservation(self):
        """PO-6: State transition Next(X, a, X') strictly preserves Global Invariant I(X')."""
        # Pre-state satisfies I(X)
        self.assertTrue(self.kernel.verify_global_invariant(self.state, current_epoch=self.epoch))

        # Build candidate Next(X, a, X')
        result = ExecutionResult(output={"matrix": 1}, output_digest="9" * 64, duration_ms=5, success=True)
        post_state = FailClosedGuardrailGate.default_state_builder(
            self.state,
            self.action,
            result,
            verifier_sig="sig-po6-valid"
        )

        # Verify transition preservation
        self.assertTrue(validate_transition(self.kernel, self.state, self.action, post_state, current_epoch=self.epoch))
        # Post-state satisfies I(X')
        self.assertTrue(self.kernel.verify_global_invariant(post_state, current_epoch=self.epoch))

    # ==========================================================================
    # PO-7: FAIL-CLOSED QUARANTINE ON INDETERMINATE STATE (Section 34.7, Axiom 4)
    # ==========================================================================
    def test_po7_fail_closed_quarantine_on_indeterminate_state(self):
        """PO-7: Indeterminate verification status UNKNOWN or crash trips into QUARANTINED mode."""
        # 1. Verification UNKNOWN forces REJECT
        res = evaluate_permit(
            self.state,
            self.action,
            verification_status=VerificationStatus.UNKNOWN,
            current_epoch=self.epoch,
        )
        self.assertEqual(res.decision, GateDecision.REJECT)
        self.assertFalse(res.ver_valid)

        # 2. Execution handler crash trips kernel into QUARANTINED
        gate = DeterministicExecutionGate(self.kernel)

        def crashing_handler(act: ActionState):
            raise ArithmeticError("Subprocess computation fault")

        with self.assertRaises(ExecutionQuarantineError):
            gate.execute_and_commit(
                pre_state=self.state,
                action=self.action,
                execution_handler=crashing_handler,
                state_builder=FailClosedGuardrailGate.default_state_builder,
                current_epoch=self.epoch,
            )

        self.assertEqual(self.kernel.mode, KernelMode.QUARANTINED)

    # ==========================================================================
    # PO-8: CRYPTOGRAPHIC LINEAGE & PROVENANCE CHAIN (Section 34.8, Defs 13, 14, 29)
    # ==========================================================================
    def test_po8_cryptographic_lineage_and_provenance(self):
        """PO-8: State ID = H(ENC(X)) and append-only ledger forms an unbroken cryptographic chain."""
        state_id = compute_state_id(self.state)
        self.assertEqual(len(state_id), 64)

        # Bind verification certificate to exact state ID
        cert = bind_verification_certificate(
            state=self.state,
            verifier_identity="verifier-po8",
            verifier_secret="SECRET_ROOT_8",
            timestamp_epoch=self.epoch,
        )
        self.assertEqual(cert.state_id, state_id)
        self.assertTrue(cert.verify_signature("SECRET_ROOT_8"))

        # Ledger append and rolling hash verification
        store = AppendOnlyLedgerStore()
        post_state, _ = build_axiom_state(sequence=2, parent_hash=state_id, current_epoch=self.epoch)
        evidence = store.append_transition(
            pre_state=self.state,
            action=self.action,
            post_state=post_state,
            csl=self.csl,
            cert=cert,
            sac_class=SafetyAssetClass.SAC_3_FORMAL_PROVENANCE,
        )
        self.assertEqual(evidence.parent_state_id, state_id)
        is_valid, count, err = store.verify_ledger_integrity()
        self.assertTrue(is_valid)
        self.assertEqual(count, 1)
        self.assertIsNone(err)

    # ==========================================================================
    # PO-9: DETERMINISTIC REPRODUCIBILITY & AUDIT REPLAY (Section 34.9)
    # ==========================================================================
    def test_po9_deterministic_reproducibility_and_replay(self):
        """PO-9: Replaying identical states and actions yields identical canonical hashes and evidence."""
        # Run 1
        enc1 = canonical_encode_state(self.state)
        id1 = compute_state_id(self.state)

        # Run 2 (reconstructed independently)
        state_clone, action_clone = build_axiom_state(current_epoch=self.epoch)
        enc2 = canonical_encode_state(state_clone)
        id2 = compute_state_id(state_clone)

        self.assertEqual(enc1, enc2)
        self.assertEqual(id1, id2)

        # Replay execution through gate produces identical transition digests
        gate = FailClosedGuardrailGate()
        commit1 = gate.execute(
            pre_state=self.state,
            action=self.action,
            execution_handler=lambda a: {"proof_verified": True},
            current_epoch=self.epoch,
        )
        commit2 = gate.execute(
            pre_state=state_clone,
            action=action_clone,
            execution_handler=lambda a: {"proof_verified": True},
            current_epoch=self.epoch,
        )

        self.assertEqual(commit1.result.output_digest, commit2.result.output_digest)
        self.assertEqual(commit1.certificate.payload_digest, commit2.certificate.payload_digest)


if __name__ == "__main__":
    unittest.main()
