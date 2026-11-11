"""Unit tests for Safe Super Intelligence Axiomatic System v1.0 Core Kernel."""

import time
import unittest
from core.kernel import (
    ActionState,
    ActionType,
    AuthorizationValidityViolationError,
    CSLValidityViolationError,
    GlobalInvariantVerdict,
    HumanAuthorization,
    IntelligenceState,
    InvariantClauseResult,
    KernelImmutabilityError,
    KernelIntegrityViolationError,
    KernelInvariantViolationError,
    KernelMode,
    MAX_WAD_INT,
    MIN_WAD_INT,
    NormativeValue,
    ProvenanceState,
    ProvenanceValidityViolationError,
    SafetyInvariantViolationError,
    SafetyKernel,
    SafetyState,
    SystemState,
    TypeValidityViolationError,
    VerificationState,
    WAD_SCALE,
    WadArithmeticError,
    WadDivisionByZeroError,
    WadOverflowError,
    WadUnderflowError,
)


def create_valid_system_state(
    current_epoch: int = 1700000000,
    action_risk_raw: int = 10**17,      # 0.1
    risk_bound_raw: int = 2 * 10**17,    # 0.2
    safety_margin_raw: int = 5 * 10**17, # 0.5
    user_clearance: int = 3,
    required_clearance: int = 2,
    quarantine: bool = False,
    barrier_intact: bool = True,
    auth_active: bool = True,
    auth_expires: int = 1800000000,
    proof_valid: bool = True,
    sequence: int = 1,
    parent_hash: str = "a" * 64,
) -> SystemState:
    """Helper factory to produce a valid baseline SystemState."""
    i_state = IntelligenceState(
        model_id="ssi-sentinel-v1",
        weights_digest="b" * 64,
        context_window_size=128000,
        cognitive_budget=NormativeValue.from_int(100),
        epistemic_confidence=NormativeValue.from_str("0.985"),
        entropy_bound=NormativeValue.from_str("0.05"),
        capabilities=frozenset({"FORMAL_REASONING", "CONTAINED_INFERENCE"}),
    )

    s_state = SafetyState(
        containment_active=True,
        containment_barrier_intact=barrier_intact,
        safety_margin=NormativeValue.from_raw(safety_margin_raw),
        risk_bound=NormativeValue.from_raw(risk_bound_raw),
        active_envelope_id="ENVELOPE-OMEGA-0",
        csl_constraints=frozenset({"NON_DECEPTION", "RESOURCE_CEILING", "CONTAINMENT_INTEGRITY"}),
        quarantine_flag=quarantine,
    )

    a_state = ActionState(
        action_id="act-001",
        action_type=ActionType.COMPUTE,
        risk_assessment=NormativeValue.from_raw(action_risk_raw),
        resource_cost=NormativeValue.from_str("0.01"),
        required_clearance=required_clearance,
        payload_digest="c" * 64,
        is_executed=False,
    )

    h_state = HumanAuthorization(
        auth_token="sec-auth-token-xyz",
        granter_id="lead-safety-officer-01",
        clearance_level=user_clearance,
        is_active=auth_active,
        expires_at_epoch=auth_expires,
        nonce="nonce-98765",
    )

    v_state = VerificationState(
        certificate_id="cert-formal-proof-42",
        proof_system="Z3_SMT_FORMAL_PROVER",
        proof_digest="d" * 64,
        invariants_verified=frozenset({"KI", "TV", "CSL", "AV", "SIV", "PV"}),
        verifier_identity="verifier-node-alpha",
        verified_at_epoch=current_epoch - 100,
        is_valid=proof_valid,
    )

    p_state = ProvenanceState(
        sequence_number=sequence,
        parent_state_hash=parent_hash,
        merkle_root="e" * 64,
        audit_trail_id="audit-trail-segment-12345",
        timestamp_epoch_ms=current_epoch * 1000,
    )

    return SystemState(
        I=i_state,
        S=s_state,
        A=a_state,
        H=h_state,
        V=v_state,
        P=p_state,
    )


class TestWad18Arithmetic(unittest.TestCase):
    """Test Suite for WAD-18 Fixed-Point Deterministic Arithmetic (Axioms 1 & 2)."""

    def test_basic_instantiation_and_properties(self):
        v = NormativeValue.from_int(5)
        self.assertEqual(v.raw, 5 * 10**18)
        self.assertEqual(v.to_int(), 5)
        self.assertEqual(v.to_float(), 5.0)
        self.assertEqual(v.to_decimal_str(), "5.000000000000000000")

    def test_decimal_string_parsing(self):
        v = NormativeValue.from_str("12.345")
        self.assertEqual(v.raw, 12345000000000000000)
        self.assertEqual(v.to_decimal_str(3), "12.345")

        v_neg = NormativeValue.from_str("-0.000000000000000001")
        self.assertEqual(v_neg.raw, -1)
        self.assertEqual(v_neg.to_decimal_str(), "-0.000000000000000001")

    def test_fractions(self):
        v = NormativeValue.from_fraction(1, 2)
        self.assertEqual(v.raw, 5 * 10**17)
        self.assertEqual(v.to_decimal_str(1), "0.5")

        with self.assertRaises(WadDivisionByZeroError):
            NormativeValue.from_fraction(1, 0)

    def test_addition_and_subtraction(self):
        a = NormativeValue.from_str("1.5")
        b = NormativeValue.from_str("2.25")
        res_add = a + b
        self.assertEqual(res_add, NormativeValue.from_str("3.75"))

        res_sub = b - a
        self.assertEqual(res_sub, NormativeValue.from_str("0.75"))

        # Integer interoperability
        self.assertEqual(a + 1, NormativeValue.from_str("2.5"))
        self.assertEqual(2 + a, NormativeValue.from_str("3.5"))
        self.assertEqual(b - 1, NormativeValue.from_str("1.25"))
        self.assertEqual(3 - a, NormativeValue.from_str("1.5"))

    def test_multiplication(self):
        a = NormativeValue.from_str("2.5")
        b = NormativeValue.from_str("4.0")
        res = a * b
        self.assertEqual(res, NormativeValue.from_str("10.0"))

        # Fractional multiplication with half-up rounding
        c = NormativeValue.from_str("0.5")
        d = NormativeValue.from_str("0.5")
        self.assertEqual(c * d, NormativeValue.from_str("0.25"))

        # Multiply by integer scalar
        self.assertEqual(a * 3, NormativeValue.from_str("7.5"))
        self.assertEqual(3 * a, NormativeValue.from_str("7.5"))

    def test_division(self):
        a = NormativeValue.from_str("10.0")
        b = NormativeValue.from_str("4.0")
        res = a / b
        self.assertEqual(res, NormativeValue.from_str("2.5"))

        # Division by zero
        zero = NormativeValue.zero()
        with self.assertRaises(WadDivisionByZeroError):
            _ = a / zero
        with self.assertRaises(WadDivisionByZeroError):
            _ = a / 0

    def test_floor_division_and_negation(self):
        a = NormativeValue.from_str("7.5")
        b = NormativeValue.from_str("2.0")
        self.assertEqual(a // b, NormativeValue.from_int(3))
        self.assertEqual(-a, NormativeValue.from_str("-7.5"))
        self.assertEqual(abs(-a), a)

    def test_overflow_and_underflow_checks(self):
        with self.assertRaises(WadOverflowError):
            NormativeValue(MAX_WAD_INT + 1)

        with self.assertRaises(WadUnderflowError):
            NormativeValue(MIN_WAD_INT - 1)

        max_val = NormativeValue.max_value()
        with self.assertRaises(WadOverflowError):
            _ = max_val + 1

        min_val = NormativeValue.min_value()
        with self.assertRaises(WadUnderflowError):
            _ = min_val - 1

    def test_immutability(self):
        v = NormativeValue.from_int(1)
        with self.assertRaises(KernelImmutabilityError):
            v.raw_value = 10  # type: ignore


class TestTypedSystemState(unittest.TestCase):
    """Test Suite for Typed System State X = (I, S, A, H, V, P) (Definition 3)."""

    def test_system_state_creation_and_tuple_unpacking(self):
        state = create_valid_system_state()
        I, S, A, H, V, P = state.as_tuple()
        self.assertEqual(I.model_id, "ssi-sentinel-v1")
        self.assertEqual(S.active_envelope_id, "ENVELOPE-OMEGA-0")
        self.assertEqual(A.action_type, ActionType.COMPUTE)
        self.assertEqual(H.clearance_level, 3)
        self.assertTrue(V.is_valid)
        self.assertEqual(P.sequence_number, 1)

    def test_deterministic_state_hash(self):
        state1 = create_valid_system_state()
        state2 = create_valid_system_state()
        hash1 = state1.compute_state_hash()
        hash2 = state2.compute_state_hash()
        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 64)

    def test_type_and_digest_validation(self):
        # Invalid weights digest type (int instead of str)
        with self.assertRaises(TypeError):
            IntelligenceState(
                model_id="test",
                weights_digest=12345,  # type: ignore
                context_window_size=1000,
                cognitive_budget=NormativeValue.from_int(1),
                epistemic_confidence=NormativeValue.from_str("0.5"),
                entropy_bound=NormativeValue.from_str("0.1"),
            )

        # Invalid clearance type
        with self.assertRaises(TypeError):
            HumanAuthorization(
                auth_token="token",
                granter_id="user",
                clearance_level="not_an_int",  # type: ignore
                is_active=True,
                expires_at_epoch=2000000000,
                nonce="nonce",
            )


class TestSafetyKernelAndGlobalInvariant(unittest.TestCase):
    """Test Suite for Safety Kernel K and Global Invariant I(X) (Definition 15, 19)."""

    def setUp(self):
        self.kernel = SafetyKernel()
        self.valid_epoch = 1700000000

    def test_kernel_immutability(self):
        with self.assertRaises(KernelImmutabilityError):
            self.kernel.custom_attr = "exploit"  # type: ignore

        with self.assertRaises(KernelImmutabilityError):
            del self.kernel._mode  # type: ignore

    def test_global_invariant_satisfaction_on_valid_state(self):
        state = create_valid_system_state(current_epoch=self.valid_epoch)
        verdict = self.kernel.evaluate_global_invariant(state, current_epoch=self.valid_epoch)
        self.assertTrue(verdict.is_valid)
        self.assertIsNone(verdict.failure_reason)
        self.assertTrue(self.kernel.verify_global_invariant(state, current_epoch=self.valid_epoch))

    def test_clause_1_kernel_integrity_failure(self):
        halted_kernel = SafetyKernel()
        halted_kernel.emergency_halt("Security breach detected")
        state = create_valid_system_state(current_epoch=self.valid_epoch)

        with self.assertRaises(KernelIntegrityViolationError):
            halted_kernel.verify_global_invariant(state, current_epoch=self.valid_epoch)

    def test_clause_2_type_validity_failure(self):
        # Epistemic confidence > 1.0 violates bounded confidence rule
        invalid_confidence = NormativeValue.from_str("1.2")
        i_state = IntelligenceState(
            model_id="ssi-model",
            weights_digest="a" * 64,
            context_window_size=1000,
            cognitive_budget=NormativeValue.from_int(10),
            epistemic_confidence=invalid_confidence,
            entropy_bound=NormativeValue.from_str("0.05"),
        )
        base = create_valid_system_state(current_epoch=self.valid_epoch)
        invalid_state = SystemState(
            I=i_state, S=base.S, A=base.A, H=base.H, V=base.V, P=base.P
        )

        with self.assertRaises(TypeValidityViolationError):
            self.kernel.verify_global_invariant(invalid_state, current_epoch=self.valid_epoch)

        # Invalid weights digest length
        i_state_bad_digest = IntelligenceState(
            model_id="ssi-model",
            weights_digest="short_digest",
            context_window_size=1000,
            cognitive_budget=NormativeValue.from_int(10),
            epistemic_confidence=NormativeValue.from_str("0.95"),
            entropy_bound=NormativeValue.from_str("0.05"),
        )
        invalid_digest_state = SystemState(
            I=i_state_bad_digest, S=base.S, A=base.A, H=base.H, V=base.V, P=base.P
        )
        with self.assertRaises(TypeValidityViolationError):
            self.kernel.verify_global_invariant(invalid_digest_state, current_epoch=self.valid_epoch)

    def test_clause_3_csl_validity_failure(self):
        # Quarantine flag raised
        state = create_valid_system_state(current_epoch=self.valid_epoch, quarantine=True)
        with self.assertRaises(CSLValidityViolationError):
            self.kernel.verify_global_invariant(state, current_epoch=self.valid_epoch)

        # Barrier breached
        state_barrier = create_valid_system_state(current_epoch=self.valid_epoch, barrier_intact=False)
        with self.assertRaises(CSLValidityViolationError):
            self.kernel.verify_global_invariant(state_barrier, current_epoch=self.valid_epoch)

    def test_clause_4_authorization_validity_failure(self):
        # Expired authorization
        state_expired = create_valid_system_state(
            current_epoch=self.valid_epoch,
            auth_expires=self.valid_epoch - 10
        )
        with self.assertRaises(AuthorizationValidityViolationError):
            self.kernel.verify_global_invariant(state_expired, current_epoch=self.valid_epoch)

        # Insufficient clearance
        state_clearance = create_valid_system_state(
            current_epoch=self.valid_epoch,
            user_clearance=1,
            required_clearance=3
        )
        with self.assertRaises(AuthorizationValidityViolationError):
            self.kernel.verify_global_invariant(state_clearance, current_epoch=self.valid_epoch)

    def test_clause_5_safety_invariant_validity_failure(self):
        # Action risk exceeds system risk bound
        state_risk = create_valid_system_state(
            current_epoch=self.valid_epoch,
            action_risk_raw=9 * 10**17, # 0.9
            risk_bound_raw=2 * 10**17,  # 0.2
        )
        with self.assertRaises(SafetyInvariantViolationError):
            self.kernel.verify_global_invariant(state_risk, current_epoch=self.valid_epoch)

        # Safety margin insufficient
        state_margin = create_valid_system_state(
            current_epoch=self.valid_epoch,
            safety_margin_raw=1 * 10**17, # 0.1
            risk_bound_raw=3 * 10**17,    # 0.3
        )
        with self.assertRaises(SafetyInvariantViolationError):
            self.kernel.verify_global_invariant(state_margin, current_epoch=self.valid_epoch)

        # Invalid verification proof
        state_proof = create_valid_system_state(
            current_epoch=self.valid_epoch,
            proof_valid=False
        )
        with self.assertRaises(SafetyInvariantViolationError):
            self.kernel.verify_global_invariant(state_proof, current_epoch=self.valid_epoch)

    def test_clause_6_provenance_validity_failure(self):
        # Sequence > 0 but invalid parent state hash
        state_prov = create_valid_system_state(
            current_epoch=self.valid_epoch,
            sequence=2,
            parent_hash="invalid_short_parent_hash"
        )
        with self.assertRaises(ProvenanceValidityViolationError):
            self.kernel.verify_global_invariant(state_prov, current_epoch=self.valid_epoch)

        # Invalid merkle root format
        p_invalid_merkle = ProvenanceState(
            sequence_number=1,
            parent_state_hash="a" * 64,
            merkle_root="short_root",
            audit_trail_id="audit-trail",
            timestamp_epoch_ms=1000,
        )
        base = create_valid_system_state(current_epoch=self.valid_epoch)
        state_bad_merkle = SystemState(
            I=base.I, S=base.S, A=base.A, H=base.H, V=base.V, P=p_invalid_merkle
        )
        with self.assertRaises(ProvenanceValidityViolationError):
            self.kernel.verify_global_invariant(state_bad_merkle, current_epoch=self.valid_epoch)


if __name__ == "__main__":
    unittest.main()
