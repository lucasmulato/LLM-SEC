"""Unit tests for Safe Super Intelligence Axiomatic System v1.0 Cognitive State Ledger (CSL)."""

from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path
from typing import Dict, Tuple

from core.kernel import (
    ActionState,
    ActionType,
    HumanAuthorization,
    IntelligenceState,
    NormativeValue,
    ProvenanceState,
    SafetyState,
    SystemState,
    VerificationState,
)
from core.ledger import (
    AppendOnlyLedgerStore,
    AuthorizationRevokedError,
    BoundVerificationCertificate,
    CanonicalEncodingError,
    CSLEnvelope,
    LedgerIntegrityError,
    OperatingEnvelope,
    SACEvidence,
    SafetyAssetClass,
    TemporalValidity,
    assert_authorization_continuity,
    bind_verification_certificate,
    canonical_encode_state,
    compute_state_id,
    verify_authorization_continuity,
)


def create_test_system_state(
    sequence: int = 1,
    budget_int: int = 100,
    risk_str: str = "0.1",
    action_type: ActionType = ActionType.COMPUTE,
    action_risk_str: str = "0.05",
    action_cost_str: str = "0.5",
    quarantine: bool = False,
    csl_constraints=("NON_DECEPTION", "CONTAINMENT_INTEGRITY"),
) -> Tuple[SystemState, ActionState]:
    """Helper creating a valid baseline SystemState and ActionState."""
    i_state = IntelligenceState(
        model_id="ssi-model-v1",
        weights_digest="a" * 64,
        context_window_size=128000,
        cognitive_budget=NormativeValue.from_int(budget_int),
        epistemic_confidence=NormativeValue.from_str("0.99"),
        entropy_bound=NormativeValue.from_str("0.05"),
        capabilities=frozenset({"MATH", "ANALYSIS"}),
    )

    s_state = SafetyState(
        containment_active=True,
        containment_barrier_intact=True,
        safety_margin=NormativeValue.from_str("0.9"),
        risk_bound=NormativeValue.from_str(risk_str),
        active_envelope_id="ENV-CORE",
        csl_constraints=frozenset(csl_constraints),
        quarantine_flag=quarantine,
    )

    a_state = ActionState(
        action_id="act-eval-01",
        action_type=action_type,
        risk_assessment=NormativeValue.from_str(action_risk_str),
        resource_cost=NormativeValue.from_str(action_cost_str),
        required_clearance=2,
        payload_digest="b" * 64,
        is_executed=False,
    )

    h_state = HumanAuthorization(
        auth_token="auth-tok-1",
        granter_id="officer-1",
        clearance_level=3,
        is_active=True,
        expires_at_epoch=2000000000,
        nonce="nonce-1",
    )

    v_state = VerificationState(
        certificate_id="cert-1",
        proof_system="Z3",
        proof_digest="c" * 64,
        invariants_verified=frozenset({"KI", "TV", "CSL", "AV", "SIV", "PV"}),
        verifier_identity="verifier-1",
        verified_at_epoch=1700000000,
        is_valid=True,
    )

    p_state = ProvenanceState(
        sequence_number=sequence,
        parent_state_hash="d" * 64,
        merkle_root="e" * 64,
        audit_trail_id="audit-1",
        timestamp_epoch_ms=1700000000000,
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


def create_test_csl(signing_key: str = "SECRET_TEST_KEY") -> CSLEnvelope:
    """Helper creating a cryptographically signed CSLEnvelope."""
    envelope = OperatingEnvelope(
        envelope_id="OPERATING-ENV-ALPHA",
        max_risk_bound=NormativeValue.from_str("0.2"),
        allowed_action_types=frozenset({ActionType.READ, ActionType.COMPUTE}),
        max_resource_cost_per_action=NormativeValue.from_str("2.0"),
        total_budget_limit=NormativeValue.from_int(1000),
    )
    validity = TemporalValidity(
        valid_from_epoch=1700000000,
        valid_until_epoch=1700010000,
        max_transitions=50,
    )
    constraints = frozenset({"NON_DECEPTION", "CONTAINMENT_INTEGRITY"})
    return CSLEnvelope.create(
        auth_id="CSL-AUTH-2026-001",
        envelope=envelope,
        validity=validity,
        constraints=constraints,
        signing_key=signing_key,
    )


class TestCognitiveStateLedgerEnvelope(unittest.TestCase):
    """Test Suite for CSL Structure and Cryptographic Signatures (Definitions 6 & 16)."""

    def test_csl_envelope_creation_and_signature_verification(self):
        csl = create_test_csl(signing_key="MY_KEY")
        self.assertEqual(csl.auth_id, "CSL-AUTH-2026-001")
        self.assertEqual(len(csl.signature), 64)
        self.assertTrue(csl.verify_signature("MY_KEY"))
        self.assertFalse(csl.verify_signature("WRONG_KEY"))

    def test_csl_signature_tampering_detection(self):
        csl = create_test_csl(signing_key="MY_KEY")
        # Forged signature
        tampered_csl = CSLEnvelope(
            auth_id=csl.auth_id,
            signature="f" * 64,
            envelope=csl.envelope,
            validity=csl.validity,
            constraints=csl.constraints,
        )
        self.assertFalse(tampered_csl.verify_signature("MY_KEY"))


class TestAuthorizationContinuity(unittest.TestCase):
    """Test Suite for Authorization Continuity (Axiom 10)."""

    def setUp(self):
        self.signing_key = "CONTINUITY_KEY"
        self.csl = create_test_csl(signing_key=self.signing_key)
        self.valid_epoch = 1700005000
        self.state, self.action = create_test_system_state(sequence=5)

    def test_nominal_continuity_succeeds(self):
        res = verify_authorization_continuity(
            csl=self.csl,
            state=self.state,
            proposed_action=self.action,
            current_epoch=self.valid_epoch,
            signing_key=self.signing_key,
        )
        self.assertTrue(res.is_authorized)
        self.assertEqual(len(res.violations), 0)
        # assert should not raise
        assert_authorization_continuity(
            csl=self.csl,
            state=self.state,
            proposed_action=self.action,
            current_epoch=self.valid_epoch,
            signing_key=self.signing_key,
        )

    def test_temporal_window_expiry_revokes_authorization(self):
        # Current epoch is past valid_until_epoch (1700010000)
        expired_epoch = 1700020000
        res = verify_authorization_continuity(
            csl=self.csl,
            state=self.state,
            current_epoch=expired_epoch,
        )
        self.assertFalse(res.is_authorized)
        self.assertTrue(any("Temporal validity" in v for v in res.violations))

        with self.assertRaises(AuthorizationRevokedError):
            assert_authorization_continuity(
                csl=self.csl,
                state=self.state,
                current_epoch=expired_epoch,
            )

    def test_max_transition_depth_breach_revokes_authorization(self):
        # Sequence 55 exceeds max_transitions (50)
        deep_state, _ = create_test_system_state(sequence=55)
        res = verify_authorization_continuity(
            csl=self.csl,
            state=deep_state,
            current_epoch=self.valid_epoch,
        )
        self.assertFalse(res.is_authorized)
        self.assertTrue(any("Max transition depth" in v for v in res.violations))

    def test_disallowed_action_type_revokes_authorization(self):
        # COMMUNICATE is not in allowed {READ, COMPUTE}
        _, forbidden_action = create_test_system_state(action_type=ActionType.COMMUNICATE)
        res = verify_authorization_continuity(
            csl=self.csl,
            state=self.state,
            proposed_action=forbidden_action,
            current_epoch=self.valid_epoch,
        )
        self.assertFalse(res.is_authorized)
        self.assertTrue(any("Action type" in v for v in res.violations))

    def test_excessive_action_resource_cost_revokes_authorization(self):
        # Cost 5.0 exceeds max_resource_cost_per_action (2.0)
        _, expensive_action = create_test_system_state(action_cost_str="5.0")
        res = verify_authorization_continuity(
            csl=self.csl,
            state=self.state,
            proposed_action=expensive_action,
            current_epoch=self.valid_epoch,
        )
        self.assertFalse(res.is_authorized)
        self.assertTrue(any("Action resource cost" in v for v in res.violations))

    def test_missing_mandatory_constraints_revokes_authorization(self):
        # State missing "CONTAINMENT_INTEGRITY"
        non_compliant_state, _ = create_test_system_state(csl_constraints=("NON_DECEPTION",))
        res = verify_authorization_continuity(
            csl=self.csl,
            state=non_compliant_state,
            current_epoch=self.valid_epoch,
        )
        self.assertFalse(res.is_authorized)
        self.assertTrue(any("Mandatory CSL constraints missing" in v for v in res.violations))


class TestCanonicalStateEncodingAndCertificateBinding(unittest.TestCase):
    """Test Suite for Canonical Encoding ENC(X) & Bound Certificates (Defs 13, 14, 29)."""

    def setUp(self):
        self.state, _ = create_test_system_state()

    def test_deterministic_encoding_and_state_id(self):
        enc1 = canonical_encode_state(self.state)
        enc2 = canonical_encode_state(self.state)
        self.assertEqual(enc1, enc2)

        id1 = compute_state_id(self.state)
        id2 = compute_state_id(self.state)
        self.assertEqual(id1, id2)
        self.assertEqual(len(id1), 64)

    def test_certificate_binding_to_state_id(self):
        verifier_key = "VERIFIER_SECRET_ROOT"
        cert = bind_verification_certificate(
            state=self.state,
            verifier_identity="formal-verifier-node-1",
            verifier_secret=verifier_key,
            invariants_verified=frozenset({"KI", "TV", "CSL", "AV", "SIV", "PV"}),
            timestamp_epoch=1700000000,
        )
        self.assertIsInstance(cert, BoundVerificationCertificate)
        self.assertEqual(cert.state_id, compute_state_id(self.state))
        self.assertTrue(cert.verify_signature(verifier_key))
        self.assertFalse(cert.verify_signature("WRONG_VERIFIER_KEY"))


class TestAppendOnlyLedgerStoreAndSACEvidence(unittest.TestCase):
    """Test Suite for Append-Only Ledger Store & SAC Evidence Rolling Hash Chain."""

    def setUp(self):
        self.csl = create_test_csl()
        self.pre_state, self.action = create_test_system_state(sequence=1)
        self.post_state, _ = create_test_system_state(sequence=2)
        self.cert = bind_verification_certificate(
            state=self.post_state,
            verifier_identity="verifier-node",
            verifier_secret="KEY",
            timestamp_epoch=1700000000,
        )

    def test_in_memory_rolling_hash_chain(self):
        store = AppendOnlyLedgerStore()
        ev1 = store.append_transition(
            pre_state=self.pre_state,
            action=self.action,
            post_state=self.post_state,
            csl=self.csl,
            cert=self.cert,
            sac_class=SafetyAssetClass.SAC_3_FORMAL_PROVENANCE,
        )
        self.assertEqual(ev1.sequence_number, 2)
        self.assertEqual(ev1.prev_record_hash, AppendOnlyLedgerStore.GENESIS_HASH)

        # Append second transition
        post_state_3, _ = create_test_system_state(sequence=3)
        cert_3 = bind_verification_certificate(
            state=post_state_3,
            verifier_identity="verifier-node",
            verifier_secret="KEY",
            timestamp_epoch=1700000100,
        )
        ev2 = store.append_transition(
            pre_state=self.post_state,
            action=self.action,
            post_state=post_state_3,
            csl=self.csl,
            cert=cert_3,
            sac_class=SafetyAssetClass.SAC_2_AUTHORIZATION_CONTINUITY,
        )
        self.assertEqual(ev2.prev_record_hash, ev1.record_hash)

        # Verify integrity
        is_valid, count, err = store.verify_ledger_integrity()
        self.assertTrue(is_valid)
        self.assertEqual(count, 2)
        self.assertIsNone(err)

    def test_file_persistence_and_tamper_detection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit_trace.jsonl"
            store = AppendOnlyLedgerStore(log_path=log_path)

            store.append_transition(
                pre_state=self.pre_state,
                action=self.action,
                post_state=self.post_state,
                csl=self.csl,
                cert=self.cert,
            )
            self.assertTrue(log_path.exists())

            # Load into a new store instance from file
            reloaded_store = AppendOnlyLedgerStore(log_path=log_path)
            self.assertEqual(reloaded_store.record_count, 1)
            is_valid, _, _ = reloaded_store.verify_ledger_integrity()
            self.assertTrue(is_valid)

            # Deliberately tamper with the file content
            with open(log_path, "r") as f:
                content = f.read()
            tampered = content.replace("act-eval-01", "act-malicious-99")
            with open(log_path, "w") as f:
                f.write(tampered)

            # Reloading tampered file must fail-closed with LedgerIntegrityError
            with self.assertRaises(LedgerIntegrityError):
                _ = AppendOnlyLedgerStore(log_path=log_path)


if __name__ == "__main__":
    unittest.main()
