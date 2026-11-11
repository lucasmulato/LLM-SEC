"""Safe Super Intelligence Axiomatic System v1.0 - Cognitive State Ledger (CSL) & Provenance.

This module implements the formal cryptographic audit trail and authorization layer:
1. Cognitive State Ledger (CSL):
   Defines the ledger envelope tuple (AuthId, Sigma, E, T, Q) (Definitions 6 & 16).
2. Authorization Continuity (Axiom 10):
   Enforces continuous authorization within envelope bounds E, temporal window T,
   and constraint set Q. Revokes authorization immediately if exceeded or expired.
3. Canonical State Encoding & Provenance (Definitions 13, 14, 29):
   Deterministic canonical encoding ENC(X) with SHA-256 state identification ID_X = H(ENC(X))
   and cryptographic certificate binding.
4. Append-Only Trace Storage & SAC Evidence:
   Cryptographically linked audit log emitting machine-checkable Safety Asset Class (SAC)
   evidence objects with unbroken Merkle-style rolling hash verification.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Final, FrozenSet, List, Mapping, Optional, Sequence, Tuple, Union

from core.kernel import (
    ActionState,
    ActionType,
    KernelException,
    NormativeValue,
    SystemState,
)


# ==============================================================================
# SECTION 0: LEDGER EXCEPTIONS (Fail-Closed Semantics)
# ==============================================================================

class LedgerException(KernelException):
    """Base exception for all Cognitive State Ledger and provenance violations."""
    pass


class AuthorizationRevokedError(LedgerException):
    """Raised when authorization continuity is breached (Axiom 10)."""
    def __init__(self, auth_id: str, reason: str, violations: Tuple[str, ...]):
        self.auth_id = auth_id
        self.reason = reason
        self.violations = violations
        super().__init__(
            f"Authorization REVOKED for CSL '{auth_id}': {reason}. Violations: {'; '.join(violations)}"
        )


class LedgerIntegrityError(LedgerException):
    """Raised when an append-only ledger trace fails cryptographic integrity checks."""
    pass


class CanonicalEncodingError(LedgerException):
    """Raised when canonical state serialization fails deterministic constraints."""
    pass


# ==============================================================================
# SECTION 1: COGNITIVE STATE LEDGER (CSL) (Definitions 6 & 16)
# ==============================================================================

@dataclass(frozen=True, slots=True)
class OperatingEnvelope:
    """Operating Envelope E of CSL (Definition 6).

    Defines the multidimensional bounded region of admissible model behavior:
    risk ceiling, permitted action types, per-action resource limit, and total budget.
    """
    envelope_id: str
    max_risk_bound: NormativeValue
    allowed_action_types: FrozenSet[ActionType]
    max_resource_cost_per_action: NormativeValue
    total_budget_limit: NormativeValue

    def __post_init__(self) -> None:
        if not self.envelope_id:
            raise TypeError("OperatingEnvelope.envelope_id cannot be empty")
        if not isinstance(self.max_risk_bound, NormativeValue):
            raise TypeError("OperatingEnvelope.max_risk_bound must be a NormativeValue")
        if not isinstance(self.max_resource_cost_per_action, NormativeValue):
            raise TypeError("OperatingEnvelope.max_resource_cost_per_action must be a NormativeValue")
        if not isinstance(self.total_budget_limit, NormativeValue):
            raise TypeError("OperatingEnvelope.total_budget_limit must be a NormativeValue")
        if not self.allowed_action_types:
            raise TypeError("OperatingEnvelope.allowed_action_types cannot be empty")


@dataclass(frozen=True, slots=True)
class TemporalValidity:
    """Temporal Validity T of CSL (Definition 6).

    Specifies the discrete epoch window and maximum transition depth for continuous authorization.
    """
    valid_from_epoch: int
    valid_until_epoch: int
    max_transitions: int

    def __post_init__(self) -> None:
        if not isinstance(self.valid_from_epoch, int) or isinstance(self.valid_from_epoch, bool):
            raise TypeError("valid_from_epoch must be an int")
        if not isinstance(self.valid_until_epoch, int) or isinstance(self.valid_until_epoch, bool):
            raise TypeError("valid_until_epoch must be an int")
        if self.valid_until_epoch <= self.valid_from_epoch:
            raise ValueError(f"valid_until_epoch ({self.valid_until_epoch}) must be > valid_from_epoch ({self.valid_from_epoch})")
        if not isinstance(self.max_transitions, int) or isinstance(self.max_transitions, bool) or self.max_transitions <= 0:
            raise TypeError("max_transitions must be a positive int")

    def is_valid_epoch(self, epoch: int) -> bool:
        """Check if epoch falls inside [valid_from, valid_until]."""
        return self.valid_from_epoch <= epoch <= self.valid_until_epoch

    def is_valid_sequence(self, sequence_number: int) -> bool:
        """Check if state sequence index does not exceed max_transitions."""
        return sequence_number <= self.max_transitions


@dataclass(frozen=True, slots=True)
class CSLEnvelope:
    """Cognitive State Ledger Envelope (Definition 16).

    Formal tuple CSL = (AuthId, Sigma, E, T, Q):
    - AuthId: Unique authorization identity
    - Sigma: Cryptographic HMAC/signature over (AuthId, E, T, Q)
    - E: Operating Envelope
    - T: Temporal Validity
    - Q: Formal Safety and Containment Constraints
    """
    auth_id: str
    signature: str
    envelope: OperatingEnvelope
    validity: TemporalValidity
    constraints: FrozenSet[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not self.auth_id:
            raise TypeError("CSLEnvelope.auth_id cannot be empty")
        if len(self.signature) != 64:
            raise TypeError("CSLEnvelope.signature must be a 64-char hex string")
        if not isinstance(self.envelope, OperatingEnvelope):
            raise TypeError("CSLEnvelope.envelope must be an OperatingEnvelope")
        if not isinstance(self.validity, TemporalValidity):
            raise TypeError("CSLEnvelope.validity must be a TemporalValidity")
        if not self.constraints:
            raise TypeError("CSLEnvelope.constraints (Q) cannot be empty")

    def canonical_digest_payload(self) -> str:
        """Construct deterministic payload string for signature verification."""
        data = {
            "auth_id": self.auth_id,
            "envelope": {
                "envelope_id": self.envelope.envelope_id,
                "max_risk_raw": self.envelope.max_risk_bound.raw,
                "allowed_actions": sorted([a.value for a in self.envelope.allowed_action_types]),
                "max_cost_raw": self.envelope.max_resource_cost_per_action.raw,
                "total_budget_raw": self.envelope.total_budget_limit.raw,
            },
            "validity": {
                "valid_from": self.validity.valid_from_epoch,
                "valid_until": self.validity.valid_until_epoch,
                "max_transitions": self.validity.max_transitions,
            },
            "constraints": sorted(list(self.constraints)),
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":"))

    def verify_signature(self, secret_key: str) -> bool:
        """Verify cryptographic authenticity of Sigma against secret key."""
        payload = self.canonical_digest_payload()
        expected = hmac.new(
            secret_key.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(self.signature, expected)

    @classmethod
    def create(
        cls,
        auth_id: str,
        envelope: OperatingEnvelope,
        validity: TemporalValidity,
        constraints: FrozenSet[str],
        signing_key: str,
    ) -> CSLEnvelope:
        """Factory creating a cryptographically signed CSLEnvelope."""
        temp_instance = cls(
            auth_id=auth_id,
            signature="0" * 64,
            envelope=envelope,
            validity=validity,
            constraints=constraints,
        )
        payload = temp_instance.canonical_digest_payload()
        sig = hmac.new(
            signing_key.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
        return cls(
            auth_id=auth_id,
            signature=sig,
            envelope=envelope,
            validity=validity,
            constraints=constraints,
        )


# ==============================================================================
# SECTION 2: AUTHORIZATION CONTINUITY (Axiom 10)
# ==============================================================================

@dataclass(frozen=True, slots=True)
class ContinuityEvaluation:
    """Evaluation record of authorization continuity (Axiom 10)."""
    is_authorized: bool
    csl_auth_id: str
    evaluated_at_epoch: int
    violations: Tuple[str, ...]

    @property
    def passed(self) -> bool:
        return self.is_authorized


def verify_authorization_continuity(
    csl: CSLEnvelope,
    state: SystemState,
    proposed_action: Optional[ActionState] = None,
    current_epoch: Optional[int] = None,
    signing_key: Optional[str] = None,
) -> ContinuityEvaluation:
    """Evaluate Authorization Continuity under Axiom 10.

    Axiom 10 (Authorization Continuity):
        An autonomous execution sequence remains authorized if and only if
        the system state X and any proposed action a stay strictly within
        the operating envelope E, temporal window T, and constraint set Q.
        If violated or expired, permit is immediately revoked.
    """
    now_epoch = current_epoch if current_epoch is not None else int(time.time())
    violations: List[str] = []

    # 1. Signature Authenticity Check
    if signing_key is not None:
        if not csl.verify_signature(signing_key):
            violations.append("CSL cryptographic signature Sigma is invalid or forged")

    # 2. Temporal Window Validity T
    if not csl.validity.is_valid_epoch(now_epoch):
        violations.append(
            f"Temporal validity window breached: current {now_epoch} not in "
            f"[{csl.validity.valid_from_epoch}, {csl.validity.valid_until_epoch}]"
        )

    # 3. Maximum Transition Depth Check
    seq = state.P.sequence_number
    if not csl.validity.is_valid_sequence(seq):
        violations.append(
            f"Max transition depth exceeded: state sequence {seq} > limit {csl.validity.max_transitions}"
        )

    # 4. Operating Envelope Bounds E: Risk
    if state.S.risk_bound > csl.envelope.max_risk_bound:
        violations.append(
            f"State risk bound {state.S.risk_bound} exceeds CSL envelope maximum {csl.envelope.max_risk_bound}"
        )

    # 5. Operating Envelope Bounds E: Action
    action_to_check = proposed_action if proposed_action is not None else state.A
    if action_to_check.action_type not in csl.envelope.allowed_action_types:
        violations.append(
            f"Action type '{action_to_check.action_type.value}' not permitted by CSL envelope "
            f"allowed types {[a.value for a in csl.envelope.allowed_action_types]}"
        )

    if action_to_check.resource_cost > csl.envelope.max_resource_cost_per_action:
        violations.append(
            f"Action resource cost {action_to_check.resource_cost} exceeds per-action ceiling "
            f"{csl.envelope.max_resource_cost_per_action}"
        )

    if action_to_check.risk_assessment > csl.envelope.max_risk_bound:
        violations.append(
            f"Action risk assessment {action_to_check.risk_assessment} exceeds envelope ceiling "
            f"{csl.envelope.max_risk_bound}"
        )

    # 6. Safety Constraints Q Subsumption
    # Active state CSL constraints must satisfy all mandatory CSL constraints in Q
    missing_constraints = set(csl.constraints) - set(state.S.csl_constraints)
    if missing_constraints:
        violations.append(
            f"Mandatory CSL constraints missing from active state: {sorted(list(missing_constraints))}"
        )

    # 7. Quarantine status
    if state.S.quarantine_flag:
        violations.append("State quarantine flag is raised; authorization revoked")

    is_ok = len(violations) == 0
    return ContinuityEvaluation(
        is_authorized=is_ok,
        csl_auth_id=csl.auth_id,
        evaluated_at_epoch=now_epoch,
        violations=tuple(violations)
    )


def assert_authorization_continuity(
    csl: CSLEnvelope,
    state: SystemState,
    proposed_action: Optional[ActionState] = None,
    current_epoch: Optional[int] = None,
    signing_key: Optional[str] = None,
) -> None:
    """Fail-closed enforcement of Axiom 10. Raises AuthorizationRevokedError on breach."""
    eval_res = verify_authorization_continuity(
        csl=csl,
        state=state,
        proposed_action=proposed_action,
        current_epoch=current_epoch,
        signing_key=signing_key
    )
    if not eval_res.is_authorized:
        raise AuthorizationRevokedError(
            auth_id=csl.auth_id,
            reason="Continuous authorization envelope breached (Axiom 10)",
            violations=eval_res.violations
        )


# ==============================================================================
# SECTION 3: CANONICAL STATE ENCODING & PROVENANCE (Definitions 13, 14, 29)
# ==============================================================================

def canonical_encode_state(state: SystemState) -> bytes:
    """Compute Deterministic Canonical Encoding ENC(X) (Definition 13).

    Encodes typed state X using canonical UTF-8 JSON with sorted keys,
    strict separator formatting, and unscaled exact NormativeValue raw integers.
    """
    if not isinstance(state, SystemState):
        raise CanonicalEncodingError(f"Expected SystemState, got {type(state).__name__}")
    try:
        raw_dict = state.canonical_dict()
        serialized = json.dumps(raw_dict, sort_keys=True, separators=(",", ":"))
        return serialized.encode("utf-8")
    except Exception as exc:
        raise CanonicalEncodingError(f"Failed to canonically encode state: {exc}") from exc


def compute_state_id(state: SystemState) -> str:
    """Generate State ID: ID_X = H(ENC(X)) (Definition 14).

    Produces the canonical 64-character SHA-256 state identifier.
    """
    encoded = canonical_encode_state(state)
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class BoundVerificationCertificate:
    """Cryptographic Certificate bound to a specific State ID (Definition 29).

    Binds verification proof to exact state ID_X, verifier identity, and signature.
    """
    certificate_id: str
    state_id: str
    verifier_identity: str
    signature: str
    invariants_verified: FrozenSet[str]
    timestamp_epoch: int

    def __post_init__(self) -> None:
        if not self.certificate_id:
            raise TypeError("certificate_id cannot be empty")
        if len(self.state_id) != 64:
            raise TypeError("state_id must be a 64-char SHA-256 hex string")
        if not self.verifier_identity:
            raise TypeError("verifier_identity cannot be empty")
        if len(self.signature) != 64:
            raise TypeError("signature must be a 64-char hex string")

    def canonical_payload(self) -> str:
        return (
            f"{self.certificate_id}:{self.state_id}:{self.verifier_identity}:"
            f"{','.join(sorted(list(self.invariants_verified)))}:{self.timestamp_epoch}"
        )

    def verify_signature(self, verifier_secret: str) -> bool:
        """Verify signature binding against verifier secret key."""
        payload = self.canonical_payload()
        expected = hmac.new(
            verifier_secret.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(self.signature, expected)


def bind_verification_certificate(
    state: SystemState,
    verifier_identity: str,
    verifier_secret: str,
    invariants_verified: FrozenSet[str] = frozenset({"KI", "TV", "CSL", "AV", "SIV", "PV"}),
    timestamp_epoch: Optional[int] = None,
) -> BoundVerificationCertificate:
    """Cryptographically bind a verification certificate to state ID_X (Definition 29)."""
    state_id = compute_state_id(state)
    now_epoch = timestamp_epoch if timestamp_epoch is not None else int(time.time())
    cert_id = f"bvc-{state_id[:16]}-{now_epoch}"

    invariants_str = ",".join(sorted(list(invariants_verified)))
    payload = f"{cert_id}:{state_id}:{verifier_identity}:{invariants_str}:{now_epoch}"
    signature = hmac.new(
        verifier_secret.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return BoundVerificationCertificate(
        certificate_id=cert_id,
        state_id=state_id,
        verifier_identity=verifier_identity,
        signature=signature,
        invariants_verified=invariants_verified,
        timestamp_epoch=now_epoch,
    )


# ==============================================================================
# SECTION 4: APPEND-ONLY TRACE STORAGE & SAC EVIDENCE
# ==============================================================================

class SafetyAssetClass(str, Enum):
    """Safety Asset Class (SAC) evidence taxonomy for high-assurance audits."""
    SAC_1_CONTROL_INTEGRITY = "SAC-1"       # Immutable kernel and barrier integrity
    SAC_2_AUTHORIZATION_CONTINUITY = "SAC-2" # CSL envelope and signoff continuity
    SAC_3_FORMAL_PROVENANCE = "SAC-3"       # Cryptographic state transition lineage


@dataclass(frozen=True, slots=True)
class SACEvidence:
    """Machine-checkable Safety Asset Class (SAC) evidence object."""
    evidence_id: str
    sac_class: SafetyAssetClass
    state_id: str
    parent_state_id: str
    sequence_number: int
    csl_auth_id: str
    certificate_id: str
    transition_hash: str
    prev_record_hash: str
    record_hash: str
    timestamp_epoch_ms: int
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize evidence object for append-only storage."""
        return {
            "evidence_id": self.evidence_id,
            "sac_class": self.sac_class.value,
            "state_id": self.state_id,
            "parent_state_id": self.parent_state_id,
            "sequence_number": self.sequence_number,
            "csl_auth_id": self.csl_auth_id,
            "certificate_id": self.certificate_id,
            "transition_hash": self.transition_hash,
            "prev_record_hash": self.prev_record_hash,
            "record_hash": self.record_hash,
            "timestamp_epoch_ms": self.timestamp_epoch_ms,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SACEvidence:
        return cls(
            evidence_id=data["evidence_id"],
            sac_class=SafetyAssetClass(data["sac_class"]),
            state_id=data["state_id"],
            parent_state_id=data["parent_state_id"],
            sequence_number=data["sequence_number"],
            csl_auth_id=data["csl_auth_id"],
            certificate_id=data["certificate_id"],
            transition_hash=data["transition_hash"],
            prev_record_hash=data["prev_record_hash"],
            record_hash=data["record_hash"],
            timestamp_epoch_ms=data["timestamp_epoch_ms"],
            metadata=data.get("metadata", {}),
        )


class AppendOnlyLedgerStore:
    """Append-only cryptographic trace store for state transitions and SAC evidence.

    Maintains a rolling SHA-256 hash chain:
    RecordHash_k = H(PrevRecordHash_{k-1} || Payload_k)
    Enables machine-checkable verification of audit log immutability and complete lineage.
    """

    GENESIS_HASH: Final[str] = "0" * 64

    def __init__(self, log_path: Optional[Union[str, Path]] = None):
        self._log_path = Path(log_path) if log_path is not None else None
        self._in_memory_records: List[SACEvidence] = []
        self._last_record_hash: str = self.GENESIS_HASH

        if self._log_path is not None and self._log_path.exists():
            self._load_and_verify_existing()

    @property
    def log_path(self) -> Optional[Path]:
        return self._log_path

    @property
    def record_count(self) -> int:
        return len(self._in_memory_records)

    @property
    def latest_record_hash(self) -> str:
        return self._last_record_hash

    def _compute_record_hash(self, prev_hash: str, payload_str: str) -> str:
        return hashlib.sha256((prev_hash + ":" + payload_str).encode("utf-8")).hexdigest()

    def _load_and_verify_existing(self) -> None:
        """Load and verify existing records from log file upon initialization."""
        assert self._log_path is not None
        records: List[SACEvidence] = []
        curr_prev_hash = self.GENESIS_HASH

        with open(self._log_path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                clean_line = line.strip()
                if not clean_line:
                    continue
                data = json.loads(clean_line)
                rec = SACEvidence.from_dict(data)

                if rec.prev_record_hash != curr_prev_hash:
                    raise LedgerIntegrityError(
                        f"Ledger hash chain broken at line {line_no}: "
                        f"expected prev_hash '{curr_prev_hash}', got '{rec.prev_record_hash}'"
                    )

                # Recompute payload hash
                payload_dict = {
                    "evidence_id": rec.evidence_id,
                    "sac_class": rec.sac_class.value,
                    "state_id": rec.state_id,
                    "parent_state_id": rec.parent_state_id,
                    "sequence_number": rec.sequence_number,
                    "csl_auth_id": rec.csl_auth_id,
                    "certificate_id": rec.certificate_id,
                    "transition_hash": rec.transition_hash,
                    "timestamp_epoch_ms": rec.timestamp_epoch_ms,
                    "metadata": dict(rec.metadata),
                }
                payload_str = json.dumps(payload_dict, sort_keys=True, separators=(",", ":"))
                expected_hash = self._compute_record_hash(curr_prev_hash, payload_str)
                if rec.record_hash != expected_hash:
                    raise LedgerIntegrityError(
                        f"Record hash tampering at line {line_no}: expected '{expected_hash}', got '{rec.record_hash}'"
                    )

                records.append(rec)
                curr_prev_hash = rec.record_hash

        self._in_memory_records = records
        self._last_record_hash = curr_prev_hash

    def append_transition(
        self,
        pre_state: SystemState,
        action: ActionState,
        post_state: SystemState,
        csl: CSLEnvelope,
        cert: BoundVerificationCertificate,
        sac_class: SafetyAssetClass = SafetyAssetClass.SAC_3_FORMAL_PROVENANCE,
        metadata: Optional[Dict[str, Any]] = None,
        timestamp_epoch_ms: Optional[int] = None,
    ) -> SACEvidence:
        """Append a cryptographically verified state transition to the ledger."""
        pre_id = compute_state_id(pre_state)
        post_id = compute_state_id(post_state)
        now_ms = timestamp_epoch_ms if timestamp_epoch_ms is not None else int(time.time() * 1000)

        # Transition hash binds pre-state, action, and post-state
        trans_payload = f"{pre_id}:{action.action_id}:{action.payload_digest}:{post_id}"
        transition_hash = hashlib.sha256(trans_payload.encode("utf-8")).hexdigest()

        evidence_id = f"sac-{sac_class.value}-{post_state.P.sequence_number}-{now_ms}"
        prev_hash = self._last_record_hash

        meta = dict(metadata) if metadata is not None else {}
        meta["action_id"] = action.action_id
        meta["action_type"] = action.action_type.value

        payload_dict = {
            "evidence_id": evidence_id,
            "sac_class": sac_class.value,
            "state_id": post_id,
            "parent_state_id": pre_id,
            "sequence_number": post_state.P.sequence_number,
            "csl_auth_id": csl.auth_id,
            "certificate_id": cert.certificate_id,
            "transition_hash": transition_hash,
            "timestamp_epoch_ms": now_ms,
            "metadata": meta,
        }
        payload_str = json.dumps(payload_dict, sort_keys=True, separators=(",", ":"))
        record_hash = self._compute_record_hash(prev_hash, payload_str)

        evidence = SACEvidence(
            evidence_id=evidence_id,
            sac_class=sac_class,
            state_id=post_id,
            parent_state_id=pre_id,
            sequence_number=post_state.P.sequence_number,
            csl_auth_id=csl.auth_id,
            certificate_id=cert.certificate_id,
            transition_hash=transition_hash,
            prev_record_hash=prev_hash,
            record_hash=record_hash,
            timestamp_epoch_ms=now_ms,
            metadata=meta,
        )

        # Persist to disk if file path provided
        if self._log_path is not None:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(evidence.to_dict()) + "\n")

        self._in_memory_records.append(evidence)
        self._last_record_hash = record_hash
        return evidence

    def get_records(self) -> Sequence[SACEvidence]:
        """Return all in-memory verified ledger records."""
        return tuple(self._in_memory_records)

    def verify_ledger_integrity(self) -> Tuple[bool, int, Optional[str]]:
        """Verify the complete cryptographic chain of the ledger.

        Returns (is_valid, record_count, error_reason).
        """
        curr_prev_hash = self.GENESIS_HASH

        for i, rec in enumerate(self._in_memory_records):
            if rec.prev_record_hash != curr_prev_hash:
                return False, i, f"Chain linkage broken at index {i}: expected {curr_prev_hash}, got {rec.prev_record_hash}"

            payload_dict = {
                "evidence_id": rec.evidence_id,
                "sac_class": rec.sac_class.value,
                "state_id": rec.state_id,
                "parent_state_id": rec.parent_state_id,
                "sequence_number": rec.sequence_number,
                "csl_auth_id": rec.csl_auth_id,
                "certificate_id": rec.certificate_id,
                "transition_hash": rec.transition_hash,
                "timestamp_epoch_ms": rec.timestamp_epoch_ms,
                "metadata": dict(rec.metadata),
            }
            payload_str = json.dumps(payload_dict, sort_keys=True, separators=(",", ":"))
            expected_hash = self._compute_record_hash(curr_prev_hash, payload_str)
            if rec.record_hash != expected_hash:
                return False, i, f"Record hash mismatch at index {i}: computed {expected_hash}, stored {rec.record_hash}"

            curr_prev_hash = rec.record_hash

        return True, len(self._in_memory_records), None


__all__ = [
    "LedgerException",
    "AuthorizationRevokedError",
    "LedgerIntegrityError",
    "CanonicalEncodingError",
    "OperatingEnvelope",
    "TemporalValidity",
    "CSLEnvelope",
    "ContinuityEvaluation",
    "verify_authorization_continuity",
    "assert_authorization_continuity",
    "canonical_encode_state",
    "compute_state_id",
    "BoundVerificationCertificate",
    "bind_verification_certificate",
    "SafetyAssetClass",
    "SACEvidence",
    "AppendOnlyLedgerStore",
]
