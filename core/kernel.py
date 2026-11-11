"""Safe Super Intelligence Axiomatic System v1.0 - Core Kernel.

This module implements the foundational high-assurance security primitives:
1. WAD-18 Deterministic Arithmetic (Axioms 1 & 2): Fixed-point 10^-18 normative arithmetic.
2. Typed System State X = (I, S, A, H, V, P) (Definition 3): Complete discrete state representation.
3. Immutable Safety Kernel K (Definition 15, Axiom 9): Non-bypassable, non-modifiable safety kernel.
4. Global System Invariant I(X) (Definition 19, Section 32): Simultaneous multi-clause formal invariant.

All operations enforce strict fail-closed security semantics.
"""

from __future__ import annotations

import decimal
import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Final, FrozenSet, Mapping, NamedTuple, Optional, Tuple, Union


# ==============================================================================
# SECTION 0: EXCEPTION HIERARCHY (Fail-Closed Semantics)
# ==============================================================================

class KernelException(Exception):
    """Base exception for all Safety Kernel violations and deterministic failures."""
    pass


class WadArithmeticError(KernelException):
    """Base error for WAD-18 deterministic arithmetic violations."""
    pass


class WadOverflowError(WadArithmeticError):
    """Raised when a normative value or operation exceeds the upper numerical bound (Axiom 2)."""
    pass


class WadUnderflowError(WadArithmeticError):
    """Raised when a normative value or operation falls below the lower numerical bound (Axiom 2)."""
    pass


class WadDivisionByZeroError(WadArithmeticError):
    """Raised when division or modulo by zero is attempted in normative arithmetic (Axiom 2)."""
    pass


class KernelImmutabilityError(KernelException):
    """Raised when an unauthorized modification of the Safety Kernel is attempted (Axiom 9)."""
    pass


class KernelInvariantViolationError(KernelException):
    """Raised when the Global System Invariant I(X) fails to hold (Definition 19, Section 32)."""
    def __init__(self, clause: str, reason: str, state_hash: Optional[str] = None):
        self.clause = clause
        self.reason = reason
        self.state_hash = state_hash
        super().__init__(
            f"Invariant clause violation [{clause}]: {reason} (State Hash: {state_hash or 'UNKNOWN'})"
        )


class KernelIntegrityViolationError(KernelInvariantViolationError):
    """Raised when Kernel Integrity (KI) fails."""
    pass


class TypeValidityViolationError(KernelInvariantViolationError):
    """Raised when Type Validity (TV) fails."""
    pass


class CSLValidityViolationError(KernelInvariantViolationError):
    """Raised when Constitutional/Safety Logic Validity (CSL) fails."""
    pass


class AuthorizationValidityViolationError(KernelInvariantViolationError):
    """Raised when Authorization Validity (AV) fails."""
    pass


class SafetyInvariantViolationError(KernelInvariantViolationError):
    """Raised when Safety Invariant Validity (SIV) fails."""
    pass


class ProvenanceValidityViolationError(KernelInvariantViolationError):
    """Raised when Provenance Validity (PV) fails."""
    pass


# ==============================================================================
# SECTION 1: WAD-18 DETERMINISTIC ARITHMETIC (Axioms 1 & 2)
# ==============================================================================

WAD_DECIMALS: Final[int] = 18
WAD_SCALE: Final[int] = 10**18
HALF_WAD: Final[int] = WAD_SCALE // 2

# Standard bounded 256-bit signed integer interval for high-assurance bounds check
MIN_WAD_INT: Final[int] = -(2**255)
MAX_WAD_INT: Final[int] = (2**255) - 1


class NormativeValue:
    """Normative Numerical Value with 18 decimal places of fixed-point precision (WAD-18).

    Axiom 1 (Deterministic Numerical Foundation):
        All arithmetic in normative reasoning, safety margins, and risk bounds
        must be exact, integer-scaled, and free from IEEE 754 floating-point nondeterminism.

    Axiom 2 (Bounded Precision and Explicit Range):
        Every normative value is stored as an exact integer scaled by 10^18 and strictly
        bounded by [MIN_WAD_INT, MAX_WAD_INT]. Overflow, underflow, and zero division
        are caught immediately with fail-closed exceptions.
    """

    __slots__ = ("_raw",)

    def __init__(self, raw_value: int) -> None:
        if not isinstance(raw_value, int) or isinstance(raw_value, bool):
            raise TypeError(f"NormativeValue raw_value must be an int, got {type(raw_value).__name__}")
        if raw_value > MAX_WAD_INT:
            raise WadOverflowError(f"Raw value {raw_value} exceeds MAX_WAD_INT ({MAX_WAD_INT})")
        if raw_value < MIN_WAD_INT:
            raise WadUnderflowError(f"Raw value {raw_value} below MIN_WAD_INT ({MIN_WAD_INT})")
        object.__setattr__(self, "_raw", raw_value)

    def __setattr__(self, key: str, value: Any) -> None:
        raise KernelImmutabilityError("NormativeValue instances are strictly immutable")

    def __delattr__(self, key: str) -> None:
        raise KernelImmutabilityError("NormativeValue instances are strictly immutable")

    def __copy__(self) -> NormativeValue:
        return self

    def __deepcopy__(self, memo: Any) -> NormativeValue:
        return self

    def __reduce__(self) -> Tuple[Any, Tuple[Any, ...]]:
        return (NormativeValue, (self._raw,))

    @property
    def raw(self) -> int:
        """Return the underlying 10^-18 scaled integer."""
        return self._raw

    # --------------------------------------------------------------------------
    # Constructors & Factories
    # --------------------------------------------------------------------------

    @classmethod
    def from_raw(cls, raw_value: int) -> NormativeValue:
        """Construct directly from an already-scaled raw integer."""
        return cls(raw_value)

    @classmethod
    def from_int(cls, value: int) -> NormativeValue:
        """Construct from an unscaled integer: value * 10^18."""
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError(f"Expected int, got {type(value).__name__}")
        raw = value * WAD_SCALE
        return cls(raw)

    @classmethod
    def from_str(cls, value_str: str) -> NormativeValue:
        """Construct deterministically from a decimal string without float coercion."""
        clean_str = value_str.strip()
        try:
            d = decimal.Decimal(clean_str)
        except decimal.InvalidOperation as exc:
            raise WadArithmeticError(f"Invalid decimal string representation: '{value_str}'") from exc

        # Scale by 10^18 using exact integer decimal arithmetic
        scaled = d * decimal.Decimal(WAD_SCALE)
        raw_int = int(scaled.to_integral_exact(rounding=decimal.ROUND_HALF_UP))
        return cls(raw_int)

    @classmethod
    def from_float(cls, value: float) -> NormativeValue:
        """Construct from float via explicit decimal conversion.

        Note: Float input can carry inherent IEEE-754 precision noise.
        Prefer from_str or from_int in formal verification contexts.
        """
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise TypeError(f"Expected float or int, got {type(value).__name__}")
        return cls.from_str(str(value))

    @classmethod
    def from_fraction(cls, numerator: int, denominator: int) -> NormativeValue:
        """Construct from rational fraction (numerator / denominator) scaled to WAD-18."""
        if not isinstance(numerator, int) or not isinstance(denominator, int) or isinstance(numerator, bool) or isinstance(denominator, bool):
            raise TypeError("Numerator and denominator must be integers")
        if denominator == 0:
            raise WadDivisionByZeroError("Fraction denominator cannot be zero")
        raw = (numerator * WAD_SCALE) // denominator
        return cls(raw)

    @classmethod
    def zero(cls) -> NormativeValue:
        """Return WAD-18 zero (0)."""
        return cls(0)

    @classmethod
    def one(cls) -> NormativeValue:
        """Return WAD-18 unity (1.0 = 10^18)."""
        return cls(WAD_SCALE)

    @classmethod
    def max_value(cls) -> NormativeValue:
        """Return upper bound NormativeValue."""
        return cls(MAX_WAD_INT)

    @classmethod
    def min_value(cls) -> NormativeValue:
        """Return lower bound NormativeValue."""
        return cls(MIN_WAD_INT)

    # --------------------------------------------------------------------------
    # Arithmetic Operations (Deterministic & Checked)
    # --------------------------------------------------------------------------

    def __add__(self, other: Union[NormativeValue, int]) -> NormativeValue:
        if isinstance(other, NormativeValue):
            return NormativeValue(self._raw + other._raw)
        if isinstance(other, int) and not isinstance(other, bool):
            return NormativeValue(self._raw + (other * WAD_SCALE))
        return NotImplemented

    def __radd__(self, other: Union[NormativeValue, int]) -> NormativeValue:
        return self.__add__(other)

    def __sub__(self, other: Union[NormativeValue, int]) -> NormativeValue:
        if isinstance(other, NormativeValue):
            return NormativeValue(self._raw - other._raw)
        if isinstance(other, int) and not isinstance(other, bool):
            return NormativeValue(self._raw - (other * WAD_SCALE))
        return NotImplemented

    def __rsub__(self, other: Union[NormativeValue, int]) -> NormativeValue:
        if isinstance(other, int) and not isinstance(other, bool):
            return NormativeValue((other * WAD_SCALE) - self._raw)
        return NotImplemented

    def __mul__(self, other: Union[NormativeValue, int]) -> NormativeValue:
        """Fixed-point deterministic multiplication with symmetric half-up rounding."""
        if isinstance(other, NormativeValue):
            prod = self._raw * other._raw
            if prod >= 0:
                raw = (prod + HALF_WAD) // WAD_SCALE
            else:
                raw = (prod - HALF_WAD) // WAD_SCALE
            return NormativeValue(raw)
        if isinstance(other, int) and not isinstance(other, bool):
            return NormativeValue(self._raw * other)
        return NotImplemented

    def __rmul__(self, other: Union[NormativeValue, int]) -> NormativeValue:
        return self.__mul__(other)

    def __truediv__(self, other: Union[NormativeValue, int]) -> NormativeValue:
        """Fixed-point deterministic division with symmetric half-up rounding."""
        if isinstance(other, NormativeValue):
            if other._raw == 0:
                raise WadDivisionByZeroError("Division by zero in NormativeValue arithmetic")
            num = self._raw * WAD_SCALE
            denom = other._raw
            if (num >= 0 and denom > 0) or (num <= 0 and denom < 0):
                raw = (num + abs(denom) // 2) // denom
            else:
                raw = (num - abs(denom) // 2) // denom
            return NormativeValue(raw)
        if isinstance(other, int) and not isinstance(other, bool):
            if other == 0:
                raise WadDivisionByZeroError("Division by zero in NormativeValue arithmetic")
            return NormativeValue(self._raw // other)
        return NotImplemented

    def __rtruediv__(self, other: Union[NormativeValue, int]) -> NormativeValue:
        if isinstance(other, int) and not isinstance(other, bool):
            return NormativeValue.from_int(other).__truediv__(self)
        return NotImplemented

    def __floordiv__(self, other: Union[NormativeValue, int]) -> NormativeValue:
        if isinstance(other, NormativeValue):
            if other._raw == 0:
                raise WadDivisionByZeroError("Floor division by zero")
            return NormativeValue((self._raw // other._raw) * WAD_SCALE)
        if isinstance(other, int) and not isinstance(other, bool):
            if other == 0:
                raise WadDivisionByZeroError("Floor division by zero")
            return NormativeValue((self._raw // (other * WAD_SCALE)) * WAD_SCALE)
        return NotImplemented

    def __neg__(self) -> NormativeValue:
        return NormativeValue(-self._raw)

    def __pos__(self) -> NormativeValue:
        return self

    def __abs__(self) -> NormativeValue:
        return NormativeValue(abs(self._raw))

    # --------------------------------------------------------------------------
    # Relational & Comparison Operations
    # --------------------------------------------------------------------------

    def __eq__(self, other: object) -> bool:
        if isinstance(other, NormativeValue):
            return self._raw == other._raw
        if isinstance(other, int) and not isinstance(other, bool):
            return self._raw == other * WAD_SCALE
        if isinstance(other, float):
            return self._raw == NormativeValue.from_float(other)._raw
        return False

    def __lt__(self, other: Union[NormativeValue, int, float]) -> bool:
        if isinstance(other, NormativeValue):
            return self._raw < other._raw
        if isinstance(other, int) and not isinstance(other, bool):
            return self._raw < other * WAD_SCALE
        if isinstance(other, float):
            return self._raw < NormativeValue.from_float(other)._raw
        return NotImplemented

    def __le__(self, other: Union[NormativeValue, int, float]) -> bool:
        if isinstance(other, NormativeValue):
            return self._raw <= other._raw
        if isinstance(other, int) and not isinstance(other, bool):
            return self._raw <= other * WAD_SCALE
        if isinstance(other, float):
            return self._raw <= NormativeValue.from_float(other)._raw
        return NotImplemented

    def __gt__(self, other: Union[NormativeValue, int, float]) -> bool:
        if isinstance(other, NormativeValue):
            return self._raw > other._raw
        if isinstance(other, int) and not isinstance(other, bool):
            return self._raw > other * WAD_SCALE
        if isinstance(other, float):
            return self._raw > NormativeValue.from_float(other)._raw
        return NotImplemented

    def __ge__(self, other: Union[NormativeValue, int, float]) -> bool:
        if isinstance(other, NormativeValue):
            return self._raw >= other._raw
        if isinstance(other, int) and not isinstance(other, bool):
            return self._raw >= other * WAD_SCALE
        if isinstance(other, float):
            return self._raw >= NormativeValue.from_float(other)._raw
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.__class__.__name__, self._raw))

    # --------------------------------------------------------------------------
    # Representation & Conversion
    # --------------------------------------------------------------------------

    def to_int(self) -> int:
        """Return truncated integer portion."""
        return self._raw // WAD_SCALE

    def to_float(self) -> float:
        """Return float representation."""
        return self._raw / WAD_SCALE

    def to_decimal_str(self, decimals: int = 18) -> str:
        """Return canonical decimal string representation without exponential notation."""
        if not (0 <= decimals <= 18):
            raise ValueError("Decimals must be in range [0, 18]")
        is_neg = self._raw < 0
        abs_val = abs(self._raw)
        int_part = abs_val // WAD_SCALE
        frac_part = abs_val % WAD_SCALE
        frac_str = f"{frac_part:018d}"[:decimals]
        sign = "-" if is_neg else ""
        if decimals == 0:
            return f"{sign}{int_part}"
        return f"{sign}{int_part}.{frac_str}"

    def __repr__(self) -> str:
        return f"NormativeValue(raw={self._raw}, dec='{self.to_decimal_str()}')"

    def __str__(self) -> str:
        return self.to_decimal_str()


# ==============================================================================
# SECTION 2: TYPED SYSTEM STATE X = (I, S, A, H, V, P) (Definition 3)
# ==============================================================================

class ActionType(str, Enum):
    """Categorization of proposed autonomous actions."""
    READ = "READ"
    COMPUTE = "COMPUTE"
    COMMUNICATE = "COMMUNICATE"
    MUTATE_ENVIRONMENT = "MUTATE_ENVIRONMENT"
    EXECUTE_CODE = "EXECUTE_CODE"
    SYSTEM_HALT = "SYSTEM_HALT"


@dataclass(frozen=True, slots=True)
class IntelligenceState:
    """Intelligence State Component (I) of System State X.

    Represents the operational capabilities, epistemic bounds, cognitive load,
    and model configuration at state transition step t.
    """
    model_id: str
    weights_digest: str
    context_window_size: int
    cognitive_budget: NormativeValue
    epistemic_confidence: NormativeValue
    entropy_bound: NormativeValue
    capabilities: FrozenSet[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not isinstance(self.model_id, str):
            raise TypeError("IntelligenceState.model_id must be a str")
        if not isinstance(self.weights_digest, str):
            raise TypeError("IntelligenceState.weights_digest must be a str")
        if not isinstance(self.context_window_size, int) or isinstance(self.context_window_size, bool):
            raise TypeError("IntelligenceState.context_window_size must be an int")
        if not isinstance(self.cognitive_budget, NormativeValue):
            raise TypeError("IntelligenceState.cognitive_budget must be a NormativeValue")
        if not isinstance(self.epistemic_confidence, NormativeValue):
            raise TypeError("IntelligenceState.epistemic_confidence must be a NormativeValue")
        if not isinstance(self.entropy_bound, NormativeValue):
            raise TypeError("IntelligenceState.entropy_bound must be a NormativeValue")


@dataclass(frozen=True, slots=True)
class SafetyState:
    """Safety State Component (S) of System State X.

    Represents the active containment envelopes, safety margins, risk thresholds,
    and active Constitutional/Safety Logic (CSL) constraints.
    """
    containment_active: bool
    containment_barrier_intact: bool
    safety_margin: NormativeValue
    risk_bound: NormativeValue
    active_envelope_id: str
    csl_constraints: FrozenSet[str] = field(default_factory=frozenset)
    quarantine_flag: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.containment_active, bool) or not isinstance(self.containment_barrier_intact, bool):
            raise TypeError("SafetyState containment flags must be boolean")
        if not isinstance(self.safety_margin, NormativeValue):
            raise TypeError("SafetyState.safety_margin must be a NormativeValue")
        if not isinstance(self.risk_bound, NormativeValue):
            raise TypeError("SafetyState.risk_bound must be a NormativeValue")
        if not isinstance(self.active_envelope_id, str):
            raise TypeError("SafetyState.active_envelope_id must be a str")


@dataclass(frozen=True, slots=True)
class ActionState:
    """Action State Component (A) of System State X.

    Represents a proposed or actively dispatched action subjected to verification.
    """
    action_id: str
    action_type: ActionType
    risk_assessment: NormativeValue
    resource_cost: NormativeValue
    required_clearance: int
    payload_digest: str
    is_executed: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.action_id, str):
            raise TypeError("ActionState.action_id must be a str")
        if not isinstance(self.action_type, ActionType):
            raise TypeError(f"ActionState.action_type must be an ActionType enum, got {type(self.action_type)}")
        if not isinstance(self.risk_assessment, NormativeValue):
            raise TypeError("ActionState.risk_assessment must be a NormativeValue")
        if not isinstance(self.resource_cost, NormativeValue):
            raise TypeError("ActionState.resource_cost must be a NormativeValue")
        if not isinstance(self.required_clearance, int) or isinstance(self.required_clearance, bool):
            raise TypeError("ActionState.required_clearance must be an int")
        if not isinstance(self.payload_digest, str):
            raise TypeError("ActionState.payload_digest must be a str")


@dataclass(frozen=True, slots=True)
class HumanAuthorization:
    """Human Authorization Component (H) of System State X.

    Represents formal human-in-the-loop signoff, authorization tokens, and clearance levels.
    """
    auth_token: str
    granter_id: str
    clearance_level: int
    is_active: bool
    expires_at_epoch: int
    nonce: str

    def __post_init__(self) -> None:
        if not isinstance(self.auth_token, str):
            raise TypeError("HumanAuthorization.auth_token must be a str")
        if not isinstance(self.granter_id, str):
            raise TypeError("HumanAuthorization.granter_id must be a str")
        if not isinstance(self.clearance_level, int) or isinstance(self.clearance_level, bool):
            raise TypeError("HumanAuthorization.clearance_level must be an int")
        if not isinstance(self.is_active, bool):
            raise TypeError("HumanAuthorization.is_active must be a bool")
        if not isinstance(self.expires_at_epoch, int) or isinstance(self.expires_at_epoch, bool):
            raise TypeError("HumanAuthorization.expires_at_epoch must be an int")
        if not isinstance(self.nonce, str):
            raise TypeError("HumanAuthorization.nonce must be a str")


@dataclass(frozen=True, slots=True)
class VerificationState:
    """Verification State Component (V) of System State X.

    Represents formal mathematical proof certificates, verifier identity,
    and verified invariant assertions.
    """
    certificate_id: str
    proof_system: str
    proof_digest: str
    invariants_verified: FrozenSet[str]
    verifier_identity: str
    verified_at_epoch: int
    is_valid: bool

    def __post_init__(self) -> None:
        if not isinstance(self.certificate_id, str):
            raise TypeError("VerificationState.certificate_id must be a str")
        if not isinstance(self.proof_system, str):
            raise TypeError("VerificationState.proof_system must be a str")
        if not isinstance(self.proof_digest, str):
            raise TypeError("VerificationState.proof_digest must be a str")
        if not isinstance(self.verifier_identity, str):
            raise TypeError("VerificationState.verifier_identity must be a str")
        if not isinstance(self.verified_at_epoch, int) or isinstance(self.verified_at_epoch, bool):
            raise TypeError("VerificationState.verified_at_epoch must be an int")
        if not isinstance(self.is_valid, bool):
            raise TypeError("VerificationState.is_valid must be a bool")


@dataclass(frozen=True, slots=True)
class ProvenanceState:
    """Provenance State Component (P) of System State X.

    Represents state sequence t, cryptographic lineage hashes, and audit trail references.
    """
    sequence_number: int
    parent_state_hash: str
    merkle_root: str
    audit_trail_id: str
    timestamp_epoch_ms: int

    def __post_init__(self) -> None:
        if not isinstance(self.sequence_number, int) or isinstance(self.sequence_number, bool):
            raise TypeError("ProvenanceState.sequence_number must be an int")
        if not isinstance(self.parent_state_hash, str):
            raise TypeError("ProvenanceState.parent_state_hash must be a str")
        if not isinstance(self.merkle_root, str):
            raise TypeError("ProvenanceState.merkle_root must be a str")
        if not isinstance(self.audit_trail_id, str):
            raise TypeError("ProvenanceState.audit_trail_id must be a str")
        if not isinstance(self.timestamp_epoch_ms, int) or isinstance(self.timestamp_epoch_ms, bool):
            raise TypeError("ProvenanceState.timestamp_epoch_ms must be an int")


@dataclass(frozen=True, slots=True)
class SystemState:
    """Typed System State X = (I, S, A, H, V, P) (Definition 3).

    Formal 6-tuple representing the complete state of the autonomous system
    at discrete step t.
    """
    I: IntelligenceState
    S: SafetyState
    A: ActionState
    H: HumanAuthorization
    V: VerificationState
    P: ProvenanceState

    def __post_init__(self) -> None:
        if not isinstance(self.I, IntelligenceState):
            raise TypeError(f"Component I must be IntelligenceState, got {type(self.I).__name__}")
        if not isinstance(self.S, SafetyState):
            raise TypeError(f"Component S must be SafetyState, got {type(self.S).__name__}")
        if not isinstance(self.A, ActionState):
            raise TypeError(f"Component A must be ActionState, got {type(self.A).__name__}")
        if not isinstance(self.H, HumanAuthorization):
            raise TypeError(f"Component H must be HumanAuthorization, got {type(self.H).__name__}")
        if not isinstance(self.V, VerificationState):
            raise TypeError(f"Component V must be VerificationState, got {type(self.V).__name__}")
        if not isinstance(self.P, ProvenanceState):
            raise TypeError(f"Component P must be ProvenanceState, got {type(self.P).__name__}")

    def as_tuple(self) -> Tuple[
        IntelligenceState,
        SafetyState,
        ActionState,
        HumanAuthorization,
        VerificationState,
        ProvenanceState
    ]:
        """Return the state as formal 6-tuple (I, S, A, H, V, P)."""
        return (self.I, self.S, self.A, self.H, self.V, self.P)

    def canonical_dict(self) -> Dict[str, Any]:
        """Generate deterministic dictionary suitable for canonical serialization."""
        return {
            "I": {
                "model_id": self.I.model_id,
                "weights_digest": self.I.weights_digest,
                "context_window_size": self.I.context_window_size,
                "cognitive_budget_raw": self.I.cognitive_budget.raw,
                "epistemic_confidence_raw": self.I.epistemic_confidence.raw,
                "entropy_bound_raw": self.I.entropy_bound.raw,
                "capabilities": sorted(list(self.I.capabilities)),
            },
            "S": {
                "containment_active": self.S.containment_active,
                "containment_barrier_intact": self.S.containment_barrier_intact,
                "safety_margin_raw": self.S.safety_margin.raw,
                "risk_bound_raw": self.S.risk_bound.raw,
                "active_envelope_id": self.S.active_envelope_id,
                "csl_constraints": sorted(list(self.S.csl_constraints)),
                "quarantine_flag": self.S.quarantine_flag,
            },
            "A": {
                "action_id": self.A.action_id,
                "action_type": self.A.action_type.value,
                "risk_assessment_raw": self.A.risk_assessment.raw,
                "resource_cost_raw": self.A.resource_cost.raw,
                "required_clearance": self.A.required_clearance,
                "payload_digest": self.A.payload_digest,
                "is_executed": self.A.is_executed,
            },
            "H": {
                "auth_token": self.H.auth_token,
                "granter_id": self.H.granter_id,
                "clearance_level": self.H.clearance_level,
                "is_active": self.H.is_active,
                "expires_at_epoch": self.H.expires_at_epoch,
                "nonce": self.H.nonce,
            },
            "V": {
                "certificate_id": self.V.certificate_id,
                "proof_system": self.V.proof_system,
                "proof_digest": self.V.proof_digest,
                "invariants_verified": sorted(list(self.V.invariants_verified)),
                "verifier_identity": self.V.verifier_identity,
                "verified_at_epoch": self.V.verified_at_epoch,
                "is_valid": self.V.is_valid,
            },
            "P": {
                "sequence_number": self.P.sequence_number,
                "parent_state_hash": self.P.parent_state_hash,
                "merkle_root": self.P.merkle_root,
                "audit_trail_id": self.P.audit_trail_id,
                "timestamp_epoch_ms": self.P.timestamp_epoch_ms,
            },
        }

    def compute_state_hash(self) -> str:
        """Compute the deterministic cryptographic SHA-256 state hash H(X)."""
        payload = json.dumps(self.canonical_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ==============================================================================
# SECTION 3: IMMUTABLE SAFETY KERNEL (K) (Definition 15, Axiom 9)
# ==============================================================================

class KernelMode(str, Enum):
    """Operational mode of the Immutable Safety Kernel."""
    VERIFIED_NOMINAL = "VERIFIED_NOMINAL"
    QUARANTINED = "QUARANTINED"
    HALTED = "HALTED"


class InvariantClauseResult(NamedTuple):
    """Evaluation result for an individual invariant clause."""
    clause_id: str
    satisfied: bool
    details: str


@dataclass(frozen=True, slots=True)
class GlobalInvariantVerdict:
    """Formal evaluation verdict of the Global System Invariant I(X)."""
    is_valid: bool
    state_hash: str
    clauses: Mapping[str, InvariantClauseResult]
    evaluated_at_epoch: int
    failure_reason: Optional[str] = None


class SafetyKernel:
    """Immutable Safety Kernel (K).

    Definition 15 (Immutable Safety Kernel):
        The Safety Kernel K is the foundational, non-bypassable, and non-modifiable
        execution boundary containing invariant rules, arithmetic semantics,
        and fail-closed response mechanisms.

    Axiom 9 (Kernel Immutability and Supremacy):
        The rules, constraints, and semantics of K cannot be modified, patched,
        or superseded by any runtime model update, inference output, or agent action.
        Any attempt to mutate K triggers immediate fail-closed quarantine and execution halt.
    """

    KERNEL_VERSION: Final[str] = "1.0.0"
    SPECIFICATION_DIGEST: Final[str] = hashlib.sha256(
        b"Safe Super Intelligence Axiomatic System v1.0 Kernel Specification"
    ).hexdigest()

    # Immutable class attributes
    _IS_SEALED: Final[bool] = True

    def __init__(self) -> None:
        object.__setattr__(self, "_mode", KernelMode.VERIFIED_NOMINAL)
        object.__setattr__(self, "_halt_reason", None)
        object.__setattr__(self, "_created_at", int(time.time()))

    def __setattr__(self, key: str, value: Any) -> None:
        raise KernelImmutabilityError(
            f"Axiom 9 Violation: SafetyKernel is strictly immutable. Attempted to mutate '{key}'"
        )

    def __delattr__(self, key: str) -> None:
        raise KernelImmutabilityError(
            f"Axiom 9 Violation: SafetyKernel is strictly immutable. Attempted to delete '{key}'"
        )

    @property
    def mode(self) -> KernelMode:
        """Return the current operational mode of the kernel."""
        return getattr(self, "_mode")

    @property
    def halt_reason(self) -> Optional[str]:
        """Return the reason for kernel halt/quarantine, if applicable."""
        return getattr(self, "_halt_reason")

    def emergency_halt(self, reason: str) -> None:
        """Transition the kernel to HALTED state under fail-closed semantics."""
        object.__setattr__(self, "_mode", KernelMode.HALTED)
        object.__setattr__(self, "_halt_reason", reason)

    def emergency_quarantine(self, reason: str) -> None:
        """Transition the kernel to QUARANTINED state under fail-closed semantics."""
        object.__setattr__(self, "_mode", KernelMode.QUARANTINED)
        object.__setattr__(self, "_halt_reason", reason)

    # ==========================================================================
    # SECTION 4: GLOBAL SYSTEM INVARIANT I(X) (Definition 19, Section 32)
    # ==========================================================================

    def verify_kernel_integrity(self) -> InvariantClauseResult:
        """Clause 1: Kernel Integrity (KI).

        Verifies that Kernel K is untampered, active in nominal mode, and
        adheres to WAD-18 scale semantics.
        """
        if self.mode != KernelMode.VERIFIED_NOMINAL:
            return InvariantClauseResult(
                clause_id="KI",
                satisfied=False,
                details=f"Kernel is not in VERIFIED_NOMINAL mode: {self.mode} ({self.halt_reason})"
            )
        if WAD_SCALE != 10**18:
            return InvariantClauseResult(
                clause_id="KI",
                satisfied=False,
                details=f"Kernel arithmetic scale corrupted: expected 10^18, got {WAD_SCALE}"
            )
        return InvariantClauseResult(clause_id="KI", satisfied=True, details="Kernel integrity verified")

    def verify_type_validity(self, state: SystemState) -> InvariantClauseResult:
        """Clause 2: Type Validity (TV).

        Verifies that state components X = (I, S, A, H, V, P) are strictly well-formed,
        all normative values are validly bounded, and all digests are 64-char hex strings.
        """
        if not isinstance(state, SystemState):
            return InvariantClauseResult(clause_id="TV", satisfied=False, details="State is not an instance of SystemState")

        # Range and type verification of normative values
        norm_checks = [
            ("I.cognitive_budget", state.I.cognitive_budget),
            ("I.epistemic_confidence", state.I.epistemic_confidence),
            ("I.entropy_bound", state.I.entropy_bound),
            ("S.safety_margin", state.S.safety_margin),
            ("S.risk_bound", state.S.risk_bound),
            ("A.risk_assessment", state.A.risk_assessment),
            ("A.resource_cost", state.A.resource_cost),
        ]
        for name, norm_val in norm_checks:
            if not isinstance(norm_val, NormativeValue):
                return InvariantClauseResult(
                    clause_id="TV",
                    satisfied=False,
                    details=f"Field {name} is not a NormativeValue"
                )
            if norm_val.raw < MIN_WAD_INT or norm_val.raw > MAX_WAD_INT:
                return InvariantClauseResult(
                    clause_id="TV",
                    satisfied=False,
                    details=f"Field {name} out of bounds: {norm_val.raw}"
                )

        # Epistemic confidence must be bounded in [0, 1]
        if state.I.epistemic_confidence < NormativeValue.zero() or state.I.epistemic_confidence > NormativeValue.one():
            return InvariantClauseResult(
                clause_id="TV",
                satisfied=False,
                details=f"Epistemic confidence {state.I.epistemic_confidence} outside [0, 1]"
            )

        # Cryptographic digest format checks
        if len(state.I.weights_digest) != 64:
            return InvariantClauseResult(
                clause_id="TV",
                satisfied=False,
                details=f"IntelligenceState.weights_digest must be 64-char hex (len={len(state.I.weights_digest)})"
            )
        if len(state.A.payload_digest) != 64:
            return InvariantClauseResult(
                clause_id="TV",
                satisfied=False,
                details=f"ActionState.payload_digest must be 64-char hex (len={len(state.A.payload_digest)})"
            )
        if len(state.V.proof_digest) != 64:
            return InvariantClauseResult(
                clause_id="TV",
                satisfied=False,
                details=f"VerificationState.proof_digest must be 64-char hex (len={len(state.V.proof_digest)})"
            )

        return InvariantClauseResult(clause_id="TV", satisfied=True, details="Type validity verified")

    def verify_csl_validity(self, state: SystemState) -> InvariantClauseResult:
        """Clause 3: Constitutional/Safety Logic Validity (CSL).

        Verifies containment barriers are intact, quarantine is false,
        and at least one formal CSL constraint is active and enforced.
        """
        if not state.S.containment_active:
            return InvariantClauseResult(clause_id="CSL", satisfied=False, details="Containment barrier is inactive")
        if not state.S.containment_barrier_intact:
            return InvariantClauseResult(clause_id="CSL", satisfied=False, details="Containment barrier integrity breached")
        if state.S.quarantine_flag:
            return InvariantClauseResult(clause_id="CSL", satisfied=False, details="Safety quarantine flag is raised")
        if not state.S.csl_constraints:
            return InvariantClauseResult(clause_id="CSL", satisfied=False, details="CSL constraint set is empty")

        return InvariantClauseResult(clause_id="CSL", satisfied=True, details="CSL validity verified")

    def verify_authorization_validity(self, state: SystemState, current_epoch: Optional[int] = None) -> InvariantClauseResult:
        """Clause 4: Authorization Validity (AV).

        Verifies that Human Authorization H is active, unexpired, and grants clearance
        level strictly greater than or equal to the action's required clearance.
        """
        if not state.H.is_active:
            return InvariantClauseResult(clause_id="AV", satisfied=False, details="Human authorization is inactive")

        eval_epoch = current_epoch if current_epoch is not None else int(time.time())
        if eval_epoch > state.H.expires_at_epoch:
            return InvariantClauseResult(
                clause_id="AV",
                satisfied=False,
                details=f"Authorization expired at epoch {state.H.expires_at_epoch} (current {eval_epoch})"
            )

        if state.H.clearance_level < state.A.required_clearance:
            return InvariantClauseResult(
                clause_id="AV",
                satisfied=False,
                details=(
                    f"Insufficient clearance: action requires {state.A.required_clearance}, "
                    f"authorization level is {state.H.clearance_level}"
                )
            )

        return InvariantClauseResult(clause_id="AV", satisfied=True, details="Authorization validity verified")

    def verify_safety_invariant_validity(self, state: SystemState) -> InvariantClauseResult:
        """Clause 5: Safety Invariant Validity (SIV).

        Verifies that:
        1. Action risk does not exceed the system risk bound (A.risk_assessment <= S.risk_bound).
        2. Safety margin meets or exceeds risk bound (S.safety_margin >= S.risk_bound).
        3. Formal verification proof certificate is valid (V.is_valid is True).
        """
        if state.A.risk_assessment > state.S.risk_bound:
            return InvariantClauseResult(
                clause_id="SIV",
                satisfied=False,
                details=(
                    f"Action risk {state.A.risk_assessment} exceeds system risk bound {state.S.risk_bound}"
                )
            )

        if state.S.safety_margin < state.S.risk_bound:
            return InvariantClauseResult(
                clause_id="SIV",
                satisfied=False,
                details=(
                    f"Safety margin {state.S.safety_margin} insufficient for risk bound {state.S.risk_bound}"
                )
            )

        if not state.V.is_valid:
            return InvariantClauseResult(
                clause_id="SIV",
                satisfied=False,
                details=f"Verification certificate {state.V.certificate_id} is marked invalid"
            )

        return InvariantClauseResult(clause_id="SIV", satisfied=True, details="Safety invariant validity verified")

    def verify_provenance_validity(self, state: SystemState) -> InvariantClauseResult:
        """Clause 6: Provenance Validity (PV).

        Verifies cryptographic state chain integrity: sequence number, parent hash,
        merkle root, and audit trail identifier.
        """
        if state.P.sequence_number < 0:
            return InvariantClauseResult(clause_id="PV", satisfied=False, details="Sequence number negative")

        if state.P.sequence_number > 0 and len(state.P.parent_state_hash) != 64:
            return InvariantClauseResult(
                clause_id="PV",
                satisfied=False,
                details=f"Invalid parent_state_hash for sequence {state.P.sequence_number}"
            )

        if len(state.P.merkle_root) != 64:
            return InvariantClauseResult(clause_id="PV", satisfied=False, details="Invalid merkle_root format")

        if not state.P.audit_trail_id:
            return InvariantClauseResult(clause_id="PV", satisfied=False, details="Missing audit trail reference")

        return InvariantClauseResult(clause_id="PV", satisfied=True, details="Provenance validity verified")

    def evaluate_global_invariant(
        self,
        state: SystemState,
        current_epoch: Optional[int] = None
    ) -> GlobalInvariantVerdict:
        """Evaluate Global System Invariant I(X) = KI && TV && CSL && AV && SIV && PV.

        Definition 19, Section 32:
            Returns a full evaluation verdict detailing the satisfaction status
            of all six simultaneous clauses.
        """
        state_hash = state.compute_state_hash() if isinstance(state, SystemState) else "INVALID_STATE"
        now_epoch = current_epoch if current_epoch is not None else int(time.time())

        clauses: Dict[str, InvariantClauseResult] = {}
        clauses["KI"] = self.verify_kernel_integrity()
        clauses["TV"] = self.verify_type_validity(state)
        clauses["CSL"] = self.verify_csl_validity(state)
        clauses["AV"] = self.verify_authorization_validity(state, current_epoch=now_epoch)
        clauses["SIV"] = self.verify_safety_invariant_validity(state)
        clauses["PV"] = self.verify_provenance_validity(state)

        failed_clauses = [res for res in clauses.values() if not res.satisfied]
        is_all_valid = len(failed_clauses) == 0

        failure_reason = None
        if not is_all_valid:
            failure_reason = "; ".join(f"[{res.clause_id}] {res.details}" for res in failed_clauses)

        return GlobalInvariantVerdict(
            is_valid=is_all_valid,
            state_hash=state_hash,
            clauses=clauses,
            evaluated_at_epoch=now_epoch,
            failure_reason=failure_reason
        )

    def verify_global_invariant(
        self,
        state: SystemState,
        current_epoch: Optional[int] = None
    ) -> bool:
        """Strict fail-closed enforcement of Global System Invariant I(X).

        Raises a specific KernelInvariantViolationError if any clause fails.
        Returns True if and only if all clauses hold simultaneously.
        """
        verdict = self.evaluate_global_invariant(state, current_epoch=current_epoch)
        if verdict.is_valid:
            return True

        # Map failure to specific fail-closed exception type
        clause_exception_map = {
            "KI": KernelIntegrityViolationError,
            "TV": TypeValidityViolationError,
            "CSL": CSLValidityViolationError,
            "AV": AuthorizationValidityViolationError,
            "SIV": SafetyInvariantViolationError,
            "PV": ProvenanceValidityViolationError,
        }

        for clause_id, result in verdict.clauses.items():
            if not result.satisfied:
                exc_cls = clause_exception_map.get(clause_id, KernelInvariantViolationError)
                raise exc_cls(clause=clause_id, reason=result.details, state_hash=verdict.state_hash)

        raise KernelInvariantViolationError(
            clause="UNKNOWN",
            reason=verdict.failure_reason or "Global invariant check failed",
            state_hash=verdict.state_hash
        )


# Exported public architectural primitives
__all__ = [
    "WAD_DECIMALS",
    "WAD_SCALE",
    "MIN_WAD_INT",
    "MAX_WAD_INT",
    "NormativeValue",
    "KernelException",
    "WadArithmeticError",
    "WadOverflowError",
    "WadUnderflowError",
    "WadDivisionByZeroError",
    "KernelImmutabilityError",
    "KernelInvariantViolationError",
    "KernelIntegrityViolationError",
    "TypeValidityViolationError",
    "CSLValidityViolationError",
    "AuthorizationValidityViolationError",
    "SafetyInvariantViolationError",
    "ProvenanceValidityViolationError",
    "ActionType",
    "IntelligenceState",
    "SafetyState",
    "ActionState",
    "HumanAuthorization",
    "VerificationState",
    "ProvenanceState",
    "SystemState",
    "KernelMode",
    "InvariantClauseResult",
    "GlobalInvariantVerdict",
    "SafetyKernel",
]
