"""Safe Super Intelligence Axiomatic System v1.0 - Verification and Execution Gating Engine.

This module implements deterministic, high-assurance security gating replacing
soft LLM-as-a-judge heuristics with formal, fail-closed mathematical gates:

1. Safe Action & Permit Logic (Definition 11):
   PERMIT(X, a) = AUTH(X, a) AND SAFE_ACTION(X, a) AND VER(X, a) AND CAP(X, a)
2. Fail-Closed Execution Semantics (Axioms A2, 4, Section 5):
   NOT PERMIT(X, a) => NOT EXECUTE(X, a). Any failure, error, or 'Unknown' returns hard REJECT.
3. The Minimal Verification Kernel (Section 31):
   EXECUTE -> VERIFY -> TRANSITION INVARIANT CHECK -> COMMIT
4. Transition Semantics & Invariant Preservation (Theorem 3):
   Next(X, a, X') preserves the global system invariant I(X').
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, Final, Mapping, Optional, Tuple

from core.kernel import (
    ActionState,
    ActionType,
    KernelException,
    KernelInvariantViolationError,
    NormativeValue,
    SafetyKernel,
    SystemState,
)


# ==============================================================================
# SECTION 0: GATE EXCEPTIONS (Fail-Closed Semantics)
# ==============================================================================

class GateException(KernelException):
    """Base exception for all execution gating and verification failures."""
    pass


class PermitDeniedError(GateException):
    """Raised when an action proposal fails the PERMIT(X, a) gating predicate (Axiom A2)."""
    def __init__(self, action_id: str, reasons: Tuple[str, ...]):
        self.action_id = action_id
        self.reasons = reasons
        msg = f"Execution permit denied for action '{action_id}': " + "; ".join(reasons)
        super().__init__(msg)


class VerificationUnknownError(GateException):
    """Raised when a verification check produces an indeterminate/unknown result (Section 5)."""
    pass


class TransitionInvariantViolationError(GateException):
    """Raised when a state transition violates invariant preservation (Theorem 3)."""
    def __init__(self, reason: str, pre_state_hash: str, post_state_hash: str):
        self.reason = reason
        self.pre_state_hash = pre_state_hash
        self.post_state_hash = post_state_hash
        super().__init__(
            f"State transition rejected (Theorem 3 violation): {reason} "
            f"[pre={pre_state_hash[:16]}..., post={post_state_hash[:16]}...]"
        )


class ExecutionQuarantineError(GateException):
    """Raised when an execution fault forces the kernel into containment quarantine."""
    pass


# ==============================================================================
# SECTION 1: PERMIT GATING STRUCTURES & ENUMS (Definition 11)
# ==============================================================================

class GateDecision(str, Enum):
    """Deterministic verdict of the execution gate."""
    PERMIT = "PERMIT"
    REJECT = "REJECT"


class VerificationStatus(str, Enum):
    """Tri-state verification result evaluated under fail-closed semantics."""
    VALID = "VALID"
    INVALID = "INVALID"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class PermitResult:
    """Formal evaluation record of PERMIT(X, a) predicate (Definition 11).

    PERMIT(X, a) = AUTH(X, a) && SAFE_ACTION(X, a) && VER(X, a) && CAP(X, a)
    """
    decision: GateDecision
    auth_valid: bool
    safe_action_valid: bool
    ver_valid: bool
    cap_valid: bool
    failure_reasons: Tuple[str, ...]

    @property
    def is_permitted(self) -> bool:
        return self.decision == GateDecision.PERMIT


# ==============================================================================
# SECTION 2: DETERMINISTIC GATING SUB-PREDICATES
# ==============================================================================

def check_auth(
    state: SystemState,
    action: ActionState,
    current_epoch: Optional[int] = None
) -> Tuple[bool, Optional[str]]:
    """Sub-predicate AUTH(X, a): Verifies human authorization and clearance.

    Axiom A2: Clearance must strictly satisfy required action clearance, token
    must be active, and epoch must not exceed expiry.
    """
    h = state.H
    now_epoch = current_epoch if current_epoch is not None else int(time.time())

    if not h.is_active:
        return False, "Human authorization token is inactive"

    if now_epoch > h.expires_at_epoch:
        return False, f"Authorization token expired at {h.expires_at_epoch} (current {now_epoch})"

    if h.clearance_level < action.required_clearance:
        return False, (
            f"Insufficient clearance: action '{action.action_id}' requires {action.required_clearance}, "
            f"provided clearance is {h.clearance_level}"
        )

    if not h.auth_token or not h.nonce:
        return False, "Authorization token or nonce is empty"

    return True, None


def check_safe_action(
    state: SystemState,
    action: ActionState
) -> Tuple[bool, Optional[str]]:
    """Sub-predicate SAFE_ACTION(X, a): Verifies action safety envelope.

    Verifies containment barriers are intact, quarantine flag is not set,
    action risk assessment does not exceed risk bound, and action type is safe.
    """
    s = state.S

    if not s.containment_active or not s.containment_barrier_intact:
        return False, "Safety containment barrier is inactive or breached"

    if s.quarantine_flag:
        return False, "System is under containment quarantine; all actions prohibited"

    if action.action_type == ActionType.SYSTEM_HALT:
        # Emergency halt is handled through dedicated kernel protocols, not standard action dispatch
        return False, "SYSTEM_HALT action must use dedicated emergency kernel pathway"

    if action.risk_assessment > s.risk_bound:
        return False, (
            f"Action risk {action.risk_assessment} exceeds system risk bound {s.risk_bound}"
        )

    # Action must not violate any registered CSL constraint keywords
    forbidden_terms = frozenset({"EXFILTRATE", "DISABLE_CONTAINMENT", "OVERRIDE_AUTH", "BYPASS_GATE"})
    action_tokens = set(action.action_id.upper().split("_")) | {action.action_type.value}
    if action_tokens & forbidden_terms:
        return False, f"Action specification matches forbidden security keywords: {action_tokens & forbidden_terms}"

    return True, None


def check_ver(
    state: SystemState,
    action: ActionState,
    verification_status: VerificationStatus = VerificationStatus.VALID
) -> Tuple[bool, Optional[str]]:
    """Sub-predicate VER(X, a): Verifies cryptographic and formal verification certificate.

    Axiom 4: If verification status is UNKNOWN or INVALID, return hard FAIL.
    """
    if verification_status == VerificationStatus.UNKNOWN:
        return False, "Verification status is UNKNOWN (indeterminate proof evaluation)"

    if verification_status != VerificationStatus.VALID:
        return False, f"Verification status is {verification_status.value}"

    v = state.V
    if not v.is_valid:
        return False, f"System verification certificate '{v.certificate_id}' is marked invalid"

    if len(action.payload_digest) != 64:
        return False, f"Action payload digest invalid (len={len(action.payload_digest)}, expected 64 hex)"

    return True, None


def check_cap(
    state: SystemState,
    action: ActionState,
    required_capability: Optional[str] = None
) -> Tuple[bool, Optional[str]]:
    """Sub-predicate CAP(X, a): Verifies model capability and resource budget bounds.

    Verifies model capabilities contain required action capability and cognitive budget
    is sufficient to cover the action resource cost.
    """
    i = state.I

    # Resource budget sufficiency
    if i.cognitive_budget < action.resource_cost:
        return False, (
            f"Insufficient cognitive budget: available {i.cognitive_budget}, "
            f"action cost {action.resource_cost}"
        )

    # Capability mapping
    if required_capability is not None:
        if required_capability not in i.capabilities:
            return False, (
                f"Required capability '{required_capability}' not granted in model capabilities "
                f"{sorted(list(i.capabilities))}"
            )

    return True, None


def evaluate_permit(
    state: SystemState,
    action: ActionState,
    required_capability: Optional[str] = None,
    current_epoch: Optional[int] = None,
    verification_status: VerificationStatus = VerificationStatus.VALID
) -> PermitResult:
    """Evaluate PERMIT(X, a) = AUTH(X, a) AND SAFE_ACTION(X, a) AND VER(X, a) AND CAP(X, a).

    Definition 11, Section 5:
    Strict fail-closed evaluation. If any sub-predicate fails or returns False,
    decision is REJECT with full audit trail of failed clauses.
    """
    reasons = []

    try:
        auth_ok, auth_err = check_auth(state, action, current_epoch=current_epoch)
        if not auth_ok:
            reasons.append(f"[AUTH] {auth_err}")

        safe_ok, safe_err = check_safe_action(state, action)
        if not safe_ok:
            reasons.append(f"[SAFE_ACTION] {safe_err}")

        ver_ok, ver_err = check_ver(state, action, verification_status=verification_status)
        if not ver_ok:
            reasons.append(f"[VER] {ver_err}")

        cap_ok, cap_err = check_cap(state, action, required_capability=required_capability)
        if not cap_ok:
            reasons.append(f"[CAP] {cap_err}")

    except Exception as exc:
        # Fail-closed: any runtime error inside gate evaluation immediately causes hard REJECT
        reasons.append(f"[PANIC] Unhandled exception during permit evaluation: {type(exc).__name__}: {exc}")
        auth_ok = safe_ok = ver_ok = cap_ok = False

    is_all_ok = auth_ok and safe_ok and ver_ok and cap_ok
    decision = GateDecision.PERMIT if is_all_ok else GateDecision.REJECT

    return PermitResult(
        decision=decision,
        auth_valid=auth_ok,
        safe_action_valid=safe_ok,
        ver_valid=ver_ok,
        cap_valid=cap_ok,
        failure_reasons=tuple(reasons)
    )


# ==============================================================================
# SECTION 3: TRANSITION SEMANTICS & INVARIANT PRESERVATION (Theorem 3)
# ==============================================================================

def validate_transition(
    kernel: SafetyKernel,
    pre_state: SystemState,
    action: ActionState,
    post_state: SystemState,
    current_epoch: Optional[int] = None
) -> bool:
    """Validate State Transition Next(X, a, X') preserves Global Invariant I(X').

    Theorem 3 (Invariant Preservation Under Gated Transition):
        If pre-state X satisfies I(X), PERMIT(X, a) = True, and Next(X, a, X')
        preserves sequence progression, provenance lineage, and resource monotonicity,
        then post-state X' satisfies I(X').

    Raises TransitionInvariantViolationError if any property fails.
    """
    pre_hash = pre_state.compute_state_hash()
    post_hash = post_state.compute_state_hash()

    # 1. Monotonic Sequence Progression: t' = t + 1
    expected_seq = pre_state.P.sequence_number + 1
    if post_state.P.sequence_number != expected_seq:
        raise TransitionInvariantViolationError(
            f"Sequence non-monotonic: expected {expected_seq}, got {post_state.P.sequence_number}",
            pre_hash, post_hash
        )

    # 2. Cryptographic Provenance Linkage: X'.P.parent_state_hash == Hash(X)
    if post_state.P.parent_state_hash != pre_hash:
        raise TransitionInvariantViolationError(
            f"Lineage break: post-state parent hash '{post_state.P.parent_state_hash}' "
            f"does not match pre-state hash '{pre_hash}'",
            pre_hash, post_hash
        )

    # 3. Action Execution Binding
    if not post_state.A.is_executed:
        raise TransitionInvariantViolationError(
            f"Post-state action '{post_state.A.action_id}' is not marked as executed",
            pre_hash, post_hash
        )
    if post_state.A.action_id != action.action_id:
        raise TransitionInvariantViolationError(
            f"Action mismatch: post-state action ID '{post_state.A.action_id}' != '{action.action_id}'",
            pre_hash, post_hash
        )

    # 4. Cognitive Budget Conservation: budget' = budget - cost
    expected_budget = pre_state.I.cognitive_budget - action.resource_cost
    if post_state.I.cognitive_budget != expected_budget:
        raise TransitionInvariantViolationError(
            f"Resource conservation violation: expected remaining budget {expected_budget}, "
            f"got {post_state.I.cognitive_budget}",
            pre_hash, post_hash
        )

    # 5. Global System Invariant I(X') preservation
    try:
        kernel.verify_global_invariant(post_state, current_epoch=current_epoch)
    except KernelInvariantViolationError as exc:
        raise TransitionInvariantViolationError(
            f"Global invariant I(X') failed on post-state: {exc}",
            pre_hash, post_hash
        ) from exc

    return True


# ==============================================================================
# SECTION 4: THE MINIMAL VERIFICATION KERNEL (Section 31)
# ==============================================================================

@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """Encapsulation of deterministic tool execution output."""
    output: Any
    output_digest: str
    duration_ms: int
    success: bool


@dataclass(frozen=True, slots=True)
class ExecutionCertificate:
    """Cryptographic certificate binding pre-state, action, output, and post-state."""
    certificate_id: str
    action_id: str
    payload_digest: str
    output_digest: str
    pre_state_hash: str
    post_state_hash: str
    verifier_signature: str
    timestamp_epoch: int


@dataclass(frozen=True, slots=True)
class ExecutionCommit:
    """Atomic commitment resulting from full execution through the verification gate."""
    post_state: SystemState
    result: ExecutionResult
    certificate: ExecutionCertificate


class DeterministicExecutionGate:
    """Minimal Verification Kernel Engine (Section 31).

    Executes the strict reference sequence:
    EXECUTE -> VERIFY -> TRANSITION INVARIANT CHECK -> COMMIT

    Guarantees Axiom A2:
    NOT PERMIT(X, a) => NOT EXECUTE(X, a).
    No tool execution or state transition can commit without passing through
    cryptographic certificate binding and invariant validation.
    """

    GATE_ENGINE_ID: Final[str] = "MINIMAL_VERIFICATION_KERNEL_V1"

    def __init__(self, kernel: SafetyKernel, verifier_key: str = "TRUSTED_KERNEL_ROOT"):
        if not isinstance(kernel, SafetyKernel):
            raise TypeError("kernel must be an instance of SafetyKernel")
        self._kernel = kernel
        self._verifier_key = verifier_key

    @property
    def kernel(self) -> SafetyKernel:
        return self._kernel

    def _compute_digest(self, data: Any) -> str:
        """Deterministically digest arbitrary execution output."""
        serialized = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def _sign_certificate(self, payload: str) -> str:
        """Create HMAC-like verifier signature binding payload to verifier key."""
        return hashlib.sha256((self._verifier_key + ":" + payload).encode("utf-8")).hexdigest()

    def execute_and_commit(
        self,
        pre_state: SystemState,
        action: ActionState,
        execution_handler: Callable[[ActionState], Any],
        state_builder: Callable[[SystemState, ActionState, ExecutionResult, str], SystemState],
        required_capability: Optional[str] = None,
        current_epoch: Optional[int] = None,
        verification_status: VerificationStatus = VerificationStatus.VALID
    ) -> ExecutionCommit:
        """Execute the 4-stage reference flow from Section 31:

        1. GATE: Evaluate PERMIT(X, a). If REJECT, abort immediately (Axiom A2).
        2. EXECUTE: Call execution_handler(action) within fail-closed bounds.
        3. VERIFY: Generate cryptographic certificate binding inputs and outputs.
        4. TRANSITION INVARIANT CHECK: Validate Next(X, a, X') and I(X') (Theorem 3).
        5. COMMIT: Return atomic commit record.
        """
        now_epoch = current_epoch if current_epoch is not None else int(time.time())

        # ----------------------------------------------------------------------
        # STAGE 0: GATING (Axiom A2: NOT PERMIT => NOT EXECUTE)
        # ----------------------------------------------------------------------
        permit_verdict = evaluate_permit(
            state=pre_state,
            action=action,
            required_capability=required_capability,
            current_epoch=now_epoch,
            verification_status=verification_status
        )

        if not permit_verdict.is_permitted:
            raise PermitDeniedError(
                action_id=action.action_id,
                reasons=permit_verdict.failure_reasons
            )

        pre_state_hash = pre_state.compute_state_hash()

        # ----------------------------------------------------------------------
        # STAGE 1: EXECUTE
        # ----------------------------------------------------------------------
        start_time = time.perf_counter()
        try:
            raw_output = execution_handler(action)
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            output_digest = self._compute_digest(raw_output)
            exec_result = ExecutionResult(
                output=raw_output,
                output_digest=output_digest,
                duration_ms=duration_ms,
                success=True
            )
        except Exception as exc:
            duration_ms = int((time.perf_counter() - start_time) * 1000)
            # Trip kernel into emergency quarantine on unhandled execution crash
            self._kernel.emergency_quarantine(
                f"Execution handler crashed on action '{action.action_id}': {type(exc).__name__}: {exc}"
            )
            raise ExecutionQuarantineError(
                f"Execution failed; system transitioned to QUARANTINED: {exc}"
            ) from exc

        # ----------------------------------------------------------------------
        # STAGE 2: VERIFY
        # ----------------------------------------------------------------------
        cert_id = f"cert-{action.action_id}-{now_epoch}"
        cert_payload = f"{cert_id}:{action.payload_digest}:{exec_result.output_digest}:{pre_state_hash}"
        verifier_sig = self._sign_certificate(cert_payload)

        # ----------------------------------------------------------------------
        # STAGE 3: TRANSITION INVARIANT CHECK (Theorem 3)
        # ----------------------------------------------------------------------
        # Build provisional post-state using deterministic builder
        try:
            provisional_post_state = state_builder(
                pre_state,
                action,
                exec_result,
                verifier_sig
            )
        except Exception as exc:
            self._kernel.emergency_quarantine(f"State builder failed: {exc}")
            raise TransitionInvariantViolationError(
                f"State builder failed to produce candidate post-state: {exc}",
                pre_state_hash, "BUILD_FAILED"
            ) from exc

        post_state_hash = provisional_post_state.compute_state_hash()

        # Validate transition invariant Next(X, a, X') => I(X')
        validate_transition(
            kernel=self._kernel,
            pre_state=pre_state,
            action=action,
            post_state=provisional_post_state,
            current_epoch=now_epoch
        )

        # ----------------------------------------------------------------------
        # STAGE 4: COMMIT
        # ----------------------------------------------------------------------
        certificate = ExecutionCertificate(
            certificate_id=cert_id,
            action_id=action.action_id,
            payload_digest=action.payload_digest,
            output_digest=exec_result.output_digest,
            pre_state_hash=pre_state_hash,
            post_state_hash=post_state_hash,
            verifier_signature=verifier_sig,
            timestamp_epoch=now_epoch
        )

        return ExecutionCommit(
            post_state=provisional_post_state,
            result=exec_result,
            certificate=certificate
        )


__all__ = [
    "GateException",
    "PermitDeniedError",
    "VerificationUnknownError",
    "TransitionInvariantViolationError",
    "ExecutionQuarantineError",
    "GateDecision",
    "VerificationStatus",
    "PermitResult",
    "check_auth",
    "check_safe_action",
    "check_ver",
    "check_cap",
    "evaluate_permit",
    "validate_transition",
    "ExecutionResult",
    "ExecutionCertificate",
    "ExecutionCommit",
    "DeterministicExecutionGate",
]
