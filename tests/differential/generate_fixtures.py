#!/usr/bin/env python3
"""Generate shared test fixtures and evaluate Python oracle decisions."""

import json
import sys
from pathlib import Path

# Add project root to sys.path
ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

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
from core.gate import VerificationStatus, evaluate_permit

def make_base_state():
    I = IntelligenceState(
        model_id="model-oracle",
        weights_digest="a" * 64,
        context_window_size=128000,
        cognitive_budget=NormativeValue.from_raw(100 * 10**18),
        epistemic_confidence=NormativeValue.from_str("0.995"),
        entropy_bound=NormativeValue.from_str("0.02"),
        capabilities=frozenset({"COMPUTE", "READ", "SAFE_DISPATCH"}),
    )
    S = SafetyState(
        containment_active=True,
        containment_barrier_intact=True,
        safety_margin=NormativeValue.from_raw(8 * 10**17),
        risk_bound=NormativeValue.from_raw(3 * 10**17),
        active_envelope_id="ENV-0",
        csl_constraints=frozenset({"NON_DECEPTION", "CONTAINMENT_INTEGRITY", "BUDGET_CEILING"}),
        quarantine_flag=False,
    )
    A = ActionState(
        action_id="act-oracle-0",
        action_type=ActionType.COMPUTE,
        risk_assessment=NormativeValue.from_raw(1 * 10**17),
        resource_cost=NormativeValue.from_raw(1 * 10**18),
        required_clearance=2,
        payload_digest="b" * 64,
        is_executed=False,
    )
    H = HumanAuthorization(
        auth_token="auth-token-oracle",
        granter_id="lead-safety-architect",
        clearance_level=3,
        is_active=True,
        expires_at_epoch=1800000000,
        nonce="nonce-oracle-0",
    )
    V = VerificationState(
        certificate_id="cert-oracle-0",
        proof_system="SSI_ORACLE",
        proof_digest="c" * 64,
        invariants_verified=frozenset({"TypeValid", "SafetyValid"}),
        verifier_identity="GATE_ROOT",
        verified_at_epoch=1700000000,
        is_valid=True,
    )
    P = ProvenanceState(
        sequence_number=1,
        parent_state_hash="d" * 64,
        merkle_root="e" * 64,
        audit_trail_id="audit-oracle-0",
        timestamp_epoch_ms=1700000000000,
    )
    return SystemState(I=I, S=S, A=A, H=H, V=V, P=P)

def serialize_state(s: SystemState):
    return {
        "I": {
            "model_id": s.I.model_id,
            "weights_digest": s.I.weights_digest,
            "context_window_size": s.I.context_window_size,
            "cognitive_budget_raw": s.I.cognitive_budget.raw,
            "epistemic_confidence_raw": s.I.epistemic_confidence.raw,
            "entropy_bound_raw": s.I.entropy_bound.raw,
            "capabilities": sorted(list(s.I.capabilities)),
        },
        "S": {
            "containment_active": s.S.containment_active,
            "containment_barrier_intact": s.S.containment_barrier_intact,
            "safety_margin_raw": s.S.safety_margin.raw,
            "risk_bound_raw": s.S.risk_bound.raw,
            "active_envelope_id": s.S.active_envelope_id,
            "csl_constraints": sorted(list(s.S.csl_constraints)),
            "quarantine_flag": s.S.quarantine_flag,
        },
        "A": {
            "action_id": s.A.action_id,
            "action_type": s.A.action_type.value,
            "risk_assessment_raw": s.A.risk_assessment.raw,
            "resource_cost_raw": s.A.resource_cost.raw,
            "required_clearance": s.A.required_clearance,
            "payload_digest": s.A.payload_digest,
            "is_executed": s.A.is_executed,
        },
        "H": {
            "auth_token": s.H.auth_token,
            "granter_id": s.H.granter_id,
            "clearance_level": s.H.clearance_level,
            "is_active": s.H.is_active,
            "expires_at_epoch": s.H.expires_at_epoch,
            "nonce": s.H.nonce,
        },
        "V": {
            "certificate_id": s.V.certificate_id,
            "proof_system": s.V.proof_system,
            "proof_digest": s.V.proof_digest,
            "invariants_verified": sorted(list(s.V.invariants_verified)),
            "verifier_identity": s.V.verifier_identity,
            "verified_at_epoch": s.V.verified_at_epoch,
            "is_valid": s.V.is_valid,
        },
        "P": {
            "sequence_number": s.P.sequence_number,
            "parent_state_hash": s.P.parent_state_hash,
            "merkle_root": s.P.merkle_root,
            "audit_trail_id": s.P.audit_trail_id,
            "timestamp_epoch_ms": s.P.timestamp_epoch_ms,
        },
    }

def generate_fixtures():
    fixtures = []
    current_epoch = 1700000000

    scenarios = [
        ("nominal_pass", {}, {}, "VALID", None),
        ("nominal_with_req_cap", {}, {}, "VALID", "COMPUTE"),
        ("auth_inactive", {"H_is_active": False}, {}, "VALID", None),
        ("auth_expired", {"H_expires_at": current_epoch - 100}, {}, "VALID", None),
        ("clearance_insufficient", {"H_clearance": 1, "A_req_clearance": 3}, {}, "VALID", None),
        ("empty_token", {"H_token": ""}, {}, "VALID", None),
        ("empty_nonce", {"H_nonce": ""}, {}, "VALID", None),
        ("containment_inactive", {"S_containment": False}, {}, "VALID", None),
        ("barrier_breached", {"S_barrier": False}, {}, "VALID", None),
        ("quarantine_raised", {"S_quarantine": True}, {}, "VALID", None),
        ("emergency_halt_action", {"A_type": ActionType.SYSTEM_HALT}, {}, "VALID", None),
        ("risk_exceeds_bound", {"A_risk": 5 * 10**17, "S_risk_bound": 2 * 10**17}, {}, "VALID", None),
        ("forbidden_keyword_exfiltrate", {"A_id": "act_exfiltrate_key"}, {}, "VALID", None),
        ("forbidden_keyword_exfiltrate_payload", {"A_id": "act_exfiltrate_payload"}, {}, "VALID", None),
        ("ver_unknown", {}, {}, "UNKNOWN", None),
        ("ver_invalid", {}, {}, "INVALID", None),
        ("cert_marked_invalid", {"V_valid": False}, {}, "VALID", None),
        ("payload_digest_invalid_len", {"A_payload": "abc"}, {}, "VALID", None),
        ("budget_overdraft", {"I_budget": 10**17, "A_cost": 5 * 10**18}, {}, "VALID", None),
        ("missing_capability", {}, {}, "VALID", "UNGRANTED_GPU_ACCESS"),
    ]

    for name, s_mods, a_mods, ver_str, req_cap in scenarios:
        s = make_base_state()
        
        # Apply modifications
        if "H_is_active" in s_mods:
            object.__setattr__(s.H, "is_active", s_mods["H_is_active"])
        if "H_expires_at" in s_mods:
            object.__setattr__(s.H, "expires_at_epoch", s_mods["H_expires_at"])
        if "H_clearance" in s_mods:
            object.__setattr__(s.H, "clearance_level", s_mods["H_clearance"])
        if "H_token" in s_mods:
            object.__setattr__(s.H, "auth_token", s_mods["H_token"])
        if "H_nonce" in s_mods:
            object.__setattr__(s.H, "nonce", s_mods["H_nonce"])
        if "S_containment" in s_mods:
            object.__setattr__(s.S, "containment_active", s_mods["S_containment"])
        if "S_barrier" in s_mods:
            object.__setattr__(s.S, "containment_barrier_intact", s_mods["S_barrier"])
        if "S_quarantine" in s_mods:
            object.__setattr__(s.S, "quarantine_flag", s_mods["S_quarantine"])
        if "S_risk_bound" in s_mods:
            object.__setattr__(s.S, "risk_bound", NormativeValue.from_raw(s_mods["S_risk_bound"]))
        if "A_type" in s_mods:
            object.__setattr__(s.A, "action_type", s_mods["A_type"])
        if "A_risk" in s_mods:
            object.__setattr__(s.A, "risk_assessment", NormativeValue.from_raw(s_mods["A_risk"]))
        if "A_cost" in s_mods:
            object.__setattr__(s.A, "resource_cost", NormativeValue.from_raw(s_mods["A_cost"]))
        if "A_req_clearance" in s_mods:
            object.__setattr__(s.A, "required_clearance", s_mods["A_req_clearance"])
        if "A_id" in s_mods:
            object.__setattr__(s.A, "action_id", s_mods["A_id"])
        if "A_payload" in s_mods:
            object.__setattr__(s.A, "payload_digest", s_mods["A_payload"])
        if "V_valid" in s_mods:
            object.__setattr__(s.V, "is_valid", s_mods["V_valid"])
        if "I_budget" in s_mods:
            object.__setattr__(s.I, "cognitive_budget", NormativeValue.from_raw(s_mods["I_budget"]))

        v_status = VerificationStatus[ver_str]
        oracle_res = evaluate_permit(
            state=s,
            action=s.A,
            required_capability=req_cap,
            current_epoch=current_epoch,
            verification_status=v_status,
        )

        fixtures.append({
            "name": name,
            "current_epoch": current_epoch,
            "ver_status": ver_str,
            "required_capability": req_cap,
            "state": serialize_state(s),
            "expected": {
                "decision": oracle_res.decision.value,
                "auth_valid": oracle_res.auth_valid,
                "safe_action_valid": oracle_res.safe_action_valid,
                "ver_valid": oracle_res.ver_valid,
                "cap_valid": oracle_res.cap_valid,
                "reasons_count": len(oracle_res.failure_reasons),
            }
        })

    out_path = ROOT / "tests" / "differential" / "fixtures.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(fixtures, f, indent=2)

    print(f"Generated {len(fixtures)} shared differential fixtures at {out_path}")

if __name__ == "__main__":
    generate_fixtures()
