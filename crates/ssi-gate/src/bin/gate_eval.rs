//! CLI tool for differential evaluation of PERMIT against the Python oracle.
//! Reads scenario JSON from stdin or arguments and prints evaluation result.

use std::collections::BTreeSet;
use std::env;
use std::io::{self, Read};
use ssi_gate::{GateDecision, VerificationStatus, evaluate_permit};
use ssi_kernel::{
    ActionProposal, ActionType, AuthorizationState, IntelligenceState, ProvenanceState,
    SafetyState, SystemState, VerificationState,
};
use wad18::Wad18;

fn main() {
    let args: Vec<String> = env::args().collect();
    let input = if args.len() > 1 {
        args[1].clone()
    } else {
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer).unwrap();
        buffer
    };

    if input.trim().is_empty() {
        eprintln!("Empty input");
        std::process::exit(1);
    }

    // Parse key-value parameters from JSON with flexible whitespace
    let get_str = |key: &str| -> Option<String> {
        let pattern = format!("\"{}\"", key);
        let key_pos = input.find(&pattern)?;
        let colon_pos = input[key_pos..].find(':')? + key_pos;
        let rest = input[colon_pos + 1..].trim_start();
        if rest.starts_with("null") || !rest.starts_with('"') {
            return None;
        }
        let quote_end = rest[1..].find('"')? + 1;
        Some(rest[1..quote_end].to_string())
    };

    let get_i128 = |key: &str| -> Option<i128> {
        let pattern = format!("\"{}\"", key);
        let key_pos = input.find(&pattern)?;
        let colon_pos = input[key_pos..].find(':')? + key_pos;
        let rest = input[colon_pos + 1..].trim_start();
        let end = rest.find(|c: char| !c.is_ascii_digit() && c != '-').unwrap_or(rest.len());
        rest[..end].trim().parse::<i128>().ok()
    };

    let get_i64 = |key: &str| -> Option<i64> {
        let pattern = format!("\"{}\"", key);
        let key_pos = input.find(&pattern)?;
        let colon_pos = input[key_pos..].find(':')? + key_pos;
        let rest = input[colon_pos + 1..].trim_start();
        let end = rest.find(|c: char| !c.is_ascii_digit() && c != '-').unwrap_or(rest.len());
        rest[..end].trim().parse::<i64>().ok()
    };

    let get_bool = |key: &str| -> Option<bool> {
        let pattern = format!("\"{}\"", key);
        let key_pos = input.find(&pattern)?;
        let colon_pos = input[key_pos..].find(':')? + key_pos;
        let rest = input[colon_pos + 1..].trim_start();
        if rest.starts_with("true") {
            Some(true)
        } else if rest.starts_with("false") {
            Some(false)
        } else {
            None
        }
    };

    let current_epoch = get_i64("current_epoch").unwrap_or(1_700_000_000);
    let ver_str = get_str("ver_status").unwrap_or_else(|| "VALID".into());
    let req_cap = get_str("required_capability");

    let ver_status = match ver_str.as_str() {
        "VALID" => VerificationStatus::Valid,
        "INVALID" => VerificationStatus::Invalid,
        _ => VerificationStatus::Unknown,
    };

    // Construct state
    let mut caps = BTreeSet::new();
    if input.contains("\"COMPUTE\"") { caps.insert("COMPUTE".into()); }
    if input.contains("\"READ\"") { caps.insert("READ".into()); }
    if input.contains("\"SAFE_DISPATCH\"") { caps.insert("SAFE_DISPATCH".into()); }

    let mut q = BTreeSet::new();
    q.insert("NON_DECEPTION".into());
    q.insert("CONTAINMENT_INTEGRITY".into());
    q.insert("BUDGET_CEILING".into());

    let act_type_str = get_str("action_type").unwrap_or_else(|| "COMPUTE".into());
    let act_type = match act_type_str.as_str() {
        "READ" => ActionType::Read,
        "COMMUNICATE" => ActionType::Communicate,
        "MUTATE_ENVIRONMENT" => ActionType::MutateEnvironment,
        "EXECUTE_CODE" => ActionType::ExecuteCode,
        "SYSTEM_HALT" => ActionType::SystemHalt,
        _ => ActionType::Compute,
    };

    let state = SystemState {
        intelligence: IntelligenceState {
            model_id: get_str("model_id").unwrap_or_else(|| "model".into()),
            weights_digest: get_str("weights_digest").unwrap_or_else(|| "a".repeat(64)),
            context_window_size: 128000,
            cognitive_budget: Wad18::from_raw(get_i128("cognitive_budget_raw").unwrap_or(100 * 10i128.pow(18))),
            epistemic_confidence: Wad18::from_raw(get_i128("epistemic_confidence_raw").unwrap_or(995 * 10i128.pow(15))),
            entropy_bound: Wad18::from_raw(get_i128("entropy_bound_raw").unwrap_or(20 * 10i128.pow(15))),
            capabilities: caps,
        },
        safety: SafetyState {
            containment_active: get_bool("containment_active").unwrap_or(true),
            containment_barrier_intact: get_bool("containment_barrier_intact").unwrap_or(true),
            safety_margin: Wad18::from_raw(get_i128("safety_margin_raw").unwrap_or(8 * 10i128.pow(17))),
            risk_bound: Wad18::from_raw(get_i128("risk_bound_raw").unwrap_or(3 * 10i128.pow(17))),
            active_envelope_id: "ENV-0".into(),
            csl_constraints: q,
            quarantine_flag: get_bool("quarantine_flag").unwrap_or(false),
        },
        action: ActionProposal {
            action_id: get_str("action_id").unwrap_or_else(|| "act-0".into()),
            action_type: act_type,
            risk_assessment: Wad18::from_raw(get_i128("risk_assessment_raw").unwrap_or(10i128.pow(17))),
            resource_cost: Wad18::from_raw(get_i128("resource_cost_raw").unwrap_or(10i128.pow(18))),
            required_clearance: get_i128("required_clearance").unwrap_or(2) as u32,
            payload_digest: get_str("payload_digest").unwrap_or_else(|| "b".repeat(64)),
            is_executed: false,
        },
        authorization: AuthorizationState {
            auth_token: get_str("auth_token").unwrap_or_else(|| "token".into()),
            granter_id: "auth".into(),
            clearance_level: get_i128("clearance_level").unwrap_or(3) as u32,
            is_active: get_bool("is_active").unwrap_or(true),
            expires_at_epoch: get_i64("expires_at_epoch").unwrap_or(1800000000),
            nonce: get_str("nonce").unwrap_or_else(|| "nonce".into()),
        },
        verification: VerificationState {
            certificate_id: "cert".into(),
            proof_system: "P".into(),
            proof_digest: "c".repeat(64),
            invariants_verified: BTreeSet::new(),
            verifier_identity: "V".into(),
            verified_at_epoch: 1700000000,
            is_valid: get_bool("is_valid").unwrap_or(true),
        },
        provenance: ProvenanceState {
            sequence_number: 1,
            parent_state_hash: "d".repeat(64),
            merkle_root: "e".repeat(64),
            audit_trail_id: "aud".into(),
            timestamp_epoch_ms: 1700000000000,
        },
    };

    let action = state.action.clone();
    let verdict = evaluate_permit(
        &state,
        &action,
        ver_status,
        current_epoch,
        req_cap.as_deref(),
    );

    let decision_str = match verdict.decision {
        GateDecision::Permit => "PERMIT",
        GateDecision::Reject => "REJECT",
    };

    println!(
        "{{\"decision\":\"{}\",\"auth_valid\":{},\"safe_action_valid\":{},\"ver_valid\":{},\"cap_valid\":{},\"reasons_count\":{}}}",
        decision_str,
        verdict.detail.auth_pass,
        verdict.detail.safe_action_pass,
        verdict.detail.ver_pass,
        verdict.detail.cap_pass,
        verdict.detail.reasons.len()
    );
}
