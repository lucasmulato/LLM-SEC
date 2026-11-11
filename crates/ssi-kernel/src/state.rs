//! Typed System State X = (I, S, A, H, V, P) — Definition 3.

use std::collections::{BTreeMap, BTreeSet};
use wad18::Wad18;

/// Enumeration of autonomous action types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ActionType {
    Read,
    Compute,
    Communicate,
    MutateEnvironment,
    ExecuteCode,
    SystemHalt,
}

impl ActionType {
    pub fn as_str(self) -> &'static str {
        match self {
            ActionType::Read => "READ",
            ActionType::Compute => "COMPUTE",
            ActionType::Communicate => "COMMUNICATE",
            ActionType::MutateEnvironment => "MUTATE_ENVIRONMENT",
            ActionType::ExecuteCode => "EXECUTE_CODE",
            ActionType::SystemHalt => "SYSTEM_HALT",
        }
    }
}

impl std::fmt::Display for ActionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Intelligence State Component (I).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntelligenceState {
    pub model_id: String,
    /// SHA-256 hex digest of model weights (64 chars).
    pub weights_digest: String,
    pub context_window_size: u64,
    pub cognitive_budget: Wad18,
    pub epistemic_confidence: Wad18,
    pub entropy_bound: Wad18,
    pub capabilities: BTreeSet<String>,
}

/// Safety State Component (S).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafetyState {
    pub containment_active: bool,
    pub containment_barrier_intact: bool,
    pub safety_margin: Wad18,
    pub risk_bound: Wad18,
    pub active_envelope_id: String,
    pub csl_constraints: BTreeSet<String>,
    pub quarantine_flag: bool,
}

/// Action Proposal being evaluated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionProposal {
    pub action_id: String,
    pub action_type: ActionType,
    pub risk_assessment: Wad18,
    pub resource_cost: Wad18,
    pub required_clearance: u32,
    /// SHA-256 hex digest of the action payload (64 chars).
    pub payload_digest: String,
    pub is_executed: bool,
}

/// Authorization State Component (H).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationState {
    pub auth_token: String,
    pub granter_id: String,
    pub clearance_level: u32,
    pub is_active: bool,
    pub expires_at_epoch: i64,
    pub nonce: String,
}

/// Verification State Component (V).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationState {
    pub certificate_id: String,
    pub proof_system: String,
    /// SHA-256 hex digest of the proof artifact (64 chars).
    pub proof_digest: String,
    pub invariants_verified: BTreeSet<String>,
    pub verifier_identity: String,
    pub verified_at_epoch: i64,
    pub is_valid: bool,
}

/// Provenance State Component (P).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenanceState {
    pub sequence_number: u64,
    /// SHA-256 hex digest of parent state ID_X (64 chars, or all-zeros for genesis).
    pub parent_state_hash: String,
    pub merkle_root: String,
    pub audit_trail_id: String,
    pub timestamp_epoch_ms: i64,
}

/// Full System State X = (I, S, A, H, V, P).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemState {
    pub intelligence: IntelligenceState,
    pub safety: SafetyState,
    pub action: ActionProposal,
    pub authorization: AuthorizationState,
    pub verification: VerificationState,
    pub provenance: ProvenanceState,
}

impl SystemState {
    /// Deterministic canonical representation for hashing.
    /// All fields are sorted; WAD-18 values encoded as big-endian hex of raw i128.
    pub fn canonical_dict(&self) -> BTreeMap<String, serde_json_core_substitute::Value> {
        // We build it manually so we stay no-std compatible.
        // Returns a sorted BTreeMap structure — callers serialize via JSON.
        use serde_json_core_substitute::Value;
        let mut map = BTreeMap::new();

        let mut i_map = BTreeMap::new();
        i_map.insert("capabilities".to_string(), Value::Array(
            self.intelligence.capabilities.iter().map(|s| Value::Str(s.clone())).collect()
        ));
        i_map.insert("cognitive_budget_raw".to_string(), Value::I128(self.intelligence.cognitive_budget.raw()));
        i_map.insert("context_window_size".to_string(), Value::U64(self.intelligence.context_window_size));
        i_map.insert("entropy_bound_raw".to_string(), Value::I128(self.intelligence.entropy_bound.raw()));
        i_map.insert("epistemic_confidence_raw".to_string(), Value::I128(self.intelligence.epistemic_confidence.raw()));
        i_map.insert("model_id".to_string(), Value::Str(self.intelligence.model_id.clone()));
        i_map.insert("weights_digest".to_string(), Value::Str(self.intelligence.weights_digest.clone()));
        map.insert("I".to_string(), Value::Map(i_map));

        let mut s_map = BTreeMap::new();
        s_map.insert("active_envelope_id".to_string(), Value::Str(self.safety.active_envelope_id.clone()));
        s_map.insert("containment_active".to_string(), Value::Bool(self.safety.containment_active));
        s_map.insert("containment_barrier_intact".to_string(), Value::Bool(self.safety.containment_barrier_intact));
        s_map.insert("csl_constraints".to_string(), Value::Array(
            self.safety.csl_constraints.iter().map(|s| Value::Str(s.clone())).collect()
        ));
        s_map.insert("quarantine_flag".to_string(), Value::Bool(self.safety.quarantine_flag));
        s_map.insert("risk_bound_raw".to_string(), Value::I128(self.safety.risk_bound.raw()));
        s_map.insert("safety_margin_raw".to_string(), Value::I128(self.safety.safety_margin.raw()));
        map.insert("S".to_string(), Value::Map(s_map));

        let mut a_map = BTreeMap::new();
        a_map.insert("action_id".to_string(), Value::Str(self.action.action_id.clone()));
        a_map.insert("action_type".to_string(), Value::Str(self.action.action_type.as_str().to_string()));
        a_map.insert("is_executed".to_string(), Value::Bool(self.action.is_executed));
        a_map.insert("payload_digest".to_string(), Value::Str(self.action.payload_digest.clone()));
        a_map.insert("required_clearance".to_string(), Value::U64(self.action.required_clearance as u64));
        a_map.insert("resource_cost_raw".to_string(), Value::I128(self.action.resource_cost.raw()));
        a_map.insert("risk_assessment_raw".to_string(), Value::I128(self.action.risk_assessment.raw()));
        map.insert("A".to_string(), Value::Map(a_map));

        let mut h_map = BTreeMap::new();
        h_map.insert("auth_token".to_string(), Value::Str(self.authorization.auth_token.clone()));
        h_map.insert("clearance_level".to_string(), Value::U64(self.authorization.clearance_level as u64));
        h_map.insert("expires_at_epoch".to_string(), Value::I64(self.authorization.expires_at_epoch));
        h_map.insert("granter_id".to_string(), Value::Str(self.authorization.granter_id.clone()));
        h_map.insert("is_active".to_string(), Value::Bool(self.authorization.is_active));
        h_map.insert("nonce".to_string(), Value::Str(self.authorization.nonce.clone()));
        map.insert("H".to_string(), Value::Map(h_map));

        let mut v_map = BTreeMap::new();
        v_map.insert("certificate_id".to_string(), Value::Str(self.verification.certificate_id.clone()));
        v_map.insert("invariants_verified".to_string(), Value::Array(
            self.verification.invariants_verified.iter().map(|s| Value::Str(s.clone())).collect()
        ));
        v_map.insert("is_valid".to_string(), Value::Bool(self.verification.is_valid));
        v_map.insert("proof_digest".to_string(), Value::Str(self.verification.proof_digest.clone()));
        v_map.insert("proof_system".to_string(), Value::Str(self.verification.proof_system.clone()));
        v_map.insert("verified_at_epoch".to_string(), Value::I64(self.verification.verified_at_epoch));
        v_map.insert("verifier_identity".to_string(), Value::Str(self.verification.verifier_identity.clone()));
        map.insert("V".to_string(), Value::Map(v_map));

        let mut p_map = BTreeMap::new();
        p_map.insert("audit_trail_id".to_string(), Value::Str(self.provenance.audit_trail_id.clone()));
        p_map.insert("merkle_root".to_string(), Value::Str(self.provenance.merkle_root.clone()));
        p_map.insert("parent_state_hash".to_string(), Value::Str(self.provenance.parent_state_hash.clone()));
        p_map.insert("sequence_number".to_string(), Value::U64(self.provenance.sequence_number));
        p_map.insert("timestamp_epoch_ms".to_string(), Value::I64(self.provenance.timestamp_epoch_ms));
        map.insert("P".to_string(), Value::Map(p_map));

        map
    }

    /// Serialize state into deterministic canonical JSON format.
    pub fn to_canonical_json(&self) -> String {
        serde_json_core_substitute::Value::Map(self.canonical_dict()).to_canonical_json()
    }
}

/// Minimal serializable value tree for canonical encoding — avoids serde/std JSON.
pub mod serde_json_core_substitute {
    use std::collections::BTreeMap;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Value {
        Str(String),
        I128(i128),
        I64(i64),
        U64(u64),
        Bool(bool),
        Array(Vec<Value>),
        Map(BTreeMap<String, Value>),
    }

    impl Value {
        /// Canonical JSON serialization — sorted keys, no whitespace, deterministic.
        pub fn to_canonical_json(&self) -> String {
            match self {
                Value::Str(s) => format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")),
                Value::I128(n) => n.to_string(),
                Value::I64(n) => n.to_string(),
                Value::U64(n) => n.to_string(),
                Value::Bool(b) => if *b { "true".to_string() } else { "false".to_string() },
                Value::Array(arr) => {
                    let items: Vec<String> = arr.iter().map(|v| v.to_canonical_json()).collect();
                    format!("[{}]", items.join(","))
                }
                Value::Map(map) => {
                    // BTreeMap is already sorted
                    let items: Vec<String> = map.iter()
                        .map(|(k, v)| format!("\"{}\":{}", k, v.to_canonical_json()))
                        .collect();
                    format!("{{{}}}", items.join(","))
                }
            }
        }
    }
}
