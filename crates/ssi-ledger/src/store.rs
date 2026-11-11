//! Append-only hash-chained ledger and SAC evidence storage.

use sha2::{Digest, Sha256};
use ssi_csl::CSLEnvelope;
use ssi_kernel::{ActionProposal, SystemState};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use crate::error::LedgerError;

/// Deterministic canonical encoding ENC(X).
pub fn canonical_encode_state(state: &SystemState) -> Vec<u8> {
    let canonical = state.canonical_dict();
    let json = canonical
        .iter()
        .map(|(k, v)| format!("\"{}\":{}", k, v.to_canonical_json()))
        .collect::<Vec<_>>()
        .join(",");
    format!("{{{}}}", json).into_bytes()
}

/// Compute state ID: ID_X = SHA-256(ENC(X)).
pub fn compute_state_id(state: &SystemState) -> String {
    let encoded = canonical_encode_state(state);
    let hash = Sha256::digest(&encoded);
    hex::encode(hash)
}

/// Safety Asset Class (SAC) taxonomy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SafetyAssetClass {
    Sac1ControlIntegrity,
    Sac2AuthorizationContinuity,
    Sac3FormalProvenance,
}

impl SafetyAssetClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            SafetyAssetClass::Sac1ControlIntegrity => "SAC-1",
            SafetyAssetClass::Sac2AuthorizationContinuity => "SAC-2",
            SafetyAssetClass::Sac3FormalProvenance => "SAC-3",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "SAC-1" => Some(SafetyAssetClass::Sac1ControlIntegrity),
            "SAC-2" => Some(SafetyAssetClass::Sac2AuthorizationContinuity),
            "SAC-3" => Some(SafetyAssetClass::Sac3FormalProvenance),
            _ => None,
        }
    }
}

/// Machine-checkable SAC Evidence object with provenance chain Γ.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SACEvidence {
    pub evidence_id: String,
    pub sac_class: SafetyAssetClass,
    pub state_id: String,
    pub parent_state_id: String,
    pub sequence_number: u64,
    pub csl_auth_id: String,
    pub certificate_id: String,
    pub transition_hash: String,
    pub prev_record_hash: String,
    pub record_hash: String,
    pub timestamp_epoch_ms: i64,
    /// Environment / toolchain manifest digest Γ.
    pub provenance_gamma: String,
}

impl SACEvidence {
    /// Payload string that is hashed with prev_record_hash to produce record_hash.
    pub fn payload_digest_str(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.evidence_id,
            self.sac_class.as_str(),
            self.state_id,
            self.parent_state_id,
            self.sequence_number,
            self.csl_auth_id,
            self.certificate_id,
            self.transition_hash,
            self.provenance_gamma
        )
    }

    /// Serialize as single-line canonical JSON for append-only storage.
    pub fn to_json_line(&self) -> String {
        format!(
            "{{\"certificate_id\":\"{}\",\"csl_auth_id\":\"{}\",\"evidence_id\":\"{}\",\"parent_state_id\":\"{}\",\"prev_record_hash\":\"{}\",\"provenance_gamma\":\"{}\",\"record_hash\":\"{}\",\"sac_class\":\"{}\",\"sequence_number\":{},\"state_id\":\"{}\",\"timestamp_epoch_ms\":{},\"transition_hash\":\"{}\"}}",
            self.certificate_id,
            self.csl_auth_id,
            self.evidence_id,
            self.parent_state_id,
            self.prev_record_hash,
            self.provenance_gamma,
            self.record_hash,
            self.sac_class.as_str(),
            self.sequence_number,
            self.state_id,
            self.timestamp_epoch_ms,
            self.transition_hash
        )
    }

    /// Parse from a JSON line.
    pub fn from_json_line(line: &str) -> Result<Self, LedgerError> {
        let trimmed = line.trim();
        // Simple robust manual key-value extraction without external json parser
        let get_str = |key: &str| -> Result<String, LedgerError> {
            let pattern = format!("\"{}\":\"", key);
            let start = trimmed.find(&pattern).ok_or_else(|| {
                LedgerError::EncodingError(format!("missing key '{key}'"))
            })? + pattern.len();
            let end = trimmed[start..].find('"').ok_or_else(|| {
                LedgerError::EncodingError(format!("unterminated string for key '{key}'"))
            })? + start;
            Ok(trimmed[start..end].to_string())
        };

        let get_u64 = |key: &str| -> Result<u64, LedgerError> {
            let pattern = format!("\"{}\":", key);
            let start = trimmed.find(&pattern).ok_or_else(|| {
                LedgerError::EncodingError(format!("missing key '{key}'"))
            })? + pattern.len();
            let rest = &trimmed[start..];
            let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
            rest[..end].parse::<u64>().map_err(|e| {
                LedgerError::EncodingError(format!("invalid u64 for '{key}': {e}"))
            })
        };

        let get_i64 = |key: &str| -> Result<i64, LedgerError> {
            let pattern = format!("\"{}\":", key);
            let start = trimmed.find(&pattern).ok_or_else(|| {
                LedgerError::EncodingError(format!("missing key '{key}'"))
            })? + pattern.len();
            let rest = &trimmed[start..];
            let end = rest.find(|c: char| !c.is_ascii_digit() && c != '-').unwrap_or(rest.len());
            rest[..end].parse::<i64>().map_err(|e| {
                LedgerError::EncodingError(format!("invalid i64 for '{key}': {e}"))
            })
        };

        let sac_str = get_str("sac_class")?;
        let sac_class = SafetyAssetClass::from_str(&sac_str).ok_or_else(|| {
            LedgerError::EncodingError(format!("unknown SAC class '{sac_str}'"))
        })?;

        Ok(Self {
            evidence_id: get_str("evidence_id")?,
            sac_class,
            state_id: get_str("state_id")?,
            parent_state_id: get_str("parent_state_id")?,
            sequence_number: get_u64("sequence_number")?,
            csl_auth_id: get_str("csl_auth_id")?,
            certificate_id: get_str("certificate_id")?,
            transition_hash: get_str("transition_hash")?,
            prev_record_hash: get_str("prev_record_hash")?,
            record_hash: get_str("record_hash")?,
            timestamp_epoch_ms: get_i64("timestamp_epoch_ms")?,
            provenance_gamma: get_str("provenance_gamma")?,
        })
    }
}

/// Append-only cryptographic trace store for state transitions.
pub struct AppendOnlyLedgerStore {
    records: Vec<SACEvidence>,
    last_record_hash: String,
    file_path: Option<String>,
}

impl AppendOnlyLedgerStore {
    pub const GENESIS_HASH: &'static str =
        "0000000000000000000000000000000000000000000000000000000000000000";

    pub fn in_memory() -> Self {
        Self {
            records: Vec::new(),
            last_record_hash: Self::GENESIS_HASH.to_string(),
            file_path: None,
        }
    }

    pub fn with_file(path: impl Into<String>) -> Result<Self, LedgerError> {
        let p = path.into();
        let mut store = Self {
            records: Vec::new(),
            last_record_hash: Self::GENESIS_HASH.to_string(),
            file_path: Some(p.clone()),
        };

        if Path::new(&p).exists() {
            store.load_and_verify(&p)?;
        }
        Ok(store)
    }

    pub fn records(&self) -> &[SACEvidence] {
        &self.records
    }

    pub fn last_record_hash(&self) -> &str {
        &self.last_record_hash
    }

    fn compute_record_hash(prev_hash: &str, payload_str: &str) -> String {
        let combined = format!("{}:{}", prev_hash, payload_str);
        let hash = Sha256::digest(combined.as_bytes());
        hex::encode(hash)
    }

    /// Append a verified state transition to the ledger.
    #[allow(clippy::too_many_arguments)]
    pub fn append_transition(
        &mut self,
        pre_state: &SystemState,
        action: &ActionProposal,
        post_state: &SystemState,
        csl: &CSLEnvelope,
        certificate_id: &str,
        sac_class: SafetyAssetClass,
        provenance_gamma: &str,
        timestamp_epoch_ms: i64,
    ) -> Result<&SACEvidence, LedgerError> {
        let pre_id = compute_state_id(pre_state);
        let post_id = compute_state_id(post_state);

        // Transition hash: binds pre_state_id, action_id, payload_digest, post_state_id
        let trans_payload = format!(
            "{}:{}:{}:{}",
            pre_id, action.action_id, action.payload_digest, post_id
        );
        let transition_hash = hex::encode(Sha256::digest(trans_payload.as_bytes()));

        let evidence_id = format!(
            "sac-{}-{}-{}",
            sac_class.as_str(),
            post_state.provenance.sequence_number,
            timestamp_epoch_ms
        );

        let mut evidence = SACEvidence {
            evidence_id,
            sac_class,
            state_id: post_id,
            parent_state_id: pre_id,
            sequence_number: post_state.provenance.sequence_number,
            csl_auth_id: csl.auth_id.clone(),
            certificate_id: certificate_id.to_string(),
            transition_hash,
            prev_record_hash: self.last_record_hash.clone(),
            record_hash: String::new(),
            timestamp_epoch_ms,
            provenance_gamma: provenance_gamma.to_string(),
        };

        evidence.record_hash =
            Self::compute_record_hash(&self.last_record_hash, &evidence.payload_digest_str());

        if let Some(ref path) = self.file_path {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| LedgerError::IoError(e.to_string()))?;
            writeln!(file, "{}", evidence.to_json_line())
                .map_err(|e| LedgerError::IoError(e.to_string()))?;
        }

        self.last_record_hash = evidence.record_hash.clone();
        self.records.push(evidence);
        Ok(self.records.last().unwrap())
    }

    /// Load and recompute the full cryptographic hash chain from file.
    fn load_and_verify(&mut self, path: &str) -> Result<(), LedgerError> {
        let file = File::open(path).map_err(|e| LedgerError::IoError(e.to_string()))?;
        let reader = BufReader::new(file);

        let mut curr_prev = Self::GENESIS_HASH.to_string();
        let mut expected_seq = 1u64;

        for (idx, line_res) in reader.lines().enumerate() {
            let line = line_res.map_err(|e| LedgerError::IoError(e.to_string()))?;
            if line.trim().is_empty() {
                continue;
            }
            let rec = SACEvidence::from_json_line(&line)?;

            // 1. Verify prev_record_hash
            if rec.prev_record_hash != curr_prev {
                return Err(LedgerError::ChainBroken {
                    index: idx,
                    expected_prev: curr_prev,
                    actual_prev: rec.prev_record_hash,
                });
            }

            // 2. Recompute payload hash
            let computed = Self::compute_record_hash(&curr_prev, &rec.payload_digest_str());
            if rec.record_hash != computed {
                return Err(LedgerError::TamperedRecord {
                    index: idx,
                    computed_hash: computed,
                    recorded_hash: rec.record_hash,
                });
            }

            // 3. Verify sequence
            if rec.sequence_number != expected_seq {
                return Err(LedgerError::SequenceDiscontinuity {
                    index: idx,
                    expected_seq,
                    actual_seq: rec.sequence_number,
                });
            }

            curr_prev = rec.record_hash.clone();
            expected_seq += 1;
            self.records.push(rec);
        }

        self.last_record_hash = curr_prev;
        Ok(())
    }

    /// In-memory re-verification of the entire chain.
    pub fn verify_integrity(&self) -> Result<usize, LedgerError> {
        let mut curr_prev = Self::GENESIS_HASH.to_string();

        for (idx, rec) in self.records.iter().enumerate() {
            let expected_seq = (idx as u64) + 1;
            if rec.prev_record_hash != curr_prev {
                return Err(LedgerError::ChainBroken {
                    index: idx,
                    expected_prev: curr_prev,
                    actual_prev: rec.prev_record_hash.clone(),
                });
            }

            let computed = Self::compute_record_hash(&curr_prev, &rec.payload_digest_str());
            if rec.record_hash != computed {
                return Err(LedgerError::TamperedRecord {
                    index: idx,
                    computed_hash: computed,
                    recorded_hash: rec.record_hash.clone(),
                });
            }

            if rec.sequence_number != expected_seq {
                return Err(LedgerError::SequenceDiscontinuity {
                    index: idx,
                    expected_seq,
                    actual_seq: rec.sequence_number,
                });
            }

            curr_prev = rec.record_hash.clone();
        }

        Ok(self.records.len())
    }
}
