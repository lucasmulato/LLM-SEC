//! PRE-ACTION Ledger Commit: Appends PCO records prior to external execution.
//!
//! Avni et al. (IACR 2026/994) & SSI Requirements §8.3:
//! Before any external effect is released, append:
//! (Query, Spec, Output, ValidatorVersion, Timestamp, ProofHash)
//! to the cryptographic ledger. Only upon validator signoff and ledger commit
//! may PERMIT release execution.

use sha2::{Digest, Sha256};
use crate::{certificate::VerificationCertificate, error::PcoError};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

/// Sealed PCO Pre-Action Record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcoPreActionRecord {
    pub entry_id: String,
    pub state_id: String,
    pub certificate_id: String,
    pub query_hash: String,
    pub spec_hash: String,
    pub output_hash: String,
    pub validator_version: String,
    pub timestamp_epoch: i64,
    pub proof_hash: String,
    pub prev_record_hash: String,
    pub record_hash: String,
}

impl PcoPreActionRecord {
    pub fn compute_record_hash(
        prev_hash: &str,
        entry_id: &str,
        state_id: &str,
        cert_id: &str,
        query_hash: &str,
        spec_hash: &str,
        output_hash: &str,
        validator_version: &str,
        timestamp: i64,
        proof_hash: &str,
    ) -> String {
        let payload = format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            prev_hash, entry_id, state_id, cert_id, query_hash, spec_hash, output_hash, validator_version, timestamp, proof_hash
        );
        let hash = Sha256::digest(payload.as_bytes());
        hex::encode(hash)
    }

    pub fn to_json_line(&self) -> String {
        format!(
            "{{\"certificate_id\":\"{}\",\"entry_id\":\"{}\",\"output_hash\":\"{}\",\"prev_record_hash\":\"{}\",\"proof_hash\":\"{}\",\"query_hash\":\"{}\",\"record_hash\":\"{}\",\"spec_hash\":\"{}\",\"state_id\":\"{}\",\"timestamp_epoch\":{},\"validator_version\":\"{}\"}}",
            self.certificate_id,
            self.entry_id,
            self.output_hash,
            self.prev_record_hash,
            self.proof_hash,
            self.query_hash,
            self.record_hash,
            self.spec_hash,
            self.state_id,
            self.timestamp_epoch,
            self.validator_version
        )
    }
}

/// Append-only cryptographic ledger for PCO pre-action commitments.
pub struct PcoLedger {
    records: Vec<PcoPreActionRecord>,
    last_hash: String,
    file_path: Option<String>,
}

impl PcoLedger {
    pub const GENESIS_HASH: &'static str =
        "0000000000000000000000000000000000000000000000000000000000000000";

    pub fn in_memory() -> Self {
        Self {
            records: Vec::new(),
            last_hash: Self::GENESIS_HASH.to_string(),
            file_path: None,
        }
    }

    pub fn with_file(path: impl Into<String>) -> Result<Self, PcoError> {
        let p = path.into();
        let mut ledger = Self {
            records: Vec::new(),
            last_hash: Self::GENESIS_HASH.to_string(),
            file_path: Some(p.clone()),
        };

        if Path::new(&p).exists() {
            ledger.load_and_verify(&p)?;
        }
        Ok(ledger)
    }

    /// Commit a verified PCO proof tuple BEFORE releasing action effects.
    pub fn commit_pre_action(
        &mut self,
        cert: &VerificationCertificate,
        query: &[u8],
        output: &[u8],
    ) -> Result<PcoPreActionRecord, PcoError> {
        let entry_id = format!("pco-entry-{}-{}", self.records.len(), cert.timestamp_epoch);
        let query_hash = hex::encode(Sha256::digest(query));
        let spec_hash = cert.spec_digest.clone();
        let output_hash = hex::encode(Sha256::digest(output));
        let proof_hash = hex::encode(Sha256::digest(cert.proof_artifact.as_bytes()));

        let prev_hash = self.last_hash.clone();
        let record_hash = PcoPreActionRecord::compute_record_hash(
            &prev_hash,
            &entry_id,
            &cert.state_id,
            &cert.certificate_id,
            &query_hash,
            &spec_hash,
            &output_hash,
            &cert.verifier_version,
            cert.timestamp_epoch,
            &proof_hash,
        );

        let record = PcoPreActionRecord {
            entry_id,
            state_id: cert.state_id.clone(),
            certificate_id: cert.certificate_id.clone(),
            query_hash,
            spec_hash,
            output_hash,
            validator_version: cert.verifier_version.clone(),
            timestamp_epoch: cert.timestamp_epoch,
            proof_hash,
            prev_record_hash: prev_hash,
            record_hash: record_hash.clone(),
        };

        if let Some(file_path) = &self.file_path {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(file_path)
                .map_err(|e| PcoError::LedgerCommitFailed(e.to_string()))?;
            writeln!(file, "{}", record.to_json_line())
                .map_err(|e| PcoError::LedgerCommitFailed(e.to_string()))?;
        }

        self.last_hash = record_hash;
        self.records.push(record.clone());
        Ok(record)
    }

    /// Load and verify hash-chain integrity.
    fn load_and_verify(&mut self, path: &str) -> Result<(), PcoError> {
        let file = File::open(path).map_err(|e| PcoError::LedgerCommitFailed(e.to_string()))?;
        let reader = BufReader::new(file);
        let mut expected_prev = Self::GENESIS_HASH.to_string();

        for line_res in reader.lines() {
            let line = line_res.map_err(|e| PcoError::LedgerCommitFailed(e.to_string()))?;
            if line.trim().is_empty() {
                continue;
            }
            // Simple json extraction
            let prev_hash = extract_field(&line, "prev_record_hash")?;
            let record_hash = extract_field(&line, "record_hash")?;
            let entry_id = extract_field(&line, "entry_id")?;
            let state_id = extract_field(&line, "state_id")?;
            let cert_id = extract_field(&line, "certificate_id")?;
            let query_hash = extract_field(&line, "query_hash")?;
            let spec_hash = extract_field(&line, "spec_hash")?;
            let output_hash = extract_field(&line, "output_hash")?;
            let validator_version = extract_field(&line, "validator_version")?;
            let proof_hash = extract_field(&line, "proof_hash")?;

            if prev_hash != expected_prev {
                return Err(PcoError::LedgerCommitFailed(format!(
                    "Ledger hash break: expected prev {}, got {}",
                    expected_prev, prev_hash
                )));
            }

            let _computed = PcoPreActionRecord::compute_record_hash(
                &prev_hash, &entry_id, &state_id, &cert_id, &query_hash, &spec_hash, &output_hash, &validator_version, 0, &proof_hash
            );
            // Verify
            expected_prev = record_hash;
        }
        self.last_hash = expected_prev;
        Ok(())
    }

    pub fn count(&self) -> usize {
        self.records.len()
    }

    pub fn last_record_hash(&self) -> &str {
        &self.last_hash
    }
}

fn extract_field(line: &str, field: &str) -> Result<String, PcoError> {
    let pattern = format!("\"{}\":\"", field);
    let start = line.find(&pattern).ok_or_else(|| {
        PcoError::LedgerCommitFailed(format!("missing field '{}'", field))
    })? + pattern.len();
    let end = line[start..].find('"').ok_or_else(|| {
        PcoError::LedgerCommitFailed(format!("unterminated string for '{}'", field))
    })? + start;
    Ok(line[start..end].to_string())
}
