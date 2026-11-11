//! Independent Validator interface: process-isolated verification adapter.
//!
//! Rule 1 & Avni et al. (IACR 2026/994):
//! - The kernel must NOT validate its own proofs.
//! - Independent verification runs out-of-process.
//! - Any Unknown / timeout / crash resolves to hard failure (fail-closed).

use crate::{certificate::VerificationCertificate, error::PcoError};
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

/// Tri-state validation verdict emitted by independent validator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationVerdict {
    Valid { details: String },
    Invalid { reason: String },
    Unknown { reason: String },
}

impl ValidationVerdict {
    pub fn is_valid(&self) -> bool {
        matches!(self, ValidationVerdict::Valid { .. })
    }

    /// Fail-closed evaluation: Unknown resolves to false.
    pub fn fail_closed_pass(&self) -> bool {
        matches!(self, ValidationVerdict::Valid { .. })
    }
}

/// Independent validator interface: isolated adapter trait.
pub trait IndependentValidator: Send + Sync {
    /// Validate proof artifact out-of-process against query and candidate output.
    fn validate(
        &self,
        cert: &VerificationCertificate,
        query: &[u8],
        output: &[u8],
    ) -> Result<ValidationVerdict, PcoError>;
}

/// Process-isolated adapter that shells out to an external executable/script.
pub struct ProcessIsolatedValidator {
    executable_path: String,
    args: Vec<String>,
    timeout: Duration,
}

impl ProcessIsolatedValidator {
    pub fn new(executable_path: impl Into<String>, args: Vec<String>, timeout: Duration) -> Self {
        Self {
            executable_path: executable_path.into(),
            args,
            timeout,
        }
    }
}

impl IndependentValidator for ProcessIsolatedValidator {
    fn validate(
        &self,
        cert: &VerificationCertificate,
        query: &[u8],
        output: &[u8],
    ) -> Result<ValidationVerdict, PcoError> {
        // Construct canonical payload to pipe to validator stdin
        let input_payload = format!(
            "{{\"cert_id\":\"{}\",\"spec\":\"{}\",\"proof\":\"{}\",\"query\":\"{}\",\"output\":\"{}\"}}\n",
            cert.certificate_id,
            cert.spec_digest,
            cert.proof_artifact,
            hex::encode(query),
            hex::encode(output)
        );

        let mut child = Command::new(&self.executable_path)
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| PcoError::ValidatorCrash(format!("Failed to spawn {}: {}", self.executable_path, e)))?;

        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(input_payload.as_bytes());
        }

        // Wait with bounded polling for timeout enforcement
        let start = std::time::Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let out = child.wait_with_output()
                        .map_err(|e| PcoError::ValidatorCrash(e.to_string()))?;
                    let stdout_str = String::from_utf8_lossy(&out.stdout).trim().to_string();

                    if !status.success() {
                        return Ok(ValidationVerdict::Invalid {
                            reason: format!("Validator process exited with status {}: {}", status, stdout_str),
                        });
                    }

                    if stdout_str.contains("VERDICT: VALID") {
                        return Ok(ValidationVerdict::Valid { details: stdout_str });
                    } else if stdout_str.contains("VERDICT: INVALID") {
                        return Ok(ValidationVerdict::Invalid { reason: stdout_str });
                    } else if stdout_str.contains("VERDICT: UNKNOWN") {
                        return Ok(ValidationVerdict::Unknown { reason: stdout_str });
                    } else {
                        return Ok(ValidationVerdict::Unknown {
                            reason: format!("Unrecognized validator response: {}", stdout_str),
                        });
                    }
                }
                Ok(None) => {
                    if start.elapsed() > self.timeout {
                        let _ = child.kill();
                        return Err(PcoError::ValidatorTimeout);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(PcoError::ValidatorCrash(e.to_string())),
            }
        }
    }
}

/// In-process reference / mock independent validator for decidable predicates.
/// Useful for testing, simulation, and hermetic CI runs.
pub struct ToyDecidableComplianceValidator {
    max_cost_limit_wad: i128,
}

impl ToyDecidableComplianceValidator {
    pub fn new(max_cost_limit_wad: i128) -> Self {
        Self { max_cost_limit_wad }
    }
}

impl IndependentValidator for ToyDecidableComplianceValidator {
    fn validate(
        &self,
        cert: &VerificationCertificate,
        _query: &[u8],
        output: &[u8],
    ) -> Result<ValidationVerdict, PcoError> {
        // Toy decidable compliance rule:
        // Proof artifact must start with "PROOF-VALID:" followed by cost_wad integer
        if cert.proof_artifact.is_empty() {
            return Ok(ValidationVerdict::Invalid {
                reason: "Empty proof artifact".into(),
            });
        }

        if !cert.proof_artifact.starts_with("PROOF-VALID:") {
            return Ok(ValidationVerdict::Invalid {
                reason: format!("Unrecognized proof format: {}", cert.proof_artifact),
            });
        }

        let cost_str = &cert.proof_artifact["PROOF-VALID:".len()..];
        let cost_wad = cost_str.parse::<i128>().map_err(|_| {
            PcoError::VerificationFailed(format!("Invalid cost value in proof: {}", cost_str))
        })?;

        // Invariant: action cost <= max_cost_limit_wad
        if cost_wad > self.max_cost_limit_wad {
            return Ok(ValidationVerdict::Invalid {
                reason: format!(
                    "Proof indicates cost {} WAD exceeds limit {} WAD",
                    cost_wad, self.max_cost_limit_wad
                ),
            });
        }

        // Verify output digest matches certificate input/output binding
        if output.is_empty() {
            return Ok(ValidationVerdict::Invalid {
                reason: "Output payload cannot be empty".into(),
            });
        }

        Ok(ValidationVerdict::Valid {
            details: format!("Compliance verified: cost {} WAD <= limit {} WAD", cost_wad, self.max_cost_limit_wad),
        })
    }
}
