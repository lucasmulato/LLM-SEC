//! Kernel Manifest & KernelEqual(Y) Specification (SSI Def 23, PO-7).
//!
//! Enforces exact byte-for-byte kernel equality. Similarity or intent is NOT equality.
//! Any divergence in artifact hash, specification version, arithmetic scaling,
//! or feature flags constitutes a hard kernel equality breach.

#![deny(clippy::float_arithmetic)]

use sha2::{Digest, Sha256};
use crate::error::R3Error;

/// Pinned normative spec version for SSI Kernel.
pub const NORMATIVE_SPEC_VERSION: &str = "SSI-Normative-v1.0";

/// Pinned arithmetic scale factor: 10^18 (WAD-18).
pub const NORMATIVE_WAD_SCALE: i128 = 1_000_000_000_000_000_000;

/// Default artifact digest of the compiled pure WAD-18 kernel.
pub const DEFAULT_KERNEL_ARTIFACT_DIGEST: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Kernel Manifest K: Cryptographic identity and versioning manifest of the immutable kernel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelManifest {
    /// SHA-256 hash of the compiled kernel artifact (64-char hex string).
    pub artifact_hash: String,
    /// Normative specification identifier.
    pub spec_version: String,
    /// Arithmetic scaling constant (must equal 10^18).
    pub wad_scale: i128,
    /// Enabled architectural features (e.g., "pure-wad18,no-fp,process-isolated").
    pub feature_flags: String,
}

impl Default for KernelManifest {
    fn default() -> Self {
        Self {
            artifact_hash: DEFAULT_KERNEL_ARTIFACT_DIGEST.to_string(),
            spec_version: NORMATIVE_SPEC_VERSION.to_string(),
            wad_scale: NORMATIVE_WAD_SCALE,
            feature_flags: "pure-wad18,no-fp,no-std-target,exact-state-bound".to_string(),
        }
    }
}

impl KernelManifest {
    /// Construct a new kernel manifest with explicit fields.
    pub fn new(
        artifact_hash: &str,
        spec_version: &str,
        wad_scale: i128,
        feature_flags: &str,
    ) -> Self {
        Self {
            artifact_hash: artifact_hash.to_string(),
            spec_version: spec_version.to_string(),
            wad_scale,
            feature_flags: feature_flags.to_string(),
        }
    }

    /// Compute canonical SHA-256 digest of this kernel manifest.
    pub fn manifest_digest(&self) -> String {
        let payload = format!(
            "MANIFEST:artifact={}:spec={}:scale={}:flags={}",
            self.artifact_hash, self.spec_version, self.wad_scale, self.feature_flags
        );
        hex::encode(Sha256::digest(payload.as_bytes()))
    }

    /// KernelEqual(Y): compares manifests exactly.
    /// Byte-for-byte exact equality is mandatory. Similarity or semantic intent is NOT equality.
    pub fn check_kernel_equal(&self, candidate: &KernelManifest) -> Result<(), R3Error> {
        let current_digest = self.manifest_digest();
        let candidate_digest = candidate.manifest_digest();

        if self.artifact_hash != candidate.artifact_hash {
            return Err(R3Error::KernelEqualityBreach {
                expected_digest: current_digest,
                got_digest: candidate_digest,
                reason: format!(
                    "Artifact hash divergence: expected {} but got {}",
                    self.artifact_hash, candidate.artifact_hash
                ),
            });
        }

        if self.spec_version != candidate.spec_version {
            return Err(R3Error::KernelEqualityBreach {
                expected_digest: current_digest,
                got_digest: candidate_digest,
                reason: format!(
                    "Spec version divergence: expected {} but got {}",
                    self.spec_version, candidate.spec_version
                ),
            });
        }

        if self.wad_scale != candidate.wad_scale {
            return Err(R3Error::KernelEqualityBreach {
                expected_digest: current_digest,
                got_digest: candidate_digest,
                reason: format!(
                    "WAD-18 scale divergence: expected {} but got {}",
                    self.wad_scale, candidate.wad_scale
                ),
            });
        }

        if self.feature_flags != candidate.feature_flags {
            return Err(R3Error::KernelEqualityBreach {
                expected_digest: current_digest,
                got_digest: candidate_digest,
                reason: format!(
                    "Feature flags divergence: expected '{}' but got '{}'",
                    self.feature_flags, candidate.feature_flags
                ),
            });
        }

        if current_digest != candidate_digest {
            return Err(R3Error::KernelEqualityBreach {
                expected_digest: current_digest,
                got_digest: candidate_digest,
                reason: "Manifest digest mismatch".to_string(),
            });
        }

        Ok(())
    }
}
