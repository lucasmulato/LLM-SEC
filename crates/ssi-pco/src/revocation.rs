//! Dynamic Revocation API for certificates and assets.
//!
//! Rule 1 & SSI Requirements §8.4:
//! Revoked certificates or assets can never authorize execution afterward.

use std::collections::BTreeMap;
use crate::error::PcoError;

/// Details of an explicit revocation action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationRecord {
    pub id: String,
    pub reason: String,
    pub revoked_at_epoch: i64,
}

/// Dynamic registry tracking revoked certificates and safety assets.
#[derive(Clone, Debug, Default)]
pub struct RevocationRegistry {
    revocations: BTreeMap<String, RevocationRecord>,
}

impl RevocationRegistry {
    pub fn new() -> Self {
        Self {
            revocations: BTreeMap::new(),
        }
    }

    /// Register explicit revocation for a certificate ID or asset hash.
    pub fn revoke(&mut self, id: impl Into<String>, reason: impl Into<String>, epoch: i64) {
        let id_str = id.into();
        self.revocations.insert(
            id_str.clone(),
            RevocationRecord {
                id: id_str,
                reason: reason.into(),
                revoked_at_epoch: epoch,
            },
        );
    }

    /// Query if an ID has been revoked.
    pub fn is_revoked(&self, id: &str) -> bool {
        self.revocations.contains_key(id)
    }

    /// Assert that an ID has not been revoked.
    pub fn check_not_revoked(&self, id: &str) -> Result<(), PcoError> {
        if let Some(record) = self.revocations.get(id) {
            Err(PcoError::CertificateRevoked {
                cert_id: id.to_string(),
                reason: record.reason.clone(),
            })
        } else {
            Ok(())
        }
    }

    /// Number of revoked entries.
    pub fn len(&self) -> usize {
        self.revocations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.revocations.is_empty()
    }
}
