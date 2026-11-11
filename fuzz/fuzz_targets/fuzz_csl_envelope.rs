#![no_main]

use libfuzzer_sys::fuzz_target;
use ssi_csl::CSLEnvelope;

fuzz_target!(|data: &[u8]| {
    // Attempt decoding arbitrary fuzz bytes into CSLEnvelope
    if let Ok(csl) = serde_json::from_slice::<CSLEnvelope>(data) {
        // Enforce fail-closed verification invariants
        // Nonce and auth_id must not cause memory faults or panics
        let _ = csl.validity.is_valid_epoch(0);
        let _ = csl.validity.is_valid_epoch(i64::MAX);
        let _ = csl.validity.is_valid_epoch(i64::MIN);
        let _ = csl.validity.is_valid_sequence(0);
        let _ = csl.validity.is_valid_sequence(u64::MAX);
    }
});
