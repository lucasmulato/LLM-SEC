#![no_main]

use libfuzzer_sys::fuzz_target;
use ssi_kernel::SystemState;
use ssi_ledger::canonical_encode_state;

fuzz_target!(|data: &[u8]| {
    // Attempt decoding arbitrary fuzz bytes into SystemState
    if let Ok(state) = serde_json::from_slice::<SystemState>(data) {
        // Invariant: if state decodes, canonical_encode_state must succeed deterministically
        let enc1 = canonical_encode_state(&state);
        let enc2 = canonical_encode_state(&state);
        assert_eq!(enc1, enc2, "Deterministic encoding violated for decoded state");
    }
});
