#![no_main]

use libfuzzer_sys::fuzz_target;
use wad18::Wad18;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    let mut b1 = [0u8; 16];
    let mut b2 = [0u8; 16];
    b1.copy_from_slice(&data[0..16]);
    b2.copy_from_slice(&data[16..32]);

    let raw1 = i128::from_le_bytes(b1);
    let raw2 = i128::from_le_bytes(b2);

    let w1 = Wad18::from_raw(raw1);
    let w2 = Wad18::from_raw(raw2);

    // Fuzz operations must never trigger unhandled CPU traps or panic
    let _ = w1.checked_add(w2);
    let _ = w1.checked_sub(w2);
    let _ = w1.checked_mul(w2);
    let _ = w1.checked_div(w2);
});
