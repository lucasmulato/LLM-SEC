use proptest::prelude::*;
use wad18::{Wad18, WadError, WAD_SCALE};

proptest! {
    /// 1. Canonical byte encoding / decoding round-trip is an exact identity.
    #[test]
    fn test_canonical_byte_roundtrip(raw in any::<i128>()) {
        let original = Wad18::from_raw(raw);
        let bytes = original.to_canonical_bytes();
        let decoded = Wad18::from_canonical_bytes(&bytes);
        prop_assert_eq!(original, decoded);
        prop_assert_eq!(original.raw(), decoded.raw());
    }

    /// 2. Addition associativity where intermediate operations do not overflow.
    #[test]
    fn test_addition_associativity(
        a in -100_000_000_000_000_000_000i128..100_000_000_000_000_000_000i128,
        b in -100_000_000_000_000_000_000i128..100_000_000_000_000_000_000i128,
        c in -100_000_000_000_000_000_000i128..100_000_000_000_000_000_000i128,
    ) {
        let w_a = Wad18::from_raw(a);
        let w_b = Wad18::from_raw(b);
        let w_c = Wad18::from_raw(c);

        if let (Ok(ab), Ok(bc)) = (w_a.checked_add(w_b), w_b.checked_add(w_c)) {
            if let (Ok(left), Ok(right)) = (ab.checked_add(w_c), w_a.checked_add(bc)) {
                prop_assert_eq!(left, right);
            }
        }
    }

    /// 3. Sign laws for exact multiplication:
    ///    a * (-1) == -a;
    ///    sign(a * b) == sign(a) * sign(b).
    #[test]
    fn test_sign_laws_mul(
        a in -1_000_000_000_000_000i128..1_000_000_000_000_000i128,
    ) {
        let w_a = Wad18::from_int_i128(a).unwrap();
        let neg_one = Wad18::from_int(-1).unwrap();

        let prod = w_a.checked_mul(neg_one).unwrap();
        prop_assert_eq!(prod.raw(), -w_a.raw());

        let expected_sign = match a.cmp(&0) {
            core::cmp::Ordering::Greater => -1,
            core::cmp::Ordering::Less => 1,
            core::cmp::Ordering::Equal => 0,
        };
        prop_assert_eq!(prod.signum(), expected_sign);
    }

    /// 4. Overflow and Underflow containment:
    ///    Extreme additions must explicitly return Overflow/Underflow without panic.
    #[test]
    fn test_addition_overflow_containment(
        val in 1i128..1_000_000_000_000_000_000i128,
    ) {
        let max_w = Wad18::MAX;
        let delta = Wad18::from_raw(val);
        let res = max_w.checked_add(delta);
        prop_assert_eq!(res, Err(WadError::Overflow));

        let min_w = Wad18::MIN;
        let res_underflow = min_w.checked_sub(delta);
        prop_assert_eq!(res_underflow, Err(WadError::Underflow));
    }

    /// 5. Inexact multiplication containment:
    ///    Any multiplication that produces a sub-WAD remainder must return InexactResult.
    #[test]
    fn test_inexact_multiplication_containment(
        rem in 1i128..999_999_999_999_999_999i128,
    ) {
        // Construct a raw value that is not a multiple of WAD_SCALE
        let a = Wad18::from_raw(WAD_SCALE + rem);
        let b = Wad18::from_raw(WAD_SCALE + rem);
        // (W + r)*(W + r) = W^2 + 2Wr + r^2.
        // Divided by W, remainder is (r^2) % W.
        // If (r^2) % W != 0, it must return InexactResult.
        if (rem as u128 * rem as u128) % (WAD_SCALE as u128) != 0 {
            let res = a.checked_mul(b);
            prop_assert!(matches!(res, Err(WadError::InexactResult)));
        }
    }

    /// 6. String serialization round-trip for exact values.
    #[test]
    fn test_string_parsing_exact(
        int_val in -1_000_000i64..1_000_000i64,
        frac_micro in 0i64..999_999i64,
    ) {
        let raw = (int_val as i128) * WAD_SCALE + (if int_val >= 0 { (frac_micro as i128) * 10i128.pow(12) } else { -(frac_micro as i128) * 10i128.pow(12) });
        let original = Wad18::from_raw(raw);
        let s = format!("{}", original);
        let parsed = Wad18::from_str(&s);
        prop_assert_eq!(parsed, Ok(original));
    }
}

/// 7. Failure Matrix Coverage: Ensure every single `WadError` variant is explicitly reachable and tested.
#[test]
fn test_failure_matrix_coverage() {
    // 1. WadError::Overflow
    let err_overflow = Wad18::MAX.checked_add(Wad18::from_raw(1));
    assert_eq!(err_overflow, Err(WadError::Overflow));

    // 2. WadError::Underflow
    let err_underflow = Wad18::MIN.checked_sub(Wad18::from_raw(1));
    assert_eq!(err_underflow, Err(WadError::Underflow));

    // 3. WadError::DivisionByZero
    let err_div_zero = Wad18::ONE.checked_div(Wad18::ZERO);
    assert_eq!(err_div_zero, Err(WadError::DivisionByZero));

    let err_ratio_zero = Wad18::from_ratio(1, 0);
    assert_eq!(err_ratio_zero, Err(WadError::DivisionByZero));

    // 4. WadError::InvalidScale
    let err_scale = Wad18::from_scaled(100, 10i128.pow(17));
    assert_eq!(err_scale, Err(WadError::InvalidScale));

    // 5. WadError::InvalidEncoding
    assert_eq!(Wad18::from_str(""), Err(WadError::InvalidEncoding));
    assert_eq!(Wad18::from_str("   "), Err(WadError::InvalidEncoding));
    assert_eq!(Wad18::from_str("1.2.3"), Err(WadError::InvalidEncoding));
    assert_eq!(Wad18::from_str("abc"), Err(WadError::InvalidEncoding));
    assert_eq!(Wad18::from_str("1.0e10"), Err(WadError::InvalidEncoding));
    assert_eq!(Wad18::from_str("--1.0"), Err(WadError::InvalidEncoding));

    // 6. WadError::OutOfRange
    let bound_min = Wad18::from_raw(10);
    let bound_max = Wad18::from_raw(100);
    let below = Wad18::from_raw(5);
    let above = Wad18::from_raw(150);
    assert_eq!(below.check_range(bound_min, bound_max), Err(WadError::OutOfRange));
    assert_eq!(above.check_range(bound_min, bound_max), Err(WadError::OutOfRange));
    assert_eq!(Wad18::from_raw(50).check_range(bound_min, bound_max), Ok(()));

    // 7. WadError::InexactResult
    // 1.0 / 3.0 has infinite repeating 3s, not representable in 10^-18 without remainder
    let one = Wad18::ONE;
    let three = Wad18::from_int(3).unwrap();
    assert_eq!(one.checked_div(three), Err(WadError::InexactResult));

    // String with non-zero digit beyond 18 decimal places
    let inexact_str = "0.0000000000000000001"; // 19 decimals
    assert_eq!(Wad18::from_str(inexact_str), Err(WadError::InexactResult));

    // Wide product high-128 overflow containment
    let extreme_prod = Wad18::MAX.checked_mul(Wad18::from_int(2).unwrap());
    assert_eq!(extreme_prod, Err(WadError::Overflow));

    // Division wide quotient overflow containment
    let extreme_div = Wad18::MAX.checked_div(Wad18::from_raw(1));
    assert_eq!(extreme_div, Err(WadError::Overflow));

    // Division quotient range check: 2 * i128::MAX fits in low_u128 (high_u128 == 0) but exceeds i128::MAX
    let half = Wad18::from_raw(500_000_000_000_000_000);
    assert_eq!(Wad18::MAX.checked_div(half), Err(WadError::Overflow));
}
