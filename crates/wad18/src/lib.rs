//! Safe Super Intelligence (SSI) Normative WAD-18 Fixed-Point Arithmetic.
//!
//! Enforces:
//! - Strict `#![no_std]` compliance.
//! - Pure integer-only 18-decimal fixed-point scaling (WAD-18 = 10^18).
//! - Zero IEEE 754 floating-point operations (#![deny(clippy::float_arithmetic)]).
//! - Wide 256-bit intermediate arithmetic preventing intermediate overflow.
//! - Exactness discipline: multiplication and division must be exact or return `InexactResult`.
//! - Explicit fail-closed errors for all numerical faults.

#![no_std]
#![deny(clippy::float_arithmetic)]

pub mod error;
pub mod wide;

pub use error::WadError;

/// Number of decimal places for standard WAD-18 fixed-point values.
pub const WAD_DECIMALS: u32 = 18;

/// Scaling factor: 10^18.
pub const WAD_SCALE: i128 = 1_000_000_000_000_000_000;

/// Unsigned WAD scaling factor: 10^18.
pub const WAD_SCALE_U128: u128 = 1_000_000_000_000_000_000;

/// Normative WAD-18 fixed-point integer value with 18 decimal places of precision.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Wad18(i128);

impl Wad18 {
    /// WAD-18 zero (0.0).
    pub const ZERO: Self = Self(0);

    /// WAD-18 unity (1.0 = 10^18).
    pub const ONE: Self = Self(WAD_SCALE);

    /// Minimum representable WAD-18 value (`i128::MIN`).
    pub const MIN: Self = Self(i128::MIN);

    /// Maximum representable WAD-18 value (`i128::MAX`).
    pub const MAX: Self = Self(i128::MAX);

    /// Construct directly from an already-scaled raw `i128` integer.
    #[inline]
    pub const fn from_raw(raw: i128) -> Self {
        Self(raw)
    }

    /// Access the underlying raw 10^-18 scaled `i128` integer.
    #[inline]
    pub const fn raw(&self) -> i128 {
        self.0
    }

    /// Construct from an unscaled integer: `val * 10^18`.
    pub fn from_int(val: i64) -> Result<Self, WadError> {
        Self::from_int_i128(val as i128)
    }

    /// Construct from an unscaled `i128` integer: `val * 10^18`.
    pub fn from_int_i128(val: i128) -> Result<Self, WadError> {
        match val.checked_mul(WAD_SCALE) {
            Some(raw) => Ok(Self(raw)),
            None => {
                if val > 0 {
                    Err(WadError::Overflow)
                } else {
                    Err(WadError::Underflow)
                }
            }
        }
    }

    /// Construct from raw integer with explicit scaling validation.
    pub fn from_scaled(raw: i128, scale: i128) -> Result<Self, WadError> {
        if scale != WAD_SCALE {
            return Err(WadError::InvalidScale);
        }
        Ok(Self(raw))
    }

    /// Construct from rational fraction `numerator / denominator` with exact WAD scaling.
    pub fn from_ratio(numerator: i128, denominator: i128) -> Result<Self, WadError> {
        if denominator == 0 {
            return Err(WadError::DivisionByZero);
        }
        Self::from_raw(numerator).checked_div(Self::from_raw(denominator))
    }

    /// Canonical big-endian fixed 16-byte serialization.
    #[inline]
    pub const fn to_canonical_bytes(&self) -> [u8; 16] {
        self.0.to_be_bytes()
    }

    /// Deterministic canonical big-endian deserialization.
    #[inline]
    pub const fn from_canonical_bytes(bytes: &[u8; 16]) -> Self {
        Self(i128::from_be_bytes(*bytes))
    }

    /// Validate that the value falls within an inclusive interval `[min, max]`.
    pub fn check_range(&self, min: Self, max: Self) -> Result<(), WadError> {
        if *self < min || *self > max {
            Err(WadError::OutOfRange)
        } else {
            Ok(())
        }
    }

    /// Checked fixed-point addition.
    pub fn checked_add(self, rhs: Self) -> Result<Self, WadError> {
        match self.0.checked_add(rhs.0) {
            Some(val) => Ok(Self(val)),
            None => {
                if self.0 > 0 && rhs.0 > 0 {
                    Err(WadError::Overflow)
                } else {
                    Err(WadError::Underflow)
                }
            }
        }
    }

    /// Checked fixed-point subtraction.
    pub fn checked_sub(self, rhs: Self) -> Result<Self, WadError> {
        match self.0.checked_sub(rhs.0) {
            Some(val) => Ok(Self(val)),
            None => {
                if self.0 >= 0 && rhs.0 < 0 {
                    Err(WadError::Overflow)
                } else {
                    Err(WadError::Underflow)
                }
            }
        }
    }

    /// Checked fixed-point multiplication with wide 256-bit intermediate math.
    ///
    /// Must be exact: if the product has a fractional component below 10^-18,
    /// returns `InexactResult`. Never silently rounds.
    pub fn checked_mul(self, rhs: Self) -> Result<Self, WadError> {
        let a = self.0;
        let b = rhs.0;

        if a == 0 || b == 0 {
            return Ok(Self::ZERO);
        }

        let negative = (a < 0) ^ (b < 0);
        let a_abs = a.unsigned_abs();
        let b_abs = b.unsigned_abs();

        let prod = wide::mul_u128(a_abs, b_abs);
        let wad_scale_u256 = wide::U256::from_u128(WAD_SCALE_U128);

        let (quotient, remainder) = match prod.div_rem(&wad_scale_u256) {
            Some(qr) => qr,
            None => return Err(WadError::DivisionByZero),
        };

        if !remainder.is_zero() {
            return Err(WadError::InexactResult);
        }

        if quotient.high_u128() != 0 {
            return if negative {
                Err(WadError::Underflow)
            } else {
                Err(WadError::Overflow)
            };
        }

        let q_u128 = quotient.low_u128();

        if negative {
            if q_u128 > (i128::MIN.unsigned_abs()) {
                return Err(WadError::Underflow);
            }
            if q_u128 == (i128::MIN.unsigned_abs()) {
                Ok(Self(i128::MIN))
            } else {
                Ok(Self(-(q_u128 as i128)))
            }
        } else {
            if q_u128 > (i128::MAX as u128) {
                return Err(WadError::Overflow);
            }
            Ok(Self(q_u128 as i128))
        }
    }

    /// Checked fixed-point division with wide 256-bit intermediate math.
    ///
    /// Must be exact: if `(a * 10^18) % b != 0`, returns `InexactResult`.
    /// Never silently rounds.
    pub fn checked_div(self, rhs: Self) -> Result<Self, WadError> {
        let a = self.0;
        let b = rhs.0;

        if b == 0 {
            return Err(WadError::DivisionByZero);
        }
        if a == 0 {
            return Ok(Self::ZERO);
        }

        let negative = (a < 0) ^ (b < 0);
        let a_abs = a.unsigned_abs();
        let b_abs = b.unsigned_abs();

        // Numerator = a_abs * 10^18 (widened to 256-bit)
        let num = wide::mul_u128(a_abs, WAD_SCALE_U128);
        let denom = wide::U256::from_u128(b_abs);

        let (quotient, remainder) = match num.div_rem(&denom) {
            Some(qr) => qr,
            None => return Err(WadError::DivisionByZero),
        };

        if !remainder.is_zero() {
            return Err(WadError::InexactResult);
        }

        if quotient.high_u128() != 0 {
            return if negative {
                Err(WadError::Underflow)
            } else {
                Err(WadError::Overflow)
            };
        }

        let q_u128 = quotient.low_u128();

        if negative {
            if q_u128 > (i128::MIN.unsigned_abs()) {
                return Err(WadError::Underflow);
            }
            if q_u128 == (i128::MIN.unsigned_abs()) {
                Ok(Self(i128::MIN))
            } else {
                Ok(Self(-(q_u128 as i128)))
            }
        } else {
            if q_u128 > (i128::MAX as u128) {
                return Err(WadError::Overflow);
            }
            Ok(Self(q_u128 as i128))
        }
    }

    /// Checked negation.
    pub fn checked_neg(self) -> Result<Self, WadError> {
        match self.0.checked_neg() {
            Some(val) => Ok(Self(val)),
            None => Err(WadError::Overflow),
        }
    }

    /// Checked absolute value.
    pub fn abs(self) -> Result<Self, WadError> {
        if self.0 >= 0 {
            Ok(self)
        } else {
            self.checked_neg()
        }
    }

    /// Sign indicator: -1, 0, or 1.
    pub fn signum(self) -> i8 {
        if self.0 > 0 {
            1
        } else if self.0 < 0 {
            -1
        } else {
            0
        }
    }

    /// Deterministic parsing from string without IEEE floating point.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self, WadError> {
        let clean = s.trim();
        if clean.is_empty() {
            return Err(WadError::InvalidEncoding);
        }

        let (negative, num_str) = if let Some(stripped) = clean.strip_prefix('-') {
            (true, stripped)
        } else if let Some(stripped) = clean.strip_prefix('+') {
            (false, stripped)
        } else {
            (false, clean)
        };

        if num_str.is_empty() {
            return Err(WadError::InvalidEncoding);
        }

        let mut parts = num_str.split('.');
        let int_str = parts.next().unwrap_or("");
        let frac_str = parts.next();

        if parts.next().is_some() {
            return Err(WadError::InvalidEncoding); // Multiple dots
        }

        let mut int_val: i128 = 0;
        if !int_str.is_empty() {
            for b in int_str.bytes() {
                if !b.is_ascii_digit() {
                    return Err(WadError::InvalidEncoding);
                }
                let digit = (b - b'0') as i128;
                int_val = int_val
                    .checked_mul(10)
                    .and_then(|v| v.checked_add(digit))
                    .ok_or(if negative {
                        WadError::Underflow
                    } else {
                        WadError::Overflow
                    })?;
            }
        }

        let mut frac_val: i128 = 0;
        if let Some(frac) = frac_str {
            if frac.is_empty() {
                return Err(WadError::InvalidEncoding);
            }
            let bytes = frac.as_bytes();
            let len = bytes.len();

            // First check if any digits beyond 18 are non-zero -> InexactResult
            if len > 18 {
                for &b in &bytes[18..] {
                    if !b.is_ascii_digit() {
                        return Err(WadError::InvalidEncoding);
                    }
                    if b != b'0' {
                        return Err(WadError::InexactResult);
                    }
                }
            }

            let parse_len = if len < 18 { len } else { 18 };
            for &b in &bytes[..parse_len] {
                if !b.is_ascii_digit() {
                    return Err(WadError::InvalidEncoding);
                }
                let digit = (b - b'0') as i128;
                frac_val = (frac_val * 10) + digit;
            }

            // Pad remaining decimal places up to 18
            for _ in parse_len..18 {
                frac_val *= 10;
            }
        }

        let scaled_int = int_val
            .checked_mul(WAD_SCALE)
            .ok_or(if negative {
                WadError::Underflow
            } else {
                WadError::Overflow
            })?;

        let total_raw = scaled_int
            .checked_add(frac_val)
            .ok_or(if negative {
                WadError::Underflow
            } else {
                WadError::Overflow
            })?;

        if negative {
            match total_raw.checked_neg() {
                Some(neg_val) => Ok(Self(neg_val)),
                None => Err(WadError::Underflow),
            }
        } else {
            Ok(Self(total_raw))
        }
    }
}

impl core::fmt::Display for Wad18 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.0 < 0 {
            write!(f, "-")?;
        }
        let abs_val = self.0.unsigned_abs();
        let int_part = abs_val / WAD_SCALE_U128;
        let frac_part = abs_val % WAD_SCALE_U128;
        write!(f, "{}.{:018}", int_part, frac_part)
    }
}

impl core::str::FromStr for Wad18 {
    type Err = WadError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str(s)
    }
}
