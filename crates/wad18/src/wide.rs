//! Unsigned 256-bit wide arithmetic for exact WAD-18 fixed-point operations.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct U256 {
    pub limbs: [u64; 4],
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        for i in (0..4).rev() {
            if self.limbs[i] != other.limbs[i] {
                return self.limbs[i].cmp(&other.limbs[i]);
            }
        }
        core::cmp::Ordering::Equal
    }
}

impl U256 {
    pub const ZERO: Self = Self { limbs: [0; 4] };
    pub const ONE: Self = Self { limbs: [1, 0, 0, 0] };

    pub const fn from_u128(val: u128) -> Self {
        Self {
            limbs: [val as u64, (val >> 64) as u64, 0, 0],
        }
    }

    pub const fn low_u128(&self) -> u128 {
        (self.limbs[0] as u128) | ((self.limbs[1] as u128) << 64)
    }

    pub const fn high_u128(&self) -> u128 {
        (self.limbs[2] as u128) | ((self.limbs[3] as u128) << 64)
    }

    pub const fn is_zero(&self) -> bool {
        self.limbs[0] == 0 && self.limbs[1] == 0 && self.limbs[2] == 0 && self.limbs[3] == 0
    }

    pub fn shift_left_1(&mut self) {
        let mut carry = 0u64;
        for limb in self.limbs.iter_mut() {
            let next_carry = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = next_carry;
        }
    }

    pub const fn bit(&self, i: usize) -> bool {
        let limb_idx = i / 64;
        let bit_idx = i % 64;
        ((self.limbs[limb_idx] >> bit_idx) & 1) != 0
    }

    pub fn set_bit(&mut self, i: usize) {
        let limb_idx = i / 64;
        let bit_idx = i % 64;
        self.limbs[limb_idx] |= 1u64 << bit_idx;
    }

    pub fn sub(&self, other: &Self) -> Self {
        let mut res = [0u64; 4];
        let mut borrow = 0u128;
        for (i, item) in res.iter_mut().enumerate() {
            let a = self.limbs[i] as u128;
            let b = (other.limbs[i] as u128) + borrow;
            if a >= b {
                *item = (a - b) as u64;
                borrow = 0;
            } else {
                *item = ((1u128 << 64) + a - b) as u64;
                borrow = 1;
            }
        }
        Self { limbs: res }
    }

    /// Bit-by-bit non-restoring long division returning (quotient, remainder).
    pub fn div_rem(&self, divisor: &Self) -> Option<(Self, Self)> {
        if divisor.is_zero() {
            return None;
        }
        if self < divisor {
            return Some((Self::ZERO, *self));
        }
        if self == divisor {
            return Some((Self::ONE, Self::ZERO));
        }

        let mut quotient = Self::ZERO;
        let mut remainder = Self::ZERO;

        for i in (0..256).rev() {
            remainder.shift_left_1();
            if self.bit(i) {
                remainder.limbs[0] |= 1;
            }
            if remainder >= *divisor {
                remainder = remainder.sub(divisor);
                quotient.set_bit(i);
            }
        }
        Some((quotient, remainder))
    }
}

/// Exact 128-bit * 128-bit -> 256-bit unsigned multiplication.
pub fn mul_u128(x: u128, y: u128) -> U256 {
    let a0 = x as u64 as u128;
    let a1 = x >> 64;
    let b0 = y as u64 as u128;
    let b1 = y >> 64;

    let p0 = a0 * b0;
    let p1 = a0 * b1;
    let p2 = a1 * b0;
    let p3 = a1 * b1;

    let l0 = p0 as u64;
    let carry0 = p0 >> 64;

    let mid1 = p1 + carry0;
    let mid_lo = mid1 as u64 as u128;
    let mid_hi = mid1 >> 64;

    let mid2 = p2 + mid_lo;
    let l1 = mid2 as u64;
    let carry1 = (mid2 >> 64) + mid_hi;

    let high = p3 + carry1;
    let l2 = high as u64;
    let l3 = (high >> 64) as u64;

    U256 { limbs: [l0, l1, l2, l3] }
}
