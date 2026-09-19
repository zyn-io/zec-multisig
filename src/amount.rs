//! Deterministic fixed-point arithmetic — part of the microchain VM spec.
//!
//! Every Zyn VM that moves value uses this type. It lives in the spec rather
//! than in an application because two VMs that round differently cannot be
//! settled against the same commitment, and because a VM author reimplementing
//! fixed-point is a VM author reimplementing a class of bug.
//!
//! All monetary and quantity values in the VM are `Fixed`: a signed 128-bit
//! integer scaled by `WAD` (1e18). The scale matches Solidity's WAD convention
//! so values cross the settlement boundary without rescaling.
//!
//! Two properties matter more than speed here:
//!
//! 1. **No silent wrapping.** Every operation is checked and returns `Option`.
//!    A margin engine that wraps on overflow is a margin engine that mints money.
//! 2. **Bit-identical results everywhere.** No floats, no platform-dependent
//!    behaviour, no compiler-reorderable associativity. Re-executing a
//!    transaction stream on any machine must produce the same state root.
//!
//! `mul` and `div` need a 256-bit intermediate: a price near 1e6 and a memecoin
//! quantity near 1e12, both WAD-scaled, produce a product around 1e42 — well past
//! i128's 1.7e38 ceiling. We compute the full 256-bit product and divide it back
//! down, so only the *result* must fit in i128, not the intermediate.

use std::format;
use core::cmp::Ordering;
use core::fmt;

/// Scaling factor: all `Fixed` values are integers scaled by 1e18.
pub const WAD: i128 = 1_000_000_000_000_000_000;

#[derive(Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Fixed(pub i128);

impl Fixed {
    pub const ZERO: Fixed = Fixed(0);
    pub const ONE: Fixed = Fixed(WAD);

    /// Construct from a whole number of units (e.g. `Fixed::whole(5)` == 5.0).
    pub const fn whole(n: i64) -> Fixed {
        Fixed((n as i128) * WAD)
    }

    /// Construct from a raw WAD-scaled integer.
    pub const fn raw(v: i128) -> Fixed {
        Fixed(v)
    }

    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
    pub const fn is_positive(self) -> bool {
        self.0 > 0
    }
    pub const fn is_negative(self) -> bool {
        self.0 < 0
    }

    pub fn abs(self) -> Option<Fixed> {
        self.0.checked_abs().map(Fixed)
    }

    pub fn neg(self) -> Option<Fixed> {
        self.0.checked_neg().map(Fixed)
    }

    pub fn add(self, o: Fixed) -> Option<Fixed> {
        self.0.checked_add(o.0).map(Fixed)
    }

    pub fn sub(self, o: Fixed) -> Option<Fixed> {
        self.0.checked_sub(o.0).map(Fixed)
    }

    pub fn min(self, o: Fixed) -> Fixed {
        if self.0 <= o.0 {
            self
        } else {
            o
        }
    }

    pub fn max(self, o: Fixed) -> Fixed {
        if self.0 >= o.0 {
            self
        } else {
            o
        }
    }

    /// `self * o`, rounding the magnitude toward zero.
    pub fn mul(self, o: Fixed) -> Option<Fixed> {
        mul_div(self.0, o.0, WAD).map(Fixed)
    }

    /// `self / o`, rounding the magnitude toward zero. `None` on divide-by-zero.
    pub fn div(self, o: Fixed) -> Option<Fixed> {
        if o.0 == 0 {
            return None;
        }
        mul_div(self.0, WAD, o.0).map(Fixed)
    }

    /// `self * num / den` in one step, keeping full precision in the
    /// intermediate. Prefer this over chained mul/div: it neither loses a
    /// rounding step nor overflows on the intermediate.
    pub fn mul_div(self, num: Fixed, den: Fixed) -> Option<Fixed> {
        if den.0 == 0 {
            return None;
        }
        mul_div(self.0, num.0, den.0).map(Fixed)
    }

    /// `self * num / den`, rounding the magnitude *away* from zero.
    ///
    /// The counterpart to `mul_div` for quantities a caller must pay rather
    /// than receive. Truncation always moves a figure toward zero, which
    /// favours whoever is on the receiving end of it; for a required input that
    /// is the wrong side, so this rounds the other way.
    pub fn mul_div_ceil(self, num: Fixed, den: Fixed) -> Option<Fixed> {
        if den.0 == 0 {
            return None;
        }
        mul_div_ceil(self.0, num.0, den.0).map(Fixed)
    }
}

impl Ord for Fixed {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}
impl PartialOrd for Fixed {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for Fixed {
    /// Renders as a decimal for readable test output. Never used in consensus.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let neg = self.0 < 0;
        let v = self.0.unsigned_abs();
        let int = v / (WAD as u128);
        let frac = v % (WAD as u128);
        let mut frac_s = format!("{:018}", frac);
        while frac_s.len() > 1 && frac_s.ends_with('0') {
            frac_s.pop();
        }
        write!(f, "{}{}.{}", if neg { "-" } else { "" }, int, frac_s)
    }
}

impl fmt::Display for Fixed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

// ---------------------------------------------------------------------------
// 256-bit intermediate arithmetic
// ---------------------------------------------------------------------------

/// `a * b / den`, computed with a full 256-bit intermediate product.
///
/// Rounds the magnitude toward zero (truncation on the absolute value), so the
/// result is sign-symmetric: `mul_div(-a, b, d) == -mul_div(a, b, d)`. Symmetry
/// matters because a rounding rule that favours one sign leaks value to one side
/// of the book.
///
/// Returns `None` if `den == 0` or the result does not fit in i128.
pub fn mul_div(a: i128, b: i128, den: i128) -> Option<i128> {
    if den == 0 {
        return None;
    }
    let neg = (a < 0) ^ (b < 0) ^ (den < 0);
    let (hi, lo) = mul_full(a.unsigned_abs(), b.unsigned_abs());
    let q = div_256_by_128(hi, lo, den.unsigned_abs())?;

    if neg {
        // i128::MIN has no positive counterpart; its magnitude is MAX+1.
        if q > (i128::MAX as u128) + 1 {
            None
        } else if q == (i128::MAX as u128) + 1 {
            Some(i128::MIN)
        } else {
            Some(-(q as i128))
        }
    } else if q > i128::MAX as u128 {
        None
    } else {
        Some(q as u128 as i128)
    }
}

/// `a * b / den`, rounding the magnitude away from zero.
///
/// Sign-symmetric like `mul_div`: the rounding is applied to the absolute value
/// and the sign restored afterwards, so it never favours one direction of a
/// trade over the other.
pub fn mul_div_ceil(a: i128, b: i128, den: i128) -> Option<i128> {
    if den == 0 {
        return None;
    }
    let neg = (a < 0) ^ (b < 0) ^ (den < 0);
    let (hi, lo) = mul_full(a.unsigned_abs(), b.unsigned_abs());
    let (q, rem) = div_256_rem(hi, lo, den.unsigned_abs())?;
    let q = if rem != 0 { q.checked_add(1)? } else { q };

    if neg {
        if q > (i128::MAX as u128) + 1 {
            None
        } else if q == (i128::MAX as u128) + 1 {
            Some(i128::MIN)
        } else {
            Some(-(q as i128))
        }
    } else if q > i128::MAX as u128 {
        None
    } else {
        Some(q as i128)
    }
}

/// Full 128x128 -> 256 bit unsigned multiply, returned as (high, low).
fn mul_full(a: u128, b: u128) -> (u128, u128) {
    const MASK: u128 = u64::MAX as u128;
    let (a_lo, a_hi) = (a & MASK, a >> 64);
    let (b_lo, b_hi) = (b & MASK, b >> 64);

    let ll = a_lo * b_lo;
    let lh = a_lo * b_hi;
    let hl = a_hi * b_lo;
    let hh = a_hi * b_hi;

    // Sum the three partial products that straddle the 64-bit boundary,
    // carrying into the high word. Each addend is < 2^128 and the running sum
    // cannot overflow because (2^64-1)^2 + 2*(2^64-1) < 2^128.
    let mid = (ll >> 64) + (lh & MASK) + (hl & MASK);
    let lo = (ll & MASK) | (mid << 64);
    let hi = hh + (lh >> 64) + (hl >> 64) + (mid >> 64);
    (hi, lo)
}

/// Divide a 256-bit unsigned value (hi:lo) by a 128-bit divisor.
///
/// Returns `None` when the quotient would exceed 128 bits.
fn div_256_by_128(hi: u128, lo: u128, den: u128) -> Option<u128> {
    div_256_rem(hi, lo, den).map(|(q, _)| q)
}

/// As `div_256_by_128`, but also returning the remainder.
///
/// The remainder is what tells `mul_div_ceil` whether the division was exact.
/// Deriving it afterwards would mean a second 256-bit multiply; the long
/// division already has it.
fn div_256_rem(hi: u128, lo: u128, den: u128) -> Option<(u128, u128)> {
    if den == 0 {
        return None;
    }
    // Fast path: the common case, where the product fit in 128 bits anyway.
    if hi == 0 {
        return Some((lo / den, lo % den));
    }
    // Quotient would overflow 128 bits.
    if hi >= den {
        return None;
    }

    // Shift-subtract long division, MSB first. 256 iterations, branch-free
    // enough to be predictable and — more importantly — exactly reproducible.
    let mut rem: u128 = hi;
    let mut quo: u128 = 0;
    let mut i = 128;
    while i > 0 {
        i -= 1;
        let bit = (lo >> i) & 1;
        // rem = rem*2 + bit. Safe: rem < den <= u128::MAX, and we check the
        // top bit before shifting.
        let carry_out = rem >> 127;
        rem = (rem << 1) | bit;
        if carry_out == 1 || rem >= den {
            rem = rem.wrapping_sub(den);
            quo |= 1u128 << i;
        }
    }
    Some((quo, rem))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_and_raw_agree() {
        assert_eq!(Fixed::whole(3).0, 3 * WAD);
        assert_eq!(Fixed::ONE, Fixed::whole(1));
    }

    #[test]
    fn mul_is_exact_for_simple_values() {
        let a = Fixed::whole(7);
        let b = Fixed::whole(6);
        assert_eq!(a.mul(b).unwrap(), Fixed::whole(42));
    }

    #[test]
    fn div_round_trips() {
        let a = Fixed::whole(100);
        let b = Fixed::whole(8);
        let q = a.div(b).unwrap();
        assert_eq!(q, Fixed::raw(12_500_000_000_000_000_000));
        assert_eq!(q.mul(b).unwrap(), a);
    }

    #[test]
    fn identity_multiplication() {
        let v = Fixed::raw(123_456_789_987_654_321);
        assert_eq!(v.mul(Fixed::ONE).unwrap(), v);
        assert_eq!(v.div(Fixed::ONE).unwrap(), v);
    }

    /// The case that motivates 256-bit intermediates: a memecoin price with
    /// eight leading zeros against a quantity in the billions. The naive
    /// i128 product overflows; the result is small and perfectly representable.
    #[test]
    fn memecoin_notional_does_not_overflow() {
        let price = Fixed::raw(12_310_000_000_000); // 0.00001231
        let qty = Fixed::whole(300_000_000); // 300M tokens
        let notional = price.mul(qty).unwrap();
        assert_eq!(notional, Fixed::raw(3_693_000_000_000_000_000_000)); // 3693.0
    }

    #[test]
    fn large_product_would_overflow_i128_but_fits_here() {
        // 1e18 * 1e18 as WAD values: raw operands are 1e36 each, product 1e72.
        let big = Fixed::whole(1_000_000_000_000_000_000);
        // big * 1.0 is fine.
        assert_eq!(big.mul(Fixed::ONE).unwrap(), big);
        // big * big genuinely does not fit in the result type.
        assert_eq!(big.mul(big), None);
    }

    #[test]
    fn rounding_is_sign_symmetric() {
        // 1 / 3 truncates; the negative case must truncate to the mirror value,
        // not floor, or shorts and longs round differently.
        let third = Fixed::ONE.div(Fixed::whole(3)).unwrap();
        let neg_third = Fixed::whole(-1).div(Fixed::whole(3)).unwrap();
        assert_eq!(third.0, 333_333_333_333_333_333);
        assert_eq!(neg_third.0, -333_333_333_333_333_333);
        assert_eq!(neg_third, third.neg().unwrap());
    }

    #[test]
    fn mul_div_keeps_precision_that_chaining_loses() {
        // (1/3) * 3 chained loses a unit; mul_div keeps it.
        let one_third_chained = Fixed::ONE
            .div(Fixed::whole(3))
            .unwrap()
            .mul(Fixed::whole(3))
            .unwrap();
        assert_eq!(one_third_chained, Fixed::raw(999_999_999_999_999_999));

        let exact = Fixed::ONE
            .mul_div(Fixed::whole(3), Fixed::whole(3))
            .unwrap();
        assert_eq!(exact, Fixed::ONE);
    }

    #[test]
    fn division_by_zero_is_none_not_panic() {
        assert_eq!(Fixed::ONE.div(Fixed::ZERO), None);
        assert_eq!(Fixed::ONE.mul_div(Fixed::ONE, Fixed::ZERO), None);
    }

    #[test]
    fn addition_overflow_is_caught() {
        assert_eq!(Fixed::raw(i128::MAX).add(Fixed::ONE), None);
        assert_eq!(Fixed::raw(i128::MIN).sub(Fixed::ONE), None);
        assert_eq!(Fixed::raw(i128::MIN).abs(), None);
    }

    #[test]
    fn mul_full_matches_school_multiplication() {
        let (hi, lo) = mul_full(u128::MAX, u128::MAX);
        // (2^128-1)^2 = 2^256 - 2^129 + 1
        assert_eq!(hi, u128::MAX - 1);
        assert_eq!(lo, 1);
    }

    #[test]
    fn div_256_handles_full_width_numerator() {
        // (2^128-1)*(2^128-1) / (2^128-1) == 2^128-1
        let (hi, lo) = mul_full(u128::MAX, u128::MAX);
        assert_eq!(div_256_by_128(hi, lo, u128::MAX), Some(u128::MAX));
        // Quotient too large to represent.
        assert_eq!(div_256_by_128(hi, lo, 1), None);
    }

    #[test]
    fn div_256_reports_the_remainder() {
        assert_eq!(div_256_rem(0, 10, 3), Some((3, 1)));
        assert_eq!(div_256_rem(0, 9, 3), Some((3, 0)));
        // Through the long-division path, where hi != 0.
        let (hi, lo) = mul_full(u128::MAX, u128::MAX);
        assert_eq!(div_256_rem(hi, lo, u128::MAX), Some((u128::MAX, 0)));
    }

    #[test]
    fn ceiling_rounds_away_from_zero_only_when_inexact() {
        // Exact divisions must not be bumped.
        assert_eq!(
            Fixed::whole(6)
                .mul_div_ceil(Fixed::whole(2), Fixed::whole(3))
                .unwrap(),
            Fixed::whole(4)
        );
        // 1/3 rounds up by exactly one raw unit against mul_div's truncation.
        let down = Fixed::ONE.mul_div(Fixed::ONE, Fixed::whole(3)).unwrap();
        let up = Fixed::ONE
            .mul_div_ceil(Fixed::ONE, Fixed::whole(3))
            .unwrap();
        assert_eq!(down.0, 333_333_333_333_333_333);
        assert_eq!(up.0, 333_333_333_333_333_334);
    }

    #[test]
    fn ceiling_is_sign_symmetric_too() {
        // Away from zero on both sides, so a rounding rule cannot leak value to
        // one direction of a trade.
        let pos = Fixed::ONE
            .mul_div_ceil(Fixed::ONE, Fixed::whole(3))
            .unwrap();
        let neg = Fixed::whole(-1)
            .mul_div_ceil(Fixed::ONE, Fixed::whole(3))
            .unwrap();
        assert_eq!(neg, pos.neg().unwrap());
    }

    #[test]
    fn ceiling_reports_the_same_failures_as_truncation() {
        assert_eq!(Fixed::ONE.mul_div_ceil(Fixed::ONE, Fixed::ZERO), None);
        let big = Fixed::whole(1_000_000_000_000_000_000);
        assert_eq!(mul_div_ceil(big.0, big.0, 1), None);
    }

    #[test]
    fn debug_rendering_is_readable() {
        assert_eq!(format!("{:?}", Fixed::whole(42)), "42.0");
        assert_eq!(
            format!("{:?}", Fixed::raw(12_310_000_000_000)),
            "0.00001231"
        );
        assert_eq!(format!("{:?}", Fixed::whole(-7)), "-7.0");
    }
}
