//! Exercise 1.4 - Additive inverses modulo `n`.
//!
//! > Write a computer program that accepts as input two integers `a` and `n`
//! > and outputs the additive inverse of `a (mod n)`.
//!
//! The additive inverse of `a` modulo `n` is the unique residue `b` in the
//! range `0 <= b < n` such that
//!
//! ```text
//! a + b ≡ 0 (mod n).
//! ```
//!
//! Concretely `b = (-a) mod n`. Reducing with a normalizing modulo keeps the
//! result in the canonical range `0..n` even when `a` is negative or larger in
//! magnitude than `n` (for example the additive inverse of `0` is `0`, not `n`).

use crypto_core::modular::modulo;

/// Compute the additive inverse of `a` modulo `n`, i.e. the unique `b` with
/// `0 <= b < n` and `a + b ≡ 0 (mod n)`.
///
/// # Panics
///
/// Panics if `n <= 0`, since additive inverses modulo `n` are only defined for
/// a positive modulus.
pub fn additive_inverse(a: i64, n: i64) -> i64 {
    assert!(n > 0, "the modulus `n` must be positive");
    modulo(-a, n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn additive_inverse_examples() {
        // 7 + 19 = 26 ≡ 0 (mod 26).
        assert_eq!(additive_inverse(7, 26), 19);
        // 0 is its own additive inverse.
        assert_eq!(additive_inverse(0, 26), 0);
        // 1 + 4 = 5 ≡ 0 (mod 5).
        assert_eq!(additive_inverse(1, 5), 4);
    }

    #[test]
    fn handles_negative_and_large_inputs() {
        // -7 ≡ 19 (mod 26), whose additive inverse is 7.
        assert_eq!(additive_inverse(-7, 26), 7);
        // 30 ≡ 4 (mod 26), whose additive inverse is 22.
        assert_eq!(additive_inverse(30, 26), 22);
    }

    #[test]
    fn inverse_sums_to_zero_over_range() {
        for n in 1..=50 {
            for a in -100..=100 {
                let b = additive_inverse(a, n);
                assert!(b >= 0 && b < n);
                assert_eq!(modulo(a + b, n), 0);
            }
        }
    }

    #[test]
    #[should_panic(expected = "positive")]
    fn non_positive_modulus_panics() {
        additive_inverse(3, 0);
    }
}
