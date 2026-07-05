//! Exercise 1.4 - Modular arithmetic operations.
//!
//! **Question 1** – Additive inverses modulo `n`.
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
//!
//! ---
//!
//! **Question 2** – Modular addition and multiplication.
//!
//! > Write a program that accepts three integers `a`, `b`, and `n` as input
//! > and then outputs `a +_{n} b` and `a \times_{n} b`.
//!
//! `a +_{n} b` (addition modulo `n`) and `a \times_{n} b` (multiplication modulo `n`)
//! are defined as
//!
//! ```text
//! a +_{n} b = (a + b) mod n
//! a \times_{n} b = (a * b) mod n
//! ```
//!
//! where `mod n` always produces the canonical representative in `0..n`.

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

/// Compute `a +_{n} b`, i.e. `(a + b) mod n`.
///
/// The result is always in the canonical range `0..n`.
///
/// # Panics
///
/// Panics if `n <= 0`.
pub fn mod_add(a: i64, b: i64, n: i64) -> i64 {
    assert!(n > 0, "the modulus `n` must be positive");
    modulo(a + b, n)
}

/// Compute `a \times_{n} b`, i.e. `(a * b) mod n`.
///
/// The result is always in the canonical range `0..n`.
///
/// # Panics
///
/// Panics if `n <= 0`.
pub fn mod_mul(a: i64, b: i64, n: i64) -> i64 {
    assert!(n > 0, "the modulus `n` must be positive");
    // Use i128 for the intermediate product to avoid overflow before reducing.
    modulo(((a as i128 * b as i128) % n as i128) as i64, n)
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

    // --- Question 2: mod_add and mod_mul ---

    #[test]
    fn mod_add_examples() {
        // 7 +₂₆ 21 = 28 mod 26 = 2
        assert_eq!(mod_add(7, 21, 26), 2);
        // 0 +ₙ 0 is always 0
        assert_eq!(mod_add(0, 0, 5), 0);
        // Wraps around once
        assert_eq!(mod_add(4, 3, 5), 2);
    }

    #[test]
    fn mod_mul_examples() {
        // 7 ×₂₆ 4 = 28 mod 26 = 2
        assert_eq!(mod_mul(7, 4, 26), 2);
        // 5 ×₅ 5 = 25 mod 5 = 0
        assert_eq!(mod_mul(5, 5, 5), 0);
        // 3 ×₇ 5 = 15 mod 7 = 1
        assert_eq!(mod_mul(3, 5, 7), 1);
    }

    #[test]
    fn mod_add_handles_negative_inputs() {
        // -1 +₂₆ 1 = 0
        assert_eq!(mod_add(-1, 1, 26), 0);
        // -3 +₅ -3 ≡ (-6) mod 5 = 4
        assert_eq!(mod_add(-3, -3, 5), 4);
    }

    #[test]
    fn mod_mul_handles_negative_inputs() {
        // -1 ×₂₆ 2 = -2 mod 26 = 24
        assert_eq!(mod_mul(-1, 2, 26), 24);
    }

    #[test]
    fn mod_add_result_always_in_range() {
        for n in 1..=50 {
            for a in -100..=100i64 {
                for b in -100..=100i64 {
                    let r = mod_add(a, b, n);
                    assert!(r >= 0 && r < n);
                }
            }
        }
    }

    #[test]
    fn mod_mul_result_always_in_range() {
        for n in 1..=50 {
            for a in -50..=50i64 {
                for b in -50..=50i64 {
                    let r = mod_mul(a, b, n);
                    assert!(r >= 0 && r < n);
                }
            }
        }
    }
}
