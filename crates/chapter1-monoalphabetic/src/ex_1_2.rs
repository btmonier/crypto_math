//! Exercise 1.2 - Greatest common divisor and the Division Algorithm.
//!
//! > Write a computer program to compute the greatest common divisor of two
//! > integers. (If you really want to have fun, write two versions of this
//! > program, one recursive and the other iterative.)
//!
//! Both versions implement the Euclidean algorithm and return a non-negative
//! result, so negative inputs (and `gcd(0, 0) == 0`) behave sensibly.
//!
//! > Write a computer program to implement the Division Algorithm. The input
//! > should be two integers `a` and `b`, and the output should be the quotient
//! > and the remainder when `a` is divided by `b`.
//!
//! The Division Algorithm guarantees that for any integers `a` and `b` with
//! `b != 0` there exist *unique* integers `q` (quotient) and `r` (remainder)
//! such that `a == b * q + r` with `0 <= r < |b|`. Note this is subtly
//! different from Rust's built-in `/` and `%`, which truncate toward zero and
//! therefore let the remainder take the sign of `a`. The implementation below
//! adjusts those primitives (the "DIV" and "MOD" mentioned in the hint) so the
//! remainder is always non-negative, matching the theorem.

/// Greatest common divisor computed iteratively via the Euclidean algorithm.
pub fn gcd_iterative(a: i64, b: i64) -> i64 {
    let (mut a, mut b) = (a.abs(), b.abs());
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}

/// Greatest common divisor computed recursively via the Euclidean algorithm.
pub fn gcd_recursive(a: i64, b: i64) -> i64 {
    if b == 0 {
        a.abs()
    } else {
        gcd_recursive(b, a % b)
    }
}

/// Result of applying the Division Algorithm to a pair of integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Division {
    /// The quotient `q` in `a == b * q + r`.
    pub quotient: i64,
    /// The remainder `r`, normalized so that `0 <= r < |b|`.
    pub remainder: i64,
}

/// Implement the Division Algorithm: given integers `a` and `b` (with
/// `b != 0`), return the unique quotient and remainder satisfying
/// `a == b * quotient + remainder` and `0 <= remainder < |b|`.
///
/// # Panics
///
/// Panics if `b == 0`, since division by zero is undefined.
pub fn divide(a: i64, b: i64) -> Division {
    assert!(b != 0, "the divisor `b` must be non-zero");

    // Rust's `%` (MOD) takes the sign of `a`; fold it into `0..|b|` so the
    // remainder matches the Division Algorithm's guarantee.
    let remainder = ((a % b) + b.abs()) % b.abs();
    // With the remainder pinned down, the quotient (DIV) follows exactly.
    let quotient = (a - remainder) / b;

    Division {
        quotient,
        remainder,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_versions_agree_on_examples() {
        let cases = [
            ((48, 18), 6),
            ((17, 5), 1),
            ((0, 9), 9),
            ((9, 0), 9),
            ((0, 0), 0),
            ((1071, 462), 21),
        ];
        for ((a, b), expected) in cases {
            assert_eq!(gcd_iterative(a, b), expected);
            assert_eq!(gcd_recursive(a, b), expected);
        }
    }

    #[test]
    fn handles_negative_inputs() {
        assert_eq!(gcd_iterative(-48, 18), 6);
        assert_eq!(gcd_recursive(-48, 18), 6);
        assert_eq!(gcd_iterative(-48, -18), 6);
        assert_eq!(gcd_recursive(-48, -18), 6);
    }

    #[test]
    fn iterative_and_recursive_match_over_range() {
        for a in -50..=50 {
            for b in -50..=50 {
                assert_eq!(gcd_iterative(a, b), gcd_recursive(a, b));
            }
        }
    }

    #[test]
    fn division_algorithm_examples() {
        // a, b, expected quotient, expected remainder.
        let cases = [
            (17, 5, 3, 2),
            (-17, 5, -4, 3),
            (17, -5, -3, 2),
            (-17, -5, 4, 3),
            (20, 4, 5, 0),
            (0, 7, 0, 0),
        ];
        for (a, b, q, r) in cases {
            assert_eq!(divide(a, b), Division { quotient: q, remainder: r });
        }
    }

    #[test]
    fn division_algorithm_invariants_hold_over_range() {
        for a in -50..=50 {
            for b in -50..=50 {
                if b == 0 {
                    continue;
                }
                let Division { quotient, remainder } = divide(a, b);
                // a == b * q + r
                assert_eq!(a, b * quotient + remainder);
                // 0 <= r < |b|
                assert!(remainder >= 0 && remainder < b.abs());
            }
        }
    }

    #[test]
    #[should_panic(expected = "non-zero")]
    fn division_by_zero_panics() {
        divide(5, 0);
    }
}
