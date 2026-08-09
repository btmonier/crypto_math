//! Exercise 2.2.1 - Factorial, permutations, and combinations.
//!
//! > Write a computer function (either recursive or iterative) that computes
//! > `n!`. Then incorporate this function into a program that computes
//! > `P(n, r)` and `C(n, r)` for any legitimate values of `n` and `r`.
//! > (Legitimate values of `n` are non-negative integers and legitimate values
//! > of `r` are those non-negative integers that are less than or equal to `n`.)
//!
//! Both an iterative and a recursive factorial are provided. Permutations and
//! combinations are then expressed in the usual way:
//!
//! - `P(n, r) = n! / (n - r)!`
//! - `C(n, r) = n! / (r! · (n - r)!)`
//!
//! Results use `u64`, so callers must keep `n` small enough that the
//! intermediate factorials fit (`20!` is the largest that does).

/// `n!` computed iteratively. `0!` is defined to be `1`.
///
/// # Panics
///
/// Panics if `n!` overflows a `u64` (i.e. when `n > 20`).
pub fn factorial_iterative(n: u64) -> u64 {
    let mut result = 1u64;
    for k in 2..=n {
        result = result
            .checked_mul(k)
            .unwrap_or_else(|| panic!("{n}! overflows a u64"));
    }
    result
}

/// `n!` computed recursively. `0!` is defined to be `1`.
///
/// # Panics
///
/// Panics if `n!` overflows a `u64` (i.e. when `n > 20`).
pub fn factorial_recursive(n: u64) -> u64 {
    if n <= 1 {
        1
    } else {
        n.checked_mul(factorial_recursive(n - 1))
            .unwrap_or_else(|| panic!("{n}! overflows a u64"))
    }
}

/// The number of permutations of `n` objects taken `r` at a time:
/// `P(n, r) = n! / (n - r)!`.
///
/// # Panics
///
/// Panics if `r > n`, or if an intermediate factorial overflows a `u64`.
pub fn permutations(n: u64, r: u64) -> u64 {
    assert!(r <= n, "r ({r}) must be less than or equal to n ({n})");
    factorial_iterative(n) / factorial_iterative(n - r)
}

/// The number of combinations of `n` objects taken `r` at a time:
/// `C(n, r) = n! / (r! · (n - r)!)`.
///
/// # Panics
///
/// Panics if `r > n`, or if an intermediate factorial overflows a `u64`.
pub fn combinations(n: u64, r: u64) -> u64 {
    assert!(r <= n, "r ({r}) must be less than or equal to n ({n})");
    factorial_iterative(n) / (factorial_iterative(r) * factorial_iterative(n - r))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factorial_known_values() {
        let expected = [
            (0, 1),
            (1, 1),
            (2, 2),
            (3, 6),
            (4, 24),
            (5, 120),
            (10, 3_628_800),
            (20, 2_432_902_008_176_640_000),
        ];
        for (n, value) in expected {
            assert_eq!(factorial_iterative(n), value);
            assert_eq!(factorial_recursive(n), value);
        }
    }

    #[test]
    fn iterative_and_recursive_factorial_agree() {
        for n in 0..=20 {
            assert_eq!(factorial_iterative(n), factorial_recursive(n));
        }
    }

    #[test]
    #[should_panic(expected = "overflows")]
    fn factorial_overflow_panics() {
        let _ = factorial_iterative(21);
    }

    #[test]
    fn permutations_known_values() {
        // P(n, r) = n! / (n - r)!
        assert_eq!(permutations(5, 0), 1);
        assert_eq!(permutations(5, 1), 5);
        assert_eq!(permutations(5, 2), 20);
        assert_eq!(permutations(5, 5), 120);
        assert_eq!(permutations(10, 3), 720);
    }

    #[test]
    fn combinations_known_values() {
        // C(n, r) = n! / (r! (n - r)!)
        assert_eq!(combinations(5, 0), 1);
        assert_eq!(combinations(5, 1), 5);
        assert_eq!(combinations(5, 2), 10);
        assert_eq!(combinations(5, 3), 10);
        assert_eq!(combinations(5, 5), 1);
        assert_eq!(combinations(10, 3), 120);
    }

    #[test]
    fn combinations_are_symmetric() {
        for n in 0..=15 {
            for r in 0..=n {
                assert_eq!(combinations(n, r), combinations(n, n - r));
            }
        }
    }

    #[test]
    fn permutations_relate_to_combinations() {
        // C(n, r) * r! == P(n, r)
        for n in 0..=12 {
            for r in 0..=n {
                assert_eq!(combinations(n, r) * factorial_iterative(r), permutations(n, r));
            }
        }
    }

    #[test]
    #[should_panic(expected = "less than or equal")]
    fn permutations_rejects_r_greater_than_n() {
        let _ = permutations(3, 4);
    }

    #[test]
    #[should_panic(expected = "less than or equal")]
    fn combinations_rejects_r_greater_than_n() {
        let _ = combinations(3, 4);
    }
}
