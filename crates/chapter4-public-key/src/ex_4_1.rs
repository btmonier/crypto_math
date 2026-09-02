//! Exercise 4.1 - More Number Theory.
//!
//! **Question 1** – Euler's totient function.
//!
//! > Write a computer program to compute \phi(n) for any positive integer `n`.
//!
//! Euler's totient `\phi(n)` counts the integers `k` in `1..=n` that are
//! relatively prime to `n` (that is, `gcd(k, n) == 1`). Once the prime
//! factorization of `n` is known, the same count is given by the product
//! formula
//!
//! ```text
//! \phi(n) = n * \prod (1 - 1/p)   over distinct primes p dividing n
//! ```
//!
//! Equivalently, if `n = p1^e1 * ... * pk^ek`, then
//!
//! ```text
//! \phi(n) = p1^(e1-1) * (p1 - 1) * ... * pk^(ek-1) * (pk - 1).
//! ```
//!
//! Special cases used throughout Chapter 4 (and later for RSA) fall out of
//! that formula immediately:
//!
//! * `\phi(1) = 1`
//! * `\phi(p) = p - 1` when `p` is prime
//! * `\phi(p^e) = p^e - p^(e-1)`
//! * `\phi(pq) = (p - 1)(q - 1)` when `p` and `q` are distinct primes
//!
//! The factorization itself is the program from Exercise 1.3; this module
//! applies the product formula to those prime factors.

use crypto_core::primes::prime_factors;

/// Euler's totient `\phi(n)`: the number of integers in `1..=n` coprime to `n`.
///
/// # Panics
///
/// Panics if `n == 0`, since the totient is defined for positive integers.
pub fn phi(n: u64) -> u64 {
    assert!(n > 0, "n must be a positive integer");

    // \phi(n) = n * \prod_{p|n} (1 - 1/p) = n * \prod_{p|n} (p - 1)/p.
    // Dividing by `p` first is safe: every prime factor of `n` still divides
    // the running product at the moment we apply it.
    let mut result = n;
    for (p, _) in prime_factors(n) {
        result = result / p * (p - 1);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_core::modular::gcd;
    use crypto_core::primes::is_prime;

    /// Direct count from the definition: #{ k in 1..=n : gcd(k, n) == 1 }.
    fn phi_by_definition(n: u64) -> u64 {
        (1..=n)
            .filter(|&k| gcd(k as i64, n as i64) == 1)
            .count() as u64
    }

    #[test]
    fn well_known_values() {
        assert_eq!(phi(1), 1);
        assert_eq!(phi(2), 1);
        assert_eq!(phi(9), 6);
        assert_eq!(phi(10), 4);
        // 360 = 2^3 * 3^2 * 5, so \phi(360) = 360 * 1/2 * 2/3 * 4/5 = 96.
        assert_eq!(phi(360), 96);
    }

    #[test]
    fn prime_is_one_less() {
        for p in [2, 3, 5, 7, 11, 13, 17, 19, 97] {
            assert_eq!(phi(p), p - 1);
        }
    }

    #[test]
    fn prime_power() {
        // \phi(p^e) = p^e - p^(e-1) = p^(e-1) * (p - 1).
        assert_eq!(phi(8), 4); // 2^3
        assert_eq!(phi(9), 6); // 3^2
        assert_eq!(phi(25), 20); // 5^2
        assert_eq!(phi(27), 18); // 3^3
        assert_eq!(phi(49), 42); // 7^2
    }

    #[test]
    fn product_of_distinct_primes() {
        // For distinct primes p, q: \phi(pq) = (p - 1)(q - 1).
        assert_eq!(phi(3 * 11), 2 * 10);
        assert_eq!(phi(17 * 19), 16 * 18);
        // Three distinct primes: \phi is still multiplicative.
        assert_eq!(phi(2 * 3 * 5), 1 * 2 * 4);
    }

    #[test]
    fn multiplicative_for_coprime_factors() {
        // gcd(m, n) == 1 implies \phi(mn) = \phi(m) \phi(n).
        for m in 1..=30 {
            for n in 1..=30 {
                if gcd(m as i64, n as i64) == 1 {
                    assert_eq!(phi(m * n), phi(m) * phi(n));
                }
            }
        }
    }

    #[test]
    fn matches_definition_over_range() {
        for n in 1..=200 {
            assert_eq!(phi(n), phi_by_definition(n), "\phi({n})");
        }
    }

    #[test]
    fn primes_in_range_match_p_minus_one() {
        for n in 2..=200 {
            if is_prime(n) {
                assert_eq!(phi(n), n - 1);
            }
        }
    }

    #[test]
    #[should_panic(expected = "positive")]
    fn zero_is_rejected() {
        phi(0);
    }
}
