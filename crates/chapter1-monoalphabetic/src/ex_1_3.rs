//! Exercise 1.3 - Writing an integer as a product of primes in standard form.
//!
//! > Write a computer program whose input is an integer and whose output is
//! > that integer written as a product of prime numbers in standard form.
//!
//! The *standard form* (or canonical form) of an integer `n > 1` guaranteed by
//! the Fundamental Theorem of Arithmetic is
//!
//! ```text
//! n = p_1^e_1 * p_2^e_2 * ... * p_k^e_k
//! ```
//!
//! where `p_1 < p_2 < ... < p_k` are distinct primes and each exponent
//! `e_i >= 1`. The heavy lifting (trial division producing ascending
//! `(prime, exponent)` pairs) already lives in [`crypto_core::primes`]; this
//! module wraps it to render the textbook's standard-form *string* and to deal
//! with the edge cases an "any integer" input implies:
//!
//! * `n == 0` has no prime factorization (every prime divides it), so it is an
//!   error.
//! * `n == 1` is the empty product, conventionally written `1`.
//! * negative `n` is factored via `|n|` with a leading `-1` factor so the
//!   output still multiplies back to the original value.

use crypto_core::primes::prime_factors;

/// Render `n` as a product of primes in standard form, e.g. `360` becomes
/// `"2^3 * 3 * 5"` and `-12` becomes `"-1 * 2^2 * 3"`.
///
/// Returns `Err` for `n == 0`, which has no prime factorization.
pub fn standard_form(n: i64) -> Result<String, &'static str> {
    if n == 0 {
        return Err("0 has no prime factorization");
    }
    if n == 1 {
        return Ok("1".to_string());
    }

    let mut terms = Vec::new();
    if n < 0 {
        terms.push("-1".to_string());
    }

    // `i64::MIN.unsigned_abs()` is handled correctly here, unlike `(-n) as u64`.
    let magnitude = n.unsigned_abs();
    for (prime, exponent) in prime_factors(magnitude) {
        if exponent == 1 {
            terms.push(prime.to_string());
        } else {
            terms.push(format!("{prime}^{exponent}"));
        }
    }

    Ok(terms.join(" * "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_form_examples() {
        assert_eq!(standard_form(360).unwrap(), "2^3 * 3^2 * 5");
        assert_eq!(standard_form(97).unwrap(), "97");
        assert_eq!(standard_form(12).unwrap(), "2^2 * 3");
        assert_eq!(standard_form(2).unwrap(), "2");
    }

    #[test]
    fn handles_one_and_zero() {
        assert_eq!(standard_form(1).unwrap(), "1");
        assert!(standard_form(0).is_err());
    }

    #[test]
    fn handles_negative_inputs() {
        assert_eq!(standard_form(-1).unwrap(), "-1");
        assert_eq!(standard_form(-12).unwrap(), "-1 * 2^2 * 3");
    }

    #[test]
    fn factors_multiply_back_to_input() {
        for n in -200i64..=200 {
            if n == 0 {
                continue;
            }
            let product: i64 = prime_factors(n.unsigned_abs())
                .into_iter()
                .map(|(p, e)| (p as i64).pow(e))
                .product::<i64>()
                * if n < 0 { -1 } else { 1 };
            assert_eq!(product, n);
            assert!(standard_form(n).is_ok());
        }
    }
}
