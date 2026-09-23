//! Exercise 4.4 - Diffie-Hellman Key Exchange.
//!
//! **Question 1** - A larger Diffie-Hellman keyword.
//!
//! > Repeat exercise #2 except this time assume that `p = 4653848293`,
//! > `q = 65478390`, one's private key is `76350293` and the other's is
//! > `233451876`.
//!
//! Exercise #2, the exchange this question repeats:
//!
//! > Two individuals decide to use the Diffie-Hellman Key Exchange System
//! > to communicate a keyword. They agree that `p = 11` and `q = 8`. One
//! > chooses private key 3 and the other private key 4. Verify that they
//! > each wind up with the same keyword.
//!
//! The two parties agree on a prime modulus `p` and a base `q`. Each keeps
//! a private key (`a` and `b`) and publishes
//!
//! ```text
//! A = q^a  (mod p)
//! B = q^b  (mod p)
//! ```
//!
//! Each then raises the other party's public value to their own private key:
//!
//! ```text
//! K = B^a = A^b = q^(a*b)  (mod p)
//! ```
//!
//! That common residue is the shared keyword. In the small example both
//! parties obtain `9`. With the Question 1 parameters both obtain
//! `2014163551`.

use crypto_core::modular::mod_pow;

/// Prime modulus from Question 1.
pub const P: u64 = 4_653_848_293;

/// Agreed base from Question 1.
pub const Q: u64 = 65_478_390;

/// First party's private key from Question 1.
pub const PRIVATE_A: u64 = 76_350_293;

/// Second party's private key from Question 1.
pub const PRIVATE_B: u64 = 233_451_876;

/// Public value `q^private mod p`.
///
/// # Panics
///
/// Panics if `p <= 1`, or if `p` does not fit in an `i64`.
pub fn public_value(p: u64, q: u64, private: u64) -> u64 {
    pow_mod(q, private, p)
}

/// Shared keyword `other_public^private mod p`.
///
/// # Panics
///
/// Panics if `p <= 1`, or if `p` does not fit in an `i64`.
pub fn shared_keyword(p: u64, private: u64, other_public: u64) -> u64 {
    pow_mod(other_public, private, p)
}

/// Run a Diffie-Hellman exchange and return each party's keyword.
///
/// The pair is `(B^a mod p, A^b mod p)`. The two values are equal.
///
/// # Panics
///
/// Panics if `p <= 1`, or if `p` does not fit in an `i64`.
pub fn exchange(p: u64, q: u64, private_a: u64, private_b: u64) -> (u64, u64) {
    let public_a = public_value(p, q, private_a);
    let public_b = public_value(p, q, private_b);
    (
        shared_keyword(p, private_a, public_b),
        shared_keyword(p, private_b, public_a),
    )
}

/// Keywords from the exercise #2 example (`p = 11`, `q = 8`, keys `3` and `4`).
pub fn example_exchange() -> (u64, u64) {
    exchange(11, 8, 3, 4)
}

/// Keywords from Question 1.
pub fn book_exchange() -> (u64, u64) {
    exchange(P, Q, PRIVATE_A, PRIVATE_B)
}

/// Square-and-multiply `base^exp mod p` for the textbook Diffie-Hellman sizes.
///
/// # Panics
///
/// Panics if `p <= 1`, or if `p` does not fit in an `i64`.
fn pow_mod(base: u64, exp: u64, p: u64) -> u64 {
    assert!(p > 1, "the modulus `p` must be greater than 1");
    let modulus = i64::try_from(p).expect("the modulus `p` must fit in an i64");
    let reduced = i64::try_from(base % p).expect("a residue modulo `p` fits in an i64");
    mod_pow(reduced, exp, modulus) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Public values and shared keyword of the exercise #2 example.
    const EXAMPLE_PUBLIC_A: u64 = 6;
    const EXAMPLE_PUBLIC_B: u64 = 4;
    const EXAMPLE_KEYWORD: u64 = 9;

    /// Public values published from the Question 1 private keys.
    const PUBLIC_A: u64 = 2_721_419_856;
    const PUBLIC_B: u64 = 4_077_302_202;

    /// Shared keyword of Question 1.
    const KEYWORD: u64 = 2_014_163_551;

    #[test]
    fn example_parties_publish_the_expected_values() {
        assert_eq!(public_value(11, 8, 3), EXAMPLE_PUBLIC_A);
        assert_eq!(public_value(11, 8, 4), EXAMPLE_PUBLIC_B);
    }

    #[test]
    fn example_parties_share_the_same_keyword() {
        let (from_a, from_b) = example_exchange();
        assert_eq!(from_a, EXAMPLE_KEYWORD);
        assert_eq!(from_b, EXAMPLE_KEYWORD);
        assert_eq!(from_a, pow_mod(8, 3 * 4, 11));
    }

    #[test]
    fn question1_parties_publish_the_expected_values() {
        assert_eq!(public_value(P, Q, PRIVATE_A), PUBLIC_A);
        assert_eq!(public_value(P, Q, PRIVATE_B), PUBLIC_B);
    }

    #[test]
    fn question1_parties_share_the_same_keyword() {
        let (from_a, from_b) = book_exchange();
        assert_eq!(from_a, KEYWORD);
        assert_eq!(from_b, KEYWORD);
        assert_eq!(from_a, shared_keyword(P, PRIVATE_A, PUBLIC_B));
        assert_eq!(from_b, shared_keyword(P, PRIVATE_B, PUBLIC_A));
        assert_eq!(from_a, pow_mod(Q, PRIVATE_A * PRIVATE_B, P));
    }

    #[test]
    #[should_panic(expected = "greater than 1")]
    fn non_positive_modulus_panics() {
        let _ = exchange(1, 8, 3, 4);
    }
}
