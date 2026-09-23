//! Exercise 4.4 - Diffie-Hellman and Massey-Omura.
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
//!
//! **Question 2** - A Massey-Omura transmission of "Joplin".
//!
//! > Repeat the prior exercise except this time assume that
//! > `p = 4658349003443`, the sender's private keys are `65477368573` and
//! > `3513574598399` and the receiver's private keys are `763485413` and
//! > `4441762259265`. And the message is: "Joplin".
//!
//! The prior exercise:
//!
//! > One individual wants to send a message consisting of the single number
//! > `25` to another using the Massey-Omura System. Both agree on the prime
//! > `p = 31`. The sender chooses two private keys: `13` and `7`; the
//! > receiver chooses two private keys: `17` and `23`. Verify that the
//! > receiver actually receives the number `25`.
//!
//! Each party holds a private pair `(e, d)` satisfying
//! `e * d ≡ 1 (mod p - 1)`. The message is an integer `M` with `0 <= M < p`.
//! It is sent in three passes, and only the receiver removes the last lock:
//!
//! ```text
//! C1 = M^e_s        (mod p)    sender locks M and sends C1
//! C2 = C1^e_r       (mod p)    receiver locks C1 and sends C2 back
//! C3 = C2^d_s       (mod p)    sender removes its lock and sends C3
//! M  = C3^d_r       (mod p)    receiver removes its lock
//! ```
//!
//! Because `e_s * d_s ≡ 1 (mod p - 1)`, Fermat's little theorem cancels the
//! sender's exponents and leaves `M^e_r`. The receiver's pair then cancels
//! in the same way. In the small example the receiver recovers `25`. "Joplin"
//! is read with the book's two-digit numbering `A = 00`, ..., `Z = 25`, so
//! the integer sent under the Question 2 prime is `091415110813`.

use crypto_core::alphabet::{index_to_letter, letter_to_index, normalize};
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

/// Prime modulus from Question 2.
pub const Q2_P: u64 = 4_658_349_003_443;

/// Sender's Massey-Omura pair `(e, d)` from Question 2.
pub const Q2_SENDER: PrivateKeys = PrivateKeys {
    e: 65_477_368_573,
    d: 3_513_574_598_399,
};

/// Receiver's Massey-Omura pair `(e, d)` from Question 2.
pub const Q2_RECEIVER: PrivateKeys = PrivateKeys {
    e: 763_485_413,
    d: 4_441_762_259_265,
};

/// Plaintext transmitted in Question 2.
pub const Q2_MESSAGE: &str = "Joplin";

/// Two decimal digits per letter (`A = 00`, ..., `Z = 25`).
const RADIX: u64 = 100;

/// One party's Massey-Omura exponents.
///
/// `e` locks a value and `d` removes that lock. They satisfy
/// `e * d ≡ 1 (mod p - 1)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateKeys {
    /// Exponent applied when this party locks a value.
    pub e: u64,
    /// Exponent applied when this party removes its lock.
    pub d: u64,
}

/// The three transmitted residues and the integer the receiver recovers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transmission {
    /// `M^e_s (mod p)`, sent from the sender to the receiver.
    pub sender_locked: u64,
    /// `M^(e_s e_r) (mod p)`, returned from the receiver to the sender.
    pub both_locked: u64,
    /// `M^e_r (mod p)`, sent back after the sender removes its lock.
    pub sender_unlocked: u64,
    /// `M (mod p)`, recovered when the receiver removes its lock.
    pub received: u64,
}

/// `e * d ≡ 1 (mod p - 1)`.
///
/// # Panics
///
/// Panics if `p <= 1`.
pub fn are_inverses(p: u64, keys: PrivateKeys) -> bool {
    assert!(p > 1, "the modulus `p` must be greater than 1");
    mul_mod(keys.e, keys.d, p - 1) == 1
}

/// Send `message` with the Massey-Omura three-pass protocol.
///
/// # Panics
///
/// Panics if `p <= 1`, if `p` does not fit in an `i64`, or if `message` is
/// not strictly less than `p`.
pub fn transmit(p: u64, message: u64, sender: PrivateKeys, receiver: PrivateKeys) -> Transmission {
    assert!(
        message < p,
        "the message {message} must be strictly less than p = {p}"
    );
    let sender_locked = pow_mod(message, sender.e, p);
    let both_locked = pow_mod(sender_locked, receiver.e, p);
    let sender_unlocked = pow_mod(both_locked, sender.d, p);
    let received = pow_mod(sender_unlocked, receiver.d, p);
    Transmission {
        sender_locked,
        both_locked,
        sender_unlocked,
        received,
    }
}

/// Transmit the single number from the Massey-Omura example (`p = 31`).
pub fn example_transmit() -> Transmission {
    transmit(
        31,
        25,
        PrivateKeys { e: 13, d: 7 },
        PrivateKeys { e: 17, d: 23 },
    )
}

/// Letters of `text` as a two-digit decimal integer (`A = 00`, ..., `Z = 25`).
///
/// Non-letters are dropped and case is ignored. A leading `A` (`00`) does not
/// appear in the integer; [`decode_message`] restores it from `letter_count`.
///
/// # Panics
///
/// Panics if `text` contains no letters, or if the integer does not fit in a
/// `u64`.
pub fn encode_message(text: &str) -> u64 {
    let letters = normalize(text);
    assert!(!letters.is_empty(), "the message must contain a letter");
    let mut value = 0u64;
    for c in letters.chars() {
        let index = letter_to_index(c).expect("normalized text is alphabetic");
        value = value
            .checked_mul(RADIX)
            .and_then(|v| v.checked_add(u64::from(index)))
            .expect("the message integer must fit in a u64");
    }
    value
}

/// Invert [`encode_message`] for a plaintext of exactly `letter_count` letters.
///
/// # Panics
///
/// Panics if `letter_count` is `0`, or if `value` needs more than
/// `letter_count` letters.
pub fn decode_message(value: u64, letter_count: usize) -> String {
    assert!(letter_count > 0, "a message contains at least one letter");
    let width = letter_count * 2;
    let digits = format!("{value:0width$}");
    assert_eq!(
        digits.len(),
        width,
        "value {value} does not fit in {letter_count} letters"
    );
    digits
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let index = (pair[0] - b'0') * 10 + (pair[1] - b'0');
            index_to_letter(index)
        })
        .collect()
}

/// Transmit Question 2's encoding of [`Q2_MESSAGE`].
pub fn book_transmit() -> Transmission {
    transmit(Q2_P, encode_message(Q2_MESSAGE), Q2_SENDER, Q2_RECEIVER)
}

/// Text recovered by the Question 2 receiver.
pub fn book_receive() -> String {
    let letter_count = normalize(Q2_MESSAGE).chars().count();
    decode_message(book_transmit().received, letter_count)
}

/// `(a * b) mod m` for products that do not fit in a `u64`.
fn mul_mod(a: u64, b: u64, m: u64) -> u64 {
    ((u128::from(a) % u128::from(m)) * (u128::from(b) % u128::from(m)) % u128::from(m)) as u64
}

/// Square-and-multiply `base^exp mod p` for the textbook moduli in this exercise.
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

    const EXAMPLE_SENDER: PrivateKeys = PrivateKeys { e: 13, d: 7 };
    const EXAMPLE_RECEIVER: PrivateKeys = PrivateKeys { e: 17, d: 23 };

    /// Residues of the Massey-Omura example: `25`, then `5`, then `5`, then `25`.
    const EXAMPLE_TRANSMISSION: Transmission = Transmission {
        sender_locked: 25,
        both_locked: 5,
        sender_unlocked: 5,
        received: 25,
    };

    /// `JOPLIN` as `J = 09`, `O = 14`, `P = 15`, `L = 11`, `I = 08`, `N = 13`.
    const Q2_PLAINTEXT_NUMBER: u64 = 91_415_110_813;

    const Q2_TRANSMISSION: Transmission = Transmission {
        sender_locked: 3_302_106_372_707,
        both_locked: 4_580_384_052_419,
        sender_unlocked: 690_503_061_637,
        received: Q2_PLAINTEXT_NUMBER,
    };

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

    #[test]
    fn example_private_keys_are_inverses_mod_p_minus_one() {
        assert!(are_inverses(31, EXAMPLE_SENDER));
        assert!(are_inverses(31, EXAMPLE_RECEIVER));
    }

    #[test]
    fn example_receiver_recovers_25() {
        assert_eq!(example_transmit(), EXAMPLE_TRANSMISSION);
    }

    #[test]
    fn joplin_uses_the_two_digit_correspondence() {
        assert_eq!(encode_message(Q2_MESSAGE), Q2_PLAINTEXT_NUMBER);
        assert_eq!(encode_message("joplin"), Q2_PLAINTEXT_NUMBER);
        assert_eq!(decode_message(Q2_PLAINTEXT_NUMBER, 6), "JOPLIN");
        assert!(Q2_PLAINTEXT_NUMBER < Q2_P);
    }

    #[test]
    fn question2_private_keys_are_inverses_mod_p_minus_one() {
        assert!(are_inverses(Q2_P, Q2_SENDER));
        assert!(are_inverses(Q2_P, Q2_RECEIVER));
    }

    #[test]
    fn question2_receiver_recovers_joplin() {
        assert_eq!(book_transmit(), Q2_TRANSMISSION);
        assert_eq!(book_receive(), "JOPLIN");
    }

    #[test]
    #[should_panic(expected = "strictly less than p")]
    fn message_as_large_as_the_modulus_panics() {
        let _ = transmit(31, 31, EXAMPLE_SENDER, EXAMPLE_RECEIVER);
    }

    #[test]
    #[should_panic(expected = "contain a letter")]
    fn empty_message_is_rejected() {
        let _ = encode_message("...");
    }
}
