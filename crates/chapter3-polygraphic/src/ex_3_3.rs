//! Exercise 3.3 - Hill's System.
//!
//! **Question 1** - Hill's digraph cipher.
//!
//! > Write a computer program to both encipher and decipher a message using
//! > Hill's (digraph) System.
//!
//! Hill's system is a *digraphic* substitution cipher that replaces each pair
//! of letters by another pair, using multiplication by a 2×2 key matrix
//! modulo 26. Letters are numbered as in the rest of the book (`A = 0`, …,
//! `Z = 25`) and each pair is written as a column vector `P`. Encipherment is
//!
//! ```text
//! C = K P  (mod 26)
//! ```
//!
//! and decipherment uses the inverse matrix:
//!
//! ```text
//! P = K^{-1} C  (mod 26).
//! ```
//!
//! The key
//!
//! ```text
//! K = | a  b |
//!     | c  d |
//! ```
//!
//! is a valid Hill key only when it is invertible modulo 26, i.e. when
//! `gcd(det(K), 26) == 1` where `det(K) = ad - bc`. Because `26 = 2 * 13`,
//! that means the determinant must be odd and not a multiple of 13. The
//! inverse is then
//!
//! ```text
//! K^{-1} = det(K)^{-1} * |  d  -b |
//!                        | -c   a |   (mod 26).
//! ```
//!
//! Non-letters are dropped and case is ignored. An odd-length message is
//! padded with `X` so every block has two letters; that filler is left in
//! the recovered text.

use std::error::Error;
use std::fmt;

use crypto_core::alphabet::{from_indices, to_indices, ALPHABET_SIZE};
use crypto_core::modular::{gcd, mod_inverse, modulo};

/// The modulus for Hill's system: the size of the alphabet.
const MODULUS: i64 = ALPHABET_SIZE as i64;

/// Null appended when the (normalized) message has odd length.
const FILLER: u8 = b'X' - b'A';

/// A 2×2 Hill key `[[a, b], [c, d]]` acting on column vectors modulo 26.
pub type HillKey = [[i64; 2]; 2];

/// Error returned when a 2×2 matrix is not invertible modulo 26.
///
/// The determinant `ad - bc` must satisfy `gcd(det, 26) == 1`; otherwise the
/// mapping `P -> K P` is not a bijection and cannot be deciphered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidHillKey {
    /// The offending determinant, reduced into the canonical range `0..26`.
    pub determinant: i64,
}

impl fmt::Display for InvalidHillKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Hill key determinant {} is not invertible modulo {MODULUS} \
             (gcd with {MODULUS} must be 1)",
            self.determinant
        )
    }
}

impl Error for InvalidHillKey {}

/// Reduce every entry of `key` into `0..26`.
pub fn reduce_key(key: HillKey) -> HillKey {
    [
        [modulo(key[0][0], MODULUS), modulo(key[0][1], MODULUS)],
        [modulo(key[1][0], MODULUS), modulo(key[1][1], MODULUS)],
    ]
}

/// Determinant of `key` modulo 26.
pub fn determinant(key: HillKey) -> i64 {
    let [[a, b], [c, d]] = reduce_key(key);
    modulo(a * d - b * c, MODULUS)
}

/// Inverse of `key` modulo 26, if it exists.
///
/// # Errors
///
/// Returns [`InvalidHillKey`] when `gcd(det(key), 26) != 1`.
pub fn inverse_key(key: HillKey) -> Result<HillKey, InvalidHillKey> {
    let det = determinant(key);
    let inv_det = mod_inverse(det, MODULUS).ok_or(InvalidHillKey { determinant: det })?;
    let [[a, b], [c, d]] = reduce_key(key);
    Ok([
        [modulo(inv_det * d, MODULUS), modulo(inv_det * -b, MODULUS)],
        [modulo(inv_det * -c, MODULUS), modulo(inv_det * a, MODULUS)],
    ])
}

/// Encipher `plaintext` with Hill's digraph system keyed by `key`.
///
/// Non-alphabetic characters are dropped and letters are treated
/// case-insensitively; the output is uppercase. An odd-length message is
/// padded with `X`.
///
/// # Errors
///
/// Returns [`InvalidHillKey`] when `key` is not invertible modulo 26.
pub fn encipher(plaintext: &str, key: HillKey) -> Result<String, InvalidHillKey> {
    let key = validated_key(key)?;
    Ok(from_indices(&apply_blocks(&prepare_blocks(plaintext), key)))
}

/// Decipher `ciphertext` that was produced by [`encipher`] with the same `key`.
///
/// The recovered text still contains any `X` that was appended to pad an
/// odd-length plaintext. An odd-length ciphertext (which a correctly produced
/// Hill message never has) is padded with `X` so the last letter can still be
/// processed as a pair.
///
/// # Errors
///
/// Returns [`InvalidHillKey`] when `key` is not invertible modulo 26.
pub fn decipher(ciphertext: &str, key: HillKey) -> Result<String, InvalidHillKey> {
    let inverse = inverse_key(key)?;
    Ok(from_indices(&apply_blocks(
        &prepare_blocks(ciphertext),
        inverse,
    )))
}

fn validated_key(key: HillKey) -> Result<HillKey, InvalidHillKey> {
    let reduced = reduce_key(key);
    let det = determinant(reduced);
    if gcd(det, MODULUS) != 1 {
        return Err(InvalidHillKey { determinant: det });
    }
    Ok(reduced)
}

fn prepare_blocks(text: &str) -> Vec<u8> {
    let mut indices = to_indices(text);
    if indices.len() % 2 == 1 {
        indices.push(FILLER);
    }
    indices
}

fn apply_blocks(indices: &[u8], key: HillKey) -> Vec<u8> {
    indices
        .chunks_exact(2)
        .flat_map(|pair| apply_pair(key, pair[0] as i64, pair[1] as i64))
        .collect()
}

/// `K * [p0, p1]^T (mod 26)`.
fn apply_pair(key: HillKey, p0: i64, p1: i64) -> [u8; 2] {
    [
        modulo(key[0][0] * p0 + key[0][1] * p1, MODULUS) as u8,
        modulo(key[1][0] * p0 + key[1][1] * p1, MODULUS) as u8,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Product `left * right` of two 2×2 matrices modulo 26.
    fn mul_keys(left: HillKey, right: HillKey) -> HillKey {
        let [[a, b], [c, d]] = left;
        let [[e, f], [g, h]] = right;
        [
            [
                modulo(a * e + b * g, MODULUS),
                modulo(a * f + b * h, MODULUS),
            ],
            [
                modulo(c * e + d * g, MODULUS),
                modulo(c * f + d * h, MODULUS),
            ],
        ]
    }

    /// Classic textbook key, used for the `HELP -> HIAT` worked example.
    const HELP_KEY: HillKey = [[3, 3], [2, 5]];

    #[test]
    fn determinant_of_help_key() {
        // det = 3*5 - 3*2 = 9, and gcd(9, 26) = 1.
        assert_eq!(determinant(HELP_KEY), 9);
    }

    #[test]
    fn inverse_of_help_key() {
        // 9^{-1} ≡ 3 (mod 26), so K^{-1} = 3 * [[5, -3], [-2, 3]] = [[15, 17], [20, 9]].
        assert_eq!(inverse_key(HELP_KEY), Ok([[15, 17], [20, 9]]));
        assert_eq!(mul_keys(HELP_KEY, inverse_key(HELP_KEY).unwrap()), [[1, 0], [0, 1]]);
    }

    #[test]
    fn help_enciphers_to_hiat() {
        assert_eq!(encipher("HELP", HELP_KEY).unwrap(), "HIAT");
        assert_eq!(decipher("HIAT", HELP_KEY).unwrap(), "HELP");
    }

    #[test]
    fn entries_are_reduced_modulo_26() {
        assert_eq!(
            encipher("HELP", [[3 + 26, 3], [2, 5 - 26]]).unwrap(),
            "HIAT"
        );
    }

    #[test]
    fn odd_length_is_padded_with_x() {
        // ACT -> ACTX; the recovered text keeps the filler.
        let cipher = encipher("ACT", HELP_KEY).unwrap();
        assert_eq!(cipher.len(), 4);
        assert_eq!(decipher(&cipher, HELP_KEY).unwrap(), "ACTX");
    }

    #[test]
    fn non_letters_are_ignored() {
        assert_eq!(
            encipher("He, LP!", HELP_KEY).unwrap(),
            encipher("HELP", HELP_KEY).unwrap()
        );
    }

    #[test]
    fn empty_message_is_empty() {
        assert_eq!(encipher("", HELP_KEY).unwrap(), "");
        assert_eq!(decipher("", HELP_KEY).unwrap(), "");
    }

    #[test]
    fn singular_key_is_rejected() {
        // det = 4, gcd(4, 26) = 2.
        assert_eq!(
            encipher("HELP", [[2, 0], [0, 2]]),
            Err(InvalidHillKey { determinant: 4 })
        );
        // det = 13, gcd(13, 26) = 13.
        assert_eq!(
            decipher("HELP", [[1, 0], [0, 13]]),
            Err(InvalidHillKey { determinant: 13 })
        );
    }

    #[test]
    fn decipher_inverts_encipher_for_sample_keys() {
        let plaintext = "THEQUICKBROWNFOX";
        let keys = [
            HELP_KEY,
            [[1, 0], [0, 1]],
            [[5, 8], [3, 7]],
            [[9, 4], [5, 7]],
        ];
        for key in keys {
            let cipher = encipher(plaintext, key).unwrap();
            assert_eq!(
                decipher(&cipher, key).unwrap(),
                plaintext,
                "key = {key:?}"
            );
        }
    }
}
