//! Exercise 1.5 - Simple ciphers.
//!
//! **Question 1** - Keyword cipher.
//!
//! > Write a program that enciphers a message using a keyword scheme. The
//! > program should accept as input both a keyword and a message and should
//! > output the enciphered message. Then enhance the program by adding
//! > decipherment capabilities, i.e., given the keyword and an enciphered
//! > message, the program should output the deciphered message.
//!
//! A *keyword cipher* is a monoalphabetic substitution cipher. The keyword
//! determines a scrambled ciphertext alphabet:
//!
//! 1. Write the keyword, removing duplicate letters (first occurrence kept).
//! 2. Append the remaining letters of the alphabet in their usual order.
//!
//! Plaintext letter `A` is replaced by the first letter of this cipher
//! alphabet, `B` by the second, and so on. Decipherment inverts that mapping.
//!
//! **Question 2** - Affine cipher.
//!
//! > Write a program that enciphers a message using an affine scheme. The
//! > program should accept as input a plaintext message, a multiplicative
//! > key, and an additive key and should output the enciphered message.
//! > (Note that by inputting a multiplicative key of 1, the affine scheme
//! > is reduced to an additive one. Similarly, by selecting an additive key
//! > of 0, the affine scheme becomes purely multiplicative. In other words,
//! > there is no need to code the additive or multiplicative enciphering
//! > schemes as stand-alone programs; they are each special cases of the
//! > affine system.) Then enhance the program by adding decipherment
//! > capabilities, i.e., given the additive and multiplicative keys and an
//! > enciphered message, the program should output the deciphered message.

use std::error::Error;
use std::fmt;

use crypto_core::alphabet::{from_indices, letter_to_index, to_indices, ALPHABET_SIZE};
use crypto_core::modular::{gcd, mod_inverse, modulo};

/// Build the 26-letter cipher alphabet determined by `keyword`.
///
/// Duplicate letters in the keyword are ignored after their first appearance;
/// non-alphabetic characters are dropped. The result is always a permutation
/// of `0..=25`.
pub fn cipher_alphabet(keyword: &str) -> [u8; ALPHABET_SIZE as usize] {
    let mut seen = [false; ALPHABET_SIZE as usize];
    let mut alphabet = Vec::with_capacity(ALPHABET_SIZE as usize);

    for index in keyword.chars().filter_map(letter_to_index) {
        let slot = index as usize;
        if !seen[slot] {
            seen[slot] = true;
            alphabet.push(index);
        }
    }

    for index in 0..ALPHABET_SIZE {
        if !seen[index as usize] {
            alphabet.push(index);
        }
    }

    alphabet
        .try_into()
        .expect("cipher alphabet must contain exactly 26 letters")
}

/// Encipher `plaintext` with the keyword cipher keyed by `keyword`.
pub fn encipher(plaintext: &str, keyword: &str) -> String {
    let cipher = cipher_alphabet(keyword);
    let enciphered: Vec<u8> = to_indices(plaintext)
        .into_iter()
        .map(|plain| cipher[plain as usize])
        .collect();
    from_indices(&enciphered)
}

/// Decipher `ciphertext` that was produced by [`encipher`] with the same
/// `keyword`.
pub fn decipher(ciphertext: &str, keyword: &str) -> String {
    let cipher = cipher_alphabet(keyword);
    let mut plain = [0u8; ALPHABET_SIZE as usize];
    for (position, &cipher_letter) in cipher.iter().enumerate() {
        plain[cipher_letter as usize] = position as u8;
    }

    let deciphered: Vec<u8> = to_indices(ciphertext)
        .into_iter()
        .map(|cipher_letter| plain[cipher_letter as usize])
        .collect();
    from_indices(&deciphered)
}

// --- Question 2: affine cipher ---

/// The modulus for the affine cipher: the size of the alphabet.
const MODULUS: i64 = ALPHABET_SIZE as i64;

/// Error returned when the multiplicative key of an affine cipher is not
/// invertible modulo 26.
///
/// The multiplicative key `a` must satisfy `gcd(a, 26) == 1`; otherwise the
/// mapping `x -> a*x + b` is not a bijection and cannot be deciphered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidMultiplicativeKey {
    /// The offending key, reduced into the canonical range `0..26`.
    pub multiplier: i64,
}

impl fmt::Display for InvalidMultiplicativeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "multiplicative key {} is not invertible modulo {MODULUS} \
             (gcd with {MODULUS} must be 1)",
            self.multiplier
        )
    }
}

impl Error for InvalidMultiplicativeKey {}

/// Encipher `plaintext` with the affine scheme `E(x) = (a*x + b) mod 26`, where
/// `a` is the `multiplier` and `b` is the `shift`.
///
/// Non-alphabetic characters are dropped and letters are treated
/// case-insensitively; the output is uppercase. Setting `multiplier == 1`
/// reduces this to a pure additive (shift) cipher, and `shift == 0` reduces it
/// to a pure multiplicative cipher.
///
/// # Errors
///
/// Returns [`InvalidMultiplicativeKey`] when `gcd(multiplier, 26) != 1`, since
/// such a key does not produce an invertible cipher.
pub fn affine_encipher(
    plaintext: &str,
    multiplier: i64,
    shift: i64,
) -> Result<String, InvalidMultiplicativeKey> {
    if gcd(multiplier, MODULUS) != 1 {
        return Err(InvalidMultiplicativeKey {
            multiplier: modulo(multiplier, MODULUS),
        });
    }

    let enciphered: Vec<u8> = to_indices(plaintext)
        .into_iter()
        .map(|plain| modulo(multiplier * plain as i64 + shift, MODULUS) as u8)
        .collect();
    Ok(from_indices(&enciphered))
}

/// Decipher `ciphertext` produced by [`affine_encipher`] with the same keys.
///
/// Inverts `E(x) = (a*x + b) mod 26` via `D(y) = a^{-1} * (y - b) mod 26`, where
/// `a^{-1}` is the multiplicative inverse of `a` modulo 26.
///
/// # Errors
///
/// Returns [`InvalidMultiplicativeKey`] when `multiplier` has no inverse modulo
/// 26 (i.e. `gcd(multiplier, 26) != 1`).
pub fn affine_decipher(
    ciphertext: &str,
    multiplier: i64,
    shift: i64,
) -> Result<String, InvalidMultiplicativeKey> {
    let inverse = mod_inverse(multiplier, MODULUS).ok_or(InvalidMultiplicativeKey {
        multiplier: modulo(multiplier, MODULUS),
    })?;

    let deciphered: Vec<u8> = to_indices(ciphertext)
        .into_iter()
        .map(|cipher| modulo(inverse * (cipher as i64 - shift), MODULUS) as u8)
        .collect();
    Ok(from_indices(&deciphered))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_alphabet_removes_duplicates_and_appends_remainder() {
        // "KRYPTOS" -> K R Y P T O S | A B C D E F G H I J L M N Q U V W X Z
        assert_eq!(
            from_indices(&cipher_alphabet("KRYPTOS")),
            "KRYPTOSABCDEFGHIJLMNQUVWXZ"
        );
        // "ZEBRAS" -> Z E B R A S | C D F G H I J K L M N O P Q T U V W X Y
        assert_eq!(
            from_indices(&cipher_alphabet("ZEBRAS")),
            "ZEBRASCDFGHIJKLMNOPQTUVWXY"
        );
    }

    #[test]
    fn encipher_maps_positionally() {
        // With keyword JULIUS the cipher alphabet begins JULIS...
        assert_eq!(encipher("A", "JULIUS"), "J");
        assert_eq!(encipher("B", "JULIUS"), "U");
        assert_eq!(encipher("ATTACK AT DAWN", "SECRET"), "SQQSCHSQRSWK");
    }

    #[test]
    fn decipher_inverts_encipher() {
        assert_eq!(decipher("SQQSCHSQRSWK", "SECRET"), "ATTACKATDAWN");
    }

    #[test]
    fn roundtrip_for_sample_keywords() {
        let plaintext = "THEQUICKBROWNFOX";
        for keyword in ["JULIUS", "CRYPTOLOGY", "ZEBRAS", "ABACAB"] {
            assert_eq!(
                decipher(&encipher(plaintext, keyword), keyword),
                plaintext,
                "keyword = {keyword}"
            );
        }
    }

    #[test]
    fn keyword_is_case_insensitive_and_ignores_non_letters() {
        assert_eq!(cipher_alphabet("kryptos"), cipher_alphabet("KRYPTOS"));
        assert_eq!(
            cipher_alphabet("Zebra-Skin"),
            cipher_alphabet("ZEBRASKIN")
        );
    }

    // --- Question 2: affine cipher ---

    #[test]
    fn affine_encipher_matches_hand_worked_example() {
        // With a = 5, b = 8: E(x) = (5x + 8) mod 26.
        // AFFINE = 0,5,5,8,13,4 -> 8,7,7,22,21,2 = I H H W V C
        assert_eq!(affine_encipher("AFFINE", 5, 8).unwrap(), "IHHWVC");
    }

    #[test]
    fn affine_decipher_inverts_encipher() {
        let cipher = affine_encipher("ATTACKATDAWN", 5, 8).unwrap();
        assert_eq!(affine_decipher(&cipher, 5, 8).unwrap(), "ATTACKATDAWN");
    }

    #[test]
    fn multiplier_one_is_a_pure_shift_cipher() {
        // a = 1, b = 3 is the Caesar cipher: A -> D, B -> E, ...
        assert_eq!(affine_encipher("ABC", 1, 3).unwrap(), "DEF");
        assert_eq!(affine_decipher("DEF", 1, 3).unwrap(), "ABC");
    }

    #[test]
    fn shift_zero_is_a_pure_multiplicative_cipher() {
        // a = 3, b = 0: E(x) = 3x mod 26. A->A, B->D, C->G, ...
        assert_eq!(affine_encipher("ABC", 3, 0).unwrap(), "ADG");
        assert_eq!(affine_decipher("ADG", 3, 0).unwrap(), "ABC");
    }

    #[test]
    fn non_invertible_multiplier_is_rejected() {
        // gcd(13, 26) = 13 != 1, so 13 has no inverse modulo 26.
        assert_eq!(
            affine_encipher("HELLO", 13, 4),
            Err(InvalidMultiplicativeKey { multiplier: 13 })
        );
        assert_eq!(
            affine_decipher("HELLO", 2, 0),
            Err(InvalidMultiplicativeKey { multiplier: 2 })
        );
    }

    #[test]
    fn affine_keys_are_normalized_and_letters_case_insensitive() {
        // Negative / out-of-range keys behave like their residues mod 26.
        assert_eq!(
            affine_encipher("hello world", 5, 8).unwrap(),
            affine_encipher("HELLO WORLD", 5, 8 + 26).unwrap()
        );
        assert_eq!(
            affine_encipher("hi", -21, 8).unwrap(),
            affine_encipher("HI", 5, 8).unwrap()
        );
    }

    #[test]
    fn affine_roundtrip_over_all_valid_keys() {
        let plaintext = "THEQUICKBROWNFOX";
        for a in 1..26 {
            if gcd(a, MODULUS) != 1 {
                continue;
            }
            for b in 0..26 {
                let cipher = affine_encipher(plaintext, a, b).unwrap();
                assert_eq!(
                    affine_decipher(&cipher, a, b).unwrap(),
                    plaintext,
                    "a = {a}, b = {b}"
                );
            }
        }
    }
}
