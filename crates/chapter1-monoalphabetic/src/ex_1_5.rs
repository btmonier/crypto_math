//! Exercise 1.5 - Simple ciphers.
//!
//! **Question 1** – Keyword cipher.
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

use crypto_core::alphabet::{from_indices, letter_to_index, to_indices, ALPHABET_SIZE};

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
}
