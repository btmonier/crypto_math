//! Exercise 1.1 - Caesar (shift) cipher.
//!
//! A worked example establishing the pattern for the rest of the book: each
//! letter is shifted by a fixed key `k` modulo 26, while non-letters are
//! dropped during normalization. Replace or extend with the exact wording of
//! the exercise you are answering.

use crypto_core::alphabet::{from_indices, to_indices, ALPHABET_SIZE};
use crypto_core::modular::modulo;

/// Encipher `plaintext` with a Caesar shift of `key`.
pub fn encipher(plaintext: &str, key: i64) -> String {
    let shifted: Vec<u8> = to_indices(plaintext)
        .into_iter()
        .map(|i| modulo(i as i64 + key, ALPHABET_SIZE as i64) as u8)
        .collect();
    from_indices(&shifted)
}

/// Decipher `ciphertext` that was enciphered with a Caesar shift of `key`.
pub fn decipher(ciphertext: &str, key: i64) -> String {
    encipher(ciphertext, -key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classic_shift_of_three() {
        assert_eq!(encipher("ATTACK AT DAWN", 3), "DWWDFNDWGDZQ");
        assert_eq!(decipher("DWWDFNDWGDZQ", 3), "ATTACKATDAWN");
    }

    #[test]
    fn roundtrip_for_all_keys() {
        let plaintext = "THEQUICKBROWNFOX";
        for key in 0..26 {
            assert_eq!(decipher(&encipher(plaintext, key), key), plaintext);
        }
    }
}
