//! Helpers for mapping between the Latin alphabet and the integers 0..=25,
//! plus utilities for normalizing plaintext before enciphering.

/// Number of letters in the alphabet the book works with.
pub const ALPHABET_SIZE: u8 = 26;

/// Convert a letter to its 0-based index (`'A'`/`'a'` -> 0, `'Z'`/`'z'` -> 25).
///
/// Returns `None` for any non-alphabetic character.
pub fn letter_to_index(c: char) -> Option<u8> {
    if c.is_ascii_alphabetic() {
        Some(c.to_ascii_uppercase() as u8 - b'A')
    } else {
        None
    }
}

/// Convert a 0-based index back to an uppercase letter.
///
/// The index is reduced modulo 26 so callers can pass raw arithmetic results.
pub fn index_to_letter(index: u8) -> char {
    (b'A' + (index % ALPHABET_SIZE)) as char
}

/// Strip everything except letters and return an uppercase `String`.
///
/// This is the canonical form most classical ciphers operate on: spaces,
/// punctuation, and digits are removed, and case is discarded.
pub fn normalize(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Convert text into a vector of 0..=25 indices, ignoring non-letters.
pub fn to_indices(text: &str) -> Vec<u8> {
    text.chars().filter_map(letter_to_index).collect()
}

/// Convert a slice of indices back into an uppercase `String`.
pub fn from_indices(indices: &[u8]) -> String {
    indices.iter().map(|&i| index_to_letter(i)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letter_index_roundtrip() {
        for i in 0..ALPHABET_SIZE {
            let letter = index_to_letter(i);
            assert_eq!(letter_to_index(letter), Some(i));
        }
    }

    #[test]
    fn letter_to_index_handles_case_and_non_letters() {
        assert_eq!(letter_to_index('a'), Some(0));
        assert_eq!(letter_to_index('Z'), Some(25));
        assert_eq!(letter_to_index('5'), None);
        assert_eq!(letter_to_index(' '), None);
    }

    #[test]
    fn index_to_letter_wraps() {
        assert_eq!(index_to_letter(0), 'A');
        assert_eq!(index_to_letter(26), 'A');
        assert_eq!(index_to_letter(27), 'B');
    }

    #[test]
    fn normalize_strips_and_uppercases() {
        assert_eq!(normalize("Hello, World! 123"), "HELLOWORLD");
    }

    #[test]
    fn indices_roundtrip() {
        let text = "Attack at dawn";
        let indices = to_indices(text);
        assert_eq!(from_indices(&indices), "ATTACKATDAWN");
    }
}
