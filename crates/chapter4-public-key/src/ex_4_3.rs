//! Exercise 4.3 - Two Examples.
//!
//! **Question 1** - RSA encipherment of a riddle.
//!
//! > Encipher the following message using the RSA algorithm with
//! > `n = 34618195959169` and `e = 20000000089`:
//! > "Why is it that when you transport something by car, it's called a
//! > shipment, but when you transport something by ship, it's called cargo?"
//! > Use a text-numeric correspondence of your choice. Check your answer by
//! > deciphering it using `d = 4771730348713`.
//!
//! RSA treats a block of plaintext as an integer `M` with `0 <= M < n` and
//! produces the ciphertext integer
//!
//! ```text
//! C = M^e  (mod n).
//! ```
//!
//! Decipherment inverts that map with the private exponent:
//!
//! ```text
//! M = C^d  (mod n).
//! ```
//!
//! The pair `(n, e)` is the public key. Here `n = p * q` with
//! `p = 768013` and `q = 45075013`, and `d` is the inverse of `e` modulo
//! `\phi(n) = (p - 1)(q - 1)`, so Euler's theorem guarantees the round trip.
//!
//! The text-numeric correspondence used here is the book's usual
//! two-digit numbering `A = 00`, `B = 01`, ..., `Z = 25`. Non-letters are
//! dropped and case is ignored. Letters are then grouped into 7-letter
//! blocks and each block is read as a 14-digit integer (so the largest
//! possible block is `25252525252525`, which is still less than `n`). A
//! short final block is padded with `X`.

use crypto_core::alphabet::{index_to_letter, letter_to_index, normalize};

/// Public modulus from the exercise.
pub const N: u64 = 34_618_195_959_169;

/// Public enciphering exponent from the exercise.
pub const E: u64 = 20_000_000_089;

/// Private deciphering exponent from the exercise.
pub const D: u64 = 4_771_730_348_713;

/// Letters per numeric block. A 7-letter block is a 14-digit integer
/// strictly less than [`N`].
pub const BLOCK_LETTERS: usize = 7;

/// Two decimal digits per letter (`A = 00`, ..., `Z = 25`).
const RADIX: u64 = 100;

/// Null appended so the last block has exactly [`BLOCK_LETTERS`] letters.
const FILLER: char = 'X';

/// The plaintext riddle from the exercise.
pub const BOOK_MESSAGE: &str = "Why is it that when you transport something by car, \
it's called a shipment, but when you transport something by ship, \
it's called cargo?";

/// Encipher `plaintext` under the RSA public key `(n, e)`.
///
/// Returns one ciphertext integer per 7-letter block. Non-letters are
/// dropped; a short final block is padded with `X`.
///
/// # Panics
///
/// Panics if `n <= 1`, or if a prepared block is not strictly less than `n`.
pub fn encipher(plaintext: &str, n: u64, e: u64) -> Vec<u64> {
    assert!(n > 1, "the modulus `n` must be greater than 1");
    prepare_blocks(plaintext)
        .into_iter()
        .map(|block| {
            let m = encode_block(&block);
            assert!(
                m < n,
                "plaintext block {m} is not strictly less than n = {n}"
            );
            rsa_pow(m, e, n)
        })
        .collect()
}

/// Decipher `ciphertext` blocks that were produced by [`encipher`] with the
/// matching private exponent `d`.
///
/// The recovered text is uppercase letters only and still contains any
/// trailing filler that was inserted during encipherment.
///
/// # Panics
///
/// Panics if `n <= 1`.
pub fn decipher(ciphertext: &[u64], n: u64, d: u64) -> String {
    assert!(n > 1, "the modulus `n` must be greater than 1");
    ciphertext
        .iter()
        .map(|&c| decode_block(rsa_pow(c, d, n)))
        .collect()
}

/// Encipher the exercise's riddle with the published public key `(n, e)`.
pub fn book_encipher() -> Vec<u64> {
    encipher(BOOK_MESSAGE, N, E)
}

/// Letters of a 7-character block as a two-digit decimal integer
/// (`A = 00`, ..., `Z = 25`).
///
/// # Panics
///
/// Panics if `letters` is not exactly [`BLOCK_LETTERS`] alphabetic characters.
pub fn encode_block(letters: &str) -> u64 {
    assert_eq!(
        letters.chars().count(),
        BLOCK_LETTERS,
        "a block must contain exactly {BLOCK_LETTERS} letters"
    );
    let mut value = 0u64;
    for c in letters.chars() {
        let index = letter_to_index(c).expect("RSA blocks contain only letters");
        value = value * RADIX + u64::from(index);
    }
    value
}

/// Invert [`encode_block`]: a 14-digit (zero-padded) integer back to 7 letters.
pub fn decode_block(value: u64) -> String {
    let width = BLOCK_LETTERS * 2;
    let digits = format!("{value:0width$}");
    debug_assert_eq!(digits.len(), width);
    digits
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let index = (pair[0] - b'0') * 10 + (pair[1] - b'0');
            index_to_letter(index)
        })
        .collect()
}

/// Normalize `text` and split it into 7-letter blocks, padding the last
/// block with [`FILLER`] if needed.
pub fn prepare_blocks(text: &str) -> Vec<String> {
    let mut letters = normalize(text);
    let rem = letters.len() % BLOCK_LETTERS;
    if rem != 0 {
        letters.extend(std::iter::repeat(FILLER).take(BLOCK_LETTERS - rem));
    }
    letters
        .as_bytes()
        .chunks_exact(BLOCK_LETTERS)
        .map(|chunk| String::from_utf8(chunk.to_vec()).expect("normalized text is ASCII"))
        .collect()
}

/// Square-and-multiply: `base^exp mod n` for the textbook-sized RSA integers.
fn rsa_pow(base: u64, exp: u64, n: u64) -> u64 {
    if n == 1 {
        return 0;
    }
    let mut result = 1u128;
    let mut base = u128::from(base % n);
    let n = u128::from(n);
    let mut exp = exp;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % n;
        }
        exp >>= 1;
        base = (base * base) % n;
    }
    result as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ciphertext of [`BOOK_MESSAGE`] under `(N, E)`, one integer per block.
    const BOOK_CIPHERTEXT: [u64; 16] = [
        8_360_669_072_153,
        12_205_476_466_241,
        12_324_761_235_770,
        7_111_519_540_119,
        375_605_416_029,
        23_775_611_562_680,
        17_973_159_007_625,
        3_225_663_211_822,
        31_201_216_912_921,
        26_342_364_620_832,
        34_244_839_962_106,
        21_417_709_404_228,
        27_423_174_642_524,
        341_237_101_749,
        16_330_606_586_561,
        15_640_529_809_729,
    ];

    #[test]
    fn two_digit_correspondence() {
        assert_eq!(encode_block("WHYISIT"), 22_072_408_180_819);
        assert_eq!(encode_block("AAAAAAA"), 0);
        assert_eq!(encode_block("GBYCARI"), 6_012_402_001_708);
        assert_eq!(decode_block(22_072_408_180_819), "WHYISIT");
        assert_eq!(decode_block(0), "AAAAAAA");
        assert_eq!(decode_block(6_012_402_001_708), "GBYCARI");
    }

    #[test]
    fn prepare_blocks_normalizes_and_pads() {
        assert_eq!(
            prepare_blocks(BOOK_MESSAGE),
            [
                "WHYISIT", "THATWHE", "NYOUTRA", "NSPORTS", "OMETHIN", "GBYCARI",
                "TSCALLE", "DASHIPM", "ENTBUTW", "HENYOUT", "RANSPOR", "TSOMETH",
                "INGBYSH", "IPITSCA", "LLEDCAR", "GOXXXXX",
            ]
        );
        assert!(prepare_blocks("...").is_empty());
        assert_eq!(prepare_blocks("Hi!"), vec!["HIXXXXX"]);
    }

    #[test]
    fn book_message_enciphers_to_expected_blocks() {
        assert_eq!(book_encipher(), BOOK_CIPHERTEXT);
    }

    #[test]
    fn book_private_key_recovers_the_riddle() {
        let recovered = decipher(&BOOK_CIPHERTEXT, N, D);
        assert_eq!(
            recovered,
            "WHYISITTHATWHENYOUTRANSPORTSOMETHINGBYCARITSCALLEDASHIPMENT\
             BUTWHENYOUTRANSPORTSOMETHINGBYSHIPITSCALLEDCARGOXXXXX"
        );
    }

    #[test]
    fn decipher_inverts_encipher_for_the_book_key() {
        let cipher = encipher(BOOK_MESSAGE, N, E);
        assert_eq!(decipher(&cipher, N, D), prepare_blocks(BOOK_MESSAGE).concat());
    }

    #[test]
    fn tiny_rsa_roundtrip() {
        // p = 11, q = 13, n = 143, \phi(n) = 120, e = 7, d = 103.
        let n = 143;
        let e = 7;
        let d = 103;
        let cipher = encipher("RSA", n, e);
        assert_eq!(decipher(&cipher, n, d), "RSAXXXX");
    }

    #[test]
    fn empty_message_is_empty() {
        assert!(encipher("", N, E).is_empty());
        assert_eq!(decipher(&[], N, D), "");
    }

    #[test]
    #[should_panic(expected = "greater than 1")]
    fn non_positive_modulus_panics() {
        let _ = encipher("A", 1, E);
    }
}
