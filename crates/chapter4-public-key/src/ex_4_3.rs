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
//!
//! **Question 2** - RSA decipherment of a mixed-alphabet message.
//!
//! > Decipher the following message using the RSA algorithm with
//! > `n = 41378299599863` and `d = 17927688850145`. Each integer in this
//! > message represents two integers in deciphered form. Convert your
//! > deciphered message into text using the correspondence between the
//! > integers and the position of the characters in the text string
//! >
//! > `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ 1234567890-=!@#$%^&*()_+[]\{}|;':",./<>?~`
//! >
//! > (Note that the space character appears between the `Z` and the `1`,
//! > i.e., in the position 53.)
//!
//! The RSA step is the same inversion `M = C^d (mod n)`, but each recovered
//! `M` is only two character positions packed as a two-digit pair
//! (`M = 100 * a + b`). Positions are 1-based in the 94-character alphabet
//! above, so `53` is a space, `01` is `a`, and `35` is `I`. A 47-block
//! ciphertext therefore yields 94 characters.
//!
//! **Question 3** - Generate sizeable public and private keys.
//!
//! > As a trusted person, you have been contracted by a small clandestine
//! > organization to generate a set of sizeable public and private keys.
//! > Money is no object. They have agreed to pay you an amount proportional
//! > to the size of `n`. Go for it.
//!
//! An RSA key starts from two distinct primes `p` and `q`. The public
//! modulus is `n = p * q`, Euler's totient is `\phi(n) = (p - 1)(q - 1)`,
//! the public exponent `e` is chosen coprime to `\phi(n)`, and the private
//! exponent `d` is the inverse of `e` modulo `\phi(n)`. The public key is
//! the pair `(n, e)`; the private key is `(n, d)` (with `p` and `q` kept
//! alongside it).
//!
//! Because pay scales with `n`, [`generate_sizeable_key`] takes the largest
//! pair of primes whose product still fits in a `u64`: the two primes just
//! below `2^32`. The resulting `n` is a 20-digit integer, well above the
//! 14-digit moduli of Questions 1 and 2. The enciphering exponent is the
//! Fermat prime `65537`.

use crypto_core::alphabet::{index_to_letter, letter_to_index, normalize};
use crypto_core::primes::is_prime;

/// Public modulus from Question 1.
pub const N: u64 = 34_618_195_959_169;

/// Public enciphering exponent from Question 1.
pub const E: u64 = 20_000_000_089;

/// Private deciphering exponent from Question 1.
pub const D: u64 = 4_771_730_348_713;

/// Public modulus from Question 2.
pub const Q2_N: u64 = 41_378_299_599_863;

/// Private deciphering exponent from Question 2.
pub const Q2_D: u64 = 17_927_688_850_145;

/// Letters per numeric block. A 7-letter block is a 14-digit integer
/// strictly less than [`N`].
pub const BLOCK_LETTERS: usize = 7;

/// Two decimal digits per letter or alphabet position.
const RADIX: u64 = 100;

/// Null appended so the last block has exactly [`BLOCK_LETTERS`] letters.
const FILLER: char = 'X';

/// The plaintext riddle from Question 1.
pub const BOOK_MESSAGE: &str = "Why is it that when you transport something by car, \
it's called a shipment, but when you transport something by ship, \
it's called cargo?";

/// 1-based alphabet from Question 2. Position 53 is a space.
pub const Q2_ALPHABET: &str = r#"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ 1234567890-=!@#$%^&*()_+[]\{}|;':",./<>?~"#;

/// Ciphertext blocks from Question 2, one RSA integer per pair of characters.
pub const Q2_CIPHERTEXT: [u64; 47] = [
    31_041_840_486_988,
    29_077_957_566_727,
    11_122_505_017_205,
    40_696_280_438_081,
    33_635_577_577_494,
    23_781_081_595_165,
    13_392_200_113_552,
    13_042_556_080_033,
    12_862_388_751_593,
    34_364_195_535_462,
    2_445_939_988_968,
    33_291_530_313_321,
    // Enciphers the pair "oi". A 16-digit neighbor that sometimes appears in
    // transcriptions (4_113_262_626_495_683) is larger than `Q2_N` and is not
    // a valid RSA block.
    41_132_626_495_683,
    34_138_477_928_943,
    5_921_732_609_276,
    12_675_552_190_449,
    3_052_697_916_053,
    20_979_766_863_114,
    33_068_565_954_829,
    29_024_930_510_830,
    29_540_937_197_477,
    25_212_533_372_768,
    5_204_853_349_407,
    1_812_489_541_036,
    11_924_887_995_293,
    22_111_140_271_445,
    6_327_640_502_644,
    22_111_140_271_445,
    26_465_841_739_700,
    39_782_824_809_293,
    24_869_716_524_496,
    35_280_750_488_903,
    39_782_824_809_293,
    29_077_957_566_727,
    11_122_505_017_205,
    5_921_732_609_276,
    14_670_735_876_808,
    6_793_151_864_986,
    32_428_301_166_222,
    5_921_732_609_276,
    12_675_552_190_449,
    34_601_196_283_821,
    26_850_267_312_878,
    35_401_622_221_039,
    9_312_542_831_382,
    35_258_512_628_692,
    2_274_436_743_060,
];

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

/// Encipher the Question 1 riddle with the published public key `(n, e)`.
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

/// Decipher Question 2 `ciphertext` blocks with the private exponent `d`.
///
/// Each recovered integer is split into two 1-based [`Q2_ALPHABET`] positions.
///
/// # Panics
///
/// Panics if `n <= 1`, if a ciphertext block is not strictly less than `n`,
/// or if a recovered pair is outside `1..=Q2_ALPHABET.len()`.
pub fn decipher_pairs(ciphertext: &[u64], n: u64, d: u64) -> String {
    assert!(n > 1, "the modulus `n` must be greater than 1");
    ciphertext
        .iter()
        .map(|&c| {
            assert!(
                c < n,
                "ciphertext block {c} is not strictly less than n = {n}"
            );
            decode_pair(rsa_pow(c, d, n))
        })
        .collect()
}

/// Decipher the Question 2 ciphertext with the published private key `(n, d)`.
pub fn book_decipher() -> String {
    decipher_pairs(&Q2_CIPHERTEXT, Q2_N, Q2_D)
}

/// Invert a two-digit pair: `value = 100 * a + b` becomes the two characters
/// at 1-based positions `a` and `b` in [`Q2_ALPHABET`].
///
/// # Panics
///
/// Panics if either digit pair is not a valid alphabet position.
pub fn decode_pair(value: u64) -> String {
    let first = value / RADIX;
    let second = value % RADIX;
    format!("{}{}", index_to_char(first), index_to_char(second))
}

/// Character at 1-based position `index` in [`Q2_ALPHABET`].
///
/// # Panics
///
/// Panics if `index` is `0` or greater than the alphabet length.
pub fn index_to_char(index: u64) -> char {
    let len = Q2_ALPHABET.len() as u64;
    assert!(
        (1..=len).contains(&index),
        "alphabet position {index} is outside 1..={len}"
    );
    Q2_ALPHABET.as_bytes()[(index - 1) as usize] as char
}

/// 1-based position of `c` in [`Q2_ALPHABET`].
///
/// Returns `None` when `c` is not in the Question 2 alphabet.
pub fn char_to_index(c: char) -> Option<u64> {
    Q2_ALPHABET
        .as_bytes()
        .iter()
        .position(|&b| b == c as u8)
        .map(|i| (i as u64) + 1)
}

/// Pack two [`Q2_ALPHABET`] characters as a two-digit integer (`100 * a + b`).
///
/// # Panics
///
/// Panics if `pair` is not exactly two characters from [`Q2_ALPHABET`].
pub fn encode_pair(pair: &str) -> u64 {
    let mut chars = pair.chars();
    let first = chars.next().expect("a pair must contain two characters");
    let second = chars.next().expect("a pair must contain two characters");
    assert!(
        chars.next().is_none(),
        "a pair must contain exactly two characters"
    );
    let a = char_to_index(first).expect("RSA pairs contain only alphabet characters");
    let b = char_to_index(second).expect("RSA pairs contain only alphabet characters");
    a * RADIX + b
}

/// An RSA key: public pair `(n, e)`, private pair `(n, d)`, and the primes
/// `p`, `q` that produced `n`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RsaKey {
    /// First prime factor of [`Self::n`].
    pub p: u64,
    /// Second prime factor of [`Self::n`].
    pub q: u64,
    /// Public modulus `p * q`.
    pub n: u64,
    /// Public enciphering exponent.
    pub e: u64,
    /// Private deciphering exponent, inverse of `e` modulo `\phi(n)`.
    pub d: u64,
}

impl RsaKey {
    /// Build a key from distinct primes `p`, `q` and a public exponent `e`.
    ///
    /// # Panics
    ///
    /// Panics if `p` or `q` is not prime, if `p == q`, if `n = p * q` or
    /// `\phi(n)` overflow a `u64`, or if `gcd(e, φ(n)) != 1`.
    pub fn from_primes(p: u64, q: u64, e: u64) -> Self {
        assert!(is_prime(p), "p must be prime");
        assert!(is_prime(q), "q must be prime");
        assert!(p != q, "RSA primes must be distinct");
        let n = p.checked_mul(q).expect("n = p * q must fit in a u64");
        let phi = (p - 1)
            .checked_mul(q - 1)
            .expect("phi(n) must fit in a u64");
        assert!(gcd_u64(e, phi) == 1, "e must be coprime to phi(n)");
        let d = mod_inverse_u64(e, phi).expect("e is coprime to phi(n)");
        Self { p, q, n, e, d }
    }

    /// Public key `(n, e)`.
    pub fn public_key(&self) -> (u64, u64) {
        (self.n, self.e)
    }

    /// Private key `(n, d)`.
    pub fn private_key(&self) -> (u64, u64) {
        (self.n, self.d)
    }

    /// Euler totient `\phi(n) = (p - 1)(q - 1)`.
    pub fn phi(&self) -> u64 {
        (self.p - 1) * (self.q - 1)
    }

    /// Encipher an integer `m` with `0 <= m < n`.
    pub fn encipher_int(&self, m: u64) -> u64 {
        assert!(m < self.n, "plaintext integer must be strictly less than n");
        rsa_pow(m, self.e, self.n)
    }

    /// Decipher an integer that was produced by [`Self::encipher_int`].
    pub fn decipher_int(&self, c: u64) -> u64 {
        rsa_pow(c, self.d, self.n)
    }
}

/// Largest RSA key whose modulus still fits in a `u64`.
///
/// Chooses the two primes immediately below `2^32` and the Fermat exponent
/// `65537`. The resulting `n` has 20 decimal digits.
pub fn generate_sizeable_key() -> RsaKey {
    let p = prev_prime(1 << 32);
    let q_limit = u64::MAX / p;
    let q = {
        let candidate = prev_prime(q_limit);
        if candidate == p {
            prev_prime(p - 1)
        } else {
            candidate
        }
    };
    RsaKey::from_primes(p, q, 65_537)
}

/// Greatest odd prime `<= n`, or `2` when `n == 2`.
fn prev_prime(n: u64) -> u64 {
    assert!(n >= 2, "no prime is less than 2");
    if n == 2 {
        return 2;
    }
    let mut n = if n % 2 == 0 { n - 1 } else { n };
    while !is_prime(n) {
        n = n.saturating_sub(2);
        assert!(n >= 2, "no prime is less than 2");
    }
    n
}

fn gcd_u64(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}

fn mod_inverse_u64(a: u64, m: u64) -> Option<u64> {
    let (g, x, _) = extended_gcd_i128(i128::from(a), i128::from(m));
    if g != 1 {
        None
    } else {
        let m = i128::from(m);
        Some((((x % m) + m) % m) as u64)
    }
}

fn extended_gcd_i128(a: i128, b: i128) -> (i128, i128, i128) {
    if b == 0 {
        (a.abs(), if a < 0 { -1 } else { 1 }, 0)
    } else {
        let (g, x, y) = extended_gcd_i128(b, a % b);
        (g, y, x - (a / b) * y)
    }
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

    /// Matching public exponent for Question 2 (`d * e ≡ 1 (mod φ(n))`).
    const Q2_E: u64 = 200_378_033;

    const Q2_PLAINTEXT: &str =
        "If you;re in a vehicle going the speed of light: what happens when you turn on the headlights<";

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
                "WHYISIT", "THATWHE", "NYOUTRA", "NSPORTS", "OMETHIN", "GBYCARI", "TSCALLE",
                "DASHIPM", "ENTBUTW", "HENYOUT", "RANSPOR", "TSOMETH", "INGBYSH", "IPITSCA",
                "LLEDCAR", "GOXXXXX",
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
        assert_eq!(
            decipher(&cipher, N, D),
            prepare_blocks(BOOK_MESSAGE).concat()
        );
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

    #[test]
    fn q2_alphabet_places_space_at_position_53() {
        assert_eq!(Q2_ALPHABET.len(), 94);
        assert_eq!(index_to_char(1), 'a');
        assert_eq!(index_to_char(26), 'z');
        assert_eq!(index_to_char(27), 'A');
        assert_eq!(index_to_char(52), 'Z');
        assert_eq!(index_to_char(53), ' ');
        assert_eq!(index_to_char(54), '1');
        assert_eq!(char_to_index(' '), Some(53));
        assert_eq!(char_to_index('?'), Some(93));
    }

    #[test]
    fn q2_two_digit_pairs_roundtrip() {
        assert_eq!(encode_pair("If"), 3506);
        assert_eq!(encode_pair(" y"), 5325);
        assert_eq!(encode_pair("ou"), 1521);
        assert_eq!(encode_pair(";r"), 8418);
        assert_eq!(encode_pair("t:"), 2086);
        assert_eq!(encode_pair("s<"), 1991);
        assert_eq!(decode_pair(3506), "If");
        assert_eq!(decode_pair(5325), " y");
        assert_eq!(decode_pair(553), "e ");
        assert_eq!(decode_pair(1991), "s<");
    }

    #[test]
    fn q2_every_alphabet_character_roundtrips() {
        for (i, c) in Q2_ALPHABET.chars().enumerate() {
            let index = (i as u64) + 1;
            assert_eq!(index_to_char(index), c);
            assert_eq!(char_to_index(c), Some(index));
        }
    }

    #[test]
    fn q2_book_private_key_recovers_the_riddle() {
        assert_eq!(book_decipher(), Q2_PLAINTEXT);
    }

    #[test]
    fn q2_book_blocks_are_valid_rsa_ciphertext() {
        assert!(Q2_CIPHERTEXT.iter().all(|&c| c < Q2_N));
    }

    #[test]
    fn q2_decipher_inverts_encipher_for_the_book_key() {
        let cipher: Vec<u64> = Q2_PLAINTEXT
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let m = encode_pair(std::str::from_utf8(pair).unwrap());
                rsa_pow(m, Q2_E, Q2_N)
            })
            .collect();
        assert_eq!(cipher, Q2_CIPHERTEXT);
        assert_eq!(decipher_pairs(&cipher, Q2_N, Q2_D), Q2_PLAINTEXT);
    }

    #[test]
    fn q2_empty_message_is_empty() {
        assert_eq!(decipher_pairs(&[], Q2_N, Q2_D), "");
    }

    #[test]
    #[should_panic(expected = "greater than 1")]
    fn q2_non_positive_modulus_panics() {
        let _ = decipher_pairs(&[1], 1, Q2_D);
    }

    #[test]
    #[should_panic(expected = "not strictly less than n")]
    fn q2_ciphertext_as_large_as_modulus_panics() {
        let _ = decipher_pairs(&[Q2_N], Q2_N, Q2_D);
    }

    #[test]
    #[should_panic(expected = "outside 1")]
    fn q2_zero_position_is_rejected() {
        let _ = index_to_char(0);
    }

    /// Largest `u64` key from [`generate_sizeable_key`].
    const Q3_P: u64 = 4_294_967_291;
    const Q3_Q: u64 = 4_294_967_279;
    const Q3_N: u64 = 18_446_743_979_220_271_189;
    const Q3_E: u64 = 65_537;
    const Q3_D: u64 = 9_331_878_932_546_167_513;

    #[test]
    fn q3_tiny_key_matches_the_book_example() {
        // p = 11, q = 13, n = 143, \phi(n) = 120, e = 7, d = 103.
        let key = RsaKey::from_primes(11, 13, 7);
        assert_eq!(key.n, 143);
        assert_eq!(key.phi(), 120);
        assert_eq!(key.public_key(), (143, 7));
        assert_eq!(key.private_key(), (143, 103));
        assert_eq!(key.encipher_int(42), rsa_pow(42, 7, 143));
        assert_eq!(key.decipher_int(key.encipher_int(42)), 42);
    }

    #[test]
    fn q3_sizeable_key_is_the_largest_u64_pair() {
        let key = generate_sizeable_key();
        assert_eq!(
            key,
            RsaKey {
                p: Q3_P,
                q: Q3_Q,
                n: Q3_N,
                e: Q3_E,
                d: Q3_D,
            }
        );
        assert!(is_prime(key.p));
        assert!(is_prime(key.q));
        assert_ne!(key.p, key.q);
        assert_eq!(key.n, key.p * key.q);
        assert!(key.n > N && key.n > Q2_N);
        assert_eq!(
            (u128::from(key.e) * u128::from(key.d)) % u128::from(key.phi()),
            1
        );
        assert_eq!(key.decipher_int(key.encipher_int(42)), 42);
    }

    #[test]
    fn q3_sizeable_key_roundtrips_the_question1_riddle() {
        let key = generate_sizeable_key();
        let cipher = encipher(BOOK_MESSAGE, key.n, key.e);
        assert_eq!(
            decipher(&cipher, key.n, key.d),
            prepare_blocks(BOOK_MESSAGE).concat()
        );
    }

    #[test]
    #[should_panic(expected = "must be prime")]
    fn q3_composite_prime_is_rejected() {
        let _ = RsaKey::from_primes(9, 13, 7);
    }

    #[test]
    #[should_panic(expected = "must be distinct")]
    fn q3_repeated_prime_is_rejected() {
        let _ = RsaKey::from_primes(11, 11, 7);
    }

    #[test]
    #[should_panic(expected = "coprime")]
    fn q3_even_exponent_is_rejected() {
        let _ = RsaKey::from_primes(11, 13, 2);
    }
}
