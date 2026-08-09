//! Exercises 2.5 - Disguising frequencies: Letter-Number, n-graphs, Vigenere.
//!
//! **Question 1** - Letter-Number encipherment / decipherment.
//!
//! > Write a program to encipher and decipher messages by means of the
//! > "Letter-Number" scheme appearing in [the table below].
//!
//! This is a *homophonic* substitution: each plaintext letter maps to a
//! disjoint subset of the two-digit integers `00..=99`, with more common
//! English letters assigned more numbers so that ciphertext digit-pair
//! frequencies look flatter than ordinary letter frequencies. Encipherment
//! cycles through a letter's assigned numbers in order; decipherment looks up
//! each two-digit code in the inverse map.
//!
//! **Question 2** - Digraph through quintgraph counts.
//!
//! > Write a program that accepts a text message and outputs a count of each
//! > digraph, trigraph, quadgraph, and quintgraph (And don't pretend you don't
//! > know what these terms mean.)
//!
//! An *n*-graph (or *n*-gram) is an ordered block of `n` adjacent letters.
//! Counts use overlapping windows after normalization, matching the digraph
//! convention from Exercise 1.6: `"THE"` contributes digraphs `TH` and `HE`,
//! and likewise for longer blocks.
//!
//! **Question 3** - Vigenere Square.
//!
//! > Write a program that enciphers and deciphers messages using the
//! > "Vigenere Square". The input to your program should be both a message
//! > and the keyword.
//!
//! The Vigenere cipher is a polyalphabetic substitution: each plaintext letter
//! is shifted by the corresponding letter of a repeating keyword
//! (`C_i = P_i + K_i (mod 26)`), which is exactly what reading the Vigenere
//! square row-by-row accomplishes. Decipherment subtracts the same key stream.
//!
//! **Question 4** - Index of Coincidence and keyword-length estimate.
//!
//! > Write a program that computes the "Index of Coincidence" of a message and
//! > then approximates the length of the keyword.
//!
//! The *index of coincidence* (IC) is the probability that two randomly chosen
//! letters of the text are equal. English plaintext has IC near
//! [`ENGLISH_IOC`]; uniformly random 26-letter text sits near [`RANDOM_IOC`].
//! A Vigenere ciphertext falls in between, and Friedman's estimate recovers an
//! approximate keyword length from that observed IC and the message length.

use std::collections::BTreeMap;
use std::fmt::Display;

use crypto_core::alphabet::{from_indices, letter_to_index, normalize, to_indices, ALPHABET_SIZE};
use crypto_core::frequency::letter_counts;
use crypto_core::modular::modulo;

pub use crypto_core::frequency::index_of_coincidence;

/// The book's Letter-Number table: index `0` (`A`) through `25` (`Z`).
///
/// Every integer in `0..=99` appears in exactly one subset.
const LETTER_NUMBERS: [&[u8]; 26] = [
    &[15, 33, 37, 55, 57, 72, 91, 96],       // A
    &[24],                                   // B
    &[3, 39, 67],                            // C
    &[4, 43, 61, 88],                        // D
    &[8, 12, 20, 46, 47, 59, 64, 79, 81, 85, 90, 94, 97], // E
    &[40, 48],                               // F
    &[29, 53],                               // G
    &[5, 16, 30, 42, 69, 99],                // H
    &[14, 45, 50, 60, 73, 82, 93],           // I
    &[11],                                   // J
    &[77],                                   // K
    &[1, 26, 71, 98],                        // L
    &[34, 87],                               // M
    &[6, 17, 22, 31, 49, 58],                // N
    &[2, 10, 41, 51, 66, 75, 83],            // O
    &[13, 18],                               // P
    &[36],                                   // Q
    &[21, 25, 65, 68, 92, 95],               // R
    &[0, 28, 52, 63, 74, 78],                // S
    &[7, 19, 23, 35, 38, 54, 70, 84, 89],    // T
    &[9, 32],                                // U
    &[44],                                   // V
    &[56, 80],                               // W
    &[86],                                   // X
    &[62, 76],                               // Y
    &[27],                                   // Z
];

/// Build the inverse map from two-digit code (`0..=99`) to plaintext letter.
fn number_to_letter() -> [char; 100] {
    let mut map = ['?'; 100];
    for (i, numbers) in LETTER_NUMBERS.iter().enumerate() {
        let letter = (b'A' + i as u8) as char;
        for &n in *numbers {
            map[n as usize] = letter;
        }
    }
    map
}

/// Encipher `plaintext` with the Letter-Number scheme.
///
/// Non-letters are dropped. Each letter is replaced by the next two-digit code
/// from its assigned subset (cycling when the subset is exhausted). Codes are
/// written zero-padded and separated by spaces, e.g. `"15 24 03"`.
pub fn encipher(plaintext: &str) -> String {
    let mut usage = [0usize; 26];
    let mut codes = Vec::new();

    for c in plaintext.chars() {
        let Some(index) = letter_to_index(c) else {
            continue;
        };
        let numbers = LETTER_NUMBERS[index as usize];
        let slot = usage[index as usize] % numbers.len();
        usage[index as usize] += 1;
        codes.push(format!("{:02}", numbers[slot]));
    }

    codes.join(" ")
}

/// Decipher a Letter-Number ciphertext back to uppercase plaintext.
///
/// Accepts space-separated two-digit codes or a continuous digit string of even
/// length. Returns `Err` if any token is not a two-digit integer in `00..=99`
/// that appears in the scheme, or if a continuous digit run has odd length.
pub fn decipher(ciphertext: &str) -> Result<String, String> {
    let inverse = number_to_letter();
    let digits: String = ciphertext.chars().filter(|c| !c.is_whitespace()).collect();

    if digits.is_empty() {
        return Ok(String::new());
    }
    if !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err("ciphertext must contain only digits and whitespace".into());
    }
    if digits.len() % 2 != 0 {
        return Err("ciphertext must contain an even number of digits".into());
    }

    let mut plaintext = String::with_capacity(digits.len() / 2);
    for pair in digits.as_bytes().chunks(2) {
        let code = (pair[0] - b'0') * 10 + (pair[1] - b'0');
        let letter = inverse[code as usize];
        if letter == '?' {
            return Err(format!("unknown Letter-Number code {code:02}"));
        }
        plaintext.push(letter);
    }
    Ok(plaintext)
}

// --- Question 2: n-graph counts ---

/// Count every overlapping `n`-letter block in `text`.
///
/// Non-letters are removed and case is discarded before windows are formed.
/// Returns an empty map when `n == 0` or the normalized text is shorter than
/// `n`. Keys are uppercase strings of length `n`.
pub fn ngraph_counts(text: &str, n: usize) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    if n == 0 {
        return counts;
    }

    let normalized = normalize(text);
    let letters: Vec<char> = normalized.chars().collect();
    if letters.len() < n {
        return counts;
    }

    for window in letters.windows(n) {
        let ngraph: String = window.iter().collect();
        *counts.entry(ngraph).or_insert(0) += 1;
    }
    counts
}

/// Frequency table for every `n`-graph appearing in `text`.
///
/// Rows are `(ngraph, count, frequency)`, sorted by descending count with ties
/// broken alphabetically. Frequencies are relative to the total number of
/// overlapping `n`-graphs and sum to `1.0` whenever that total is positive.
pub fn ngraph_frequency_table(text: &str, n: usize) -> Vec<(String, u64, f64)> {
    let counts = ngraph_counts(text, n);
    let total: u64 = counts.values().sum();
    let mut rows: Vec<(String, u64, f64)> = counts
        .into_iter()
        .map(|(ngraph, count)| {
            let frequency = if total > 0 {
                count as f64 / total as f64
            } else {
                0.0
            };
            (ngraph, count, frequency)
        })
        .collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rows
}

/// Digraph counts (`n = 2`).
pub fn digraph_counts(text: &str) -> BTreeMap<String, u64> {
    ngraph_counts(text, 2)
}

/// Trigraph counts (`n = 3`).
pub fn trigraph_counts(text: &str) -> BTreeMap<String, u64> {
    ngraph_counts(text, 3)
}

/// Quadgraph counts (`n = 4`).
pub fn quadgraph_counts(text: &str) -> BTreeMap<String, u64> {
    ngraph_counts(text, 4)
}

/// Quintgraph counts (`n = 5`).
pub fn quintgraph_counts(text: &str) -> BTreeMap<String, u64> {
    ngraph_counts(text, 5)
}

/// Render a frequency table as `SYMBOL: count (frequency)` lines.
pub fn format_table<S: Display>(rows: &[(S, u64, f64)]) -> String {
    let mut out = String::new();
    for (symbol, count, frequency) in rows {
        out.push_str(&format!("{symbol}: {count} ({frequency:.4})\n"));
    }
    out
}

/// Full program output for Question 2: digraph through quintgraph tables.
pub fn format_ngraph_report(text: &str) -> String {
    let sections = [
        (2, "Digraphs"),
        (3, "Trigraphs"),
        (4, "Quadgraphs"),
        (5, "Quintgraphs"),
    ];
    let mut out = String::new();
    for (i, &(n, title)) in sections.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(title);
        out.push('\n');
        out.push_str(&format_table(&ngraph_frequency_table(text, n)));
    }
    out
}

// --- Question 3: Vigenere Square ---

/// Extract the repeating key stream as 0..=25 indices from `keyword`.
///
/// Non-letters are dropped. Panics if the keyword contains no letters, since
/// then there is no row of the Vigenere square to consult.
fn key_stream(keyword: &str) -> Vec<u8> {
    let keys = to_indices(keyword);
    assert!(
        !keys.is_empty(),
        "keyword must contain at least one letter"
    );
    keys
}

/// Encipher `plaintext` with the Vigenere Square keyed by `keyword`.
///
/// Non-letters in the message and keyword are dropped; the keyword repeats to
/// match the length of the normalized plaintext. Each letter is shifted by its
/// key letter: `C = (P + K) mod 26`.
///
/// # Panics
///
/// Panics if `keyword` contains no alphabetic characters.
pub fn vigenere_encipher(plaintext: &str, keyword: &str) -> String {
    let keys = key_stream(keyword);
    let modulus = ALPHABET_SIZE as i64;
    let enciphered: Vec<u8> = to_indices(plaintext)
        .into_iter()
        .enumerate()
        .map(|(i, plain)| {
            let key = keys[i % keys.len()] as i64;
            modulo(plain as i64 + key, modulus) as u8
        })
        .collect();
    from_indices(&enciphered)
}

/// Decipher `ciphertext` that was produced by [`vigenere_encipher`] with the
/// same `keyword`.
///
/// Inverts the Vigenere shift: `P = (C - K) mod 26`.
///
/// # Panics
///
/// Panics if `keyword` contains no alphabetic characters.
pub fn vigenere_decipher(ciphertext: &str, keyword: &str) -> String {
    let keys = key_stream(keyword);
    let modulus = ALPHABET_SIZE as i64;
    let deciphered: Vec<u8> = to_indices(ciphertext)
        .into_iter()
        .enumerate()
        .map(|(i, cipher)| {
            let key = keys[i % keys.len()] as i64;
            modulo(cipher as i64 - key, modulus) as u8
        })
        .collect();
    from_indices(&deciphered)
}

// --- Question 4: Index of Coincidence and Friedman keyword-length estimate ---

/// Expected index of coincidence for English plaintext (Lewand).
pub const ENGLISH_IOC: f64 = 0.0667;

/// Expected index of coincidence for uniformly random 26-letter text (`1/26`).
pub const RANDOM_IOC: f64 = 0.0385;

/// Result of the Friedman analysis for Question 4.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FriedmanEstimate {
    /// Number of letters in the message (non-letters ignored).
    pub letter_count: u64,
    /// Observed index of coincidence of the message.
    pub index_of_coincidence: f64,
    /// Approximate Vigenere keyword length from the Friedman formula.
    pub keyword_length: f64,
}

/// Approximate the Vigenere keyword length from an observed IC and letter count.
///
/// Uses Friedman's estimate
///
/// ```text
/// r ≈ (κ_p - κ_r) · N / ((N - 1) · IC - κ_r · N + κ_p)
/// ```
///
/// with `κ_p = `[`ENGLISH_IOC`] and `κ_r = `[`RANDOM_IOC`]. Returns `0.0` when
/// `N < 2`, and `f64::INFINITY` when the denominator is effectively zero (IC so
/// close to `κ_r` that no finite period is implied).
pub fn keyword_length_from_ioc(ic: f64, letter_count: u64) -> f64 {
    if letter_count < 2 {
        return 0.0;
    }
    let n = letter_count as f64;
    let numerator = (ENGLISH_IOC - RANDOM_IOC) * n;
    let denominator = (n - 1.0) * ic - RANDOM_IOC * n + ENGLISH_IOC;
    if denominator.abs() < 1e-15 {
        return f64::INFINITY;
    }
    numerator / denominator
}

/// Approximate the keyword length of a (presumed Vigenere) message from its IC.
pub fn approximate_keyword_length(text: &str) -> f64 {
    let n: u64 = letter_counts(text).iter().sum();
    keyword_length_from_ioc(index_of_coincidence(text), n)
}

/// Compute the index of coincidence of `text` and the Friedman keyword-length
/// estimate — the full Question 4 "program" output.
pub fn friedman_estimate(text: &str) -> FriedmanEstimate {
    let letter_count: u64 = letter_counts(text).iter().sum();
    let index_of_coincidence = index_of_coincidence(text);
    let keyword_length = keyword_length_from_ioc(index_of_coincidence, letter_count);
    FriedmanEstimate {
        letter_count,
        index_of_coincidence,
        keyword_length,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letter_number_table_partitions_0_through_99() {
        let mut seen = [false; 100];
        let mut total = 0usize;
        for numbers in &LETTER_NUMBERS {
            for &n in *numbers {
                assert!(n < 100, "code {n} out of range");
                assert!(!seen[n as usize], "duplicate code {n:02}");
                seen[n as usize] = true;
                total += 1;
            }
        }
        assert_eq!(total, 100);
        assert!(seen.iter().all(|&s| s));
    }

    #[test]
    fn encipher_cycles_through_a_letter_subset() {
        // A has eight numbers; the first three uses take the first three codes.
        assert_eq!(encipher("aaa"), "15 33 37");
        assert_eq!(encipher("b"), "24");
        assert_eq!(encipher("e"), "08");
    }

    #[test]
    fn encipher_drops_non_letters() {
        assert_eq!(encipher("A B!"), "15 24");
    }

    #[test]
    fn decipher_roundtrips_spaced_and_packed() {
        let cipher = encipher("Attack at dawn");
        assert_eq!(decipher(&cipher).unwrap(), "ATTACKATDAWN");
        let packed: String = cipher.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(decipher(&packed).unwrap(), "ATTACKATDAWN");
    }

    #[test]
    fn decipher_rejects_odd_length_and_non_digits() {
        assert!(decipher("15 2").is_err());
        assert!(decipher("15 xz").is_err());
    }

    #[test]
    fn digraphs_and_trigraphs_overlap() {
        // "THE" -> digraphs TH, HE; trigraph THE.
        let digraphs = digraph_counts("THE");
        assert_eq!(digraphs.get("TH"), Some(&1));
        assert_eq!(digraphs.get("HE"), Some(&1));

        let trigraphs = trigraph_counts("THE");
        assert_eq!(trigraphs.get("THE"), Some(&1));
        assert_eq!(trigraphs.len(), 1);
    }

    #[test]
    fn longer_ngraphs_on_mississippi() {
        // MISSISSIPPI
        // quadgraphs (8): MISS ISSI SSIS SISS ISSI SSIP SIPP IPPI
        let quads = quadgraph_counts("MISSISSIPPI");
        assert_eq!(quads.get("ISSI"), Some(&2));
        assert_eq!(quads.values().sum::<u64>(), 8);

        // quintgraphs (7): MISSI ISSIS SSISS SISSI ISSIP SSIPP SIPPI
        let quints = quintgraph_counts("MISSISSIPPI");
        assert_eq!(quints.get("MISSI"), Some(&1));
        assert_eq!(quints.get("ISSIS"), Some(&1));
        assert_eq!(quints.values().sum::<u64>(), 7);
    }

    #[test]
    fn ngraph_table_sorted_by_count() {
        let table = ngraph_frequency_table("MISSISSIPPI", 2);
        let order: Vec<&str> = table.iter().map(|(d, _, _)| d.as_str()).collect();
        assert_eq!(order, ["IS", "SI", "SS", "IP", "MI", "PI", "PP"]);
    }

    #[test]
    fn short_text_yields_empty_longer_ngraphs() {
        assert!(trigraph_counts("AB").is_empty());
        assert!(quadgraph_counts("ABC").is_empty());
        assert!(quintgraph_counts("ABCD").is_empty());
    }

    #[test]
    fn report_contains_all_four_sections() {
        let report = format_ngraph_report("THE");
        assert!(report.contains("Digraphs\n"));
        assert!(report.contains("Trigraphs\n"));
        assert!(report.contains("Quadgraphs\n"));
        assert!(report.contains("Quintgraphs\n"));
        assert!(report.contains("TH: 1"));
        assert!(report.contains("THE: 1"));
    }

    #[test]
    fn vigenere_classic_lemon_example() {
        // Classic textbook / Wikipedia example.
        assert_eq!(
            vigenere_encipher("ATTACKATDAWN", "LEMON"),
            "LXFOPVEFRNHR"
        );
        assert_eq!(
            vigenere_decipher("LXFOPVEFRNHR", "LEMON"),
            "ATTACKATDAWN"
        );
    }

    #[test]
    fn vigenere_drops_non_letters_in_message_and_keyword() {
        assert_eq!(
            vigenere_encipher("Attack at dawn!", "Le mon"),
            "LXFOPVEFRNHR"
        );
    }

    #[test]
    fn vigenere_roundtrip() {
        let plaintext = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG";
        let keyword = "CIPHER";
        assert_eq!(
            vigenere_decipher(&vigenere_encipher(plaintext, keyword), keyword),
            plaintext
        );
    }

    #[test]
    fn vigenere_single_letter_keyword_is_caesar() {
        // Keyword A is a shift of 0; keyword D is a shift of 3.
        assert_eq!(vigenere_encipher("ATTACKATDAWN", "A"), "ATTACKATDAWN");
        assert_eq!(vigenere_encipher("ATTACKATDAWN", "D"), "DWWDFNDWGDZQ");
    }

    #[test]
    #[should_panic(expected = "at least one letter")]
    fn vigenere_empty_keyword_panics() {
        let _ = vigenere_encipher("HELLO", "123");
    }

    #[test]
    fn friedman_formula_matches_worked_example() {
        // n = 473, IC = 0.0422 with κ_p = 0.0667, κ_r = 0.0385:
        // r = 0.0282·473 / ((473-1)·0.0422 - 0.0385·473 + 0.0667) ≈ 7.517
        let r = keyword_length_from_ioc(0.0422, 473);
        assert!((r - 7.517).abs() < 0.01, "got {r}");
    }

    #[test]
    fn english_plaintext_suggests_monoalphabetic() {
        let text = "\
            THE INDEX OF COINCIDENCE IS A STATISTICAL MEASURE OF HOW LIKELY \
            TWO RANDOMLY SELECTED LETTERS FROM A TEXT ARE TO BE THE SAME \
            LETTER ENGLISH PLAINTEXT HAS A CHARACTERISTIC INDEX NEAR THE \
            VALUE EXPECTED FOR NATURAL LANGUAGE WHILE A POLYALPHABETIC \
            CIPHER DRIVES THE INDEX TOWARD THAT OF RANDOM TEXT";
        let estimate = friedman_estimate(text);
        assert!(
            (estimate.index_of_coincidence - ENGLISH_IOC).abs() < 0.015,
            "IC = {}",
            estimate.index_of_coincidence
        );
        // Monoalphabetic / plaintext: Friedman estimate should be near 1.
        assert!(
            estimate.keyword_length > 0.5 && estimate.keyword_length < 2.0,
            "keyword length = {}",
            estimate.keyword_length
        );
    }

    #[test]
    fn vigenere_ciphertext_ioc_estimates_keyword_length() {
        let plaintext = "\
            THE INDEX OF COINCIDENCE IS A STATISTICAL MEASURE OF HOW LIKELY \
            TWO RANDOMLY SELECTED LETTERS FROM A TEXT ARE TO BE THE SAME \
            LETTER ENGLISH PLAINTEXT HAS A CHARACTERISTIC INDEX NEAR THE \
            VALUE EXPECTED FOR NATURAL LANGUAGE WHILE A POLYALPHABETIC \
            CIPHER DRIVES THE INDEX TOWARD THAT OF RANDOM TEXT AND THE \
            FRIEDMAN TEST USES THAT DROP TO APPROXIMATE THE PERIOD OF THE \
            REPEATING KEYWORD USED BY THE VIGENERE CIPHER SYSTEM ITSELF";
        let keyword = "LEMON"; // length 5
        let ciphertext = vigenere_encipher(plaintext, keyword);
        let estimate = friedman_estimate(&ciphertext);

        assert!(
            estimate.index_of_coincidence < ENGLISH_IOC - 0.005,
            "Vigenere IC should fall below English; got {}",
            estimate.index_of_coincidence
        );
        assert!(
            estimate.index_of_coincidence > RANDOM_IOC,
            "Vigenere IC should stay above random; got {}",
            estimate.index_of_coincidence
        );
        // Friedman is an approximation; for a few hundred letters expect the
        // estimate to land in the right neighborhood of the true period 5.
        assert!(
            estimate.keyword_length > 2.0 && estimate.keyword_length < 10.0,
            "keyword length = {}",
            estimate.keyword_length
        );
    }

    #[test]
    fn short_messages_have_zero_keyword_estimate() {
        assert_eq!(approximate_keyword_length(""), 0.0);
        assert_eq!(approximate_keyword_length("A"), 0.0);
    }
}
