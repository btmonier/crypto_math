//! Exercise 1.6 - Letter and digraph frequency counts.
//!
//! > Write a program that accepts a text message and outputs the frequency of
//! > each letter appearing in the message. A bit more challenging (perhaps)
//! > would be to write a program that outputs the frequency of all *digraphs*
//! > in the message.
//!
//! Frequency analysis is the foundational tool for breaking monoalphabetic
//! ciphers: because a substitution cipher preserves the statistical profile of
//! the plaintext, the most common ciphertext letter is very likely to stand for
//! `E`, and so on.
//!
//! A *digraph* is an ordered pair of adjacent letters. The pairs are taken
//! *overlapping* (so `THE` contributes `TH` and `HE`) and are counted after
//! normalization strips spaces and punctuation, which means digraphs run across
//! word boundaries exactly as classical cryptanalysts tabulated them.
//!
//! Both tabulators reuse the shared [`crypto_core::frequency`] helpers where
//! possible and report each symbol's raw count alongside its relative frequency
//! (a proportion in `0.0..=1.0`).

use std::collections::BTreeMap;
use std::fmt::Display;

use crypto_core::alphabet::{index_to_letter, normalize, ALPHABET_SIZE};
use crypto_core::frequency::{letter_counts, letter_frequencies};

/// Frequency table for the 26 letters `A..Z` in `text`.
///
/// Returns one row per letter, in alphabetical order, as
/// `(letter, count, frequency)`. Letters that never appear are included with a
/// count of `0` so the result is always the complete frequency profile. The
/// frequencies sum to `1.0` whenever at least one letter is present.
pub fn letter_frequency_table(text: &str) -> Vec<(char, u64, f64)> {
    let counts = letter_counts(text);
    let freqs = letter_frequencies(text);
    (0..ALPHABET_SIZE)
        .map(|i| (index_to_letter(i), counts[i as usize], freqs[i as usize]))
        .collect()
}

/// Count every overlapping two-letter digraph in `text`.
///
/// Non-letters are removed and case is discarded before pairs are formed, so a
/// message such as `"To be."` yields the digraphs `TO`, `OB`, and `BE`. The
/// keys are two-character uppercase strings; digraphs that do not occur are
/// absent from the map.
pub fn digraph_counts(text: &str) -> BTreeMap<String, u64> {
    let normalized = normalize(text);
    let letters: Vec<char> = normalized.chars().collect();
    let mut counts = BTreeMap::new();
    for pair in letters.windows(2) {
        let digraph: String = pair.iter().collect();
        *counts.entry(digraph).or_insert(0) += 1;
    }
    counts
}

/// Frequency table for every digraph appearing in `text`.
///
/// Returns `(digraph, count, frequency)` rows sorted by descending count, with
/// ties broken alphabetically. The frequency is relative to the total number of
/// digraphs (i.e. one fewer than the number of letters in the message), so the
/// frequencies sum to `1.0` whenever the message contains at least two letters.
pub fn digraph_frequency_table(text: &str) -> Vec<(String, u64, f64)> {
    let counts = digraph_counts(text);
    let total: u64 = counts.values().sum();
    let mut rows: Vec<(String, u64, f64)> = counts
        .into_iter()
        .map(|(digraph, count)| {
            let frequency = if total > 0 {
                count as f64 / total as f64
            } else {
                0.0
            };
            (digraph, count, frequency)
        })
        .collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rows
}

/// Render a frequency table as aligned `SYMBOL: count (frequency)` lines.
///
/// Works for either the [`letter_frequency_table`] or [`digraph_frequency_table`]
/// output; this is the "output" half of the exercise, turning the tabulated
/// rows into the text a program would print.
pub fn format_table<S: Display>(rows: &[(S, u64, f64)]) -> String {
    let mut out = String::new();
    for (symbol, count, frequency) in rows {
        out.push_str(&format!("{symbol}: {count} ({frequency:.4})\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letter_table_counts_ignore_case_and_non_letters() {
        let table = letter_frequency_table("Hello, World!");
        // "HELLOWORLD": H1 E1 L3 O2 W1 R1 D1 -> 10 letters total.
        let count = |c: char| table[(c as u8 - b'A') as usize].1;
        assert_eq!(count('L'), 3);
        assert_eq!(count('O'), 2);
        assert_eq!(count('H'), 1);
        assert_eq!(count('Z'), 0);
        assert_eq!(table.len(), ALPHABET_SIZE as usize);
    }

    #[test]
    fn letter_frequencies_sum_to_one() {
        let table = letter_frequency_table("ABBCCC");
        let total: f64 = table.iter().map(|&(_, _, f)| f).sum();
        assert!((total - 1.0).abs() < 1e-12);
        // C is 3 of 6.
        let c = table[('C' as u8 - b'A') as usize];
        assert_eq!(c.1, 3);
        assert!((c.2 - 0.5).abs() < 1e-12);
    }

    #[test]
    fn letter_table_empty_message_is_all_zero() {
        let table = letter_frequency_table("12345 !?");
        assert!(table.iter().all(|&(_, count, freq)| count == 0 && freq == 0.0));
    }

    #[test]
    fn digraphs_are_overlapping() {
        // "THE" -> TH, HE.
        let counts = digraph_counts("THE");
        assert_eq!(counts.get("TH"), Some(&1));
        assert_eq!(counts.get("HE"), Some(&1));
        assert_eq!(counts.len(), 2);
    }

    #[test]
    fn digraphs_cross_word_boundaries_after_normalizing() {
        // "To be" -> TOBE -> TO, OB, BE.
        let counts = digraph_counts("To be.");
        assert_eq!(counts.get("TO"), Some(&1));
        assert_eq!(counts.get("OB"), Some(&1));
        assert_eq!(counts.get("BE"), Some(&1));
        assert_eq!(counts.len(), 3);
    }

    #[test]
    fn repeated_digraphs_are_tallied() {
        // "AAAA" -> AA, AA, AA.
        let counts = digraph_counts("AAAA");
        assert_eq!(counts.get("AA"), Some(&3));
    }

    #[test]
    fn digraph_table_sorted_by_descending_count_then_alpha() {
        // MISSISSIPPI -> MI IS SS SI IS SS SI IP PP PI
        // IS:2, SS:2, SI:2, then IP MI PI PP each 1.
        let table = digraph_frequency_table("MISSISSIPPI");
        let order: Vec<&str> = table.iter().map(|(d, _, _)| d.as_str()).collect();
        assert_eq!(order, ["IS", "SI", "SS", "IP", "MI", "PI", "PP"]);
        assert_eq!(table[0], ("IS".to_string(), 2, 2.0 / 10.0));
    }

    #[test]
    fn digraph_frequencies_sum_to_one() {
        let table = digraph_frequency_table("MISSISSIPPI");
        let total: f64 = table.iter().map(|&(_, _, f)| f).sum();
        assert!((total - 1.0).abs() < 1e-12);
    }

    #[test]
    fn short_messages_have_no_digraphs() {
        assert!(digraph_frequency_table("A").is_empty());
        assert!(digraph_frequency_table("").is_empty());
    }

    #[test]
    fn format_table_renders_rows() {
        let rows = vec![('E', 3u64, 0.5f64), ('T', 1, 0.25)];
        assert_eq!(format_table(&rows), "E: 3 (0.5000)\nT: 1 (0.2500)\n");
    }
}
