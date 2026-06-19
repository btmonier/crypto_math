//! Letter-frequency analysis helpers, the workhorse of the cryptanalysis
//! exercises in Chapters 1 and 2.

use crate::alphabet::{letter_to_index, ALPHABET_SIZE};

/// Count occurrences of each letter A..Z in `text`, ignoring non-letters.
///
/// The returned array is indexed 0 (`A`) through 25 (`Z`).
pub fn letter_counts(text: &str) -> [u64; ALPHABET_SIZE as usize] {
    let mut counts = [0u64; ALPHABET_SIZE as usize];
    for c in text.chars() {
        if let Some(i) = letter_to_index(c) {
            counts[i as usize] += 1;
        }
    }
    counts
}

/// Relative frequency (proportion) of each letter A..Z in `text`.
///
/// Each entry is in `0.0..=1.0`; the array sums to 1.0 when at least one letter
/// is present, and is all zeros otherwise.
pub fn letter_frequencies(text: &str) -> [f64; ALPHABET_SIZE as usize] {
    let counts = letter_counts(text);
    let total: u64 = counts.iter().sum();
    let mut freqs = [0.0f64; ALPHABET_SIZE as usize];
    if total > 0 {
        for (i, &c) in counts.iter().enumerate() {
            freqs[i] = c as f64 / total as f64;
        }
    }
    freqs
}

/// Index of coincidence: the probability that two letters drawn at random from
/// `text` are equal. English plaintext sits near 0.0667; uniformly random text
/// near 0.0385. A key statistic for the Chapter 2 exercises.
pub fn index_of_coincidence(text: &str) -> f64 {
    let counts = letter_counts(text);
    let n: u64 = counts.iter().sum();
    if n < 2 {
        return 0.0;
    }
    let numerator: u64 = counts.iter().map(|&c| c * c.saturating_sub(1)).sum();
    numerator as f64 / (n * (n - 1)) as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_ignore_non_letters_and_case() {
        let counts = letter_counts("aAbB!1");
        assert_eq!(counts[0], 2); // A/a
        assert_eq!(counts[1], 2); // B/b
        assert_eq!(counts[2], 0);
    }

    #[test]
    fn frequencies_sum_to_one() {
        let freqs = letter_frequencies("ABBCCC");
        let total: f64 = freqs.iter().sum();
        assert!((total - 1.0).abs() < 1e-12);
        assert!((freqs[2] - 0.5).abs() < 1e-12); // C is 3 of 6
    }

    #[test]
    fn frequencies_empty_is_zero() {
        let freqs = letter_frequencies("12345");
        assert_eq!(freqs.iter().sum::<f64>(), 0.0);
    }

    #[test]
    fn ioc_all_same_letter_is_one() {
        assert!((index_of_coincidence("AAAA") - 1.0).abs() < 1e-12);
    }

    #[test]
    fn ioc_too_short_is_zero() {
        assert_eq!(index_of_coincidence("A"), 0.0);
    }
}
