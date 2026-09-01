//! Exercise 3.1 - Playfair's Method.
//!
//! > Write a computer program to implement Playfair's Method. The program
//! > should be capable of both enciphering and deciphering messages using
//! > this system.
//!
//! Playfair is a *digraphic* substitution cipher: letters are enciphered in
//! pairs using a 5×5 keyword square rather than one-at-a-time. The English
//! alphabet has 26 letters and the square has only 25 cells, so `I` and `J`
//! share a cell (`J` is treated as `I` throughout).
//!
//! The square is filled left-to-right, top-to-bottom by writing the keyword
//! (duplicate letters dropped after their first appearance) and then the
//! remaining letters of the alphabet in their usual order, omitting `J`.
//!
//! Before pairing, the plaintext is normalized (non-letters stripped, case
//! discarded, `J` folded to `I`). A pair of identical letters is split by
//! inserting a filler (`X`, or `Q` if the repeated letter is itself `X`). An
//! odd-length message is padded with the same filler. Each pair is then
//! replaced by the geometric rule that matches its position in the square:
//!
//! - **Same row** – each letter moves one cell right (encipher) or left
//!   (decipher), wrapping at the edges.
//! - **Same column** – each letter moves one cell down (encipher) or up
//!   (decipher), wrapping at the edges.
//! - **Rectangle** – each letter is replaced by the letter in its own row
//!   but in the other letter's column (the opposite corners of the rectangle).
//!
//! Decipherment inverts the row/column shifts and applies the same rectangle
//! rule. Filler letters are left in the recovered text; they are not uniquely
//! removable without knowing the original wording.

use crypto_core::alphabet::{letter_to_index, normalize};

/// Side length of the Playfair keyword square.
const GRID: usize = 5;

/// Default null inserted between a doubled letter or at the end of an
/// odd-length message.
const FILLER: char = 'X';

/// Alternate null used when the letter being split or padded is itself [`FILLER`].
const ALT_FILLER: char = 'Q';

/// 5×5 Playfair square together with a letter-to-position lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Square {
    /// Letters of the square, row-major.
    grid: [[char; GRID]; GRID],
    /// Row/column of each letter `A..Z`. `J` shares `I`'s coordinates.
    pos: [(usize, usize); 26],
}

impl Square {
    /// Build the keyword square determined by `keyword`.
    ///
    /// Non-letters are ignored and `J` is folded to `I`. An empty (or
    /// non-alphabetic) keyword produces the alphabet in order, minus `J`.
    pub fn from_keyword(keyword: &str) -> Self {
        let mut seen = [false; 26];
        let mut letters = Vec::with_capacity(GRID * GRID);

        let mut push = |c: char| {
            let folded = fold_j(c);
            let slot = letter_index(folded);
            if !seen[slot] {
                seen[slot] = true;
                letters.push(folded);
            }
        };

        for c in normalize(keyword).chars() {
            push(c);
        }
        for c in 'A'..='Z' {
            if c != 'J' {
                push(c);
            }
        }

        debug_assert_eq!(letters.len(), GRID * GRID);

        let mut grid = [['?'; GRID]; GRID];
        let mut pos = [(0usize, 0usize); 26];
        for (k, &letter) in letters.iter().enumerate() {
            let row = k / GRID;
            let col = k % GRID;
            grid[row][col] = letter;
            pos[letter_index(letter)] = (row, col);
        }
        // `J` occupies the same cell as `I`.
        pos[letter_index('J')] = pos[letter_index('I')];

        Self { grid, pos }
    }

    /// The 5×5 letter grid.
    pub fn grid(&self) -> [[char; GRID]; GRID] {
        self.grid
    }

    fn locate(&self, letter: char) -> (usize, usize) {
        self.pos[letter_index(fold_j(letter))]
    }

    fn at(&self, row: usize, col: usize) -> char {
        self.grid[row][col]
    }

    /// Encipher or decipher one digraph.
    ///
    /// `row_delta` / `col_delta` are the wrap-around shifts applied when the
    /// two letters share a column or a row. The rectangle rule is independent
    /// of the deltas.
    fn transform_pair(&self, a: char, b: char, row_delta: isize, col_delta: isize) -> [char; 2] {
        let (r1, c1) = self.locate(a);
        let (r2, c2) = self.locate(b);
        if r1 == r2 {
            [self.at(r1, wrap(c1, col_delta)), self.at(r2, wrap(c2, col_delta))]
        } else if c1 == c2 {
            [self.at(wrap(r1, row_delta), c1), self.at(wrap(r2, row_delta), c2)]
        } else {
            [self.at(r1, c2), self.at(r2, c1)]
        }
    }
}

/// Build the 5×5 Playfair square determined by `keyword`.
pub fn key_square(keyword: &str) -> [[char; GRID]; GRID] {
    Square::from_keyword(keyword).grid()
}

/// Encipher `plaintext` with Playfair's Method keyed by `keyword`.
///
/// Non-alphabetic characters are dropped and letters are treated
/// case-insensitively; the output is uppercase. `J` is identified with `I`.
pub fn encipher(plaintext: &str, keyword: &str) -> String {
    let square = Square::from_keyword(keyword);
    prepare_digraphs(plaintext)
        .into_iter()
        .flat_map(|[a, b]| square.transform_pair(a, b, 1, 1))
        .collect()
}

/// Decipher `ciphertext` that was produced by [`encipher`] with the same
/// `keyword`.
///
/// The recovered text still contains any filler letters that were inserted
/// during encipherment. An odd-length ciphertext (which a correctly produced
/// Playfair message never has) is padded with [`FILLER`] so the last letter
/// can still be processed as a pair.
pub fn decipher(ciphertext: &str, keyword: &str) -> String {
    let square = Square::from_keyword(keyword);
    let mut letters: Vec<char> = normalize(ciphertext).chars().map(fold_j).collect();
    if letters.len() % 2 == 1 {
        letters.push(FILLER);
    }
    letters
        .chunks_exact(2)
        .flat_map(|pair| square.transform_pair(pair[0], pair[1], -1, -1))
        .collect()
}

/// Normalize `text` and split it into Playfair digraphs, inserting fillers
/// between doubled letters and padding an odd-length remainder.
pub fn prepare_digraphs(text: &str) -> Vec<[char; 2]> {
    let letters: Vec<char> = normalize(text).chars().map(fold_j).collect();
    let mut pairs = Vec::new();
    let mut i = 0;
    while i < letters.len() {
        let first = letters[i];
        if i + 1 == letters.len() {
            pairs.push([first, filler_for(first)]);
            break;
        }
        let second = letters[i + 1];
        if first == second {
            pairs.push([first, filler_for(first)]);
            i += 1;
        } else {
            pairs.push([first, second]);
            i += 2;
        }
    }
    pairs
}

fn fold_j(c: char) -> char {
    if c == 'J' {
        'I'
    } else {
        c
    }
}

fn filler_for(letter: char) -> char {
    if letter == FILLER {
        ALT_FILLER
    } else {
        FILLER
    }
}

fn letter_index(c: char) -> usize {
    letter_to_index(c).expect("Playfair letters are ASCII alphabetic") as usize
}

fn wrap(index: usize, delta: isize) -> usize {
    (index as isize + delta).rem_euclid(GRID as isize) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flatten(grid: [[char; GRID]; GRID]) -> String {
        grid.into_iter().flatten().collect()
    }

    #[test]
    fn square_from_monarchy() {
        assert_eq!(
            flatten(key_square("MONARCHY")),
            "MONARCHYBDEFGIKLPQSTUVWXZ"
        );
    }

    #[test]
    fn square_from_playfair_example() {
        // Classic worked example: keyword "playfair example".
        assert_eq!(
            flatten(key_square("playfair example")),
            "PLAYFIREXMBCDGHKNOQSTUVWZ"
        );
    }

    #[test]
    fn square_drops_duplicate_letters_and_folds_j() {
        // J is I, so "JULIUS" contributes I only once.
        assert_eq!(flatten(key_square("JULIUS")), flatten(key_square("ULIS")));
        assert_eq!(key_square("kryptos"), key_square("KRYPTOS"));
        assert_eq!(key_square("Zebra-Skin"), key_square("ZEBRASKIN"));
    }

    #[test]
    fn empty_keyword_is_the_alphabet_without_j() {
        assert_eq!(
            flatten(key_square("")),
            "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        );
    }

    #[test]
    fn prepare_digraphs_inserts_filler_and_pads() {
        assert_eq!(prepare_digraphs("HELLO"), vec![['H', 'E'], ['L', 'X'], ['L', 'O']]);
        assert_eq!(prepare_digraphs("X"), vec![['X', 'Q']]);
        assert_eq!(prepare_digraphs("XX"), vec![['X', 'Q'], ['X', 'Q']]);
        assert_eq!(
            prepare_digraphs("Hide the gold!"),
            vec![['H', 'I'], ['D', 'E'], ['T', 'H'], ['E', 'G'], ['O', 'L'], ['D', 'X']]
        );
    }

    #[test]
    fn prepare_digraphs_folds_j_to_i() {
        assert_eq!(prepare_digraphs("JUST"), vec![['I', 'U'], ['S', 'T']]);
    }

    #[test]
    fn wikipedia_hide_the_gold() {
        // "Hide the gold in the tree stump" with keyword "playfair example".
        // TREE contributes a doubled E, which is split by an X.
        assert_eq!(
            encipher("Hide the gold in the tree stump", "playfair example"),
            "BMODZBXDNABEKUDMUIXMMOUVIF"
        );
        assert_eq!(
            decipher("BMODZBXDNABEKUDMUIXMMOUVIF", "playfair example"),
            "HIDETHEGOLDINTHETREXESTUMP"
        );
    }

    #[test]
    fn instruments_with_monarchy() {
        // INSTRUMENTS is 11 letters, so it is padded with X.
        // IN ST RU ME NT SX -> GA TL MZ CL RQ XA
        assert_eq!(encipher("INSTRUMENTS", "MONARCHY"), "GATLMZCLRQXA");
        assert_eq!(decipher("GATLMZCLRQXA", "MONARCHY"), "INSTRUMENTSX");
    }

    #[test]
    fn decipher_inverts_encipher_for_sample_keywords() {
        let plaintext = "THEQUICKBROWNFOX";
        for keyword in ["MONARCHY", "PLAYFAIR", "CRYPTOLOGY", "JULIUS"] {
            let cipher = encipher(plaintext, keyword);
            assert_eq!(
                decipher(&cipher, keyword),
                plaintext,
                "keyword = {keyword}"
            );
        }
    }

    #[test]
    fn doubled_letters_roundtrip_with_filler() {
        let cipher = encipher("HELLO", "MONARCHY");
        assert_eq!(decipher(&cipher, "MONARCHY"), "HELXLO");
    }

    #[test]
    fn empty_message_is_empty() {
        assert_eq!(encipher("", "KEY"), "");
        assert_eq!(decipher("", "KEY"), "");
        assert!(prepare_digraphs("...").is_empty());
    }
}
