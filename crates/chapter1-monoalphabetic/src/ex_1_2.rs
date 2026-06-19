//! Exercise 1.2 - Greatest common divisor.
//!
//! > Write a computer program to compute the greatest common divisor of two
//! > integers. (If you really want to have fun, write two versions of this
//! > program, one recursive and the other iterative.)
//!
//! Both versions implement the Euclidean algorithm and return a non-negative
//! result, so negative inputs (and `gcd(0, 0) == 0`) behave sensibly.

/// Greatest common divisor computed iteratively via the Euclidean algorithm.
pub fn gcd_iterative(a: i64, b: i64) -> i64 {
    let (mut a, mut b) = (a.abs(), b.abs());
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}

/// Greatest common divisor computed recursively via the Euclidean algorithm.
pub fn gcd_recursive(a: i64, b: i64) -> i64 {
    if b == 0 {
        a.abs()
    } else {
        gcd_recursive(b, a % b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_versions_agree_on_examples() {
        let cases = [
            ((48, 18), 6),
            ((17, 5), 1),
            ((0, 9), 9),
            ((9, 0), 9),
            ((0, 0), 0),
            ((1071, 462), 21),
        ];
        for ((a, b), expected) in cases {
            assert_eq!(gcd_iterative(a, b), expected);
            assert_eq!(gcd_recursive(a, b), expected);
        }
    }

    #[test]
    fn handles_negative_inputs() {
        assert_eq!(gcd_iterative(-48, 18), 6);
        assert_eq!(gcd_recursive(-48, 18), 6);
        assert_eq!(gcd_iterative(-48, -18), 6);
        assert_eq!(gcd_recursive(-48, -18), 6);
    }

    #[test]
    fn iterative_and_recursive_match_over_range() {
        for a in -50..=50 {
            for b in -50..=50 {
                assert_eq!(gcd_iterative(a, b), gcd_recursive(a, b));
            }
        }
    }
}
