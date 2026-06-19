//! Modular-arithmetic primitives (gcd, extended gcd, modular inverse, modular
//! exponentiation) used throughout the book, especially in Chapters 1 and 4.

/// Greatest common divisor of two integers (always non-negative).
pub fn gcd(a: i64, b: i64) -> i64 {
    let (mut a, mut b) = (a.abs(), b.abs());
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}

/// Extended Euclidean algorithm.
///
/// Returns `(g, x, y)` such that `a * x + b * y == g == gcd(a, b)`.
pub fn extended_gcd(a: i64, b: i64) -> (i64, i64, i64) {
    if b == 0 {
        (a.abs(), if a < 0 { -1 } else { 1 }, 0)
    } else {
        let (g, x, y) = extended_gcd(b, a % b);
        (g, y, x - (a / b) * y)
    }
}

/// Reduce `a` into the canonical range `0..m` (handles negative inputs).
pub fn modulo(a: i64, m: i64) -> i64 {
    ((a % m) + m) % m
}

/// Multiplicative inverse of `a` modulo `m`, if it exists.
///
/// Returns `Some(x)` with `0 <= x < m` and `a * x % m == 1`, or `None` when
/// `gcd(a, m) != 1`.
pub fn mod_inverse(a: i64, m: i64) -> Option<i64> {
    let (g, x, _) = extended_gcd(modulo(a, m), m);
    if g != 1 {
        None
    } else {
        Some(modulo(x, m))
    }
}

/// Compute `base^exp mod m` using fast (square-and-multiply) exponentiation.
pub fn mod_pow(base: i64, exp: u64, m: i64) -> i64 {
    if m == 1 {
        return 0;
    }
    let mut result = 1i128;
    let mut base = modulo(base, m) as i128;
    let m = m as i128;
    let mut exp = exp;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % m;
        }
        exp >>= 1;
        base = (base * base) % m;
    }
    result as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcd_basic() {
        assert_eq!(gcd(48, 18), 6);
        assert_eq!(gcd(17, 5), 1);
        assert_eq!(gcd(-48, 18), 6);
        assert_eq!(gcd(0, 9), 9);
    }

    #[test]
    fn extended_gcd_identity() {
        let (g, x, y) = extended_gcd(240, 46);
        assert_eq!(g, 2);
        assert_eq!(240 * x + 46 * y, g);
    }

    #[test]
    fn modulo_normalizes_negatives() {
        assert_eq!(modulo(-3, 26), 23);
        assert_eq!(modulo(29, 26), 3);
    }

    #[test]
    fn mod_inverse_exists_and_missing() {
        // 7 is invertible mod 26 (gcd(7, 26) == 1); inverse is 15.
        assert_eq!(mod_inverse(7, 26), Some(15));
        assert_eq!((7 * 15) % 26, 1);
        // 13 shares a factor with 26, so no inverse.
        assert_eq!(mod_inverse(13, 26), None);
    }

    #[test]
    fn mod_pow_matches_naive() {
        assert_eq!(mod_pow(7, 256, 13), 9);
        assert_eq!(mod_pow(2, 10, 1000), 24);
        assert_eq!(mod_pow(5, 0, 7), 1);
    }
}
