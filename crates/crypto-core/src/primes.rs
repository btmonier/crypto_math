//! Primality testing, factoring, and Euler's totient - the number-theory
//! groundwork the book builds toward RSA in Chapter 4.

/// Trial-division primality test. Adequate for the textbook-sized numbers used
/// in the exercises.
pub fn is_prime(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    if n % 2 == 0 {
        return n == 2;
    }
    if n % 3 == 0 {
        return n == 3;
    }
    let mut i = 5u64;
    while i * i <= n {
        if n % i == 0 || n % (i + 2) == 0 {
            return false;
        }
        i += 6;
    }
    true
}

/// Prime factorization as `(prime, exponent)` pairs in ascending order.
pub fn prime_factors(mut n: u64) -> Vec<(u64, u32)> {
    let mut factors = Vec::new();
    let mut d = 2u64;
    while d * d <= n {
        if n % d == 0 {
            let mut exp = 0u32;
            while n % d == 0 {
                n /= d;
                exp += 1;
            }
            factors.push((d, exp));
        }
        d += 1;
    }
    if n > 1 {
        factors.push((n, 1));
    }
    factors
}

/// Euler's totient `phi(n)`: the count of integers in `1..=n` coprime to `n`.
pub fn euler_phi(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut result = n;
    for (p, _) in prime_factors(n) {
        result = result / p * (p - 1);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primality() {
        assert!(!is_prime(0));
        assert!(!is_prime(1));
        assert!(is_prime(2));
        assert!(is_prime(3));
        assert!(!is_prime(9));
        assert!(is_prime(97));
        assert!(!is_prime(91)); // 7 * 13
    }

    #[test]
    fn factorization() {
        assert_eq!(prime_factors(1), vec![]);
        assert_eq!(prime_factors(360), vec![(2, 3), (3, 2), (5, 1)]);
        assert_eq!(prime_factors(97), vec![(97, 1)]);
    }

    #[test]
    fn totient() {
        assert_eq!(euler_phi(1), 1);
        assert_eq!(euler_phi(9), 6);
        assert_eq!(euler_phi(10), 4);
        // For distinct primes p, q: phi(pq) = (p-1)(q-1).
        assert_eq!(euler_phi(3 * 11), 2 * 10);
    }
}
