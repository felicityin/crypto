pub fn gcd(a: i32, b: i32) -> i32 {
    if b == 0 {
        return a;
    }
    gcd(b, a % b)
}

pub fn extended_euclidean(a: i32, b: i32) -> (i32, i32, i32) {
    if b == 0 {
        return (a, 1, 0);
    }

    let (d, mut t, s) = extended_euclidean(b, a % b);
    t -= a / b * s;
    (d, s, t)
}

#[cfg(test)]
mod tests {
    use super::{gcd, extended_euclidean};

    #[test]
    fn test_gcd() {
        let a = 6;
        let b = 8;
        let d = gcd(a, b);
        println!("d: {}", d);

        assert_eq!(a % d, 0);
        assert_eq!(b % d, 0);
    }

    #[test]
    fn test_ext_euc() {
        let a = 6;
        let b = 8;
        let (d, s, t) = extended_euclidean(a, b);
        println!("d: {}, s: {}, t: {}", d, s, t);

        assert_eq!(a % d, 0);
        assert_eq!(b % d, 0);
        assert_eq!(d, s * a + t * b);
    }
}
