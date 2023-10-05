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

pub fn chinese_remainder(n: Vec<i32>, a: Vec<i32>) -> (i32, i32) {
    assert_eq!(n.len(), a.len());

    let mut n_product = 1;
    for i in n.iter() {
        n_product *= *i;
    }

    let it = n.into_iter().zip(a.into_iter());
    let mut x = 0;

    for (ni, ai) in it {
        let nn = n_product / ni;
        let (_, s, _) = extended_euclidean(nn, ni);
        x += ai * s * nn;
        x %= n_product;
    }

    (x, n_product)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gcd() {
        let a = 6;
        let b = 8;
        let d = gcd(a, b);

        assert_eq!(d, 2);
        assert_eq!(a % d, 0);
        assert_eq!(b % d, 0);
    }

    #[test]
    fn test_ext_euc() {
        let a = 6;
        let b = 8;
        let (d, s, t) = extended_euclidean(a, b);

        assert_eq!(d, 2);
        assert_eq!(s, -1);
        assert_eq!(t, 1);

        assert_eq!(a % d, 0);
        assert_eq!(b % d, 0);
        assert_eq!(d, s * a + t * b);
    }

    #[test]
    fn test_chinese_remainder() {
        let n: Vec<i32> = vec![7, 3, 5, 11];
        let a: Vec<i32> = vec![4, 1, 3, 0];
        let (x, n_product) = chinese_remainder(n, a);

        assert_eq!(x, 88);
        assert_eq!(n_product, 1155);
    }
}
