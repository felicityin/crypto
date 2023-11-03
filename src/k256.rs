use ark_ff::fields::Field;
use ark_ff::{BigInteger, PrimeField};
use ark_secp256k1::Fq as FieldElement;
use core::ops::{Add, Mul, Neg};

#[derive(Default, Clone)]
pub struct Point {
    pub x: FieldElement,
    pub y: FieldElement,
}

impl Point {
    pub fn infinite() -> Self {
        Self {
            x: FieldElement::from(0u64),
            y: FieldElement::from(0u64),
        }
    }

    pub fn negate(&self) -> Point {
        Point {
            x: self.x,
            y: -self.y,
        }
    }

    pub fn add(&self, other: &Point) -> Point {
        if self == &Point::infinite() {
            return other.to_owned();
        }

        if other == &Point::infinite() {
            return self.to_owned();
        }

        // p1 + (-p1) = 0
        if self.x == other.x && self.y != other.y {
            return Point::infinite();
        }

        let k = if self == other {
            // 3 * x1 * x1 / (2 * y1)
            FieldElement::from(3u64) * self.x.square() / (FieldElement::from(2u64) * other.y)
        } else {
            // (y1 - y2) / (x1 - x2)
            (self.y - other.y) / (self.x - other.x)
        };

        // x3 = k * k - x1 - x2
        let x = k.square() - self.x - other.x;

        // y3 = k * (x1 - x3) - y1
        let y = k * (self.x - x) - self.y;

        Point { x, y }
    }

    pub fn multiply(&self, k: FieldElement) -> Point {
        let mut result = Point::default();
        let mut added = self.to_owned();
        let k = k.into_bigint();

        for i in 0..256 {
            if k.get_bit(i) {
                // Add
                result = result + &added;
            }
            // Double
            added = added.clone() + &added;
        }

        result
    }
}

impl PartialEq for Point {
    fn eq(&self, other: &Point) -> bool {
        self.x == other.x && self.y == other.y
    }
}

impl Add<&Point> for Point {
    type Output = Point;

    fn add(self, other: &Point) -> Point {
        Point::add(&self, other)
    }
}

impl Mul<FieldElement> for Point {
    type Output = Point;

    fn mul(self, other: FieldElement) -> Point {
        Point::multiply(&self, other)
    }
}

impl Neg for &Point {
    type Output = Point;

    fn neg(self) -> Point {
        self.negate()
    }
}

pub fn pow(v: FieldElement, k: FieldElement) -> FieldElement {
    let mut result = FieldElement::ONE;
    let mut muled = v;
    let k = k.into_bigint();

    for i in 0..256 {
        if k.get_bit(i) {
            // Mul
            result *= &muled;
        }
        // Square
        muled = muled * muled;
    }

    result
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn point_math() {
        let p1 = Point {
            x: FieldElement::from_str(
                "36034668029310999675425029227919426304128362788024891102120850317866231552679",
            )
            .unwrap(),
            y: FieldElement::from_str(
                "81120990977494636963407451456021843404486499021598452981689548730055179196713",
            )
            .unwrap(),
        };

        let p2 = Point {
            x: FieldElement::from_str(
                "17178020516540951919986460933710490672232047574774824837208169858689311129064",
            )
            .unwrap(),
            y: FieldElement::from_str(
                "71957217096292920627957410906773462576199313707110833846387209016083557649656",
            )
            .unwrap(),
        };

        let p3 = -&p1;
        assert_eq!(
            p3.x,
            FieldElement::from_str(
                "36034668029310999675425029227919426304128362788024891102120850317866231552679"
            )
            .unwrap()
        );
        assert_eq!(
            p3.y,
            FieldElement::from_str(
                "34671098259821558460163533552666064448783485644042111057768035277853655474950"
            )
            .unwrap()
        );

        let p4 = p1.clone() + &p2;
        assert_eq!(
            p4.x,
            FieldElement::from_str(
                "12850441572289222826268148243729979017890630118624241839987625101740938348466"
            )
            .unwrap()
        );
        assert_eq!(
            p4.y,
            FieldElement::from_str(
                "22998669537191510336934301146704402979589226976016852634025302622651985952471"
            )
            .unwrap()
        );

        let p5 = p1.mul(
            FieldElement::from_str(
                "112722522736802425171074620119739342837016662713926899217486478633056306669418",
            )
            .unwrap(),
        );
        assert_eq!(
            p5.x,
            FieldElement::from_str(
                "73707384766949889764105736370123844781212106662496289319891395883448143582247"
            )
            .unwrap()
        );
        assert_eq!(
            p5.y,
            FieldElement::from_str(
                "95271305537511489348684992965407999959735620294149413580098632976294826784577"
            )
            .unwrap()
        );
    }

    #[test]
    fn field_math() {
        let r = pow(
            FieldElement::from_str(
                "37495995483093812530829120344068921073950778374277050857635845226183990889532",
            )
            .unwrap(),
            FieldElement::from_str(
                "36273884976317350876892933450181613438664462160902682135941368945682163872771",
            )
            .unwrap(),
        );
        assert_eq!(
            r,
            FieldElement::from_str(
                "2791087902176469651285404386547319620812200712893544393938950383463540502195"
            )
            .unwrap()
        );
    }
}
