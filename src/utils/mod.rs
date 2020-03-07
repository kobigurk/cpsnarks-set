use rug::Integer;
use rug::rand::MutRandState;
use algebra_core::{PrimeField, ProjectiveCurve, biginteger::BigInteger, FpParameters};
use rug::integer::Order;
use accumulator::group::{ElemTo, ElemFrom, UnknownOrderGroup};

pub trait ConvertibleUnknownOrderGroup : UnknownOrderGroup + ElemFrom<Integer> + ElemTo<Integer> {}
impl<T: UnknownOrderGroup + ElemFrom<Integer> + ElemTo<Integer>> ConvertibleUnknownOrderGroup for T {}


pub fn random_between<R: MutRandState>(rng: &mut R, min: &Integer, max: &Integer) -> Integer {
    min + Integer::from(max-min).random_below(rng)
}

pub fn random_symmetric_range<R: MutRandState>(rng: &mut R, max: &Integer) -> Integer {
    Integer::from(-max) + Integer::from(2*max).random_below(rng)
}

pub fn bytes_big_endian_to_bits_big_endian(bytes: &[u8]) -> Vec<bool> {
    let mut bits = vec![];
    for b in bytes {
        let mut p = 1 << 7;
        for _ in 0..8 {
            bits.push(b & p == p);
            p /= 2;
        }
    }
    bits
}

pub fn bits_big_endian_to_bytes_big_endian(bits: &[bool]) -> Vec<u8> {
    let byte_length = (bits.len() + 7)/8;
    let mut bytes = vec![];
    for b in 0..byte_length {
        let mut byte = 0 as u8;
        for i in 0..8 {
            byte |= (bits[8*b + i] as u8)<<(7-i);
        }
        bytes.push(byte);
    }
    bytes
}

pub fn integer_to_bytes(num: &Integer) -> Vec<u8> {
    let digits = num.significant_digits::<u8>();
    let mut bytes = vec![0u8; digits];
    num.write_digits(&mut bytes, Order::MsfBe);
    bytes
}

pub fn integer_to_bigint<P: ProjectiveCurve>(num: &Integer)
                         -> <P::ScalarField as PrimeField>::BigInt {
    let bytes = integer_to_bytes(num);
    let bits = bytes_big_endian_to_bits_big_endian(&bytes);
    <P::ScalarField as PrimeField>::BigInt::from_bits(&bits)
}

pub fn integer_mod_q<P: ProjectiveCurve>(num: &Integer) -> Result<Integer, Integer> {
    let q = bigint_to_integer::<P>(&<P::ScalarField as PrimeField>::Params::MODULUS);
    num.clone().pow_mod(&Integer::from(1), &q)
}

pub fn integer_to_bigint_mod_q<P: ProjectiveCurve>(num: &Integer)
                                             -> Result<<P::ScalarField as PrimeField>::BigInt, Integer> {
    let bytes = integer_to_bytes(&integer_mod_q::<P>(num)?);
    let bits = bytes_big_endian_to_bits_big_endian(&bytes);
    Ok(<P::ScalarField as PrimeField>::BigInt::from_bits(&bits))
}

pub fn bigint_to_bytes<P: ProjectiveCurve>(num: &<P::ScalarField as PrimeField>::BigInt) -> Vec<u8> {
    let bits = num.to_bits();
    let bytes = bits_big_endian_to_bytes_big_endian(&bits);
    bytes
}

pub fn bigint_to_integer<P: ProjectiveCurve>(num: &<P::ScalarField as PrimeField>::BigInt)
                                             ->  Integer {
    let bytes = bigint_to_bytes::<P>(num);
    let mut big = Integer::from(0);
    big.assign_digits(&bytes, Order::MsfBe);
    big
}

#[cfg(test)]
mod test {
    use crate::utils::{integer_to_bigint, bigint_to_integer};
    use rug::Integer;
    use algebra::jubjub::JubJubProjective;

    #[test]
    fn test_back_and_forth() {
        let int = Integer::from(2493823);
        let big = integer_to_bigint::<JubJubProjective>(&int);
        let int2 = bigint_to_integer::<JubJubProjective>(&big);
        assert_eq!(int, int2);
    }

}
