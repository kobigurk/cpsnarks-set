use rug::Integer;
use rug::rand::MutRandState;
use rug::integer::Order;
use accumulator::group::{ElemTo, ElemFrom, UnknownOrderGroup};

pub mod curve;
use curve::{CurvePointProjective, Field};

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

pub fn integer_to_bigint<P: CurvePointProjective>(num: &Integer)
                         -> P::ScalarField {
    let bytes = integer_to_bytes(num);
    let bits = bytes_big_endian_to_bits_big_endian(&bytes);
    P::ScalarField::from_bits(&bits)
}

pub fn integer_mod_q<P: CurvePointProjective>(num: &Integer) -> Result<Integer, Integer> {
    let q = P::ScalarField::modulus();
    num.clone().pow_mod(&Integer::from(1), &q)
}

pub fn integer_to_bigint_mod_q<P: CurvePointProjective>(num: &Integer)
                                             -> Result<P::ScalarField, Integer> {
    let bytes = integer_to_bytes(&integer_mod_q::<P>(num)?);
    let bits = bytes_big_endian_to_bits_big_endian(&bytes);
    Ok(P::ScalarField::from_bits(&bits))
}

pub fn bigint_to_bytes<P: CurvePointProjective>(num: &P::ScalarField) -> Vec<u8> {
    let bits = num.to_bits();
    let bytes = bits_big_endian_to_bytes_big_endian(&bits);
    bytes
}

pub fn bytes_to_integer(bytes: &[u8]) ->  Integer {
    let mut big = Integer::from(0);
    big.assign_digits(bytes, Order::MsfBe);
    big
}

pub fn bigint_to_integer<P: CurvePointProjective>(num: &P::ScalarField)
                                             ->  Integer {
    let bytes = bigint_to_bytes::<P>(num);
    let mut big = Integer::from(0);
    big.assign_digits(&bytes, Order::MsfBe);
    big
}

#[cfg(all(test, feature="zexe"))]
mod test {
    use crate::utils::{integer_to_bigint, bigint_to_integer};
    use rug::Integer;
    use algebra::bls12_381::G1Projective;

    #[test]
    fn test_back_and_forth() {
        let int = Integer::from(2493823);
        let big = integer_to_bigint::<G1Projective>(&int);
        let int2 = bigint_to_integer::<G1Projective>(&big);
        assert_eq!(int, int2);
    }

}
