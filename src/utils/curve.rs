use algebra_core::{ProjectiveCurve, PrimeField, FpParameters, BigInteger, ToBytes};
use rug::Integer;
use super::{bytes_to_integer, bits_big_endian_to_bytes_big_endian};
use rand::Rng;
use std::fmt::Display;

pub trait Field
where Self: Clone + Sized {
    fn size_in_bits() -> usize;

    fn to_bits(&self) -> Vec<bool>;
    fn from_bits(bits: &[bool]) -> Self;
    fn add(&self, other: &Self) -> Self;
    fn sub(&self, other: &Self) -> Self;
    fn neg(&self) -> Self;
    fn mul(&self, other: &Self) -> Self;
    fn inverse(&self) -> Option<Self>;
    fn rand<R: Rng>(rng: &mut R) -> Self;

}

impl <F: PrimeField> Field for F {
    fn size_in_bits() -> usize {
        F::size_in_bits()
    }
    fn to_bits(&self) -> Vec<bool> {
        self.into_repr().to_bits()
    }
    fn from_bits(bits: &[bool]) -> Self {
        F::from(F::BigInt::from_bits(bits))
    }
    fn add(&self, other: &Self) -> Self {
        F::add(*self, *other)
    }
    fn sub(&self, other: &Self) -> Self {
        F::sub(*self, *other)
    }
    fn neg(&self) -> Self {
        F::neg(*self)
    }
    fn mul(&self, other: &Self) -> Self {
        F::mul(*self, *other)
    }
    fn inverse(&self) -> Option<Self> {
        F::inverse(self)
    }
    fn rand<R: Rng>(rng: &mut R) -> Self {
        F::rand(rng)
    }
}
pub trait CurvePointProjective
where Self: Clone + PartialEq {
    type ScalarField: Field + Display;

    fn modulus() -> Integer;
    fn mul(&self, s: &Self::ScalarField) -> Self;
    fn add(&self, other: &Self) -> Self;

    fn to_affine_bytes(&self) -> Vec<u8>;
    fn rand<R: Rng>(rng: &mut R) -> Self;
}

impl<P: ProjectiveCurve> CurvePointProjective for P {
    type ScalarField = P::ScalarField;

    fn modulus() -> Integer {
        let repr = <P::ScalarField as PrimeField>::Params::MODULUS;
        let bits = repr.to_bits();
        let bytes = bits_big_endian_to_bytes_big_endian(&bits);
        bytes_to_integer(&bytes)
    }

    fn mul(&self, s: &Self::ScalarField) -> Self {
       P::mul(*self, *s)
    }

    fn add(&self, other: &Self) -> Self {
        P::add(*self, *other)
    }

    fn to_affine_bytes(&self) -> Vec<u8> {
        //TODO(kobi): make this safer and just better serialization
        let affine = self.into_affine();
        let mut bytes = vec![];
        affine.write(&mut bytes).unwrap();
        bytes
    }

    fn rand<R: Rng>(rng: &mut R) -> Self {
        P::rand(rng)
    }
}