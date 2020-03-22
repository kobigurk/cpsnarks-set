use rug::Integer;
use rand::{RngCore, CryptoRng};

pub trait Field
where Self: Clone + Sized {
    fn modulus() -> Integer;
    fn size_in_bits() -> usize;
    fn to_bits(&self) -> Vec<bool>;
    fn from_bits(bits: &[bool]) -> Self;
    fn add(&self, other: &Self) -> Self;
    fn sub(&self, other: &Self) -> Self;
    fn neg(&self) -> Self;
    fn mul(&self, other: &Self) -> Self;
    fn inverse(&self) -> Option<Self>;
    fn rand<R: RngCore + CryptoRng>(rng: &mut R) -> Self;
}

pub trait CurvePointProjective
where Self: Clone + PartialEq {
    type ScalarField: Field;

    fn mul(&self, s: &Self::ScalarField) -> Self;
    fn add(&self, other: &Self) -> Self;

    fn to_affine_bytes(&self) -> Vec<u8>;
    fn rand<R: RngCore + CryptoRng>(rng: &mut R) -> Self;
}

#[cfg(feature = "zexe")]
mod zexe {
    use algebra_core::{ProjectiveCurve, PrimeField, FpParameters, BigInteger, ToBytes};
    use crate::utils::{bytes_to_integer, bits_big_endian_to_bytes_big_endian};
    use super::{Field, CurvePointProjective};
    use rug::Integer;
    use rand::{RngCore, CryptoRng};

    impl <F: PrimeField> Field for F {
        fn modulus() -> Integer {
            let repr = F::Params::MODULUS;
            let bits = repr.to_bits();
            let bytes = bits_big_endian_to_bytes_big_endian(&bits);
            bytes_to_integer(&bytes)
        }
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
        fn rand<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
            F::rand(rng)
        }
    }

    impl<P: ProjectiveCurve> CurvePointProjective for P {
        type ScalarField = P::ScalarField;

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

        fn rand<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
            P::rand(rng)
        }
    }
}

#[cfg(feature = "dalek")]
mod dalek {
    use curve25519_dalek::{
        scalar::Scalar,
        ristretto::RistrettoPoint,
        constants::BASEPOINT_ORDER,
    };
    use crate::utils::{bits_big_endian_to_bytes_big_endian, bytes_big_endian_to_bits_big_endian, bigint_to_integer};
    use super::{Field, CurvePointProjective};
    use rug::Integer;
    use rand::{RngCore, CryptoRng};

    impl Field for Scalar {
        fn modulus() -> Integer {
            bigint_to_integer::<RistrettoPoint>(&BASEPOINT_ORDER)
        }

        fn size_in_bits() -> usize {
            255 
        }
        fn to_bits(&self) -> Vec<bool> {
            let little_endian_bytes = self.to_bytes();
            let big_endian_bytes = little_endian_bytes.iter().map(|x| *x).rev().collect::<Vec<_>>();
            bytes_big_endian_to_bits_big_endian(&big_endian_bytes)
        }
        fn from_bits(bits: &[bool]) -> Self {
            let little_endian_bits = bits.to_vec().into_iter().rev().collect::<Vec<_>>();
            let little_endian_bytes = bits_big_endian_to_bytes_big_endian(&little_endian_bits);
            let mut little_endian_fixed_bytes = [0u8; 32];
            little_endian_fixed_bytes[..].copy_from_slice(little_endian_bytes.as_ref());
            Scalar::from_bits(little_endian_fixed_bytes)
        }
        fn add(&self, other: &Self) -> Self {
            self + other
        }
        fn sub(&self, other: &Self) -> Self {
            self - other
        }
        fn neg(&self) -> Self {
            -self
        }
        fn mul(&self, other: &Self) -> Self {
            self * other
        }
        fn inverse(&self) -> Option<Self> {
            if *self == Scalar::zero() {
                None
            } else {
                Some(self.invert())
            }
        }
        fn rand<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
            Scalar::random(rng)
        }
    }

    impl CurvePointProjective for RistrettoPoint {
        type ScalarField = Scalar;

        fn mul(&self, s: &Self::ScalarField) -> Self {
            self * s
        }
        fn add(&self, other: &Self) -> Self {
            self + other
        }

        fn to_affine_bytes(&self) -> Vec<u8> {
            self.compress().to_bytes()[..].to_vec()
        }
        fn rand<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
            RistrettoPoint::random(rng)
        }

    }
}