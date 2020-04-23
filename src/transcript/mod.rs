use crate::{
    utils::{
        bigint_to_bytes, curve::CurvePointProjective, integer_to_bytes, ConvertibleUnknownOrderGroup,
    },
    protocols::root::transcript::TranscriptProtocolRoot,
};
use merlin::Transcript;
use rug::integer::Order;
use rug::Integer;

pub mod hash_to_prime;
pub mod membership;
pub mod modeq;
pub mod nonmembership;

pub use hash_to_prime::TranscriptProtocolHashToPrime;
pub use membership::TranscriptProtocolMembership;
pub use modeq::TranscriptProtocolModEq;

quick_error! {
    #[derive(Debug)]
    pub enum TranscriptChannelError {
        Incomplete {}
    }
}

pub trait TranscriptProtocolMembershipPrime<
    G: ConvertibleUnknownOrderGroup,
    P: CurvePointProjective,
>:
    TranscriptProtocolRoot<G> + TranscriptProtocolModEq<G, P> + TranscriptProtocolHashToPrime<P>
{
}

pub trait TranscriptProtocolChallenge {
    fn challenge_scalar(&mut self, label: &'static [u8], length_in_bits: u16) -> Integer;
}

pub trait TranscriptProtocolInteger<G: ConvertibleUnknownOrderGroup> {
    fn append_integer_scalar(&mut self, label: &'static [u8], scalar: &Integer);
    fn append_integer_point(&mut self, label: &'static [u8], point: &G::Elem);
}

pub trait TranscriptProtocolCurve<P: CurvePointProjective> {
    fn append_curve_scalar(&mut self, label: &'static [u8], scalar: &P::ScalarField);
    fn append_curve_point(&mut self, label: &'static [u8], point: &P);
}

impl<G: ConvertibleUnknownOrderGroup> TranscriptProtocolInteger<G> for Transcript {
    fn append_integer_scalar(&mut self, label: &'static [u8], scalar: &Integer) {
        self.append_message(label, &integer_to_bytes(scalar));
    }

    fn append_integer_point(&mut self, label: &'static [u8], point: &G::Elem) {
        self.append_message(label, &G::elem_to_bytes(point));
    }
}

impl<P: CurvePointProjective> TranscriptProtocolCurve<P> for Transcript {
    fn append_curve_scalar(&mut self, label: &'static [u8], scalar: &P::ScalarField) {
        self.append_message(label, &bigint_to_bytes::<P>(&scalar));
    }

    fn append_curve_point(&mut self, label: &'static [u8], point: &P) {
        let bytes = point.to_affine_bytes();
        self.append_message(label, &bytes);
    }
}

impl TranscriptProtocolChallenge for Transcript {
    fn challenge_scalar(&mut self, label: &'static [u8], length_in_bits: u16) -> Integer {
        let mut buf = vec![0u8; (length_in_bits / 8) as usize];
        self.challenge_bytes(label, &mut buf);
        Integer::from_digits(&buf[..], Order::MsfBe)
    }
}
