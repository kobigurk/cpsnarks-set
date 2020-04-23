use crate::{
    transcript::{TranscriptChannelError, TranscriptProtocolChallenge, TranscriptProtocolCurve},
    channels::ChannelError,
    protocols::hash_to_prime::{
        CRSHashToPrime, HashToPrimeProtocol,
        channel::{HashToPrimeProverChannel, HashToPrimeVerifierChannel},
    },
    utils::curve::CurvePointProjective,
};
use merlin::Transcript;
use std::cell::RefCell;

pub trait TranscriptProtocolHashToPrime<P: CurvePointProjective>:
    TranscriptProtocolCurve<P> + TranscriptProtocolChallenge
{
    fn hash_to_prime_domain_sep(&mut self);
}

impl<P: CurvePointProjective> TranscriptProtocolHashToPrime<P> for Transcript {
    fn hash_to_prime_domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"hash_to_prime");
    }
}

pub struct TranscriptVerifierChannel<
    'a,
    P: CurvePointProjective,
    HP: HashToPrimeProtocol<P>,
    T: TranscriptProtocolHashToPrime<P>,
> {
    proof: Option<HP::Proof>,
    crs_type: std::marker::PhantomData<CRSHashToPrime<P, HP>>,
    transcript_type: std::marker::PhantomData<&'a RefCell<T>>,
}

impl<
        'a,
        P: CurvePointProjective,
        HP: HashToPrimeProtocol<P>,
        T: TranscriptProtocolHashToPrime<P>,
    > TranscriptVerifierChannel<'a, P, HP, T>
{
    pub fn new(
        _: &CRSHashToPrime<P, HP>,
        _: &'a RefCell<T>,
    ) -> TranscriptVerifierChannel<'a, P, HP, T> {
        TranscriptVerifierChannel {
            proof: None,
            crs_type: std::marker::PhantomData,
            transcript_type: std::marker::PhantomData,
        }
    }

    pub fn proof(&self) -> Result<HP::Proof, TranscriptChannelError> {
        if self.proof.is_some() {
            Ok(self.proof.as_ref().unwrap().clone())
        } else {
            Err(TranscriptChannelError::Incomplete)
        }
    }
}

impl<
        'a,
        P: CurvePointProjective,
        HP: HashToPrimeProtocol<P>,
        T: TranscriptProtocolHashToPrime<P>,
    > HashToPrimeVerifierChannel<P, HP> for TranscriptVerifierChannel<'a, P, HP, T>
{
    fn send_proof(&mut self, proof: &HP::Proof) -> Result<(), ChannelError> {
        self.proof = Some(proof.clone());
        Ok(())
    }
}

pub struct TranscriptProverChannel<
    'a,
    P: CurvePointProjective,
    HP: HashToPrimeProtocol<P>,
    T: TranscriptProtocolHashToPrime<P>,
> {
    proof: HP::Proof,
    crs_type: std::marker::PhantomData<CRSHashToPrime<P, HP>>,
    transcript_type: std::marker::PhantomData<&'a RefCell<T>>,
}

impl<
        'a,
        P: CurvePointProjective,
        HP: HashToPrimeProtocol<P>,
        T: TranscriptProtocolHashToPrime<P>,
    > TranscriptProverChannel<'a, P, HP, T>
{
    pub fn new(
        _: &CRSHashToPrime<P, HP>,
        _: &'a RefCell<T>,
        proof: &HP::Proof,
    ) -> TranscriptProverChannel<'a, P, HP, T> {
        TranscriptProverChannel {
            proof: proof.clone(),
            crs_type: std::marker::PhantomData,
            transcript_type: std::marker::PhantomData,
        }
    }
}

impl<
        'a,
        P: CurvePointProjective,
        HP: HashToPrimeProtocol<P>,
        T: TranscriptProtocolHashToPrime<P>,
    > HashToPrimeProverChannel<P, HP> for TranscriptProverChannel<'a, P, HP, T>
{
    fn receive_proof(&mut self) -> Result<HP::Proof, ChannelError> {
        Ok(self.proof.clone())
    }
}
