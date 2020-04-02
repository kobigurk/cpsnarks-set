use merlin::Transcript;
use std::cell::RefCell;
use crate::{
    channels::{
        ChannelError,
        hash_to_prime::{HashToPrimeProverChannel, HashToPrimeVerifierChannel},
    },
    protocols::hash_to_prime::{CRSHashToPrime, HashToPrimeProtocol},
    utils::curve::CurvePointProjective,
};
use super::{TranscriptProtocolCurve, TranscriptProtocolChallenge, TranscriptChannelError};

pub trait TranscriptProtocolHashToPrime<P: CurvePointProjective>:
    TranscriptProtocolCurve<P> + TranscriptProtocolChallenge {
    fn hash_to_prime_domain_sep(&mut self);
}

impl<P: CurvePointProjective> TranscriptProtocolHashToPrime<P> for Transcript {
    fn hash_to_prime_domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"hash_to_prime");
    }
}

pub struct TranscriptVerifierChannel<'a, P: CurvePointProjective, RP: HashToPrimeProtocol<P>, T: TranscriptProtocolHashToPrime<P>> {
    proof: Option<RP::Proof>,
    crs_type: std::marker::PhantomData<CRSHashToPrime<P, RP>>,
    transcript_type: std::marker::PhantomData<&'a RefCell<T>>,
}

impl<'a, P: CurvePointProjective, RP: HashToPrimeProtocol<P>, T: TranscriptProtocolHashToPrime<P>> TranscriptVerifierChannel<'a, P, RP, T> {
    pub fn new(_: &CRSHashToPrime<P, RP>, _: &'a RefCell<T>) -> TranscriptVerifierChannel<'a, P, RP, T> {
        TranscriptVerifierChannel {
            proof: None,
            crs_type: std::marker::PhantomData,
            transcript_type: std::marker::PhantomData,
        }
    }

    pub fn proof(&self) -> Result<RP::Proof, TranscriptChannelError> {
        if self.proof.is_some() {
            Ok(self.proof.as_ref().unwrap().clone())
        } else {
            Err(TranscriptChannelError::Incomplete)
        }
    }
}

impl<'a, P: CurvePointProjective, RP: HashToPrimeProtocol<P>, T: TranscriptProtocolHashToPrime<P>> HashToPrimeVerifierChannel<P, RP> for TranscriptVerifierChannel<'a, P, RP, T> {
    fn send_proof(&mut self, proof: &RP::Proof) -> Result<(), ChannelError> {
        self.proof = Some(proof.clone());
        Ok(())
    }
}

pub struct TranscriptProverChannel<'a, P: CurvePointProjective, RP: HashToPrimeProtocol<P>, T: TranscriptProtocolHashToPrime<P>> {
    proof: RP::Proof,
    crs_type: std::marker::PhantomData<CRSHashToPrime<P, RP>>,
    transcript_type: std::marker::PhantomData<&'a RefCell<T>>,
}

impl<'a, P: CurvePointProjective, RP: HashToPrimeProtocol<P>, T: TranscriptProtocolHashToPrime<P>> TranscriptProverChannel<'a, P, RP, T> {
    pub fn new(_: &CRSHashToPrime<P, RP>, _: &'a RefCell<T>, proof: &RP::Proof) -> TranscriptProverChannel<'a, P, RP, T> {
        TranscriptProverChannel {
            proof: proof.clone(),
            crs_type: std::marker::PhantomData,
            transcript_type: std::marker::PhantomData,
        }
    }
}

impl<'a, P: CurvePointProjective, RP: HashToPrimeProtocol<P>, T: TranscriptProtocolHashToPrime<P>> HashToPrimeProverChannel<P, RP> for TranscriptProverChannel<'a, P, RP, T> {
    fn receive_proof(&mut self) -> Result<RP::Proof, ChannelError> {
        Ok(self.proof.clone())
    }
}
