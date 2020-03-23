use merlin::Transcript;
use std::cell::RefCell;
use crate::{
    channels::{
        ChannelError,
        range::{RangeProverChannel, RangeVerifierChannel},
    },
    protocols::range::{CRSRangeProof, RangeProofProtocol},
    utils::curve::CurvePointProjective,
};
use super::{TranscriptProtocolCurve, TranscriptProtocolChallenge, TranscriptChannelError};

pub trait TranscriptProtocolRange<P: CurvePointProjective>:
    TranscriptProtocolCurve<P> + TranscriptProtocolChallenge {
    fn range_domain_sep(&mut self);
}

impl<P: CurvePointProjective> TranscriptProtocolRange<P> for Transcript {
    fn range_domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"range");
    }
}

pub struct TranscriptVerifierChannel<'a, P: CurvePointProjective, RP: RangeProofProtocol<P>, T: TranscriptProtocolRange<P>> {
    proof: Option<RP::Proof>,
    crs_type: std::marker::PhantomData<CRSRangeProof<P, RP>>,
    transcript_type: std::marker::PhantomData<&'a RefCell<T>>,
}

impl<'a, P: CurvePointProjective, RP: RangeProofProtocol<P>, T: TranscriptProtocolRange<P>> TranscriptVerifierChannel<'a, P, RP, T> {
    pub fn new(_: &CRSRangeProof<P, RP>, _: &'a RefCell<T>) -> TranscriptVerifierChannel<'a, P, RP, T> {
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

impl<'a, P: CurvePointProjective, RP: RangeProofProtocol<P>, T: TranscriptProtocolRange<P>> RangeVerifierChannel<P, RP> for TranscriptVerifierChannel<'a, P, RP, T> {
    fn send_proof(&mut self, proof: &RP::Proof) -> Result<(), ChannelError> {
        self.proof = Some(proof.clone());
        Ok(())
    }
}

pub struct TranscriptProverChannel<'a, P: CurvePointProjective, RP: RangeProofProtocol<P>, T: TranscriptProtocolRange<P>> {
    proof: RP::Proof,
    crs_type: std::marker::PhantomData<CRSRangeProof<P, RP>>,
    transcript_type: std::marker::PhantomData<&'a RefCell<T>>,
}

impl<'a, P: CurvePointProjective, RP: RangeProofProtocol<P>, T: TranscriptProtocolRange<P>> TranscriptProverChannel<'a, P, RP, T> {
    pub fn new(_: &CRSRangeProof<P, RP>, _: &'a RefCell<T>, proof: &RP::Proof) -> TranscriptProverChannel<'a, P, RP, T> {
        TranscriptProverChannel {
            proof: proof.clone(),
            crs_type: std::marker::PhantomData,
            transcript_type: std::marker::PhantomData,
        }
    }
}

impl<'a, P: CurvePointProjective, RP: RangeProofProtocol<P>, T: TranscriptProtocolRange<P>> RangeProverChannel<P, RP> for TranscriptProverChannel<'a, P, RP, T> {
    fn receive_proof(&mut self) -> Result<RP::Proof, ChannelError> {
        Ok(self.proof.clone())
    }
}
