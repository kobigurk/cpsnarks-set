use algebra_core::ProjectiveCurve;
use crate::{
    channels::ChannelError,
    protocols::range::RangeProofProtocol,
};
pub trait RangeVerifierChannel<P: ProjectiveCurve, RP: RangeProofProtocol<P>> {
    fn send_proof(&mut self, proof: &RP::Proof) -> Result<(), ChannelError>;
}

pub trait RangeProverChannel<P: ProjectiveCurve, RP: RangeProofProtocol<P>> {
    fn receive_proof(&mut self) -> Result<RP::Proof, ChannelError>;
}