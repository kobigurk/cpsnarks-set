use crate::{
    channels::ChannelError,
    protocols::range::RangeProofProtocol,
    utils::curve::CurvePointProjective,
};
pub trait RangeVerifierChannel<P: CurvePointProjective, RP: RangeProofProtocol<P>> {
    fn send_proof(&mut self, proof: &RP::Proof) -> Result<(), ChannelError>;
}

pub trait RangeProverChannel<P: CurvePointProjective, RP: RangeProofProtocol<P>> {
    fn receive_proof(&mut self) -> Result<RP::Proof, ChannelError>;
}