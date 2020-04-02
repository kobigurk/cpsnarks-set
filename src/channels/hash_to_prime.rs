use crate::{
    channels::ChannelError,
    protocols::hash_to_prime::HashToPrimeProtocol,
    utils::curve::CurvePointProjective,
};
pub trait HashToPrimeVerifierChannel<P: CurvePointProjective, RP: HashToPrimeProtocol<P>> {
    fn send_proof(&mut self, proof: &RP::Proof) -> Result<(), ChannelError>;
}

pub trait HashToPrimeProverChannel<P: CurvePointProjective, RP: HashToPrimeProtocol<P>> {
    fn receive_proof(&mut self) -> Result<RP::Proof, ChannelError>;
}