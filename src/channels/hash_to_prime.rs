use crate::{
    channels::ChannelError, protocols::hash_to_prime::HashToPrimeProtocol,
    utils::curve::CurvePointProjective,
};
pub trait HashToPrimeVerifierChannel<P: CurvePointProjective, HP: HashToPrimeProtocol<P>> {
    fn send_proof(&mut self, proof: &HP::Proof) -> Result<(), ChannelError>;
}

pub trait HashToPrimeProverChannel<P: CurvePointProjective, HP: HashToPrimeProtocol<P>> {
    fn receive_proof(&mut self) -> Result<HP::Proof, ChannelError>;
}
