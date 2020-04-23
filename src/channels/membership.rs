use super::ChannelError;
use crate::{
    commitments::{integer::IntegerCommitment, Commitment},
    utils::ConvertibleUnknownOrderGroup,
};

pub trait MembershipVerifierChannel<G: ConvertibleUnknownOrderGroup> {
    fn send_c_e(
        &mut self,
        c_e: &<IntegerCommitment<G> as Commitment>::Instance,
    ) -> Result<(), ChannelError>;
}

pub trait MembershipProverChannel<G: ConvertibleUnknownOrderGroup> {
    fn receive_c_e(
        &mut self,
    ) -> Result<<IntegerCommitment<G> as Commitment>::Instance, ChannelError>;
}
