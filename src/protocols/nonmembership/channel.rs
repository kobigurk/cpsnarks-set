use crate::{
    channels::ChannelError,
    commitments::{integer::IntegerCommitment, Commitment},
    utils::ConvertibleUnknownOrderGroup,
};

pub trait NonMembershipVerifierChannel<G: ConvertibleUnknownOrderGroup> {
    fn send_c_e(
        &mut self,
        c_e: &<IntegerCommitment<G> as Commitment>::Instance,
    ) -> Result<(), ChannelError>;
}

pub trait NonMembershipProverChannel<G: ConvertibleUnknownOrderGroup> {
    fn receive_c_e(
        &mut self,
    ) -> Result<<IntegerCommitment<G> as Commitment>::Instance, ChannelError>;
}
