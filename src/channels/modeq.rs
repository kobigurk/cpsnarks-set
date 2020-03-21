use rug::Integer;
use super::ChannelError;
use crate::{
    utils::ConvertibleUnknownOrderGroup,
    protocols::modeq::{Message1, Message2}
};
use algebra_core::ProjectiveCurve;

pub trait ModEqVerifierChannel<G: ConvertibleUnknownOrderGroup, P: ProjectiveCurve> {
    fn send_message1(&mut self, message: &Message1<G, P>) -> Result<(), ChannelError>;
    fn send_message2(&mut self, message: &Message2<P>) -> Result<(), ChannelError>;
    fn receive_challenge(&mut self) -> Result<Integer, ChannelError>;
}

pub trait ModEqProverChannel<G: ConvertibleUnknownOrderGroup, P: ProjectiveCurve> {
    fn receive_message1(&mut self) -> Result<Message1<G, P>, ChannelError>;
    fn receive_message2(&mut self) -> Result<Message2<P>, ChannelError>;
    fn generate_and_send_challenge(&mut self) -> Result<Integer, ChannelError>;
}