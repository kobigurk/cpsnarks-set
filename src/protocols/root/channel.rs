use crate::{
    channels::ChannelError,
    protocols::root::{Message1, Message2, Message3},
    utils::ConvertibleUnknownOrderGroup,
};
use rug::Integer;

pub trait RootVerifierChannel<G: ConvertibleUnknownOrderGroup> {
    fn send_message1(&mut self, message: &Message1<G>) -> Result<(), ChannelError>;
    fn send_message2(&mut self, message: &Message2<G>) -> Result<(), ChannelError>;
    fn send_message3(&mut self, message: &Message3) -> Result<(), ChannelError>;
    fn receive_challenge(&mut self) -> Result<Integer, ChannelError>;
}

pub trait RootProverChannel<G: ConvertibleUnknownOrderGroup> {
    fn receive_message1(&mut self) -> Result<Message1<G>, ChannelError>;
    fn receive_message2(&mut self) -> Result<Message2<G>, ChannelError>;
    fn receive_message3(&mut self) -> Result<Message3, ChannelError>;
    fn generate_and_send_challenge(&mut self) -> Result<Integer, ChannelError>;
}
