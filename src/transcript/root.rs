use crate::{
    channels::{
        root::{RootProverChannel, RootVerifierChannel},
        ChannelError,
    },
    protocols::root::{CRSRoot, Message1, Message2, Message3, Proof},
    utils::ConvertibleUnknownOrderGroup,
};
use merlin::Transcript;
use rug::Integer;
use std::cell::RefCell;

use super::{TranscriptChannelError, TranscriptProtocolChallenge, TranscriptProtocolInteger};
pub trait TranscriptProtocolRoot<G: ConvertibleUnknownOrderGroup>:
    TranscriptProtocolInteger<G> + TranscriptProtocolChallenge
{
    fn root_domain_sep(&mut self);
}

impl<G: ConvertibleUnknownOrderGroup> TranscriptProtocolRoot<G> for Transcript {
    fn root_domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"root");
    }
}

pub struct TranscriptVerifierChannel<
    'a,
    G: ConvertibleUnknownOrderGroup,
    T: TranscriptProtocolRoot<G>,
> {
    crs: CRSRoot<G>,
    transcript: &'a RefCell<T>,
    message1: Option<Message1<G>>,
    message2: Option<Message2<G>>,
    message3: Option<Message3>,
}

impl<'a, G: ConvertibleUnknownOrderGroup, T: TranscriptProtocolRoot<G>>
    TranscriptVerifierChannel<'a, G, T>
{
    pub fn new(
        crs: &CRSRoot<G>,
        transcript: &'a RefCell<T>,
    ) -> TranscriptVerifierChannel<'a, G, T> {
        TranscriptVerifierChannel {
            crs: crs.clone(),
            transcript,
            message1: None,
            message2: None,
            message3: None,
        }
    }

    pub fn proof(&self) -> Result<Proof<G>, TranscriptChannelError> {
        if self.message1.is_some() && self.message2.is_some() && self.message3.is_some() {
            Ok(Proof {
                message1: self.message1.as_ref().unwrap().clone(),
                message2: self.message2.as_ref().unwrap().clone(),
                message3: self.message3.as_ref().unwrap().clone(),
            })
        } else {
            Err(TranscriptChannelError::Incomplete)
        }
    }
}

impl<'a, G: ConvertibleUnknownOrderGroup, T: TranscriptProtocolRoot<G>> RootVerifierChannel<G>
    for TranscriptVerifierChannel<'a, G, T>
{
    fn send_message1(&mut self, message: &Message1<G>) -> Result<(), ChannelError> {
        let mut transcript = self.transcript.try_borrow_mut()?;
        transcript.root_domain_sep();
        transcript.append_integer_point(b"c_w", &message.c_w);
        transcript.append_integer_point(b"c_r", &message.c_r);
        self.message1 = Some(message.clone());
        Ok(())
    }
    fn send_message2(&mut self, message: &Message2<G>) -> Result<(), ChannelError> {
        let mut transcript = self.transcript.try_borrow_mut()?;
        transcript.root_domain_sep();
        transcript.append_integer_point(b"alpha1", &message.alpha1);
        transcript.append_integer_point(b"alpha2", &message.alpha2);
        transcript.append_integer_point(b"alpha3", &message.alpha3);
        transcript.append_integer_point(b"alpha4", &message.alpha4);
        self.message2 = Some(message.clone());
        Ok(())
    }
    fn send_message3(&mut self, message: &Message3) -> Result<(), ChannelError> {
        self.message3 = Some(message.clone());
        Ok(())
    }
    fn receive_challenge(&mut self) -> Result<Integer, ChannelError> {
        let mut transcript = self.transcript.try_borrow_mut()?;
        transcript.root_domain_sep();
        Ok(transcript.challenge_scalar(b"c", self.crs.parameters.security_soundness))
    }
}

pub struct TranscriptProverChannel<
    'a,
    G: ConvertibleUnknownOrderGroup,
    T: TranscriptProtocolRoot<G>,
> {
    crs: CRSRoot<G>,
    transcript: &'a RefCell<T>,
    proof: Proof<G>,
}

impl<'a, G: ConvertibleUnknownOrderGroup, T: TranscriptProtocolRoot<G>>
    TranscriptProverChannel<'a, G, T>
{
    pub fn new(
        crs: &CRSRoot<G>,
        transcript: &'a RefCell<T>,
        proof: &Proof<G>,
    ) -> TranscriptProverChannel<'a, G, T> {
        TranscriptProverChannel {
            crs: crs.clone(),
            transcript,
            proof: proof.clone(),
        }
    }
}

impl<'a, G: ConvertibleUnknownOrderGroup, T: TranscriptProtocolRoot<G>> RootProverChannel<G>
    for TranscriptProverChannel<'a, G, T>
{
    fn receive_message1(&mut self) -> Result<Message1<G>, ChannelError> {
        let mut transcript = self.transcript.try_borrow_mut()?;
        transcript.root_domain_sep();
        transcript.append_integer_point(b"c_w", &self.proof.message1.c_w);
        transcript.append_integer_point(b"c_r", &self.proof.message1.c_r);
        Ok(self.proof.message1.clone())
    }
    fn receive_message2(&mut self) -> Result<Message2<G>, ChannelError> {
        let mut transcript = self.transcript.try_borrow_mut()?;
        transcript.root_domain_sep();
        transcript.append_integer_point(b"alpha1", &self.proof.message2.alpha1);
        transcript.append_integer_point(b"alpha2", &self.proof.message2.alpha2);
        transcript.append_integer_point(b"alpha3", &self.proof.message2.alpha3);
        transcript.append_integer_point(b"alpha4", &self.proof.message2.alpha4);

        Ok(self.proof.message2.clone())
    }
    fn receive_message3(&mut self) -> Result<Message3, ChannelError> {
        Ok(self.proof.message3.clone())
    }
    fn generate_and_send_challenge(&mut self) -> Result<Integer, ChannelError> {
        let mut transcript = self.transcript.try_borrow_mut()?;
        transcript.root_domain_sep();
        Ok(transcript.challenge_scalar(b"c", self.crs.parameters.security_soundness))
    }
}
