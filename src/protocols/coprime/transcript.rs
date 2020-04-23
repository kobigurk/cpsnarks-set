use crate::{
    channels::ChannelError,
    protocols::coprime::{
        channel::{CoprimeProverChannel, CoprimeVerifierChannel},
        CRSCoprime, Message1, Message2, Message3, Proof,
    },
    transcript::{TranscriptChannelError, TranscriptProtocolChallenge, TranscriptProtocolInteger},
    utils::ConvertibleUnknownOrderGroup,
};
use merlin::Transcript;
use rug::Integer;
use std::cell::RefCell;

pub trait TranscriptProtocolCoprime<G: ConvertibleUnknownOrderGroup>:
    TranscriptProtocolInteger<G> + TranscriptProtocolChallenge
{
    fn coprime_domain_sep(&mut self);
}

impl<G: ConvertibleUnknownOrderGroup> TranscriptProtocolCoprime<G> for Transcript {
    fn coprime_domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"coprime");
    }
}

pub struct TranscriptVerifierChannel<
    'a,
    G: ConvertibleUnknownOrderGroup,
    T: TranscriptProtocolCoprime<G>,
> {
    crs: CRSCoprime<G>,
    transcript: &'a RefCell<T>,
    message1: Option<Message1<G>>,
    message2: Option<Message2<G>>,
    message3: Option<Message3>,
}

impl<'a, G: ConvertibleUnknownOrderGroup, T: TranscriptProtocolCoprime<G>>
    TranscriptVerifierChannel<'a, G, T>
{
    pub fn new(
        crs: &CRSCoprime<G>,
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

impl<'a, G: ConvertibleUnknownOrderGroup, T: TranscriptProtocolCoprime<G>> CoprimeVerifierChannel<G>
    for TranscriptVerifierChannel<'a, G, T>
{
    fn send_message1(&mut self, message: &Message1<G>) -> Result<(), ChannelError> {
        let mut transcript = self.transcript.try_borrow_mut()?;
        transcript.coprime_domain_sep();
        transcript.append_integer_point(b"c_a", &message.c_a);
        transcript.append_integer_point(b"c_r_a", &message.c_r_a);
        transcript.append_integer_point(b"c_b_cap", &message.c_b_cap);
        transcript.append_integer_point(b"c_rho_b_cap", &message.c_rho_b_cap);
        self.message1 = Some(message.clone());
        Ok(())
    }
    fn send_message2(&mut self, message: &Message2<G>) -> Result<(), ChannelError> {
        let mut transcript = self.transcript.try_borrow_mut()?;
        transcript.coprime_domain_sep();
        transcript.append_integer_point(b"alpha2", &message.alpha2);
        transcript.append_integer_point(b"alpha3", &message.alpha3);
        transcript.append_integer_point(b"alpha4", &message.alpha4);
        transcript.append_integer_point(b"alpha5", &message.alpha5);
        transcript.append_integer_point(b"alpha6", &message.alpha6);
        transcript.append_integer_point(b"alpha7", &message.alpha7);
        self.message2 = Some(message.clone());
        Ok(())
    }
    fn send_message3(&mut self, message: &Message3) -> Result<(), ChannelError> {
        self.message3 = Some(message.clone());
        Ok(())
    }
    fn receive_challenge(&mut self) -> Result<Integer, ChannelError> {
        let mut transcript = self.transcript.try_borrow_mut()?;
        transcript.coprime_domain_sep();
        Ok(transcript.challenge_scalar(b"c", self.crs.parameters.security_soundness))
    }
}

pub struct TranscriptProverChannel<
    'a,
    G: ConvertibleUnknownOrderGroup,
    T: TranscriptProtocolCoprime<G>,
> {
    crs: CRSCoprime<G>,
    transcript: &'a RefCell<T>,
    proof: Proof<G>,
}

impl<'a, G: ConvertibleUnknownOrderGroup, T: TranscriptProtocolCoprime<G>>
    TranscriptProverChannel<'a, G, T>
{
    pub fn new(
        crs: &CRSCoprime<G>,
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

impl<'a, G: ConvertibleUnknownOrderGroup, T: TranscriptProtocolCoprime<G>> CoprimeProverChannel<G>
    for TranscriptProverChannel<'a, G, T>
{
    fn receive_message1(&mut self) -> Result<Message1<G>, ChannelError> {
        let mut transcript = self.transcript.try_borrow_mut()?;
        transcript.coprime_domain_sep();
        transcript.append_integer_point(b"c_a", &self.proof.message1.c_a);
        transcript.append_integer_point(b"c_r_a", &self.proof.message1.c_r_a);
        transcript.append_integer_point(b"c_b_cap", &self.proof.message1.c_b_cap);
        transcript.append_integer_point(b"c_rho_b_cap", &self.proof.message1.c_rho_b_cap);
        Ok(self.proof.message1.clone())
    }
    fn receive_message2(&mut self) -> Result<Message2<G>, ChannelError> {
        let mut transcript = self.transcript.try_borrow_mut()?;
        transcript.coprime_domain_sep();
        transcript.append_integer_point(b"alpha2", &self.proof.message2.alpha2);
        transcript.append_integer_point(b"alpha3", &self.proof.message2.alpha3);
        transcript.append_integer_point(b"alpha4", &self.proof.message2.alpha4);
        transcript.append_integer_point(b"alpha5", &self.proof.message2.alpha5);
        transcript.append_integer_point(b"alpha6", &self.proof.message2.alpha6);
        transcript.append_integer_point(b"alpha7", &self.proof.message2.alpha7);

        Ok(self.proof.message2.clone())
    }
    fn receive_message3(&mut self) -> Result<Message3, ChannelError> {
        Ok(self.proof.message3.clone())
    }
    fn generate_and_send_challenge(&mut self) -> Result<Integer, ChannelError> {
        let mut transcript = self.transcript.try_borrow_mut()?;
        transcript.coprime_domain_sep();
        Ok(transcript.challenge_scalar(b"c", self.crs.parameters.security_soundness))
    }
}
