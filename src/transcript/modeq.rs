use super::{
    TranscriptChannelError, TranscriptProtocolChallenge, TranscriptProtocolCurve,
    TranscriptProtocolInteger,
};
use crate::{
    channels::{
        modeq::{ModEqProverChannel, ModEqVerifierChannel},
        ChannelError,
    },
    protocols::modeq::{CRSModEq, Message1, Message2, Proof},
    utils::{curve::CurvePointProjective, ConvertibleUnknownOrderGroup},
};
use merlin::Transcript;
use rug::Integer;
use std::cell::RefCell;

pub trait TranscriptProtocolModEq<G: ConvertibleUnknownOrderGroup, P: CurvePointProjective>:
    TranscriptProtocolInteger<G> + TranscriptProtocolCurve<P> + TranscriptProtocolChallenge
{
    fn modeq_domain_sep(&mut self);
}

impl<G: ConvertibleUnknownOrderGroup, P: CurvePointProjective> TranscriptProtocolModEq<G, P>
    for Transcript
{
    fn modeq_domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"modeq");
    }
}
pub struct TranscriptVerifierChannel<
    'a,
    G: ConvertibleUnknownOrderGroup,
    P: CurvePointProjective,
    T: TranscriptProtocolModEq<G, P>,
> {
    crs: CRSModEq<G, P>,
    transcript: &'a RefCell<T>,
    message1: Option<Message1<G, P>>,
    message2: Option<Message2<P>>,
}

impl<
        'a,
        G: ConvertibleUnknownOrderGroup,
        P: CurvePointProjective,
        T: TranscriptProtocolModEq<G, P>,
    > TranscriptVerifierChannel<'a, G, P, T>
{
    pub fn new(
        crs: &CRSModEq<G, P>,
        transcript: &'a RefCell<T>,
    ) -> TranscriptVerifierChannel<'a, G, P, T> {
        TranscriptVerifierChannel {
            crs: crs.clone(),
            transcript,
            message1: None,
            message2: None,
        }
    }

    pub fn proof(&self) -> Result<Proof<G, P>, TranscriptChannelError> {
        if self.message1.is_some() && self.message2.is_some() {
            Ok(Proof {
                message1: self.message1.as_ref().unwrap().clone(),
                message2: self.message2.as_ref().unwrap().clone(),
            })
        } else {
            Err(TranscriptChannelError::Incomplete)
        }
    }
}

impl<
        'a,
        G: ConvertibleUnknownOrderGroup,
        P: CurvePointProjective,
        T: TranscriptProtocolModEq<G, P>,
    > ModEqVerifierChannel<G, P> for TranscriptVerifierChannel<'a, G, P, T>
{
    fn send_message1(&mut self, message: &Message1<G, P>) -> Result<(), ChannelError> {
        let mut transcript = self.transcript.try_borrow_mut()?;
        transcript.modeq_domain_sep();
        transcript.append_integer_point(b"alpha1", &message.alpha1);
        transcript.append_curve_point(b"alpha2", &message.alpha2);
        self.message1 = Some(message.clone());
        Ok(())
    }
    fn send_message2(&mut self, message: &Message2<P>) -> Result<(), ChannelError> {
        self.message2 = Some(message.clone());
        Ok(())
    }
    fn receive_challenge(&mut self) -> Result<Integer, ChannelError> {
        let mut transcript = self.transcript.try_borrow_mut()?;
        transcript.modeq_domain_sep();
        Ok(transcript.challenge_scalar(b"c", self.crs.parameters.security_soundness))
    }
}

pub struct TranscriptProverChannel<
    'a,
    G: ConvertibleUnknownOrderGroup,
    P: CurvePointProjective,
    T: TranscriptProtocolModEq<G, P>,
> {
    crs: CRSModEq<G, P>,
    transcript: &'a RefCell<T>,
    proof: Proof<G, P>,
}

impl<
        'a,
        G: ConvertibleUnknownOrderGroup,
        P: CurvePointProjective,
        T: TranscriptProtocolModEq<G, P>,
    > TranscriptProverChannel<'a, G, P, T>
{
    pub fn new(
        crs: &CRSModEq<G, P>,
        transcript: &'a RefCell<T>,
        proof: &Proof<G, P>,
    ) -> TranscriptProverChannel<'a, G, P, T> {
        TranscriptProverChannel {
            crs: crs.clone(),
            transcript,
            proof: proof.clone(),
        }
    }
}

impl<
        'a,
        G: ConvertibleUnknownOrderGroup,
        P: CurvePointProjective,
        T: TranscriptProtocolModEq<G, P>,
    > ModEqProverChannel<G, P> for TranscriptProverChannel<'a, G, P, T>
{
    fn receive_message1(&mut self) -> Result<Message1<G, P>, ChannelError> {
        let mut transcript = self.transcript.try_borrow_mut()?;
        transcript.modeq_domain_sep();
        transcript.append_integer_point(b"alpha1", &self.proof.message1.alpha1);
        transcript.append_curve_point(b"alpha2", &self.proof.message1.alpha2);
        Ok(self.proof.message1.clone())
    }
    fn receive_message2(&mut self) -> Result<Message2<P>, ChannelError> {
        Ok(self.proof.message2.clone())
    }
    fn generate_and_send_challenge(&mut self) -> Result<Integer, ChannelError> {
        let mut transcript = self.transcript.try_borrow_mut()?;
        transcript.modeq_domain_sep();
        Ok(transcript.challenge_scalar(b"c", self.crs.parameters.security_soundness))
    }
}
