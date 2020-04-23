use super::{TranscriptChannelError, TranscriptProtocolChallenge, TranscriptProtocolInteger};
use crate::{
    channels::{
        hash_to_prime::{HashToPrimeProverChannel, HashToPrimeVerifierChannel},
        modeq::{ModEqProverChannel, ModEqVerifierChannel},
        nonmembership::{NonMembershipProverChannel, NonMembershipVerifierChannel},
        ChannelError,
    },
    commitments::{integer::IntegerCommitment, Commitment},
    protocols::{
        hash_to_prime::HashToPrimeProtocol,
        nonmembership::{Proof, CRS},
        coprime::{
            channel::{CoprimeProverChannel, CoprimeVerifierChannel},
            transcript::{
                TranscriptProtocolCoprime, TranscriptProverChannel as CoprimeTranscriptProverChannel,
                TranscriptVerifierChannel as CoprimeTranscriptVerifierChannel,
            },
        },
    },
    transcript::{
        hash_to_prime::{
            TranscriptProtocolHashToPrime,
            TranscriptProverChannel as HashToPrimeTranscriptProverChannel,
            TranscriptVerifierChannel as HashToPrimeTranscriptVerifierChannel,
        },
        modeq::{
            TranscriptProtocolModEq, TranscriptProverChannel as ModEqTranscriptProverChannel,
            TranscriptVerifierChannel as ModEqTranscriptVerifierChannel,
        },
    },
    utils::{curve::CurvePointProjective, ConvertibleUnknownOrderGroup},
};
use merlin::Transcript;
use rug::Integer;
use std::cell::RefCell;

pub trait TranscriptProtocolNonMembership<G: ConvertibleUnknownOrderGroup>:
    TranscriptProtocolInteger<G> + TranscriptProtocolChallenge
{
    fn nonmembership_domain_sep(&mut self);
}

impl<G: ConvertibleUnknownOrderGroup> TranscriptProtocolNonMembership<G> for Transcript {
    fn nonmembership_domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"nonmembership");
    }
}
pub struct TranscriptVerifierChannel<
    'a,
    G: ConvertibleUnknownOrderGroup,
    P: CurvePointProjective,
    HP: HashToPrimeProtocol<P>,
    T: TranscriptProtocolNonMembership<G>
        + TranscriptProtocolCoprime<G>
        + TranscriptProtocolModEq<G, P>
        + TranscriptProtocolHashToPrime<P>,
> {
    transcript: &'a RefCell<T>,
    c_e: Option<<IntegerCommitment<G> as Commitment>::Instance>,
    coprime_transcript_verifier_channel: CoprimeTranscriptVerifierChannel<'a, G, T>,
    modeq_transcript_verifier_channel: ModEqTranscriptVerifierChannel<'a, G, P, T>,
    hash_to_prime_transcript_verifier_channel: HashToPrimeTranscriptVerifierChannel<'a, P, HP, T>,
}

impl<
        'a,
        G: ConvertibleUnknownOrderGroup,
        P: CurvePointProjective,
        HP: HashToPrimeProtocol<P>,
        T: TranscriptProtocolNonMembership<G>
            + TranscriptProtocolCoprime<G>
            + TranscriptProtocolModEq<G, P>
            + TranscriptProtocolHashToPrime<P>,
    > TranscriptVerifierChannel<'a, G, P, HP, T>
{
    pub fn new(
        crs: &CRS<G, P, HP>,
        transcript: &'a RefCell<T>,
    ) -> TranscriptVerifierChannel<'a, G, P, HP, T> {
        TranscriptVerifierChannel {
            transcript,
            c_e: None,
            coprime_transcript_verifier_channel: CoprimeTranscriptVerifierChannel::new(
                &crs.crs_coprime,
                transcript,
            ),
            modeq_transcript_verifier_channel: ModEqTranscriptVerifierChannel::new(
                &crs.crs_modeq,
                transcript,
            ),
            hash_to_prime_transcript_verifier_channel: HashToPrimeTranscriptVerifierChannel::new(
                &crs.crs_hash_to_prime,
                transcript,
            ),
        }
    }

    pub fn proof(&self) -> Result<Proof<G, P, HP>, TranscriptChannelError> {
        let proof_coprime = self.coprime_transcript_verifier_channel.proof()?;
        let proof_modeq = self.modeq_transcript_verifier_channel.proof()?;
        let proof_hash_to_prime = self.hash_to_prime_transcript_verifier_channel.proof()?;
        if self.c_e.is_some() {
            Ok(Proof {
                c_e: self.c_e.as_ref().unwrap().clone(),
                proof_coprime,
                proof_modeq,
                proof_hash_to_prime,
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
        HP: HashToPrimeProtocol<P>,
        T: TranscriptProtocolNonMembership<G>
            + TranscriptProtocolCoprime<G>
            + TranscriptProtocolModEq<G, P>
            + TranscriptProtocolHashToPrime<P>,
    > CoprimeVerifierChannel<G> for TranscriptVerifierChannel<'a, G, P, HP, T>
{
    fn send_message1(
        &mut self,
        message: &crate::protocols::coprime::Message1<G>,
    ) -> Result<(), ChannelError> {
        self.coprime_transcript_verifier_channel
            .send_message1(message)
    }
    fn send_message2(
        &mut self,
        message: &crate::protocols::coprime::Message2<G>,
    ) -> Result<(), ChannelError> {
        self.coprime_transcript_verifier_channel
            .send_message2(message)
    }
    fn send_message3(
        &mut self,
        message: &crate::protocols::coprime::Message3,
    ) -> Result<(), ChannelError> {
        self.coprime_transcript_verifier_channel
            .send_message3(message)
    }
    fn receive_challenge(&mut self) -> Result<Integer, ChannelError> {
        self.coprime_transcript_verifier_channel.receive_challenge()
    }
}

impl<
        'a,
        G: ConvertibleUnknownOrderGroup,
        P: CurvePointProjective,
        HP: HashToPrimeProtocol<P>,
        T: TranscriptProtocolNonMembership<G>
            + TranscriptProtocolCoprime<G>
            + TranscriptProtocolModEq<G, P>
            + TranscriptProtocolHashToPrime<P>,
    > ModEqVerifierChannel<G, P> for TranscriptVerifierChannel<'a, G, P, HP, T>
{
    fn send_message1(
        &mut self,
        message: &crate::protocols::modeq::Message1<G, P>,
    ) -> Result<(), ChannelError> {
        self.modeq_transcript_verifier_channel
            .send_message1(message)
    }
    fn send_message2(
        &mut self,
        message: &crate::protocols::modeq::Message2<P>,
    ) -> Result<(), ChannelError> {
        self.modeq_transcript_verifier_channel
            .send_message2(message)
    }
    fn receive_challenge(&mut self) -> Result<Integer, ChannelError> {
        self.modeq_transcript_verifier_channel.receive_challenge()
    }
}

impl<
        'a,
        G: ConvertibleUnknownOrderGroup,
        P: CurvePointProjective,
        HP: HashToPrimeProtocol<P>,
        T: TranscriptProtocolNonMembership<G>
            + TranscriptProtocolCoprime<G>
            + TranscriptProtocolModEq<G, P>
            + TranscriptProtocolHashToPrime<P>,
    > HashToPrimeVerifierChannel<P, HP> for TranscriptVerifierChannel<'a, G, P, HP, T>
{
    fn send_proof(&mut self, proof: &HP::Proof) -> Result<(), ChannelError> {
        self.hash_to_prime_transcript_verifier_channel
            .send_proof(proof)
    }
}

pub struct TranscriptProverChannel<
    'a,
    G: ConvertibleUnknownOrderGroup,
    P: CurvePointProjective,
    HP: HashToPrimeProtocol<P>,
    T: TranscriptProtocolNonMembership<G>
        + TranscriptProtocolCoprime<G>
        + TranscriptProtocolModEq<G, P>
        + TranscriptProtocolHashToPrime<P>,
> {
    transcript: &'a RefCell<T>,
    coprime_transcript_prover_channel: CoprimeTranscriptProverChannel<'a, G, T>,
    modeq_transcript_prover_channel: ModEqTranscriptProverChannel<'a, G, P, T>,
    hash_to_prime_transcript_prover_channel: HashToPrimeTranscriptProverChannel<'a, P, HP, T>,
    proof: Proof<G, P, HP>,
}

impl<
        'a,
        G: ConvertibleUnknownOrderGroup,
        P: CurvePointProjective,
        HP: HashToPrimeProtocol<P>,
        T: TranscriptProtocolNonMembership<G>
            + TranscriptProtocolCoprime<G>
            + TranscriptProtocolModEq<G, P>
            + TranscriptProtocolHashToPrime<P>,
    > CoprimeProverChannel<G> for TranscriptProverChannel<'a, G, P, HP, T>
{
    fn receive_message1(&mut self) -> Result<crate::protocols::coprime::Message1<G>, ChannelError> {
        self.coprime_transcript_prover_channel.receive_message1()
    }
    fn receive_message2(&mut self) -> Result<crate::protocols::coprime::Message2<G>, ChannelError> {
        self.coprime_transcript_prover_channel.receive_message2()
    }
    fn receive_message3(&mut self) -> Result<crate::protocols::coprime::Message3, ChannelError> {
        self.coprime_transcript_prover_channel.receive_message3()
    }
    fn generate_and_send_challenge(&mut self) -> Result<Integer, ChannelError> {
        self.coprime_transcript_prover_channel
            .generate_and_send_challenge()
    }
}

impl<
        'a,
        G: ConvertibleUnknownOrderGroup,
        P: CurvePointProjective,
        HP: HashToPrimeProtocol<P>,
        T: TranscriptProtocolNonMembership<G>
            + TranscriptProtocolCoprime<G>
            + TranscriptProtocolModEq<G, P>
            + TranscriptProtocolHashToPrime<P>,
    > ModEqProverChannel<G, P> for TranscriptProverChannel<'a, G, P, HP, T>
{
    fn receive_message1(
        &mut self,
    ) -> Result<crate::protocols::modeq::Message1<G, P>, ChannelError> {
        self.modeq_transcript_prover_channel.receive_message1()
    }
    fn receive_message2(&mut self) -> Result<crate::protocols::modeq::Message2<P>, ChannelError> {
        self.modeq_transcript_prover_channel.receive_message2()
    }
    fn generate_and_send_challenge(&mut self) -> Result<Integer, ChannelError> {
        self.modeq_transcript_prover_channel
            .generate_and_send_challenge()
    }
}

impl<
        'a,
        G: ConvertibleUnknownOrderGroup,
        P: CurvePointProjective,
        HP: HashToPrimeProtocol<P>,
        T: TranscriptProtocolNonMembership<G>
            + TranscriptProtocolCoprime<G>
            + TranscriptProtocolModEq<G, P>
            + TranscriptProtocolHashToPrime<P>,
    > HashToPrimeProverChannel<P, HP> for TranscriptProverChannel<'a, G, P, HP, T>
{
    fn receive_proof(&mut self) -> Result<HP::Proof, ChannelError> {
        self.hash_to_prime_transcript_prover_channel.receive_proof()
    }
}

impl<
        'a,
        G: ConvertibleUnknownOrderGroup,
        P: CurvePointProjective,
        HP: HashToPrimeProtocol<P>,
        T: TranscriptProtocolNonMembership<G>
            + TranscriptProtocolCoprime<G>
            + TranscriptProtocolModEq<G, P>
            + TranscriptProtocolHashToPrime<P>,
    > NonMembershipVerifierChannel<G> for TranscriptVerifierChannel<'a, G, P, HP, T>
{
    fn send_c_e(
        &mut self,
        c_e: &<IntegerCommitment<G> as Commitment>::Instance,
    ) -> Result<(), ChannelError> {
        let mut transcript = self.transcript.try_borrow_mut()?;
        transcript.nonmembership_domain_sep();
        transcript.append_integer_point(b"c_e", c_e);
        self.c_e = Some(c_e.clone());
        Ok(())
    }
}

impl<
        'a,
        G: ConvertibleUnknownOrderGroup,
        P: CurvePointProjective,
        HP: HashToPrimeProtocol<P>,
        T: TranscriptProtocolNonMembership<G>
            + TranscriptProtocolCoprime<G>
            + TranscriptProtocolModEq<G, P>
            + TranscriptProtocolHashToPrime<P>,
    > NonMembershipProverChannel<G> for TranscriptProverChannel<'a, G, P, HP, T>
{
    fn receive_c_e(
        &mut self,
    ) -> Result<<IntegerCommitment<G> as Commitment>::Instance, ChannelError> {
        let mut transcript = self.transcript.try_borrow_mut()?;
        transcript.nonmembership_domain_sep();
        transcript.append_integer_point(b"c_e", &self.proof.c_e);
        Ok(self.proof.c_e.clone())
    }
}

impl<
        'a,
        G: ConvertibleUnknownOrderGroup,
        P: CurvePointProjective,
        HP: HashToPrimeProtocol<P>,
        T: TranscriptProtocolNonMembership<G>
            + TranscriptProtocolCoprime<G>
            + TranscriptProtocolModEq<G, P>
            + TranscriptProtocolHashToPrime<P>,
    > TranscriptProverChannel<'a, G, P, HP, T>
{
    pub fn new(
        crs: &CRS<G, P, HP>,
        transcript: &'a RefCell<T>,
        proof: &Proof<G, P, HP>,
    ) -> TranscriptProverChannel<'a, G, P, HP, T> {
        TranscriptProverChannel {
            transcript,
            coprime_transcript_prover_channel: CoprimeTranscriptProverChannel::new(
                &crs.crs_coprime,
                transcript,
                &proof.proof_coprime,
            ),
            modeq_transcript_prover_channel: ModEqTranscriptProverChannel::new(
                &crs.crs_modeq,
                transcript,
                &proof.proof_modeq,
            ),
            hash_to_prime_transcript_prover_channel: HashToPrimeTranscriptProverChannel::new(
                &crs.crs_hash_to_prime,
                transcript,
                &proof.proof_hash_to_prime,
            ),
            proof: proof.clone(),
        }
    }
}
