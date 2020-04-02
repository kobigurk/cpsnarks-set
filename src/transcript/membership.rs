use merlin::Transcript;
use std::cell::RefCell;
use crate::{
    channels::{
        ChannelError,
        root::{RootProverChannel, RootVerifierChannel},
        modeq::{ModEqProverChannel, ModEqVerifierChannel},
        hash_to_prime::{HashToPrimeProverChannel, HashToPrimeVerifierChannel},
        membership::{MembershipProverChannel, MembershipVerifierChannel},
    },
    utils::{
        ConvertibleUnknownOrderGroup,
        curve::{CurvePointProjective},
    },
    commitments::{
        Commitment,
        integer::IntegerCommitment
    },
    protocols::{
        membership::{CRS, Proof},
        hash_to_prime::HashToPrimeProtocol,
    },
    transcript::{
        root::{TranscriptProtocolRoot, TranscriptProverChannel as RootTranscriptProverChannel, TranscriptVerifierChannel as RootTranscriptVerifierChannel},
        modeq::{TranscriptProtocolModEq, TranscriptProverChannel as ModEqTranscriptProverChannel, TranscriptVerifierChannel as ModEqTranscriptVerifierChannel},
        hash_to_prime::{TranscriptProtocolHashToPrime, TranscriptProverChannel as HashToPrimeTranscriptProverChannel, TranscriptVerifierChannel as HashToPrimeTranscriptVerifierChannel},
    }
};
use super::{TranscriptProtocolInteger, TranscriptProtocolChallenge, TranscriptChannelError};
use rug::Integer;

pub trait TranscriptProtocolMembership<G: ConvertibleUnknownOrderGroup>:
    TranscriptProtocolInteger<G> + TranscriptProtocolChallenge {
    fn membership_domain_sep(&mut self);
}

impl<G: ConvertibleUnknownOrderGroup> TranscriptProtocolMembership<G> for Transcript {
    fn membership_domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"membership");
    }
}
pub struct TranscriptVerifierChannel<
    'a, 
    G: ConvertibleUnknownOrderGroup, 
    P: CurvePointProjective, 
    HP: HashToPrimeProtocol<P>,
    T: TranscriptProtocolMembership<G> + TranscriptProtocolRoot<G> + TranscriptProtocolModEq<G, P> + TranscriptProtocolHashToPrime<P>
> {
    transcript: &'a RefCell<T>,
    c_e: Option<<IntegerCommitment<G> as Commitment>::Instance>,
    root_transcript_verifier_channel: RootTranscriptVerifierChannel<'a, G, T>,
    modeq_transcript_verifier_channel: ModEqTranscriptVerifierChannel<'a, G, P, T>,
    hash_to_prime_transcript_verifier_channel: HashToPrimeTranscriptVerifierChannel<'a, P, HP, T>,
}

impl<
    'a, 
    G: ConvertibleUnknownOrderGroup, 
    P: CurvePointProjective, 
    HP: HashToPrimeProtocol<P>,
    T: TranscriptProtocolMembership<G> + TranscriptProtocolRoot<G> + TranscriptProtocolModEq<G, P> + TranscriptProtocolHashToPrime<P>
> TranscriptVerifierChannel<'a, G, P, HP, T> {
    pub fn new(crs: &CRS<G, P, HP>, transcript: &'a RefCell<T>) -> TranscriptVerifierChannel<'a, G, P, HP, T> {
        TranscriptVerifierChannel {
            transcript,
            c_e: None,
            root_transcript_verifier_channel: RootTranscriptVerifierChannel::new(&crs.crs_root, transcript),
            modeq_transcript_verifier_channel: ModEqTranscriptVerifierChannel::new(&crs.crs_modeq, transcript),
            hash_to_prime_transcript_verifier_channel: HashToPrimeTranscriptVerifierChannel::new(&crs.crs_hash_to_prime, transcript),
        }
    }

    pub fn proof(&self) -> Result<Proof<G, P, HP>, TranscriptChannelError> {
        let proof_root = self.root_transcript_verifier_channel.proof()?;
        let proof_modeq = self.modeq_transcript_verifier_channel.proof()?;
        let proof_hash_to_prime = self.hash_to_prime_transcript_verifier_channel.proof()?;
        if self.c_e.is_some() {
            Ok(Proof {
                c_e: self.c_e.as_ref().unwrap().clone(),
                proof_root: proof_root,
                proof_modeq: proof_modeq,
                proof_hash_to_prime: proof_hash_to_prime,
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
    T: TranscriptProtocolMembership<G> + TranscriptProtocolRoot<G> + TranscriptProtocolModEq<G, P> + TranscriptProtocolHashToPrime<P>
> RootVerifierChannel<G> for TranscriptVerifierChannel<'a, G, P, HP, T> {
    fn send_message1(&mut self, message: &crate::protocols::root::Message1<G>) -> Result<(), ChannelError> {
        self.root_transcript_verifier_channel.send_message1(message)
    }
    fn send_message2(&mut self, message: &crate::protocols::root::Message2<G>) -> Result<(), ChannelError> {
        self.root_transcript_verifier_channel.send_message2(message)
    }
    fn send_message3(&mut self, message: &crate::protocols::root::Message3) -> Result<(), ChannelError> {
        self.root_transcript_verifier_channel.send_message3(message)
    }
    fn receive_challenge(&mut self) -> Result<Integer, ChannelError> {
        self.root_transcript_verifier_channel.receive_challenge()
    }
}

impl<
    'a, 
    G: ConvertibleUnknownOrderGroup, 
    P: CurvePointProjective, 
    HP: HashToPrimeProtocol<P>,
    T: TranscriptProtocolMembership<G> + TranscriptProtocolRoot<G> + TranscriptProtocolModEq<G, P> + TranscriptProtocolHashToPrime<P>
> ModEqVerifierChannel<G, P> for TranscriptVerifierChannel<'a, G, P, HP, T> {
    fn send_message1(&mut self, message: &crate::protocols::modeq::Message1<G, P>) -> Result<(), ChannelError> {
        self.modeq_transcript_verifier_channel.send_message1(message)
    }
    fn send_message2(&mut self, message: &crate::protocols::modeq::Message2<P>) -> Result<(), ChannelError> {
        self.modeq_transcript_verifier_channel.send_message2(message)
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
    T: TranscriptProtocolMembership<G> + TranscriptProtocolRoot<G> + TranscriptProtocolModEq<G, P> + TranscriptProtocolHashToPrime<P>
> HashToPrimeVerifierChannel<P, HP> for TranscriptVerifierChannel<'a, G, P, HP, T> {
    fn send_proof(&mut self, proof: &HP::Proof) -> Result<(), ChannelError> {
        self.hash_to_prime_transcript_verifier_channel.send_proof(proof)
    }
}

pub struct TranscriptProverChannel<
    'a, 
    G: ConvertibleUnknownOrderGroup, 
    P: CurvePointProjective, 
    HP: HashToPrimeProtocol<P>,
    T: TranscriptProtocolMembership<G> + TranscriptProtocolRoot<G> + TranscriptProtocolModEq<G, P> + TranscriptProtocolHashToPrime<P>
> {
    transcript: &'a RefCell<T>,
    root_transcript_prover_channel: RootTranscriptProverChannel<'a, G, T>,
    modeq_transcript_prover_channel: ModEqTranscriptProverChannel<'a, G, P, T>,
    hash_to_prime_transcript_prover_channel: HashToPrimeTranscriptProverChannel<'a, P, HP, T>,
    proof: Proof<G,P, HP>,
}

impl<
    'a, 
    G: ConvertibleUnknownOrderGroup, 
    P: CurvePointProjective, 
    HP: HashToPrimeProtocol<P>,
    T: TranscriptProtocolMembership<G> + TranscriptProtocolRoot<G> + TranscriptProtocolModEq<G, P> + TranscriptProtocolHashToPrime<P>
> RootProverChannel<G> for TranscriptProverChannel<'a, G, P, HP, T> {
    fn receive_message1(&mut self) -> Result<crate::protocols::root::Message1<G>, ChannelError> {
        self.root_transcript_prover_channel.receive_message1()
    }
    fn receive_message2(&mut self) -> Result<crate::protocols::root::Message2<G>, ChannelError> {
        self.root_transcript_prover_channel.receive_message2()
    }
    fn receive_message3(&mut self) -> Result<crate::protocols::root::Message3, ChannelError> {
        self.root_transcript_prover_channel.receive_message3()
    }
    fn generate_and_send_challenge(&mut self) -> Result<Integer, ChannelError> {
        self.root_transcript_prover_channel.generate_and_send_challenge()
    }
}

impl<
    'a, 
    G: ConvertibleUnknownOrderGroup, 
    P: CurvePointProjective, 
    HP: HashToPrimeProtocol<P>,
    T: TranscriptProtocolMembership<G> + TranscriptProtocolRoot<G> + TranscriptProtocolModEq<G, P> + TranscriptProtocolHashToPrime<P>
> ModEqProverChannel<G, P> for TranscriptProverChannel<'a, G, P, HP, T> {
    fn receive_message1(&mut self) -> Result<crate::protocols::modeq::Message1<G, P>, ChannelError> {
        self.modeq_transcript_prover_channel.receive_message1()
    }
    fn receive_message2(&mut self) -> Result<crate::protocols::modeq::Message2<P>, ChannelError> {
        self.modeq_transcript_prover_channel.receive_message2()
    }
    fn generate_and_send_challenge(&mut self) -> Result<Integer, ChannelError> {
        self.modeq_transcript_prover_channel.generate_and_send_challenge()
    }
}

impl<
    'a, 
    G: ConvertibleUnknownOrderGroup, 
    P: CurvePointProjective, 
    HP: HashToPrimeProtocol<P>,
    T: TranscriptProtocolMembership<G> + TranscriptProtocolRoot<G> + TranscriptProtocolModEq<G, P> + TranscriptProtocolHashToPrime<P>
> HashToPrimeProverChannel<P, HP> for TranscriptProverChannel<'a, G, P, HP, T> {
    fn receive_proof(&mut self) -> Result<HP::Proof, ChannelError> {
        self.hash_to_prime_transcript_prover_channel.receive_proof()
    }
}

impl<
    'a, 
    G: ConvertibleUnknownOrderGroup, 
    P: CurvePointProjective, 
    HP: HashToPrimeProtocol<P>,
    T: TranscriptProtocolMembership<G> + TranscriptProtocolRoot<G> + TranscriptProtocolModEq<G, P> + TranscriptProtocolHashToPrime<P>
> MembershipVerifierChannel<G> for TranscriptVerifierChannel<'a, G, P, HP, T> {
    fn send_c_e(&mut self, c_e: &<IntegerCommitment<G> as Commitment>::Instance) -> Result<(), ChannelError> {
        let mut transcript = self.transcript.try_borrow_mut()?;
        transcript.membership_domain_sep();
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
    T: TranscriptProtocolMembership<G> + TranscriptProtocolRoot<G> + TranscriptProtocolModEq<G, P> + TranscriptProtocolHashToPrime<P>
> MembershipProverChannel<G> for TranscriptProverChannel<'a, G, P, HP, T> {
    fn receive_c_e(&mut self) -> Result<<IntegerCommitment<G> as Commitment>::Instance, ChannelError> {
        let mut transcript = self.transcript.try_borrow_mut()?;
        transcript.membership_domain_sep();
        transcript.append_integer_point(b"c_e", &self.proof.c_e);
        Ok(self.proof.c_e.clone())
    }
}
  
impl<
    'a, 
    G: ConvertibleUnknownOrderGroup, 
    P: CurvePointProjective, 
    HP: HashToPrimeProtocol<P>,
    T: TranscriptProtocolMembership<G> + TranscriptProtocolRoot<G> + TranscriptProtocolModEq<G, P> + TranscriptProtocolHashToPrime<P>
> TranscriptProverChannel<'a, G, P, HP, T> {
    pub fn new(crs: &CRS<G, P, HP>, transcript: &'a RefCell<T>, proof: &Proof<G, P, HP>) -> TranscriptProverChannel<'a, G, P, HP, T> {
        TranscriptProverChannel {
            transcript,
            root_transcript_prover_channel: RootTranscriptProverChannel::new(&crs.crs_root, transcript, &proof.proof_root),
            modeq_transcript_prover_channel: ModEqTranscriptProverChannel::new(&crs.crs_modeq, transcript, &proof.proof_modeq),
            hash_to_prime_transcript_prover_channel: HashToPrimeTranscriptProverChannel::new(&crs.crs_hash_to_prime, transcript, &proof.proof_hash_to_prime),
            proof: proof.clone(),
        }
    }
}