use crate::{channels::ChannelError, commitments::CommitmentError, protocols::hash_to_prime::HashToPrimeError};
use r1cs_core::SynthesisError;
use rug::Integer;

pub mod root;
pub mod coprime;
pub mod modeq;
pub mod hash_to_prime;
pub mod membership;
pub mod nonmembership;

quick_error! {
    #[derive(Debug)]
    pub enum SetupError {
        CouldNotPerformSetup {}
        SNARKError(err: SynthesisError) {
            from()
        }
    }
}


#[cfg(feature = "dalek")]
type R1CSError = bulletproofs::r1cs::R1CSError;

#[cfg(feature = "zexe")]
quick_error! {
    #[derive(Debug)]
    pub enum DummyBPError {}
}
#[cfg(feature = "zexe")]
type R1CSError = DummyBPError;


quick_error! {
    #[derive(Debug)]
    pub enum ProofError {
        CouldNotCreateProof {}
        CommitmentError(err: CommitmentError) {
            from()
        }
        IntegerError(err: Integer) {
            from()
        }
        SNARKError(err: SynthesisError) {
            from()
        }
        VerifierChannelError(err: ChannelError) {
            from()
        }
        PrimeError(err: HashToPrimeError) {
            from()
        }
        BPError(err: R1CSError) {
            from()
        }
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum VerificationError {
        VerificationFailed {}
        CommitmentError(err: CommitmentError) {
            from()
        }
        IntegerError(err: Integer) {
            from()
        }
        SNARKError(err: SynthesisError) {
            from()
        }
        ProverChannelError(err: ChannelError) {
            from()
        }
        BPError(err: R1CSError) {
            from()
        }
    }
}