use rand::Rng;
use crate::{
    parameters::Parameters,
    channels::range::{RangeProverChannel, RangeVerifierChannel},
    protocols::membership_prime::{SetupError, ProofError, VerificationError},
    commitments::{
        Commitment,
        pedersen::PedersenCommitment
    },
};
use rug::Integer;
use algebra_core::ProjectiveCurve;

pub mod snark;

pub trait RangeProofProtocol<P: ProjectiveCurve> {
    type Proof: Clone;
    type Parameters: Clone;

    fn from_crs(
        crs: &CRSRangeProof<P, Self>
    ) -> Self
    where Self : Sized;

    fn setup<R: Rng>(rng: &mut R, hash_to_prime_bits: u16) -> Result<Self::Parameters, SetupError>;

    fn prove<R: Rng, C: RangeVerifierChannel<P, Self>> (
        &self,
        verifier_channel: &mut C,
        rng: &mut R,
        _: &Statement<P>,
        witness: &Witness,
    ) -> Result<(), ProofError>
        where
            Self: Sized;
    fn verify<C: RangeProverChannel<P, Self>>(
        &self,
        prover_channel: &mut C,
        statement: &Statement<P>,
    ) -> Result<(), VerificationError>
        where
            Self: Sized;
}

pub struct CRSRangeProof<P: ProjectiveCurve, RP: RangeProofProtocol<P>> {
    pub parameters: Parameters,
    pub pedersen_commitment_parameters: PedersenCommitment<P>,
    pub range_proof_parameters: RP::Parameters,
}

impl<P: ProjectiveCurve, RP: RangeProofProtocol<P>> Clone for CRSRangeProof<P, RP> {
    fn clone(&self) -> Self {
        Self {
            parameters: self.parameters.clone(),
            pedersen_commitment_parameters: self.pedersen_commitment_parameters.clone(),
            range_proof_parameters: self.range_proof_parameters.clone(),
        }
    }
}

pub struct Statement<P: ProjectiveCurve> {
    pub c_e_q: <PedersenCommitment<P> as Commitment>::Instance,
}

pub struct Witness {
    pub e: Integer,
    pub r_q: Integer,
}

