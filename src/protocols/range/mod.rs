use rand::Rng;
use crate::{
    parameters::Parameters,
    protocols::membership_prime::{SetupError, ProofError, VerificationError},
    commitments::{
        Commitment,
        pedersen::PedersenCommitment
    },
};
use rug::Integer;
use algebra_core::ProjectiveCurve;
use merlin::Transcript;
use crate::transcript::TranscriptProtocolRange;

pub mod snark;

pub trait RangeProofProtocol<P: ProjectiveCurve> {
    type Proof;
    type Parameters: Clone;

    fn from_crs(
        crs: &CRSRangeProof<P, Self>
    ) -> Self
    where Self : Sized;

    fn setup<R: Rng>(rng: &mut R, hash_to_prime_bits: u16) -> Result<Self::Parameters, SetupError>;

    fn prove<'t, R: Rng>(
        &self,
        transcript: &'t mut Transcript,
        rng: &mut R,
        _: &Statement<P>,
        witness: &Witness,
    ) -> Result<Self::Proof, ProofError>
        where
            Transcript: TranscriptProtocolRange<P>;
    fn verify<'t>(
        &self,
        transcript: &'t mut Transcript,
        statement: &Statement<P>,
        proof: &Self::Proof,
    ) -> Result<(), VerificationError>
        where
            Transcript: TranscriptProtocolRange<P>;
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

