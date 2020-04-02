use rand::{RngCore, CryptoRng};
use crate::{
    parameters::Parameters,
    channels::hash_to_prime::{HashToPrimeProverChannel, HashToPrimeVerifierChannel},
    protocols::membership::{SetupError, ProofError, VerificationError},
    commitments::{
        Commitment,
        pedersen::PedersenCommitment
    },
    utils::curve::CurvePointProjective,
};
use rug::Integer;

#[cfg(feature = "zexe")]
pub mod snark_range;
#[cfg(feature = "zexe")]
pub mod snark_hash;

#[cfg(feature = "dalek")]
pub mod bp;

pub trait HashToPrimeProtocol<P: CurvePointProjective> {
    type Proof: Clone;
    type Parameters: Clone;

    fn from_crs(
        crs: &CRSHashToPrime<P, Self>
    ) -> Self
    where Self : Sized;

    fn setup<R: RngCore + CryptoRng>(rng: &mut R, pedersen_commitment_parameters: &PedersenCommitment<P>, parameters: &Parameters) -> Result<Self::Parameters, SetupError>;

    fn prove<R: RngCore + CryptoRng, C: HashToPrimeVerifierChannel<P, Self>> (
        &self,
        verifier_channel: &mut C,
        rng: &mut R,
        _: &Statement<P>,
        witness: &Witness,
    ) -> Result<(), ProofError>
        where
            Self: Sized;
    fn verify<C: HashToPrimeProverChannel<P, Self>>(
        &self,
        prover_channel: &mut C,
        statement: &Statement<P>,
    ) -> Result<(), VerificationError>
        where
            Self: Sized;
    fn hash_to_prime(&self, e: &Integer) -> Result<(Integer, u64), HashToPrimeError>;
}

pub struct CRSHashToPrime<P: CurvePointProjective, HP: HashToPrimeProtocol<P>> {
    pub parameters: Parameters,
    pub pedersen_commitment_parameters: PedersenCommitment<P>,
    pub hash_to_prime_parameters: HP::Parameters,
}

impl<P: CurvePointProjective, HP: HashToPrimeProtocol<P>> Clone for CRSHashToPrime<P, HP> {
    fn clone(&self) -> Self {
        Self {
            parameters: self.parameters.clone(),
            pedersen_commitment_parameters: self.pedersen_commitment_parameters.clone(),
            hash_to_prime_parameters: self.hash_to_prime_parameters.clone(),
        }
    }
}

pub struct Statement<P: CurvePointProjective> {
    pub c_e_q: <PedersenCommitment<P> as Commitment>::Instance,
}

pub struct Witness {
    pub e: Integer,
    pub r_q: Integer,
}

quick_error! {
    #[derive(Debug)]
    pub enum HashToPrimeError {
        CouldNotFindIndex {}
        ValueTooBig {}
        IntegerError(num: Integer) {
            from()
        }
    }
}

