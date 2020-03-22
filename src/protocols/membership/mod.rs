use algebra_core::ProjectiveCurve;
use crate::{
    utils::ConvertibleUnknownOrderGroup,
    parameters::Parameters,
    commitments::{
        integer::IntegerCommitment, pedersen::PedersenCommitment, CommitmentError,
    },
    protocols::{
        modeq::CRSModEq,
        root::CRSRoot,
        range::{CRSRangeProof, RangeProofProtocol},
    },
    channels::ChannelError,
};
use rug::rand::MutRandState;
use rand::Rng;
use rug::Integer;
use r1cs_core::SynthesisError;

quick_error! {
    #[derive(Debug)]
    pub enum SetupError {
        CouldNotPerformSetup {}
        SNARKError(err: SynthesisError) {
            from()
        }
    }
}

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
    }
}

pub struct CRS<G: ConvertibleUnknownOrderGroup, P: ProjectiveCurve, RP: RangeProofProtocol<P>> {
    // G contains the information about Z^*_N
    pub parameters: Parameters,
    pub crs_modeq: CRSModEq<G, P>,
    pub crs_root: CRSRoot<G>,
    pub crs_range: CRSRangeProof<P, RP>,
}

pub struct Protocol<G: ConvertibleUnknownOrderGroup, P: ProjectiveCurve, RP: RangeProofProtocol<P>> {
    pub crs: CRS<G, P, RP>,
}

impl<G: ConvertibleUnknownOrderGroup, P: ProjectiveCurve, RP: RangeProofProtocol<P>> Protocol<G, P, RP> {
    pub fn setup<R1: MutRandState, R2: Rng>(
        parameters: &Parameters,
        rng1: &mut R1,
        rng2: &mut R2,
    ) -> Result<Protocol<G, P, RP>, SetupError> {
        let integer_commitment_parameters = IntegerCommitment::<G>::setup(rng1);
        let pedersen_commitment_parameters = PedersenCommitment::<P>::setup(rng2);
        let range_proof_parameters = RP::setup(rng2, parameters.hash_to_prime_bits)?;
        Ok(Protocol {
            crs: CRS::<G, P, RP> {
                parameters: parameters.clone(),
                crs_modeq: CRSModEq::<G, P> {
                    parameters: parameters.clone(),
                    integer_commitment_parameters: integer_commitment_parameters.clone(),
                    pedersen_commitment_parameters: pedersen_commitment_parameters.clone(),
                },
                crs_root: CRSRoot::<G> {
                    parameters: parameters.clone(),
                    integer_commitment_parameters: integer_commitment_parameters.clone(),
                },
                crs_range: CRSRangeProof::<P, RP> {
                    parameters: parameters.clone(),
                    pedersen_commitment_parameters: pedersen_commitment_parameters.clone(),
                    range_proof_parameters: range_proof_parameters.clone(),
                }

            }
        })
    }
}
