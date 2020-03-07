use algebra_core::ProjectiveCurve;
use crate::utils::ConvertibleUnknownOrderGroup;
use crate::parameters::Parameters;
use crate::commitments::{
    integer::IntegerCommitment, pedersen::PedersenCommitment,
};
use crate::protocols::modeq::CRSModEq;
use crate::protocols::root::CRSRoot;
use rug::rand::MutRandState;
use rand::Rng;

pub struct CRS<G: ConvertibleUnknownOrderGroup, P: ProjectiveCurve> {
    // G contains the information about Z^*_N
    pub parameters: Parameters,
    pub crs_modeq: CRSModEq<G, P>,
    pub crs_root: CRSRoot<G>,
}

pub struct Protocol<G: ConvertibleUnknownOrderGroup, P: ProjectiveCurve> {
    pub crs: CRS<G, P>,
}

impl<G: ConvertibleUnknownOrderGroup, P: ProjectiveCurve> Protocol<G, P> {
    pub fn setup<R1: MutRandState, R2: Rng>(
        parameters: &Parameters,
        rng1: &mut R1,
        rng2: &mut R2,
    ) -> Protocol<G, P> {
        let integer_commitment_parameters = IntegerCommitment::<G>::setup(rng1);
        let pedersen_commitment_parameters = PedersenCommitment::<P>::setup(rng2);
        Protocol {
            crs: CRS::<G, P> {
                parameters: parameters.clone(),
                crs_modeq: CRSModEq::<G, P> {
                    parameters: parameters.clone(),
                    integer_commitment_parameters: integer_commitment_parameters.clone(),
                    pedersen_commitment_parameters: pedersen_commitment_parameters.clone(),
                },
                crs_root: CRSRoot::<G> {
                    parameters: parameters.clone(),
                    integer_commitment_parameters: integer_commitment_parameters.clone(),
                }
            }
        }
    }
}
