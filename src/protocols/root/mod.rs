use crate::commitments::integer::IntegerCommitment;
use crate::parameters::Parameters;
use crate::utils::ConvertibleUnknownOrderGroup;

pub struct CRSRoot<G: ConvertibleUnknownOrderGroup> {
    // G contains the information about Z^*_N
    pub parameters: Parameters,
    pub integer_commitment_parameters: IntegerCommitment<G>, // G, H
}


