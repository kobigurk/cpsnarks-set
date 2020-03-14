use algebra_core::ProjectiveCurve;
use rand::Rng;
use crate::commitments::{CommitmentError, Commitment};
use rug::Integer;
use crate::utils::integer_to_bigint;

#[derive(Clone)]
pub struct PedersenCommitment<P: ProjectiveCurve> {
    g: P,
    h: P,
}

impl<P: ProjectiveCurve> PedersenCommitment<P> {
    pub fn setup<R: Rng>(rng: &mut R) -> PedersenCommitment<P> {
        PedersenCommitment {
            g: P::rand(rng),
            h: P::rand(rng),
        }
    }

    pub fn new(g: &P, h: &P) -> PedersenCommitment<P> {
        PedersenCommitment {
            g: g.clone(),
            h: h.clone(),
        }
    }


}
impl<P: ProjectiveCurve> Commitment for PedersenCommitment<P> {
    type Instance = P;

    fn commit(&self, value: &Integer, randomness: &Integer)
        -> Result<Self::Instance, CommitmentError> {
        let v = integer_to_bigint::<P>(value);
        let r = integer_to_bigint::<P>(randomness);
        Ok(self.g.mul(v) +
            &self.h.mul(r))
    }

    fn open(&self, commitment: &Self::Instance, value: &Integer, randomness: &Integer)
        -> Result<(), CommitmentError> {
        let expected = self.g.mul(integer_to_bigint::<P>(value)) +
            &self.h.mul(integer_to_bigint::<P>(randomness));
        if expected == *commitment {
            Ok(())
        } else {
            Err(CommitmentError::WrongOpening)
        }
    }
}

#[cfg(test)]
mod test {
    use rug::Integer;
    use super::PedersenCommitment;
    use algebra::bls12_381::G1Projective;
    use rand_xorshift::XorShiftRng;
    use rand::SeedableRng;
    use crate::commitments::Commitment;

    #[test]
    fn test_simple_commitment() {
        let mut rng = XorShiftRng::seed_from_u64(1231275789u64);

        let value = Integer::from(2);
        let randomness = Integer::from(5);
        let pedersen = PedersenCommitment::<G1Projective>::setup(&mut rng);
        let commitment = pedersen.commit(&value, &randomness).unwrap();
        pedersen.open(&commitment, &value, &randomness).unwrap();
        let wrong_value = Integer::from(5);
        pedersen.open(&commitment, &wrong_value, &randomness).unwrap_err();
        let wrong_randomness = Integer::from(7);
        pedersen.open(&commitment, &value, &wrong_randomness).unwrap_err();
        pedersen.open(&commitment, &wrong_value, &wrong_randomness).unwrap_err();
    }
}