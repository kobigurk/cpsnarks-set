use rug::Integer;
use rug::rand::MutRandState;
use crate::{
    commitments::{CommitmentError, Commitment},
    utils::ConvertibleUnknownOrderGroup,
};

#[derive(Clone)]
pub struct IntegerCommitment<G: ConvertibleUnknownOrderGroup> {
    pub g: G::Elem,
    pub h: G::Elem,
}

impl<G: ConvertibleUnknownOrderGroup> IntegerCommitment<G> {
    pub fn setup<R: MutRandState>(rng: &mut R) -> IntegerCommitment<G> {
        let upper_bound = G::order_upper_bound();
        //TODO: should do N/2? how to generalize?
        let g = G::elem(Integer::from(upper_bound.clone()/2).random_below(rng));
        let h = G::exp(&g, &upper_bound.random_below(rng));
        IntegerCommitment {
            g,
            h,
        }
    }

    pub fn new(g: &G::Elem, h: &G::Elem) -> IntegerCommitment<G> {
        IntegerCommitment {
            g: g.clone(),
            h: h.clone(),
        }
    }
}

impl<G: ConvertibleUnknownOrderGroup> Commitment for IntegerCommitment<G> {
    type Instance = G::Elem;

    fn commit(&self, value: &Integer, randomness: &Integer) -> Result<Self::Instance, CommitmentError> {
        Ok(G::op(&G::exp(&self.g, value), &G::exp(&self.h, randomness)))
    }

    fn open(&self, commitment: &Self::Instance, value: &Integer, randomness: &Integer) -> Result<(), CommitmentError> {
        let expected = G::op(&G::exp(&self.g, value), &G::exp(&self.h, randomness));
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
    use rug::rand::RandState;
    use super::IntegerCommitment;
    use crate::commitments::Commitment;
    use accumulator::group::Rsa2048;

    #[test]
    fn test_simple_commitment() {
        let mut rng = RandState::new();
        rng.seed(&Integer::from(13));

        let value = Integer::from(2);
        let randomness = Integer::from(5);
        let integer = IntegerCommitment::<Rsa2048>::setup(&mut rng);
        let commitment = integer.commit(&value, &randomness).unwrap();
        integer.open(&commitment, &value, &randomness).unwrap();
        let wrong_value = Integer::from(5);
        integer.open(&commitment, &wrong_value, &randomness).unwrap_err();
        let wrong_randomness = Integer::from(7);
        integer.open(&commitment, &value, &wrong_randomness).unwrap_err();
        integer.open(&commitment, &wrong_value, &wrong_randomness).unwrap_err();
    }
}
