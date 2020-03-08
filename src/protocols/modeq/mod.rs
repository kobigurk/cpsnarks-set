use crate::commitments::{
    integer::IntegerCommitment, pedersen::PedersenCommitment, Commitment,
};
use crate::parameters::Parameters;
use crate::transcript::{TranscriptProtocolModEq, TranscriptProtocolChallenge, TranscriptProtocolCurve, TranscriptProtocolInteger};
use crate::utils::{bigint_to_integer, integer_mod_q, random_symmetric_range, ConvertibleUnknownOrderGroup, integer_to_bigint_mod_q};
use algebra_core::{PrimeField, ProjectiveCurve, UniformRand};
use merlin::Transcript;
use rand::Rng;
use rug::rand::MutRandState;
use rug::Integer;
use crate::protocols::membership_prime::{ProofError, VerificationError};

#[derive(Clone)]
pub struct CRSModEq<G: ConvertibleUnknownOrderGroup, P: ProjectiveCurve> {
    // G contains the information about Z^*_N
    pub parameters: Parameters,
    pub integer_commitment_parameters: IntegerCommitment<G>, // G, H
    pub pedersen_commitment_parameters: PedersenCommitment<P>, // g, h
}

pub struct Statement<G: ConvertibleUnknownOrderGroup, P: ProjectiveCurve> {
    pub c_e: <IntegerCommitment<G> as Commitment>::Instance,
    pub c_e_q: <PedersenCommitment<P> as Commitment>::Instance,
}

pub struct Witness {
    pub e: Integer,
    pub r: Integer,
    pub r_q: Integer,
}

pub struct Message1<G: ConvertibleUnknownOrderGroup, P: ProjectiveCurve> {
    pub alpha1: <IntegerCommitment<G> as Commitment>::Instance,
    pub alpha2: <PedersenCommitment<P> as Commitment>::Instance,
}

pub struct Message2<P: ProjectiveCurve> {
    pub s_e: Integer,
    pub s_r: Integer,
    pub s_r_q: P::ScalarField,
}

pub struct Proof<G: ConvertibleUnknownOrderGroup, P: ProjectiveCurve> {
    pub message1: Message1<G, P>,
    pub message2: Message2<P>,
}

pub struct Protocol<G: ConvertibleUnknownOrderGroup, P: ProjectiveCurve> {
    pub crs: CRSModEq<G, P>,
}

impl<G: ConvertibleUnknownOrderGroup, P: ProjectiveCurve> Protocol<G, P> {
    pub fn from_crs(
        crs: &CRSModEq<G, P>
    ) -> Protocol<G, P> {
        Protocol {
            crs: crs.clone(),
        }
    }

    pub fn prove<'t, R1: MutRandState, R2: Rng>(
        &self,
        transcript: &'t mut Transcript,
        rng1: &mut R1,
        rng2: &mut R2,
        _: &Statement<G, P>,
        witness: &Witness,
    ) -> Result<Proof<G, P>, ProofError>
    where
        Transcript: TranscriptProtocolModEq<G, P>,
    {
        let r_e_range = Integer::from(Integer::u_pow_u(
            2,
            (self.crs.parameters.security_zk
                + self.crs.parameters.security_soundness
                + self.crs.parameters.hash_to_prime_bits) as u32,
        ));
        let r_e = random_symmetric_range(rng1, &r_e_range);
        let r_r_range = Integer::from(
            G::order_upper_bound() / 4
                * Integer::from(Integer::u_pow_u(
                    2,
                    (self.crs.parameters.security_zk + self.crs.parameters.security_soundness)
                        as u32,
                )),
        );
        let r_r = random_symmetric_range(rng1, &r_r_range);
        assert!(
            self.crs.parameters.field_size_bits as usize
                >= <P::ScalarField as PrimeField>::size_in_bits()
        );
        let r_r_q_field = P::ScalarField::rand(rng2);
        let r_r_q = bigint_to_integer::<P>(&r_r_q_field.into_repr());

        let alpha1 = self.crs.integer_commitment_parameters.commit(&r_e, &r_r)?;
        let alpha2 = self
            .crs
            .pedersen_commitment_parameters
            .commit(&integer_mod_q::<P>(&r_e)?, &r_r_q)?;

        transcript.append_integer_point(b"alpha1", &alpha1);
        transcript.append_curve_point(b"alpha2", &alpha2);

        let message1 = Message1::<G, P> { alpha1, alpha2 };

        let c = transcript.challenge_scalar(b"c", self.crs.parameters.security_soundness);
        let r_q = P::ScalarField::from_repr(integer_to_bigint_mod_q::<P>(&witness.r_q.clone())?);
        let s_e = r_e - c.clone() * witness.e.clone();
        let s_r = r_r - c.clone() * witness.r.clone();
        let c_big = integer_to_bigint_mod_q::<P>(&c)?;
        let s_r_q = r_r_q_field - &(r_q * &P::ScalarField::from_repr(c_big));

        let message2 = Message2::<P> { s_e, s_r, s_r_q };

        Ok(Proof { message1, message2 })
    }

    pub fn verify<'t>(
        &self,
        transcript: &'t mut Transcript,
        statement: &Statement<G, P>,
        proof: &Proof<G, P>,
    ) -> Result<(), VerificationError>
    where
        Transcript: TranscriptProtocolModEq<G, P>,
    {
        transcript.append_integer_point(b"alpha1", &proof.message1.alpha1);
        transcript.append_curve_point(b"alpha2", &proof.message1.alpha2);
        let c = transcript.challenge_scalar(b"c", self.crs.parameters.security_soundness);

        let commitment2 = self.crs.integer_commitment_parameters.commit(&proof.message2.s_e, &proof.message2.s_r)?;
        let commitment2_extra = G::exp(&statement.c_e, &c);
        let expected_alpha1 = G::op(&commitment2, &commitment2_extra);

        let s_e_mod_q = integer_mod_q::<P>(&proof.message2.s_e)?;
        let s_r_q_int = bigint_to_integer::<P>(&proof.message2.s_r_q.into_repr());
        let commitment1 = self.crs.pedersen_commitment_parameters.commit(&s_e_mod_q, &s_r_q_int)?;
        let c_big = integer_to_bigint_mod_q::<P>(&c)?;
        let commitment1_extra = statement.c_e_q.mul(P::ScalarField::from_repr(c_big));
        let expected_alpha2 = commitment1 + &commitment1_extra;

        if expected_alpha1 == proof.message1.alpha1 && expected_alpha2 == proof.message1.alpha2 {
            Ok(())
        } else {
            Err(VerificationError::VerificationFailed)
        }
    }
}

#[cfg(test)]
mod test {
    use rug::Integer;
    use algebra::jubjub::JubJubProjective;
    use rand_xorshift::XorShiftRng;
    use rand::SeedableRng;
    use crate::commitments::Commitment;
    use rug::rand::RandState;
    use accumulator::group::Rsa2048;
    use super::{Protocol, Statement, Witness};
    use crate::parameters::Parameters;
    use merlin::Transcript;

    #[test]
    fn test_proof() {
        let params = Parameters::from_security_level(128).unwrap();
        let mut rng1 = RandState::new();
        rng1.seed(&Integer::from(13));
        let mut rng2 = XorShiftRng::seed_from_u64(1231275789u64);

        let crs = crate::protocols::membership_prime::Protocol::<Rsa2048, JubJubProjective>::setup(&params, &mut rng1, &mut rng2).crs.crs_modeq;
        let protocol = Protocol::<Rsa2048, JubJubProjective>::from_crs(&crs);

        let value1 = Integer::from(2);
        let randomness1 = Integer::from(5);
        let randomness2 = Integer::from(9);
        let commitment1 = protocol.crs.integer_commitment_parameters.commit(&value1, &randomness1).unwrap();
        let commitment2 = protocol.crs.pedersen_commitment_parameters.commit(&value1, &randomness2).unwrap();

        let mut proof_transcript = Transcript::new(b"modeq");
        let statement = Statement {
            c_e: commitment1,
            c_e_q: commitment2,
        };
        let proof = protocol.prove(&mut proof_transcript, &mut rng1, &mut rng2, &statement, &Witness {
            e: value1,
            r: randomness1,
            r_q: randomness2,
        }).unwrap();

        let mut verification_transcript = Transcript::new(b"modeq");
        protocol.verify(&mut verification_transcript, &statement, &proof).unwrap();
    }

}
