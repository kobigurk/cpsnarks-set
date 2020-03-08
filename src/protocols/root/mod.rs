use crate::commitments::{
    Commitment,
    integer::IntegerCommitment,
};
use crate::parameters::Parameters;
use crate::utils::{ConvertibleUnknownOrderGroup, random_symmetric_range};
use rug::Integer;
use rug::rand::MutRandState;
use merlin::Transcript;
use crate::transcript::{TranscriptProtocolRoot, TranscriptProtocolInteger, TranscriptProtocolChallenge};
use crate::protocols::membership_prime::{ProofError, VerificationError};

#[derive(Clone)]
pub struct CRSRoot<G: ConvertibleUnknownOrderGroup> {
    // G contains the information about Z^*_N
    pub parameters: Parameters,
    pub integer_commitment_parameters: IntegerCommitment<G>, // G, H
}
pub struct Statement<G: ConvertibleUnknownOrderGroup> {
    pub c_e: <IntegerCommitment<G> as Commitment>::Instance,
    pub acc: G::Elem,
}

pub struct Witness<G: ConvertibleUnknownOrderGroup> {
    pub e: Integer,
    pub r: Integer,
    pub w: G::Elem,
}

pub struct Message1<G: ConvertibleUnknownOrderGroup> {
    pub c_w: G::Elem,
    pub c_r: <IntegerCommitment<G> as Commitment>::Instance,
}

pub struct Message2<G: ConvertibleUnknownOrderGroup> {
    pub alpha1: <IntegerCommitment<G> as Commitment>::Instance,
    pub alpha2: <IntegerCommitment<G> as Commitment>::Instance,
    pub alpha3: <IntegerCommitment<G> as Commitment>::Instance,
    pub alpha4: G::Elem,
}

pub struct Message3 {
    pub s_e: Integer,
    pub s_r: Integer,
    pub s_r_2: Integer,
    pub s_r_3: Integer,
    pub s_beta: Integer,
    pub s_delta: Integer,
}

pub struct Proof<G: ConvertibleUnknownOrderGroup> {
    pub message1: Message1<G>,
    pub message2: Message2<G>,
    pub message3: Message3,
}

pub struct Protocol<G: ConvertibleUnknownOrderGroup> {
    pub crs: CRSRoot<G>,
}

impl<G: ConvertibleUnknownOrderGroup> Protocol<G> {
    pub fn from_crs(
        crs: &CRSRoot<G>
    ) -> Protocol<G> {
        Protocol {
            crs: crs.clone(),
        }
    }

    pub fn prove<'t, R: MutRandState>(
        &self,
        transcript: &'t mut Transcript,
        rng: &mut R,
        _: &Statement<G>,
        witness: &Witness<G>,
    ) -> Result<Proof<G>, ProofError>
        where
            Transcript: TranscriptProtocolRoot<G>,
    {
        let r_2 = random_symmetric_range(rng, &Integer::from(G::order_upper_bound()/4));
        let r_3 = random_symmetric_range(rng, &Integer::from(G::order_upper_bound()/4));
        let c_w = G::op(&witness.w, &G::exp(&self.crs.integer_commitment_parameters.h, &r_2));
        let c_r = self.crs.integer_commitment_parameters.commit(&r_2, &r_3)?;

        transcript.append_integer_point(b"c_w", &c_w);
        transcript.append_integer_point(b"c_r", &c_r);
        let message1 = Message1::<G> { c_w, c_r };

        let r_e_range = Integer::from(Integer::u_pow_u(
            2,
            (self.crs.parameters.security_zk
                + self.crs.parameters.security_soundness
                + self.crs.parameters.hash_to_prime_bits) as u32,
        ));
        let r_e = random_symmetric_range(rng, &r_e_range);

        let r_r_range = Integer::from(
            G::order_upper_bound() / 4
                * Integer::from(Integer::u_pow_u(
                2,
                (self.crs.parameters.security_zk + self.crs.parameters.security_soundness)
                    as u32,
            )),
        );
        let r_r = random_symmetric_range(rng, &r_r_range);
        let r_r_2 = random_symmetric_range(rng, &r_r_range);
        let r_r_3 = random_symmetric_range(rng, &r_r_range);

        let r_beta_delta_range = Integer::from(
            G::order_upper_bound() / 4
                * Integer::from(Integer::u_pow_u(
                2,
                (self.crs.parameters.security_zk
                    + self.crs.parameters.security_soundness
                    + self.crs.parameters.hash_to_prime_bits)
                    as u32,
            )),
        );
        let r_beta = random_symmetric_range(rng, &r_beta_delta_range);
        let r_delta = random_symmetric_range(rng, &r_beta_delta_range);

        let alpha1 = self.crs.integer_commitment_parameters.commit(&r_e, &r_r)?;
        let alpha2 = self.crs.integer_commitment_parameters.commit(&r_r_2, &r_r_3)?;
        let integer_commitment_alpha3 = IntegerCommitment::<G>::new(
            &message1.c_w,
            &G::inv(&self.crs.integer_commitment_parameters.h),
        );
        let alpha3 = integer_commitment_alpha3.commit(&r_e, &r_beta)?;
        let integer_commitment_alpha4 = IntegerCommitment::<G>::new(
            &G::inv(&self.crs.integer_commitment_parameters.h),
            &G::inv(&self.crs.integer_commitment_parameters.g),
        );
        let alpha4 = G::op(
            &G::exp(&message1.c_r, &r_e),
            &integer_commitment_alpha4.commit(&r_delta, &r_beta)?,
        );
        transcript.append_integer_point(b"alpha1", &alpha1);
        transcript.append_integer_point(b"alpha2", &alpha2);
        transcript.append_integer_point(b"alpha3", &alpha3);
        transcript.append_integer_point(b"alpha4", &alpha4);
        let message2 = Message2::<G> {
            alpha1,
            alpha2,
            alpha3,
            alpha4
        };

        let c = transcript.challenge_scalar(b"c", self.crs.parameters.security_soundness);
        let s_e = r_e - c.clone() * witness.e.clone();
        let s_r = r_r - c.clone() * witness.r.clone();
        let s_r_2 = r_r_2 - c.clone() * r_2.clone();
        let s_r_3 = r_r_3 - c.clone() * r_3.clone();
        let s_beta = r_beta - c.clone() * witness.e.clone() * r_2.clone();
        let s_delta = r_delta - c.clone() * witness.e.clone() * r_3.clone();
        let message3 = Message3 {
            s_e,
            s_r,
            s_r_2,
            s_r_3,
            s_beta,
            s_delta,
        };
        Ok(Proof::<G> {
            message1,
            message2,
            message3,
        })
    }

    pub fn verify<'t>(
        &self,
        transcript: &'t mut Transcript,
        statement: &Statement<G>,
        proof: &Proof<G>,
    ) -> Result<(), VerificationError>
        where
            Transcript: TranscriptProtocolRoot<G>,
    {
        transcript.append_integer_point(b"c_w", &proof.message1.c_w);
        transcript.append_integer_point(b"c_r", &proof.message1.c_r);
        transcript.append_integer_point(b"alpha1", &proof.message2.alpha1);
        transcript.append_integer_point(b"alpha2", &proof.message2.alpha2);
        transcript.append_integer_point(b"alpha3", &proof.message2.alpha3);
        transcript.append_integer_point(b"alpha4", &proof.message2.alpha4);
        let c = transcript.challenge_scalar(b"c", self.crs.parameters.security_soundness);
        let expected_alpha1 = G::op(
            &G::exp(&statement.c_e, &c),
            &self.crs.integer_commitment_parameters.commit(&proof.message3.s_e, &proof.message3.s_r)?
        );
        let expected_alpha2 = G::op(
            &G::exp(&proof.message1.c_r, &c),
            &self.crs.integer_commitment_parameters.commit(&proof.message3.s_r_2, &proof.message3.s_r_3)?
        );
        let integer_commitment_alpha3 = IntegerCommitment::<G>::new(
            &proof.message1.c_w,
            &G::inv(&self.crs.integer_commitment_parameters.h),
        );
        let expected_alpha3 = G::op(
            &G::exp(&statement.acc, &c),
            &integer_commitment_alpha3.commit(&proof.message3.s_e, &proof.message3.s_beta)?,
        );
        let integer_commitment_alpha4 = IntegerCommitment::<G>::new(
            &G::inv(&self.crs.integer_commitment_parameters.h),
            &G::inv(&self.crs.integer_commitment_parameters.g),
        );
        let expected_alpha4 = G::op(
            &G::exp(&proof.message1.c_r, &proof.message3.s_e),
            &integer_commitment_alpha4.commit(&proof.message3.s_delta, &proof.message3.s_beta)?,
        );

        if expected_alpha1 == proof.message2.alpha1 &&
            expected_alpha2 == proof.message2.alpha2 &&
            expected_alpha3 == proof.message2.alpha3 &&
            expected_alpha4 == proof.message2.alpha4 {
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
    use accumulator::group::{Group, Rsa2048};
    use super::{Protocol, Statement, Witness};
    use crate::parameters::Parameters;
    use merlin::Transcript;
    use accumulator::AccumulatorWithoutHashToPrime;

    const LARGE_PRIMES: [u64; 4] = [
        553_525_575_239_331_913,
        12_702_637_924_034_044_211,
        378_373_571_372_703_133,
        8_640_171_141_336_142_787,
    ];

    #[test]
    fn test_proof() {
        let params = Parameters::from_security_level(128).unwrap();
        let mut rng1 = RandState::new();
        rng1.seed(&Integer::from(13));
        let mut rng2 = XorShiftRng::seed_from_u64(1231275789u64);

        let crs = crate::protocols::membership_prime::Protocol::<Rsa2048, JubJubProjective>::setup(&params, &mut rng1, &mut rng2).crs.crs_root;
        let protocol = Protocol::<Rsa2048>::from_crs(&crs);

        let value = Integer::from(LARGE_PRIMES[0]);
        let randomness = Integer::from(5);
        let commitment = protocol.crs.integer_commitment_parameters.commit(&value, &randomness).unwrap();

        let accum = accumulator::Accumulator::<Rsa2048, Integer, AccumulatorWithoutHashToPrime>::empty();
        let accum = accum.add(&LARGE_PRIMES.iter().skip(1).map(|p| Integer::from(*p)).collect::<Vec<_>>());

        let accum = accum.add_with_proof(&[value.clone()]);
        let acc = accum.0.value;
        let w = accum.1.witness.0.value;
        assert_eq!(Rsa2048::exp(&w, &value), acc);

        let mut proof_transcript = Transcript::new(b"root");
        let statement = Statement {
            c_e: commitment,
            acc,
        };
        let proof = protocol.prove(&mut proof_transcript, &mut rng1, &statement, &Witness {
            e: value,
            r: randomness,
            w,
        }).unwrap();

        let mut verification_transcript = Transcript::new(b"root");
        protocol.verify(&mut verification_transcript, &statement, &proof).unwrap();
    }

}
