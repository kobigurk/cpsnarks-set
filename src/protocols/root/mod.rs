use crate::{
    channels::root::{RootProverChannel, RootVerifierChannel},
    commitments::{integer::IntegerCommitment, Commitment},
    parameters::Parameters,
    protocols::{ProofError, VerificationError},
    utils::{random_symmetric_range, ConvertibleUnknownOrderGroup},
};
use rug::rand::MutRandState;
use rug::Integer;

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

#[derive(Clone)]
pub struct Message1<G: ConvertibleUnknownOrderGroup> {
    pub c_w: G::Elem,
    pub c_r: <IntegerCommitment<G> as Commitment>::Instance,
}

#[derive(Clone)]
pub struct Message2<G: ConvertibleUnknownOrderGroup> {
    pub alpha1: <IntegerCommitment<G> as Commitment>::Instance,
    pub alpha2: <IntegerCommitment<G> as Commitment>::Instance,
    pub alpha3: <IntegerCommitment<G> as Commitment>::Instance,
    pub alpha4: G::Elem,
}

#[derive(Clone)]
pub struct Message3 {
    pub s_e: Integer,
    pub s_r: Integer,
    pub s_r_2: Integer,
    pub s_r_3: Integer,
    pub s_beta: Integer,
    pub s_delta: Integer,
}

#[derive(Clone)]
pub struct Proof<G: ConvertibleUnknownOrderGroup> {
    pub message1: Message1<G>,
    pub message2: Message2<G>,
    pub message3: Message3,
}

pub struct Protocol<G: ConvertibleUnknownOrderGroup> {
    pub crs: CRSRoot<G>,
}

impl<G: ConvertibleUnknownOrderGroup> Protocol<G> {
    pub fn from_crs(crs: &CRSRoot<G>) -> Protocol<G> {
        Protocol { crs: crs.clone() }
    }

    pub fn prove<R: MutRandState, C: RootVerifierChannel<G>>(
        &self,
        verifier_channel: &mut C,
        rng: &mut R,
        _: &Statement<G>,
        witness: &Witness<G>,
    ) -> Result<(), ProofError> {
        let r_2 = random_symmetric_range(rng, &(G::order_upper_bound() / Integer::from(2)));
        let r_3 = random_symmetric_range(rng, &(G::order_upper_bound() / Integer::from(2)));
        let c_w = G::op(
            &witness.w,
            &G::exp(&self.crs.integer_commitment_parameters.h, &r_2),
        );
        let c_r = self.crs.integer_commitment_parameters.commit(&r_2, &r_3)?;

        let message1 = Message1::<G> { c_w, c_r };
        verifier_channel.send_message1(&message1)?;

        let r_e_range = Integer::from(Integer::u_pow_u(
            2,
            (self.crs.parameters.security_zk
                + self.crs.parameters.security_soundness
                + self.crs.parameters.hash_to_prime_bits) as u32,
        ));
        let r_e = random_symmetric_range(rng, &r_e_range);

        let r_r_range: Integer = 
            G::order_upper_bound() / 2
                * Integer::from(Integer::u_pow_u(
                    2,
                    (self.crs.parameters.security_zk + self.crs.parameters.security_soundness)
                        as u32,
                ));
        let r_r = random_symmetric_range(rng, &r_r_range);
        let r_r_2 = random_symmetric_range(rng, &r_r_range);
        let r_r_3 = random_symmetric_range(rng, &r_r_range);

        let r_beta_delta_range: Integer = 
            G::order_upper_bound() / 2
                * Integer::from(Integer::u_pow_u(
                    2,
                    (self.crs.parameters.security_zk
                        + self.crs.parameters.security_soundness
                        + self.crs.parameters.hash_to_prime_bits) as u32,
                ));
        let r_beta = random_symmetric_range(rng, &r_beta_delta_range);
        let r_delta = random_symmetric_range(rng, &r_beta_delta_range);

        let alpha1 = self.crs.integer_commitment_parameters.commit(&r_e, &r_r)?;
        let alpha2 = self
            .crs
            .integer_commitment_parameters
            .commit(&r_r_2, &r_r_3)?;
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
        let message2 = Message2::<G> {
            alpha1,
            alpha2,
            alpha3,
            alpha4,
        };
        verifier_channel.send_message2(&message2)?;

        let c = verifier_channel.receive_challenge()?;
        let s_e = r_e - c.clone() * witness.e.clone();
        let s_r = r_r - c.clone() * witness.r.clone();
        let s_r_2 = r_r_2 - c.clone() * r_2.clone();
        let s_r_3 = r_r_3 - c.clone() * r_3.clone();
        let s_beta = r_beta - c.clone() * witness.e.clone() * r_2;
        let s_delta = r_delta - c * witness.e.clone() * r_3;
        let message3 = Message3 {
            s_e,
            s_r,
            s_r_2,
            s_r_3,
            s_beta,
            s_delta,
        };
        verifier_channel.send_message3(&message3)?;

        Ok(())
    }

    pub fn verify<C: RootProverChannel<G>>(
        &self,
        prover_channel: &mut C,
        statement: &Statement<G>,
    ) -> Result<(), VerificationError> {
        let message1 = prover_channel.receive_message1()?;
        let message2 = prover_channel.receive_message2()?;
        let c = prover_channel.generate_and_send_challenge()?;
        let message3 = prover_channel.receive_message3()?;
        let expected_alpha1 = G::op(
            &G::exp(&statement.c_e, &c),
            &self
                .crs
                .integer_commitment_parameters
                .commit(&message3.s_e, &message3.s_r)?,
        );
        let expected_alpha2 = G::op(
            &G::exp(&message1.c_r, &c),
            &self
                .crs
                .integer_commitment_parameters
                .commit(&message3.s_r_2, &message3.s_r_3)?,
        );
        let integer_commitment_alpha3 = IntegerCommitment::<G>::new(
            &message1.c_w,
            &G::inv(&self.crs.integer_commitment_parameters.h),
        );
        let expected_alpha3 = G::op(
            &G::exp(&statement.acc, &c),
            &integer_commitment_alpha3.commit(&message3.s_e, &message3.s_beta)?,
        );
        let integer_commitment_alpha4 = IntegerCommitment::<G>::new(
            &G::inv(&self.crs.integer_commitment_parameters.h),
            &G::inv(&self.crs.integer_commitment_parameters.g),
        );
        let expected_alpha4 = G::op(
            &G::exp(&message1.c_r, &message3.s_e),
            &integer_commitment_alpha4.commit(&message3.s_delta, &message3.s_beta)?,
        );

        let s_e_expected_right = Integer::from(Integer::u_pow_u(
            2,
            (self.crs.parameters.security_zk
                + self.crs.parameters.security_soundness
                + self.crs.parameters.hash_to_prime_bits
                + 1) as u32,
        ));

        let s_e_expected_left: Integer = -s_e_expected_right.clone();
        let is_s_e_in_range =
            message3.s_e >= s_e_expected_left && message3.s_e <= s_e_expected_right;

        if expected_alpha1 == message2.alpha1
            && expected_alpha2 == message2.alpha2
            && expected_alpha3 == message2.alpha3
            && expected_alpha4 == message2.alpha4
            && is_s_e_in_range
        {
            Ok(())
        } else {
            Err(VerificationError::VerificationFailed)
        }
    }
}

#[cfg(all(test, feature = "zexe"))]
mod test {
    use super::{Protocol, Statement, Witness};
    use crate::{
        commitments::Commitment,
        parameters::Parameters,
        protocols::hash_to_prime::snark_range::Protocol as HPProtocol,
        transcript::root::{TranscriptProverChannel, TranscriptVerifierChannel},
    };
    use accumulator::{
        group::{Group, Rsa2048},
        AccumulatorWithoutHashToPrime,
    };
    use algebra::bls12_381::{Bls12_381, G1Projective};
    use merlin::Transcript;
    use rand::thread_rng;
    use rug::rand::RandState;
    use rug::Integer;
    use std::cell::RefCell;

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
        let mut rng2 = thread_rng();

        let crs = crate::protocols::membership::Protocol::<
            Rsa2048,
            G1Projective,
            HPProtocol<Bls12_381>,
        >::setup(&params, &mut rng1, &mut rng2)
        .unwrap()
        .crs
        .crs_root;
        let protocol = Protocol::<Rsa2048>::from_crs(&crs);

        let value = Integer::from(LARGE_PRIMES[0]);
        let randomness = Integer::from(5);
        let commitment = protocol
            .crs
            .integer_commitment_parameters
            .commit(&value, &randomness)
            .unwrap();

        let accum =
            accumulator::Accumulator::<Rsa2048, Integer, AccumulatorWithoutHashToPrime>::empty();
        let accum = accum.add(
            &LARGE_PRIMES
                .iter()
                .skip(1)
                .map(|p| Integer::from(*p))
                .collect::<Vec<_>>(),
        );

        let accum = accum.add_with_proof(&[value.clone()]);
        let acc = accum.0.value;
        let w = accum.1.witness.0.value;
        assert_eq!(Rsa2048::exp(&w, &value), acc);

        let proof_transcript = RefCell::new(Transcript::new(b"root"));
        let mut verifier_channel = TranscriptVerifierChannel::new(&crs, &proof_transcript);
        let statement = Statement {
            c_e: commitment,
            acc,
        };
        protocol
            .prove(
                &mut verifier_channel,
                &mut rng1,
                &statement,
                &Witness {
                    e: value,
                    r: randomness,
                    w,
                },
            )
            .unwrap();

        let proof = verifier_channel.proof().unwrap();
        let verification_transcript = RefCell::new(Transcript::new(b"root"));
        let mut prover_channel =
            TranscriptProverChannel::new(&crs, &verification_transcript, &proof);
        protocol.verify(&mut prover_channel, &statement).unwrap();
    }
}
