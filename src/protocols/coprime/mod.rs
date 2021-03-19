//! Implements coprime, to be used in the nonmembership protocol.
use crate::{
    commitments::{integer::IntegerCommitment, Commitment},
    parameters::Parameters,
    protocols::{CRSError, ProofError, VerificationError},
    utils::{random_symmetric_range, ConvertibleUnknownOrderGroup},
};
use channel::{CoprimeProverChannel, CoprimeVerifierChannel};
use rug::rand::MutRandState;
use rug::Integer;

pub mod channel;
pub mod transcript;

#[derive(Clone)]
pub struct CRSCoprime<G: ConvertibleUnknownOrderGroup> {
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
    pub d: G::Elem,
    pub b: Integer,
}

#[derive(Clone)]
pub struct Message1<G: ConvertibleUnknownOrderGroup> {
    pub c_a: G::Elem,
    pub c_r_a: <IntegerCommitment<G> as Commitment>::Instance,
    pub c_b_cap: <IntegerCommitment<G> as Commitment>::Instance,
    pub c_rho_b_cap: <IntegerCommitment<G> as Commitment>::Instance,
}

#[derive(Clone)]
pub struct Message2<G: ConvertibleUnknownOrderGroup> {
    pub alpha2: <IntegerCommitment<G> as Commitment>::Instance,
    pub alpha3: <IntegerCommitment<G> as Commitment>::Instance,
    pub alpha4: <IntegerCommitment<G> as Commitment>::Instance,
    pub alpha5: <IntegerCommitment<G> as Commitment>::Instance,
    pub alpha6: <IntegerCommitment<G> as Commitment>::Instance,
    pub alpha7: <IntegerCommitment<G> as Commitment>::Instance,
}

#[derive(Clone)]
pub struct Message3 {
    pub s_b: Integer,
    pub s_e: Integer,
    pub s_rho_b_cap: Integer,
    pub s_r: Integer,
    pub s_r_a: Integer,
    pub s_r_a_prime: Integer,
    pub s_rho_b_cap_prime: Integer,
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
    pub crs: CRSCoprime<G>,
}

impl<G: ConvertibleUnknownOrderGroup> Protocol<G> {
    pub fn from_crs(crs: &CRSCoprime<G>) -> Result<Protocol<G>, CRSError> {
        let modulus = G::rsa_modulus().map_err(|_| CRSError::InvalidParameters)?;
        if crs.parameters.security_soundness + 1 >= crs.parameters.hash_to_prime_bits
            || crs.parameters.security_soundness >= modulus / 2
        {
            return Err(CRSError::InvalidParameters);
        }
        Ok(Protocol { crs: crs.clone() })
    }

    pub fn prove<R: MutRandState, C: CoprimeVerifierChannel<G>>(
        &self,
        verifier_channel: &mut C,
        rng: &mut R,
        statement: &Statement<G>,
        witness: &Witness<G>,
    ) -> Result<(), ProofError> {
        let r_a = random_symmetric_range(rng, &(G::order_upper_bound() / 2));
        let r_a_prime = random_symmetric_range(rng, &(G::order_upper_bound() / 2));
        let rho_b_cap = random_symmetric_range(rng, &(G::order_upper_bound() / 2));
        let rho_b_cap_prime = random_symmetric_range(rng, &(G::order_upper_bound() / 2));
        let c_a = G::op(
            &witness.d,
            &G::exp(&self.crs.integer_commitment_parameters.h, &r_a),
        );
        let c_r_a = self
            .crs
            .integer_commitment_parameters
            .commit(&r_a, &r_a_prime)?;
        let integer_commitment_c_b_cap =
            IntegerCommitment::<G>::new(&statement.acc, &self.crs.integer_commitment_parameters.h);
        let c_b_cap = integer_commitment_c_b_cap.commit(&witness.b, &rho_b_cap)?;
        let c_rho_b_cap = self
            .crs
            .integer_commitment_parameters
            .commit(&rho_b_cap, &rho_b_cap_prime)?;

        let message1 = Message1::<G> {
            c_a,
            c_r_a,
            c_b_cap,
            c_rho_b_cap,
        };
        verifier_channel.send_message1(&message1)?;

        let r_b_e_range = Integer::from(Integer::u_pow_u(
            2,
            (self.crs.parameters.security_zk
                + self.crs.parameters.security_soundness
                + self.crs.parameters.hash_to_prime_bits) as u32,
        ));
        let r_b = random_symmetric_range(rng, &r_b_e_range);
        let r_e = random_symmetric_range(rng, &r_b_e_range);

        let r_r_range = G::order_upper_bound() / 2
            * Integer::from(Integer::u_pow_u(
                2,
                (self.crs.parameters.security_zk + self.crs.parameters.security_soundness) as u32,
            ));
        let r_rho_b_cap = random_symmetric_range(rng, &r_r_range);
        let r_r = random_symmetric_range(rng, &r_r_range);
        let r_r_a = random_symmetric_range(rng, &r_r_range);
        let r_r_a_prime = random_symmetric_range(rng, &r_r_range);
        let r_rho_b_cap_prime = random_symmetric_range(rng, &r_r_range);

        let r_beta_delta_range = G::order_upper_bound() / 2
            * Integer::from(Integer::u_pow_u(
                2,
                (self.crs.parameters.security_zk
                    + self.crs.parameters.security_soundness
                    + self.crs.parameters.hash_to_prime_bits) as u32,
            ));
        let r_beta = random_symmetric_range(rng, &r_beta_delta_range);
        let r_delta = random_symmetric_range(rng, &r_beta_delta_range);

        let alpha2 = integer_commitment_c_b_cap.commit(&r_b, &r_rho_b_cap)?;
        let alpha3 = self.crs.integer_commitment_parameters.commit(&r_e, &r_r)?;
        let alpha4 = self
            .crs
            .integer_commitment_parameters
            .commit(&r_r_a, &r_r_a_prime)?;

        let integer_commitment_alpha5 =
            IntegerCommitment::<G>::new(&message1.c_a, &self.crs.integer_commitment_parameters.h);
        let alpha5 = integer_commitment_alpha5.commit(&r_e, &r_beta)?;

        let alpha6 = G::op(
            &G::exp(&message1.c_r_a, &r_e),
            &self
                .crs
                .integer_commitment_parameters
                .commit(&r_beta, &r_delta)?,
        );
        let alpha7 = self
            .crs
            .integer_commitment_parameters
            .commit(&r_rho_b_cap, &r_rho_b_cap_prime)?;

        let message2 = Message2::<G> {
            alpha2,
            alpha3,
            alpha4,
            alpha5,
            alpha6,
            alpha7,
        };
        verifier_channel.send_message2(&message2)?;

        let c = verifier_channel.receive_challenge()?;
        let s_b = r_b - c.clone() * witness.b.clone();
        let s_e = r_e - c.clone() * witness.e.clone();
        let s_rho_b_cap = r_rho_b_cap - c.clone() * rho_b_cap.clone();
        let s_r = r_r - c.clone() * witness.r.clone();
        let s_r_a = r_r_a - c.clone() * r_a.clone();
        let s_r_a_prime = r_r_a_prime - c.clone() * r_a_prime.clone();
        let s_rho_b_cap_prime = r_rho_b_cap_prime - c.clone() * rho_b_cap_prime.clone();
        let s_beta = r_beta + c.clone() * (witness.e.clone() * r_a + rho_b_cap);
        let s_delta = r_delta + c * (witness.e.clone() * r_a_prime + rho_b_cap_prime);
        let message3 = Message3 {
            s_b,
            s_e,
            s_rho_b_cap,
            s_r,
            s_r_a,
            s_r_a_prime,
            s_rho_b_cap_prime,
            s_beta,
            s_delta,
        };
        verifier_channel.send_message3(&message3)?;

        Ok(())
    }

    pub fn verify<C: CoprimeProverChannel<G>>(
        &self,
        prover_channel: &mut C,
        statement: &Statement<G>,
    ) -> Result<(), VerificationError> {
        let message1 = prover_channel.receive_message1()?;
        let message2 = prover_channel.receive_message2()?;
        let c = prover_channel.generate_and_send_challenge()?;
        let message3 = prover_channel.receive_message3()?;
        let integer_commitment_alpha2 =
            IntegerCommitment::<G>::new(&statement.acc, &self.crs.integer_commitment_parameters.h);
        let expected_alpha2 = G::op(
            &G::exp(&message1.c_b_cap, &c),
            &integer_commitment_alpha2.commit(&message3.s_b, &message3.s_rho_b_cap)?,
        );
        let expected_alpha3 = G::op(
            &G::exp(&statement.c_e, &c),
            &self
                .crs
                .integer_commitment_parameters
                .commit(&message3.s_e, &message3.s_r)?,
        );
        let expected_alpha4 = G::op(
            &G::exp(&message1.c_r_a, &c),
            &self
                .crs
                .integer_commitment_parameters
                .commit(&message3.s_r_a, &message3.s_r_a_prime)?,
        );
        let integer_commitment_alpha5 =
            IntegerCommitment::<G>::new(&message1.c_a, &G::inv(&message1.c_b_cap));
        let expected_alpha5 = G::op(
            &integer_commitment_alpha5.commit(&message3.s_e, &c)?,
            &self
                .crs
                .integer_commitment_parameters
                .commit(&c, &message3.s_beta)?,
        );
        let integer_commitment_alpha6 =
            IntegerCommitment::<G>::new(&message1.c_r_a, &G::inv(&message1.c_rho_b_cap));
        let expected_alpha6 = G::op(
            &integer_commitment_alpha6.commit(&message3.s_e, &c)?,
            &self
                .crs
                .integer_commitment_parameters
                .commit(&message3.s_beta, &message3.s_delta)?,
        );
        let expected_alpha7 = G::op(
            &G::exp(&message1.c_rho_b_cap, &c),
            &self
                .crs
                .integer_commitment_parameters
                .commit(&message3.s_rho_b_cap, &message3.s_rho_b_cap_prime)?,
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

        if expected_alpha2 == message2.alpha2
            && expected_alpha3 == message2.alpha3
            && expected_alpha4 == message2.alpha4
            && expected_alpha5 == message2.alpha5
            && expected_alpha6 == message2.alpha6
            && expected_alpha7 == message2.alpha7
            && is_s_e_in_range
        {
            Ok(())
        } else {
            Err(VerificationError::VerificationFailed)
        }
    }
}

#[cfg(all(test, feature = "arkworks"))]
mod test {
    use super::{Protocol, Statement, Witness};
    use crate::{
        commitments::Commitment,
        parameters::Parameters,
        protocols::{
            coprime::transcript::{TranscriptProverChannel, TranscriptVerifierChannel},
            hash_to_prime::snark_range::Protocol as HPProtocol,
        },
    };
    use accumulator::{
        group::{Group, Rsa2048},
        AccumulatorWithoutHashToPrime,
    };
    use ark_bls12_381::{Bls12_381, G1Projective};
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

        let crs = crate::protocols::nonmembership::Protocol::<
            Rsa2048,
            G1Projective,
            HPProtocol<Bls12_381>,
        >::setup(&params, &mut rng1, &mut rng2)
        .unwrap()
        .crs
        .crs_coprime;
        let protocol = Protocol::<Rsa2048>::from_crs(&crs).unwrap();

        let value = Integer::from(LARGE_PRIMES[0]);
        let randomness = Integer::from(5);
        let commitment = protocol
            .crs
            .integer_commitment_parameters
            .commit(&value, &randomness)
            .unwrap();

        let accum =
            accumulator::Accumulator::<Rsa2048, Integer, AccumulatorWithoutHashToPrime>::empty();
        let acc_set = LARGE_PRIMES
            .iter()
            .skip(1)
            .map(|p| Integer::from(*p))
            .collect::<Vec<_>>();
        let accum = accum.add(&acc_set);

        let non_mem_proof = accum
            .prove_nonmembership(&acc_set, &[value.clone()])
            .unwrap();

        let acc = accum.value;
        let d = non_mem_proof.d.clone();
        let b = non_mem_proof.b;
        assert_eq!(
            Rsa2048::op(&Rsa2048::exp(&d, &value), &Rsa2048::exp(&acc, &b)),
            protocol.crs.integer_commitment_parameters.g
        );

        let proof_transcript = RefCell::new(Transcript::new(b"coprime"));
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
                    d,
                    b,
                },
            )
            .unwrap();

        let proof = verifier_channel.proof().unwrap();
        let verification_transcript = RefCell::new(Transcript::new(b"coprime"));
        let mut prover_channel =
            TranscriptProverChannel::new(&crs, &verification_transcript, &proof);
        protocol.verify(&mut prover_channel, &statement).unwrap();
    }
}
