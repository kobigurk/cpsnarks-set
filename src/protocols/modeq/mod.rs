use crate::commitments::{
    integer::IntegerCommitment, pedersen::PedersenCommitment, Commitment,
};
use crate::{
    parameters::Parameters,
    utils::{
        bigint_to_integer, integer_mod_q, random_symmetric_range, ConvertibleUnknownOrderGroup, integer_to_bigint_mod_q,
        curve::{Field, CurvePointProjective},
    },
    protocols::membership::{ProofError, VerificationError},
    channels::modeq::{ModEqProverChannel, ModEqVerifierChannel},
};
use rand::{RngCore, CryptoRng};
use rug::{Integer, rand::MutRandState};

#[derive(Clone)]
pub struct CRSModEq<G: ConvertibleUnknownOrderGroup, P: CurvePointProjective> {
    // G contains the information about Z^*_N
    pub parameters: Parameters,
    pub integer_commitment_parameters: IntegerCommitment<G>, // G, H
    pub pedersen_commitment_parameters: PedersenCommitment<P>, // g, h
}

pub struct Statement<G: ConvertibleUnknownOrderGroup, P: CurvePointProjective> {
    pub c_e: <IntegerCommitment<G> as Commitment>::Instance,
    pub c_e_q: <PedersenCommitment<P> as Commitment>::Instance,
}

pub struct Witness {
    pub e: Integer,
    pub r: Integer,
    pub r_q: Integer,
}

#[derive(Clone)]
pub struct Message1<G: ConvertibleUnknownOrderGroup, P: CurvePointProjective> {
    pub alpha1: <IntegerCommitment<G> as Commitment>::Instance,
    pub alpha2: <PedersenCommitment<P> as Commitment>::Instance,
}

#[derive(Clone)]
pub struct Message2<P: CurvePointProjective> {
    pub s_e: Integer,
    pub s_r: Integer,
    pub s_r_q: P::ScalarField,
}

#[derive(Clone)]
pub struct Proof<G: ConvertibleUnknownOrderGroup, P: CurvePointProjective> {
    pub message1: Message1<G, P>,
    pub message2: Message2<P>,
}

pub struct Protocol<G: ConvertibleUnknownOrderGroup, P: CurvePointProjective> {
    pub crs: CRSModEq<G, P>,
}

impl<G: ConvertibleUnknownOrderGroup, P: CurvePointProjective> Protocol<G, P> {
    pub fn from_crs(
        crs: &CRSModEq<G, P>
    ) -> Protocol<G, P> {
        Protocol {
            crs: crs.clone(),
        }
    }

    pub fn prove<R1: MutRandState, R2: RngCore + CryptoRng, C: ModEqVerifierChannel<G, P>> (
        &self,
        verifier_channel: &mut C,
        rng1: &mut R1,
        rng2: &mut R2,
        _: &Statement<G, P>,
        witness: &Witness,
    ) -> Result<(), ProofError>
    {
        let r_e_range = Integer::from(Integer::u_pow_u(
            2,
            (self.crs.parameters.security_zk
                + self.crs.parameters.security_soundness
                + self.crs.parameters.hash_to_prime_bits) as u32,
        ));
        let r_e = random_symmetric_range(rng1, &r_e_range);
        let r_r_range = Integer::from(
            G::order_upper_bound() / 2
                * Integer::from(Integer::u_pow_u(
                    2,
                    (self.crs.parameters.security_zk + self.crs.parameters.security_soundness)
                        as u32,
                )),
        );
        let r_r = random_symmetric_range(rng1, &r_r_range);
        assert!(
            self.crs.parameters.field_size_bits as usize
                >= P::ScalarField::size_in_bits()
        );
        let r_r_q_field = P::ScalarField::rand(rng2);
        let r_r_q = bigint_to_integer::<P>(&r_r_q_field);

        let alpha1 = self.crs.integer_commitment_parameters.commit(&r_e, &r_r)?;
        let alpha2 = self
            .crs
            .pedersen_commitment_parameters
            .commit(&integer_mod_q::<P>(&r_e)?, &r_r_q)?;

        let message1 = Message1::<G, P> { alpha1, alpha2 };
        verifier_channel.send_message1(&message1)?;

        let c = verifier_channel.receive_challenge()?;
        let r_q = integer_to_bigint_mod_q::<P>(&witness.r_q.clone())?;
        let s_e = r_e - c.clone() * witness.e.clone();
        let s_r = r_r - c.clone() * witness.r.clone();
        let c_big = integer_to_bigint_mod_q::<P>(&c)?;
        let s_r_q = r_r_q_field.sub(&(r_q.mul(&c_big)));

        let message2 = Message2::<P> { s_e, s_r, s_r_q };
        verifier_channel.send_message2(&message2)?;

        Ok(())
    }

    pub fn verify<C: ModEqProverChannel<G, P>>(
        &self,
        prover_channel: &mut C,
        statement: &Statement<G, P>,
    ) -> Result<(), VerificationError>
    {
        let message1 = prover_channel.receive_message1()?;
        let c = prover_channel.generate_and_send_challenge()?;
        let message2 = prover_channel.receive_message2()?;

        let commitment2 = self.crs.integer_commitment_parameters.commit(&message2.s_e, &message2.s_r)?;
        let commitment2_extra = G::exp(&statement.c_e, &c);
        let expected_alpha1 = G::op(&commitment2, &commitment2_extra);

        let s_e_mod_q = integer_mod_q::<P>(&message2.s_e)?;
        let s_r_q_int = bigint_to_integer::<P>(&message2.s_r_q);
        let commitment1 = self.crs.pedersen_commitment_parameters.commit(&s_e_mod_q, &s_r_q_int)?;
        let c_big = integer_to_bigint_mod_q::<P>(&c)?;
        let commitment1_extra = statement.c_e_q.mul(&c_big);
        let expected_alpha2 = commitment1.add(&commitment1_extra);


        if expected_alpha1 == message1.alpha1 && expected_alpha2 == message1.alpha2 {
            Ok(())
        } else {
            Err(VerificationError::VerificationFailed)
        }
    }
}

#[cfg(all(test, feature="zexe"))]
mod test {
    use rug::Integer;
    use std::cell::RefCell;
    use algebra::bls12_381::{Bls12_381, G1Projective};
    use rand::thread_rng;
    use crate::{
        parameters::Parameters,
        commitments::Commitment,
        transcript::modeq::{TranscriptProverChannel, TranscriptVerifierChannel},
        protocols::hash_to_prime::snark_range::Protocol as HPProtocol,
    };
    use rug::rand::RandState;
    use accumulator::group::Rsa2048;
    use super::{Protocol, Statement, Witness};
    use merlin::Transcript;

    #[test]
    fn test_proof() {
        let params = Parameters::from_security_level(128).unwrap();
        let mut rng1 = RandState::new();
        rng1.seed(&Integer::from(13));
        let mut rng2 = thread_rng();

        let crs = crate::protocols::membership::Protocol::<Rsa2048, G1Projective, HPProtocol<Bls12_381>>::setup(&params, &mut rng1, &mut rng2).unwrap().crs.crs_modeq;
        let protocol = Protocol::<Rsa2048, G1Projective>::from_crs(&crs);

        let value1 = Integer::from(2);
        let randomness1 = Integer::from(5);
        let randomness2 = Integer::from(9);
        let commitment1 = protocol.crs.integer_commitment_parameters.commit(&value1, &randomness1).unwrap();
        let commitment2 = protocol.crs.pedersen_commitment_parameters.commit(&value1, &randomness2).unwrap();

        let proof_transcript = RefCell::new(Transcript::new(b"modeq"));
        let statement = Statement {
            c_e: commitment1,
            c_e_q: commitment2,
        };
        let mut verifier_channel = TranscriptVerifierChannel::new(&crs, &proof_transcript);
        protocol.prove(&mut verifier_channel, &mut rng1, &mut rng2, &statement, &Witness {
            e: value1,
            r: randomness1,
            r_q: randomness2,
        }).unwrap();

        let proof = verifier_channel.proof().unwrap();

        let verification_transcript = RefCell::new(Transcript::new(b"modeq"));
        let mut prover_channel = TranscriptProverChannel::new(&crs, &verification_transcript, &proof);
        protocol.verify(&mut prover_channel, &statement).unwrap();
    }
}
