use r1cs_core::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
use algebra_core::{PrimeField, PairingEngine, UniformRand};
use r1cs_std::{
    Assignment,
    boolean::Boolean,
    bits::ToBitsGadget,
    alloc::AllocGadget,
    fields::fp::FpGadget,
    eq::EqGadget,
};
use crate::{
    channels::range::{RangeProverChannel, RangeVerifierChannel},
    utils::{integer_to_bigint_mod_q},
    protocols::{
        range::{RangeProofProtocol, CRSRangeProof, Statement, Witness},
        membership::{SetupError, ProofError, VerificationError},
    }
};
use rand::Rng;

pub struct RangeProofCircuit<E: PairingEngine> {
    required_bit_size: u16,
    value: Option<E::Fr>,
}

impl<E: PairingEngine> ConstraintSynthesizer<E::Fr>  for RangeProofCircuit<E> {
    fn generate_constraints<CS: ConstraintSystem<E::Fr>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let f = FpGadget::alloc_input(cs.ns( || "alloc value"),|| self.value.get())?;
        // big-endian bits
        let bits = f.to_bits_strict(cs.ns(|| "to bits"))?;
        let modulus_bits = E::Fr::size_in_bits();
        bits[modulus_bits - self.required_bit_size as usize].enforce_equal(cs.ns(|| "enforce highest required bit is zero"), &Boolean::constant(true))?;

        let bits_not = bits[modulus_bits - self.required_bit_size as usize + 1..].into_iter().map(|b| b.not()).collect::<Vec<_>>();
        let anded = Boolean::kary_and(cs.ns(|| "and all negated bits"), &bits_not)?;

        // We want at least one of the original bits to be 1. This means that at least one of the negated bits should have been 0,
        // and so result in a 0.
        anded.enforce_equal(cs.ns(|| "check at least one 0"), &Boolean::constant(false))?;

        Ok(())
    }
}

pub struct Protocol<E: PairingEngine> {
    pub crs: CRSRangeProof<E::G1Projective, Self>,
}

impl<E: PairingEngine> RangeProofProtocol<E::G1Projective> for Protocol<E> {
    type Proof = ccgro16::Proof<E>;
    type Parameters = ccgro16::Parameters<E>;

    fn from_crs(
        crs: &CRSRangeProof<E::G1Projective, Self>
    ) -> Protocol<E> {
        Protocol {
            crs: (*crs).clone(),
        }
    }

    fn setup<R: Rng>(rng: &mut R, hash_to_prime_bits: u16) -> Result<Self::Parameters, SetupError> {
        let c = RangeProofCircuit::<E> {
            required_bit_size: hash_to_prime_bits,
            value: None,
        };
        Ok(ccgro16::generate_random_parameters(c, rng)?)
    }

    fn prove<R: Rng, C: RangeVerifierChannel<E::G1Projective, Self>>(
        &self,
        verifier_channel: &mut C,
        rng: &mut R,
        _: &Statement<E::G1Projective>,
        witness: &Witness,
    ) -> Result<(), ProofError>
    {
        let c = RangeProofCircuit::<E> {
            required_bit_size: self.crs.parameters.hash_to_prime_bits,
            value: Some(integer_to_bigint_mod_q::<E::G1Projective>(&witness.e.clone())?),
        };
        let v = E::Fr::rand(rng);
        let proof = ccgro16::create_random_proof::<E, _, _>(c, v, &self.crs.range_proof_parameters, rng)?;
        verifier_channel.send_proof(&proof)?;
        Ok(())
    }

    fn verify<C: RangeProverChannel<E::G1Projective, Self>> (
        &self,
        prover_channel: &mut C,
        _statement: &Statement<E::G1Projective>,
    ) -> Result<(), VerificationError>
    {
        let proof = prover_channel.receive_proof()?;
        let pvk = ccgro16::prepare_verifying_key(&self.crs.range_proof_parameters.vk);
        if !ccgro16::verify_proof(&pvk, &proof)? {
            return Err(VerificationError::VerificationFailed);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use rug::Integer;
    use algebra::bls12_381::{Bls12_381, G1Projective, Fr};
    use r1cs_std::test_constraint_system::TestConstraintSystem;
    use r1cs_core::ConstraintSynthesizer;
    use rand::thread_rng;
    use crate::{
        parameters::Parameters,
        commitments::Commitment,
        transcript::range::{TranscriptProverChannel, TranscriptVerifierChannel},
        protocols::range::{
            RangeProofProtocol,
            snark::Protocol as RPProtocol,
        },
        utils::integer_to_bigint_mod_q,
    };
    use rug::rand::RandState;
    use accumulator::group::Rsa2048;
    use super::{Protocol, Statement, Witness, RangeProofCircuit};
    use merlin::Transcript;

    #[test]
    fn test_circuit() {
        let mut cs = TestConstraintSystem::<Fr>::new();
        let c = RangeProofCircuit::<Bls12_381> {
            required_bit_size: 4,
            value: Some(integer_to_bigint_mod_q::<G1Projective>(&Integer::from(12)).unwrap().into()),
        };
        c.generate_constraints(&mut cs).unwrap();
        if !cs.is_satisfied() {
            panic!(format!("not satisfied: {}", cs.which_is_unsatisfied().unwrap()));
        }
    }

    #[test]
    fn test_proof() {
        let params = Parameters::from_security_level(128).unwrap();
        let mut rng1 = RandState::new();
        rng1.seed(&Integer::from(13));
        let mut rng2 = thread_rng();

        let crs = crate::protocols::membership::Protocol::<Rsa2048, G1Projective, RPProtocol<Bls12_381>>::setup(&params, &mut rng1, &mut rng2).unwrap().crs.crs_range;
        let protocol = Protocol::<Bls12_381>::from_crs(&crs);

        let value = Integer::from(Integer::u_pow_u(
                2,
                (crs.parameters.hash_to_prime_bits)
                    as u32,
            )) - &Integer::from(5);
        let randomness = Integer::from(9);
        let commitment = protocol.crs.pedersen_commitment_parameters.commit(&value, &randomness).unwrap();

        let mut proof_transcript = Transcript::new(b"range");
        let statement = Statement {
            c_e_q: commitment,
        };
        let mut verifier_channel = TranscriptVerifierChannel::new(&crs, &mut proof_transcript);
        protocol.prove(&mut verifier_channel, &mut rng2, &statement, &Witness {
            e: value,
            r_q: randomness,
        }).unwrap();

        let proof = verifier_channel.proof().unwrap();

        let mut verification_transcript = Transcript::new(b"modeq");
        let mut prover_channel = TranscriptProverChannel::new(&crs, &mut verification_transcript, &proof);
        protocol.verify(&mut prover_channel, &statement).unwrap();
    }
}