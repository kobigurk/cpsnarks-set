use r1cs_core::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
use algebra_core::{PrimeField, PairingEngine, UniformRand, BigInteger, log2};
use r1cs_std::{
    Assignment,
    boolean::Boolean,
    bits::ToBitsGadget,
    alloc::AllocGadget,
    fields::fp::FpGadget,
    eq::EqGadget,
};
use crypto_primitives::prf::blake2s::constraints::blake2s_gadget;
use crate::{
    parameters::Parameters,
    commitments::pedersen::PedersenCommitment,
    channels::hash_to_prime::{HashToPrimeProverChannel, HashToPrimeVerifierChannel},
    utils::{integer_to_bigint_mod_q},
    protocols::{
        hash_to_prime::{HashToPrimeProtocol, CRSHashToPrime, Statement, Witness},
        membership::{SetupError, ProofError, VerificationError},
    }
};
use rand::Rng;

pub trait HashToPrimeHashParameters {
    const MESSAGE_SIZE: u16;

    fn index_bit_length(security_level: u16) -> u64 {
        log2((security_level as usize)*(Self::MESSAGE_SIZE as usize)) as u64
    }
}

pub struct HashToPrimeHashCircuit<E: PairingEngine, P: HashToPrimeHashParameters> {
    security_level: u16,
    required_bit_size: u16,
    value: Option<E::Fr>,
    index: Option<u64>,
    parameters_type: std::marker::PhantomData<P>,
}

impl<E: PairingEngine, P: HashToPrimeHashParameters> ConstraintSynthesizer<E::Fr>  for HashToPrimeHashCircuit<E, P> {
    fn generate_constraints<CS: ConstraintSystem<E::Fr>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let f = FpGadget::alloc(cs.ns( || "alloc value"),|| self.value.get())?;
        let mut index_bits = vec![];
        let index_bit_length = P::index_bit_length(self.security_level);
        if index_bit_length > 64 {
            return Err(SynthesisError::Unsatisfiable);
        }
        for i in 0..index_bit_length {
            index_bits.push(Boolean::alloc(cs.ns(
                || format!("index bit {}", i)), 
                || {
                    if self.index.is_none() {
                        Err(SynthesisError::AssignmentMissing)
                    } else {
                        let mask = 1u64 << i;
                        Ok((mask & self.index.unwrap()) == mask)
                    }
                },
            )?);
        }
        // big-endian bits
        let bits = f.to_bits(cs.ns(|| "to bits"))?;
        let bits_to_hash: Vec<Boolean> = [index_bits.as_slice(), &bits[<E::Fr as PrimeField>::size_in_bits() - P::MESSAGE_SIZE as usize..]].concat();
        let bits_to_hash_padded = if bits_to_hash.len() % 8 != 0 {
            let padding_length = 8 - bits_to_hash.len() % 8;
            [&vec![Boolean::constant(false); padding_length][..], bits_to_hash.as_slice()].concat()
        } else {
            bits_to_hash
        };
        let hash_result = blake2s_gadget(cs.ns(|| "blake2s hash"), &bits_to_hash_padded)?;
        let hash_bits = hash_result
            .into_iter()
            .map(|n| n.to_bits_le())
            .flatten()
            .take((self.required_bit_size - 1) as usize)
            .collect::<Vec<Boolean>>();
        let hash_bits = [&[Boolean::constant(true)][..], &hash_bits].concat();
        let result = FpGadget::alloc_input(cs.ns( || "alloc hash"),|| {
            if hash_bits.iter().any(|x| x.get_value().is_none()) {
                Err(SynthesisError::AssignmentMissing)
            } else {
                Ok(E::Fr::from_repr(<E::Fr as PrimeField>::BigInt::from_bits(&hash_bits.iter().map(|x| x.get_value().unwrap()).collect::<Vec<_>>())))
            }
        })?;
        let result_bits = result.to_bits(cs.ns(|| "hash number to bits"))?;
        for (i, b) in result_bits.iter().take(<E::Fr as PrimeField>::size_in_bits() - self.required_bit_size as usize).enumerate() {
            b.enforce_equal(cs.ns(|| format!("enforce result header is zero, bit {}", i)), &Boolean::constant(false))?;
        }
        for (i, (h, r)) in hash_bits.iter().zip(result_bits.iter().skip(<E::Fr as PrimeField>::size_in_bits() - self.required_bit_size as usize)).enumerate() {
            h.enforce_equal(cs.ns(|| format!("enforce result bit {}", i)), &r)?;
        }

        Ok(())
    }
}

pub struct Protocol<E: PairingEngine, P: HashToPrimeHashParameters> {
    pub crs: CRSHashToPrime<E::G1Projective, Self>,
    parameters_type: std::marker::PhantomData<P>,
}

impl<E: PairingEngine, P: HashToPrimeHashParameters> HashToPrimeProtocol<E::G1Projective> for Protocol<E, P> {
    type Proof = legogro16::Proof<E>;
    type Parameters = legogro16::Parameters<E>;

    fn from_crs(
        crs: &CRSHashToPrime<E::G1Projective, Self>
    ) -> Protocol<E, P> {
        Protocol {
            crs: (*crs).clone(),
            parameters_type: std::marker::PhantomData,
        }
    }

    fn setup<R: Rng>(rng: &mut R, pedersen_commitment_parameters: &PedersenCommitment<E::G1Projective>, parameters: &Parameters) -> Result<Self::Parameters, SetupError> {
        let c = HashToPrimeHashCircuit::<E, P> {
            security_level: parameters.security_level,
            required_bit_size: parameters.hash_to_prime_bits,
            value: None,
            index: None,
            parameters_type: std::marker::PhantomData,
        };
        let base_one = E::G1Projective::rand(rng);
        let pedersen_bases = vec![base_one, pedersen_commitment_parameters.g, pedersen_commitment_parameters.h];
        Ok(legogro16::generate_random_parameters(c, &pedersen_bases, rng)?)
    }

    fn prove<R: Rng, C: HashToPrimeVerifierChannel<E::G1Projective, Self>>(
        &self,
        verifier_channel: &mut C,
        rng: &mut R,
        _: &Statement<E::G1Projective>,
        witness: &Witness,
    ) -> Result<(), ProofError>
    {
        let c = HashToPrimeHashCircuit::<E, P> {
            security_level: self.crs.parameters.security_level,
            required_bit_size: self.crs.parameters.hash_to_prime_bits,
            value: Some(integer_to_bigint_mod_q::<E::G1Projective>(&witness.e.clone())?),
            index: Some(0),
            parameters_type: std::marker::PhantomData,
        };
        let v = E::Fr::rand(rng);
        let link_v = integer_to_bigint_mod_q::<E::G1Projective>(&witness.r_q.clone())?;
        let proof = legogro16::create_random_proof::<E, _, _>(c, v, link_v, &self.crs.hash_to_prime_parameters, rng)?;
        verifier_channel.send_proof(&proof)?;
        Ok(())
    }

    fn verify<C: HashToPrimeProverChannel<E::G1Projective, Self>> (
        &self,
        prover_channel: &mut C,
        _statement: &Statement<E::G1Projective>,
    ) -> Result<(), VerificationError>
    {
        let proof = prover_channel.receive_proof()?;
        let pvk = legogro16::prepare_verifying_key(&self.crs.hash_to_prime_parameters.vk);
        if !legogro16::verify_proof(&pvk, &proof)? {
            return Err(VerificationError::VerificationFailed);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use rug::Integer;
    use std::cell::RefCell;
    use algebra::bls12_381::{Bls12_381, G1Projective, Fr};
    use r1cs_std::test_constraint_system::TestConstraintSystem;
    use r1cs_core::ConstraintSynthesizer;
    use rand::thread_rng;
    use crate::{
        parameters::Parameters,
        commitments::Commitment,
        transcript::hash_to_prime::{TranscriptProverChannel, TranscriptVerifierChannel},
        protocols::hash_to_prime::{
            HashToPrimeProtocol,
            snark_hash::Protocol as HPProtocol,
        },
        utils::integer_to_bigint_mod_q,
    };
    use rug::rand::RandState;
    use accumulator::group::Rsa2048;
    use super::{Protocol, Statement, Witness, HashToPrimeHashCircuit, HashToPrimeHashParameters};
    use merlin::Transcript;

    struct TestParameters {}
    impl HashToPrimeHashParameters for TestParameters {
        const MESSAGE_SIZE: u16 = 16;
    }

    #[test]
    fn test_circuit() {
        let mut cs = TestConstraintSystem::<Fr>::new();
        let c = HashToPrimeHashCircuit::<Bls12_381, TestParameters> {
            security_level: 64,
            required_bit_size: 254,
            value: Some(integer_to_bigint_mod_q::<G1Projective>(&Integer::from(12)).unwrap().into()),
            index: Some(10),
            parameters_type: std::marker::PhantomData,
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

        let crs = crate::protocols::membership::Protocol::<Rsa2048, G1Projective, HPProtocol<Bls12_381, TestParameters>>::setup(&params, &mut rng1, &mut rng2).unwrap().crs.crs_hash_to_prime;
        let protocol = Protocol::<Bls12_381, TestParameters>::from_crs(&crs);

        let value = Integer::from(Integer::u_pow_u(
                2,
                (crs.parameters.hash_to_prime_bits)
                    as u32,
            )) - &Integer::from(245);
        let randomness = Integer::from(9);
        let commitment = protocol.crs.pedersen_commitment_parameters.commit(&value, &randomness).unwrap();

        let proof_transcript = RefCell::new(Transcript::new(b"hash_to_prime"));
        let statement = Statement {
            c_e_q: commitment,
        };
        let mut verifier_channel = TranscriptVerifierChannel::new(&crs, &proof_transcript);
        protocol.prove(&mut verifier_channel, &mut rng2, &statement, &Witness {
            e: value,
            r_q: randomness,
        }).unwrap();

        let proof = verifier_channel.proof().unwrap();

        let verification_transcript = RefCell::new(Transcript::new(b"modeq"));
        let mut prover_channel = TranscriptProverChannel::new(&crs, &verification_transcript, &proof);
        protocol.verify(&mut prover_channel, &statement).unwrap();
    }
}