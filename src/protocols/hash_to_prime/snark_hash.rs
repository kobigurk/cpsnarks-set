use crate::{
    commitments::pedersen::PedersenCommitment,
    parameters::Parameters,
    protocols::{
        hash_to_prime::{
            channel::{HashToPrimeProverChannel, HashToPrimeVerifierChannel},
            CRSHashToPrime, HashToPrimeError, HashToPrimeProtocol, Statement, Witness,
        },
        ProofError, SetupError, VerificationError,
    },
    utils::{
        bigint_to_integer, bits_big_endian_to_bytes_big_endian,
        bytes_big_endian_to_bits_big_endian, integer_to_bigint_mod_q, log2,
    },
};
use algebra_core::{AffineCurve, BigInteger, One, PairingEngine, PrimeField, UniformRand};
use blake2::Blake2s;
use crypto_primitives::prf::blake2s::constraints::blake2s_gadget;
use digest::{FixedOutput, Input};
use r1cs_core::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
use r1cs_std::{
    alloc::AllocGadget, bits::ToBitsGadget, boolean::Boolean, eq::EqGadget, fields::fp::FpGadget,
    Assignment,
};
use rand::Rng;
use rug::{integer::IsPrime, Integer};
use std::ops::{Neg, Sub};

pub trait HashToPrimeHashParameters {
    const MESSAGE_SIZE: u16;

    fn index_bit_length(security_level: u16) -> u64 {
        log2((security_level as usize) * (Self::MESSAGE_SIZE as usize)) as u64
    }
}

pub struct HashToPrimeHashCircuit<E: PairingEngine, P: HashToPrimeHashParameters> {
    security_level: u16,
    required_bit_size: u16,
    value: Option<E::Fr>,
    index: Option<u64>,
    parameters_type: std::marker::PhantomData<P>,
}

impl<E: PairingEngine, P: HashToPrimeHashParameters> ConstraintSynthesizer<E::Fr>
    for HashToPrimeHashCircuit<E, P>
{
    fn generate_constraints<CS: ConstraintSystem<E::Fr>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let f = FpGadget::alloc(cs.ns(|| "alloc value"), || self.value.get())?;
        let mut index_bits = vec![];
        let index_bit_length = P::index_bit_length(self.security_level);
        if index_bit_length > 64 {
            return Err(SynthesisError::Unsatisfiable);
        }
        for i in 0..index_bit_length {
            index_bits.push(Boolean::alloc(
                cs.ns(|| format!("index bit {}", i)),
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
        let bits_to_hash: Vec<Boolean> = [
            index_bits.as_slice(),
            &bits[<E::Fr as PrimeField>::size_in_bits() - P::MESSAGE_SIZE as usize..],
        ]
        .concat();
        let bits_to_hash_padded = if bits_to_hash.len() % 8 != 0 {
            let padding_length = 8 - bits_to_hash.len() % 8;
            [
                &vec![Boolean::constant(false); padding_length][..],
                bits_to_hash.as_slice(),
            ]
            .concat()
        } else {
            bits_to_hash
        };

        let hash_result = blake2s_gadget(cs.ns(|| "blake2s hash"), &bits_to_hash_padded)?;
        let hash_bits = hash_result
            .into_iter()
            .map(|n| n.to_bits_le())
            .flatten()
            .collect::<Vec<Boolean>>();

        let hash_bits = hash_bits
            .into_iter()
            .take((self.required_bit_size - 1) as usize)
            .collect::<Vec<_>>();
        let hash_bits = [&[Boolean::constant(true)][..], &hash_bits].concat();
        let result = FpGadget::alloc_input(cs.ns(|| "prime"), || {
            if hash_bits.iter().any(|x| x.get_value().is_none()) {
                Err(SynthesisError::AssignmentMissing)
            } else {
                Ok(E::Fr::from_repr(<E::Fr as PrimeField>::BigInt::from_bits(
                    &hash_bits
                        .iter()
                        .map(|x| x.get_value().unwrap())
                        .collect::<Vec<_>>(),
                )))
            }
        })?;
        let result_bits = result.to_bits(cs.ns(|| "hash number to bits"))?;
        for (i, b) in result_bits
            .iter()
            .take(<E::Fr as PrimeField>::size_in_bits() - self.required_bit_size as usize)
            .enumerate()
        {
            b.enforce_equal(
                cs.ns(|| format!("enforce result header is zero, bit {}", i)),
                &Boolean::constant(false),
            )?;
        }
        for (i, (h, r)) in hash_bits
            .iter()
            .zip(
                result_bits
                    .iter()
                    .skip(<E::Fr as PrimeField>::size_in_bits() - self.required_bit_size as usize),
            )
            .enumerate()
        {
            h.enforce_equal(cs.ns(|| format!("enforce result bit {}", i)), &r)?;
        }

        Ok(())
    }
}

pub struct Protocol<E: PairingEngine, P: HashToPrimeHashParameters> {
    pub crs: CRSHashToPrime<E::G1Projective, Self>,
    parameters_type: std::marker::PhantomData<P>,
}

impl<E: PairingEngine, P: HashToPrimeHashParameters> HashToPrimeProtocol<E::G1Projective>
    for Protocol<E, P>
{
    type Proof = legogro16::Proof<E>;
    type Parameters = legogro16::Parameters<E>;

    fn from_crs(crs: &CRSHashToPrime<E::G1Projective, Self>) -> Protocol<E, P> {
        Protocol {
            crs: (*crs).clone(),
            parameters_type: std::marker::PhantomData,
        }
    }

    fn setup<R: Rng>(
        rng: &mut R,
        pedersen_commitment_parameters: &PedersenCommitment<E::G1Projective>,
        parameters: &Parameters,
    ) -> Result<Self::Parameters, SetupError> {
        let c = HashToPrimeHashCircuit::<E, P> {
            security_level: parameters.security_level,
            required_bit_size: parameters.hash_to_prime_bits,
            value: None,
            index: None,
            parameters_type: std::marker::PhantomData,
        };
        let base_one = E::G1Projective::rand(rng);
        let pedersen_bases = vec![
            base_one,
            pedersen_commitment_parameters.g,
            pedersen_commitment_parameters.h,
        ];
        Ok(legogro16::generate_random_parameters(
            c,
            &pedersen_bases,
            rng,
        )?)
    }

    fn prove<R: Rng, C: HashToPrimeVerifierChannel<E::G1Projective, Self>>(
        &self,
        verifier_channel: &mut C,
        rng: &mut R,
        _: &Statement<E::G1Projective>,
        witness: &Witness,
    ) -> Result<(), ProofError> {
        let (_, index) = self.hash_to_prime(&witness.e)?;
        let c = HashToPrimeHashCircuit::<E, P> {
            security_level: self.crs.parameters.security_level,
            required_bit_size: self.crs.parameters.hash_to_prime_bits,
            value: Some(integer_to_bigint_mod_q::<E::G1Projective>(
                &witness.e.clone(),
            )?),
            index: Some(index),
            parameters_type: std::marker::PhantomData,
        };
        let v = E::Fr::rand(rng);
        let link_v = integer_to_bigint_mod_q::<E::G1Projective>(&witness.r_q.clone())?;
        let proof = legogro16::create_random_proof::<E, _, _>(
            c,
            v,
            link_v,
            &self.crs.hash_to_prime_parameters,
            rng,
        )?;
        verifier_channel.send_proof(&proof)?;
        Ok(())
    }

    fn verify<C: HashToPrimeProverChannel<E::G1Projective, Self>>(
        &self,
        prover_channel: &mut C,
        statement: &Statement<E::G1Projective>,
    ) -> Result<(), VerificationError> {
        let proof = prover_channel.receive_proof()?;
        let pvk = legogro16::prepare_verifying_key(&self.crs.hash_to_prime_parameters.vk);
        if !legogro16::verify_proof(&pvk, &proof)? {
            return Err(VerificationError::VerificationFailed);
        }
        let proof_link_d_without_one = proof
            .link_d
            .into_projective()
            .sub(&self.crs.hash_to_prime_parameters.vk.link_bases[0]);
        if statement.c_e_q != proof_link_d_without_one {
            return Err(VerificationError::VerificationFailed);
        }

        Ok(())
    }

    fn hash_to_prime(&self, e: &Integer) -> Result<(Integer, u64), HashToPrimeError> {
        let index_bit_length = P::index_bit_length(self.crs.parameters.security_level);
        let value = integer_to_bigint_mod_q::<E::G1Projective>(e)?;
        let bigint_bits = 64 * ((E::Fr::one().neg().into_repr().num_bits() + 63) / 64);
        let bits_to_skip = bigint_bits as usize - P::MESSAGE_SIZE as usize;
        let value_raw_bits = value.into_repr().to_bits();
        for b in &value_raw_bits[..bits_to_skip] {
            if *b {
                return Err(HashToPrimeError::ValueTooBig);
            }
        }
        let mut value_bits = value_raw_bits[bits_to_skip..].to_vec();
        if value_bits.len() < P::MESSAGE_SIZE as usize {
            value_bits = [
                vec![false; P::MESSAGE_SIZE as usize - value_bits.len()],
                value_bits,
            ]
            .concat();
        }
        for index in 0..1 << index_bit_length {
            let mut index_bits = vec![];
            for i in 0..index_bit_length {
                let mask = 1u64 << i;
                let bit = mask & index == mask;
                index_bits.push(bit);
            }
            let bits_to_hash = [index_bits.as_slice(), &value_bits].concat();
            let bits_to_hash_padded = if bits_to_hash.len() % 8 != 0 {
                let padding_length = 8 - bits_to_hash.len() % 8;
                [&vec![false; padding_length][..], bits_to_hash.as_slice()].concat()
            } else {
                bits_to_hash
            };
            let bits_big_endian = bits_to_hash_padded.into_iter().rev().collect::<Vec<_>>();
            let bytes_to_hash = bits_big_endian_to_bytes_big_endian(&bits_big_endian)
                .into_iter()
                .rev()
                .collect::<Vec<_>>();
            let mut hasher = Blake2s::new_keyed(&[], 32);
            hasher.process(&bytes_to_hash);
            let hash = hasher.fixed_result();
            let hash_big_endian = hash.into_iter().rev().collect::<Vec<_>>();
            let hash_bits = [
                vec![true].as_slice(),
                bytes_big_endian_to_bits_big_endian(&hash_big_endian)
                    .into_iter()
                    .rev()
                    .take(self.crs.parameters.hash_to_prime_bits as usize - 1)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ]
            .concat();

            let element = E::Fr::from_repr(<E::Fr as PrimeField>::BigInt::from_bits(&hash_bits));
            let integer = bigint_to_integer::<E::G1Projective>(&element);
            // from the gmp documentation: "A composite number will be identified as a prime with an asymptotic probability of less than 4^(-reps)", so we choose reps = security_level/2
            let is_prime = integer.is_probably_prime(self.crs.parameters.security_level as u32 / 2);
            if is_prime == IsPrime::No {
                continue;
            }

            return Ok((integer, index));
        }

        Err(HashToPrimeError::CouldNotFindIndex)
    }
}

#[cfg(test)]
mod test {
    use super::{HashToPrimeHashCircuit, HashToPrimeHashParameters, Protocol, Statement, Witness};
    use crate::{
        commitments::Commitment,
        parameters::Parameters,
        protocols::hash_to_prime::{
            snark_hash::Protocol as HPProtocol,
            transcript::{TranscriptProverChannel, TranscriptVerifierChannel},
            HashToPrimeProtocol,
        },
        utils::{bigint_to_integer, integer_to_bigint_mod_q},
    };
    use accumulator::group::Rsa2048;
    use algebra::bls12_381::{Bls12_381, Fr, G1Projective};
    use merlin::Transcript;
    use r1cs_core::ConstraintSynthesizer;
    use r1cs_std::test_constraint_system::TestConstraintSystem;
    use rand::thread_rng;
    use rug::rand::RandState;
    use rug::Integer;
    use std::cell::RefCell;

    struct TestParameters {}
    impl HashToPrimeHashParameters for TestParameters {
        const MESSAGE_SIZE: u16 = 254;
    }

    #[test]
    fn test_circuit() {
        let mut cs = TestConstraintSystem::<Fr>::new();
        let params = Parameters::from_security_level(128).unwrap();
        let mut rng1 = RandState::new();
        rng1.seed(&Integer::from(13));
        let mut rng2 = thread_rng();

        let crs = crate::protocols::membership::Protocol::<
            Rsa2048,
            G1Projective,
            HPProtocol<Bls12_381, TestParameters>,
        >::setup(&params, &mut rng1, &mut rng2)
        .unwrap()
        .crs
        .crs_hash_to_prime;
        let protocol = Protocol::<Bls12_381, TestParameters>::from_crs(&crs);

        let value = Integer::from(12);
        let (prime, index) = protocol.hash_to_prime(&value).unwrap();
        let c = HashToPrimeHashCircuit::<Bls12_381, TestParameters> {
            security_level: crs.parameters.security_level,
            required_bit_size: crs.parameters.hash_to_prime_bits,
            value: Some(integer_to_bigint_mod_q::<G1Projective>(&value).unwrap()),
            index: Some(index),
            parameters_type: std::marker::PhantomData,
        };
        c.generate_constraints(&mut cs).unwrap();
        if !cs.is_satisfied() {
            panic!(format!(
                "not satisfied: {}",
                cs.which_is_unsatisfied().unwrap()
            ));
        }
        assert_eq!(
            prime,
            bigint_to_integer::<G1Projective>(&cs.get("prime/alloc"))
        );
    }

    #[test]
    fn test_proof() {
        let params = Parameters::from_security_level(128).unwrap();
        let mut rng1 = RandState::new();
        rng1.seed(&Integer::from(13));
        let mut rng2 = thread_rng();

        let crs = crate::protocols::membership::Protocol::<
            Rsa2048,
            G1Projective,
            HPProtocol<Bls12_381, TestParameters>,
        >::setup(&params, &mut rng1, &mut rng2)
        .unwrap()
        .crs
        .crs_hash_to_prime;
        let protocol = Protocol::<Bls12_381, TestParameters>::from_crs(&crs);

        let value = Integer::from(13);
        let (hashed_value, _) = protocol.hash_to_prime(&value).unwrap();
        let randomness = Integer::from(9);
        let commitment = protocol
            .crs
            .pedersen_commitment_parameters
            .commit(&hashed_value, &randomness)
            .unwrap();

        let proof_transcript = RefCell::new(Transcript::new(b"hash_to_prime"));
        let statement = Statement { c_e_q: commitment };
        let mut verifier_channel = TranscriptVerifierChannel::new(&crs, &proof_transcript);
        protocol
            .prove(
                &mut verifier_channel,
                &mut rng2,
                &statement,
                &Witness {
                    e: value,
                    r_q: randomness,
                },
            )
            .unwrap();

        let proof = verifier_channel.proof().unwrap();

        let verification_transcript = RefCell::new(Transcript::new(b"hash_to_prime"));
        let mut prover_channel =
            TranscriptProverChannel::new(&crs, &verification_transcript, &proof);
        protocol.verify(&mut prover_channel, &statement).unwrap();
    }
}
