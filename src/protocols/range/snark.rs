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
use crate::protocols::{
    range::{RangeProofProtocol, CRSRangeProof, Statement, Witness},
    membership_prime::{SetupError, ProofError, VerificationError},
};
use rand::Rng;
use merlin::Transcript;
use crate::transcript::TranscriptProtocolRange;

use crate::utils::{integer_to_bigint_mod_q};

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

    fn prove<'t, R: Rng>(
        &self,
        _: &'t mut Transcript,
        rng: &mut R,
        _: &Statement<E::G1Projective>,
        witness: &Witness,
    ) -> Result<Self::Proof, ProofError>
        where
            Transcript: TranscriptProtocolRange<E::G1Projective>,
    {
        let c = RangeProofCircuit::<E> {
            required_bit_size: self.crs.parameters.hash_to_prime_bits,
            value: Some(integer_to_bigint_mod_q::<E::G1Projective>(&witness.e.clone())?.into()),
        };
        let v = E::Fr::rand(rng);
        let proof = ccgro16::create_random_proof::<E, _, _>(c, v, &self.crs.range_proof_parameters, rng)?;
        Ok(proof)
    }

    fn verify<'t>(
        &self,
        _: &'t mut Transcript,
        _statement: &Statement<E::G1Projective>,
        proof: &Self::Proof,
    ) -> Result<(), VerificationError>
        where
            Transcript: TranscriptProtocolRange<E::G1Projective>,
    {
        let pvk = ccgro16::prepare_verifying_key(&self.crs.range_proof_parameters.vk);
        if !ccgro16::verify_proof(&pvk, proof)? {
            return Err(VerificationError::VerificationFailed);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    
    
    
    use rand::{self};

    #[test]
    fn test_satisfied() {
        let _rng = &mut rand::thread_rng();
    }
}