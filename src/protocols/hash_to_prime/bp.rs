use bulletproofs::{
    BulletproofGens,
    PedersenGens,
    r1cs::{ConstraintSystem, LinearCombination, R1CSError, R1CSProof, Prover, Verifier},
};
use curve25519_dalek::{
    ristretto::RistrettoPoint,
    scalar::Scalar,
};
use crate::{
    parameters::Parameters,
    commitments::pedersen::PedersenCommitment,
    channels::hash_to_prime::{HashToPrimeProverChannel, HashToPrimeVerifierChannel},
    utils::{integer_to_bigint_mod_q, log2, curve::Field},
    protocols::{
        hash_to_prime::{HashToPrimeProtocol, CRSHashToPrime, Statement, Witness, HashToPrimeError},
        membership::{SetupError, ProofError, VerificationError},
    }
};
use rand::Rng;
use rug::Integer;
use merlin::Transcript;

pub fn range_proof<CS: ConstraintSystem>(
    cs: &mut CS,
    mut v: LinearCombination,
    v_assignment: Option<Scalar>,
    required_bit_size: usize,
) -> Result<(), R1CSError> {
    let mut exp_2 = Scalar::one();
    let bits = v_assignment.map(|q| q.to_bits().into_iter().rev().collect::<Vec<_>>());
    for i in 0..required_bit_size {
        // Create low-level variables and add them to constraints
        let (a, b, o) = cs.allocate_multiplier(bits.as_ref().and_then(|bits| {
            let bit = if bits[i] { 1 as u64 } else { 0 };
            Some(((1 - bit).into(), bit.into()))
        }))?;

        // Enforce a * b = 0, so one of (a,b) is zero
        cs.constrain(o.into());

        // Enforce that a = 1 - b, so they both are 1 or 0.
        cs.constrain(a + (b - 1u64));

        // if this is the highest order bit, ensure it's set
        if i == required_bit_size - 1 {
            cs.constrain(b - 1u64);
        }

        // Add `-b_i*2^i` to the linear combination
        // in order to form the following constraint by the end of the loop:
        // v = Sum(b_i * 2^i, i = 0..n-1)
        v = v - b * exp_2;

        exp_2 = exp_2 + exp_2;
    }

    // Enforce that v = Sum(b_i * 2^i, i = 0..n-1)
    //cs.constrain(v);

    Ok(())
}

pub struct Protocol {
    pub crs: CRSHashToPrime<RistrettoPoint, Self>,
}

impl HashToPrimeProtocol<RistrettoPoint> for Protocol {
    type Proof = R1CSProof;
    type Parameters = BulletproofGens;

    fn from_crs(
        crs: &CRSHashToPrime<RistrettoPoint, Self>
    ) -> Protocol {
        Protocol {
            crs: (*crs).clone(),
        }
    }

    fn setup<R: Rng>(_: &mut R, _: &PedersenCommitment<RistrettoPoint>, parameters: &Parameters) -> Result<Self::Parameters, SetupError> {
        let rounded_hash_to_prime_bits = 1 << log2(parameters.hash_to_prime_bits as usize);
        Ok(BulletproofGens::new(rounded_hash_to_prime_bits, 1))
    }

    fn prove<R: Rng, C: HashToPrimeVerifierChannel<RistrettoPoint, Self>>(
        &self,
        verifier_channel: &mut C,
        _: &mut R,
        _: &Statement<RistrettoPoint>,
        witness: &Witness,
    ) -> Result<(), ProofError>
    {
        let pedersen_gens = PedersenGens {
            B: self.crs.pedersen_commitment_parameters.g,
            B_blinding: self.crs.pedersen_commitment_parameters.h,
        };

        let (proof, _) = {
            let mut prover_transcript = Transcript::new(b"bp_range_proof");

            let mut prover = Prover::new(&pedersen_gens, &mut prover_transcript);

            let value = integer_to_bigint_mod_q::<RistrettoPoint>(&witness.e)?;
            let randomness = integer_to_bigint_mod_q::<RistrettoPoint>(&witness.r_q)?;
            let (com, var) = prover.commit(value, randomness);
            assert!(range_proof(&mut prover, var.into(), Some(value), self.crs.parameters.hash_to_prime_bits as usize).is_ok());

            let proof = prover.prove(&self.crs.hash_to_prime_parameters)?;

            (proof, com)
        };

        verifier_channel.send_proof(&proof)?;

        Ok(())
    }

    fn verify<C: HashToPrimeProverChannel<RistrettoPoint, Self>> (
        &self,
        prover_channel: &mut C,
        statement: &Statement<RistrettoPoint>,
    ) -> Result<(), VerificationError>
    {
        let pedersen_gens = PedersenGens {
            B: self.crs.pedersen_commitment_parameters.g,
            B_blinding: self.crs.pedersen_commitment_parameters.h,
        };

        let mut verifier_transcript = Transcript::new(b"bp_range_proof");
        let mut verifier = Verifier::new(&mut verifier_transcript);

        let var = verifier.commit(statement.c_e_q.compress());

        assert!(range_proof(&mut verifier, var.into(), None, self.crs.parameters.hash_to_prime_bits as usize).is_ok());

        let proof = prover_channel.receive_proof()?;
        Ok(verifier.verify(&proof, &pedersen_gens, &self.crs.hash_to_prime_parameters)?)
    }

    fn hash_to_prime(&self, e: &Integer) -> Result<(Integer, u64), HashToPrimeError>  {
        Ok((e.clone(), 0))
    }
}

#[cfg(test)]
mod tests {
    use rug::Integer;
    use std::cell::RefCell;
    use rand::thread_rng;
    use crate::{
        parameters::Parameters,
        commitments::Commitment,
        transcript::hash_to_prime::{TranscriptProverChannel, TranscriptVerifierChannel},
        protocols::hash_to_prime::{
            HashToPrimeProtocol,
            bp::Protocol as HPProtocol,
        },
    };
    use rug::rand::RandState;
    use accumulator::group::Rsa2048;
    use super::{Protocol, Statement, Witness};
    use curve25519_dalek::{
        scalar::Scalar,
        ristretto::RistrettoPoint,
    };
    use merlin::Transcript;

    #[test]
    fn test_proof() {
        let params = Parameters::from_curve::<Scalar>().unwrap().0;
        let mut rng1 = RandState::new();
        rng1.seed(&Integer::from(13));
        let mut rng2 = thread_rng();

        let crs = crate::protocols::membership::Protocol::<Rsa2048, RistrettoPoint, HPProtocol>::setup(&params, &mut rng1, &mut rng2).unwrap().crs.crs_hash_to_prime;
        let protocol = Protocol::from_crs(&crs);

        let value = Integer::from(Integer::u_pow_u(
                2,
                (crs.parameters.hash_to_prime_bits)
                    as u32,
            )) - &Integer::from(129);
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

        let verification_transcript = RefCell::new(Transcript::new(b"hash_to_prime"));
        let mut prover_channel = TranscriptProverChannel::new(&crs, &verification_transcript, &proof);
        protocol.verify(&mut prover_channel, &statement).unwrap();
    }
}

