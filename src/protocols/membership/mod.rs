use crate::{
    utils::ConvertibleUnknownOrderGroup,
    parameters::Parameters,
    commitments::{
        Commitment, integer::IntegerCommitment, pedersen::PedersenCommitment, CommitmentError,
    },
    protocols::{
        root::{CRSRoot, Protocol as RootProtocol, Statement as RootStatement, Witness as RootWitness, Proof as RootProof},
        modeq::{CRSModEq, Protocol as ModEqProtocol, Statement as ModEqStatement, Witness as ModEqWitness, Proof as ModEqProof},
        hash_to_prime::{CRSHashToPrime, HashToPrimeProtocol, Statement as HashToPrimeStatement, Witness as HashToPrimeWitness, HashToPrimeError},
    },
    channels::{membership::*, root::*, modeq::*, hash_to_prime::*, ChannelError},
    utils::{curve::CurvePointProjective, random_between},
};
use rug::rand::MutRandState;
use rand::{RngCore, CryptoRng};
use rug::Integer;
use r1cs_core::SynthesisError;

quick_error! {
    #[derive(Debug)]
    pub enum SetupError {
        CouldNotPerformSetup {}
        SNARKError(err: SynthesisError) {
            from()
        }
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum ProofError {
        CouldNotCreateProof {}
        CommitmentError(err: CommitmentError) {
            from()
        }
        IntegerError(err: Integer) {
            from()
        }
        SNARKError(err: SynthesisError) {
            from()
        }
        VerifierChannelError(err: ChannelError) {
            from()
        }
        PrimeError(err: HashToPrimeError) {
            from()
        }
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum VerificationError {
        VerificationFailed {}
        CommitmentError(err: CommitmentError) {
            from()
        }
        IntegerError(err: Integer) {
            from()
        }
        SNARKError(err: SynthesisError) {
            from()
        }
        ProverChannelError(err: ChannelError) {
            from()
        }
    }
}

pub struct CRS<G: ConvertibleUnknownOrderGroup, P: CurvePointProjective, HP: HashToPrimeProtocol<P>> {
    // G contains the information about Z^*_N
    pub parameters: Parameters,
    pub crs_root: CRSRoot<G>,
    pub crs_modeq: CRSModEq<G, P>,
    pub crs_hash_to_prime: CRSHashToPrime<P, HP>,
}

impl<
    G: ConvertibleUnknownOrderGroup, 
    P: CurvePointProjective, 
    HP: HashToPrimeProtocol<P>
 > Clone for CRS<G, P, HP> {
    fn clone(&self) -> Self {
        Self {
            parameters: self.parameters.clone(),
            crs_root: self.crs_root.clone(),
            crs_modeq: self.crs_modeq.clone(),
            crs_hash_to_prime: self.crs_hash_to_prime.clone(),
        }
    }
}


pub struct Protocol<G: ConvertibleUnknownOrderGroup, P: CurvePointProjective, HP: HashToPrimeProtocol<P>> {
    pub crs: CRS<G, P, HP>,
}

pub struct Statement<G: ConvertibleUnknownOrderGroup, P: CurvePointProjective> {
    pub c_p: G::Elem,
    pub c_e_q: <PedersenCommitment<P> as Commitment>::Instance,
}

pub struct Witness<G: ConvertibleUnknownOrderGroup> {
    pub e: Integer,
    pub r_q: Integer,
    pub w: G::Elem,
}

pub struct Proof<G: ConvertibleUnknownOrderGroup, P: CurvePointProjective, HP: HashToPrimeProtocol<P>> {
    pub c_e: <IntegerCommitment<G> as Commitment>::Instance,
    pub proof_root: RootProof<G>,
    pub proof_modeq: ModEqProof<G, P>,
    pub proof_hash_to_prime: HP::Proof,
}

impl<
    G: ConvertibleUnknownOrderGroup, 
    P: CurvePointProjective, 
    HP: HashToPrimeProtocol<P>
 > Clone for Proof<G, P, HP> {
    fn clone(&self) -> Self {
        Self {
            c_e: self.c_e.clone(),
            proof_root: self.proof_root.clone(),
            proof_modeq: self.proof_modeq.clone(),
            proof_hash_to_prime: self.proof_hash_to_prime.clone(),
        }
    }
}

impl<G: ConvertibleUnknownOrderGroup, P: CurvePointProjective, HP: HashToPrimeProtocol<P>> Protocol<G, P, HP> {
    pub fn setup<R1: MutRandState, R2: RngCore + CryptoRng>(
        parameters: &Parameters,
        rng1: &mut R1,
        rng2: &mut R2,
    ) -> Result<Protocol<G, P, HP>, SetupError> {
        let integer_commitment_parameters = IntegerCommitment::<G>::setup(rng1);
        let pedersen_commitment_parameters = PedersenCommitment::<P>::setup(rng2);
        let hash_to_prime_parameters = HP::setup(rng2, &pedersen_commitment_parameters, parameters)?;
        Ok(Protocol {
            crs: CRS::<G, P, HP> {
                parameters: parameters.clone(),
                crs_modeq: CRSModEq::<G, P> {
                    parameters: parameters.clone(),
                    integer_commitment_parameters: integer_commitment_parameters.clone(),
                    pedersen_commitment_parameters: pedersen_commitment_parameters.clone(),
                },
                crs_root: CRSRoot::<G> {
                    parameters: parameters.clone(),
                    integer_commitment_parameters: integer_commitment_parameters.clone(),
                },
                crs_hash_to_prime: CRSHashToPrime::<P, HP> {
                    parameters: parameters.clone(),
                    pedersen_commitment_parameters: pedersen_commitment_parameters.clone(),
                    hash_to_prime_parameters: hash_to_prime_parameters.clone(),
                }

            }
        })
    }

    pub fn prove<
        R1: MutRandState, 
        R2: RngCore + CryptoRng, 
        C: MembershipVerifierChannel<G> + RootVerifierChannel<G> + ModEqVerifierChannel<G, P> + HashToPrimeVerifierChannel<P, HP>,
    > (
        &self,
        verifier_channel: &mut C,
        rng1: &mut R1,
        rng2: &mut R2,
        statement: &Statement<G, P>,
        witness: &Witness<G>,
    ) -> Result<(), ProofError> {
        let r = random_between(rng1, &Integer::from(0), &G::order_upper_bound());
        let c_e = self.crs.crs_root.integer_commitment_parameters.commit(
            &witness.e, 
            &r,
        )?;
        verifier_channel.send_c_e(&c_e)?;
        let root = RootProtocol::from_crs(&self.crs.crs_root);
        root.prove(verifier_channel, rng1, &RootStatement {
            c_e: c_e.clone(),
            acc: statement.c_p.clone(),
        }, &RootWitness {
            e: witness.e.clone(),
            r: r.clone(),
            w: witness.w.clone(),
        })?;
        let modeq = ModEqProtocol::from_crs(&self.crs.crs_modeq);
        modeq.prove(verifier_channel, rng1, rng2, &ModEqStatement {
            c_e: c_e.clone(),
            c_e_q: statement.c_e_q.clone(),
        }, &ModEqWitness {
            e: witness.e.clone(),
            r: r.clone(),
            r_q: witness.r_q.clone(),
        })?;
        let hash_to_prime = HashToPrimeProtocol::from_crs(&self.crs.crs_hash_to_prime);
        hash_to_prime.prove(verifier_channel, rng2, &HashToPrimeStatement {
            c_e_q: statement.c_e_q.clone(),
        }, &HashToPrimeWitness {
            e: witness.e.clone(),
            r_q: witness.r_q.clone(),
        })?;

        Ok(())
    }

    pub fn verify<C: MembershipProverChannel<G> + RootProverChannel<G> + ModEqProverChannel<G, P> + HashToPrimeProverChannel<P, HP>>(
        &self,
        prover_channel: &mut C,
        statement: &Statement<G, P>,
    ) -> Result<(), VerificationError>
    {
        let c_e = prover_channel.receive_c_e()?;
        let root = RootProtocol::from_crs(&self.crs.crs_root);
        root.verify(prover_channel, &RootStatement {
            c_e: c_e.clone(),
            acc: statement.c_p.clone(),
        })?;
        let modeq = ModEqProtocol::from_crs(&self.crs.crs_modeq);
        modeq.verify(prover_channel, &ModEqStatement {
            c_e: c_e.clone(),
            c_e_q: statement.c_e_q.clone(),
        })?;
        let hash_to_prime = HashToPrimeProtocol::from_crs(&self.crs.crs_hash_to_prime);
        hash_to_prime.verify(prover_channel, &HashToPrimeStatement {
            c_e_q: statement.c_e_q.clone(),
        })?;

        Ok(())
    }

    pub fn from_crs(
        crs: &CRS<G, P, HP>
    ) -> Protocol<G, P, HP> {
        Protocol {
            crs: crs.clone(),
        }
    }
}

#[cfg(test)]
mod test {
    use rug::Integer;
    use std::cell::RefCell;
    use algebra::bls12_381::{Bls12_381, G1Projective};
    use rand::thread_rng;
    use crate::{
        parameters::Parameters,
        commitments::Commitment,
        transcript::membership::{TranscriptProverChannel, TranscriptVerifierChannel},
        protocols::hash_to_prime::snark::Protocol as HPProtocol,
    };
    use rug::rand::RandState;
    use accumulator::group::Rsa2048;
    use super::{Protocol, Statement, Witness};
    use merlin::Transcript;
    use accumulator::{AccumulatorWithoutHashToPrime, group::Group};

    const LARGE_PRIMES: [u64; 4] = [
        553_525_575_239_331_913,
        12_702_637_924_034_044_211,
        378_373_571_372_703_133,
        8_640_171_141_336_142_787,
    ];

    #[test]
    fn test_e2e() {
        let params = Parameters::from_security_level(128).unwrap();
        let mut rng1 = RandState::new();
        rng1.seed(&Integer::from(13));
        let mut rng2 = thread_rng();

        let crs = crate::protocols::membership::Protocol::<Rsa2048, G1Projective, HPProtocol<Bls12_381>>::setup(&params, &mut rng1, &mut rng2).unwrap().crs;
        let protocol = Protocol::<Rsa2048, G1Projective, HPProtocol<Bls12_381>>::from_crs(&crs);

        let value = Integer::from(Integer::u_pow_u(
                2,
                (crs.parameters.hash_to_prime_bits)
                    as u32,
            )) - &Integer::from(245);
        let randomness = Integer::from(5);
        let commitment = protocol.crs.crs_modeq.pedersen_commitment_parameters.commit(&value, &randomness).unwrap();

        let accum = accumulator::Accumulator::<Rsa2048, Integer, AccumulatorWithoutHashToPrime>::empty();
        let accum = accum.add(&LARGE_PRIMES.iter().skip(1).map(|p| Integer::from(*p)).collect::<Vec<_>>());

        let accum = accum.add_with_proof(&[value.clone()]);
        let acc = accum.0.value;
        let w = accum.1.witness.0.value;
        assert_eq!(Rsa2048::exp(&w, &value), acc);


        let proof_transcript = RefCell::new(Transcript::new(b"membership"));
        let mut verifier_channel = TranscriptVerifierChannel::new(&crs, &proof_transcript);
        let statement = Statement {
            c_e_q: commitment,
            c_p: acc,
        };
        protocol.prove(&mut verifier_channel, &mut rng1, &mut rng2, &statement, &Witness {
            e: value,
            r_q: randomness,
            w,
        }).unwrap();
        let proof = verifier_channel.proof().unwrap();
        let verification_transcript = RefCell::new(Transcript::new(b"membership"));
        let mut prover_channel = TranscriptProverChannel::new(&crs, &verification_transcript, &proof);
        protocol.verify(&mut prover_channel, &statement).unwrap();
    }
}