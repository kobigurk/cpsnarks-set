//! Implements an abstract hash-to-prime protocol, which can also be just a range proof.
use crate::{
    commitments::{pedersen::PedersenCommitment, Commitment},
    parameters::Parameters,
    protocols::{ProofError, SetupError, VerificationError},
    utils::curve::CurvePointProjective,
};
use channel::{HashToPrimeProverChannel, HashToPrimeVerifierChannel};
use rand::{CryptoRng, RngCore};
use rug::Integer;

pub mod channel;
pub mod transcript;

cfg_if::cfg_if! {
    if #[cfg(feature = "zexe")] {
        pub mod snark_hash;
        pub mod snark_range;

        use algebra_core::{PairingEngine, ConstantSerializedSize, CanonicalSerialize};

        impl<E: PairingEngine> CRSSize for legogro16::Parameters::<E> {
            fn crs_size(&self) -> (usize, usize) {
                let mut vk_accum = 0;
                // Groth16 vk
                vk_accum += self.vk.alpha_g1.serialized_size();
                vk_accum += self.vk.beta_g2.serialized_size();
                vk_accum += self.vk.gamma_g2.serialized_size();
                vk_accum += self.vk.delta_g2.serialized_size();
                for g in &self.vk.gamma_abc_g1 {
                    vk_accum += g.serialized_size();
                }
                vk_accum += self.vk.eta_gamma_inv_g1.serialized_size();

                // link
                vk_accum += 8; // l
                vk_accum += 8; // t
                vk_accum += E::G1Affine::SERIALIZED_SIZE;
                vk_accum += E::G2Affine::SERIALIZED_SIZE;

                for b in &self.vk.link_bases {
                    vk_accum += b.serialized_size();
                }
                vk_accum += E::G2Affine::SERIALIZED_SIZE;
                for b in &self.vk.link_vk.c {
                    vk_accum += b.serialized_size();
                }

                let mut pk_accum = 0;
                pk_accum += self.beta_g1.serialized_size();
                pk_accum += self.delta_g1.serialized_size();
                pk_accum += self.eta_delta_inv_g1.serialized_size();
                pk_accum += self.eta_delta_inv_g1.serialized_size();
                for g in &self.a_query {
                    pk_accum += g.serialized_size();
                }
                for g in &self.b_g1_query {
                    pk_accum += g.serialized_size();
                }
                for g in &self.b_g2_query {
                    pk_accum += g.serialized_size();
                }
                for g in &self.h_query {
                    pk_accum += g.serialized_size();
                }
                for g in &self.l_query {
                    pk_accum += g.serialized_size();
                }
                for g in &self.link_ek.p {
                    pk_accum += g.serialized_size();
                }

                (vk_accum, pk_accum)
            }
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature = "dalek")] {
        pub mod bp;
    }
}

pub trait CRSSize {
    fn crs_size(&self) -> (usize, usize);
}

pub trait HashToPrimeProtocol<P: CurvePointProjective> {
    type Proof: Clone;
    type Parameters: Clone;

    fn from_crs(crs: &CRSHashToPrime<P, Self>) -> Self
    where
        Self: Sized;

    fn setup<R: RngCore + CryptoRng>(
        rng: &mut R,
        pedersen_commitment_parameters: &PedersenCommitment<P>,
        parameters: &Parameters,
    ) -> Result<Self::Parameters, SetupError>;

    fn prove<R: RngCore + CryptoRng, C: HashToPrimeVerifierChannel<P, Self>>(
        &self,
        verifier_channel: &mut C,
        rng: &mut R,
        _: &Statement<P>,
        witness: &Witness,
    ) -> Result<(), ProofError>
    where
        Self: Sized;
    fn verify<C: HashToPrimeProverChannel<P, Self>>(
        &self,
        prover_channel: &mut C,
        statement: &Statement<P>,
    ) -> Result<(), VerificationError>
    where
        Self: Sized;
    fn hash_to_prime(&self, e: &Integer) -> Result<(Integer, u64), HashToPrimeError>;
}

pub struct CRSHashToPrime<P: CurvePointProjective, HP: HashToPrimeProtocol<P>> {
    pub parameters: Parameters,
    pub pedersen_commitment_parameters: PedersenCommitment<P>,
    pub hash_to_prime_parameters: HP::Parameters,
}

impl<P: CurvePointProjective, HP: HashToPrimeProtocol<P>> Clone for CRSHashToPrime<P, HP> {
    fn clone(&self) -> Self {
        Self {
            parameters: self.parameters.clone(),
            pedersen_commitment_parameters: self.pedersen_commitment_parameters.clone(),
            hash_to_prime_parameters: self.hash_to_prime_parameters.clone(),
        }
    }
}

pub struct Statement<P: CurvePointProjective> {
    pub c_e_q: <PedersenCommitment<P> as Commitment>::Instance,
}

pub struct Witness {
    pub e: Integer,
    pub r_q: Integer,
}

quick_error! {
    #[derive(Debug)]
    pub enum HashToPrimeError {
        CouldNotFindIndex {}
        ValueTooBig {}
        IntegerError(num: Integer) {
            from()
        }
    }
}
