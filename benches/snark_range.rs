use accumulator::group::Rsa2048;
use algebra::bls12_381::{Bls12_381, G1Projective};
use cpsnarks_set::commitments::Commitment;
use cpsnarks_set::{
    parameters::Parameters,
    protocols::hash_to_prime::{
        snark_range::Protocol, HashToPrimeProtocol, Statement, Witness, transcript::{TranscriptProverChannel, TranscriptVerifierChannel},
    },
};
use criterion::{criterion_group, criterion_main, Criterion};
use merlin::Transcript;
use rand::thread_rng;
use rug::rand::RandState;
use rug::Integer;
use std::cell::RefCell;

pub fn criterion_benchmark(c: &mut Criterion) {
    let params = Parameters::from_security_level(128).unwrap();
    let mut rng1 = RandState::new();
    rng1.seed(&Integer::from(13));
    let mut rng2 = thread_rng();

    let crs = cpsnarks_set::protocols::membership::Protocol::<
        Rsa2048,
        G1Projective,
        Protocol<Bls12_381>,
    >::setup(&params, &mut rng1, &mut rng2)
    .unwrap()
    .crs
    .crs_hash_to_prime;
    let protocol = Protocol::<Bls12_381>::from_crs(&crs);

    let value = Integer::from(Integer::u_pow_u(
        2,
        (crs.parameters.hash_to_prime_bits) as u32,
    )) - &Integer::from(245);
    let randomness = Integer::from(9);
    let commitment = protocol
        .crs
        .pedersen_commitment_parameters
        .commit(&value, &randomness)
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
                e: value.clone(),
                r_q: randomness.clone(),
            },
        )
        .unwrap();

    let proof = verifier_channel.proof().unwrap();

    let verification_transcript = RefCell::new(Transcript::new(b"hash_to_prime"));
    let mut prover_channel = TranscriptProverChannel::new(&crs, &verification_transcript, &proof);
    protocol.verify(&mut prover_channel, &statement).unwrap();

    c.bench_function("snark_range protocol", |b| {
        b.iter(|| {
            let proof_transcript = RefCell::new(Transcript::new(b"hash_to_prime"));
            let statement = Statement { c_e_q: commitment };
            let mut verifier_channel = TranscriptVerifierChannel::new(&crs, &proof_transcript);
            protocol
                .prove(
                    &mut verifier_channel,
                    &mut rng2,
                    &statement,
                    &Witness {
                        e: value.clone(),
                        r_q: randomness.clone(),
                    },
                )
                .unwrap();
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
