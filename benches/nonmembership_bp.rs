use accumulator::group::Rsa2048;
use accumulator::{group::Group, AccumulatorWithoutHashToPrime};
use cpsnarks_set::{
    commitments::Commitment,
    parameters::Parameters,
    protocols::{
        hash_to_prime::bp::Protocol as HPProtocol,
        nonmembership::{Protocol, Statement, Witness},
    },
    transcript::nonmembership::{TranscriptProverChannel, TranscriptVerifierChannel},
};
use criterion::{criterion_group, criterion_main, Criterion};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use merlin::Transcript;
use rand::thread_rng;
use rug::rand::RandState;
use rug::Integer;
use std::cell::RefCell;

const LARGE_PRIMES: [u64; 3] = [
    12_702_637_924_034_044_211,
    378_373_571_372_703_133,
    8_640_171_141_336_142_787,
];

pub fn criterion_benchmark(c: &mut Criterion) {
    let params = Parameters::from_curve::<Scalar>().unwrap().0;
    println!("params: {}", params);
    let mut rng1 = RandState::new();
    rng1.seed(&Integer::from(13));
    let mut rng2 = thread_rng();

    let mut crs = cpsnarks_set::protocols::nonmembership::Protocol::<
        Rsa2048,
        RistrettoPoint,
        HPProtocol,
    >::setup(&params, &mut rng1, &mut rng2)
    .unwrap()
    .crs;
    let protocol = Protocol::<Rsa2048, RistrettoPoint, HPProtocol>::from_crs(&crs);

    let value = Integer::from(Integer::u_pow_u(
        2,
        (crs.parameters.hash_to_prime_bits) as u32,
    )) - &Integer::from(129);
    let randomness = Integer::from(5);
    let commitment = protocol
        .crs
        .crs_modeq
        .pedersen_commitment_parameters
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
        protocol.crs.crs_coprime.integer_commitment_parameters.g
    );

    let proof_transcript = RefCell::new(Transcript::new(b"nonmembership"));
    crs.crs_hash_to_prime.hash_to_prime_parameters.transcript = Some(proof_transcript.clone());
    let mut verifier_channel = TranscriptVerifierChannel::new(&crs, &proof_transcript);
    let statement = Statement {
        c_e_q: commitment,
        c_p: acc.clone(),
    };
    protocol
        .prove(
            &mut verifier_channel,
            &mut rng1,
            &mut rng2,
            &statement,
            &Witness {
                e: value.clone(),
                r_q: randomness.clone(),
                d: d.clone(),
                b: b.clone(),
            },
        )
        .unwrap();
    let proof = verifier_channel.proof().unwrap();
    let verification_transcript = RefCell::new(Transcript::new(b"nonmembership"));
    crs.crs_hash_to_prime.hash_to_prime_parameters.transcript =
        Some(verification_transcript.clone());
    let mut prover_channel = TranscriptProverChannel::new(&crs, &verification_transcript, &proof);
    protocol.verify(&mut prover_channel, &statement).unwrap();

    c.bench_function("nonmembership_bp protocol", |be| {
        be.iter(|| {
            let proof_transcript = RefCell::new(Transcript::new(b"nonmembership"));
            crs.crs_hash_to_prime.hash_to_prime_parameters.transcript =
                Some(proof_transcript.clone());
            let mut verifier_channel = TranscriptVerifierChannel::new(&crs, &proof_transcript);
            let statement = Statement {
                c_e_q: commitment,
                c_p: acc.clone(),
            };
            protocol
                .prove(
                    &mut verifier_channel,
                    &mut rng1,
                    &mut rng2,
                    &statement,
                    &Witness {
                        e: value.clone(),
                        r_q: randomness.clone(),
                        d: d.clone(),
                        b: b.clone(),
                    },
                )
                .unwrap();
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
