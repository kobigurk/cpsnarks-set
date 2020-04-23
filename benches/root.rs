use accumulator::group::{Group, Rsa2048};
use accumulator::AccumulatorWithoutHashToPrime;
use algebra::bls12_381::{Bls12_381, G1Projective};
use cpsnarks_set::commitments::Commitment;
use cpsnarks_set::{
    parameters::Parameters,
    protocols::{
        hash_to_prime::snark_range::Protocol as HPProtocol,
        root::{
            transcript::{TranscriptProverChannel, TranscriptVerifierChannel},
            Protocol, Statement, Witness,
        },
    },
};
use criterion::{criterion_group, criterion_main, Criterion};
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
    let params = Parameters::from_security_level(128).unwrap();
    let mut rng1 = RandState::new();
    rng1.seed(&Integer::from(13));
    let mut rng2 = thread_rng();

    let crs = cpsnarks_set::protocols::membership::Protocol::<
        Rsa2048,
        G1Projective,
        HPProtocol<Bls12_381>,
    >::setup(&params, &mut rng1, &mut rng2)
    .unwrap()
    .crs
    .crs_root;
    let protocol = Protocol::<Rsa2048>::from_crs(&crs);

    // prime from https://primes.utm.edu/lists/2small/200bit.html
    let value = (Integer::from(1) << 256) - 189;
    let randomness = Integer::from(5);
    let commitment = protocol
        .crs
        .integer_commitment_parameters
        .commit(&value, &randomness)
        .unwrap();

    let accum =
        accumulator::Accumulator::<Rsa2048, Integer, AccumulatorWithoutHashToPrime>::empty();
    let accum = accum.add(
        &LARGE_PRIMES
            .iter()
            .map(|p| Integer::from(*p))
            .collect::<Vec<_>>(),
    );

    let accum = accum.add_with_proof(&[value.clone()]);
    let acc = accum.0.value;
    let w = accum.1.witness.0.value;
    assert_eq!(Rsa2048::exp(&w, &value), acc);

    let proof_transcript = RefCell::new(Transcript::new(b"root"));
    let mut verifier_channel = TranscriptVerifierChannel::new(&crs, &proof_transcript);
    let statement = Statement {
        c_e: commitment.clone(),
        acc: acc.clone(),
    };
    protocol
        .prove(
            &mut verifier_channel,
            &mut rng1,
            &statement,
            &Witness {
                e: value.clone(),
                r: randomness.clone(),
                w: w.clone(),
            },
        )
        .unwrap();

    let verification_transcript = RefCell::new(Transcript::new(b"root"));
    let mut prover_channel = TranscriptProverChannel::new(
        &crs,
        &verification_transcript,
        &verifier_channel.proof().unwrap(),
    );
    protocol.verify(&mut prover_channel, &statement).unwrap();

    c.bench_function("root protocol", |b| {
        b.iter(|| {
            let proof_transcript = RefCell::new(Transcript::new(b"root"));
            let mut verifier_channel = TranscriptVerifierChannel::new(&crs, &proof_transcript);
            let statement = Statement {
                c_e: commitment.clone(),
                acc: acc.clone(),
            };
            protocol
                .prove(
                    &mut verifier_channel,
                    &mut rng1,
                    &statement,
                    &Witness {
                        e: value.clone(),
                        r: randomness.clone(),
                        w: w.clone(),
                    },
                )
                .unwrap();
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
