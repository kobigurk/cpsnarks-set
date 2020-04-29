use accumulator::group::Rsa2048;
use accumulator::{group::Group, AccumulatorWithoutHashToPrime};
use algebra::{
    bls12_381::{Bls12_381, Fr, G1Projective},
    PrimeField,
};
use cpsnarks_set::{
    commitments::Commitment,
    parameters::Parameters,
    protocols::{
        hash_to_prime::{snark_range::Protocol as HPProtocol, CRSSize},
        membership::{
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
    let params = Parameters::from_curve_and_small_prime_size::<Fr>(50, 70)
        .unwrap()
        .0;
    println!("params: {}", params);
    let mut rng1 = RandState::new();
    rng1.seed(&Integer::from(13));
    let mut rng2 = thread_rng();

    let crs = cpsnarks_set::protocols::membership::Protocol::<
        Rsa2048,
        G1Projective,
        HPProtocol<Bls12_381>,
    >::setup(&params, &mut rng1, &mut rng2)
    .unwrap()
    .crs;
    println!(
        "crs size: {:?}",
        crs.crs_hash_to_prime.hash_to_prime_parameters.crs_size()
    );
    let protocol = Protocol::<Rsa2048, G1Projective, HPProtocol<Bls12_381>>::from_crs(&crs);

    let value = Integer::from(Integer::u_pow_u(
        2,
        (crs.parameters.hash_to_prime_bits) as u32,
    )) - &Integer::from(245);
    let randomness =
        Integer::from(Integer::u_pow_u(2, Fr::size_in_bits() as u32)).random_below(&mut rng1);
    let commitment = protocol
        .crs
        .crs_modeq
        .pedersen_commitment_parameters
        .commit(&value, &randomness)
        .unwrap();

    let accum =
        accumulator::Accumulator::<Rsa2048, Integer, AccumulatorWithoutHashToPrime>::empty();
    let accum = accum.add(
        &LARGE_PRIMES
            .iter()
            .skip(1)
            .map(|p| Integer::from(*p))
            .collect::<Vec<_>>(),
    );

    let accum = accum.add_with_proof(&[value.clone()]);
    let acc = accum.0.value;
    let w = accum.1.witness.0.value;
    assert_eq!(Rsa2048::exp(&w, &value), acc);

    let proof_transcript = RefCell::new(Transcript::new(b"membership"));
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
                w: w.clone(),
            },
        )
        .unwrap();
    let proof = verifier_channel.proof().unwrap();
    let verification_transcript = RefCell::new(Transcript::new(b"membership"));
    let mut prover_channel = TranscriptProverChannel::new(&crs, &verification_transcript, &proof);
    protocol.verify(&mut prover_channel, &statement).unwrap();

    c.bench_function("membership_prime_60 protocol proving", |b| {
        b.iter(|| {
            let proof_transcript = RefCell::new(Transcript::new(b"membership"));
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
                        w: w.clone(),
                    },
                )
                .unwrap();
        })
    });

    c.bench_function("membership_prime_60 protocol verification", |b| {
        b.iter(|| {
            let verification_transcript = RefCell::new(Transcript::new(b"membership"));
            let mut prover_channel =
                TranscriptProverChannel::new(&crs, &verification_transcript, &proof);
            protocol.verify(&mut prover_channel, &statement).unwrap();
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
