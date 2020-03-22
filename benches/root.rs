use criterion::{criterion_group, criterion_main, Criterion};
use rug::Integer;
use algebra::bls12_381::{Bls12_381, G1Projective};
use rand_xorshift::XorShiftRng;
use rand::SeedableRng;
use cpsnarks_set::commitments::Commitment;
use rug::rand::RandState;
use accumulator::group::{Group, Rsa2048};
use cpsnarks_set::{
    protocols::{
        root::{Protocol, Statement, Witness},
        range::snark::Protocol as RPProtocol,
    },
    parameters::Parameters,
    transcript::root::{TranscriptVerifierChannel, TranscriptProverChannel}
};
use merlin::Transcript;
use accumulator::AccumulatorWithoutHashToPrime;

const LARGE_PRIMES: [u64; 3] = [
    12_702_637_924_034_044_211,
    378_373_571_372_703_133,
    8_640_171_141_336_142_787,
];


pub fn criterion_benchmark(c: &mut Criterion) {
    let params = Parameters::from_security_level(128).unwrap();
    let mut rng1 = RandState::new();
    rng1.seed(&Integer::from(13));
    let mut rng2 = XorShiftRng::seed_from_u64(1231275789u64);

    let crs = cpsnarks_set::protocols::membership::Protocol::<Rsa2048, G1Projective, RPProtocol<Bls12_381>>::setup(&params, &mut rng1, &mut rng2).unwrap().crs.crs_root;
    let protocol = Protocol::<Rsa2048>::from_crs(&crs);

    // prime from https://primes.utm.edu/lists/2small/200bit.html
    let value = (Integer::from(1) << 256) - 189;
    let randomness = Integer::from(5);
    let commitment = protocol.crs.integer_commitment_parameters.commit(&value, &randomness).unwrap();

    let accum = accumulator::Accumulator::<Rsa2048, Integer, AccumulatorWithoutHashToPrime>::empty();
    let accum = accum.add(&LARGE_PRIMES.iter().map(|p| Integer::from(*p)).collect::<Vec<_>>());

    let accum = accum.add_with_proof(&[value.clone()]);
    let acc = accum.0.value;
    let w = accum.1.witness.0.value;
    assert_eq!(Rsa2048::exp(&w, &value), acc);

    let mut proof_transcript = Transcript::new(b"root");
    let mut verifier_channel = TranscriptVerifierChannel::new(&crs, &mut proof_transcript);
    let statement = Statement {
        c_e: commitment.clone(),
        acc: acc.clone(),
    };
    protocol.prove(&mut verifier_channel, &mut rng1, &statement, &Witness {
        e: value.clone(),
        r: randomness.clone(),
        w: w.clone(),
    }).unwrap();

    let mut verification_transcript = Transcript::new(b"root");
    let mut prover_channel = TranscriptProverChannel::new(&crs, &mut verification_transcript, &verifier_channel.proof().unwrap());
    protocol.verify(&mut prover_channel, &statement).unwrap();

    c.bench_function("root protocol", |b| b.iter(|| {
        let mut proof_transcript = Transcript::new(b"root");
        let mut verifier_channel = TranscriptVerifierChannel::new(&crs, &mut proof_transcript);
        let statement = Statement {
            c_e: commitment.clone(),
            acc: acc.clone(),
        };
        protocol.prove(&mut verifier_channel, &mut rng1, &statement, &Witness {
            e: value.clone(),
            r: randomness.clone(),
            w: w.clone(),
        }).unwrap();
    }));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
