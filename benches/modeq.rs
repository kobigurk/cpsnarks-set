use criterion::{criterion_group, criterion_main, Criterion};
use rug::Integer;
use std::cell::RefCell;
use algebra::bls12_381::{Bls12_381, G1Projective};
use rand::thread_rng;
use cpsnarks_set::commitments::Commitment;
use rug::rand::RandState;
use accumulator::group::Rsa2048;
use cpsnarks_set::{
    protocols::{
        modeq::{Protocol, Statement, Witness},
        hash_to_prime::snark_range::Protocol as HPProtocol,
    },
    parameters::Parameters,
    transcript::modeq::{TranscriptVerifierChannel, TranscriptProverChannel}
};
use merlin::Transcript;

pub fn criterion_benchmark(c: &mut Criterion) {
    let params = Parameters::from_security_level(128).unwrap();
    let mut rng1 = RandState::new();
    rng1.seed(&Integer::from(13));
    let mut rng2 = thread_rng();

    let crs = cpsnarks_set::protocols::membership::Protocol::<Rsa2048, G1Projective, HPProtocol<Bls12_381>>::setup(&params, &mut rng1, &mut rng2).unwrap().crs.crs_modeq;
    let protocol = Protocol::<Rsa2048, G1Projective>::from_crs(&crs);

    let value1 = Integer::from(2);
    let randomness1 = Integer::from(5);
    let randomness2 = Integer::from(9);
    let commitment1 = protocol.crs.integer_commitment_parameters.commit(&value1, &randomness1).unwrap();
    let commitment2 = protocol.crs.pedersen_commitment_parameters.commit(&value1, &randomness2).unwrap();

    let proof_transcript = RefCell::new(Transcript::new(b"modeq"));
    let mut verifier_channel = TranscriptVerifierChannel::new(&crs, &proof_transcript);
    let statement = Statement {
        c_e: commitment1.clone(),
        c_e_q: commitment2.clone(),
    };
    protocol.prove(&mut verifier_channel, &mut rng1, &mut rng2, &statement, &Witness {
        e: value1.clone(),
        r: randomness1.clone(),
        r_q: randomness2.clone(),
    }).unwrap();

    let verification_transcript = RefCell::new(Transcript::new(b"modeq"));
    let mut prover_channel = TranscriptProverChannel::new(&crs, &verification_transcript, &verifier_channel.proof().unwrap());
    protocol.verify(&mut prover_channel, &statement).unwrap();

    c.bench_function("modeq protocol", |b| b.iter(|| {
        let proof_transcript = RefCell::new(Transcript::new(b"modeq"));
        let mut verifier_channel = TranscriptVerifierChannel::new(&crs, &proof_transcript);
        let statement = Statement {
            c_e: commitment1.clone(),
            c_e_q: commitment2.clone(),
        };
        protocol.prove(&mut verifier_channel, &mut rng1, &mut rng2, &statement, &Witness {
            e: value1.clone(),
            r: randomness1.clone(),
            r_q: randomness2.clone(),
        }).unwrap();
    }));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
