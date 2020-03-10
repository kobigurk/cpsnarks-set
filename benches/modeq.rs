use rug::Integer;
use algebra::jubjub::JubJubProjective;
use rand_xorshift::XorShiftRng;
use rand::SeedableRng;
use cpsnarks_set::commitments::Commitment;
use rug::rand::RandState;
use accumulator::group::Rsa2048;
use cpsnarks_set::protocols::modeq::{Protocol, Statement, Witness};
use cpsnarks_set::parameters::Parameters;
use merlin::Transcript;

use criterion::{criterion_group, criterion_main, Criterion};

pub fn criterion_benchmark(c: &mut Criterion) {
    let params = Parameters::from_security_level(128).unwrap();
    let mut rng1 = RandState::new();
    rng1.seed(&Integer::from(13));
    let mut rng2 = XorShiftRng::seed_from_u64(1231275789u64);

    let crs = cpsnarks_set::protocols::membership_prime::Protocol::<Rsa2048, JubJubProjective>::setup(&params, &mut rng1, &mut rng2).crs.crs_modeq;
    let protocol = Protocol::<Rsa2048, JubJubProjective>::from_crs(&crs);

    let value1 = Integer::from(2);
    let randomness1 = Integer::from(5);
    let randomness2 = Integer::from(9);
    let commitment1 = protocol.crs.integer_commitment_parameters.commit(&value1, &randomness1).unwrap();
    let commitment2 = protocol.crs.pedersen_commitment_parameters.commit(&value1, &randomness2).unwrap();

    let mut proof_transcript = Transcript::new(b"modeq");
    let statement = Statement {
        c_e: commitment1.clone(),
        c_e_q: commitment2.clone(),
    };
    let proof = protocol.prove(&mut proof_transcript, &mut rng1, &mut rng2, &statement, &Witness {
        e: value1.clone(),
        r: randomness1.clone(),
        r_q: randomness2.clone(),
    }).unwrap();

    let mut verification_transcript = Transcript::new(b"modeq");
    protocol.verify(&mut verification_transcript, &statement, &proof).unwrap();

    c.bench_function("modeq protocol", |b| b.iter(|| {
        let mut proof_transcript = Transcript::new(b"modeq");
        let statement = Statement {
            c_e: commitment1.clone(),
            c_e_q: commitment2.clone(),
        };
        protocol.prove(&mut proof_transcript, &mut rng1, &mut rng2, &statement, &Witness {
            e: value1.clone(),
            r: randomness1.clone(),
            r_q: randomness2.clone(),
        }).unwrap();
    }));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
