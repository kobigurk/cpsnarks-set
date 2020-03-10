use rug::Integer;
use rug::rand::RandState;
use accumulator::group::{UnknownOrderGroup, ElemFrom, Group, Rsa2048};
use cpsnarks_set::parameters::Parameters;

use criterion::{criterion_group, criterion_main, Criterion};
use cpsnarks_set::utils::{random_between, random_symmetric_range};

pub fn criterion_benchmark(c: &mut Criterion) {
    let params = Parameters::from_security_level(128).unwrap();
    let mut rng1 = RandState::new();
    rng1.seed(&Integer::from(13));


    c.bench_function("RSA exponentiation", |b| b.iter(|| {
        let e = Rsa2048::elem(&random_between(&mut rng1, &Integer::from(0), &Rsa2048::order_upper_bound()));
        let r_range = Integer::from(
            Rsa2048::order_upper_bound() / 4
                * Integer::from(Integer::u_pow_u(
                2,
                (params.security_zk + params.security_soundness)
                    as u32,
            )),
        );
        let r = random_symmetric_range(&mut rng1, &r_range);
        Rsa2048::exp(&e, &r);
    }));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
