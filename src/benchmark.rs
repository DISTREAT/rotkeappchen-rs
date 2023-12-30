use criterion::{criterion_group, criterion_main, Criterion};
use rotkeappchen::Rotkeappchen;

fn benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("benchmark");
    let rot = Rotkeappchen::default(b"secret", 1);

    group.bench_function("generation", |b| {
        b.iter(|| {
            _ = rot.digest("client");
        })
    });

    group.bench_function("verification", |b| {
        b.iter(|| rot.is_valid("client", |_| false))
    });

    group.bench_function("symbiosis", |b| {
        b.iter(|| {
            let code = rot.digest("client");
            assert!(rot.is_valid("client", |digest| digest == code))
        })
    });
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
