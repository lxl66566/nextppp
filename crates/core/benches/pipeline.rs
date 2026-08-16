//! End-to-end pipeline benchmarks: steady-state in-memory encrypt/decrypt.
//!
//! `iter_batched` builds a fresh encoder/decoder pair in setup (excluded from
//! timing), so each iteration measures exactly one packet through the hot
//! path with warm scratch buffers and advancing nonce counters.

use std::io::{Read, Write};

use criterion::{BatchSize, Criterion, Throughput, black_box, criterion_group, criterion_main};
use openppp3_core::{ObfuscationKey, Transmission};

/// IO sink that discards writes and never reads: the in-memory codec paths
/// (`encrypt_into`/`decrypt`) never touch it.
struct NullIo;
impl Read for NullIo {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Ok(0)
    }
}
impl Write for NullIo {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn data(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    let mut s = 0xfeed_face_dead_beefu64;
    for b in &mut v {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        *b = (s >> 56) as u8;
    }
    v
}

fn bench(c: &mut Criterion) {
    for (group_name, plaintext_mode) in [("pipeline_plaintext", true), ("pipeline_binary", false)] {
        let key = ObfuscationKey {
            plaintext: plaintext_mode,
            ..ObfuscationKey::default()
        };
        let mut g = c.benchmark_group(group_name);

        for size in [64usize, 1024, 16384, 65536] {
            let src = data(size);
            g.throughput(Throughput::Bytes(size as u64));

            g.bench_with_input(
                criterion::BenchmarkId::new("encrypt", size),
                &src,
                |b, src| {
                    b.iter_batched_ref(
                        || Transmission::new(NullIo, key.clone()),
                        |tx| {
                            let mut out = Vec::new();
                            tx.encrypt_into(&mut out, black_box(src)).unwrap();
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
            g.bench_with_input(
                criterion::BenchmarkId::new("roundtrip", size),
                &src,
                |b, src| {
                    b.iter_batched_ref(
                        || {
                            (
                                Transmission::new(NullIo, key.clone()),
                                Transmission::new(NullIo, key.clone()),
                                Vec::new(),
                            )
                        },
                        |(tx, rx, wire)| {
                            wire.clear();
                            tx.encrypt_into(wire, black_box(src)).unwrap();
                            let plain = rx.decrypt(wire).unwrap();
                            black_box(plain);
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }
        g.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
