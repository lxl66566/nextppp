//! Micro-benchmarks for the SSEA obfuscation primitives (hot per-packet path).

use std::hint::black_box;

use base94_simd::{
    decode_into_kf as base94_decode_into, encode_into_kf as base94_encode_into,
    encoded_len_kf as base94_encoded_len,
};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use nextppp_core::crypto::{
    cipher::{CipherRole, Method, SessionCipher},
    ssea::{delta_decode, delta_encode, masked_xor_random_next, shuffle, unshuffle},
};

const N: usize = 65536;

/// Deterministic xorshift fill (bench data only; no CSPRNG needed).
fn data(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    let mut s = 0x1234_5678_9abc_def0u64;
    for b in &mut v {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        *b = (s >> 56) as u8;
    }
    v
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("ssea");
    g.throughput(Throughput::Bytes(N as u64));

    let src = data(N);
    let mut buf = src.clone();

    g.bench_function("shuffle", |b| {
        b.iter(|| shuffle(black_box(&mut buf), black_box(0x5bd1_6a7f)));
    });
    g.bench_function("unshuffle", |b| {
        b.iter(|| unshuffle(black_box(&mut buf), black_box(0x5bd1_6a7f)));
    });
    g.bench_function("masked_xor", |b| {
        b.iter(|| masked_xor_random_next(black_box(&mut buf), black_box(0x5bd1_6a7f)));
    });
    g.bench_function("delta_encode", |b| {
        b.iter(|| delta_encode(black_box(&mut buf), black_box(154_543_927)));
    });
    g.bench_function("delta_decode", |b| {
        b.iter(|| delta_decode(black_box(&mut buf), black_box(154_543_927)));
    });

    let kf = 154_543_927u32;
    let mut encoded = Vec::new();
    base94_encode_into(&mut encoded, &src, kf);
    let mut decoded = Vec::new();
    g.bench_function("base94_encode", |b| {
        b.iter(|| {
            encoded.clear();
            base94_encode_into(&mut encoded, black_box(&src), kf);
        });
    });
    g.bench_function("base94_decode", |b| {
        b.iter(|| {
            decoded.clear();
            base94_decode_into(&mut decoded, black_box(&encoded), kf).unwrap();
        });
    });
    g.bench_function("base94_encoded_len", |b| {
        b.iter(|| base94_encoded_len(black_box(&src), kf));
    });
    drop(decoded);
    drop(encoded);

    // Session cipher: large payload (transport) and 2-byte header (protocol).
    let mut transport = SessionCipher::new(Method::Aes256Cfb, CipherRole::Transport, "bench-key");
    g.bench_function("cipher_aes256cfb_payload", |b| {
        b.iter(|| transport.apply(black_box(&mut buf)));
    });
    let mut protocol = SessionCipher::new(Method::Aes128Cfb, CipherRole::Protocol, "bench-key");
    let mut two = [0x11u8, 0x22];
    g.bench_function("cipher_aes128cfb_header2b", |b| {
        b.iter(|| protocol.apply(black_box(&mut two)));
    });

    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
