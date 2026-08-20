//! End-to-end pipeline benchmarks: steady-state in-memory encrypt/decrypt.
//!
//! `iter_batched` builds a fresh encoder/decoder pair in setup (excluded from
//! timing), so each iteration measures exactly one packet through the hot
//! path with warm scratch buffers and advancing nonce counters.
//!
//! Both framings are measured in their real data-plane state: the pair runs
//! a full handshake over a throwaway loopback socket first (pre-handshake
//! traffic always uses the base94 envelope, so without this the "binary"
//! group silently benchmarked the plaintext path). The socket is never
//! touched again — the in-memory codec paths (`encrypt_into`/`decrypt`) do
//! not touch the transport.

use std::{
    hint::black_box,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread,
};

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use nextppp_core::{ObfuscationKey, Transmission};

/// IO sink that discards writes and never reads. Retained for bench
/// authors who want a transport-free codec loop (unused by the current
/// handshake-based setup).
#[allow(dead_code)]
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

/// Handshaked encoder/decoder pair. The loopback socket carries the
/// handshake only; the codec state (keys, nonces, frame state) is
/// transport-independent from there on.
fn handshaked_pair(key: &ObfuscationKey) -> (Transmission<TcpStream>, Transmission<TcpStream>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback bind");
    let addr = listener.local_addr().expect("loopback addr");
    let server_key = key.clone();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("loopback accept");
        let mut t = Transmission::new(stream, server_key);
        t.handshake_server(1, false).expect("handshake");
        t
    });
    let mut client = Transmission::new(
        TcpStream::connect(addr).expect("loopback connect"),
        key.clone(),
    );
    client.handshake_client().expect("handshake");
    (client, server.join().expect("server thread"))
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

            // The output buffer lives in the batch state: allocating it per
            // iteration would pollute the measurement with allocator noise.
            g.bench_with_input(
                criterion::BenchmarkId::new("encrypt", size),
                &src,
                |b, src| {
                    b.iter_batched_ref(
                        || (handshaked_pair(&key).0, Vec::new()),
                        |(tx, out)| {
                            out.clear();
                            tx.encrypt_into(out, black_box(src)).unwrap();
                        },
                        // Large batches amortize the handshake-bearing setup.
                        BatchSize::LargeInput,
                    );
                },
            );
            g.bench_with_input(
                criterion::BenchmarkId::new("roundtrip", size),
                &src,
                |b, src| {
                    b.iter_batched_ref(
                        || {
                            let (tx, rx) = handshaked_pair(&key);
                            (tx, rx, Vec::new())
                        },
                        |(tx, rx, wire)| {
                            wire.clear();
                            tx.encrypt_into(wire, black_box(src)).unwrap();
                            let plain = rx.decrypt(wire).unwrap();
                            black_box(plain);
                        },
                        BatchSize::LargeInput,
                    );
                },
            );
        }
        g.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
