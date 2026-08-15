//! End-to-end integration tests over an in-memory duplex pipe.

// Pseudo-random generators and protocol values use intentional narrowing casts.
#![allow(clippy::cast_possible_truncation)]

use std::{
    collections::VecDeque,
    io::{self, Read, Write},
    sync::{Arc, Condvar, Mutex},
    thread::scope,
};

use openppp3_core::{Error, Method, ObfuscationKey, Transmission};

// ---------------------------------------------------------------------------
// Minimal blocking in-memory duplex pipe (std::io::duplex is still unstable).
// ---------------------------------------------------------------------------

struct PipeShared {
    buf: VecDeque<u8>,
    closed: bool,
}

#[derive(Clone)]
struct PipeChannel {
    shared: Arc<Mutex<PipeShared>>,
    cvar: Arc<Condvar>,
}

impl PipeChannel {
    fn new() -> Self {
        Self {
            shared: Arc::new(Mutex::new(PipeShared {
                buf: VecDeque::new(),
                closed: false,
            })),
            cvar: Arc::new(Condvar::new()),
        }
    }
}

/// One end of an unbounded, thread-safe, blocking duplex pipe.
#[derive(Clone)]
pub struct PipeEnd {
    rx: PipeChannel,
    tx: PipeChannel,
}

/// Creates a connected pipe pair.
fn duplex_pair() -> (PipeEnd, PipeEnd) {
    let a2b = PipeChannel::new();
    let b2a = PipeChannel::new();
    (
        PipeEnd {
            rx: b2a.clone(),
            tx: a2b.clone(),
        },
        PipeEnd { rx: a2b, tx: b2a },
    )
}

impl Read for PipeEnd {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut guard = self.rx.shared.lock().unwrap();
        loop {
            if !guard.buf.is_empty() {
                let n = out.len().min(guard.buf.len());
                for slot in &mut out[..n] {
                    *slot = guard.buf.pop_front().expect("non-empty");
                }
                return Ok(n);
            }
            if guard.closed {
                return Ok(0);
            }
            guard = self.rx.cvar.wait(guard).unwrap();
        }
    }
}

impl Write for PipeEnd {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut guard = self.tx.shared.lock().unwrap();
        guard.buf.extend(data.iter().copied());
        drop(guard);
        self.tx.cvar.notify_all();
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for PipeEnd {
    fn drop(&mut self) {
        let mut guard = self.tx.shared.lock().unwrap();
        guard.closed = true;
        drop(guard);
        self.tx.cvar.notify_all();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const TEST_SID: u128 = 0x1234_5678_9abc_def0_1234_5678_9abc_def0;

type Pair = (Transmission<PipeEnd>, Transmission<PipeEnd>);

/// Handshakes a client/server pair over a duplex pipe and returns both ends.
fn make_pair(client_key: ObfuscationKey, server_key: ObfuscationKey, mux: bool) -> Pair {
    let (client_io, server_io) = duplex_pair();
    scope(|s| {
        let server = s.spawn(move || {
            let mut server = Transmission::new(server_io, server_key);
            server.handshake_server(TEST_SID, mux).unwrap();
            server
        });
        let mut client = Transmission::new(client_io, client_key);
        let (sid, client_mux) = client.handshake_client().unwrap();
        assert_eq!(client_mux, mux);
        assert_eq!(sid, TEST_SID);
        let server = server.join().unwrap();
        (client, server)
    })
}

fn default_pair() -> Pair {
    make_pair(ObfuscationKey::default(), ObfuscationKey::default(), false)
}

#[test]
fn handshake_and_bidirectional_transfer() {
    let (mut client, mut server) = default_pair();
    let payloads: Vec<Vec<u8>> = vec![
        b"hello".to_vec(),
        vec![0u8; 1],
        (0..=255u32).map(|i| i as u8).collect(),
        vec![0xab; 65536],
    ];
    for payload in &payloads {
        client.write(payload).unwrap();
        assert_eq!(&server.read().unwrap(), payload);

        server.write(payload).unwrap();
        assert_eq!(&client.read().unwrap(), payload);
    }
}

#[test]
fn many_small_messages_in_sequence() {
    let (mut client, mut server) = default_pair();
    for i in 0..200u32 {
        let msg = format!("message-{i}").into_bytes();
        client.write(&msg).unwrap();
        assert_eq!(server.read().unwrap(), msg);
    }
}

#[test]
fn pre_handshake_traffic_is_printable() {
    // Capture the raw client->server bytes emitted before any handshake:
    // everything on the wire must be printable ASCII.
    let (client_io, mut server_raw) = duplex_pair();
    {
        let mut client = Transmission::new(client_io, ObfuscationKey::default());
        client.write(b"probe").unwrap();
    } // dropping the transmission drops the pipe end -> writer closed

    let mut buf = [0u8; 8192];
    let n = server_raw.read(&mut buf).unwrap();
    assert!(n > 0);
    for &b in &buf[..n] {
        assert!((0x20..=0x7e).contains(&b), "non-printable byte {b:#04x}");
    }
    // EOF after close.
    assert_eq!(server_raw.read(&mut buf).unwrap(), 0);
}

#[test]
fn mux_negotiation_parity() {
    let (mut client, mut server) =
        make_pair(ObfuscationKey::default(), ObfuscationKey::default(), true);
    client.write(b"post-mux").unwrap();
    assert_eq!(server.read().unwrap(), b"post-mux");
}

#[test]
fn flag_canary_mismatch_client_error() {
    let client_key = ObfuscationKey {
        shuffle_data: !ObfuscationKey::default().shuffle_data,
        ..ObfuscationKey::default()
    };
    let (client_io, server_io) = duplex_pair();
    let mut client = Transmission::new(client_io, client_key);
    let server_thread = std::thread::spawn(move || {
        let mut server = Transmission::new(server_io, ObfuscationKey::default());
        // Server finishes its side; the client rejects the canary instead.
        let _ = server.handshake_server(7, false);
    });
    let err = client.handshake_client().unwrap_err();
    server_thread.join().unwrap();
    assert_eq!(err, Error::FlagsMismatch);
}

#[test]
fn kf_mismatch_breaks_handshake() {
    let mut client_key = ObfuscationKey::default();
    client_key.kf ^= 0x0101;
    let (client_io, server_io) = duplex_pair();
    let mut client = Transmission::new(client_io, client_key);
    let server_thread = std::thread::spawn(move || {
        let mut server = Transmission::new(server_io, ObfuscationKey::default());
        // kf feeds the first-frame checksum: the server cannot decode the
        // client's NOP prelude and fails quickly.
        let _ = server.handshake_server(7, false);
    });
    // The client must fail too (EOF after the server tears down, or a decode
    // error); a "successful" handshake is impossible with mismatched kf.
    assert!(client.handshake_client().is_err());
    server_thread.join().unwrap();
}

#[test]
fn wrong_password_yields_garbage_not_plaintext() {
    // With differing transport passwords the base94 layer still decodes (kf
    // matches) and the binary frame stays structurally valid, so decrypt
    // returns "Ok" — but the payload is indistinguishable-from-random
    // garbage, never the peer's plaintext. (This layer provides no MAC by
    // design, mirroring openppp2: integrity of handshake values comes from
    // session-id parsing + the flag canary + first-frame checksum.)
    let server_key = ObfuscationKey {
        transport_key: String::from("different-password"),
        ..ObfuscationKey::default()
    };
    let mut a = Transmission::new((), ObfuscationKey::default());
    let mut b = Transmission::new((), server_key);

    let mut wire = Vec::new();
    a.encrypt_into(&mut wire, b"secret").unwrap();
    let garbage = b.decrypt(&wire).unwrap();
    assert_eq!(garbage.len(), b"secret".len());
    assert_ne!(&garbage, b"secret");
}

#[test]
fn zero_length_write_rejected() {
    let (mut client, _server) = default_pair();
    assert_eq!(client.write(&[]), Err(Error::ZeroLength));
    assert_eq!(
        client.encrypt_into(&mut Vec::new(), b""),
        Err(Error::ZeroLength)
    );
}

#[test]
fn in_memory_path_interops_with_streaming() {
    // vmux-style in-memory packets decode identically on both sides.
    // Pre-handshake: no I/O bound needed at all.
    let mut a = Transmission::new((), ObfuscationKey::default());
    let mut b = Transmission::new((), ObfuscationKey::default());

    let mut wire = Vec::new();
    a.encrypt_into(&mut wire, b"pre-handshake").unwrap();
    assert_eq!(b.decrypt(&wire).unwrap(), b"pre-handshake");

    let mut wire = Vec::new();
    b.encrypt_into(&mut wire, b"reply-pre").unwrap();
    assert_eq!(a.decrypt(&wire).unwrap(), b"reply-pre");

    // Post-handshake in-memory path over a real handshake.
    let (mut client, mut server) = default_pair();
    let mut wire = Vec::new();
    client.encrypt_into(&mut wire, b"after-handshake").unwrap();
    assert_eq!(server.decrypt(&wire).unwrap(), b"after-handshake");

    let mut wire = Vec::new();
    server.encrypt_into(&mut wire, b"reply-post").unwrap();
    assert_eq!(client.decrypt(&wire).unwrap(), b"reply-post");
}

#[test]
fn all_cipher_methods_interop() {
    for (proto, transport) in [
        (Method::Aes128Cfb, Method::Aes256Cfb),
        (Method::Aes256Ctr, Method::Aes256Ctr),
        (Method::Aes128Ctr, Method::ChaCha20),
        (Method::ChaCha20, Method::ChaCha20),
        (Method::Aes256Cfb, Method::Aes128Ctr),
    ] {
        let key = ObfuscationKey {
            protocol: proto,
            transport,
            ..ObfuscationKey::default()
        };
        let (mut client, mut server) = make_pair(key.clone(), key, false);
        client.write(b"cipher-interop").unwrap();
        assert_eq!(server.read().unwrap(), b"cipher-interop");
        server.write(b"ok").unwrap();
        assert_eq!(client.read().unwrap(), b"ok");
    }
}

#[test]
fn binary_mode_after_handshake() {
    // plaintext=false: post-handshake frames use the 3-byte binary header
    // without the base94 envelope.
    let key = ObfuscationKey {
        plaintext: false,
        ..ObfuscationKey::default()
    };
    let (mut client, mut server) = make_pair(key.clone(), key, false);
    let payload = vec![0x5a; 4096];
    client.write(&payload).unwrap();
    assert_eq!(server.read().unwrap(), payload);
    server.write(&payload).unwrap();
    assert_eq!(client.read().unwrap(), payload);
}

#[test]
fn random_sized_roundtrip() {
    // Pseudo-random payload sizes exercise all frame-length digit widths.
    let mut state = 0x1234_5678u64;
    let mut next = |n: u64| {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (state >> 33) % n
    };
    let (mut client, mut server) = default_pair();
    for _ in 0..30 {
        let len = 1 + next(8000) as usize;
        let payload: Vec<u8> = (0..len).map(|_| next(256) as u8).collect();
        client.write(&payload).unwrap();
        assert_eq!(server.read().unwrap(), payload);
    }
}

#[test]
fn truncated_packet_rejected_in_memory() {
    // Truncation/splicing must be rejected by the exact-length checks.
    let (mut client, mut server) = default_pair();
    let mut wire = Vec::new();
    client
        .encrypt_into(&mut wire, b"will-be-truncated")
        .unwrap();
    assert_eq!(
        server.decrypt(&wire[..wire.len() - 1]).unwrap_err(),
        Error::InvalidFrame
    );
    let mut doubled = wire.clone();
    doubled.extend_from_slice(&wire);
    assert_eq!(server.decrypt(&doubled).unwrap_err(), Error::InvalidFrame);
    assert_eq!(server.decrypt(&wire).unwrap(), b"will-be-truncated");
}

#[test]
fn session_id_and_state_reported() {
    let (client, _server) = default_pair();
    assert!(client.is_handshaked());
    assert_eq!(client.session_id(), TEST_SID);
}

#[test]
fn abrupt_close_surfaces_io_error() {
    let (mut client, server_io) = duplex_pair();
    let mut client = Transmission::new(&mut client, ObfuscationKey::default());
    let server_holder = std::thread::spawn(move || {
        // Server never handshakes; holding the end keeps the pipe open.
        std::thread::sleep(std::time::Duration::from_millis(50));
        drop(server_io);
    });
    let err = client.handshake_client().unwrap_err();
    server_holder.join().unwrap();
    assert!(err.is_eof(), "expected EOF, got {err:?}");
}

#[test]
fn split_halves_interop_with_unsplit_peer() {
    // Both sides split, exchanging data concurrently in both directions:
    // the classic two-thread pump model used by the proxy server/client.
    for plaintext in [true, false] {
        let key = ObfuscationKey {
            plaintext,
            ..ObfuscationKey::default()
        };
        let (client_io, server_io) = duplex_pair();
        scope(|s| {
            let server_key = key.clone();
            let server = s.spawn(move || {
                let mut server = Transmission::new(server_io, server_key);
                server.handshake_server(TEST_SID, false).unwrap();
                let (mut tx, mut rx) = {
                    let rx_io = server.io().clone();
                    server.split_with(rx_io)
                };
                // Upstream -> client while the client pumps the other way.
                let pump = s.spawn(move || {
                    for i in 0..50u32 {
                        tx.write(format!("srv-{i}").as_bytes()).unwrap();
                    }
                    tx
                });
                for i in 0..50u32 {
                    assert_eq!(rx.read().unwrap(), format!("cli-{i}").as_bytes());
                }
                pump.join().unwrap()
            });

            let mut client = Transmission::new(client_io, key);
            client.handshake_client().unwrap();
            let rx_io = client.io().clone();
            let (mut tx, mut rx) = client.split_with(rx_io);
            let pump = scope(|s2| {
                let rx = s2.spawn(move || {
                    for i in 0..50u32 {
                        assert_eq!(rx.read().unwrap(), format!("srv-{i}").as_bytes());
                    }
                    rx
                });
                for i in 0..50u32 {
                    tx.write(format!("cli-{i}").as_bytes()).unwrap();
                }
                rx.join().unwrap()
            });
            drop((tx, pump));
            server.join().unwrap();
        });
    }
}
