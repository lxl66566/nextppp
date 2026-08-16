#![no_main]

//! Fuzzing the stateful `Base94Framer` (base94 framing layer): encode/decode
//! roundtrip over the streaming and in-memory paths, the extended-then-simple
//! header sequence, printable-output invariant, and no-panic on garbage.

use libfuzzer_sys::fuzz_target;
use nextppp_core::frame::base94::Base94Framer;
use rand::{SeedableRng, rngs::StdRng};

fuzz_target!(|data: &[u8]| {
    let (&kf0, rest) = data.split_first().unwrap_or((&0, &[]));
    let (&kf1, payload) = rest.split_first().unwrap_or((&0, &[]));
    let kf = u32::from(u16::from(kf0) | (u16::from(kf1) << 8));
    let mut seed = 0u64;
    for (i, &b) in data.iter().take(8).enumerate() {
        seed ^= u64::from(b) << (8 * i);
    }
    let mut rng = StdRng::seed_from_u64(seed);

    // Single-frame roundtrip over the in-memory datagram path.
    let mut tx = Base94Framer::new(kf);
    let mut rx = Base94Framer::new(kf);
    let mut wire = Vec::new();
    if payload.is_empty() {
        // Encode/decode symmetry: empty payloads are rejected at encode time.
        assert!(matches!(
            tx.encode_frame(&mut rng, &mut wire, payload),
            Err(nextppp_core::error::Error::ZeroLength)
        ));
        assert!(wire.is_empty());
    } else if tx.encode_frame(&mut rng, &mut wire, payload).is_ok() {
        assert!(wire.iter().all(|&c| (0x20..=0x7e).contains(&c)));
        assert_eq!(rx.decode_packet(&wire).unwrap(), payload);
    }

    // Multi-frame sequence over the streaming path: the first frame must use
    // the extended header, later frames the simple one.
    let mut tx2 = Base94Framer::new(kf);
    let mut rx2 = Base94Framer::new(kf);
    let mut wire2 = Vec::new();
    let mid = payload.len() / 2;
    let (a, b) = payload.split_at(mid);
    if tx2.encode_frame(&mut rng, &mut wire2, a).is_ok()
        && tx2.encode_frame(&mut rng, &mut wire2, b).is_ok()
    {
        let mut stream: &[u8] = &wire2;
        assert_eq!(rx2.read_frame(&mut stream).unwrap(), a);
        assert_eq!(rx2.read_frame(&mut stream).unwrap(), b);
        assert!(stream.is_empty(), "frame must be consumed exactly");
    }

    // Garbage decode must never panic.
    let mut rx3 = Base94Framer::new(kf);
    let _ = rx3.decode_packet(payload);
});