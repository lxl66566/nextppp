#![no_main]

//! Differential fuzzing: the SIMD-assisted encoder must match an independent
//! scalar reference bit-for-bit, pinning the exact wire format (not just the
//! roundtrip). Also checks `encoded_len` and the append-to-prefix contract.

use libfuzzer_sys::fuzz_target;

const ESCAPE_RADIX: u8 = 93;

/// Independent reference: greedy scalar encode written straight from the
/// format definition (`v = (b - kf) mod 256`; `v >= 93` escapes into a
/// `0x7D`/`0x7E` leader + follower).
fn encode_reference(out: &mut Vec<u8>, src: &[u8], kf: u32) {
    let kf8 = kf as u8;
    for &b in src {
        let v = b.wrapping_sub(kf8);
        if v < ESCAPE_RADIX {
            out.push(0x20 + v);
        } else if v < 2 * ESCAPE_RADIX {
            out.push(0x7d);
            out.push(0x20 + (v - ESCAPE_RADIX));
        } else {
            out.push(0x7e);
            out.push(0x20 + (v - 2 * ESCAPE_RADIX));
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let (&kf, payload) = data.split_first().unwrap_or((&0, &[]));
    let kf = u32::from(kf);

    let mut want = Vec::new();
    encode_reference(&mut want, payload, kf);

    let mut got = Vec::new();
    base94_simd::encode_into(&mut got, payload, kf);
    assert_eq!(got, want, "encode diverged from reference on {payload:?} kf={kf}");
    assert_eq!(
        got.len(),
        base94_simd::encoded_len(payload, kf),
        "encoded_len diverged on {payload:?} kf={kf}"
    );

    // Append semantics: a pre-seeded output must keep its prefix.
    let mut prefix = Vec::new();
    encode_reference(&mut prefix, b"prefix", kf);
    let mut appended = prefix.clone();
    base94_simd::encode_into(&mut appended, payload, kf);
    assert_eq!(appended, [prefix.as_slice(), want.as_slice()].concat());
});