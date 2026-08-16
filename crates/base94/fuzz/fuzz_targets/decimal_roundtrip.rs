#![no_main]

//! Fuzzing the base94 digit codec (`decimal_encode`/`decimal_decode`):
//! roundtrip for arbitrary u64 values, zero-padding decode, and a
//! differential decode against a u128 reference that cannot overflow.

use libfuzzer_sys::fuzz_target;

const SYMBOL_COUNT: u128 = 94;

/// Independent reference: parse base94 digits with u128 accumulation (no
/// overflow possible for <= 10 digits), failing when the value exceeds u64.
fn decode_reference(s: &[u8]) -> Result<u64, ()> {
    if s.is_empty() {
        return Err(());
    }
    let mut n: u128 = 0;
    for &c in s {
        if c < 0x20 {
            return Err(());
        }
        let d = u128::from(c - 0x20);
        if d >= SYMBOL_COUNT {
            return Err(());
        }
        n = n * SYMBOL_COUNT + d;
        if n > u64::MAX as u128 {
            return Err(());
        }
    }
    Ok(n as u64)
}

fuzz_target!(|data: &[u8]| {
    // First up-to-8 bytes drive the roundtrip value (little-endian).
    let mut v = 0u64;
    for (i, &b) in data.iter().take(8).enumerate() {
        v |= u64::from(b) << (8 * i);
    }

    // Roundtrip: minimal digits must decode back exactly.
    let mut buf = [0u8; base94_simd::DECIMAL_MAX_LEN];
    let len = base94_simd::decimal_encode(v, &mut buf);
    assert!((1..=base94_simd::DECIMAL_MAX_LEN).contains(&len));
    let digits = &buf[..len];
    assert!(digits.iter().all(|&c| c >= 0x20));
    if v > 0 {
        assert_ne!(digits[0], 0x20, "no leading zero");
    }
    assert_eq!(
        base94_simd::decimal_decode(digits).unwrap(),
        v,
        "roundtrip failed for {v}"
    );

    // Zero-padding: any u64 fits in 10 digits, so a 0x20-padded decode must
    // succeed and reproduce v.
    let mut padded = [0x20u8; base94_simd::DECIMAL_MAX_LEN];
    padded[base94_simd::DECIMAL_MAX_LEN - len..].copy_from_slice(digits);
    assert_eq!(base94_simd::decimal_decode(&padded).unwrap(), v);

    // Differential decode on the remaining bytes (arbitrary garbage).
    let s = data.get(8..).unwrap_or(&[]);
    let got = base94_simd::decimal_decode(s);
    let want = decode_reference(s);
    assert_eq!(got.is_ok(), want.is_ok(), "ok-ness diverged on {s:?}");
    if let Ok(w) = want {
        assert_eq!(got.unwrap(), w, "value diverged on {s:?}");
    }
});