//! SSEA obfuscation primitives, a faithful port of openppp2
//! `ppp/cryptography/ssea.cpp`.
//!
//! Every primitive keeps the reference wrapping byte semantics so the
//! anti-censorship behavior (printable output, length obfuscation, key
//! mixing) stays identical to the battle-tested C++ implementation.

// Intentional truncating/wrapping casts below mirror the C++ `Byte(int)`
// conversions: the protocol relies on low-byte / modulo-256 semantics.
#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]

use crate::error::{Error, Result};

/// Number of printable symbols: 0x20..0x7E.
pub const BASE94_SYMBOL_COUNT: u8 = 94;
/// Escape radix: values >= 93 are encoded as two characters.
const BASE93_RADIX: u8 = 93;
/// Max digits of a u64 in base 94 (94^10 > 2^64 > 94^9).
pub const BASE94_DECIMAL_MAX_LEN: usize = 10;

/// Advances the 31-bit LCG seed and returns a 31-bit value
/// (ssea.cpp `random_next`).
#[must_use]
pub fn lcg_next(seed: &mut u32) -> u32 {
    let mut next = *seed;
    next = next.wrapping_mul(1_103_515_245).wrapping_add(12_345);
    let mut result = (next / 65_536) % 2048;
    next = next.wrapping_mul(1_103_515_245).wrapping_add(12_345);
    result = (result << 10) ^ ((next / 65_536) % 1024);
    next = next.wrapping_mul(1_103_515_245).wrapping_add(12_345);
    result = (result << 10) ^ ((next / 65_536) % 1024);
    *seed = next;
    result
}

/// Closed-range LCG sample in `[min, max]` (ssea.cpp `random_next(seed,..)`).
#[must_use]
pub fn lcg_range(seed: &mut u32, min: u32, max: u32) -> u32 {
    debug_assert!(min <= max, "lcg_range requires min <= max");
    lcg_next(seed) % (max - min + 1) + min
}

/// Key-driven in-place permutation (ssea.cpp `shuffle_data`).
///
/// `j = (i ^ key) % size` produces a deterministic key-dependent swap chain;
/// not a cryptographic permutation but effective against naive DPI pattern
/// matching at negligible cost. (Note: for size <= 2 the chain degenerates to
/// the identity permutation, exactly like the C++ original.)
pub fn shuffle(data: &mut [u8], key: u32) {
    let size = data.len();
    if size < 2 {
        return;
    }
    let size32 = u32::try_from(size).expect("frames are far below 4 GiB");
    for i in 0..size {
        let j = ((i as u32 ^ key) % size32) as usize;
        data.swap(i, j);
    }
}

/// Exact inverse of [`shuffle`], running the swap chain backwards.
pub fn unshuffle(data: &mut [u8], key: u32) {
    let size = data.len();
    if size < 2 {
        return;
    }
    let size32 = u32::try_from(size).expect("frames are far below 4 GiB");
    for i in (0..size).rev() {
        let j = ((i as u32 ^ key) % size32) as usize;
        data.swap(i, j);
    }
}

/// In-place delta encoding: `out[0] = in[0] - kf`, `out[i] = in[i] - in[i-1]`.
///
/// Safe to run in place: the previous plaintext byte is kept in a local.
pub fn delta_encode(data: &mut [u8], kf: u32) {
    let kf8 = kf as u8;
    if data.is_empty() {
        return;
    }
    let mut prev = data[0];
    data[0] = prev.wrapping_sub(kf8);
    for b in &mut data[1..] {
        let cur = *b;
        *b = cur.wrapping_sub(prev);
        prev = cur;
    }
}

/// In-place inverse of [`delta_encode`].
pub fn delta_decode(data: &mut [u8], kf: u32) {
    let kf8 = kf as u8;
    if data.is_empty() {
        return;
    }
    let mut prev = data[0].wrapping_add(kf8);
    data[0] = prev;
    for b in &mut data[1..] {
        prev = prev.wrapping_add(*b);
        *b = prev;
    }
}

/// XOR mask that evolves the key with the LCG after each 4-byte word / 2-byte
/// half-word chunk (ssea.cpp `masked_xor_random_next`).
///
/// Self-inverse for a fixed initial key. Chunks are processed little-endian;
/// the final odd byte is masked with the low byte of the current key.
pub fn masked_xor_random_next(data: &mut [u8], kf: u32) {
    let mut kf = lcg_next(&mut { kf });
    let mut chunks = data.chunks_exact_mut(4);
    for word in &mut chunks {
        let v = u32::from_le_bytes(word.try_into().expect("chunk is 4 bytes")) ^ kf;
        word.copy_from_slice(&v.to_le_bytes());
        kf = lcg_next(&mut kf);
    }
    let rest = chunks.into_remainder();
    if rest.len() >= 2 {
        let v = u16::from_le_bytes([rest[0], rest[1]]) ^ kf as u16;
        rest[0..2].copy_from_slice(&v.to_le_bytes());
        kf = lcg_next(&mut kf);
    }
    if rest.len() % 2 == 1 {
        let last = rest.len() - 1;
        rest[last] ^= kf as u8;
    }
}

/// Encodes binary bytes into printable 0x20..0x7E chars, appending to `out`.
///
/// Each byte `b` maps to `(b - kf) mod 256`; values >= 93 escape into two
/// chars (0x7D/0x7E prefix + remainder) so output is at most 2x input.
pub fn base94_encode_into(out: &mut Vec<u8>, src: &[u8], kf: u32) {
    let kf8 = kf as u8;
    out.reserve(src.len());
    for &b in src {
        let v = b.wrapping_sub(kf8);
        if v >= BASE93_RADIX {
            out.push(0x20 + (v / BASE93_RADIX - 1 + BASE93_RADIX));
            out.push(0x20 + v % BASE93_RADIX);
        } else {
            out.push(0x20 + v);
        }
    }
}

/// Number of chars [`base94_encode_into`] would emit for `src`.
#[must_use]
pub fn base94_encoded_len(src: &[u8], kf: u32) -> usize {
    let kf8 = kf as u8;
    let escapes = src
        .iter()
        .filter(|&&b| b.wrapping_sub(kf8) >= BASE93_RADIX)
        .count();
    src.len() + escapes
}

/// Decodes base94 text (see [`base94_encode_into`]) and appends the bytes to
/// `out`. On invalid input `out` is left unchanged and an error is returned.
pub fn base94_decode_into(out: &mut Vec<u8>, src: &[u8], kf: u32) -> Result<()> {
    let kf8 = kf as u8;
    let start = out.len();
    out.reserve(src.len());
    let mut i = 0;
    while i < src.len() {
        let c = src[i];
        if c < 0x20 {
            out.truncate(start);
            return Err(Error::InvalidBase94);
        }
        let b = c - 0x20;
        if b < BASE93_RADIX {
            out.push(b.wrapping_add(kf8));
            i += 1;
            continue;
        }
        // Escape sequence: leader must stay within the 94-symbol alphabet,
        // and the follower must exist and stay in the sub-93 range.
        if b > 94 {
            out.truncate(start);
            return Err(Error::InvalidBase94);
        }
        let Some(&c2) = src.get(i + 1) else {
            out.truncate(start);
            return Err(Error::InvalidBase94);
        };
        if c2 < 0x20 {
            out.truncate(start);
            return Err(Error::InvalidBase94);
        }
        let b2 = c2 - 0x20;
        if b2 > BASE93_RADIX {
            out.truncate(start);
            return Err(Error::InvalidBase94);
        }
        // b is 93 or 94; only b == 94 can overflow a byte after reconstruction.
        if b == 94 && b2 > 0xff - 2 * BASE93_RADIX {
            out.truncate(start);
            return Err(Error::InvalidBase94);
        }
        let v = u32::from(b - BASE93_RADIX + 1) * u32::from(BASE93_RADIX) + u32::from(b2);
        out.push((v as u8).wrapping_add(kf8));
        i += 2;
    }
    Ok(())
}

/// Minimal-length base94 digits of `v`; returns the digit count written.
#[must_use]
pub fn base94_decimal_encode(v: u64, out: &mut [u8; BASE94_DECIMAL_MAX_LEN]) -> usize {
    let mut n = v;
    let mut len = 0;
    loop {
        out[len] = (n % u64::from(BASE94_SYMBOL_COUNT)) as u8 + 0x20;
        len += 1;
        n /= u64::from(BASE94_SYMBOL_COUNT);
        if n == 0 {
            break;
        }
    }
    out[..len].reverse();
    len
}

/// Parses base94 digits (produced by [`base94_decimal_encode`], possibly
/// zero-padded with 0x20 chars) back into a u64.
pub fn base94_decimal_decode(s: &[u8]) -> Result<u64> {
    if s.is_empty() {
        return Err(Error::InvalidBase94);
    }
    let mut n: u64 = 0;
    for &c in s {
        if c < 0x20 {
            return Err(Error::InvalidBase94);
        }
        let d = c - 0x20;
        if d >= BASE94_SYMBOL_COUNT {
            return Err(Error::InvalidBase94);
        }
        n = n
            .checked_mul(u64::from(BASE94_SYMBOL_COUNT))
            .and_then(|n| n.checked_add(u64::from(d)))
            .ok_or(Error::InvalidBase94)?;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lcg_is_deterministic_and_31bit() {
        let mut a = 154_543_927u32;
        let mut b = 154_543_927u32;
        for _ in 0..1000 {
            let (x, y) = (lcg_next(&mut a), lcg_next(&mut b));
            assert_eq!(x, y);
            assert_eq!(x & 0x8000_0000, 0, "31-bit output expected");
        }
        assert_ne!(a, 154_543_927, "seed must advance");
    }

    #[test]
    fn lcg_range_stays_in_bounds() {
        let mut seed = 42u32;
        for _ in 0..1000 {
            let v = lcg_range(&mut seed, 262_144, 830_584);
            assert!((262_144..=830_584).contains(&v));
        }
        assert_eq!(lcg_range(&mut seed, 7, 7), 7);
    }

    #[test]
    fn shuffle_roundtrip_various_sizes() {
        let mut seed = 1u32;
        for size in [0usize, 1, 2, 3, 7, 64, 255, 1000, 65540] {
            let key = lcg_next(&mut seed);
            let original: Vec<u8> = (0..size).map(|i| (i * 31 % 251) as u8).collect();
            let mut data = original.clone();
            shuffle(&mut data, key);
            unshuffle(&mut data, key);
            assert_eq!(data, original, "size {size} roundtrip failed");
        }
    }

    #[test]
    fn shuffle_actually_permutes_for_suitable_keys() {
        // key = 1, size = 3: net permutation [a,b,c] -> [c,b,a].
        let mut data = [1u8, 2, 3];
        shuffle(&mut data, 1);
        assert_eq!(data, [3, 2, 1]);
        // size <= 2 degenerates to the identity permutation (by design of
        // the reference algorithm).
        let mut two = [1u8, 2];
        shuffle(&mut two, 0x5a5a_5a5a);
        assert_eq!(two, [1, 2]);
    }

    #[test]
    fn delta_roundtrip() {
        let kf = 154_543_927u32;
        let original: Vec<u8> = (0..1000u32).map(|i| (i * 7 % 256) as u8).collect();
        let mut data = original.clone();
        delta_encode(&mut data, kf);
        assert_ne!(data, original);
        delta_decode(&mut data, kf);
        assert_eq!(data, original);
    }

    #[test]
    fn delta_first_byte_matches_formula() {
        let kf = 0xabu32;
        let mut data = [0x10u8];
        delta_encode(&mut data, kf);
        assert_eq!(data[0], 0x10u8.wrapping_sub(0xab));
    }

    #[test]
    fn masked_xor_is_self_inverse() {
        let mut seed = 9u32;
        for len in [1usize, 2, 3, 4, 5, 8, 17, 100, 4097] {
            let key = lcg_next(&mut seed);
            let original: Vec<u8> = (0..len).map(|i| (i * 91 % 253) as u8).collect();
            let mut data = original.clone();
            masked_xor_random_next(&mut data, key);
            assert_ne!(data, original, "len {len}");
            masked_xor_random_next(&mut data, key);
            assert_eq!(data, original, "len {len}");
        }
    }

    #[test]
    fn base94_roundtrip_and_printable() {
        for kf in [0u32, 1, 93, 94, 0xff, 0xdead_beef] {
            let original: Vec<u8> = (0..=u8::MAX).collect();
            let mut encoded = Vec::new();
            base94_encode_into(&mut encoded, &original, kf);
            assert!(encoded.iter().all(|&c| (0x20..=0x7e).contains(&c)));
            assert_eq!(encoded.len(), base94_encoded_len(&original, kf));
            let mut decoded = Vec::new();
            base94_decode_into(&mut decoded, &encoded, kf).unwrap();
            assert_eq!(decoded, original);
        }
    }

    #[test]
    fn base94_escape_boundaries() {
        // kf = 0: values 93/94 escape, values 0..92 stay single.
        let mut encoded = Vec::new();
        base94_encode_into(&mut encoded, &[0, 92, 93, 94, 255], 0);
        // 0 -> 0x20, 92 -> 0x7C, 93 -> 0x7D 0x20, 94 -> 0x7D 0x21,
        // 255 -> (0x20 + 94, 0x20 + 69) = 0x7E 0x65
        assert_eq!(encoded, [0x20, 0x7c, 0x7d, 0x20, 0x7d, 0x21, 0x7e, 0x65]);
    }

    #[test]
    fn base94_decode_rejects_garbage() {
        let mut out = Vec::new();
        assert!(base94_decode_into(&mut out, &[0x1f], 0).is_err());
        assert!(base94_decode_into(&mut out, &[0x7f], 0).is_err());
        assert!(base94_decode_into(&mut out, &[0x7d], 0).is_err()); // truncated escape
        assert!(base94_decode_into(&mut out, &[0x7d, 0x7e], 0).is_err()); // v > 0xFF
        assert!(base94_decode_into(&mut out, &[0x7e, 0x7e], 0).is_err()); // follower is escape
        assert!(out.is_empty(), "no partial output on failure");
    }

    #[test]
    fn base94_decimal_roundtrip() {
        let mut buf = [0u8; BASE94_DECIMAL_MAX_LEN];
        for v in [0u64, 1, 93, 94, 830_583, u64::from(u32::MAX), u64::MAX] {
            let len = base94_decimal_encode(v, &mut buf);
            let digits = &buf[..len];
            assert!(digits.iter().all(|&c| c >= 0x20));
            if v > 0 {
                assert_ne!(digits[0], 0x20, "no leading zero");
            }
            assert_eq!(base94_decimal_decode(digits).unwrap(), v);
            // Zero padding (as used in fixed 3-digit frame headers) also
            // decodes, for values that fit.
            if len <= 3 {
                let mut padded = [0x20u8; 3];
                padded[3 - len..].copy_from_slice(digits);
                assert_eq!(base94_decimal_decode(&padded).unwrap(), v);
            }
        }
    }

    #[test]
    fn base94_decimal_known_value() {
        // 94^2 = 8836 -> digits (1, 0, 0) -> chars 0x21, 0x20, 0x20
        let mut buf = [0u8; BASE94_DECIMAL_MAX_LEN];
        let len = base94_decimal_encode(8836, &mut buf);
        assert_eq!(len, 3);
        assert_eq!(&buf[..3], &[0x21, 0x20, 0x20]);
    }
}
