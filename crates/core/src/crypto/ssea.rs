//! SSEA obfuscation primitives, a faithful port of openppp2
//! `ppp/cryptography/ssea.cpp`.
//!
//! Every primitive keeps the reference wrapping byte semantics so the
//! anti-censorship behavior (printable output, length obfuscation, key
//! mixing) stays identical to the battle-tested C++ implementation.
//!
//! Performance notes (wire output unchanged):
//! * shuffle/unshuffle replace the hardware `%` (~20+ cycle `div` inside a serial swap chain) with
//!   Lemire's two-multiply fastmod.
//! * `lcg_next` computes the three LCG steps with a 2-multiply dependency depth instead of 3
//!   chained multiplies (next2/next3 both derive from next1), which matters because masked-XOR is
//!   bound by the LCG chain.
//! * base94 encode/decode are branchless: escape decisions become cmovs, validation runs as one
//!   SIMD bulk pass plus cold error branches.

// Intentional truncating/wrapping casts below mirror the C++ `Byte(int)`
// conversions: the protocol relies on low-byte / modulo-256 semantics.
#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
// Hot loops use raw-pointer swaps/stores to skip bounds checks that the
// compiler cannot elide (`j` comes from a modulo).
#![allow(unsafe_code)]

use crate::{
    crypto::simd,
    error::{Error, Result},
};

/// Number of printable symbols: 0x20..0x7E.
pub const BASE94_SYMBOL_COUNT: u8 = 94;
/// Escape radix: values >= 93 are encoded as two characters.
const BASE93_RADIX: u8 = 93;
/// Max digits of a u64 in base 94 (94^10 > 2^64 > 94^9).
pub const BASE94_DECIMAL_MAX_LEN: usize = 10;

/// LCG multiplier / increment (ssea.cpp constants).
const LCG_A: u32 = 1_103_515_245;
const LCG_C: u32 = 12_345;
/// Two-step jump for the restructured `lcg_next`: next3 = next1*A^2 + C*(A+1).
const LCG_A2: u32 = LCG_A.wrapping_mul(LCG_A);
const LCG_C2: u32 = LCG_C.wrapping_mul(LCG_A.wrapping_add(1));

/// Advances the 31-bit LCG seed and returns a 31-bit value
/// (ssea.cpp `random_next`).
///
/// Algebraically identical to three chained `x*A+C` steps: steps 2 and 3 are
/// both affine in next1, so they evaluate in parallel. This halves the
/// multiply-chain depth (3 -> 2), the critical path of masked-XOR.
#[must_use]
pub fn lcg_next(seed: &mut u32) -> u32 {
    let next1 = seed.wrapping_mul(LCG_A).wrapping_add(LCG_C);
    let next2 = next1.wrapping_mul(LCG_A).wrapping_add(LCG_C);
    let next3 = next1.wrapping_mul(LCG_A2).wrapping_add(LCG_C2);
    *seed = next3;
    (((next1 >> 16) & 2047) << 20) | (((next2 >> 16) & 1023) << 10) | ((next3 >> 16) & 1023)
}

/// Closed-range LCG sample in `[min, max]` (ssea.cpp `random_next(seed,..)`).
#[must_use]
pub fn lcg_range(seed: &mut u32, min: u32, max: u32) -> u32 {
    debug_assert!(min <= max, "lcg_range requires min <= max");
    lcg_next(seed) % (max - min + 1) + min
}

/// Lemire fast-modulo magic for a fixed divisor `d >= 2` (all u32 dividends).
fn fastmod_magic(d: u32) -> u64 {
    // M = floor((2^64 - 1) / d) + 1 == ceil(2^64 / d) for every d >= 2.
    u64::MAX / u64::from(d) + 1
}

/// `x % d` via two multiplies (Lemire, "Faster remainders when the divisor is
/// a constant"); exact for all u32 `x` when built with [`fastmod_magic`].
#[inline]
fn fast_mod(x: u32, magic: u64, d: u32) -> u32 {
    let lowbits = magic.wrapping_mul(u64::from(x));
    ((u128::from(lowbits) * u128::from(d)) >> 64) as u32
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
    let magic = fastmod_magic(size32);
    let ptr = data.as_mut_ptr();
    for i in 0..size {
        let j = fast_mod((i as u32) ^ key, magic, size32) as usize;
        // SAFETY: i < len by the loop range and j < size32 <= len by fastmod.
        unsafe { std::ptr::swap(ptr.add(i), ptr.add(j)) };
    }
}

/// Exact inverse of [`shuffle`], running the swap chain backwards.
pub fn unshuffle(data: &mut [u8], key: u32) {
    let size = data.len();
    if size < 2 {
        return;
    }
    let size32 = u32::try_from(size).expect("frames are far below 4 GiB");
    let magic = fastmod_magic(size32);
    let ptr = data.as_mut_ptr();
    for i in (0..size).rev() {
        let j = fast_mod((i as u32) ^ key, magic, size32) as usize;
        // SAFETY: i < len by the loop range and j < size32 <= len by fastmod.
        unsafe { std::ptr::swap(ptr.add(i), ptr.add(j)) };
    }
}

/// In-place delta encoding: `out[0] = in[0] - kf`, `out[i] = in[i] - in[i-1]`.
///
/// Safe to run in place: the previous plaintext byte is kept in a local.
/// SIMD-accelerated (`crypto::simd`); wire output identical.
pub fn delta_encode(data: &mut [u8], kf: u32) {
    simd::delta_encode(data, kf as u8);
}

/// In-place inverse of [`delta_encode`]. SIMD-accelerated (prefix-sum scan).
pub fn delta_decode(data: &mut [u8], kf: u32) {
    simd::delta_decode(data, kf as u8);
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
///
/// Branchless: the leader char is always stored, the follower slot always
/// written (garbage when unused, overwritten by the next leader), and the
/// write cursor advances by `1 + escape` — no mispredicted branches on the
/// ~50/50 escape mix.
pub fn base94_encode_into(out: &mut Vec<u8>, src: &[u8], kf: u32) {
    // 8-wide unroll: the output offsets form a short serial prefix chain
    // (7 adds amortized over 8 bytes) while the 16 leader/follower stores
    // issue independently — a per-byte `p += 1 + esc` chain would otherwise
    // cap the loop at the address-generation latency.
    const UNROLL: usize = 8;

    let kf8 = kf as u8;
    let total = src.len() + simd::count_sub_ge(src, kf8, BASE93_RADIX);
    let start = out.len();
    // +1 slack: the follower store may land one past the final length when
    // the last byte is single-char; set_len below erases it.
    out.reserve(total + 1);
    let dst = out.as_mut_ptr();
    let mut p = start;
    let mut idx = 0usize;
    while idx + UNROLL <= src.len() {
        let chunk: [u8; UNROLL] = src[idx..idx + UNROLL].try_into().expect("fixed size");
        let mut offs = [0usize; UNROLL];
        let mut cursor = 0usize;
        for (k, &b) in chunk.iter().enumerate() {
            offs[k] = cursor;
            cursor += 1 + usize::from(b.wrapping_sub(kf8) >= BASE93_RADIX);
        }
        for (k, &b) in chunk.iter().enumerate() {
            let v = b.wrapping_sub(kf8);
            let esc = u8::from(v >= BASE93_RADIX);
            // Escape: c1 = 0x7D + (v >= 186), c2 = 0x20 + v - 93 - 93*(v >= 186).
            // Single: c1 = 0x20 + v (c2 unused, overwritten by a later leader).
            let q2 = u8::from(v >= 2 * BASE93_RADIX);
            let c1 = if esc != 0 {
                0x7d + q2
            } else {
                0x20 + v
            };
            let c2 = 0x20u8.wrapping_add(
                v.wrapping_sub(BASE93_RADIX)
                    .wrapping_sub(BASE93_RADIX.wrapping_mul(q2)),
            );
            // SAFETY: offsets stay within `total + 1` reserved capacity.
            unsafe {
                let q = dst.add(p + offs[k]);
                *q = c1;
                *q.add(1) = c2;
            }
        }
        p += cursor;
        idx += UNROLL;
    }
    for &b in &src[idx..] {
        let v = b.wrapping_sub(kf8);
        let esc = u8::from(v >= BASE93_RADIX);
        let q2 = u8::from(v >= 2 * BASE93_RADIX);
        let c1 = if esc != 0 {
            0x7d + q2
        } else {
            0x20 + v
        };
        let c2 = 0x20u8.wrapping_add(
            v.wrapping_sub(BASE93_RADIX)
                .wrapping_sub(BASE93_RADIX.wrapping_mul(q2)),
        );
        // SAFETY: same invariants as the unrolled body.
        unsafe {
            *dst.add(p) = c1;
            *dst.add(p + 1) = c2;
        }
        p += 1 + usize::from(esc);
    }
    // SAFETY: exactly `total` bytes were committed by leader stores.
    unsafe { out.set_len(start + total) };
}

/// Number of chars [`base94_encode_into`] would emit for `src`.
#[must_use]
pub fn base94_encoded_len(src: &[u8], kf: u32) -> usize {
    src.len() + simd::count_sub_ge(src, kf as u8, BASE93_RADIX)
}

/// Decodes base94 text (see [`base94_encode_into`]) and appends the bytes to
/// `out`. On invalid input `out` is left unchanged and an error is returned.
///
/// A SIMD bulk pass proves `>= 0x20` for every char up front; the hot loop
/// then only checks the (data-dependent but almost-never-taken) escape
/// validation branch.
pub fn base94_decode_into(out: &mut Vec<u8>, src: &[u8], kf: u32) -> Result<()> {
    if !simd::all_ge(src, 0x20) {
        return Err(Error::InvalidBase94);
    }
    let kf8 = kf as u8;
    let kf16 = u16::from(kf8);
    let start = out.len();
    out.reserve(src.len());
    let dst = out.as_mut_ptr();
    let mut i = 0usize;
    let mut p = start;
    let n = src.len();
    // Main loop: every position still has a potential follower char. The
    // escape validation folds into ONE branch on a value that is zero for
    // all valid input — branching on `esc` itself would mispredict on the
    // ~50/50 escape mix.
    while i + 1 < n {
        let b = u16::from(src[i]) - 0x20;
        let b2 = u16::from(src[i + 1]) - 0x20;
        let esc = u16::from(b >= u16::from(BASE93_RADIX));
        // Escape reconstruction: v = (b - 92) * 93 + b2. Only meaningful when
        // escaping; wrapped for the single-char arm (b < 93).
        let v_esc = (b.wrapping_sub(92))
            .wrapping_mul(u16::from(BASE93_RADIX))
            .wrapping_add(b2);
        // Invalid: leader > 0x7E, follower > 0x7C, or value overflow past
        // 0xFF. All combined into a single (cold) taken-never branch.
        let bad = esc
            & (u16::from(b > 94)
                | u16::from(b2 > u16::from(BASE93_RADIX))
                | u16::from(v_esc > 0xff));
        if bad != 0 {
            return Err(Error::InvalidBase94);
        }
        let val = if esc != 0 {
            v_esc
        } else {
            b
        };
        // SAFETY: at most one output byte per input char, and `p` advanced
        // only by committed bytes within the reserved capacity.
        unsafe { *dst.add(p) = val.wrapping_add(kf16) as u8 };
        p += 1;
        i += 1 + esc as usize;
    }
    if i < n {
        // Trailing single char; an escape leader here is a truncated pair.
        let b = src[i] - 0x20;
        if b >= BASE93_RADIX {
            return Err(Error::InvalidBase94);
        }
        unsafe { *dst.add(p) = b.wrapping_add(kf8) };
        p += 1;
    }
    // SAFETY: p - start bytes were committed by the loop above.
    unsafe { out.set_len(p) };
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

    /// Three chained reference steps — the original ssea.cpp formulation the
    /// restructured [`lcg_next`] must match bit-for-bit.
    fn lcg_next_reference(seed: &mut u32) -> u32 {
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

    #[test]
    fn lcg_restructure_matches_reference() {
        let mut a;
        let mut b;
        for seed in [0u32, 1, 42, 154_543_927, u32::MAX] {
            a = seed;
            b = seed;
            for _ in 0..1000 {
                assert_eq!(lcg_next(&mut a), lcg_next_reference(&mut b));
                assert_eq!(a, b);
            }
        }
    }

    #[test]
    fn fast_mod_matches_hardware_division() {
        let mut s = 0x1234_5678_9abc_def0u64;
        let mut step = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        let divisors: Vec<u32> = (2u32..3000)
            .chain([
                4096,
                65536,
                65539,
                830_584,
                u32::MAX / 2 + 1,
                2u32.pow(31) - 1,
            ])
            .collect();
        for d in divisors {
            let magic = fastmod_magic(d);
            for _ in 0..64 {
                let x = (step() >> 32) as u32;
                assert_eq!(fast_mod(x, magic, d), x % d, "d={d} x={x}");
            }
            // Boundary values too.
            for x in [0u32, 1, d - 1, d, d + 1, u32::MAX] {
                assert_eq!(fast_mod(x, magic, d), x % d, "d={d} x={x}");
            }
        }
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
    fn base94_roundtrip_large_and_edge_shapes() {
        let mut s = 0x0bad_c0deu64;
        let mut step = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s >> 56) as u8
        };
        // Random data (~50% escapes), all-escape and no-escape shapes, plus
        // lengths that hit the SIMD tails and the trailing-single-char path.
        let all_escape: Vec<u8> = (0..2000)
            .map(|i| 93u8.wrapping_add(i as u8 % 163))
            .collect();
        let no_escape: Vec<u8> = vec![7u8; 2001];
        for dataset in [all_escape, no_escape] {
            for kf in [0u32, 0x5a5a_5a5a] {
                let mut encoded = Vec::new();
                base94_encode_into(&mut encoded, &dataset, kf);
                assert_eq!(encoded.len(), base94_encoded_len(&dataset, kf));
                let mut decoded = Vec::new();
                base94_decode_into(&mut decoded, &encoded, kf).unwrap();
                assert_eq!(decoded, dataset);
            }
        }
        let mut random: Vec<u8> = (0..65_537).map(|_| step()).collect();
        random[0] = 0x93; // force at least one boundary escape
        let mut encoded = Vec::new();
        base94_encode_into(&mut encoded, &random, 154_543_927);
        let mut decoded = Vec::new();
        base94_decode_into(&mut decoded, &encoded, 154_543_927).unwrap();
        assert_eq!(decoded, random);
    }

    #[test]
    fn base94_decode_uses_existing_out_prefix() {
        // Appending must respect pre-existing content (protocol framing
        // relies on encode-into semantics; decode mirrors it).
        let original = vec![0xde, 0xad, 0xbe, 0xef];
        let mut encoded = Vec::new();
        base94_encode_into(&mut encoded, &original, 123);
        let mut out = b"prefix".to_vec();
        base94_decode_into(&mut out, &encoded, 123).unwrap();
        assert_eq!(out, [b"prefix".as_slice(), original.as_slice()].concat());
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
        // Non-0x20 leader of length 1 (0x7F => b=95) is an invalid escape.
        assert!(base94_decode_into(&mut out, &[0x7f, 0x20], 0).is_err());
        assert!(out.is_empty(), "no partial output on failure");
    }

    /// The pre-optimization reference decoder: greedy scalar parse. The optimized
    /// fast path must match it bit-for-bit, including on crafted
    /// inputs (e.g. legal 0x7D 0x7D pairs) and error cases.
    fn base94_decode_reference(out: &mut Vec<u8>, src: &[u8], kf: u32) -> Result<()> {
        let kf8 = kf as u8;
        let start = out.len();
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

    #[test]
    fn base94_decode_fuzz_matches_reference() {
        let mut s = 0x00c0_ffee_d00d_feedu64;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        // Bias the alphabet toward the tricky boundary range 0x7B..=0x7F so
        // the adjacent-escape fallback and leader/follower boundaries get
        // hammered; mix in ordinary printable chars and invalid bytes.
        for len in 0..200usize {
            for _ in 0..40 {
                let input: Vec<u8> = (0..len)
                    .map(|_| {
                        let r = (next() >> 32) as u8;
                        match r % 8 {
                            0..=4 => 0x20 + (r % 93),
                            5 => 0x7b,
                            6 => 0x7d + (r % 2),
                            _ => r, // sometimes < 0x20 or > 0x7E (invalid)
                        }
                    })
                    .collect();
                for kf in [0u32, 77, 0x5a5a_5a5a] {
                    let mut got = Vec::new();
                    let mut want = Vec::new();
                    let a = base94_decode_into(&mut got, &input, kf);
                    let b = base94_decode_reference(&mut want, &input, kf);
                    assert_eq!(a.is_ok(), b.is_ok(), "len={len} kf={kf} ok-ness");
                    if let (Ok(()), Ok(())) = (a, b) {
                        assert_eq!(got, want, "len={len} kf={kf}");
                    }
                }
            }
        }
    }

    #[test]
    fn base94_decode_legal_adjacent_escape_pair() {
        // 0x7D 0x7D decodes to a single byte (v = 93 + 93 = 186), exercising
        // the adjacent-escape boundary in the optimized path.
        let mut big = vec![0x7du8; 64];
        big.extend_from_slice(&[0x41; 8]);
        for kf in [0u32, 200] {
            let mut got = Vec::new();
            base94_decode_into(&mut got, &big, kf).unwrap();
            let mut want = Vec::new();
            base94_decode_reference(&mut want, &big, kf).unwrap();
            assert_eq!(got, want);
            assert_eq!(got.len(), 32 + 8);
        }
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
