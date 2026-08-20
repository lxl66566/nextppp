//! SIMD-accelerated base94 codec: binary data in printable ASCII.
//!
//! Each byte `b` maps to `(b - kf) mod 256`; mixed values `>= 93` escape into
//! two chars (`0x7D`/`0x7E` leader + follower) so every emitted char stays in
//! `0x20..=0x7E` and the output is at most 2x the input. `kf` is a key-mixing
//! parameter (only its low byte participates); pass `0` for the plain codec.
//! The format is a faithful port of openppp2 `ppp/cryptography/ssea.cpp`.
//!
//! Performance notes (wire output unchanged):
//! * encode/decode run SIMD fast paths over 16-byte blocks (see `simd`): the decoder solves the
//!   leader/follower alternation and escape reconstruction in-register and compacts leaders via a
//!   byte-shuffle LUT (pshufb on x86_64, vqtbl1 on aarch64; ~3x over scalar); the encoder
//!   precomputes interleaved leader/follower pairs and deletes non-escape followers through the
//!   same LUT (~2.5x).
//! * Invalid input and sub-block tails fall back to the scalar reference loop, so error semantics
//!   stay bit-exact (pinned by fuzz + unit tests).

// Intentional truncating/wrapping casts below mirror the C++ `Byte(int)`
// conversions: the format relies on low-byte / modulo-256 semantics.
#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
// Hot loops use raw-pointer stores to skip bounds checks that the compiler
// cannot elide.
#![allow(unsafe_code)]

mod simd;

use std::fmt;

/// Number of printable symbols: 0x20..=0x7E.
pub const SYMBOL_COUNT: u8 = 94;
/// Escape radix: mixed values >= 93 are encoded as two characters.
const ESCAPE_RADIX: u8 = 93;
/// Max digits of a u64 in base 94 (94^10 > 2^64 > 94^9).
pub const DECIMAL_MAX_LEN: usize = 10;

/// The input contains characters outside the printable alphabet or a
/// truncated/overflowing escape sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeError;

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid base94 data")
    }
}

impl std::error::Error for DecodeError {}

/// Encodes binary bytes into printable 0x20..=0x7E chars, appending to `out`.
///
/// Branchless scalar tail: the leader char is always stored, the follower
/// slot always written (garbage when unused, overwritten by the next
/// leader), and the write cursor advances by `1 + escape` — no mispredicted
/// branches on the ~50/50 escape mix.
pub fn encode_into(out: &mut Vec<u8>, src: &[u8], kf: u32) {
    encode_into_with_len(out, src, kf, encoded_len(src, kf));
}

/// [`encode_into`] with a caller-computed output length, skipping the
/// escape-count scan (`encoded_len`) when the caller already ran it for
/// bounds checking. Frame builders need the length up front, so this halves
/// the source scans on their hot path.
///
/// # Contract
///
/// `len` must be exactly `encoded_len(src, kf)`. A wrong value corrupts or
/// overruns the output buffer (the writes trust `len` for capacity);
/// `debug_assert` catches misuse in debug builds.
#[cfg_attr(feature = "hotpath", hotpath::measure)]
pub fn encode_into_with_len(out: &mut Vec<u8>, src: &[u8], kf: u32, len: usize) {
    // 8-wide unroll: the output offsets form a short serial prefix chain
    // (7 adds amortized over 8 bytes) while the 16 leader/follower stores
    // issue independently — a per-byte `p += 1 + esc` chain would otherwise
    // cap the loop at the address-generation latency.
    const UNROLL: usize = 8;

    debug_assert_eq!(len, encoded_len(src, kf), "stale/wrong encode length");
    let kf8 = kf as u8;
    let total = len;
    let start = out.len();
    // +16 slack: the SIMD kernel's per-quarter compaction stores are
    // 8-byte writes whose padding past the count is only overwritten by
    // *later* quarters/blocks; the final store may overrun the logical
    // length by up to 8 bytes. set_len below erases the padding.
    out.reserve(total + 16);
    let dst = out.as_mut_ptr();
    let mut p = start;
    // SIMD fast path over whole 16-byte blocks first.
    let simd_consumed = simd::encode_simd(dst, &mut p, src, kf8);
    let mut idx = simd_consumed;
    while idx + UNROLL <= src.len() {
        let chunk: [u8; UNROLL] = src[idx..idx + UNROLL].try_into().expect("fixed size");
        let mut offs = [0usize; UNROLL];
        let mut cursor = 0usize;
        for (k, &b) in chunk.iter().enumerate() {
            offs[k] = cursor;
            cursor += 1 + usize::from(b.wrapping_sub(kf8) >= ESCAPE_RADIX);
        }
        for (k, &b) in chunk.iter().enumerate() {
            let v = b.wrapping_sub(kf8);
            let esc = u8::from(v >= ESCAPE_RADIX);
            // Escape: c1 = 0x7D + (v >= 186), c2 = 0x20 + v - 93 - 93*(v >= 186).
            // Single: c1 = 0x20 + v (c2 unused, overwritten by a later leader).
            let q2 = u8::from(v >= 2 * ESCAPE_RADIX);
            let c1 = if esc != 0 {
                0x7d + q2
            } else {
                0x20 + v
            };
            let c2 = 0x20u8.wrapping_add(
                v.wrapping_sub(ESCAPE_RADIX)
                    .wrapping_sub(ESCAPE_RADIX.wrapping_mul(q2)),
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
        let esc = u8::from(v >= ESCAPE_RADIX);
        let q2 = u8::from(v >= 2 * ESCAPE_RADIX);
        let c1 = if esc != 0 {
            0x7d + q2
        } else {
            0x20 + v
        };
        let c2 = 0x20u8.wrapping_add(
            v.wrapping_sub(ESCAPE_RADIX)
                .wrapping_sub(ESCAPE_RADIX.wrapping_mul(q2)),
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

/// Number of chars [`encode_into`] would emit for `src`.
#[must_use]
pub fn encoded_len(src: &[u8], kf: u32) -> usize {
    src.len() + simd::count_sub_ge(src, kf as u8, ESCAPE_RADIX)
}

/// Decodes base94 text (see [`encode_into`]) and appends the bytes to `out`.
/// On invalid input `out` is left unchanged and an error is returned.
///
/// A SIMD bulk pass proves `>= 0x20` for every char up front and a vectorized
/// kernel decodes whole 16-char blocks (leader/follower pairing, escape
/// reconstruction and leader compaction in-register). Invalid constructs fall
/// back to the scalar reference loop, which reports the exact wire-legal
/// error; both paths are bit-exact (pinned by the fuzz test below).
#[cfg_attr(feature = "hotpath", hotpath::measure)]
pub fn decode_into(out: &mut Vec<u8>, src: &[u8], kf: u32) -> Result<(), DecodeError> {
    if !simd::all_ge(src, 0x20) {
        return Err(DecodeError);
    }
    let kf8 = kf as u8;
    let kf16 = u16::from(kf8);
    let start = out.len();
    // +16 slack for the SIMD kernel's fixed 8-byte compact stores (see
    // encode_into); the final set_len erases the padding.
    out.reserve(src.len() + 16);
    let dst = out.as_mut_ptr();
    let mut i;
    let mut p = start;
    let n = src.len();
    // SIMD fast path over whole 16-char blocks. `Ok` leaves the sub-block
    // tail; `Err` hands back the last valid prefix. Either way the scalar
    // reference loop resumes exactly where the kernel stopped.
    match simd::decode_simd(dst, &mut p, src, kf8) {
        Ok((consumed, _)) | Err((consumed, _)) => i = consumed,
    }
    // Main loop: every position still has a potential follower char. The
    // escape validation folds into ONE branch on a value that is zero for
    // all valid input — branching on `esc` itself would mispredict on the
    // ~50/50 escape mix.
    while i + 1 < n {
        let b = u16::from(src[i]) - 0x20;
        let b2 = u16::from(src[i + 1]) - 0x20;
        let esc = u16::from(b >= u16::from(ESCAPE_RADIX));
        // Escape reconstruction: v = (b - 92) * 93 + b2. Only meaningful when
        // escaping; wrapped for the single-char arm (b < 93).
        let v_esc = (b.wrapping_sub(92))
            .wrapping_mul(u16::from(ESCAPE_RADIX))
            .wrapping_add(b2);
        // Invalid: leader > 0x7E, follower > 0x7C, or value overflow past
        // 0xFF. All combined into a single (cold) taken-never branch.
        let bad = esc
            & (u16::from(b > 94)
                | u16::from(b2 > u16::from(ESCAPE_RADIX))
                | u16::from(v_esc > 0xff));
        if bad != 0 {
            return Err(DecodeError);
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
        if b >= ESCAPE_RADIX {
            return Err(DecodeError);
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
pub fn decimal_encode(v: u64, out: &mut [u8; DECIMAL_MAX_LEN]) -> usize {
    let mut n = v;
    let mut len = 0;
    loop {
        out[len] = (n % u64::from(SYMBOL_COUNT)) as u8 + 0x20;
        len += 1;
        n /= u64::from(SYMBOL_COUNT);
        if n == 0 {
            break;
        }
    }
    out[..len].reverse();
    len
}

/// Parses base94 digits (produced by [`decimal_encode`], possibly zero-padded
/// with 0x20 chars) back into a u64.
pub fn decimal_decode(s: &[u8]) -> Result<u64, DecodeError> {
    if s.is_empty() {
        return Err(DecodeError);
    }
    let mut n: u64 = 0;
    for &c in s {
        if c < 0x20 {
            return Err(DecodeError);
        }
        let d = c - 0x20;
        if d >= SYMBOL_COUNT {
            return Err(DecodeError);
        }
        n = n
            .checked_mul(u64::from(SYMBOL_COUNT))
            .and_then(|n| n.checked_add(u64::from(d)))
            .ok_or(DecodeError)?;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_printable() {
        for kf in [0u32, 1, 93, 94, 0xff, 0xdead_beef] {
            let original: Vec<u8> = (0..=u8::MAX).collect();
            let mut encoded = Vec::new();
            encode_into(&mut encoded, &original, kf);
            assert!(encoded.iter().all(|&c| (0x20..=0x7e).contains(&c)));
            assert_eq!(encoded.len(), encoded_len(&original, kf));
            let mut decoded = Vec::new();
            decode_into(&mut decoded, &encoded, kf).unwrap();
            assert_eq!(decoded, original);
        }
    }

    #[test]
    fn roundtrip_large_and_edge_shapes() {
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
                encode_into(&mut encoded, &dataset, kf);
                assert_eq!(encoded.len(), encoded_len(&dataset, kf));
                let mut decoded = Vec::new();
                decode_into(&mut decoded, &encoded, kf).unwrap();
                assert_eq!(decoded, dataset);
            }
        }
        let mut random: Vec<u8> = (0..65_537).map(|_| step()).collect();
        random[0] = 0x93; // force at least one boundary escape
        let mut encoded = Vec::new();
        encode_into(&mut encoded, &random, 154_543_927);
        let mut decoded = Vec::new();
        decode_into(&mut decoded, &encoded, 154_543_927).unwrap();
        assert_eq!(decoded, random);
    }

    #[test]
    fn decode_uses_existing_out_prefix() {
        // Appending must respect pre-existing content (callers rely on
        // encode-into semantics; decode mirrors it).
        let original = vec![0xde, 0xad, 0xbe, 0xef];
        let mut encoded = Vec::new();
        encode_into(&mut encoded, &original, 123);
        let mut out = b"prefix".to_vec();
        decode_into(&mut out, &encoded, 123).unwrap();
        assert_eq!(out, [b"prefix".as_slice(), original.as_slice()].concat());
    }

    #[test]
    fn escape_boundaries() {
        // kf = 0: values 93/94 escape, values 0..92 stay single.
        let mut encoded = Vec::new();
        encode_into(&mut encoded, &[0, 92, 93, 94, 255], 0);
        // 0 -> 0x20, 92 -> 0x7C, 93 -> 0x7D 0x20, 94 -> 0x7D 0x21,
        // 255 -> (0x20 + 94, 0x20 + 69) = 0x7E 0x65
        assert_eq!(encoded, [0x20, 0x7c, 0x7d, 0x20, 0x7d, 0x21, 0x7e, 0x65]);
    }

    #[test]
    fn decode_rejects_garbage() {
        let mut out = Vec::new();
        assert!(decode_into(&mut out, &[0x1f], 0).is_err());
        assert!(decode_into(&mut out, &[0x7f], 0).is_err());
        assert!(decode_into(&mut out, &[0x7d], 0).is_err()); // truncated escape
        assert!(decode_into(&mut out, &[0x7d, 0x7e], 0).is_err()); // v > 0xFF
        assert!(decode_into(&mut out, &[0x7e, 0x7e], 0).is_err()); // follower is escape
        // Non-0x20 leader of length 1 (0x7F => b=95) is an invalid escape.
        assert!(decode_into(&mut out, &[0x7f, 0x20], 0).is_err());
        assert!(out.is_empty(), "no partial output on failure");
    }

    /// The pre-optimization reference decoder: greedy scalar parse. The
    /// optimized fast path must match it bit-for-bit, including on crafted
    /// inputs (e.g. legal 0x7D 0x7D pairs) and error cases.
    fn decode_reference(out: &mut Vec<u8>, src: &[u8], kf: u32) -> Result<(), DecodeError> {
        let kf8 = kf as u8;
        let start = out.len();
        let mut i = 0;
        while i < src.len() {
            let c = src[i];
            if c < 0x20 {
                out.truncate(start);
                return Err(DecodeError);
            }
            let b = c - 0x20;
            if b < ESCAPE_RADIX {
                out.push(b.wrapping_add(kf8));
                i += 1;
                continue;
            }
            if b > 94 {
                out.truncate(start);
                return Err(DecodeError);
            }
            let Some(&c2) = src.get(i + 1) else {
                out.truncate(start);
                return Err(DecodeError);
            };
            if c2 < 0x20 {
                out.truncate(start);
                return Err(DecodeError);
            }
            let b2 = c2 - 0x20;
            if b2 > ESCAPE_RADIX {
                out.truncate(start);
                return Err(DecodeError);
            }
            if b == 94 && b2 > 0xff - 2 * ESCAPE_RADIX {
                out.truncate(start);
                return Err(DecodeError);
            }
            let v = u32::from(b - ESCAPE_RADIX + 1) * u32::from(ESCAPE_RADIX) + u32::from(b2);
            out.push((v as u8).wrapping_add(kf8));
            i += 2;
        }
        Ok(())
    }

    #[test]
    fn decode_fuzz_matches_reference() {
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
        for len in [
            0usize, 1, 15, 16, 17, 31, 33, 64, 100, 199, 200, 201, 255, 256, 257, 513,
        ] {
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
                    let a = decode_into(&mut got, &input, kf);
                    let b = decode_reference(&mut want, &input, kf);
                    assert_eq!(a.is_ok(), b.is_ok(), "len={len} kf={kf} ok-ness");
                    if let (Ok(()), Ok(())) = (a, b) {
                        assert_eq!(got, want, "len={len} kf={kf}");
                    }
                }
            }
        }
    }

    #[test]
    fn decode_rejects_7e_follower_in_simd_block() {
        // cargo-fuzz crash: a 0x7D leader with a 0x7E follower evades the
        // escape-overflow check (93 + 94 = 187 <= 0xFF) yet the follower is
        // out of range. Exactly 16 bytes to land in the SIMD kernel.
        let input: Vec<u8> = b"ppppppppp#i}~C}(".to_vec();
        assert_eq!(input.len(), 16);
        let mut out = Vec::new();
        assert!(decode_into(&mut out, &input, 125).is_err());
        assert_eq!(out, [] as [u8; 0]);
        // Same construct shifted to other lanes / with a leading carry.
        for shift in 0..15usize {
            let mut v = vec![0x41u8; 16];
            v[shift] = 0x7d;
            v[shift + 1] = 0x7e;
            let mut out = Vec::new();
            assert!(decode_into(&mut out, &v, 0).is_err(), "shift {shift}");
        }
        // Overflowing escape (ev > 0xFF) inside a SIMD block: 0x7E leader
        // with a large follower, e.g. "7e 7d" -> 186 + 93 = 279.
        let mut v = vec![0x41u8; 16];
        v[0] = 0x7e;
        v[1] = 0x7d;
        let mut out = Vec::new();
        assert!(decode_into(&mut out, &v, 0).is_err());
        assert_eq!(out, [] as [u8; 0]);
    }

    #[test]
    fn decode_legal_adjacent_escape_pair() {
        // 0x7D 0x7D decodes to a single byte (v = 93 + 93 = 186), exercising
        // the adjacent-escape boundary in the optimized path.
        let mut big = vec![0x7du8; 64];
        big.extend_from_slice(&[0x41; 8]);
        for kf in [0u32, 200] {
            let mut got = Vec::new();
            decode_into(&mut got, &big, kf).unwrap();
            let mut want = Vec::new();
            decode_reference(&mut want, &big, kf).unwrap();
            assert_eq!(got, want);
            assert_eq!(got.len(), 32 + 8);
        }
    }

    #[test]
    fn decimal_roundtrip() {
        let mut buf = [0u8; DECIMAL_MAX_LEN];
        for v in [0u64, 1, 93, 94, 830_583, u64::from(u32::MAX), u64::MAX] {
            let len = decimal_encode(v, &mut buf);
            let digits = &buf[..len];
            assert!(digits.iter().all(|&c| c >= 0x20));
            if v > 0 {
                assert_ne!(digits[0], 0x20, "no leading zero");
            }
            assert_eq!(decimal_decode(digits).unwrap(), v);
            // Zero padding (as used in fixed 3-digit fields) also decodes,
            // for values that fit.
            if len <= 3 {
                let mut padded = [0x20u8; 3];
                padded[3 - len..].copy_from_slice(digits);
                assert_eq!(decimal_decode(&padded).unwrap(), v);
            }
        }
    }

    #[test]
    fn decimal_known_value() {
        // 94^2 = 8836 -> digits (1, 0, 0) -> chars 0x21, 0x20, 0x20
        let mut buf = [0u8; DECIMAL_MAX_LEN];
        let len = decimal_encode(8836, &mut buf);
        assert_eq!(len, 3);
        assert_eq!(&buf[..3], &[0x21, 0x20, 0x20]);
    }
}
