//! SIMD kernels for the per-packet hot path.
//!
//! Backends use only baseline ISA guarantees (SSE2 on x86_64, NEON on
//! aarch64) so no runtime detection is needed; other targets use the portable
//! scalar fallback. Wire semantics are identical across backends — the scalar
//! code here doubles as the reference definition.

// Raw core::arch intrinsics require unsafe. Every block only touches
// block-sized loads/stores over slices already split to exact block sizes,
// so indexing cannot go out of bounds.
#![allow(unsafe_code)]
// Intrinsic parameters are i8 lanes; u8 <-> i8 bit reinterpretation (and the
// matching truncating casts on extract) is the intended semantic.
#![allow(clippy::cast_possible_wrap, clippy::cast_sign_loss, clippy::cast_possible_truncation)]

// Reference implementations: selected on targets without a SIMD backend and
// reused by arch backends for sub-block tails; the equivalence tests also
// drive them directly.
#[allow(dead_code)]
mod scalar {
    pub(super) fn count_sub_ge(src: &[u8], sub: u8, threshold: u8) -> usize {
        let mut count = 0usize;
        for &b in src {
            count += usize::from(b.wrapping_sub(sub) >= threshold);
        }
        count
    }

    pub(super) fn all_ge(src: &[u8], threshold: u8) -> bool {
        src.iter().all(|&b| b >= threshold)
    }

    pub(super) fn delta_encode(data: &mut [u8], kf8: u8) {
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

    pub(super) fn delta_decode(data: &mut [u8], kf8: u8) {
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
}

#[cfg(target_arch = "x86_64")]
mod arch {
    use core::arch::x86_64::*;

    // SSE2 lane-0 byte replacement mask (SSE2 has no insert_epi8, which is
    // SSE4.1): value = (v & keep15) | (set1(x) & lane0).
    const KEEP15: [i8; 16] = [0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1];
    const LANE0: [i8; 16] = [-1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    pub(super) fn count_sub_ge(src: &[u8], sub: u8, threshold: u8) -> usize {
        debug_assert!(threshold >= 1);
        // SAFETY: SSE2 is baseline on x86_64; intrinsics are plain data
        // shuffles with no memory unsafety beyond the block loads below.
        let vsub = unsafe { _mm_set1_epi8(sub as i8) };
        // Unsigned `x >= t` <=> signed `(x ^ 0x80) > ((t - 1) ^ 0x80)`.
        let vbound = unsafe { _mm_set1_epi8(((threshold - 1) ^ 0x80) as i8) };
        let flip = unsafe { _mm_set1_epi8(-0x80_i8) };
        let mut chunks = src.chunks_exact(16);
        let mut acc = 0u32;
        for c in &mut chunks {
            // SAFETY: chunk length is exactly 16 bytes.
            let v = unsafe { _mm_sub_epi8(_mm_loadu_si128(c.as_ptr().cast()), vsub) };
            let m = unsafe { _mm_cmpgt_epi8(_mm_xor_si128(v, flip), vbound) };
            acc += (unsafe { _mm_movemask_epi8(m) } as u32).count_ones();
        }
        acc as usize + super::scalar::count_sub_ge(chunks.remainder(), sub, threshold)
    }

    pub(super) fn all_ge(src: &[u8], threshold: u8) -> bool {
        debug_assert!(threshold >= 1);
        let vbound = unsafe { _mm_set1_epi8(((threshold - 1) ^ 0x80) as i8) };
        let flip = unsafe { _mm_set1_epi8(-0x80_i8) };
        let mut chunks = src.chunks_exact(16);
        let mut ok = true;
        for c in &mut chunks {
            // SAFETY: chunk length is exactly 16 bytes.
            let v = unsafe { _mm_loadu_si128(c.as_ptr().cast()) };
            let m = unsafe { _mm_cmpgt_epi8(_mm_xor_si128(v, flip), vbound) };
            ok &= unsafe { _mm_movemask_epi8(m) } as u32 == 0xFFFF;
        }
        ok && chunks.remainder().iter().all(|&b| b >= threshold)
    }

    pub(super) fn delta_encode(data: &mut [u8], kf8: u8) {
        if data.is_empty() {
            return;
        }
        let orig0 = data[0];
        data[0] = orig0.wrapping_sub(kf8);
        if data.len() < 2 {
            return;
        }
        // out[i] = in[i] - in[i-1]: pure input-relative subtraction, fully
        // vectorizable with a one-byte cross-block shift.
        let keep15 = unsafe { _mm_loadu_si128(KEEP15.as_ptr().cast()) };
        let lane0 = unsafe { _mm_loadu_si128(LANE0.as_ptr().cast()) };
        let mut chunks = data[1..].chunks_exact_mut(16);
        let mut prev = orig0;
        for c in &mut chunks {
            // SAFETY: chunk length is exactly 16 bytes.
            let v = unsafe { _mm_loadu_si128(c.as_ptr().cast()) };
            let shifted = unsafe {
                _mm_or_si128(
                    _mm_and_si128(_mm_slli_si128(v, 1), keep15),
                    _mm_and_si128(_mm_set1_epi8(prev as i8), lane0),
                )
            };
            unsafe { _mm_storeu_si128(c.as_mut_ptr().cast(), _mm_sub_epi8(v, shifted)) };
            prev = (unsafe { _mm_extract_epi16(v, 7) } >> 8) as u8;
        }
        let mut p = prev;
        for b in chunks.into_remainder() {
            let cur = *b;
            *b = cur.wrapping_sub(p);
            p = cur;
        }
    }

    pub(super) fn delta_decode(data: &mut [u8], kf8: u8) {
        if data.is_empty() {
            return;
        }
        let d0 = data[0].wrapping_add(kf8);
        data[0] = d0;
        if data.len() < 2 {
            return;
        }
        // out[i] = kf + sum(in[0..=i]): byte-wise inclusive scan (Hillis-
        // Steele, 4 shift-add steps per 16 lanes) with a cross-block carry
        // folded into lane 0.
        let lane0 = unsafe { _mm_loadu_si128(LANE0.as_ptr().cast()) };
        let mut chunks = data[1..].chunks_exact_mut(16);
        let mut carry = d0;
        for c in &mut chunks {
            // SAFETY: chunk length is exactly 16 bytes.
            let mut v = unsafe { _mm_loadu_si128(c.as_ptr().cast()) };
            v = unsafe { _mm_add_epi8(v, _mm_and_si128(_mm_set1_epi8(carry as i8), lane0)) };
            v = unsafe { _mm_add_epi8(v, _mm_slli_si128(v, 1)) };
            v = unsafe { _mm_add_epi8(v, _mm_slli_si128(v, 2)) };
            v = unsafe { _mm_add_epi8(v, _mm_slli_si128(v, 4)) };
            v = unsafe { _mm_add_epi8(v, _mm_slli_si128(v, 8)) };
            unsafe { _mm_storeu_si128(c.as_mut_ptr().cast(), v) };
            carry = (unsafe { _mm_extract_epi16(v, 7) } >> 8) as u8;
        }
        let mut acc = carry;
        for b in chunks.into_remainder() {
            acc = acc.wrapping_add(*b);
            *b = acc;
        }
    }
}

#[cfg(target_arch = "aarch64")]
mod arch {
    use core::arch::aarch64::*;

    pub(super) fn count_sub_ge(src: &[u8], sub: u8, threshold: u8) -> usize {
        debug_assert!(threshold >= 1);
        let vsub = vdupq_n_u8(sub);
        let vt = vdupq_n_u8(threshold);
        let mut chunks = src.chunks_exact(16);
        let mut acc = 0u32;
        for c in &mut chunks {
            // SAFETY: chunk length is exactly 16 bytes.
            let v = unsafe { vld1q_u8(c.as_ptr()) };
            let m = unsafe { vcgeq_u8(vsubq_u8(v, vsub), vt) };
            acc += u32::from(unsafe { vaddvq_u8(vandq_u8(m, vdupq_n_u8(1))) });
        }
        acc as usize + super::scalar::count_sub_ge(chunks.remainder(), sub, threshold)
    }

    pub(super) fn all_ge(src: &[u8], threshold: u8) -> bool {
        debug_assert!(threshold >= 1);
        let vt = vdupq_n_u8(threshold);
        let mut chunks = src.chunks_exact(16);
        let mut ok = true;
        for c in &mut chunks {
            // SAFETY: chunk length is exactly 16 bytes.
            let v = unsafe { vld1q_u8(c.as_ptr()) };
            ok &= unsafe { vminvq_u8(vcgeq_u8(v, vt)) } == 0xFF;
        }
        ok && chunks.remainder().iter().all(|&b| b >= threshold)
    }

    /// `[0]*k ++ v[0..16-k]` (lane i holds lane i-k), the NEON equivalent of
    /// `_mm_slli_si128`.
    #[inline]
    unsafe fn shl_bytes(v: uint8x16_t, k: i32) -> uint8x16_t {
        unsafe { vextq_u8(vdupq_n_u8(0), v, 16 - k) }
    }

    pub(super) fn delta_encode(data: &mut [u8], kf8: u8) {
        if data.is_empty() {
            return;
        }
        let orig0 = data[0];
        data[0] = orig0.wrapping_sub(kf8);
        if data.len() < 2 {
            return;
        }
        let mut chunks = data[1..].chunks_exact_mut(16);
        let mut prev = orig0;
        for c in &mut chunks {
            // SAFETY: chunk length is exactly 16 bytes.
            let v = unsafe { vld1q_u8(c.as_ptr()) };
            let mut shifted = unsafe { shl_bytes(v, 1) };
            shifted = unsafe { vsetq_lane_u8(prev, shifted, 0) };
            unsafe { vst1q_u8(c.as_mut_ptr(), vsubq_u8(v, shifted)) };
            prev = unsafe { vgetq_lane_u8(v, 15) };
        }
        let mut p = prev;
        for b in chunks.into_remainder() {
            let cur = *b;
            *b = cur.wrapping_sub(p);
            p = cur;
        }
    }

    pub(super) fn delta_decode(data: &mut [u8], kf8: u8) {
        if data.is_empty() {
            return;
        }
        let d0 = data[0].wrapping_add(kf8);
        data[0] = d0;
        if data.len() < 2 {
            return;
        }
        let mut chunks = data[1..].chunks_exact_mut(16);
        let mut carry = d0;
        for c in &mut chunks {
            // SAFETY: chunk length is exactly 16 bytes.
            let mut v = unsafe { vld1q_u8(c.as_ptr()) };
            v = unsafe { vsetq_lane_u8(carry, v, 0) };
            v = unsafe { vaddq_u8(v, shl_bytes(v, 1)) };
            v = unsafe { vaddq_u8(v, shl_bytes(v, 2)) };
            v = unsafe { vaddq_u8(v, shl_bytes(v, 4)) };
            v = unsafe { vaddq_u8(v, shl_bytes(v, 8)) };
            unsafe { vst1q_u8(c.as_mut_ptr(), v) };
            carry = unsafe { vgetq_lane_u8(v, 15) };
        }
        let mut acc = carry;
        for b in chunks.into_remainder() {
            acc = acc.wrapping_add(*b);
            *b = acc;
        }
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use arch as selected;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
use scalar as selected;

/// Counts bytes where `b.wrapping_sub(sub) >= threshold` (`threshold >= 1`).
pub(super) fn count_sub_ge(src: &[u8], sub: u8, threshold: u8) -> usize {
    selected::count_sub_ge(src, sub, threshold)
}

/// Whether every byte satisfies `b >= threshold` (`threshold >= 1`).
pub(super) fn all_ge(src: &[u8], threshold: u8) -> bool {
    selected::all_ge(src, threshold)
}

/// In-place delta encode (see [`crate::crypto::ssea::delta_encode`]).
pub(super) fn delta_encode(data: &mut [u8], kf8: u8) {
    selected::delta_encode(data, kf8);
}

/// In-place delta decode (see [`crate::crypto::ssea::delta_decode`]).
pub(super) fn delta_decode(data: &mut [u8], kf8: u8) {
    selected::delta_decode(data, kf8);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        let mut s = 0x0bad_c0de_dead_beefu64;
        for b in &mut v {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            *b = (s >> 56) as u8;
        }
        v
    }

    #[test]
    fn simd_matches_scalar() {
        for n in [0usize, 1, 2, 15, 16, 17, 31, 32, 33, 100, 65536, 65539] {
            let src = sample(n);
            for kf in [0u8, 1, 0x5a, 0xa7] {
                assert_eq!(
                    count_sub_ge(&src, kf, 93),
                    scalar::count_sub_ge(&src, kf, 93),
                    "count n={n} kf={kf}"
                );
                assert_eq!(all_ge(&src, 1), scalar::all_ge(&src, 1), "all n={n}");


                let mut a = src.clone();
                let mut b = src.clone();
                delta_encode(&mut a, kf);
                scalar::delta_encode(&mut b, kf);
                assert_eq!(a, b, "enc n={n} kf={kf}");

                let mut a = src.clone();
                let mut b = src.clone();
                delta_decode(&mut a, kf);
                scalar::delta_decode(&mut b, kf);
                assert_eq!(a, b, "dec n={n} kf={kf}");
            }
        }
    }

    #[test]
    fn delta_roundtrip_through_simd() {
        let src = sample(65539);
        let mut data = src.clone();
        delta_encode(&mut data, 154);
        delta_decode(&mut data, 154);
        assert_eq!(data, src);
    }
}


