//! SIMD kernels for the codec hot path.
//!
//! x86_64 uses SSSE3 kernels (runtime-detected at dispatch; `_mm_shuffle_epi8`
//! is SSSE3, not SSE2 — the pre-extraction code compiled it unconditionally).
//! aarch64 uses baseline NEON for the helper scans; other targets use the
//! portable scalar fallback. Wire semantics are identical across backends —
//! the scalar code in `lib.rs` doubles as the reference definition.

// Raw core::arch intrinsics require unsafe. Every block only touches
// block-sized loads/stores over slices already split to exact block sizes,
// so indexing cannot go out of bounds.
#![allow(unsafe_code)]
// Intrinsic parameters are i8 lanes; u8 <-> i8 bit reinterpretation (and the
// matching truncating casts on extract) is the intended semantic.
#![allow(
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]

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
}

#[cfg(target_arch = "x86_64")]
mod arch {
    use core::arch::x86_64::*;

    // SSE2 lane-0 byte replacement mask (SSE2 has no insert_epi8, which is
    // SSE4.1): value = (v & keep15) | (set1(x) & lane0).
    const KEEP15: [i8; 16] = [
        0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    ];
    const LANE0: [i8; 16] = [-1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    /// 16-entry table: spreads the 4 bits of `n` to even byte positions
    /// (bit 2k of the result = bit k of n) — feeds the quarter keep-mask
    /// computation in the encode fast path.
    const fn build_spread4() -> [u8; 16] {
        let mut t = [0u8; 16];
        let mut n = 0usize;
        while n < 16 {
            let mut v = 0u8;
            let mut k = 0;
            while k < 4 {
                v |= (((n >> k) & 1) as u8) << (2 * k);
                k += 1;
            }
            t[n] = v;
            n += 1;
        }
        t
    }
    const SPREAD4: [u8; 16] = build_spread4();

    /// SIMD encode fast path (see [`crate::encode_into`]).
    ///
    /// Encodes whole 16-byte blocks of `src` into `dst_ptr` at `*p`,
    /// advancing it; returns the number of source bytes consumed (a
    /// multiple of 16; the tail goes to the scalar path). For each input
    /// byte the leader/follower char pair is precomputed into a 32-byte
    /// interleaved scratch `(c1, c2)` layout; a per-quarter keep-mask
    /// (always keep c1, keep c2 only on escapes) then compacts it through
    /// the same pshufb LUT the decoder uses.
    ///
    /// # Safety
    ///
    /// Requires SSSE3; the dispatcher runtime-detects it before calling.
    #[target_feature(enable = "ssse3")]
    #[allow(clippy::too_many_lines)]
    pub(super) fn encode_simd(dst_ptr: *mut u8, pos: &mut usize, src: &[u8], kf8: u8) -> usize {
        let n_blocks = src.len() / 16;
        if n_blocks == 0 {
            return 0;
        }
        // SAFETY: SSSE3 is guaranteed by the caller (runtime-detected at
        // dispatch). Loads stay inside `src`; the 32-byte scratch is a stack
        // array; stores into `dst_ptr` stay within the caller-reserved
        // `2*src.len()+16` bytes (each block emits at most 32 bytes;
        // over-stored compact padding is overwritten by later quarters or
        // cut by the caller's final `set_len`).
        unsafe {
            let flip = _mm_set1_epi8(-0x80_i8);
            // Unsigned v >= t <=> signed (v^0x80) > (t-1)^0x80.
            let esc_bound = _mm_set1_epi8((0x5cu8 ^ 0x80) as i8);
            let hi_bound = _mm_set1_epi8((0xb9u8 ^ 0x80) as i8);
            let kf_vec = _mm_set1_epi8(kf8 as i8);
            let c20 = _mm_set1_epi8(0x20);
            // 0x20 - 93 (wrapping): first constant of the follower char.
            let c2_base = _mm_set1_epi8(0x20u8.wrapping_sub(93) as i8);
            let c93 = _mm_set1_epi8(93);
            let c1hi = _mm_set1_epi8(0x7d);
            let one = _mm_set1_epi8(1);

            let mut scratch = [0u8; 32];
            let mut off = 0usize;
            for _ in 0..n_blocks {
                let b = _mm_loadu_si128(src.as_ptr().add(off).cast());
                let v = _mm_sub_epi8(b, kf_vec);
                let flipped = _mm_xor_si128(v, flip);
                let esc = _mm_cmpgt_epi8(flipped, esc_bound);
                let hi = _mm_cmpgt_epi8(flipped, hi_bound);

                // c1 = esc ? 0x7D + (v >= 186) : 0x20 + v. Note 0x7D is odd,
                // so the q2 bit must be *added*, not OR-ed in.
                let c1 = _mm_or_si128(
                    _mm_and_si128(esc, _mm_add_epi8(_mm_and_si128(hi, one), c1hi)),
                    _mm_andnot_si128(esc, _mm_add_epi8(v, c20)),
                );
                // c2 = 0x20 + v - 93 - 93*(v >= 186) (only meaningful on esc)
                let c2 = _mm_sub_epi8(_mm_add_epi8(v, c2_base), _mm_and_si128(hi, c93));

                // Interleaved (c1_0, c2_0, c1_1, c2_1, ...) scratch.
                let ilo = _mm_unpacklo_epi8(c1, c2);
                let ihi = _mm_unpackhi_epi8(c1, c2);
                _mm_storeu_si128(scratch.as_mut_ptr().cast(), ilo);
                _mm_storeu_si128(scratch.as_mut_ptr().add(16).cast(), ihi);

                // Per-quarter compaction: delete the c2 slots of non-escape
                // bytes. Quarter q covers input bytes 4q..4q+4, i.e. scratch
                // slots 8q..8q+8; its delete-mask has bit 2t+1 set when
                // input 4q+t did not escape.
                let m = _mm_movemask_epi8(esc) as u16;
                let mut q = 0usize;
                while q < 4 {
                    let nib = ((m >> (4 * q)) & 0xf) as usize;
                    // spread nib to even bits, shift to odd slots: the keep
                    // mask is 0x55 | (spread << 1); the delete mask is its
                    // complement within the odd slots.
                    let keep = 0x55u8 | ((SPREAD4[nib] << 1) & 0xaa);
                    let del = keep ^ 0xff;
                    let row = _mm_loadu_si128(COMPACT.0[del as usize * 16..].as_ptr().cast());
                    // Load only the quarter's 8 slots (`_mm_loadl_epi64`,
                    // zero-extended): a 16-byte load would read past the
                    // 32-byte scratch for q = 3 (lanes 8.. are never
                    // selected by the row, but the load itself was OOB).
                    let v8 = _mm_loadl_epi64(scratch.as_ptr().add(8 * q).cast());
                    let packed = _mm_shuffle_epi8(v8, row);
                    let cnt = COMPACT.1[del as usize] as usize;
                    _mm_storel_epi64(dst_ptr.add(*pos).cast(), packed);
                    *pos += cnt;
                    q += 1;
                }
                off += 16;
            }
            off
        }
    }

    /// 256-entry x 16B pshufb control table: for an 8-lane leader mask `m`,
    /// row `m` packs the non-leader lanes to the front (low half) and the
    /// high-half variant with +8 lane offset (bytes 8..16 of the row).
    /// Counts live beside it (`cnt[m]` / `cnt[256+m]`).
    const fn build_compact_tables() -> ([u8; 256 * 16], [u8; 512]) {
        let mut shuf = [0u8; 256 * 16];
        let mut cnt = [0u8; 512];
        let mut m = 0usize;
        while m < 256 {
            let mut k = 0usize;
            let mut i = 0usize;
            while i < 8 {
                if m & (1 << i) == 0 {
                    shuf[m * 16 + k] = i as u8;
                    k += 1;
                }
                i += 1;
            }
            let mut j = k;
            while j < 8 {
                shuf[m * 16 + j] = 0x80;
                j += 1;
            }
            cnt[m] = k as u8;
            let mut k2 = 0usize;
            let mut i2 = 0usize;
            while i2 < 8 {
                if m & (1 << i2) == 0 {
                    shuf[m * 16 + 8 + k2] = (8 + i2) as u8;
                    k2 += 1;
                }
                i2 += 1;
            }
            let mut j2 = 8 + k2;
            while j2 < 16 {
                shuf[m * 16 + j2] = 0x80;
                j2 += 1;
            }
            cnt[256 + m] = k2 as u8;
            m += 1;
        }
        (shuf, cnt)
    }
    static COMPACT: ([u8; 256 * 16], [u8; 512]) = build_compact_tables();

    /// SIMD decode fast path (see [`crate::decode_into`]).
    ///
    /// Decodes whole 16-byte blocks of `src` (assumed `>= 0x20`, checked by
    /// the caller) into `out` at `*p`, advancing both. On a block containing
    /// an invalid construct the successfully decoded prefix is returned as
    /// `Err(consumed_src, produced_dst)` so the scalar reference path can
    /// resume there and produce the exact wire-legal error; `Ok` means every
    /// whole block was consumed (the tail is left to the scalar path).
    ///
    /// Hand-off invariant: the returned source position never directly
    /// follows an unconsumed escape leader, so the scalar path never needs
    /// cross-boundary pair context — a failing block that carries an
    /// incoming follower rolls the previous block back with it.
    ///
    /// # Safety
    ///
    /// Requires SSSE3; the dispatcher runtime-detects it before calling.
    #[target_feature(enable = "ssse3")]
    #[allow(clippy::too_many_lines)]
    pub(super) fn decode_simd(
        dst_ptr: *mut u8,
        pos: &mut usize,
        src: &[u8],
        kf8: u8,
    ) -> Result<(usize, usize), (usize, usize)> {
        let n_blocks = src.len() / 16;
        if n_blocks == 0 {
            return Ok((0, 0));
        }
        // SAFETY: SSSE3 is guaranteed by the caller (runtime-detected at
        // dispatch). All loads are 16-byte block loads inside `src`; all
        // stores stay within the `src.len()` bytes the caller reserved past
        // `*pos` (each block emits < 16 bytes, and over-stored padding bytes
        // are overwritten by later blocks or cut by the caller's final
        // `set_len`).
        unsafe {
            let flip = _mm_set1_epi8(-0x80_i8);
            // Unsigned c >= 0x7D <=> signed (c^0x80) > (0x7D-1)^0x80 = 0xFC.
            let lead_bound = _mm_set1_epi8(0xfcu8 as i8);
            // c > 0x7D (invalid follower) <=> flipped > 0xFD. Not covered by
            // the overflow check: a 0x7D leader with a 0x7E follower yields
            // ev = 93 + 94 = 187 <= 0xFF yet is rejected by the reference
            // (found by cargo-fuzz).
            let foll_bound = _mm_set1_epi8(0xfdu8 as i8);
            // c > 0x7E (invalid leader) <=> flipped > 0xFE.
            let bad_bound = _mm_set1_epi8(0xfeu8 as i8);
            let keep15 = _mm_loadu_si128(KEEP15.as_ptr().cast());
            let lane0 = _mm_loadu_si128(LANE0.as_ptr().cast());
            let zero = _mm_setzero_si128();
            let kf_vec = _mm_set1_epi8(kf8 as i8);
            let c93 = _mm_set1_epi16(93);
            let c255 = _mm_set1_epi16(255);
            let sub20 = _mm_set1_epi8(0x20);

            let mut off = 0usize; // consumed bytes
            let mut carry = false; // lane0 of the next block is a follower
            let mut prev_char = 0u8; // last byte of the previous block
            // Last block boundary where no cross-boundary pair is pending:
            // the scalar path can always resume from here without missing
            // pair context. Updated whenever a block starts with carry=false.
            let mut safe = (0usize, 0usize);
            let mut block = 0usize;
            while block < n_blocks {
                if !carry {
                    safe = (off, *pos);
                }
                let v = _mm_loadu_si128(src.as_ptr().add(off).cast());
                let flipped = _mm_xor_si128(v, flip);
                let raw_lead = _mm_cmpgt_epi8(flipped, lead_bound);
                let bad_lead = _mm_movemask_epi8(_mm_cmpgt_epi8(flipped, bad_bound)) as u32;

                // Effective leaders under sequential consumption:
                // L[i] = R[i] & ~L[i-1] — a raw leader immediately after a
                // consumed leader is itself consumed as a follower (legal
                // "7d 7d" pairs). The recurrence's depth grows one lane per
                // iteration from the run-head seed, so the five statements
                // below settle runs up to 6 raw leaders long. Runs of 7+
                // (~1e-10 in legitimate traffic, only crafted inputs) fall
                // back to the scalar path via the run-length check below.
                let mut lead = raw_lead;
                if carry {
                    lead = _mm_andnot_si128(lane0, lead);
                }
                let r16 = _mm_movemask_epi8(lead) as u16;
                let long_run = r16
                    & (r16 << 1)
                    & (r16 << 2)
                    & (r16 << 3)
                    & (r16 << 4)
                    & (r16 << 5)
                    & (r16 << 6);
                if long_run != 0 {
                    *pos = safe.1;
                    return Err(safe);
                }
                let mut l = _mm_andnot_si128(_mm_slli_si128(lead, 1), lead);
                l = _mm_andnot_si128(_mm_slli_si128(l, 1), lead);
                l = _mm_andnot_si128(_mm_slli_si128(l, 1), lead);
                l = _mm_andnot_si128(_mm_slli_si128(l, 1), lead);
                l = _mm_andnot_si128(_mm_slli_si128(l, 1), lead);
                let lead_eff = l;
                let mk = _mm_movemask_epi8(lead_eff) as u16;
                let carry_out = mk & 0x8000 != 0;

                // Follower lanes (lane0 patched by the incoming carry).
                let mut fmask = _mm_slli_si128(lead_eff, 1);
                if carry {
                    fmask = _mm_or_si128(fmask, lane0);
                }

                // Escape value = 93*(prev-0x20-92) + (c-0x20), computed in
                // u16 lanes; garbage on non-follower lanes is blended away.
                let mut vl = _mm_slli_si128(v, 1);
                vl = _mm_or_si128(
                    _mm_and_si128(vl, keep15),
                    _mm_and_si128(_mm_set1_epi8(prev_char as i8), lane0),
                );
                let b = _mm_sub_epi8(v, sub20);
                let bl = _mm_sub_epi8(vl, sub20);
                let q = _mm_sub_epi8(bl, _mm_set1_epi8(92));
                let q_lo = _mm_unpacklo_epi8(q, zero);
                let q_hi = _mm_unpackhi_epi8(q, zero);
                let b_lo = _mm_unpacklo_epi8(b, zero);
                let b_hi = _mm_unpackhi_epi8(b, zero);
                let ev_lo = _mm_add_epi16(_mm_mullo_epi16(q_lo, c93), b_lo);
                let ev_hi = _mm_add_epi16(_mm_mullo_epi16(q_hi, c93), b_hi);
                // Overflow (> 0xFF) is only an error on follower lanes. The
                // compares live in i16 lanes: narrow back to byte lanes with
                // packs_epi16 (signed saturate: 0xFFFF == -1 passes through
                // as 0xFF; packus would wrongly clamp it to 0x00 — found by
                // cargo-fuzz) before intersecting with the byte-lane
                // follower mask.
                let ovf_lo = _mm_cmpgt_epi16(ev_lo, c255);
                let ovf_hi = _mm_cmpgt_epi16(ev_hi, c255);
                let ovf_bytes =
                    _mm_or_si128(_mm_packs_epi16(ovf_lo, zero), _mm_packs_epi16(zero, ovf_hi));
                let bad_esc = _mm_movemask_epi8(_mm_and_si128(ovf_bytes, fmask)) as u32;
                let bad_foll =
                    _mm_movemask_epi8(_mm_and_si128(_mm_cmpgt_epi8(flipped, foll_bound), fmask))
                        as u32;
                if bad_lead != 0 || bad_esc != 0 || bad_foll != 0 {
                    // Invalid construct: resume from the last safe boundary
                    // (no pending cross-block pair) so the scalar reference
                    // path sees whole pairs and reports the exact error.
                    *pos = safe.1;
                    return Err(safe);
                }
                let ev8 = _mm_packus_epi16(_mm_and_si128(ev_lo, c255), _mm_and_si128(ev_hi, c255));

                // val = follower ? esc_val : (c - 0x20), plus kf (wrapping).
                let val = _mm_add_epi8(
                    _mm_or_si128(_mm_and_si128(fmask, ev8), _mm_andnot_si128(fmask, b)),
                    kf_vec,
                );

                // Compact out the leader lanes via the pshufb LUT. The two
                // 8-lane halves use *their own* mask rows: a row's low half
                // packs lanes 0..8, its high half packs lanes 8..16 with +8
                // lane offsets (pshufb indexes the full 16-lane register).
                let lo = (mk & 0xff) as usize;
                let hi = (mk >> 8) as usize;
                let row_lo = _mm_loadu_si128(COMPACT.0[lo * 16..].as_ptr().cast());
                let row_hi = _mm_loadu_si128(COMPACT.0[hi * 16..].as_ptr().cast());
                let lo_packed = _mm_shuffle_epi8(val, row_lo);
                let hi_packed = _mm_shuffle_epi8(val, row_hi);
                let cnt_lo = COMPACT.1[lo] as usize;
                let cnt_hi = COMPACT.1[256 + hi] as usize;
                let outp = dst_ptr.add(*pos);
                _mm_storel_epi64(outp.cast(), lo_packed);
                let high = _mm_unpackhi_epi64(hi_packed, hi_packed);
                _mm_storel_epi64(outp.add(cnt_lo).cast(), high);
                *pos += cnt_lo + cnt_hi;
                off += 16;
                prev_char = *src.as_ptr().add(off - 1);
                carry = carry_out;
                block += 1;

                // The last processed block may end with a leader whose
                // follower lies in the scalar tail. Consume that pair here
                // so the scalar tail never starts with an orphaned follower
                // (which the sequential scan would misread as a single
                // char). A missing or invalid follower is a truncated/
                // malformed escape: roll back to the safe boundary and let
                // the scalar path produce the exact error.
                if carry && block == n_blocks {
                    if let Some(c2) = src.get(off).copied() {
                        let q15 = u32::from(prev_char) - 0x20 - 92;
                        let b2 = u32::from(c2) - 0x20;
                        let v_esc = q15.wrapping_mul(93) + b2;
                        if !(1..=2).contains(&q15) || b2 > 93 || v_esc > 0xff {
                            *pos = safe.1;
                            return Err(safe);
                        }
                        *dst_ptr.add(*pos) = (v_esc as u8).wrapping_add(kf8);
                        *pos += 1;
                        off += 1;
                        carry = false;
                    } else {
                        *pos = safe.1;
                        return Err(safe);
                    }
                }
            }
            Ok((off, *pos))
        }
    }

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
            ok &= unsafe { _mm_movemask_epi8(m) } as u32 == 0xffff;
        }
        ok && chunks.remainder().iter().all(|&b| b >= threshold)
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
            ok &= unsafe { vminvq_u8(vcgeq_u8(v, vt)) } == 0xff;
        }
        ok && chunks.remainder().iter().all(|&b| b >= threshold)
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use arch as selected;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
use scalar as selected;

/// Counts bytes where `b.wrapping_sub(sub) >= threshold` (`threshold >= 1`).
pub(crate) fn count_sub_ge(src: &[u8], sub: u8, threshold: u8) -> usize {
    selected::count_sub_ge(src, sub, threshold)
}

/// Whether every byte satisfies `b >= threshold` (`threshold >= 1`).
pub(crate) fn all_ge(src: &[u8], threshold: u8) -> bool {
    selected::all_ge(src, threshold)
}

/// SIMD encode fast path (x86_64 with runtime SSSE3 detection only; other
/// targets use the scalar loop). Returns the consumed source prefix
/// (multiple of 16).
pub(crate) fn encode_simd(dst_ptr: *mut u8, p: &mut usize, src: &[u8], kf8: u8) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("ssse3") {
            // SAFETY: SSSE3 support was just detected.
            return unsafe { arch::encode_simd(dst_ptr, p, src, kf8) };
        }
        0
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (dst_ptr, p, src, kf8);
        0
    }
}

/// SIMD decode fast path (x86_64 with runtime SSSE3 detection only; other
/// targets decode with the scalar reference loop). See the x86_64 backend
/// for semantics.
pub(crate) fn decode_simd(
    dst_ptr: *mut u8,
    p: &mut usize,
    src: &[u8],
    kf8: u8,
) -> Result<(usize, usize), (usize, usize)> {
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("ssse3") {
            // SAFETY: SSSE3 support was just detected.
            return unsafe { arch::decode_simd(dst_ptr, p, src, kf8) };
        }
        Ok((0, 0))
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (dst_ptr, p, src, kf8);
        Ok((0, 0))
    }
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
            }
        }
    }
}
