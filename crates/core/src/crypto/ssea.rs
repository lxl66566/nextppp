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
//! * `lcg_next` computes the three LCG steps as three independent affine maps of the seed (chain
//!   depth 1), which matters because masked-XOR feeds each 31-bit mix output back as the next seed
//!   — that nonlinear feedback also rules out any closed-form jump-ahead (leapfrog).
//! * base94 encode/decode live in the `base94-simd` crate (SIMD fast paths over 16-byte blocks,
//!   bit-exact with the scalar reference).

// Intentional truncating/wrapping casts below mirror the C++ `Byte(int)`
// conversions: the protocol relies on low-byte / modulo-256 semantics.
#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
// Hot loops use raw-pointer swaps/stores to skip bounds checks that the
// compiler cannot elide (`j` comes from a modulo).
#![allow(unsafe_code)]

use crate::crypto::simd;

/// LCG multiplier / increment (ssea.cpp constants).
const LCG_A: u32 = 1_103_515_245;
const LCG_C: u32 = 12_345;
/// Two-step jump for the restructured `lcg_next`: next3 = next1*A^2 + C*(A+1).
const LCG_A2: u32 = LCG_A.wrapping_mul(LCG_A);
const LCG_C2: u32 = LCG_C.wrapping_mul(LCG_A.wrapping_add(1));
/// Three-step affine map, all in one multiply from the seed: next3 = seed*A^3 + C3.
const LCG_A3: u32 = LCG_A2.wrapping_mul(LCG_A);
const LCG_C3: u32 = LCG_C
    .wrapping_mul(LCG_A2)
    .wrapping_add(LCG_C.wrapping_mul(LCG_A))
    .wrapping_add(LCG_C);

/// Advances the 31-bit LCG seed and returns a 31-bit value
/// (ssea.cpp `random_next`).
///
/// Algebraically identical to three chained `x*A+C` steps; each step is an
/// affine map of the seed, so all three evaluate as independent multiplies
/// (chain depth 1). This shortens the critical path of masked-XOR, which
/// feeds each output back as the next seed (strictly serial).
#[must_use]
pub fn lcg_next(seed: &mut u32) -> u32 {
    let next1 = seed.wrapping_mul(LCG_A).wrapping_add(LCG_C);
    let next2 = seed.wrapping_mul(LCG_A2).wrapping_add(LCG_C2);
    let next3 = seed.wrapping_mul(LCG_A3).wrapping_add(LCG_C3);
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
#[cfg_attr(feature = "hotpath", hotpath::measure)]
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
#[cfg_attr(feature = "hotpath", hotpath::measure)]
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
#[cfg_attr(feature = "hotpath", hotpath::measure)]
pub fn delta_encode(data: &mut [u8], kf: u32) {
    simd::delta_encode(data, kf as u8);
}

/// In-place inverse of [`delta_encode`]. SIMD-accelerated (prefix-sum scan).
#[cfg_attr(feature = "hotpath", hotpath::measure)]
pub fn delta_decode(data: &mut [u8], kf: u32) {
    simd::delta_decode(data, kf as u8);
}

/// XOR mask that evolves the key with the LCG after each 4-byte word / 2-byte
/// half-word chunk (ssea.cpp `masked_xor_random_next`).
///
/// Self-inverse for a fixed initial key. Chunks are processed little-endian;
/// the final odd byte is masked with the low byte of the current key.
///
/// Perf note: the chain runs on the 31-bit *return values* (`kf = lcg_next(kf)`),
/// not on the internal LCG states — the nonlinear mix output is the next seed,
/// so the recurrence admits no closed-form jump-ahead (a stride-4 leapfrog
/// attempt changes the keystream and breaks the golden vectors). Each word's
/// multiplies are independent (see [`lcg_next`]); the serial mix+mul chain
/// bounds this primitive.
#[cfg_attr(feature = "hotpath", hotpath::measure)]
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
            assert_ne!(&data, &original, "len {len}");
            masked_xor_random_next(&mut data, key);
            assert_eq!(data, original, "len {len}");
        }
    }
}
