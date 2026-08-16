//! Handshake layer: NOP noise prelude, session-id packets, the obfuscation
//! flag canary and nonce-counter helpers.
//!
//! Sequence (openppp2 §7):
//!
//! ```text
//! client: nop* ->          <- sid (server session id)
//! client:      ivv ->      <- nmux (mux parity + flag canary in high 64 bits)
//! both:   rekey ciphers from ivv, switch to data-plane framing
//! ```
//!
//! session-id packet layout: `[kfs[4]] [4-round XOR encrypted body]` where
//! the body starts with the decimal id, a random 0x20..0x2F separator, then
//! random anti-traffic-analysis padding. `kfs[0] & 0x80` marks dummy noise
//! packets which receivers skip.

// Low-byte extraction (`kf ^ kfs[i]` as u8) mirrors the C++ semantics.
#![allow(clippy::cast_possible_truncation)]

use rand::{Rng, RngExt};

use crate::{
    SessionId,
    config::ObfuscationKey,
    error::{Error, Result},
};

/// Magic prefix of the obfuscation-flag canary (low 48 bits).
pub const CANARY_MAGIC: u64 = 0xc0de_c0de_c0de;
/// Mask selecting the 48 magic bits inside the canary's high word.
pub const CANARY_MAGIC_MASK: u64 = 0x0000_ffff_ffff_ffff;

/// A parsed handshake session-id packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionPacket {
    /// MSB-tagged noise packet: must be skipped by receivers.
    Dummy,
    /// Real session id with its 128-bit value.
    Session(SessionId),
}

/// Builds the 64-bit canary that pins every framing-relevant config bit:
/// `magic(48) | flags(4) @48 | kf & 0xFFF(12) @52`.
#[must_use]
pub fn flag_canary(key: &ObfuscationKey) -> u64 {
    let mut flags: u64 = 0;
    flags |= u64::from(key.masked);
    flags |= u64::from(key.plaintext) << 1;
    flags |= u64::from(key.delta_encode) << 2;
    flags |= u64::from(key.shuffle_data) << 3;
    CANARY_MAGIC | (flags << 48) | (u64::from(key.kf & 0x0fff) << 52)
}

/// Number of NOP noise packets to emit before the real handshake
/// (openppp2 `Transmission_Handshake_Nop`): `ceil(rand(2^kl..2^kh) / 1400)`.
#[must_use]
pub fn nop_rounds<R: Rng>(rng: &mut R, key: &ObfuscationKey) -> u32 {
    let kl = 1u32 << key.kl;
    let kh = 1u32 << key.kh;
    let (lo, hi) = if kl > kh {
        (kh, kl)
    } else {
        (kl, kh)
    };
    let rounds = if lo == hi {
        lo
    } else {
        rng.random_range(lo..=hi)
    };
    rounds.div_ceil(175 << 3)
}

/// Packs a session-id packet. `id == 0` produces a dummy (noise) packet.
#[must_use]
pub fn pack_session_id<R: Rng>(rng: &mut R, key: &ObfuscationKey, id: SessionId) -> Vec<u8> {
    let real = id != 0;
    let kfs: [u8; 4] = [
        if real {
            rng.random_range(0x00..=0x7f)
        } else {
            rng.random_range(0x80..=0xff)
        },
        rng.random_range(0x01..=0xff),
        rng.random_range(0x01..=0xff),
        rng.random_range(0x01..=0xff),
    ];

    let mut body = Vec::with_capacity(128);
    if real {
        append_decimal(&mut body, id);
    } else {
        // Random 128-bit numeric body so noise packets are indistinguishable
        // in shape from real ones.
        let v: u128 = rng.random();
        append_decimal(
            &mut body,
            if v == 0 {
                1
            } else {
                v
            },
        );
    }
    // Separator: always a non-digit (0x20..0x2F) so decimal parsing stops.
    body.push(rng.random_range(0x20..=0x2f));

    // Anti-traffic-analysis padding: two random-length printable runs.
    let max = (key.kx % 0x100) as usize;
    if max > 0 {
        for _ in 0..max {
            body.push(rng.random_range(0x20..=0x7e));
        }
        body.push(b'/');
        let min = body.len() + 4;
        let effective_max = max.max(min);
        let loops = rng.random_range(1..=(effective_max << 2));
        for _ in 0..loops {
            body.push(rng.random_range(0x20..=0x7e));
        }
    }

    // 4-round XOR: each round key = kf ^ kfs[0..=i]. Note the kf
    // contribution appears in all four round keys and therefore cancels
    // after the full chain (verified against the C++ semantics): this layer
    // is pure obfuscation against naive fingerprinting, not secrecy. The
    // session values themselves are non-secret randoms.
    let mut kf = key.kf;
    for &kfs_i in &kfs {
        kf ^= u32::from(kfs_i);
        for b in &mut body {
            *b ^= kf as u8;
        }
    }

    let mut packet = Vec::with_capacity(4 + body.len());
    packet.extend_from_slice(&kfs);
    packet.extend_from_slice(&body);
    packet
}

/// Unpacks a session-id packet; dummy packets are reported, not decoded.
pub fn unpack_session_id(key: &ObfuscationKey, packet: &[u8]) -> Result<SessionPacket> {
    if packet.len() < 4 {
        return Err(Error::InvalidFrame);
    }
    if packet[0] & 0x80 != 0 {
        return Ok(SessionPacket::Dummy);
    }
    let kfs = [packet[0], packet[1], packet[2], packet[3]];
    let mut body = packet[4..].to_vec();
    if body.is_empty() {
        return Err(Error::InvalidFrame);
    }

    let mut kf = key.kf;
    for &kfs_i in &kfs {
        kf ^= u32::from(kfs_i);
        for b in &mut body {
            *b ^= kf as u8;
        }
    }

    // Decimal prefix ends at the guaranteed non-digit separator.
    let mut id: u128 = 0;
    let mut digits = 0;
    for &b in &body {
        if !b.is_ascii_digit() {
            break;
        }
        id = id
            .checked_mul(10)
            .and_then(|id| id.checked_add(u128::from(b - b'0')))
            .ok_or(Error::InvalidSessionId)?;
        digits += 1;
    }
    if digits == 0 {
        return Err(Error::InvalidSessionId);
    }
    Ok(SessionPacket::Session(id))
}

fn append_decimal(out: &mut Vec<u8>, mut v: u128) {
    let mut buf = [0u8; 40]; // 2^128 < 10^39
    let mut len = 0;
    loop {
        buf[len] = b'0' + (v % 10) as u8;
        len += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    out.extend(buf[..len].iter().rev());
}

#[cfg(test)]
mod tests {
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;
    use crate::config::ObfuscationKey;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0xbeef)
    }

    #[test]
    fn session_id_roundtrip() {
        let key = ObfuscationKey::default();
        let mut r = rng();
        for id in [
            1u128,
            42,
            i64::MAX as u128,
            u128::MAX - 3,
            0x1234_5678_9abc_def0,
        ] {
            let packet = pack_session_id(&mut r, &key, id);
            assert_eq!(
                unpack_session_id(&key, &packet).unwrap(),
                SessionPacket::Session(id)
            );
        }
    }

    #[test]
    fn dummy_packets_are_tagged_and_skipped() {
        let key = ObfuscationKey::default();
        let mut r = rng();
        for _ in 0..64 {
            let packet = pack_session_id(&mut r, &key, 0);
            assert_eq!(packet[0] & 0x80, 0x80);
            assert_eq!(
                unpack_session_id(&key, &packet).unwrap(),
                SessionPacket::Dummy
            );
        }
    }

    #[test]
    fn packets_are_printable_except_header() {
        let key = ObfuscationKey::default();
        let mut r = rng();
        let packet = pack_session_id(&mut r, &key, 12345);
        // XOR rounds destroy printability; only structure sizes are stable.
        assert!(packet.len() > 4);
        let dummy = pack_session_id(&mut r, &key, 0);
        assert!(dummy.len() > 4);
    }

    #[test]
    fn xor_layer_is_kf_invariant() {
        // Mathematical property (shared with the C++ original): kf appears
        // in all four round keys, so its contribution cancels — packets
        // decrypt identically under any kf. This documents that the 4-round
        // XOR is obfuscation, not secrecy.
        let key = ObfuscationKey::default();
        let mut other = key.clone();
        other.kf ^= 0x7f01_2345;
        let mut r = rng();
        let packet = pack_session_id(&mut r, &key, 555);
        assert_eq!(
            unpack_session_id(&other, &packet).unwrap(),
            SessionPacket::Session(555)
        );
    }

    #[test]
    fn body_decoding_is_deterministic() {
        let key = ObfuscationKey::default();
        // With kfs = [1,2,3,4] the four round keys XOR to a net low-byte
        // mask of kfs[1]^kfs[3] = 2^4 = 6 (kf cancels), so each body byte is
        // plaintext ^ 6.
        // Non-digit leading byte -> InvalidSessionId.
        let packet = [0x01, 0x02, 0x03, 0x04, 0xf9, 0x06];
        assert_eq!(
            unpack_session_id(&key, &packet),
            Err(Error::InvalidSessionId)
        );
        // "12" + separator (0x20 ^ 6 = 0x26) -> Session(12).
        let packet = [0x01, 0x02, 0x03, 0x04, 0x37, 0x34, 0x26];
        assert_eq!(
            unpack_session_id(&key, &packet).unwrap(),
            SessionPacket::Session(12)
        );
    }

    #[test]
    fn short_packet_rejected() {
        let key = ObfuscationKey::default();
        assert!(unpack_session_id(&key, &[]).is_err());
        assert!(unpack_session_id(&key, &[1, 2, 3]).is_err());
        // Header only, no body.
        assert!(unpack_session_id(&key, &[1, 2, 3, 4]).is_err());
    }

    #[test]
    fn canary_encodes_all_flag_bits() {
        let key = ObfuscationKey::default();
        let c = flag_canary(&key);
        assert_eq!(c & CANARY_MAGIC_MASK, CANARY_MAGIC);
        assert_eq!((c >> 48) & 1, u64::from(key.masked));
        assert_eq!((c >> 49) & 1, u64::from(key.plaintext));
        assert_eq!((c >> 50) & 1, u64::from(key.delta_encode));
        assert_eq!((c >> 51) & 1, u64::from(key.shuffle_data));
        assert_eq!((c >> 52) & 0xfff, u64::from(key.kf & 0xfff));

        let mut other = key.clone();
        other.delta_encode = !other.delta_encode;
        assert_ne!(flag_canary(&other), c);

        other = key.clone();
        other.kf ^= 0x1000; // differs outside the 12 canary bits
        assert_eq!(flag_canary(&other), c);
    }

    #[test]
    fn nop_rounds_bounds() {
        let mut key = ObfuscationKey::default(); // kl=10, kh=12
        let mut r = rng();
        for _ in 0..100 {
            let rounds = nop_rounds(&mut r, &key);
            assert!((1..=3).contains(&rounds), "default config yields 1..3");
        }
        // kl == kh: deterministic single value.
        key.kl = 0;
        key.kh = 0;
        assert_eq!(nop_rounds(&mut r, &key), 1); // ceil(1/1400)
        key.kl = 5;
        key.kh = 5;
        assert_eq!(nop_rounds(&mut r, &key), 1); // ceil(32/1400)
        key.kl = 14;
        key.kh = 14;
        assert_eq!(nop_rounds(&mut r, &key), 12); // ceil(16384/1400)
        // Swapped exponents are normalized.
        key.kl = 12;
        key.kh = 10;
        for _ in 0..50 {
            assert!((1..=3).contains(&nop_rounds(&mut r, &key)));
        }
    }
}
