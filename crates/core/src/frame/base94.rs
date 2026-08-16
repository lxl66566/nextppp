//! base94 framing: the printable-ASCII envelope used before the handshake
//! completes (and permanently in `plaintext` mode).
//!
//! Wire format (see `docs/openppp2-algo.md` §4):
//!
//! ```text
//! first frame:  [k][f][d1][d2][d3][c1][c2][c3]   (7-byte extended header)
//! later frames: [k][f][d1][d2][d3]               (4-byte simple header)
//!               [ base94-encoded binary packet ... ]
//! ```
//!
//! * `d1..d3`: length digits `(encoded_len + kf_mod) % mod`, right-aligned, zero (0x20) padded,
//!   then `h[2]`/`h[3]` are byte-swapped.
//! * Parity trick: `k` is **even** when `h[1]` is random filler (length took fewer than 3 digits)
//!   and **odd** when `h[1]` is a real length digit.
//! * The 3 checksum digits in the first frame carry `(inet_chksum(header) ^ length + kf_mod) %
//!   mod`, shuffled — any stream corruption or a mismatched `kf` fails the check immediately.

// Length arithmetic intentionally mirrors the C++ int/u32/usize mixing:
// truncating casts are part of the protocol semantics.
#![allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]

use std::io::Read;

use base94_simd::{
    DECIMAL_MAX_LEN as BASE94_DECIMAL_MAX_LEN, decimal_decode as base94_decimal_decode,
    decimal_encode as base94_decimal_encode, decode_into as base94_decode_into,
    encode_into as base94_encode_into, encoded_len as base94_encoded_len,
};
use rand::{Rng, RngExt};

use crate::{
    BASE94_MAX_FRAME, MOD_MAX, MOD_MIN,
    crypto::ssea::{lcg_range, shuffle, unshuffle},
    error::{Error, Result},
    frame::checksum::inet_chksum,
};

/// Simple header size (all frames).
pub const HEADER_SIMPLE: usize = 4;
/// Extended header size (first frame per direction, includes checksum).
pub const HEADER_EXTENDED: usize = 7;

/// Stateful base94 frame codec. Transmit and receive first-frame states are
/// tracked independently, mirroring openppp2's `frame_tn_`/`frame_rn_`.
///
/// `Clone` exists for [`crate::Transmission::split`]: each half keeps its own
/// copy and only ever touches its own direction's first-frame flag.
#[derive(Clone)]
pub struct Base94Framer {
    kf: u32,
    mod_: u32,
    kf_mod: u32,
    tx_first: bool,
    rx_first: bool,
}

impl Base94Framer {
    /// Derives the length-obfuscation modulus from `kf`
    /// (`Lcgmod(TRANSMISSION)` in openppp2).
    #[must_use]
    pub fn new(kf: u32) -> Self {
        let mut seed = kf;
        let mod_ = lcg_range(&mut seed, MOD_MIN, MOD_MAX);
        // openppp2 uses abs(int32(kf) % int32(MOD)); replicate exactly.
        let kf_mod = ((kf as i32) % (mod_ as i32)).unsigned_abs();
        Self {
            kf,
            mod_,
            kf_mod,
            tx_first: true,
            rx_first: true,
        }
    }

    /// Encodes one framed packet (header + base94 payload) and appends it to
    /// `out`. `binary` is the encrypted binary-frame packet.
    #[cfg_attr(feature = "hotpath", hotpath::measure(impl_type = "Base94Framer"))]
    pub fn encode_frame<R: Rng>(
        &mut self,
        rng: &mut R,
        out: &mut Vec<u8>,
        binary: &[u8],
    ) -> Result<()> {
        let encoded_len = base94_encoded_len(binary, self.kf);
        if encoded_len > BASE94_MAX_FRAME {
            return Err(Error::FrameTooLarge { len: encoded_len });
        }
        let (header, hlen) = self.encode_header(rng, encoded_len)?;
        out.reserve(hlen + encoded_len);
        out.extend_from_slice(&header[..hlen]);
        base94_encode_into(out, binary, self.kf);
        Ok(())
    }

    /// Builds the randomized base94 header for an encoded payload of
    /// `length` chars. Returns the header bytes and their valid length.
    fn encode_header<R: Rng>(
        &mut self,
        rng: &mut R,
        length: usize,
    ) -> Result<([u8; HEADER_EXTENDED], usize)> {
        let mut digits = [0u8; BASE94_DECIMAL_MAX_LEN];
        let n = (length as u32 + self.kf_mod) % self.mod_;
        let dl = base94_decimal_encode(u64::from(n), &mut digits);
        if dl == 0 || dl >= HEADER_SIMPLE {
            return Err(Error::InvalidFrame); // unreachable with valid bounds
        }

        let mut h = [0x20u8; HEADER_EXTENDED];
        h[HEADER_SIMPLE - dl..HEADER_SIMPLE].copy_from_slice(&digits[..dl]);

        let mut k: u8 = rng.random_range(0x20..=0x7e);
        if h[1] == 0x20 {
            // Length took < 3 digits: h[1] stays filler, k must be even.
            if k & 1 != 0 {
                k += 1; // 0x7E is even, so no overflow past 0x7E
            }
            h[1] = rng.random_range(0x20..=0x7e);
        } else if k & 1 == 0 {
            // h[1] is a real length digit: k must be odd.
            k += 1;
            if k > 0x7e {
                k = 0x21;
            }
        }
        h[0] = k;
        h.swap(2, 3);

        if self.tx_first {
            // Extended header: 3 checksum digits, shuffled with kf.
            let chk = u32::from(inet_chksum(&h[..HEADER_SIMPLE])) ^ length as u32;
            let cn = (chk + self.kf_mod) % self.mod_;
            let cl = base94_decimal_encode(u64::from(cn), &mut digits);
            if cl != 3 {
                return Err(Error::InvalidFrame);
            }
            h[HEADER_SIMPLE..HEADER_EXTENDED].copy_from_slice(&digits[..3]);
            shuffle(&mut h[HEADER_SIMPLE..HEADER_EXTENDED], self.kf);
            self.tx_first = false;
            Ok((h, HEADER_EXTENDED))
        } else {
            Ok((h, HEADER_SIMPLE))
        }
    }

    /// Restores the canonical header form: clears filler when `k` is even,
    /// resets the seed byte and undoes the length-digit swap.
    fn restore_header(h: &mut [u8]) {
        if h[0] & 1 == 0 {
            h[1] = 0x20;
        }
        h[0] = 0x20;
        h.swap(2, 3);
    }

    /// `(base94_decimal(digits) - kf_mod + mod) % mod` — un-obfuscates a
    /// length field.
    fn decode_length(&self, digits: &[u8]) -> Result<u32> {
        let n = base94_decimal_decode(digits)?;
        Ok(((n + u64::from(self.mod_ - self.kf_mod)) % u64::from(self.mod_)) as u32)
    }

    /// Decodes and validates the 7-byte extended (first) header. Does not
    /// advance the first-frame flag; callers flip it once the whole frame
    /// has been validated.
    fn decode_header_extended(&self, h: &mut [u8; HEADER_EXTENDED]) -> Result<usize> {
        let chk = u32::from(inet_chksum(&h[..HEADER_SIMPLE]));
        Self::restore_header(&mut h[..HEADER_SIMPLE]);
        let payload_length = self.decode_length(&h[1..HEADER_SIMPLE])?;
        if payload_length < 1 {
            return Err(Error::InvalidFrame);
        }
        unshuffle(&mut h[HEADER_SIMPLE..HEADER_EXTENDED], self.kf);
        let n = self.decode_length(&h[HEADER_SIMPLE..HEADER_EXTENDED])?;
        if n != chk ^ payload_length {
            return Err(Error::ChecksumMismatch);
        }
        Ok(payload_length as usize)
    }

    /// Decodes a 4-byte simple header.
    fn decode_header_simple(&self, h: &mut [u8; HEADER_SIMPLE]) -> Result<usize> {
        Self::restore_header(h);
        let len = self.decode_length(&h[1..HEADER_SIMPLE])?;
        if len < 1 {
            return Err(Error::InvalidFrame);
        }
        Ok(len as usize)
    }

    fn check_bound(len: usize) -> Result<()> {
        if len > BASE94_MAX_FRAME {
            Err(Error::FrameTooLarge { len })
        } else {
            Ok(())
        }
    }

    /// Reads one complete base94 frame from `r` and returns the decoded
    /// binary packet. Blocking; requires the whole frame to arrive. The
    /// first-frame flag advances only after the entire frame validates.
    pub fn read_frame<Rd: Read>(&mut self, r: &mut Rd) -> Result<Vec<u8>> {
        let mut scratch = Vec::new();
        let mut out = Vec::new();
        self.read_frame_into(r, &mut scratch, &mut out)?;
        Ok(out)
    }

    /// [`Self::read_frame`] with caller-provided scratch buffers for the
    /// encoded (still base94) bytes and the decoded binary packet, avoiding
    /// per-frame allocations on steady-state streaming paths. `out` is
    /// cleared and refilled with the full binary packet (3-byte binary
    /// header included).
    #[cfg_attr(feature = "hotpath", hotpath::measure(impl_type = "Base94Framer"))]
    pub fn read_frame_into<Rd: Read>(
        &mut self,
        r: &mut Rd,
        scratch: &mut Vec<u8>,
        out: &mut Vec<u8>,
    ) -> Result<()> {
        let first = self.rx_first;
        let len = if first {
            let mut header = [0u8; HEADER_EXTENDED];
            r.read_exact(&mut header).map_err(Error::Io)?;
            let len = self.decode_header_extended(&mut header)?;
            Self::check_bound(len)?;
            len
        } else {
            let mut header = [0u8; HEADER_SIMPLE];
            r.read_exact(&mut header).map_err(Error::Io)?;
            let len = self.decode_header_simple(&mut header)?;
            Self::check_bound(len)?;
            len
        };

        scratch.clear();
        scratch.resize(len, 0);
        r.read_exact(scratch).map_err(Error::Io)?;
        out.clear();
        out.reserve(len);
        base94_decode_into(out, scratch, self.kf)?;
        self.rx_first = false;
        Ok(())
    }

    /// Compatibility wrapper kept for external callers; steady-state paths
    /// should prefer [`Self::read_frame_into`].
    pub fn read_frame_with<Rd: Read>(
        &mut self,
        r: &mut Rd,
        scratch: &mut Vec<u8>,
    ) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.read_frame_into(r, scratch, &mut out)?;
        Ok(out)
    }

    /// In-memory variant of [`Self::read_frame`] for datagram-style
    /// transports: decodes one frame from the front of `packet`, honoring
    /// first-frame state and the length-consistency check. Failed decodes do
    /// not advance the first-frame flag.
    pub fn decode_packet(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        let (header_len, len) = if self.rx_first {
            if packet.len() < HEADER_EXTENDED {
                return Err(Error::InvalidFrame);
            }
            let mut header = [0u8; HEADER_EXTENDED];
            header.copy_from_slice(&packet[..HEADER_EXTENDED]);
            let len = self.decode_header_extended(&mut header)?;
            Self::check_bound(len)?;
            (HEADER_EXTENDED, len)
        } else {
            if packet.len() < HEADER_SIMPLE {
                return Err(Error::InvalidFrame);
            }
            let mut header = [0u8; HEADER_SIMPLE];
            header.copy_from_slice(&packet[..HEADER_SIMPLE]);
            let len = self.decode_header_simple(&mut header)?;
            Self::check_bound(len)?;
            (HEADER_SIMPLE, len)
        };
        if len + header_len != packet.len() {
            return Err(Error::InvalidFrame);
        }
        let mut out = Vec::with_capacity(len);
        base94_decode_into(&mut out, &packet[header_len..], self.kf)?;
        self.rx_first = false;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0xc0de)
    }

    /// Interop pair: encoder + decoder sharing kf.
    fn pair(kf: u32) -> (Base94Framer, Base94Framer) {
        (Base94Framer::new(kf), Base94Framer::new(kf))
    }

    fn roundtrip(kf: u32, payloads: &[Vec<u8>]) {
        let (mut tx, mut rx) = pair(kf);
        let mut rx_mem = Base94Framer::new(kf);
        let mut rng = rng();
        for payload in payloads {
            let mut wire = Vec::new();
            tx.encode_frame(&mut rng, &mut wire, payload).unwrap();
            let mut stream: &[u8] = &wire;
            let decoded = rx.read_frame(&mut stream).unwrap();
            assert_eq!(decoded, *payload, "kf={kf}");
            assert!(stream.is_empty(), "frame must be consumed exactly");
            // In-memory path agrees with the stream path on the same bytes,
            // mirroring the encoder's first-frame state.
            assert_eq!(rx_mem.decode_packet(&wire).unwrap(), *payload);
        }
    }

    #[test]
    fn frame_roundtrip_sequences() {
        let payloads: Vec<Vec<u8>> = vec![
            vec![1],
            vec![0xff; 3],
            (0..300u32).map(|i| (i % 256) as u8).collect(),
            vec![0x20; 1000],
        ];
        for kf in [0u32, 1, 154_543_927, u32::MAX] {
            roundtrip(kf, &payloads);
        }
    }

    #[test]
    fn first_frame_is_extended_then_simple() {
        let (mut tx, _) = pair(154_543_927);
        let mut rng = rng();
        let mut first = Vec::new();
        tx.encode_frame(&mut rng, &mut first, b"hello").unwrap();
        assert_eq!(
            first.len() - base94_encoded_len(b"hello", 154_543_927),
            HEADER_EXTENDED
        );
        let mut second = Vec::new();
        tx.encode_frame(&mut rng, &mut second, b"second").unwrap();
        assert_eq!(
            second.len() - base94_encoded_len(b"second", 154_543_927),
            HEADER_SIMPLE
        );
    }

    #[test]
    fn all_frames_are_printable() {
        let (mut tx, _) = pair(0x1234_5678);
        let mut rng = rng();
        let payload: Vec<u8> = (0..255u32).map(|i| i as u8).collect();
        let mut wire = Vec::new();
        tx.encode_frame(&mut rng, &mut wire, &payload).unwrap();
        assert!(wire.iter().all(|&c| (0x20..=0x7e).contains(&c)));
    }

    #[test]
    fn tampered_first_frame_fails_checksum() {
        let (mut tx, mut rx) = pair(154_543_927);
        let mut rng = rng();
        let mut wire = Vec::new();
        tx.encode_frame(&mut rng, &mut wire, b"payload").unwrap();
        // Flip one bit inside the checksum digits region (bytes 4..7).
        wire[4] ^= 0x01;
        let mut stream: &[u8] = &wire;
        assert!(matches!(
            rx.read_frame(&mut stream),
            Err(Error::ChecksumMismatch)
        ));
    }

    #[test]
    fn wrong_kf_fails_first_frame() {
        let (mut tx, _) = pair(111);
        let (_, mut rx) = pair(222);
        let mut rng = rng();
        let mut wire = Vec::new();
        tx.encode_frame(&mut rng, &mut wire, b"payload").unwrap();
        let mut stream: &[u8] = &wire;
        // Different kf yields a different kf_mod/mod -> checksum mismatch or
        // garbage length; either way decoding must fail.
        assert!(rx.read_frame(&mut stream).is_err());
    }

    #[test]
    fn in_memory_length_mismatch_rejected() {
        let (mut tx, mut rx) = pair(154_543_927);
        let mut rng = rng();
        let mut wire = Vec::new();
        tx.encode_frame(&mut rng, &mut wire, b"abcdef").unwrap();
        // Truncated / concatenated datagram fails the exact-length check.
        assert!(rx.decode_packet(&wire[..wire.len() - 1]).is_err());
        let mut doubled = wire.clone();
        doubled.extend_from_slice(&wire);
        assert!(rx.decode_packet(&doubled).is_err());
        // Untouched packet decodes fine.
        assert_eq!(rx.decode_packet(&wire).unwrap(), b"abcdef");
    }
}
