//! Binary framing: the inner encrypted packet layout used after the base94
//! shell is stripped (see `docs/openppp2-algo.md` §5).
//!
//! ```text
//! packet = header[3] || payload
//!   header = delta_encode(seed || enc16(len-1))
//!     * seed: random per packet, defines header_kf = kf ^ seed
//!     * len-1 avoids an all-zero length field for max-size frames
//!     * the 2 length bytes are optionally protocol-cipher encrypted, then
//!       XOR-masked and shuffled with header_kf
//!   payload = transform(transport_cipher(plaintext), header_kf)
//!     * transform = masked_xor? shuffle? delta? (all forced pre-handshake)
//! ```

// header_kf byte masking intentionally uses the low byte only (C++ `Byte(x)`).
#![allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]

use std::io::Read;

use rand::Rng;

use crate::{
    PPP_BUFFER_SIZE,
    crypto::{
        cipher::SessionCipher,
        ssea::{delta_decode, delta_encode, masked_xor_random_next, shuffle, unshuffle},
    },
    error::{Error, Result},
};

/// Binary header size in bytes.
pub const HEADER_SIZE: usize = 3;

/// Effective payload-transform switches. Pre-handshake ("safest") mode forces
/// all three on regardless of configuration, matching openppp2.
#[derive(Clone, Copy, Debug)]
pub struct PayloadFlags {
    /// Evolving-LCG XOR mask with header_kf.
    pub masked: bool,
    /// Key-driven byte permutation with header_kf.
    pub shuffle: bool,
    /// Delta encoding with the configured kf.
    pub delta: bool,
}

impl PayloadFlags {
    /// No transforms at all.
    pub const NONE: Self = Self {
        masked: false,
        shuffle: false,
        delta: false,
    };
    /// All transforms enabled (pre-handshake mode).
    pub const SAFEST: Self = Self {
        masked: true,
        shuffle: true,
        delta: true,
    };

    #[must_use]
    pub fn or(self, other: Self) -> Self {
        Self {
            masked: self.masked || other.masked,
            shuffle: self.shuffle || other.shuffle,
            delta: self.delta || other.delta,
        }
    }
}

/// Builds the 3-byte encrypted header. Returns the header and the derived
/// `header_kf` used later for the payload transform.
///
/// `payload_len` must be in `1..=PPP_BUFFER_SIZE`.
pub fn header_encrypt<R: Rng>(
    rng: &mut R,
    kf: u32,
    protocol: Option<&mut SessionCipher>,
    payload_len: usize,
) -> Result<([u8; HEADER_SIZE], u32)> {
    if payload_len == 0 || payload_len > PPP_BUFFER_SIZE {
        return Err(Error::FrameTooLarge { len: payload_len });
    }
    let adjusted = payload_len - 1;
    let mut array = [
        rng.random_range(1..=0xff),
        (adjusted >> 8) as u8,
        (adjusted & 0xff) as u8,
    ];
    let header_kf = kf ^ u32::from(array[0]);

    if let Some(cipher) = protocol {
        cipher.apply(&mut array[1..3]);
    }
    array[1] ^= header_kf as u8;
    array[2] ^= header_kf as u8;
    shuffle(&mut array[1..3], header_kf);
    delta_encode(&mut array, kf);
    Ok((array, header_kf))
}

/// Decrypts a 3-byte header. Returns `(payload_len, header_kf)`.
pub fn header_decrypt(
    kf: u32,
    protocol: Option<&mut SessionCipher>,
    header: &[u8; HEADER_SIZE],
) -> Result<(usize, u32)> {
    let mut array = *header;
    delta_decode(&mut array, kf);
    let header_kf = kf ^ u32::from(array[0]);
    unshuffle(&mut array[1..3], header_kf);
    array[1] ^= header_kf as u8;
    array[2] ^= header_kf as u8;
    if let Some(cipher) = protocol {
        cipher.apply(&mut array[1..3]);
    }
    let len = ((u16::from(array[1]) << 8) | u16::from(array[2])) as usize + 1;
    Ok((len, header_kf))
}

/// Applies the payload transform chain in place (order matters:
/// mask -> shuffle -> delta).
pub fn payload_obfuscate(data: &mut [u8], flags: &PayloadFlags, header_kf: u32, kf: u32) {
    if flags.masked {
        masked_xor_random_next(data, header_kf);
    }
    if flags.shuffle {
        shuffle(data, header_kf);
    }
    if flags.delta {
        delta_encode(data, kf);
    }
}

/// Reverses [`payload_obfuscate`] in place.
pub fn payload_deobfuscate(data: &mut [u8], flags: &PayloadFlags, header_kf: u32, kf: u32) {
    if flags.delta {
        delta_decode(data, kf);
    }
    if flags.shuffle {
        unshuffle(data, header_kf);
    }
    if flags.masked {
        masked_xor_random_next(data, header_kf);
    }
}

/// Reads `len` bytes from `r` into a fresh buffer (used by the streaming
/// binary-frame receive path).
pub fn read_payload<Rd: Read>(r: &mut Rd, len: usize) -> Result<Vec<u8>> {
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).map_err(Error::Io)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;
    use crate::crypto::cipher::Method;

    fn roundtrip_case(flags: PayloadFlags, use_protocol: bool, len: usize) {
        let kf = 154_543_927u32;
        let mut rng = StdRng::seed_from_u64(len as u64);
        // Mirror the real transmission: separate tx/rx instances derived from
        // the same password, so their nonce counters stay in lockstep.
        let mut proto_tx = SessionCipher::new(Method::Aes128Cfb, "test");
        let mut proto_rx = SessionCipher::new(Method::Aes128Cfb, "test").for_decryption();

        let plaintext: Vec<u8> = (0..len).map(|i| (i * 89 + 7) as u8).collect();
        let (header, hkf) = header_encrypt(
            &mut rng,
            kf,
            use_protocol.then_some(&mut proto_tx),
            plaintext.len(),
        )
        .unwrap();

        let mut wire = plaintext.clone();
        payload_obfuscate(&mut wire, &flags, hkf, kf);
        let mut packet = header.to_vec();
        packet.extend_from_slice(&wire);

        let hdr: [u8; HEADER_SIZE] = packet[..HEADER_SIZE].try_into().unwrap();
        let (decoded_len, decoded_hkf) =
            header_decrypt(kf, use_protocol.then_some(&mut proto_rx), &hdr).unwrap();
        assert_eq!(decoded_len, plaintext.len());
        assert_eq!(decoded_hkf, hkf);

        let mut body = packet[HEADER_SIZE..].to_vec();
        payload_deobfuscate(&mut body, &flags, decoded_hkf, kf);
        assert_eq!(body, plaintext);
    }

    #[test]
    fn header_and_payload_roundtrip() {
        // Safest (pre-handshake) and configured-off variants.
        roundtrip_case(PayloadFlags::SAFEST, false, 1);
        roundtrip_case(PayloadFlags::SAFEST, false, 100);
        roundtrip_case(PayloadFlags::NONE, false, 100);
        roundtrip_case(PayloadFlags::NONE, true, PPP_BUFFER_SIZE);
        roundtrip_case(
            PayloadFlags {
                masked: true,
                shuffle: false,
                delta: true,
            },
            true,
            999,
        );
    }

    #[test]
    fn length_field_wraps_correctly() {
        let kf = 42u32;
        let mut rng = StdRng::seed_from_u64(1);
        // Max frame: len-1 = 0xFFFF must survive the roundtrip.
        let (header, _) = header_encrypt(&mut rng, kf, None, PPP_BUFFER_SIZE).unwrap();
        let (len, _) = header_decrypt(kf, None, &header).unwrap();
        assert_eq!(len, PPP_BUFFER_SIZE);
    }

    #[test]
    fn zero_length_rejected() {
        let mut rng = StdRng::seed_from_u64(1);
        assert!(header_encrypt(&mut rng, 0, None, 0).is_err());
        assert!(header_encrypt(&mut rng, 0, None, PPP_BUFFER_SIZE + 1).is_err());
    }
}
