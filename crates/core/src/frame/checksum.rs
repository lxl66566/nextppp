//! Standard Internet checksum (RFC 1071), used by the base94 first-frame
//! extended header as a tampering/truncation detector.

// `sum as u16` below is safe: the fold loop guarantees sum <= 0xFFFF.
#![allow(clippy::cast_possible_truncation)]

/// One's complement of the 16-bit one's-complement sum over big-endian
/// 16-bit words (odd trailing byte counted as the high byte of a padded
/// zero byte), matching lwIP `inet_chksum`.
#[must_use]
pub fn inet_chksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut words = data.chunks_exact(2);
    for w in &mut words {
        sum += u32::from(u16::from_be_bytes([w[0], w[1]]));
    }
    if let [b] = words.remainder() {
        sum += u32::from(*b) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc1071_example() {
        // Classic RFC1071/lwIP example vector: 00 01 f2 03 f4 f5 f6 f7 -> 220d
        assert_eq!(
            inet_chksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]),
            0x220d
        );
    }

    #[test]
    fn odd_length_and_zeros() {
        // Odd length: trailing 0xf7 acts as 0xf700 -> sum 0x2ddf9 -> 0x2204.
        assert_eq!(
            inet_chksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf7]),
            0x2204
        );
        // All-zero input has checksum 0xFFFF (one's complement of 0).
        assert_eq!(inet_chksum(&[0u8; 6]), 0xffff);
        assert_eq!(inet_chksum(&[]), 0xffff);
    }
}
