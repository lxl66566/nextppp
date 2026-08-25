//! Mux wire protocol (v2): every post-handshake nextppp message carries one
//! mux frame, so many logical streams share a single tunnel connection.
//!
//! ```text
//! message = [kind u8][stream_id varint][payload...]
//!
//! OPEN  c->s  payload = ProxyAddr encoding   open a new stream
//! REPLY s->c  payload = [status u8]          open verdict (STATUS_*)
//! DATA  both    payload = stream bytes (non-empty)
//! EOF   both    half-close: forwards a TCP write-side shutdown
//! CLOSE both    abortive teardown: forwards a TCP reset
//! ```
//!
//! Only the client opens streams, so a single per-tunnel counter suffices
//! for stream ids (no odd/even split). `EOF`/`CLOSE` exist because the
//! nextppp framing itself has no in-band stream-level close: a tunnel-wide
//! TCP FIN would kill every stream at once.
//!
//! HEAD-OF-LINE NOTE: streams on one tunnel share its TCP congestion and
//! loss fate; the client pool spreads streams over several tunnels to
//! bound the blast radius (see `docs/extreme-network-optimization.md` B8).

use thiserror::Error;

/// Stream identifier within one tunnel (varint-encoded on the wire).
pub type StreamId = u32;

/// Maximum encoded size of a frame header: kind byte + 5 varint bytes.
pub const HEADER_MAX: usize = 1 + 5;

/// Mux frame kind; the first byte of every frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    /// Client -> server: open a stream to the encoded target.
    Open,
    /// Server -> client: stream-open verdict (`STATUS_OK`/`STATUS_REFUSED`).
    Reply,
    /// Stream payload (both directions).
    Data,
    /// Half-close (both directions).
    Eof,
    /// Abortive teardown (both directions).
    Close,
}

impl FrameKind {
    const CLOSE: u8 = 0x04;
    const DATA: u8 = 0x02;
    const EOF: u8 = 0x03;
    const OPEN: u8 = 0x00;
    const REPLY: u8 = 0x01;

    fn from_u8(v: u8) -> Option<Self> {
        match v {
            Self::OPEN => Some(Self::Open),
            Self::REPLY => Some(Self::Reply),
            Self::DATA => Some(Self::Data),
            Self::EOF => Some(Self::Eof),
            Self::CLOSE => Some(Self::Close),
            _ => None,
        }
    }

    /// Wire byte of this kind.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Open => Self::OPEN,
            Self::Reply => Self::REPLY,
            Self::Data => Self::DATA,
            Self::Eof => Self::EOF,
            Self::Close => Self::CLOSE,
        }
    }
}

/// Errors while parsing a mux frame header.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MuxError {
    /// Empty message (frames carry at least kind + stream id).
    #[error("empty mux frame")]
    Empty,
    /// Varint stream id runs past the message end.
    #[error("truncated stream id")]
    TruncatedStreamId,
    /// Unknown frame kind byte.
    #[error("unknown mux frame kind {0:#04x}")]
    UnknownKind(u8),
}

/// An encoded frame header (kind + varint stream id), stack-allocated for
/// direct use as the `prefix` of `Session::encrypt_into_prefixed`.
pub struct FrameHeader {
    buf: [u8; HEADER_MAX],
    len: usize,
}

impl FrameHeader {
    /// Encodes `kind` and `stream` into a ready-to-use header.
    #[must_use]
    pub fn new(kind: FrameKind, stream: StreamId) -> Self {
        let mut hdr = Self {
            buf: [0u8; HEADER_MAX],
            len: 0,
        };
        hdr.buf[0] = kind.as_u8();
        hdr.len = 1 + encode_varint(stream, &mut hdr.buf[1..]);
        hdr
    }

    /// The encoded header bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// Parses the frame header off `msg`, returning kind, stream id and the
/// remaining payload.
///
/// # Errors
///
/// See [`MuxError`].
pub fn parse_frame(msg: &[u8]) -> Result<(FrameKind, StreamId, &[u8]), MuxError> {
    let (&kind, rest) = msg.split_first().ok_or(MuxError::Empty)?;
    let kind = FrameKind::from_u8(kind).ok_or(MuxError::UnknownKind(kind))?;
    let (stream, n) = decode_varint(rest).ok_or(MuxError::TruncatedStreamId)?;
    Ok((kind, stream, &rest[n..]))
}

/// LEB128 varint: 7 bits per byte, MSB set on all but the last. Returns the
/// number of bytes written (1-5 for u32). `out` must hold at least 5 bytes.
pub fn encode_varint(mut v: u32, out: &mut [u8]) -> usize {
    let mut n = 0;
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out[n] = b;
        n += 1;
        if v == 0 {
            return n;
        }
    }
}

/// Inverse of [`encode_varint`]: the value and its encoded length, or
/// `None` on truncation/overflow (more than 5 bytes or bits past u32).
#[must_use]
pub fn decode_varint(buf: &[u8]) -> Option<(u32, usize)> {
    let mut v = 0u32;
    for (i, &b) in buf.iter().enumerate().take(5) {
        let bits = u32::from(b & 0x7f);
        // The 5th byte may carry at most 4 payload bits (32 = 4*7 + 4).
        if i == 4 && bits > 0x0f {
            return None;
        }
        v |= bits << (7 * i);
        if b & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    None
}

/// REPLY payload statuses (identical to protocol v1's `STATUS_*`).
pub use crate::proto::{STATUS_OK as REPLY_OK, STATUS_REFUSED as REPLY_REFUSED};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip_boundaries() {
        for v in [
            0,
            1,
            127,
            128,
            300,
            16_383,
            16_384,
            2_097_151,
            2_097_152,
            268_435_455,
            268_435_456,
            u32::MAX,
        ] {
            let mut buf = [0u8; 5];
            let n = encode_varint(v, &mut buf);
            assert_eq!(decode_varint(&buf[..n]), Some((v, n)), "v={v}");
        }
    }

    #[test]
    fn varint_encoding_matches_leb128() {
        let mut buf = [0u8; 5];
        assert_eq!(encode_varint(0, &mut buf), 1);
        assert_eq!(buf[0], 0x00);
        let n = encode_varint(300, &mut buf);
        assert_eq!(&buf[..n], &[0xac, 0x02]);
        let n = encode_varint(u32::MAX, &mut buf);
        assert_eq!(&buf[..n], &[0xff, 0xff, 0xff, 0xff, 0x0f]);
    }

    #[test]
    fn varint_rejects_truncation_and_overflow() {
        assert_eq!(decode_varint(&[]), None);
        assert_eq!(decode_varint(&[0x80]), None);
        assert_eq!(decode_varint(&[0x80, 0x80, 0x80, 0x80, 0x80]), None);
        // 5th byte with more than 4 payload bits overflows u32.
        assert_eq!(decode_varint(&[0xff, 0xff, 0xff, 0xff, 0x1f]), None);
        assert_eq!(
            decode_varint(&[0xff, 0xff, 0xff, 0xff, 0x0f]),
            Some((u32::MAX, 5))
        );
    }

    #[test]
    fn frame_header_roundtrip() {
        for (kind, stream) in [
            (FrameKind::Open, 1),
            (FrameKind::Reply, 127),
            (FrameKind::Data, 128),
            (FrameKind::Eof, 70_000),
            (FrameKind::Close, u32::MAX),
        ] {
            let hdr = FrameHeader::new(kind, stream);
            let mut msg = hdr.as_slice().to_vec();
            msg.extend_from_slice(b"payload");
            let (k, s, payload) = parse_frame(&msg).unwrap();
            assert_eq!((k, s, payload), (kind, stream, &b"payload"[..]));
        }
    }

    #[test]
    fn parse_rejects_malformed_frames() {
        assert_eq!(parse_frame(&[]), Err(MuxError::Empty));
        assert_eq!(parse_frame(&[0x02]), Err(MuxError::TruncatedStreamId));
        assert_eq!(parse_frame(&[0x02, 0x80]), Err(MuxError::TruncatedStreamId));
        assert_eq!(parse_frame(&[0x7f, 0x01]), Err(MuxError::UnknownKind(0x7f)));
    }

    #[test]
    fn reply_status_constants_stable() {
        // The REPLY payload carries the same status bytes as protocol v1.
        assert_eq!(REPLY_OK, 0x00);
        assert_eq!(REPLY_REFUSED, 0x01);
    }
}
