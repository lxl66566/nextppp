//! Crate error types.

/// Errors produced by the openppp3 core protocol stack.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Underlying transport I/O failure (connection reset, EOF, timeout, ...).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// A frame header or body failed structural validation.
    #[error("invalid frame")]
    InvalidFrame,

    /// base94 payload contains characters outside the printable alphabet or a
    /// truncated/overflowing escape sequence.
    #[error("invalid base94 data")]
    InvalidBase94,

    /// First-frame extended checksum mismatch: the stream is corrupted or
    /// tampered with, or the peer uses a different `kf`.
    #[error("first-frame checksum mismatch")]
    ChecksumMismatch,

    /// A handshake session-id packet failed to parse.
    #[error("invalid session id")]
    InvalidSessionId,

    /// Handshake sequence failed; the static string describes the stage.
    #[error("handshake failed: {0}")]
    HandshakeFailed(&'static str),

    /// The obfuscation-flag canary exchanged in `nmux` does not match the
    /// local configuration (`masked`/`plaintext`/`delta_encode`/
    /// `shuffle_data`/`kf` differ between endpoints).
    #[error("obfuscation flags mismatch between client and server")]
    FlagsMismatch,

    /// A decoded frame length exceeds the protocol ceiling.
    #[error("frame too large: {len}")]
    FrameTooLarge {
        /// Offending decoded length.
        len: usize,
    },

    /// Zero-length payloads cannot be framed (see openppp2 ITransmission).
    #[error("zero-length payload rejected")]
    ZeroLength,
}

/// Convenience alias used across the crate.
pub type Result<T, E = Error> = core::result::Result<T, E>;

impl Error {
    /// Returns `true` when the error is caused by the transport being closed
    /// (useful for clean shutdown detection in read loops).
    #[must_use]
    pub fn is_eof(&self) -> bool {
        matches!(
            self,
            Self::Io(e) if e.kind() == std::io::ErrorKind::UnexpectedEof
        )
    }
}

// Manual impl needed only to keep `Eq` on the enum despite `io::Error`.
impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Io(a), Self::Io(b)) => a.kind() == b.kind(),
            (Self::InvalidFrame, Self::InvalidFrame)
            | (Self::InvalidBase94, Self::InvalidBase94)
            | (Self::ChecksumMismatch, Self::ChecksumMismatch)
            | (Self::InvalidSessionId, Self::InvalidSessionId)
            | (Self::FlagsMismatch, Self::FlagsMismatch)
            | (Self::ZeroLength, Self::ZeroLength) => true,
            (Self::HandshakeFailed(a), Self::HandshakeFailed(b)) => a == b,
            (Self::FrameTooLarge { len: a }, Self::FrameTooLarge { len: b }) => a == b,
            _ => false,
        }
    }
}

impl Eq for Error {}

impl From<base94_simd::DecodeError> for Error {
    fn from(_: base94_simd::DecodeError) -> Self {
        Self::InvalidBase94
    }
}
