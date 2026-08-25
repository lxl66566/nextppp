//! Transport-free session codec for event-driven (async) callers.
//!
//! [`Session`] owns the same per-direction codec cores as
//! [`crate::Transmission`] but performs no I/O itself: the caller feeds
//! wire bytes into a buffer and drains complete frames with
//! [`Session::poll_frame`], and produces wire packets with
//! [`Session::encrypt_into`] / [`Session::encrypt_into_prefixed`]. This is
//! the buffer bridge the mux/event-driven data plane is built on: one
//! `read(2)` chunk may contain several frames (or half a frame), which the
//! streaming `Read`-based API cannot express.
//!
//! Obtain a session from a handshaked transmission via
//! [`crate::Transmission::into_session`]; the typical deployment runs the
//! handshake on a blocking thread and moves the data plane onto an async
//! runtime.
//!
//! Copy budget: binary framing decrypts in place inside the caller's
//! buffer (zero copy); base94 framing decodes into the internal scratch
//! and is therefore one copy per frame (unchanged from the streaming
//! path).

use rand::{Rng, rngs::StdRng};

use crate::{
    SessionId,
    error::Result,
    frame::binary::{HEADER_SIZE, payload_deobfuscate},
    transmission::{RxCore, TxCore, decrypt_tail, effective_flags, parse_binary_header},
};

/// A handshaked nextppp session decoupled from its transport; see the
/// module docs.
// `session_id` mirrors Transmission's field/accessor naming on purpose.
#[allow(clippy::struct_field_names)]
pub struct Session<R = StdRng> {
    tx: TxCore<R>,
    rx: RxCore,
    session_id: SessionId,
    /// Binary frame whose 3-byte header was already consumed from the
    /// caller's buffer but whose body is still incomplete: the header
    /// decrypt advances the protocol cipher exactly once per frame, so the
    /// parsed `(len, header_kf)` must be stashed until the body arrives.
    pending_binary: Option<(usize, u32)>,
    /// Bytes of the caller's buffer occupied by the last frame returned
    /// from [`Self::poll_frame`]; drained via [`Self::take_consumed`].
    consumed: usize,
}

impl<R: Rng> Session<R> {
    /// Wraps codec cores moved out of a [`crate::Transmission`].
    pub(crate) fn from_cores(tx: TxCore<R>, rx: RxCore, session_id: SessionId) -> Self {
        Self {
            tx,
            rx,
            session_id,
            pending_binary: None,
            consumed: 0,
        }
    }

    /// The negotiated session id (server-assigned).
    #[must_use]
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Encrypts `plaintext` into a complete wire packet appended to `out`
    /// (see [`crate::Transmission::encrypt_into`]).
    #[cfg_attr(feature = "hotpath", hotpath::measure(impl_type = "Session"))]
    pub fn encrypt_into(&mut self, out: &mut Vec<u8>, plaintext: &[u8]) -> Result<()> {
        self.tx.encrypt_into(out, plaintext)
    }

    /// Prefixed variant of [`Self::encrypt_into`]: the wire message is
    /// `prefix || payload`, assembled without an intermediate buffer. Mux
    /// callers pass `[kind, varint stream id ..]` as the prefix.
    #[cfg_attr(feature = "hotpath", hotpath::measure(impl_type = "Session"))]
    pub fn encrypt_into_prefixed(
        &mut self,
        out: &mut Vec<u8>,
        prefix: &[u8],
        payload: &[u8],
    ) -> Result<()> {
        self.tx.encrypt_into_prefixed(out, prefix, payload)
    }

    /// Attempts to decode one frame from the front of `buf`.
    ///
    /// Returns `Ok(None)` when the buffered bytes are an incomplete frame
    /// (read more). On success the returned slice borrows `buf` (binary
    /// framing, decrypted in place) or an internal scratch (base94
    /// framing); the frame's wire bytes stay in `buf` until the caller
    /// drops the borrow and drains `self.take_consumed()` bytes off the
    /// front.
    ///
    /// A failed poll may have advanced cipher state (the binary header
    /// must be decrypted to learn the frame length); like the streaming
    /// path, any error means the session is desynced and must be dropped.
    #[cfg_attr(feature = "hotpath", hotpath::measure(impl_type = "Session"))]
    pub fn poll_frame<'a>(&'a mut self, buf: &'a mut Vec<u8>) -> Result<Option<&'a [u8]>> {
        poll_frame_impl(
            &mut self.rx,
            &mut self.pending_binary,
            &mut self.consumed,
            buf,
        )
    }

    /// Bytes of the caller's buffer occupied by the last frame from
    /// [`Self::poll_frame`]; the caller drains this many bytes off the
    /// front once the returned borrow ends.
    pub fn take_consumed(&mut self) -> usize {
        std::mem::take(&mut self.consumed)
    }

    /// Splits into independent sending/receiving halves that can live on
    /// separate async tasks (mux tunnels run one reader and one writer
    /// task per connection). The halves stay wire-compatible with an
    /// unsplit peer: per-direction cipher state never crosses over.
    #[must_use]
    pub fn split(self) -> (SessionTx<R>, SessionRx) {
        let Self {
            tx,
            rx,
            session_id: _,
            pending_binary,
            consumed,
        } = self;
        debug_assert!(pending_binary.is_none() && consumed == 0);
        (SessionTx { core: tx }, SessionRx {
            core: rx,
            pending_binary,
            consumed,
        })
    }
}

/// Sending half of a [`Session`] (see [`Session::split`]).
pub struct SessionTx<R = StdRng> {
    core: TxCore<R>,
}

impl<R: Rng> SessionTx<R> {
    /// See [`Session::encrypt_into`].
    #[cfg_attr(feature = "hotpath", hotpath::measure(impl_type = "SessionTx"))]
    pub fn encrypt_into(&mut self, out: &mut Vec<u8>, plaintext: &[u8]) -> Result<()> {
        self.core.encrypt_into(out, plaintext)
    }

    /// See [`Session::encrypt_into_prefixed`].
    #[cfg_attr(feature = "hotpath", hotpath::measure(impl_type = "SessionTx"))]
    pub fn encrypt_into_prefixed(
        &mut self,
        out: &mut Vec<u8>,
        prefix: &[u8],
        payload: &[u8],
    ) -> Result<()> {
        self.core.encrypt_into_prefixed(out, prefix, payload)
    }
}

/// Receiving half of a [`Session`] (see [`Session::split`]).
pub struct SessionRx {
    core: RxCore,
    pending_binary: Option<(usize, u32)>,
    consumed: usize,
}

impl SessionRx {
    /// See [`Session::poll_frame`].
    #[cfg_attr(feature = "hotpath", hotpath::measure(impl_type = "SessionRx"))]
    pub fn poll_frame<'a>(&'a mut self, buf: &'a mut Vec<u8>) -> Result<Option<&'a [u8]>> {
        poll_frame_impl(
            &mut self.core,
            &mut self.pending_binary,
            &mut self.consumed,
            buf,
        )
    }

    /// See [`Session::take_consumed`].
    pub fn take_consumed(&mut self) -> usize {
        std::mem::take(&mut self.consumed)
    }
}

/// Shared incremental-decode body behind [`Session::poll_frame`] and
/// [`SessionRx::poll_frame`].
fn poll_frame_impl<'a>(
    rx: &'a mut RxCore,
    pending_binary: &'a mut Option<(usize, u32)>,
    consumed: &'a mut usize,
    buf: &'a mut Vec<u8>,
) -> Result<Option<&'a [u8]>> {
    if !rx.handshaked || rx.key.plaintext {
        // base94 envelope: the header is unencrypted, so the frame
        // length can be peeked without touching cipher state.
        let Some(total) = rx.b94.peek_frame_len(buf)? else {
            return Ok(None);
        };
        if buf.len() < total {
            return Ok(None);
        }
        rx.b94
            .decode_packet_into(&mut rx.scratch_body, &buf[..total])?;
        let msg = decrypt_tail(
            &rx.key,
            &mut rx.protocol_rx,
            &mut rx.transport_rx,
            rx.handshaked,
            &mut rx.scratch_body,
        )?;
        *consumed = total;
        Ok(Some(msg))
    } else {
        // Binary framing: decrypt the header once the 3 bytes are in
        // (consuming them off the buffer), then wait for the body.
        let (len, header_kf) = if let Some(pending) = *pending_binary {
            pending
        } else {
            if buf.len() < HEADER_SIZE {
                return Ok(None);
            }
            let header: [u8; HEADER_SIZE] = buf[..HEADER_SIZE].try_into().expect("length checked");
            let (len, header_kf) =
                parse_binary_header(rx.key.kf, &mut rx.protocol_rx, header, None)?;
            buf.drain(..HEADER_SIZE);
            *pending_binary = Some((len, header_kf));
            (len, header_kf)
        };
        if buf.len() < len {
            return Ok(None);
        }
        let flags = effective_flags(&rx.key, rx.handshaked);
        let body = &mut buf[..len];
        payload_deobfuscate(body, &flags, header_kf, rx.key.kf);
        rx.transport_rx.apply(body);
        *pending_binary = None;
        *consumed = len;
        Ok(Some(body))
    }
}
