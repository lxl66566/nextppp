//! Unified data plane: owns the I/O transport, framing state, session
//! ciphers and the handshake state machine.
//!
//! Packet pipeline (openppp2 §5/§6):
//!
//! ```text
//! write:  plaintext
//!           -> transport_cipher                (in place)
//!           -> header_encrypt(len)             (protocol cipher + seed xor
//!                                               + shuffle + delta)
//!           -> payload transform               (masked? shuffle? delta?)
//!           -> [ base94 envelope ]             (pre-handshake or plaintext)
//!           -> io
//! read:   the exact inverse, streaming.
//! ```
//!
//! The per-direction codec state lives in the transport-independent
//! [`TxCore`]/[`RxCore`]; [`Transmission`] bundles both with a duplex
//! transport, and [`Transmission::split_with`] moves each core into a
//! [`TransmissionTx`]/[`TransmissionRx`] half for the classic two-thread
//! bidirectional pump model. In-memory entry points
//! (`encrypt_into`/`decrypt`) do not touch the transport, so they are
//! usable for datagram/mux style callers and are available for any `T`.

// `(nmux >> 64) as u64` and similar narrowing casts are structurally safe.
#![allow(clippy::cast_possible_truncation)]

use std::{
    io::{self, Read, Write},
    mem,
    sync::Arc,
};

use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};

use crate::{
    PPP_BUFFER_SIZE, SessionId,
    config::ObfuscationKey,
    crypto::cipher::{CipherRole, SessionCipher},
    error::{Error, Result},
    frame::{
        base94::Base94Framer,
        binary::{
            HEADER_SIZE, PayloadFlags, header_decrypt, header_encrypt, payload_deobfuscate,
            payload_obfuscate,
        },
    },
    handshake::{
        CANARY_MAGIC, CANARY_MAGIC_MASK, SessionPacket, flag_canary, max_nop_packets, nop_rounds,
        pack_session_id, unpack_session_id,
    },
};

/// Shared in-memory decrypt tail: parses the binary header off `buf` (the
/// full `[header][body]` packet), validates length consistency, then
/// deobfuscates the body in place. Returns the message past the header
/// (the header bytes stay in place; no strip memmove).
fn decrypt_tail<'a>(
    key: &ObfuscationKey,
    protocol_rx: &mut SessionCipher,
    transport_rx: &mut SessionCipher,
    handshaked: bool,
    buf: &'a mut [u8],
) -> Result<&'a [u8]> {
    if buf.len() <= HEADER_SIZE {
        return Err(Error::InvalidFrame);
    }
    let header: [u8; HEADER_SIZE] = buf[..HEADER_SIZE].try_into().expect("length checked");
    let (_, header_kf) = parse_binary_header(key.kf, protocol_rx, header, Some(buf.len()))?;
    let (_, body) = buf.split_at_mut(HEADER_SIZE);
    let flags = effective_flags(key, handshaked);
    payload_deobfuscate(body, &flags, header_kf, key.kf);
    transport_rx.apply(body);
    Ok(body)
}

/// Parses a binary frame header and validates the declared body length
/// against `PPP_BUFFER_SIZE`. `declared_total` is the full packet's byte
/// length on in-memory paths, where it guards against truncation/splicing;
/// stream callers pass `None` because they read exactly `len` bytes.
fn parse_binary_header(
    kf: u32,
    cipher: &mut SessionCipher,
    header: [u8; HEADER_SIZE],
    declared_total: Option<usize>,
) -> Result<(usize, u32)> {
    let (len, header_kf) = header_decrypt(kf, Some(cipher), &header)?;
    if !(1..=PPP_BUFFER_SIZE).contains(&len) {
        return Err(Error::FrameTooLarge { len });
    }
    if let Some(total) = declared_total {
        if len + HEADER_SIZE != total {
            return Err(Error::InvalidFrame);
        }
    }
    Ok((len, header_kf))
}

/// Data-plane flags; pre-handshake everything is forced on ("safest").
fn effective_flags(key: &ObfuscationKey, handshaked: bool) -> PayloadFlags {
    if handshaked {
        PayloadFlags {
            masked: key.masked,
            shuffle: key.shuffle_data,
            delta: key.delta_encode,
        }
    } else {
        PayloadFlags::SAFEST
    }
}

/// Tx-direction codec state: everything needed to turn plaintext into wire
/// packets. Shared verbatim by [`Transmission`] and its split
/// [`TransmissionTx`] half, so streaming and split paths can never drift
/// apart.
struct TxCore<R> {
    rng: R,
    key: Arc<ObfuscationKey>,
    b94: Base94Framer,
    protocol_tx: SessionCipher,
    transport_tx: SessionCipher,
    handshaked: bool,
    /// Intermediate binary packet on base94 paths (the envelope needs a
    /// contiguous input buffer).
    scratch_bin: Vec<u8>,
    /// Wire output of `write`, reused across packets.
    scratch_out: Vec<u8>,
}

impl<R: Rng> TxCore<R> {
    fn new(key: Arc<ObfuscationKey>, rng: R) -> Self {
        Self {
            rng,
            b94: Base94Framer::new(key.kf),
            protocol_tx: SessionCipher::new(key.protocol, CipherRole::Protocol, &key.protocol_key),
            transport_tx: SessionCipher::new(
                key.transport,
                CipherRole::Transport,
                &key.transport_key,
            ),
            key,
            handshaked: false,
            scratch_bin: Vec::new(),
            scratch_out: Vec::new(),
        }
    }

    /// Encrypts `plaintext` into a complete wire packet appended to `out`.
    fn encrypt_into(&mut self, out: &mut Vec<u8>, plaintext: &[u8]) -> Result<()> {
        self.encrypt_impl(out, None, plaintext)
    }

    /// Tagged variant of [`TxCore::encrypt_into`]: the wire message is
    /// `tag || payload`, assembled without an intermediate buffer.
    fn encrypt_into_tagged(&mut self, out: &mut Vec<u8>, tag: u8, payload: &[u8]) -> Result<()> {
        self.encrypt_impl(out, Some(tag), payload)
    }

    fn encrypt_impl(&mut self, out: &mut Vec<u8>, tag: Option<u8>, payload: &[u8]) -> Result<()> {
        let total = payload.len() + usize::from(tag.is_some());
        if total == 0 {
            return Err(Error::ZeroLength);
        }
        if total > PPP_BUFFER_SIZE {
            return Err(Error::FrameTooLarge { len: total });
        }

        let flags = effective_flags(&self.key, self.handshaked);
        let (header, header_kf) = header_encrypt(
            &mut self.rng,
            self.key.kf,
            Some(&mut self.protocol_tx),
            total,
        )?;

        if !self.handshaked || self.key.plaintext {
            // base94 envelope: the binary packet must exist as a contiguous
            // input buffer, so it is assembled in scratch first.
            let bin = &mut self.scratch_bin;
            bin.clear();
            bin.reserve(HEADER_SIZE + total);
            bin.extend_from_slice(&header);
            if let Some(tag) = tag {
                bin.push(tag);
            }
            bin.extend_from_slice(payload);
            let body = &mut bin[HEADER_SIZE..];
            self.transport_tx.apply(body);
            payload_obfuscate(body, &flags, header_kf, self.key.kf);
            self.b94.encode_frame(&mut self.rng, out, bin)
        } else {
            // Binary framing builds the packet directly in `out`: one full
            // packet copy saved vs assembling in scratch first.
            let start = out.len();
            out.reserve(HEADER_SIZE + total);
            out.extend_from_slice(&header);
            if let Some(tag) = tag {
                out.push(tag);
            }
            out.extend_from_slice(payload);
            let body = &mut out[start + HEADER_SIZE..];
            self.transport_tx.apply(body);
            payload_obfuscate(body, &flags, header_kf, self.key.kf);
            Ok(())
        }
    }

    /// Encrypts one message and writes it to the transport.
    fn write(&mut self, io: &mut impl Write, plaintext: &[u8]) -> Result<()> {
        let mut out = mem::take(&mut self.scratch_out);
        out.clear();
        // Restore the scratch even on failure: dropping it here would cost
        // the allocation on every subsequent packet.
        let result = self
            .encrypt_into(&mut out, plaintext)
            .and_then(|()| io.write_all(&out).map_err(Error::Io));
        self.scratch_out = out;
        result
    }

    /// Rebuilds both tx cipher instances with per-connection key material.
    fn rekey(&mut self, ivv: u128) {
        self.protocol_tx = SessionCipher::derive(
            self.key.protocol,
            CipherRole::Protocol,
            &self.key.protocol_key,
            Some(ivv),
        );
        self.transport_tx = SessionCipher::derive(
            self.key.transport,
            CipherRole::Transport,
            &self.key.transport_key,
            Some(ivv),
        );
    }

    /// Marks the handshake complete. In binary framing mode the base94-only
    /// scratch (sized by pre-handshake traffic, which always uses base94,
    /// up to ~131KB) is dead weight for the rest of the connection and gets
    /// released instead of pinned.
    fn on_handshake_complete(&mut self) {
        self.handshaked = true;
        if !self.key.plaintext {
            self.scratch_bin = Vec::new();
        }
    }
}

/// Rx-direction codec state, the exact inverse of [`TxCore`]. Shared
/// verbatim by [`Transmission`] and its split [`TransmissionRx`] half.
struct RxCore {
    key: Arc<ObfuscationKey>,
    b94: Base94Framer,
    protocol_rx: SessionCipher,
    transport_rx: SessionCipher,
    handshaked: bool,
    /// Encoded (pre-decode) frame bytes, reused across packets.
    scratch_read: Vec<u8>,
    /// Decoded message, reused across packets and borrowed out by `read_buf`.
    scratch_body: Vec<u8>,
}

impl RxCore {
    fn new(key: Arc<ObfuscationKey>) -> Self {
        Self {
            b94: Base94Framer::new(key.kf),
            protocol_rx: SessionCipher::new(key.protocol, CipherRole::Protocol, &key.protocol_key)
                .for_decryption(),
            transport_rx: SessionCipher::new(
                key.transport,
                CipherRole::Transport,
                &key.transport_key,
            )
            .for_decryption(),
            key,
            handshaked: false,
            scratch_read: Vec::new(),
            scratch_body: Vec::new(),
        }
    }

    /// Decrypts one complete wire packet (in-memory inverse of
    /// [`TxCore::encrypt_into`]). Allocating compatibility path; see
    /// [`Self::decrypt_in_place`] for the zero-alloc hot path.
    fn decrypt(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        if !self.handshaked || self.key.plaintext {
            let Self {
                b94, scratch_body, ..
            } = self;
            b94.decode_packet_into(scratch_body, packet)?;
        } else {
            self.scratch_body.clear();
            self.scratch_body.extend_from_slice(packet);
        }
        let Self {
            key,
            protocol_rx,
            transport_rx,
            handshaked,
            scratch_body,
            ..
        } = self;
        decrypt_tail(key, protocol_rx, transport_rx, *handshaked, scratch_body).map(<[u8]>::to_vec)
    }

    /// In-place variant of [`Self::decrypt`]: `packet` (one complete wire
    /// packet) is decrypted and the message borrows either `packet` (binary
    /// framing) or the internal base94 scratch — zero allocation either
    /// way, and no header-strip memmove (the header stays in place and the
    /// returned slice starts past it).
    fn decrypt_in_place<'a>(&'a mut self, packet: &'a mut [u8]) -> Result<&'a [u8]> {
        if !self.handshaked || self.key.plaintext {
            let Self {
                b94,
                scratch_body,
                key,
                protocol_rx,
                transport_rx,
                handshaked,
                ..
            } = self;
            b94.decode_packet_into(scratch_body, packet)?;
            decrypt_tail(key, protocol_rx, transport_rx, *handshaked, scratch_body)
        } else {
            let Self {
                key,
                protocol_rx,
                transport_rx,
                handshaked,
                ..
            } = self;
            decrypt_tail(key, protocol_rx, transport_rx, *handshaked, packet)
        }
    }

    /// Reads one framed message from `io`, returning a slice into the
    /// internal scratch buffer (overwritten by the next call).
    fn read_buf(&mut self, io: &mut impl Read) -> Result<&[u8]> {
        let handshaked = self.handshaked;
        let (header_kf, offset) = if !handshaked || self.key.plaintext {
            {
                let Self {
                    b94,
                    scratch_read,
                    scratch_body,
                    ..
                } = self;
                b94.read_frame_into(io, scratch_read, scratch_body)?;
            }
            let Self {
                key,
                protocol_rx,
                scratch_body,
                ..
            } = self;
            if scratch_body.len() <= HEADER_SIZE {
                return Err(Error::InvalidFrame);
            }
            let header: [u8; HEADER_SIZE] = scratch_body[..HEADER_SIZE]
                .try_into()
                .expect("length checked");
            let (_, header_kf) =
                parse_binary_header(key.kf, protocol_rx, header, Some(scratch_body.len()))?;
            // The decoded packet still carries its 3-byte binary header.
            (header_kf, HEADER_SIZE)
        } else {
            let Self {
                key,
                protocol_rx,
                scratch_body,
                ..
            } = self;
            let mut header = [0u8; HEADER_SIZE];
            io.read_exact(&mut header).map_err(Error::Io)?;
            // No length-consistency check: the body below is read to exactly
            // `len` bytes off the stream, so it matches by construction.
            let (len, header_kf) = parse_binary_header(key.kf, protocol_rx, header, None)?;
            // No binary header here: the wire header was consumed above.
            // take+read_to_end writes into spare capacity directly, skipping
            // the zeroing that resize+read_exact would do first.
            scratch_body.clear();
            scratch_body.reserve(len);
            let n = io
                .by_ref()
                .take(len as u64)
                .read_to_end(scratch_body)
                .map_err(Error::Io)?;
            if n != len {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated binary frame",
                )));
            }
            (header_kf, 0)
        };
        let Self {
            key,
            transport_rx,
            scratch_body,
            ..
        } = self;
        let flags = effective_flags(key, handshaked);
        let body = &mut scratch_body[offset..];
        payload_deobfuscate(body, &flags, header_kf, key.kf);
        transport_rx.apply(body);
        Ok(body)
    }

    /// Rebuilds both rx cipher instances with per-connection key material.
    fn rekey(&mut self, ivv: u128) {
        self.protocol_rx = SessionCipher::derive(
            self.key.protocol,
            CipherRole::Protocol,
            &self.key.protocol_key,
            Some(ivv),
        )
        .for_decryption();
        self.transport_rx = SessionCipher::derive(
            self.key.transport,
            CipherRole::Transport,
            &self.key.transport_key,
            Some(ivv),
        )
        .for_decryption();
    }

    /// See [`TxCore::on_handshake_complete`]: drops the base94 read scratch
    /// (~131KB peak) once binary framing takes over.
    fn on_handshake_complete(&mut self) {
        self.handshaked = true;
        if !self.key.plaintext {
            self.scratch_read = Vec::new();
        }
    }
}

/// A framed, encrypted, optionally base94-wrapped connection over any
/// duplex byte transport.
///
/// A `Transmission` is inherently single-threaded per direction; wrap it in
/// your favorite executor, or [`Transmission::split_with`] it into
/// [`TransmissionTx`]/[`TransmissionRx`] halves for the classic two-thread
/// bidirectional pump model.
pub struct Transmission<T, R = StdRng> {
    io: T,
    tx: TxCore<R>,
    rx: RxCore,
    session_id: SessionId,
}

impl<T> Transmission<T, StdRng> {
    /// Creates a transmission with an OS-seeded CSPRNG. Accepts an owned or
    /// already-shared ([`Arc`]) key; long-lived callers should share one
    /// `Arc<ObfuscationKey>` across connections instead of cloning the
    /// struct (it carries two `String` passwords) per connection.
    #[must_use]
    pub fn new(io: T, key: impl Into<Arc<ObfuscationKey>>) -> Self {
        // rand 0.10 removed SeedableRng::from_os_rng; SysRng is the stateless
        // OS-entropy interface, StdRng::try_from_rng seeds it from there.
        let rng = StdRng::try_from_rng(&mut rand::rngs::SysRng)
            .expect("failed to seed StdRng from OS entropy");
        Self::with_rng(io, key, rng)
    }
}

/// Transport-independent core: in-memory packet codec, state and rekeying.
impl<T, R: Rng> Transmission<T, R> {
    /// Creates a transmission with an explicit RNG (deterministic tests).
    #[must_use]
    pub fn with_rng(io: T, key: impl Into<Arc<ObfuscationKey>>, rng: R) -> Self {
        let key = key.into();
        // Config validation is the upper layer's job (see
        // `ObfuscationKey::validate`); this only guards against misuse in
        // debug builds, e.g. hand-constructed keys in tests.
        debug_assert!(key.validate().is_ok());
        Self {
            io,
            tx: TxCore::new(Arc::clone(&key), rng),
            rx: RxCore::new(key),
            session_id: 0,
        }
    }

    /// Whether the handshake completed and data-plane framing is active.
    #[must_use]
    pub fn is_handshaked(&self) -> bool {
        // The handshake flips both cores together; they never diverge.
        self.tx.handshaked
    }

    /// The negotiated session id (server-assigned; 0 before the handshake).
    #[must_use]
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Access to the underlying transport.
    #[must_use]
    pub fn io(&self) -> &T {
        &self.io
    }

    /// Mutable access to the underlying transport (e.g. for timeouts).
    pub fn io_mut(&mut self) -> &mut T {
        &mut self.io
    }

    // ------------------------------------------------------------------
    // In-memory codec (transport untouched)
    // ------------------------------------------------------------------

    /// Encrypts `plaintext` into a complete wire packet appended to `out`
    /// (in-memory path, e.g. for datagram/mux transports).
    #[cfg_attr(feature = "hotpath", hotpath::measure(impl_type = "Transmission"))]
    pub fn encrypt_into(&mut self, out: &mut Vec<u8>, plaintext: &[u8]) -> Result<()> {
        self.tx.encrypt_into(out, plaintext)
    }

    /// Decrypts one complete wire packet (in-memory inverse of
    /// [`Self::encrypt_into`]).
    pub fn decrypt(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        self.rx.decrypt(packet)
    }

    /// [`Self::decrypt`] without allocation: the decrypted message borrows
    /// `packet` (binary framing) or an internal scratch (base94 framing),
    /// overwritten by the next call.
    pub fn decrypt_in_place<'a>(&'a mut self, packet: &'a mut [u8]) -> Result<&'a [u8]> {
        self.rx.decrypt_in_place(packet)
    }

    /// Rebuilds all four cipher instances with per-connection key material.
    fn rekey(&mut self, ivv: u128) {
        self.tx.rekey(ivv);
        self.rx.rekey(ivv);
    }
}

/// Streaming data plane and handshake: requires a duplex byte transport.
impl<T: Read + Write, R: Rng> Transmission<T, R> {
    /// Writes one encrypted message.
    #[cfg_attr(feature = "hotpath", hotpath::measure(impl_type = "Transmission"))]
    pub fn write(&mut self, plaintext: &[u8]) -> Result<()> {
        self.tx.write(&mut self.io, plaintext)
    }

    /// Reads and decrypts one message, blocking until a full frame arrives.
    #[cfg_attr(feature = "hotpath", hotpath::measure(impl_type = "Transmission"))]
    pub fn read(&mut self) -> Result<Vec<u8>> {
        self.read_buf().map(Vec::from)
    }

    /// [`Self::read`] without copying: the message borrows an internal
    /// scratch buffer that is overwritten by the next call.
    #[cfg_attr(feature = "hotpath", hotpath::measure(impl_type = "Transmission"))]
    pub fn read_buf(&mut self) -> Result<&[u8]> {
        self.rx.read_buf(&mut self.io)
    }

    // ------------------------------------------------------------------
    // Handshake
    // ------------------------------------------------------------------

    /// Runs the client-side handshake. Returns `(server_session_id, mux)`;
    /// `mux` reflects the server's multiplexing decision (parity of `nmux`).
    #[cfg_attr(feature = "hotpath", hotpath::measure(impl_type = "Transmission"))]
    pub fn handshake_client(&mut self) -> Result<(SessionId, bool)> {
        self.handshake_prelude()?;

        let sid = self.read_session_id()?;
        if sid == 0 {
            return Err(Error::HandshakeFailed("server session id is zero"));
        }

        let ivv: u128 = self.tx.rng.random();
        if ivv == 0 {
            return Err(Error::HandshakeFailed("ivv generated as zero"));
        }
        self.send_session_id(ivv)?;

        let nmux = self.read_session_id()?;
        if nmux == 0 {
            return Err(Error::HandshakeFailed("nmux is zero"));
        }
        let mux = nmux & 1 == 1;

        // Obfuscation-flag canary, backward compatible: a peer that does not
        // embed the magic leaves fully random high bits (2^-48 false positive)
        // and is silently accepted.
        let nmux_high = (nmux >> 64) as u64;
        if nmux_high & CANARY_MAGIC_MASK == CANARY_MAGIC {
            let local = flag_canary(&self.tx.key);
            if nmux_high != local {
                return Err(Error::FlagsMismatch);
            }
        }

        self.rekey(ivv);
        self.tx.on_handshake_complete();
        self.rx.on_handshake_complete();
        self.session_id = sid;
        Ok((sid, mux))
    }

    /// Runs the server-side handshake for an upper-layer assigned non-zero
    /// `session_id`. `mux` is the multiplexing request encoded into `nmux`'s
    /// parity for the client.
    #[cfg_attr(feature = "hotpath", hotpath::measure(impl_type = "Transmission"))]
    pub fn handshake_server(&mut self, session_id: SessionId, mux: bool) -> Result<()> {
        if session_id == 0 {
            return Err(Error::InvalidSessionId);
        }
        self.handshake_prelude()?;

        self.send_session_id(session_id)?;

        let low: u64 = self.tx.rng.random();
        let mut nmux = (u128::from(flag_canary(&self.tx.key)) << 64) | u128::from(low);
        // Parity carries the mux decision. Bit ops instead of `+1` loops: an
        // increment at u64::MAX would carry into the canary word.
        if mux {
            nmux |= 1;
        } else {
            nmux &= !1;
        }
        self.send_session_id(nmux)?;

        let ivv = self.read_session_id()?;
        if ivv == 0 {
            return Err(Error::HandshakeFailed("client ivv is zero"));
        }
        self.rekey(ivv);
        self.tx.on_handshake_complete();
        self.rx.on_handshake_complete();
        self.session_id = session_id;
        Ok(())
    }

    /// Sends the NOP noise prelude.
    fn handshake_prelude(&mut self) -> Result<()> {
        let rounds = nop_rounds(&mut self.tx.rng, &self.tx.key);
        for _ in 0..rounds {
            self.send_session_id(0)?;
        }
        Ok(())
    }

    /// Sends one (possibly dummy) session-id packet through the full
    /// encrypt+frame pipeline.
    fn send_session_id(&mut self, id: SessionId) -> Result<()> {
        let packet = pack_session_id(&mut self.tx.rng, &self.tx.key, id);
        self.write(&packet)
    }

    /// Reads real session-id packets, skipping dummy noise. The skip budget
    /// is bounded by [`max_nop_packets`] so a hostile peer cannot pin the
    /// connection in the handshake phase with an endless dummy stream.
    fn read_session_id(&mut self) -> Result<SessionId> {
        let mut budget = max_nop_packets(&self.tx.key);
        loop {
            let packet = self.read()?;
            if let SessionPacket::Session(id) = unpack_session_id(&self.rx.key, &packet)? {
                return Ok(id);
            }
            budget = budget
                .checked_sub(1)
                .ok_or(Error::HandshakeFailed("too many dummy packets"))?;
        }
    }
}

/// Sending half of a [`Transmission`] produced by
/// [`Transmission::split_with`]. Owns the write side of the transport and
/// the tx-direction codec state, so it can be moved to a dedicated writer
/// thread while [`TransmissionRx`] keeps reading.
pub struct TransmissionTx<T, R = StdRng> {
    io: T,
    core: TxCore<R>,
}

impl<T, R: Rng> TransmissionTx<T, R> {
    /// Whether the owning transmission completed its handshake.
    #[must_use]
    pub fn is_handshaked(&self) -> bool {
        self.core.handshaked
    }

    /// Access to the underlying transport (write side).
    #[must_use]
    pub fn io(&self) -> &T {
        &self.io
    }

    /// Mutable access to the underlying transport.
    pub fn io_mut(&mut self) -> &mut T {
        &mut self.io
    }

    /// Encrypts `plaintext` into a complete wire packet appended to `out`
    /// (in-memory path; see [`Transmission::encrypt_into`]).
    #[cfg_attr(feature = "hotpath", hotpath::measure(impl_type = "TransmissionTx"))]
    pub fn encrypt_into(&mut self, out: &mut Vec<u8>, plaintext: &[u8]) -> Result<()> {
        self.core.encrypt_into(out, plaintext)
    }
}

impl<T: Write, R: Rng> TransmissionTx<T, R> {
    /// Writes one encrypted message to the transport (streaming).
    #[cfg_attr(feature = "hotpath", hotpath::measure(impl_type = "TransmissionTx"))]
    pub fn write(&mut self, plaintext: &[u8]) -> Result<()> {
        self.core.write(&mut self.io, plaintext)
    }

    /// Tagged streaming write: the message is `tag || payload`, encrypted
    /// without assembling an intermediate contiguous buffer (one full
    /// payload copy saved per frame vs `write(&[tag, ..payload])`).
    #[cfg_attr(feature = "hotpath", hotpath::measure(impl_type = "TransmissionTx"))]
    pub fn write_tagged(&mut self, tag: u8, payload: &[u8]) -> Result<()> {
        let mut out = mem::take(&mut self.core.scratch_out);
        out.clear();
        // Restore the scratch even on failure: dropping it here would cost
        // the allocation on every subsequent packet.
        let result = self
            .core
            .encrypt_into_tagged(&mut out, tag, payload)
            .and_then(|()| self.io.write_all(&out).map_err(Error::Io));
        self.core.scratch_out = out;
        result
    }
}

/// Receiving half of a [`Transmission`] produced by
/// [`Transmission::split_with`]. Owns the read side of the transport and the
/// rx-direction codec state.
pub struct TransmissionRx<T> {
    io: T,
    core: RxCore,
}

impl<T> TransmissionRx<T> {
    /// Whether the owning transmission completed its handshake.
    #[must_use]
    pub fn is_handshaked(&self) -> bool {
        self.core.handshaked
    }

    /// Access to the underlying transport (read side).
    #[must_use]
    pub fn io(&self) -> &T {
        &self.io
    }

    /// Mutable access to the underlying transport.
    pub fn io_mut(&mut self) -> &mut T {
        &mut self.io
    }
}

impl<T: Read> TransmissionRx<T> {
    /// Reads and decrypts one message, blocking until a full frame arrives
    /// (see [`Transmission::read`]).
    #[cfg_attr(feature = "hotpath", hotpath::measure(impl_type = "TransmissionRx"))]
    pub fn read(&mut self) -> Result<Vec<u8>> {
        self.read_buf().map(Vec::from)
    }

    /// [`Self::read`] without copying: the message borrows an internal
    /// scratch buffer that is overwritten by the next call.
    #[cfg_attr(feature = "hotpath", hotpath::measure(impl_type = "TransmissionRx"))]
    pub fn read_buf(&mut self) -> Result<&[u8]> {
        self.core.read_buf(&mut self.io)
    }

    /// In-memory decrypt for datagram-style callers (see
    /// [`Transmission::decrypt_in_place`]): zero allocation, no header
    /// strip; the message borrows `packet` or the internal base94 scratch.
    pub fn decrypt_in_place<'a>(&'a mut self, packet: &'a mut [u8]) -> Result<&'a [u8]> {
        self.core.decrypt_in_place(packet)
    }
}

/// Split support: requires a duplex transport (read + write per half).
impl<T: Read + Write, R: Rng> Transmission<T, R> {
    /// Splits the transmission into independent sending/receiving halves for
    /// the classic two-thread bidirectional pump model:
    ///
    /// * `TransmissionTx` keeps `self.io` as its **write** side;
    /// * `TransmissionRx` uses `rx_io` as its **read** side — the caller must pass a handle
    ///   aliasing the *same* connection (e.g. `TcpStream::try_clone`), which must happen **before**
    ///   the split while the original stream is still owned by the caller.
    ///
    /// Per-direction cipher nonces and base94 first-frame states live in the
    /// respective direction's codec core, so the halves stay wire-compatible
    /// with an unsplit peer.
    pub fn split_with(self, rx_io: T) -> (TransmissionTx<T, R>, TransmissionRx<T>) {
        let Self {
            io,
            tx,
            rx,
            session_id: _,
        } = self;
        (TransmissionTx { io, core: tx }, TransmissionRx {
            io: rx_io,
            core: rx,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    pub(super) fn test_rng() -> StdRng {
        StdRng::try_from_rng(&mut rand::rngs::SysRng).expect("failed to seed StdRng")
    }

    // Pre-handshake traffic always uses base94 and sizes the scratch
    // buffers; binary mode must release them at handshake completion while
    // plaintext mode keeps them (they stay on the hot path there).
    #[test]
    fn scratch_released_in_binary_mode_kept_in_plaintext_mode() {
        for (plaintext, expect_kept) in [(false, false), (true, true)] {
            let key = ObfuscationKey {
                plaintext,
                ..ObfuscationKey::default()
            };
            // TxCore::write / RxCore::read_buf take the transport as a
            // parameter, so the transmission itself carries a unit sink.
            let mut wire = Vec::new();
            let mut tx = Transmission::with_rng((), key.clone(), test_rng());
            tx.tx.write(&mut wire, b"handshake-ish payload").unwrap();
            assert!(tx.tx.scratch_bin.capacity() > 0);

            let mut rx = Transmission::with_rng((), key, test_rng());
            rx.rx.read_buf(&mut Cursor::new(&wire)).unwrap();
            assert!(rx.rx.scratch_read.capacity() > 0);

            tx.tx.on_handshake_complete();
            rx.rx.on_handshake_complete();
            let kept_bin = tx.tx.scratch_bin.capacity() > 0;
            let kept_read = rx.rx.scratch_read.capacity() > 0;
            assert_eq!(kept_bin, expect_kept);
            assert_eq!(kept_read, expect_kept);
        }
    }

    // write_tagged frames `tag || payload`; the rx side must see exactly
    // that, both pre-handshake (base94 envelope) and in binary mode the
    // callers always handshake first, so this covers the pre-handshake leg
    // plus the encrypt_into_tagged assembly itself.
    #[test]
    fn tagged_write_roundtrip_pre_handshake() {
        let key = ObfuscationKey::default();
        let mut wire = Vec::new();
        let mut tx = Transmission::with_rng((), key.clone(), test_rng());
        tx.tx
            .encrypt_into_tagged(&mut wire, 0xd1, b"hello tagged")
            .unwrap();

        let mut rx = Transmission::with_rng((), key, test_rng());
        let msg = rx.rx.read_buf(&mut Cursor::new(&wire)).unwrap();
        assert_eq!(msg, [
            0xd1, b'h', b'e', b'l', b'l', b'o', b' ', b't', b'a', b'g', b'g', b'e', b'd'
        ]);
    }
}

#[cfg(test)]
mod decrypt_in_place_tests {
    use super::{tests::test_rng, *};

    // decrypt_in_place must agree with the allocating decrypt on both
    // framings, and the message must start past the 3-byte header without
    // any strip memmove.
    #[test]
    fn in_place_matches_allocating_decrypt() {
        for plaintext in [false, true] {
            let key = ObfuscationKey {
                plaintext,
                ..ObfuscationKey::default()
            };
            let mut wire = Vec::new();
            let mut tx = Transmission::with_rng((), key.clone(), test_rng());
            tx.tx.write(&mut wire, b"datagram body").unwrap();

            let mut rx_a = Transmission::with_rng((), key.clone(), test_rng());
            let alloc = rx_a.rx.decrypt(&wire).unwrap();

            let mut rx_b = Transmission::with_rng((), key, test_rng());
            let mut owned = wire.clone();
            let in_place = rx_b.rx.decrypt_in_place(&mut owned).unwrap();
            assert_eq!(alloc, in_place);
            assert_eq!(in_place, b"datagram body");
        }
    }
}
