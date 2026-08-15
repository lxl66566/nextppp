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
//! In-memory entry points (`encrypt_into`/`decrypt`) do not touch the
//! transport, so they are usable for datagram/mux style callers and are
//! available for any `T`.

// `(nmux >> 64) as u64` and similar narrowing casts are structurally safe.
#![allow(clippy::cast_possible_truncation)]

use std::{
    io::{Read, Write},
    mem,
};

use rand::{Rng, SeedableRng, rngs::StdRng};

use crate::{
    PPP_BUFFER_SIZE, SessionId,
    config::ObfuscationKey,
    crypto::cipher::SessionCipher,
    error::{Error, Result},
    frame::{
        base94::Base94Framer,
        binary::{
            HEADER_SIZE, PayloadFlags, header_decrypt, header_encrypt, payload_deobfuscate,
            payload_obfuscate,
        },
    },
    handshake::{
        CANARY_MAGIC, CANARY_MAGIC_MASK, SessionPacket, flag_canary, nop_rounds, pack_session_id,
        unpack_session_id,
    },
};

/// A framed, encrypted, optionally base94-wrapped connection over any
/// duplex byte transport.
///
/// A `Transmission` is inherently single-threaded per direction; wrap it in
/// your favorite executor or split the I/O to add async support.
pub struct Transmission<T, R = StdRng> {
    io: T,
    rng: R,
    key: ObfuscationKey,
    b94: Base94Framer,
    protocol_tx: SessionCipher,
    protocol_rx: SessionCipher,
    transport_tx: SessionCipher,
    transport_rx: SessionCipher,
    handshaked: bool,
    session_id: SessionId,
    /// Scratch buffers reused across packets to avoid per-write allocation.
    scratch_a: Vec<u8>,
    scratch_b: Vec<u8>,
}

impl<T> Transmission<T, StdRng> {
    /// Creates a transmission with an OS-seeded CSPRNG.
    #[must_use]
    pub fn new(io: T, key: ObfuscationKey) -> Self {
        Self::with_rng(io, key, StdRng::from_os_rng())
    }
}

/// Transport-independent core: in-memory packet codec, state and rekeying.
impl<T, R: Rng> Transmission<T, R> {
    /// Creates a transmission with an explicit RNG (deterministic tests).
    #[must_use]
    pub fn with_rng(io: T, key: ObfuscationKey, rng: R) -> Self {
        let protocol_tx = SessionCipher::new(key.protocol, &key.protocol_key);
        let protocol_rx = SessionCipher::new(key.protocol, &key.protocol_key).for_decryption();
        let transport_tx = SessionCipher::new(key.transport, &key.transport_key);
        let transport_rx = SessionCipher::new(key.transport, &key.transport_key).for_decryption();
        let b94 = Base94Framer::new(key.kf);
        Self {
            io,
            rng,
            key,
            b94,
            protocol_tx,
            protocol_rx,
            transport_tx,
            transport_rx,
            handshaked: false,
            session_id: 0,
            scratch_a: Vec::new(),
            scratch_b: Vec::new(),
        }
    }

    /// Whether the handshake completed and data-plane framing is active.
    #[must_use]
    pub fn is_handshaked(&self) -> bool {
        self.handshaked
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
    pub fn encrypt_into(&mut self, out: &mut Vec<u8>, plaintext: &[u8]) -> Result<()> {
        if plaintext.is_empty() {
            return Err(Error::ZeroLength);
        }
        if plaintext.len() > PPP_BUFFER_SIZE {
            return Err(Error::FrameTooLarge {
                len: plaintext.len(),
            });
        }

        let flags = self.effective_flags();
        let (header, header_kf) = header_encrypt(
            &mut self.rng,
            self.key.kf,
            Some(&mut self.protocol_tx),
            plaintext.len(),
        )?;

        // Assemble the binary packet in scratch: header || transformed body.
        let bin = &mut self.scratch_b;
        bin.clear();
        bin.reserve(HEADER_SIZE + plaintext.len());
        bin.extend_from_slice(&header);
        bin.extend_from_slice(plaintext);
        let body = &mut bin[HEADER_SIZE..];
        self.transport_tx.apply(body);
        payload_obfuscate(body, &flags, header_kf, self.key.kf);

        if !self.handshaked || self.key.plaintext {
            self.b94.encode_frame(&mut self.rng, out, bin)
        } else {
            out.extend_from_slice(bin);
            Ok(())
        }
    }

    /// Decrypts one complete wire packet (in-memory inverse of
    /// [`Self::encrypt_into`]).
    pub fn decrypt(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        let binary = if !self.handshaked || self.key.plaintext {
            self.b94.decode_packet(packet)?
        } else {
            packet.to_vec()
        };
        self.decrypt_packet(&binary)
    }

    fn decrypt_packet(&mut self, binary: &[u8]) -> Result<Vec<u8>> {
        if binary.len() <= HEADER_SIZE {
            return Err(Error::InvalidFrame);
        }
        let header: [u8; HEADER_SIZE] = binary[..HEADER_SIZE].try_into().expect("length checked");
        let (len, header_kf) = header_decrypt(self.key.kf, Some(&mut self.protocol_rx), &header)?;
        if !(1..=PPP_BUFFER_SIZE).contains(&len) {
            return Err(Error::FrameTooLarge { len });
        }
        // Truncation/splicing guard: length must match the buffer exactly.
        if len + HEADER_SIZE != binary.len() {
            return Err(Error::InvalidFrame);
        }
        let mut body = binary[HEADER_SIZE..].to_vec();
        self.decrypt_body(header_kf, &mut body);
        Ok(body)
    }

    fn decrypt_body(&mut self, header_kf: u32, body: &mut [u8]) {
        let flags = self.effective_flags();
        payload_deobfuscate(body, &flags, header_kf, self.key.kf);
        self.transport_rx.apply(body);
    }

    /// Data-plane flags; pre-handshake everything is forced on ("safest").
    fn effective_flags(&self) -> PayloadFlags {
        if self.handshaked {
            PayloadFlags {
                masked: self.key.masked,
                shuffle: self.key.shuffle_data,
                delta: self.key.delta_encode,
            }
        } else {
            PayloadFlags::SAFEST
        }
    }

    /// Rebuilds all four cipher instances with per-connection key material.
    fn rekey(&mut self, ivv: u128) {
        self.protocol_tx =
            SessionCipher::derive(self.key.protocol, &self.key.protocol_key, Some(ivv));
        self.protocol_rx =
            SessionCipher::derive(self.key.protocol, &self.key.protocol_key, Some(ivv))
                .for_decryption();
        self.transport_tx =
            SessionCipher::derive(self.key.transport, &self.key.transport_key, Some(ivv));
        self.transport_rx =
            SessionCipher::derive(self.key.transport, &self.key.transport_key, Some(ivv))
                .for_decryption();
    }
}

/// Streaming data plane and handshake: requires a duplex byte transport.
impl<T: Read + Write, R: Rng> Transmission<T, R> {
    /// Writes one encrypted message.
    pub fn write(&mut self, plaintext: &[u8]) -> Result<()> {
        let mut out = mem::take(&mut self.scratch_a);
        out.clear();
        self.encrypt_into(&mut out, plaintext)?;
        let result = self.io.write_all(&out).map_err(Error::Io);
        self.scratch_a = out;
        result?;
        Ok(())
    }

    /// Reads and decrypts one message, blocking until a full frame arrives.
    pub fn read(&mut self) -> Result<Vec<u8>> {
        if !self.handshaked || self.key.plaintext {
            let binary = {
                let Self { b94, io, .. } = self;
                b94.read_frame(io)?
            };
            self.decrypt_packet(&binary)
        } else {
            let mut header = [0u8; HEADER_SIZE];
            self.io.read_exact(&mut header).map_err(Error::Io)?;
            let (len, header_kf) =
                header_decrypt(self.key.kf, Some(&mut self.protocol_rx), &header)?;
            if !(1..=PPP_BUFFER_SIZE).contains(&len) {
                return Err(Error::FrameTooLarge { len });
            }
            let mut body = vec![0u8; len];
            self.io.read_exact(&mut body).map_err(Error::Io)?;
            self.decrypt_body(header_kf, &mut body);
            Ok(body)
        }
    }

    // ------------------------------------------------------------------
    // Handshake
    // ------------------------------------------------------------------

    /// Runs the client-side handshake. Returns `(server_session_id, mux)`;
    /// `mux` reflects the server's multiplexing decision (parity of `nmux`).
    pub fn handshake_client(&mut self) -> Result<(SessionId, bool)> {
        self.handshake_prelude()?;

        let sid = self.read_session_id()?;
        if sid == 0 {
            return Err(Error::HandshakeFailed("server session id is zero"));
        }

        let ivv: u128 = self.rng.random();
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
            let local = flag_canary(&self.key);
            if nmux_high != local {
                return Err(Error::FlagsMismatch);
            }
        }

        self.rekey(ivv);
        self.handshaked = true;
        self.session_id = sid;
        Ok((sid, mux))
    }

    /// Runs the server-side handshake for an upper-layer assigned non-zero
    /// `session_id`. `mux` is the multiplexing request encoded into `nmux`'s
    /// parity for the client.
    pub fn handshake_server(&mut self, session_id: SessionId, mux: bool) -> Result<()> {
        if session_id == 0 {
            return Err(Error::InvalidSessionId);
        }
        self.handshake_prelude()?;

        self.send_session_id(session_id)?;

        let low: u64 = self.rng.random();
        let mut nmux = (u128::from(flag_canary(&self.key)) << 64) | u128::from(low);
        // Parity carries the mux decision; increments stay inside the low
        // word, so the canary high word is preserved.
        if mux {
            while nmux & 1 == 0 {
                nmux += 1;
            }
        } else {
            while nmux & 1 != 0 {
                nmux += 1;
            }
        }
        self.send_session_id(nmux)?;

        let ivv = self.read_session_id()?;
        if ivv == 0 {
            return Err(Error::HandshakeFailed("client ivv is zero"));
        }
        self.rekey(ivv);
        self.handshaked = true;
        self.session_id = session_id;
        Ok(())
    }

    /// Sends the NOP noise prelude.
    fn handshake_prelude(&mut self) -> Result<()> {
        let rounds = nop_rounds(&mut self.rng, &self.key);
        for _ in 0..rounds {
            self.send_session_id(0)?;
        }
        Ok(())
    }

    /// Sends one (possibly dummy) session-id packet through the full
    /// encrypt+frame pipeline.
    fn send_session_id(&mut self, id: SessionId) -> Result<()> {
        let packet = pack_session_id(&mut self.rng, &self.key, id);
        self.write(&packet)
    }

    /// Reads real session-id packets, skipping dummy noise.
    fn read_session_id(&mut self) -> Result<SessionId> {
        loop {
            let packet = self.read()?;
            if let SessionPacket::Session(id) = unpack_session_id(&self.key, &packet)? {
                return Ok(id);
            }
        }
    }
}
