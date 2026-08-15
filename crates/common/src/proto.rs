//! Application layer tunneled above the openppp3 transmission.
//!
//! Once the openppp3 handshake completes, the connection carries a tiny
//! proxy protocol:
//!
//! ```text
//! client -> server : [ATYP][addr][port BE16]     connect request
//! server -> client : [STATUS]                    1-byte connect result
//! both          : [FRAME_DATA][payload...]       data frame (payload non-empty)
//! both          : [FRAME_EOF]                    half-close (forward TCP FIN)
//! ```
//!
//! `FRAME_EOF` propagates half-closes across the tunnel: without it a local
//! `shutdown(write)` could never reach the far end, since the openppp3
//! framing has no in-band EOF.

/// Data frame marker: the rest of the message is payload.
pub const FRAME_DATA: u8 = 0x00;
/// Half-close frame marker: forward a TCP write-side shutdown.
pub const FRAME_EOF: u8 = 0x01;

/// Connect response: target connected, tunnel established.
pub const STATUS_OK: u8 = 0x00;
/// Connect response: the server could not connect to the target.
pub const STATUS_REFUSED: u8 = 0x01;
