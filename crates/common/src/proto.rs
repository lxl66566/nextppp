//! Application layer tunneled above the nextppp transmission.
//!
//! Post-handshake the connection speaks the mux protocol (see
//! [`crate::mux`]): every message is `[kind][stream_id varint][payload]`.
//! This module keeps the connect-verdict statuses carried in `REPLY`
//! frames, shared by both protocol generations.

/// Connect response: target connected, tunnel established.
pub const STATUS_OK: u8 = 0x00;
/// Connect response: the server could not connect to the target.
pub const STATUS_REFUSED: u8 = 0x01;
