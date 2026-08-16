//! Shared building blocks for the openppp3 proxy server and client:
//! configuration loading (jsonc), the application layer tunneled above the
//! openppp3 transmission, and bidirectional pump helpers for the synchronous
//! two-thread connection model.
//!
//! Routing/splitting is deliberately out of scope: the client is a plain
//! SOCKS5-to-tunnel forwarder meant to be chained behind sing-box & co.

pub mod addr;
pub mod config;
pub mod proto;
pub mod pump;

pub use addr::{Host, ProxyAddr};
pub use config::{ClientConfig, ConfigError, ObfuscationConfig, ServerConfig};
pub use proto::{FRAME_DATA, FRAME_EOF, STATUS_OK, STATUS_REFUSED};
