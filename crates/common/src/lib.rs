//! Shared building blocks for the nextppp proxy server and client:
//! configuration loading (jsonc), the application layer tunneled above the
//! nextppp transmission, and bidirectional pump helpers for the synchronous
//! two-thread connection model.
//!
//! Routing/splitting is deliberately out of scope: the client is a plain
//! SOCKS5-to-tunnel forwarder meant to be chained behind sing-box & co.

pub mod addr;
pub mod config;
pub mod fmt;
pub mod proto;
pub mod pump;
pub mod shutdown;

pub use addr::{Host, ProxyAddr};
pub use config::{ClientConfig, ConfigError, ObfuscationConfig, ServerConfig};
pub use fmt::{fmt_bytes, fmt_duration};
pub use proto::{FRAME_DATA, FRAME_EOF, STATUS_OK, STATUS_REFUSED};
pub use pump::{PumpEnd, PumpStats};
