//! Shared building blocks for the openppp3 proxy server and client:
//! configuration loading (jsonc), the routing rule engine, the application
//! layer tunneled above the openppp3 transmission, and bidirectional pump
//! helpers for the synchronous two-thread connection model.

pub mod addr;
pub mod config;
pub mod proto;
pub mod pump;
pub mod rule;

pub use addr::{Host, ProxyAddr};
pub use config::{ClientConfig, ConfigError, ObfuscationConfig, ServerConfig, SystemProxyConfig};
pub use proto::{FRAME_DATA, FRAME_EOF, STATUS_OK, STATUS_REFUSED};
pub use rule::{Policy, RuleSet};
