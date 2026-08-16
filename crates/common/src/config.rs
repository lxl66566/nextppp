//! jsonc configuration loading for the server and client binaries.
//!
//! All fields have safe defaults mirroring openppp2's `AppConfiguration`,
//! except the deployment secrets (`protocol_key`/`transport_key`), which
//! every real deployment must change.

use std::{fs, path::Path};

use openppp3_core::{Method, ObfuscationKey};
use serde::Deserialize;
use thiserror::Error;

/// Errors while loading or validating a configuration file.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Filesystem failure.
    #[error("read {path}: {source}")]
    Io {
        /// The offending path.
        path: String,
        /// Underlying error.
        source: std::io::Error,
    },
    /// jsonc syntax or serde failure.
    #[error("parse {path}: {source}")]
    Parse {
        /// The offending path.
        path: String,
        /// Underlying json5 error.
        source: json5::Error,
    },
    /// Semantic validation failure.
    #[error("validate {path}: {message}")]
    Validate {
        /// The offending path.
        path: String,
        /// Validation message.
        message: String,
    },
}

fn validate(path: &str, message: String) -> ConfigError {
    ConfigError::Validate {
        path: path.to_owned(),
        message,
    }
}

/// Obfuscation/cipher parameters, the wire-compatible subset of
/// [`ObfuscationKey`]. Method names use openppp2 spelling
/// (`aes-128-cfb`, `aes-256-cfb`, `aes-128-ctr`, `aes-256-ctr`,
/// `chacha20-ietf`).
// Mirrors ObfuscationKey's four data-plane switches (see core).
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ObfuscationConfig {
    /// Global obfuscation key.
    pub kf: u32,
    /// NOP prelude lower exponent.
    pub kl: u8,
    /// NOP prelude upper exponent.
    pub kh: u8,
    /// Handshake packet padding amount.
    pub kx: u32,
    /// Protocol cipher name (frame header).
    pub protocol: String,
    /// Protocol cipher password.
    pub protocol_key: String,
    /// Transport cipher name (payload).
    pub transport: String,
    /// Transport cipher password.
    pub transport_key: String,
    /// Payload masked-XOR switch.
    pub masked: bool,
    /// Keep the printable base94 shell after the handshake.
    pub plaintext: bool,
    /// Payload delta-encoding switch.
    pub delta_encode: bool,
    /// Payload shuffle switch.
    pub shuffle_data: bool,
}

impl Default for ObfuscationConfig {
    fn default() -> Self {
        let k = ObfuscationKey::default();
        Self {
            kf: k.kf,
            kl: k.kl,
            kh: k.kh,
            kx: k.kx,
            protocol: k.protocol.name().to_owned(),
            protocol_key: k.protocol_key,
            transport: k.transport.name().to_owned(),
            transport_key: k.transport_key,
            masked: k.masked,
            plaintext: k.plaintext,
            delta_encode: k.delta_encode,
            shuffle_data: k.shuffle_data,
        }
    }
}

impl ObfuscationConfig {
    fn method(name: &str) -> Result<Method, String> {
        Method::from_name(name).ok_or_else(|| {
            format!(
                "unknown cipher method {name:?} (supported: aes-128-cfb, aes-256-cfb, \
                 aes-128-ctr, aes-256-ctr, chacha20-ietf)"
            )
        })
    }

    /// Validates and converts into the core [`ObfuscationKey`].
    ///
    /// # Errors
    ///
    /// Unknown cipher method name.
    pub fn to_key(&self) -> Result<ObfuscationKey, String> {
        Ok(ObfuscationKey {
            kf: self.kf,
            kl: self.kl,
            kh: self.kh,
            kx: self.kx,
            protocol: Self::method(&self.protocol)?,
            protocol_key: self.protocol_key.clone(),
            transport: Self::method(&self.transport)?,
            transport_key: self.transport_key.clone(),
            masked: self.masked,
            plaintext: self.plaintext,
            delta_encode: self.delta_encode,
            shuffle_data: self.shuffle_data,
        })
    }
}

/// Server configuration (`openppp3-server.jsonc`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Listen address, e.g. `"0.0.0.0:6666"`.
    pub listen: String,
    /// Outbound (server -> target) connect timeout in seconds.
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout: u64,
    /// Handshake timeout in seconds (anti slow-loris).
    #[serde(default = "default_handshake_timeout")]
    pub handshake_timeout: u64,
    /// Obfuscation parameters, shared with clients.
    #[serde(default)]
    pub obfuscation: ObfuscationConfig,
}

/// Client configuration (`openppp3-client.jsonc`).
///
/// Intentionally minimal: the client is a plain SOCKS5-to-tunnel forwarder;
/// all routing (direct/block/geosite/...) belongs to the front-end proxy
/// (e.g. sing-box) that points its socks outbound at `listen`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// Local SOCKS5 inbound listen address.
    pub listen: String,
    /// Remote server section.
    pub server: ServerSection,
}

/// Remote server section of the client configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    /// Server address (`host:port`).
    pub address: String,
    /// Connect + handshake timeout in seconds.
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout: u64,
    /// Obfuscation parameters, must match the server (except secrets).
    #[serde(default)]
    pub obfuscation: ObfuscationConfig,
}

fn default_connect_timeout() -> u64 {
    10
}

fn default_handshake_timeout() -> u64 {
    15
}

/// Loads and validates a jsonc configuration file.
///
/// # Errors
///
/// See [`ConfigError`].
pub fn load_jsonc<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, ConfigError> {
    let path_str = path.display().to_string();
    let text = fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path_str.clone(),
        source,
    })?;
    let cfg: T = json5::from_str(&text).map_err(|source| ConfigError::Parse {
        path: path_str.clone(),
        source,
    })?;
    Ok(cfg)
}

impl ClientConfig {
    /// Loads, parses and validates a client configuration file.
    ///
    /// # Errors
    ///
    /// See [`ConfigError`].
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let path_str = path.display().to_string();
        let cfg: Self = load_jsonc(path)?;
        cfg.server
            .obfuscation
            .to_key()
            .map_err(|e| validate(&path_str, e))?;
        Ok(cfg)
    }
}

impl ServerConfig {
    /// Loads, parses and validates a server configuration file.
    ///
    /// # Errors
    ///
    /// See [`ConfigError`].
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let path_str = path.display().to_string();
        let cfg: Self = load_jsonc(path)?;
        cfg.obfuscation
            .to_key()
            .map_err(|e| validate(&path_str, e))?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obfuscation_defaults_match_core() {
        assert_eq!(
            ObfuscationConfig::default().to_key().unwrap(),
            ObfuscationKey::default()
        );
    }

    #[test]
    fn obfuscation_partial_override() {
        let text = r#"{
            // only secrets change for a real deployment
            "protocol_key": "sekrit",
        }"#;
        let cfg: ObfuscationConfig = json5::from_str(text).unwrap();
        assert_eq!(cfg.protocol_key, "sekrit");
        assert_eq!(cfg.kf, ObfuscationKey::default().kf);
        let key = cfg.to_key().unwrap();
        assert_eq!(key.protocol_key, "sekrit");
        assert_eq!(key.transport, Method::Aes256Cfb);
    }

    #[test]
    fn unknown_method_rejected() {
        let cfg = ObfuscationConfig {
            transport: String::from("rc4-md5"),
            ..ObfuscationConfig::default()
        };
        assert!(cfg.to_key().unwrap_err().contains("unknown cipher"));
    }

    #[test]
    fn client_config_parses_with_comments_and_defaults() {
        let text = r#"{
            // local socks5 inbound
            "listen": "127.0.0.1:1080",
            "server": { "address": "example.com:6666" },
        }"#;
        let cfg: ClientConfig = json5::from_str(text).unwrap();
        assert_eq!(cfg.listen, "127.0.0.1:1080");
        assert_eq!(cfg.server.address, "example.com:6666");
        assert_eq!(cfg.server.connect_timeout, 10);
    }

    #[test]
    fn unknown_fields_rejected() {
        let text = r#"{ "listen": "x", "server": {"address": "y"}, "rulesss": [] }"#;
        let res: Result<ClientConfig, _> = json5::from_str(text);
        assert!(res.is_err());
    }
}
