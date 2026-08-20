//! jsonc configuration loading for the server and client binaries.
//!
//! All fields have safe defaults mirroring openppp2's `AppConfiguration`,
//! except the deployment secrets (`protocol_key`/`transport_key`), which
//! every real deployment must change.

use std::{fs, path::Path};

use nextppp_core::{Method, ObfuscationKey};
use serde::Deserialize;
use spdlog::prelude::*;
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
    /// Protocol cipher password. Falls back to the shared `password`,
    /// then the built-in placeholder.
    pub protocol_key: Option<String>,
    /// Transport cipher name (payload).
    pub transport: String,
    /// Transport cipher password. Falls back to the shared `password`,
    /// then the built-in placeholder.
    pub transport_key: Option<String>,
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
            protocol_key: None,
            transport: k.transport.name().to_owned(),
            transport_key: None,
            masked: k.masked,
            plaintext: k.plaintext,
            delta_encode: k.delta_encode,
            shuffle_data: k.shuffle_data,
        }
    }
}

/// Built-in placeholder password; every real deployment must override it.
const PLACEHOLDER_PASSWORD: &str = "nextppp";

impl ObfuscationConfig {
    fn method(name: &str) -> Result<Method, String> {
        Method::from_name(name).ok_or_else(|| {
            format!(
                "unknown cipher method {name:?} (supported: aes-128-cfb, aes-256-cfb, \
                 aes-128-ctr, aes-256-ctr, chacha20-ietf)"
            )
        })
    }

    fn resolve_password(
        key: Option<&str>,
        shared: Option<&str>,
        field: &str,
    ) -> Result<String, String> {
        match key.or(shared) {
            Some(p) if !p.is_empty() => Ok(p.to_owned()),
            // An explicitly set but empty string is almost certainly a mistake.
            Some(_) => Err(format!("empty password for {field}")),
            None => Ok(String::from(PLACEHOLDER_PASSWORD)),
        }
    }

    /// Validates and converts into the core [`ObfuscationKey`].
    /// `shared_password` (the top-level `password` field) backs any cipher
    /// key left unset; sharing one password across layers is safe because
    /// the core KDF domain-separates cipher roles.
    ///
    /// # Errors
    ///
    /// Unknown cipher method name, empty password or out-of-range NOP
    /// exponents.
    pub fn to_key(&self, shared_password: Option<&str>) -> Result<ObfuscationKey, String> {
        let key = ObfuscationKey {
            kf: self.kf,
            kl: self.kl,
            kh: self.kh,
            kx: self.kx,
            protocol_key: Self::resolve_password(
                self.protocol_key.as_deref(),
                shared_password,
                "protocol_key",
            )?,
            protocol: Self::method(&self.protocol)?,
            transport_key: Self::resolve_password(
                self.transport_key.as_deref(),
                shared_password,
                "transport_key",
            )?,
            transport: Self::method(&self.transport)?,
            masked: self.masked,
            plaintext: self.plaintext,
            delta_encode: self.delta_encode,
            shuffle_data: self.shuffle_data,
        };
        // Centralized in the core so hand-constructed keys get the same
        // guarantees as config-loaded ones.
        key.validate().map_err(|e| e.to_string())?;
        Ok(key)
    }

    /// Emits a startup warning when the deployment still runs on the
    /// built-in placeholder password (trivially bypassable by anyone).
    pub fn warn_placeholder(key: &ObfuscationKey) {
        if key.protocol_key == PLACEHOLDER_PASSWORD && key.transport_key == PLACEHOLDER_PASSWORD {
            warn!(
                "obfuscation passwords are left at the built-in placeholder; set `password` (or \
                 `protocol_key`/`transport_key`) per deployment"
            );
        }
    }
}

/// Server configuration (`nextppp-server.jsonc`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Listen address, e.g. `"0.0.0.0:6666"`.
    pub listen: String,
    /// Shared tunnel password; backs any obfuscation cipher key left unset.
    /// Prefer this over writing `protocol_key`/`transport_key` twice —
    /// sharing is safe (the core KDF separates the two cipher roles).
    #[serde(default)]
    pub password: Option<String>,
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

/// Client configuration (`nextppp-client.jsonc`).
///
/// Intentionally minimal: the client is a plain SOCKS5-to-tunnel forwarder;
/// all routing (direct/block/geosite/...) belongs to the front-end proxy
/// (e.g. sing-box) that points its socks outbound at `listen`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// Local SOCKS5 inbound listen address.
    pub listen: String,
    /// Shared tunnel password; backs any obfuscation cipher key left unset.
    /// Must match the server.
    #[serde(default)]
    pub password: Option<String>,
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
    /// Obfuscation parameters, must match the server.
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
            .to_key(cfg.password.as_deref())
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
            .to_key(cfg.password.as_deref())
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
            ObfuscationConfig::default().to_key(None).unwrap(),
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
        assert_eq!(cfg.protocol_key.as_deref(), Some("sekrit"));
        assert_eq!(cfg.kf, ObfuscationKey::default().kf);
        let key = cfg.to_key(None).unwrap();
        assert_eq!(key.protocol_key, "sekrit");
        // Unset transport key falls back to the placeholder.
        assert_eq!(key.transport_key, "nextppp");
        assert_eq!(key.transport, Method::Aes256Cfb);
    }

    #[test]
    fn shared_password_backs_unset_keys() {
        let cfg: ObfuscationConfig = json5::from_str("{}").unwrap();
        let key = cfg.to_key(Some("shared")).unwrap();
        assert_eq!(key.protocol_key, "shared");
        assert_eq!(key.transport_key, "shared");
        // Explicit per-layer keys win over the shared password.
        let cfg: ObfuscationConfig =
            json5::from_str(r#"{ "protocol_key": "one", "transport_key": "two" }"#).unwrap();
        let key = cfg.to_key(Some("shared")).unwrap();
        assert_eq!(key.protocol_key, "one");
        assert_eq!(key.transport_key, "two");
    }

    #[test]
    fn empty_password_rejected() {
        let cfg: ObfuscationConfig = json5::from_str(r#"{ "protocol_key": "" }"#).unwrap();
        let err = cfg.to_key(Some("shared")).unwrap_err();
        assert!(err.contains("empty password"));
    }

    #[test]
    fn unknown_method_rejected() {
        let cfg = ObfuscationConfig {
            transport: String::from("rc4-md5"),
            ..ObfuscationConfig::default()
        };
        assert!(cfg.to_key(None).unwrap_err().contains("unknown cipher"));
    }

    #[test]
    fn nop_exponent_overflow_rejected() {
        // kl feeds `1 << kl` in the core handshake; >= 32 would overflow.
        let cfg = ObfuscationConfig {
            kl: 32,
            ..ObfuscationConfig::default()
        };
        assert!(cfg.to_key(None).unwrap_err().contains("kl/kh"));
        let cfg = ObfuscationConfig {
            kh: 21,
            ..ObfuscationConfig::default()
        };
        assert!(cfg.to_key(None).unwrap_err().contains("kl/kh"));
    }

    #[test]
    fn client_config_parses_with_comments_and_defaults() {
        let text = r#"{
            // local socks5 inbound
            "listen": "127.0.0.1:1080",
            "password": "sekrit",
            "server": { "address": "example.com:6666" },
        }"#;
        let cfg: ClientConfig = json5::from_str(text).unwrap();
        assert_eq!(cfg.listen, "127.0.0.1:1080");
        assert_eq!(cfg.server.address, "example.com:6666");
        assert_eq!(cfg.server.connect_timeout, 10);
        assert_eq!(cfg.password.as_deref(), Some("sekrit"));
        let key = cfg
            .server
            .obfuscation
            .to_key(cfg.password.as_deref())
            .unwrap();
        assert_eq!(key.protocol_key, "sekrit");
        assert_eq!(key.transport_key, "sekrit");
    }

    #[test]
    fn unknown_fields_rejected() {
        let text = r#"{ "listen": "x", "server": {"address": "y"}, "rulesss": [] }"#;
        let res: Result<ClientConfig, _> = json5::from_str(text);
        assert!(res.is_err());
    }
}
