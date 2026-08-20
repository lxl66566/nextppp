//! nextppp proxy client: a plain SOCKS5 inbound that forwards every
//! CONNECT through the nextppp tunnel. No local routing — chain it
//! behind a front-end proxy (e.g. sing-box) via its socks outbound.
//!
//! Logging contract: `info` for proxied connection open/close (with byte
//! counts and duration), `warn` for tunnel setup failures and protocol
//! faults, `debug` for negotiation detail.

use std::{net::TcpListener, sync::Arc, thread, time::Duration};

use anyhow::Context;
use nextppp_common::{addr::Host, config::ClientConfig};
use nextppp_core::ObfuscationKey;
use spdlog::prelude::*;
pub mod outbound;
pub mod socks5;

/// Immutable runtime parameters derived from the configuration.
#[derive(Clone)]
pub struct ClientRuntime {
    /// Remote nextppp server endpoint, parsed once at startup (per-CONNECT
    /// re-parsing cost a lowercase alloc and a split every time).
    pub server_host: Host,
    pub server_port: u16,
    /// Obfuscation parameters shared with the server, shared across tunnels.
    pub server_key: Arc<ObfuscationKey>,
    /// Connect + handshake timeout toward the server.
    pub connect_timeout: Duration,
}

impl ClientRuntime {
    /// Validates the configuration into runtime parameters.
    ///
    /// # Errors
    ///
    /// Cipher method or server address failure.
    pub fn from_config(cfg: &ClientConfig) -> anyhow::Result<Self> {
        let key = cfg
            .server
            .obfuscation
            .to_key(cfg.password.as_deref())
            .map_err(anyhow::Error::msg)
            .context("obfuscation config")?;
        nextppp_common::ObfuscationConfig::warn_placeholder(&key);
        let (server_host, server_port) = parse_host_port(&cfg.server.address)
            .with_context(|| format!("invalid server address {:?}", cfg.server.address))?;
        Ok(Self {
            server_host,
            server_port,
            server_key: Arc::new(key),
            connect_timeout: Duration::from_secs(cfg.server.connect_timeout),
        })
    }
}

/// Splits `host:port`, accepting domain names, `[v6]:port` and literal IPs.
///
/// # Errors
///
/// Missing port / non-numeric port / malformed or unbracketed IPv6.
pub fn parse_host_port(s: &str) -> anyhow::Result<(Host, u16)> {
    if let Ok(sa) = s.parse::<std::net::SocketAddr>() {
        return Ok((Host::Ip(sa.ip()), sa.port()));
    }
    let (host, port) = s
        .rsplit_once(':')
        .with_context(|| format!("missing port in {s:?}"))?;
    let port: u16 = port.parse().with_context(|| format!("bad port {port:?}"))?;
    let host = if let Some(inner) = host.strip_prefix('[') {
        inner
            .strip_suffix(']')
            .with_context(|| format!("unmatched '[' in {s:?}"))?
    } else {
        // An unbracketed remainder that still contains ':' is a bare IPv6
        // address; parsing it as a domain would only fail later at DNS time
        // with an opaque error.
        if host.contains(':') {
            anyhow::bail!("bare IPv6 address {s:?} must use the [addr]:port form");
        }
        host
    };
    if host.is_empty() {
        anyhow::bail!("empty host in {s:?}");
    }
    let h = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => Host::Ip(ip),
        Err(_) => Host::Domain(host.to_ascii_lowercase()),
    };
    Ok((h, port))
}

/// Accept loop; blocks the calling thread forever.
///
/// # Errors
///
/// Fatal listener failure.
// `serve` owns the listener: it lives exactly as long as the accept loop.
#[allow(clippy::needless_pass_by_value)]
pub fn serve(listener: TcpListener, rt: Arc<ClientRuntime>) -> anyhow::Result<()> {
    info!(
        "nextppp client socks5 inbound on {}",
        listener.local_addr()?.to_string()
    );
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let rt = rt.clone();
                let spawned = thread::Builder::new()
                    .name("nextppp-inbound".to_owned())
                    .spawn(move || socks5::handle(stream, &rt));
                if let Err(e) = spawned {
                    error!("inbound spawn failed: {e}");
                }
            },
            Err(e) => warn!("accept failed: {e}"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_host_port_forms() {
        let (Host::Ip(ip), 80) = parse_host_port("1.2.3.4:80").unwrap() else {
            panic!("v4 literal")
        };
        assert_eq!(ip.to_string(), "1.2.3.4");
        let (Host::Ip(ip), 443) = parse_host_port("[2001:db8::1]:443").unwrap() else {
            panic!("bracketed v6")
        };
        assert_eq!(ip.to_string(), "2001:db8::1");
        let (Host::Domain(d), 8080) = parse_host_port("Example.COM:8080").unwrap() else {
            panic!("domain")
        };
        assert_eq!(d, "example.com");
    }

    #[test]
    fn parse_host_port_rejects_bad_forms() {
        // Bare IPv6 used to parse as the garbage domain "2001:db8:" + port 1.
        assert!(parse_host_port("2001:db8::1").is_err());
        assert!(parse_host_port("2001:db8::1:8080").is_err());
        assert!(parse_host_port("[2001:db8::1").is_err());
        assert!(parse_host_port("example.com").is_err());
        assert!(parse_host_port("example.com:http").is_err());
        assert!(parse_host_port(":80").is_err());
    }
}
