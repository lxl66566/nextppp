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
    /// Remote nextppp server address (`host:port`, kept unresolved).
    pub server_address: String,
    /// Obfuscation parameters shared with the server.
    pub server_key: ObfuscationKey,
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
        parse_host_port(&cfg.server.address)
            .with_context(|| format!("invalid server address {:?}", cfg.server.address))?;
        Ok(Self {
            server_address: cfg.server.address.clone(),
            server_key: key,
            connect_timeout: Duration::from_secs(cfg.server.connect_timeout),
        })
    }
}

/// Splits `host:port`, accepting domain names, `[v6]:port` and literal IPs.
///
/// # Errors
///
/// Missing port / non-numeric port.
pub fn parse_host_port(s: &str) -> anyhow::Result<(Host, u16)> {
    if let Ok(sa) = s.parse::<std::net::SocketAddr>() {
        return Ok((Host::Ip(sa.ip()), sa.port()));
    }
    let (host, port) = s
        .rsplit_once(':')
        .with_context(|| format!("missing port in {s:?}"))?;
    let port: u16 = port.parse().with_context(|| format!("bad port {port:?}"))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
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
