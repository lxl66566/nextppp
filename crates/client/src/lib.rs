//! openppp3 proxy client: a mixed-protocol (SOCKS5 + HTTP CONNECT) local
//! inbound that routes each request through the configured rule list to
//! `direct`, `proxy` (openppp3 tunnel) or `block`.

use std::{
    net::{TcpListener, TcpStream},
    sync::Arc,
    thread,
    time::Duration,
};

use anyhow::Context;
use openppp3_common::{addr::Host, config::ClientConfig, pump, rule::RuleSet};
use openppp3_core::ObfuscationKey;
use tracing::{debug, info, warn};

pub mod http;
pub mod outbound;
pub mod socks5;
#[cfg(feature = "system-proxy")]
pub mod sysproxy;

/// Immutable runtime parameters derived from the configuration.
#[derive(Clone)]
pub struct ClientRuntime {
    /// Routing rules.
    pub rules: RuleSet,
    /// Remote openppp3 server address (`host:port`, kept unresolved).
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
    /// Rule syntax, cipher method or server address failure.
    pub fn from_config(cfg: &ClientConfig) -> anyhow::Result<Self> {
        let rules = RuleSet::parse(&cfg.rules, cfg.r#final)
            .map_err(anyhow::Error::msg)
            .context("rules")?;
        let key = cfg
            .server
            .obfuscation
            .to_key()
            .map_err(anyhow::Error::msg)
            .context("obfuscation config")?;
        parse_host_port(&cfg.server.address)
            .with_context(|| format!("invalid server address {:?}", cfg.server.address))?;
        Ok(Self {
            rules,
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
        "openppp3 client mixed inbound (socks5/http) on {}",
        listener.local_addr()?.to_string()
    );
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let rt = rt.clone();
                let spawned = thread::Builder::new()
                    .name("openppp3-inbound".to_owned())
                    .spawn(move || {
                        if let Err(e) = handle_inbound(stream, &rt) {
                            debug!("inbound ended: {e:#}");
                        }
                    });
                if let Err(e) = spawned {
                    warn!("spawn failed: {e}");
                }
            }
            Err(e) => warn!("accept failed: {e}"),
        }
    }
    Ok(())
}

/// Inbound handshake timeout: bounds the protocol-detection peek and the
/// socks5/http negotiation against slow clients; the handlers clear it
/// before the data-plane pump takes over.
const INBOUND_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Protocol-detects the inbound connection and hands it to the SOCKS5 or
/// HTTP inbound handler.
fn handle_inbound(stream: TcpStream, rt: &Arc<ClientRuntime>) -> anyhow::Result<()> {
    pump::nodelay(&stream);
    stream.set_read_timeout(Some(INBOUND_HANDSHAKE_TIMEOUT))?;
    stream.set_write_timeout(Some(INBOUND_HANDSHAKE_TIMEOUT))?;
    let mut peek = [0u8; 1];
    stream.peek(&mut peek).context("peek")?;
    if peek[0] == 0x05 {
        socks5::handle(stream, rt)
    } else {
        http::handle(stream, rt)
    }
}
