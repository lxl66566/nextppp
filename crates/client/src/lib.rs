//! nextppp proxy client: a plain SOCKS5 inbound that forwards every
//! CONNECT through the nextppp tunnel. No local routing — chain it
//! behind a front-end proxy (e.g. sing-box) via its socks outbound.
//!
//! Connection model: event-driven on a fixed tokio worker pool. SOCKS
//! CONNECTs open mux streams on the shared tunnel pool (see [`pool`]);
//! one task per inbound connection, one reader + one writer task per
//! tunnel. With the optional `bond` inbound configured, a second SOCKS5
//! listener serves streams over link-aggregated tunnels (see [`bond`]):
//! the default listener stays the latency path, the bond listener is the
//! bandwidth path, and the front-end proxy routes traffic per rule.
//!
//! Logging contract: `info` for proxied connection open/close (with byte
//! counts and duration), `warn` for tunnel setup failures and protocol
//! faults, `debug` for negotiation detail.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::Context;
use nextppp_common::{
    addr::Host,
    config::ClientConfig,
    pump::{accept_exhausted, log_accept_exhausted},
    shutdown,
};
use nextppp_core::ObfuscationKey;
use spdlog::prelude::*;

pub mod bond;
pub mod pool;
pub mod socks5;

use pool::{Pool, PoolParams, TunnelDialer};

/// Heartbeat interval for the health/stats log line.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

/// How often the accept loop polls the shutdown flag.
const SHUTDOWN_POLL: Duration = Duration::from_millis(200);

/// Bonded-tunnel runtime parameters (bandwidth inbound).
#[derive(Debug, Clone)]
pub struct BondParams {
    /// Server bond-listener endpoint (parsed once at startup).
    pub host: Host,
    pub port: u16,
    /// Link sessions per bonded tunnel.
    pub links: u32,
    /// Bonded tunnels kept hot by the pool.
    pub pool_size: u32,
    /// Streams a bonded tunnel may carry before another is preferred.
    pub max_streams: u32,
    /// Endpoint string for dial-failure messages.
    pub target: String,
}

/// Immutable runtime parameters derived from the configuration.
pub struct ClientRuntime {
    /// Remote nextppp server endpoint, parsed once at startup (per-CONNECT
    /// re-parsing cost a lowercase alloc and a split every time).
    pub server_host: Host,
    pub server_port: u16,
    /// Obfuscation parameters shared with the server, shared across tunnels.
    pub server_key: Arc<ObfuscationKey>,
    /// Connect + handshake timeout toward the server.
    pub connect_timeout: Duration,
    /// Extra dial attempts after a routine transport failure.
    pub connect_retries: u32,
    /// Maximum concurrently active inbound connections (`None` = unlimited).
    pub max_connections: Option<u64>,
    /// Mux pool size (`0` = dedicated tunnel per CONNECT).
    pub pool_size: u32,
    /// Streams a pool tunnel may carry before another is preferred.
    pub max_streams: u32,
    /// Bonded-tunnel parameters; `None` disables the bond inbound.
    pub bond: Option<BondParams>,
    /// Server-address DNS cache: without it every pool dial re-resolves the
    /// server domain on its own resolver thread.
    pub dns: Arc<nextppp_common::dns::DnsCache>,
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
        let bond = match (&cfg.bond, &cfg.server.bond_address) {
            (Some(bond), Some(address)) => {
                let (host, port) = parse_host_port(address)
                    .with_context(|| format!("invalid server bond address {address:?}"))?;
                Some(BondParams {
                    host,
                    port,
                    links: bond.links,
                    pool_size: bond.pool_size,
                    max_streams: bond.max_streams.max(1),
                    target: address.clone(),
                })
            },
            // Bond without an address is rejected by config validation.
            (Some(_), None) => anyhow::bail!("bond inbound requires server.bond_address"),
            (None, _) => None,
        };
        Ok(Self {
            server_host,
            server_port,
            server_key: Arc::new(key),
            connect_timeout: Duration::from_secs(cfg.server.connect_timeout),
            connect_retries: cfg.server.connect_retries,
            max_connections: cfg.max_connections,
            pool_size: cfg.server.mux.effective_pool_size(),
            max_streams: cfg.server.mux.max_streams.max(1),
            bond,
            dns: Arc::new(nextppp_common::dns::DnsCache::new()),
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
        // Original case preserved: DNS lookups are case-insensitive, and
        // mutating the configured address would surprise log diffs.
        Err(_) => Host::Domain(host.to_owned()),
    };
    Ok((h, port))
}

/// Lifetime counters backing the heartbeat log (the client-side mirror
/// of the server's stats).
#[derive(Default)]
pub struct ClientStats {
    /// Currently open inbound sessions.
    active: AtomicU64,
    /// Total accepted inbound connections.
    connections: AtomicU64,
    /// Streams established on pool tunnels (server REPLY OK).
    tunnels: AtomicU64,
    /// Tunnel/stream setup failures (connect, handshake, refused).
    tunnel_failures: AtomicU64,
    /// Bytes pumped from local apps into tunnels.
    bytes_up: AtomicU64,
    /// Bytes pumped from tunnels back to local apps.
    bytes_down: AtomicU64,
}

/// Periodically logs client health (see [`ClientStats`]).
fn spawn_heartbeat(stats: Arc<ClientStats>) {
    tokio::spawn(async move {
        let started = std::time::Instant::now();
        loop {
            tokio::time::sleep(HEARTBEAT_INTERVAL).await;
            info!(
                "heartbeat: uptime {} active {} connections {} tunnels {} failed_tunnels {} up {} \
                 down {}",
                nextppp_common::fmt_duration(started.elapsed()),
                stats.active.load(Ordering::Relaxed),
                stats.connections.load(Ordering::Relaxed),
                stats.tunnels.load(Ordering::Relaxed),
                stats.tunnel_failures.load(Ordering::Relaxed),
                nextppp_common::fmt_bytes(stats.bytes_up.load(Ordering::Relaxed)),
                nextppp_common::fmt_bytes(stats.bytes_down.load(Ordering::Relaxed)),
            );
        }
    });
}

/// Accept loop; blocks the calling thread forever. `bond_listener`, when
/// present, additionally serves the bond (bandwidth) inbound.
///
/// # Errors
///
/// Fatal listener failure.
// `serve` owns the listener: it lives exactly as long as the accept loop.
#[allow(clippy::needless_pass_by_value)]
pub fn serve(
    listener: std::net::TcpListener,
    bond_listener: Option<std::net::TcpListener>,
    rt: Arc<ClientRuntime>,
) -> anyhow::Result<()> {
    info!(
        "nextppp client socks5 inbound on {}",
        listener.local_addr()?.to_string()
    );
    let stats: Arc<ClientStats> = Arc::new(ClientStats::default());
    listener.set_nonblocking(true)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("nextppp-worker")
        .build()
        .context("build tokio runtime")?;
    runtime.block_on(async move {
        let listener =
            tokio::net::TcpListener::from_std(listener).context("convert listener to tokio")?;
        shutdown::install(listener.local_addr()?);
        spawn_heartbeat(Arc::clone(&stats));
        let pool = Pool::new(&rt, pool::PlainDialer, PoolParams {
            pool_size: rt.pool_size,
            max_streams: rt.max_streams,
            target: format!("{}:{}", rt.server_host.to_display(), rt.server_port),
        });
        if let Some(bond) = bond_listener {
            bond.set_nonblocking(true)
                .context("bond listener nonblocking")?;
            let bond = tokio::net::TcpListener::from_std(bond)
                .context("convert bond listener to tokio")?;
            let params = rt.bond.as_ref().expect("bond listener implies bond params");
            info!("nextppp client bond inbound on {}", bond.local_addr()?);
            let bond_pool = Pool::new(&rt, bond::BondDialer, PoolParams {
                pool_size: params.pool_size,
                max_streams: params.max_streams,
                target: params.target.clone(),
            });
            tokio::spawn(accept_inbound(
                bond,
                Arc::clone(&rt),
                Arc::clone(&stats),
                bond_pool,
            ));
        }
        accept_inbound(listener, Arc::clone(&rt), Arc::clone(&stats), pool).await;
        // Drain with the runtime alive (the sleep loop must not block a
        // worker, hence spawn_blocking).
        let drained = {
            let stats = Arc::clone(&stats);
            tokio::task::spawn_blocking(move || {
                shutdown::drain_sessions(move || stats.active.load(Ordering::Relaxed));
            })
            .await
        };
        if let Err(e) = drained {
            warn!("drain task failed: {e}");
        }
        Ok(())
    })
}

/// One SOCKS5 inbound accept loop over one tunnel pool.
async fn accept_inbound<D: TunnelDialer>(
    listener: tokio::net::TcpListener,
    rt: Arc<ClientRuntime>,
    stats: Arc<ClientStats>,
    pool: Pool<D>,
) {
    loop {
        if shutdown::requested() {
            break;
        }
        tokio::select! {
            r = listener.accept() => match r {
                Ok((stream, _)) => {
                    // Best-effort gate against local apps wedging the
                    // process with half-open socks sessions.
                    if let Some(max) = rt.max_connections
                        && stats.active.load(Ordering::Relaxed) >= max
                    {
                        debug!("inbound rejected: connection limit {max} reached");
                        continue; // dropping `stream` closes it
                    }
                    stats.connections.fetch_add(1, Ordering::Relaxed);
                    stats.active.fetch_add(1, Ordering::Relaxed);
                    tokio::spawn({
                        let stats = Arc::clone(&stats);
                        let pool = pool.clone();
                        async move {
                            let _guard = ActiveGuard(Arc::clone(&stats));
                            socks5::handle(stream, stats, pool).await;
                        }
                    });
                },
                Err(e) => {
                    if shutdown::requested() {
                        break;
                    }
                    warn!("accept failed: {e}");
                    if accept_exhausted(&e) {
                        log_accept_exhausted(&e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                },
            },
            () = tokio::time::sleep(SHUTDOWN_POLL) => {},
        }
    }
    info!("shutdown signal received; draining sessions");
}

/// Decrements the active-inbound counter when a connection ends.
struct ActiveGuard(Arc<ClientStats>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
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
        // Case is preserved end to end (DNS is case-insensitive).
        assert_eq!(d, "Example.COM");
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
