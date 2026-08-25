//! SOCKS5 inbound: no-auth negotiation + CONNECT, always forwarded through
//! the nextppp tunnel (routing is the front-end proxy's job).
//!
//! Every proxied connection logs its lifecycle: open (target + tunnel) at
//! `info`, close (byte counts, duration, cause) at `info`, setup failures
//! and protocol faults at `warn`.

use std::{
    io::ErrorKind,
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};

use anyhow::Context;
use nextppp_common::{
    addr::{Host, ProxyAddr},
    pump, tunnel,
};
use spdlog::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{ClientStats, pool::Pool};

const VER: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NONE_ACCEPTABLE: u8 = 0xff;
const CMD_CONNECT: u8 = 0x01;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

// Reply codes (RFC 1928).
const REP_SUCCEEDED: u8 = 0x00;
const REP_GENERAL: u8 = 0x01;
const REP_CMD_UNSUPPORTED: u8 = 0x07;
const REP_ATYP_UNSUPPORTED: u8 = 0x08;

/// Negotiation timeout: bounds the socks5 negotiation against slow clients;
/// irrelevant once the data-plane pump takes over.
const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(30);

/// Handles one SOCKS5 connection end to end, logging its full lifecycle.
pub async fn handle(stream: tokio::net::TcpStream, stats: Arc<ClientStats>, pool: Pool) {
    let _ = stream.set_nodelay(true);
    pump::keepalive(&stream);
    let peer = stream
        .peer_addr()
        .map_or_else(|_| String::from("?"), |a| a.to_string());

    if let Err(e) = negotiate_and_forward(stream, &peer, &stats, pool).await {
        // Local apps poking the inbound with non-socks5 traffic or vanishing
        // mid-negotiation are routine; anything else deserves a warning.
        if pump::is_clean_close(&e) {
            debug!("[{peer}] inbound session ended: {e:#}");
        } else {
            warn!("[{peer}] inbound session failed: {e:#}");
        }
    }
}

/// Negotiation + CONNECT + tunnel forwarding. Failure points log at their
/// proper levels before returning the error for the routine/fault split.
#[cfg_attr(feature = "hotpath", hotpath::measure)]
async fn negotiate_and_forward(
    mut stream: tokio::net::TcpStream,
    peer: &str,
    stats: &ClientStats,
    pool: Pool,
) -> anyhow::Result<()> {
    let addr = tokio::time::timeout(NEGOTIATION_TIMEOUT, read_connect(&mut stream))
        .await
        .map_err(|_| std::io::Error::new(ErrorKind::TimedOut, "socks5 negotiation timeout"))??;
    let target = format!("{}:{}", addr.host.to_display(), addr.port);

    match pool.open_stream(&addr).await {
        Ok(mut tun) => {
            stats.tunnels.fetch_add(1, Ordering::Relaxed);
            reply(&mut stream, REP_SUCCEEDED)
                .await
                .context("reply succeeded")?;
            let started = Instant::now();
            let sid = tun.sid();
            let out = tun.out().clone();
            let o = tunnel::pump_stream(stream, sid, &mut tun.events, &out).await;
            stats.bytes_up.fetch_add(o.up, Ordering::Relaxed);
            stats.bytes_down.fetch_add(o.down, Ordering::Relaxed);
            if o.end.is_graceful() {
                tun.mark_graceful();
            }
            drop(tun);
            tunnel::log_stream_close(&format!("[{peer}] stream {sid}"), &target, &o, started);
            Ok(())
        },
        Err(e) => {
            stats.tunnel_failures.fetch_add(1, Ordering::Relaxed);
            let _ = reply(&mut stream, REP_GENERAL).await;
            // No inner log line: the failure (with target) rides the error
            // chain into the single warn in `handle`.
            Err(e.context(format!("tunnel connect to {target}")))
        },
    }
}

/// Method negotiation + CONNECT request, returning the target address.
async fn read_connect(stream: &mut tokio::net::TcpStream) -> anyhow::Result<ProxyAddr> {
    negotiate(stream).await.context("greeting")?;

    let mut head = [0u8; 4];
    stream
        .read_exact(&mut head)
        .await
        .context("read request head")?;
    if head[0] != VER {
        anyhow::bail!("bad SOCKS version {:#04x}", head[0]);
    }
    if head[1] != CMD_CONNECT {
        let _ = reply(stream, REP_CMD_UNSUPPORTED).await;
        anyhow::bail!("unsupported command {:#04x}", head[1]);
    }
    // RFC 1928: RSV is reserved and must be zero.
    if head[2] != 0 {
        let _ = reply(stream, REP_GENERAL).await;
        anyhow::bail!("non-zero reserved byte {:#04x}", head[2]);
    }
    match read_addr(stream, head[3]).await {
        Ok(addr) => Ok(addr),
        Err(e) => {
            let rep = if e.kind() == ErrorKind::InvalidData {
                REP_ATYP_UNSUPPORTED
            } else {
                REP_GENERAL
            };
            let _ = reply(stream, rep).await;
            Err(e).context("read request address")
        },
    }
}

/// Method negotiation: only NO-AUTH is offered.
async fn negotiate(stream: &mut tokio::net::TcpStream) -> std::io::Result<()> {
    let mut ver_nmethods = [0u8; 2];
    stream.read_exact(&mut ver_nmethods).await?;
    if ver_nmethods[0] != VER {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!("bad SOCKS version {:#04x}", ver_nmethods[0]),
        ));
    }
    let mut methods = vec![0u8; ver_nmethods[1] as usize];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&METHOD_NO_AUTH) {
        let _ = stream.write_all(&[VER, METHOD_NONE_ACCEPTABLE]).await;
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "client offered no acceptable auth method",
        ));
    }
    stream.write_all(&[VER, METHOD_NO_AUTH]).await?;
    Ok(())
}

/// Reads `[ATYP][addr][port BE16]` from the request body.
async fn read_addr(stream: &mut tokio::net::TcpStream, atyp: u8) -> std::io::Result<ProxyAddr> {
    let host = match atyp {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            Host::Ip(octets.into())
        },
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            Host::Ip(octets.into())
        },
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            if len[0] == 0 {
                return Err(std::io::Error::new(ErrorKind::InvalidData, "empty domain"));
            }
            let mut name = vec![0u8; len[0] as usize];
            stream.read_exact(&mut name).await?;
            let name = String::from_utf8(name)
                .map_err(|_| std::io::Error::new(ErrorKind::InvalidData, "domain is not utf-8"))?;
            if name.bytes().any(|b| !(0x21..=0x7e).contains(&b)) {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "invalid domain characters",
                ));
            }
            // Original case preserved: DNS is case-insensitive but the
            // domain must be forwarded verbatim per RFC 1928.
            Host::Domain(name)
        },
        _ => {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("unsupported ATYP {atyp:#04x}"),
            ));
        },
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(ProxyAddr {
        host,
        port: u16::from_be_bytes(port),
    })
}

/// Writes a minimal SOCKS5 reply (BND.ADDR = 0.0.0.0, BND.PORT = 0).
async fn reply(stream: &mut tokio::net::TcpStream, rep: u8) -> std::io::Result<()> {
    stream
        .write_all(&[VER, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await
}
