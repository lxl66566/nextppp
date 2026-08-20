//! SOCKS5 inbound: no-auth negotiation + CONNECT, always forwarded through
//! the nextppp tunnel (routing is the front-end proxy's job).
//!
//! Every proxied connection logs its lifecycle: open (target + tunnel) at
//! `info`, close (byte counts, duration, cause) at `info`, setup failures
//! and protocol faults at `warn`.

use std::{
    io::{ErrorKind, Read, Write},
    net::TcpStream,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use nextppp_common::{
    addr::{Host, ProxyAddr},
    pump,
};
use spdlog::prelude::*;

use crate::{ClientRuntime, outbound};

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
/// cleared before the data-plane pump takes over.
const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(30);

/// Handles one SOCKS5 connection end to end, logging its full lifecycle.
pub fn handle(stream: TcpStream, rt: &Arc<ClientRuntime>) {
    pump::nodelay(&stream);
    let peer = stream
        .peer_addr()
        .map_or_else(|_| String::from("?"), |a| a.to_string());

    if let Err(e) = negotiate_and_forward(stream, rt, &peer) {
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
fn negotiate_and_forward(
    mut stream: TcpStream,
    rt: &Arc<ClientRuntime>,
    peer: &str,
) -> anyhow::Result<()> {
    let _ = stream.set_read_timeout(Some(NEGOTIATION_TIMEOUT));
    let _ = stream.set_write_timeout(Some(NEGOTIATION_TIMEOUT));
    negotiate(&mut stream).context("greeting")?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).context("read request head")?;
    if head[0] != VER {
        warn!("[{peer}] bad SOCKS version {:#04x}", head[0]);
        anyhow::bail!("bad SOCKS version {:#04x}", head[0]);
    }
    if head[1] != CMD_CONNECT {
        warn!("[{peer}] unsupported command {:#04x}", head[1]);
        let _ = reply(&mut stream, REP_CMD_UNSUPPORTED);
        anyhow::bail!("unsupported command {:#04x}", head[1]);
    }
    // RFC 1928: RSV is reserved and must be zero.
    if head[2] != 0 {
        warn!("[{peer}] non-zero reserved byte {:#04x}", head[2]);
        let _ = reply(&mut stream, REP_GENERAL);
        anyhow::bail!("non-zero reserved byte {:#04x}", head[2]);
    }
    let addr = match read_addr(&mut stream, head[3]) {
        Ok(addr) => addr,
        Err(e) => {
            let rep = if e.kind() == ErrorKind::InvalidData {
                REP_ATYP_UNSUPPORTED
            } else {
                REP_GENERAL
            };
            let _ = reply(&mut stream, rep);
            return Err(e).context("read request address");
        },
    };
    let target = format!("{}:{}", addr.host.to_display(), addr.port);

    match outbound::tunnel_connect(&addr, rt) {
        Ok((tx, rx)) => {
            reply(&mut stream, REP_SUCCEEDED).context("reply succeeded")?;
            // The inbound negotiation timeout must not apply to the data plane.
            stream.set_read_timeout(None)?;
            stream.set_write_timeout(None)?;
            let started = Instant::now();
            let s = pump::pump_tunnel(*tx, *rx, stream);
            pump::log_close(&format!("[{peer}]"), &target, &s, started);
            Ok(())
        },
        Err(e) => {
            warn!("[{peer}] tunnel connect to {target} failed: {e:#}");
            let _ = reply(&mut stream, REP_GENERAL);
            Err(e.context("outbound connect"))
        },
    }
}

/// Method negotiation: only NO-AUTH is offered.
fn negotiate(stream: &mut TcpStream) -> std::io::Result<()> {
    let mut ver_nmethods = [0u8; 2];
    stream.read_exact(&mut ver_nmethods)?;
    if ver_nmethods[0] != VER {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!("bad SOCKS version {:#04x}", ver_nmethods[0]),
        ));
    }
    let mut methods = vec![0u8; ver_nmethods[1] as usize];
    stream.read_exact(&mut methods)?;
    if !methods.contains(&METHOD_NO_AUTH) {
        let _ = stream.write_all(&[VER, METHOD_NONE_ACCEPTABLE]);
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "client offered no acceptable auth method",
        ));
    }
    stream.write_all(&[VER, METHOD_NO_AUTH])
}

/// Reads `[ATYP][addr][port BE16]` from the request body.
fn read_addr(stream: &mut TcpStream, atyp: u8) -> std::io::Result<ProxyAddr> {
    let host = match atyp {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets)?;
            Host::Ip(octets.into())
        },
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets)?;
            Host::Ip(octets.into())
        },
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            if len[0] == 0 {
                return Err(std::io::Error::new(ErrorKind::InvalidData, "empty domain"));
            }
            let mut name = vec![0u8; len[0] as usize];
            stream.read_exact(&mut name)?;
            let name = String::from_utf8(name)
                .map_err(|_| std::io::Error::new(ErrorKind::InvalidData, "domain is not utf-8"))?;
            if name.bytes().any(|b| !(0x21..=0x7e).contains(&b)) {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "invalid domain characters",
                ));
            }
            Host::Domain(name.to_ascii_lowercase())
        },
        _ => {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("unsupported ATYP {atyp:#04x}"),
            ));
        },
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port)?;
    Ok(ProxyAddr {
        host,
        port: u16::from_be_bytes(port),
    })
}

/// Writes a minimal SOCKS5 reply (BND.ADDR = 0.0.0.0, BND.PORT = 0).
fn reply(stream: &mut TcpStream, rep: u8) -> std::io::Result<()> {
    stream.write_all(&[VER, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
}
