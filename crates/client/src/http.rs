//! HTTP inbound.
//!
//! * `CONNECT host:port` is routed per the rule list and tunneled;
//! * plain requests (`GET http://…/path …` absolute-form, or origin-form
//!   with a `Host` header) are routed the same way, then the *original*
//!   bytes (head included) are piped through unchanged. Keeping the
//!   absolute-form request line is intentional: RFC 7230 requires servers
//!   to accept it, and not rewriting preserves exact framing.
//!   The connection then behaves as a tunnel, so keep-alive requests to
//!   different hosts on one connection are not re-routed.

use std::{
    io::{ErrorKind, Read, Write},
    net::TcpStream,
    sync::Arc,
};

use anyhow::Context;
use openppp3_common::{addr::Host, addr::ProxyAddr, pump, Policy};
use tracing::debug;

use crate::{outbound, ClientRuntime};

/// Request head size cap; plenty for real-world header blocks.
const MAX_HEAD: usize = 16 * 1024;

/// Handles one HTTP(-ish) inbound connection.
///
/// # Errors
///
/// Any protocol or I/O failure ends the session.
pub fn handle(mut stream: TcpStream, rt: &Arc<ClientRuntime>) -> anyhow::Result<()> {
    let (head, extra) = read_head(&mut stream).context("read request head")?;
    let head_str = String::from_utf8_lossy(&head);
    let line = head_str.lines().next().unwrap_or_default();
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_ascii_uppercase();
    let target = parts.next().unwrap_or_default().to_owned();
    if method.is_empty() || target.is_empty() {
        respond(&mut stream, 400, "Bad Request").ok();
        anyhow::bail!("malformed request line {line:?}");
    }

    let addr = if method == "CONNECT" {
        parse_target_authority(&target, 443)?
    } else {
        parse_plain_target(&target, &head_str)?
    };

    let policy = rt.rules.decide(&addr.host);
    debug!("http {} {target} -> {policy:?}", addr.host.to_display());
    if policy == Policy::Block {
        respond(&mut stream, 403, "Forbidden").ok();
        return Ok(());
    }

    match outbound::connect(policy, &addr, rt) {
        Ok(mut out) => {
            if method == "CONNECT" {
                // The CONNECT head is negotiation, not payload: only bytes
                // the client pipelined after it may be forwarded.
                respond(&mut stream, 200, "Connection Established").context("reply 200")?;
                out.write_initial(&extra).context("forward pipelined bytes")?;
            } else {
                // Plain requests are forwarded verbatim, head included.
                out.write_initial(&head)
                    .and_then(|()| out.write_initial(&extra))
                    .context("forward buffered request")?;
            }
            // The inbound handshake timeout must not apply to the data plane.
            stream.set_read_timeout(None)?;
            stream.set_write_timeout(None)?;
            pump_stream(stream, out);
            Ok(())
        }
        Err(e) => {
            respond(&mut stream, 502, "Bad Gateway").ok();
            Err(e.context("outbound connect"))
        }
    }
}

fn pump_stream(stream: TcpStream, out: outbound::Outbound) {
    match out {
        outbound::Outbound::Direct(target) => {
            let (up, down) = pump::pump_tcp(stream, target);
            debug!("http direct closed (up {up}, down {down})");
        }
        outbound::Outbound::Tunnel(tx, rx) => {
            let (up, down) = pump::pump_tunnel(*tx, *rx, stream);
            debug!("http tunnel closed (up {up}, down {down})");
        }
    }
}

/// Reads until `\r\n\r\n`, returning `(head, buffered-extra)`; `extra` may
/// carry request body bytes that arrived with the head.
fn read_head(stream: &mut TcpStream) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = match stream.read(&mut chunk) {
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if n == 0 {
            return Err(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "connection closed before request head completed",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let extra = buf.split_off(pos + 4);
            return Ok((buf, extra));
        }
        if buf.len() > MAX_HEAD {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "request head too large",
            ));
        }
    }
}

/// `CONNECT` target is a bare authority (`host[:port]`, default 443).
fn parse_target_authority(target: &str, default_port: u16) -> anyhow::Result<ProxyAddr> {
    let (host, port) = if let Some(rest) = target.strip_prefix('[') {
        // [v6]:port
        let (h, p) = rest
            .split_once(']')
            .with_context(|| format!("malformed v6 authority {target:?}"))?;
        let port = if p.is_empty() {
            default_port
        } else {
            p.strip_prefix(':')
                .with_context(|| format!("malformed v6 authority {target:?}"))?
                .parse()
                .with_context(|| format!("bad port in {target:?}"))?
        };
        (h.to_owned(), port)
    } else if target.contains(':') {
        let (h, p) = target.rsplit_once(':').expect("checked");
        (h.to_owned(), p.parse().context("bad port in CONNECT target")?)
    } else {
        (target.to_owned(), default_port)
    };
    let host = match host.parse() {
        Ok(ip) => Host::Ip(ip),
        Err(_) => Host::Domain(host.to_ascii_lowercase()),
    };
    Ok(ProxyAddr { host, port })
}

/// Plain request target: absolute-form (`http://host:port/path`) or
/// origin-form (`/path`, host from the `Host` header).
fn parse_plain_target(target: &str, head: &str) -> anyhow::Result<ProxyAddr> {
    if let Some(rest) = target.strip_prefix("http://") {
        let authority = rest.split('/').next().unwrap_or_default();
        return parse_target_authority(authority, 80);
    }
    if let Some(rest) = target.strip_prefix("https://") {
        let authority = rest.split('/').next().unwrap_or_default();
        return parse_target_authority(authority, 443);
    }
    let host_header = head
        .lines()
        .find(|l| {
            l.as_bytes()
                .get(..5)
                .is_some_and(|p| p.eq_ignore_ascii_case(b"host:"))
        })
        .with_context(|| "origin-form request without Host header")?;
    let value = host_header[5..].trim();
    parse_target_authority(value, 80)
}

fn respond(stream: &mut TcpStream, code: u16, reason: &str) -> std::io::Result<()> {
    let body = format!("HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    stream.write_all(body.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority(s: &str, default_port: u16) -> ProxyAddr {
        parse_target_authority(s, default_port).unwrap()
    }

    #[test]
    fn authority_default_ports() {
        assert_eq!(authority("example.com", 443).port, 443);
        assert_eq!(authority("example.com:8080", 443).port, 8080);
        assert_eq!(authority("[::1]", 443).port, 443);
        assert_eq!(authority("[::1]:8443", 443).port, 8443);
        assert_eq!(authority("127.0.0.1", 80).port, 80);
        assert_eq!(authority("127.0.0.1:3128", 80).port, 3128);
    }

    #[test]
    fn authority_rejects_bad_ports() {
        assert!(parse_target_authority("[::1]:abc", 443).is_err());
        assert!(parse_target_authority("[::1]garbage", 443).is_err());
        assert!(parse_target_authority("example.com:", 443).is_err());
        assert!(parse_target_authority("example.com:notaport", 443).is_err());
    }

    #[test]
    fn plain_target_defaults_to_80() {
        // Absolute-form http:// defaults to port 80, https:// to 443.
        let http = parse_plain_target("http://example.com/path", "").unwrap();
        assert_eq!(http.port, 80);
        assert_eq!(http.host, Host::Domain(String::from("example.com")));
        let https = parse_plain_target("https://example.com/path", "").unwrap();
        assert_eq!(https.port, 443);
        // Origin-form takes the Host header, defaulting to 80.
        let origin = parse_plain_target("/x", "GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap();
        assert_eq!(origin.port, 80);
        let origin_port = parse_plain_target("/x", "GET /x HTTP/1.1\r\nHost: example.com:8080\r\n\r\n").unwrap();
        assert_eq!(origin_port.port, 8080);
    }

    #[test]
    fn plain_target_non_ascii_host_header_does_not_panic() {
        // The old byte-slice `l[..5]` panicked on multi-byte characters; the
        // line must be skipped (no match) instead.
        assert!(parse_plain_target("/x", "GET /x HTTP/1.1\r\nHöst: example.com\r\n\r\n").is_err());
        // A valid Host header after a non-ASCII line still parses.
        let addr = parse_plain_target(
            "/x",
            "GET /x HTTP/1.1\r\nX-Üser: 1\r\nHost: example.com\r\n\r\n",
        )
        .unwrap();
        assert_eq!(addr.port, 80);
        assert_eq!(addr.host, Host::Domain(String::from("example.com")));
    }

    #[test]
    fn plain_target_without_host_header_fails() {
        assert!(parse_plain_target("/x", "GET /x HTTP/1.1\r\n\r\n").is_err());
    }
}
