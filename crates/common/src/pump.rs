//! Bidirectional connection pumps for the synchronous two-thread model.
//!
//! The single shape: a local TCP peer against a split openppp3 tunnel,
//! wrapping data in `FRAME_DATA` frames and propagating half-closes as
//! `FRAME_EOF` (the openppp3 framing itself has no in-band EOF).
//!
//! Pumps classify how each direction ended (clean close / routine reset /
//! fault) so callers can log connection teardown at the right level.

use std::{
    io::{self, ErrorKind, Read, Write},
    net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs},
    thread,
    time::Duration,
};

use openppp3_core::{Error as CoreError, TransmissionRx, TransmissionTx};

use crate::{FRAME_DATA, FRAME_EOF, addr::Host};

/// Read chunk size: small enough for interactive latency, large enough to
/// amortize per-frame crypto/header overhead.
const CHUNK: usize = 16 * 1024;

/// How one pump direction terminated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PumpEnd {
    /// Clean or routine teardown (EOF, reset, broken pipe, timeout); the
    /// short static cause feeds the connection-close log.
    Closed(&'static str),
    /// Protocol violation or unexpected I/O failure; worth a warning.
    Fault(String),
}

/// Classifies a local (non-tunnel) I/O error.
fn classify_io(err: &io::Error) -> PumpEnd {
    match err.kind() {
        // Routine transport teardown seen on every proxied network.
        ErrorKind::ConnectionReset => PumpEnd::Closed("connection reset"),
        ErrorKind::ConnectionAborted => PumpEnd::Closed("connection aborted"),
        ErrorKind::BrokenPipe => PumpEnd::Closed("broken pipe"),
        ErrorKind::UnexpectedEof => PumpEnd::Closed("eof"),
        ErrorKind::TimedOut | ErrorKind::WouldBlock => PumpEnd::Closed("timeout"),
        ErrorKind::Interrupted => PumpEnd::Closed("interrupted"),
        _ => PumpEnd::Fault(err.to_string()),
    }
}

/// Classifies a tunnel (openppp3) error.
fn classify_core(err: CoreError) -> PumpEnd {
    if err.is_eof() {
        PumpEnd::Closed("eof")
    } else {
        match err {
            CoreError::Io(e) => classify_io(&e),
            // Every other variant is a protocol violation (tampering,
            // desync, wrong keys) and gets escalated to a fault.
            other => PumpEnd::Fault(other.to_string()),
        }
    }
}

/// Enables `TCP_NODELAY` on every proxied stream (interactive workloads).
pub fn nodelay(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
}

/// Connects to `host:port` honoring a timeout. All resolved addresses are
/// tried in order (first success wins; no happy-eyeballs).
///
/// # Errors
///
/// DNS resolution failure or every candidate address failing to connect.
pub fn tcp_connect(host: &Host, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    match host {
        Host::Ip(ip) => TcpStream::connect_timeout(&SocketAddr::new(*ip, port), timeout),
        Host::Domain(domain) => {
            let addrs: Vec<SocketAddr> = (domain.as_str(), port).to_socket_addrs()?.collect();
            let mut last = io::Error::new(ErrorKind::AddrNotAvailable, "no addresses resolved");
            for addr in addrs {
                match TcpStream::connect_timeout(&addr, timeout) {
                    Ok(s) => return Ok(s),
                    Err(e) => last = e,
                }
            }
            Err(last)
        },
    }
}

/// Local -> tunnel direction: wraps chunks in `FRAME_DATA`, emits `FRAME_EOF`
/// on local half-close. Dropping `tx` afterwards sends the TCP FIN.
fn tunnel_up(mut tx: TransmissionTx<TcpStream>, mut local: TcpStream) -> (u64, PumpEnd) {
    let mut buf = vec![0u8; CHUNK];
    let mut frame = Vec::with_capacity(CHUNK + 1);
    let mut total = 0u64;
    loop {
        match local.read(&mut buf) {
            Ok(0) => {
                let _ = tx.write(&[FRAME_EOF]);
                return (total, PumpEnd::Closed("local eof"));
            },
            Ok(n) => {
                frame.clear();
                frame.push(FRAME_DATA);
                frame.extend_from_slice(&buf[..n]);
                if let Err(e) = tx.write(&frame) {
                    return (total, classify_core(e));
                }
                total += n as u64;
            },
            Err(e) if e.kind() == ErrorKind::Interrupted => {},
            Err(e) => return (total, classify_io(&e)),
        }
    }
}

/// Tunnel -> local direction: unwraps `FRAME_DATA`, forwards `FRAME_EOF` as
/// a local write-side shutdown.
fn tunnel_down(mut rx: TransmissionRx<TcpStream>, mut local: TcpStream) -> (u64, PumpEnd) {
    let mut total = 0u64;
    loop {
        match rx.read() {
            Ok(msg) => {
                let Some((&tag, payload)) = msg.split_first() else {
                    continue; // zero-payload data frame: harmless no-op
                };
                match tag {
                    FRAME_DATA if !payload.is_empty() => {
                        if let Err(e) = local.write_all(payload) {
                            return (total, classify_io(&e));
                        }
                        total += payload.len() as u64;
                    },
                    FRAME_EOF => {
                        let _ = local.shutdown(Shutdown::Write);
                        return (total, PumpEnd::Closed("remote eof"));
                    },
                    _ => {
                        // Unknown frame kind: protocol violation.
                        return (
                            total,
                            PumpEnd::Fault(format!("unknown frame kind {tag:#04x}")),
                        );
                    },
                }
            },
            Err(e) => return (total, classify_core(e)),
        }
    }
}

/// Outcome of pumping one connection end to end.
#[derive(Debug)]
pub struct PumpStats {
    /// Bytes pumped local -> tunnel.
    pub up: u64,
    /// Bytes pumped tunnel -> local.
    pub down: u64,
    /// How the up direction ended.
    pub up_end: PumpEnd,
    /// How the down direction ended.
    pub down_end: PumpEnd,
}

impl PumpStats {
    /// The first fault-level termination, if any (for warning logs).
    #[must_use]
    pub fn fault(&self) -> Option<&str> {
        match (&self.up_end, &self.down_end) {
            (PumpEnd::Fault(e), _) | (_, PumpEnd::Fault(e)) => Some(e),
            _ => None,
        }
    }

    /// A short human-readable cause list for close logs.
    #[must_use]
    pub fn end_causes(&self) -> String {
        let up = self.up_end.cause();
        let down = self.down_end.cause();
        if up == down {
            String::from(up)
        } else {
            format!("up: {up}, down: {down}")
        }
    }
}

impl PumpEnd {
    /// Short cause string for logs.
    #[must_use]
    pub fn cause(&self) -> &str {
        match self {
            Self::Closed(why) => why,
            Self::Fault(e) => e.as_str(),
        }
    }

    /// Whether this end needs a warning rather than an info line.
    #[must_use]
    pub fn is_fault(&self) -> bool {
        matches!(self, Self::Fault(_))
    }
}

/// Pumps a local TCP peer against a split openppp3 tunnel until either side
/// closes or fails; returns per-direction byte counts and end reasons.
#[must_use = "stats feed connection logs"]
pub fn pump_tunnel(
    tx: TransmissionTx<TcpStream>,
    rx: TransmissionRx<TcpStream>,
    local: TcpStream,
) -> PumpStats {
    let local_w = local.try_clone().expect("tcp stream clone");
    thread::scope(|s| {
        let down = s.spawn(move || tunnel_down(rx, local_w));
        let up = s.spawn(move || tunnel_up(tx, local));
        let (up, up_end) = up
            .join()
            .unwrap_or((0, PumpEnd::Fault("up pump panicked".into())));
        let (down, down_end) = down
            .join()
            .unwrap_or((0, PumpEnd::Fault("down pump panicked".into())));
        PumpStats {
            up,
            down,
            up_end,
            down_end,
        }
    })
}
