//! Bidirectional connection pumps for the synchronous pump model.
//!
//! The single shape: a local TCP peer against a split nextppp tunnel,
//! wrapping data in `FRAME_DATA` frames and propagating half-closes as
//! `FRAME_EOF` (the nextppp framing itself has no in-band EOF).
//!
//! Pumps classify how each direction ended (graceful half-close / routine
//! reset / fault) so callers can log connection teardown at the right level.
//! A non-graceful end shuts down both sockets, waking the sibling pump;
//! a graceful half-close (`FRAME_EOF`) leaves the other direction running.
//!
//! Threading: the uplink runs inline on the caller's thread and only the
//! downlink gets a dedicated small-stack thread, so a session costs two
//! threads total. The local socket is shared via `Arc` (`&TcpStream`
//! implements both `Read` and `Write`), so no fd clones are needed for
//! concurrent access or teardown.

use std::{
    io::{self, ErrorKind, Read, Write},
    net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs},
    sync::{Arc, mpsc},
    thread,
    time::{Duration, Instant},
};

use nextppp_core::{Error as CoreError, TransmissionRx, TransmissionTx};
use spdlog::prelude::*;

use crate::{
    FRAME_DATA, FRAME_EOF,
    addr::Host,
    fmt::{fmt_bytes, fmt_duration},
};

/// Read chunk size: small enough for interactive latency, large enough to
/// amortize per-frame crypto/header overhead.
const CHUNK: usize = 16 * 1024;

/// Stack for the spawned downlink pump: the call chain is shallow (read ->
/// decrypt -> local write, no recursion, no large stack arrays), so the
/// 2MiB default is pure waste at 10k+ connections.
const PUMP_STACK: usize = 256 * 1024;

/// How one pump direction terminated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PumpEnd {
    /// Graceful in-band half-close (`FRAME_EOF` sent/received): the sibling
    /// direction may still be legitimately active, so the session stays up.
    Eof(&'static str),
    /// Routine transport teardown (EOF, reset, broken pipe, timeout); the
    /// short static cause feeds the connection-close log.
    Closed(&'static str),
    /// Protocol violation or unexpected I/O failure; worth a warning.
    Fault(String),
}

/// The `ErrorKind`s of routine transport teardown, mapped to their short
/// log causes. `None` means the error is a fault worth a warning.
fn routine_cause(kind: ErrorKind) -> Option<&'static str> {
    match kind {
        // Routine transport teardown seen on every proxied network.
        ErrorKind::ConnectionReset => Some("connection reset"),
        ErrorKind::ConnectionAborted => Some("connection aborted"),
        ErrorKind::BrokenPipe => Some("broken pipe"),
        ErrorKind::UnexpectedEof => Some("eof"),
        ErrorKind::TimedOut | ErrorKind::WouldBlock => Some("timeout"),
        ErrorKind::Interrupted => Some("interrupted"),
        _ => None,
    }
}

/// Whether an I/O error is routine connection teardown (peer reset,
/// half-close, timeout) rather than a fault.
#[must_use]
pub fn is_routine_io(err: &io::Error) -> bool {
    routine_cause(err.kind()).is_some()
}

/// Whether a tunnel error is a routine close: transport EOF, routine I/O
/// teardown, or a handshake failure (probes and timeouts land there).
/// Everything else is a protocol violation (tampering, desync, wrong keys).
#[must_use]
pub fn is_routine_core(err: &CoreError) -> bool {
    match err {
        e if e.is_eof() => true,
        CoreError::Io(e) => is_routine_io(e),
        CoreError::HandshakeFailed(_) => true,
        _ => false,
    }
}

/// Whether an error chain is a routine close: every recognized cause
/// (`io::Error` / tunnel error) must be routine, and at least one
/// recognized cause must be present — a bare anyhow failure is a fault.
/// anyhow contexts and other wrappers are neutral. Use this to keep
/// routine closes at `debug` while protocol faults stay at `warn`.
#[must_use]
pub fn is_clean_close(err: &anyhow::Error) -> bool {
    let mut recognized = false;
    let clean = err.chain().all(|cause| {
        if let Some(e) = cause.downcast_ref::<io::Error>() {
            recognized = true;
            is_routine_io(e)
        } else if let Some(e) = cause.downcast_ref::<CoreError>() {
            recognized = true;
            is_routine_core(e)
        } else {
            true
        }
    });
    recognized && clean
}

/// Classifies a local (non-tunnel) I/O error.
fn classify_io(err: &io::Error) -> PumpEnd {
    match routine_cause(err.kind()) {
        Some(cause) => PumpEnd::Closed(cause),
        None => PumpEnd::Fault(err.to_string()),
    }
}

/// Classifies a tunnel (nextppp) error.
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

/// Accept-loop backoff on resource exhaustion. Once accept() starts failing
/// with EMFILE/ENFILE/ENOMEM it fails again immediately, so the loop would
/// spin at 100% CPU (and flood the log) until descriptors free up; a short
/// pause lets sessions drain. Other accept errors (ECONNABORTED under port
/// scans, transient resets) are routine and must not stall the loop.
pub fn accept_backoff(err: &io::Error) {
    // Raw errno constants: libc is only a dev-dependency here. Unix:
    // ENFILE/EMFILE/ENOMEM. Windows sockets exhaust as WSAENOBUFS.
    #[cfg(unix)]
    let exhausted = matches!(err.raw_os_error(), Some(23 | 24 | 12));
    #[cfg(windows)]
    let exhausted = matches!(err.raw_os_error(), Some(10055));
    #[cfg(not(any(unix, windows)))]
    let exhausted = false;
    if exhausted {
        warn!("accept exhausted ({err}); backing off 100ms for sessions to drain");
        thread::sleep(Duration::from_millis(100));
    }
}

/// Connects to `host:port` under one overall `timeout` deadline: DNS
/// resolution and every resolved-address attempt share it (previously each
/// address got a full timeout, N A-records cost N * timeout). Addresses are
/// tried in order, first success wins; no happy-eyeballs.
///
/// `getaddrinfo` has no deadline API, so resolution runs on a helper thread
/// and the wait is bounded: a hung resolver parks exactly that one helper
/// thread (until libc gives up) instead of the caller's session thread
/// forever, unkillable by socket shutdowns.
///
/// # Errors
///
/// DNS resolution failure/timeout or every candidate address failing to
/// connect before the deadline.
#[cfg_attr(feature = "hotpath", hotpath::measure)]
pub fn tcp_connect(host: &Host, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    match host {
        Host::Ip(ip) => TcpStream::connect_timeout(&SocketAddr::new(*ip, port), timeout),
        Host::Domain(domain) => {
            let deadline = Instant::now() + timeout;
            let (tx, rx) = mpsc::channel();
            let owned = domain.clone();
            let spawned = thread::Builder::new()
                .name("nextppp-resolve".to_owned())
                .spawn(move || {
                    // The send races with `recv_timeout` giving up; a late
                    // send just fails silently, the thread then exits.
                    let res = (owned.as_str(), port)
                        .to_socket_addrs()
                        .map(Iterator::collect::<Vec<SocketAddr>>);
                    let _ = tx.send(res);
                });
            let addrs = match spawned {
                Ok(_) => match rx.recv_timeout(timeout) {
                    Ok(res) => res?,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        return Err(io::Error::new(
                            ErrorKind::TimedOut,
                            "dns resolution timed out",
                        ));
                    },
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        return Err(io::Error::other("resolver thread died"));
                    },
                },
                Err(e) => return Err(io::Error::other(e)),
            };
            let mut last = io::Error::new(ErrorKind::AddrNotAvailable, "no addresses resolved");
            for addr in addrs {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(io::Error::new(
                        ErrorKind::TimedOut,
                        "connect deadline exceeded",
                    ));
                }
                match TcpStream::connect_timeout(&addr, remaining) {
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
// Function-level measurement spans the whole connection lifetime (mostly
// local-read wait); subtracting the nested `tx.write` time yields the local
// I/O share.
#[cfg_attr(feature = "hotpath", hotpath::measure)]
fn tunnel_up(mut tx: TransmissionTx<TcpStream>, local: Arc<TcpStream>) -> (u64, PumpEnd) {
    let r = pump_up_loop(&mut tx, &local);
    if r.1.kills_session() {
        kill_session(tx.io(), &local);
    }
    r
}

// `mut` on the shared reference: Read/Write are implemented for
// `&TcpStream`, whose methods need `&mut &TcpStream`.
fn pump_up_loop(tx: &mut TransmissionTx<TcpStream>, mut local: &TcpStream) -> (u64, PumpEnd) {
    let mut buf = vec![0u8; CHUNK];
    let mut total = 0u64;
    loop {
        match local.read(&mut buf) {
            Ok(0) => {
                // Best-effort FRAME_EOF; if the tunnel is already dead the
                // write fails and the session is torn down (non-graceful)
                // instead of reported as a clean half-close.
                return match tx.write(&[FRAME_EOF]) {
                    Ok(()) => (total, PumpEnd::Eof("local eof")),
                    Err(e) => (total, classify_core(e)),
                };
            },
            Ok(n) => {
                // Tagged write: no intermediate [tag][payload] buffer.
                if let Err(e) = tx.write_tagged(FRAME_DATA, &buf[..n]) {
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
#[cfg_attr(feature = "hotpath", hotpath::measure)]
fn tunnel_down(mut rx: TransmissionRx<TcpStream>, local: Arc<TcpStream>) -> (u64, PumpEnd) {
    let r = pump_down_loop(&mut rx, &local);
    if r.1.kills_session() {
        kill_session(rx.io(), &local);
    }
    r
}

fn pump_down_loop(rx: &mut TransmissionRx<TcpStream>, mut local: &TcpStream) -> (u64, PumpEnd) {
    let mut total = 0u64;
    loop {
        match rx.read_buf() {
            Ok(msg) => {
                // The core read path guarantees non-empty messages.
                let (&tag, payload) = msg.split_first().expect("messages are non-empty");
                match tag {
                    FRAME_DATA if !payload.is_empty() => {
                        if let Err(e) = local.write_all(payload) {
                            return (total, classify_io(&e));
                        }
                        total += payload.len() as u64;
                    },
                    FRAME_EOF => {
                        let _ = local.shutdown(Shutdown::Write);
                        return (total, PumpEnd::Eof("remote eof"));
                    },
                    FRAME_DATA => {
                        // proto.rs: data frames must carry a non-empty
                        // payload; an empty one is a protocol violation.
                        return (total, PumpEnd::Fault(String::from("empty data frame")));
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
            Self::Eof(why) | Self::Closed(why) => why,
            Self::Fault(e) => e.as_str(),
        }
    }

    /// Whether this end needs a warning rather than an info line.
    #[must_use]
    pub fn is_fault(&self) -> bool {
        matches!(self, Self::Fault(_))
    }

    /// Whether this end kills the whole session: everything except a
    /// graceful in-band half-close means the sibling pump can never make
    /// progress again and must be woken up via socket shutdown.
    fn kills_session(&self) -> bool {
        !matches!(self, Self::Eof(_))
    }
}

/// Wakes the sibling pump after a non-graceful end. Dropping a handle never
/// wakes a thread blocked in `read`/`write` on another handle of the same
/// socket (no FIN is sent while handles remain); `shutdown` acts on the
/// socket itself and does. Shutting down both directions of both sockets
/// unblocks the sibling wherever it is parked (NAT timeouts and network
/// partitions make this routine on proxied networks). Each pump uses the
/// handles it already owns, so no fd clones are needed.
fn kill_session(tunnel: &TcpStream, local: &TcpStream) {
    let _ = tunnel.shutdown(Shutdown::Both);
    let _ = local.shutdown(Shutdown::Both);
}

/// Logs a pumped connection's teardown at `info`, escalating to `warn` when
/// either direction ended in a fault. `subject` identifies the connection
/// (e.g. `[1.2.3.4:5]` client-side, `session 0123.. (1.2.3.4:5)` server-side).
pub fn log_close(subject: &str, target: &str, s: &PumpStats, started: Instant) {
    let summary = format!(
        "up {} down {} in {} ({})",
        fmt_bytes(s.up),
        fmt_bytes(s.down),
        fmt_duration(started.elapsed()),
        s.end_causes(),
    );
    if let Some(fault) = s.fault() {
        warn!("{subject} {target} aborted: {summary}, fault: {fault}");
    } else {
        info!("{subject} {target} closed: {summary}");
    }
}

/// Pumps a local TCP peer against a split nextppp tunnel until either side
/// closes or fails; returns per-direction byte counts and end reasons.
#[must_use = "stats feed connection logs"]
pub fn pump_tunnel(
    tx: TransmissionTx<TcpStream>,
    rx: TransmissionRx<TcpStream>,
    local: TcpStream,
) -> PumpStats {
    let local = Arc::new(local);
    // Downlink on a dedicated small-stack thread; uplink runs inline, one
    // spawned thread per session instead of two.
    let spawned = thread::Builder::new()
        .name("nextppp-pump-down".to_owned())
        .stack_size(PUMP_STACK)
        .spawn({
            let local = Arc::clone(&local);
            move || tunnel_down(rx, local)
        });
    let (up, up_end) = tunnel_up(tx, local);
    let (down, down_end) = match spawned {
        Ok(handle) => handle
            .join()
            .unwrap_or((0, PumpEnd::Fault("down pump panicked".into()))),
        Err(e) => {
            // Thread-creation failure (resource exhaustion): the downlink
            // never ran; report it and let the already-failing session
            // tear itself down.
            error!("downlink pump spawn failed: {e}");
            (0, PumpEnd::Fault("down pump spawn failed".into()))
        },
    };
    PumpStats {
        up,
        down,
        up_end,
        down_end,
    }
}
