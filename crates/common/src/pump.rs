//! Socket helpers and error classifiers shared by the async data plane.
//!
//! The event-driven pump lives in [`crate::tunnel`]; this module keeps the
//! transport-level pieces: routine-teardown classification (logs and retry
//! decisions), `TCP_NODELAY`/keepalive setup, accept-loop exhaustion
//! detection and the timeout-bounded connect helper.

use std::{
    io::{self, ErrorKind},
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

use nextppp_core::Error as CoreError;
use spdlog::prelude::*;

use crate::addr::Host;

/// The `ErrorKind`s of routine transport teardown, mapped to their short
/// log causes. `None` means the error is a fault worth a warning.
pub(crate) fn routine_cause(kind: ErrorKind) -> Option<&'static str> {
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

/// Enables `TCP_NODELAY` on every proxied stream (interactive workloads).
pub fn nodelay(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
}

/// Enables kernel dead-peer detection on long-lived proxied streams.
///
/// The data plane runs with all socket timeouts cleared (a stall must
/// surface as slow, never as a spurious error), so without keepalive a
/// task parked in `read()` on a silently-dead peer (NAT timeout, power
/// loss, blackholed path) would hang until process restart. After 60s
/// idle the kernel probes every 15s; a dead peer errors the socket with
/// ETIMEDOUT/RST, which [`routine_cause`] already classifies as a routine
/// close — no log-path changes needed. Keepalive probes are empty ACKs
/// and add no DPI fingerprint.
pub fn keepalive<S>(stream: &S)
where
    for<'a> socket2::SockRef<'a>: From<&'a S>,
{
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(15));
    // Custom probe counts are not portable: Windows uses a fixed system
    // default. 3 probes after 60s idle bounds detection at ~105s.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    ))]
    let ka = ka.with_retries(3);
    let _ = socket2::SockRef::from(stream).set_tcp_keepalive(&ka);
}

/// Whether an `accept(2)` failure signals descriptor/memory exhaustion.
/// Once accept starts failing with EMFILE/ENFILE/ENOMEM it fails again
/// immediately, so a loop without backoff would spin at 100% CPU (and
/// flood the log) until descriptors free up. Other accept errors
/// (ECONNABORTED under port scans, transient resets) are routine and must
/// not stall the loop.
#[must_use]
pub fn accept_exhausted(err: &io::Error) -> bool {
    // Raw errno constants: libc is only a dev-dependency here. Unix:
    // ENFILE/EMFILE/ENOMEM. Windows sockets exhaust as WSAENOBUFS.
    #[cfg(unix)]
    return matches!(err.raw_os_error(), Some(23 | 24 | 12));
    #[cfg(windows)]
    return matches!(err.raw_os_error(), Some(10055));
    #[cfg(not(any(unix, windows)))]
    return false;
}

/// Logs and lets the caller back off after an exhausted accept (see
/// [`accept_exhausted`]); pair with a short sleep.
pub fn log_accept_exhausted(err: &io::Error) {
    warn!("accept exhausted ({err}); backing off 100ms for sessions to drain");
}

/// Whether an accept(2) error is routine peer misbehavior (aborted
/// handshakes under scans) that must not spam the log at `warn`.
#[must_use]
pub fn accept_routine(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset | ErrorKind::Interrupted
    )
}

/// Connects to `host:port` under one overall `timeout` deadline: DNS
/// resolution (served by `dns`, see [`crate::dns`]) and every
/// resolved-address attempt share it (previously each address got a full
/// timeout, N A-records cost N * timeout). Addresses are tried in order,
/// first success wins; no happy-eyeballs.
///
/// # Errors
///
/// DNS resolution failure/timeout (without a usable stale cache entry) or
/// every candidate address failing to connect before the deadline.
#[cfg_attr(feature = "hotpath", hotpath::measure)]
pub fn tcp_connect(
    host: &Host,
    port: u16,
    timeout: Duration,
    dns: &crate::dns::DnsCache,
) -> io::Result<TcpStream> {
    let deadline = Instant::now() + timeout;
    let addrs: Vec<SocketAddr> = match host {
        Host::Ip(ip) => vec![SocketAddr::new(*ip, port)],
        Host::Domain(domain) => dns
            .resolve(domain, deadline.saturating_duration_since(Instant::now()))?
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect(),
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
            Ok(s) => {
                keepalive(&s);
                return Ok(s);
            },
            Err(e) => last = e,
        }
    }
    Err(last)
}
