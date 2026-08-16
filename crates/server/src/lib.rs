//! nextppp proxy server: accepts nextppp-tunneled connections, connects
//! to the requested target and pumps bytes both ways.
//!
//! Connection model: one handshake thread per accepted stream, then the
//! classic two-thread pump ([`nextppp_common::pump`]). Session ids are
//! `random_base + counter`, never zero.
//!
//! Logging contract:
//! - `info`: connection lifecycle (tunnel established, target connected, connection closed with
//!   byte counts) and the periodic heartbeat.
//! - `warn`: handshake failures (probing / wrong secrets) and protocol faults detected on the data
//!   plane.
//! - `debug`: accepted sockets and other high-volume detail.

use std::{
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::Context;
use nextppp_common::{
    PumpStats,
    addr::ProxyAddr,
    config::{ObfuscationConfig, ServerConfig},
    fmt::{fmt_bytes, fmt_duration},
    proto, pump,
};
use nextppp_core::{ObfuscationKey, Transmission};
use rand::Rng;
use spdlog::prelude::*;

/// Heartbeat interval for the health/stats log line.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

/// Immutable runtime parameters derived from the configuration.
#[derive(Clone)]
pub struct ServerRuntime {
    /// Obfuscation/cipher parameters.
    pub key: ObfuscationKey,
    /// Server -> target connect timeout.
    pub connect_timeout: Duration,
    /// Handshake timeout (anti slow-loris).
    pub handshake_timeout: Duration,
}

impl ServerRuntime {
    /// Validates the configuration into runtime parameters.
    ///
    /// # Errors
    ///
    /// Cipher method validation failure.
    pub fn from_config(cfg: &ServerConfig) -> anyhow::Result<Self> {
        let key = cfg
            .obfuscation
            .to_key(cfg.password.as_deref())
            .map_err(anyhow::Error::msg)
            .context("obfuscation config")?;
        ObfuscationConfig::warn_placeholder(&key);
        Ok(Self {
            key,
            connect_timeout: Duration::from_secs(cfg.connect_timeout),
            handshake_timeout: Duration::from_secs(cfg.handshake_timeout),
        })
    }
}

/// Lifetime counters backing the heartbeat log and ops monitoring.
#[derive(Default)]
struct ServerStats {
    /// Currently open sessions.
    active: AtomicU64,
    /// Total accepted connections (post-handshake successes).
    sessions: AtomicU64,
    /// Handshake failures: active probing, wrong secrets, timeouts.
    handshake_failures: AtomicU64,
    /// Bytes tunneled from clients towards targets.
    bytes_to_targets: AtomicU64,
    /// Bytes tunneled from targets back to clients.
    bytes_to_clients: AtomicU64,
}

/// Decrements the active-session counter when a session ends, however it ends.
struct ActiveGuard<'a>(&'a AtomicU64);

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Accept loop; blocks the calling thread forever.
///
/// # Errors
///
/// Fatal listener failure.
// `serve` owns the listener: it lives exactly as long as the accept loop.
#[allow(clippy::needless_pass_by_value)]
pub fn serve(listener: TcpListener, rt: ServerRuntime) -> anyhow::Result<()> {
    info!(
        "nextppp server listening on {}",
        listener.local_addr()?.to_string()
    );
    let stats: Arc<ServerStats> = Arc::new(ServerStats::default());
    spawn_heartbeat(Arc::clone(&stats));

    let base = u128::from(rand::rng().next_u64()); // session ids only need uniqueness
    let counter = AtomicU64::new(0);
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let rt = rt.clone();
                let stats = Arc::clone(&stats);
                let mut sid =
                    base.wrapping_add(u128::from(counter.fetch_add(1, Ordering::Relaxed)));
                if sid == 0 {
                    sid = 1;
                }
                let spawned = thread::Builder::new()
                    .name(format!("nextppp-{sid:016x}"))
                    .spawn(move || handle_conn(stream, &rt, sid, &stats));
                if let Err(e) = spawned {
                    error!("session {sid:016x} spawn failed: {e}");
                }
            },
            Err(e) => warn!("accept failed: {e}"),
        }
    }
    Ok(())
}

/// Periodically logs server health: uptime, session counters and traffic.
fn spawn_heartbeat(stats: Arc<ServerStats>) {
    let started = Instant::now();
    let spawned = thread::Builder::new()
        .name("nextppp-heartbeat".to_owned())
        .spawn(move || {
            loop {
                thread::sleep(HEARTBEAT_INTERVAL);
                info!(
                    "heartbeat: uptime {} active {} sessions {} failed_handshakes {} to-targets \
                     {} to-clients {}",
                    fmt_duration(started.elapsed()),
                    stats.active.load(Ordering::Relaxed),
                    stats.sessions.load(Ordering::Relaxed),
                    stats.handshake_failures.load(Ordering::Relaxed),
                    fmt_bytes(stats.bytes_to_targets.load(Ordering::Relaxed)),
                    fmt_bytes(stats.bytes_to_clients.load(Ordering::Relaxed)),
                );
            }
        });
    if let Err(e) = spawned {
        warn!("heartbeat thread spawn failed: {e}");
    }
}

/// Handles one tunneled connection end to end, logging its full lifecycle.
fn handle_conn(stream: TcpStream, rt: &ServerRuntime, sid: u128, stats: &ServerStats) {
    stats.active.fetch_add(1, Ordering::Relaxed);
    let _guard = ActiveGuard(&stats.active);

    let peer = stream
        .peer_addr()
        .map_or_else(|_| String::from("?"), |a| a.to_string());
    debug!("session {sid:016x} accepted from {peer}");

    if let Err(e) = handle_conn_inner(stream, rt, sid, &peer, stats) {
        debug!("session {sid:016x} ({peer}) ended: {e:#}");
    }
}

/// Connection body; every failure point logs at its proper level already.
#[cfg_attr(feature = "hotpath", hotpath::measure)]
fn handle_conn_inner(
    stream: TcpStream,
    rt: &ServerRuntime,
    sid: u128,
    peer: &str,
    stats: &ServerStats,
) -> anyhow::Result<()> {
    pump::nodelay(&stream);
    stream.set_read_timeout(Some(rt.handshake_timeout))?;
    stream.set_write_timeout(Some(rt.handshake_timeout))?;
    let rx_io = stream.try_clone().context("clone stream")?;

    let mut tx = Transmission::new(stream, rt.key.clone());
    if let Err(e) = tx.handshake_server(sid, false) {
        stats.handshake_failures.fetch_add(1, Ordering::Relaxed);
        // Probes/scanners with wrong secrets land here (checksum/base94
        // errors); healthy deployments see almost none of these.
        warn!("session {sid:016x} ({peer}) handshake failed: {e}");
        return Err(e).context("handshake");
    }

    let started = Instant::now();
    let req = match tx.read().context("read request") {
        Ok(req) => req,
        Err(e) => {
            if is_clean_close(&e) {
                debug!("session {sid:016x} ({peer}) closed before request");
            } else {
                warn!("session {sid:016x} ({peer}) read request failed: {e:#}");
            }
            return Err(e);
        },
    };
    let addr = match ProxyAddr::decode(&req).context("decode request") {
        Ok(addr) => addr,
        Err(e) => {
            warn!("session {sid:016x} ({peer}) bad request frame: {e:#}");
            return Err(e);
        },
    };
    let target = format!("{}:{}", addr.host.to_display(), addr.port);
    stats.sessions.fetch_add(1, Ordering::Relaxed);
    info!("session {sid:016x} ({peer}) -> {target}");

    let outgoing = pump::tcp_connect(&addr.host, addr.port, rt.connect_timeout);
    match outgoing {
        Ok(target_stream) => {
            pump::nodelay(&target_stream);
            if let Err(e) = tx.write(&[proto::STATUS_OK]).context("reply ok") {
                warn!("session {sid:016x} ({peer}) reply failed: {e:#}");
                return Err(e);
            }
            // Handshake done: the data plane must not time out.
            tx.io_mut().set_read_timeout(None)?;
            rx_io.set_read_timeout(None)?;
            tx.io_mut().set_write_timeout(None)?;

            let (txh, rxh) = tx.split_with(rx_io);
            let s = pump::pump_tunnel(txh, rxh, target_stream);
            stats.bytes_to_targets.fetch_add(s.up, Ordering::Relaxed);
            stats.bytes_to_clients.fetch_add(s.down, Ordering::Relaxed);
            log_close(sid, peer, &target, &s, started);
            Ok(())
        },
        Err(e) => {
            // Refused targets are client-side routing issues, not server
            // faults: info, not warn.
            info!("session {sid:016x} ({peer}) connect {target} failed: {e}");
            let _ = tx.write(&[proto::STATUS_REFUSED]);
            Ok(())
        },
    }
}

/// Whether an anyhow error chain is a routine close (EOF/reset/timeout).
fn is_clean_close(e: &anyhow::Error) -> bool {
    for cause in e.chain() {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            if !matches!(
                io.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::WouldBlock
            ) {
                return false;
            }
        } else if let Some(core) = cause.downcast_ref::<nextppp_core::Error>() {
            match core {
                nextppp_core::Error::Io(_) | nextppp_core::Error::HandshakeFailed(_) => {},
                _ => return false,
            }
        }
    }
    true
}

/// Logs the connection teardown: faults escalate to `warn`.
fn log_close(sid: u128, peer: &str, target: &str, s: &PumpStats, started: Instant) {
    let summary = format!(
        "up {} down {} in {} ({})",
        fmt_bytes(s.up),
        fmt_bytes(s.down),
        fmt_duration(started.elapsed()),
        s.end_causes(),
    );
    if let Some(fault) = s.fault() {
        warn!("session {sid:016x} ({peer}) {target} aborted: {summary}, fault: {fault}");
    } else {
        info!("session {sid:016x} ({peer}) {target} closed: {summary}");
    }
}
