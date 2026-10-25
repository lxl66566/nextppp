//! nextppp proxy server: accepts nextppp-tunneled connections, demultiplexes
//! their streams, connects to the requested targets and pumps bytes both
//! ways.
//!
//! Connection model: event-driven on a fixed tokio worker pool. Per
//! accepted tunnel: one handshake (on the blocking pool, bounded by
//! `handshake_timeout`), then one writer task + one demux loop; per mux
//! stream: one pump task ([`nextppp_common::tunnel::pump_stream`]). No
//! thread-per-connection anywhere, so capacity tracks the async runtime,
//! not the OS thread limit. Session ids are `random_base + counter`,
//! never zero.
//!
//! Logging contract:
//! - `info`: tunnel/stream lifecycle (established, closed with byte counts) and the periodic
//!   heartbeat.
//! - `warn`: handshake failures (probing / wrong secrets) and protocol faults detected on the data
//!   plane.
//! - `debug`: accepted sockets and other high-volume detail.

use std::{
    collections::HashMap,
    net::TcpStream,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::Context;
use nextppp_common::{
    addr::ProxyAddr,
    config::{ObfuscationConfig, ServerConfig},
    fmt::{fmt_bytes, fmt_duration},
    mux::{FrameKind, REPLY_OK, REPLY_REFUSED, StreamId, parse_frame},
    pump, shutdown,
    tunnel::{self, FrameReader, OutFrame, STREAM_SEND_TIMEOUT, StreamEvent, TxWire},
};
use nextppp_core::{ObfuscationKey, Session, SessionRole, Transmission};
use rand::Rng;
use spdlog::prelude::*;
use tokio::{io::AsyncRead, sync::mpsc};

mod bond;

/// Heartbeat interval for the health/stats log line.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

/// Per-tunnel outbound channel bound (frames); a full channel backpressures
/// every stream's local reader on this tunnel.
const OUTBOUND_BOUND: usize = 256;

/// Per-stream event channel bound (frames).
const STREAM_BOUND: usize = 32;

/// How often the accept loop polls the shutdown flag (the signal handler's
/// wake-up connect makes this a fallback, not the trigger).
const SHUTDOWN_POLL: Duration = Duration::from_millis(200);

/// Immutable runtime parameters derived from the configuration.
#[derive(Clone)]
pub struct ServerRuntime {
    /// Obfuscation/cipher parameters, shared across sessions.
    pub key: Arc<ObfuscationKey>,
    /// Server -> target connect timeout.
    pub connect_timeout: Duration,
    /// Handshake timeout (anti slow-loris).
    pub handshake_timeout: Duration,
    /// Maximum concurrently active tunnels (`None` = unlimited).
    pub max_connections: Option<u64>,
    /// Maximum concurrent in-progress handshakes (`None` = unlimited).
    pub max_handshakes: Option<u64>,
    /// Maximum mux streams per tunnel (`None` = unlimited).
    pub max_streams_per_conn: Option<u64>,
    /// Accept bond-link sessions declared in the handshake (`bond_enabled`).
    pub allow_bond: bool,
    /// Target DNS cache: collapses per-stream `getaddrinfo` bursts into a
    /// single lookup per TTL window.
    pub dns: Arc<nextppp_common::dns::DnsCache>,
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
            key: Arc::new(key),
            connect_timeout: Duration::from_secs(cfg.connect_timeout),
            handshake_timeout: Duration::from_secs(cfg.handshake_timeout),
            max_connections: cfg.max_connections,
            max_handshakes: cfg.max_handshakes,
            max_streams_per_conn: cfg.max_streams_per_conn,
            allow_bond: cfg.bond_enabled,
            dns: Arc::new(nextppp_common::dns::DnsCache::new()),
        })
    }
}

/// Lifetime counters backing the heartbeat log and ops monitoring.
#[derive(Default)]
struct ServerStats {
    /// Currently open tunnels.
    active: AtomicU64,
    /// Total streams served (post-OPEN successes).
    sessions: AtomicU64,
    /// Handshake failures: active probing, wrong secrets, timeouts.
    handshake_failures: AtomicU64,
    /// Connections currently inside the handshake (probe-flood gate,
    /// separate from `active` so slow handshakes cannot squeeze out the
    /// tunnel budget).
    handshaking: AtomicU64,
    /// Connections dropped at accept time because `max_connections` was
    /// reached (the per-rejection log stays at `debug` to survive floods).
    rejected_overload: AtomicU64,
    /// Bytes tunneled from clients towards targets.
    bytes_to_targets: AtomicU64,
    /// Bytes tunneled from targets back to clients.
    bytes_to_clients: AtomicU64,
}

/// Decrements the active-tunnel counter when a tunnel ends, however it ends.
struct ActiveGuard(Arc<ServerStats>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Decrements the in-progress-handshake counter; scoped to the handshake
/// call itself so the gate only throttles the pre-auth phase.
struct HandshakingGuard<'a>(&'a AtomicU64);

impl HandshakingGuard<'_> {
    fn new(counter: &AtomicU64) -> HandshakingGuard<'_> {
        counter.fetch_add(1, Ordering::Relaxed);
        HandshakingGuard(counter)
    }
}

impl Drop for HandshakingGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Rate limit for handshake-failure warnings: probe floods would otherwise
/// turn the log into the actual DoS. The first failure and every 64th are
/// logged; the heartbeat counter still carries the exact total.
fn should_log_failure(n: u64) -> bool {
    n == 1 || n.is_multiple_of(64)
}

/// Per-tunnel stream registry: the demux loop routes events to stream
/// pumps through these senders. Dropping the map (tunnel teardown) closes
/// every channel, which breaks every pump out of its `select!`.
type Registry = Arc<Mutex<HashMap<StreamId, mpsc::Sender<StreamEvent>>>>;

/// Accept loop; blocks the calling thread forever. One listen port serves
/// both session roles: plain mux tunnels and bond links (aggregated-tunnel
/// members), declared by the client in the handshake and routed after it
/// (see [`bond`]).
///
/// # Errors
///
/// Fatal listener failure.
// `serve` owns the listener: it lives exactly as long as the accept loop.
#[allow(clippy::needless_pass_by_value)]
pub fn serve(listener: std::net::TcpListener, rt: ServerRuntime) -> anyhow::Result<()> {
    info!(
        "nextppp server listening on {} (bond links {})",
        listener.local_addr()?.to_string(),
        if rt.allow_bond {
            "enabled"
        } else {
            "disabled"
        },
    );
    let stats: Arc<ServerStats> = Arc::new(ServerStats::default());
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
        accept_loop(&listener, &rt, &stats).await;
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

/// The accept loop proper; returns when shutdown is requested.
async fn accept_loop(
    listener: &tokio::net::TcpListener,
    rt: &ServerRuntime,
    stats: &Arc<ServerStats>,
) {
    let agg = bond::new_aggregator();
    let mut agg_listen = match agg.listen() {
        Ok(l) => l,
        Err(e) => {
            warn!("bond aggregator setup failed: {e}");
            return;
        },
    };
    let base = u128::from(rand::rng().next_u64()); // session ids only need uniqueness
    let counter = AtomicU64::new(0);
    loop {
        if shutdown::requested() {
            break;
        }
        tokio::select! {
            r = listener.accept() => match r {
                Ok((stream, _)) => {
                    // Best-effort tunnel gate: the load/increment below is
                    // not atomic, so a burst can overshoot by a few; good
                    // enough against slowloris-style exhaustion.
                    if let Some(max) = rt.max_connections
                        && stats.active.load(Ordering::Relaxed) >= max
                    {
                        stats.rejected_overload.fetch_add(1, Ordering::Relaxed);
                        debug!("tunnel rejected: connection limit {max} reached");
                        continue; // dropping `stream` closes it
                    }
                    // Probe-flood gate: capped separately so a scanner
                    // cannot occupy the tunnel budget for
                    // `handshake_timeout` apiece.
                    if let Some(max) = rt.max_handshakes
                        && stats.handshaking.load(Ordering::Relaxed) >= max
                    {
                        stats.rejected_overload.fetch_add(1, Ordering::Relaxed);
                        debug!("connection rejected: handshake limit {max} reached");
                        continue;
                    }
                    let mut sid =
                        base.wrapping_add(u128::from(counter.fetch_add(1, Ordering::Relaxed)));
                    if sid == 0 {
                        sid = 1;
                    }
                    tokio::spawn(handle_conn(
                        stream,
                        rt.clone(),
                        sid,
                        Arc::clone(stats),
                        agg.clone(),
                    ));
                },
                Err(e) => {
                    if shutdown::requested() {
                        break;
                    }
                    if pump::accept_routine(&e) {
                        debug!("accept failed: {e}");
                    } else {
                        warn!("accept failed: {e}");
                    }
                    if pump::accept_exhausted(&e) {
                        pump::log_accept_exhausted(&e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                },
            },
            r = agg_listen.next() => match r {
                Ok(incoming) => {
                    tokio::spawn(bond::run_bonded(incoming, rt.clone(), Arc::clone(stats)));
                },
                Err(e) => {
                    warn!("bond aggregator listener failed: {e}");
                    return;
                },
            },
            () = tokio::time::sleep(SHUTDOWN_POLL) => {},
        }
    }
    info!("shutdown signal received; draining sessions");
}

/// Periodically logs server health: uptime, session counters and traffic.
fn spawn_heartbeat(stats: Arc<ServerStats>) {
    let started = Instant::now();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(HEARTBEAT_INTERVAL).await;
            info!(
                "heartbeat: uptime {} active {} sessions {} failed_handshakes {} overloaded {} \
                 to-targets {} to-clients {}",
                fmt_duration(started.elapsed()),
                stats.active.load(Ordering::Relaxed),
                stats.sessions.load(Ordering::Relaxed),
                stats.handshake_failures.load(Ordering::Relaxed),
                stats.rejected_overload.load(Ordering::Relaxed),
                fmt_bytes(stats.bytes_to_targets.load(Ordering::Relaxed)),
                fmt_bytes(stats.bytes_to_clients.load(Ordering::Relaxed)),
            );
        }
    });
}

/// Handles one accepted connection end to end, logging its full lifecycle.
async fn handle_conn(
    stream: tokio::net::TcpStream,
    rt: ServerRuntime,
    sid: u128,
    stats: Arc<ServerStats>,
    agg: bond::AggServer,
) {
    let peer = stream
        .peer_addr()
        .map_or_else(|_| String::from("?"), |a| a.to_string());
    debug!("session {sid:016x} accepted from {peer}");

    if let Err(e) = Box::pin(handle_conn_inner(stream, &rt, sid, &peer, &stats, agg)).await {
        debug!("session {sid:016x} ({peer}) ended: {e:#}");
    }
}

/// Handshake (blocking pool) + role routing: mux tunnel body or bond-link
/// registration.
#[cfg_attr(feature = "hotpath", hotpath::measure)]
async fn handle_conn_inner(
    stream: tokio::net::TcpStream,
    rt: &ServerRuntime,
    sid: u128,
    peer: &str,
    stats: &Arc<ServerStats>,
    agg: bond::AggServer,
) -> anyhow::Result<()> {
    let std_stream = stream.into_std().context("tunnel stream into_std")?;
    // The handshake runs the synchronous Transmission API with timeouts on
    // the blocking pool; the event-driven data plane takes over afterwards.
    std_stream
        .set_nonblocking(false)
        .context("blocking mode for handshake")?;
    let rt2 = rt.clone();
    let handshaking = Arc::clone(stats);
    let allow_bond = rt.allow_bond;
    let hs = tokio::task::spawn_blocking(move || {
        handshake_sync(std_stream, &rt2, sid, &handshaking.handshaking, allow_bond)
    })
    .await
    .context("handshake task join")?;
    let (session, io, role) = match hs {
        Ok(v) => v,
        Err(e) => {
            let n = stats.handshake_failures.fetch_add(1, Ordering::Relaxed) + 1;
            // Probes/scanners with wrong secrets land here (checksum/base94
            // errors); healthy deployments see almost none of these.
            if should_log_failure(n) {
                warn!("session {sid:016x} ({peer}) handshake failed: {e:#} (failure #{n})");
            } else {
                debug!("session {sid:016x} ({peer}) handshake failed: {e:#}");
            }
            return Err(e).context("handshake");
        },
    };
    // One active-connection slot per authenticated session — tunnel or
    // link — until it ends. A link's slot is bound to the aggregator's
    // ownership (see `bond::register_link`), so it outlives this call.
    stats.active.fetch_add(1, Ordering::Relaxed);
    match role {
        SessionRole::MuxTunnel => {
            info!("session {sid:016x} ({peer}) tunnel established");
            io.set_nonblocking(true).context("nonblocking mode")?;
            let stream = tokio::net::TcpStream::from_std(io).context("tunnel stream from_std")?;
            let _guard = ActiveGuard(Arc::clone(stats));
            run_tunnel(session, stream, rt, sid, peer, stats).await;
        },
        SessionRole::BondLink => {
            info!("session {sid:016x} ({peer}) bond link established");
            Box::pin(bond::register_link(
                session,
                io,
                sid,
                peer.to_owned(),
                agg,
                Arc::clone(stats),
            ))
            .await;
        },
    }
    Ok(())
}

/// Synchronous server handshake on the blocking pool. `allow_bond`
/// downgrades bond-link requests to mux tunnels (echoed as refused to the
/// client); returns the session's effective role learned from the client's
/// ivv, so the single-port caller can route the session.
fn handshake_sync(
    stream: TcpStream,
    rt: &ServerRuntime,
    sid: u128,
    handshaking: &AtomicU64,
    allow_bond: bool,
) -> anyhow::Result<(Session, TcpStream, SessionRole)> {
    pump::nodelay(&stream);
    // The tunnel stream is long-lived and the data plane clears all
    // timeouts; keepalive is the only dead-peer detection it has.
    pump::keepalive(&stream);
    stream.set_read_timeout(Some(rt.handshake_timeout))?;
    stream.set_write_timeout(Some(rt.handshake_timeout))?;
    let mut tx = Transmission::new(stream, Arc::clone(&rt.key));
    // The handshaking gauge covers exactly the pre-auth phase.
    let role = {
        let _guard = HandshakingGuard::new(handshaking);
        tx.handshake_server(sid, allow_bond)?
    };
    // Data plane: no timeouts (kernel keepalive covers dead peers).
    tx.io_mut().set_read_timeout(None)?;
    tx.io_mut().set_write_timeout(None)?;
    let (session, io) = tx.into_session();
    Ok((session, io, role))
}

/// Mux tunnel body: one writer task + this demux loop. Per-stream events
/// are routed through the registry; unknown streams get bounced a CLOSE so
/// neither side leaks registry entries after a race.
async fn run_tunnel(
    session: Session,
    stream: tokio::net::TcpStream,
    rt: &ServerRuntime,
    sid: u128,
    peer: &str,
    stats: &Arc<ServerStats>,
) {
    let (stx, srx) = session.split();
    let (rh, wh) = stream.into_split();
    let (out_tx, out_rx) = mpsc::channel::<OutFrame>(OUTBOUND_BOUND);
    let mut writer = tokio::spawn(tunnel::run_writer(
        TxWire::Session(Box::new(stx)),
        wh,
        out_rx,
    ));
    let reader = FrameReader::new(srx, rh);
    let subject = format!("session {sid:016x} ({peer})");
    run_demux(reader, &mut writer, out_tx, rt, &subject, stats).await;
}

/// Shared demux loop of plain and bonded tunnels: routes frames from any
/// mux carrier to per-stream pumps until the carrier or writer ends.
async fn run_demux<R: AsyncRead + Unpin>(
    mut reader: FrameReader<R>,
    writer: &mut tokio::task::JoinHandle<()>,
    out_tx: mpsc::Sender<OutFrame>,
    rt: &ServerRuntime,
    subject: &str,
    stats: &Arc<ServerStats>,
) {
    let registry = Registry::default();
    loop {
        tokio::select! {
            frame = reader.next() => match frame {
                Ok(Some(msg)) => match parse_frame(&msg) {
                    Ok((FrameKind::Open, stream, payload)) => handle_open(
                        &registry,
                        rt,
                        stream,
                        payload,
                        &out_tx,
                        stats,
                        subject,
                    ),
                    Ok((FrameKind::Data, stream, payload)) => {
                        route(&registry, stream, StreamEvent::Data(payload.to_vec()), &out_tx)
                            .await;
                    },
                    Ok((FrameKind::Eof, stream, _)) => {
                        route(&registry, stream, StreamEvent::Eof, &out_tx).await;
                    },
                    Ok((FrameKind::Close, stream, _)) => {
                        registry.lock().unwrap().remove(&stream);
                    },
                    Ok((FrameKind::Reply, ..)) => {
                        warn!("{subject} unexpected REPLY frame (client role violation)");
                        break;
                    },
                    Err(e) => {
                        warn!("{subject} bad mux frame: {e}");
                        break;
                    },
                },
                Ok(None) => {
                    debug!("{subject} tunnel closed (eof)");
                    break;
                },
                Err(e) => {
                    if pump::is_routine_core(&e) {
                        debug!("{subject} tunnel read ended: {e}");
                    } else {
                        warn!("{subject} tunnel read failed: {e}");
                    }
                    break;
                },
            },
            _ = &mut *writer => {
                debug!("{subject} tunnel writer ended");
                break;
            },
        }
    }
    writer.abort();
    // Dropping the registry closes every stream's event channel; the
    // stream tasks break out of pump_stream and drop their targets.
}

/// Routes one event to a stream pump, bouncing CLOSE on unknown/dead
/// streams so the peer's registry cannot leak after a close race. A
/// consumer that stops draining its channel closes only its own stream
/// (see [`STREAM_SEND_TIMEOUT`]) instead of parking the demux.
async fn route(
    registry: &Registry,
    stream: StreamId,
    ev: StreamEvent,
    out: &mpsc::Sender<OutFrame>,
) {
    let tx = registry.lock().unwrap().get(&stream).cloned();
    match tx {
        Some(tx) => {
            if let Ok(res) = tokio::time::timeout(STREAM_SEND_TIMEOUT, tx.send(ev)).await {
                if res.is_err() {
                    registry.lock().unwrap().remove(&stream);
                    let _ = out.try_send(OutFrame::bare(FrameKind::Close, stream));
                }
            } else {
                registry.lock().unwrap().remove(&stream);
                let _ = out.try_send(OutFrame::bare(FrameKind::Close, stream));
                debug!("stream {stream} stalled, closed");
            }
        },
        None => {
            let _ = out.try_send(OutFrame::bare(FrameKind::Close, stream));
        },
    }
}

/// Handles one OPEN frame: validates, registers and spawns the stream.
fn handle_open(
    registry: &Registry,
    rt: &ServerRuntime,
    stream: StreamId,
    payload: &[u8],
    out: &mpsc::Sender<OutFrame>,
    stats: &Arc<ServerStats>,
    subject: &str,
) {
    {
        let reg = registry.lock().unwrap();
        if reg.contains_key(&stream) {
            debug!("{subject} duplicate stream id {stream}");
            let _ = out.try_send(OutFrame::bare(FrameKind::Close, stream));
            return;
        }
        if let Some(cap) = rt.max_streams_per_conn
            && reg.len() as u64 >= cap
        {
            debug!("{subject} stream {stream} rejected: per-tunnel stream limit {cap}");
            let _ = out.try_send(OutFrame::bare(FrameKind::Close, stream));
            return;
        }
    }
    let addr = match ProxyAddr::decode(payload) {
        Ok(addr) => addr,
        Err(e) => {
            warn!("{subject} bad OPEN frame: {e}");
            let _ = out.try_send(OutFrame::bare(FrameKind::Close, stream));
            return;
        },
    };
    let (ev_tx, ev_rx) = mpsc::channel(STREAM_BOUND);
    registry.lock().unwrap().insert(stream, ev_tx);
    tokio::spawn(handle_stream(
        addr,
        stream,
        ev_rx,
        out.clone(),
        rt.clone(),
        Arc::clone(registry),
        Arc::clone(stats),
        subject.to_owned(),
    ));
}

/// One proxied stream: connect the target, REPLY, then pump.
async fn handle_stream(
    addr: ProxyAddr,
    stream: StreamId,
    events: mpsc::Receiver<StreamEvent>,
    out: mpsc::Sender<OutFrame>,
    rt: ServerRuntime,
    registry: Registry,
    stats: Arc<ServerStats>,
    subject: String,
) {
    let target = format!("{}:{}", addr.host.to_display(), addr.port);
    let started = Instant::now();
    let sock = match tunnel::tcp_connect(
        addr.host.clone(),
        addr.port,
        rt.connect_timeout,
        Arc::clone(&rt.dns),
    )
    .await
    {
        Ok(sock) => sock,
        Err(e) => {
            // Refused targets are client-side routing issues, not server
            // faults: info, not warn.
            info!("{subject} stream {stream} connect {target} failed: {e}");
            let _ = out
                .send(OutFrame::new(FrameKind::Reply, stream, vec![REPLY_REFUSED]))
                .await;
            registry.lock().unwrap().remove(&stream);
            return;
        },
    };
    let _ = sock.set_nodelay(true);
    if out
        .send(OutFrame::new(FrameKind::Reply, stream, vec![REPLY_OK]))
        .await
        .is_err()
    {
        registry.lock().unwrap().remove(&stream);
        return;
    }
    stats.sessions.fetch_add(1, Ordering::Relaxed);
    info!("{subject} stream {stream} -> {target}");

    let outcome = tunnel::pump_stream(sock, stream, events, out).await;
    // `local` is the target stream here, so `up` is target->client.
    stats
        .bytes_to_clients
        .fetch_add(outcome.up, Ordering::Relaxed);
    stats
        .bytes_to_targets
        .fetch_add(outcome.down, Ordering::Relaxed);
    tunnel::log_stream_close(
        &format!("{subject} stream {stream}"),
        &target,
        &outcome,
        started,
    );
    registry.lock().unwrap().remove(&stream);
}

#[cfg(test)]
mod tests {
    use super::should_log_failure;

    #[test]
    fn handshake_failure_log_rate_limit() {
        assert!(should_log_failure(1));
        for n in 2..64 {
            assert!(!should_log_failure(n), "n={n}");
        }
        assert!(should_log_failure(64));
        assert!(should_log_failure(128));
        assert!(!should_log_failure(129));
    }
}
