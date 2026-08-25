//! Mux tunnel pool (B8): a few long-lived tunnels to the server, kept hot
//! by a background maintainer; every SOCKS CONNECT opens a mux stream on
//! the least-loaded tunnel instead of paying a TCP connect + handshake
//! per request.
//!
//! Tradeoff (see `docs/extreme-network-optimization.md`): pooling removes
//! the per-connect ~3 RTT setup tax and the thread/fd cost of bursty
//! connects, but streams on one tunnel share its TCP loss fate (HOL).
//! `pool_size` + least-loaded assignment bounds the blast radius, and a
//! dead tunnel fails only its own streams while the maintainer dials a
//! replacement. `pool_size = 0` disables pooling: one dedicated tunnel
//! per CONNECT (full loss isolation, the pre-mux behavior).
//!
//! Lifecycle: `Tunnel::mark_dead` (reader task or a failed OPEN send)
//! flips `alive`, fails every pending OPEN (dropping the oneshot senders)
//! and every live stream (dropping the event senders), then wakes the
//! maintainer to refill. All of it is idempotent via `AtomicBool::swap`.

use std::{
    collections::HashMap,
    net::TcpStream,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::Context;
use nextppp_common::{
    addr::ProxyAddr,
    fmt_duration,
    mux::{FrameKind, REPLY_OK, StreamId, parse_frame},
    pump,
    tunnel::{self, FrameReader, OutFrame, StreamEvent},
};
use nextppp_core::{Session, Transmission};
use spdlog::prelude::*;
use tokio::sync::{Notify, mpsc, oneshot};

use crate::ClientRuntime;

/// Per-tunnel outbound channel bound (frames).
const OUTBOUND_BOUND: usize = 256;

/// Per-stream event channel bound (frames).
const STREAM_BOUND: usize = 32;

/// Delay between pool refill rounds while dials keep failing.
const DIAL_RETRY_DELAY: Duration = Duration::from_secs(1);

/// Idle sweep interval: re-checks pool liveness when nothing notified.
const MAINTAIN_IDLE_SLEEP: Duration = Duration::from_secs(30);

/// The server answered REPLY REFUSED: the target itself is unreachable
/// from the server — a deterministic verdict that redialing cannot change.
#[derive(Debug, thiserror::Error)]
#[error("server refused connection to {0}")]
struct RefusedTarget(String);

/// Pool of mux tunnels plus the notifications that coordinate waiters.
#[derive(Clone)]
pub struct Pool {
    rt: Arc<ClientRuntime>,
    inner: Arc<PoolInner>,
}

struct PoolInner {
    tunnels: Mutex<Vec<Arc<Tunnel>>>,
    /// Dials currently in flight; counted alongside live tunnels so
    /// concurrent refill rounds cannot overshoot `pool_size`.
    dialing: AtomicU32,
    /// A tunnel joined the pool (open_stream waiters wake up).
    added: Notify,
    /// A tunnel died (the maintainer wakes up to refill). Notified with
    /// `notify_one`, which stores a permit: `notify_waiters` would lose
    /// deaths that happen between the maintainer's loop iterations and
    /// stall refills until the idle sweep.
    died: Notify,
}

impl Pool {
    /// Creates the pool and spawns its maintainer (unless pooling is
    /// disabled with `pool_size = 0`). Must be called on the runtime.
    #[must_use]
    pub fn new(rt: &Arc<ClientRuntime>) -> Self {
        let pool = Self {
            rt: Arc::clone(rt),
            inner: Arc::new(PoolInner {
                tunnels: Mutex::new(Vec::new()),
                dialing: AtomicU32::new(0),
                added: Notify::new(),
                died: Notify::new(),
            }),
        };
        if rt.pool_size > 0 {
            tokio::spawn(maintain(Arc::clone(&pool.inner), Arc::clone(rt)));
        }
        pool
    }

    /// Opens a mux stream to `addr`: picks the least-loaded live tunnel,
    /// waits for the maintainer when the pool is empty, and dials a
    /// dedicated tunnel when pooling is disabled.
    ///
    /// Budgets are per phase, each a full `connect_timeout`: waiting for a
    /// pool tunnel, dialing (with retries) and the OPEN/REPLY exchange
    /// never eat into each other. A single shared deadline made every
    /// slow-recovered dial (blackholed first attempt, retry succeeds) fail
    /// with a fake REPLY timeout — the dial had already spent the whole
    /// budget.
    ///
    /// # Errors
    ///
    /// Target refused by the server, or no usable tunnel within
    /// `connect_timeout`.
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub async fn open_stream(&self, addr: &ProxyAddr) -> anyhow::Result<Stream> {
        if self.rt.pool_size == 0 {
            return self.open_dedicated(addr).await;
        }
        // The pool-wait phase is bounded once, from entry; every dial and
        // OPEN exchange below carries a budget of its own.
        let wait_deadline = Instant::now() + self.rt.connect_timeout;
        loop {
            let Some(tunnel) = self.pick() else {
                // Kick the maintainer (it may be idling) and wait for a
                // tunnel to arrive.
                self.inner.died.notify_one();
                let remaining = wait_deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero()
                    || tokio::time::timeout(remaining, self.inner.added.notified())
                        .await
                        .is_err()
                {
                    anyhow::bail!(
                        "no pool tunnel to {}:{} within {}",
                        self.rt.server_host.to_display(),
                        self.rt.server_port,
                        fmt_duration(self.rt.connect_timeout),
                    );
                }
                continue;
            };
            match tunnel.open(addr, self.rt.connect_timeout).await {
                Ok(stream) => return Ok(stream),
                // Tunnel died mid-open: drop it and try another one.
                Err(e) if !tunnel.alive() => {
                    self.inner
                        .tunnels
                        .lock()
                        .unwrap()
                        .retain(|t| !Arc::ptr_eq(t, &tunnel));
                    debug!("pool tunnel {:016x} dropped during open: {e:#}", tunnel.id);
                },
                Err(e) => return Err(e),
            }
        }
    }

    /// Dials a tunnel dedicated to this one stream (pooling disabled) and
    /// runs the OPEN on it. Dedicated tunnels die with their single stream.
    async fn open_dedicated(&self, addr: &ProxyAddr) -> anyhow::Result<Stream> {
        let (session, io) = dial(&self.rt).await?;
        let tunnel = spawn_tunnel(session, io, Weak::new())?;
        tunnel.open(addr, self.rt.connect_timeout).await
    }

    /// Least-loaded live tunnel with stream capacity left.
    fn pick(&self) -> Option<Arc<Tunnel>> {
        self.inner
            .tunnels
            .lock()
            .unwrap()
            .iter()
            .filter(|t| t.alive() && t.streams.load(Ordering::Relaxed) < self.rt.max_streams)
            .min_by_key(|t| t.streams.load(Ordering::Relaxed))
            .cloned()
    }
}

/// One mux tunnel: the writer channel, the OPEN waiters and the live
/// stream registry shared with the reader task.
pub struct Tunnel {
    /// Server-assigned session id (log correlation).
    id: u128,
    out: mpsc::Sender<OutFrame>,
    registry: Mutex<HashMap<StreamId, mpsc::Sender<StreamEvent>>>,
    pending: Mutex<HashMap<StreamId, oneshot::Sender<bool>>>,
    next_stream: AtomicU32,
    /// Open streams; drives least-loaded assignment and the per-tunnel cap.
    streams: AtomicU32,
    alive: AtomicBool,
    /// Reader task handle; dedicated tunnels abort it when their stream
    /// ends. Pooled tunnels are reaped by the maintainer instead.
    reader: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Back-reference for death notification (`Weak::new()` on dedicated
    /// tunnels, which are never pooled).
    pool: Weak<PoolInner>,
}

impl Tunnel {
    fn alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    /// Idempotent teardown: fail pending OPENs and live streams, wake the
    /// maintainer. See the module docs.
    fn mark_dead(&self) {
        if !self.alive.swap(false, Ordering::Relaxed) {
            return;
        }
        self.pending.lock().unwrap().clear();
        self.registry.lock().unwrap().clear();
        if let Some(pool) = self.pool.upgrade() {
            pool.died.notify_one();
        }
    }

    fn alloc_stream(&self) -> StreamId {
        // 0 is avoided so a varint-0 wire id always means "real stream".
        self.next_stream
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
    }

    /// Removes every trace of a stream and frees its load slot.
    fn unregister(&self, sid: StreamId) {
        self.pending.lock().unwrap().remove(&sid);
        self.registry.lock().unwrap().remove(&sid);
        self.streams.fetch_sub(1, Ordering::Relaxed);
    }

    /// Sends OPEN and waits for the server's REPLY under a budget of
    /// `budget` starting now (see [`Pool::open_stream`] for why the budget
    /// is per exchange).
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn open(
        self: &Arc<Tunnel>,
        addr: &ProxyAddr,
        budget: Duration,
    ) -> anyhow::Result<Stream> {
        let deadline = Instant::now() + budget;
        let sid = self.alloc_stream();
        let (reply_tx, reply_rx) = oneshot::channel();
        let (ev_tx, ev_rx) = mpsc::channel(STREAM_BOUND);
        self.pending.lock().unwrap().insert(sid, reply_tx);
        self.registry.lock().unwrap().insert(sid, ev_tx);
        self.streams.fetch_add(1, Ordering::Relaxed);

        let mut payload = Vec::new();
        addr.encode_into(&mut payload);
        if self
            .out
            .send(OutFrame::new(FrameKind::Open, sid, payload))
            .await
            .is_err()
        {
            self.unregister(sid);
            self.mark_dead();
            anyhow::bail!("tunnel {:016x} closed before OPEN", self.id);
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(remaining, reply_rx).await {
            Ok(Ok(true)) => Ok(Stream {
                sid,
                tunnel: Arc::clone(self),
                events: ev_rx,
                graceful: false,
            }),
            Ok(Ok(false)) => {
                self.unregister(sid);
                Err(RefusedTarget(format!("{}:{}", addr.host.to_display(), addr.port)).into())
            },
            // Pending waiters are dropped by mark_dead: the tunnel is dead.
            Ok(Err(_)) => {
                self.unregister(sid);
                anyhow::bail!("tunnel {:016x} died while opening stream {sid}", self.id)
            },
            Err(_) => {
                self.unregister(sid);
                let _ = self.out.try_send(OutFrame::bare(FrameKind::Close, sid));
                anyhow::bail!(
                    "stream {sid} to {}:{}: REPLY timed out",
                    addr.host.to_display(),
                    addr.port,
                )
            },
        }
    }
}

/// A live mux stream on a pool tunnel. Drop closes it: `CLOSE` unless the
/// pump marked the exchange graceful (EOF both ways); dedicated tunnels
/// are torn down with it.
pub struct Stream {
    sid: StreamId,
    tunnel: Arc<Tunnel>,
    /// Incoming events from the tunnel demux (moved into the pump).
    pub events: mpsc::Receiver<StreamEvent>,
    graceful: bool,
}

impl Stream {
    /// Stream id within the tunnel.
    #[must_use]
    pub fn sid(&self) -> StreamId {
        self.sid
    }

    /// Outbound frame channel of the owning tunnel.
    #[must_use]
    pub fn out(&self) -> &mpsc::Sender<OutFrame> {
        &self.tunnel.out
    }

    /// Moves the event receiver out for the pump (the stream handle stays
    /// in charge of deregistration).
    #[must_use]
    pub fn take_events(&mut self) -> mpsc::Receiver<StreamEvent> {
        // The placeholder channel is never used: the pump owns the real
        // receiver for the rest of the stream's life.
        std::mem::replace(&mut self.events, mpsc::channel(1).1)
    }

    /// Marks a clean both-directions close; suppresses the drop-time CLOSE.
    pub fn mark_graceful(&mut self) {
        self.graceful = true;
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.tunnel.unregister(self.sid);
        if !self.graceful {
            let _ = self
                .tunnel
                .out
                .try_send(OutFrame::bare(FrameKind::Close, self.sid));
        }
        // Dedicated tunnels (no pool back-reference) die with their stream.
        if self.tunnel.pool.strong_count() == 0 {
            if let Some(reader) = self.tunnel.reader.lock().unwrap().take() {
                reader.abort();
            }
        }
    }
}

/// Dials one tunnel with `connect_retries` attempts on routine transport
/// failures (each attempt a fresh TCP connection; DNS hits the cache).
async fn dial(rt: &Arc<ClientRuntime>) -> anyhow::Result<(Session, TcpStream)> {
    let rt = Arc::clone(rt);
    tokio::task::spawn_blocking(move || dial_sync(&rt))
        .await
        .context("dial task join")?
}

fn dial_sync(rt: &ClientRuntime) -> anyhow::Result<(Session, TcpStream)> {
    let mut attempt = 0u32;
    loop {
        match dial_once(rt) {
            Ok(v) => return Ok(v),
            Err(e) => {
                if attempt >= rt.connect_retries || !retryable(&e) {
                    return Err(e);
                }
                attempt += 1;
                debug!(
                    "tunnel dial to {}:{} failed ({e:#}); retry {attempt}/{}",
                    rt.server_host.to_display(),
                    rt.server_port,
                    rt.connect_retries,
                );
            },
        }
    }
}

fn dial_once(rt: &ClientRuntime) -> anyhow::Result<(Session, TcpStream)> {
    let started = Instant::now();
    let stream = pump::tcp_connect(&rt.server_host, rt.server_port, rt.connect_timeout, &rt.dns)
        .with_context(|| {
            format!(
                "connect server {}:{}",
                rt.server_host.to_display(),
                rt.server_port
            )
        })?;
    pump::nodelay(&stream);
    // Bound the whole handshake exchange by the connect timeout.
    stream.set_read_timeout(Some(rt.connect_timeout))?;
    stream.set_write_timeout(Some(rt.connect_timeout))?;
    let mut tx = Transmission::new(stream, Arc::clone(&rt.server_key));
    tx.handshake_client().context("nextppp handshake")?;
    // Data plane: no timeouts (kernel keepalive, set by `tcp_connect`,
    // covers dead-peer detection instead).
    tx.io_mut().set_read_timeout(None)?;
    tx.io_mut().set_write_timeout(None)?;
    let sid = tx.session_id();
    debug!(
        "pool tunnel {sid:016x} to {}:{} handshaked in {}",
        rt.server_host.to_display(),
        rt.server_port,
        fmt_duration(started.elapsed()),
    );
    Ok(tx.into_session())
}

/// Whether a failed dial attempt is worth retrying with a fresh TCP
/// connection: routine transport teardown (RST, timeout, refused SYN) is;
/// misconfiguration (`FlagsMismatch`) is deterministic and must not burn
/// retries.
fn retryable(err: &anyhow::Error) -> bool {
    if pump::is_clean_close(err) {
        return true;
    }
    // A SYN answered with RST surfaces as ECONNREFUSED (connect), which
    // `is_clean_close` deliberately does not classify as routine teardown.
    err.chain().any(|c| {
        c.downcast_ref::<std::io::Error>()
            .is_some_and(|e| e.kind() == std::io::ErrorKind::ConnectionRefused)
    })
}

/// Splits a dialed session into the writer/reader task pair of a tunnel.
fn spawn_tunnel(
    session: Session,
    io: TcpStream,
    pool: Weak<PoolInner>,
) -> anyhow::Result<Arc<Tunnel>> {
    io.set_nonblocking(true).context("nonblocking mode")?;
    let sock = tokio::net::TcpStream::from_std(io).context("tunnel stream from_std")?;
    let id = session.session_id();
    let (stx, srx) = session.split();
    let (rh, wh) = sock.into_split();
    let (out_tx, out_rx) = mpsc::channel(OUTBOUND_BOUND);
    let writer = tokio::spawn(tunnel::run_writer(stx, wh, out_rx));
    let tunnel = Arc::new(Tunnel {
        id,
        out: out_tx,
        registry: Mutex::new(HashMap::new()),
        pending: Mutex::new(HashMap::new()),
        next_stream: AtomicU32::new(0),
        streams: AtomicU32::new(0),
        alive: AtomicBool::new(true),
        reader: Mutex::new(None),
        pool,
    });
    let reader = tokio::spawn(run_reader(
        Arc::clone(&tunnel),
        FrameReader::new(srx, rh),
        writer,
    ));
    *tunnel.reader.lock().unwrap() = Some(reader);
    Ok(tunnel)
}

/// Tunnel reader task: demultiplexes frames into OPEN replies and
/// per-stream events.
async fn run_reader(
    tunnel: Arc<Tunnel>,
    mut reader: FrameReader<tokio::net::tcp::OwnedReadHalf>,
    mut writer: tokio::task::JoinHandle<()>,
) {
    let subject = format!("tunnel {:016x}", tunnel.id);
    loop {
        tokio::select! {
            frame = reader.next() => match frame {
                Ok(Some(msg)) => match parse_frame(&msg) {
                    Ok((FrameKind::Reply, sid, payload)) => {
                        let tx = tunnel.pending.lock().unwrap().remove(&sid);
                        if let Some(tx) = tx {
                            let _ = tx.send(payload.first() == Some(&REPLY_OK));
                        }
                    },
                    Ok((FrameKind::Data, sid, payload)) => {
                        route_event(&tunnel, sid, StreamEvent::Data(payload.to_vec())).await;
                    },
                    Ok((FrameKind::Eof, sid, _)) => {
                        route_event(&tunnel, sid, StreamEvent::Eof).await;
                    },
                    Ok((FrameKind::Close, sid, _)) => {
                        // Dropping the sender ends the stream's pump.
                        tunnel.registry.lock().unwrap().remove(&sid);
                    },
                    Ok((FrameKind::Open, ..)) => {
                        warn!("{subject} server sent OPEN (role violation)");
                        break;
                    },
                    Err(e) => {
                        warn!("{subject} bad mux frame: {e}");
                        break;
                    },
                },
                Ok(None) => {
                    debug!("{subject} closed (eof)");
                    break;
                },
                Err(e) => {
                    if pump::is_routine_core(&e) {
                        debug!("{subject} read ended: {e}");
                    } else {
                        warn!("{subject} read failed: {e}");
                    }
                    break;
                },
            },
            _ = &mut writer => {
                debug!("{subject} writer ended");
                break;
            },
        }
    }
    writer.abort();
    tunnel.mark_dead();
}

/// Routes one event to a stream pump, bouncing CLOSE on unknown/dead
/// streams so the server's registry cannot leak after a close race.
async fn route_event(tunnel: &Tunnel, sid: StreamId, ev: StreamEvent) {
    let tx = tunnel.registry.lock().unwrap().get(&sid).cloned();
    match tx {
        Some(tx) => {
            if tx.send(ev).await.is_err() {
                tunnel.registry.lock().unwrap().remove(&sid);
                let _ = tunnel.out.try_send(OutFrame::bare(FrameKind::Close, sid));
            }
        },
        None => {
            let _ = tunnel.out.try_send(OutFrame::bare(FrameKind::Close, sid));
        },
    }
}

/// Pool maintainer: keeps `pool_size` live tunnels. Refill rounds are
/// paced by DIAL_RETRY_DELAY so a dead server cannot spin the dial loop;
/// a tunnel death wakes the maintainer immediately.
async fn maintain(inner: Arc<PoolInner>, rt: Arc<ClientRuntime>) {
    loop {
        let live = {
            let mut tunnels = inner.tunnels.lock().unwrap();
            tunnels.retain(|t| t.alive());
            u32::try_from(tunnels.len()).unwrap_or(u32::MAX)
        };
        // In-flight dials count towards the target: without this, a dial
        // completing mid-round makes the next round spawn one too many.
        let dialing = inner.dialing.load(Ordering::Relaxed);
        let short = rt.pool_size.saturating_sub(live + dialing);
        if short == 0 {
            tokio::select! {
                () = inner.died.notified() => {},
                () = tokio::time::sleep(MAINTAIN_IDLE_SLEEP) => {},
            }
            continue;
        }
        for _ in 0..short {
            let inner = Arc::clone(&inner);
            let rt = Arc::clone(&rt);
            inner.dialing.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                let _dialing = DialingGuard(&inner);
                match dial(&rt).await {
                    Ok((session, io)) => match spawn_tunnel(session, io, Arc::downgrade(&inner)) {
                        Ok(tunnel) => {
                            inner.tunnels.lock().unwrap().push(tunnel);
                            inner.added.notify_waiters();
                        },
                        Err(e) => debug!("pool tunnel setup failed: {e:#}"),
                    },
                    Err(e) => debug!("pool dial failed: {e:#}"),
                }
            });
        }
        tokio::select! {
            () = inner.added.notified() => {},
            () = inner.died.notified() => {},
            () = tokio::time::sleep(DIAL_RETRY_DELAY) => {},
        }
    }
}

/// Decrements the in-flight dial counter when a dial task ends.
struct DialingGuard<'a>(&'a Arc<PoolInner>);

impl Drop for DialingGuard<'_> {
    fn drop(&mut self) {
        self.0.dialing.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use nextppp_core::Error as CoreError;

    use super::*;

    #[test]
    fn retryable_classification() {
        // Routine transport teardown: retry.
        let reset: anyhow::Error = CoreError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "reset",
        ))
        .into();
        assert!(retryable(&reset));
        // Refused SYN (RST attack on connect): retry.
        let refused_syn: anyhow::Error =
            std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused").into();
        assert!(retryable(&refused_syn));
        // Deterministic failures: never retry.
        let flags: anyhow::Error = CoreError::FlagsMismatch.into();
        assert!(!retryable(&flags));
        // Unknown/bare errors: no recognized cause, not retryable.
        assert!(!retryable(&anyhow::anyhow!("mystery")));
    }
}
