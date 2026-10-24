//! Async tunnel drivers for the event-driven data plane: one writer task
//! and one reader task per mux tunnel connection, fed by the
//! transport-free [`Session`] codec halves.
//!
//! The writer owns the tx cipher and the socket write half; every stream
//! queues [`OutFrame`]s onto a bounded channel (backpressure: a full
//! channel stalls the sending stream's local reader). The reader owns the
//! rx cipher and reassembles frames from the byte stream — one `read(2)`
//! may carry several frames or half of one, which the incremental
//! [`SessionRx::poll_frame`] absorbs.

use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use nextppp_core::{BASE94_MAX_FRAME, Error, SessionRx, SessionTx};
use spdlog::prelude::*;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc,
};

use crate::{
    fmt::{fmt_bytes, fmt_duration},
    mux::{FrameHeader, FrameKind, StreamId, decode_varint, encode_varint},
    pump::routine_cause,
};

/// Read chunk for tunnel sockets.
const READ_CHUNK: usize = 16 * 1024;

/// Read chunk for local (app/target) sockets in stream pumps.
const STREAM_CHUNK: usize = 16 * 1024;

/// Upper bound on the reassembly buffer. A frame's wire form can never
/// exceed `BASE94_MAX_FRAME` (+ the small headers); more buffered bytes
/// without a completed frame means a desynced or hostile peer.
const BUF_CAP: usize = BASE94_MAX_FRAME + 64;

/// Largest mux message accepted in prefix framing (see [`TxWire::Prefix`]).
pub const PREFIX_MAX_FRAME: usize = BASE94_MAX_FRAME;

/// Frames coalesced into one write(2) when the outbound channel has a
/// backlog (busy tunnels only; idle latency is unaffected because the
/// first frame never waits for batching).
const WRITE_BATCH: usize = 32;

/// One outbound mux frame queued for the tunnel writer task. The payload
/// is moved, not copied; encryption prepends the header in place.
pub struct OutFrame {
    /// Frame header (kind + varint stream id).
    pub header: FrameHeader,
    /// Frame payload (empty for EOF/CLOSE).
    pub payload: Vec<u8>,
}

impl OutFrame {
    /// Builds a frame with a moved payload.
    #[must_use]
    pub fn new(kind: FrameKind, stream: StreamId, payload: Vec<u8>) -> Self {
        Self {
            header: FrameHeader::new(kind, stream),
            payload,
        }
    }

    /// Builds a payload-less frame (EOF/CLOSE).
    #[must_use]
    pub fn bare(kind: FrameKind, stream: StreamId) -> Self {
        Self::new(kind, stream, Vec::new())
    }
}

/// Events delivered from a tunnel's demux to a per-stream pump.
#[derive(Debug)]
pub enum StreamEvent {
    /// Payload bytes from the peer.
    Data(Vec<u8>),
    /// Peer half-closed the stream.
    Eof,
    /// Peer aborted the stream.
    Close,
}

/// Per-frame wire encoding of a mux tunnel carrier.
pub enum TxWire {
    /// nextppp session frames: every mux message becomes one encrypted
    /// wire packet (plain single-socket tunnels).
    Session(Box<SessionTx>),
    /// `varint(len) || mux frame` length-prefixed messages (bonded
    /// carriers, where an aggregated channel replaces the session
    /// transport). The nextppp encryption lives in the links underneath.
    Prefix,
}

impl TxWire {
    /// Appends one complete wire message (header + payload) to `out`.
    fn encode(&mut self, out: &mut Vec<u8>, header: &[u8], payload: &[u8]) -> Result<(), Error> {
        match self {
            Self::Session(tx) => tx.encrypt_into_prefixed(out, header, payload),
            Self::Prefix => {
                let total = header.len() + payload.len();
                if total == 0 {
                    return Err(Error::ZeroLength);
                }
                if total > PREFIX_MAX_FRAME {
                    return Err(Error::FrameTooLarge { len: total });
                }
                let mut len = [0u8; 5];
                let n = encode_varint(u32::try_from(total).expect("bounded"), &mut len);
                out.extend_from_slice(&len[..n]);
                out.extend_from_slice(header);
                out.extend_from_slice(payload);
                Ok(())
            },
        }
    }
}

/// Tunnel writer task: drains the outbound channel, encodes and writes.
/// Returns when the channel closes (all senders dropped) or the carrier
/// fails; the write half is shut down either way so the peer sees a clean
/// end instead of a half-open tunnel.
#[cfg_attr(feature = "hotpath", hotpath::measure)]
pub async fn run_writer<W: AsyncWrite + Unpin>(
    mut wire: TxWire,
    mut sock: W,
    mut rx: mpsc::Receiver<OutFrame>,
) {
    let mut out = Vec::new();
    'outer: while let Some(first) = rx.recv().await {
        out.clear();
        if wire
            .encode(&mut out, first.header.as_slice(), &first.payload)
            .is_err()
        {
            break;
        }
        // Coalesce a backlog into one write; try_recv never awaits, so
        // the first frame's latency is untouched.
        for _ in 1..WRITE_BATCH {
            match rx.try_recv() {
                Ok(frame) => {
                    if wire
                        .encode(&mut out, frame.header.as_slice(), &frame.payload)
                        .is_err()
                    {
                        break 'outer;
                    }
                },
                Err(_) => break,
            }
        }
        if sock.write_all(&out).await.is_err() {
            break;
        }
        // Aggregated carriers hold unwritten bytes until an explicit flush
        // or their own flush delay; TCP flush is a no-op, so always flush
        // and keep both carriers at the same latency.
        if sock.flush().await.is_err() {
            break;
        }
    }
    let _ = sock.shutdown().await;
}

/// Per-frame wire decoding of a mux tunnel carrier (see [`TxWire`]).
enum RxWire {
    Session(Box<SessionRx>),
    Prefix,
}

/// Length prefix of the message at the front of `buf`, if fully readable:
/// `(message length, varint bytes)`.
fn peek_prefix(buf: &[u8]) -> Result<Option<(usize, usize)>, Error> {
    match decode_varint(buf) {
        Some((len, vlen)) => {
            if len == 0 {
                return Err(Error::ZeroLength);
            }
            if len as usize > PREFIX_MAX_FRAME {
                return Err(Error::FrameTooLarge { len: len as usize });
            }
            Ok(Some((len as usize, vlen)))
        },
        // An unterminated varint only needs more bytes when fewer than 5
        // are buffered; beyond that it can never decode.
        None if buf.len() >= 5 => Err(Error::InvalidFrame),
        None => Ok(None),
    }
}

/// Incremental frame reader over an async byte stream: owns the rx codec
/// (session framing) or the prefix parser and the reassembly buffer.
pub struct FrameReader<R> {
    wire: RxWire,
    sock: R,
    buf: Vec<u8>,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    /// Wraps a session rx half and a carrier read half (nextppp framing).
    #[must_use]
    pub fn new(session: SessionRx, sock: R) -> Self {
        Self {
            wire: RxWire::Session(Box::new(session)),
            sock,
            buf: Vec::new(),
        }
    }

    /// Length-prefix framing over an already decrypted carrier (bonded
    /// tunnels).
    #[must_use]
    pub fn prefix(sock: R) -> Self {
        Self {
            wire: RxWire::Prefix,
            sock,
            buf: Vec::new(),
        }
    }

    /// Reads the next complete mux message. `Ok(None)` is a clean tunnel
    /// EOF; `Err` is a transport failure or a protocol violation — either
    /// way the tunnel is dead.
    ///
    /// # Errors
    ///
    /// Transport I/O failure or frame decode (desync/tampering) failure.
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub async fn next(&mut self) -> Result<Option<Vec<u8>>, Error> {
        loop {
            match self.wire {
                RxWire::Session(ref mut session) => {
                    // The block ends the borrow: poll_frame borrows both
                    // the session and the buffer.
                    let decoded = {
                        match session.poll_frame(&mut self.buf) {
                            Ok(Some(msg)) => {
                                let frame = msg.to_vec();
                                let used = session.take_consumed();
                                self.buf.drain(..used);
                                Some(frame)
                            },
                            Ok(None) => None,
                            Err(e) => return Err(e),
                        }
                    };
                    if let Some(frame) = decoded {
                        return Ok(Some(frame));
                    }
                },
                RxWire::Prefix => {
                    if let Some((total, vlen)) = peek_prefix(&self.buf)?
                        && self.buf.len() >= vlen + total
                    {
                        let frame = self.buf[vlen..vlen + total].to_vec();
                        self.buf.drain(..vlen + total);
                        return Ok(Some(frame));
                    }
                },
            }
            if self.buf.len() > BUF_CAP {
                return Err(Error::InvalidFrame);
            }
            self.buf.reserve(READ_CHUNK);
            let n = self.sock.read_buf(&mut self.buf).await.map_err(Error::Io)?;
            if n == 0 {
                return Ok(None);
            }
        }
    }
}

/// Async wrapper around [`crate::dns::DnsCache`]-backed
/// [`crate::pump::tcp_connect`]: the sync resolver/connect runs on the
/// blocking thread pool so the runtime worker is never parked in
/// `getaddrinfo`.
///
/// # Errors
///
/// See [`crate::pump::tcp_connect`].
pub async fn tcp_connect(
    host: crate::addr::Host,
    port: u16,
    timeout: std::time::Duration,
    dns: Arc<crate::dns::DnsCache>,
) -> io::Result<TcpStream> {
    let stream =
        tokio::task::spawn_blocking(move || crate::pump::tcp_connect(&host, port, timeout, &dns))
            .await
            .map_err(io::Error::other)??;
    stream.set_nonblocking(true)?;
    TcpStream::from_std(stream)
}

// ---------------------------------------------------------------------------
// Per-stream pump
// ---------------------------------------------------------------------------

/// How one proxied stream terminated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEnd {
    /// Both directions half-closed cleanly (EOF exchanged both ways).
    Graceful,
    /// Routine teardown (reset, broken pipe, tunnel loss); the static
    /// cause feeds the close log.
    Closed(&'static str),
    /// Unexpected I/O failure worth a warning.
    Fault(String),
}

impl StreamEnd {
    /// Short cause string for logs.
    #[must_use]
    pub fn cause(&self) -> &str {
        match self {
            Self::Graceful => "eof",
            Self::Closed(why) => why,
            Self::Fault(e) => e.as_str(),
        }
    }

    /// Whether this end needs a warning rather than an info line.
    #[must_use]
    pub fn is_fault(&self) -> bool {
        matches!(self, Self::Fault(_))
    }

    /// Clean both-directions half-close: no CLOSE frame is sent on drop.
    #[must_use]
    pub fn is_graceful(&self) -> bool {
        matches!(self, Self::Graceful)
    }
}

/// Outcome of pumping one stream end to end.
#[derive(Debug)]
pub struct PumpOutcome {
    /// Bytes pumped local -> tunnel.
    pub up: u64,
    /// Bytes pumped tunnel -> local.
    pub down: u64,
    /// How the stream ended.
    pub end: StreamEnd,
}

fn classify_io_end(err: &io::Error) -> DirEnd {
    match routine_cause(err.kind()) {
        Some(cause) => DirEnd::Closed(cause),
        None => DirEnd::Fault(err.to_string()),
    }
}

/// How one pump direction terminated.
#[derive(Debug)]
enum DirEnd {
    /// Graceful in-band half-close (EOF sent/received): the sibling may
    /// still be legitimately active, so it is left running.
    Eof,
    /// Routine teardown (reset, broken pipe, tunnel loss); aborts the
    /// sibling — it can never make progress again.
    Closed(&'static str),
    /// Unexpected I/O failure worth a warning; aborts the sibling.
    Fault(String),
}

impl DirEnd {
    /// Whether the sibling direction may legitimately continue.
    fn graceful(&self) -> bool {
        matches!(self, Self::Eof)
    }
}

/// Local -> tunnel direction: wraps chunks in DATA frames, emits EOF on
/// local half-close, CLOSE on local faults. Byte count goes into `bytes`
/// so an aborted task's progress is not lost.
async fn pump_up(
    mut rd: tokio::net::tcp::OwnedReadHalf,
    stream: StreamId,
    out: mpsc::Sender<OutFrame>,
    bytes: Arc<AtomicU64>,
) -> DirEnd {
    let mut buf = vec![0u8; STREAM_CHUNK];
    loop {
        match rd.read(&mut buf).await {
            Ok(0) => {
                return match out.send(OutFrame::bare(FrameKind::Eof, stream)).await {
                    Ok(()) => DirEnd::Eof,
                    Err(_) => DirEnd::Closed("tunnel closed"),
                };
            },
            Ok(n) => {
                if out
                    .send(OutFrame::new(FrameKind::Data, stream, buf[..n].to_vec()))
                    .await
                    .is_err()
                {
                    return DirEnd::Closed("tunnel closed");
                }
                bytes.fetch_add(n as u64, Ordering::Relaxed);
            },
            Err(e) => {
                let _ = out.try_send(OutFrame::bare(FrameKind::Close, stream));
                return classify_io_end(&e);
            },
        }
    }
}

/// Tunnel -> local direction: unwraps DATA, forwards EOF as a local
/// write-side shutdown, ends on CLOSE or a dead tunnel (channel closed).
async fn pump_down(
    mut wr: tokio::net::tcp::OwnedWriteHalf,
    stream: StreamId,
    mut events: mpsc::Receiver<StreamEvent>,
    out: mpsc::Sender<OutFrame>,
    bytes: Arc<AtomicU64>,
) -> DirEnd {
    loop {
        match events.recv().await {
            // The demux dropped the sender: tunnel death or an abortive
            // close it already logged.
            None => return DirEnd::Closed("tunnel closed"),
            Some(StreamEvent::Data(data)) => {
                if let Err(e) = wr.write_all(&data).await {
                    let _ = out.try_send(OutFrame::bare(FrameKind::Close, stream));
                    return classify_io_end(&e);
                }
                bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
            },
            Some(StreamEvent::Eof) => {
                let _ = wr.shutdown().await;
                return DirEnd::Eof;
            },
            Some(StreamEvent::Close) => return DirEnd::Closed("peer reset"),
        }
    }
}

fn join_dir(r: Result<DirEnd, tokio::task::JoinError>) -> DirEnd {
    match r {
        Ok(end) => end,
        Err(e) if e.is_cancelled() => DirEnd::Closed("aborted"),
        Err(_) => DirEnd::Fault(String::from("stream pump panicked")),
    }
}

/// Pumps one local socket against a mux stream until either side closes.
///
/// Two independent direction tasks (the old two-thread pump's async
/// shape). They MUST be independent: a single task that blocks inside a
/// bounded-channel `send().await` cannot drain the inbound direction
/// meanwhile, which closes a backpressure cycle across both tunnel ends
/// and deadlocks bulk transfers. Coordination mirrors the old
/// `kill_session` contract: a graceful in-band half-close (EOF) leaves
/// the sibling running; any other end aborts it.
///
/// [`StreamEnd::Graceful`] means EOF went both ways; the caller must not
/// send CLOSE afterwards.
#[cfg_attr(feature = "hotpath", hotpath::measure)]
pub async fn pump_stream(
    local: TcpStream,
    stream: StreamId,
    events: mpsc::Receiver<StreamEvent>,
    out: mpsc::Sender<OutFrame>,
) -> PumpOutcome {
    let (rd, wr) = local.into_split();
    let up_bytes = Arc::new(AtomicU64::new(0));
    let down_bytes = Arc::new(AtomicU64::new(0));
    let mut up = tokio::spawn(pump_up(rd, stream, out.clone(), Arc::clone(&up_bytes)));
    let mut down = tokio::spawn(pump_down(wr, stream, events, out, Arc::clone(&down_bytes)));
    let (up_end, down_end) = tokio::select! {
        r = &mut up => {
            let up_end = join_dir(r);
            if up_end.graceful() {
                let down_end = join_dir(down.await);
                (up_end, down_end)
            } else {
                down.abort();
                (up_end, join_dir(down.await))
            }
        },
        r = &mut down => {
            let down_end = join_dir(r);
            if down_end.graceful() {
                let up_end = join_dir(up.await);
                (up_end, down_end)
            } else {
                up.abort();
                (join_dir(up.await), down_end)
            }
        },
    };
    let end = match (up_end, down_end) {
        (DirEnd::Eof, DirEnd::Eof) => StreamEnd::Graceful,
        // The first non-graceful end decides; abort-related seconds are
        // consequences, not causes.
        (DirEnd::Fault(e), _) | (_, DirEnd::Fault(e)) => StreamEnd::Fault(e),
        (DirEnd::Closed(c), _) | (_, DirEnd::Closed(c)) => StreamEnd::Closed(c),
    };
    PumpOutcome {
        up: up_bytes.load(Ordering::Relaxed),
        down: down_bytes.load(Ordering::Relaxed),
        end,
    }
}

/// Logs a pumped stream's teardown at `info`, escalating to `warn` on a
/// fault. `subject` identifies the owning connection (e.g.
/// `[1.2.3.4:5] stream 7` client-side, `session 0123.. stream 7` server-side).
pub fn log_stream_close(subject: &str, target: &str, o: &PumpOutcome, started: std::time::Instant) {
    let summary = format!(
        "up {} down {} in {} ({})",
        fmt_bytes(o.up),
        fmt_bytes(o.down),
        fmt_duration(started.elapsed()),
        o.end.cause(),
    );
    if let StreamEnd::Fault(fault) = &o.end {
        warn!("{subject} {target} aborted: {summary}, fault: {fault}");
    } else {
        info!("{subject} {target} closed: {summary}");
    }
}
