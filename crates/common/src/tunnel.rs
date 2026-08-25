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

use std::io;

use nextppp_core::{BASE94_MAX_FRAME, Error, SessionRx, SessionTx};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
};

use crate::mux::{FrameHeader, FrameKind, StreamId};

/// Read chunk for tunnel sockets.
const READ_CHUNK: usize = 16 * 1024;

/// Upper bound on the reassembly buffer. A frame's wire form can never
/// exceed `BASE94_MAX_FRAME` (+ the small headers); more buffered bytes
/// without a completed frame means a desynced or hostile peer.
const BUF_CAP: usize = BASE94_MAX_FRAME + 64;

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

/// Tunnel writer task: drains the outbound channel, encrypts and writes.
/// Returns when the channel closes (all senders dropped) or the socket
/// fails; the write half is shut down either way so the peer sees a clean
/// end instead of a half-open tunnel.
#[cfg_attr(feature = "hotpath", hotpath::measure)]
pub async fn run_writer<W: AsyncWrite + Unpin>(
    mut session: SessionTx,
    mut sock: W,
    mut rx: mpsc::Receiver<OutFrame>,
) {
    let mut out = Vec::new();
    'outer: while let Some(first) = rx.recv().await {
        out.clear();
        if session
            .encrypt_into_prefixed(&mut out, first.header.as_slice(), &first.payload)
            .is_err()
        {
            break;
        }
        // Coalesce a backlog into one write(2); try_recv never awaits, so
        // the first frame's latency is untouched.
        for _ in 1..WRITE_BATCH {
            match rx.try_recv() {
                Ok(frame) => {
                    if session
                        .encrypt_into_prefixed(&mut out, frame.header.as_slice(), &frame.payload)
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
    }
    let _ = sock.shutdown().await;
}

/// Incremental frame reader over an async byte stream: owns the rx cipher
/// and the reassembly buffer.
pub struct FrameReader<R> {
    session: SessionRx,
    sock: R,
    buf: Vec<u8>,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    /// Wraps a session rx half and a socket read half.
    #[must_use]
    pub fn new(session: SessionRx, sock: R) -> Self {
        Self {
            session,
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
            {
                // The borrow ends inside this scope: poll_frame borrows
                // both the session and the buffer.
                match self.session.poll_frame(&mut self.buf) {
                    Ok(Some(msg)) => {
                        let frame = msg.to_vec();
                        let used = self.session.take_consumed();
                        self.buf.drain(..used);
                        return Ok(Some(frame));
                    },
                    Ok(None) => {},
                    Err(e) => return Err(e),
                }
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
    dns: std::sync::Arc<crate::dns::DnsCache>,
) -> io::Result<tokio::net::TcpStream> {
    let stream =
        tokio::task::spawn_blocking(move || crate::pump::tcp_connect(&host, port, timeout, &dns))
            .await
            .map_err(io::Error::other)??;
    stream.set_nonblocking(true)?;
    tokio::net::TcpStream::from_std(stream)
}
