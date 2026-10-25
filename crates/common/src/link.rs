//! Async carrier adapters around the transport-free [`Session`] codec.
//!
//! A bonded tunnel's links are plain nextppp sessions whose decrypted byte
//! stream is driven by the link aggregator (aggligator), which requires
//! `AsyncRead`/`AsyncWrite` IO. [`LinkReadHalf`] / [`LinkWriteHalf`] provide
//! exactly that: they own a session codec half plus the matching socket half
//! and expose the decrypted frame stream as one async byte stream. On the
//! wire a link is indistinguishable from a plain tunnel.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
    time::Duration,
};

use nextppp_core::{Error, PPP_BUFFER_SIZE, Session, SessionRx, SessionTx};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Upper bound on buffered wire bytes: a frame's wire form can never exceed
/// `BASE94_MAX_FRAME` (+ small headers); more without a completed frame
/// means a desynced or hostile peer.
const WIRE_CAP: usize = nextppp_core::BASE94_MAX_FRAME + 64;

/// Bytes pulled from the carrier per read (via a reusable scratch buffer;
/// tokio exposes no poll-level `read_buf` for `Vec` growth).
const READ_CHUNK: usize = 16 * 1024;

fn core_to_io(e: Error) -> io::Error {
    match e {
        Error::Io(e) => e,
        e => io::Error::new(io::ErrorKind::InvalidData, e),
    }
}

/// Receiving half of a link: decrypts nextppp frames off the carrier and
/// serves the plaintext as an async byte stream.
pub struct LinkReadHalf<R> {
    session: SessionRx,
    sock: R,
    /// Wire bytes read but not yet decoded into a complete frame.
    wire: Vec<u8>,
    /// Reusable carrier read buffer.
    scratch: Vec<u8>,
    /// Decrypted frame bytes not yet handed to the caller. Serving from a
    /// plain buffer (instead of re-polling the codec) is what makes partial
    /// deliveries safe: a re-parsed binary frame would decrypt its header a
    /// second time and desync the cipher.
    plain: Vec<u8>,
    plain_off: usize,
}

impl<R> LinkReadHalf<R> {
    /// Wraps a session rx half and the carrier's read half.
    #[must_use]
    pub fn new(session: SessionRx, sock: R) -> Self {
        Self {
            session,
            sock,
            wire: Vec::new(),
            scratch: vec![0u8; READ_CHUNK],
            plain: Vec::new(),
            plain_off: 0,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for LinkReadHalf<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.plain_off < this.plain.len() {
                let end = this.plain.len();
                let n = buf.remaining().min(end - this.plain_off);
                let off = this.plain_off;
                buf.put_slice(&this.plain[off..off + n]);
                this.plain_off += n;
                if this.plain_off == end {
                    this.plain.clear();
                    this.plain_off = 0;
                }
                return Poll::Ready(Ok(()));
            }
            match this.session.poll_frame(&mut this.wire) {
                // The frame borrows `wire` (binary framing decrypts in
                // place), so copy it out before draining the wire bytes.
                Ok(Some(msg)) => {
                    // `msg` borrows both the session and `wire`; end that
                    // borrow before re-borrowing them below.
                    this.plain.clear();
                    this.plain.extend_from_slice(msg);
                    this.plain_off = 0;
                    let used = this.session.take_consumed();
                    this.wire.drain(..used);
                },
                Ok(None) => {
                    if this.wire.len() > WIRE_CAP {
                        return Poll::Ready(Err(core_to_io(Error::InvalidFrame)));
                    }
                    let mut rb = ReadBuf::new(&mut this.scratch);
                    match Pin::new(&mut this.sock).poll_read(cx, &mut rb) {
                        Poll::Ready(Ok(())) => {
                            let n = rb.filled().len();
                            if n == 0 {
                                // A parsed-but-undelivered binary frame
                                // leaves `wire` empty (the codec drained
                                // the 3 header bytes), so the mid-frame
                                // state must also gate the clean-EOF
                                // decision.
                                return if this.wire.is_empty() && !this.session.is_frame_pending() {
                                    Poll::Ready(Ok(()))
                                } else {
                                    Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "link eof inside a frame",
                                    )))
                                };
                            }
                            this.wire.extend_from_slice(&this.scratch[..n]);
                        },
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                },
                Err(e) => return Poll::Ready(Err(core_to_io(e))),
            }
        }
    }
}

/// Sending half of a link: encrypts written bytes into nextppp frames and
/// pushes them onto the carrier.
pub struct LinkWriteHalf<W> {
    session: SessionTx,
    sock: W,
    /// One encoded wire frame in flight to the carrier. Input is only
    /// accepted once the previous frame fully left, which bounds buffering
    /// to a single frame.
    out: Vec<u8>,
    out_off: usize,
}

impl<W> LinkWriteHalf<W> {
    /// Wraps a session tx half and the carrier's write half.
    #[must_use]
    pub fn new(session: SessionTx, sock: W) -> Self {
        Self {
            session,
            sock,
            out: Vec::new(),
            out_off: 0,
        }
    }
}

/// Drives the pending frame fully onto the carrier.
fn flush_out<W: AsyncWrite + Unpin>(
    sock: &mut W,
    out: &mut Vec<u8>,
    out_off: &mut usize,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    while *out_off < out.len() {
        let n = ready!(Pin::new(&mut *sock).poll_write(cx, &out[*out_off..]))?;
        if n == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "link carrier wrote zero bytes",
            )));
        }
        *out_off += n;
    }
    out.clear();
    *out_off = 0;
    Poll::Ready(Ok(()))
}

impl<W: AsyncWrite + Unpin> AsyncWrite for LinkWriteHalf<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.out_off < this.out.len() {
            ready!(flush_out(
                &mut this.sock,
                &mut this.out,
                &mut this.out_off,
                cx
            ))?;
        }
        let len = buf.len().min(PPP_BUFFER_SIZE);
        if len == 0 {
            return Poll::Ready(Ok(0));
        }
        this.session
            .encrypt_into(&mut this.out, &buf[..len])
            .map_err(core_to_io)?;
        this.out_off = 0;
        // Push what the carrier accepts right away; a partial push just
        // delays the next accepted input until this frame is out.
        if let Poll::Ready(Err(e)) = flush_out(&mut this.sock, &mut this.out, &mut this.out_off, cx)
        {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(flush_out(
            &mut this.sock,
            &mut this.out,
            &mut this.out_off,
            cx
        ))?;
        Pin::new(&mut this.sock).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(flush_out(
            &mut this.sock,
            &mut this.out,
            &mut this.out_off,
            cx
        ))?;
        Pin::new(&mut this.sock).poll_shutdown(cx)
    }
}

/// Splits a handshaked session and its (blocking-mode) TCP stream into the
/// async link halves the aggregator consumes.
///
/// # Errors
///
/// Nonblocking-mode switch or tokio conversion failure.
pub fn split_link(
    session: Session,
    io: std::net::TcpStream,
) -> io::Result<(
    LinkReadHalf<tokio::net::tcp::OwnedReadHalf>,
    LinkWriteHalf<tokio::net::tcp::OwnedWriteHalf>,
)> {
    io.set_nonblocking(true)?;
    let sock = tokio::net::TcpStream::from_std(io)?;
    let (stx, srx) = session.split();
    let (rh, wh) = sock.into_split();
    Ok((LinkReadHalf::new(srx, rh), LinkWriteHalf::new(stx, wh)))
}

/// Link-aggregator configuration shared by the client and server bond
/// paths. Throughput-oriented: the latency path never rides bonded tunnels
/// (the bond inbound exists precisely to keep both strategies available).
#[must_use]
pub fn bond_cfg() -> aggligator::Cfg {
    aggligator::Cfg {
        // All links dying must fail the channel quickly so the owner
        // redials a fresh tunnel; the default 120 s would pin streams on a
        // dead channel.
        no_link_timeout: Duration::from_secs(15),
        // The per-link counter probe only burns time and bandwidth inside
        // an already encrypted carrier; handshake RTT and pings measure
        // links.
        link: aggligator::LinkCfg {
            test_data_limit: 0,
            ..aggligator::LinkCfg::default()
        },
        // One aggregator chunk per full 64 KiB nextppp frame: minimal
        // per-chunk overhead for bulk streams.
        io_write_size: std::num::NonZeroUsize::new(PPP_BUFFER_SIZE).unwrap(),
        ..aggligator::Cfg::default()
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Write as _, net::TcpListener, sync::Arc};

    use nextppp_core::{SessionRole, Transmission};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// One handshaked session pair over loopback TCP (server on its own
    /// thread: both handshakes block on each other's packets).
    fn session_pair() -> (Session, std::net::TcpStream, Session, std::net::TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(addr).unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut s =
                Transmission::new(stream, Arc::new(nextppp_core::ObfuscationKey::default()));
            s.handshake_server(0x1234, true).unwrap();
            s.into_session()
        });
        let mut c = Transmission::new(client, Arc::new(nextppp_core::ObfuscationKey::default()));
        c.handshake_client(SessionRole::BondLink).unwrap();
        let (cs, cio) = c.into_session();
        let (ss, sio) = server.join().unwrap();
        (cs, cio, ss, sio)
    }

    #[tokio::test]
    async fn link_roundtrip_and_partial_delivery() {
        let (cs, cio, ss, sio) = session_pair();
        let (mut cread, mut cwrite) = split_link(cs, cio).unwrap();
        let (mut sread, mut swrite) = split_link(ss, sio).unwrap();

        // Three frames in one burst; delivered across many small reads must
        // reassemble exactly (partial-delivery path of `plain`).
        let payloads: Vec<Vec<u8>> = vec![vec![7u8; 1000], vec![8u8; 4096], vec![9u8; 17]];
        for p in &payloads {
            swrite.write_all(p).await.unwrap();
        }
        swrite.flush().await.unwrap();

        let mut got = Vec::new();
        let mut chunk = [0u8; 333]; // deliberately not frame-aligned
        let expected: usize = payloads.iter().map(Vec::len).sum();
        while got.len() < expected {
            let n = cread.read(&mut chunk).await.unwrap();
            assert!(n > 0, "unexpected eof");
            got.extend_from_slice(&chunk[..n]);
        }
        let want: Vec<u8> = payloads.concat();
        assert_eq!(got, want);

        // Client direction still works afterwards (cipher state stayed in
        // sync through the partial deliveries).
        cwrite.write_all(b"reply").await.unwrap();
        cwrite.flush().await.unwrap();
        let mut buf = [0u8; 16];
        let n = sread.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"reply");
    }

    #[tokio::test]
    async fn link_eof_inside_frame_errors() {
        let (cs, cio, ss, sio) = session_pair();
        let (mut sread, _swrite) = split_link(ss, sio).unwrap();
        // Produce one valid client wire frame, but deliver only its first
        // bytes before closing: the reader must report eof-inside-frame.
        let (mut stx, _srx) = cs.split();
        let mut frame = Vec::new();
        stx.encrypt_into(&mut frame, b"hello").unwrap();
        let cut = frame.len() - 1;
        let mut cio = cio;
        cio.write_all(&frame[..cut]).unwrap();
        drop(cio);
        let mut buf = [0u8; 8];
        let res = sread.read(&mut buf).await;
        assert!(matches!(&res, Err(e) if e.kind() == io::ErrorKind::UnexpectedEof));

        // Header only: the codec drains the 3 header bytes, so `wire` is
        // empty and the pending-frame state alone must flag the
        // eof-inside-frame.
        let (cs, cio, ss, sio) = session_pair();
        let (mut sread, _swrite) = split_link(ss, sio).unwrap();
        let (mut stx, _srx) = cs.split();
        let mut frame = Vec::new();
        stx.encrypt_into(&mut frame, b"hello").unwrap();
        let mut cio = cio;
        cio.write_all(&frame[..nextppp_core::frame::binary::HEADER_SIZE])
            .unwrap();
        drop(cio);
        let mut buf = [0u8; 8];
        let res = sread.read(&mut buf).await;
        assert!(matches!(&res, Err(e) if e.kind() == io::ErrorKind::UnexpectedEof));
    }
}
