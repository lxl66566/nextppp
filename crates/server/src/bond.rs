//! Bonded-tunnel link plumbing: the shared accept loop (see [`crate::serve`])
//! hands every link session here after the handshake declares its role.
//! Links join the link aggregator's channels, and the mux protocol is served
//! over each aggregated channel.
//!
//! On the wire a link carries only nextppp frames; the aggregator's own
//! protocol (connection joining, striping, retransmission) travels inside
//! the encrypted link sessions, so bonding adds no DPI-visible fingerprint.
//!
//! Load gates: links are authenticated sessions like plain tunnels — the
//! same accept-time handshake cap, one active-connection slot per link
//! (bound to the aggregator's ownership, not the registering task). The
//! channel body rides its links' slots.

use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use aggligator::{
    connect::Server,
    io::{IoRx, IoTx},
};
use nextppp_common::{
    link::{LinkReadHalf, LinkWriteHalf, bond_cfg, split_link},
    tunnel::{FrameReader, OutFrame, TxWire, run_writer},
};
use nextppp_core::Session;
use spdlog::prelude::*;
use tokio::{
    io::{AsyncRead, ReadBuf},
    sync::mpsc,
};

use crate::{OUTBOUND_BOUND, ServerRuntime, ServerStats, run_demux};

/// Link read half over a tokio TCP read half.
type LinkRead = LinkReadHalf<tokio::net::tcp::OwnedReadHalf>;
/// Link write half over a tokio TCP write half.
type LinkWrite = LinkWriteHalf<tokio::net::tcp::OwnedWriteHalf>;

/// Read half that keeps its link counted as an active connection: the
/// aggregator owns the halves past registration, so the session slot must
/// be bound to the half's lifetime, not the registering task.
pub(crate) struct CountedLinkRead<R> {
    inner: R,
    _guard: crate::ActiveGuard,
}

impl<R: AsyncRead + Unpin> AsyncRead for CountedLinkRead<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

/// Aggregated-connection server over counted nextppp link streams (link
/// tag = peer address string).
pub(crate) type AggServer = Server<IoTx<LinkWrite>, IoRx<CountedLinkRead<LinkRead>>, String>;

/// One aggregated connection handed over by [`AggServer`].
type AggIncoming = aggligator::Incoming<IoTx<LinkWrite>, IoRx<CountedLinkRead<LinkRead>>, String>;

/// Builds the aggregator serving the listen port's bond links.
pub(crate) fn new_aggregator() -> AggServer {
    Server::new(bond_cfg())
}

/// Registers one handshaked link session with the aggregator, which joins
/// it to its channel or spawns a new one. The caller has already counted
/// the link as an active connection; the counted read half releases that
/// slot when the aggregator drops the link.
pub(crate) async fn register_link(
    session: Session,
    io: std::net::TcpStream,
    sid: u128,
    peer: String,
    agg: AggServer,
    stats: Arc<ServerStats>,
) {
    let (read, write) = match split_link(session, io) {
        Ok(v) => v,
        Err(e) => {
            debug!("bond link {sid:016x} ({peer}) async conversion failed: {e}");
            return;
        },
    };
    let read = CountedLinkRead {
        inner: read,
        _guard: crate::ActiveGuard(stats),
    };
    match agg.add_incoming_io(read, write, peer, &[], None).await {
        Ok(_) => debug!("bond link {sid:016x} registered"),
        Err(e) => debug!("bond link {sid:016x} refused by aggregator: {e}"),
    }
}

/// Serves one aggregated connection: the mux tunnel over the aggregated
/// channel, using the same demux as plain tunnels.
pub(crate) async fn run_bonded(incoming: AggIncoming, rt: ServerRuntime, stats: Arc<ServerStats>) {
    let (task, channel, control) = incoming.accept();
    drop(control);
    let id = channel.id().0;
    tokio::spawn(async move {
        if let Err(e) = task.run().await {
            debug!("bond channel {id:016x} task ended: {e}");
        }
    });

    let (rh, wh) = channel.into_stream().into_split();
    let (out_tx, out_rx) = mpsc::channel::<OutFrame>(OUTBOUND_BOUND);
    let mut writer = tokio::spawn(run_writer(TxWire::Prefix, wh, out_rx));
    let reader = FrameReader::prefix(rh);
    info!("bond channel {id:016x} established");
    run_demux(
        reader,
        &mut writer,
        out_tx,
        &rt,
        &format!("bond {id:016x}"),
        &stats,
    )
    .await;
}
