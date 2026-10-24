//! Bonded-tunnel listener: accepts link connections (each an ordinary
//! nextppp session, indistinguishable from a plain tunnel on the wire),
//! hands them to the link aggregator, and serves the mux protocol over
//! each aggregated channel.
//!
//! On the wire a link carries only nextppp frames; the aggregator's own
//! protocol (connection joining, striping, retransmission) travels inside
//! the encrypted link sessions, so bonding adds no DPI-visible fingerprint.
//!
//! Load gates: link handshakes are subject to `max_handshakes` and count
//! toward `handshake_failures`; each aggregated channel counts as one
//! active connection toward `max_connections`. Links themselves are not
//! capped per client — they are authenticated sessions like plain tunnels.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use aggligator::{
    connect::Server,
    io::{IoRx, IoTx},
};
use nextppp_common::{
    link::{LinkReadHalf, LinkWriteHalf, bond_cfg, split_link},
    tunnel::{FrameReader, OutFrame, TxWire, run_writer},
};
use rand::Rng;
use spdlog::prelude::*;
use tokio::{net::TcpListener, sync::mpsc};

use crate::{OUTBOUND_BOUND, SHUTDOWN_POLL, ServerRuntime, ServerStats, handshake_sync, run_demux};

/// Link read half over a tokio TCP read half.
type LinkRead = LinkReadHalf<tokio::net::tcp::OwnedReadHalf>;
/// Link write half over a tokio TCP write half.
type LinkWrite = LinkWriteHalf<tokio::net::tcp::OwnedWriteHalf>;

/// Aggregated-connection server over nextppp link streams (link tag = peer
/// address string).
type AggServer = Server<IoTx<LinkWrite>, IoRx<LinkRead>, String>;

/// One aggregated connection handed over by [`AggServer`].
type AggIncoming = aggligator::Incoming<IoTx<LinkWrite>, IoRx<LinkRead>, String>;

/// Bond accept loop: one branch accepts link TCPs, the other drains
/// aggregated connections as they form.
pub(crate) async fn accept_loop(listener: TcpListener, rt: ServerRuntime, stats: Arc<ServerStats>) {
    let agg: AggServer = Server::new(bond_cfg());
    let mut listen = match agg.listen() {
        Ok(l) => l,
        Err(e) => {
            warn!("bond listener setup failed: {e}");
            return;
        },
    };
    let counter = AtomicU64::new(0);
    let base = u128::from(rand::rng().next_u64());
    loop {
        tokio::select! {
            r = listener.accept() => match r {
                Ok((stream, peer)) => {
                    // Probe-flood gate only: links join an authenticated
                    // channel or die at the nextppp handshake.
                    if let Some(max) = rt.max_handshakes
                        && stats.handshaking.load(Ordering::Relaxed) >= max
                    {
                        stats.rejected_overload.fetch_add(1, Ordering::Relaxed);
                        debug!("bond link rejected: handshake limit {max} reached");
                        continue;
                    }
                    let mut sid = base.wrapping_add(u128::from(counter.fetch_add(1, Ordering::Relaxed)));
                    if sid == 0 {
                        sid = 1;
                    }
                    tokio::spawn(handle_link(
                        stream,
                        peer.to_string(),
                        agg.clone(),
                        rt.clone(),
                        Arc::clone(&stats),
                        sid,
                    ));
                },
                Err(e) => {
                    if nextppp_common::pump::accept_exhausted(&e) {
                        nextppp_common::pump::log_accept_exhausted(&e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    } else {
                        warn!("bond accept failed: {e}");
                    }
                },
            },
            r = listen.next() => match r {
                Ok(incoming) => {
                    tokio::spawn(run_bonded(incoming, rt.clone(), Arc::clone(&stats)));
                },
                Err(e) => {
                    warn!("bond aggregator listener failed: {e}");
                    return;
                },
            },
            () = tokio::time::sleep(SHUTDOWN_POLL) => {
                if nextppp_common::shutdown::requested() {
                    return;
                }
            },
        }
    }
}

/// Handshakes one link connection and registers it with the aggregator,
/// which joins it to its channel or spawns a new one.
async fn handle_link(
    stream: tokio::net::TcpStream,
    peer: String,
    agg: AggServer,
    rt: ServerRuntime,
    stats: Arc<ServerStats>,
    sid: u128,
) {
    let std_stream = match stream.into_std() {
        Ok(s) => s,
        Err(e) => {
            debug!("bond link {sid:016x} ({peer}) setup failed: {e}");
            return;
        },
    };
    if let Err(e) = std_stream.set_nonblocking(false) {
        debug!("bond link {sid:016x} ({peer}) blocking mode failed: {e}");
        return;
    }
    let hs = {
        let rt = rt.clone();
        let stats = Arc::clone(&stats);
        tokio::task::spawn_blocking(move || {
            handshake_sync(std_stream, &rt, sid, &stats.handshaking, false)
        })
        .await
    };
    let (session, io) = match hs {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            let n = stats.handshake_failures.fetch_add(1, Ordering::Relaxed) + 1;
            if n == 1 || n.is_multiple_of(64) {
                warn!("bond link ({peer}) handshake failed: {e:#} (failure #{n})");
            } else {
                debug!("bond link ({peer}) handshake failed: {e:#}");
            }
            return;
        },
        Err(e) => {
            debug!("bond link ({peer}) handshake task failed: {e}");
            return;
        },
    };
    let (read, write) = match split_link(session, io) {
        Ok(v) => v,
        Err(e) => {
            debug!("bond link {sid:016x} ({peer}) async conversion failed: {e}");
            return;
        },
    };
    let tag = peer.clone();
    match agg.add_incoming_io(read, write, tag, &[], None).await {
        Ok(_) => debug!("bond link {sid:016x} ({peer}) registered"),
        Err(e) => debug!("bond link {sid:016x} ({peer}) refused by aggregator: {e}"),
    }
}

/// Serves one aggregated connection: the mux tunnel over the aggregated
/// channel, using the same demux as plain tunnels.
async fn run_bonded(incoming: AggIncoming, rt: ServerRuntime, stats: Arc<ServerStats>) {
    let (task, channel, control) = incoming.accept();
    drop(control);
    let id = channel.id().0;
    tokio::spawn(async move {
        if let Err(e) = task.run().await {
            debug!("bond channel {id:016x} task ended: {e}");
        }
    });
    stats.active.fetch_add(1, Ordering::Relaxed);
    let _guard = crate::ActiveGuard(Arc::clone(&stats));

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
