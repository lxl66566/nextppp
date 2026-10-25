//! Bonded-tunnel dialer (bandwidth path): one mux tunnel per aggregated
//! channel, each channel striped over `links` nextppp link sessions to
//! the server's bond listener.
//!
//! On the wire every link is an ordinary nextppp session, so bonding adds
//! no DPI-visible fingerprint; the aggregator's own protocol travels
//! inside the encrypted links. A channel tolerates link loss (unacked
//! packets are resent over surviving links) and the pool maintainer tops
//! lost links back up; only the loss of *all* links for
//! `no_link_timeout` kills the channel, after which the pool redials a
//! fresh tunnel.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use aggligator::{
    alc::{ReceiverStream, SenderSink},
    connect::connect,
    control::Control,
    io::{IoRx, IoTx},
};
use nextppp_common::{
    link::{LinkReadHalf, LinkWriteHalf, bond_cfg, split_link},
    tunnel::{FrameReader, TxWire},
};
use spdlog::prelude::*;

use crate::{
    ClientRuntime,
    pool::{Tunnel, TunnelDialer, TunnelEnds, dial_endpoint},
};

/// Link read half over a tokio TCP read half.
type LinkRead = LinkReadHalf<tokio::net::tcp::OwnedReadHalf>;
/// Link write half over a tokio TCP write half.
type LinkWrite = LinkWriteHalf<tokio::net::tcp::OwnedWriteHalf>;

/// Link controller of one bonded channel.
type AggControl = Control<IoTx<LinkWrite>, IoRx<LinkRead>, String>;

/// Dialer of bonded tunnels: one aggregated channel of `links` nextppp
/// sessions per tunnel.
pub struct BondDialer;

impl TunnelDialer for BondDialer {
    type R = ReceiverStream;
    type W = SenderSink;

    async fn dial(&self, rt: &Arc<ClientRuntime>) -> anyhow::Result<TunnelEnds<Self::R, Self::W>> {
        let bond = rt
            .bond
            .as_ref()
            .expect("bond dialer requires bond runtime params");
        let (task, outgoing, control) =
            connect::<IoTx<LinkWrite>, IoRx<LinkRead>, String>(bond_cfg());
        let task_id = control.id().0;
        tokio::spawn(async move {
            if let Err(e) = task.run().await {
                debug!("bond channel {task_id:016x} task ended: {e}");
            }
        });

        // Dial all links in parallel; the channel works with whatever
        // succeeded (>= 1), and the maintainer tops up the rest later.
        let mut link_tasks = Vec::new();
        for _ in 0..bond.links {
            let rt = Arc::clone(rt);
            link_tasks.push(tokio::spawn(async move { dial_link(&rt).await }));
        }
        let mut live = 0u32;
        for task in link_tasks {
            let link = match task.await {
                Ok(link) => link,
                Err(e) => {
                    control.terminate();
                    return Err(anyhow::Error::new(e).context("link dial task join"));
                },
            };
            match link {
                Ok((read, write, tag)) => {
                    match Box::pin(control.add_io(read, write, tag, &[], None)).await {
                        Ok(_) => live += 1,
                        Err(e) => debug!("bond link refused: {e}"),
                    }
                },
                Err(e) => debug!("bond link dial failed: {e:#}"),
            }
        }
        if live == 0 {
            control.terminate();
            anyhow::bail!("all {} bond links failed to {}", bond.links, bond.target);
        }
        // The aggregator registers links with `Control::links` only
        // eventually: wait until every freshly added link is visible
        // (bounded) before the tunnel enters the pool, so a maintainer
        // round firing right after this dial cannot undercount the links
        // and top up past `bond.links`.
        let settled = Instant::now() + Duration::from_millis(250);
        while u32::try_from(control.links().len()).unwrap_or(u32::MAX) < live
            && Instant::now() < settled
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // Every failure path below must terminate the aggregator: links
        // already added would otherwise linger on both ends until the
        // aggregator's default 300 s termination timeout fires.
        let channel = match tokio::time::timeout(rt.connect_timeout, outgoing.connect()).await {
            Ok(Ok(channel)) => channel,
            Ok(Err(e)) => {
                control.terminate();
                return Err(anyhow::anyhow!(
                    "bond channel connect to {}: {e}",
                    bond.target
                ));
            },
            Err(_) => {
                control.terminate();
                return Err(anyhow::anyhow!(
                    "bond channel connect timeout to {}",
                    bond.target
                ));
            },
        };

        let id = channel.id().0;
        let (rh, wh) = channel.into_stream().into_split();
        let terminator = control.clone();
        debug!(
            "bond channel {id:016x} established over {live}/{} links",
            bond.links
        );
        Ok(TunnelEnds {
            reader: FrameReader::prefix(rh),
            writer: TxWire::Prefix,
            write: wh,
            id,
            teardown: Some(Box::new(move || terminator.terminate())),
            ctx: Some(Box::new(control)),
        })
    }

    async fn maintain_tunnel(&self, rt: &Arc<ClientRuntime>, tunnel: &Arc<Tunnel>) {
        // A tunnel that died mid-round must not be topped up: its links
        // dial into a channel nothing will ever use again.
        if !tunnel.alive() {
            return;
        }
        let bond = rt
            .bond
            .as_ref()
            .expect("bond dialer requires bond runtime params");
        let control = tunnel_link_control(tunnel);
        let Some(control) = control else { return };
        let mut missing = bond
            .links
            .saturating_sub(u32::try_from(control.links().len()).unwrap_or(0));
        if missing > 0 {
            // Second look after a grace period: `Control::links` is
            // eventually consistent, so a round racing a fresh dial would
            // undercount and overshoot `bond.links`.
            tokio::time::sleep(Duration::from_millis(250)).await;
            if !tunnel.alive() {
                return;
            }
            missing = bond
                .links
                .saturating_sub(u32::try_from(control.links().len()).unwrap_or(0));
        }
        for _ in 0..missing {
            match dial_link(rt).await {
                Ok((read, write, tag)) => {
                    match Box::pin(control.add_io(read, write, tag, &[], None)).await {
                        Ok(_) => {},
                        // Dead channel: its tunnel dies on its own; stop here.
                        Err(e) => {
                            debug!("bond top-up link refused: {e}");
                            return;
                        },
                    }
                },
                Err(e) => {
                    debug!("bond top-up dial failed: {e:#}");
                    return;
                },
            }
        }
    }
}

/// The link controller stored in a bond tunnel's dialer context.
fn tunnel_link_control(tunnel: &Arc<Tunnel>) -> Option<AggControl> {
    let ctx = tunnel.ctx.lock().unwrap();
    ctx.as_ref()?.downcast_ref::<AggControl>().cloned()
}

/// Dials one nextppp link session to the server's bond listener.
async fn dial_link(rt: &Arc<ClientRuntime>) -> anyhow::Result<(LinkRead, LinkWrite, String)> {
    let bond = rt
        .bond
        .as_ref()
        .expect("bond dialer requires bond runtime params");
    // Per-link whole-dial-phase cap; each attempt keeps a full
    // `connect_timeout` budget (see `PlainDialer::dial`).
    let deadline = Instant::now() + rt.connect_timeout * (rt.connect_retries + 1);
    let (session, io) = dial_endpoint(rt, &bond.host, bond.port, deadline).await?;
    let tag = io
        .peer_addr()
        .map_or_else(|_| String::from("?"), |a| a.to_string());
    let (read, write) = split_link(session, io)?;
    Ok((read, write, tag))
}
