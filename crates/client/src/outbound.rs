//! Outbound: every request goes through the nextppp tunnel. Splitting and
//! direct connections are the front-end proxy's (sing-box & co.) job.

use std::{net::TcpStream, sync::Arc};

use anyhow::Context;
use nextppp_common::{addr::ProxyAddr, proto::STATUS_OK, pump};
use nextppp_core::{Transmission, TransmissionRx, TransmissionTx};
use spdlog::prelude::*;

use crate::ClientRuntime;

/// A split nextppp tunnel ready for the pump.
pub type Tunnel = (
    Box<TransmissionTx<TcpStream>>,
    Box<TransmissionRx<TcpStream>>,
);

/// Connects to the remote server, runs the nextppp handshake, forwards the
/// connect request and splits the transmission.
///
/// # Errors
///
/// Connect / handshake / remote-refused failure.
#[cfg_attr(feature = "hotpath", hotpath::measure)]
pub fn tunnel_connect(addr: &ProxyAddr, rt: &ClientRuntime) -> anyhow::Result<Tunnel> {
    let started = std::time::Instant::now();
    let stream = pump::tcp_connect(&rt.server_host, rt.server_port, rt.connect_timeout)
        .with_context(|| {
            format!(
                "connect server {}:{}",
                rt.server_host.to_display(),
                rt.server_port
            )
        })?;
    pump::nodelay(&stream);

    // Bound the whole handshake + request exchange by the connect timeout.
    stream
        .set_read_timeout(Some(rt.connect_timeout))
        .context("set read timeout")?;
    stream
        .set_write_timeout(Some(rt.connect_timeout))
        .context("set write timeout")?;
    let rx_io = stream.try_clone().context("clone stream")?;

    let mut tx = Transmission::new(stream, Arc::clone(&rt.server_key));
    let (sid, _mux) = tx.handshake_client().context("nextppp handshake")?;
    debug!(
        "tunnel {sid:016x} to {}:{} handshaked in {}",
        rt.server_host.to_display(),
        rt.server_port,
        nextppp_common::fmt_duration(started.elapsed())
    );
    tx.write(&addr.encode()).context("send request")?;
    let reply = tx.read().context("read reply")?;
    if reply.first() != Some(&STATUS_OK) {
        anyhow::bail!(
            "server refused connection to {} (status {:02x?})",
            addr.host.to_display(),
            reply.first()
        );
    }

    // Data plane: no timeouts.
    tx.io_mut().set_read_timeout(None)?;
    tx.io_mut().set_write_timeout(None)?;
    rx_io.set_read_timeout(None)?;
    rx_io.set_write_timeout(None)?;
    let (tx_half, rx_half) = tx.split_with(rx_io);
    Ok((Box::new(tx_half), Box::new(rx_half)))
}
