//! Outbound: every request goes through the openppp3 tunnel. Splitting and
//! direct connections are the front-end proxy's (sing-box & co.) job.

use std::net::TcpStream;

use anyhow::Context;
use openppp3_common::{addr::ProxyAddr, proto::STATUS_OK, pump};
use openppp3_core::{Transmission, TransmissionRx, TransmissionTx};
use spdlog::prelude::*;

use crate::ClientRuntime;

/// A split openppp3 tunnel ready for the pump.
pub type Tunnel = (
    Box<TransmissionTx<TcpStream>>,
    Box<TransmissionRx<TcpStream>>,
);

/// Connects to the remote server, runs the openppp3 handshake, forwards the
/// connect request and splits the transmission.
///
/// # Errors
///
/// Connect / handshake / remote-refused failure.
pub fn tunnel_connect(addr: &ProxyAddr, rt: &ClientRuntime) -> anyhow::Result<Tunnel> {
    let started = std::time::Instant::now();
    let (host, port) = crate::parse_host_port(&rt.server_address)?;
    let stream = pump::tcp_connect(&host, port, rt.connect_timeout)
        .with_context(|| format!("connect server {}", rt.server_address))?;
    pump::nodelay(&stream);

    // Bound the whole handshake + request exchange by the connect timeout.
    stream
        .set_read_timeout(Some(rt.connect_timeout))
        .context("set read timeout")?;
    stream
        .set_write_timeout(Some(rt.connect_timeout))
        .context("set write timeout")?;
    let rx_io = stream.try_clone().context("clone stream")?;

    let mut tx = Transmission::new(stream, rt.server_key.clone());
    let (sid, _mux) = tx.handshake_client().context("openppp3 handshake")?;
    debug!(
        "tunnel {sid:016x} to {} handshaked in {}",
        rt.server_address,
        openppp3_common::fmt_duration(started.elapsed())
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
