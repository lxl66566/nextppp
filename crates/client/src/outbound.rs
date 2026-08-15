//! Outbound connections: `direct` TCP or the openppp3 `tunnel`.

use std::{
    io::Write,
    net::TcpStream,
};

use anyhow::Context;
use openppp3_common::{
    addr::ProxyAddr,
    pump,
    proto::STATUS_OK,
};
use openppp3_core::{Transmission, TransmissionRx, TransmissionTx};

use crate::ClientRuntime;

/// An established outbound connection toward the requested target.
pub enum Outbound {
    /// Plain TCP connection (policy `direct`).
    Direct(TcpStream),
    /// openppp3 tunneled connection (policy `proxy`), already split into
    /// directional halves for the pump.
    Tunnel(Box<TransmissionTx<TcpStream>>, Box<TransmissionRx<TcpStream>>),
}

impl Outbound {
    /// Forwards initial pending bytes (an already-buffered HTTP head/body)
    /// before the pump takes over.
    ///
    /// # Errors
    ///
    /// I/O failure on the outbound path.
    pub fn write_initial(&mut self, buf: &[u8]) -> std::io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        match self {
            Self::Direct(s) => s.write_all(buf),
            Self::Tunnel(tx, _) => {
                // Must be frame-tagged exactly like pump_tunnel's upstream.
                let mut frame = Vec::with_capacity(buf.len() + 1);
                frame.push(openppp3_common::FRAME_DATA);
                frame.extend_from_slice(buf);
                tx.write(&frame).map_err(|e| {
                    std::io::Error::other(e.to_string())
                })
            }
        }
    }
}

/// Establishes the outbound connection for `addr` per the routing `policy`.
///
/// # Errors
///
/// Connect / handshake / remote-refused failure.
pub fn connect(policy: openppp3_common::Policy, addr: &ProxyAddr, rt: &ClientRuntime) -> anyhow::Result<Outbound> {
    match policy {
        openppp3_common::Policy::Direct => {
            let stream = pump::tcp_connect(&addr.host, addr.port, rt.connect_timeout)
                .with_context(|| format!("direct connect to {}", addr.host.to_display()))?;
            pump::nodelay(&stream);
            Ok(Outbound::Direct(stream))
        }
        openppp3_common::Policy::Proxy => tunnel_connect(addr, rt),
        // `block` is resolved by the caller before reaching here.
        openppp3_common::Policy::Block => unreachable!("block policy handled by inbound"),
    }
}

/// Connects to the remote server, runs the openppp3 handshake, forwards the
/// connect request and splits the transmission.
fn tunnel_connect(addr: &ProxyAddr, rt: &ClientRuntime) -> anyhow::Result<Outbound> {
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
    tx.handshake_client().context("openppp3 handshake")?;
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
    Ok(Outbound::Tunnel(Box::new(tx_half), Box::new(rx_half)))
}
