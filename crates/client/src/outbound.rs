//! Outbound: every request goes through the nextppp tunnel. Splitting and
//! direct connections are the front-end proxy's (sing-box & co.) job.

use std::{io::ErrorKind, net::TcpStream, sync::Arc};

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

/// The server answered `STATUS_REFUSED`: the target itself is unreachable
/// from the server — a deterministic verdict that retrying cannot change.
#[derive(Debug, thiserror::Error)]
#[error("server refused connection to {0}")]
struct RefusedTarget(String);

/// Whether a failed attempt is worth retrying with a fresh TCP connection:
/// routine transport teardown (RST, timeout, refused SYN) and handshake
/// failures are — misconfiguration (`FlagsMismatch`) and explicit
/// `STATUS_REFUSED` are deterministic and must not burn retries.
fn retryable(err: &anyhow::Error) -> bool {
    if err
        .chain()
        .any(|c| c.downcast_ref::<RefusedTarget>().is_some())
    {
        return false;
    }
    if pump::is_clean_close(err) {
        return true;
    }
    // A SYN answered with RST surfaces as ECONNREFUSED (connect), which
    // `is_clean_close` deliberately does not classify as routine teardown.
    err.chain().any(|c| {
        c.downcast_ref::<std::io::Error>()
            .is_some_and(|e| e.kind() == ErrorKind::ConnectionRefused)
    })
}

/// Connects to the remote server, runs the nextppp handshake, forwards the
/// connect request and splits the transmission. Routine transport failures
/// are retried up to `rt.connect_retries` times, each attempt on a fresh
/// `TcpStream` (all session state lives in `Transmission::new`, so a retry
/// is a clean restart; DNS hits the runtime cache, not the resolver).
///
/// # Errors
///
/// Connect / handshake / remote-refused failure after all attempts.
#[cfg_attr(feature = "hotpath", hotpath::measure)]
pub fn tunnel_connect(addr: &ProxyAddr, rt: &ClientRuntime) -> anyhow::Result<Tunnel> {
    let mut attempt = 0u32;
    loop {
        match tunnel_connect_once(addr, rt) {
            Ok(tunnel) => return Ok(tunnel),
            Err(e) => {
                if attempt >= rt.connect_retries || !retryable(&e) {
                    return Err(e);
                }
                attempt += 1;
                debug!(
                    "tunnel connect to {}:{} failed ({e:#}); retry {attempt}/{}",
                    addr.host.to_display(),
                    addr.port,
                    rt.connect_retries
                );
            },
        }
    }
}

/// One tunnel-establishment attempt.
fn tunnel_connect_once(addr: &ProxyAddr, rt: &ClientRuntime) -> anyhow::Result<Tunnel> {
    let started = std::time::Instant::now();
    let stream = pump::tcp_connect(&rt.server_host, rt.server_port, rt.connect_timeout, &rt.dns)
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
    // 0-RTT: the tx direction rekeys from the client-generated ivv, so the
    // request flies immediately after the ivv instead of waiting one RTT
    // for the server's sid/nmux. The confirm phase (rx rekey + canary
    // check) runs just before the first read.
    tx.handshake_client_send().context("nextppp handshake")?;
    tx.write(&addr.encode()).context("send request")?;
    let (sid, _mux) = tx.handshake_client_confirm().context("nextppp handshake")?;
    debug!(
        "tunnel {sid:016x} to {}:{} handshaked in {}",
        rt.server_host.to_display(),
        rt.server_port,
        nextppp_common::fmt_duration(started.elapsed())
    );
    let reply = tx.read().context("read reply")?;
    if reply.first() != Some(&STATUS_OK) {
        return Err(RefusedTarget(format!(
            "{}:{} (status {:02x?})",
            addr.host.to_display(),
            addr.port,
            reply.first()
        ))
        .into());
    }

    // Data plane: no timeouts (kernel keepalive, set by `tcp_connect`,
    // covers dead-peer detection instead).
    tx.io_mut().set_read_timeout(None)?;
    tx.io_mut().set_write_timeout(None)?;
    rx_io.set_read_timeout(None)?;
    rx_io.set_write_timeout(None)?;
    let (tx_half, rx_half) = tx.split_with(rx_io);
    Ok((Box::new(tx_half), Box::new(rx_half)))
}

#[cfg(test)]
mod tests {
    use nextppp_core::Error as CoreError;

    use super::*;

    fn refused() -> anyhow::Error {
        RefusedTarget("example:80 (status Some(1))".into()).into()
    }

    #[test]
    fn retryable_classification() {
        // Routine transport teardown: retry.
        let reset: anyhow::Error = CoreError::Io(std::io::Error::new(
            ErrorKind::ConnectionReset,
            "reset",
        ))
        .into();
        assert!(retryable(&reset));
        // Refused SYN (RST attack on connect): retry.
        let refused_syn: anyhow::Error =
            std::io::Error::new(ErrorKind::ConnectionRefused, "refused").into();
        assert!(retryable(&refused_syn));
        // Deterministic failures: never retry.
        assert!(!retryable(&refused()));
        let flags: anyhow::Error = CoreError::FlagsMismatch.into();
        assert!(!retryable(&flags));
        // Unknown/bare errors: no recognized cause, not retryable.
        assert!(!retryable(&anyhow::anyhow!("mystery")));
    }
}

