//! openppp3 proxy server: accepts openppp3-tunneled connections, connects
//! to the requested target and pumps bytes both ways.
//!
//! Connection model: one handshake thread per accepted stream, then the
//! classic two-thread pump ([`openppp3_common::pump`]). Session ids are
//! `random_base + counter`, never zero.

use std::{
    net::{TcpListener, TcpStream},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::Duration,
};

use anyhow::Context;
use openppp3_common::{addr::ProxyAddr, config::ServerConfig, pump, proto};
use openppp3_core::{ObfuscationKey, Transmission};
use rand::RngCore;
use tracing::{debug, info, warn};

/// Immutable runtime parameters derived from the configuration.
#[derive(Clone)]
pub struct ServerRuntime {
    /// Obfuscation/cipher parameters.
    pub key: ObfuscationKey,
    /// Server -> target connect timeout.
    pub connect_timeout: Duration,
    /// Handshake timeout (anti slow-loris).
    pub handshake_timeout: Duration,
}

impl ServerRuntime {
    /// Validates the configuration into runtime parameters.
    ///
    /// # Errors
    ///
    /// Cipher method validation failure.
    pub fn from_config(cfg: &ServerConfig) -> anyhow::Result<Self> {
        Ok(Self {
            key: cfg
                .obfuscation
                .to_key()
                .map_err(anyhow::Error::msg)
                .context("obfuscation config")?,
            connect_timeout: Duration::from_secs(cfg.connect_timeout),
            handshake_timeout: Duration::from_secs(cfg.handshake_timeout),
        })
    }
}

/// Accept loop; blocks the calling thread forever.
///
/// # Errors
///
/// Fatal listener failure.
// `serve` owns the listener: it lives exactly as long as the accept loop.
#[allow(clippy::needless_pass_by_value)]
pub fn serve(listener: TcpListener, rt: ServerRuntime) -> anyhow::Result<()> {
    info!(
        "openppp3 server listening on {}",
        listener.local_addr()?.to_string()
    );
    let base = u128::from(rand::rng().next_u64()); // session ids only need uniqueness
    let counter = AtomicU64::new(0);
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let rt = rt.clone();
                let mut sid = base.wrapping_add(u128::from(counter.fetch_add(1, Ordering::Relaxed)));
                if sid == 0 {
                    sid = 1;
                }
                let spawned = thread::Builder::new()
                    .name(format!("openppp3-{sid:016x}"))
                    .spawn(move || {
                        if let Err(e) = handle_conn(stream, rt, sid) {
                            debug!("session {sid:016x} ended: {e:#}");
                        }
                    });
                if let Err(e) = spawned {
                    warn!("spawn failed: {e}");
                }
            }
            Err(e) => warn!("accept failed: {e}"),
        }
    }
    Ok(())
}

/// Handles one tunneled connection end to end.
fn handle_conn(stream: TcpStream, rt: ServerRuntime, sid: u128) -> anyhow::Result<()> {
    pump::nodelay(&stream);
    stream.set_read_timeout(Some(rt.handshake_timeout))?;
    stream.set_write_timeout(Some(rt.handshake_timeout))?;
    let rx_io = stream.try_clone().context("clone stream")?;

    let mut tx = Transmission::new(stream, rt.key);
    tx.handshake_server(sid, false)
        .context("handshake")?;

    let req = tx.read().context("read request")?;
    let addr = ProxyAddr::decode(&req).context("decode request")?;
    debug!("session {sid:016x} -> {}", addr.host.to_display());

    let target = pump::tcp_connect(&addr.host, addr.port, rt.connect_timeout);
    match target {
        Ok(target) => {
            pump::nodelay(&target);
            tx.write(&[proto::STATUS_OK]).context("reply ok")?;
            // Handshake done: the data plane must not time out.
            tx.io_mut().set_read_timeout(None)?;
            rx_io.set_read_timeout(None)?;
            tx.io_mut().set_write_timeout(None)?;

            let (txh, rxh) = tx.split_with(rx_io);
            let (up, down) = pump::pump_tunnel(txh, rxh, target);
            debug!("session {sid:016x} closed (up {up}, down {down})");
            Ok(())
        }
        Err(e) => {
            info!("session {sid:016x} connect to {} failed: {e}", addr.host.to_display());
            let _ = tx.write(&[proto::STATUS_REFUSED]);
            Ok(())
        }
    }
}
