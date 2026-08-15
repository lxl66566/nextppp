//! Bidirectional connection pumps for the synchronous two-thread model.
//!
//! Two shapes exist:
//!
//! * [`pump_tcp`]: two plain TCP streams (direct connections);
//! * [`pump_tunnel`]: a local TCP peer against a split openppp3 tunnel,
//!   wrapping data in `FRAME_DATA` frames and propagating half-closes as
//!   `FRAME_EOF` (the openppp3 framing itself has no in-band EOF).

use std::{
    io::{self, ErrorKind, Read, Write},
    net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs},
    thread,
    time::Duration,
};

use openppp3_core::{TransmissionRx, TransmissionTx};

use crate::{addr::Host, FRAME_DATA, FRAME_EOF};

/// Read chunk size: small enough for interactive latency, large enough to
/// amortize per-frame crypto/header overhead.
const CHUNK: usize = 16 * 1024;

/// Enables `TCP_NODELAY` on every proxied stream (interactive workloads).
pub fn nodelay(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
}

/// Connects to `host:port` honoring a timeout. All resolved addresses are
/// tried in order (first success wins; no happy-eyeballs).
///
/// # Errors
///
/// DNS resolution failure or every candidate address failing to connect.
pub fn tcp_connect(host: &Host, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    match host {
        Host::Ip(ip) => TcpStream::connect_timeout(&SocketAddr::new(*ip, port), timeout),
        Host::Domain(domain) => {
            let addrs: Vec<SocketAddr> = (domain.as_str(), port).to_socket_addrs()?.collect();
            let mut last = io::Error::new(ErrorKind::AddrNotAvailable, "no addresses resolved");
            for addr in addrs {
                match TcpStream::connect_timeout(&addr, timeout) {
                    Ok(s) => return Ok(s),
                    Err(e) => last = e,
                }
            }
            Err(last)
        }
    }
}

/// Copies one direction until EOF or error, then shuts down the destination
/// write side so the half-close propagates.
fn copy_tcp<R: Read>(mut r: R, mut w: TcpStream) -> u64 {
    let mut buf = vec![0u8; CHUNK];
    let mut total = 0u64;
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if w.write_all(&buf[..n]).is_err() {
                    break;
                }
                total += n as u64;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    let _ = w.shutdown(Shutdown::Write);
    total
}

/// Pumps two plain TCP streams in both directions. Returns `(a→b, b→a)`
/// byte counts. Both directions are shut down once they finish.
#[must_use = "byte counts feed connection logs"]
pub fn pump_tcp(a: TcpStream, b: TcpStream) -> (u64, u64) {
    let a_w = a.try_clone().expect("tcp stream clone");
    let b_w = b.try_clone().expect("tcp stream clone");
    thread::scope(|s| {
        let up = s.spawn(move || copy_tcp(a, b_w));
        let down = s.spawn(move || copy_tcp(b, a_w));
        (up.join().unwrap_or(0), down.join().unwrap_or(0))
    })
}

/// Local -> tunnel direction: wraps chunks in `FRAME_DATA`, emits `FRAME_EOF`
/// on local half-close. Dropping `tx` afterwards sends the TCP FIN.
fn tunnel_up(mut tx: TransmissionTx<TcpStream>, mut local: TcpStream) -> u64 {
    let mut buf = vec![0u8; CHUNK];
    let mut frame = Vec::with_capacity(CHUNK + 1);
    let mut total = 0u64;
    loop {
        match local.read(&mut buf) {
            Ok(0) => {
                let _ = tx.write(&[FRAME_EOF]);
                break;
            }
            Ok(n) => {
                frame.clear();
                frame.push(FRAME_DATA);
                frame.extend_from_slice(&buf[..n]);
                if tx.write(&frame).is_err() {
                    break;
                }
                total += n as u64;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    total
}

/// Tunnel -> local direction: unwraps `FRAME_DATA`, forwards `FRAME_EOF` as
/// a local write-side shutdown.
fn tunnel_down(mut rx: TransmissionRx<TcpStream>, mut local: TcpStream) -> u64 {
    let mut total = 0u64;
    loop {
        match rx.read() {
            Ok(msg) => {
                let Some((&tag, payload)) = msg.split_first() else {
                    continue; // zero-payload data frame: harmless no-op
                };
                match tag {
                    FRAME_DATA if !payload.is_empty() => {
                        if local.write_all(payload).is_err() {
                            break;
                        }
                        total += payload.len() as u64;
                    }
                    FRAME_EOF => {
                        let _ = local.shutdown(Shutdown::Write);
                        break;
                    }
                    _ => break, // unknown frame kind: protocol violation
                }
            }
            Err(e) if e.is_eof() => break,
            Err(_) => break,
        }
    }
    total
}

/// Pumps a local TCP peer against a split openppp3 tunnel.
/// Returns `(local→tunnel, tunnel→local)` byte counts.
#[must_use = "byte counts feed connection logs"]
pub fn pump_tunnel(
    tx: TransmissionTx<TcpStream>,
    rx: TransmissionRx<TcpStream>,
    local: TcpStream,
) -> (u64, u64) {
    let local_w = local.try_clone().expect("tcp stream clone");
    thread::scope(|s| {
        let down = s.spawn(move || tunnel_down(rx, local_w));
        let up = s.spawn(move || tunnel_up(tx, local));
        (up.join().unwrap_or(0), down.join().unwrap_or(0))
    })
}
