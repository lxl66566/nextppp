//! Throughput benchmark for the full tunnel: socks5 inbound -> client ->
//! nextppp tunnel -> server -> loopback echo target.
//!
//! The server and client accept loops are each pinned to a single, distinct
//! CPU via `sched_setaffinity(2)` (and their per-connection threads inherit
//! that mask), so the numbers are comparable and expose single-core
//! bottlenecks in the crypto/data-plane path. Linux-only for that reason.
//!
//! It is `#[ignore]`d: it moves 256 MiB and must be run in release mode.
//!
//! ```text
//! cargo test -p nextppp-client --release --test throughput -- --ignored --nocapture
//! ```
//!
//! Override the transfer size with `NEXTPPP_THROUGHPUT_BYTES`.
//!
//! With `--features hotpath` the whole in-process stack (server + client +
//! pumps) is hotpath-instrumented and the report prints on exit; combine
//! with `hotpath-alloc` for allocation stats.

#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // sched_setaffinity(2) FFI is the whole point here

use std::{
    io::{Read, Write},
    mem::size_of,
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::Arc,
    thread,
    time::Duration,
};

use nextppp_client::ClientRuntime;
use nextppp_common::config::{ClientConfig, ObfuscationConfig, ServerConfig, ServerSection};
use nextppp_server::ServerRuntime;

/// Echo buffer: large enough that the loopback echo is never the bottleneck
/// next to single-core crypto.
const ECHO_BUF: usize = 64 * 1024;

/// Transfer chunk size for the timed bulk phase.
const CHUNK: usize = 64 * 1024;

/// Default bytes moved in one direction.
const DEFAULT_BYTES: usize = 256 * 1024 * 1024;

/// `cpu_set_t` spans 128 bytes = 1024 bits (glibc `CPU_SETSIZE`); a fixed
/// bound avoids signed casts and keeps the FFI minimal.
const MAX_CPUS: usize = 1024;

/// Pins the calling thread to `cpu` (pid 0 = calling thread). Threads spawned
/// from here inherit the mask, so an endpoint stays on a single CPU.
fn pin_thread(cpu: usize) {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
        let rc = libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &raw const set);
        assert_eq!(rc, 0, "sched_setaffinity({cpu}) failed");
    }
}

/// CPUs this process is currently allowed to run on, ascending.
fn allowed_cores() -> Vec<usize> {
    let set = unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        let rc = libc::sched_getaffinity(0, size_of::<libc::cpu_set_t>(), &raw mut set);
        assert_eq!(rc, 0, "sched_getaffinity failed");
        set
    };
    (0..MAX_CPUS)
        .filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, &set) })
        .collect()
}

/// Loopback echo target that reflects bytes and propagates half-closes.
fn start_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::Builder::new()
        .name("throughput-echo".to_owned())
        .spawn(move || {
            for conn in listener.incoming().flatten() {
                thread::spawn(move || {
                    let mut conn = conn;
                    let _ = conn.set_nodelay(true);
                    let mut buf = vec![0u8; ECHO_BUF];
                    loop {
                        match conn.read(&mut buf) {
                            Ok(0) => {
                                let _ = conn.shutdown(Shutdown::Write);
                                break;
                            },
                            Ok(n) => {
                                if conn.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                            },
                            Err(_) => break,
                        }
                    }
                });
            }
        })
        .unwrap();
    addr
}

/// Starts the server pinned to `cpu`, returning its listen address.
fn start_server(cpu: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = ServerConfig {
        listen: addr.to_string(),
        password: None,
        connect_timeout: 5,
        handshake_timeout: 10,
        obfuscation: ObfuscationConfig::default(),
    };
    let rt = ServerRuntime::from_config(&cfg).unwrap();
    thread::Builder::new()
        .name(format!("throughput-server@{cpu}"))
        .spawn(move || {
            pin_thread(cpu);
            nextppp_server::serve(listener, rt).unwrap();
        })
        .unwrap();
    addr
}

/// Starts the client (socks5 inbound) pinned to `cpu`, returning its listen address.
fn start_client(cpu: usize, server: SocketAddr) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = ClientConfig {
        listen: addr.to_string(),
        password: None,
        server: ServerSection {
            address: server.to_string(),
            connect_timeout: 5,
            obfuscation: ObfuscationConfig::default(),
        },
    };
    let rt = Arc::new(ClientRuntime::from_config(&cfg).unwrap());
    thread::Builder::new()
        .name(format!("throughput-client@{cpu}"))
        .spawn(move || {
            pin_thread(cpu);
            nextppp_client::serve(listener, rt).unwrap();
        })
        .unwrap();
    addr
}

/// SOCKS5 no-auth + IPv4 CONNECT to `target`, returning the tunneled stream.
fn socks5_connect(client: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut s = TcpStream::connect(client).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(30))).unwrap();

    s.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut method = [0u8; 2];
    s.read_exact(&mut method).unwrap();
    assert_eq!(method, [0x05, 0x00]);

    let std::net::IpAddr::V4(v4) = target.ip() else {
        panic!("throughput test uses IPv4 targets only");
    };
    let mut req = Vec::with_capacity(10);
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x01]);
    req.extend_from_slice(&v4.octets());
    req.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&req).unwrap();

    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).unwrap();
    assert_eq!(
        reply[1], 0x00,
        "connect not accepted: rep={:#04x}",
        reply[1]
    );

    // The data plane must not be subject to the negotiation timeout.
    s.set_read_timeout(None).unwrap();
    s.set_write_timeout(None).unwrap();
    s
}

/// One-way byte rate in MiB/s.
fn mib_per_sec(bytes: usize, elapsed: Duration) -> f64 {
    #[allow(clippy::cast_precision_loss)] // bytes < 2^32 in practice: exact in f64
    let bytes = bytes as f64;
    bytes / elapsed.as_secs_f64() / (1024.0 * 1024.0)
}

/// Timed bulk transfer: writes `size` bytes on one thread while reading the
/// same amount back on the main thread. Returns the one-way rate and elapsed
/// time. Data integrity is checked separately by the probe before the run.
fn blast(stream: &mut TcpStream, size: usize) -> (f64, Duration) {
    let mut send = stream.try_clone().unwrap();
    let started = std::time::Instant::now();

    let writer = thread::spawn(move || {
        let buf = vec![0u8; CHUNK];
        let mut remaining = size;
        while remaining > 0 {
            let n = remaining.min(buf.len());
            send.write_all(&buf[..n]).unwrap();
            remaining -= n;
        }
        let _ = send.shutdown(Shutdown::Write);
    });

    let mut sink = vec![0u8; CHUNK];
    let mut remaining = size;
    while remaining > 0 {
        let n = remaining.min(sink.len());
        stream.read_exact(&mut sink[..n]).unwrap();
        remaining -= n;
    }
    writer.join().unwrap();

    let elapsed = started.elapsed();
    (mib_per_sec(size, elapsed), elapsed)
}

fn total_bytes() -> usize {
    std::env::var("NEXTPPP_THROUGHPUT_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_BYTES)
}

#[test]
#[ignore = "slow 256 MiB single-core benchmark; run manually in release mode"]
fn single_core_throughput() {
    // Test harness has no main we control: build the profiler guard
    // programmatically (noop without the hotpath feature).
    #[cfg(feature = "hotpath")]
    let _hotpath = hotpath::HotpathGuardBuilder::new("throughput").build();

    let cores = allowed_cores();
    if cores.len() < 2 {
        eprintln!("throughput test skipped: fewer than 2 CPUs available");
        return;
    }
    let (server_cpu, client_cpu) = (cores[0], cores[1]);

    let echo = start_echo();
    let server = start_server(server_cpu);
    let client = start_client(client_cpu, server);

    let mut stream = socks5_connect(client, echo);

    // Correctness sanity before the timed run, which only counts bytes.
    let probe = b"throughput probe 0123456789abcdef";
    stream.write_all(probe).unwrap();
    let mut got = vec![0u8; probe.len()];
    stream.read_exact(&mut got).unwrap();
    assert_eq!(got, probe, "probe round-trip corrupted");

    let size = total_bytes();
    let (rate, elapsed) = blast(&mut stream, size);

    #[allow(clippy::cast_precision_loss)]
    let size_mib = size as f64 / (1024.0 * 1024.0);
    eprintln!(
        "throughput: {size} bytes ({size_mib:.0} MiB) in {secs:.2}s = {rate:.2} MiB/s (server cpu \
         {server_cpu}, client cpu {client_cpu})",
        secs = elapsed.as_secs_f64(),
    );

    // Smoke floor: a broken tunnel or a starved CPU still clears this.
    assert!(rate >= 1.0, "throughput suspiciously low: {rate:.2} MiB/s");
}
