//! Probe-flood gate: with `max_handshakes` reached, connections are dropped
//! at accept time instead of each costing a session thread plus the full
//! handshake timeout.

use std::{
    io::Read,
    net::{SocketAddr, TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};

use nextppp_common::config::{ObfuscationConfig, ServerConfig};
use nextppp_server::ServerRuntime;

fn start_server(max_handshakes: Option<u64>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = ServerConfig {
        listen: addr.to_string(),
        password: None,
        connect_timeout: 5,
        handshake_timeout: 10,
        max_connections: None,
        max_handshakes,
        obfuscation: ObfuscationConfig::default(),
    };
    let rt = ServerRuntime::from_config(&cfg).unwrap();
    thread::spawn(move || {
        nextppp_server::serve(listener, rt).unwrap();
    });
    addr
}

#[test]
fn handshake_cap_drops_excess_probes() {
    let server = start_server(Some(1));

    // Probe #1 connects and stays silent: it holds the single handshake
    // slot (the session thread is parked in the handshake read).
    let _held = TcpStream::connect(server).unwrap();
    // Give the accept loop a moment to spawn the session and block in the
    // handshake; otherwise probe #2 may be accepted before the gauge rises.
    thread::sleep(Duration::from_millis(300));

    // Probe #2 is dropped at accept time: its reads hit EOF/RST promptly,
    // far short of the 10s handshake timeout a queued probe would cost.
    let mut probe = TcpStream::connect(server).unwrap();
    probe
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let started = Instant::now();
    let mut buf = [0u8; 1];
    let result = probe.read(&mut buf);
    assert!(
        matches!(&result, Ok(0) | Err(_)),
        "rejected probe must observe a closed socket, got {result:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "rejected probe must not hang for the handshake timeout"
    );
}
