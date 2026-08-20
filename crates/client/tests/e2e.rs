//! End-to-end tests: real sockets through
//! socks5 inbound -> nextppp tunnel -> server -> echo target, covering
//! IP/domain targets, connect failures and half-close propagation.

use std::{
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::Arc,
    thread,
    time::Duration,
};

use nextppp_client::ClientRuntime;
use nextppp_common::{
    addr::Host,
    config::{ClientConfig, ObfuscationConfig, ServerConfig, ServerSection},
};
use nextppp_server::ServerRuntime;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// Echo target: reflects bytes, propagates half-closes.
fn start_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut conn = conn;
                let mut buf = [0u8; 4096];
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
    });
    addr
}

fn start_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = ServerConfig {
        listen: addr.to_string(),
        password: None,
        connect_timeout: 5,
        handshake_timeout: 10,
        max_connections: None,
        obfuscation: ObfuscationConfig::default(),
    };
    let rt = ServerRuntime::from_config(&cfg).unwrap();
    thread::spawn(move || {
        nextppp_server::serve(listener, rt).unwrap();
    });
    addr
}

fn start_client(server: SocketAddr) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = ClientConfig {
        listen: addr.to_string(),
        password: None,
        max_connections: None,
        server: ServerSection {
            address: server.to_string(),
            connect_timeout: 5,
            obfuscation: ObfuscationConfig::default(),
        },
    };
    let rt = Arc::new(ClientRuntime::from_config(&cfg).unwrap());
    thread::spawn(move || {
        nextppp_client::serve(listener, rt).unwrap();
    });
    addr
}

fn timed(stream: TcpStream) -> TcpStream {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
}

/// Performs the SOCKS5 no-auth + CONNECT handshake, asserting success.
fn socks5_connect(client: SocketAddr, host: &Host, port: u16) -> TcpStream {
    let mut s = timed(TcpStream::connect(client).unwrap());
    s.write_all(&[0x05, 1, 0x00]).unwrap();
    let mut method = [0u8; 2];
    s.read_exact(&mut method).unwrap();
    assert_eq!(method, [0x05, 0x00]);

    let mut req = vec![0x05, 0x01, 0x00];
    match host {
        Host::Domain(d) => {
            req.push(0x03);
            req.push(u8::try_from(d.len()).unwrap());
            req.extend_from_slice(d.as_bytes());
        },
        Host::Ip(ip) => match ip {
            std::net::IpAddr::V4(v4) => {
                req.push(0x01);
                req.extend_from_slice(&v4.octets());
            },
            std::net::IpAddr::V6(v6) => {
                req.push(0x04);
                req.extend_from_slice(&v6.octets());
            },
        },
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).unwrap();

    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).unwrap();
    assert_eq!(reply[0], 0x05, "bad reply version");
    assert_eq!(
        reply[1], 0x00,
        "connect not accepted: rep={:#04x}",
        reply[1]
    );
    s
}

fn socks5_connect_rep(client: SocketAddr, host: &Host, port: u16) -> u8 {
    // Same as socks5_connect but without the success assert; returns REP.
    let mut s = timed(TcpStream::connect(client).unwrap());
    s.write_all(&[0x05, 1, 0x00]).unwrap();
    let mut method = [0u8; 2];
    s.read_exact(&mut method).unwrap();
    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    if let Host::Domain(d) = host {
        req[3] = 0x03;
        req.truncate(4);
        req.push(u8::try_from(d.len()).unwrap());
        req.extend_from_slice(d.as_bytes());
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).unwrap();
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).unwrap();
    reply[1]
}

fn echo_roundtrip(s: &mut TcpStream, payload: &[u8]) {
    s.write_all(payload).unwrap();
    let mut got = vec![0u8; payload.len()];
    s.read_exact(&mut got).unwrap();
    assert_eq!(got, payload);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn socks5_tunnel_roundtrip_ipv4_and_domain() {
    let echo = start_echo();
    let server = start_server();
    let client = start_client(server);

    let mut s = socks5_connect(client, &Host::Ip("127.0.0.1".parse().unwrap()), echo.port());
    echo_roundtrip(&mut s, b"hello through the tunnel");
    echo_roundtrip(
        &mut s,
        &(0..255u32)
            .map(|i| u8::try_from(i).unwrap())
            .collect::<Vec<u8>>(),
    );
    drop(s);

    // A domain target reaches the same echo server by name.
    let mut s = socks5_connect(
        client,
        &Host::Domain(String::from("localhost")),
        echo.port(),
    );
    echo_roundtrip(&mut s, b"by-name");
}

#[test]
fn socks5_unreachable_target_reports_failure() {
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap();
        drop(l);
        a
    };
    let client = start_client(start_server());
    let rep = socks5_connect_rep(client, &Host::Ip("127.0.0.1".parse().unwrap()), dead.port());
    assert_eq!(rep, 0x01, "expected general failure for refused target");
}

#[test]
fn half_close_propagates_through_tunnel() {
    let echo = start_echo();
    let server = start_server();
    let client = start_client(server);

    let mut s = socks5_connect(client, &Host::Ip("127.0.0.1".parse().unwrap()), echo.port());
    s.write_all(b"ping").unwrap();
    // Half-close the client side; the FRAME_EOF must reach the echo target,
    // which echoes back "ping" and its own FIN.
    s.shutdown(Shutdown::Write).unwrap();
    let mut got = Vec::new();
    s.read_to_end(&mut got).unwrap();
    assert_eq!(got, b"ping");
}
