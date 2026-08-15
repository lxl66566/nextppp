//! End-to-end tests: real sockets through
//! inbound (socks5/http) -> client routing -> openppp3 tunnel -> server ->
//! echo target, covering both `direct` and `proxy` policies, blocking,
//! half-close propagation and connect failures.

use std::{
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::Arc,
    thread,
    time::Duration,
};

use openppp3_client::ClientRuntime;
use openppp3_common::{
    addr::Host,
    config::{ClientConfig, ObfuscationConfig, ServerSection, SystemProxyConfig},
    Policy, ServerConfig,
};
use openppp3_server::ServerRuntime;

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
                        }
                        Ok(n) => {
                            if conn.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
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
        connect_timeout: 5,
        handshake_timeout: 10,
        obfuscation: ObfuscationConfig::default(),
    };
    let rt = ServerRuntime::from_config(&cfg).unwrap();
    thread::spawn(move || {
        openppp3_server::serve(listener, rt).unwrap();
    });
    addr
}

fn start_client(server: SocketAddr, rules: &[&str], final_policy: Policy) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = ClientConfig {
        listen: addr.to_string(),
        server: ServerSection {
            address: server.to_string(),
            connect_timeout: 5,
            obfuscation: ObfuscationConfig::default(),
        },
        rules: rules.iter().map(|s| (*s).to_owned()).collect(),
        r#final: final_policy,
        system_proxy: SystemProxyConfig::default(),
    };
    let rt = Arc::new(ClientRuntime::from_config(&cfg).unwrap());
    thread::spawn(move || {
        openppp3_client::serve(listener, rt).unwrap();
    });
    addr
}

fn timed(stream: TcpStream) -> TcpStream {
    init_tracing();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
}

/// Enables debug logs for whichever test runs first.
fn init_tracing() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        tracing_subscriber::fmt()
            .with_env_filter("trace")
            .with_test_writer()
            .init();
    });
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
        }
        Host::Ip(ip) => {
            match ip {
                std::net::IpAddr::V4(v4) => {
                    req.push(0x01);
                    req.extend_from_slice(&v4.octets());
                }
                std::net::IpAddr::V6(v6) => {
                    req.push(0x04);
                    req.extend_from_slice(&v6.octets());
                }
            }
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).unwrap();

    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).unwrap();
    assert_eq!(reply[0], 0x05, "bad reply version");
    assert_eq!(reply[1], 0x00, "connect not accepted: rep={:#04x}", reply[1]);
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

/// Performs an HTTP CONNECT handshake, asserting 200.
fn http_connect(client: SocketAddr, authority: &str) -> TcpStream {
    let mut s = timed(TcpStream::connect(client).unwrap());
    s.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .unwrap();
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        s.read_exact(&mut byte).unwrap();
        buf.push(byte[0]);
    }
    let head = String::from_utf8(buf).unwrap();
    assert!(head.starts_with("HTTP/1.1 200"), "unexpected: {head}");
    s
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
    let client = start_client(server, &[], Policy::Proxy);

    let mut s = socks5_connect(
        client,
        &Host::Ip("127.0.0.1".parse().unwrap()),
        echo.port(),
    );
    echo_roundtrip(&mut s, b"hello through the tunnel");
    echo_roundtrip(&mut s, &(0..255u32).map(|i| u8::try_from(i).unwrap()).collect::<Vec<u8>>());
    drop(s);

    // A domain routed via final=proxy reaches the same target by name.
    let mut s = socks5_connect(
        client,
        &Host::Domain(String::from("localhost")),
        echo.port(),
    );
    echo_roundtrip(&mut s, b"by-name");
}

#[test]
fn socks5_direct_rule_bypasses_dead_server() {
    let echo = start_echo();
    // Server address that refuses connections immediately.
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap();
        drop(l); // port now closed; connects get RST (best effort)
        a
    };
    let client = start_client(dead, &["ip-cidr:127.0.0.0/8,direct"], Policy::Proxy);
    let mut s = socks5_connect(client, &Host::Ip("127.0.0.1".parse().unwrap()), echo.port());
    echo_roundtrip(&mut s, b"direct still works");
}

#[test]
fn socks5_block_rule_refuses() {
    let client = start_client(
        start_server(),
        &["domain-suffix:blocked.test,block"],
        Policy::Proxy,
    );
    let rep = socks5_connect_rep(
        client,
        &Host::Domain(String::from("www.blocked.test")),
        443,
    );
    assert_eq!(rep, 0x02);
}

#[test]
fn socks5_unreachable_target_reports_failure() {
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap();
        drop(l);
        a
    };
    let client = start_client(start_server(), &[], Policy::Proxy);
    let rep = socks5_connect_rep(client, &Host::Ip("127.0.0.1".parse().unwrap()), dead.port());
    assert_eq!(rep, 0x01, "expected general failure for refused target");
}

#[test]
fn http_connect_tunnel_roundtrip() {
    let echo = start_echo();
    let server = start_server();
    let client = start_client(server, &[], Policy::Proxy);

    let mut s = http_connect(client, &format!("127.0.0.1:{}", echo.port()));
    echo_roundtrip(&mut s, b"http connect payload");
}

#[test]
fn http_plain_request_passthrough() {
    let echo = start_echo();
    let server = start_server();
    let client = start_client(server, &[], Policy::Proxy);

    // Plain absolute-form GET: the client must forward it verbatim, so the
    // echo target returns the exact same bytes back to us.
    let mut s = timed(TcpStream::connect(client).unwrap());
    let req = format!("GET http://127.0.0.1:{}/x HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", echo.port());
    s.write_all(req.as_bytes()).unwrap();
    let mut got = vec![0u8; req.len()];
    s.read_exact(&mut got).unwrap();
    assert_eq!(got, req.as_bytes());
}

#[test]
fn http_block_rule_forbidden() {
    let echo = start_echo();
    let client = start_client(
        start_server(),
        &["domain:blocked.test,block"],
        Policy::Proxy,
    );
    let mut s = timed(TcpStream::connect(client).unwrap());
    s.write_all(b"CONNECT blocked.test:443 HTTP/1.1\r\nHost: blocked.test\r\n\r\n")
        .unwrap();
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        match s.read(&mut byte) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                buf.push(byte[0]);
                if buf.len() > 1024 {
                    break;
                }
            }
        }
    }
    let head = String::from_utf8_lossy(&buf);
    assert!(head.starts_with("HTTP/1.1 403"), "unexpected: {head}");
    let _ = echo;
}

#[test]
fn half_close_propagates_through_tunnel() {
    let echo = start_echo();
    let server = start_server();
    let client = start_client(server, &[], Policy::Proxy);

    let mut s = socks5_connect(client, &Host::Ip("127.0.0.1".parse().unwrap()), echo.port());
    s.write_all(b"ping").unwrap();
    // Half-close the client side; the FRAME_EOF must reach the echo target,
    // which echoes back "ping" and its own FIN.
    s.shutdown(Shutdown::Write).unwrap();
    let mut got = Vec::new();
    s.read_to_end(&mut got).unwrap();
    assert_eq!(got, b"ping");
}
