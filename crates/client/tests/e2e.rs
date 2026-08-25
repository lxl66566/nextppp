//! End-to-end tests: real sockets through
//! socks5 inbound -> mux tunnel pool -> server -> echo target, covering
//! IP/domain targets, connect failures, half-close propagation, pool
//! sharing and pool recovery after tunnel death.

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use nextppp_client::ClientRuntime;
use nextppp_common::{
    addr::{Host, ProxyAddr},
    config::{ClientConfig, MuxSection, ObfuscationConfig, ServerConfig, ServerSection},
    dns::DnsCache,
    mux::{FrameHeader, FrameKind, parse_frame},
    proto::{STATUS_OK, STATUS_REFUSED},
    pump,
};
use nextppp_core::{ObfuscationKey, SessionRx, SessionTx, Transmission};
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
        max_handshakes: None,
        max_streams_per_conn: None,
        obfuscation: ObfuscationConfig::default(),
    };
    let rt = ServerRuntime::from_config(&cfg).unwrap();
    thread::spawn(move || {
        nextppp_server::serve(listener, rt).unwrap();
    });
    addr
}

fn start_client(server: SocketAddr) -> SocketAddr {
    start_client_with(server, 0, 4)
}

fn start_client_with(server: SocketAddr, connect_retries: u32, pool_size: u32) -> SocketAddr {
    start_client_full(server, 5, connect_retries, pool_size, 64)
}

/// Full-fidelity client harness: explicit `connect_timeout`, retry count,
/// pool size and per-tunnel stream cap (saturation tests need them).
fn start_client_full(
    server: SocketAddr,
    connect_timeout: u64,
    connect_retries: u32,
    pool_size: u32,
    max_streams: u32,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = ClientConfig {
        listen: addr.to_string(),
        password: None,
        max_connections: None,
        server: ServerSection {
            address: server.to_string(),
            connect_timeout,
            connect_retries,
            mux: MuxSection {
                enabled: true,
                pool_size,
                max_streams,
            },
            obfuscation: ObfuscationConfig::default(),
        },
    };
    let rt = Arc::new(ClientRuntime::from_config(&cfg).unwrap());
    thread::spawn(move || {
        nextppp_client::serve(listener, rt).unwrap();
    });
    addr
}

/// Waits until `cond` holds, panicking after a generous timeout.
fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    for _ in 0..100 {
        if cond() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out waiting for {what}");
}

// ---------------------------------------------------------------------------
// Minimal in-test mux server: an independent, synchronous implementation of
// the mux wire protocol (handshake -> demux -> target pumps), used to prove
// interop and to inject tunnel-level failures the real server never causes.
// ---------------------------------------------------------------------------

/// Accepts connections but never speaks: a dial attempt against it burns
/// its full handshake timeout (the slowest failure mode — unlike RST).
fn start_blackhole() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        // Hold every accepted socket open forever (test-lifetime leak on
        // purpose; the blackhole must not close anything).
        for conn in listener.incoming().flatten() {
            Box::leak(Box::new(conn));
        }
    });
    addr
}

/// A stand-in server address whose connection #0 is forwarded to `first`
/// and every later connection to `rest`. Downlink chunks are delayed a
/// few milliseconds to model real-network RTT: on pure loopback a REPLY
/// can outrun `timeout(Duration::ZERO)`'s ~1ms timer tick and mask
/// deadline-budget bugs.
fn start_flaky_forwarder(first: SocketAddr, rest: SocketAddr) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let conns = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&conns);
    thread::spawn(move || {
        for (i, conn) in listener.incoming().enumerate() {
            let mut conn = conn.unwrap();
            seen.fetch_add(1, Ordering::Relaxed);
            let target = if i == 0 {
                first
            } else {
                rest
            };
            let up = TcpStream::connect(target).unwrap();
            let up_dn = up.try_clone().unwrap();
            // target -> client (downlink, delayed per chunk)
            let mut dn = conn.try_clone().unwrap();
            thread::spawn(move || {
                let mut up = up_dn;
                let mut buf = [0u8; 8192];
                loop {
                    match up.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            thread::sleep(Duration::from_millis(2));
                            if dn.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        },
                    }
                }
            });
            // client -> target (uplink, plain)
            thread::spawn(move || {
                let mut up = up;
                let mut buf = [0u8; 8192];
                loop {
                    match conn.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if up.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        },
                    }
                }
            });
        }
    });
    (addr, conns)
}

/// Shared mux writer: encrypts `kind || sid || payload` frames on demand.
/// The mutex serializes the tx cipher across per-stream pump threads.
struct SyncWriter(Mutex<(SessionTx, TcpStream)>);

impl SyncWriter {
    fn send(&self, kind: FrameKind, sid: u32, payload: &[u8]) -> std::io::Result<()> {
        let mut guard = self.0.lock().unwrap();
        let (session, io) = &mut *guard;
        let mut out = Vec::new();
        session
            .encrypt_into_prefixed(&mut out, FrameHeader::new(kind, sid).as_slice(), payload)
            .map_err(std::io::Error::other)?;
        io.write_all(&out)
    }
}

/// Blocking variant of the async FrameReader: one complete mux message per
/// call, `None` on EOF/error.
fn next_frame(srx: &mut SessionRx, io: &mut TcpStream, buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    loop {
        match srx.poll_frame(buf) {
            Ok(Some(msg)) => {
                let frame = msg.to_vec();
                let used = srx.take_consumed();
                buf.drain(..used);
                return Some(frame);
            },
            Ok(None) => {},
            Err(_) => return None,
        }
        let mut tmp = [0u8; 8192];
        match io.read(&mut tmp) {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
}

#[derive(Clone, Copy)]
struct MiniServer {
    rst_first: bool,
    drop_on_first_data: bool,
}

/// Starts the mini mux server, returning its address and the completed-
/// handshake counter.
fn start_mini_server(opts: MiniServer) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handshakes = Arc::new(AtomicUsize::new(0));
    let hs = Arc::clone(&handshakes);
    thread::spawn(move || {
        for (i, conn) in listener.incoming().enumerate() {
            let conn = conn.unwrap();
            if opts.rst_first && i == 0 {
                // linger(0) turns the close into a RST: the client's
                // in-flight handshake attempt dies with ECONNRESET.
                // (`TcpStream::set_linger` is unstable; socket2 it is.)
                socket2::SockRef::from(&conn)
                    .set_linger(Some(Duration::ZERO))
                    .unwrap();
                drop(conn);
                continue;
            }
            let hs = Arc::clone(&hs);
            let drop_on_first_data = opts.drop_on_first_data;
            thread::spawn(move || serve_mux(conn, &hs, drop_on_first_data));
        }
    });
    (addr, handshakes)
}

/// Serves one mux tunnel against live targets (the loopback echo in
/// practice). With `drop_on_first_data` the tunnel dies on the first DATA
/// frame, simulating a mid-stream tunnel reset.
fn serve_mux(conn: TcpStream, handshakes: &Arc<AtomicUsize>, drop_on_first_data: bool) {
    let mut t = Transmission::new(conn, ObfuscationKey::default());
    if t.handshake_server(7, true).is_err() {
        return;
    }
    handshakes.fetch_add(1, Ordering::Relaxed);
    let (session, io) = t.into_session();
    let (stx, mut srx) = session.split();
    let writer = Arc::new(SyncWriter(Mutex::new((
        stx,
        io.try_clone().expect("clone tunnel stream"),
    ))));
    let targets: Arc<Mutex<HashMap<u32, Arc<TcpStream>>>> = Arc::new(Mutex::new(HashMap::new()));
    let mut io = io;
    run_mux(&mut io, &mut srx, &writer, &targets, drop_on_first_data);
    // The writer's cloned handle keeps the socket alive in target-pump
    // threads; kill the socket explicitly so the client observes the
    // tunnel death.
    let _ = io.shutdown(Shutdown::Both);
}

/// The demux loop of [`serve_mux`].
fn run_mux(
    io: &mut TcpStream,
    srx: &mut SessionRx,
    writer: &Arc<SyncWriter>,
    targets: &Arc<Mutex<HashMap<u32, Arc<TcpStream>>>>,
    drop_on_first_data: bool,
) {
    let mut buf = Vec::new();
    while let Some(msg) = next_frame(srx, io, &mut buf) {
        let Ok((kind, sid, payload)) = parse_frame(&msg) else {
            return;
        };
        match kind {
            FrameKind::Open => {
                let addr = ProxyAddr::decode(payload).expect("mini server: valid OPEN");
                match pump::tcp_connect(
                    &addr.host,
                    addr.port,
                    Duration::from_secs(5),
                    &DnsCache::new(),
                ) {
                    Ok(target) => {
                        if writer.send(FrameKind::Reply, sid, &[STATUS_OK]).is_err() {
                            return;
                        }
                        let target = Arc::new(target);
                        targets.lock().unwrap().insert(sid, Arc::clone(&target));
                        // Target -> tunnel pump.
                        let writer = Arc::clone(writer);
                        let targets = Arc::clone(targets);
                        thread::spawn(move || {
                            let mut buf = [0u8; 8192];
                            loop {
                                match target.as_ref().read(&mut buf) {
                                    Ok(0) => {
                                        let _ = writer.send(FrameKind::Eof, sid, &[]);
                                        break;
                                    },
                                    Ok(n) => {
                                        if writer.send(FrameKind::Data, sid, &buf[..n]).is_err() {
                                            break;
                                        }
                                    },
                                    Err(_) => {
                                        let _ = writer.send(FrameKind::Close, sid, &[]);
                                        break;
                                    },
                                }
                            }
                            targets.lock().unwrap().remove(&sid);
                        });
                    },
                    Err(_) => {
                        if writer
                            .send(FrameKind::Reply, sid, &[STATUS_REFUSED])
                            .is_err()
                        {
                            return;
                        }
                    },
                }
            },
            FrameKind::Data => {
                if drop_on_first_data {
                    return; // tunnel dies mid-stream
                }
                let target = targets.lock().unwrap().get(&sid).cloned();
                if let Some(target) = target {
                    if target.as_ref().write_all(payload).is_err() {
                        targets.lock().unwrap().remove(&sid);
                    }
                }
            },
            FrameKind::Eof => {
                let target = targets.lock().unwrap().get(&sid).cloned();
                if let Some(target) = target {
                    let _ = target.shutdown(Shutdown::Write);
                }
            },
            FrameKind::Close => {
                let target = targets.lock().unwrap().remove(&sid);
                if let Some(target) = target {
                    let _ = target.shutdown(Shutdown::Both);
                }
            },
            FrameKind::Reply => return, // role violation
        }
    }
}

// ---------------------------------------------------------------------------
// SOCKS5 client-side helpers
// ---------------------------------------------------------------------------

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
    let rep = socks5_connect_raw(client, host, port);
    assert_eq!(rep.1, 0x00, "connect not accepted: rep={:#04x}", rep.1);
    rep.0
}

/// Same as [`socks5_connect`] but returns the reply code instead of
/// asserting on it.
fn socks5_connect_rep(client: SocketAddr, host: &Host, port: u16) -> u8 {
    socks5_connect_raw(client, host, port).1
}

fn socks5_connect_raw(client: SocketAddr, host: &Host, port: u16) -> (TcpStream, u8) {
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
    (s, reply[1])
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
fn retry_recovers_from_rst_during_handshake() {
    let echo = start_echo();
    // First pool dial is RST mid-handshake; only a retry can succeed.
    let (server, handshakes) = start_mini_server(MiniServer {
        rst_first: true,
        drop_on_first_data: false,
    });
    let client = start_client_with(server, 1, 1);

    let mut s = socks5_connect(client, &Host::Ip("127.0.0.1".parse().unwrap()), echo.port());
    echo_roundtrip(&mut s, b"second attempt wins");
    assert_eq!(
        handshakes.load(Ordering::Relaxed),
        1,
        "the RST attempt dies pre-handshake; exactly one tunnel handshakes"
    );
}

/// Regression: a dial whose first attempt burns the whole connect_timeout
/// (black hole) and whose retry then succeeds must still complete the
/// OPEN/REPLY exchange. With a deadline shared across dial and open, the
/// dial always spent the whole budget and the OPEN failed with a fake
/// REPLY timeout.
#[test]
fn slow_retry_dial_does_not_starve_the_open_exchange() {
    let echo = start_echo();
    let server = start_server();
    let (fwd, conns) = start_flaky_forwarder(start_blackhole(), server);
    // 2s budget, one retry: attempt 1 eats its full timeout in the black
    // hole, attempt 2 reaches the real server.
    let client = start_client_full(fwd, 2, 1, 0, 64);

    let t0 = Instant::now();
    let mut s = socks5_connect(client, &Host::Ip("127.0.0.1".parse().unwrap()), echo.port());
    let elapsed = t0.elapsed();
    echo_roundtrip(&mut s, b"fresh budget for the open");
    assert_eq!(
        conns.load(Ordering::Relaxed),
        2,
        "the blackhole attempt plus one retry"
    );
    assert!(
        elapsed >= Duration::from_secs(2),
        "the blackhole attempt must burn its full timeout ({elapsed:?})"
    );
    assert!(
        elapsed < Duration::from_secs(4),
        "the open exchange must not wait out another full timeout ({elapsed:?})"
    );
}

#[test]
fn refused_target_is_not_retried() {
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap();
        drop(l);
        a
    };
    let (server, handshakes) = start_mini_server(MiniServer {
        rst_first: false,
        drop_on_first_data: false,
    });
    let client = start_client_with(server, 2, 1);
    let rep = socks5_connect_rep(client, &Host::Ip("127.0.0.1".parse().unwrap()), dead.port());
    assert_eq!(rep, 0x01, "expected general failure for refused target");
    assert_eq!(
        handshakes.load(Ordering::Relaxed),
        1,
        "REPLY REFUSED is a per-stream verdict; no redial must fire"
    );
}

#[test]
fn half_close_propagates_through_tunnel() {
    let echo = start_echo();
    let server = start_server();
    let client = start_client(server);

    let mut s = socks5_connect(client, &Host::Ip("127.0.0.1".parse().unwrap()), echo.port());
    s.write_all(b"ping").unwrap();
    // Half-close the client side; the EOF frame must reach the echo target,
    // which echoes back "ping" and its own FIN.
    s.shutdown(Shutdown::Write).unwrap();
    let mut got = Vec::new();
    s.read_to_end(&mut got).unwrap();
    assert_eq!(got, b"ping");
}

#[test]
fn pool_tunnels_are_shared_across_socks_connections() {
    let echo = start_echo();
    let (server, handshakes) = start_mini_server(MiniServer {
        rst_first: false,
        drop_on_first_data: false,
    });
    let client = start_client_with(server, 0, 2);

    // The pool warms up to its configured size without any traffic.
    wait_until("pool warmup", || handshakes.load(Ordering::Relaxed) >= 2);

    // Eight concurrent proxied connections must all work while the tunnel
    // count stays at the pool size: streams share tunnels.
    let mut threads = Vec::new();
    for i in 0..8u8 {
        threads.push(thread::spawn(move || {
            let mut s =
                socks5_connect(client, &Host::Ip("127.0.0.1".parse().unwrap()), echo.port());
            echo_roundtrip(&mut s, &[i; 1024]);
        }));
    }
    for t in threads {
        t.join().unwrap();
    }
    // No tunnel may have been dialed for the burst.
    thread::sleep(Duration::from_millis(200));
    assert_eq!(
        handshakes.load(Ordering::Relaxed),
        2,
        "streams must share pool tunnels; no per-CONNECT dials"
    );
}

#[test]
fn tunnel_death_fails_streams_and_pool_recovers() {
    let echo = start_echo();
    let (server, handshakes) = start_mini_server(MiniServer {
        rst_first: false,
        drop_on_first_data: true,
    });
    let client = start_client_with(server, 0, 1);

    // First connection: opens fine, then the tunnel dies on the first DATA
    // frame — the in-flight stream must fail instead of hanging.
    let mut s = socks5_connect(client, &Host::Ip("127.0.0.1".parse().unwrap()), echo.port());
    s.write_all(b"trigger the drop").unwrap();
    let mut buf = [0u8; 16];
    let result = s.read(&mut buf);
    assert!(
        matches!(result, Ok(0) | Err(_)),
        "dead tunnel must surface as a closed socks connection, got {result:?}"
    );
    drop(s);

    // The maintainer dials a replacement; new connections work again.
    wait_until("pool recovery", || handshakes.load(Ordering::Relaxed) >= 2);
    let rep = socks5_connect_rep(client, &Host::Ip("127.0.0.1".parse().unwrap()), echo.port());
    assert_eq!(rep, 0x00, "recovered pool must accept new streams");
}
