//! Bond (link aggregation) throughput benchmark: one logical bulk stream
//! carried over N aggregated TCP links vs the plain single-link path.
//!
//! ```text
//! cargo test -p nextppp-client --release --test bond_bench -- --ignored --nocapture
//! ```
//!
//! Two phases:
//!
//! * Unshaped loopback — measures the pipeline ceiling. On 127.0.0.1 a single TCP connection faces
//!   no congestion window or loss ceiling, so this can only expose per-link cipher parallelism and
//!   aggligator's own cost; the congestion-window gain that motivates bonding on real lossy WAN
//!   links is invisible here.
//! * Per-flow shaped — every TCP connection to the nextppp endpoints goes through a token-bucket
//!   forwarder capped at `SHAPED_FLOW_CAP`, modeling a per-flow WAN bandwidth ceiling. This is
//!   where aggregation must show its N-times multiplier (until the phase-1 pipeline ceiling).
//!
//! Override the transfer sizes with `NEXTPPP_BOND_BYTES` (unshaped) and
//! `NEXTPPP_BOND_SHAPED_BYTES` (shaped).

use std::{
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
use nextppp_common::config::{
    BondClientSection, BondServerSection, ClientConfig, MuxSection, ObfuscationConfig,
    ServerConfig, ServerSection,
};
use nextppp_server::ServerRuntime;

/// Echo buffer: large enough that the loopback echo is never the bottleneck.
const ECHO_BUF: usize = 64 * 1024;

/// Transfer chunk size for the timed bulk phase.
const CHUNK: usize = 64 * 1024;

/// Default bytes moved in one direction per timed run (unshaped phase).
const DEFAULT_BYTES: usize = 256 * 1024 * 1024;

/// Default bytes per run of the shaped phase (slower, so smaller).
const DEFAULT_SHAPED_BYTES: usize = 64 * 1024 * 1024;

/// Per-flow ceiling of the shaped phase, in bytes/s (20 MiB/s per TCP
/// connection, both directions).
const SHAPED_FLOW_CAP: f64 = 20.0 * 1024.0 * 1024.0;

/// Token-bucket refill tick of the shaper: 8ms keeps refills inside Windows
/// timer granularity while pacing at percent-level accuracy.
const SHAPER_TICK_MS: u64 = 8;

/// Timed runs per path; the best one approximates the achievable peak.
const RUNS: usize = 3;

/// Bond link-count matrix; `1` isolates aggligator's own overhead over the
/// plain path (both carry the stream over a single TCP connection).
const LINKS: [u32; 4] = [1, 2, 4, 8];

/// Loopback echo target that reflects bytes and propagates half-closes.
fn start_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::Builder::new()
        .name("bond-bench-echo".to_owned())
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

/// Server with a bond link listener; returns (plain, bond) addresses.
fn start_bond_server() -> (SocketAddr, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let bond_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let bond_addr = bond_listener.local_addr().unwrap();
    let cfg = ServerConfig {
        listen: addr.to_string(),
        bond: Some(BondServerSection {
            listen: bond_addr.to_string(),
        }),
        password: None,
        connect_timeout: 5,
        handshake_timeout: 10,
        max_connections: None,
        max_handshakes: None,
        max_streams_per_conn: None,
        obfuscation: ObfuscationConfig::default(),
    };
    let rt = ServerRuntime::from_config(&cfg).unwrap();
    thread::Builder::new()
        .name("bond-bench-server".to_owned())
        .spawn(move || {
            nextppp_server::serve(listener, Some(bond_listener), rt).unwrap();
        })
        .unwrap();
    (addr, bond_addr)
}

/// Client with both inbounds and a bond pool of `links` links per tunnel;
/// returns (plain inbound, bond inbound).
fn start_bond_client(
    server: SocketAddr,
    bond_listener: SocketAddr,
    links: u32,
) -> (SocketAddr, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let bond_in = TcpListener::bind("127.0.0.1:0").unwrap();
    let bond_in_addr = bond_in.local_addr().unwrap();
    let cfg = ClientConfig {
        listen: addr.to_string(),
        bond: Some(BondClientSection {
            listen: bond_in_addr.to_string(),
            links,
            pool_size: 1,
            max_streams: 64,
        }),
        password: None,
        max_connections: None,
        server: ServerSection {
            address: server.to_string(),
            bond_address: Some(bond_listener.to_string()),
            connect_timeout: 5,
            connect_retries: 1,
            mux: MuxSection {
                enabled: true,
                pool_size: 1,
                max_streams: 64,
            },
            obfuscation: ObfuscationConfig::default(),
        },
    };
    let rt = Arc::new(ClientRuntime::from_config(&cfg).unwrap());
    thread::Builder::new()
        .name(format!("bond-bench-client-{links}"))
        .spawn(move || {
            nextppp_client::serve(listener, Some(bond_in), rt).unwrap();
        })
        .unwrap();
    (addr, bond_in_addr)
}

/// Refills the token bucket for the whole interval since `last` (possibly
/// spanning several ticks, e.g. time parked in `read`), in place.
fn refill_tokens(tokens: &mut usize, last: &mut Instant, per_tick: usize, cap: usize) {
    let elapsed = u64::try_from(last.elapsed().as_millis()).unwrap_or(u64::MAX);
    let ticks = elapsed / SHAPER_TICK_MS;
    if ticks > 0 {
        *tokens = (*tokens + per_tick * ticks as usize).min(cap);
        *last += Duration::from_millis(ticks * SHAPER_TICK_MS);
    }
}

/// Accounting for one accepted shaper flow: bytes relayed per direction.
struct FlowStat {
    peer: SocketAddr,
    opened: Instant,
    c2s: Arc<AtomicUsize>,
    s2c: Arc<AtomicUsize>,
}

/// Registry of all flows a shaper accepted, for post-run attribution.
type FlowLog = Arc<Mutex<Vec<Arc<FlowStat>>>>;

/// Copies one direction, capping the flow at `per_flow` bytes/s with a
/// token bucket (8ms refills, 4-tick burst cap), counting into `moved`.
/// Models a per-TCP-flow WAN bandwidth ceiling: TCP flow control
/// back-pressures the sender onto the bucket pace, exactly like a
/// rate-limited carrier.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
fn shaped_relay(mut from: TcpStream, mut to: TcpStream, per_flow: f64, moved: &AtomicUsize) {
    let per_tick = (per_flow * SHAPER_TICK_MS as f64 / 1000.0).ceil() as usize;
    let cap = per_tick.saturating_mul(4);
    let mut tokens = per_tick;
    let mut last = Instant::now();
    let mut buf = vec![0u8; CHUNK];
    loop {
        refill_tokens(&mut tokens, &mut last, per_tick, cap);
        let n = match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let mut off = 0;
        while off < n {
            if tokens == 0 {
                thread::sleep(Duration::from_millis(SHAPER_TICK_MS));
                refill_tokens(&mut tokens, &mut last, per_tick, cap);
                continue;
            }
            let len = (n - off).min(tokens).min(buf.len());
            if to.write_all(&buf[off..off + len]).is_err() {
                return;
            }
            moved.fetch_add(len, Ordering::Relaxed);
            tokens -= len;
            off += len;
        }
    }
    let _ = to.shutdown(Shutdown::Write);
}

/// Forwards every accepted TCP connection to `target` with each connection
/// (and each direction) capped at `per_flow` bytes/s. Independent relay
/// threads per connection: N bonded links hit N independent caps. Returns
/// the listen address and a per-flow byte log.
fn start_shaper(target: SocketAddr, per_flow: f64) -> (SocketAddr, FlowLog) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let log: FlowLog = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&log);
    thread::Builder::new()
        .name("bond-bench-shaper".to_owned())
        .spawn(move || {
            for conn in listener.incoming().flatten() {
                let stat = Arc::new(FlowStat {
                    peer: conn.peer_addr().unwrap(),
                    opened: Instant::now(),
                    c2s: Arc::new(AtomicUsize::new(0)),
                    s2c: Arc::new(AtomicUsize::new(0)),
                });
                seen.lock().unwrap().push(Arc::clone(&stat));
                let up = TcpStream::connect(target).unwrap();
                let up_dn = up.try_clone().unwrap();
                let dn = conn.try_clone().unwrap();
                let f = per_flow;
                let c2s = Arc::clone(&stat.c2s);
                let s2c = Arc::clone(&stat.s2c);
                thread::spawn(move || shaped_relay(conn, up, f, &c2s));
                thread::spawn(move || shaped_relay(up_dn, dn, f, &s2c));
            }
        })
        .unwrap();
    (addr, log)
}

/// Prints every flow's open time (relative to `phase_start`) and relayed
/// bytes, so a path's bandwidth can be attributed to individual flows.
#[allow(clippy::cast_precision_loss)] // byte counters: exact in f64
fn print_flows(name: &str, phase_start: Instant, log: &FlowLog) {
    eprintln!("shaper {name} flows:");
    for f in log.lock().unwrap().iter() {
        let open = f.opened.duration_since(phase_start).as_secs_f64();
        let c2s = f.c2s.load(Ordering::Relaxed) as f64 / (1024.0 * 1024.0);
        let s2c = f.s2c.load(Ordering::Relaxed) as f64 / (1024.0 * 1024.0);
        eprintln!(
            "  +{open:6.1}s  {peer:<22} c2s {c2s:9.1} MiB  s2c {s2c:9.1} MiB",
            peer = f.peer
        );
    }
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
        panic!("bond bench uses IPv4 targets only");
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
/// same amount back on the main thread (echo), returning the one-way rate.
/// The stream is NOT half-closed afterwards: the echo propagates half-closes
/// and [`RUNS`] reuses the same stream. Data integrity is checked separately
/// by the probe before the first run.
fn blast(stream: &mut TcpStream, size: usize) -> f64 {
    let mut send = stream.try_clone().unwrap();
    let started = Instant::now();

    let writer = thread::spawn(move || {
        let buf = vec![0u8; CHUNK];
        let mut remaining = size;
        while remaining > 0 {
            let n = remaining.min(buf.len());
            send.write_all(&buf[..n]).unwrap();
            remaining -= n;
        }
        // Dropping this clone leaves the shared socket open (the reader
        // still holds a handle), so the next run can write again.
    });

    let mut sink = vec![0u8; CHUNK];
    let mut remaining = size;
    while remaining > 0 {
        let n = remaining.min(sink.len());
        stream.read_exact(&mut sink[..n]).unwrap();
        remaining -= n;
    }
    writer.join().unwrap();

    mib_per_sec(size, started.elapsed())
}

fn total_bytes() -> usize {
    std::env::var("NEXTPPP_BOND_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_BYTES)
}

fn shaped_bytes() -> usize {
    std::env::var("NEXTPPP_BOND_SHAPED_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_SHAPED_BYTES)
}

/// Connects through `inbound`, verifies integrity with a probe, then runs
/// [`RUNS`] timed blasts, returning the per-run one-way rates.
fn measure(inbound: SocketAddr, echo: SocketAddr, size: usize) -> Vec<f64> {
    let mut stream = socks5_connect(inbound, echo);

    let probe = b"bond bench probe 0123456789abcdef";
    stream.write_all(probe).unwrap();
    let mut got = vec![0u8; probe.len()];
    stream.read_exact(&mut got).unwrap();
    assert_eq!(got, probe, "probe round-trip corrupted");

    (0..RUNS).map(|_| blast(&mut stream, size)).collect()
}

#[test]
#[ignore = "slow multi-phase benchmark (256 + 64 MiB per run); run manually in release mode"]
fn bond_link_scaling() {
    let echo = start_echo();
    let (server, bond_listener) = start_bond_server();
    let cores = thread::available_parallelism().map_or(1, std::num::NonZero::get);
    eprintln!("bond bench: loopback, {cores} logical cores");

    // Phase 1: raw loopback — the pipeline ceiling, no per-flow cap. This
    // is NOT where aggregation helps: a single loopback TCP flow has no
    // bandwidth ceiling to multiply.
    run_matrix(
        "phase 1: unshaped (pipeline ceiling)",
        server,
        bond_listener,
        echo,
        total_bytes(),
    );

    // Phase 2: every TCP flow capped at 20 MiB/s — the per-flow WAN ceiling
    // aggregation exists to beat.
    let (plain_shaped, plain_log) = start_shaper(server, SHAPED_FLOW_CAP);
    let (bond_shaped, bond_log) = start_shaper(bond_listener, SHAPED_FLOW_CAP);
    let phase2 = Instant::now();
    run_matrix(
        "phase 2: per-flow shaped at 20 MiB/s (WAN per-flow ceiling)",
        plain_shaped,
        bond_shaped,
        echo,
        shaped_bytes(),
    );
    print_flows("plain", phase2, &plain_log);
    print_flows("bond", phase2, &bond_log);
}

/// Runs the plain + bond-`LINKS` matrix against `plain_via`/`bond_via`
/// (endpoints directly, or a shaping forwarder in front of them): one
/// client per link count, one bulk stream per inbound. Prints per-run and
/// best-of rates; returns the per-path best one-way rates (plain first).
fn run_matrix(
    name: &str,
    plain_via: SocketAddr,
    bond_via: SocketAddr,
    echo: SocketAddr,
    size: usize,
) -> Vec<f64> {
    // One client per link count; the links=1 client's plain inbound doubles
    // as the no-aggregator baseline (identical config otherwise).
    let mut inbounds: Vec<(String, SocketAddr)> = Vec::new();
    for links in LINKS {
        let (plain_in, bond_in) = start_bond_client(plain_via, bond_via, links);
        if links == 1 {
            inbounds.push(("plain  1 tcp".to_owned(), plain_in));
        }
        inbounds.push((format!("bond  {links} tcp"), bond_in));
    }

    eprintln!("--- {name}: {RUNS} runs x {size} bytes per direction ---");
    let mut bests = Vec::new();
    for (label, inbound) in &inbounds {
        let rates = measure(*inbound, echo, size);
        eprintln!(
            "  {label}: {} MiB/s",
            rates
                .iter()
                .map(|r| format!("{r:.1}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let best = rates.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        assert!(best >= 1.0, "{label} suspiciously low: {best:.2} MiB/s");
        bests.push(best);
    }

    let base = if bests[0] > 0.0 && bests[0].is_finite() {
        bests[0]
    } else {
        1.0
    };
    eprintln!("  peak one-way rate (best of {RUNS}):");
    for ((label, _), best) in inbounds.iter().zip(&bests) {
        eprintln!(
            "  {label:<12} {best:9.2} MiB/s   x{:.2} vs plain",
            best / base
        );
    }
    bests
}

/// Calibrates the shaper in isolation: N raw TCP echo streams through it
/// must aggregate to N x the per-flow cap. Any systematic deviation here is
/// a shaper bug and invalidates the shaped phase above.
#[test]
#[ignore = "manual shaper calibration (about 6s)"]
fn shaper_calibration() {
    let echo = start_echo();
    let (shaped, log) = start_shaper(echo, SHAPED_FLOW_CAP);
    let phase = Instant::now();
    let size = 32 * 1024 * 1024;
    for n in [1u8, 2, 4] {
        let started = Instant::now();
        let mut joins = Vec::new();
        for _ in 0..n {
            let mut s = TcpStream::connect(shaped).unwrap();
            joins.push(thread::spawn(move || blast(&mut s, size)));
        }
        for j in joins {
            j.join().unwrap();
        }
        let expect = f64::from(n) * SHAPED_FLOW_CAP / (1024.0 * 1024.0);
        eprintln!(
            "  {n} raw flow(s): {:.2} MiB/s aggregate (expect ~{expect:.0})",
            mib_per_sec(usize::from(n) * size, started.elapsed())
        );
    }
    print_flows("calibration", phase, &log);
}
