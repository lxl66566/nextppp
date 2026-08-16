//! Regression tests for pump teardown semantics over real loopback sockets.

use std::{
    io::Read,
    net::{TcpListener, TcpStream},
    thread,
    time::Duration,
};

use nextppp_common::{PumpEnd, pump};
use nextppp_core::{ObfuscationKey, Transmission};

/// Builds a handshaked transmission pair over loopback TCP.
fn tunnel_pair() -> (Transmission<TcpStream>, Transmission<TcpStream>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut t = Transmission::new(stream, ObfuscationKey::default());
        t.handshake_server(1, false).unwrap();
        t
    });
    let mut client =
        Transmission::new(TcpStream::connect(addr).unwrap(), ObfuscationKey::default());
    client.handshake_client().unwrap();
    (client, server.join().unwrap())
}

/// A non-graceful tunnel death (bare TCP FIN without an in-band FRAME_EOF)
/// must tear down the whole session: the sibling pump blocked on the idle
/// local socket has to wake up instead of hanging forever.
#[test]
fn tunnel_death_tears_down_local_side() {
    let (client, server) = tunnel_pair();
    let local_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let local_addr = local_listener.local_addr().unwrap();
    let pump_thread = thread::spawn(move || {
        let local = TcpStream::connect(local_addr).unwrap();
        let rx_io = client.io().try_clone().unwrap();
        let (tx, rx) = client.split_with(rx_io);
        pump::pump_tunnel(tx, rx, local)
    });
    let (mut peer, _) = local_listener.accept().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    drop(server);

    // Pre-fix the pump hung on the idle local read forever; now the local
    // peer must observe the teardown and the pump must return.
    let mut buf = [0u8; 16];
    let n = peer.read(&mut buf).unwrap();
    assert_eq!(n, 0, "local side must observe teardown");
    let stats = pump_thread.join().unwrap();
    assert!(
        !matches!(stats.down_end, PumpEnd::Eof(_)),
        "a bare tunnel FIN is not a graceful half-close"
    );
}
