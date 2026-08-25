//! Async tunnel drivers over real loopback sockets: writer batching,
//! incremental frame reassembly and clean-EOF propagation.

use std::{net::TcpListener, thread};

use nextppp_common::{
    mux::{FrameKind, parse_frame},
    tunnel::{FrameReader, OutFrame, run_writer},
};
use nextppp_core::{ObfuscationKey, SessionRx, SessionTx, Transmission};
use tokio::sync::mpsc;

/// Handshakes a loopback pair and returns both ends as split async
/// halves over tokio streams.
async fn tunnel_pair() -> (
    (SessionTx, SessionRx, tokio::net::TcpStream),
    (SessionTx, SessionRx, tokio::net::TcpStream),
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut t = Transmission::new(stream, ObfuscationKey::default());
        t.handshake_server(1, true).unwrap();
        t
    });
    let mut client = Transmission::new(
        std::net::TcpStream::connect(addr).unwrap(),
        ObfuscationKey::default(),
    );
    client.handshake_client().unwrap();
    let server = server.join().unwrap();

    let to_async = |t: Transmission<std::net::TcpStream>| {
        let (session, io) = t.into_session();
        io.set_nonblocking(true).unwrap();
        let sock = tokio::net::TcpStream::from_std(io).unwrap();
        let (tx, rx) = session.split();
        (tx, rx, sock)
    };
    (to_async(client), to_async(server))
}

#[tokio::test]
async fn writer_reader_roundtrip_mixed_sizes() {
    let ((client_tx, _, client_sock), (_, server_rx, server_sock)) = tunnel_pair().await;
    let (client_rh, client_wh) = client_sock.into_split();
    let (server_rh, _server_wh) = server_sock.into_split();
    drop(client_rh);

    let (out_tx, out_rx) = mpsc::channel::<OutFrame>(256);
    let writer = tokio::spawn(run_writer(client_tx, client_wh, out_rx));
    let mut reader = FrameReader::new(server_rx, server_rh);

    let payloads: Vec<Vec<u8>> = vec![
        b"one".to_vec(),
        vec![0x55; 16 * 1024],
        b"three".to_vec(),
        vec![0xaa; 60_000],
    ];
    for (i, p) in payloads.iter().enumerate() {
        out_tx
            .send(OutFrame::new(FrameKind::Data, i as u32 + 1, p.clone()))
            .await
            .unwrap();
    }
    for (i, p) in payloads.iter().enumerate() {
        let msg = reader.next().await.unwrap().expect("frame");
        let (kind, sid, payload) = parse_frame(&msg).unwrap();
        assert_eq!(
            (kind, sid, payload),
            (FrameKind::Data, i as u32 + 1, &p[..])
        );
    }

    // Dropping every sender ends the writer, which shuts the write half
    // down: the reader observes a clean tunnel EOF (Ok(None)).
    drop(out_tx);
    writer.await.unwrap();
    assert_eq!(reader.next().await.unwrap(), None);
}

#[tokio::test]
async fn backlog_is_batched_but_order_preserved() {
    let ((client_tx, _, client_sock), (_, server_rx, server_sock)) = tunnel_pair().await;
    let (_client_rh, client_wh) = client_sock.into_split();
    let (server_rh, _server_wh) = server_sock.into_split();

    let (out_tx, out_rx) = mpsc::channel::<OutFrame>(4096);
    tokio::spawn(run_writer(client_tx, client_wh, out_rx));
    let mut reader = FrameReader::new(server_rx, server_rh);

    // Fill the channel faster than the writer drains: exercises the
    // try_recv batching path without depending on timing.
    const N: u32 = 500;
    for i in 0..N {
        out_tx
            .send(OutFrame::new(
                FrameKind::Data,
                i,
                format!("frame-{i}").into_bytes(),
            ))
            .await
            .unwrap();
    }
    for i in 0..N {
        let msg = reader.next().await.unwrap().expect("frame");
        let (kind, sid, payload) = parse_frame(&msg).unwrap();
        assert_eq!(kind, FrameKind::Data);
        assert_eq!(sid, i);
        assert_eq!(payload, format!("frame-{i}").as_bytes());
    }
}

#[tokio::test]
async fn bidirectional_simultaneous() {
    let ((client_tx, client_rx, client_sock), (server_tx, server_rx, server_sock)) =
        tunnel_pair().await;
    let (client_rh, client_wh) = client_sock.into_split();
    let (server_rh, server_wh) = server_sock.into_split();

    let (c_tx, c_rx) = mpsc::channel::<OutFrame>(256);
    let (s_tx, s_rx) = mpsc::channel::<OutFrame>(256);
    tokio::spawn(run_writer(client_tx, client_wh, c_rx));
    tokio::spawn(run_writer(server_tx, server_wh, s_rx));
    let mut client_reader = FrameReader::new(client_rx, client_rh);
    let mut server_reader = FrameReader::new(server_rx, server_rh);

    let up = tokio::spawn(async move {
        for i in 0..100u32 {
            c_tx.send(OutFrame::new(FrameKind::Data, 1, vec![b'u'; 1024]))
                .await
                .unwrap();
            let _ = i;
        }
        for _ in 0..100u32 {
            server_reader.next().await.unwrap().expect("up frame");
        }
    });
    let down = tokio::spawn(async move {
        for _ in 0..100u32 {
            s_tx.send(OutFrame::new(FrameKind::Data, 1, vec![b'd'; 1024]))
                .await
                .unwrap();
        }
        for _ in 0..100u32 {
            client_reader.next().await.unwrap().expect("down frame");
        }
    });
    up.await.unwrap();
    down.await.unwrap();
}
