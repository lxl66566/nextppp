//! Regression tests for socket-level helpers over real loopback sockets.

use std::{
    net::{TcpListener, TcpStream},
    time::Duration,
};

use nextppp_common::pump;

/// Dead-peer detection must actually land on the socket: a silently-dead
/// peer (NAT timeout, blackholed path) would otherwise pin a read task
/// forever, since the data plane clears all socket timeouts.
#[test]
fn keepalive_is_applied() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    pump::keepalive(&stream);
    let sock = socket2::SockRef::from(&stream);
    assert!(sock.keepalive().unwrap(), "SO_KEEPALIVE must be on");
    #[cfg(target_os = "linux")]
    {
        assert_eq!(sock.tcp_keepalive_time().unwrap(), Duration::from_secs(60));
        assert_eq!(
            sock.tcp_keepalive_interval().unwrap(),
            Duration::from_secs(15)
        );
        assert_eq!(sock.tcp_keepalive_retries().unwrap(), 3);
    }
}
