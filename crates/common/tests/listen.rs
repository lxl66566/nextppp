//! Listener construction tests: burst-sized backlog and, on Linux,
//! `TCP_DEFER_ACCEPT` semantics (accept wakes on first data, not on SYN).

use std::{
    io::{ErrorKind, Write},
    net::{SocketAddr, TcpStream},
    os::unix::io::AsRawFd,
    time::{Duration, Instant},
};

use nextppp_common::listen::bind_listen;

fn bind_loopback() -> (std::net::TcpListener, SocketAddr) {
    let listener = bind_listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, addr)
}

#[test]
fn listener_serves_connections() {
    let (listener, addr) = bind_loopback();
    let mut client = TcpStream::connect(addr).unwrap();
    client.write_all(b"x").unwrap();
    let (accepted, _) = listener.accept().unwrap();
    drop(accepted);
}

/// `TCP_DEFER_ACCEPT` must be set with the documented 30s cap.
#[cfg(target_os = "linux")]
#[test]
fn defer_accept_option_is_set() {
    let (listener, _) = bind_loopback();
    let mut value: libc::c_int = 0;
    let mut len = libc::socklen_t::try_from(size_of_val(&value)).unwrap();
    // SAFETY: `value`/`len` are valid out-pointers for an int-sized option.
    #[allow(unsafe_code)]
    let rc = unsafe {
        libc::getsockopt(
            listener.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_DEFER_ACCEPT,
            (&raw mut value).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    assert_eq!(rc, 0, "getsockopt: {}", std::io::Error::last_os_error());
    // The kernel stores the value as a retransmit count and converts back
    // on read, rounding up: 30s reads back as 31. Assert "set", not the
    // exact echo.
    assert!(value >= 30, "TCP_DEFER_ACCEPT must be set, got {value}");
}

/// A scanner that completes the handshake but never sends data must not
/// wake `accept()`; a peer that speaks must be accepted immediately.
#[cfg(target_os = "linux")]
#[test]
fn defer_accept_hides_silent_peers() {
    let (listener, addr) = bind_loopback();
    listener.set_nonblocking(true).unwrap();

    let mut silent = TcpStream::connect(addr).unwrap();
    let deadline = Instant::now() + Duration::from_millis(500);
    while Instant::now() < deadline {
        match listener.accept() {
            Err(e) if e.kind() == ErrorKind::WouldBlock => {},
            Ok(_) => panic!("silent peer must not be accepted"),
            Err(e) => panic!("accept: {e}"),
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    silent.write_all(b"hello").unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match listener.accept() {
            Ok(_) => break,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "speaking peer never accepted");
                std::thread::sleep(Duration::from_millis(10));
            },
            Err(e) => panic!("accept: {e}"),
        }
    }
}
