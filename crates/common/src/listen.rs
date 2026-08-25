//! Listener construction: the accept queue is the first bottleneck under
//! connect bursts, so the std default backlog (128) is raised and, on
//! Linux, `TCP_DEFER_ACCEPT` defers `accept()` until the first data byte.

use std::{
    io,
    net::{SocketAddr, TcpListener},
};

use socket2::{Domain, Socket, Type};

/// Accept-queue depth. The std backlog of 128 overflows under SYN bursts
/// (the kernel then drops SYNs or answers RST, surfacing as client-side
/// connect failures); 4096 matches common reverse-proxy practice.
const LISTEN_BACKLOG: i32 = 4096;

/// Binds a TCP listener with a burst-sized backlog.
///
/// On Linux, `TCP_DEFER_ACCEPT` makes `accept()` return only once the peer
/// has sent its first byte (or 30s elapse). This protocol is pure win from
/// it: the client speaks first (NOP prelude), so legitimate accepts are
/// unaffected, while pure port scanners that never send data never wake a
/// session thread.
///
/// # Errors
///
/// Socket creation / bind / listen failure.
pub fn bind_listen(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, None)?;
    // SO_REUSEADDR gives unix its TIME_WAIT rebind semantics for quick
    // restarts. On Windows the flag has no TIME_WAIT meaning and instead
    // lets a second process silently double-bind (hijack) the port, so it
    // must stay off there; a Windows restart simply waits out any lingering
    // sockets, and socket2 (0.6) exposes no SO_EXCLUSIVEADDRUSE to do
    // better.
    #[cfg(not(windows))]
    socket.set_reuse_address(true)?;
    #[cfg(target_os = "linux")]
    set_defer_accept(&socket)?;
    socket.bind(&addr.into())?;
    socket.listen(LISTEN_BACKLOG)?;
    Ok(socket.into())
}

/// `TCP_DEFER_ACCEPT` with a 30s cap: after the timeout the kernel wakes
/// `accept()` anyway, so a data-less connection degrades to today's
/// behavior instead of hanging invisible forever.
#[cfg(target_os = "linux")]
fn set_defer_accept(socket: &Socket) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;

    let secs: libc::c_int = 30;
    let optlen = libc::socklen_t::try_from(size_of_val(&secs)).expect("socklen fits");
    // SAFETY: `secs` outlives the call; setsockopt only reads it.
    #[allow(unsafe_code)]
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_DEFER_ACCEPT,
            (&raw const secs).cast::<libc::c_void>(),
            optlen,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
