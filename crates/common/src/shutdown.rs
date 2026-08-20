//! Graceful shutdown: a global flag set from SIGINT/SIGTERM (Ctrl-C on
//! Windows) that serve loops poll between accepts.
//!
//! The flag alone cannot unblock a thread parked in `accept()`; the signal
//! handler also fires a throwaway connect at the listener so the accept
//! loop wakes up, sees the flag and exits. Sessions then drain for a
//! bounded time before the process gives up (systemd's default 90s
//! SIGKILL grace leaves ample headroom).

use std::{
    net::{SocketAddr, TcpStream},
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use spdlog::prelude::*;

/// How long a draining serve loop waits for active sessions to finish.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

static FLAG: AtomicBool = AtomicBool::new(false);
static WAKE_ADDR: OnceLock<Mutex<Option<SocketAddr>>> = OnceLock::new();

fn wake_slot() -> &'static Mutex<Option<SocketAddr>> {
    WAKE_ADDR.get_or_init(|| Mutex::new(None))
}

/// Installs the SIGINT/SIGTERM handler. `wake_addr` is the listening
/// address whose accept loop must be unblocked. Installing twice (client +
/// server roles in one process is not a thing, but tests may re-enter)
/// only updates the wake address.
pub fn install(wake_addr: SocketAddr) {
    match wake_slot().lock() {
        Ok(mut slot) => *slot = Some(wake_addr),
        Err(poisoned) => {
            *poisoned.into_inner() = Some(wake_addr);
        },
    }
    // First install wins for the handler itself; ctrlc has no unset.
    let set = ctrlc::set_handler(|| {
        FLAG.store(true, Ordering::SeqCst);
        let addr = match wake_slot().lock() {
            Ok(slot) => *slot,
            Err(poisoned) => *poisoned.into_inner(),
        };
        if let Some(addr) = addr {
            // Best-effort wake-up connect; the accepted connection is
            // dropped by the serve loop as it exits.
            let _ = TcpStream::connect(addr);
        }
    });
    if let Err(e) = set {
        warn!("signal handler install failed: {e}");
    }
}

/// Whether shutdown was requested.
#[must_use]
pub fn requested() -> bool {
    FLAG.load(Ordering::SeqCst)
}

/// Waits until `active_sessions()` reports zero or the drain timeout
/// expires, logging the outcome. Called by serve loops after the accept
/// loop exits.
pub fn drain_sessions(mut active_sessions: impl FnMut() -> u64) {
    let deadline = Instant::now() + DRAIN_TIMEOUT;
    loop {
        let active = active_sessions();
        if active == 0 {
            info!("shutdown complete: all sessions drained");
            return;
        }
        if Instant::now() >= deadline {
            warn!("shutdown: {active} session(s) still active after drain timeout, exiting");
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drain_returns_when_sessions_hit_zero() {
        let mut active = 1u64;
        let now = Instant::now();
        drain_sessions(|| {
            active = active.saturating_sub(1);
            active
        });
        // Zero-active fast path: no full timeout wait.
        assert!(now.elapsed() < DRAIN_TIMEOUT);
    }
}
