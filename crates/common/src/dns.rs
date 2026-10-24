//! TTL DNS cache for outbound connects.
//!
//! Without it, every proxied CONNECT runs its own `getaddrinfo` on a helper
//! thread (the resolver has no deadline API); a burst of 1000 same-domain
//! connects means 1000 concurrent resolver threads, and glibc can hang for
//! 10s+ on a bad network. The cache collapses hot domains to a memory read
//! and bounds resolution failures with a short negative TTL.
//!
//! Stale-while-error: on a resolution failure an expired positive entry is
//! still returned — on lossy networks DNS is the first dependency to die
//! while the old addresses usually keep working.

use std::{
    collections::HashMap,
    io::{self, ErrorKind},
    net::{IpAddr, ToSocketAddrs},
    sync::{RwLock, mpsc},
    thread,
    time::{Duration, Instant},
};

use spdlog::prelude::*;

/// Positive cache lifetime: long enough to absorb connect bursts, short
/// enough to follow target migrations.
const POSITIVE_TTL: Duration = Duration::from_secs(300);
/// Negative cache lifetime: keeps a failing domain from spawning a resolver
/// thread per connect attempt, without black-holing a transient failure.
const NEGATIVE_TTL: Duration = Duration::from_secs(30);
/// Hard cap on cached domains; a proxy sees unbounded target diversity, so
/// the map must not grow without bound.
const MAX_ENTRIES: usize = 1024;

/// A cached resolution. Failures are cached too (negative caching), storing
/// the error kind + message so the `io::Error` can be rebuilt per caller.
struct Entry {
    result: Result<Vec<IpAddr>, (ErrorKind, String)>,
    expires: Instant,
}

/// Thread-safe TTL cache from domain name to resolved addresses.
#[derive(Default)]
pub struct DnsCache {
    map: RwLock<HashMap<String, Entry>>,
}

impl DnsCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolves `domain`, serving fresh entries from the cache and falling
    /// back to stale entries when resolution fails. `timeout` bounds the
    /// wait for the system resolver (see [`resolve_sys`]).
    ///
    /// # Errors
    ///
    /// Resolution failed and no (stale) cached answer exists; the failure
    /// itself is negative-cached for [`NEGATIVE_TTL`].
    pub fn resolve(&self, domain: &str, timeout: Duration) -> io::Result<Vec<IpAddr>> {
        self.resolve_with(domain, timeout, resolve_sys)
    }

    /// Lookup-injectable core of [`Self::resolve`] (deterministic tests).
    fn resolve_with(
        &self,
        domain: &str,
        timeout: Duration,
        lookup: impl FnOnce(&str, Duration) -> io::Result<Vec<IpAddr>>,
    ) -> io::Result<Vec<IpAddr>> {
        let now = Instant::now();
        {
            let map = self.map.read().expect("dns cache poisoned");
            if let Some(entry) = map.get(domain)
                && entry.expires > now
            {
                return clone_result(&entry.result);
            }
        }

        let result = match lookup(domain, timeout) {
            Ok(ips) if !ips.is_empty() => Ok(ips),
            Ok(_) => Err(io::Error::new(
                ErrorKind::AddrNotAvailable,
                "no addresses resolved",
            )),
            Err(e) => Err(e),
        };

        match result {
            Ok(ips) => {
                self.insert(domain, Ok(ips.clone()), POSITIVE_TTL);
                Ok(ips)
            },
            Err(e) => {
                let stale = {
                    let map = self.map.read().expect("dns cache poisoned");
                    map.get(domain)
                        .and_then(|entry| entry.result.as_ref().ok().cloned())
                };
                if let Some(ips) = stale {
                    // Stale-while-error: on lossy networks DNS dies first
                    // while the old addresses usually keep working.
                    debug!("dns resolve {domain} failed ({e}); serving stale cache");
                    Ok(ips)
                } else {
                    self.insert(domain, Err((e.kind(), e.to_string())), NEGATIVE_TTL);
                    Err(e)
                }
            },
        }
    }

    fn insert(
        &self,
        domain: &str,
        result: Result<Vec<IpAddr>, (ErrorKind, String)>,
        ttl: Duration,
    ) {
        let mut map = self.map.write().expect("dns cache poisoned");
        if map.len() >= MAX_ENTRIES && !map.contains_key(domain) {
            // Cheap eviction: drop expired entries. If everything is fresh
            // the new entry is simply not cached — correctness never depends
            // on the cache, so skipping beats an unbounded map or LRU state.
            let now = Instant::now();
            map.retain(|_, entry| entry.expires > now);
            if map.len() >= MAX_ENTRIES {
                return;
            }
        }
        map.insert(domain.to_owned(), Entry {
            result,
            expires: Instant::now() + ttl,
        });
    }

    #[cfg(test)]
    fn insert_with_ttl(&self, domain: &str, ips: Vec<IpAddr>, ttl: Duration) {
        self.insert(domain, Ok(ips), ttl);
    }
}

fn clone_result(result: &Result<Vec<IpAddr>, (ErrorKind, String)>) -> io::Result<Vec<IpAddr>> {
    match result {
        Ok(ips) => Ok(ips.clone()),
        Err((kind, msg)) => Err(io::Error::new(*kind, msg.clone())),
    }
}

/// System resolution via `getaddrinfo`. It has no deadline API, so the call
/// runs on a helper thread and the wait is bounded: a hung resolver parks
/// exactly that one helper thread (until libc gives up) instead of the
/// caller's session thread forever, unkillable by socket shutdowns.
fn resolve_sys(domain: &str, timeout: Duration) -> io::Result<Vec<IpAddr>> {
    let (tx, rx) = mpsc::channel();
    let owned = domain.to_owned();
    let spawned = thread::Builder::new()
        .name("nextppp-resolve".to_owned())
        .spawn(move || {
            // Port 0: only the addresses are wanted; callers re-attach the
            // real port per connect. The send races with `recv_timeout`
            // giving up; a late send just fails silently, thread then exits.
            let res = (owned.as_str(), 0)
                .to_socket_addrs()
                .map(|it| it.map(|sa| sa.ip()).collect::<Vec<IpAddr>>());
            let _ = tx.send(res);
        });
    match spawned {
        Ok(_) => match rx.recv_timeout(timeout) {
            Ok(res) => res,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
                ErrorKind::TimedOut,
                "dns resolution timed out",
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(io::Error::other("resolver thread died"))
            },
        },
        Err(e) => Err(io::Error::other(e)),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn ok_lookup(ips: Vec<IpAddr>) -> impl FnOnce(&str, Duration) -> io::Result<Vec<IpAddr>> {
        move |_, _| Ok(ips.clone())
    }

    #[test]
    fn fresh_hit_skips_lookup() {
        let cache = DnsCache::new();
        let calls = AtomicUsize::new(0);
        let lookup = |_: &str, _: Duration| -> io::Result<Vec<IpAddr>> {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok(vec![ip("10.0.0.1")])
        };
        // Two resolves share one lookup. First call consumes `lookup`, so
        // go through insert + a second counting closure instead.
        let first = cache
            .resolve_with("a.test", Duration::ZERO, lookup)
            .unwrap();
        assert_eq!(first, vec![ip("10.0.0.1")]);
        let second = cache
            .resolve_with("a.test", Duration::ZERO, |_, _| {
                panic!("fresh cache entry must skip the lookup")
            })
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn expired_entry_triggers_fresh_lookup() {
        let cache = DnsCache::new();
        cache.insert_with_ttl("b.test", vec![ip("10.0.0.1")], Duration::ZERO);
        let fresh = cache
            .resolve_with("b.test", Duration::ZERO, ok_lookup(vec![ip("10.0.0.2")]))
            .unwrap();
        assert_eq!(fresh, vec![ip("10.0.0.2")]);
    }

    #[test]
    fn failures_are_negative_cached() {
        let cache = DnsCache::new();
        let calls = AtomicUsize::new(0);
        let fail = |_: &str, _: Duration| -> io::Result<Vec<IpAddr>> {
            calls.fetch_add(1, Ordering::Relaxed);
            Err(io::Error::new(ErrorKind::NotFound, "NXDOMAIN"))
        };
        assert!(cache.resolve_with("c.test", Duration::ZERO, fail).is_err());
        // Second failure must come from the cache: no new lookup, and the
        // original error kind survives the rebuild.
        let err = cache
            .resolve_with("c.test", Duration::ZERO, |_, _| {
                panic!("negative cache entry must skip the lookup")
            })
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn stale_entry_survives_resolution_failure() {
        let cache = DnsCache::new();
        // Zero TTL: immediately expired, i.e. stale.
        cache.insert_with_ttl("d.test", vec![ip("10.0.0.9")], Duration::ZERO);
        let ips = cache
            .resolve_with("d.test", Duration::ZERO, |_, _| {
                Err(io::Error::new(ErrorKind::TimedOut, "resolver dead"))
            })
            .unwrap();
        assert_eq!(ips, vec![ip("10.0.0.9")]);
    }

    #[test]
    fn stale_negative_entry_does_not_mask_lookup() {
        let cache = DnsCache::new();
        // Seed a negative entry, let it expire, then succeed on lookup.
        assert!(
            cache
                .resolve_with("e.test", Duration::ZERO, |_, _| Err(io::Error::other(
                    "boom"
                )))
                .is_err()
        );
        // Force expiry by re-inserting through the zero-TTL path.
        cache.insert(
            "e.test",
            Err((ErrorKind::Other, "boom".into())),
            Duration::ZERO,
        );
        let ips = cache
            .resolve_with("e.test", Duration::ZERO, ok_lookup(vec![ip("10.0.0.3")]))
            .unwrap();
        assert_eq!(ips, vec![ip("10.0.0.3")]);
    }

    #[test]
    fn system_resolver_resolves_localhost() {
        let cache = DnsCache::new();
        let ips = cache.resolve("localhost", Duration::from_secs(5)).unwrap();
        assert!(
            ips.iter().any(|ip| *ip == IpAddr::from([127, 0, 0, 1])
                || *ip == IpAddr::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])),
            "localhost must resolve to a loopback address, got {ips:?}"
        );
    }
}
