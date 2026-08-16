//! Proxy target addresses in SOCKS5 wire format, shared by the client
//! (request origin) and the server (request consumer).

use std::net::IpAddr;

use thiserror::Error;

/// Address type byte for an IPv4 host (SOCKS5 `ATYP`).
pub const ATYP_IPV4: u8 = 0x01;
/// Address type byte for a domain name (SOCKS5 `ATYP`).
pub const ATYP_DOMAIN: u8 = 0x03;
/// Address type byte for an IPv6 host (SOCKP5 `ATYP`).
pub const ATYP_IPV6: u8 = 0x04;

/// Target host: either a domain name (resolved remotely) or a literal IP.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Host {
    /// Domain name, original case preserved; matching normalizes.
    Domain(String),
    /// Literal IP address.
    Ip(IpAddr),
}

impl Host {
    /// The host as a display string (`[v6]` bracketed for use in `host:port`).
    #[must_use]
    pub fn to_display(&self) -> String {
        match self {
            Self::Domain(d) => d.clone(),
            Self::Ip(IpAddr::V4(v4)) => v4.to_string(),
            Self::Ip(IpAddr::V6(v6)) => format!("[{v6}]"),
        }
    }
}

/// A proxy request target: host + TCP port.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProxyAddr {
    /// Target host.
    pub host: Host,
    /// Target port, network byte order on the wire.
    pub port: u16,
}

/// Errors while decoding a [`ProxyAddr`] frame.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AddrError {
    /// The frame is structurally invalid (bad ATYP, length or port bytes).
    #[error("malformed proxy address frame")]
    Malformed,
}

impl ProxyAddr {
    /// Appends the SOCKS5-style encoding `[ATYP][addr][port BE16]`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        match &self.host {
            Host::Domain(d) => {
                // Length prefix is capped by SOCKS5 to one byte.
                let len = d.len().min(u8::MAX as usize);
                out.push(ATYP_DOMAIN);
                out.push(u8::try_from(len).expect("capped at u8::MAX"));
                out.extend_from_slice(&d.as_bytes()[..len]);
            },
            Host::Ip(IpAddr::V4(v4)) => {
                out.push(ATYP_IPV4);
                out.extend_from_slice(&v4.octets());
            },
            Host::Ip(IpAddr::V6(v6)) => {
                out.push(ATYP_IPV6);
                out.extend_from_slice(&v6.octets());
            },
        }
        out.extend_from_slice(&self.port.to_be_bytes());
    }

    /// Encodes into a fresh buffer.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 255 + 2);
        self.encode_into(&mut out);
        out
    }

    /// Decodes a frame that must be consumed exactly (no trailing bytes).
    pub fn decode(buf: &[u8]) -> Result<Self, AddrError> {
        let Some((&atyp, rest)) = buf.split_first() else {
            return Err(AddrError::Malformed);
        };
        let (host, after) = match atyp {
            ATYP_IPV4 => {
                let octets: [u8; 4] = rest.first_chunk().ok_or(AddrError::Malformed)?.to_owned();
                let ip = IpAddr::from(octets);
                (Host::Ip(ip), &rest[4..])
            },
            ATYP_IPV6 => {
                let octets: [u8; 16] = rest.first_chunk().ok_or(AddrError::Malformed)?.to_owned();
                let ip = IpAddr::from(octets);
                (Host::Ip(ip), &rest[16..])
            },
            ATYP_DOMAIN => {
                let (&len, rest) = rest.split_first().ok_or(AddrError::Malformed)?;
                let len = len as usize;
                if rest.len() < len || len == 0 {
                    return Err(AddrError::Malformed);
                }
                let name = std::str::from_utf8(&rest[..len]).map_err(|_| AddrError::Malformed)?;
                if name.bytes().any(|b| !(0x21..=0x7e).contains(&b)) {
                    return Err(AddrError::Malformed);
                }
                (Host::Domain(name.to_owned()), &rest[len..])
            },
            _ => return Err(AddrError::Malformed),
        };
        let port = after.first_chunk::<2>().ok_or(AddrError::Malformed)?;
        let port = u16::from_be_bytes(*port);
        if !after[2..].is_empty() {
            return Err(AddrError::Malformed);
        }
        Ok(Self { host, port })
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn roundtrip(addr: &ProxyAddr) {
        assert_eq!(ProxyAddr::decode(&addr.encode()).unwrap(), *addr);
    }

    #[test]
    fn roundtrip_all_atyps() {
        roundtrip(&ProxyAddr {
            host: Host::Domain(String::from("example.com")),
            port: 443,
        });
        roundtrip(&ProxyAddr {
            host: Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            port: 8080,
        });
        roundtrip(&ProxyAddr {
            host: Host::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            port: 65535,
        });
    }

    #[test]
    fn domain_length_prefix_is_exact() {
        let addr = ProxyAddr {
            host: Host::Domain(String::from("a.io")),
            port: 1,
        };
        let wire = addr.encode();
        assert_eq!(wire[0], ATYP_DOMAIN);
        assert_eq!(wire[1], 4);
        assert_eq!(wire.len(), 1 + 1 + 4 + 2);
    }

    #[test]
    fn rejects_malformed_frames() {
        // Empty.
        assert_eq!(ProxyAddr::decode(&[]), Err(AddrError::Malformed));
        // Unknown ATYP.
        assert_eq!(
            ProxyAddr::decode(&[0x02, 1, 2, 3, 4, 0, 80]),
            Err(AddrError::Malformed)
        );
        // IPv4 too short.
        assert_eq!(
            ProxyAddr::decode(&[ATYP_IPV4, 1, 2, 3, 0, 80]),
            Err(AddrError::Malformed)
        );
        // Trailing garbage.
        assert_eq!(
            ProxyAddr::decode(&[ATYP_IPV4, 1, 2, 3, 4, 0, 80, 0]),
            Err(AddrError::Malformed)
        );
        // Domain: length prefix longer than buffer.
        assert_eq!(
            ProxyAddr::decode(&[ATYP_DOMAIN, 9, b'a', b'.', b'i', b'o', 0, 80]),
            Err(AddrError::Malformed)
        );
        // Domain: empty name.
        assert_eq!(
            ProxyAddr::decode(&[ATYP_DOMAIN, 0, 0, 80]),
            Err(AddrError::Malformed)
        );
        // Missing port.
        let mut v6 = vec![ATYP_IPV6];
        v6.extend_from_slice(&[0u8; 16]);
        assert_eq!(ProxyAddr::decode(&v6), Err(AddrError::Malformed));
    }

    #[test]
    fn long_domain_truncates_safely() {
        // Domains longer than 255 bytes are truncated by the length prefix;
        // the result must still roundtrip the truncated form.
        let long = String::from("a").repeat(300);
        let addr = ProxyAddr {
            host: Host::Domain(long),
            port: 443,
        };
        let wire = addr.encode();
        let decoded = ProxyAddr::decode(&wire).unwrap();
        match decoded.host {
            Host::Domain(d) => assert_eq!(d.len(), 255),
            other @ Host::Ip(_) => panic!("expected domain, got {other:?}"),
        }
    }
}
