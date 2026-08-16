//! nextppp-core: anti-censorship transmission protocol core.
//!
//! A Rust rewrite of the openppp2 transport algorithms (framing, handshake,
//! obfuscation) as the core of a proxy (not a VPN). The wire protocol is not
//! byte-compatible with the original, but every anti-blocking design element
//! is preserved:
//!
//! * printable base94 envelope for the whole pre-handshake stream,
//! * randomized headers with parity-encoded filler, length obfuscation and a first-frame checksum,
//! * NOP noise prelude and dummy handshake packets against active probing,
//! * per-connection key derivation (`ivv`), obfuscation-flag canary,
//! * masked-XOR / shuffle / delta payload transforms.
//!
//! Deviations (security/perf fixes, see module docs of
//! [`crypto::cipher`]): HKDF-SHA256 instead of MD5-based `EVP_BytesToKey`,
//! per-packet nonces instead of keystream reuse, CSPRNG instead of a .NET
//! subtractor generator, no RC4.
//!
//! ```no_run
//! use nextppp_core::{ObfuscationKey, Transmission};
//!
//! # fn main() -> std::io::Result<()> {
//! let io = std::net::TcpStream::connect("1.2.3.4:1234")?;
//! let mut tx = Transmission::new(io, ObfuscationKey::default());
//! let (session, mux) = tx.handshake_client().unwrap();
//! tx.write(b"hello").unwrap();
//! let reply = tx.read().unwrap();
//! # Ok(())
//! # }
//! ```

pub mod config;
pub mod crypto;
pub mod error;
pub mod frame;
pub mod handshake;
pub mod transmission;

pub use config::ObfuscationKey;
pub use crypto::cipher::{CipherRole, Method, SessionCipher};
pub use error::{Error, Result};
pub use transmission::{Transmission, TransmissionRx, TransmissionTx};

/// 128-bit session identifier (openppp2 `Int128`).
pub type SessionId = u128;

/// Maximum single-frame plaintext size (openppp2 `PPP_BUFFER_SIZE`).
pub const PPP_BUFFER_SIZE: usize = 65536;
/// Worst-case base94 frame length: every input byte may expand to 2 chars.
pub const BASE94_MAX_FRAME: usize = PPP_BUFFER_SIZE * 2 + 64;
/// Length-modulus lower bound (`64^3`).
pub const MOD_MIN: u32 = 64 * 64 * 64;
/// Length-modulus upper bound (`94^3`).
pub const MOD_MAX: u32 = 94 * 94 * 94;
