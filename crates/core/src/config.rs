//! Protocol configuration (the `key` section of openppp2's AppConfiguration).

use crate::crypto::cipher::Method;

/// Obfuscation and cipher parameters shared by both endpoints. All fields
/// except the passwords feed the flag canary, so a mismatched pair fails the
/// handshake with [`crate::Error::FlagsMismatch`] instead of hanging.
// The four data-plane switches intentionally mirror openppp2's key section.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObfuscationKey {
    /// Global obfuscation key: drives base94/delta/masked transforms and the
    /// length modulus. openppp2 default: 154543927.
    pub kf: u32,
    /// NOP prelude lower exponent: rounds sampled in `2^kl ..= 2^kh`.
    pub kl: u8,
    /// NOP prelude upper exponent.
    pub kh: u8,
    /// Handshake packet padding amount, used as `kx % 256`.
    pub kx: u32,
    /// Cipher protecting the frame header length field (2 bytes per packet).
    pub protocol: Method,
    /// Password for the protocol cipher. **Must be changed per deployment.**
    pub protocol_key: String,
    /// Cipher protecting the packet payload.
    pub transport: Method,
    /// Password for the transport cipher. **Must be changed per deployment.**
    pub transport_key: String,
    /// Payload masked-XOR switch (data plane only; always on pre-handshake).
    pub masked: bool,
    /// Keep the printable base94 shell after the handshake. `true` maximizes
    /// DPI resistance (all traffic stays printable ASCII); `false` switches
    /// to the compact 3-byte binary header after handshaking.
    pub plaintext: bool,
    /// Payload delta-encoding switch.
    pub delta_encode: bool,
    /// Payload shuffle switch.
    pub shuffle_data: bool,
}

impl Default for ObfuscationKey {
    /// Matches openppp2 `AppConfiguration::Clear()` defaults, except that the
    /// placeholder passwords are namespaced to this project.
    fn default() -> Self {
        Self {
            kf: 154_543_927,
            kl: 10,
            kh: 12,
            kx: 128,
            protocol: Method::Aes128Cfb,
            protocol_key: String::from("openppp3"),
            transport: Method::Aes256Cfb,
            transport_key: String::from("openppp3"),
            masked: true,
            plaintext: true,
            delta_encode: true,
            shuffle_data: true,
        }
    }
}
