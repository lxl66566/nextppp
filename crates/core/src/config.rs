//! Protocol configuration (the `key` section of openppp2's AppConfiguration).

use crate::{
    crypto::cipher::Method,
    error::{Error, Result},
};

/// Highest NOP exponent accepted by [`ObfuscationKey::validate`]. `kl`/`kh`
/// feed `1 << exp`, so values >= 32 overflow, and anything above 20 stalls
/// the handshake under thousands of noise packets (2^20 / 1400 is ~750).
pub const MAX_NOP_EXPONENT: u8 = 20;
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
            protocol_key: String::from("nextppp"),
            transport: Method::Aes256Cfb,
            transport_key: String::from("nextppp"),
            masked: true,
            plaintext: true,
            delta_encode: true,
            shuffle_data: true,
        }
    }
}

impl ObfuscationKey {
    /// Checks the invariants the protocol stack relies on. The upper config
    /// layer must run this on every loaded key; the core only
    /// `debug_assert`s it (misuse is a programming error, not a wire error).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] naming the offending field.
    pub fn validate(&self) -> Result<()> {
        if self.kl > MAX_NOP_EXPONENT || self.kh > MAX_NOP_EXPONENT {
            return Err(Error::InvalidConfig("kl/kh exceed MAX_NOP_EXPONENT"));
        }
        if self.protocol_key.is_empty() || self.transport_key.is_empty() {
            return Err(Error::InvalidConfig("cipher password is empty"));
        }
        Ok(())
    }
}
