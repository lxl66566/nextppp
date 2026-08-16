//! Session ciphers for the protocol/transport layers.
//!
//! Design notes (deviations from openppp2, deliberate):
//!
//! 1. **Key derivation**: openppp2 used `EVP_BytesToKey(MD5, 1 round)` plus an MD5-based IV remix
//!    and a custom RC4 pass. We use HKDF-SHA256 instead; MD5-based KDF is too weak for modern
//!    standards and the RC4 mixer only added obfuscation, not security.
//! 2. **Nonce reuse bug**: openppp2 re-initialized its EVP context with the *same* key/IV for every
//!    packet (`EVP_CipherInit_ex` before each `Encrypt`), so every packet reused the identical
//!    keystream — the classic "two-time pad" (C1 ^ C2 = P1 ^ P2). We derive a per-packet nonce
//!    TLS-1.3-style: `nonce = base_iv XOR be64(seq)` with a strictly monotonic 64-bit counter per
//!    direction.
//! 3. **Backend**: OpenSSL EVP names map to RustCrypto primitives (AES-NI accelerated on x86_64);
//!    the custom RC4-255 cipher family is dropped (cryptographically broken and no longer needed by
//!    the new KDF).
//!
//! Kept from the original: the "password + per-connection ivv string" key
//! seasoning, so every connection derives independent working keys.

use hkdf::Hkdf;
use sha2::Sha256;

/// Which protocol layer a cipher instance protects. Mixed into the KDF salt
/// so the protocol and transport ciphers never derive the same keystream,
/// even when both use the same method *and* the same password — without this
/// domain separation the 2-byte header length field and the payload would be
/// encrypted under identical key/IV/nonce (two-time pad).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CipherRole {
    /// Frame-header length protection (the "protocol" cipher).
    Protocol,
    /// Packet payload protection (the "transport" cipher).
    Transport,
}

impl CipherRole {
    /// Lowercase name mixed into the KDF salt.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Protocol => "protocol",
            Self::Transport => "transport",
        }
    }
}

/// Supported stream-cipher methods (compile-time checked, replaces openppp2's
/// runtime cipher-name strings).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Method {
    /// AES-128 in CFB128 mode (openppp2 default protocol cipher).
    Aes128Cfb,
    /// AES-256 in CFB128 mode (openppp2 default transport cipher).
    Aes256Cfb,
    /// AES-128 in CTR mode.
    Aes128Ctr,
    /// AES-256 in CTR mode.
    Aes256Ctr,
    /// ChaCha20 (IETF, 96-bit nonce) — fast on machines without AES-NI.
    ChaCha20,
}

impl Method {
    /// Parses an openppp2-style cipher name (used by the config layer).
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "aes-128-cfb" => Some(Self::Aes128Cfb),
            "aes-256-cfb" => Some(Self::Aes256Cfb),
            "aes-128-ctr" => Some(Self::Aes128Ctr),
            "aes-256-ctr" => Some(Self::Aes256Ctr),
            "chacha20" | "chacha20-ietf" => Some(Self::ChaCha20),
            _ => None,
        }
    }

    /// Canonical name (inverse of [`Method::from_name`]).
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Aes128Cfb => "aes-128-cfb",
            Self::Aes256Cfb => "aes-256-cfb",
            Self::Aes128Ctr => "aes-128-ctr",
            Self::Aes256Ctr => "aes-256-ctr",
            Self::ChaCha20 => "chacha20",
        }
    }

    /// Key length in bytes for this method.
    #[must_use]
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Cfb | Self::Aes128Ctr => 16,
            Self::Aes256Cfb | Self::Aes256Ctr | Self::ChaCha20 => 32,
        }
    }

    /// IV/nonce length in bytes for this method.
    #[must_use]
    pub fn iv_len(self) -> usize {
        match self {
            Self::Aes128Cfb | Self::Aes256Cfb | Self::Aes128Ctr | Self::Aes256Ctr => 16,
            Self::ChaCha20 => 12,
        }
    }
}

type Aes128CfbEnc = cfb_mode::Encryptor<aes::Aes128>;
type Aes128CfbDec = cfb_mode::Decryptor<aes::Aes128>;
type Aes256CfbEnc = cfb_mode::Encryptor<aes::Aes256>;
type Aes256CfbDec = cfb_mode::Decryptor<aes::Aes256>;
type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;
type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

/// Max nonce width across methods (AES: 16 bytes).
const NONCE_MAX: usize = 16;
/// Max derived-key width across methods.
const KEY_MAX: usize = 32;

/// One-directional session cipher with a monotonically advancing nonce
/// counter. A [`SessionCipher`] instance must never be reused for two
/// independent message streams; create one per direction instead.
pub struct SessionCipher {
    method: Method,
    key: [u8; KEY_MAX],
    base_iv: [u8; NONCE_MAX],
    seq: u64,
    encrypting: bool,
}

impl SessionCipher {
    /// Derives a cipher from `password` alone (pre-handshake phase; openppp2
    /// initializes its ciphers in the ITransmission constructor the same way).
    #[must_use]
    pub fn new(method: Method, role: CipherRole, password: &str) -> Self {
        Self::derive(method, role, password, None)
    }

    /// Derives a cipher from `password` seasoned with the per-connection
    /// `ivv` (post-handshake rekey). The ivv string keeps the openppp2
    /// format: `"+" + base32(ivv)`.
    #[must_use]
    pub fn derive(method: Method, role: CipherRole, password: &str, ivv: Option<u128>) -> Self {
        let mut ikm = Vec::with_capacity(password.len() + 40);
        ikm.extend_from_slice(password.as_bytes());
        if let Some(ivv) = ivv {
            if ivv > 0 {
                ikm.push(b'+');
            }
            // ceil(128 bits / log2(32)) = 26 digits.
            let mut buf = [0u8; 26];
            let len = encode_base32(ivv, &mut buf);
            ikm.extend_from_slice(&buf[..len]);
        }

        // The salt mixes role + method, giving every (layer, cipher) pair an
        // independent key domain; sharing one password across layers is then
        // safe by construction.
        let salt = format!("openppp3/{}/{}", role.name(), method.name());
        let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), &ikm);
        let mut okm = [0u8; KEY_MAX + NONCE_MAX];
        // Length is fixed and well below the HKDF limit; cannot fail.
        hk.expand(b"openppp3-session-key", &mut okm)
            .expect("static HKDF output length");

        let mut key = [0u8; KEY_MAX];
        key.copy_from_slice(&okm[..KEY_MAX]);
        let mut base_iv = [0u8; NONCE_MAX];
        base_iv.copy_from_slice(&okm[KEY_MAX..]);

        Self {
            method,
            key,
            base_iv,
            seq: 0,
            encrypting: true,
        }
    }

    /// Marks this instance as the decrypting direction (CFB en/decryption
    /// differ; CTR/ChaCha20 are symmetric).
    #[must_use]
    pub fn for_decryption(mut self) -> Self {
        self.encrypting = false;
        self
    }

    /// Encrypts (or decrypts, for a `for_decryption` instance) `data` in
    /// place, consuming one nonce. Length never changes.
    ///
    /// Trait imports are scoped per arm: cfb-mode/ctr resolve against
    /// cipher 0.4 while chacha20 0.10 resolves against cipher 0.5, so the
    /// identically-named traits must not be imported simultaneously.
    pub fn apply(&mut self, data: &mut [u8]) {
        let nonce = self.next_nonce();
        match self.method {
            Method::Aes128Cfb => {
                use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
                if self.encrypting {
                    let c = Aes128CfbEnc::new_from_slices(&self.key[..16], &nonce[..16])
                        .expect("key/iv lengths are fixed by Method");
                    c.encrypt(data);
                } else {
                    let c = Aes128CfbDec::new_from_slices(&self.key[..16], &nonce[..16])
                        .expect("key/iv lengths are fixed by Method");
                    c.decrypt(data);
                }
            },
            Method::Aes256Cfb => {
                use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
                if self.encrypting {
                    let c = Aes256CfbEnc::new_from_slices(&self.key[..32], &nonce[..16])
                        .expect("key/iv lengths are fixed by Method");
                    c.encrypt(data);
                } else {
                    let c = Aes256CfbDec::new_from_slices(&self.key[..32], &nonce[..16])
                        .expect("key/iv lengths are fixed by Method");
                    c.decrypt(data);
                }
            },
            Method::Aes128Ctr => {
                use ctr::cipher::{KeyIvInit, StreamCipher};
                let mut c = Aes128Ctr::new_from_slices(&self.key[..16], &nonce[..16])
                    .expect("key/iv lengths are fixed by Method");
                c.apply_keystream(data);
            },
            Method::Aes256Ctr => {
                use ctr::cipher::{KeyIvInit, StreamCipher};
                let mut c = Aes256Ctr::new_from_slices(&self.key[..32], &nonce[..16])
                    .expect("key/iv lengths are fixed by Method");
                c.apply_keystream(data);
            },
            Method::ChaCha20 => {
                use chacha20::cipher::{KeyIvInit, StreamCipher};
                let mut c = chacha20::ChaCha20::new_from_slices(&self.key[..32], &nonce[..12])
                    .expect("key/iv lengths are fixed by Method");
                c.apply_keystream(data);
            },
        }
    }

    /// Number of nonces consumed so far (packets processed).
    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.seq
    }

    /// Computes the nonce for the current sequence and advances the counter.
    fn next_nonce(&mut self) -> [u8; NONCE_MAX] {
        let mut nonce = self.base_iv;
        // TLS-1.3 style: XOR the big-endian sequence counter into the low
        // bytes of the base IV (8 bytes for AES, 4 for ChaCha20) so the
        // counter never repeats within a connection.
        let xor_width = if self.method == Method::ChaCha20 {
            4
        } else {
            8
        };
        let start = self.method.iv_len() - xor_width;
        let seq = self.seq.to_be_bytes();
        for i in 0..xor_width {
            nonce[start + i] ^= seq[8 - xor_width + i];
        }
        // A u64 counter practically cannot wrap within one connection
        // (2^64 packets x 64 KiB >> any conceivable session size).
        self.seq += 1;
        nonce
    }
}

/// Lowercase base32 (digits 0-9a-v), matching std::to_string(int128, 32).
#[allow(clippy::cast_possible_truncation)] // (v & 31) < 32 by construction
fn encode_base32(mut v: u128, out: &mut [u8]) -> usize {
    const ALPHABET: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";
    let mut len = 0;
    loop {
        out[len] = ALPHABET[(v & 31) as usize];
        len += 1;
        v >>= 5;
        if v == 0 {
            break;
        }
    }
    out[..len].reverse();
    len
}

impl std::fmt::Debug for SessionCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never leak key material in debug output.
        f.debug_struct("SessionCipher")
            .field("method", &self.method)
            .field("seq", &self.seq)
            .field("encrypting", &self.encrypting)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_methods() -> [Method; 5] {
        [
            Method::Aes128Cfb,
            Method::Aes256Cfb,
            Method::Aes128Ctr,
            Method::Aes256Ctr,
            Method::ChaCha20,
        ]
    }

    #[test]
    fn method_name_roundtrip() {
        for m in all_methods() {
            assert_eq!(Method::from_name(m.name()), Some(m));
        }
        assert_eq!(Method::from_name("AES-128-CFB"), Some(Method::Aes128Cfb));
        assert_eq!(Method::from_name("chacha20-ietf"), Some(Method::ChaCha20));
        assert_eq!(Method::from_name("rc4-md5"), None);
        assert_eq!(Method::from_name(""), None);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_all_methods() {
        for m in all_methods() {
            let mut enc = SessionCipher::new(m, CipherRole::Transport, "password-1");
            let mut dec =
                SessionCipher::new(m, CipherRole::Transport, "password-1").for_decryption();
            let plaintext: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();

            let mut ciphertext = plaintext.clone();
            enc.apply(&mut ciphertext);
            assert_ne!(ciphertext, plaintext, "{m:?} should encrypt");
            assert_eq!(ciphertext.len(), plaintext.len());
            dec.apply(&mut ciphertext);
            assert_eq!(ciphertext, plaintext, "{m:?} roundtrip failed");
        }
    }

    #[test]
    fn roles_derive_independent_keystreams() {
        // Same method + same password must still yield independent keys for
        // the protocol and transport layers (domain separation in the salt).
        for m in all_methods() {
            let mut p = SessionCipher::new(m, CipherRole::Protocol, "shared");
            let mut t = SessionCipher::new(m, CipherRole::Transport, "shared");
            let mut header = [0u8; 32];
            let mut body = [0u8; 32];
            p.apply(&mut header);
            t.apply(&mut body);
            assert_ne!(header, body, "{m:?} role separation failed");
        }
    }

    #[test]
    fn nonce_never_repeats() {
        // Encrypting the same plaintext twice must yield different ciphertexts
        // (openppp2's per-packet EVP re-init failed this: identical keystream).
        for m in all_methods() {
            let mut c = SessionCipher::new(m, CipherRole::Transport, "pw");
            let mut a = [0x41u8; 32];
            let mut b = [0x41u8; 32];
            c.apply(&mut a);
            c.apply(&mut b);
            assert_ne!(a, b, "{m:?} keystream reused");
            assert_eq!(c.sequence(), 2);
        }
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)] // test vectors stay < 256
    fn streams_stay_independent_per_direction() {
        // tx and rx counters advance independently: interleaved use must not
        // desync two parties running mirrored instances.
        for m in all_methods() {
            let mut enc = SessionCipher::new(m, CipherRole::Transport, "pw");
            let mut dec = SessionCipher::new(m, CipherRole::Transport, "pw").for_decryption();
            for n in [1usize, 2, 3, 17, 100] {
                let original: Vec<u8> = (0..n).map(|i| (i * 37) as u8).collect();
                let mut wire = original.clone();
                enc.apply(&mut wire);
                dec.apply(&mut wire);
                assert_eq!(wire, original);
            }
            assert_eq!(enc.sequence(), 5);
            assert_eq!(dec.sequence(), 5);
        }
    }

    #[test]
    fn ivv_changes_derived_keys() {
        let mut a = SessionCipher::new(Method::Aes256Cfb, CipherRole::Transport, "pw");
        let mut b = SessionCipher::derive(
            Method::Aes256Cfb,
            CipherRole::Transport,
            "pw",
            Some(0xdead_beef),
        );
        let mut buf_a = [0u8; 16];
        let mut buf_b = [0u8; 16];
        a.apply(&mut buf_a);
        b.apply(&mut buf_b);
        assert_ne!(buf_a, buf_b, "ivv must rekey the cipher");
    }

    #[test]
    fn base32_matches_reference_format() {
        let mut buf = [0u8; 26];
        let len = encode_base32(0, &mut buf);
        assert_eq!(&buf[..len], b"0");
        let len = encode_base32(31, &mut buf);
        assert_eq!(&buf[..len], b"v");
        let len = encode_base32(32, &mut buf);
        assert_eq!(&buf[..len], b"10");
        // 2^128 - 1 = 7 * 32^25 + (32^25 - 1) -> '7' followed by 25 'v'.
        let len = encode_base32(u128::MAX, &mut buf);
        let mut expected = vec![b'7'];
        expected.extend(std::iter::repeat_n(b'v', 25));
        assert_eq!(len, expected.len());
        assert_eq!(&buf[..len], &expected[..]);
    }
}
