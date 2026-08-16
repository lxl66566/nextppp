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
//! 4. **Key-schedule caching** (perf, wire-identical): the AES key expansion is computed once per
//!    connection in [`Core`] instead of per `apply` call — the old `new_from_slices`-per-packet
//!    pattern cost hundreds of cycles for the 2-byte protocol-header cipher on every frame. CFB/CTR
//!    are hand-rolled on top of the cached schedule; byte-exact equivalence with the `cfb-mode` /
//!    `ctr` crates is pinned by unit tests. CFB decryption and CTR encrypt ciphertext blocks in
//!    batches of 8 (independent under AES-NI; CFB *encryption* stays serial by construction).
//!
//! Kept from the original: the "password + per-connection ivv string" key
//! seasoning, so every connection derives independent working keys.

use aes::cipher::{
    BlockEncrypt, BlockSizeUser, KeyInit,
    generic_array::{GenericArray, typenum::U16},
};
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

type Block = GenericArray<u8, U16>;

/// Precomputed AES key schedule (see design note 4). One boxed-free enum
/// holding either schedule; the variant size gap is inherent and harmless
/// (one instance per direction per connection).
#[allow(clippy::large_enum_variant)]
enum Core {
    Aes128(aes::Aes128),
    Aes256(aes::Aes256),
}

/// Max nonce width across methods (AES: 16 bytes).
const NONCE_MAX: usize = 16;
/// Max derived-key width across methods.
const KEY_MAX: usize = 32;

/// One-directional session cipher with a monotonically advancing nonce
/// counter. A [`SessionCipher`] instance must never be reused for two
/// independent message streams; create one per direction instead.
pub struct SessionCipher {
    method: Method,
    core: Core,
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

        let core = match method {
            Method::Aes128Cfb | Method::Aes128Ctr => {
                Core::Aes128(aes::Aes128::new(GenericArray::from_slice(&key[..16])))
            },
            Method::Aes256Cfb | Method::Aes256Ctr | Method::ChaCha20 => {
                Core::Aes256(aes::Aes256::new(GenericArray::from_slice(&key[..32])))
            },
        };

        Self {
            method,
            core,
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
    pub fn apply(&mut self, data: &mut [u8]) {
        let nonce = self.next_nonce();
        let Self {
            core,
            key,
            method,
            encrypting,
            ..
        } = self;
        match (method, core) {
            (Method::Aes128Cfb, Core::Aes128(c)) => cfb_apply(c, &nonce, data, *encrypting),
            (Method::Aes256Cfb, Core::Aes256(c)) => cfb_apply(c, &nonce, data, *encrypting),
            (Method::Aes128Ctr, Core::Aes128(c)) => ctr_apply(c, &nonce, data),
            (Method::Aes256Ctr, Core::Aes256(c)) => ctr_apply(c, &nonce, data),
            (Method::ChaCha20, Core::Aes128(_) | Core::Aes256(_)) => {
                // State init is just word writes (rounds run lazily per
                // block), so per-packet construction is cheap.
                use chacha20::cipher::{KeyIvInit, StreamCipher};
                let mut c = chacha20::ChaCha20::new_from_slices(&key[..32], &nonce[..12])
                    .expect("key/nonce lengths are fixed by Method");
                c.apply_keystream(data);
            },
            // `Core` is derived from `method` at construction; these pairings
            // cannot exist.
            (
                Method::Aes128Cfb | Method::Aes128Ctr,
                Core::Aes256(_),
            )
            | (
                Method::Aes256Cfb | Method::Aes256Ctr,
                Core::Aes128(_),
            ) => unreachable!("cipher core must match method"),
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

/// AES-CFB128 over `data` with the per-packet `iv`.
fn cfb_apply<E>(cipher: &E, iv: &[u8; NONCE_MAX], data: &mut [u8], encrypting: bool)
where
    E: BlockEncrypt + BlockSizeUser<BlockSize = U16>,
{
    if encrypting {
        cfb_encrypt(cipher, iv, data);
    } else {
        cfb_decrypt(cipher, iv, data);
    }
}

/// CFB encryption is inherently serial: the keystream for block i depends on
/// the ciphertext of block i-1. The feedback move/XOR are fused into u64
/// halves to keep per-block overhead off the AES latency chain.
fn cfb_encrypt<E>(cipher: &E, iv: &[u8; NONCE_MAX], data: &mut [u8])
where
    E: BlockEncrypt + BlockSizeUser<BlockSize = U16>,
{
    let mut fb: Block = (*iv).into();
    let mut chunks = data.chunks_exact_mut(16);
    for chunk in &mut chunks {
        cipher.encrypt_block(&mut fb);
        let ct = xor16_store(chunk, &fb);
        fb.copy_from_slice(&ct);
    }
    xor_tail(cipher, &fb, chunks.into_remainder());
}

/// XORs `ks` into the 16-byte `chunk` in place and returns the result (the
/// new ciphertext) as a fixed-size array.
fn xor16_store(chunk: &mut [u8], ks: &Block) -> [u8; 16] {
    debug_assert_eq!(chunk.len(), 16);
    let ct = u128::from_le_bytes(chunk.try_into().expect("16-byte chunk"))
        ^ u128::from_le_bytes(ks.as_slice().try_into().expect("16-byte block"));
    let bytes = ct.to_le_bytes();
    chunk.copy_from_slice(&bytes);
    bytes
}

/// CFB decryption needs `E(ct[i-1])`: the ciphertext is known up front, so
/// blocks are encrypted in batches of 8 at the cost of one ciphertext copy —
/// AES-NI pipelines independent `encrypt_blocks` far better than the serial
/// feedback chain.
fn cfb_decrypt<E>(cipher: &E, iv: &[u8; NONCE_MAX], data: &mut [u8])
where
    E: BlockEncrypt + BlockSizeUser<BlockSize = U16>,
{
    const BATCH: usize = 8;
    let nb = data.len() / 16;
    // ks[k] holds ct[i+k-1] before encryption (ks[0] = previous ciphertext)
    // and the keystream E(ct[i+k-1]) for data block i+k afterwards.
    let mut ks: [Block; BATCH] = core::array::from_fn(|_| Block::from([0u8; 16]));
    let mut prev: Block = (*iv).into();
    let mut i = 0;
    while i < nb {
        let n = (nb - i).min(BATCH);
        // Save the batch's last ciphertext before the batch loop overwrites
        // `data` in place; it seeds the next batch's feedback.
        let mut last_ct = Block::from([0u8; 16]);
        last_ct.copy_from_slice(&data[(i + n - 1) * 16..(i + n) * 16]);
        ks[0].copy_from_slice(&prev);
        for k in 1..n {
            ks[k].copy_from_slice(&data[(i + k - 1) * 16..(i + k) * 16]);
        }
        cipher.encrypt_blocks(&mut ks[..n]);
        for k in 0..n {
            xor16_store(&mut data[(i + k) * 16..(i + k + 1) * 16], &ks[k]);
        }
        prev = last_ct;
        i += n;
    }
    xor_tail(cipher, &prev, &mut data[nb * 16..]);
}

/// Keystream prefix XOR for the sub-block tail (identical for both CFB
/// directions).
fn xor_tail<E>(cipher: &E, feedback: &Block, rem: &mut [u8])
where
    E: BlockEncrypt + BlockSizeUser<BlockSize = U16>,
{
    if rem.is_empty() {
        return;
    }
    let mut keystream = *feedback;
    cipher.encrypt_block(&mut keystream);
    for (b, k) in rem.iter_mut().zip(keystream.iter()) {
        *b ^= k;
    }
}

/// AES-CTR: fully parallel — 8 counter blocks encrypted and XORed per batch.
fn ctr_apply<E>(cipher: &E, iv: &[u8; NONCE_MAX], data: &mut [u8])
where
    E: BlockEncrypt + BlockSizeUser<BlockSize = U16>,
{
    const BATCH: usize = 8;
    let mut ks: [Block; BATCH] = core::array::from_fn(|_| Block::from([0u8; 16]));
    let mut counter = u128::from_be_bytes(*iv);
    let mut pos = 0;
    while pos < data.len() {
        let take = (data.len() - pos).min(BATCH * 16);
        let n = take.div_ceil(16);
        for (k, blk) in ks[..n].iter_mut().enumerate() {
            *blk = Block::from((counter + k as u128).to_be_bytes());
        }
        cipher.encrypt_blocks(&mut ks[..n]);
        let chunk = &mut data[pos..pos + take];
        for (b, k) in chunk.iter_mut().zip(ks[..n].iter().flatten()) {
            *b ^= k;
        }
        counter += n as u128;
        pos += take;
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
            let mut dec =
                SessionCipher::new(m, CipherRole::Transport, "pw").for_decryption();
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

    // ------------------------------------------------------------------
    // Byte-exact equivalence of the hand-rolled CFB/CTR against the
    // reference crates (kept as dev-dependencies for this purpose).
    // ------------------------------------------------------------------

    impl SessionCipher {
        /// Test-only view for driving the reference implementations with the
        /// exact nonce material `apply` will use next.
        fn material(&self) -> (&[u8; KEY_MAX], &[u8; NONCE_MAX], u64) {
            (&self.key, &self.base_iv, self.seq)
        }
    }

    /// Mirrors `next_nonce` for the reference drivers.
    fn ref_nonce(method: Method, base_iv: &[u8; NONCE_MAX], seq: u64) -> [u8; NONCE_MAX] {
        let mut nonce = *base_iv;
        let xor_width = if method == Method::ChaCha20 { 4 } else { 8 };
        let start = method.iv_len() - xor_width;
        let seq = seq.to_be_bytes();
        for i in 0..xor_width {
            nonce[start + i] ^= seq[8 - xor_width + i];
        }
        nonce
    }

    #[allow(clippy::cast_possible_truncation)] // test data generation only
    fn sample(n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        let mut s = 0x0bad_c0de_dead_beefu64;
        for b in &mut v {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            *b = (s >> 32) as u8;
        }
        v
    }

    #[test]
    fn manual_cfb_ctr_match_reference_crates() {
        use aes::Aes128 as RefAes128;
        use aes::Aes256 as RefAes256;

        for method in [Method::Aes128Cfb, Method::Aes256Cfb, Method::Aes128Ctr, Method::Aes256Ctr]
        {
            for encrypting in [true, false] {
                let base = SessionCipher::new(method, CipherRole::Transport, "cross-check");
                let mut mine = if encrypting { base } else { base.for_decryption() };
                // Lengths hit: partial tails, single blocks, multi-batch
                // (> 8*16 = CFB decrypt / CTR batch boundary) and full frames.
                for len in [0usize, 1, 2, 15, 16, 17, 31, 128, 129, 1000, 65536] {
                    let data = sample(len);
                    let (key, base_iv, seq) = mine.material();
                    let nonce = ref_nonce(method, base_iv, seq);

                    let mut expected = data.clone();
                    match (method, encrypting) {
                        (Method::Aes128Cfb, true) => {
                            use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
                            cfb_mode::Encryptor::<RefAes128>::new_from_slices(&key[..16], &nonce)
                                .expect("static lengths")
                                .encrypt(&mut expected);
                        },
                        (Method::Aes128Cfb, false) => {
                            use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
                            cfb_mode::Decryptor::<RefAes128>::new_from_slices(&key[..16], &nonce)
                                .expect("static lengths")
                                .decrypt(&mut expected);
                        },
                        (Method::Aes256Cfb, true) => {
                            use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
                            cfb_mode::Encryptor::<RefAes256>::new_from_slices(&key[..32], &nonce)
                                .expect("static lengths")
                                .encrypt(&mut expected);
                        },
                        (Method::Aes256Cfb, false) => {
                            use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
                            cfb_mode::Decryptor::<RefAes256>::new_from_slices(&key[..32], &nonce)
                                .expect("static lengths")
                                .decrypt(&mut expected);
                        },
                        (Method::Aes128Ctr, _) => {
                            use ctr::cipher::{KeyIvInit, StreamCipher};
                            ctr::Ctr128BE::<RefAes128>::new_from_slices(&key[..16], &nonce)
                                .expect("static lengths")
                                .apply_keystream(&mut expected);
                        },
                        (Method::Aes256Ctr, _) => {
                            use ctr::cipher::{KeyIvInit, StreamCipher};
                            ctr::Ctr128BE::<RefAes256>::new_from_slices(&key[..32], &nonce)
                                .expect("static lengths")
                                .apply_keystream(&mut expected);
                        },
                        (Method::ChaCha20, _) => unreachable!("covered by other tests"),
                    }

                    let mut got = data;
                    mine.apply(&mut got);
                    assert_eq!(got, expected, "{method:?} encrypting={encrypting} len={len}");
                }
            }
        }
    }
}

