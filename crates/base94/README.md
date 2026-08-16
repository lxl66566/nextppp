# base94-simd

SIMD-accelerated base94 codec: encodes arbitrary binary data into the
printable ASCII range `0x20..=0x7E` (94 symbols), with an optional key-mixing
step (`kf`) and a base94 digit encoding for integers.

Bytes are key-mixed (`(b - kf) mod 256`); mixed values `>= 93` escape into two
chars (`0x7D`/`0x7E` leader + follower), so output is at most twice the input
size. With `kf = 0` the mixing is the identity.

## Backends

- x86_64: SSSE3 kernels over 16-byte blocks (runtime-detected; SSE2 helpers
  for the validity scan and length computation).
- aarch64: NEON helpers; the codec main loops use the portable scalar path.
- other targets: portable scalar path (the reference definition).

All backends are bit-exact, pinned by fuzzing against the scalar reference.

```rust
let mut encoded = Vec::new();
base94_simd::encode_into(&mut encoded, b"hello", 0);
assert!(encoded.iter().all(|&c| (0x20..=0x7e).contains(&c)));
let mut decoded = Vec::new();
base94_simd::decode_into(&mut decoded, &encoded, 0).unwrap();
assert_eq!(decoded, b"hello");
```
