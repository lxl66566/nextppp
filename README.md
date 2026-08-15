# openppp3-rs

A Rust rewrite of the [openppp2](https://github.com/user/swp])
anti-censorship transport, as a **proxy** (not a VPN).

- `openppp3-core` — protocol core: base94 printable framing, randomized
  headers, NOP noise prelude, per-connection key derivation, payload
  obfuscation transforms (see `docs/openppp2-algo.md` for the algorithm
  survey). The wire protocol is not byte-compatible with the original;
  every anti-blocking design element is preserved, with cryptography
  upgraded (HKDF-SHA256 instead of MD5 `EVP_BytesToKey`, per-packet
  nonces, CSPRNG, no RC4).
- `openppp3-common` — shared building blocks: jsonc configuration, routing
  rules (`domain` / `domain-suffix` / `domain-keyword` / `ip-cidr`, policies
  `proxy` / `direct` / `block`), SOCKS5-style address codec, connection
  pumps.
- `openppp3-server` — the proxy server.
- `openppp3-client` — local mixed-protocol (SOCKS5 + HTTP CONNECT) inbound
  with rule-based routing and optional desktop system-proxy integration.

## Quick start

```sh
# server
openppp3-server --init            # writes openppp3-server.jsonc
# edit listen + passwords, then
openppp3-server -c openppp3-server.jsonc

# client
openppp3-client --init            # writes openppp3-client.jsonc
# edit server address + matching passwords, then
openppp3-client -c openppp3-client.jsonc
```

Point any SOCKS5/HTTP-capable application at `127.0.0.1:1080` (see the
`listen` field), or enable `system_proxy` in the client configuration.

## MSRV

Rust 1.85 (edition 2024).

## License

MIT OR Apache-2.0.
