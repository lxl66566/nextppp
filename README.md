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
- `openppp3-common` — shared building blocks: jsonc configuration,
  SOCKS5-style address codec, connection pumps.
- `openppp3-server` — the proxy server (library).
- `openppp3-client` — a plain SOCKS5 inbound that forwards everything
  through the openppp3 tunnel. No built-in routing: chain it behind a
  mature front-end (sing-box, etc.) via its socks outbound.
- `openppp3` — the unified binary (`openppp3 server` / `openppp3 client`);
  one artifact for both ends, so their versions cannot drift apart.

## Quick start

```sh
# server
openppp3 server --init          # writes openppp3-server.jsonc
# edit listen + passwords, then
openppp3 server -c openppp3-server.jsonc

# client
openppp3 client --init          # writes openppp3-client.jsonc
# edit server address + matching passwords, then
openppp3 client -c openppp3-client.jsonc
```

Point a SOCKS5-capable application at `127.0.0.1:1080` (see the `listen`
field), or use sing-box as the front-end for rules / geosite / system
proxy:

```jsonc
// sing-box sketch: apps -> sing-box (rules) -> openppp3-client -> tunnel
{
    "inbounds": [
        { "type": "mixed", "listen": "127.0.0.1", "listen_port": 2080 }
    ],
    "outbounds": [
        { "type": "socks", "tag": "openppp3", "server": "127.0.0.1", "server_port": 1080 },
        { "type": "direct", "tag": "direct" }
    ],
    "route": {
        "rules": [{ "domain_suffix": [".cn"], "outbound": "direct" }],
        "final": "openppp3"
    }
}
```

## MSRV

Rust 1.85 (edition 2024).

## License

MIT OR Apache-2.0.
