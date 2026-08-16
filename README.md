# openppp3-rs

用 Rust 重写的 [openppp2](https://github.com/user/swp) 抗封锁传输协议，定位是**代理**（proxy）而非 VPN。

- 抗封锁传输协议：base94 可打印外壳、随机化帧头、NOP 噪声前奏、每连接独立密钥，握手前流量无加密特征。
- 单二进制双角色：`openppp3 server` / `openppp3 client`。
- 客户端是纯粹的 **SOCKS5 入站 -> openppp3 隧道** 转发器，分流交给 sing-box 等前端。
- 跨平台（Windows / Linux / macOS）。

## 快速开始

```sh
# 构建
cargo build --release

# 服务端：生成示例配置并编辑（务必修改两个密码）
./target/release/openppp3 server --init
./target/release/openppp3 server -c openppp3-server.jsonc

# 客户端：生成示例配置并编辑（server 地址 + 与服务器一致的密码）
./target/release/openppp3 client --init
./target/release/openppp3 client -c openppp3-client.jsonc
```

客户端默认监听 `127.0.0.1:1080`。直接把 SOCKS5 应用指向该地址即可；
更常见的用法是作为 sing-box 的 outbound，由 sing-box 负责分流：

```jsonc
// sing-box 配置示意：apps -> sing-box (规则/geosite/geoip) -> openppp3-client -> 隧道
{
  "inbounds": [{ "type": "mixed", "listen": "127.0.0.1", "listen_port": 2080 }],
  "outbounds": [
    { "type": "socks", "tag": "openppp3", "server": "127.0.0.1", "server_port": 1080 },
    { "type": "direct", "tag": "direct" },
  ],
  "route": {
    "rules": [{ "domain_suffix": [".cn"], "outbound": "direct" }],
    "final": "openppp3",
  },
}
```

## 配置

`--init` 生成的示例配置已带注释，按注释修改即可。要点：

- 两端 `obfuscation` 段必须一致（含密码）；除密码外所有字段参与握手校验，不一致会显式报错。
- 密码（`protocol_key` / `transport_key`）部署时必须修改。
- 配置文件为 jsonc，支持注释与尾逗号。

## 文档

- 协议规范：[crates/core/README.md](crates/core/README.md)
- 原版 openppp2 算法复现规范：[docs/openppp2-algo.md](docs/openppp2-algo.md)

## MSRV

Rust 1.85（edition 2024）。

## License

MIT OR Apache-2.0。
