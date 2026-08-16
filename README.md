# nextppp

Rust 写的代理，bypass GFW。协议魔改自 [openppp2](https://github.com/liulilittle/openppp2)。

- 抗封锁传输协议：base94、随机化帧头、NOP 噪声前奏、每连接独立密钥，握手前流量无加密特征。
- 不差的性能，详见[端到端吞吐量](#端到端吞吐量)。

## 安装

从 [Release](https://github.com/lxl66566/nextppp/releases) 下载 prebuilt binary。

## 快速开始

```sh
# 服务端：生成示例配置并编辑（务必修改 password）
nextppp server --init
nextppp server -c nextppp-server.jsonc

# 客户端：生成示例配置并编辑（server 地址 + 与服务器一致的 password）
nextppp client --init
nextppp client -c nextppp-client.jsonc
```

客户端默认监听 `127.0.0.1:1080`。直接把系统代理指向该 SOCKS5 地址即可；
更常见的用法是作为 sing-box 的 outbound，由 sing-box 负责分流：

```jsonc
// sing-box 配置示意：apps -> sing-box (规则/geosite/geoip) -> nextppp-client -> 隧道
{
  "inbounds": [{ "type": "mixed", "listen": "127.0.0.1", "listen_port": 2080 }],
  "outbounds": [
    { "type": "socks", "tag": "nextppp", "server": "127.0.0.1", "server_port": 1080 },
    { "type": "direct", "tag": "direct" },
  ],
  "route": {
    "rules": [{ "domain_suffix": [".cn"], "outbound": "direct" }],
    "final": "nextppp",
  },
}
```

## 配置

`--init` 生成的示例配置已带注释，按注释修改即可。要点：

- 顶层 `password` 是共享隧道口令，同时充当两层 cipher 的密钥；
  需要分层密钥时才在 `obfuscation` 里覆写 `protocol_key` / `transport_key`
  （共用一个口令是安全的，核心 KDF 对两层做了域分离，见协议文档 §5.2.1）。
- 两端 `obfuscation` 段必须一致（含密码）；除密码外所有字段参与握手校验，不一致会显式报错。
- `password` 部署时必须修改（仍为内置占位符时启动会告警）。
- 配置文件为 jsonc，支持注释与尾逗号。

## 其他

- 日志级别通过 `SPDLOG_RS_LEVEL` 环境变量控制（`debug` / `trace` / `off`），默认 `info`。

## 测试与基准

### 端到端吞吐量

集成测试 `crates/client/tests/throughput.rs` 走完整链路（socks5 入站 -> client ->
nextppp 隧道 -> server -> 本地 echo），测单向字节速率，server 与 client 均为单核：

```sh
cargo test -p nextppp-client --release --test throughput -- --ignored --nocapture
# throughput: 268435456 bytes (256 MiB) in 1.64s = 156.45 MiB/s (server cpu 0, client cpu 1)
```

## 文档

- 协议规范：[crates/core/README.md](crates/core/README.md)
- 原版 openppp2 算法复现规范：[docs/openppp2-algo.md](docs/openppp2-algo.md)
